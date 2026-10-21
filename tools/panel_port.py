#!/usr/bin/env python3
"""Change only the panel listener, with validation, backup and rollback."""
import argparse
import datetime
import http.client
import json
import re
import secrets
import socket
import ssl
import subprocess
import time
from pathlib import Path

from gateway import domain, port, render, write_private
from panel_access import entry_url, print_panel_entry
from ports import choose_port


LISTEN = re.compile(r"(?m)^(\s*listen\s+)(\[::\]:)?(\d+)(?=\s|;)")


def legacy_plan(text, new_port):
    listeners = list(LISTEN.finditer(text))
    old_ports = {int(match[3]) for match in listeners}
    # Legacy templates have one HTTP or HTTPS server. Never guess in a combined gateway.
    if len(re.findall(r"\bserver\s*\{", text)) != 1 or len(old_ports) != 1:
        raise ValueError("Multiple server blocks found without gateway state; use menu 26 to configure the private gateway first")
    old_port = old_ports.pop()
    result = LISTEN.sub(lambda match: match[1] + (match[2] or "") + str(new_port), text)
    result = re.sub(r"(https?://\$host:)" + str(old_port) + r"(?=\$request_uri)", lambda match: match[1] + str(new_port), result)
    return old_port, result, " ssl" in text


def check_available(value):
    sockets = []
    try:
        for family, address in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
            if family == socket.AF_INET6 and not socket.has_ipv6:
                continue
            handle = socket.socket(family, socket.SOCK_STREAM)
            sockets.append(handle)
            handle.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                handle.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            handle.bind((address, value))
    except OSError as error:
        raise ValueError("Port is occupied or unavailable; no configuration changed") from error
    finally:
        for handle in sockets:
            handle.close()


def execute(args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode:
        raise RuntimeError("Nginx operation failed; inspect server diagnostics")


def probe(value, tls, path, expected):
    for _ in range(20):
        try:
            # Local readiness probe only; sends neither passwords nor entry keys.
            connection = (http.client.HTTPSConnection("127.0.0.1", value, context=ssl._create_unverified_context(), timeout=1)
                          if tls else http.client.HTTPConnection("127.0.0.1", value, timeout=1))
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                response.read()
                if response.status == expected:
                    return
            finally:
                connection.close()
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.25)
    raise RuntimeError("New panel port did not become ready")


def change_port(new_port, state, output, backup_directory, container="trojan-panel-ui"):
    new_port = port(new_port)
    inspected = subprocess.run(["docker", "inspect", "--format", "{{json .Mounts}}", container], capture_output=True)
    if inspected.returncode or not any(m["Destination"] == "/etc/nginx/conf.d" and m["Type"] == "bind" for m in json.loads(inspected.stdout)):
        raise ValueError("Upgrade the UI to a configuration directory mount first; no configuration changed")
    state, output = Path(state), Path(output)
    original = output.read_text()
    state_text = state.read_text() if state.exists() else None
    config = json.loads(state_text) if state_text is not None else None
    if config is not None:
        old_port = port(config["panel_port"])
        config["panel_port"] = new_port
        candidate = render(config)  # Reject subscription-port collisions before changing anything.
        tls, path, expected = True, config["panel_path"], 404 if config.get("entry_key_enabled") else 200
    else:
        old_port, candidate, tls = legacy_plan(original, new_port)
        path, expected = "/", 200
    if new_port == old_port:
        return config
    check_available(new_port)
    directory = Path(backup_directory) / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4))
    directory.mkdir(parents=True, mode=0o700)
    write_private(directory / "nginx-before.conf", original)
    if state_text is not None:
        write_private(directory / "gateway-before.json", state_text)
    write_private(directory / "candidate.conf", candidate)
    temp = "/tmp/xwarp-panel-port-" + secrets.token_hex(8)
    write_private(directory / "validate.conf", "events {}\nhttp { include /etc/nginx/mime.types; include " + temp + ".conf; }\n")
    execute(["docker", "cp", str(directory / "candidate.conf"), container + ":" + temp + ".conf"])
    execute(["docker", "cp", str(directory / "validate.conf"), container + ":" + temp + "-validate.conf"])
    execute(["docker", "exec", container, "nginx", "-t", "-c", temp + "-validate.conf"])
    try:
        write_private(output, candidate)
        execute(["docker", "exec", container, "nginx", "-t"])
        execute(["docker", "exec", container, "nginx", "-s", "reload"])
        probe(new_port, tls, path, expected)
        if config is not None:
            write_private(state, json.dumps(config, indent=2) + "\n")
    except Exception:
        write_private(output, original)
        if state_text is not None:
            write_private(state, state_text)
        execute(["docker", "exec", container, "nginx", "-s", "reload"])
        probe(old_port, tls, path, expected)
        raise RuntimeError("Panel port change failed; previous configuration restored")
    print("Panel port changed: " + str(old_port) + " -> " + str(new_port))
    print("Configuration backup: " + str(directory))
    print("Subscription port, entry key and panel path unchanged. If a cloud firewall is used, allow the new TCP port there.")
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choices = parser.add_mutually_exclusive_group(required=True)
    choices.add_argument("--port", type=int)
    choices.add_argument("--random", action="store_true")
    parser.add_argument("--state", default="/tpdata/trojan-panel/config/gateway.json")
    parser.add_argument("--output", default="/tpdata/trojan-panel-ui/nginx/default.conf")
    parser.add_argument("--backups", default="/root/xwarp-maintenance/panel-port")
    parser.add_argument("--host", help="Domain or IP for a legacy panel without gateway state")
    args = parser.parse_args()
    try:
        if not Path(args.state).exists() and not args.host:
            raise ValueError("Provide --host for a legacy panel")
        if args.host:
            domain(args.host)
        if args.random:
            excluded = [json.loads(Path(args.state).read_text())["subscription_port"]] if Path(args.state).exists() else []
            value = choose_port(exclude=excluded)
        else:
            value = port(args.port)
        config = change_port(value, args.state, args.output, args.backups)
        if config is not None:
            print_panel_entry(entry_url(args.state))
        else:
            tls = " ssl" in Path(args.output).read_text()
            print_panel_entry(("https" if tls else "http") + "://" + args.host + ":" + str(value) + "/")
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
