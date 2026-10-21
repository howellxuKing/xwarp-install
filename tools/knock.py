#!/usr/bin/env python3
"""Optional HTTPS authorization gate backed by kernel-expiring IP sets, not traditional port knocking."""
import argparse
import hmac
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from gateway import write_private


def run(argv, check=True):
    return subprocess.run(argv, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def policy(port, execute=run, remove=False):
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid panel port")
    for binary, version, family in [("iptables", 4, "inet"), ("ip6tables", 6, "inet6")]:
        chain, ipset = "XWARP_PANEL", "xwarp_panel" + str(version)
        base = [binary, "-w", "5"]
        jump = ["-p", "tcp", "--dport", str(port), "-j", chain]
        exists = execute(base + ["-C", "INPUT"] + jump, check=False).returncode == 0
        guard = jump[:-1] + ["DROP"]
        if remove:
            if exists:
                execute(base + ["-D", "INPUT"] + jump)
            # Remove safety guards left by interrupted updates of this exact port set.
            for _ in range(16):
                if execute(base + ["-C", "INPUT"] + guard, check=False).returncode != 0:
                    break
                execute(base + ["-D", "INPUT"] + guard)
            execute(base + ["-F", chain], check=False)
            execute(base + ["-X", chain], check=False)
            execute(["ipset", "destroy", ipset], check=False)
            continue
        execute(["ipset", "create", ipset, "hash:ip", "family", family, "timeout", "43200", "maxelem", "1024", "-exist"])
        # Temporarily fail closed while replacing an attached chain. On failure the guard remains.
        if exists:
            execute(base + ["-I", "INPUT", "1"] + guard)
        execute(base + ["-N", chain], check=False)
        execute(base + ["-F", chain])
        execute(base + ["-A", chain, "-m", "addrtype", "--src-type", "LOCAL", "-j", "RETURN"])
        execute(base + ["-A", chain, "-m", "set", "--match-set", ipset, "src", "-j", "RETURN"])
        execute(base + ["-A", chain, "-j", "DROP"])
        if not exists:
            execute(base + ["-I", "INPUT", "1"] + jump)
        # A prior interrupted update may also have left a guard. The populated chain is now safe.
        for _ in range(16):
            if execute(base + ["-C", "INPUT"] + guard, check=False).returncode != 0:
                break
            execute(base + ["-D", "INPUT"] + guard)


def grant(address, execute=run):
    address = ipaddress.ip_address(address)
    execute(["ipset", "add", "xwarp_panel" + str(address.version), str(address), "timeout", "43200", "-exist"])


def handler(key):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log paths, query strings, keys, or cookies.

        def answer(self):
            # Only the local nginx gateway may supply the visitor's actual IP.
            if self.client_address[0] not in ["127.0.0.1", "::1"]:
                self.send_error(403)
                return
            query = parse_qs(urlparse(self.path).query)
            if self.command == "POST":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 <= length <= 256:
                        raise ValueError()
                    query = parse_qs(self.rfile.read(length).decode())
                except (ValueError, UnicodeDecodeError):
                    self.send_error(400)
                    return
            given = query.get("key", [""])[0]
            if len(given) > 128 or not hmac.compare_digest(given, key):
                self.send_error(404)
                return
            try:
                address = ipaddress.ip_address(self.headers.get("X-Real-IP", ""))
                if address.is_unspecified or address.is_multicast:
                    raise ValueError()
                grant(str(address))
            except (ValueError, subprocess.CalledProcessError):
                self.send_error(503)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write('<!doctype html><meta charset="utf-8"><script>history.replaceState(null,"","/_knock")</script><p>当前网络已获准访问面板，12小时后自动到期。切换网络后请重新授权。</p>'.encode())

        do_GET = answer
        do_POST = answer
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", default="/tpdata/trojan-panel/config/gateway.json")
    parser.add_argument("--key", default="/tpdata/trojan-panel/config/knock.key")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        parser.error("Explicit --apply is required; this feature closes the configured panel port")
    for binary in ["iptables", "ip6tables", "ipset"]:
        if not shutil.which(binary):
            parser.error(binary + " must be installed before enabling the gate")
    config = json.loads(Path(args.state).read_text())
    if config["panel_port"] == config["subscription_port"]:
        parser.error("Panel and subscription ports must be separate")
    if not args.remove and not config.get("knock_enabled"):
        parser.error("Generate the public authorization endpoint with gateway.py --knock first")
    if args.remove:
        config["knock_enabled"] = False
        write_private(args.state, json.dumps(config, indent=2) + "\n")
        policy(config["panel_port"], remove=True)
        print("Panel IP gate removed; normal panel authentication still applies.")
        return
    key_path = Path(args.key)
    if not key_path.exists():
        write_private(key_path, secrets.token_urlsafe(36) + "\n")
    if key_path.is_symlink() or key_path.stat().st_mode & 0o077:
        parser.error("Knock key must be a private regular file")
    key = key_path.read_text().strip()
    if len(key) < 32:
        parser.error("Invalid knock key")
    server = ThreadingHTTPServer(("127.0.0.1", 8099), handler(key))
    policy(config["panel_port"])
    # Failed or stopped daemon leaves the panel closed; ipset timeouts expire in the kernel.
    server.serve_forever()


if __name__ == "__main__":
    main()
