#!/usr/bin/env python3
"""Upgrade selected application containers to reviewed image digests after a consistent backup."""
import argparse
import copy
import json
import re
import subprocess
import time
import configparser
import ipaddress
import urllib.request
from pathlib import Path

from snapshot import run, create_backup, container_spec, restore_backup


def validate_image(image):
    if not re.fullmatch(r"[a-z0-9./_:-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("Upgrade images must be immutable repository@sha256 digests")
    return image


def current_backend_bind(snapshot, proc_root="/proc"):
    """Preserve the live listener when upgrading legacy images without an explicit bind."""
    env = dict(item.split("=", 1) for item in snapshot["Config"].get("Env", []) if "=" in item)
    if env.get("XWARP_API_BIND"):
        return env["XWARP_API_BIND"]
    if snapshot.get("HostConfig", {}).get("NetworkMode") != "host":
        raise ValueError("Legacy backend network is unsupported; configure XWARP_API_BIND explicitly before upgrading")
    ini = configparser.ConfigParser()
    ini.read("/tpdata/trojan-panel/config/config.ini")
    api_port = int(env.get("server_port") or ini.getint("server", "port", fallback=8081))
    pid = int(snapshot.get("State", {}).get("Pid", 0))
    if pid <= 0:
        raise ValueError("Backend must be running to preserve its API listener")
    addresses = set()
    for table, ipv6 in [("tcp", False), ("tcp6", True)]:
        file = Path(proc_root) / str(pid) / "net" / table
        if not file.exists():
            continue
        for line in file.read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            encoded, encoded_port = fields[1].split(":")
            if int(encoded_port, 16) != api_port:
                continue
            raw = bytes.fromhex(encoded)
            raw = b"".join(raw[i:i+4][::-1] for i in range(0, 16, 4)) if ipv6 else raw[::-1]
            address = str(ipaddress.ip_address(raw))
            addresses.add("[" + address + "]" if ipv6 else address)
    if len(addresses) != 1:
        raise ValueError("Cannot determine the current API listener safely; set XWARP_API_BIND explicitly before upgrading")
    return addresses.pop()


def upgrade_spec(snapshot, image, image_config, backend_bind=None):
    updated = copy.deepcopy(snapshot)
    # Use the new release's executable wrapper; retain runtime env and host mounts.
    updated["Config"]["Entrypoint"] = image_config.get("Entrypoint") or []
    updated["Config"]["Cmd"] = image_config.get("Cmd") or []
    if updated["Name"].lstrip("/") == "trojan-panel" and backend_bind is not None:
        env = [item for item in updated["Config"].get("Env", []) if not item.startswith("XWARP_API_BIND=")]
        updated["Config"]["Env"] = env + ["XWARP_API_BIND=" + backend_bind]
    if updated["Name"].lstrip("/") == "trojan-panel-ui":
        for mount in updated.get("Mounts", []):
            if mount["Destination"] == "/etc/nginx/conf.d/default.conf":
                if mount["Type"] != "bind" or Path(mount["Source"]).name != "default.conf":
                    raise ValueError("Unsupported old UI configuration mount")
                if not Path(mount["Source"]).is_file():
                    raise ValueError("Old UI configuration file is missing")
                mount["Source"] = str(Path(mount["Source"]).parent)
                mount["Destination"] = "/etc/nginx/conf.d"
        if Path("/tpdata/web").is_dir() and not any(m["Destination"] == "/tpdata/web" for m in updated.get("Mounts", [])):
            updated.setdefault("Mounts", []).append(dict(Type="bind", Source="/tpdata/web", Destination="/tpdata/web", RW=False))

    return container_spec(updated, image)


def backend_healthy(bind="127.0.0.1"):
    ini = configparser.ConfigParser()
    ini.read("/tpdata/trojan-panel/config/config.ini")
    port = ini.getint("server", "port", fallback=8081)
    try:
        host = {"0.0.0.0": "127.0.0.1", "[::]": "[::1]"}.get(bind, bind)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://%s:%d/api/auth/health" % (host, port), timeout=5) as response:
            return response.status == 204
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-image")
    parser.add_argument("--ui-image")
    parser.add_argument("--core-image")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    images = {name: validate_image(value) for name, value in [("trojan-panel", args.backend_image), ("trojan-panel-ui", args.ui_image), ("trojan-panel-core", args.core_image)] if value}
    if not images:
        parser.error("Specify at least one reviewed image digest")
    snapshots = json.loads(run(["docker", "inspect"] + list(images)))
    backend_bind = next((current_backend_bind(s) for s in snapshots if s["Name"].lstrip("/") == "trojan-panel"), "127.0.0.1")
    plans = {s["Name"].lstrip("/"): container_spec(s, images[s["Name"].lstrip("/")]) for s in snapshots}
    if not args.apply:
        print("Validated upgrade plan (no changes): " + ", ".join(images))
        return
    for image in images.values():
        run(["docker", "pull", image], stdout=subprocess.DEVNULL)
    for s in snapshots:
        name = s["Name"].lstrip("/")
        image_config = json.loads(run(["docker", "image", "inspect", images[name]]))[0]["Config"]
        plans[name] = upgrade_spec(s, images[name], image_config, backend_bind=backend_bind)
    archive = create_backup("/root/xwarp-backups", quiesce=True, include_images=True)
    print("Pre-upgrade backup: " + str(archive))
    try:
        for name, plan in plans.items():
            run(["docker", "stop", name])
            run(["docker", "rm", name])
            run(plan, stdout=subprocess.DEVNULL)
            run(["docker", "start", name], stdout=subprocess.DEVNULL)
        for _ in range(30):
            current = json.loads(run(["docker", "inspect"] + list(plans)))
            if all(s["State"]["Running"] and s["RestartCount"] == 0 for s in current):
                time.sleep(5)
                current = json.loads(run(["docker", "inspect"] + list(plans)))
                if all(s["State"]["Running"] and s["RestartCount"] == 0 for s in current) and ("trojan-panel" not in plans or backend_healthy(backend_bind)):
                    print("Containers remain running. Node and subscription acceptance still require explicit functional tests.")
                    return
            time.sleep(2)
        raise RuntimeError("New containers failed the startup check")
    except Exception:
        print("Startup failed; restoring the pre-upgrade snapshot.")
        restore_backup(archive, archive.name)
        raise RuntimeError("Upgrade failed and rollback was attempted; inspect diagnostics before retrying")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error))
