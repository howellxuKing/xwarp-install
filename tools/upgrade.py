#!/usr/bin/env python3
"""Upgrade selected application containers to reviewed image digests after a consistent backup."""
import argparse
import copy
import json
import re
import subprocess
import time
import configparser
import urllib.request
from pathlib import Path

from snapshot import run, create_backup, container_spec, restore_backup


def validate_image(image):
    if not re.fullmatch(r"[a-z0-9./_:-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("Upgrade images must be immutable repository@sha256 digests")
    return image


def upgrade_spec(snapshot, image, image_config):
    updated = copy.deepcopy(snapshot)
    # Use the new release's executable wrapper; retain runtime env and host mounts.
    updated["Config"]["Entrypoint"] = image_config.get("Entrypoint") or []
    updated["Config"]["Cmd"] = image_config.get("Cmd") or []
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


def backend_healthy():
    ini = configparser.ConfigParser()
    ini.read("/tpdata/trojan-panel/config/config.ini")
    port = ini.getint("server", "port", fallback=8081)
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/auth/health" % port, timeout=5) as response:
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
    plans = {s["Name"].lstrip("/"): container_spec(s, images[s["Name"].lstrip("/")]) for s in snapshots}
    if not args.apply:
        print("Validated upgrade plan (no changes): " + ", ".join(images))
        return
    for image in images.values():
        run(["docker", "pull", image], stdout=subprocess.DEVNULL)
    for s in snapshots:
        name = s["Name"].lstrip("/")
        image_config = json.loads(run(["docker", "image", "inspect", images[name]]))[0]["Config"]
        plans[name] = upgrade_spec(s, images[name], image_config)
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
                if all(s["State"]["Running"] and s["RestartCount"] == 0 for s in current) and ("trojan-panel" not in plans or backend_healthy()):
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
