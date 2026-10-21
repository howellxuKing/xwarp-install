#!/usr/bin/env python3
"""Private database/configuration/image backups and explicit offline restoration."""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

CONFIG_NAMES = ("cert", "caddy", "nginx", "web", "trojan-panel", "trojan-panel-ui", "trojan-panel-core", "domain.lock")
APP_NAMES = ("trojan-panel", "trojan-panel-ui", "trojan-panel-core", "trojan-panel-caddy", "trojan-panel-nginx")


def run(argv, stdout=subprocess.PIPE, stdin=None):
    result = subprocess.run(argv, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE)
    if result.returncode:
        # Container creation arguments can contain credentials; never include them in exceptions.
        raise RuntimeError("Operation failed: " + argv[0] + "; sensitive command output suppressed")
    return result.stdout


def private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing symbolic link backup directory")
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def image_digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def container_spec(snapshot, image=None):
    name = snapshot["Name"].lstrip("/")
    host, config = snapshot["HostConfig"], snapshot["Config"]
    if host["NetworkMode"] != "host" or host.get("Privileged"):
        raise ValueError("Only the project's non-privileged host-network containers are supported")
    args = ["docker", "create", "--name", name, "--network", "host"]
    restart = host.get("RestartPolicy", {}).get("Name", "no")
    args += ["--restart", restart or "no"]
    for variable in config.get("Env") or []:
        args += ["--env", variable]
    for mount in snapshot.get("Mounts", []):
        source = mount.get("Name") if mount["Type"] == "volume" else mount["Source"]
        if mount["Type"] not in ("bind", "volume") or not source:
            raise ValueError("Unsupported container mount")
        value = "type=" + mount["Type"] + ",source=" + source + ",target=" + mount["Destination"]
        if not mount.get("RW", True):
            value += ",readonly"
        args += ["--mount", value]
    for option, field in [("--user", "User"), ("--workdir", "WorkingDir")]:
        if config.get(field):
            args += [option, config[field]]
    for label, value in (config.get("Labels") or {}).items():
        args += ["--label", label + "=" + value]
    for cap in host.get("CapAdd") or []:
        args += ["--cap-add", cap]
    for cap in host.get("CapDrop") or []:
        args += ["--cap-drop", cap]
    if host.get("Memory"):
        args += ["--memory", str(host["Memory"])]
    entry = config.get("Entrypoint") or []
    if entry:
        args += ["--entrypoint", entry[0]]
    args.append(image or snapshot["Image"])
    args.extend(entry[1:] + (config.get("Cmd") or []))
    return args


def create_backup(output, quiesce=False, include_images=True):
    output = private_directory(output)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = output / ("xwarp-" + stamp + ".tar.gz")
    if archive.exists():
        raise ValueError("Backup filename already exists")
    ids = run(["docker", "ps", "-aq"]).decode().split()
    snapshots = json.loads(run(["docker", "inspect"] + ids)) if ids else []
    selected = [s for s in snapshots if s["Name"].lstrip("/").startswith("trojan-panel")]
    if not any(s["Name"] == "/trojan-panel-mariadb" for s in selected):
        raise ValueError("Local database container is required; remote databases need a separate coordinated backup")
    stopped = []
    with tempfile.TemporaryDirectory(prefix="snapshot-", dir=output) as staging:
        staging = Path(staging)
        try:
            if quiesce:
                for s in selected:
                    if s["Name"].lstrip("/") in APP_NAMES and s["State"]["Running"]:
                        run(["docker", "stop", s["Name"].lstrip("/")])
                        stopped.append(s["Name"].lstrip("/"))
            (staging / "containers.json").write_text(json.dumps(selected, indent=2))
            with open(staging / "database.sql", "wb") as dump:
                run(["docker", "exec", "trojan-panel-mariadb", "sh", "-c", 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mariadb-dump -uroot --single-transaction --routines --events --triggers --databases trojan_panel_db'], stdout=dump)
            with open(staging / "database.sql", "rb") as dump:
                dump.seek(max(0, (staging / "database.sql").stat().st_size - 4096))
                if b"Dump completed" not in dump.read():
                    raise ValueError("Database export was not completed")
            image_ids = sorted({s["Image"] for s in selected})
            if include_images:
                with open(staging / "images.tar", "wb") as saved:
                    run(["docker", "image", "save"] + image_ids, stdout=saved)
            (staging / "manifest.json").write_text(json.dumps({"format": 1, "created_utc": stamp, "images_included": include_images, "quiesced": quiesce, "config_names": [n for n in CONFIG_NAMES if (Path("/tpdata") / n).exists()]}, indent=2))
            with tarfile.open(archive, "w:gz", dereference=True) as tar:
                tar.add(staging, arcname="snapshot")
                for name in CONFIG_NAMES:
                    path = Path("/tpdata") / name
                    if path.exists():
                        tar.add(path, arcname="tpdata/" + name, filter=lambda info: None if "/logs/" in info.name else info)
            os.chmod(archive, 0o600)
            (archive.with_suffix(archive.suffix + ".sha256")).write_text(image_digest(archive) + "\n")
            os.chmod(archive.with_suffix(archive.suffix + ".sha256"), 0o600)
        except Exception:
            if archive.exists():
                archive.unlink()
            raise
        finally:
            for name in stopped:
                run(["docker", "start", name], stdout=subprocess.DEVNULL)
    return archive


def extract_verified(archive, destination):
    archive, destination = Path(archive), Path(destination).resolve()
    expected = archive.with_suffix(archive.suffix + ".sha256").read_text().strip()
    if image_digest(archive) != expected:
        raise ValueError("Backup SHA256 mismatch")
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            target = (destination / member.name).resolve()
            if target != destination and destination not in target.parents:
                raise ValueError("Unsafe backup path")
            if not (member.isfile() or member.isdir()):
                raise ValueError("Backup contains links or special files")
            if member.name.startswith("tpdata/") and member.name.split("/")[1] not in CONFIG_NAMES:
                raise ValueError("Unexpected configuration directory")
        tar.extractall(destination)
    return json.loads((destination / "snapshot/manifest.json").read_text())


def restore_backup(archive, confirm):
    archive = Path(archive).resolve()
    if confirm != archive.name:
        raise ValueError("Restoration requires --confirm followed by the exact backup filename")
    staging = private_directory(tempfile.mkdtemp(prefix="restore-", dir=archive.parent))
    manifest = extract_verified(archive, staging)
    snapshots = json.loads((staging / "snapshot/containers.json").read_text())
    # Validate all recreation plans before stopping anything.
    plans = {s["Name"].lstrip("/"): container_spec(s) for s in snapshots if s["Name"].lstrip("/") in APP_NAMES}
    current = run(["docker", "ps", "-a", "--format", "{{.Names}}"]).decode().split()
    if "trojan-panel-mariadb" not in current:
        raise ValueError("Restore requires the original local database container")
    if manifest.get("format") != 1 or not isinstance(manifest.get("config_names"), list):
        raise ValueError("Unsupported backup format")
    for name in manifest["config_names"]:
        if name not in CONFIG_NAMES or not (staging / "tpdata" / name).exists():
            raise ValueError("Missing or unexpected restore configuration")
        target = Path("/tpdata") / name
        if target.is_symlink():
            raise ValueError("Refusing symbolic link restore destination")
    if manifest.get("images_included") and not (staging / "snapshot/images.tar").is_file():
        raise ValueError("Missing saved images")
    if not (staging / "snapshot/database.sql").is_file():
        raise ValueError("Missing database snapshot")
    cache_plan = None
    for cache in json.loads(run(["docker", "inspect", "trojan-panel-redis"])):
        command = cache["Config"].get("Cmd") or []
        if "--requirepass" not in command:
            raise ValueError("Restore requires a supported authenticated Redis container")
        secret = command[command.index("--requirepass") + 1]
        cache_port = command[command.index("--port") + 1] if "--port" in command else "6379"
        cache_plan = ["docker", "exec", "-e", "REDISCLI_AUTH=" + secret, "trojan-panel-redis", "redis-cli", "--no-auth-warning", "-p", cache_port]
        if run(cache_plan + ["PING"]).strip() != b"PONG":
            raise ValueError("Redis access validation failed")
    # Verify database access before stopping applications.
    run(["docker", "exec", "trojan-panel-mariadb", "sh", "-c", 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mariadb -uroot -e "SELECT 1"'])

    for name in plans:
        if name in current:
            run(["docker", "stop", name])
    preserved = private_directory(staging / "pre-restore")
    for name in manifest["config_names"]:
        if name not in CONFIG_NAMES:
            raise ValueError("Unexpected restore target")
        target, source = Path("/tpdata") / name, staging / "tpdata" / name
        if target.is_symlink() or target.parent.resolve() != Path("/tpdata").resolve():
            raise ValueError("Unsafe restore destination")
        if target.exists():
            shutil.move(str(target), str(preserved / name))
        shutil.copytree(source, target) if source.is_dir() else shutil.copy2(source, target)
    if manifest["images_included"]:
        with open(staging / "snapshot/images.tar", "rb") as saved:
            run(["docker", "image", "load"], stdin=saved, stdout=subprocess.DEVNULL)
    # Restore the whole application schema, including removed/added security tables.
    with open(staging / "database-restore.sql", "wb") as prepared:
        prepared.write(b"DROP DATABASE IF EXISTS trojan_panel_db;\n")
        with open(staging / "snapshot/database.sql", "rb") as source:
            shutil.copyfileobj(source, prepared)
    with open(staging / "database-restore.sql", "rb") as dump:
        run(["docker", "exec", "-i", "trojan-panel-mariadb", "sh", "-c", 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mariadb -uroot'], stdin=dump)
    if run(cache_plan + ["FLUSHDB"]).strip() != b"OK":
        raise ValueError("Restoration cache invalidation failed; applications remain stopped")
    for s in snapshots:
        name = s["Name"].lstrip("/")
        if name not in plans:
            continue
        if name in current:
            run(["docker", "rm", name])
        run(plans[name], stdout=subprocess.DEVNULL)
        if s["State"]["Running"]:
            run(["docker", "start", name], stdout=subprocess.DEVNULL)
    print("Database, application configuration and application containers restored. Review health checks before using nodes.")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    backup = sub.add_parser("backup")
    backup.add_argument("--output", default="/root/xwarp-backups")
    backup.add_argument("--quiesce", action="store_true")
    backup.add_argument("--no-images", action="store_true")
    restore = sub.add_parser("restore")
    restore.add_argument("archive")
    restore.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.command == "backup":
        print(create_backup(args.output, args.quiesce, not args.no_images))
    else:
        restore_backup(args.archive, args.confirm)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error))
