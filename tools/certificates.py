#!/usr/bin/env python3
"""Check managed certificates, synchronize renewed pairs and reload nginx safely."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from gateway import write_private, domain


def run(args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    if check and result.returncode:
        raise RuntimeError("Certificate operation failed: " + args[0])
    return result


def matched_pair(cert, key, hostname):
    host = domain(hostname)
    checked = run(["openssl", "x509", "-in", str(cert), "-noout", "-checkhost", host])
    # Some OpenSSL releases print a mismatch while returning zero for -checkhost.
    if checked.stdout.decode(errors="replace").strip() != "Hostname " + host + " does match certificate":
        raise ValueError("Certificate does not cover the configured hostname")
    run(["openssl", "x509", "-in", str(cert), "-noout", "-checkend", "0"])
    public_cert = run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"]).stdout
    public_key = run(["openssl", "pkey", "-in", str(key), "-pubout"]).stdout
    if public_cert != public_key:
        raise ValueError("Certificate and private key do not match")


def sync(config, reload_core=False):
    changed = False
    for hostname, cert_path, key_path in [
        (config["panel_domain"], config["certificate"], config["private_key"]),
        (config["subscription_domain"], config.get("subscription_certificate", config["certificate"]), config.get("subscription_private_key", config["private_key"])),
    ]:
        cert, key = Path(cert_path), Path(key_path)
        candidates = [p for p in Path("/tpdata/cert").rglob(hostname + ".crt") if p != cert and p.with_suffix(".key").exists()]
        for source in sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True):
            source_key = source.with_suffix(".key")
            matched_pair(source, source_key, hostname)
            if cert.exists() and cert.read_bytes() == source.read_bytes() and key.exists() and key.read_bytes() == source_key.read_bytes():
                break
            old_cert = cert.read_text() if cert.exists() else None
            old_key = key.read_text() if key.exists() else None
            write_private(cert, source.read_text())
            write_private(key, source_key.read_text())
            try:
                run(["docker", "exec", "trojan-panel-ui", "nginx", "-t"])
            except Exception:
                if old_cert is not None:
                    write_private(cert, old_cert)
                if old_key is not None:
                    write_private(key, old_key)
                raise
            changed = True
            break
        matched_pair(cert, key, hostname)
    # Directly mounted Caddy renewals can change files without copying them.
    fingerprint_path = Path("/tpdata/trojan-panel/config/certificate-fingerprints.json")
    current = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in {config["certificate"], config.get("subscription_certificate", config["certificate"])}}
    prior = json.loads(fingerprint_path.read_text()) if fingerprint_path.exists() else current
    if current != prior:
        changed = True
    if changed:
        run(["docker", "exec", "trojan-panel-ui", "nginx", "-t"])
        run(["docker", "exec", "trojan-panel-ui", "nginx", "-s", "reload"])
        if reload_core:
            run(["docker", "restart", "trojan-panel-core"])
        print("Renewed certificates loaded by nginx; core reload " + ("performed" if reload_core else "requires a maintenance decision"))
    write_private(fingerprint_path, json.dumps(current))


def add_domain(path, hostname):
    mounts = json.loads(run(["docker", "inspect", "trojan-panel-caddy"]).stdout)[0]["Mounts"]
    if not any(m["Destination"].rstrip("/") == str(Path(path).parent) for m in mounts):
        raise ValueError("Caddy configuration must use a directory mount before automated changes")
    config = json.loads(Path(path).read_text())
    host = domain(hostname)
    automate = config.setdefault("apps", {}).setdefault("tls", {}).setdefault("certificates", {}).setdefault("automate", [])
    if host not in automate:
        automate.append(host)
    # Keep a private rollback copy before changing the existing Caddy configuration.
    backup = Path(str(path) + ".before-domain")
    write_private(backup, Path(path).read_text())
    write_private(path, json.dumps(config, indent=2))
    try:
        run(["docker", "exec", "trojan-panel-caddy", "caddy", "validate", "--config", str(path)])
        run(["docker", "restart", "trojan-panel-caddy"])
    except Exception:
        write_private(path, backup.read_text())
        raise
    print("Caddy certificate automation configured. DNS and ACME challenge reachability must still be verified.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", default="/tpdata/trojan-panel/config/gateway.json")
    parser.add_argument("--reload-core-on-renewal", action="store_true")
    parser.add_argument("--add-domain")
    parser.add_argument("--caddy-config", default="/tpdata/caddy/config.json")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        parser.error("--apply is required because certificate synchronization can reload services")
    if args.add_domain:
        add_domain(args.caddy_config, args.add_domain)
    else:
        sync(json.loads(Path(args.state).read_text()), args.reload_core_on_renewal)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Certificate operation failed; check local certificate and service state")
