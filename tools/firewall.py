#!/usr/bin/env python3
"""Restrict only selected core management TCP ports; proxy, SSH and subscription ports are untouched."""
import argparse
import json
from pathlib import Path
import ipaddress
import shutil
import subprocess


def run(argv, check=True):
    return subprocess.run(argv, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def core_rules(ports, allowed, execute=run, remove=False):
    ports = [int(p) for p in ports]
    if not ports or len(ports) > 15 or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Supply 1 to 15 valid management ports")
    addresses = [ipaddress.ip_network(address, strict=False) for address in allowed]
    chain = "XWARP_CORE"
    for binary, version in [("iptables", 4), ("ip6tables", 6)]:
        base = [binary, "-w", "5"]
        jumps = ["-p", "tcp", "-m", "multiport", "--dports", ",".join(map(str, ports)), "-j", chain]
        exists = execute(base + ["-C", "INPUT"] + jumps, check=False).returncode == 0
        guard = jumps[:-1] + ["DROP"]
        if remove:
            if exists:
                execute(base + ["-D", "INPUT"] + jumps)
            # Remove safety guards left by interrupted updates of this exact port set.
            for _ in range(16):
                if execute(base + ["-C", "INPUT"] + guard, check=False).returncode != 0:
                    break
                execute(base + ["-D", "INPUT"] + guard)
            execute(base + ["-F", chain], check=False)
            execute(base + ["-X", chain], check=False)
            continue
        # Temporarily fail closed while replacing an attached chain. On failure the guard remains.
        if exists:
            execute(base + ["-I", "INPUT", "1"] + guard)
        execute(base + ["-N", chain], check=False)
        # Install rules before attaching the chain, so a fresh setup never has an empty gate.
        execute(base + ["-F", chain])
        execute(base + ["-A", chain, "-m", "addrtype", "--src-type", "LOCAL", "-j", "RETURN"])
        for address in addresses:
            if address.version == version:
                execute(base + ["-A", chain, "-s", str(address), "-j", "RETURN"])
        execute(base + ["-A", chain, "-j", "DROP"])
        if not exists:
            execute(base + ["-I", "INPUT", "1"] + jumps)
        # A prior interrupted update may also have left a guard. The populated chain is now safe.
        for _ in range(16):
            if execute(base + ["-C", "INPUT"] + guard, check=False).returncode != 0:
                break
            execute(base + ["-D", "INPUT"] + guard)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ports", default="8082,8100")
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        parser.error("Use --apply only after reviewing the management ports and backend server addresses")
    for binary in ["iptables", "ip6tables"]:
        if not shutil.which(binary):
            parser.error(binary + " is required; no firewall rules were changed")
    core_rules(args.ports.split(","), args.allow, remove=args.remove)
    state = Path("/tpdata/trojan-panel/config/gateway.json")
    if not args.remove and state.exists():
        config = json.loads(state.read_text())
        if config.get("knock_enabled"):
            if config["panel_port"] == config["subscription_port"]:
                raise ValueError("Panel IP gate cannot share the subscription port")
            if not shutil.which("ipset"):
                raise ValueError("ipset required for enabled panel IP gate")
            from knock import policy
            policy(config["panel_port"])
    print("Core management policy applied to IPv4 and IPv6. Persist using the supplied systemd unit.")


if __name__ == "__main__":
    main()
