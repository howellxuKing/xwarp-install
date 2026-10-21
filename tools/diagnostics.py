#!/usr/bin/env python3
"""Read-only server health classification and local alerts; never infer censorship from a timeout."""
import argparse
import configparser
import datetime
import json
import shutil
import socket
import subprocess
import syslog
from pathlib import Path

from gateway import write_private


def command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    return result.returncode, result.stdout.decode(errors="replace")


def collect(state="/tpdata/trojan-panel/config/gateway.json"):
    report = {"checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "warnings": [], "containers": [], "certificates": []}
    uptime = Path("/proc/uptime")
    if uptime.exists():
        report["server_uptime_seconds"] = int(float(uptime.read_text().split()[0]))
        if report["server_uptime_seconds"] < 600:
            report["warnings"].append("服务器近期启动；请结合重启记录判断连接中断原因")
    disk = shutil.disk_usage("/tpdata" if Path("/tpdata").exists() else "/")
    report["disk_free_bytes"] = disk.free
    if disk.free < 512 * 1024 * 1024:
        report["warnings"].append("磁盘剩余空间不足512MB")
    if shutil.which("docker"):
        code, ids = command(["docker", "ps", "-aq", "--filter", "name=trojan-panel"])
        if not code and ids.strip():
            code, data = command(["docker", "inspect"] + ids.split())
            if not code:
                for raw in json.loads(data):
                    item = {"name": raw["Name"].lstrip("/"), "status": raw["State"]["Status"], "restarts": raw["RestartCount"], "oom_killed": raw["State"].get("OOMKilled", False), "started_at": raw["State"].get("StartedAt"), "image_id": raw["Image"]}
                    report["containers"].append(item)
                    if item["status"] != "running" or item["oom_killed"] or item["restarts"]:
                        report["warnings"].append(item["name"] + "存在停止、重启或内存不足记录")
        else:
            report["warnings"].append("Docker状态无法读取或未找到项目容器")
    if Path(state).exists():
        config = json.loads(Path(state).read_text())
        for label, path in [("panel", config["certificate"]), ("subscription", config.get("subscription_certificate", config["certificate"]))]:
            item = {"purpose": label, "path": path, "valid_for_7_days": False}
            if Path(path).exists() and shutil.which("openssl"):
                code, expires = command(["openssl", "x509", "-in", path, "-noout", "-enddate"])
                item["expiry"] = expires.strip() if not code else "读取失败"
                code, _ = command(["openssl", "x509", "-in", path, "-noout", "-checkend", "604800"])
                item["valid_for_7_days"] = code == 0
            if not item["valid_for_7_days"]:
                report["warnings"].append(label + "证书缺失、无效或7天内到期")
            report["certificates"].append(item)
    if shutil.which("ss"):
        code, data = command(["ss", "-H", "-lnt"])
        if not code:
            report["tcp_listeners"] = [line.split()[3] for line in data.splitlines() if len(line.split()) > 3]
    settings = configparser.ConfigParser()
    settings.read("/tpdata/trojan-panel/config/config.ini")
    database_port = settings.getint("mysql", "port", fallback=9507)
    redis_port = settings.getint("redis", "port", fallback=6378)
    for address in report.get("tcp_listeners", []):
        host, separator, port = address.rpartition(":")
        if separator and port in [str(database_port), str(redis_port)] and host in ["*", "0.0.0.0", "[::]", "::"]:
            report["warnings"].append("数据库或Redis监听所有网卡（端口" + port + "）；公网是否可访问仍需结合云防火墙核实")
    if shutil.which("iptables"):
        code, rules = command(["iptables", "-S", "INPUT"])
        report["management_policy_attached"] = code == 0 and "-j XWARP_CORE" in rules
        if not report["management_policy_attached"]:
            report["warnings"].append("未检测到本项目的核心管理端口限制规则；如采用其他防火墙，请核实其策略")
    report["interpretation"] = "这些结果用于区分服务、重启、资源和证书问题。UDP需要客户端实际协议握手；单次超时不能判断被墙。"
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", default="/tpdata/trojan-panel/config/gateway.json")
    parser.add_argument("--output", default="/tpdata/trojan-panel/logs/security-health.json")
    parser.add_argument("--monitor", action="store_true")
    args = parser.parse_args()
    report = collect(args.state)
    previous = {}
    if Path(args.output).exists():
        previous = json.loads(Path(args.output).read_text())
    write_private(args.output, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if args.monitor and report["warnings"] != previous.get("warnings", []):
        syslog.syslog(syslog.LOG_WARNING, "XWarp health changed: " + "; ".join(report["warnings"]) if report["warnings"] else "XWarp health recovered")
    if not args.monitor:
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Health inspection failed; no service changes were made")
