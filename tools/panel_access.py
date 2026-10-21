#!/usr/bin/env python3
"""Print the complete panel entry locally after successful installation."""
import argparse
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener

from gateway import domain, port, render


def print_panel_entry(url):
    """Keep the URL on its own line and emphasize it in interactive SSH terminals."""
    color = sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ
    for line in ["", "=" * 64, "完整面板登录入口（请复制并收藏整行）：", "", url, "", "=" * 64, ""]:
        print("\033[1;91m" + line + "\033[0m" if color and line else line)
    print("入口包含访问密钥，请妥善保存；不要复制浏览器跳转后的地址。" if "_entry?" in url else "请保存此登录地址。")


def legacy_entry_url(config_file):
    text = Path(config_file).read_text()
    listeners = re.findall(r"(?m)^\s*listen\s+(?:\[::\]:)?(\d+)([^;]*);", text)
    values = {port(value) for value, _ in listeners}
    names = re.findall(r"(?m)^\s*server_name\s+([^;\s]+)\s*;", text)
    if len(values) != 1 or len(names) != 1 or names[0] == "localhost":
        raise ValueError("Unable to determine the installed panel address; configure the gateway with menu 26")
    scheme = "https" if any("ssl" in flags.split() for _, flags in listeners) else "http"
    return scheme + "://" + domain(names[0]) + ":" + str(values.pop()) + "/"


def entry_url(state):
    state = Path(state)
    config = json.loads(state.read_text())
    render(config)  # Validate stored domain, ports and panel path before displaying them.
    base = "https://" + config["panel_domain"] + ":" + str(config["panel_port"]) + config["panel_path"]
    if not config.get("entry_key_enabled"):
        return base
    key = (state.parent / "entry.key").read_text().strip()
    if not key or any(char.isspace() for char in key):
        raise ValueError("Entry key is missing or invalid")
    return base + "_entry?" + urlencode({"key": key})


def credential_lines(config_directory):
    password_file = Path(config_directory) / "initial-admin-password.txt"
    if not password_file.exists():
        return ["已有安装：管理员账号和密码保持原设置，不会自动重置。",
                "忘记密码时可使用菜单 22 重置管理员密码。"]
    info = password_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("Initial password file must be a private regular file")
    password = password_file.read_text().strip()
    if len(password) != 16 or not password.isascii() or not password.isalnum():
        raise ValueError("Invalid initial administrator password")
    return ["初始管理员账号：sysadmin", "初始登录密码：" + password,
            "首次登录使用以上密码；如果已经修改过账号或密码，请使用修改后的信息。",
            "请妥善保存，勿公开分享。"]


def wait_for_backend(port):
    if not 1 <= port <= 65535:
        raise ValueError("Invalid backend port")
    opener = build_opener(ProxyHandler({}))
    for _ in range(20):
        try:
            with opener.open("http://127.0.0.1:" + str(port) + "/api/auth/health", timeout=1) as response:
                if response.status == 204:
                    return
        except OSError:
            pass
        time.sleep(1)
    raise ValueError("Backend is not ready; no successful installation credentials were reported")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default="/tpdata/trojan-panel/config/gateway.json")
    parser.add_argument("--credentials-only", action="store_true")
    parser.add_argument("--legacy-config", help="Read the installed root panel address from its Nginx configuration")
    parser.add_argument("--existing", action="store_true", help="Do not display initial credentials during upgrades")
    parser.add_argument("--wait-backend-port", type=int)
    args = parser.parse_args()
    try:
        if args.wait_backend_port is not None:
            wait_for_backend(args.wait_backend_port)
        url = None if args.credentials_only else (legacy_entry_url(args.legacy_config) if args.legacy_config else entry_url(args.state))
        credentials = (["已有安装：管理员账号和密码保持原设置，不会自动重置。"] if args.existing
                       else credential_lines(Path(args.state).parent))
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, "Unable to read the complete panel entry: " + str(error) + "\n")
    if url:
        print_panel_entry(url)
    print("\n".join(credentials))


if __name__ == "__main__":
    main()
