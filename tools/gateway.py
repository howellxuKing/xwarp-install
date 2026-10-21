#!/usr/bin/env python3
"""Generate a private HTTPS panel gateway and a separately accessible subscription vhost."""
import argparse
import json
import os
import re
import secrets
from pathlib import Path
from ports import choose_port


def domain(value):
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", value):
        raise ValueError("Invalid domain")
    return value


def port(value):
    value = int(value)
    if not 1 <= value <= 65535:
        raise ValueError("Invalid port")
    return value


def safe_path(value):
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(value)) or ".." in Path(value).parts:
        raise ValueError("Invalid absolute configuration path")
    return str(value)


def render(config):
    prefix = config["panel_path"]
    simple = prefix == "/" and not config.get("entry_key_enabled")
    if not simple and not re.fullmatch(r"/[A-Za-z0-9_-]{16,64}/", prefix):
        raise ValueError("Panel path must contain at least 16 random characters")
    panel_domain = domain(config["panel_domain"])
    subscription_domain = domain(config["subscription_domain"])
    panel_port, sub_port = port(config["panel_port"]), port(config["subscription_port"])
    if panel_port == sub_port:
        raise ValueError("Panel and subscription must use separate ports")
    backend = "127.0.0.1:" + str(port(config.get("backend_port", 8081)))
    cert, key = safe_path(config["certificate"]), safe_path(config["private_key"])
    sub_cert = safe_path(config.get("subscription_certificate", cert))
    sub_key = safe_path(config.get("subscription_private_key", key))
    common = 'access_log off;\n    error_log /dev/null crit;\n    server_tokens off;\n    add_header Referrer-Policy "no-referrer" always;\n    add_header X-Content-Type-Options "nosniff" always;'
    tls = f"ssl_certificate {cert};\n    ssl_certificate_key {key};\n    ssl_protocols TLSv1.2 TLSv1.3;"
    auth = "auth_request /_entry_check;" if config.get("entry_key_enabled") else ""
    proxy = f"proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $remote_addr;\n        proxy_set_header Host $host;\n        proxy_pass http://{backend}"
    knock = ""
    if config.get("knock_enabled"):
        knock = '''location = /_knock {
        proxy_set_header X-Real-IP $remote_addr;
        proxy_pass http://127.0.0.1:8099;
    }'''
    entry = "" if simple else f'''error_page 401 403 =404 /_hidden;
    location = /_hidden {{ internal; return 404; }}
    location = /_entry_check {{
        internal;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Cookie $http_cookie;
        proxy_pass http://{backend}/api/auth/entry/verify;
    }}
    location = {prefix}_entry {{
        {proxy}/api/auth/entry/open;
    }}'''
    camouflage = "" if simple else "location / { root /tpdata/web; index index.html; try_files $uri $uri/ =404; }"
    return f'''# Generated private gateway. Subscription never inherits the panel gate.
server {{
    listen {panel_port} ssl;
    listen [::]:{panel_port} ssl;
    server_name {panel_domain};
    {common}
    {tls}
    {entry}
    location ^~ {prefix}api/auth/subscribe/ {{ return 404; }}
    location ^~ {prefix}api/ {{
        {auth}
        {proxy}/api/;
        proxy_redirect /api/ {prefix}api/;
    }}
    location ^~ {prefix} {{
        {auth}
        alias /tpdata/trojan-panel-ui/;
        index index.html;
        sub_filter_once on;
        sub_filter '<head>' '<head><script>window.__XWARP_BASE__="{prefix}";</script>';
    }}
    {camouflage}
}}
server {{
    listen {sub_port} ssl;
    listen [::]:{sub_port} ssl;
    server_name {subscription_domain};
    {common}
    ssl_certificate {sub_cert};
    ssl_certificate_key {sub_key};
    ssl_protocols TLSv1.2 TLSv1.3;
    location ^~ /api/auth/subscribe/ {{
        {proxy};
    }}
    {knock}
    location ^~ /api/ {{ return 404; }}
    location / {{ root /tpdata/web; index index.html; try_files $uri $uri/ =404; }}
}}
'''


def write_private(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing symbolic link destination")
    temp = path.with_name(path.name + ".new")
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--panel-domain", required=True)
    parser.add_argument("--subscription-domain")
    parser.add_argument("--panel-port", type=int)
    parser.add_argument("--random-port", action="store_true")
    parser.add_argument("--subscription-port", type=int, default=443)
    parser.add_argument("--backend-port", type=int, default=8081)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--subscription-certificate")
    parser.add_argument("--subscription-private-key")
    parser.add_argument("--state", default="/tpdata/trojan-panel/config/gateway.json")
    parser.add_argument("--output", default="/tpdata/trojan-panel-ui/nginx/default.conf")
    parser.add_argument("--entry-key", action="store_true")
    parser.add_argument("--simple-panel", action="store_true", help="Use the panel root without an entry key")
    parser.add_argument("--knock", action="store_true")
    args = parser.parse_args()
    state = Path(args.state)
    old = json.loads(state.read_text()) if state.exists() else {}
    if args.simple_panel and args.entry_key:
        parser.error("Simple panel cannot require an entry key")
    sub_domain = args.subscription_domain or args.panel_domain
    if sub_domain != args.panel_domain and not (args.subscription_certificate and args.subscription_private_key):
        parser.error("A separate subscription domain requires its matching certificate and private key")
    panel_path = old.get("panel_path")
    if args.simple_panel:
        panel_path = "/"
    elif not panel_path or (args.entry_key and panel_path == "/"):
        panel_path = "/p-" + secrets.token_hex(16) + "/"
    panel_port = args.panel_port if args.panel_port is not None else old.get("panel_port")
    if args.random_port or panel_port is None:
        panel_port = choose_port(exclude=[args.subscription_port])
    config = {
        "panel_domain": args.panel_domain, "subscription_domain": sub_domain,
        "panel_path": panel_path,
        "panel_port": panel_port,
        "subscription_port": args.subscription_port, "backend_port": args.backend_port,
        "certificate": args.certificate, "private_key": args.private_key,
        "subscription_certificate": args.subscription_certificate or args.certificate,
        "subscription_private_key": args.subscription_private_key or args.private_key,
        "entry_key_enabled": False if args.simple_panel else (args.entry_key or old.get("entry_key_enabled", False)), "knock_enabled": args.knock,
        "subscription_base": "https://" + sub_domain + (":" + str(args.subscription_port) if args.subscription_port != 443 else ""),
    }
    rendered = render(config)
    from certificates import matched_pair
    matched_pair(config["certificate"], config["private_key"], config["panel_domain"])
    matched_pair(config["subscription_certificate"], config["subscription_private_key"], config["subscription_domain"])
    key_path = state.parent / "entry.key"
    if args.entry_key and not key_path.exists():
        write_private(key_path, secrets.token_urlsafe(36) + "\n")
    # Generating a configuration does not restart any service or modify firewall rules.
    write_private(args.output, rendered)
    write_private(state, json.dumps(config, indent=2) + "\n")
    print("Private gateway files generated. Validate nginx configuration before reloading.")
    print("The installer will display the complete panel entry after nginx validation and reload.")


if __name__ == "__main__":
    main()
