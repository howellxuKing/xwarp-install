#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export XWARP_TEST_MODE=1 XWARP_SOURCE_ONLY=1
source ./install_script.sh
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir "$fixture/nginx" "$fixture/cert"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$fixture/cert/test.example.key" -out "$fixture/cert/test.example.crt" -days 1 -subj /CN=test.example >/dev/null 2>&1
UI_NGINX_CONFIG="$fixture/nginx/ui.conf"
NGINX_CONFIG="$fixture/nginx/web.conf"
CERT_PATH=/cert/
domain=test.example
trojan_panel_ui_port=18888
trojan_panel_ip=127.0.0.1
trojan_panel_server_port=8081
TROJAN_PANEL_UI_DATA=/tpdata/trojan-panel-ui/
nginx_port=18880
nginx_remote_port=18863
WEB_PATH=/tpdata/web/
ui_https_config
nginx_https_config test.example
! grep -q 'ssl on;' "$fixture/nginx/"*.conf
docker run --rm --network none -v "$fixture/nginx:/etc/nginx/conf.d:ro" -v "$fixture/cert:/cert:ro" nginx:1.30.5-alpine nginx -t
echo 'Fresh panel and website HTTPS templates pass current Nginx validation'
