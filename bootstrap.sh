#!/usr/bin/env bash
# Public entry: no GitHub account, access token or registry login is required.
set -euo pipefail
set +x
umask 077
[[ "$(id -u)" == 0 ]] || { echo "请在服务器 root 终端运行。" >&2; exit 1; }
[[ "$(uname -m)" == x86_64 ]] || { echo "当前公开镜像支持 x86_64 服务器。" >&2; exit 1; }
[[ -r /etc/os-release ]] || exit 1
. /etc/os-release
[[ "${ID:-}" == debian || "${ID:-}" == ubuntu ]] || { echo "此入口支持 Debian/Ubuntu。" >&2; exit 1; }
command -v curl >/dev/null || { apt-get update; apt-get install -y curl ca-certificates; }
command -v python3 >/dev/null || { apt-get update; apt-get install -y python3; }
task_staging="$(mktemp -d)"
cleanup() { rm -rf -- "$task_staging"; }
trap cleanup EXIT
download() {
  curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 --proto '=https' --proto-redir '=https' "$1" -o "$2"
}
# Resolve main once. Every installer file and the image manifest use that revision.
download 'https://api.github.com/repos/howellxuKing/xwarp-install/commits/main' "$task_staging/commit.json"
task_ref="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha"])' "$task_staging/commit.json")"
[[ "$task_ref" =~ ^[a-f0-9]{40}$ ]] || { echo "无法读取安装版本，请稍后重试。" >&2; exit 1; }
download "https://api.github.com/repos/howellxuKing/xwarp-install/tarball/$task_ref" "$task_staging/installer.tar.gz"
mkdir "$task_staging/source"
tar -xzf "$task_staging/installer.tar.gz" --strip-components=1 -C "$task_staging/source"
python3 "$task_staging/source/tools/release.py" "$task_staging/source/release.json" > "$task_staging/images.env"
source "$task_staging/images.env"
export XWARP_BACKEND_IMAGE XWARP_UI_IMAGE XWARP_CORE_IMAGE
export XWARP_SOURCE_ONLY=1
source "$task_staging/source/install_script.sh"
if [[ -d /tpdata ]]; then
  echo "检测到已有 /tpdata。输入 1：先备份再进入维护/升级菜单；输入 0：退出。"
  read_menu_choice bootstrap_choice "请选择: " 0 1 || exit 1
  [[ "$bootstrap_choice" == 1 ]] || exit 0
  command -v docker >/dev/null || { echo "现有安装未找到 Docker，未修改数据。" >&2; exit 1; }
  if [[ -n "$(docker ps -aq -f 'name=^trojan-panel-mariadb$')" ]]; then
    echo "备份期间节点会短暂停止；后台任务会继续并恢复服务，SSH 断开后请稍后重连。"
    security_tool snapshot.py backup --quiesce
  elif [[ -n "$(docker ps -aq -f 'name=^trojan-panel$')" ]]; then
    echo "现有后端没有本机数据库，无法自动做一致性备份；未继续升级。" >&2; exit 1
  else
    install -d -m 700 /root/xwarp-backups
    task_partial="/root/xwarp-backups/partial-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar.gz"
    tar -czf "$task_partial" -C / tpdata
    echo "已备份尚未完成的安装：$task_partial"
  fi
fi
# Do not depend on, or alter, an existing Docker registry login.
export DOCKER_CONFIG="$task_staging/docker-anonymous"
mkdir "$DOCKER_CONFIG"
init_var
check_sys
depend_install
install_docker
docker pull "$XWARP_BACKEND_IMAGE" >/dev/null
docker pull "$XWARP_UI_IMAGE" >/dev/null
if [[ -L /opt/xwarp-install || ( -e /opt/xwarp-install && ! -d /opt/xwarp-install ) ]]; then
  echo "/opt/xwarp-install 不是目录；未覆盖。" >&2; exit 1
fi
mkdir -p /opt/xwarp-install
cp -a "$task_staging/source/." /opt/xwarp-install/
XWARP_INSTALL_DIR=/opt/xwarp-install
export XWARP_INSTALL_DIR
echo "公开版已准备好，无需 GitHub Token。"
echo "新安装按 2 后端、3 核心、1 前端的顺序选择；已有安装选择 8/9 升级。"
echo "HTTPS 独立订阅与简洁入口使用菜单 26；面板端口留空、入口选 1 自动生成高位随机端口。"
while :; do
  main
  read_menu_choice bootstrap_continue "继续配置其他组件？1=继续，0=退出: " 0 1 || break
  [[ "$bootstrap_continue" == 1 ]] || break
done
