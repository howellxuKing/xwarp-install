#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# A failed public download must stop without installing or silently succeeding.
curl() { return 23; }
export -f curl
if env -u XWARP_TEST_MODE bash install_script.sh </dev/null > /dev/null 2>&1; then
  echo "Installer ignored the failed bootstrap download" >&2
  exit 1
fi
curl() { printf '%s\n' "echo PUBLIC_BOOTSTRAP_WRAPPER_OK"; }
export -f curl
wrapper_output=$(bash -c 'source ./install_script.sh; echo CALLER_STILL_RUNNING')
grep -q PUBLIC_BOOTSTRAP_WRAPPER_OK <<< "$wrapper_output"
grep -q CALLER_STILL_RUNNING <<< "$wrapper_output"
wrapper_output=$(bash ./install_script.sh)
grep -q PUBLIC_BOOTSTRAP_WRAPPER_OK <<< "$wrapper_output"
unset -f curl

export XWARP_TEST_MODE=1 XWARP_SOURCE_ONLY=1
source ./install_script.sh
init_var
export CALL_LOG
CALL_LOG=$(mktemp)
trap 'rm -f "$CALL_LOG"' EXIT

docker() {
  printf '%s\n' "$*" >> "$CALL_LOG"
  case "$*" in
    'ps -a '*) return 0 ;;
    'ps -q '*) echo mock-running-container ;;
  esac
}

# Exercise actual installation commands without containers or network access.
install_mariadb <<< $'\n\ntest-password' > /dev/null
install_redis <<< $'\ntest-password' > /dev/null
grep -q -- '--bind-address=127.0.0.1' "$CALL_LOG"
grep -q -- 'redis-server --bind 127.0.0.1 --protected-mode yes' "$CALL_LOG"

# Remote deployments remain an explicit opt-in for newly created services.
XWARP_MARIADB_BIND=10.0.0.10 XWARP_REDIS_BIND=10.0.0.10 init_var
: > "$CALL_LOG"
install_mariadb <<< $'\n\ntest-password' > /dev/null
install_redis <<< $'\ntest-password' > /dev/null
grep -q -- '--bind-address=10.0.0.10' "$CALL_LOG"
grep -q -- 'redis-server --bind 10.0.0.10 --protected-mode yes' "$CALL_LOG"

# Existing services must not be recreated or silently have their bindings changed.
docker() {
  printf '%s\n' "$*" >> "$CALL_LOG"
  case "$*" in 'ps -a '*) echo existing-container ;; esac
}
: > "$CALL_LOG"
install_mariadb > /dev/null
install_redis > /dev/null
if grep -q -- '^run\|^pull' "$CALL_LOG"; then
  echo "Existing containers were modified" >&2
  exit 1
fi
echo "Installer security checks passed (mock Docker; no deployment)"

[[ "$(normalize_menu_choice $' ２\r')" == 2 ]]
read_menu_choice fixture_choice "" 0 32 <<< $'bad\n９'
[[ "$fixture_choice" == 9 ]]
: > "$CALL_LOG"
forget_pass > /dev/null
grep -q -- 'exec trojan-panel ./trojan-panel -resetAdminPassword' "$CALL_LOG"
! grep -q -- '123456\|update account' "$CALL_LOG"

! grep -q -- 'ufw disable\|systemctl disable firewalld' install_script.sh

! grep -q -- "kill -9" install_script.sh

# Backup/upgrade workers must belong to systemd, rather than the SSH session.
stage_security_runtime() { :; }
systemd-run() { printf '%s\n' "$*" >> "$CALL_LOG"; return 0; }
export XWARP_MAINTENANCE_LOG_DIR="$(mktemp -d)"
trap 'rm -f "$CALL_LOG"; rm -rf -- "$XWARP_MAINTENANCE_LOG_DIR"' EXIT
: > "$CALL_LOG"
security_tool snapshot.py backup --quiesce > /dev/null
security_tool upgrade.py --backend-image fixture --apply > /dev/null
grep -q -- '--wait --collect --service-type=exec --unit=xwarp-maintenance-' "$CALL_LOG"
grep -q -- '--property=StandardOutput=append:' "$CALL_LOG"
grep -q -- 'flock --nonblock /run/xwarp-maintenance.lock' "$CALL_LOG"
grep -q -- '/opt/xwarp-install/tools/snapshot.py backup --quiesce' "$CALL_LOG"
grep -q -- '/opt/xwarp-install/tools/upgrade.py --backend-image fixture --apply' "$CALL_LOG"

# Run the actual menu 26 flow: choosing a simple entry must select a high port automatically.
docker() {
  printf '%s\n' "$*" >> "$CALL_LOG"
  [[ "$1" != inspect ]] || printf '/etc/nginx/conf.d\n'
  return 0
}
security_tool() {
  printf '%s\n' "$*" >> "$CALL_LOG"
  [[ "$1" != snapshot.py ]] || printf '/fixture/backup.tar.gz\n'
  return 0
}
show_panel_access() { :; }
: > "$CALL_LOG"
secure_gateway <<< $'panel.example\n/cert/test.crt\n/cert/test.key\n\n\n1\n0'
grep '^gateway.py ' "$CALL_LOG" | grep -q -- '--random-port'
grep '^gateway.py ' "$CALL_LOG" | grep -q -- '--simple-panel'
! grep '^gateway.py ' "$CALL_LOG" | grep -q -- '--panel-port'
: > "$CALL_LOG"
secure_gateway <<< $'panel.example\n/cert/test.crt\n/cert/test.key\n55555\n\n1\n0'
grep '^gateway.py ' "$CALL_LOG" | grep -q -- '--panel-port 55555'
! grep '^gateway.py ' "$CALL_LOG" | grep -q -- '--random-port'
: > "$CALL_LOG"
secure_gateway <<< $'panel.example\n/cert/test.crt\n/cert/test.key\n\n\n\n0'
! grep '^gateway.py ' "$CALL_LOG" | grep -q -- '--random-port'
echo 'Menu 26 passed: automatic random high port for explicit simple mode, manual override, unchanged default preservation'
