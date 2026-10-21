#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'CI only' >&2; exit 1; }
cd "$(dirname "$0")/.."
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
mkdir "$fixture/source"
cp -a bootstrap.sh install_script.sh tools systemd "$fixture/source/"
cat >> "$fixture/source/install_script.sh" <<'MOCK'
check_sys() { :; }
depend_install() { :; }
install_docker() { :; }
main() { echo 'BOOTSTRAP_MENU_READY'; }
MOCK
python3 - "$fixture/source/release.json" <<'PY'
import json,sys
images={"backend":"ghcr.io/howellxuking/xwarp", "ui":"ghcr.io/howellxuking/xwarp-ui", "core":"jonssonyan/trojan-panel-core"}
open(sys.argv[1],"w").write(json.dumps(dict(format=1,platform="linux/amd64",images={k:v+"@sha256:"+"a"*64 for k,v in images.items()})))
PY
tar -czf "$fixture/source.tar.gz" --transform='s,^,checkout/,' -C "$fixture/source" .
export BOOTSTRAP_FIXTURE="$fixture"
curl() {
  local destination='' url='' value
  while (( $# )); do
    case "$1" in -o) destination="$2"; shift 2;; https://*) url="$1"; shift;; *) shift;; esac
  done
  case "$url" in
    */commits/main) printf '{"sha":"%040d"}' 1 > "$destination";;
    */tarball/*) cp "$BOOTSTRAP_FIXTURE/source.tar.gz" "$destination";;
    *) return 42;;
  esac
}
docker() {
  case "$1" in
    ps) return 0;;
    login) echo 'Public installation must not request a registry login' >&2; return 42;;
    pull) [[ "$2" == *@sha256:* ]];;
    *) return 42;;
  esac
}
export -f curl docker
# The real public bootstrap uses a fixture tarball without any token or registry login.
output="$(env -u XWARP_GITHUB_TOKEN bash bootstrap.sh <<< $'1\n0')"
grep -q 'BOOTSTRAP_MENU_READY' <<< "$output"
! grep -q ci_bootstrap_token <<< "$output"
echo 'Public bootstrap passed: complete checkout, fixed manifest, anonymous image pulls, interactive menu'
