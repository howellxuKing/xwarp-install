#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Keep the original one-command entry compatible, including source <(curl ...).
if [[ "${XWARP_SOURCE_ONLY:-0}" != "1" ]]; then
  if public_bootstrap=$(curl -fsSL --retry 3 https://raw.githubusercontent.com/howellxuKing/xwarp-install/main/bootstrap.sh) && [[ -n "$public_bootstrap" ]]; then
    bash -c "$public_bootstrap"
    public_result=$?
  else
    echo "无法下载安装入口，请检查服务器网络后重试。" >&2
    public_result=1
  fi
  return "$public_result" 2>/dev/null || exit "$public_result"
fi

# Release tools: Debian/Ubuntu x86_64, Python 3, Docker, systemd
# Version: v2.5.0
# Description: One click Install XWarp server
# Author: jonssonyan <https://jonssonyan.com>
# Github: https://github.com/trojanpanel/install-script


XWARP_INSTALL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
normalize_menu_choice() {
  local choice="$1"
  choice="${choice//$'\r'/}"
  choice="${choice//０/0}"; choice="${choice//１/1}"; choice="${choice//２/2}"
  choice="${choice//３/3}"; choice="${choice//４/4}"; choice="${choice//５/5}"
  choice="${choice//６/6}"; choice="${choice//７/7}"; choice="${choice//８/8}"; choice="${choice//９/9}"
  choice="${choice//[[:space:]]/}"
  printf '%s' "$choice"
}
read_menu_choice() {
  local target="$1" prompt="$2" minimum="$3" maximum="$4" choice
  while read -r -p "$prompt" choice; do
    choice="$(normalize_menu_choice "$choice")"
    if [[ "$choice" =~ ^[0-9]{1,2}$ ]] && (( 10#$choice >= minimum && 10#$choice <= maximum )); then
      printf -v "$target" '%s' "$((10#$choice))"
      return 0
    fi
    echo "Invalid selection; enter a number between $minimum and $maximum." >&2
  done
  return 1
}
security_tool() {
  [[ -f "$XWARP_INSTALL_DIR/tools/$1" ]] || { echo "Clone the complete private installer repository first." >&2; return 1; }
  local tool="$1"; shift
  case "$tool" in
    panel_port.py)
      flock --nonblock /run/xwarp-maintenance.lock python3 "$XWARP_INSTALL_DIR/tools/$tool" "$@"
      return $?
      ;;
    snapshot.py|upgrade.py)
      # A client can reach SSH through the very core that this task stops.
      # systemd owns the worker so a disconnected terminal cannot kill recovery.
      command -v systemd-run >/dev/null && command -v flock >/dev/null || { echo "Persistent maintenance requires systemd-run and flock; no services were stopped." >&2; return 1; }
      stage_security_runtime || return 1
      local task_unit="xwarp-maintenance-$(date -u +%Y%m%dT%H%M%S)-$$-$RANDOM"
      local task_log_dir="${XWARP_MAINTENANCE_LOG_DIR:-/root/xwarp-maintenance}"
      install -d -m 700 "$task_log_dir" || return 1
      local task_log="$task_log_dir/$task_unit.log" task_result=0
      (umask 077; : > "$task_log") || return 1
      local -a task_env=()
      [[ -z "${DOCKER_CONFIG:-}" ]] || task_env+=("--setenv=DOCKER_CONFIG=$DOCKER_CONFIG")
      echo "Maintenance task: $task_unit. It continues if SSH disconnects; log: $task_log" >&2
      systemd-run --quiet --wait --collect --service-type=exec --unit="$task_unit" "${task_env[@]}" \
        "--property=StandardOutput=append:$task_log" "--property=StandardError=append:$task_log" \
        flock --nonblock /run/xwarp-maintenance.lock python3 "/opt/xwarp-install/tools/$tool" "$@" </dev/null || task_result=$?
      if (( task_result == 0 )); then cat "$task_log"; else cat "$task_log" >&2; fi
      return "$task_result"
      ;;
  esac
  python3 "$XWARP_INSTALL_DIR/tools/$tool" "$@"
}
pull_immutable_image() {
  docker pull "$1" || return 1
  XWARP_PINNED_IMAGE="$(docker image inspect "$1" --format '{{index .RepoDigests 0}}')" || return 1
  [[ "$XWARP_PINNED_IMAGE" =~ ^[a-z0-9./_:-]+@sha256:[a-f0-9]{64}$ ]] || { echo "Image has no registry digest; refusing a mutable container reference." >&2; return 1; }
}
stage_security_runtime() {
  [[ -d "$XWARP_INSTALL_DIR/tools" && -d "$XWARP_INSTALL_DIR/systemd" ]] || { echo "Use a complete private repository checkout." >&2; return 1; }
  if [[ "$XWARP_INSTALL_DIR" != /opt/xwarp-install ]]; then
    install -d -m 755 /opt/xwarp-install/tools /opt/xwarp-install/systemd
    cp "$XWARP_INSTALL_DIR"/tools/*.py /opt/xwarp-install/tools/
    cp "$XWARP_INSTALL_DIR"/systemd/* /opt/xwarp-install/systemd/
  fi
}
protect_new_core() {
  local -a args=(--apply --ports "$trojan_panel_core_port,$grpc_port")
  [[ -n "${XWARP_CORE_ALLOW:-}" ]] && args+=(--allow "$XWARP_CORE_ALLOW")
  stage_security_runtime || return 1
  security_tool firewall.py "${args[@]}" || return 1
  umask 077
  printf 'XWARP_CORE_FIREWALL_ARGS=--ports %s%s\n' "$trojan_panel_core_port,$grpc_port" "${XWARP_CORE_ALLOW:+ --allow $XWARP_CORE_ALLOW}" > /etc/xwarp-core-firewall.env
  cp "$XWARP_INSTALL_DIR/systemd/xwarp-core-firewall.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable xwarp-core-firewall.service
}

show_panel_access() {
  if [[ -f /tpdata/trojan-panel/config/gateway.json ]]; then
    # Print only to the installer's terminal, never to a maintenance worker log.
    security_tool panel_access.py "$@"
  elif [[ -f "${UI_NGINX_CONFIG:-/nonexistent}" ]] && grep -Eq '^\s*server_name\s+[^; ]+;' "${UI_NGINX_CONFIG}" && ! grep -Eq '^\s*server_name\s+localhost;' "${UI_NGINX_CONFIG}"; then
    security_tool panel_access.py --legacy-config "${UI_NGINX_CONFIG}" "$@"
  elif [[ -n "${https_flag:-}" && -n "${domain_or_ip:-}" && -n "${trojan_panel_ui_port:-}" ]]; then
    echo_content yellow "Web management panel address: ${https_flag}://${domain_or_ip}:${trojan_panel_ui_port}"
    security_tool panel_access.py --credentials-only "$@"
  fi
}
reviewed_upgrade() {
  local kind="$1" digest
  case "$kind" in
    backend) digest="${XWARP_BACKEND_IMAGE:-}" ;;
    ui) digest="${XWARP_UI_IMAGE:-}" ;;
    core) digest="${XWARP_CORE_IMAGE:-}" ;;
  esac
  if [[ -z "$digest" ]]; then
    read -r -p "Reviewed $kind image repository@sha256 digest: " digest || return 1
  fi
  security_tool upgrade.py "--${kind}-image" "$digest" --apply || return 1
  [[ "$kind" != ui ]] || show_panel_access --existing
}
secure_gateway() {
  local panel_domain panel_port subscription_port certificate private_key entry_mode knock_enabled
  read -r -p "Panel/subscription domain: " panel_domain
  read -r -p "Certificate absolute path: " certificate
  read -r -p "Private key absolute path: " private_key
  read -r -p "Panel HTTPS port (blank: mode 1 auto-random 49152-65535; otherwise keep installed port): " panel_port
  read -r -p "Subscription HTTPS port (default 443): " subscription_port
  read -r -p "Panel entry: 1=simple domain:port, 2=random path + key (blank: keep existing, new install uses 1): " entry_mode || return 1
  [[ -z "$entry_mode" || "$entry_mode" == 1 || "$entry_mode" == 2 ]] || { echo "Invalid entry mode." >&2; return 1; }
  read_menu_choice knock_enabled "Generate optional IP gate endpoint? 0=no 1=yes: " 0 1 || return 1
  local -a args=(--panel-domain "$panel_domain" --certificate "$certificate" --private-key "$private_key" --subscription-port "${subscription_port:-443}")
  if [[ -z "$panel_port" && "$entry_mode" == 1 ]]; then
    args+=(--random-port)
  elif [[ -z "$panel_port" && ! -f /tpdata/trojan-panel/config/gateway.json && -f "${UI_NGINX_CONFIG}" ]]; then
    panel_port=$(python3 -c 'import re,sys; s=open(sys.argv[1]).read(); p=set(re.findall(r"(?m)^\s*listen\s+(?:\[::\]:)?(\d+)",s)); print(p.pop() if len(p)==1 else "")' "${UI_NGINX_CONFIG}") || return 1
  fi
  [[ -z "$panel_port" ]] || args+=(--panel-port "$panel_port")
  if [[ "$entry_mode" == 1 || ( -z "$entry_mode" && ! -f /tpdata/trojan-panel/config/gateway.json ) ]]; then
    args+=(--simple-panel)
  elif [[ "$entry_mode" == 2 ]]; then
    args+=(--entry-key)
  fi
  [[ "$knock_enabled" == 1 ]] && args+=(--knock)
  docker inspect trojan-panel-ui --format '{{range .Mounts}}{{println .Destination}}{{end}}' | grep -qx '/etc/nginx/conf.d' || { echo "Upgrade the UI container to a directory mount before configuring the gateway." >&2; return 1; }
  local gateway_snapshot
  gateway_snapshot="$(security_tool snapshot.py backup --quiesce)" || return 1
  security_tool gateway.py "${args[@]}" || { security_tool snapshot.py restore "$gateway_snapshot" --confirm "$(basename "$gateway_snapshot")"; return 1; }
  if ! docker exec trojan-panel-ui nginx -t; then
    echo "Generated configuration failed validation; restoring the pre-change snapshot." >&2
    security_tool snapshot.py restore "$gateway_snapshot" --confirm "$(basename "$gateway_snapshot")"
    return 1
  fi
  docker exec trojan-panel-ui nginx -s reload || return 1
  show_panel_access
}
install_security_units() {
  [[ -d "$XWARP_INSTALL_DIR/systemd" ]] || return 1
  [[ "$XWARP_INSTALL_DIR" == /opt/xwarp-install ]] || { echo "Place the complete checkout in /opt/xwarp-install first." >&2; return 1; }
  case "$1" in
    timers) cp "$XWARP_INSTALL_DIR"/systemd/xwarp-health.* "$XWARP_INSTALL_DIR"/systemd/xwarp-certificates.* /etc/systemd/system/
            systemctl daemon-reload; systemctl enable --now xwarp-health.timer xwarp-certificates.timer ;;
    knock) [[ -f /etc/systemd/system/xwarp-core-firewall.service ]] || { echo "Configure persistent management policy with menu 29 first." >&2; return 1; }
           systemctl enable xwarp-core-firewall.service
           cp "$XWARP_INSTALL_DIR/systemd/xwarp-knock.service" /etc/systemd/system/
           systemctl daemon-reload; systemctl enable --now xwarp-knock.service ;;
  esac
}

init_var() {
  ECHO_TYPE="echo -e"

  package_manager=""
  release=""
  get_arch=""
  can_google=0

  # Docker
  DOCKER_MIRROR='"https://hub-mirror.c.163.com","https://ccr.ccs.tencentyun.com","https://mirror.baidubce.com","https://dockerproxy.com"'

  # Project directory
  TP_DATA="/tpdata/"

  STATIC_HTML="https://github.com/trojanpanel/install-script/releases/download/v1.0/html.tar.gz"

  # Web
  WEB_PATH="/tpdata/web/"

  # Cert
  CERT_PATH="/tpdata/cert/"
  DOMAIN_FILE="/tpdata/domain.lock"
  domain=""
  crt_path=""
  key_path=""

  # Caddy2
  CADDY_DATA="/tpdata/caddy/"
  CADDY_CONFIG="${CADDY_DATA}config.json"
  CADDY_LOG="${CADDY_DATA}logs/"
  CADDY_CERT_DIR="${CERT_PATH}certificates/acme-v02.api.letsencrypt.org-directory/"
  caddy_port=80
  caddy_remote_port=8863
  your_email=""
  ssl_option=1
  ssl_module_type=1
  ssl_module="acme"

  # Nginx
  NGINX_DATA="/tpdata/nginx/"
  NGINX_CONFIG="${NGINX_DATA}default.conf"
  nginx_port=80
  nginx_remote_port=8863
  nginx_https=1

  # MariaDB
  MARIA_DATA="/tpdata/mariadb/"
  mariadb_ip="127.0.0.1"
  mariadb_bind="${XWARP_MARIADB_BIND:-127.0.0.1}"
  mariadb_port=9507
  mariadb_user="root"
  mariadb_pas=""

  # Redis
  REDIS_DATA="/tpdata/redis/"
  redis_host="127.0.0.1"
  redis_bind="${XWARP_REDIS_BIND:-127.0.0.1}"
  redis_port=6378
  redis_pass=""

  # XWarp Frontend
  TROJAN_PANEL_UI_DATA="/tpdata/trojan-panel-ui/"
  # Nginx
  UI_NGINX_DATA="${TROJAN_PANEL_UI_DATA}nginx/"
  UI_NGINX_CONFIG="${UI_NGINX_DATA}default.conf"
  trojan_panel_ui_port=""
  ui_https=1
  trojan_panel_ip="127.0.0.1"
  trojan_panel_server_port=8081

  # XWarp Backend
  TROJAN_PANEL_DATA="/tpdata/trojan-panel/"
  TROJAN_PANEL_WEBFILE="${TROJAN_PANEL_DATA}webfile/"
  TROJAN_PANEL_LOGS="${TROJAN_PANEL_DATA}logs/"
  TROJAN_PANEL_CONFIG="${TROJAN_PANEL_DATA}config/"
  trojan_panel_config_path="${TROJAN_PANEL_DATA}config/config.ini"
  trojan_panel_port=8081

  # XWarp Core
  TROJAN_PANEL_CORE_DATA="/tpdata/trojan-panel-core/"
  TROJAN_PANEL_CORE_LOGS="${TROJAN_PANEL_CORE_DATA}logs/"
  TROJAN_PANEL_CORE_CONFIG="${TROJAN_PANEL_CORE_DATA}config/"
  trojan_panel_core_config_path="${TROJAN_PANEL_CORE_DATA}config/config.ini"
  database="trojan_panel_db"
  account_table="account"
  grpc_port=8100
  trojan_panel_core_port=8082

  # Version
  trojan_panel_ui_current_version=""
  trojan_panel_ui_latest_version="v2.4.8"
  trojan_panel_current_version=""
  trojan_panel_latest_version="v2.4.3"
  trojan_panel_core_current_version=""
  trojan_panel_core_latest_version="v2.3.1"

  # SQL
  sql_215="alter table account change validity_period preset_expire int unsigned default 0 not null comment '预设过期时长';alter table account add preset_quota bigint default 0 not null comment '预设配额' after preset_expire;update account set preset_quota = quota where last_login_time = 0;update account set quota = 0 where last_login_time = 0;alter table node add priority int default 100 not null comment '优先级' after port;INSERT INTO casbin_rule (p_type, v0, v1, v2, v3, v4, v5) VALUES ('p', 'sysadmin', '/api/account/clashSubscribeForSb', 'GET', 'default', 'default', 'default');alter table node_hysteria add server_name varchar(64) default '' not null comment '用于验证服务端证书的 hostname' after down_mbps;alter table node_hysteria add insecure tinyint(1) default 0 not null comment '忽略一切证书错误' after server_name;alter table node_hysteria add fast_open tinyint(1) default 0 not null comment '启用 Fast Open (降低连接建立延迟)' after insecure;"
  sql_230="CREATE TABLE node_hysteria2 ( id bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键', obfs_password varchar(64) NOT NULL DEFAULT '' COMMENT '混淆密码', up_mbps int(10) NOT NULL DEFAULT '100' COMMENT '单客户端最大上传速度 单位:Mbps', down_mbps int(10) NOT NULL DEFAULT '100' COMMENT '单客户端最大下载速度 单位:Mbps', server_name varchar(64) NOT NULL DEFAULT '' COMMENT '用于验证服务端证书的 hostname', insecure tinyint(1) NOT NULL DEFAULT '0' COMMENT '忽略一切证书错误', create_time datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间', update_time datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间', PRIMARY KEY (id) ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Hysteria2节点';INSERT INTO node_type (id, name, create_time, update_time) VALUES (5, 'hysteria2', '2022-04-01 00:00:00', '2022-04-01 00:00:00');"
  sql_243="ALTER TABLE system MODIFY COLUMN template_config TEXT NOT NULL COMMENT '模板设置';"
}

echo_content() {
  case $1 in
  "red")
    ${ECHO_TYPE} "\033[31m$2\033[0m"
    ;;
  "green")
    ${ECHO_TYPE} "\033[32m$2\033[0m"
    ;;
  "yellow")
    ${ECHO_TYPE} "\033[33m$2\033[0m"
    ;;
  "blue")
    ${ECHO_TYPE} "\033[34m$2\033[0m"
    ;;
  "purple")
    ${ECHO_TYPE} "\033[35m$2\033[0m"
    ;;
  "skyBlue")
    ${ECHO_TYPE} "\033[36m$2\033[0m"
    ;;
  "white")
    ${ECHO_TYPE} "\033[37m$2\033[0m"
    ;;
  esac
}

mkdir_tools() {
  # Project directory
  mkdir -p ${TP_DATA}

  # Web
  mkdir -p ${WEB_PATH}

  # Cert
  mkdir -p ${CERT_PATH}
  touch ${DOMAIN_FILE}

  # Caddy2
  mkdir -p ${CADDY_DATA}
  touch ${CADDY_CONFIG}
  mkdir -p ${CADDY_LOG}

  # Nginx
  mkdir -p ${NGINX_DATA}
  touch ${NGINX_CONFIG}

  # MariaDB
  mkdir -p ${MARIA_DATA}

  # Redis
  mkdir -p ${REDIS_DATA}

  # XWarp Frontend
  mkdir -p ${TROJAN_PANEL_UI_DATA}
  # Nginx
  mkdir -p ${UI_NGINX_DATA}
  touch ${UI_NGINX_CONFIG}

  # XWarp Backend
  mkdir -p ${TROJAN_PANEL_DATA}
  mkdir -p ${TROJAN_PANEL_LOGS}

  # XWarp Core
  mkdir -p ${TROJAN_PANEL_CORE_DATA}
  mkdir -p ${TROJAN_PANEL_CORE_LOGS}
}

can_connect() {
  ping -c2 -i0.3 -W1 "$1" &>/dev/null
  if [[ "$?" == "0" ]]; then
    return 0
  else
    return 1
  fi
}

# query .ini configuration file information
get_ini_value() {
  local config_file="$1"
  local key="$2"
  local section=""
  local section_flag=0

  # split group and key names
  IFS='.' read -r group_name key_name <<<"$key"

  while IFS='=' read -r name val; do
    # processing section name
    if [[ $name =~ ^\[(.*)\]$ ]]; then
      section="${BASH_REMATCH[1]}"
      if [[ $section == $group_name ]]; then
        section_flag=1
      else
        section_flag=0
      fi
      continue
    fi

    # extract the value of the configuration item
    if [[ $section_flag -eq 1 && $name == $key_name ]]; then
      echo "$val"
      return
    fi
  done <"$config_file"
}

# Version number comparison greater than or equal to
version_ge() {
  local v1=${1#v}
  local v2=${2#v}

  local v1_parts=(${v1//./ })
  local v2_parts=(${v2//./ })

  for ((i = 0; i < 3; i++)); do
    if ((${v1_parts[i]} < ${v2_parts[i]})); then
      echo false
      return 0
    elif ((${v1_parts[i]} > ${v2_parts[i]})); then
      echo true
      return 0
    fi
  done
  echo true
}

check_sys() {
  if [[ $(command -v yum) ]]; then
    package_manager='yum'
  elif [[ $(command -v dnf) ]]; then
    package_manager='dnf'
  elif [[ $(command -v apt) ]]; then
    package_manager='apt'
  elif [[ $(command -v apt-get) ]]; then
    package_manager='apt-get'
  fi

  if [[ -z "${package_manager}" ]]; then
    echo_content red "The system is not currently supported"
    exit 0
  fi

  if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
    release="centos"
  elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then
    release="debian"
  elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then
    release="ubuntu"
  fi

  if [[ -z "${release}" ]]; then
    echo_content red "The operating system only supports CentOS 7+/Ubuntu 18+/Debian 10+"
    exit 0
  fi

  if [[ $(arch) =~ ("x86_64"|"amd64"|"arm64"|"aarch64"|"arm"|"s390x") ]]; then
    get_arch=$(arch)
  fi

  if [[ -z "${get_arch}" ]]; then
    echo_content red "The processor architecture only supports amd64/arm64/arm/s390x"
    exit 0
  fi

  can_connect www.google.com
  [[ "$?" == "0" ]] && can_google=1
}

depend_install() {
  if [[ "${package_manager}" != 'yum' && "${package_manager}" != 'dnf' ]]; then
    ${package_manager} update -y
  fi
  ${package_manager} install -y \
    curl \
    wget \
    tar \
    lsof \
    systemd \
    python3 \
    openssl \
    iptables \
    ipset
}

# Install Docker
install_docker() {
  if [[ ! $(docker -v 2>/dev/null) ]]; then
    echo_content green "---> Install Docker"

    # Preserve the host firewall; installation must not globally disable its policy.

    # set time zone
    timedatectl set-timezone Asia/Shanghai

    if [[ ${can_google} == 0 ]]; then
      sh <(curl -sL https://get.docker.com) --mirror Aliyun
      mkdir -p /etc/docker &&
        cat >/etc/docker/daemon.json <<EOF
{
  "registry-mirrors":[${DOCKER_MIRROR}],
  "log-driver":"json-file",
  "log-opts":{
      "max-size":"50m",
      "max-file":"3"
  }
}
EOF
    else
      sh <(curl -sL https://get.docker.com)
      mkdir -p /etc/docker &&
        cat >/etc/docker/daemon.json <<EOF
{
  "log-driver":"json-file",
  "log-opts":{
      "max-size":"50m",
      "max-file":"3"
  }
}
EOF
    fi

    systemctl enable docker &&
      systemctl restart docker

    if [[ $(docker -v 2>/dev/null) ]]; then
      echo_content skyBlue "---> Docker installation completed"
    else
      echo_content red "---> Docker installation failed"
      exit 0
    fi
  else
    echo_content skyBlue "---> You have installed Docker"
  fi
}

# Custom Settings Certificate
install_custom_cert() {
  if [[ -z "$(cat "${DOMAIN_FILE}")" ]]; then
    while read -r -p "Please enter the file path of the .crt certificate (required): " crt_path; do
      if [[ -z "${crt_path}" ]]; then
        echo_content red "Path cannot be empty"
      else
        if [[ ! -f "${crt_path}" ]]; then
          echo_content red "The file path for the .crt certificate does not exist"
        else
          cp "${crt_path}" "${CERT_PATH}$1.crt"
          break
        fi
      fi
    done
    while read -r -p "Please enter the file path of the .key certificate (required): " key_path; do
      if [[ -z "${key_path}" ]]; then
        echo_content red "Path cannot be empty"
      else
        if [[ ! -f "${key_path}" ]]; then
          echo_content red "The file path for the .key certificate does not exist"
        else
          cp "${key_path}" "${CERT_PATH}$1.key"
          break
        fi
      fi
    done
    cat >${DOMAIN_FILE} <<EOF
$1
EOF
    echo_content red "\n=============================================================="
    echo_content skyBlue "---> Custom settings certificate installation completed"
    echo_content yellow "Certificate Directory: ${CERT_PATH}"
    echo_content red "\n=============================================================="
  fi
}

# Caddy2 https custom settings certificate configuration file
caddy2_https_config() {
  domain=$1
  cat >${CADDY_CONFIG} <<EOF
{
    "admin":{
        "disabled":true
    },
    "logging":{
        "logs":{
            "default":{
                "writer":{
                    "output":"file",
                    "filename":"${CADDY_LOG}error.log"
                },
                "level":"ERROR"
            }
        }
    },
    "storage":{
        "module":"file_system",
        "root":"${CERT_PATH}"
    },
    "apps":{
        "http":{
            "http_port": ${caddy_port},
            "servers":{
                "srv0":{
                    "listen":[
                        ":${caddy_port}"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "host":[
                                        "${domain}"
                                    ]
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"static_response",
                                    "headers":{
                                        "Location":[
                                            "https://{http.request.host}:${caddy_remote_port}{http.request.uri}"
                                        ]
                                    },
                                    "status_code":301
                                }
                            ]
                        }
                    ]
                },
                "srv1":{
                    "listen":[
                        ":${caddy_remote_port}"
                    ],
                    "routes":[
                        {
                            "handle":[
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "match":[
                                                {
                                                    "host":[
                                                        "${domain}"
                                                    ]
                                                }
                                            ],
                                            "handle":[
                                                {
                                                    "handler":"file_server",
                                                    "root":"${WEB_PATH}",
                                                    "index_names":[
                                                        "index.html",
                                                        "index.htm"
                                                    ]
                                                }
                                            ],
                                            "terminal":true
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "tls_connection_policies":[
                        {
                            "match":{
                                "sni":[
                                    "${domain}"
                                ]
                            }
                        }
                    ],
                    "automatic_https":{
                        "disable":true
                    }
                }
            }
        },
        "tls":{
            "certificates":{
                "automate":[
                    "${domain}"
                ],
                "load_files":[
                    {
                        "certificate":"${CADDY_CERT_DIR}${domain}/${domain}.crt",
                        "key":"${CADDY_CERT_DIR}${domain}/${domain}.key"
                    }
                ]
            },
            "automation":{
                "policies":[
                    {
                        "issuers":[
                            {
                                "module":"${ssl_module}",
                                "email":"${your_email}"
                            }
                        ]
                    }
                ]
            }
        }
    }
}
EOF
}

# Caddy2 https automatic application and renewal certificate configuration file
caddy2_https_auto_config() {
  domain=$1
  cat >${CADDY_CONFIG} <<EOF
{
    "admin":{
        "disabled":true
    },
    "logging":{
        "logs":{
            "default":{
                "writer":{
                    "output":"file",
                    "filename":"${CADDY_LOG}error.log"
                },
                "level":"ERROR"
            }
        }
    },
    "storage":{
        "module":"file_system",
        "root":"${CERT_PATH}"
    },
    "apps":{
        "http":{
            "http_port": ${caddy_port},
            "servers":{
                "srv0":{
                    "listen":[
                        ":${caddy_port}"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "host":[
                                        "${domain}"
                                    ]
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"static_response",
                                    "headers":{
                                        "Location":[
                                            "https://{http.request.host}:${caddy_remote_port}{http.request.uri}"
                                        ]
                                    },
                                    "status_code":301
                                }
                            ]
                        }
                    ]
                },
                "srv1":{
                    "listen":[
                        ":${caddy_remote_port}"
                    ],
                    "routes":[
                        {
                            "handle":[
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "match":[
                                                {
                                                    "host":[
                                                        "${domain}"
                                                    ]
                                                }
                                            ],
                                            "handle":[
                                                {
                                                    "handler":"file_server",
                                                    "root":"${WEB_PATH}",
                                                    "index_names":[
                                                        "index.html",
                                                        "index.htm"
                                                    ]
                                                }
                                            ],
                                            "terminal":true
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "tls_connection_policies":[
                        {
                            "match":{
                                "sni":[
                                    "${domain}"
                                ]
                            }
                        }
                    ],
                    "automatic_https":{
                        "disable":true
                    }
                }
            }
        },
        "tls":{
            "certificates":{
                "automate":[
                    "${domain}"
                ]
            },
            "automation":{
                "policies":[
                    {
                        "issuers":[
                            {
                                "module":"${ssl_module}",
                                "email":"${your_email}"
                            }
                        ]
                    }
                ]
            }
        }
    }
}
EOF
}

# Install Caddy2
install_caddy2() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
    echo_content green "---> Install Caddy2+https"

    wget --no-check-certificate -O ${WEB_PATH}html.tar.gz -N ${STATIC_HTML} &&
      tar -zxvf ${WEB_PATH}html.tar.gz -k -C ${WEB_PATH}

    read -r -p "Please enter the port of Caddy2 (default: 80): " caddy_port
    [[ -z "${caddy_port}" ]] && caddy_port=80
    read -r -p "Please enter the forwarding port of Caddy2 (default: 8863): " caddy_remote_port
    [[ -z "${caddy_remote_port}" ]] && caddy_remote_port=8863

    echo_content yellow "Tip: Please confirm that the domain name has been resolved to this machine, otherwise the installation may fail"
    while read -r -p "Please enter your domain name (required): " domain; do
      if [[ -z "${domain}" ]]; then
        echo_content red "Domain name cannot be empty"
      else
        break
      fi
    done

    read -r -p "Please enter your email (optional): " your_email

    while read -r -p "Please choose the way to set up the certificate? (1/automatically apply for and renew the certificate 2/manually set the certificate path default: 1: " ssl_option; do
      if [[ -z ${ssl_option} || ${ssl_option} == 1 ]]; then
        while read -r -p "Please choose the way to apply for the certificate (1/acme 2/zerossl default: 1: " ssl_module_type; do
          if [[ -z "${ssl_module_type}" || ${ssl_module_type} == 1 ]]; then
            ssl_module="acme"
            CADDY_CERT_DIR="${CERT_PATH}certificates/acme-v02.api.letsencrypt.org-directory/"
            break
          elif [[ ${ssl_module_type} == 2 ]]; then
            ssl_module="zerossl"
            CADDY_CERT_DIR="${CERT_PATH}certificates/acme.zerossl.com-v2-dv90/"
            break
          else
            echo_content red "Cannot enter other characters except 1 and 2"
          fi
        done
        caddy2_https_auto_config "${domain}"
        break
      elif [[ ${ssl_option} == 2 ]]; then
        install_custom_cert "${domain}"
        caddy2_https_config "${domain}"
        break
      else
        echo_content red "Cannot enter other characters except 1 and 2"
      fi
    done

    # Caddy2 temporary listening port for automatic certificate application
    if lsof -nP -iTCP:"${caddy_port},${caddy_remote_port}" -sTCP:LISTEN -t >/dev/null; then
      echo_content red "Caddy ports are already occupied. No process was stopped; choose free ports."
      return 1
    fi

    docker pull caddy:2.6.2 &&
      docker run -d --name trojan-panel-caddy --restart always \
        --network=host \
        -v "${CADDY_DATA}":"${CADDY_DATA}" \
        -v ${CERT_PATH}:"${CADDY_CERT_DIR}${domain}/" \
        -v ${WEB_PATH}:${WEB_PATH} \
        -v ${CADDY_LOG}:${CADDY_LOG} \
        caddy:2.6.2 caddy run --config ${CADDY_CONFIG}

    cat >${DOMAIN_FILE} <<EOF
${domain}
EOF

    if [[ -n $(docker ps -q -f "name=^trojan-panel-caddy$" -f "status=running") ]]; then
      echo_content red "\n=============================================================="
      echo_content skyBlue "---> Caddy2+https installation completed"
      echo_content yellow "Certificate Directory: ${CERT_PATH}"
      echo_content red "\n=============================================================="
    else
      echo_content red "---> Caddy2+https installation fails or runs abnormally, please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> You have installed Caddy2+https"
  fi
}

# Nginx http configuration file
nginx_http_config() {
  cat >${NGINX_CONFIG} <<-EOF
server {
    listen       ${nginx_port};
    server_name  localhost;
    access_log off;

    location / {
        root   ${WEB_PATH};
        index  index.html index.htm;
    }

    error_page  497               http://\$host:${nginx_port}\$request_uri;

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
}

# Nginx https configuration file
nginx_https_config() {
  domain=$1
  cat >${NGINX_CONFIG} <<-EOF
server {
    listen ${nginx_port};
    server_name localhost;

    return 301 http://\$host:${nginx_remote_port}\$request_uri;
}

server {
    listen       ${nginx_remote_port} ssl;
    server_name  localhost;
    access_log off;

    ssl_certificate      ${CERT_PATH}${domain}.crt;
    ssl_certificate_key  ${CERT_PATH}${domain}.key;
    # cache validity period
    ssl_session_timeout  5m;
    # secure link optional encryption protocol
    ssl_protocols  TLSv1.2 TLSv1.3;
    # encryption algorithm
    ssl_ciphers  ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    # use server-side preferred algorithm
    ssl_prefer_server_ciphers  on;

    # Access logs disabled: subscription URLs contain credentials.

    location / {
        root   ${WEB_PATH};
        index  index.html index.htm;
    }

    #error_page  404              /404.html;
    #497 http->https
    error_page  497               https://\$host:${nginx_remote_port}\$request_uri;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
}

# Install Nginx
install_nginx() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-nginx$") ]]; then
    echo_content green "---> Install Nginx"

    wget --no-check-certificate -O ${WEB_PATH}html.tar.gz -N ${STATIC_HTML} &&
      tar -zxvf ${WEB_PATH}html.tar.gz -k -C ${WEB_PATH}

    read -r -p "Please enter the port of Nginx (default: 80): " nginx_port
    [[ -z "${nginx_port}" ]] && nginx_port=80
    read -r -p "Please enter the forwarding port of Nginx (default: 8863): " nginx_remote_port
    [[ -z "${nginx_remote_port}" ]] && nginx_remote_port=8863

    while read -r -p "Please choose whether to enable https in Nginx? (0/off 1/on default: 1): " nginx_https; do
      if [[ -z ${nginx_https} || ${nginx_https} == 1 ]]; then
        install_custom_cert "custom_cert"
        nginx_https_config "custom_cert"
        break
      elif [[ ${nginx_https} == 0 ]]; then
        nginx_http_config
        break
      else
        echo_content red "Cannot enter other characters except 1 and 2"
      fi
    done

    docker pull nginx:1.20-alpine &&
      docker run -d --name trojan-panel-nginx --restart always \
        --network=host \
        -v "${NGINX_CONFIG}":"/etc/nginx/conf.d/default.conf" \
        -v ${CERT_PATH}:${CERT_PATH} \
        -v ${WEB_PATH}:${WEB_PATH} \
        nginx:1.20-alpine

    if [[ -n $(docker ps -q -f "name=^trojan-panel-nginx$" -f "status=running") ]]; then
      echo_content skyBlue "---> Nginx installation completed"
    else
      echo_content red "---> Nginx installation fails or runs abnormally, please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> You have installed Nginx"
  fi
}

# Install a web server
install_reverse_proxy() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-caddy$|^trojan-panel-nginx$") ]]; then
    echo_content green "---> Install a web server"

    while :; do
      echo_content yellow "1. Install Caddy2+https (recommend)"
      echo_content yellow "2. Install Nginx"
      echo_content yellow "3. Not install"
      read -r -p "Please select (default: 1): " whether_install_reverse_proxy
      [[ -z "${whether_install_reverse_proxy}" ]] && whether_install_reverse_proxy=1

      case ${whether_install_reverse_proxy} in
      1)
        install_caddy2
        break
        ;;
      2)
        install_nginx
        break
        ;;
      3)
        break
        ;;
      *)
        echo_content red "No such option"
        continue
        ;;
      esac
    done

    echo_content skyBlue "---> Web server installation completed"
  fi
}

# Set certificate
install_cert() {
  if [[ -z "$(cat "${DOMAIN_FILE}")" ]]; then
    echo_content green "---> Set certificate"

    while :; do
      echo_content yellow "1. Custom certificate"
      echo_content yellow "2. Not set"
      read -r -p "Please select (default: 1): " whether_install_cert
      [[ -z "${whether_install_cert}" ]] && whether_install_cert=1

      case ${whether_install_cert} in
      1)
        install_custom_cert "custom_cert"
        break
        ;;
      2)
        break
        ;;
      *)
        echo_content red "No such option"
        continue
        ;;
      esac
    done

    echo_content green "---> Certificate setup completed"
  fi
}

# Install MariaDB
install_mariadb() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-mariadb$") ]]; then
    echo_content green "---> Install MariaDB"

    read -r -p "Please enter the port of MariaDB (default: 9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the username of MariaDB (default: root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the password of MariaDB (required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "Password can not be empty"
      else
        break
      fi
    done

    if [[ "${mariadb_user}" == "root" ]]; then
      docker pull mariadb:10.7.3 &&
        docker run -d --name trojan-panel-mariadb --restart always \
          --network=host \
          -e MYSQL_DATABASE="trojan_panel_db" \
          -e MYSQL_ROOT_PASSWORD="${mariadb_pas}" \
          -e TZ=Asia/Shanghai \
          mariadb:10.7.3 \
          --port ${mariadb_port} \
          --bind-address="${mariadb_bind}" \
          --character-set-server=utf8mb4 \
          --collation-server=utf8mb4_unicode_ci
    else
      docker pull mariadb:10.7.3 &&
        docker run -d --name trojan-panel-mariadb --restart always \
          --network=host \
          -e MYSQL_DATABASE="trojan_panel_db" \
          -e MYSQL_ROOT_PASSWORD="${mariadb_pas}" \
          -e MYSQL_USER="${mariadb_user}" \
          -e MYSQL_PASSWORD="${mariadb_pas}" \
          -e TZ=Asia/Shanghai \
          mariadb:10.7.3 \
          --port ${mariadb_port} \
          --bind-address="${mariadb_bind}" \
          --character-set-server=utf8mb4 \
          --collation-server=utf8mb4_unicode_ci
    fi

    if [[ -n $(docker ps -q -f "name=^trojan-panel-mariadb$" -f "status=running") ]]; then
      echo_content skyBlue "---> MariaDB installation completed"
      echo_content yellow "---> The MariaDB password of root (please keep it safe): ${mariadb_pas}"
      if [[ "${mariadb_user}" != "root" ]]; then
        echo_content yellow "---> The MariaDB password of ${mariadb_user} (please keep it safe): ${mariadb_pas}"
      fi
    else
      echo_content red "---> MariaDB installation fails or runs abnormally, please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> You have installed MariaDB"
  fi
}

# Install Redis
install_redis() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-redis$") ]]; then
    echo_content green "---> Install Redis"

    read -r -p "Please enter the port of Redis (default: 6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "Please enter the Redis password (required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "Password can not be empty"
      else
        break
      fi
    done

    docker pull redis:6.2.7 &&
      docker run -d --name trojan-panel-redis --restart always \
        --network=host \
        redis:6.2.7 \
        redis-server --bind "${redis_bind}" --protected-mode yes --requirepass "${redis_pass}" --port "${redis_port}"

    if [[ -n $(docker ps -q -f "name=^trojan-panel-redis$" -f "status=running") ]]; then
      echo_content skyBlue "---> Redis installation completed"
      echo_content yellow "---> Redis password (please keep it safe): ${redis_pass}"
    else
      echo_content red "---> Redis installation fails or runs abnormally, please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> You have installed Redis"
  fi
}

# XWarp Frontend Nginx http configuration file
ui_http_config() {
  cat >${UI_NGINX_CONFIG} <<-EOF
server {
    listen       ${trojan_panel_ui_port};
    server_name  ${domain:-localhost};
    access_log off;

    location / {
        root   ${TROJAN_PANEL_UI_DATA};
        index  index.html index.htm;
    }

    location /api {
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_pass http://${trojan_panel_ip}:${trojan_panel_server_port};
    }

    error_page  497               http://\$host:${trojan_panel_ui_port}\$request_uri;

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
}

# XWarp Frontend Nginx https configuration file
ui_https_config() {
  cat >${UI_NGINX_CONFIG} <<-EOF
server {
    listen       ${trojan_panel_ui_port} ssl;
    server_name  ${ui_panel_host:-${domain}};
    access_log off;

    ssl_certificate      ${CERT_PATH}${domain}.crt;
    ssl_certificate_key  ${CERT_PATH}${domain}.key;
    # cache validity period
    ssl_session_timeout  5m;
    # secure link optional encryption protocol
    ssl_protocols  TLSv1.2 TLSv1.3;
    # encryption algorithm
    ssl_ciphers  ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    # use server-side preferred algorithm
    ssl_prefer_server_ciphers  on;

    # Access logs disabled: subscription URLs contain credentials.

    location / {
        root   ${TROJAN_PANEL_UI_DATA};
        index  index.html index.htm;
    }

    location /api {
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_pass http://${trojan_panel_ip}:${trojan_panel_server_port};
    }

    #error_page  404              /404.html;
    #497 http->https
    error_page  497               https://\$host:${trojan_panel_ui_port}\$request_uri;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
}

# Install XWarp Frontend
install_trojan_panel_ui() {
  local ui_panel_host=""
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-ui$") ]]; then
    echo_content green "---> Install XWarp Frontend"

    read -r -p "Please enter the IP address of the XWarp Backend (default: local host): " trojan_panel_ip
    [[ -z "${trojan_panel_ip}" ]] && trojan_panel_ip="127.0.0.1"
    read -r -p "Please enter the service port of the XWarp Backend (default: 8081): " trojan_panel_server_port
    [[ -z "${trojan_panel_server_port}" ]] && trojan_panel_server_port=8081

    local requested_panel_port
    read -r -p "Panel port (blank: random available high port 49152-65535): " requested_panel_port || return 1
    local -a panel_port_args=()
    [[ -z "$requested_panel_port" ]] || panel_port_args+=(--port "$requested_panel_port")
    trojan_panel_ui_port=$(security_tool ports.py "${panel_port_args[@]}") || return 1
    echo_content yellow "Panel TCP port: ${trojan_panel_ui_port}. Allow this port in your cloud firewall if enabled."
    while read -r -p "Please choose whether to enable https on the XWarp Frontend? (0/off 1/on default: 1): " ui_https; do
      if [[ -z ${ui_https} || ${ui_https} == 1 ]]; then
        install_custom_cert "custom_cert"
        domain=$(cat "${DOMAIN_FILE}")
        if [[ "$domain" == custom_cert ]]; then
          read -r -p "Public domain matching the uploaded certificate: " ui_panel_host || return 1
          [[ "$ui_panel_host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || { echo "Invalid public hostname." >&2; return 1; }
        fi
        ui_https_config
        break
      elif [[ ${ui_https} == 0 ]]; then
        read -r -p "Public domain or IPv4 address for the panel login URL: " domain || return 1
        [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || { echo "Invalid public hostname." >&2; return 1; }
        ui_http_config
        break
      else
        echo_content red "Cannot enter other characters except 1 and 2"
      fi
    done

    pull_immutable_image "${XWARP_UI_IMAGE:-ghcr.io/howellxuking/xwarp-ui:test}" || return 1
    
      docker run -d --name trojan-panel-ui --restart always \
        --network=host \
        -v "${UI_NGINX_DATA}":"/etc/nginx/conf.d" \
        -v "${WEB_PATH}":"${WEB_PATH}":ro \
        -v ${CERT_PATH}:${CERT_PATH} \
        "$XWARP_PINNED_IMAGE"

    if [[ -n $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
      echo_content skyBlue "---> XWarp Frontend installation completed"

      https_flag=$([[ -z ${ui_https} || ${ui_https} == 1 ]] && echo "https" || echo "http")
      domain_or_ip=$([[ -z ${domain} || "${domain}" == "custom_cert" ]] && echo "ip" || echo "${domain}")

      echo_content red "\n=============================================================="
      echo_content skyBlue "XWarp Frontend installed successfully"
      show_panel_access
      echo_content red "\n=============================================================="
    else
      echo_content red "---> XWarp Frontend installation fails or runs abnormally, please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> You have installed the XWarp Frontend"
    show_panel_access
  fi
}

# Install XWarp Backend
install_trojan_panel() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel$") ]]; then
    echo_content green "---> Install XWarp Backend"

    read -r -p "Please enter the service port of the XWarp Backend (default: 8081): " trojan_panel_port
    [[ -z "${trojan_panel_port}" ]] && trojan_panel_port=8081

    read -r -p "Please enter the IP address of MariaDB (default: local host): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the port of MariaDB (default: 9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the username of MariaDB (default: root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the password of MariaDB (required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "Password can not be empty"
      else
        break
      fi
    done

    docker exec trojan-panel-mariadb mysql --default-character-set=utf8 -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -e "create database if not exists trojan_panel_db;" &>/dev/null

    read -r -p "Please enter the IP address of Redis (default: local host): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "Please enter the port of Redis (default: 6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "Please enter the Redis password (required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "Password can not be empty"
      else
        break
      fi
    done

    docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p "${redis_port}" -a "${redis_pass}" -e "flushall" &>/dev/null

    pull_immutable_image "${XWARP_BACKEND_IMAGE:-ghcr.io/howellxuking/xwarp:test}" || return 1
    
      docker run -d --name trojan-panel --restart always \
        --network=host \
        -v ${WEB_PATH}:${TROJAN_PANEL_WEBFILE} \
        -v ${TROJAN_PANEL_LOGS}:${TROJAN_PANEL_LOGS} \
        -v ${TROJAN_PANEL_CONFIG}:${TROJAN_PANEL_CONFIG} \
        -v /etc/localtime:/etc/localtime \
        -e GIN_MODE=release \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        -e "server_port=${trojan_panel_port}" \
        "$XWARP_PINNED_IMAGE"

    if [[ -n $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
      echo_content skyBlue "---> XWarp Backend installation completed"

      echo_content red "\n=============================================================="
      echo_content skyBlue "XWarp Backend installed successfully"
      echo_content yellow "MariaDB ${mariadb_user} password (please keep it safe): ${mariadb_pas}"
      echo_content yellow "Redis password (please keep it safe): ${redis_pass}"
      security_tool panel_access.py --credentials-only --wait-backend-port "$trojan_panel_port" || return 1
      echo_content yellow "Please log in to the management panel to change the password in time"
      echo_content red "\n=============================================================="
    else
      echo_content red "---> XWarp Backend installation fails or runs abnormally, please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> You have installed the XWarp Backend"
  fi
}

# Install XWarp Core
install_trojan_panel_core() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-core$") ]]; then
    echo_content green "---> Install XWarp Core"

    read -r -p "Please enter the service port of the XWarp Core (default: 8082): " trojan_panel_core_port
    [[ -z "${trojan_panel_core_port}" ]] && trojan_panel_core_port=8082

    read -r -p "Please enter the IP address of MariaDB (default: local host): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the port of MariaDB (default: 9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the username of MariaDB (default: root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the password of MariaDB (required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "Password can not be empty"
      else
        break
      fi
    done
    read -r -p "Please enter the database name (default: trojan_panel_db): " database
    [[ -z "${database}" ]] && database="trojan_panel_db"
    read -r -p "Please enter the user table name of the database (default: account): " account_table
    [[ -z "${account_table}" ]] && account_table="account"

    read -r -p "Please enter the IP address of Redis (default: local host): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "Please enter the port of Redis (default: 6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "Please enter the Redis password (required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "Password can not be empty"
      else
        break
      fi
    done
    read -r -p "Please enter the API port (default: 8100): " grpc_port
    [[ -z "${grpc_port}" ]] && grpc_port=8100

    domain=$(cat "${DOMAIN_FILE}")

    pull_immutable_image "${XWARP_CORE_IMAGE:-jonssonyan/trojan-panel-core}" || return 1
    protect_new_core || return 1
    
      docker run -d --name trojan-panel-core --restart always \
        --network=host \
        -v ${TROJAN_PANEL_CORE_DATA}bin/xray/config/:${TROJAN_PANEL_CORE_DATA}bin/xray/config/ \
        -v ${TROJAN_PANEL_CORE_DATA}bin/trojango/config/:${TROJAN_PANEL_CORE_DATA}bin/trojango/config/ \
        -v ${TROJAN_PANEL_CORE_DATA}bin/hysteria/config/:${TROJAN_PANEL_CORE_DATA}bin/hysteria/config/ \
        -v ${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config/:${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config/ \
        -v ${TROJAN_PANEL_CORE_DATA}bin/hysteria2/config/:${TROJAN_PANEL_CORE_DATA}bin/hysteria2/config/ \
        -v ${TROJAN_PANEL_CORE_LOGS}:${TROJAN_PANEL_CORE_LOGS} \
        -v ${TROJAN_PANEL_CORE_CONFIG}:${TROJAN_PANEL_CORE_CONFIG} \
        -v ${CERT_PATH}:${CERT_PATH} \
        -v ${WEB_PATH}:${WEB_PATH} \
        -v /etc/localtime:/etc/localtime \
        -e GIN_MODE=release \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "database=${database}" \
        -e "account-table=${account_table}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        -e "crt_path=${CERT_PATH}${domain}.crt" \
        -e "key_path=${CERT_PATH}${domain}.key" \
        -e "grpc_port=${grpc_port}" \
        -e "server_port=${trojan_panel_core_port}" \
        "$XWARP_PINNED_IMAGE"
    if [[ -n $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
      echo_content skyBlue "---> XWarp Core installation completed"
    else
      echo_content red "---> XWarp Core installation fails or runs abnormally, please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> You have installed the XWarp Core"
  fi
}

# Update XWarp database structure
update_trojan_panel_database() {
  echo_content skyBlue "---> Update XWarp database structure"

  version_214_215=("v2.1.4")
  if [[ "${version_214_215[*]}" =~ "${trojan_panel_current_version}" ]]; then
    docker exec trojan-panel-mariadb mysql --default-character-set=utf8 -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_215}" &>/dev/null &&
      trojan_panel_current_version="v2.1.5"
  fi
  version_215_230=("v2.1.5" "v2.1.6" "v2.1.7" "v2.1.8" "v2.2.0" "v2.2.1")
  if [[ "${version_215_230[*]}" =~ "${trojan_panel_current_version}" ]]; then
    docker exec trojan-panel-mariadb mysql --default-character-set=utf8 -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_230}" &>/dev/null &&
      trojan_panel_current_version="v2.3.0"
  fi

  # 可重复执行：修复旧安装中模板设置仅允许 512 字符的问题
  docker exec trojan-panel-mariadb mysql --default-character-set=utf8 -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_243}" &>/dev/null

  echo_content skyBlue "---> XWarp database structure update completed"
}

# Update XWarp Core database structure
update_trojan_panel_core_database() {
  echo_content skyBlue "---> Update XWarp Core database structure"

  echo_content skyBlue "---> XWarp Core database structure update completed"
}

# Update XWarp Frontend
update_trojan_panel_ui() {
  reviewed_upgrade ui
}

# Update XWarp Backend
update_trojan_panel() {
  reviewed_upgrade backend
}

# Update XWarp Core
update_trojan_panel_core() {
  reviewed_upgrade core
}

# Uninstall Caddy2+https
uninstall_caddy2() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
    echo_content green "---> Uninstall Caddy2+https"

    docker rm -f trojan-panel-caddy &&
      rm -rf ${CADDY_DATA}

    echo_content skyBlue "---> Caddy2+https uninstallation completed"
  else
    echo_content red "---> Please install Caddy2+https first"
  fi
}

# Uninstall Nginx
uninstall_nginx() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-nginx") ]]; then
    echo_content green "---> Uninstall Nginx"

    docker rm -f trojan-panel-nginx &&
      rm -rf ${NGINX_DATA}

    echo_content skyBlue "---> Nginx uninstallation completed"
  else
    echo_content red "---> Please install Nginx first"
  fi
}

# Uninstall MariaDB
uninstall_mariadb() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-mariadb$") ]]; then
    echo_content green "---> Uninstall MariaDB"

    docker rm -f trojan-panel-mariadb &&
      rm -rf ${MARIA_DATA}

    echo_content skyBlue "---> MariaDB uninstall completed"
  else
    echo_content red "---> Please install MariaDB first"
  fi
}

# Uninstall Redis
uninstall_redis() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-redis$") ]]; then
    echo_content green "---> Uninstall Redis"

    docker rm -f trojan-panel-redis &&
      rm -rf ${REDIS_DATA}

    echo_content skyBlue "---> Redis uninstall completed"
  else
    echo_content red "---> Please install Redis first"
  fi
}

# Uninstall XWarp Frontend
uninstall_trojan_panel_ui() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-ui$") ]]; then
    echo_content green "---> Uninstall XWarp Frontend"

    docker rm -f trojan-panel-ui &&
      docker rmi -f ghcr.io/howellxuking/xwarp-ui:test &&
      rm -rf ${TROJAN_PANEL_UI_DATA}

    echo_content skyBlue "---> XWarp Frontend uninstallation completed"
  else
    echo_content red "---> Please install the XWarp Frontend first"
  fi
}

# Uninstall XWarp Backend
uninstall_trojan_panel() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel$") ]]; then
    echo_content green "---> Uninstall XWarp Backend"

    docker rm -f trojan-panel &&
      docker rmi -f ghcr.io/howellxuking/xwarp:test &&
      rm -rf ${TROJAN_PANEL_DATA}

    echo_content skyBlue "---> XWarp Backend uninstallation completed"
  else
    echo_content red "---> Please install the XWarp Backend first"
  fi
}

# Uninstall XWarp Core
uninstall_trojan_panel_core() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") ]]; then
    echo_content green "---> Uninstall XWarp Core"

    docker rm -f trojan-panel-core &&
      docker rmi -f jonssonyan/trojan-panel-core &&
      rm -rf ${TROJAN_PANEL_CORE_DATA}

    echo_content skyBlue "---> XWarp Core uninstallation completed"
  else
    echo_content red "---> Please install the XWarp Core first"
  fi
}

# Uninstall all XWarp related containers
uninstall_all() {
  echo_content green "---> Uninstall all XWarp related containers"

  docker rm -f $(docker ps -a -q -f "name=^trojan-panel")
  docker rmi -f $(docker images | grep "^ghcr.io/howellxuking/xwarp:test" | awk '{print $3}')
  rm -rf ${TP_DATA}

  echo_content skyBlue "---> Uninstall all XWarp related containers completed"
}

# Modify XWarp Frontend port
update_trojan_panel_ui_port() {
  if [[ -z $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
    echo_content red "面板未运行，请先修复或安装面板。"
    return 1
  fi
  local new_panel_port legacy_host
  local -a args=()
  read -r -p "请输入新的面板端口（留空自动选择随机高位端口）：" new_panel_port || return 1
  new_panel_port="$(normalize_menu_choice "$new_panel_port")"
  if [[ -z "$new_panel_port" ]]; then
    args+=(--random)
  elif [[ "$new_panel_port" =~ ^[0-9]{1,5}$ ]]; then
    args+=(--port "$((10#$new_panel_port))")
  else
    echo_content red "端口必须是 1–65535 之间的数字。"
    return 1
  fi
  if [[ ! -f /tpdata/trojan-panel/config/gateway.json ]]; then
    read -r -p "请输入当前面板域名或 IP（用于显示新登录地址）：" legacy_host || return 1
    args+=(--host "$legacy_host")
  fi
  security_tool panel_port.py "${args[@]}"
}

# Refresh Redis cache
redis_flush_all() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-redis$") ]]; then
    echo_content red "---> Please install Redis first"
    exit 0
  fi

  if [[ -z $(docker ps -q -f "name=^trojan-panel-redis$" -f "status=running") ]]; then
    echo_content red "---> Redis is running abnormally"
    exit 0
  fi

  echo_content green "---> Refresh Redis cache"

  read -r -p "Please enter the IP address of Redis (default: local host): " redis_host
  [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
  read -r -p "Please enter the port of Redis (default: 6378): " redis_port
  [[ -z "${redis_port}" ]] && redis_port=6378
  while read -r -p "Please enter the Redis password (required): " redis_pass; do
    if [[ -z "${redis_pass}" ]]; then
      echo_content red "Password can not be empty"
    else
      break
    fi
  done

  docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p "${redis_port}" -a "${redis_pass}" -e "flushall" &>/dev/null

  echo_content skyBlue "---> Redis cache refresh completed"
}

# Replace certificate
change_cert() {
  domain_1=$(cat "${DOMAIN_FILE}")

  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
    docker rm -f trojan-panel-caddy &&
      rm -rf ${CADDY_LOG}* &&
      echo "" >${CADDY_CONFIG} &&
      rm -rf ${WEB_PATH}*
  fi

  rm -rf ${CERT_PATH}* &&
    echo "" >${DOMAIN_FILE}

  install_reverse_proxy
  install_cert

  domain_2=$(cat "${DOMAIN_FILE}")
  if [[ -n "${domain_1}" && -n "${domain_2}" ]]; then
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-nginx$") ]]; then
      sed -i "s/${domain_1}/${domain_2}/g" ${NGINX_CONFIG} &&
        docker restart trojan-panel-nginx
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-ui$") ]]; then
      sed -i "s/${domain_1}/${domain_2}/g" ${UI_NGINX_DATA} &&
        docker restart trojan-panel-ui
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") ]]; then
      find /tpdata/trojan-panel-core/bin/ -type f -exec sed -i "s/${domain_1}/${domain_2}/g" {} + &&
        sed -i "s/${domain_1}/${domain_2}/g" ${trojan_panel_core_config_path} &&
        docker restart trojan-panel-core
    fi
  fi
}

# Recovery affects only administrator login/MFA, never node credentials.
forget_pass() {
  docker exec trojan-panel ./trojan-panel -resetAdminPassword || return 1
  echo_content yellow "Read the recovered-admin-*.txt file locally under /tpdata/trojan-panel/config; login with the existing administrator name. Remove the file after changing the password."
}

# Fault detection
failure_testing() {
  echo_content green "---> Start troubleshooting"
  if [[ ! $(docker -v 2>/dev/null) ]]; then
    echo_content red "---> Docker is running abnormally"
  else
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
      if [[ -z $(docker ps -q -f "name=^trojan-panel-caddy$" -f "status=running") ]]; then
        echo_content red "---> Caddy2 is running abnormally and the running log is as follows:"
        docker logs trojan-panel-caddy
      fi
      domain=$(cat "${DOMAIN_FILE}")
      if [[ -n ${domain} && ! -f "${CERT_PATH}${domain}.crt" ]]; then
        echo_content red "---> The certificate application is abnormal, please try 1. Change the sub-domain name to re-build 2. Restart the server to re-apply for the certificate 3. Re-build and select the custom certificate option"
        if [[ -f ${CADDY_LOG}error.log ]]; then
          echo_content red "Caddy2 error log is as follows:"
          tail -n 20 ${CADDY_LOG}error.log | grep error
        fi
      fi
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-mariadb$") && -z $(docker ps -q -f "name=^trojan-panel-mariadb$" -f "status=running") ]]; then
      echo_content red "---> The MariaDB is running abnormally and the running log is as follows:"
      docker logs trojan-panel-mariadb
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-redis$") && -z $(docker ps -q -f "name=^trojan-panel-redis$" -f "status=running") ]]; then
      echo_content red "---> The Redis is running abnormally and the running log is as follows:"
      docker logs trojan-panel-redis
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel$") && -z $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
      echo_content red "---> The XWarp Backend is running abnormally and the running log is as follows:"
      if [[ -f ${TROJAN_PANEL_LOGS}trojan-panel.log ]]; then
        tail -n 20 ${TROJAN_PANEL_LOGS}trojan-panel.log | grep error
      else
        docker logs trojan-panel
      fi
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-ui$") && -z $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
      echo_content red "---> The XWarp Frontend is running abnormally and the running log is as follows:"
      docker logs trojan-panel-ui
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") && -z $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
      echo_content red "---> The XWarp Core is running abnormally and the running log is as follows:"
      if [[ -f ${TROJAN_PANEL_CORE_LOGS}trojan-panel.log ]]; then
        tail -n 20 ${TROJAN_PANEL_CORE_LOGS}trojan-panel.log | grep error
      else
        docker logs trojan-panel-core
      fi
    fi
  fi
  echo_content green "---> Troubleshooting ended"
}

log_query() {
  while :; do
    echo_content skyBlue "Applications that can query logs are as follows:"
    echo_content yellow "1. XWarp Backend"
    echo_content yellow "2. XWarp Frontend"
    echo_content yellow "3. Quit"
    read -r -p "Please select an application (default: 3): " select_log_query_type
    [[ -z "${select_log_query_type}" ]] && select_log_query_type=3

    case ${select_log_query_type} in
    1)
      log_file_path=${TROJAN_PANEL_LOGS}trojan-panel.log
      ;;
    2)
      log_file_path=${TROJAN_PANEL_CORE_LOGS}trojan-panel-core.log
      ;;
    3)
      break
      ;;
    *)
      echo_content red "No such option"
      continue
      ;;
    esac

    read -r -p "Please enter the number of rows to query (default: 20): " select_log_query_line_type
    [[ -z "${select_log_query_line_type}" ]] && select_log_query_line_type=20

    if [[ -f ${log_file_path} ]]; then
      echo_content skyBlue "The log is as follows:"
      tail -n ${select_log_query_line_type} ${log_file_path}
    else
      echo_content red "No log file exists"
    fi
  done
}

version_query() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-ui$") && -n $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
    trojan_panel_ui_current_version=$(docker exec trojan-panel-ui cat ${TROJAN_PANEL_UI_DATA}version)
    echo_content yellow "The current version of XWarp Frontend is ${trojan_panel_ui_current_version} the latest version is ${trojan_panel_ui_latest_version}"
  fi
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel$") && -n $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
    trojan_panel_current_version=$(docker exec trojan-panel ./trojan-panel -version)
    echo_content yellow "The current version of XWarp Backend is ${trojan_panel_current_version} the latest version is ${trojan_panel_latest_version}"
  fi
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") && -n $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
    trojan_panel_core_current_version=$(docker exec trojan-panel-core ./trojan-panel-core -version)
    echo_content yellow "The current version of XWarp Core is ${trojan_panel_core_current_version} the latest version is ${trojan_panel_core_latest_version}"
  fi
}

main() {
  cd "$HOME" || exit 0
  init_var
  mkdir_tools
  check_sys
  depend_install
  clear
  echo_content red "\n=============================================================="
  echo_content skyBlue "Private security tools: Debian 11+/Ubuntu 20.04+, Python 3.8+, Docker, systemd"
  echo_content skyBlue "Version: v2.5.0"
  echo_content skyBlue "Description: One click Install XWarp server"
  echo_content skyBlue "Author: jonssonyan <https://jonssonyan.com>"
  echo_content skyBlue "Github: https://github.com/howellxuKing"
  echo_content skyBlue "Docs: https://github.com/howellxuKing"
  echo_content red "\n=============================================================="
  echo_content yellow "1. Install XWarp Frontend"
  echo_content yellow "2. Install XWarp Backend"
  echo_content yellow "3. Install XWarp Core"
  echo_content yellow "4. Install Caddy2+https"
  echo_content yellow "5. Install Nginx"
  echo_content yellow "6. Install MariaDB"
  echo_content yellow "7. Install Redis"
  echo_content green "\n=============================================================="
  echo_content yellow "8. Update XWarp Frontend"
  echo_content yellow "9. Update XWarp Backend"
  echo_content yellow "10. Update XWarp Core"
  echo_content green "\n=============================================================="
  echo_content yellow "11. Uninstall XWarp Frontend"
  echo_content yellow "12. Uninstall XWarp Backend"
  echo_content yellow "13. Uninstall XWarp Core"
  echo_content yellow "14. Uninstall Caddy2+https"
  echo_content yellow "15. Uninstall Nginx"
  echo_content yellow "16. Uninstall MariaDB"
  echo_content yellow "17. Uninstall Redis"
  echo_content yellow "18. Uninstall all XWarp related containers"
  echo_content green "\n=============================================================="
  echo_content yellow "19. Modify XWarp Frontend port"
  echo_content yellow "20. Refresh Redis cache"
  echo_content yellow "21. Replace certificate"
  echo_content yellow "22. Forgot sysadmin password"
  echo_content green "\n=============================================================="
  echo_content yellow "23. Fault detection"
  echo_content yellow "24. Log query"
  echo_content yellow "25. Version query"
  echo_content yellow "26. Configure private HTTPS gateway"
  echo_content yellow "27. Consistent database/config/image backup"
  echo_content yellow "28. Restore a reviewed backup"
  echo_content yellow "29. Restrict core management TCP ports"
  echo_content yellow "30. Server health report"
  echo_content yellow "31. Install health/certificate timers"
  echo_content yellow "32. Enable optional 12-hour panel IP gate"
  echo_content yellow "0. Quit"
  read_menu_choice selectInstall_type "Please choose (0=quit): " 0 32 || return 0
  case ${selectInstall_type} in
  1)
    install_docker
    install_reverse_proxy
    install_cert
    install_trojan_panel_ui
    ;;
  2)
    install_docker
    install_mariadb
    install_redis
    install_trojan_panel
    ;;
  3)
    install_docker
    install_reverse_proxy
    install_cert
    install_trojan_panel_core
    ;;
  4)
    install_docker
    install_caddy2
    ;;
  5)
    install_docker
    install_nginx
    ;;
  6)
    install_docker
    install_mariadb
    ;;
  7)
    install_docker
    install_redis
    ;;
  8)
    reviewed_upgrade ui
    ;;
  9)
    reviewed_upgrade backend
    ;;
  10)
    reviewed_upgrade core
    ;;
  11)
    uninstall_trojan_panel_ui
    ;;
  12)
    uninstall_trojan_panel
    ;;
  13)
    uninstall_trojan_panel_core
    ;;
  14)
    uninstall_caddy2
    ;;
  15)
    uninstall_nginx
    ;;
  16)
    uninstall_mariadb
    ;;
  17)
    uninstall_redis
    ;;
  18)
    uninstall_all
    ;;
  19)
    update_trojan_panel_ui_port
    ;;
  20)
    redis_flush_all
    ;;
  21)
    change_cert
    ;;
  22)
    forget_pass
    ;;
  23)
    security_tool diagnostics.py
    ;;
  24)
    log_query
    ;;
  25)
    version_query
    ;;
  26) secure_gateway ;;
  27) security_tool snapshot.py backup --quiesce ;;
  28) read -r -p "Backup archive absolute path: " snapshot_archive
      read -r -p "Confirm by typing the exact archive filename: " snapshot_confirm
      security_tool snapshot.py restore "$snapshot_archive" --confirm "$snapshot_confirm" ;;
  29) read -r -p "Core management ports (default 8082,8100): " security_ports
      read -r -p "Allowed backend IP/CIDR (empty = local only): " security_peer
      local -a security_args=(--apply --ports "${security_ports:-8082,8100}")
      [[ -n "$security_peer" ]] && security_args+=(--allow "$security_peer")
      security_tool firewall.py "${security_args[@]}" || return 1
      if [[ "$XWARP_INSTALL_DIR" == /opt/xwarp-install ]]; then
        umask 077
        printf 'XWARP_CORE_FIREWALL_ARGS=--ports %s%s\n' "${security_ports:-8082,8100}" "${security_peer:+ --allow $security_peer}" > /etc/xwarp-core-firewall.env
        cp "$XWARP_INSTALL_DIR/systemd/xwarp-core-firewall.service" /etc/systemd/system/
        systemctl daemon-reload; systemctl enable xwarp-core-firewall.service
      else
        echo "Policy applied for this boot. Place checkout in /opt/xwarp-install and repeat to persist it."
      fi ;;
  30) security_tool diagnostics.py ;;
  31) install_security_units timers ;;
  32) install_security_units knock ;;
  0) return 0 ;;
  *) echo_content red "No such option" ;;
  esac
}

if [[ "${XWARP_SOURCE_ONLY:-0}" != "1" ]]; then
  main
fi
