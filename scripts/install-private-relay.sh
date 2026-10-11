#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

release_version="v0.1.0-preview.2"
control_url='' hostname='' token_file='' ca_file=''
port=9091 region_id=40001 stun=false stun_port=3478
upgrade=false dry_run=false
fail() {
  if [ "${restore_upgrade:-false}" = true ]; then rollback_installation; restore_upgrade=false; fi
  printf '%s\n' "$1" >&2
  exit 1
}
usage() {
  printf '%s\n' 'Usage: install-private-relay.sh --control-url HTTPS_ROOT --hostname PUBLIC_HOST [--port 9091] [--region-id 40001] [--stun] [--stun-port 3478] [--control-ca-file PUBLIC_CA] [--token-file PRIVATE_FILE] [--upgrade] [--dry-run]'
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --control-url|--hostname|--port|--region-id|--stun-port|--token-file|--control-ca-file)
      [ "$#" -ge 2 ] || fail 'missing option value'
      case "$1" in
        --control-url) control_url=$2 ;; --hostname) hostname=$2 ;; --port) port=$2 ;;
        --region-id) region_id=$2 ;; --stun-port) stun_port=$2 ;; --token-file) token_file=$2 ;;
        --control-ca-file) ca_file=$2 ;;
      esac
      shift 2 ;;
    --stun) stun=true; shift ;; --upgrade) upgrade=true; shift ;; --dry-run) dry_run=true; shift ;;
    --help|-h) usage; exit 0 ;; *) fail 'unsupported option' ;;
  esac
done
for command in python3 curl sha256sum install stat mktemp; do command -v "$command" >/dev/null || fail 'required installation tools are missing'; done
[ "$(uname -s)" = Linux ] || fail 'this installer supports Linux systemd only'
case "$(uname -m)" in x86_64|amd64) architecture=amd64 ;; aarch64|arm64) architecture=arm64 ;; armv7l) architecture=armv7 ;; *) fail 'unsupported server architecture' ;; esac

# 参数只传公共配置；凭据不进 argv、URL 或诊断输出。
python3 - "$control_url" "$hostname" "$port" "$region_id" "$stun_port" <<'PY'
import ipaddress, re, sys
from urllib.parse import urlsplit
try:
    origin = urlsplit(sys.argv[1])
    assert '%' not in sys.argv[1] and '%' not in sys.argv[2]
    assert origin.scheme == 'https' and origin.hostname and origin.username is None and origin.password is None
    assert origin.path in ('', '/') and not origin.query and not origin.fragment and not origin.netloc.endswith(':')
    assert '?' not in sys.argv[1] and '#' not in sys.argv[1]
    if origin.port is not None: assert 0 < origin.port <= 65535
    def host(value):
        try: ipaddress.ip_address(value); return
        except ValueError: pass
        assert len(value) <= 253 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part) for part in value.split('.'))
    host(origin.hostname); host(sys.argv[2])
    for value in sys.argv[3:]: assert re.fullmatch(r'[0-9]{1,10}', value)
    assert 0 < int(sys.argv[3]) <= 65535 and 0 < int(sys.argv[4]) <= 2147483647 and 0 < int(sys.argv[5]) <= 65535
except Exception:
    raise SystemExit('invalid public installation configuration')
PY
control_url=${control_url%/}
asset="xunara-relay_linux_$architecture"
base="https://github.com/xunara-net/xunara-relay/releases/download/$release_version"
if [ "$dry_run" = true ]; then
  printf 'Validated Linux %s installation, version %s, port %s; no files changed and no credential read.\n' "$architecture" "$release_version" "$port"
  exit 0
fi
[ "$(id -u)" = 0 ] || fail 'run this installer with sudo'
for command in systemctl useradd getent openssl; do command -v "$command" >/dev/null || fail 'Linux systemd and certificate tools are required'; done
root=/opt/xunara-private-relay
state=/var/lib/xunara-private-relay
config=/etc/xunara-private-relay
unit=/etc/systemd/system/xunara-private-relay.service
identity="$state/relay-identity.json"
for directory in "$root" "$state" "$config"; do [ ! -L "$directory" ] || fail 'installation directory must not be a symlink'; done
for file in "$unit" "$root/xunara-relay" "$root/xunara-relay.previous" "$config/enrollment.env" "$config/control-ca.pem" "$unit.d" "$unit.d/control-ca.conf"; do
  [ ! -L "$file" ] || fail 'installation files must not be symlinks'
done
if [ -e "$unit" ]; then
  [ "$upgrade" = true ] || fail 'private relay already installed; use --upgrade without changing its configuration'
  [ -z "$token_file" ] || fail 'upgrade uses the existing identity, not an enrollment token'
  [ -f "$unit" ] && [ -f "$root/xunara-relay" ] || fail 'existing service or binary is missing'
  [ "$(stat -c '%u:%a' "$config/install.json")" = '0:600' ] || fail 'existing installation record must be private and root-owned'
  [ -f "$config/install.json" ] && [ ! -L "$config/install.json" ] || fail 'existing installation record is missing'
  [ -f "$identity" ] && [ ! -L "$identity" ] || fail 'existing relay identity is missing; do not re-enroll automatically'
  python3 - "$config/install.json" "$identity" "$control_url" "$hostname" "$port" "$region_id" "$stun" "$stun_port" <<'PY'
import json, sys
try:
    settings = json.load(open(sys.argv[1])); identity = json.load(open(sys.argv[2]))
    assert identity.get('relay_id') and identity.get('relay_token') and identity.get('control_url') == sys.argv[3]
    expected = dict(control_url=sys.argv[3], hostname=sys.argv[4], port=int(sys.argv[5]), region_id=int(sys.argv[6]), stun=sys.argv[7]=='true', stun_port=int(sys.argv[8]))
    assert settings == expected
except Exception: raise SystemExit('existing identity or public configuration differs; upgrade cannot reset it')
PY
elif [ -e "$identity" ] || [ -e "$state" ] || [ -e "$root" ] || [ -e "$config" ]; then
  fail 'unrecognized existing state; inspect it instead of overwriting'
fi

work=$(mktemp -d)
restore_upgrade=false
rollback_installation() {
  if [ "$restore_upgrade" = true ]; then
    # 升级失败连同进程专用 CA 一起恢复，不重置身份、证书或配置高水位。
    systemctl stop xunara-private-relay || true
    install -m 0755 "$work/previous-binary" "$root/xunara-relay"
    if [ -f "$work/previous-control-ca.pem" ]; then
      install -m 0644 "$work/previous-control-ca.pem" "$config/control-ca.pem"
    else
      rm -f -- "$config/control-ca.pem"
    fi
    if [ -f "$work/previous-control-ca.conf" ]; then
      install -m 0644 "$work/previous-control-ca.conf" "$unit.d/control-ca.conf"
    else
      rm -f -- "$unit.d/control-ca.conf"
    fi
    systemctl daemon-reload || true
    systemctl start xunara-private-relay || true
  fi
}
trap 'rollback_installation; rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 "$base/$asset" -o "$work/$asset"
curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 "$base/SHA256SUMS" -o "$work/SHA256SUMS"
expected=$(awk -v asset="$asset" '$2 == asset { print $1 }' "$work/SHA256SUMS")
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail 'release checksum is missing or ambiguous'
(cd "$work"; printf '%s  %s\n' "$expected" "$asset" | sha256sum --check --status -) || fail 'binary checksum verification failed'
chmod 0700 "$work/$asset"
[ "$("$work/$asset" -version)" = "xunara-relay $release_version" ] || fail 'binary release version differs'

if [ -n "$ca_file" ]; then
  [ -f "$ca_file" ] && [ ! -L "$ca_file" ] || fail 'provide a verified public CA certificate file'
  ! grep -q 'PRIVATE KEY' "$ca_file" || fail 'never provide a private key as a CA file'
  openssl x509 -in "$ca_file" -noout -text >"$work/ca-description"
  grep -q 'CA:TRUE' "$work/ca-description" || fail 'provided certificate is not a CA'
  openssl x509 -in "$ca_file" -out "$work/control-ca.pem"
fi
if [ "$upgrade" = false ]; then
  if [ -n "$token_file" ]; then
    [ -f "$token_file" ] && [ ! -L "$token_file" ] || fail 'enrollment token file must be a regular private file'
    [ "$(stat -c '%u:%a' "$token_file")" = '0:600' ] || fail 'enrollment token file must be root-owned with mode 0600'
    [ "$(stat -c '%s' "$token_file")" -le 512 ] || fail 'enrollment token file is too large'
    token=$(cat "$token_file")
  else
    IFS= read -r -s -p '请输入一次性中继接入令牌（输入隐藏）: ' token </dev/tty || fail 'unable to read enrollment token'
    printf '\n' >/dev/tty
  fi
  [[ "$token" =~ ^xrelay-enroll-[a-zA-Z2-7]+$ ]] || fail 'enrollment token format invalid'
fi

if ! getent passwd xunara-private-relay >/dev/null; then
  useradd --system --user-group --home-dir "$state" --no-create-home --shell /usr/sbin/nologin xunara-private-relay
fi
[ "$(id -u xunara-private-relay)" != 0 ] || fail 'relay service user must not be root'
[ "$(getent passwd xunara-private-relay | cut -d: -f6)" = "$state" ] || fail 'existing service user has a different home directory'
if [ "$upgrade" = true ]; then
  [ "$(stat -c '%u:%a' "$identity")" = "$(id -u xunara-private-relay):600" ] || fail 'existing relay identity must be private and owned by its service user'
fi
install -d -m 0755 -o root -g root "$root"
install -d -m 0750 -o root -g xunara-private-relay "$config"
install -d -m 0700 -o xunara-private-relay -g xunara-private-relay "$state"
if [ "$upgrade" = true ]; then
  install -m 0700 "$root/xunara-relay" "$work/previous-binary"
  install -m 0700 "$root/xunara-relay" "$root/xunara-relay.previous"
  if [ -f "$config/control-ca.pem" ]; then install -m 0600 "$config/control-ca.pem" "$work/previous-control-ca.pem"; fi
  if [ -f "$unit.d/control-ca.conf" ]; then install -m 0600 "$unit.d/control-ca.conf" "$work/previous-control-ca.conf"; fi
fi
install -m 0755 "$work/$asset" "$root/xunara-relay.new"
if [ "$upgrade" = true ]; then restore_upgrade=true; systemctl stop xunara-private-relay; fi
mv "$root/xunara-relay.new" "$root/xunara-relay"
if [ "$upgrade" = false ]; then
  printf 'XUNARA_RELAY_TOKEN=%s\n' "$token" >"$config/enrollment.env"
  chmod 0600 "$config/enrollment.env"
  unset token
  python3 - "$config/install.json" "$control_url" "$hostname" "$port" "$region_id" "$stun" "$stun_port" <<'PY'
import json, sys
with open(sys.argv[1], 'x') as output:
    json.dump(dict(control_url=sys.argv[2], hostname=sys.argv[3], port=int(sys.argv[4]), region_id=int(sys.argv[5]), stun=sys.argv[6]=='true', stun_port=int(sys.argv[7])), output)
PY
  chmod 0600 "$config/install.json"
  cat >"$unit" <<EOF
[Unit]
Description=Xunara private relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=xunara-private-relay
Group=xunara-private-relay
EnvironmentFile=$config/enrollment.env
ExecStart=$root/xunara-relay -control-url $control_url -enroll-token-env XUNARA_RELAY_TOKEN -state-dir $state -hostname $hostname -listen :$port -region-id $region_id -region-code private -region-name "私有中继" -relay-visibility private -cert-mode selfsigned -stun=$stun -stun-port $stun_port
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$state
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$unit"
fi
if [ -f "$work/control-ca.pem" ]; then
  install -m 0644 "$work/control-ca.pem" "$config/control-ca.pem"
  install -d -m 0755 "$unit.d"
  printf '[Service]\nEnvironment=SSL_CERT_FILE=%s/control-ca.pem\n' "$config" >"$unit.d/control-ca.conf"
fi
systemctl daemon-reload
if ! systemctl enable --now xunara-private-relay; then
  fail 'private relay startup failed; existing identity was not reset'
fi
health_host=$hostname
if [[ "$hostname" == *:* ]]; then health_host="[$hostname]"; fi
for ((attempt = 1; attempt <= 60; attempt++)); do
  if [ -f "$identity" ] && [ -f "$state/selfsigned.crt" ] && systemctl is-active --quiet xunara-private-relay && \
    curl --noproxy '*' --connect-to "$health_host:$port:127.0.0.1:$port" --cacert "$state/selfsigned.crt" \
      --connect-timeout 2 --max-time 3 -fsS "https://$health_host:$port/derp/probe" >/dev/null 2>"$work/local-probe-error"; then
    python3 - "$identity" "$control_url" <<'PY'
import json, sys
identity = json.load(open(sys.argv[1]))
assert identity.get('relay_id') and identity.get('relay_token') and identity.get('control_url') == sys.argv[2]
PY
    # 已接入后清掉复制的短期令牌；长期身份与配置高水位仍保留。
    : >"$config/enrollment.env"
    restore_upgrade=false
    printf '私有中继已安装到独立服务 xunara-private-relay；请确认防火墙并在用户中心检测公网可达性。\n'
    exit 0
  fi
  sleep 1
done
fail 'enrollment not confirmed; inspect service locally without sharing credential files; existing identity was not reset'
