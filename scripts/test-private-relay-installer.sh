#!/usr/bin/env bash
set -euo pipefail

# 只在一次性 Docker 文件系统中执行安装器，绝不改宿主机的服务目录。
if [ "${1:-}" != --container ]; then
  root=$(cd "$(dirname "$0")/.." && pwd)
  work=$(mktemp -d)
  trap 'rm -rf -- "$work"' EXIT
  cd "$root"
  CGO_ENABLED=0 go build -trimpath -ldflags '-X main.version=v0.1.0-preview.2' -o "$work/xunara-relay_linux_amd64" ./cmd/xunara-relay
  docker run --rm --entrypoint bash -v "$root/scripts:/fixture-scripts:ro" -v "$work:/fixture-assets:ro" \
    "${INSTALLER_TEST_IMAGE:-ubuntu:24.04}" /fixture-scripts/test-private-relay-installer.sh --container
  exit 0
fi
[ -f /.dockerenv ] && [ "$(id -u)" = 0 ] || exit 1
if ! command -v python3 >/dev/null || ! command -v openssl >/dev/null || ! command -v curl >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq python3 curl ca-certificates openssl passwd util-linux >/dev/null
fi
umask 077
mkdir /fixture /fixture/bin
cp /fixture-assets/xunara-relay_linux_amd64 /fixture/
(cd /fixture; sha256sum xunara-relay_linux_amd64 > SHA256SUMS)
openssl req -x509 -newkey rsa:2048 -nodes -keyout /fixture/control.key -out /fixture/control-ca.pem \
  -days 1 -subj '/CN=isolated-installer-fixture' -addext 'subjectAltName=IP:127.0.0.1' -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1
python3 - <<'PY'
import base64, os
with open('/fixture/token', 'w') as output:
    output.write('xrelay-enroll-' + base64.b32encode(os.urandom(24)).decode().rstrip('='))
PY
cat >/fixture/control.py <<'PY'
import json, ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
enrollments = 0
class Control(BaseHTTPRequestHandler):
    def log_message(self, *arguments): pass
    def do_POST(self):
        global enrollments
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if self.path == '/api/relay/v1/enroll':
            assert self.headers['Authorization'] == 'Bearer ' + Path('/fixture/token').read_text()
            assert body['hostname'] == '127.0.0.1' and body['region_id'] == 40001
            assert body['cert_name'].startswith('sha256-raw:') and body['visibility'] == 'private'
            enrollments += 1
            Path('/fixture/enrollments').write_text(str(enrollments))
            result = dict(relay_id='isolated-fixture', relay_token='fixture-service-identity', control_url='https://127.0.0.1:9443')
        elif self.path == '/api/relay/v1/heartbeat':
            assert self.headers['Authorization'] == 'Bearer fixture-service-identity'
            result = dict(desired_state='online', config_version='fixture-v1', config_revision=1, bandwidth_limit=0, region_name='')
        else:
            self.send_error(404); return
        encoded = json.dumps(result).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded))); self.end_headers(); self.wfile.write(encoded)
server = HTTPServer(('127.0.0.1', 9443), Control)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/fixture/control-ca.pem', '/fixture/control.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
python3 /fixture/control.py >/fixture/control.log 2>&1 &
cat >/fixture/bin/curl <<'SH'
#!/usr/bin/env bash
set -euo pipefail
original=("$@")
url='' output=''
while [ "$#" -gt 0 ]; do
  case "$1" in -o) output=$2; shift 2 ;; https://github.com/xunara-net/xunara-relay/releases/download/v0.1.0-preview.2/*) url=$1; shift ;; *) shift ;; esac
done
if [ -n "$url" ]; then
  case "$url" in *\?*|*\#*) exit 1 ;; esac
  asset=${url##*/}
  case "$asset" in xunara-relay_linux_amd64|SHA256SUMS) cp "/fixture/$asset" "$output" ;; *) exit 1 ;; esac
else
  exec /usr/bin/curl "${original[@]}"
fi
SH
# CDN 与 systemd 为显式夹具；安装出的 Go 二进制、身份文件和 TLS 探测是真实执行。
cat >/fixture/bin/systemctl <<'PY'
#!/usr/bin/env python3
import os, shlex, signal, subprocess, sys, time
from pathlib import Path
arguments = sys.argv[1:]
assert arguments and (arguments[0]=='daemon-reload' or 'xunara-private-relay' in arguments)
pid_file = Path('/fixture/relay.pid')
if arguments[0]=='daemon-reload': raise SystemExit(0)
if arguments[0]=='stop':
    if pid_file.exists():
        try: os.killpg(int(pid_file.read_text()), signal.SIGTERM)
        except ProcessLookupError: pass
        pid_file.unlink()
        time.sleep(.2)
    raise SystemExit(0)
if arguments[0]=='is-active':
    try: os.kill(int(pid_file.read_text()), 0)
    except (FileNotFoundError, ProcessLookupError): raise SystemExit(1)
    raise SystemExit(0)
if arguments[0]=='enable' and Path('/fixture/fail-start').exists():
    Path('/fixture/fail-start').unlink(); raise SystemExit(1)
assert arguments[0] in ('start', 'enable')
unit = Path('/etc/systemd/system/xunara-private-relay.service').read_text()
command = next(line[len('ExecStart='):] for line in unit.splitlines() if line.startswith('ExecStart='))
environment = dict(os.environ, SSL_CERT_FILE='/etc/xunara-private-relay/control-ca.pem')
for line in Path('/etc/xunara-private-relay/enrollment.env').read_text().splitlines():
    name, value = line.split('=', 1); environment[name] = value
with open('/fixture/relay.log', 'ab') as log:
    process = subprocess.Popen(['runuser', '-u', 'xunara-private-relay', '--'] + shlex.split(command),
        env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
pid_file.write_text(str(process.pid))
PY
chmod 0755 /fixture/bin/*
export PATH=/fixture/bin:$PATH
options=(--control-url https://127.0.0.1:9443 --hostname 127.0.0.1 --port 9444 --region-id 40001 --control-ca-file /fixture/control-ca.pem)
bash /fixture-scripts/install-private-relay.sh "${options[@]}" --token-file /fixture/token >/fixture/install.log 2>&1
identity=/var/lib/xunara-private-relay/relay-identity.json
certificate=/var/lib/xunara-private-relay/selfsigned.crt
before=$(sha256sum "$identity" "$certificate" /var/lib/xunara-private-relay/relay-identity.json.config)
[ "$(stat -c '%a' "$identity")" = 600 ]
[ "$(stat -c '%a' /var/lib/xunara-private-relay)" = 700 ]
[ ! -s /etc/xunara-private-relay/enrollment.env ]
[ "$(cat /fixture/enrollments)" = 1 ]
bash /fixture-scripts/install-private-relay.sh "${options[@]}" --upgrade >/fixture/upgrade.log 2>&1
[ "$before" = "$(sha256sum "$identity" "$certificate" /var/lib/xunara-private-relay/relay-identity.json.config)" ]
[ "$(cat /fixture/enrollments)" = 1 ]
for invalid in 'http://127.0.0.1:9443' 'https://user:secret@control.example' 'https://control.example/?token=fixture'; do
  if bash /fixture-scripts/install-private-relay.sh --control-url "$invalid" --hostname relay.example --dry-run >/fixture/invalid.log 2>&1; then exit 1; fi
done
if bash /fixture-scripts/install-private-relay.sh "${options[@]}" --upgrade --token-file /fixture/token >/fixture/invalid.log 2>&1; then exit 1; fi
original_ca=$(sha256sum /etc/xunara-private-relay/control-ca.pem /etc/systemd/system/xunara-private-relay.service.d/control-ca.conf)
openssl req -x509 -newkey rsa:2048 -nodes -keyout /fixture/other.key -out /fixture/other-ca.pem \
  -days 1 -subj '/CN=isolated-other-ca' >/dev/null 2>&1
touch /fixture/fail-start
if bash /fixture-scripts/install-private-relay.sh --control-url https://127.0.0.1:9443 --hostname 127.0.0.1 --port 9444 \
  --control-ca-file /fixture/other-ca.pem --upgrade >/fixture/failure.log 2>&1; then exit 1; fi
[ "$original_ca" = "$(sha256sum /etc/xunara-private-relay/control-ca.pem /etc/systemd/system/xunara-private-relay.service.d/control-ca.conf)" ]
[ "$before" = "$(sha256sum "$identity" "$certificate" /var/lib/xunara-private-relay/relay-identity.json.config)" ]
[ "$(cat /fixture/enrollments)" = 1 ]
sleep 1
curl --cacert "$certificate" --noproxy '*' --max-time 3 -fsS https://127.0.0.1:9444/derp/probe >/dev/null
if grep -Fq "$(cat /fixture/token)" /fixture/*.log; then exit 1; fi
systemctl stop xunara-private-relay
printf 'PASS: isolated installer, real relay TLS, private files, identity-preserving upgrade, CA rollback, invalid configuration; CDN/systemd/control responses are fixtures.\n'
