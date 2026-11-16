#!/usr/bin/env bash
# Start pcap-analyzer with start-pcap-analyzer.py as the README says, then walk through it with tools/smoke.py.
#   check_install.sh local                  on this host, with its python3
#   check_install.sh image IMAGE            in that image without network, with the bundled Python
#   check_install.sh image IMAGE system     in that image without network, with the image's own python3,
#                                           which also unpacks the bundle there
# PCAP_ANALYZER_PORT changes the port.
set -euo pipefail

ROOT=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
PORT=${PCAP_ANALYZER_PORT:-8000}
WORK=$(mktemp -d)
PASSWORD=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
export PCAP_ANALYZER_SMOKE_PASSWORD=$PASSWORD

die() { echo "error: $*" >&2; exit 1; }

app_copy() {
  mkdir "$WORK/app"
  (cd "$ROOT" && tar cf - --exclude=./runtime --exclude=./data --exclude=./pcap-analyzer.env --exclude=./pcap-analyzer.log \
    --exclude=./pcap-analyzer.pid --exclude=./.git --exclude=./samples .) | tar xf - -C "$WORK/app"
  # A password for the walk. Without one, the first sign-in would be admin / admin and ask for a new password.
  printf 'PCAP_ANALYZER_ADMIN_PASSWORD=%s\nPCAP_ANALYZER_PORT=%s\n' "$PASSWORD" "$PORT" >"$WORK/app/pcap-analyzer.env"
  python3 "$ROOT/tools/gen_samples.py" "$WORK/samples" >/dev/null
}

local_check() {
  app_copy
  cd "$WORK/app"
  trap 'python3 start-pcap-analyzer.py stop || true; tail -20 pcap-analyzer.log 2>/dev/null || true' ERR
  python3 start-pcap-analyzer.py
  runtime/python/bin/python3 tools/smoke.py "http://127.0.0.1:$PORT" "$WORK/samples/http_scenarios.pcap"
  python3 start-pcap-analyzer.py status
  python3 start-pcap-analyzer.py restart
  python3 start-pcap-analyzer.py stop
}

image_check() {
  local image=${1:?give an image, such as ubuntu:18.04} python=${2:-bundled}
  app_copy
  if [[ $python != system ]]; then
    # The image may have no python3 at all, so the bundled one starts the script. It is unpacked here first.
    (cd "$WORK/app" && python3 start-pcap-analyzer.py cli list >/dev/null)
  fi
  chmod -R a+rX "$WORK"
  docker run --rm --network none --user 1000:1000 --tmpfs /tmp:exec,mode=1777 -e HOME=/tmp -e PCAP_ANALYZER_SMOKE_PASSWORD \
    -e PYTHON_KIND="$python" -e PORT="$PORT" -v "$WORK:/work:ro" "$image" sh -c '
    set -e
    getconf GNU_LIBC_VERSION
    cp -a /work/app /tmp/app
    cd /tmp/app
    if [ "$PYTHON_KIND" = system ]; then PY=python3; rm -rf runtime; else PY=runtime/python/bin/python3; fi
    $PY --version
    $PY start-pcap-analyzer.py || { tail -20 pcap-analyzer.log; exit 1; }
    runtime/python/bin/python3 tools/smoke.py "http://127.0.0.1:$PORT" /work/samples/http_scenarios.pcap
    runtime/tshark/bin/tshark --version | head -1
    runtime/python/bin/python3 -c "import duckdb; print(\"duckdb\", duckdb.__version__)"
    $PY start-pcap-analyzer.py stop'
}

case ${1:-} in
  local) local_check ;;
  image) image_check "${2:-}" "${3:-bundled}" ;;
  *) sed -n '2,7p' "$0"; exit 2 ;;
esac
rm -rf "$WORK"
echo "Install check passed: $*"
