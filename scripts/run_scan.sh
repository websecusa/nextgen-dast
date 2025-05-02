#!/usr/bin/env bash
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
# Wrapper: spawn a per-scan mitmdump (forward proxy), then run the scanner
# with HTTP(S)_PROXY pointed at it. When the scanner exits the proxy is killed
# automatically — so the lifecycle stays bound to a single tracked PID.
#
# Usage:
#   run_scan.sh <scan_dir> <proxy_port> -- <scanner_cmd...>
#
# Files written under <scan_dir>:
#   flows/<flowid>_request.txt
#   flows/<flowid>_response.txt
#   flows.jsonl
#   proxy.log
set -euo pipefail

SCAN_DIR=$1
PROXY_PORT=$2
shift 2
[[ "${1:-}" == "--" ]] || { echo "expected -- separator before scanner cmd" >&2; exit 2; }
shift

mkdir -p "$SCAN_DIR/flows"

mitmdump \
    --mode regular \
    --listen-host 127.0.0.1 \
    --listen-port "$PROXY_PORT" \
    -s /app/proxy_addon.py \
    --set "flows_dir=$SCAN_DIR/flows" \
    --set "flow_log_path=$SCAN_DIR/flows.jsonl" \
    --set ssl_insecure=true \
    --set termlog_verbosity=warn \
    > "$SCAN_DIR/proxy.log" 2>&1 &
PROXY_PID=$!

cleanup() {
    if kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null || true
        # let it flush + close files
        for _ in 1 2 3 4 5; do
            kill -0 "$PROXY_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$PROXY_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# wait for proxy port to come up (up to ~5 s)
for i in $(seq 1 25); do
    if (echo > "/dev/tcp/127.0.0.1/$PROXY_PORT") 2>/dev/null; then break; fi
    sleep 0.2
done

export HTTP_PROXY="http://127.0.0.1:$PROXY_PORT"
export HTTPS_PROXY="http://127.0.0.1:$PROXY_PORT"
export http_proxy="http://127.0.0.1:$PROXY_PORT"
export https_proxy="http://127.0.0.1:$PROXY_PORT"

"$@"
