#!/usr/bin/env bash
# Benchmark real utun datapath on macOS with two wireguard-go processes + iperf3.
#
# Topology (loopback UDP endpoints):
#
#   iperf3 -c 10.66.66.2  →  utunA (10.66.66.1)  ⇄  UDP 127.0.0.1  ⇄  utunB (10.66.66.2)  →  iperf3 -s
#
# Usage (from repo root):
#   ./tests/mac_utun_bench.sh
#   WG_BIN=./wireguard-go TIME=30 PARALLEL=4 ./tests/mac_utun_bench.sh
#   ./tests/mac_utun_bench.sh --udp
#   ./tests/mac_utun_bench.sh --udp -b 30M
#   BANDWIDTH=30M ./tests/mac_utun_bench.sh --udp
#
# CPU flame graphs (real Darwin utun + UDP):
#   PROFILE=1 TIME=20 PARALLEL=2 ./tests/mac_utun_bench.sh --udp
#   open ./utun-bench-a-flame.html
#
# Requires: sudo, wireguard-tools (wg), iperf3, Go (to build if WG_BIN missing).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TIME="${TIME:-10}"
PARALLEL="${PARALLEL:-4}"
UDP=0
# UDP target bitrate for iperf3 -b (default 0 = as fast as possible).
BANDWIDTH="${BANDWIDTH:-0}"
MTU="${MTU:-1420}"
PROFILE="${PROFILE:-0}"
PROFILE_OUT="${PROFILE_OUT:-$ROOT}"
# Optional overrides; default is listen-port 0 (kernel-chosen ephemeral).
PORT_A="${PORT_A:-0}"
PORT_B="${PORT_B:-0}"
# Use a less common /30 so we don't collide with other local tunnels.
IP_A="${IP_A:-10.77.77.1}"
IP_B="${IP_B:-10.77.77.2}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script is for macOS (real utun)" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "==> re-running under sudo (utun requires root)"
  exec sudo --preserve-env=WG_BIN,TIME,PARALLEL,BANDWIDTH,MTU,PORT_A,PORT_B,IP_A,IP_B,KEEP,LOG_LEVEL,WG_UDP_BATCH,PROFILE,PROFILE_OUT,PATH,HOME "$0" "$@"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --udp) UDP=1 ;;
    -b|--bandwidth)
      if [[ $# -lt 2 ]]; then
        echo "error: $1 requires a value (e.g. 30M, 1G, 0)" >&2
        exit 1
      fi
      BANDWIDTH="$2"
      shift
      ;;
    -b=*|--bandwidth=*)
      BANDWIDTH="${1#*=}"
      ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 1
      ;;
  esac
  shift
done

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: missing '$1'. Try: brew install $2" >&2
    exit 1
  }
}
need wg wireguard-tools
need iperf3 iperf3

WG_BIN="${WG_BIN:-$ROOT/wireguard-go}"
if [[ "$PROFILE" == "1" || ! -x "$WG_BIN" ]]; then
  echo "==> building wireguard-go"
  (cd "$ROOT" && go build -o "$WG_BIN" .)
fi

PROF_A=""
PROF_B=""
if [[ "$PROFILE" == "1" ]]; then
  mkdir -p "$PROFILE_OUT"
  PROF_A="$PROFILE_OUT/utun-bench-a.prof"
  PROF_B="$PROFILE_OUT/utun-bench-b.prof"
  rm -f "$PROF_A" "$PROF_B"
  echo "==> CPU profiling enabled -> $PROF_A / $PROF_B"
fi

TMP="$(mktemp -d /tmp/wg-mac-bench.XXXXXX)"
NAME_A="$TMP/name_a"
NAME_B="$TMP/name_b"
LOG_A="$TMP/a.log"
LOG_B="$TMP/b.log"
KEY_A="$TMP/a.key"
KEY_B="$TMP/b.key"
PUB_A="$TMP/a.pub"
PUB_B="$TMP/b.pub"
PID_A=""
PID_B=""
IF_A=""
IF_B=""
IPERF_PID=""

cleanup() {
  set +e
  [[ -n "$IPERF_PID" ]] && kill "$IPERF_PID" 2>/dev/null
  [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null
  [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null
  wait "$PID_A" "$PID_B" "$IPERF_PID" 2>/dev/null
  # Removing the UAPI socket asks wireguard-go to exit if still alive.
  [[ -n "$IF_A" ]] && rm -f "/var/run/wireguard/${IF_A}.sock"
  [[ -n "$IF_B" ]] && rm -f "/var/run/wireguard/${IF_B}.sock"
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo "kept workdir: $TMP"
  else
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT

echo "==> generating keys"
wg genkey | tee "$KEY_A" | wg pubkey >"$PUB_A"
wg genkey | tee "$KEY_B" | wg pubkey >"$PUB_B"

echo "==> starting wireguard-go peers"
echo "    WG_UDP_BATCH=${WG_UDP_BATCH:-1 (default on)}"
WG_TUN_NAME_FILE="$NAME_A" LOG_LEVEL="${LOG_LEVEL:-error}" \
  WG_UDP_BATCH="${WG_UDP_BATCH:-}" \
  WG_CPUPROFILE="${PROF_A}" \
  "$WG_BIN" -f utun >"$LOG_A" 2>&1 &
PID_A=$!
WG_TUN_NAME_FILE="$NAME_B" LOG_LEVEL="${LOG_LEVEL:-error}" \
  WG_UDP_BATCH="${WG_UDP_BATCH:-}" \
  WG_CPUPROFILE="${PROF_B}" \
  "$WG_BIN" -f utun >"$LOG_B" 2>&1 &
PID_B=$!

# Wait for interface names to appear.
for _ in $(seq 1 50); do
  [[ -s "$NAME_A" && -s "$NAME_B" ]] && break
  if ! kill -0 "$PID_A" 2>/dev/null || ! kill -0 "$PID_B" 2>/dev/null; then
    echo "error: wireguard-go exited early" >&2
    echo "---- peer A log ----"; cat "$LOG_A" || true
    echo "---- peer B log ----"; cat "$LOG_B" || true
    exit 1
  fi
  sleep 0.1
done
IF_A="$(tr -d '[:space:]' <"$NAME_A")"
IF_B="$(tr -d '[:space:]' <"$NAME_B")"
if [[ -z "$IF_A" || -z "$IF_B" ]]; then
  echo "error: failed to learn utun names (is WG_TUN_NAME_FILE supported?)" >&2
  cat "$LOG_A" "$LOG_B" || true
  exit 1
fi
echo "    peer A: $IF_A"
echo "    peer B: $IF_B"

echo "==> configuring WireGuard + addresses"
# Bind first (port 0 => ephemeral), then learn real ports and set endpoints.
# Fixed 51820/51821 often hit "Address already in use" from leftover daemons.
if ! wg set "$IF_A" \
  listen-port "$PORT_A" \
  private-key "$KEY_A" \
  peer "$(cat "$PUB_B")" \
  allowed-ips "${IP_B}/32"; then
  echo "error: wg set $IF_A failed (port in use?). Try: sudo pkill wireguard-go" >&2
  exit 1
fi
if ! wg set "$IF_B" \
  listen-port "$PORT_B" \
  private-key "$KEY_B" \
  peer "$(cat "$PUB_A")" \
  allowed-ips "${IP_A}/32"; then
  echo "error: wg set $IF_B failed (port in use?). Try: sudo pkill wireguard-go" >&2
  exit 1
fi

PORT_A="$(wg show "$IF_A" listen-port)"
PORT_B="$(wg show "$IF_B" listen-port)"
echo "    UDP ports: A=$PORT_A B=$PORT_B"

wg set "$IF_A" peer "$(cat "$PUB_B")" endpoint "127.0.0.1:${PORT_B}"
wg set "$IF_B" peer "$(cat "$PUB_A")" endpoint "127.0.0.1:${PORT_A}"

ifconfig "$IF_A" inet "$IP_A" "$IP_B" mtu "$MTU" up
ifconfig "$IF_B" inet "$IP_B" "$IP_A" mtu "$MTU" up

echo "==> waiting for handshake"
ok=0
for _ in $(seq 1 50); do
  if ping -c 1 -W 1000 "$IP_B" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.1
done
if [[ "$ok" -ne 1 ]]; then
  echo "error: ping ${IP_B} failed" >&2
  wg show
  echo "---- peer A log ----"; cat "$LOG_A" || true
  echo "---- peer B log ----"; cat "$LOG_B" || true
  exit 1
fi
wg show

echo "==> starting iperf3 server on ${IP_B}"
iperf3 -s -1 -B "$IP_B" >"$TMP/iperf-server.log" 2>&1 &
IPERF_PID=$!
for _ in $(seq 1 50); do
  if kill -0 "$IPERF_PID" 2>/dev/null; then
    # server is up once it binds; give it a beat
    sleep 0.2
    break
  fi
  sleep 0.1
done

echo "==> running iperf3 client → ${IP_B} (time=${TIME}s parallel=${PARALLEL} udp=${UDP} bandwidth=${BANDWIDTH})"
set +e
if [[ "$UDP" -eq 1 ]]; then
  iperf3 -c "$IP_B" -B "$IP_A" -u -b "$BANDWIDTH" -t "$TIME" -P "$PARALLEL" | tee "$TMP/iperf-client.log"
else
  iperf3 -c "$IP_B" -B "$IP_A" -t "$TIME" -P "$PARALLEL" | tee "$TMP/iperf-client.log"
fi
rc=$?
set -e

echo
echo "Done (iperf exit=${rc})."
echo "  interfaces: $IF_A <-> $IF_B"
echo "  set KEEP=1 to preserve logs under $TMP"

# UDP batch occupancy (need LOG_LEVEL=debug). Peer B is the iperf server side.
# Print each histogram in full (until max_batch_size= footer), not a fixed -A window.
dump_udp_recv_hist() {
  awk '
    /UDP recv/ { printing=1 }
    printing {
      print
      if ($0 ~ /max_batch_size=/) { print ""; printing=0 }
    }
  ' "$1"
}
if grep -q 'UDP recv' "$LOG_A" "$LOG_B" 2>/dev/null; then
  echo
  echo "==> UDP recv batch stats (1s windows)"
  echo "---- peer A (client / ${IP_A}) ----"
  dump_udp_recv_hist "$LOG_A"
  echo "---- peer B (server / ${IP_B}) ----"
  dump_udp_recv_hist "$LOG_B"
else
  echo
  echo "  tip: re-run with LOG_LEVEL=debug to print UDP recv batch sizes"
fi

if [[ "$PROFILE" == "1" ]]; then
  set +e
  [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null
  [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null
  wait "$PID_A" "$PID_B" 2>/dev/null
  PID_A=""
  PID_B=""
  set -e
  sleep 0.3

  write_flame_html() {
    local peer="$1" prof="$2" html="$3" port="$4"
    if [[ ! -s "$prof" ]]; then
      echo "warning: empty profile $prof (peer $peer)" >&2
      return 0
    fi
    echo "==> writing flame graph -> $html"
    go tool pprof -top -nodecount=30 "$WG_BIN" "$prof" | tee "${prof%.prof}-top.txt"
    go tool pprof -http="127.0.0.1:${port}" -no_browser "$WG_BIN" "$prof" >/dev/null 2>&1 &
    local ppid=$!
    local ok=0
    for _ in $(seq 1 50); do
      if curl -sf "http://127.0.0.1:${port}/ui/flamegraph" -o "$html"; then
        ok=1
        break
      fi
      sleep 0.1
    done
    kill "$ppid" 2>/dev/null || true
    wait "$ppid" 2>/dev/null || true
    if [[ "$ok" -ne 1 ]]; then
      echo "warning: failed to fetch flame graph for peer $peer" >&2
      echo "  try: go tool pprof -http=:8080 \"$WG_BIN\" \"$prof\"" >&2
    fi
  }

  write_flame_html a "$PROF_A" "$PROFILE_OUT/utun-bench-a-flame.html" 18081
  write_flame_html b "$PROF_B" "$PROFILE_OUT/utun-bench-b-flame.html" 18082
  echo "  profiles: $PROF_A / $PROF_B"
  echo "  flames:   $PROFILE_OUT/utun-bench-a-flame.html / $PROFILE_OUT/utun-bench-b-flame.html"
  echo "  open \"$PROFILE_OUT/utun-bench-a-flame.html\""
fi

exit "$rc"
