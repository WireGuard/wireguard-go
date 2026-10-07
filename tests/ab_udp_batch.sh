#!/usr/bin/env bash
# A/B Darwin UDP bind batching on real utun (utun batching stays on).
# Usage: ./tests/ab_udp_batch.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TIME="${TIME:-10}"
PARALLEL="${PARALLEL:-2}"
RUNS="${RUNS:-3}"
OUT="${OUT:-$ROOT/udp-batch-ab.txt}"

echo "==> building wireguard-go"
go build -o "$ROOT/wireguard-go" .

pkill -f "$ROOT/wireguard-go" 2>/dev/null || true
sleep 0.5

{
  echo "UDP batch A/B — TIME=${TIME}s PARALLEL=${PARALLEL} RUNS=${RUNS} --udp"
  echo "utun batching: ON for both; only WG_UDP_BATCH toggled"
  echo
} | tee "$OUT"

run_mode() {
  local mode="$1" # on|off
  local batch_env
  if [[ "$mode" == "on" ]]; then
    batch_env=1
  else
    batch_env=0
  fi
  echo "=== UDP batch ${mode} (WG_UDP_BATCH=${batch_env}) ===" | tee -a "$OUT"
  local i
  for i in $(seq 1 "$RUNS"); do
    echo "--- run $i/$RUNS ---" | tee -a "$OUT"
    set +e
    WG_BIN="$ROOT/wireguard-go" WG_UDP_BATCH="$batch_env" TIME="$TIME" PARALLEL="$PARALLEL" \
      ./tests/mac_utun_bench.sh --udp 2>&1 | tee -a "$OUT" | tee "/tmp/wg-ab-${mode}-${i}.log"
    local rc=${PIPESTATUS[0]}
    set -e
    # iperf3 summary lines
    rg -n "sender|receiver|bit/s|Done|error" "/tmp/wg-ab-${mode}-${i}.log" | tee -a "$OUT" || true
    if [[ "$rc" -ne 0 ]]; then
      echo "warning: bench exit $rc for mode=$mode run=$i" | tee -a "$OUT"
    fi
    sleep 1
  done
  echo | tee -a "$OUT"
}

run_mode off
run_mode on

echo "==> extracting receiver bitrates"
python3 - "$OUT" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
# iperf3 UDP receiver lines often look like:
# [SUM]  0.00-10.00 sec  ... Mbits/sec  ...
# or non-SUM single-stream receiver line with "receiver"
mode = None
rows = []
for line in text.splitlines():
    if line.startswith("=== UDP batch"):
        mode = "on" if " on " in line or line.endswith(" on ===") or "batch on" in line else "off"
        if "batch on" in line: mode = "on"
        if "batch off" in line: mode = "off"
        continue
    # Prefer SUM receiver, else any receiver bitrate
    m = re.search(r"\[SUM\].*?([\d.]+)\s+([GMK]?)bits/sec.*?receiver", line)
    if not m:
        m = re.search(r"\]\s+[\d.-]+\s+sec.*?([\d.]+)\s+([GMK]?)bits/sec.*?receiver", line)
    if m and mode:
        val = float(m.group(1))
        unit = m.group(2)
        mult = {"":1, "K":1e-3, "M":1, "G":1e3}[unit]
        # normalize to Mbits/sec
        if unit == "G":
            mbps = val * 1000
        elif unit == "K":
            mbps = val / 1000
        elif unit == "":
            mbps = val / 1e6
        else:
            mbps = val
        rows.append((mode, mbps, line.strip()))

from statistics import mean, pstdev
for mode in ("off", "on"):
    vals = [v for m,v,_ in rows if m == mode]
    print(f"UDP batch {mode}: n={len(vals)} values={['%.1f'%v for v in vals]}")
    if vals:
        print(f"  mean={mean(vals):.1f} Mbits/sec  stdev={pstdev(vals) if len(vals)>1 else 0:.1f}")
if any(m=="off" for m,_,__ in rows) and any(m=="on" for m,_,__ in rows):
    off = mean([v for m,v,_ in rows if m=="off"])
    on = mean([v for m,v,_ in rows if m=="on"])
    if off:
        print(f"speedup: {on/off:.3f}x  ({(on-off)/off*100:+.1f}%)")
PY

echo "full log: $OUT"
