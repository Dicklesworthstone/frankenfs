#!/bin/bash
# Per-DAEMON-THREAD CPU during the create phase. Distinguishes "dispatch is still
# serial" (one thread has all the CPU) from "the work is lock-serialized" (CPU is
# spread across workers but still sums to ~one core).
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
FM=/home/ubuntu/pmeta-fa
FENV=${FENV:-}
TAG=${TAG:-thr}
fusermount3 -u "$FM" 2>/dev/null || true
mkdir -p "$FM"
cp "$W/pimg-base.ext4" "$W/pimg-fa.ext4"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn $FENV \
  taskset -c 8-15 "$ELF" mount --rw "$W/pimg-fa.ext4" "$FM" >> "$W/pfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 200); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
"$W/pmeta_ab" 1 4096 8 8 0 f="$FM" >/dev/null 2>&1

python3 - "$FPID" "$W" "$FM" <<'PY'
import os, subprocess, sys, time
pid, W, FM = sys.argv[1], sys.argv[2], sys.argv[3]
def snap():
    out = {}
    for t in os.listdir(f"/proc/{pid}/task"):
        try:
            s = open(f"/proc/{pid}/task/{t}/stat").read()
            f = s[s.rindex(")") + 2:].split()
            name = open(f"/proc/{pid}/task/{t}/comm").read().strip()
            out[t] = (name, int(f[11]) + int(f[12]))
        except OSError:
            pass
    return out
before = snap()
t0 = time.monotonic()
subprocess.run([f"{W}/pmeta_ab", "6", "4096", "8", "8", "0", f"f={FM}"],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
wall = time.monotonic() - t0
after = snap()
hz = os.sysconf("SC_CLK_TCK")
tot = 0.0
rows = []
for t, (name, ticks) in after.items():
    d = ticks - before.get(t, (name, 0))[1]
    if d:
        rows.append((d / hz, name, t))
        tot += d / hz
rows.sort(reverse=True)
print(f"wall={wall:.3f}s  daemon_cpu_total={tot:.3f}s  cores_used={tot/wall:.2f}")
for cpu, name, t in rows:
    print(f"  tid={t:<8s} {name:<16s} cpu={cpu:.3f}s  {100*cpu/max(tot,1e-9):5.1f}% of daemon  {100*cpu/wall:5.1f}% of one core")
PY
fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true
