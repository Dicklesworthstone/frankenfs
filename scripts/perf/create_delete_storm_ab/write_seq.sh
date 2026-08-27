#!/bin/bash
# Capture the DEVICE WRITE SEQUENCE (offset, length, barrier) a daemon emits for a
# fixed workload, so two configurations can be diffed byte-for-byte.
#
# Crash consistency is a function of WHAT is written, in WHAT ORDER, with barriers
# WHERE. If two configurations emit an identical sequence, neither can differ in
# crash behaviour — which is a sharper and far cheaper gate than crash injection for
# levers that are not supposed to touch ordering at all.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
OPS=${OPS:-200}
FENV=${FENV:-}
OUT=${OUT:?set OUT to the sequence file to write}
FM=/home/ubuntu/ws-fa
TAG=${TAG:-ws}
LOOPS=""
cleanup() {
  fusermount3 -u "$FM" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/simg-base.ext4" "$W/simg-ws.ext4"
DEV=$(sudo -n losetup --find --show --direct-io=on "$W/simg-ws.ext4")
LOOPS="$DEV"
sudo -n chown "$(id -u)" "$DEV"

# shellcheck disable=SC2086
env RUST_LOG=warn $FENV taskset -c 18 "$ELF" mount --rw "$DEV" "$FM" \
  >> "$W/wsfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }

sudo -n strace -f -p "$FPID" -e trace=pwrite64,pwritev,fdatasync,fsync \
  -o "$W/wsraw-$TAG.txt" &
SPID=$!
sleep 1
"$W/storm_ab" 1 "$OPS" 8 0 "f=$FM" >/dev/null 2>&1
sleep 1
sudo -n kill -INT "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true
sudo -n chown "$(id -u)" "$W/wsraw-$TAG.txt" 2>/dev/null || true
fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true

# Normalise to "W <len> <offset>" / "BARRIER", dropping pids and payload bytes.
python3 - "$W/wsraw-$TAG.txt" "$OUT" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
wr = re.compile(r'pwrite64\(\d+, .*, (\d+), (\d+)\)\s*=\s*\d+')
out = []
for line in open(src, errors="replace"):
    m = wr.search(line)
    if m:
        out.append(f"W {m.group(1)} {m.group(2)}")
    elif "fdatasync(" in line or "fsync(" in line:
        out.append("BARRIER")
open(dst, "w").write("\n".join(out) + "\n")
print(f"{dst}: {len(out)} events ({sum(1 for x in out if x=='BARRIER')} barriers)")
PY
