#!/bin/bash
# WHERE do our 8 device writes per fsyncdir go? The per-phase census counted 8 write
# I/Os against the kernel's 3 for the same ~1160 sectors; this reads the daemon's
# actual pwrite offsets and lengths so the runs and the gaps between them are known
# rather than guessed.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
OPS=${OPS:-2000}
FM=/home/ubuntu/st-fa
TAG=${TAG:-strace}
LOOPS=""
cleanup() {
  fusermount3 -u "$FM" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/simg-base.ext4" "$W/simg-tr.ext4"
DEV=$(sudo -n losetup --find --show --direct-io=on "$W/simg-tr.ext4")
LOOPS="$DEV"
sudo -n chown "$(id -u)" "$DEV"
echo "loop=$DEV dio=$(cat /sys/block/$(basename "$DEV")/loop/dio)"

env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn taskset -c 18 \
  "$ELF" mount --rw "$DEV" "$FM" >> "$W/stfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
echo "daemon pid $FPID"

# warm: one full batch, untraced
"$W/storm_ab" 1 "$OPS" 8 0 "f=$FM" >/dev/null 2>&1

sudo -n strace -f -p "$FPID" -e trace=pwrite64,pwritev,pwritev2,fdatasync,fsync \
  -o "$W/sttrace-$TAG.txt" &
SPID=$!
sleep 1
"$W/storm_ab" 1 "$OPS" 8 0 "f=$FM" >/dev/null 2>&1
sleep 1
sudo -n kill -INT "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true
sudo -n chown "$(id -u)" "$W/sttrace-$TAG.txt" 2>/dev/null || true

echo "== syscall totals in the traced batch"
grep -c pwrite64 "$W/sttrace-$TAG.txt" || true
grep -c fdatasync "$W/sttrace-$TAG.txt" || true
echo "== the writes bracketing each fdatasync (offset, length), last 40 lines"
grep -E "pwrite64|fdatasync" "$W/sttrace-$TAG.txt" | tail -40
fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true
