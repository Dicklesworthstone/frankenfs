#!/bin/bash
# WHY does our 64 MiB flush become 130 device requests where kernel ext4 uses 54?
# The loop device's max_sectors_kb is 1280, and the kernel arm saturates it
# (2427 sectors/request); we average 1008. Read the daemon's actual pwrite sizes.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
CHUNKS=${CHUNKS:-64}
FM=/home/ubuntu/bt-fa
TAG=${TAG:-btrace}
LOOPS=""
cleanup() {
  fusermount3 -u "$FM" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/bimg-base.ext4" "$W/bimg-tr.ext4"
DEV=$(sudo -n losetup --find --show --direct-io=on "$W/bimg-tr.ext4")
LOOPS="$DEV"
sudo -n chown "$(id -u)" "$DEV"
echo "loop=$DEV dio=$(cat /sys/block/$(basename "$DEV")/loop/dio) max_sectors_kb=$(cat /sys/block/$(basename "$DEV")/queue/max_sectors_kb)"

env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn taskset -c 18 \
  "$ELF" mount --rw "$DEV" "$FM" >> "$W/btfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
echo "daemon pid $FPID"
"$W/bulkwrite_ab" 1 "$CHUNKS" 8 0 "f=$FM" >/dev/null 2>&1

sudo -n strace -f -p "$FPID" -e trace=pwrite64,pwritev,fdatasync,fsync \
  -o "$W/bttrace-$TAG.txt" &
SPID=$!
sleep 1
"$W/bulkwrite_ab" 1 "$CHUNKS" 8 0 "f=$FM" >/dev/null 2>&1
sleep 1
sudo -n kill -INT "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true
sudo -n chown "$(id -u)" "$W/bttrace-$TAG.txt" 2>/dev/null || true

echo "== pwrite length histogram (bytes -> count)"
grep -oE "pwrite64\(3, [^)]*, [0-9]+, [0-9]+\)" "$W/bttrace-$TAG.txt" 2>/dev/null | \
  sed -E 's/.*, ([0-9]+), [0-9]+\)/\1/' | sort -n | uniq -c | sort -rn | head -12
echo "== totals"
echo "pwrite64 calls: $(grep -c pwrite64 "$W/bttrace-$TAG.txt" || true)"
echo "fdatasync calls: $(grep -c fdatasync "$W/bttrace-$TAG.txt" || true)"
fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true
