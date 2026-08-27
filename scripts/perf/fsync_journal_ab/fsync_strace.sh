#!/bin/bash
# Count the DAEMON's own durability syscalls per client fsync on the btrfs fsync row.
# bd-4zjkz used exactly this technique on the ext4 twin; here it decides whether the
# 3.000 device FLUSH barriers per client fsync are issued by our daemon or by the
# block layer underneath it.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
OPS=${OPS:-200}
FM=/home/ubuntu/fs-fa
TAG=${TAG:-strace}
LOOPS=""
cleanup() {
  fusermount3 -u "$FM" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$FM"
cp "$W/fsimg-base.btrfs" "$W/fsimg-fa.btrfs"
DEV=$(sudo -n losetup --find --show --direct-io=on "$W/fsimg-fa.btrfs")
LOOPS="$DEV"
sudo -n chown "$(id -u)" "$DEV"
echo "loop=$DEV dio=$(cat /sys/block/$(basename "$DEV")/loop/dio)"

env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn taskset -c 18 \
  "$ELF" mount --rw "$DEV" "$FM" >> "$W/fsfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
echo "daemon pid $FPID"

"$W/fsync_ab" 1 20 8 0 f="$FM" >/dev/null 2>&1   # warm, untraced

STATF=/sys/block/$(basename "$DEV")/stat
read -r -a B <<<"$(cat "$STATF")"
sudo -n strace -c -f -p "$FPID" -e trace=fsync,fdatasync,sync_file_range,pwrite64,pwritev,write \
  -o "$W/strace-$TAG.txt" &
SPID=$!
sleep 1
"$W/fsync_ab" 1 "$OPS" 8 0 f="$FM" >/dev/null 2>&1
sleep 1
sudo -n kill -INT "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true
read -r -a A <<<"$(cat "$STATF")"

echo "== device deltas over $OPS client fsyncs"
echo "   write_ios=$(( A[4] - B[4] ))  sectors=$(( A[6] - B[6] ))  flush_ios=$(( A[15] - B[15] ))"
python3 -c "
ops = $OPS
print('   per client fsync: write_ios=%.3f sectors=%.3f flush_ios=%.3f' % (
    ($(( A[4] - B[4] )))/ops, ($(( A[6] - B[6] )))/ops, ($(( A[15] - B[15] )))/ops))
"
echo "== daemon syscall census"
sudo -n cat "$W/strace-$TAG.txt" 2>/dev/null | tail -15
fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true
