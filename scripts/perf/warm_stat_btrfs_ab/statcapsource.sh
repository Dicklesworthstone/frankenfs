#!/bin/bash
# Does the warm-stat row share the worst row's structural signature?
#
# The campaign ranks its targets by wall-time ratio (xattr 8.43x, warm stat ~4.98x,
# readdir+stat 3.83x). Those ratios are measured on a host where four of eight runs in
# one session had to be voided for load spikes. Blocking crossings per user operation
# is deterministic — five consecutive counted results have reproduced to +/-1 — so it
# is the better floor metric, and this asks whether the ranking survives it.
#
# Same shape as xattr_ab/capsource.sh: ONE client binary over ONE fixture on ONE host,
# against a LIVE kernel btrfs mount (the incumbent) and a FrankenFS FUSE mount, with
# bpftrace counting get_vfs_caps_from_disk on the kernel side of the boundary.
#
# Prediction registered before running: a warm stat() resolves a path, so it should
# cost 1 capability probe + 1 getattr = ~2 blocking crossings per op — the same 2.001
# amplification measured on the worst row. If that holds, the two rows are
# structurally identical and their very different wall-time ratios come from something
# other than round-trip count.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
N=${N:-20000}
KMNT=/home/ubuntu/statcap-k
FMNT=/home/ubuntu/statcap-f
LOOPS=""

cleanup() {
  fusermount3 -u "$FMNT" 2>/dev/null || true
  sudo -n umount "$KMNT" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$KMNT" "$FMNT"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256" || true
echo "== workload: $N warm stat() calls on one file, identical client both arms"

probe_run() {  # $1=label $2=mountpoint
  local out="$W/statcap-$1.txt"
  sudo -n bpftrace -e "
kprobe:get_vfs_caps_from_disk /comm == \"statblockprobe\"/ { @caps = count(); }
kprobe:__vfs_getxattr        /comm == \"statblockprobe\"/ { @vfs_getxattr = count(); }
interval:s:180 { exit(); }" > "$out" 2>&1 &
  local bp=$!
  for _ in $(seq 1 100); do grep -q "Attaching" "$out" 2>/dev/null && break; sleep 0.1; done
  sleep 1
  taskset -c 8 "$W/statblockprobe" "$2" "$N"
  sudo -n pkill -INT -x bpftrace 2>/dev/null || true
  wait "$bp" 2>/dev/null || true
  echo "  $(grep -E '^@(caps|vfs_getxattr)' "$out" | tr '\n' ' ')"
}

dev=$(sudo -n losetup --find --show "$W/wimgb-base.btrfs")
sudo -n losetup --direct-io=on "$dev" 2>/dev/null || true
LOOPS="$LOOPS $dev"
sudo -n mount -o ro "$dev" "$KMNT"
echo "--- kernel btrfs (live incumbent)"
probe_run kernel "$KMNT"
sudo -n umount "$KMNT"

cp "$W/wimgb-base.btrfs" "$W/wimgb-caps.btrfs"
sync
fdev=$(sudo -n losetup --find --show "$W/wimgb-caps.btrfs")
sudo -n losetup --direct-io=on "$fdev" 2>/dev/null || true
sudo -n chown "$(id -u)" "$fdev"
LOOPS="$LOOPS $fdev"
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn \
  taskset -c 18 "$ELF" mount "$fdev" "$FMNT" >> "$W/statcap-fuse.log" 2>&1 &
fpid=$!
for _ in $(seq 1 200); do mountpoint -q "$FMNT" && break; kill -0 "$fpid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$FMNT" || { echo "fuse mount never came up"; tail -5 "$W/statcap-fuse.log"; exit 1; }
echo "--- FrankenFS (FUSE)"
probe_run fuse "$FMNT"
fusermount3 -u "$FMNT"; wait "$fpid" 2>/dev/null || true
grep -o "mount_candidate_crossings,.*" "$W/statcap-fuse.log" | tail -1 \
  | grep -oE "crossings_(lookup|getattr|getxattr|other|total)=[0-9]+" | tr '\n' ' ' | sed 's/^/  daemon /'
echo
grep -o "op_counts.*" "$W/statcap-fuse.log" | tail -1 | sed 's/^/  /' || true
