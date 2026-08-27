#!/bin/bash
# Interleaved create/delete storm on BTRFS: two LIVE kernel btrfs loop mounts (the
# A/A null) and two LIVE FrankenFS --rw mounts of btrfs images from the SAME ELF,
# arm order rotated per round inside ONE rig invocation.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-32}
OPS=${OPS:-2000}
CPU=${CPU:-8}
FA_CPUS=${FA_CPUS:-18}
FB_CPUS=${FB_CPUS:-19}
FA_ENV=${FA_ENV:-}
FB_ENV=${FB_ENV:-}
FA_LABEL=${FA_LABEL:-ffsA}
FB_LABEL=${FB_LABEL:-ffsB}
TAG=${TAG:-btrun}

K1=/home/ubuntu/bs-k1; K2=/home/ubuntu/bs-k2
FA=/home/ubuntu/bs-fa; FB=/home/ubuntu/bs-fb

cleanup() {
  fusermount3 -u "$FA" 2>/dev/null || true
  fusermount3 -u "$FB" 2>/dev/null || true
  sudo -n umount "$K1" 2>/dev/null || true
  sudo -n umount "$K2" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$K1" "$K2" "$FA" "$FB"

for n in k1 k2 fa fb; do cp "$W/bimgb-base.btrfs" "$W/bimgb-$n.btrfs"; done
sync

sudo -n mount -o loop "$W/bimgb-k1.btrfs" "$K1"
sudo -n mount -o loop "$W/bimgb-k2.btrfs" "$K2"
sudo -n chown -R "$(id -u):$(id -g)" "$K1/create-delete-storm" "$K2/create-delete-storm"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256" || true

start_fuse() {
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount --rw "$3" "$2" >> "$W/bsfuse-$TAG-$4.log" 2>&1 &
  echo $!
}
APID=$(start_fuse "$FA_CPUS" "$FA" "$W/bimgb-fa.btrfs" "a" "$FA_ENV")
BPID=$(start_fuse "$FB_CPUS" "$FB" "$W/bimgb-fb.btrfs" "b" "$FB_ENV")

wait_mount() {
  for _ in $(seq 1 300); do
    mountpoint -q "$1" && return 0
    kill -0 "$2" 2>/dev/null || { echo "daemon $2 died"; tail -20 "$3"; return 1; }
    sleep 0.1
  done
  echo "mount $1 never came up"; tail -20 "$3"; return 1
}
wait_mount "$FA" "$APID" "$W/bsfuse-$TAG-a.log"
wait_mount "$FB" "$BPID" "$W/bsfuse-$TAG-b.log"

echo "== $FA_LABEL pid $APID cpus $FA_CPUS env '$FA_ENV'"
echo "== $FB_LABEL pid $BPID cpus $FB_CPUS env '$FB_ENV'"

"$W/storm_ab" "$ROUNDS" "$OPS" "$CPU" "$APID" \
  "k1=$K1" "k2=$K2" "$FA_LABEL=$FA" "$FB_LABEL=$FB" | tee "$W/bstorm-$TAG.csv"

echo "== unmount + census"
fusermount3 -u "$FA"; wait "$APID" 2>/dev/null || true
echo "--- $FA_LABEL"; grep -h "crossings_total\|op_counts" "$W/bsfuse-$TAG-a.log" | tail -2 || true
fusermount3 -u "$FB"; wait "$BPID" 2>/dev/null || true
echo "--- $FB_LABEL"; grep -h "crossings_total\|op_counts" "$W/bsfuse-$TAG-b.log" | tail -2 || true
