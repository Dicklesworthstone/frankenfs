#!/bin/bash
# Interleaved btrfs fsync/journal-commit with SYMMETRIC TRANSPORT: all four arms sit
# on their own loop device with `--direct-io=on`, which is exactly the artifact
# bd-4zjkz found on the ext4 twin (a buffered image file for us against loop-dio for
# the kernel was worth 2.20x by itself). Two kernel btrfs mounts (the A/A null) and
# two FrankenFS --rw mounts from the SAME ELF, arm order rotated per round.
#
# Each arm carries its loop device's /sys/block/<dev>/stat so SECTORS WRITTEN per
# batch are counted per arm — the durability-class check this row needs.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-32}
OPS=${OPS:-200}
CPU=${CPU:-8}
FA_CPUS=${FA_CPUS:-18}
FB_CPUS=${FB_CPUS:-19}
FA_ENV=${FA_ENV:-}
FB_ENV=${FB_ENV:-}
FA_LABEL=${FA_LABEL:-ffsA}
FB_LABEL=${FB_LABEL:-ffsB}
FB_RAW=${FB_RAW:-0}   # 1 = give arm B the buffered IMAGE FILE instead of its loop device
TAG=${TAG:-fsrun}

K1=/home/ubuntu/fs-k1; K2=/home/ubuntu/fs-k2
FA=/home/ubuntu/fs-fa; FB=/home/ubuntu/fs-fb
LOOPS=""

cleanup() {
  fusermount3 -u "$FA" 2>/dev/null || true
  fusermount3 -u "$FB" 2>/dev/null || true
  sudo -n umount "$K1" 2>/dev/null || true
  sudo -n umount "$K2" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$K1" "$K2" "$FA" "$FB"

for n in k1 k2 fa fb; do cp "$W/fsimg-base.btrfs" "$W/fsimg-$n.btrfs"; done
sync

attach() {  # $1=image -> echoes device, direct-io on
  local dev
  dev=$(sudo -n losetup --find --show --direct-io=on "$1")
  sudo -n chown "$(id -u)" "$dev"
  echo "$dev"
}
DK1=$(attach "$W/fsimg-k1.btrfs"); LOOPS="$LOOPS $DK1"
DK2=$(attach "$W/fsimg-k2.btrfs"); LOOPS="$LOOPS $DK2"
DFA=$(attach "$W/fsimg-fa.btrfs"); LOOPS="$LOOPS $DFA"
DFB=$(attach "$W/fsimg-fb.btrfs"); LOOPS="$LOOPS $DFB"
echo "== loop devices (all --direct-io=on): k1=$DK1 k2=$DK2 fa=$DFA fb=$DFB"
for d in $LOOPS; do printf '   %s dio=%s\n' "$d" "$(cat /sys/block/$(basename "$d")/loop/dio 2>/dev/null || echo n/a)"; done

sudo -n mount "$DK1" "$K1"
sudo -n mount "$DK2" "$K2"
sudo -n chown -R "$(id -u):$(id -g)" "$K1" "$K2"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256" || true

start_fuse() {  # $1=cpus $2=mnt $3=dev $4=suffix $5=env
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount --rw "$3" "$2" >> "$W/fsfuse-$TAG-$4.log" 2>&1 &
  echo $!
}
APID=$(start_fuse "$FA_CPUS" "$FA" "$DFA" "a" "$FA_ENV")
FBTARGET="$DFB"
if [ "$FB_RAW" = "1" ]; then FBTARGET="$W/fsimg-fb.btrfs"; echo "  (arm B on the BUFFERED image file, not $DFB)"; fi
BPID=$(start_fuse "$FB_CPUS" "$FB" "$FBTARGET" "b" "$FB_ENV")

wait_mount() {
  for _ in $(seq 1 300); do
    mountpoint -q "$1" && return 0
    kill -0 "$2" 2>/dev/null || { echo "daemon $2 died"; tail -20 "$3"; return 1; }
    sleep 0.1
  done
  echo "mount $1 never came up"; tail -20 "$3"; return 1
}
wait_mount "$FA" "$APID" "$W/fsfuse-$TAG-a.log"
wait_mount "$FB" "$BPID" "$W/fsfuse-$TAG-b.log"

echo "== $FA_LABEL pid $APID cpus $FA_CPUS env '$FA_ENV'"
echo "== $FB_LABEL pid $BPID cpus $FB_CPUS env '$FB_ENV'"
echo "== client cpu $CPU, $OPS write+fsync per batch"

S() { echo "/sys/block/$(basename "$1")/stat"; }
"$W/fsync_ab" "$ROUNDS" "$OPS" "$CPU" "$APID" \
  "k1=$K1=$(S "$DK1")" "k2=$K2=$(S "$DK2")" \
  "$FA_LABEL=$FA=$(S "$DFA")" "$FB_LABEL=$FB=$(S "$DFB")" | tee "$W/fsync-$TAG.csv"

echo "== unmount + census"
fusermount3 -u "$FA"; wait "$APID" 2>/dev/null || true
echo "--- $FA_LABEL"; grep -h "crossings_total\|op_counts" "$W/fsfuse-$TAG-a.log" | tail -2 || true
fusermount3 -u "$FB"; wait "$BPID" 2>/dev/null || true
echo "--- $FB_LABEL"; grep -h "crossings_total\|op_counts" "$W/fsfuse-$TAG-b.log" | tail -2 || true
