#!/bin/bash
# FIVE-arm ext4 fsync/journal-commit, symmetric transport: every arm on its own loop
# device with --direct-io=on, all live in ONE rig invocation, order rotated per round.
#   k1, k2        two JOURNALLED kernel ext4 mounts  (the kernel A/A null)
#   knj           one UNJOURNALLED kernel ext4 mount (bd-4zjkz's middle arm)
#   ffsA, ffsA2   two FrankenFS --rw mounts from the SAME ELF (the candidate A/A null)
# Each arm carries its device's /sys/block/<dev>/stat so write I/Os, sectors and FLUSH
# requests are counted per arm per batch.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-48}
OPS=${OPS:-8}
CPU=${CPU:-8}
FA_CPUS=${FA_CPUS:-18}
FB_CPUS=${FB_CPUS:-19}
FA_ENV=${FA_ENV:-}
FB_ENV=${FB_ENV:-}
FA_LABEL=${FA_LABEL:-ffsA}
FB_LABEL=${FB_LABEL:-ffsA2}
TAG=${TAG:-e4run}

K1=/home/ubuntu/e4-k1; K2=/home/ubuntu/e4-k2; KNJ=/home/ubuntu/e4-knj
FA=/home/ubuntu/e4-fa; FB=/home/ubuntu/e4-fb
LOOPS=""

cleanup() {
  fusermount3 -u "$FA" 2>/dev/null || true
  fusermount3 -u "$FB" 2>/dev/null || true
  for m in "$K1" "$K2" "$KNJ"; do sudo -n umount "$m" 2>/dev/null || true; done
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$K1" "$K2" "$KNJ" "$FA" "$FB"

for n in k1 k2 fa fb; do python3 "$W/mkcopy.py" "$W/fsimg4-base.ext4" "$W/fsimg4-$n.ext4"; done
python3 "$W/mkcopy.py" "$W/fsimg4-nojrnl.ext4" "$W/fsimg4-knj.ext4"
sync

attach() {
  local dev
  dev=$(sudo -n losetup --find --show --direct-io=on "$1")
  sudo -n chown "$(id -u)" "$dev"
  echo "$dev"
}
DK1=$(attach "$W/fsimg4-k1.ext4");  LOOPS="$LOOPS $DK1"
DK2=$(attach "$W/fsimg4-k2.ext4");  LOOPS="$LOOPS $DK2"
DKNJ=$(attach "$W/fsimg4-knj.ext4"); LOOPS="$LOOPS $DKNJ"
DFA=$(attach "$W/fsimg4-fa.ext4");  LOOPS="$LOOPS $DFA"
DFB=$(attach "$W/fsimg4-fb.ext4");  LOOPS="$LOOPS $DFB"
echo "== loop devices (all --direct-io=on):$LOOPS"

sudo -n mount "$DK1"  "$K1"
sudo -n mount "$DK2"  "$K2"
sudo -n mount "$DKNJ" "$KNJ"
sudo -n chown -R "$(id -u):$(id -g)" "$K1" "$K2" "$KNJ"
echo "== kernel mount options"
for m in "$K1" "$KNJ"; do printf '   %s -> %s\n' "$m" "$(findmnt -no OPTIONS "$m")"; done

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256" || true

start_fuse() {
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount --rw "$3" "$2" >> "$W/e4fuse-$TAG-$4.log" 2>&1 &
  echo $!
}
APID=$(start_fuse "$FA_CPUS" "$FA" "$DFA" "a" "$FA_ENV")
BPID=$(start_fuse "$FB_CPUS" "$FB" "$DFB" "b" "$FB_ENV")

wait_mount() {
  for _ in $(seq 1 300); do
    mountpoint -q "$1" && return 0
    kill -0 "$2" 2>/dev/null || { echo "daemon $2 died"; tail -20 "$3"; return 1; }
    sleep 0.1
  done
  echo "mount $1 never came up"; tail -20 "$3"; return 1
}
wait_mount "$FA" "$APID" "$W/e4fuse-$TAG-a.log"
wait_mount "$FB" "$BPID" "$W/e4fuse-$TAG-b.log"
echo "== $FA_LABEL pid $APID cpus $FA_CPUS env '$FA_ENV'"
echo "== $FB_LABEL pid $BPID cpus $FB_CPUS env '$FB_ENV'"

S() { echo "/sys/block/$(basename "$1")/stat"; }
"$W/fsync_ab" "$ROUNDS" "$OPS" "$CPU" "$APID" \
  "k1=$K1=$(S "$DK1")" "k2=$K2=$(S "$DK2")" "knj=$KNJ=$(S "$DKNJ")" \
  "$FA_LABEL=$FA=$(S "$DFA")" "$FB_LABEL=$FB=$(S "$DFB")" | tee "$W/fsync4-$TAG.csv"

echo "== unmount + census"
fusermount3 -u "$FA"; wait "$APID" 2>/dev/null || true
echo "--- $FA_LABEL"; grep -h "op_counts" "$W/e4fuse-$TAG-a.log" | tail -1 || true
fusermount3 -u "$FB"; wait "$BPID" 2>/dev/null || true
