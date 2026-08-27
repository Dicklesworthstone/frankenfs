#!/bin/bash
# Interleaved create/delete storm: two LIVE kernel ext4 RW mounts (the A/A null) and
# up to two LIVE FrankenFS RW mounts from the SAME ELF, all up simultaneously, arm
# order rotated per round inside ONE rig invocation.
set -euo pipefail
W=/data/tmp/claude-1000/-data-projects-frankenfs/fa3fd948-7c8c-4eba-a14b-940646d78340/scratchpad
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-24}
OPS=${OPS:-2000}
CPU=${CPU:-8}
FA_CPUS=${FA_CPUS:-16}
FB_CPUS=${FB_CPUS:-17}
FA_ENV=${FA_ENV:-}
FB_ENV=${FB_ENV:-}
FA_LABEL=${FA_LABEL:-ffsA}
FB_LABEL=${FB_LABEL:-ffsB}
TAG=${TAG:-sdio}
LOOPS=""

K1=/home/ubuntu/storm-k1
K2=/home/ubuntu/storm-k2
FA=/home/ubuntu/storm-fa
FB=/home/ubuntu/storm-fb

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

for n in k1 k2 fa fb; do python3 "$W/mkcopy.py" "$W/simg-base.ext4" "$W/simg-$n.ext4"; done
sync

# SYMMETRIC TRANSPORT (bd-4zjkz): every arm on its own loop device, --direct-io=on.
attach() {
  local dev
  dev=$(sudo -n losetup --find --show --direct-io=on "$1")
  sudo -n chown "$(id -u)" "$dev"
  echo "$dev"
}
DK1=$(attach "$W/simg-k1.ext4"); LOOPS="$LOOPS $DK1"
DK2=$(attach "$W/simg-k2.ext4"); LOOPS="$LOOPS $DK2"
DFA=$(attach "$W/simg-fa.ext4"); LOOPS="$LOOPS $DFA"
DFB=$(attach "$W/simg-fb.ext4"); LOOPS="$LOOPS $DFB"
echo "== loop devices (all --direct-io=on):$LOOPS"
sudo -n mount "$DK1" "$K1"
sudo -n mount "$DK2" "$K2"
sudo -n chown -R "$(id -u):$(id -g)" "$K1/create-delete-storm" "$K2/create-delete-storm"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256|codegen_isa|pgo_profile" || true

start_fuse() {  # $1=cpus $2=mnt $3=img $4=suffix $5=env
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=${BENCH_EV:-1} FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount --rw "$3" "$2" >> "$W/sfuse-$TAG-$4.log" 2>&1 &
  echo $!
}
APID=$(start_fuse "$FA_CPUS" "$FA" "$DFA" "a" "$FA_ENV")
BPID=0
[ -n "$FB_LABEL" ] && BPID=$(start_fuse "$FB_CPUS" "$FB" "$DFB" "b" "$FB_ENV")

wait_mount() {
  for _ in $(seq 1 200); do
    mountpoint -q "$1" && return 0
    kill -0 "$2" 2>/dev/null || { echo "daemon $2 died"; tail -20 "$3"; return 1; }
    sleep 0.1
  done
  echo "mount $1 never came up"; tail -20 "$3"; return 1
}
wait_mount "$FA" "$APID" "$W/sfuse-$TAG-a.log"
ARMS=("k1=$K1" "k2=$K2" "$FA_LABEL=$FA")
if [ -n "$FB_LABEL" ]; then
  wait_mount "$FB" "$BPID" "$W/sfuse-$TAG-b.log"
  ARMS+=("$FB_LABEL=$FB")
fi

echo "== $FA_LABEL pid $APID cpus $FA_CPUS env '$FA_ENV'"
grep -h "mount_candidate_knobs" "$W/sfuse-$TAG-a.log" | tail -1 || true
if [ -n "$FB_LABEL" ]; then
  echo "== $FB_LABEL pid $BPID cpus $FB_CPUS env '$FB_ENV'"
  grep -h "mount_candidate_knobs" "$W/sfuse-$TAG-b.log" | tail -1 || true
fi
echo "== client cpu $CPU, $OPS create+delete pairs per batch"

"$W/storm_ab" "$ROUNDS" "$OPS" "$CPU" "$APID" "${ARMS[@]}" | tee "$W/stormdio-$TAG.csv"

echo "== unmount + census"
fusermount3 -u "$FA"; wait "$APID" 2>/dev/null || true
echo "--- $FA_LABEL"; grep -h "crossings_total\|op_counts" "$W/sfuse-$TAG-a.log" | tail -2 || true
if [ -n "$FB_LABEL" ]; then
  fusermount3 -u "$FB"; wait "$BPID" 2>/dev/null || true
  echo "--- $FB_LABEL"; grep -h "crossings_total\|op_counts" "$W/sfuse-$TAG-b.log" | tail -2 || true
fi
