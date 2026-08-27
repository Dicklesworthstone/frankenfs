#!/bin/bash
# Interleaved parallel-read-8t: two LIVE kernel ext4 ro loop mounts (the A/A null) and
# up to two LIVE FrankenFS ro mounts from the SAME ELF, all up simultaneously, arm
# order rotated per round inside ONE rig invocation.
#
# FA_LOOP/FB_LOOP=1 puts that FUSE arm behind a loop device (bd-w2u82 symmetric
# transport) instead of letting the daemon open the image file directly.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-24}
THREADS=${THREADS:-8}
CPUBASE=${CPUBASE:-8}
FA_CPUS=${FA_CPUS:-16}
FB_CPUS=${FB_CPUS:-17}
FA_ENV=${FA_ENV:-}
FB_ENV=${FB_ENV:-}
FA_LOOP=${FA_LOOP:-0}
FB_LOOP=${FB_LOOP:-0}
FA_LABEL=${FA_LABEL:-ffsA}
FB_LABEL=${FB_LABEL:-ffsB}
TAG=${TAG:-rrun}

K1=/home/ubuntu/pread-k1
K2=/home/ubuntu/pread-k2
FA=/home/ubuntu/pread-fa
FB=/home/ubuntu/pread-fb
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

for n in k1 k2 fa fb; do cp "$W/rimg-base.ext4" "$W/rimg-$n.ext4"; done
sync

sudo -n mount -o loop,ro "$W/rimg-k1.ext4" "$K1"
sudo -n mount -o loop,ro "$W/rimg-k2.ext4" "$K2"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256|codegen_isa|pgo_profile" || true

attach_loop() {  # $1=image -> echoes device
  local dev
  dev=$(sudo -n losetup --find --show "$1")
  sudo -n chown "$(id -u)" "$dev"
  echo "$dev"
}

start_fuse() {  # $1=cpus $2=mnt $3=img $4=suffix $5=env $6=useloop
  local img="$3"
  if [ "$6" = "1" ]; then
    img=$(attach_loop "$3")
    LOOPS="$LOOPS $img"
    echo "  (loop transport: $3 -> $img)" >&2
  fi
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount "$img" "$2" >> "$W/rfuse-$TAG-$4.log" 2>&1 &
  echo $!
}
APID=$(start_fuse "$FA_CPUS" "$FA" "$W/rimg-fa.ext4" "a" "$FA_ENV" "$FA_LOOP")
BPID=0
[ -n "$FB_LABEL" ] && BPID=$(start_fuse "$FB_CPUS" "$FB" "$W/rimg-fb.ext4" "b" "$FB_ENV" "$FB_LOOP")

wait_mount() {
  for _ in $(seq 1 200); do
    mountpoint -q "$1" && return 0
    kill -0 "$2" 2>/dev/null || { echo "daemon $2 died"; tail -20 "$3"; return 1; }
    sleep 0.1
  done
  echo "mount $1 never came up"; tail -20 "$3"; return 1
}
wait_mount "$FA" "$APID" "$W/rfuse-$TAG-a.log"
ARMS=("k1=$K1" "k2=$K2" "$FA_LABEL=$FA")
if [ -n "$FB_LABEL" ]; then
  wait_mount "$FB" "$BPID" "$W/rfuse-$TAG-b.log"
  ARMS+=("$FB_LABEL=$FB")
fi

echo "== $FA_LABEL pid $APID cpus $FA_CPUS loop=$FA_LOOP env '$FA_ENV'"
echo "== $FB_LABEL pid $BPID cpus $FB_CPUS loop=$FB_LOOP env '$FB_ENV'"
echo "== clients cpus $CPUBASE..$((CPUBASE+THREADS-1))"

"$W/pread_ab" "$ROUNDS" "$THREADS" "$CPUBASE" "$APID" "${ARMS[@]}" | tee "$W/pread-$TAG.csv"

echo "== unmount + census"
fusermount3 -u "$FA"; wait "$APID" 2>/dev/null || true
echo "--- $FA_LABEL"; grep -h "crossings_total\|op_counts" "$W/rfuse-$TAG-a.log" | tail -2 || true
if [ -n "$FB_LABEL" ]; then
  fusermount3 -u "$FB"; wait "$BPID" 2>/dev/null || true
  echo "--- $FB_LABEL"; grep -h "crossings_total\|op_counts" "$W/rfuse-$TAG-b.log" | tail -2 || true
fi
