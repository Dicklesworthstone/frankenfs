#!/bin/bash
# Interleaved readdir+stat with two LIVE kernel ext4 mounts (the A/A null) and up to
# two LIVE FrankenFS mounts from the SAME ELF (the candidate A/A or A/B), all up
# simultaneously, arm order rotated per round inside ONE rig invocation.
#
# env: FA_ENV / FB_ENV  = space-separated KEY=VAL applied to that FUSE arm
#      FA_CPUS / FB_CPUS = taskset cpu list for that daemon
#      FB_LABEL          = arm label for the second FUSE arm ("" disables it)
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
FA_LABEL=${FA_LABEL:-ffsA}
FB_LABEL=${FB_LABEL:-ffsB}
TAG=${TAG:-run}

K1=/home/ubuntu/rdstat-k1
K2=/home/ubuntu/rdstat-k2
FA=/home/ubuntu/rdstat-fa
FB=/home/ubuntu/rdstat-fb

cleanup() {
  fusermount3 -u "$FA" 2>/dev/null || true
  fusermount3 -u "$FB" 2>/dev/null || true
  sudo -n umount "$K1" 2>/dev/null || true
  sudo -n umount "$K2" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$K1" "$K2" "$FA" "$FB"

cp "$W/img-base.ext4" "$W/img-fa.ext4"
cp "$W/img-base.ext4" "$W/img-fb.ext4"

sudo -n mount -o loop,ro "$W/img-k1.ext4" "$K1"
sudo -n mount -o loop,ro "$W/img-k2.ext4" "$K2"

echo "== candidate ELF"
sha256sum "$ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256|codegen_isa|pgo_profile" || true

start_fuse() {  # $1=cpus $2=mnt $3=img $4=logsuffix $5=extra env string
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount "$3" "$2" >> "$W/fuse-$TAG-$4.log" 2>&1 &
  echo $!
}

APID=$(start_fuse "$FA_CPUS" "$FA" "$W/img-fa.ext4" "a" "$FA_ENV")
BPID=0
if [ -n "$FB_LABEL" ]; then
  BPID=$(start_fuse "$FB_CPUS" "$FB" "$W/img-fb.ext4" "b" "$FB_ENV")
fi

wait_mount() {
  for _ in $(seq 1 150); do
    mountpoint -q "$1" && return 0
    kill -0 "$2" 2>/dev/null || { echo "daemon $2 died"; tail -20 "$3"; return 1; }
    sleep 0.1
  done
  echo "mount $1 never came up"; tail -20 "$3"; return 1
}
wait_mount "$FA" "$APID" "$W/fuse-$TAG-a.log"
ARMS=("k1=$K1" "k2=$K2" "$FA_LABEL=$FA")
if [ -n "$FB_LABEL" ]; then
  wait_mount "$FB" "$BPID" "$W/fuse-$TAG-b.log"
  ARMS+=("$FB_LABEL=$FB")
fi

echo "== $FA_LABEL pid $APID cpus $FA_CPUS env '$FA_ENV'"
grep -h "mount_candidate_knobs" "$W/fuse-$TAG-a.log" | tail -1
if [ -n "$FB_LABEL" ]; then
  echo "== $FB_LABEL pid $BPID cpus $FB_CPUS env '$FB_ENV'"
  grep -h "mount_candidate_knobs" "$W/fuse-$TAG-b.log" | tail -1
fi
echo "== clients cpus $CPUBASE..$((CPUBASE+THREADS-1))"

"$W/rdstat_ab" "$ROUNDS" "$THREADS" "$CPUBASE" "$APID" "${ARMS[@]}" | tee "$W/rdstat-$TAG.csv"

echo "== unmount + census"
fusermount3 -u "$FA"; wait "$APID" 2>/dev/null || true
echo "--- $FA_LABEL"; grep -h "crossings_total\|op_counts\|getattr_split" "$W/fuse-$TAG-a.log" | tail -3
if [ -n "$FB_LABEL" ]; then
  fusermount3 -u "$FB"; wait "$BPID" 2>/dev/null || true
  echo "--- $FB_LABEL"; grep -h "crossings_total\|op_counts\|getattr_split" "$W/fuse-$TAG-b.log" | tail -3
fi
