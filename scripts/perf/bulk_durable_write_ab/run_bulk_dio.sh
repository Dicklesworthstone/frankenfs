#!/bin/bash
# Interleaved bulk-durable-write: two LIVE kernel ext4 RW mounts (the A/A null) and up
# to two LIVE FrankenFS RW mounts from the SAME ELF, all up simultaneously, arm order
# rotated per round inside ONE rig invocation.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-24}
CHUNKS=${CHUNKS:-64}
CPU=${CPU:-8}
FA_CPUS=${FA_CPUS:-16}
FB_CPUS=${FB_CPUS:-17}
FA_ENV=${FA_ENV:-}
FB_ENV=${FB_ENV:-}
FA_LABEL=${FA_LABEL:-ffsA}
FB_LABEL=${FB_LABEL:-ffsB}
TAG=${TAG:-bdio}
LOOPS=""

K1=/home/ubuntu/bulk-k1
K2=/home/ubuntu/bulk-k2
FA=/home/ubuntu/bulk-fa
FB=/home/ubuntu/bulk-fb

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

# Preallocated copies so every arm's backing file has the SAME host extent layout;
# a plain `cp` made two identical kernel arms measure 6.6% apart under loop-dio.
for n in k1 k2 fa fb; do python3 "$W/mkcopy.py" "$W/bimg-base.ext4" "$W/bimg-$n.ext4"; done
sync

# SYMMETRIC TRANSPORT (bd-4zjkz): every arm on its own loop device, --direct-io=on.
# This row is ~64% fsync by wall, so it is a durability row and the artifact applies.
attach() {
  local dev
  dev=$(sudo -n losetup --find --show --direct-io=on "$1")
  sudo -n chown "$(id -u)" "$dev"
  echo "$dev"
}
DK1=$(attach "$W/bimg-k1.ext4"); LOOPS="$LOOPS $DK1"
DK2=$(attach "$W/bimg-k2.ext4"); LOOPS="$LOOPS $DK2"
DFA=$(attach "$W/bimg-fa.ext4"); LOOPS="$LOOPS $DFA"
DFB=$(attach "$W/bimg-fb.ext4"); LOOPS="$LOOPS $DFB"
echo "== loop devices (all --direct-io=on):$LOOPS"
sudo -n mount "$DK1" "$K1"
sudo -n mount "$DK2" "$K2"
sudo -n chown "$(id -u):$(id -g)" "$K1/bulk-durable.bin" "$K2/bulk-durable.bin"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256|codegen_isa|pgo_profile" || true

start_fuse() {  # $1=cpus $2=mnt $3=img $4=logsuffix $5=env
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount --rw "$3" "$2" >> "$W/bfuse-$TAG-$4.log" 2>&1 &
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
wait_mount "$FA" "$APID" "$W/bfuse-$TAG-a.log"
ARMS=("k1=$K1" "k2=$K2" "$FA_LABEL=$FA")
if [ -n "$FB_LABEL" ]; then
  wait_mount "$FB" "$BPID" "$W/bfuse-$TAG-b.log"
  ARMS+=("$FB_LABEL=$FB")
fi

echo "== $FA_LABEL pid $APID cpus $FA_CPUS env '$FA_ENV'"
grep -h "mount_candidate_knobs" "$W/bfuse-$TAG-a.log" | tail -1
if [ -n "$FB_LABEL" ]; then
  echo "== $FB_LABEL pid $BPID cpus $FB_CPUS env '$FB_ENV'"
  grep -h "mount_candidate_knobs" "$W/bfuse-$TAG-b.log" | tail -1
fi
echo "== client cpu $CPU, $CHUNKS x 1 MiB + fsync"

S() { echo "/sys/block/$(basename "$1")/stat"; }
ARMS=("k1=$K1=$(S "$DK1")=0" "k2=$K2=$(S "$DK2")=0" "$FA_LABEL=$FA=$(S "$DFA")=$APID")
[ -n "$FB_LABEL" ] && ARMS+=("$FB_LABEL=$FB=$(S "$DFB")=$BPID")
# bd-3giz2: the copy this row's lever removes is DAEMON CPU, and on a loaded box
# CPU ticks measure work done while wall measures waiting. Snapshot utime+stime for
# BOTH daemons around the whole run, per arm, exactly as the xattr rig does.
ticks_of() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
A_TK0=$(ticks_of "$APID"); B_TK0=0
[ -n "$FB_LABEL" ] && B_TK0=$(ticks_of "$BPID")

"$W/bulkwrite_ab" "$ROUNDS" "$CHUNKS" "$CPU" "${ARMS[@]}" | tee "$W/bulkdio-$TAG.csv"

A_TK1=$(ticks_of "$APID"); B_TK1=0
[ -n "$FB_LABEL" ] && B_TK1=$(ticks_of "$BPID")
echo "== daemon CPU over the whole run (ticks, utime+stime)"
echo "daemon_cpu_ticks,$FA_LABEL,$((A_TK1-A_TK0))"
[ -n "$FB_LABEL" ] && echo "daemon_cpu_ticks,$FB_LABEL,$((B_TK1-B_TK0))"

echo "== unmount + census"
fusermount3 -u "$FA"; wait "$APID" 2>/dev/null || true
echo "--- $FA_LABEL"; grep -h "crossings_total\|op_counts" "$W/bfuse-$TAG-a.log" | tail -2
if [ -n "$FB_LABEL" ]; then
  fusermount3 -u "$FB"; wait "$BPID" 2>/dev/null || true
  echo "--- $FB_LABEL"; grep -h "crossings_total\|op_counts" "$W/bfuse-$TAG-b.log" | tail -2
fi
