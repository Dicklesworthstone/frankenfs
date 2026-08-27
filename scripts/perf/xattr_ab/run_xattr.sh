#!/bin/bash
# Interleaved xattr-get-list-report: two LIVE kernel ext4 read-only mounts (the A/A
# null) and up to two LIVE FrankenFS mounts from the SAME ELF, all up
# simultaneously, arm order rotated per round inside ONE rig invocation.
#
# env: FA_ENV / FB_ENV   = space-separated KEY=VAL applied to that FUSE arm
#      FA_CPUS / FB_CPUS = taskset cpu list for that daemon (never cpu16)
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-24}
OPS=${OPS:-2000}
CPU=${CPU:-8}
FA_CPUS=${FA_CPUS:-18}
FB_CPUS=${FB_CPUS:-19}
FA_ENV=${FA_ENV:-}
FB_ENV=${FB_ENV:-}
FA_LABEL=${FA_LABEL:-ffsA}
FB_LABEL=${FB_LABEL:-ffsB}
TAG=${TAG:-xrun}

K1=/home/ubuntu/xattr-k1; K2=/home/ubuntu/xattr-k2
FA=/home/ubuntu/xattr-fa; FB=/home/ubuntu/xattr-fb

cleanup() {
  fusermount3 -u "$FA" 2>/dev/null || true
  fusermount3 -u "$FB" 2>/dev/null || true
  sudo -n umount "$K1" 2>/dev/null || true
  sudo -n umount "$K2" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$K1" "$K2" "$FA" "$FB"
for n in k1 k2 fa fb; do cp "$W/ximg-base.ext4" "$W/ximg-$n.ext4"; done

sudo -n mount -o loop,ro "$W/ximg-k1.ext4" "$K1"
sudo -n mount -o loop,ro "$W/ximg-k2.ext4" "$K2"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256|codegen_isa|pgo_profile" || true

start_fuse() {  # $1=cpus $2=mnt $3=img $4=logsuffix $5=extra env
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount "$3" "$2" >> "$W/xfuse-$TAG-$4.log" 2>&1 &
  echo $!
}
APID=$(start_fuse "$FA_CPUS" "$FA" "$W/ximg-fa.ext4" "a" "$FA_ENV")
BPID=0
[ -n "$FB_LABEL" ] && BPID=$(start_fuse "$FB_CPUS" "$FB" "$W/ximg-fb.ext4" "b" "$FB_ENV")

wait_mount() {
  for _ in $(seq 1 300); do
    mountpoint -q "$1" && return 0
    kill -0 "$2" 2>/dev/null || { echo "daemon $2 died"; tail -20 "$3"; return 1; }
    sleep 0.1
  done
  echo "mount $1 never came up"; tail -20 "$3"; return 1
}
wait_mount "$FA" "$APID" "$W/xfuse-$TAG-a.log"
ARMS=("k1=$K1" "k2=$K2" "$FA_LABEL=$FA")
if [ -n "$FB_LABEL" ]; then
  wait_mount "$FB" "$BPID" "$W/xfuse-$TAG-b.log"
  ARMS+=("$FB_LABEL=$FB")
fi
echo "== $FA_LABEL pid $APID cpus $FA_CPUS env '$FA_ENV'"
grep -h mount_candidate_knobs "$W/xfuse-$TAG-a.log" | tail -1 || true
[ -n "$FB_LABEL" ] && { echo "== $FB_LABEL pid $BPID cpus $FB_CPUS env '$FB_ENV'";
  grep -h mount_candidate_knobs "$W/xfuse-$TAG-b.log" | tail -1 || true; }
echo "== client cpu $CPU, $OPS reports/batch"

# bd-3d2c0: the client's daemon_ticks column follows ONE pid, so it can only
# price the arm that happens to be A. Snapshot BOTH daemons around the whole run
# and report utime+stime per arm, which is what a CPU price needs.
ticks_of() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
A_TK0=$(ticks_of "$APID"); B_TK0=0
[ -n "$FB_LABEL" ] && B_TK0=$(ticks_of "$BPID")

"$W/xattr_ab" "$ROUNDS" "$OPS" "$CPU" "$APID" "${ARMS[@]}"

A_TK1=$(ticks_of "$APID"); B_TK1=0
[ -n "$FB_LABEL" ] && B_TK1=$(ticks_of "$BPID")
echo "== daemon CPU over the whole run (ticks, utime+stime)"
echo "daemon_cpu_ticks,$FA_LABEL,$((A_TK1-A_TK0))"
[ -n "$FB_LABEL" ] && echo "daemon_cpu_ticks,$FB_LABEL,$((B_TK1-B_TK0))"

echo "== unmount + census"
fusermount3 -u "$FA"; [ -n "$FB_LABEL" ] && fusermount3 -u "$FB"
wait "$APID" 2>/dev/null || true; [ -n "$FB_LABEL" ] && wait "$BPID" 2>/dev/null || true
for s in a b; do
  [ -f "$W/xfuse-$TAG-$s.log" ] || continue
  echo "--- arm $s"
  grep -h 'mount_candidate_crossings' "$W/xfuse-$TAG-$s.log" | tail -1 || true
  grep -h 'op_counts' "$W/xfuse-$TAG-$s.log" | tail -1 || true
done
