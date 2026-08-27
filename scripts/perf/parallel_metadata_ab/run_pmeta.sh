#!/bin/bash
# Interleaved parallel-metadata-write: two LIVE kernel ext4 RW mounts (the A/A null)
# and up to two LIVE FrankenFS RW mounts from the SAME ELF, all up simultaneously,
# arm order rotated per round inside ONE rig invocation.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-24}
OPS=${OPS:-512}
THREADS=${THREADS:-8}
CPUBASE=${CPUBASE:-8}
FA_CPUS=${FA_CPUS:-16}
FB_CPUS=${FB_CPUS:-17}
FA_ENV=${FA_ENV:-}
FB_ENV=${FB_ENV:-}
FA_LABEL=${FA_LABEL:-ffsA}
FB_LABEL=${FB_LABEL:-ffsB}
TAG=${TAG:-prun}

K1=/home/ubuntu/pmeta-k1
K2=/home/ubuntu/pmeta-k2
FA=/home/ubuntu/pmeta-fa
FB=/home/ubuntu/pmeta-fb

cleanup() {
  fusermount3 -u "$FA" 2>/dev/null || true
  fusermount3 -u "$FB" 2>/dev/null || true
  sudo -n umount "$K1" 2>/dev/null || true
  sudo -n umount "$K2" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$K1" "$K2" "$FA" "$FB"

for n in k1 k2 fa fb; do cp "$W/pimg-base.ext4" "$W/pimg-$n.ext4"; done
sync

sudo -n mount -o loop "$W/pimg-k1.ext4" "$K1"
sudo -n mount -o loop "$W/pimg-k2.ext4" "$K2"
sudo -n chown -R "$(id -u):$(id -g)" "$K1/parallel-metadata" "$K2/parallel-metadata"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256|codegen_isa|pgo_profile" || true

start_fuse() {  # $1=cpus $2=mnt $3=img $4=suffix $5=env
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount --rw "$3" "$2" >> "$W/pfuse-$TAG-$4.log" 2>&1 &
  echo $!
}
APID=$(start_fuse "$FA_CPUS" "$FA" "$W/pimg-fa.ext4" "a" "$FA_ENV")
BPID=0
[ -n "$FB_LABEL" ] && BPID=$(start_fuse "$FB_CPUS" "$FB" "$W/pimg-fb.ext4" "b" "$FB_ENV")

wait_mount() {
  for _ in $(seq 1 200); do
    mountpoint -q "$1" && return 0
    kill -0 "$2" 2>/dev/null || { echo "daemon $2 died"; tail -20 "$3"; return 1; }
    sleep 0.1
  done
  echo "mount $1 never came up"; tail -20 "$3"; return 1
}
wait_mount "$FA" "$APID" "$W/pfuse-$TAG-a.log"
ARMS=("k1=$K1" "k2=$K2" "$FA_LABEL=$FA")
if [ -n "$FB_LABEL" ]; then
  wait_mount "$FB" "$BPID" "$W/pfuse-$TAG-b.log"
  ARMS+=("$FB_LABEL=$FB")
fi

echo "== $FA_LABEL pid $APID cpus $FA_CPUS env '$FA_ENV'"
grep -h "mount_candidate_knobs" "$W/pfuse-$TAG-a.log" | tail -1
if [ -n "$FB_LABEL" ]; then
  echo "== $FB_LABEL pid $BPID cpus $FB_CPUS env '$FB_ENV'"
  grep -h "mount_candidate_knobs" "$W/pfuse-$TAG-b.log" | tail -1
fi
echo "== clients cpus $CPUBASE..$((CPUBASE+THREADS-1)), $OPS creates over $THREADS workers"

"$W/pmeta_ab" "$ROUNDS" "$OPS" "$THREADS" "$CPUBASE" "$APID" "${ARMS[@]}" | tee "$W/pmeta-$TAG.csv"

echo "== unmount + census"
fusermount3 -u "$FA"; wait "$APID" 2>/dev/null || true
echo "--- $FA_LABEL"; grep -h "crossings_total\|op_counts" "$W/pfuse-$TAG-a.log" | tail -2
if [ -n "$FB_LABEL" ]; then
  fusermount3 -u "$FB"; wait "$BPID" 2>/dev/null || true
  echo "--- $FB_LABEL"; grep -h "crossings_total\|op_counts" "$W/pfuse-$TAG-b.log" | tail -2
fi
