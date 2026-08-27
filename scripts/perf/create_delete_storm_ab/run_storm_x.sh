#!/bin/bash
# SIX-arm cross-filesystem create/delete storm, all live in ONE rig invocation with
# the arm order rotated per round:
#   kext4_1 kext4_2   two kernel ext4  loop mounts  (the ext4  kernel A/A null)
#   kbtr_1  kbtr_2    two kernel btrfs loop mounts  (the btrfs kernel A/A null)
#   ffs_ext4          FrankenFS on the ext4  image
#   ffs_btr           FrankenFS on the btrfs image
# Both FrankenFS arms are the SAME ELF, so "our ext4 vs our btrfs" is a paired
# within-invocation ratio and answers whether a MUTATING row carries any
# btrfs-specific excess, the way the readdir+stat row already answered it for reads.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-36}
OPS=${OPS:-2000}
CPU=${CPU:-8}
FE_CPUS=${FE_CPUS:-18}
FB_CPUS=${FB_CPUS:-19}
FE_ENV=${FE_ENV:-}
FB_ENV=${FB_ENV:-}
TAG=${TAG:-xrun}

KE1=/home/ubuntu/xs-ke1; KE2=/home/ubuntu/xs-ke2
KB1=/home/ubuntu/xs-kb1; KB2=/home/ubuntu/xs-kb2
FE=/home/ubuntu/xs-fe;   FB=/home/ubuntu/xs-fb

cleanup() {
  fusermount3 -u "$FE" 2>/dev/null || true
  fusermount3 -u "$FB" 2>/dev/null || true
  for m in "$KE1" "$KE2" "$KB1" "$KB2"; do sudo -n umount "$m" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$KE1" "$KE2" "$KB1" "$KB2" "$FE" "$FB"

for n in k1 k2 fa; do cp "$W/simg-base.ext4" "$W/simg-$n.ext4"; done
for n in k1 k2 fb; do cp "$W/bimgb-base.btrfs" "$W/bimgb-$n.btrfs"; done
sync

sudo -n mount -o loop "$W/simg-k1.ext4"    "$KE1"
sudo -n mount -o loop "$W/simg-k2.ext4"    "$KE2"
sudo -n mount -o loop "$W/bimgb-k1.btrfs"  "$KB1"
sudo -n mount -o loop "$W/bimgb-k2.btrfs"  "$KB2"
sudo -n chown -R "$(id -u):$(id -g)" "$KE1/create-delete-storm" "$KE2/create-delete-storm" \
                                     "$KB1/create-delete-storm" "$KB2/create-delete-storm"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256|codegen_isa|pgo_profile" || true

start_fuse() {  # $1=cpus $2=mnt $3=img $4=suffix $5=env
  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $5 \
    taskset -c "$1" "$ELF" mount --rw "$3" "$2" >> "$W/xfuse-$TAG-$4.log" 2>&1 &
  echo $!
}
EPID=$(start_fuse "$FE_CPUS" "$FE" "$W/simg-fa.ext4"   "e" "$FE_ENV")
BPID=$(start_fuse "$FB_CPUS" "$FB" "$W/bimgb-fb.btrfs" "b" "$FB_ENV")

wait_mount() {
  for _ in $(seq 1 300); do
    mountpoint -q "$1" && return 0
    kill -0 "$2" 2>/dev/null || { echo "daemon $2 died"; tail -20 "$3"; return 1; }
    sleep 0.1
  done
  echo "mount $1 never came up"; tail -20 "$3"; return 1
}
wait_mount "$FE" "$EPID" "$W/xfuse-$TAG-e.log"
wait_mount "$FB" "$BPID" "$W/xfuse-$TAG-b.log"

echo "== ffs_ext4 pid $EPID cpus $FE_CPUS env '$FE_ENV'"
echo "== ffs_btr  pid $BPID cpus $FB_CPUS env '$FB_ENV'"
echo "== client cpu $CPU, $OPS create+delete pairs per batch"

"$W/storm_ab" "$ROUNDS" "$OPS" "$CPU" "$EPID" \
  "kext4_1=$KE1" "kext4_2=$KE2" "kbtr_1=$KB1" "kbtr_2=$KB2" \
  "ffs_ext4=$FE" "ffs_btr=$FB" | tee "$W/xstorm-$TAG.csv"

echo "== unmount + census"
fusermount3 -u "$FE"; wait "$EPID" 2>/dev/null || true
echo "--- ffs_ext4"; grep -h "crossings_total\|op_counts" "$W/xfuse-$TAG-e.log" | tail -2 || true
fusermount3 -u "$FB"; wait "$BPID" 2>/dev/null || true
echo "--- ffs_btr";  grep -h "crossings_total\|op_counts" "$W/xfuse-$TAG-b.log" | tail -2 || true
