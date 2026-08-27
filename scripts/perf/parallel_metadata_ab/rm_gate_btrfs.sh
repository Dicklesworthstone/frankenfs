#!/bin/bash
# Concurrent-mutation correctness gate for FFS_FUSE_CONCURRENT_MUTATIONS on BTRFS.
# The ext4 gate passed 28/28; the ledger's remaining named gaps were "btrfs and
# crash-consistency". This closes the btrfs half (crash-consistency is separate).
#
# Mounts one FrankenFS --rw btrfs image, runs the concurrent create+remove stress,
# unmounts, then runs `btrfs check` (read-only, the fsck equivalent) and verifies the
# tree is empty through a live KERNEL btrfs mount.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
THREADS=${THREADS:-8}
OPS=${OPS:-4096}
MODE=${MODE:-shared}
FENV=${FENV:-}
FM=/home/ubuntu/rmb-fa
V=/home/ubuntu/rmb-verify
TAG=${TAG:-rmb}

fusermount3 -u "$FM" 2>/dev/null || true
sudo -n umount "$V" 2>/dev/null || true
mkdir -p "$FM" "$V"
python3 "$W/mkcopy.py" "$W/pimgb-base.btrfs" "$W/pimgb-rmb.btrfs"

# shellcheck disable=SC2086
env RUST_LOG=warn $FENV taskset -c 8-15 "$ELF" mount --rw "$W/pimgb-rmb.btrfs" "$FM" \
  >> "$W/rmbfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "FAIL: no mount"; exit 1; }

rc=0
"$W/pmeta_rm" "$FM" "$THREADS" "$OPS" "$MODE" || rc=$?

fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true

# `btrfs check` is the strong oracle here: it walks every tree and reports extent,
# ref-count and free-space-cache inconsistencies that a concurrent-mutation defect
# would leave behind, which is what e2fsck did for the ext4 half.
if btrfs check --readonly "$W/pimgb-rmb.btrfs" >"$W/btrfscheck-$TAG.txt" 2>&1; then
  chk=clean
else
  chk=DIRTY
fi

sudo -n mount -o loop,ro "$W/pimgb-rmb.btrfs" "$V" 2>/dev/null && mounted=1 || mounted=0
if [ "$mounted" = "1" ]; then
  left=$(find "$V/parallel-metadata" -type f 2>/dev/null | wc -l)
  sudo -n umount "$V"
else
  left=-1
fi

if [ "$rc" = "0" ] && [ "$chk" = "clean" ] && [ "$left" = "0" ]; then
  echo "PASS mode=$MODE threads=$THREADS ops=$OPS btrfs_check=$chk files_left_on_disk=$left"
else
  echo "FAIL mode=$MODE threads=$THREADS ops=$OPS rc=$rc btrfs_check=$chk files_left_on_disk=$left kernel_mount=$mounted"
  tail -5 "$W/btrfscheck-$TAG.txt" 2>/dev/null || true
  exit 1
fi
