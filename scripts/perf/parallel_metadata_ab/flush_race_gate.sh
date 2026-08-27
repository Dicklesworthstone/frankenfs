#!/bin/bash
# Concurrent-committer gate for FFS_MVCC_FLUSH_BORROW. Mutator threads churn the
# shard maps while fsync threads hammer directory fsyncs, so the two-pass flush walk
# runs with commits landing between its passes. Then quiesce, sweep the tree empty,
# unmount, e2fsck, and require free inodes back at the pristine value.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
MUT=${MUT:-8}
FSY=${FSY:-4}
SECS=${SECS:-10}
DIRS=${DIRS:-8}
FENV=${FENV:-}
FM=/home/ubuntu/fr-fa
V=/home/ubuntu/fr-verify
TAG=${TAG:-fr}

fusermount3 -u "$FM" 2>/dev/null || true
sudo -n umount "$V" 2>/dev/null || true
mkdir -p "$FM" "$V"
python3 "$W/mkcopy.py" "$W/pimg-base.ext4" "$W/pimg-fr.ext4"

# shellcheck disable=SC2086
env RUST_LOG=warn $FENV taskset -c 8-15 "$ELF" mount --rw "$W/pimg-fr.ext4" "$FM" \
  >> "$W/frfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "FAIL: no mount"; exit 1; }

rc=0
out=$("$W/flush_race" "$FM" "$MUT" "$FSY" "$SECS" "$DIRS") || rc=$?
echo "  $out"

fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true

if e2fsck -fn "$W/pimg-fr.ext4" >/dev/null 2>&1; then fsck=clean; else fsck=DIRTY; fi
sudo -n mount -o loop,ro "$W/pimg-fr.ext4" "$V"
left=$(find "$V/parallel-metadata" -type f 2>/dev/null | wc -l)
sudo -n umount "$V"
fi_now=$(dumpe2fs -h "$W/pimg-fr.ext4" 2>/dev/null | awk -F: '/Free inodes:/{gsub(/ /,"",$2);print $2}')
fi_base=$(dumpe2fs -h "$W/pimg-base.ext4" 2>/dev/null | awk -F: '/Free inodes:/{gsub(/ /,"",$2);print $2}')

if [ "$rc" = "0" ] && [ "$fsck" = "clean" ] && [ "$left" = "0" ] && [ "$fi_now" = "$fi_base" ]; then
  echo "PASS borrow_env='$FENV' e2fsck=$fsck left=$left free_inodes=$fi_now/$fi_base"
else
  echo "FAIL borrow_env='$FENV' rc=$rc e2fsck=$fsck left=$left free_inodes=$fi_now/$fi_base"
  exit 1
fi
