#!/bin/bash
# Concurrent-UNLINK correctness gate for FFS_FUSE_CONCURRENT_MUTATIONS.
# Mounts one FrankenFS --rw ext4 image, runs the concurrent create+remove stress,
# unmounts, then e2fscks the image and checks the tree is empty through a KERNEL
# mount. Prints one PASS/FAIL line per invocation.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
THREADS=${THREADS:-8}
OPS=${OPS:-4096}
MODE=${MODE:-shared}
FENV=${FENV:-}
FM=/home/ubuntu/rmg-fa
V=/home/ubuntu/rmg-verify
TAG=${TAG:-rmg}

fusermount3 -u "$FM" 2>/dev/null || true
sudo -n umount "$V" 2>/dev/null || true
mkdir -p "$FM" "$V"
python3 "$W/mkcopy.py" "$W/pimg-base.ext4" "$W/pimg-rmg.ext4"

# shellcheck disable=SC2086
env RUST_LOG=warn $FENV taskset -c 8-15 "$ELF" mount --rw "$W/pimg-rmg.ext4" "$FM" \
  >> "$W/rmgfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "FAIL: no mount"; exit 1; }

rc=0
"$W/pmeta_rm" "$FM" "$THREADS" "$OPS" "$MODE" || rc=$?

fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true

if e2fsck -fn "$W/pimg-rmg.ext4" >/dev/null 2>&1; then fsck=clean; else fsck=DIRTY; fi
sudo -n mount -o loop,ro "$W/pimg-rmg.ext4" "$V"
left=$(find "$V/parallel-metadata" -type f 2>/dev/null | wc -l)
sudo -n umount "$V"

# SHARPER ORACLE than "e2fsck says ok": after creating and removing every file the
# image must return to the PRISTINE free-inode / free-block counts. A leaked inode,
# a double-freed block or a lost directory entry moves these even when e2fsck -fn is
# happy about internal consistency.
fi_now=$(dumpe2fs -h "$W/pimg-rmg.ext4" 2>/dev/null | awk -F: '/Free inodes:/{gsub(/ /,"",$2);print $2}')
fb_now=$(dumpe2fs -h "$W/pimg-rmg.ext4" 2>/dev/null | awk -F: '/Free blocks:/{gsub(/ /,"",$2);print $2}')
fi_base=$(dumpe2fs -h "$W/pimg-base.ext4" 2>/dev/null | awk -F: '/Free inodes:/{gsub(/ /,"",$2);print $2}')
fb_base=$(dumpe2fs -h "$W/pimg-base.ext4" 2>/dev/null | awk -F: '/Free blocks:/{gsub(/ /,"",$2);print $2}')

# The free-BLOCK comparison against pristine is CONFOUNDED: ext4 does not shrink a
# directory on unlink, so both arms end below the pristine count. Measured control:
# kernel ext4 running this identical stress leaves free_blocks=118470 against a
# pristine 118534. The usable oracle is therefore free INODES exactly pristine (a
# leaked or double-freed inode moves it) plus e2fsck clean plus an empty tree; the
# block count is RECORDED for comparison against the kernel reference, not gated.
if [ "$rc" = "0" ] && [ "$fsck" = "clean" ] && [ "$left" = "0" ] \
   && [ "$fi_now" = "$fi_base" ]; then
  echo "PASS mode=$MODE threads=$THREADS ops=$OPS e2fsck=$fsck left=$left free_inodes=$fi_now/$fi_base free_blocks=$fb_now/$fb_base"
else
  echo "FAIL mode=$MODE threads=$THREADS ops=$OPS rc=$rc e2fsck=$fsck left=$left free_inodes=$fi_now/$fi_base free_blocks=$fb_now/$fb_base"
  exit 1
fi
