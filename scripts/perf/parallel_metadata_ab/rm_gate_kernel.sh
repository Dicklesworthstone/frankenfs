#!/bin/bash
# ORACLE CONTROL: run the identical concurrent create+remove stress through a live
# KERNEL ext4 mount. If the kernel also leaves free_blocks below the pristine value,
# the free-block oracle is measuring ext4's directories not shrinking on unlink, not
# a FrankenFS defect.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
THREADS=${THREADS:-16}
OPS=${OPS:-8192}
MODE=${MODE:-shared}
KM=/home/ubuntu/rmg-k
TAG=${TAG:-krm}

sudo -n umount "$KM" 2>/dev/null || true
mkdir -p "$KM"
python3 "$W/mkcopy.py" "$W/pimg-base.ext4" "$W/pimg-krm.ext4"
sudo -n mount -o loop "$W/pimg-krm.ext4" "$KM"
sudo -n chown -R "$(id -u):$(id -g)" "$KM/parallel-metadata"

rc=0
"$W/pmeta_rm" "$KM" "$THREADS" "$OPS" "$MODE" || rc=$?
sync
sudo -n umount "$KM"

if e2fsck -fn "$W/pimg-krm.ext4" >/dev/null 2>&1; then fsck=clean; else fsck=DIRTY; fi
fi_now=$(dumpe2fs -h "$W/pimg-krm.ext4" 2>/dev/null | awk -F: '/Free inodes:/{gsub(/ /,"",$2);print $2}')
fb_now=$(dumpe2fs -h "$W/pimg-krm.ext4" 2>/dev/null | awk -F: '/Free blocks:/{gsub(/ /,"",$2);print $2}')
fi_base=$(dumpe2fs -h "$W/pimg-base.ext4" 2>/dev/null | awk -F: '/Free inodes:/{gsub(/ /,"",$2);print $2}')
fb_base=$(dumpe2fs -h "$W/pimg-base.ext4" 2>/dev/null | awk -F: '/Free blocks:/{gsub(/ /,"",$2);print $2}')
echo "KERNEL mode=$MODE threads=$THREADS ops=$OPS rc=$rc e2fsck=$fsck free_inodes=$fi_now/$fi_base free_blocks=$fb_now/$fb_base"
