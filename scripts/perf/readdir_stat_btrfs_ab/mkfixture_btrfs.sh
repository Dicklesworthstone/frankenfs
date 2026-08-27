#!/bin/bash
# The btrfs twin of readdir_stat_ab/mkfixture.sh: build the 32,768-entry directory
# THROUGH A KERNEL MOUNT so btrfs lays out its own DIR_INDEX/DIR_ITEM keys, rather
# than through any FrankenFS write path.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
N=${N:-32768}
MIB=${MIB:-1024}
SEED=/home/ubuntu/rdstatb-seed

rm -f "$W/bimgr-base.btrfs"
python3 -c "
import os
f=os.open('$W/bimgr-base.btrfs', os.O_CREAT|os.O_RDWR, 0o644)
os.ftruncate(f, $MIB*1024*1024); os.close(f)"
mkfs.btrfs -q -f "$W/bimgr-base.btrfs"

mkdir -p "$SEED"
sudo -n mount -o loop "$W/bimgr-base.btrfs" "$SEED"
sudo -n chown "$(id -u):$(id -g)" "$SEED"
mkdir -p "$SEED/large-directory"
python3 - <<PY
import os
d = "$SEED/large-directory"
for i in range($N):
    fd = os.open(os.path.join(d, "entry-%08d" % i), os.O_CREAT | os.O_WRONLY, 0o644)
    os.close(fd)
PY
echo "seeded $(ls -U "$SEED/large-directory" | wc -l) entries"
sync
sudo -n umount "$SEED"
rmdir "$SEED"

btrfs check --readonly "$W/bimgr-base.btrfs" >/dev/null 2>&1 || { echo "btrfs check FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/bimgr-base.btrfs" "$W/bimgr-$n.btrfs"; done
echo "fixture ready: $W/bimgr-base.btrfs"
