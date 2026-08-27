#!/bin/bash
# Build the readdir-stat-8t fixture the BANKABLE way (bd-plkzd): mkfs, then create
# the 32,768 entries THROUGH A KERNEL MOUNT so ext4 builds its own htree.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
N=${N:-32768}
SEED=/home/ubuntu/rdstat-seed

rm -f "$W/img-base.ext4"
python3 -c "
import os
f=os.open('$W/img-base.ext4', os.O_CREAT|os.O_RDWR, 0o644)
os.ftruncate(f, 512*1024*1024)
os.close(f)
"
mke2fs -t ext4 -F -q -b 4096 -i 4096 "$W/img-base.ext4"

mkdir -p "$SEED"
sudo -n mount -o loop "$W/img-base.ext4" "$SEED"
sudo -n chown "$(id -u):$(id -g)" "$SEED"
mkdir -p "$SEED/large-directory"
python3 - <<PY
import os
d = "$SEED/large-directory"
for i in range($N):
    fd = os.open(os.path.join(d, "entry-%08d" % i), os.O_CREAT|os.O_WRONLY, 0o644)
    os.close(fd)
PY
echo "seeded $(ls -U "$SEED/large-directory" | wc -l) entries"
sync
sudo -n umount "$SEED"
rmdir "$SEED"

e2fsck -fn "$W/img-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
cp "$W/img-base.ext4" "$W/img-k1.ext4"
cp "$W/img-base.ext4" "$W/img-k2.ext4"
cp "$W/img-base.ext4" "$W/img-ffs.ext4"
sha256sum "$W"/img-*.ext4
