#!/bin/bash
# Fixture for parallel-read-8t, built the BANKABLE way (bd-c5210): mkfs, then write
# the 256 x 256 KiB files THROUGH A KERNEL MOUNT so ext4 lays them out natively.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
N=${N:-256}
BYTES=${BYTES:-262144}
MIB=${MIB:-512}
SEED=/home/ubuntu/pread-seed

python3 -c "
import os
p='$W/rimg-base.ext4'
if os.path.exists(p): os.remove(p)
f=os.open(p, os.O_CREAT|os.O_RDWR, 0o644)
os.ftruncate(f, $MIB*1024*1024)
os.close(f)
"
mke2fs -t ext4 -F -q -b 4096 -i 4096 "$W/rimg-base.ext4"

mkdir -p "$SEED"
sudo -n mount -o loop "$W/rimg-base.ext4" "$SEED"
sudo -n chown "$(id -u):$(id -g)" "$SEED"
mkdir -p "$SEED/parallel-read"
python3 - <<PY
import os
d = "$SEED/parallel-read"
n, nbytes = $N, $BYTES
for i in range(n):
    # deterministic per-index payload, same spirit as the harness fixture
    body = bytes(((i * 131 + j * 7) & 0xFF) for j in range(256)) * (nbytes // 256)
    fd = os.open(os.path.join(d, "read-%06d.bin" % i), os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, body)
    os.close(fd)
PY
echo "seeded $(ls -U "$SEED/parallel-read" | wc -l) files of $BYTES bytes"
sync
sudo -n umount "$SEED"
rmdir "$SEED"

e2fsck -fn "$W/rimg-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/rimg-base.ext4" "$W/rimg-$n.ext4"; done
sha256sum "$W/rimg-base.ext4"
