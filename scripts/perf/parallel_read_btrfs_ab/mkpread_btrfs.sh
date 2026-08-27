#!/bin/bash
# The btrfs twin of parallel_read_ab/mkpread.sh: 256 x 256 KiB files written THROUGH A
# KERNEL MOUNT so btrfs lays them out natively — and, critically for bd-6kpp4, so the
# kernel writes real crc32c entries into the csum tree. A fixture built any other way
# would not exercise the checksum-verify path this row exists to price.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
N=${N:-256}
BYTES=${BYTES:-262144}
MIB=${MIB:-2048}
SEED=/home/ubuntu/preadb-seed
BASE="$W/rimgb-base.btrfs"

rm -f "$BASE"
python3 -c "
import os
f = os.open('$BASE', os.O_CREAT | os.O_RDWR, 0o644)
os.ftruncate(f, $MIB * 1024 * 1024)
os.close(f)"
"$(command -v mkfs.btrfs)" -q -f "$BASE"

mkdir -p "$SEED"
sudo -n mount -o loop "$BASE" "$SEED"
sudo -n chown "$(id -u):$(id -g)" "$SEED"
mkdir -p "$SEED/parallel-read"
python3 - <<PY
import os
n, nbytes = $N, $BYTES
for i in range(n):
    # Distinct bytes per file so a checksum mismatch cannot hide behind identical
    # content, and so the client's digest is content-sensitive.
    buf = bytes(((i * 31 + j) & 0xFF) for j in range(256)) * (nbytes // 256)
    fd = os.open(os.path.join("$SEED", "parallel-read", "read-%06d.bin" % i), os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, buf)
    os.close(fd)
PY
sync
echo "seeded $(ls -U "$SEED/parallel-read" | wc -l) files"
sudo -n umount "$SEED"
rmdir "$SEED"

btrfs check --readonly "$BASE" >/dev/null 2>&1 || { echo "btrfs check FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$BASE" "$W/rimgb-$n.btrfs"; done
echo "fixture ready: $BASE"
