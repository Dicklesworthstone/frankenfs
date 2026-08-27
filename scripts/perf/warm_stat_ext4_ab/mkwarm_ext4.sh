#!/bin/bash
# Warm-stat ext4 fixture (the btrfs twin's mirror, for bd-b07o1): one `payload.bin` created THROUGH A KERNEL MOUNT, so ext4
# lays out its own inode rather than any FrankenFS write path — the same rule the
# ext4 and btrfs readdir+stat fixtures follow.
#
# Deliberately tiny: `warm-stat` stats ONE file repeatedly, so the fixture's job is to
# exist and be warm, not to be large.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
MIB=${MIB:-512}
SEED=/home/ubuntu/warm4-seed
BASE="$W/wimg4-base.ext4"

rm -f "$BASE"
python3 -c "
import os
f = os.open('$BASE', os.O_CREAT | os.O_RDWR, 0o644)
os.ftruncate(f, $MIB * 1024 * 1024)
os.close(f)"
mke2fs -t ext4 -F -q -b 4096 "$BASE"

mkdir -p "$SEED"
sudo -n mount -o loop "$BASE" "$SEED"
sudo -n chown "$(id -u):$(id -g)" "$SEED"
python3 -c "
import os
fd = os.open('$SEED/payload.bin', os.O_CREAT | os.O_WRONLY, 0o644)
os.write(fd, b'\xa5' * 65536)
os.fsync(fd)
os.close(fd)"
sync
sudo -n umount "$SEED"
rmdir "$SEED"

e2fsck -fn "$BASE" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$BASE" "$W/wimg4-$n.ext4"; done
echo "fixture ready: $BASE"
