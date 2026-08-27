#!/bin/bash
# btrfs fixture for fsync-journal-commit: one 4096-byte `fsync.bin` at the root.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
MIB=${MIB:-1024}
SEED="$W/fsyncseed"
mkdir -p "$SEED"
find "$SEED" -mindepth 1 -delete 2>/dev/null || true
python3 -c "
import os
fd = os.open('$SEED/fsync.bin', os.O_CREAT | os.O_WRONLY, 0o644)
os.write(fd, b'\x00' * 4096); os.fsync(fd); os.close(fd)
p = '$W/fsimg-base.btrfs'
if os.path.exists(p): os.remove(p)
f = os.open(p, os.O_CREAT | os.O_RDWR, 0o644)
os.ftruncate(f, $MIB * 1024 * 1024)
os.close(f)
"
mkfs.btrfs -f -q -r "$SEED" "$W/fsimg-base.btrfs"
for n in k1 k2 fa fb; do cp "$W/fsimg-base.btrfs" "$W/fsimg-$n.btrfs"; done
sha256sum "$W/fsimg-base.btrfs"
