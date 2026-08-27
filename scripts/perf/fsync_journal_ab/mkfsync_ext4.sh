#!/bin/bash
# ext4 fixtures for fsync-journal-commit: one 4096-byte `fsync.bin` at the root.
# Two images are built: the normal journalled one, and a `^has_journal` copy so
# bd-4zjkz's three-way decomposition can run WITH A BARRIER COUNT this time.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
MIB=${MIB:-512}
SEED="$W/fsyncseed_ext4"
mkdir -p "$SEED"
find "$SEED" -mindepth 1 -delete 2>/dev/null || true
python3 -c "
import os
fd = os.open('$SEED/fsync.bin', os.O_CREAT | os.O_WRONLY, 0o644)
os.write(fd, b'\x00' * 4096); os.fsync(fd); os.close(fd)
p = '$W/fsimg4-base.ext4'
if os.path.exists(p): os.remove(p)
f = os.open(p, os.O_CREAT | os.O_RDWR, 0o644)
os.ftruncate(f, $MIB * 1024 * 1024)
os.close(f)
"
mke2fs -t ext4 -F -q -b 4096 -d "$SEED" "$W/fsimg4-base.ext4"
e2fsck -fn "$W/fsimg4-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }

# the unjournalled reference image (bd-4zjkz's middle arm)
python3 "$W/mkcopy.py" "$W/fsimg4-base.ext4" "$W/fsimg4-nojrnl.ext4"
e2fsck -fy "$W/fsimg4-nojrnl.ext4" >/dev/null 2>&1 || true
tune2fs -O ^has_journal "$W/fsimg4-nojrnl.ext4" >/dev/null
e2fsck -fy "$W/fsimg4-nojrnl.ext4" >/dev/null 2>&1 || true
echo "journalled:   $(dumpe2fs -h "$W/fsimg4-base.ext4"   2>/dev/null | grep -c has_journal) has_journal hits"
echo "unjournalled: $(dumpe2fs -h "$W/fsimg4-nojrnl.ext4" 2>/dev/null | grep -c has_journal) has_journal hits"
sha256sum "$W/fsimg4-base.ext4" "$W/fsimg4-nojrnl.ext4"
