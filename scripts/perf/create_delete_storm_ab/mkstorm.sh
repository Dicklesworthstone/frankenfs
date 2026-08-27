#!/bin/bash
# Fixture for create-delete-storm: one empty create-delete-storm/ directory,
# baked into the image by `mke2fs -d`.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
MIB=${MIB:-512}
SEED="$W/stormseed"
mkdir -p "$SEED/create-delete-storm"
find "$SEED" -mindepth 2 -delete 2>/dev/null || true

python3 -c "
import os
p='$W/simg-base.ext4'
if os.path.exists(p): os.remove(p)
f=os.open(p, os.O_CREAT|os.O_RDWR, 0o644)
os.ftruncate(f, $MIB*1024*1024)
os.close(f)
"
# NO JOURNAL, deliberately (94fdba50b + bd-4zjkz). A writable journalled ext4
# mount is REFUSED as of 94fdba50b -- the mounted fsync path never calls
# commit_transaction_journaled, so a journalled image would look durable while
# skipping descriptor and commit blocks. bd-4zjkz separately established that our
# write path matches UNJOURNALLED kernel ext4 EXACTLY (128 sectors / 24 write I/Os
# / 8 flushes against the journalled kernel's 256/24/16), so a no-journal image is
# also the only form in which the FUSE and kernel arms are the same durability
# class. Both reasons point the same way.
mke2fs -t ext4 -O ^has_journal -F -q -b 4096 -i 4096 -d "$SEED" "$W/simg-base.ext4"
e2fsck -fn "$W/simg-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/simg-base.ext4" "$W/simg-$n.ext4"; done
sha256sum "$W/simg-base.ext4"
