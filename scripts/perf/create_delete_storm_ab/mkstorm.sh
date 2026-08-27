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
mke2fs -t ext4 -F -q -b 4096 -i 4096 -d "$SEED" "$W/simg-base.ext4"
e2fsck -fn "$W/simg-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/simg-base.ext4" "$W/simg-$n.ext4"; done
sha256sum "$W/simg-base.ext4"
