#!/bin/bash
# btrfs fixture for create-delete-storm, built the way the comparator does:
# `mkfs.btrfs -f -q -r <fixture_root> <image>`.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
MIB=${MIB:-1024}
SEED="$W/stormseed"
mkdir -p "$SEED/create-delete-storm"
find "$SEED" -mindepth 2 -delete 2>/dev/null || true

python3 -c "
import os
p='$W/bimgb-base.btrfs'
if os.path.exists(p): os.remove(p)
f=os.open(p, os.O_CREAT|os.O_RDWR, 0o644)
os.ftruncate(f, $MIB*1024*1024)
os.close(f)
"
mkfs.btrfs -f -q -r "$SEED" "$W/bimgb-base.btrfs"
for n in k1 k2 fb; do cp "$W/bimgb-base.btrfs" "$W/bimgb-$n.btrfs"; done
sha256sum "$W/bimgb-base.btrfs"
