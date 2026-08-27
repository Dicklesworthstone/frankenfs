#!/bin/bash
# btrfs fixture for parallel-metadata-write: parallel-metadata/worker-0..N-1, empty.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
THREADS=${THREADS:-8}
MIB=${MIB:-1024}
SEED="$W/pmetaseed_btrfs"
mkdir -p "$SEED/parallel-metadata"
find "$SEED" -mindepth 2 -delete 2>/dev/null || true
for w in $(seq 0 $((THREADS-1))); do mkdir -p "$SEED/parallel-metadata/worker-$w"; done

python3 -c "
import os
p='$W/pimgb-base.btrfs'
if os.path.exists(p): os.remove(p)
f=os.open(p, os.O_CREAT|os.O_RDWR, 0o644)
os.ftruncate(f, $MIB*1024*1024)
os.close(f)
"
mkfs.btrfs -f -q -r "$SEED" "$W/pimgb-base.btrfs"
for n in k1 k2 fa fb; do cp "$W/pimgb-base.btrfs" "$W/pimgb-$n.btrfs"; done
sha256sum "$W/pimgb-base.btrfs"
