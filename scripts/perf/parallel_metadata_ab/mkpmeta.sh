#!/bin/bash
# Fixture for parallel-metadata-write: parallel-metadata/worker-0..N-1, empty.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
THREADS=${THREADS:-8}
MIB=${MIB:-512}
SEED="$W/pmetaseed"

rm -rf "$SEED"; mkdir -p "$SEED/parallel-metadata"
for w in $(seq 0 $((THREADS-1))); do mkdir -p "$SEED/parallel-metadata/worker-$w"; done

rm -f "$W/pimg-base.ext4"
python3 -c "
import os
f=os.open('$W/pimg-base.ext4', os.O_CREAT|os.O_RDWR, 0o644)
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
mke2fs -t ext4 -O ^has_journal -F -q -b 4096 -i 4096 -d "$SEED" "$W/pimg-base.ext4"
e2fsck -fn "$W/pimg-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/pimg-base.ext4" "$W/pimg-$n.ext4"; done
sha256sum "$W/pimg-base.ext4"
