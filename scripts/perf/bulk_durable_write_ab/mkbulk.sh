#!/bin/bash
# Build the bulk-durable-write fixture the way the comparator does: `bulk-durable.bin`
# preallocated to chunks*1MiB filled with 0xB7, baked in by `mke2fs -d`.
set -euo pipefail
W=/data/tmp/claude-1000/-data-projects-frankenfs/fa3fd948-7c8c-4eba-a14b-940646d78340/scratchpad
CHUNKS=${CHUNKS:-64}
MIB=${MIB:-512}
SEED="$W/bulkseed"

rm -rf "$SEED"; mkdir -p "$SEED"
python3 - <<PY
import os
n = $CHUNKS * 1024 * 1024
buf = b"\xb7" * (1024 * 1024)
fd = os.open("$SEED/bulk-durable.bin", os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
for _ in range($CHUNKS):
    os.write(fd, buf)
os.fsync(fd); os.close(fd)
assert os.path.getsize("$SEED/bulk-durable.bin") == n
PY

rm -f "$W/bimg-base.ext4"
python3 -c "
import os
f=os.open('$W/bimg-base.ext4', os.O_CREAT|os.O_RDWR, 0o644)
os.ftruncate(f, $MIB*1024*1024)
os.close(f)
"
# NO JOURNAL, deliberately (94fdba50b + bd-4zjkz). A writable journalled ext4
# mount is now REFUSED -- the mounted fsync path never calls
# commit_transaction_journaled, so a journalled image would look durable while
# skipping descriptor and commit blocks. And bd-4zjkz already established that our
# write path matches UNJOURNALLED kernel ext4 exactly (128 sectors / 24 write I/Os
# / 8 flushes against the journalled kernel's 256/24/16), so a no-journal image is
# also the only form in which both arms are the same durability class.
mke2fs -t ext4 -O ^has_journal -F -q -b 4096 -d "$SEED" "$W/bimg-base.ext4"
e2fsck -fn "$W/bimg-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/bimg-base.ext4" "$W/bimg-$n.ext4"; done
sha256sum "$W"/bimg-base.ext4
ls -la "$W"/bimg-*.ext4
