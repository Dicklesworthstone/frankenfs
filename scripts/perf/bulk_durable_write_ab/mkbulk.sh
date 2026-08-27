#!/bin/bash
# Build the bulk-durable-write fixture the way the comparator does: `bulk-durable.bin`
# preallocated to chunks*1MiB filled with 0xB7, baked in by `mke2fs -d`.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
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
mke2fs -t ext4 -F -q -b 4096 -d "$SEED" "$W/bimg-base.ext4"
e2fsck -fn "$W/bimg-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/bimg-base.ext4" "$W/bimg-$n.ext4"; done
sha256sum "$W"/bimg-base.ext4
ls -la "$W"/bimg-*.ext4
