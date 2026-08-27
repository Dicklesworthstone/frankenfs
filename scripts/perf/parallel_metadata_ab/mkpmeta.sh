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
# ⛔ THIS ROW IS CURRENTLY BLOCKED, and the fixture is left JOURNALLED on purpose.
#
# 94fdba50b refuses a writable JOURNALLED ext4 mount ("the mounted fsync path has
# no active JBD2 durability writer"), so this fixture no longer mounts --rw and the
# row fails LOUDLY at mount.
#
# The obvious fix -- rebuild with `-O ^has_journal`, which the guard permits -- was
# measured 2026-08-27 and is WORSE THAN THE BLOCK: it collapses the KERNEL arm.
# Same rig, same rounds, kernel k1 on this row:
#     journalled   create   29.4 ms   total   89.0 ms
#     no-journal   create 3942.3 ms   total 3986.8 ms      (134x / 44.8x slower)
# A no-journal ext4 cannot batch metadata into a transaction, so on a `--direct-io`
# loop device every create's inode-table and bitmap update goes to the device
# individually. The resulting `k1/ffsA = 7.106774` is FrankenFS "beating" kernel
# ext4 sevenfold, and it is a fixture artifact, not a result.
#
# So: journalled = refused at mount (safe), no-journal = a silent 7x fake win
# (dangerous). The fixture stays journalled so the failure is the loud one. The
# real fix is the one 94fdba50b's own doc names: route the mounted fsync path
# through the JBD2 writer. btrfs mutating rows are unaffected and are where write
# work can still be measured today.
mke2fs -t ext4 -F -q -b 4096 -i 4096 -d "$SEED" "$W/pimg-base.ext4"
e2fsck -fn "$W/pimg-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/pimg-base.ext4" "$W/pimg-$n.ext4"; done
sha256sum "$W/pimg-base.ext4"
