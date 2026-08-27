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
mke2fs -t ext4 -F -q -b 4096 -i 4096 -d "$SEED" "$W/simg-base.ext4"
e2fsck -fn "$W/simg-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/simg-base.ext4" "$W/simg-$n.ext4"; done
sha256sum "$W/simg-base.ext4"
