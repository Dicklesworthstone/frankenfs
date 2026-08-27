#!/bin/bash
# Build the ext4 xattr-get-list-report fixture exactly as
# `ffs_mounted_kernel_bench::seed_ext4_xattr_fixture` does: one INLINE xattr that
# must stay in the inode body, one 512-byte EXTERNAL xattr that must allocate an
# xattr block, and a 24-name file whose list also lives out of line. The storage
# shape is the point of the row, so it is asserted, not assumed.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
MIB=${MIB:-512}
SEED="$W/xattrseed"
rm -rf "$SEED"; mkdir -p "$SEED"
for f in xattr-inline.bin xattr-external.bin xattr-many.bin; do : > "$SEED/$f"; done

rm -f "$W/ximg-base.ext4"
python3 -c "
import os
f=os.open('$W/ximg-base.ext4', os.O_CREAT|os.O_RDWR, 0o644)
os.ftruncate(f, $MIB*1024*1024); os.close(f)"
mke2fs -t ext4 -F -q -b 4096 -d "$SEED" "$W/ximg-base.ext4"

EXT=$(python3 -c "print(''.join(chr(ord('A')+i%26) for i in range(512)))")
debugfs -w -R "ea_set xattr-inline.bin user.inline inline-value" "$W/ximg-base.ext4" >/dev/null 2>&1
debugfs -w -R "ea_set xattr-external.bin user.external $EXT" "$W/ximg-base.ext4" >/dev/null 2>&1
for i in $(seq 0 23); do
  n=$(printf "user.item%02d" "$i"); v=$(printf "%02d" "$i")
  debugfs -w -R "ea_set xattr-many.bin $n $v" "$W/ximg-base.ext4" >/dev/null 2>&1
done

acl() { debugfs -R "stat <$(debugfs -R "ls -l /" "$W/ximg-base.ext4" 2>/dev/null | awk -v f="$1" '$NF==f{print $1}')>" "$W/ximg-base.ext4" 2>/dev/null | awk '/File ACL:/{print $3}'; }
inline_acl=$(acl xattr-inline.bin); ext_acl=$(acl xattr-external.bin); many_acl=$(acl xattr-many.bin)
echo "storage shape: inline File ACL=$inline_acl (want 0)  external=$ext_acl (want !=0)  many=$many_acl (want !=0)"
[ "$inline_acl" = "0" ] || { echo "FAIL: small xattr escaped the inode body"; exit 1; }
[ "$ext_acl" != "0" ] || { echo "FAIL: 512-byte xattr did not allocate a block"; exit 1; }
[ "$many_acl" != "0" ] || { echo "FAIL: 24-name list did not allocate a block"; exit 1; }

e2fsck -fn "$W/ximg-base.ext4" >/dev/null 2>&1 || { echo "e2fsck FAILED"; exit 1; }
for n in k1 k2 fa fb; do cp "$W/ximg-base.ext4" "$W/ximg-$n.ext4"; done
echo "fixture ready: $W/ximg-base.ext4"
