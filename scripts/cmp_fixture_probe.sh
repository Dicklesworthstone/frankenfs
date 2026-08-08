#!/usr/bin/env bash
# bd-3zx2x: does the MOUNTED COMPARATOR's ext4 fixture get an htree?
#
# ffs_mounted_kernel_bench builds all `operations` entries on the HOST
# (build_fixture_tree, Workload::ReaddirStat8) and bakes the tree into the image
# with `mke2fs -d fixture_root`. PlumRiver showed that `mke2fs -d` writes linear
# directory blocks and never builds the htree; he voided one of his own runs over
# exactly that. This reproduces the comparator's construction verbatim and asks
# debugfs, rather than assuming either way.
set -u -o pipefail

BASE=/tmp/zx2x-cmpfix
FIX="$BASE/fixture"
IMG="$BASE/ext4.img"
N="${1:-32768}"

mkdir -p "$FIX/large-directory" || exit 1
i=0
while [ "$i" -lt "$N" ]; do
  printf '' > "$FIX/large-directory/entry-$(printf '%08d' "$i")"
  i=$((i+1))
done
echo "host fixture entries: $(ls -U "$FIX/large-directory" | wc -l)"

fallocate -l 2048M "$IMG" || exit 1
# Verbatim from create_base_image(FilesystemKind::Ext4, ...).
mke2fs -t ext4 -F -q -b 4096 -d "$FIX" "$IMG" || exit 1
echo "mke2fs -d completed"

echo "--- dumpe2fs feature line ---"
dumpe2fs -h "$IMG" 2>/dev/null | grep -i "Filesystem features"
echo "--- debugfs htree_dump /large-directory ---"
debugfs -R "htree_dump /large-directory" "$IMG" 2>&1 | head -6
