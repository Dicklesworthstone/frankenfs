#!/usr/bin/env bash
# bd-c5210 pre-measurement check: does moving the parallel-read fixture from
# `mke2fs -d` to through-the-mount creation change the on-disk EXTENT layout, not
# just the directory index?
#
# This matters because parallel-read files carry 256 KiB of content each (unlike
# readdir+stat's zero-byte entries), and the workload is a read benchmark. A
# layout change would be a second, independent confound in any re-measurement.
set -u -o pipefail
BASE=$(mktemp -d "${TMPDIR:-/data/tmp}/ffs-extent-layout-XXXXXX")
echo "scratch: $BASE"
cd "$BASE"

mkdir -p fix/parallel-read mnt
i=0
while [ "$i" -lt 4 ]; do
  head -c 262144 /dev/urandom > "fix/parallel-read/read-00000${i}.bin"
  i=$((i + 1))
done

fallocate -l 512M baked.img
fallocate -l 512M mount.img
mke2fs -t ext4 -F -q -b 4096 -d fix baked.img 2>/dev/null
mke2fs -t ext4 -F -q -b 4096 mount.img 2>/dev/null

sudo mount -o loop mount.img mnt || exit 1
sudo mkdir -p mnt/parallel-read
sudo cp fix/parallel-read/*.bin mnt/parallel-read/
sync
sudo umount mnt

for f in read-000000.bin read-000001.bin; do
  echo "=== $f ==="
  echo -n "  baked  (mke2fs -d)  : "
  debugfs -R "stat /parallel-read/$f" baked.img 2>/dev/null | tr '\n' ' ' | grep -oE 'EXTENTS:.*' | head -c 200; echo
  echo -n "  seeded (thru mount) : "
  debugfs -R "stat /parallel-read/$f" mount.img 2>/dev/null | tr '\n' ' ' | grep -oE 'EXTENTS:.*' | head -c 200; echo
done
