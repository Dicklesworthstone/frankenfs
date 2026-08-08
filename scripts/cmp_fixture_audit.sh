#!/usr/bin/env bash
# bd-plkzd residual audit: which OTHER comparator fixtures does `mke2fs -d` leave
# unindexed, and would a real (through-the-mount) ext4 have indexed them?
#
# Two arms per shape, same entry count and same name length:
#   BAKED  — reproduce create_base_image's ext4 path verbatim (`mke2fs -d`)
#   MOUNT  — mkfs an empty image, mount it, create the entries through the mount
# then ask debugfs which of them is hash-indexed. Assumption-free: the second arm
# IS the counterfactual, not a rule quoted from the ext4 docs. The 3-entry shape
# is the negative control — it must come back UNINDEXED on both arms, or the
# discriminator is measuring "did we mount it" rather than "is it indexed".
#
# Needs sudo (loop mount) and e2fsprogs. Writes to a fresh mktemp -d and does not
# delete anything; remove the printed directory by hand when done.
set -u -o pipefail

BASE=$(mktemp -d "${TMPDIR:-/data/tmp}/cmp-fixture-audit-XXXXXX") || exit 1
echo "scratch: $BASE"

probe() {           # probe <label> <dirname> <count> <name-format>
  local label="$1" dir="$2" n="$3" fmt="$4"
  local fix="$BASE/$label/fix" img_b="$BASE/$label/baked.img" img_m="$BASE/$label/mount.img"
  local mnt="$BASE/$label/mnt"
  mkdir -p "$fix/$dir" "$mnt"

  local i=0
  while [ "$i" -lt "$n" ]; do
    printf '' > "$fix/$dir/$(printf "$fmt" "$i")"; i=$((i+1))
  done

  # Size the image from the entry count, not a constant: mke2fs's default inode
  # ratio is one inode per 16 KiB, so a 512M image tops out around 32k inodes and
  # the 32,768-entry shape silently runs out of BOTH space and inodes — which
  # reads as "no output" from debugfs and looks like a passing control.
  local mib=$(( 512 + n / 8 ))
  fallocate -l "${mib}M" "$img_b"; fallocate -l "${mib}M" "$img_m"
  # verbatim from create_base_image(FilesystemKind::Ext4, ...)
  mke2fs -t ext4 -F -q -b 4096 -d "$fix" "$img_b" >/dev/null 2>&1 \
    || { echo "$label: mke2fs -d FAILED (image too small?)"; return; }
  mke2fs -t ext4 -F -q -b 4096       "$img_m" >/dev/null 2>&1

  sudo mount -o loop "$img_m" "$mnt" 2>/dev/null || { echo "$label: MOUNT FAILED"; return; }
  sudo mkdir -p "$mnt/$dir"
  sudo bash -c "i=0; while [ \$i -lt $n ]; do printf '' > \"$mnt/$dir/\$(printf '$fmt' \$i)\"; i=\$((i+1)); done"
  sudo umount "$mnt"

  local baked mounted
  baked=$(debugfs -R "htree_dump /$dir" "$img_b" 2>&1 | grep -iE "not a hash|Hash Version" | head -1)
  mounted=$(debugfs -R "htree_dump /$dir" "$img_m" 2>&1 | grep -iE "not a hash|Hash Version" | head -1)
  local bytes
  bytes=$(debugfs -R "stat /$dir" "$img_b" 2>/dev/null | grep -oE "Size: [0-9]+" | head -1)
  printf '%-26s n=%-6s dir %s\n' "$label" "$n" "$bytes"
  printf '    mke2fs -d : %s\n' "${baked:-<no output>}"
  printf '    thru mount: %s\n' "${mounted:-<no output>}"
}

echo "=== bd-plkzd residual audit: comparator fixtures built by create_fixture_tree ==="
probe parallel-read       parallel-read      256   'read-%06d.bin'
probe readdir-stat-CONTROL large-directory   32768 'entry-%08d'
probe xattr-3-files       xattr-dir          3     'file-%d'
