#!/bin/bash
# Why does holding a descriptor NOT remove the capability probe on the xattr row?
#
# On the warm-stat row, fstat(fd) took `__audit_inode` from 20,004 to 4 and the row
# to zero blocking crossings: no path resolution, no audit inode record, no probe.
# The campaign's model predicted the same for fgetxattr on the xattr row. It does
# NOT hold — fd mode measured the same crossings and the same blocking crossings as
# path mode. This counts the kernel functions directly to find out which of them is
# still firing, on the LIVE KERNEL arm where no FUSE is involved at all.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
N=${N:-2000}
KMNT=/home/ubuntu/xfd-k
DEV=""

cleanup() {
  sudo -n umount "$KMNT" 2>/dev/null || true
  [ -n "$DEV" ] && sudo -n losetup -d "$DEV" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$KMNT"

DEV=$(sudo -n losetup --find --show "$W/ximg-base.ext4")
sudo -n mount -o ro "$DEV" "$KMNT"

probe() {  # $1=label $2=extra env
  local out="$W/fdcap-$1.txt"
  sudo -n bpftrace -e '
kprobe:get_vfs_caps_from_disk /comm == "xblockprobe"/ { @caps = count(); }
kprobe:__audit_inode         /comm == "xblockprobe"/ { @audit_inode = count(); }
kprobe:vfs_getxattr          /comm == "xblockprobe"/ { @vfs_getxattr = count(); }
interval:s:60 { exit(); }' > "$out" 2>&1 &
  local bp=$!
  for _ in $(seq 1 100); do grep -q "Attaching" "$out" 2>/dev/null && break; sleep 0.1; done
  sleep 1
  # shellcheck disable=SC2086
  env $2 taskset -c 8 "$W/xblockprobe" "$KMNT" "$N" | head -1 | sed 's/^/  /'
  sudo -n pkill -INT -x bpftrace 2>/dev/null || true
  wait "$bp" 2>/dev/null || true
  echo "    $(grep -E '^@' "$out" | tr '\n' ' ')"
}

echo "--- path addressing"
probe path ""
echo "--- fd addressing"
probe fd "XPROBE_FD=1"
