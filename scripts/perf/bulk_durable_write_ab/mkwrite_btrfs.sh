#!/bin/bash
# Fresh btrfs fixtures for the write-side instructions-per-op comparison.
#
# Two independent images so the kernel arm and the FUSE arm never share a device, and
# BOTH are prepared identically: a fresh mkfs leaves the root directory owned by root,
# so each image is mounted once through the KERNEL, chowned to the running user, and
# unmounted. Doing that to only one image (or chowning a live mountpoint on one arm
# only) makes the arms asymmetric — the FUSE arm then fails with EACCES on the first
# create, which is a fixture defect and not a result.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
MIB=${MIB:-1024}
PREP=/home/ubuntu/bwprep

mkdir -p "$PREP"
for n in k f; do
  python3 -c "
import os
f = os.open('$W/bimgb-$n.btrfs', os.O_CREAT | os.O_RDWR, 0o644)
os.ftruncate(f, $MIB * 1024 * 1024)
os.close(f)"
  "$(command -v mkfs.btrfs)" -q -f "$W/bimgb-$n.btrfs"

  # Same preparation on both images, through the kernel, so neither arm is privileged.
  sudo -n mount -o loop "$W/bimgb-$n.btrfs" "$PREP"
  sudo -n chown "$(id -u):$(id -g)" "$PREP"
  sync
  sudo -n umount "$PREP"
done
rmdir "$PREP" 2>/dev/null || true

btrfs check --readonly "$W/bimgb-k.btrfs" >/dev/null 2>&1 || { echo "btrfs check FAILED"; exit 1; }
echo "write fixtures ready: $W/bimgb-{k,f}.btrfs (${MIB} MiB each, root owned by $(id -u))"
