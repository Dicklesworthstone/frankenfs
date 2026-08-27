#!/bin/bash
# Is the security.capability probe UNCONDITIONAL kernel behaviour, or something the
# FUSE mount provokes?
#
# This decides how to read the campaign's biggest read-side result. Four rows reached
# "kernel parity" by suppressing the probe, and the worst row (ext4
# xattr-get-list-report) spends exactly 50.0% of its crossings on it. If the kernel
# performs the same capability lookup on EVERY path resolution regardless of
# filesystem, then FUSE's extra cost is purely the round trip and the 50% is a
# permanent floor. If the kernel arm does NOT do it, the probe is ours and is a
# defect rather than a floor.
#
# The comparison must be like-for-like, so both arms run the SAME client binary over
# the SAME fixture on the SAME host, and the probe counts come from one bpftrace
# session per arm counting `get_vfs_caps_from_disk` attributed to the client comm.
#
# get_vfs_caps_from_disk is the function that reads security.capability off the inode;
# counting it directly avoids arguing from the FUSE side of the boundary.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
N=${N:-2000}
KMNT=/home/ubuntu/capsrc-k
FMNT=/home/ubuntu/capsrc-f
LOOPS=""

cleanup() {
  fusermount3 -u "$FMNT" 2>/dev/null || true
  sudo -n umount "$KMNT" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$KMNT" "$FMNT"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256" || true
echo "== workload: $N reports x 5 path-based xattr syscalls, identical client both arms"

probe_run() {  # $1=label $2=mountpoint
  local out="$W/capsrc-$1.txt"
  sudo -n bpftrace -e "
kprobe:get_vfs_caps_from_disk /comm == \"xblockprobe\"/ { @caps = count(); }
kprobe:__vfs_getxattr        /comm == \"xblockprobe\"/ { @vfs_getxattr = count(); }
interval:s:120 { exit(); }" > "$out" 2>&1 &
  local bp=$!
  # Give bpftrace time to attach; a probe that attaches late undercounts and would
  # look exactly like the finding this script exists to test.
  for _ in $(seq 1 100); do grep -q "Attaching" "$out" 2>/dev/null && break; sleep 0.1; done
  sleep 1

  taskset -c 8 "$W/xblockprobe" "$2" "$N"

  sudo -n pkill -INT -x bpftrace 2>/dev/null || true
  wait "$bp" 2>/dev/null || true
  echo "  $(grep -E '^@(caps|vfs_getxattr)' "$out" | tr '\n' ' ')"
}

# Arm 1: the live incumbent — kernel ext4 on a loop device.
dev=$(sudo -n losetup --find --show "$W/ximg-base.ext4")
sudo -n losetup --direct-io=on "$dev" 2>/dev/null || true
LOOPS="$LOOPS $dev"
sudo -n mount -o ro "$dev" "$KMNT"
echo "--- kernel ext4 (live incumbent)"
probe_run kernel "$KMNT"
sudo -n umount "$KMNT"

# Arm 2: FrankenFS over FUSE, same fixture, same client.
cp "$W/ximg-base.ext4" "$W/ximg-caps.ext4"
sync
fdev=$(sudo -n losetup --find --show "$W/ximg-caps.ext4")
sudo -n losetup --direct-io=on "$fdev" 2>/dev/null || true
sudo -n chown "$(id -u)" "$fdev"
LOOPS="$LOOPS $fdev"
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn \
  taskset -c 18 "$ELF" mount "$fdev" "$FMNT" >> "$W/capsrc-fuse.log" 2>&1 &
fpid=$!
for _ in $(seq 1 200); do mountpoint -q "$FMNT" && break; kill -0 "$fpid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$FMNT" || { echo "fuse mount never came up"; tail -5 "$W/capsrc-fuse.log"; exit 1; }
echo "--- FrankenFS (FUSE)"
probe_run fuse "$FMNT"
fusermount3 -u "$FMNT"; wait "$fpid" 2>/dev/null || true
grep -o "crossings_getxattr=[0-9]*" "$W/capsrc-fuse.log" | tail -1 | sed 's/^/  daemon /'
