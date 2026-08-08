#!/usr/bin/env bash
# bd-pbyu0: minimal MOUNTED reproduction of the ext4 group-descriptor free-inode
# leak, without the four-arm comparator.
#
# Both in-process paths are already known clean at 20,000 allocations (the two
# negative-control tests in ffs-core). What remains untested is everything only a
# real mount has: the kernel VFS driving the operations, the daemon's unmount
# `flush_on_destroy` path, and a base image built by `mke2fs -d` rather than a
# fresh in-test format.
#
# This isolates exactly that: mount FrankenFS on an image built the way the
# comparator builds its base, run the same create/delete storm shape through the
# kernel, unmount, and ask e2fsck.
#
# Usage: pbyu0_mounted_repro.sh <ffs-cli> [cycles] [files-per-cycle] [image-mib]
set -u -o pipefail

FFS_CLI="${1:?usage: pbyu0_mounted_repro.sh <ffs-cli> [cycles] [files] [mib]}"
CYCLES="${2:-40}"
FILES="${3:-2000}"
MIB="${4:-2048}"

BASE=$(mktemp -d "${TMPDIR:-/data/tmp}/ffs-pbyu0-repro-XXXXXX")
chmod 0755 "$BASE"   # mktemp gives 0700; FUSE needs the mountpoint path traversable
echo "scratch: $BASE"
IMG="$BASE/ext4.img"
FIX="$BASE/fixture"
# The mountpoint MUST live under /tmp, not /data/tmp: the comparator uses a
# /tmp MOUNT_ROOT for the same reason — a user FUSE mount under /data/tmp is
# refused with `fusermount3: mount failed: Permission denied`.
MNT=$(mktemp -d "/tmp/ffs-pbyu0-mnt-XXXXXX")
mkdir -p "$FIX/create-delete-storm"

# Built exactly as create_base_image does for a mutating workload: `-d` over a
# fixture tree, which leaves most groups BG_INODE_UNINIT.
fallocate -l "${MIB}M" "$IMG"
mke2fs -t ext4 -F -q -b 4096 -d "$FIX" "$IMG" || { echo "mke2fs failed"; exit 1; }

echo ">> pre-mount e2fsck"
e2fsck -fn "$IMG" >/dev/null 2>&1 && echo "   clean" || { echo "   DIRTY BEFORE WE STARTED"; exit 1; }

# FFS_AUTO_UNMOUNT=0 as the comparator sets it: auto_unmount forces allow_other,
# which needs user_allow_other in /etc/fuse.conf and otherwise fails EPERM.
env FFS_AUTO_UNMOUNT=0 \
  ${FFS_BHH0I_SHARDED+FFS_BHH0I_SHARDED="$FFS_BHH0I_SHARDED"} \
  "$FFS_CLI" mount --rw --no-background-scrub "$IMG" "$MNT" \
  >"$BASE/daemon.out" 2>"$BASE/daemon.err" &
DAEMON=$!

for _ in $(seq 1 60); do
  mountpoint -q "$MNT" && break
  sleep 0.5
done
mountpoint -q "$MNT" || { echo "mount failed:"; tail -5 "$BASE/daemon.err"; exit 1; }
echo ">> mounted"

DIR="$MNT/create-delete-storm"
mkdir -p "$DIR"
cycle=0
while [ "$cycle" -lt "$CYCLES" ]; do
  i=0
  while [ "$i" -lt "$FILES" ]; do
    : > "$DIR/storm-$(printf '%05d' "$i")" || {
      echo "CREATE FAILED at cycle $cycle file $i — this is the ENOSPC face of bd-pbyu0"
      break 2
    }
    i=$((i + 1))
  done
  i=0
  while [ "$i" -lt "$FILES" ]; do
    rm -f "$DIR/storm-$(printf '%05d' "$i")"
    i=$((i + 1))
  done
  cycle=$((cycle + 1))
  [ $((cycle % 10)) -eq 0 ] && echo "   cycle $cycle/$CYCLES"
done

sync
fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null || sudo umount "$MNT"
wait "$DAEMON" 2>/dev/null || true
echo ">> unmounted after $cycle cycles"

echo ">> post-unmount e2fsck"
e2fsck -fn "$IMG" 2>&1 | grep -E "Free inodes count wrong|Free blocks count wrong|clean|WARNING" | head -15
e2fsck -fn "$IMG" >/dev/null 2>&1 && echo "   RESULT: clean (did NOT reproduce)" \
                                  || echo "   RESULT: DIRTY (reproduced bd-pbyu0)"
