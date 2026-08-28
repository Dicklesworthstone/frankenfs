#!/bin/bash
# Second attempt at naming the post-create GETATTR's origin.
#
# The first attempt probed `fuse_getattr` filtered to the client comm and captured
# NOTHING, which is itself informative: the GETATTR requests counted in the daemon's
# census are not being issued through that entry point in the client's context. So
# probe the whole family and attribute by comm, with no filter to bias the answer.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
N=${N:-500}
MNT=/home/ubuntu/gsrc2-f
DEV=""

cleanup() {
  fusermount3 -u "$MNT" 2>/dev/null || true
  [ -n "$DEV" ] && sudo -n losetup -d "$DEV" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$MNT"

DEV=$(sudo -n losetup --find --show "$W/simgb-f.btrfs")
sudo -n losetup --direct-io=on "$DEV" 2>/dev/null || true
sudo -n chown "$(id -u)" "$DEV"
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn \
  taskset -c 18 "$ELF" mount --rw "$DEV" "$MNT" >> "$W/gsrc2-fuse.log" 2>&1 &
pid=$!
for _ in $(seq 1 300); do mountpoint -q "$MNT" && break; kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$MNT" || { echo "mount never came up"; tail -8 "$W/gsrc2-fuse.log"; exit 1; }

sudo -n bpftrace -e '
kprobe:fuse_getattr          { @getattr[comm] = count(); }
kprobe:fuse_do_getattr       { @do_getattr[comm] = count(); }
kprobe:fuse_update_attributes{ @update_attributes[comm] = count(); }
kprobe:fuse_dentry_revalidate{ @dentry_revalidate[comm] = count(); }
kprobe:fuse_invalidate_attr  { @invalidate_attr[comm] = count(); }
interval:s:45 { exit(); }' > "$W/gsrc2.txt" 2>&1 &
bp=$!
for _ in $(seq 1 100); do grep -q "Attaching" "$W/gsrc2.txt" 2>/dev/null && break; sleep 0.1; done
sleep 1

STORMPROBE_CREATE_ONLY=1 taskset -c 8 "$W/stormblockprobe" "$MNT" "$N" | sed 's/^/  /'

sudo -n pkill -INT -x bpftrace 2>/dev/null || true
wait "$bp" 2>/dev/null || true
fusermount3 -u "$MNT"; wait "$pid" 2>/dev/null || true

echo "== kernel-side attribute path, by comm"
grep -E "^@" "$W/gsrc2.txt" | sed 's/^/  /'
echo "== daemon census"
grep -o "op_counts.*" "$W/gsrc2-fuse.log" | tail -1 | grep -oE "getattr=[0-9]+|create=[0-9]+|lookup=[0-9]+" | tr '\n' ' ' | sed 's/^/  /'
echo
