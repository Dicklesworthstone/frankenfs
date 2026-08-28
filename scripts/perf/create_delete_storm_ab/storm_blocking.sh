#!/bin/bash
# create/delete storm, deterministic scale, live kernel btrfs vs FrankenFS --rw.
#
# The storm is the second-worst cell and the first MUTATING METADATA row this
# campaign has put on the blocking-crossings scale. Both arms are read-WRITE mounts,
# so both fixtures are prepared identically through the kernel (a fresh mkfs leaves
# the root owned by root; chowning only one arm's mountpoint is a fixture defect that
# shows up as EACCES on the FUSE arm, which already cost one run on the write row).
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
N=${N:-4000}
FENV=${FENV:-}
KMNT=/home/ubuntu/storm-k
FMNT=/home/ubuntu/storm-f
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
echo "== workload: $N creates then $N unlinks, single client thread"

dev=$(sudo -n losetup --find --show "$W/simgb-k.btrfs")
sudo -n losetup --direct-io=on "$dev" 2>/dev/null || true
LOOPS="$LOOPS $dev"
sudo -n mount "$dev" "$KMNT"
echo "--- kernel btrfs (live incumbent)"
taskset -c 8 "$W/stormblockprobe" "$KMNT" "$N"
sudo -n umount "$KMNT"

fdev=$(sudo -n losetup --find --show "$W/simgb-f.btrfs")
sudo -n losetup --direct-io=on "$fdev" 2>/dev/null || true
sudo -n chown "$(id -u)" "$fdev"
LOOPS="$LOOPS $fdev"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $FENV \
  taskset -c 18 "$ELF" mount --rw "$fdev" "$FMNT" >> "$W/storm-fuse.log" 2>&1 &
fpid=$!
for _ in $(seq 1 300); do mountpoint -q "$FMNT" && break; kill -0 "$fpid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$FMNT" || { echo "fuse mount never came up"; tail -8 "$W/storm-fuse.log"; exit 1; }
echo "--- FrankenFS (FUSE, --rw)"
taskset -c 8 "$W/stormblockprobe" "$FMNT" "$N"
fusermount3 -u "$FMNT"; wait "$fpid" 2>/dev/null || true
grep -o "mount_candidate_crossings,.*" "$W/storm-fuse.log" | tail -1 \
  | grep -oE "crossings_(lookup|getattr|getxattr|create|unlink|other|total)=[0-9]+" \
  | tr '\n' ' ' | sed 's/^/    /'
echo
grep -o "op_counts.*" "$W/storm-fuse.log" | tail -1 | sed 's/^/    /' || true
