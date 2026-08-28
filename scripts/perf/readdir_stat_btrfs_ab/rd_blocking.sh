#!/bin/bash
# readdir+stat on the campaign's deterministic scale: blocking crossings per op,
# live kernel btrfs vs FrankenFS, same fixture, same client binary.
#
# bd-cjqhh is closed; this is the next worst cell not yet decomposed with these
# instruments. The banked row is a wall-time ratio measured on a host that voided
# four of eight runs in one session for load; blocking crossings reproduce to +/-1.
#
# FENV lets the known dispatch lever (FFS_FUSE_WORKERS) be A/B'd from ONE ELF, since
# this row is recorded as one where serial dispatch costs ~2x at zero extra CPU.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
FENV=${FENV:-}
KMNT=/home/ubuntu/rdb-k
FMNT=/home/ubuntu/rdb-f
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

dev=$(sudo -n losetup --find --show "$W/bimgr-base.btrfs")
sudo -n losetup --direct-io=on "$dev" 2>/dev/null || true
LOOPS="$LOOPS $dev"
sudo -n mount -o ro "$dev" "$KMNT"
echo "--- kernel btrfs (live incumbent)"
taskset -c 8 "$W/rdblockprobe" "$KMNT"
sudo -n umount "$KMNT"

cp "$W/bimgr-base.btrfs" "$W/bimgr-f.btrfs"
sync
fdev=$(sudo -n losetup --find --show "$W/bimgr-f.btrfs")
sudo -n losetup --direct-io=on "$fdev" 2>/dev/null || true
sudo -n chown "$(id -u)" "$fdev"
LOOPS="$LOOPS $fdev"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $FENV \
  taskset -c 18 "$ELF" mount "$fdev" "$FMNT" >> "$W/rdb-fuse.log" 2>&1 &
fpid=$!
for _ in $(seq 1 300); do mountpoint -q "$FMNT" && break; kill -0 "$fpid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$FMNT" || { echo "fuse mount never came up"; tail -8 "$W/rdb-fuse.log"; exit 1; }
echo "--- FrankenFS (FUSE)"
taskset -c 8 "$W/rdblockprobe" "$FMNT"
fusermount3 -u "$FMNT"; wait "$fpid" 2>/dev/null || true
echo "  attested knobs:"
grep -o "fuse_dispatch_workers=[0-9]*" "$W/rdb-fuse.log" | tail -1 | sed 's/^/    /'
grep -o "mount_candidate_crossings,.*" "$W/rdb-fuse.log" | tail -1 \
  | grep -oE "crossings_(lookup|getattr|getxattr|readdir|readdirplus|opendir|total)=[0-9]+" \
  | tr '\n' ' ' | sed 's/^/    /'
echo
