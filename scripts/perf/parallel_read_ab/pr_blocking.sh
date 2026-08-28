#!/bin/bash
# Parallel-read on the campaign's deterministic scale, in the SHIPPING configuration.
#
# Zero-message open became the default on 2026-08-27. Every banked figure for this row
# was measured with it OFF, so the row's headline now prices a configuration that no
# longer ships — the same trap that made the banked "worst row" wrong once before.
# This re-measures it as shipped, in counts rather than wall time.
#
# FENV exists so the shipping default can be A/B'd against an explicit opt-out from
# ONE ELF, which is what makes "the default changed the row" attestable rather than
# asserted.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
FENV=${FENV:-}
KMNT=/home/ubuntu/pr-k
FMNT=/home/ubuntu/pr-f
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

dev=$(sudo -n losetup --find --show "$W/rimg-base.ext4")
sudo -n losetup --direct-io=on "$dev" 2>/dev/null || true
LOOPS="$LOOPS $dev"
sudo -n mount -o ro "$dev" "$KMNT"
echo "--- kernel ext4 (live incumbent)"
taskset -c 8 "$W/blockprobe" "$KMNT" "${NFILES:-256}"
sudo -n umount "$KMNT"

cp "$W/rimg-base.ext4" "$W/rimg-pr.ext4"
sync
fdev=$(sudo -n losetup --find --show "$W/rimg-pr.ext4")
sudo -n losetup --direct-io=on "$fdev" 2>/dev/null || true
sudo -n chown "$(id -u)" "$fdev"
LOOPS="$LOOPS $fdev"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $FENV \
  taskset -c 18 "$ELF" mount "$fdev" "$FMNT" >> "$W/pr-fuse.log" 2>&1 &
fpid=$!
for _ in $(seq 1 300); do mountpoint -q "$FMNT" && break; kill -0 "$fpid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$FMNT" || { echo "fuse mount never came up"; tail -8 "$W/pr-fuse.log"; exit 1; }
echo "--- FrankenFS (FUSE)"
taskset -c 8 "$W/blockprobe" "$FMNT" "${NFILES:-256}"
fusermount3 -u "$FMNT"; wait "$fpid" 2>/dev/null || true
echo "    zmo_negotiated_this_run=$(grep -c 'FUSE_NO_OPEN_SUPPORT negotiated' "$W/pr-fuse.log")"
grep -o "mount_candidate_crossings,.*" "$W/pr-fuse.log" | tail -1 \
  | grep -oE "crossings_(lookup|getattr|getxattr|open|release|other|total)=[0-9]+" \
  | tr '\n' ' ' | sed 's/^/    /'
echo
