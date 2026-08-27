#!/bin/bash
# TOTAL INSTRUCTIONS PER OPERATION — FrankenFS vs the live kernel, on a WRITE row.
#
# Why a different metric here. Every read row this campaign has decomposed turned out
# to be ~99% FUSE round trip with the daemon doing almost no work (9 handler entries
# for 10,000 user ops on the worst row). The write rows are the opposite: bulk durable
# write is the one row measured where WE are the cost, with 36.7% of daemon CPU in our
# own memcpy and allocator. Counting crossings there would measure the wrong thing.
#
# Instructions retired is the deterministic analogue of wall time: it does not move
# when a peer spikes the host, which is what voided four of eight runs in one session.
#
# The comparison is made FAIR by counting the same total work on both sides:
#   kernel arm : instructions in the CLIENT (kernel work happens in its syscall context)
#   FUSE arm   : instructions in the CLIENT *plus* the daemon (our work is split across
#                the boundary, and counting only the client would flatter us enormously)
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
MB=${MB:-64}
BS=${BS:-65536}
SYNC_EVERY=${SYNC_EVERY:-16}
# Extra daemon env, e.g. FFS_BTRFS_GROW_CHUNKS=1 (bd-a136s): the btrfs write side
# hits ENOSPC once the first data chunk fills unless chunk growth is enabled.
FENV=${FENV:-}
KMNT=/home/ubuntu/instr-k
FMNT=/home/ubuntu/instr-f
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
echo "== workload: ${MB}MiB in ${BS}B writes, fsync every $SYNC_EVERY writes"

# --- kernel btrfs, rw
dev=$(sudo -n losetup --find --show "$W/bimgb-k.btrfs")
sudo -n losetup --direct-io=on "$dev" 2>/dev/null || true
LOOPS="$LOOPS $dev"
sudo -n mount "$dev" "$KMNT"
echo "--- kernel btrfs (live incumbent)"
perf stat -e instructions,task-clock -x, -o "$W/instr-k.txt" -- \
  taskset -c 8 "$W/writeprobe" "$KMNT/out.bin" "$MB" "$BS" "$SYNC_EVERY" || true
grep -E "instructions|task-clock" "$W/instr-k.txt" | sed 's/^/    /'
sudo -n umount "$KMNT"

# --- FrankenFS, rw
fdev=$(sudo -n losetup --find --show "$W/bimgb-f.btrfs")
sudo -n losetup --direct-io=on "$fdev" 2>/dev/null || true
sudo -n chown "$(id -u)" "$fdev"
LOOPS="$LOOPS $fdev"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $FENV \
  taskset -c 18 "$ELF" mount --rw "$fdev" "$FMNT" >> "$W/instr-fuse.log" 2>&1 &
fpid=$!
for _ in $(seq 1 300); do mountpoint -q "$FMNT" && break; kill -0 "$fpid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$FMNT" || { echo "fuse mount never came up"; tail -8 "$W/instr-fuse.log"; exit 1; }

echo "--- FrankenFS (FUSE, --rw)"
# Attach to the daemon FIRST so no daemon work escapes the count.
perf stat -e instructions -x, -o "$W/instr-fd.txt" -p "$fpid" &
dperf=$!
sleep 1
perf stat -e instructions,task-clock -x, -o "$W/instr-fc.txt" -- \
  taskset -c 8 "$W/writeprobe" "$FMNT/out.bin" "$MB" "$BS" "$SYNC_EVERY" || true
kill -INT "$dperf" 2>/dev/null || true
wait "$dperf" 2>/dev/null || true
echo "    client:"; grep -E "instructions|task-clock" "$W/instr-fc.txt" | sed 's/^/      /'
echo "    daemon:"; grep -E "instructions" "$W/instr-fd.txt" | sed 's/^/      /'
fusermount3 -u "$FMNT"; wait "$fpid" 2>/dev/null || true
grep -o "crossings_total=[0-9]*\|crossings_write=[0-9]*" "$W/instr-fuse.log" | tail -2 | sed 's/^/    /'
