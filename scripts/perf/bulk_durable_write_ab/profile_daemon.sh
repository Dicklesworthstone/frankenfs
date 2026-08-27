#!/bin/bash
# Where do the daemon's instructions go on the bulk durable write row?
#
# The write row is the one place measured where WE are the cost: 2.48x the kernel's
# instructions for byte-identical durable work, with 83.3% of ours inside the daemon.
# Every read row was ~99% round trip with the daemon idle, so this is the only row
# where a profile can point at a lever rather than at the FUSE boundary.
#
# Runs INSIDE the working range (bd-cjqhh bounds the row at ~16 MiB until data-chunk
# growth exists), so the workload completes and the profile is of a successful run
# rather than of an error path.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
MB=${MB:-12}
BS=${BS:-65536}
SYNC_EVERY=${SYNC_EVERY:-16}
FMNT=/home/ubuntu/prof-f
LOOPS=""

cleanup() {
  fusermount3 -u "$FMNT" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$FMNT"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256" || true

fdev=$(sudo -n losetup --find --show "$W/bimgb-f.btrfs")
sudo -n losetup --direct-io=on "$fdev" 2>/dev/null || true
sudo -n chown "$(id -u)" "$fdev"
LOOPS="$LOOPS $fdev"
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn \
  taskset -c 18 "$ELF" mount --rw "$fdev" "$FMNT" >> "$W/prof-fuse.log" 2>&1 &
fpid=$!
for _ in $(seq 1 300); do mountpoint -q "$FMNT" && break; kill -0 "$fpid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$FMNT" || { echo "fuse mount never came up"; tail -8 "$W/prof-fuse.log"; exit 1; }

# Sample the daemon only. -g gives callers so a hot leaf (memcpy, malloc) can be
# attributed to the path that called it rather than reported as an anonymous total.
# EVENT=page-faults attributes each FAULT to the stack that caused it, which is
# what names the allocating path; the default cycles profile only shows where
# the kernel spends the fault, not who asked for the page (bd-cjqhh).
perf record -q -e "${EVENT:-cycles}" -c "${PERIOD:-1}" -g -p "$fpid" -o "$W/prof.data" &
prec=$!
sleep 1
taskset -c 8 "$W/writeprobe" "$FMNT/out.bin" "$MB" "$BS" "$SYNC_EVERY"
sudo -n kill -INT "$prec" 2>/dev/null || kill -INT "$prec" 2>/dev/null || true
wait "$prec" 2>/dev/null || true
fusermount3 -u "$FMNT"; wait "$fpid" 2>/dev/null || true

echo "== daemon profile: ${EVENT:-cycles} (top 25)"
perf report -i "$W/prof.data" --no-children --percent-limit 0.4 --stdio 2>/dev/null \
  | grep -E "^ +[0-9]" | head -25
