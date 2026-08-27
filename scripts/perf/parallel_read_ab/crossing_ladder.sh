#!/bin/bash
# The parallel-read row's COUNTED decomposition: how many FUSE round trips does one
# file read cost, and what does each knob remove?
#
# Why counts rather than a wall-time A/B: the census on this row measured
# dispatch_ns_total 146.36ms against ops_ns_total 0.96ms, i.e. ~99% of the row is the
# round trip and ~0.7% is our filesystem work. Crossings therefore SET the floor, and
# a crossing count is exact and reproducible where this host's wall-time ratios are
# not — three measurement windows were voided for load spikes in one session.
#
# One config per mount lifetime, because `crossings_*` is cumulative and only emitted
# at unmount. Identical workload every time, so the counts are directly comparable.
#
# Each knob is recorded with whether it is SHIPPABLE, because a ladder that mixes
# shippable rungs with restricted ones would otherwise read as an available speedup:
#   zero-message open  bd-q0xnl  gated on the backend guard; default OFF pending
#                                rows outside this regime
#   xattr no-support             RESTRICTED: the mount refuses xattrs entirely, sound
#                                only on an image that has none. Never a default.
#   no-flush                     MEASUREMENT ONLY: answers FLUSH with ENOSYS, valid
#                                while FsOps::flush is a stub and not before.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
ROUNDS=${ROUNDS:-4}
THREADS=${THREADS:-8}
CPUBASE=${CPUBASE:-8}
CPUS=${CPUS:-18}
MNT=/home/ubuntu/ladder-mnt
LOOPS=""

cleanup() {
  fusermount3 -u "$MNT" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$MNT"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256" || true
echo "== workload: $ROUNDS rounds x $THREADS threads over 256 files x 256 KiB"

run_cfg() {  # $1=label $2=env
  local log="$W/ladder-$1.log"
  : > "$log"
  cp "$W/rimg-base.ext4" "$W/rimg-ladder.ext4"
  sync
  local dev
  dev=$(sudo -n losetup --find --show "$W/rimg-ladder.ext4")
  sudo -n losetup --direct-io=on "$dev" 2>/dev/null || true
  sudo -n chown "$(id -u)" "$dev"
  LOOPS="$LOOPS $dev"

  # shellcheck disable=SC2086
  env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $2 \
    taskset -c "$CPUS" "$ELF" mount "$dev" "$MNT" >> "$log" 2>&1 &
  local pid=$!
  local up=0
  for _ in $(seq 1 200); do
    if mountpoint -q "$MNT"; then up=1; break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$up" != "1" ]; then echo "$1: mount never came up"; tail -5 "$log"; return 1; fi

  if [ "${BLOCKPROBE:-0}" = "1" ]; then
    # bd-4iqg6: count VOLUNTARY context switches per file instead of timing, to
    # separate crossings the client waits on from background ones.
    taskset -c "$CPUBASE" "$W/blockprobe" "$MNT" "${NFILES:-256}"
  else
    "$W/pread_ab" "$ROUNDS" "$THREADS" "$CPUBASE" "$pid" "solo=$MNT" > "$W/ladder-$1.csv" 2>/dev/null || true
  fi

  fusermount3 -u "$MNT" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sudo -n losetup -d "$dev" 2>/dev/null || true

  # Attest that the knob reached the code, per config, rather than trusting the env.
  local zmo
  zmo=$(grep -c "FUSE_NO_OPEN_SUPPORT negotiated" "$log" || true)
  local c
  c=$(grep -o "mount_candidate_crossings,.*" "$log" | tail -1)
  echo "--- $1 (zmo_negotiated=$zmo)"
  echo "$c" | grep -oE "crossings_(lookup|getxattr|open|release|readdir|readdirplus|opendir|releasedir|other|total)=[0-9]+" | tr '\n' ' '
  echo
}

run_cfg base        ""
run_cfg zmo         "FFS_FUSE_ZERO_MESSAGE_OPEN=1"
run_cfg noxattr     "FFS_FUSE_XATTR_NO_SUPPORT=1"
run_cfg noflush     "FFS_FUSE_NO_FLUSH=1"
run_cfg all3        "FFS_FUSE_ZERO_MESSAGE_OPEN=1 FFS_FUSE_XATTR_NO_SUPPORT=1 FFS_FUSE_NO_FLUSH=1"
