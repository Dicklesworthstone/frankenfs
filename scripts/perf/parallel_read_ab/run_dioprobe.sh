#!/bin/bash
# bd-q0xnl: measure the ONE thing keeping zero-message open (a balanced 1.160389x)
# from shipping — whether an O_DIRECT open silently gets page-cached behaviour when
# the daemon never sees the open flags.
#
# FOUR mounts, one ELF, one image, one pass each, because `op_counts` is cumulative
# and only emitted at unmount: giving every (config, mode) pair its own mount
# lifetime is what makes each read count attributable to that pass.
#
#   base + buf   negative control, expected ~1   (page cache absorbs the repeats)
#   base + dio   positive control, expected ~N   (O_DIRECT honoured today)
#   zmo  + buf   negative control, expected ~1
#   zmo  + dio   THE ANSWER: ~N = honoured, ~1 = silently page-cached
#
# The buffered arms are not decoration. If a `buf` pass reports ~N the oracle is
# void — it would mean the count cannot see caching on this stack, and the `dio`
# numbers would say nothing at all.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
N=${N:-64}
CPUS=${CPUS:-18}
PROBE="$W/dioprobe"
MNT=/home/ubuntu/dioprobe-mnt
LOOPS=""

cleanup() {
  fusermount3 -u "$MNT" 2>/dev/null || true
  for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$MNT"

echo "== candidate ELF"
"$ELF" bench-evidence 2>/dev/null | grep -E "binary_sha256|codegen_isa" || true

run_pass() {  # $1=label $2=env $3=mode
  local log="$W/dio-$1-$3.log"
  : > "$log"
  cp "$W/rimg-base.ext4" "$W/rimg-dio.ext4"
  sync
  local dev
  dev=$(sudo -n losetup --find --show "$W/rimg-dio.ext4")
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
  if [ "$up" != "1" ]; then echo "$1/$3: mount never came up"; tail -5 "$log"; return 1; fi

  # Prove the knob reached the code for this pass rather than trusting the env var.
  local zmo
  zmo=$(grep -c "FUSE_NO_OPEN_SUPPORT negotiated" "$log" || true)

  local out
  out=$("$PROBE" "$3" "$MNT/parallel-read/read-000000.bin" "$N" 2>/dev/null || true)

  fusermount3 -u "$MNT" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sudo -n losetup -d "$dev" 2>/dev/null || true

  local reads crossings
  reads=$(grep -o "op_counts.*" "$log" | tail -1 | grep -oE " read=[0-9]+" | tr -d ' read=' || echo "?")
  crossings=$(grep -o "crossings_read=[0-9]*" "$log" | tail -1 | cut -d= -f2 || echo "?")
  echo "$1/$3: $out | daemon op_counts read=${reads:-0} crossings_read=${crossings:-0} zmo_negotiated=$zmo"
}

run_pass base "" buf
run_pass base "" dio
run_pass zmo "FFS_FUSE_ZERO_MESSAGE_OPEN=1" buf
run_pass zmo "FFS_FUSE_ZERO_MESSAGE_OPEN=1" dio
