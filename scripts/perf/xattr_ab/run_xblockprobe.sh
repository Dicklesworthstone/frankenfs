#!/bin/bash
# Deterministic decomposition of the campaign's worst row (ext4 xattr-get-list-report).
# One config per mount lifetime, because crossings_* is cumulative and emitted at unmount.
#
# The knob under test is the capability MEMO, not the ENOSYS suppression: this image has
# real xattrs, so FFS_FUSE_XATTR_NO_SUPPORT is refused here and would be a lie. What can
# legitimately vary is whether the daemon answers repeat capability probes from the memo
# or re-reads the format each time — and, per bd-t0xoq, whether the proven-absent
# short-circuit can help on an image whose xattrs are PRESENT (it should not: the whole
# gate is XattrPresence::ProvenAbsent).
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
N=${N:-2000}
CPUS=${CPUS:-18}
CLIENTCPU=${CLIENTCPU:-8}
MNT=/home/ubuntu/xblock-mnt
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
echo "== workload: $N reports x 5 path-based xattr syscalls"

run_cfg() {  # $1=label $2=env
  local log="$W/xblock-$1.log"
  : > "$log"
  cp "$W/ximg-base.ext4" "$W/ximg-run.ext4"
  sync
  local dev
  dev=$(sudo -n losetup --find --show "$W/ximg-run.ext4")
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

  local out
  out=$(env ${PROBEENV:-} taskset -c "$CLIENTCPU" "$W/xblockprobe" "$MNT" "$N")

  fusermount3 -u "$MNT" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sudo -n losetup -d "$dev" 2>/dev/null || true

  echo "--- $1"
  echo "  $out"
  # An ABSENT short-circuit line is ambiguous, so report whatever the daemon said.
  grep -o "mount_candidate_shortcircuit,.*" "$log" | tail -1 | sed 's/^/  /' || true
  grep -o "mount_candidate_crossings,.*" "$log" | tail -1 \
    | grep -oE "crossings_(lookup|getxattr|listxattr|getattr|other|total)=[0-9]+" | tr '\n' ' ' | sed 's/^/  /'
  echo
  grep -o "op_counts.*" "$log" | tail -1 | sed 's/^/  /' || true
}

run_cfg base            ""
run_cfg shortcircuit    "FFS_FUSE_XATTR_PROVEN_ABSENT_SHORTCIRCUIT=1"
