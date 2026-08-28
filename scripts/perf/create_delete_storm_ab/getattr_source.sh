#!/bin/bash
# WHO calls fuse_getattr after a create?
#
# The create phase pays ~1.0 getattr per file (2.0 per mkdir) and three hypotheses
# have already been eliminated by measurement: it is not our cache invalidation
# (unmoved by all three knobs), not close/flush (holding descriptors open doubled it),
# and not descriptor handling (mkdir has no descriptor and pays more). Elimination by
# client variant has run out of road.
#
# The same tool that settled the audit-probe question in one shot -- a kprobe with a
# kernel stack -- names the caller directly instead of narrowing the space further.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
N=${N:-500}
MNT=/home/ubuntu/gsrc-f
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
  taskset -c 18 "$ELF" mount --rw "$DEV" "$MNT" >> "$W/gsrc-fuse.log" 2>&1 &
pid=$!
for _ in $(seq 1 300); do mountpoint -q "$MNT" && break; kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$MNT" || { echo "mount never came up"; tail -8 "$W/gsrc-fuse.log"; exit 1; }

# Filter on the CLIENT comm: fuse_getattr runs in the caller's context, so this
# attributes each call to the syscall that provoked it rather than to the daemon.
sudo -n bpftrace -e '
kprobe:fuse_getattr /comm == "stormblockprobe"/ { @[kstack(10)] = count(); }
interval:s:45 { exit(); }' > "$W/gsrc.txt" 2>&1 &
bp=$!
for _ in $(seq 1 100); do grep -q "Attaching" "$W/gsrc.txt" 2>/dev/null && break; sleep 0.1; done
sleep 1

STORMPROBE_CREATE_ONLY=1 taskset -c 8 "$W/stormblockprobe" "$MNT" "$N" | sed 's/^/  /'

sudo -n pkill -INT -x bpftrace 2>/dev/null || true
wait "$bp" 2>/dev/null || true
fusermount3 -u "$MNT"; wait "$pid" 2>/dev/null || true

echo "== fuse_getattr callers (top stacks)"
grep -v "^$" "$W/gsrc.txt" | tail -40
