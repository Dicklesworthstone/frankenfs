#!/bin/bash
# WHY does open(O_CREAT|O_EXCL) pay TWO audit capability probes when mkdir pays one?
#
# Every read row in this campaign measures 1.000 probes per path-based operation, and
# mkdir measures 1.000 — so file creation via open is the outlier, at 2.00. That is
# 33% of the create phase's crossings, twice the size of the getattr item that has
# already cost four withdrawn attributions.
#
# mkdir is the control: same directory, same daemon, same client, creation without
# the second probe. Diffing the two kernel stacks names the extra call site instead
# of inferring it.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
N=${N:-300}
MNT=/home/ubuntu/dblsrc-f
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
  taskset -c 18 "$ELF" mount --rw "$DEV" "$MNT" >> "$W/dblsrc-fuse.log" 2>&1 &
pid=$!
for _ in $(seq 1 300); do mountpoint -q "$MNT" && break; kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$MNT" || { echo "mount never came up"; tail -8 "$W/dblsrc-fuse.log"; exit 1; }

run_variant() {  # $1=label $2=probe env
  local out="$W/dblsrc-$1.txt"
  sudo -n bpftrace -e '
kprobe:__audit_inode /comm == "stormblockprobe"/ { @audit_inode = count(); }
kprobe:get_vfs_caps_from_disk /comm == "stormblockprobe"/ { @caps = count(); }
kprobe:fuse_getxattr /comm == "stormblockprobe"/ { @fuse_getxattr = count(); }
interval:s:40 { exit(); }' > "$out" 2>&1 &
  local bp=$!
  for _ in $(seq 1 100); do grep -q "Attaching" "$out" 2>/dev/null && break; sleep 0.1; done
  sleep 1
  # shellcheck disable=SC2086
  env $2 taskset -c 8 "$W/stormblockprobe" "$MNT" "$N" | sed 's/^/  /'
  sudo -n pkill -INT -x bpftrace 2>/dev/null || true
  wait "$bp" 2>/dev/null || true
  echo "== $1: __audit_inode call sites"
  grep -E "^@" "$out" | sed "s/^/  /"
}

run_variant open_create "STORMPROBE_CREATE_ONLY=1"
fusermount3 -u "$MNT"; wait "$pid" 2>/dev/null || true
