#!/bin/bash
# The audit counterfactual that does NOT require touching host security config.
#
# bd-4iqg6 established the capability probe's caller is __audit_inode, reached from
# filename_lookup. The decisive test — drop the audit rules and re-run — is a host-wide
# security change on a shared machine and needs operator approval. This is the version
# that does not: a syscall which resolves no path cannot reach __audit_inode at all.
#
#   stat(path)  -> filename_lookup -> __audit_inode -> get_vfs_caps_from_disk
#   fstat(fd)   -> no path resolution
#
# Same file, same mount, same process, fd opened outside the counted region in both
# modes so the open's own probe cannot be mistaken for per-op cost. Run against BOTH a
# live kernel btrfs mount and FrankenFS, because the prediction is about the kernel's
# path-resolution behaviour and must hold on the incumbent too.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
N=${N:-20000}
KMNT=/home/ubuntu/fstcf-k
FMNT=/home/ubuntu/fstcf-f
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
echo "== workload: $N ops, stat(path) vs fstat(fd), same file"

probe_mode() {  # $1=arm $2=mode $3=mountpoint
  local out="$W/fstcf-$1-$2.txt"
  sudo -n bpftrace -e "
kprobe:get_vfs_caps_from_disk /comm == \"fstatprobe\"/ { @caps = count(); }
kprobe:__audit_inode         /comm == \"fstatprobe\"/ { @audit_inode = count(); }
interval:s:120 { exit(); }" > "$out" 2>&1 &
  local bp=$!
  for _ in $(seq 1 100); do grep -q "Attaching" "$out" 2>/dev/null && break; sleep 0.1; done
  sleep 1
  local res
  res=$(taskset -c 8 "$W/fstatprobe" "$2" "$3" "$N")
  sudo -n pkill -INT -x bpftrace 2>/dev/null || true
  wait "$bp" 2>/dev/null || true
  echo "  $res"
  echo "    $(grep -E '^@(caps|audit_inode)' "$out" | tr '\n' ' ')"
}

dev=$(sudo -n losetup --find --show "$W/wimgb-base.btrfs")
sudo -n losetup --direct-io=on "$dev" 2>/dev/null || true
LOOPS="$LOOPS $dev"
sudo -n mount -o ro "$dev" "$KMNT"
echo "--- kernel btrfs (live incumbent)"
probe_mode kernel stat  "$KMNT"
probe_mode kernel fstat "$KMNT"
sudo -n umount "$KMNT"

cp "$W/wimgb-base.btrfs" "$W/wimgb-fstcf.btrfs"
sync
fdev=$(sudo -n losetup --find --show "$W/wimgb-fstcf.btrfs")
sudo -n losetup --direct-io=on "$fdev" 2>/dev/null || true
sudo -n chown "$(id -u)" "$fdev"
LOOPS="$LOOPS $fdev"
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn \
  taskset -c 18 "$ELF" mount "$fdev" "$FMNT" >> "$W/fstcf-fuse.log" 2>&1 &
fpid=$!
for _ in $(seq 1 200); do mountpoint -q "$FMNT" && break; kill -0 "$fpid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$FMNT" || { echo "fuse mount never came up"; tail -5 "$W/fstcf-fuse.log"; exit 1; }
echo "--- FrankenFS (FUSE)"
probe_mode fuse stat  "$FMNT"
probe_mode fuse fstat "$FMNT"
fusermount3 -u "$FMNT"; wait "$fpid" 2>/dev/null || true
echo "  daemon census (both modes together):"
grep -o "mount_candidate_crossings,.*" "$W/fstcf-fuse.log" | tail -1 \
  | grep -oE "crossings_(lookup|getattr|getxattr|other|total)=[0-9]+" | tr '\n' ' ' | sed 's/^/    /'
echo
