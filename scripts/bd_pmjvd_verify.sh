#!/usr/bin/env bash
# bd-pmjvd verification (bd_ltx9e_attr.sh shape, proven working): 300
# pwrite+fsync ops, NO creates (isolates the write path; setxattr-on-create
# is a different invalidation site). With bd-pkioo's flip (write-side inode
# invalidation default OFF), inode_sends must be 0 at teardown — the
# "unexplained" ~1.000 futex wake/op was exactly this enqueue.
set -uo pipefail
CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
W="$HOME/bd-pmjvd-verify"
PAIRS="${PAIRS:-300}"

rm -f "$W/img-shipping.img"; rm -rf "$W/mnt-shipping"
mkdir -p "$W/mnt-shipping"
fallocate -l 256M "$W/img-shipping.img"
mkfs.btrfs -q "$W/img-shipping.img"
sudo -n mount -o loop "$W/img-shipping.img" "$W/mnt-shipping"
sudo -n chown "$(id -u):$(id -g)" "$W/mnt-shipping"
sudo -n umount "$W/mnt-shipping"
mkdir -p "$W/mnt-shipping"

FFS_NOTIFY_SEND_COUNT=1 FFS_FUSE_PARENT_INVAL=1 FFS_AUTO_UNMOUNT=0 RUST_LOG=info \
    "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$W/img-shipping.img" "$W/mnt-shipping" \
    > "$W/daemon-shipping.log" 2>&1 &
DAEMON=$!
for _ in $(seq 1 120); do mountpoint -q "$W/mnt-shipping" && break; sleep 0.5; done

python3 - "$W/mnt-shipping" "$PAIRS" <<'PY'
import os, sys
mnt, pairs = sys.argv[1], int(sys.argv[2])
for i in range(pairs):
    p = os.path.join(mnt, f"pmjvd-{i:04d}.bin")
    fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o644)
    os.pwrite(fd, b"pmjvd" * 204, i * 1020)
    os.fsync(fd)
    os.close(fd)
print(f"{pairs} pwrite+fsync ops done")
PY

fusermount3 -u "$W/mnt-shipping" 2>/dev/null
for _ in $(seq 1 60); do mountpoint -q "$W/mnt-shipping" || break; sleep 0.5; done
[ -n "$DAEMON" ] && wait "$DAEMON" 2>/dev/null
echo "===== notify_send_counts (teardown) ====="
grep -E "notify_send_counts" "$W/daemon-shipping.log" | tail -1
