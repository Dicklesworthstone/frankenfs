#!/usr/bin/env bash
# bd-pkioo live verification: with the restated default (write-side inode
# invalidation OFF), 50 pwrite+fsync ops must enqueue ZERO inode invalidations.
set -uo pipefail
CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
W="$HOME/bd-pkioo-verify"
rm -rf "$W"
mkdir -p "$W/mnt"
fallocate -l 256M "$W/img.img"
mkfs.btrfs -q "$W/img.img"
sudo -n mount -o loop "$W/img.img" "$W/mnt"
sudo -n chown "$(id -u):$(id -g)" "$W/mnt"
sudo -n umount "$W/mnt"
mkdir -p "$W/mnt"
(FFS_NOTIFY_SEND_COUNT=1 FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$W/img.img" "$W/mnt" > "$W/daemon.log" 2>&1 &)
for _ in $(seq 1 120); do mountpoint -q "$W/mnt" && break; sleep 0.5; done
python3 - "$W/mnt" <<'PY'
import os, sys
mnt = sys.argv[1]
for i in range(50):
    fd = os.open(os.path.join(mnt, f"pre-{i:03d}.bin"), os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, b"seed")
    os.close(fd)
for i in range(50):
    fd = os.open(os.path.join(mnt, f"pre-{i:03d}.bin"), os.O_WRONLY)
    os.write(fd, b"pkioo-verify" * 128)
    os.fsync(fd)
    os.close(fd)
print("50 seed creates + 50 rewrites+fsync done")
PY
echo "===== notify_send_counts at teardown ====="
grep -E "notify_send_counts" "$W/daemon.log" | tail -1
