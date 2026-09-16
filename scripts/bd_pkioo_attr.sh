#!/usr/bin/env bash
# bd-pkioo attribution: 50 rewrites of PRE-EXISTING files (no creates, no
# setxattr) with the new default. Counts inode invalidation sends at teardown.
# If sends == 0, the write path no longer invalidates; residual sends would
# come from the create/setxattr path instead.
set -uo pipefail
CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
W="$HOME/bd-pkioo-attr"

# Self-cleanup of any stale state from prior runs.
fusermount3 -uz "$W/mnt" 2>/dev/null
sudo -n umount -l "$W/mnt" 2>/dev/null
pkill -f "bd-pkioo-attr" 2>/dev/null
rm -rf "$W"
mkdir -p "$W/kmnt" "$W/mnt"

fallocate -l 256M "$W/base.img"
mkfs.btrfs -q "$W/base.img"
sudo -n mount -o loop "$W/base.img" "$W/kmnt"
sudo -n chown "$(id -u):$(id -g)" "$W/kmnt"
sudo -n umount "$W/kmnt"
cp "$W/base.img" "$W/probe.img"

DAEMON=""
mount_rw() {
    FFS_NOTIFY_SEND_COUNT=1 FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw \
        --btrfs-rw-ephemeral-ok "$W/probe.img" "$W/mnt" >>"$W/daemon.log" 2>&1 &
    DAEMON=$!
    for _ in $(seq 1 120); do mountpoint -q "$W/mnt" && return 0
        kill -0 "$DAEMON" 2>/dev/null || return 1; sleep 0.5; done
    return 1
}

echo "===== SEED (50 creates via daemon) ====="
mount_rw || { echo "FATAL: seed mount failed"; exit 1; }
python3 - "$W/mnt" <<'PY'
import os, sys
for i in range(50):
    fd = os.open(os.path.join(sys.argv[1], f"pre-{i:03d}.bin"), os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, b"seed")
    os.close(fd)
PY
unmount_done=0
fusermount3 -u "$W/mnt" 2>/dev/null
for _ in $(seq 1 60); do mountpoint -q "$W/mnt" || { unmount_done=1; break; }; sleep 0.5; done
[ "$unmount_done" = 1 ] || { fusermount3 -uz "$W/mnt"; }
[ -n "$DAEMON" ] && wait "$DAEMON" 2>/dev/null
DAEMON=""
echo "seed phase done"

echo "===== ATTRIBUTION (50 rewrites, no creates) ====="
mount_rw || { echo "FATAL: attribution mount failed"; exit 1; }
python3 - "$W/mnt" <<'PY'
import os, sys
for i in range(50):
    fd = os.open(os.path.join(sys.argv[1], f"pre-{i:03d}.bin"), os.O_WRONLY)
    os.write(fd, b"pkioo-verify" * 128)
    os.fsync(fd)
    os.close(fd)
print("50 rewrites+fsync done")
PY
fusermount3 -u "$W/mnt" 2>/dev/null
for _ in $(seq 1 60); do mountpoint -q "$W/mnt" || break; sleep 0.5; done
[ -n "$DAEMON" ] && wait "$DAEMON" 2>/dev/null

echo "===== notify_send_counts (attribution phase daemon) ====="
grep -E "notify_send_counts" "$W/daemon.log" | tail -1
