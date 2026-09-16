#!/usr/bin/env bash
# bd-a136s diagnosis: trace the grow block's decisions during a data fill.
set -uo pipefail
W=/tmp/bd-a136s-dbg
rm -rf "$W"
mkdir -p "$W/mnt"
fallocate -l 256M "$W/img.img"
mkfs.btrfs -q "$W/img.img"
sudo -n mount -o loop "$W/img.img" "$W/mnt"
sudo -n chown "$(id -u):$(id -g)" "$W/mnt"
sudo -n umount "$W/mnt"
mkdir -p "$W/mnt"
(FFS_BTRFS_GROW_CHUNKS=1 FFS_AUTO_UNMOUNT=0 RUST_LOG=debug /data/tmp/cargo-target/debug/ffs-cli mount --rw --btrfs-rw-ephemeral-ok "$W/img.img" "$W/mnt" > /tmp/bd-a136s-daemon.log 2>&1 &)
for i in $(seq 1 120); do mountpoint -q "$W/mnt" && break; sleep 0.5; done
python3 - "$W/mnt" <<'PY'
import os, sys
mnt = sys.argv[1]
payload = b"x" * (1024 * 1024)
for i in range(12):
    try:
        fd = os.open(os.path.join(mnt, f"data-{i:03d}.bin"), os.O_CREAT | os.O_WRONLY, 0o644)
        os.write(fd, payload)
        os.fsync(fd)
        os.close(fd)
        print(f"file {i}: ok")
    except OSError as e:
        print(f"file {i}: errno {e.errno}")
PY
fusermount3 -u "$W/mnt"
echo "===== growth/alloc evidence ====="
grep -icE "grow|alloc_no_space" /tmp/bd-a136s-daemon.log
grep -iE "alloc_no_space|grew_|growth_|chunk_trees_dirty|data_low|allocatable|low_water" /tmp/bd-a136s-daemon.log | sed -n '1,14p'
