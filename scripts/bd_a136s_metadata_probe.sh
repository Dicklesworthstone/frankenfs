#!/usr/bin/env bash
# bd-a136s acceptance probe (data half): on a 256 MiB btrfs image, write 1 MiB
# files until ENOSPC, measuring how far each arm gets: FFS_BTRFS_GROW_CHUNKS
# unset (baseline) vs =1 (data-chunk growth on). Baseline ENOSPCs when the
# initial data block groups fill; growth ON should allocate new data chunks
# from unallocated device space (the kernel-btrfs behaviour this bead asks
# for) and keep going.
set -uo pipefail
CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
W="${W:-$HOME/bd-a136s-probe}"

arm() {
    local mode="$1" grow="$2"
    local img="$W/img-$mode.img"
    local mnt="$W/mnt-$mode"
    local log="$W/daemon-$mode.log"
    rm -f "$img"; rm -rf "$mnt"; mkdir -p "$mnt"
    fallocate -l 256M "$img"
    mkfs.btrfs -q "$img"
    # mkfs leaves the fs root owned by uid 0; without allow_other our
    # unprivileged creates EPERM. One kernel round-trip rewrites ownership.
    sudo -n mount -o loop "$img" "$mnt"
    sudo -n chown "$(id -u):$(id -g)" "$mnt"
    sudo -n umount "$mnt"
    mkdir -p "$mnt"
    if [ "$grow" = "1" ]; then
        FFS_BTRFS_GROW_CHUNKS=1 FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$img" "$mnt" >>"$log" 2>&1 &
    else
        FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$img" "$mnt" >>"$log" 2>&1 &
    fi
    DAEMON=$!
    for _ in $(seq 1 120); do
        mountpoint -q "$mnt" && break
        kill -0 "$DAEMON" 2>/dev/null || { echo "FATAL: daemon died before mounting (see $log)"; exit 1; }
        sleep 0.5
    done
    mountpoint -q "$mnt" || { echo "FATAL: mount never appeared"; exit 1; }

    python3 - "$mnt" <<'PY'
import os, sys
mnt = sys.argv[1]
payload = b"x" * (1024 * 1024)
i = 0
while i < 1024:
    try:
        fd = os.open(os.path.join(mnt, f"data-{i:03d}.bin"), os.O_CREAT | os.O_WRONLY, 0o644)
        os.write(fd, payload)
        os.fsync(fd)
        os.close(fd)
        i += 1
    except OSError as e:
        if e.errno == 28:
            print(f"ENOSPC_AT {i} files ({i} MiB written)")
            sys.exit(0)
        raise
print(f"NO_ENOSPC all {i} files written")
PY
    fusermount3 -u "$mnt" 2>/dev/null
    for _ in $(seq 1 60); do mountpoint -q "$mnt" || break; sleep 0.5; done
    [ -n "$DAEMON" ] && wait "$DAEMON" 2>/dev/null
    echo "arm=$mode btrfs check: $(btrfs check --readonly "$img" 2>&1 | grep -oE 'no error found|error\(s\) found|not a recognized|invalid' | head -1)"
    kill -9 "${DAEMON:-0}" 2>/dev/null
    DAEMON=""
}

echo "===== arm baseline (growth unset) ====="
arm baseline 0
echo "===== arm growth (FFS_BTRFS_GROW_CHUNKS=1) ====="
arm growth 1
echo "PROBE COMPLETE"
