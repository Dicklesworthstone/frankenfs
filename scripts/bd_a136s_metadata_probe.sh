#!/usr/bin/env bash
# bd-a136s acceptance probe (metadata half): on a deliberately small btrfs
# image, fill the metadata chunk with entries until ENOSPC, measuring how far
# each arm gets: FFS_BTRFS_GROW_CHUNKS unset (baseline) vs =1 (growth on).
# Growth ON should relieve the ENOSPC (metadata chunk allocation on demand);
# growth OFF should hit ENOSPC at the initial metadata chunk's capacity.
set -uo pipefail
CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
W="${W:-$HOME/bd-a136s-probe}"

arm() {
    local mode="$1" grow="$2"
    local img="$W/img-$mode.img"
    local mnt="$W/mnt-$mode"
    local log="$W/daemon-$mode.log"
    rm -f "$img"; rm -rf "$mnt"
    fallocate -l 64M "$img"
    mkfs.btrfs -q "$img"
    mkdir -p "$mnt"
    sudo -n mount -o loop "$img" "$mnt"
    sudo -n chown "$(id -u):$(id -g)" "$mnt"
    sudo -n umount "$mnt"
    mkdir -p "$mnt"
    if [ "$grow" = "1" ]; then
        FFS_BTRFS_GROW_CHUNKS=1 FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$img" "$mnt" >>"$log" 2>&1 &
    else
        FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$img" "$mnt" >>"$log" 2>&1 &
    fi
    local daemon=$!
    for _ in $(seq 1 120); do mountpoint -q "$mnt" && break; sleep 0.5; done
    local created=0 enospc_at=0
    python3 - "$mnt" <<'PY'
import os, sys
mnt = sys.argv[1]
i = 0
while i < 200000:
    try:
        d = os.path.join(mnt, f"d{i // 64:04d}")
        if not os.path.isdir(d):
            os.mkdir(d)
        fd = os.open(os.path.join(d, f"e{i:05d}"), os.O_CREAT, 0o644)
        os.close(fd)
        i += 1
    except OSError as e:
        if e.errno == 28:
            print(f"ENOSPC_AT {i}")
            sys.exit(3)
        raise
PY
    rc=$?
    created=$(python3 -c "print(0)" 2>/dev/null)
    if [ "$rc" -eq 3 ]; then
        enospc_at=$(grep -oE "ENOSPC_AT [0-9]+" /dev/null 2>/dev/null || true)
        # recover the count from the python print
        enospc_at=$(python3 - "$mnt" <<'PY2'
import os, sys
mnt = sys.argv[1]
n = 0
while n < 200000:
    d = os.path.join(mnt, f"d{n // 64:04d}")
    if not os.path.isdir(d):
        break
    if not os.path.exists(os.path.join(d, f"e{n:05d}")):
        break
    n += 1
print(n)
PY2
)
        echo "arm=$mode ENOSPC after $enospc_at entries"
    else
        echo "arm=$mode NO ENOSPC: all entries created created"
    fi
    fusermount3 -u "$mnt" 2>/dev/null
    for _ in $(seq 1 60); do mountpoint -q "$mnt" || break; sleep 0.5; done
    [ -n "$DAEMON" ] && wait "$DAEMON" 2>/dev/null
    echo "arm=$mode btrfs check: $(btrfs check --readonly "$img" 2>&1 | grep -oE 'no error found|error\(s\) found' | head -1)"
    kill -9 ${DAEMON:-0} 2>/dev/null
    DAEMON=""
}

echo "===== arm baseline (growth unset) ====="
arm baseline 0
echo "===== arm growth (FFS_BTRFS_GROW_CHUNKS=1) ====="
arm growth 1
echo "PROBE COMPLETE"
