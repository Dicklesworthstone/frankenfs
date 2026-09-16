#!/usr/bin/env bash
# bd-ltx9e attribution: N create/delete pairs on a default mount. Counts (a)
# notify sends by kind and (b) the getattr storm, via the daemon's own
# FFS_NOTIFY_SEND_COUNT / FFS_OP_COUNTS teardown lines. Run twice: with
# FFS_FUSE_PARENT_INVAL=1 (shipping) and =0 (the rejected lever, for the
# getattr delta).
set -uo pipefail
CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
W="${W:-$HOME/bd-ltx9e-probe}"
PAIRS="${PAIRS:-300}"

run_arm() {
    local mode="$1" pinval="$2"
    local img="$W/img-$mode.img"
    local mnt="$W/mnt-$mode"
    local log="$W/daemon-$mode.log"
    rm -f "$img"; rm -rf "$mnt"; mkdir -p "$mnt"
    fallocate -l 256M "$img"
    mkfs.btrfs -q "$img"
    sudo -n mount -o loop "$img" "$mnt"
    sudo -n chown "$(id -u):$(id -g)" "$mnt"
    sudo -n umount "$mnt"
    mkdir -p "$mnt"
    if [ "$pinval" = "1" ]; then
        FFS_NOTIFY_SEND_COUNT=1 FFS_OP_COUNTS=1 FFS_FUSE_PARENT_INVAL=1 FFS_AUTO_UNMOUNT=0 \
            RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$img" "$mnt" >>"$log" 2>&1 &
    else
        FFS_NOTIFY_SEND_COUNT=1 FFS_OP_COUNTS=1 FFS_FUSE_PARENT_INVAL=0 FFS_AUTO_UNMOUNT=0 \
            RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$img" "$mnt" >>"$log" 2>&1 &
    fi
    DAEMON=$!
    for _ in $(seq 1 120); do mountpoint -q "$mnt" && break; sleep 0.5; done
    python3 - "$mnt" "$PAIRS" <<'PY'
import os, sys
mnt, pairs = sys.argv[1], int(sys.argv[2])
for i in range(pairs):
    p = os.path.join(mnt, f"pair-{i:04d}")
    fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, b"x" * 4096)
    os.fsync(fd)
    os.close(fd)
    os.stat(p)            # getattr: the file (victim)
    os.stat(mnt)          # getattr: the parent dir (the suspected drop)
    os.unlink(p)
    os.stat(mnt)          # getattr after unlink
print(f"{pairs} pairs done")
PY
    fusermount3 -u "$mnt" 2>/dev/null
    for _ in $(seq 1 60); do mountpoint -q "$mnt" || break; sleep 0.5; done
    [ -n "$DAEMON" ] && wait "$DAEMON" 2>/dev/null
    echo "===== arm=$mode teardown evidence ====="
    grep -E "notify_send_counts|getattr_split" "$log" | tail -2 | sed 's/^/  /'
    grep -oE '"opcode="?[A-Za-z]+=[0-9]+' "$log" | tail -8 | sed 's/^/  /'
}

echo "===== arm shipping (FFS_FUSE_PARENT_INVAL=1) ====="
run_arm shipping 1
echo "===== arm lever-off (FFS_FUSE_PARENT_INVAL=0) ====="
run_arm leveroff 0
echo "PROBE COMPLETE"
