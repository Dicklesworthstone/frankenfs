#!/usr/bin/env bash
# bd-0ajub probe: does the ephemeral fsync path still leak the superseded
# tree-log leaf (nodesize) plus its extent item on the current tree? Five
# write+fsync -> clean-unmount cycles on one image; the stored "bytes used"
# after each cycle is the signal. A leak shows as a step that never comes
# back down; a healthy retire shows the used footprint plateau.
set -uo pipefail
CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
W="${W:-$HOME/bd-0ajub-probe}"
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
    FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok \
        "$W/probe.img" "$W/mnt" >>"$W/daemon.log" 2>&1 &
    DAEMON=$!
    for _ in $(seq 1 120); do mountpoint -q "$W/mnt" && return 0; sleep 0.5; done
    return 1
}
unmount_clean() {
    fusermount3 -u "$W/mnt" 2>/dev/null
    for _ in $(seq 1 60); do mountpoint -q "$W/mnt" || break; sleep 0.5; done
    [ -n "$DAEMON" ] && wait "$DAEMON" 2>/dev/null
    DAEMON=""
}

for cycle in 1 2 3 4 5; do
    mount_rw || { echo "FATAL: mount failed at cycle $cycle"; exit 1; }
    mount_rw || { echo "FATAL: mount failed at cycle $cycle"; exit 1; }
    # Same name, same bytes every cycle: any growth beyond the first write is
    # the superseded tree-log leaf the bead says is never freed.
    python3 - "$W/mnt" <<'PY'
import os, sys
fd = os.open(os.path.join(sys.argv[1], "file.bin"), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
os.write(fd, b"x" * 4096)
os.fsync(fd)
os.close(fd)
PY
    unmount_clean
    used=$(btrfs check --readonly "$W/probe.img" 2>/dev/null | grep -oE "found [0-9]+ bytes used" | grep -oE "[0-9]+")
    echo "cycle $cycle: bytes_used=$used"
done
echo "PROBE COMPLETE"
PY
    unmount_clean
    used=$(btrfs check --readonly "$W/probe.img" 2>/dev/null | grep -oE "found [0-9]+ bytes used" | grep -oE "[0-9]+")
    echo "cycle $cycle: bytes_used=$used"
done
echo "PROBE COMPLETE"
