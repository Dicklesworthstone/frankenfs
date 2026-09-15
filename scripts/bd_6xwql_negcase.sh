#!/usr/bin/env bash
# bd-6xwql acceptance 1: a create after a failed lookup must be visible to a
# stat within milliseconds, WITH the new default (create-side invalidation
# off) and, as a control, with FFS_FUSE_CREATE_INVAL=1. A dropped invalidation
# returns the right answer ~60 s late rather than throwing, so this asserts on
# ELAPSED TIME, never on exit codes.
set -uo pipefail

CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
MODE="${1:-default}"
WORK="${WORK:-$HOME/bd-6xwql-work}"
BASE="$WORK/negcase-$MODE.img"
MNT="$WORK/negcase-mnt"
LOG="$WORK/negcase-$MODE.log"
mkdir -p "$WORK"

cleanup() {
    if [ -n "${DAEMON:-}" ] && kill -0 "$DAEMON" 2>/dev/null; then
        kill -INT "$DAEMON" 2>/dev/null; sleep 2
        kill -0 "$DAEMON" 2>/dev/null && kill -9 "$DAEMON"
    fi
    mountpoint -q "$MNT" && fusermount3 -u "$MNT" 2>/dev/null
}
trap cleanup EXIT

rm -f "$BASE"; rm -rf "$MNT"
fallocate -l 256M "$BASE"
mkfs.btrfs -q "$BASE"
mkdir -p "$MNT"
sudo -n mount -o loop "$BASE" "$MNT"
sudo -n chown "$(id -u):$(id -g)" "$MNT"
sudo -n umount "$MNT"
mkdir -p "$MNT"

echo "===== arm=$MODE ====="
if [ "$MODE" = "optin" ]; then
    FFS_FUSE_CREATE_INVAL=1 FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$BASE" "$MNT" >>"$LOG" 2>&1 &
else
    FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$BASE" "$MNT" >>"$LOG" 2>&1 &
fi
DAEMON=$!
DEADLINE=$((SECONDS+120))
until mountpoint -q "$MNT"; do
    kill -0 "$DAEMON" 2>/dev/null || { echo "!! daemon exited before mounting"; tail -20 "$LOG"; exit 1; }
    [ $SECONDS -lt $DEADLINE ] || { echo "!! mount deadline"; exit 1; }
    sleep 0.5
done

python3 - "$MNT" <<'PY'
import os, sys, time
mnt = sys.argv[1]
name = os.path.join(mnt, "negcase-target.bin")
for attempt in range(3):
    missed = os.path.join(mnt, f"probe-miss-{attempt}.tmp")
    try:
        os.stat(missed)          # failed lookup: installs the negative dentry
    except FileNotFoundError:
        pass
    start = time.perf_counter()
    fd = os.open(name, os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, b"negcase-payload")
    os.close(fd)
    deadline = time.perf_counter() + 5.0
    while True:
        try:
            st = os.stat(name)
            if st.st_size == len(b"negcase-payload"):
                break
        except FileNotFoundError:
            pass
        if time.perf_counter() > deadline:
            sys.exit(f"STALE: post-create stat still wrong after 5 s (attempt {attempt})")
        time.sleep(0.001)
    print(f"  attempt {attempt}: visible after {(time.perf_counter() - start)*1000:.3f} ms")
    os.unlink(name)
print("PASS: create after failed lookup visible in milliseconds")
PY
rc=$?
cleanup
exit "$rc"
