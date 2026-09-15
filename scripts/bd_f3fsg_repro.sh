#!/usr/bin/env bash
# bd-f3fsg acceptance step 2: clean-in / dirty-out reproduction.
#
# The recorded finding (2026-08-24): the acct-* fixtures failed `btrfs check`
# AS STORED — tree blocks in roots 1 and 2 with no extent-tree backref, error
# count scaling with entry count. Those images have since been removed from
# $HOME, so provenance-by-inspection is moot. What remains decidable TODAY is
# the writer question: does a CURRENT build, populating a kernel-created
# (therefore sound by construction) base image through our own read-write FUSE
# mount, leave tree blocks without backrefs?
#
# Clean image in -> populate through the daemon -> `btrfs check` on the stored
# bytes, before anything else touches the file. rc=0 means the writer is clean
# on the current tree; rc=1 reproduces the finding against today's source.
set -uo pipefail

COUNT="${COUNT:-2000}"
SIZE_MIB="${SIZE_MIB:-256}"
BASE="${BASE:-$HOME/bd-f3fsg-base.img}"
POPULATED="${POPULATED:-$HOME/bd-f3fsg-populated.img}"
MNT="${MNT:-$HOME/bd-f3fsg-mnt}"
CLI="${CLI:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/ffs-cli}"
WORK="${WORK:-$HOME/bd-f3fsg-work}"

S="${LOGDIR:-${TMPDIR:-/tmp}/bd-f3fsg}"
mkdir -p "$S" "$WORK"
LOG="$S/repro.log"

cleanup() {
    if [ -n "${DAEMON:-}" ] && kill -0 "$DAEMON" 2>/dev/null; then
        kill -INT "$DAEMON" 2>/dev/null
        sleep 2
        kill -0 "$DAEMON" 2>/dev/null && kill -9 "$DAEMON"
    fi
    mountpoint -q "$MNT" && fusermount3 -u "$MNT" 2>/dev/null
}
trap cleanup EXIT

echo "===== SETUP ====="
df -BG / | tail -1 | awk '{print "AVAIL: "$4}'
[ -x "$CLI" ] || { echo "FATAL: no ffs-cli at $CLI"; exit 1; }

echo "===== KERNEL-CREATED BASE (sound by construction) ====="
rm -f "$BASE" "$POPULATED"
truncate -s "${SIZE_MIB}M" "$BASE"
mkfs.btrfs -q "$BASE" || { echo "FATAL: base image creation failed"; exit 1; }

echo "===== NEGATIVE CONTROL: btrfs check on the pristine base ====="
btrfs check --readonly "$BASE"
BASE_RC=$?
echo "base check rc=$BASE_RC"
[ "$BASE_RC" -eq 0 ] || { echo "FATAL: base image is not sound; the run is void"; exit 1; }

# mkfs leaves the fs root owned by uid 0, and without allow_other the kernel
# would EPERM our unprivileged creates. One kernel round-trip rewrites the
# ownership on the stored image; the clean unmount keeps it sound.
KMNT="$WORK/kernel-mount"
mkdir -p "$KMNT"
sudo -n mount -o loop "$BASE" "$KMNT"
sudo -n chown "$(id -u):$(id -g)" "$KMNT"
sudo -n umount "$KMNT"
cp "$BASE" "$POPULATED"

echo "===== POPULATE THROUGH OUR FUSE MOUNT (--count $COUNT) ====="
mkdir -p "$MNT"
FFS_AUTO_UNMOUNT=0 RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$POPULATED" "$MNT" >>"$LOG" 2>&1 &
DAEMON=$!
echo "daemon pid=$DAEMON"
DEADLINE=$((SECONDS+120))
until mountpoint -q "$MNT"; do
    kill -0 "$DAEMON" 2>/dev/null || { echo "!! daemon exited before mounting"; tail -30 "$LOG"; exit 1; }
    sleep 0.5
done
echo "mounted after ${SECONDS}s"

python3 - "$MNT" "$COUNT" <<'PY'
import os, sys
mnt, count = sys.argv[1], int(sys.argv[2])
created = 0
for i in range(count):
    d = os.path.join(mnt, f"d{i // 100:03d}")
    if not os.path.isdir(d):
        os.mkdir(d)
    p = os.path.join(d, f"f{i:05d}.bin")
    fd = os.open(p, os.O_CREAT | os.O_RDWR, 0o644)
    os.write(fd, bytes([i & 0xFF]) * (256 + (i % 384)))
    os.close(fd)
    created += 1
print(f"  created {created} entries through the daemon")
PY

echo "===== CLEAN UNMOUNT (full commit path) ====="
fusermount3 -u "$MNT" || { echo "!! unmount failed"; kill -9 "$DAEMON"; exit 1; }
wait "$DAEMON" 2>/dev/null
DAEMON=""

echo "===== btrfs check AS STORED ====="
btrfs check --readonly "$POPULATED"
CHECK_RC=$?
echo "populated check rc=$CHECK_RC"

echo "===== VERDICT ====="
if [ "$CHECK_RC" -eq 0 ]; then
    echo "bd-f3fsg: CLEAN-IN/CLEAN-OUT on the current tree at count=$COUNT — the recorded writer defect does not reproduce."
else
    echo "bd-f3fsg: REPRODUCED on the current tree at count=$COUNT — our write path leaves the stored image invalid (rc=$CHECK_RC)."
fi
exit "$CHECK_RC"
