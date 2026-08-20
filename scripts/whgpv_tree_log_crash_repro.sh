#!/usr/bin/env bash
# bd-whgpv / bd-dm01m step 2: MOUNTED crash reproduction for the btrfs tree log.
#
# WHAT THIS EXISTS TO CATCH. Two defects were found with exactly this sequence and
# neither was visible to any in-process test:
#
#   bd-whgpv  the mount-path replay closure mapped its already-physical argument a
#             SECOND time, read unwritten space, failed the block checksum, and —
#             because replay failure is only a warning — the mount continued with
#             every acknowledged fsync silently lost. Invisible in-process because
#             every fixture we own is identity-mapped (`build_btrfs_csum_image` says
#             so; there is an `identity_chunks()` helper), and when logical ==
#             physical, mapping twice is a no-op.
#
#   bd-dm01m  the log held only the LAST fsync'd inode, so every earlier fsync in a
#             transaction was lost. The in-process pin for this passes through
#             TestDevice, which does not re-verify the block checksum on read.
#
# WHY kill -9 AND NOT unmount. A clean unmount performs a full transaction commit,
# which supersedes the log and hides exactly what this is testing. The daemon must
# die without that chance.
#
# WHY TWO FILES. A single-file test passes against the broken bd-dm01m code, because
# the surviving inode is the last one fsync'd. B is asserted first, with its own
# message: if B is missing the defect is NOT bd-dm01m and the reader is told so.
#
# NOT A MEASUREMENT. This is pass/fail, so host contention does not invalidate it and
# it needs no quiet window and no build slot. It does need a mount, so it cannot run
# on the rch fleet.
#
# Usage:  scripts/whgpv_tree_log_crash_repro.sh [SOURCE_BTRFS_IMAGE] [FFS_CLI]
#
# The source image is COPIED; the original is never mutated. The copy is removed on
# exit — these are 512 MiB each and this host has run at 93% full.
set -uo pipefail

SRC="${1:-$HOME/btrfs-bisect-2500.img}"
CLI="${2:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/ffs-cli}"
IMG="$HOME/whgpv-crash-throwaway.$$.img"
MNT="$HOME/whgpv-crash-mnt.$$"

# The mountpoint must live under $HOME: the command guard on this host refuses
# redirects and mount targets elsewhere.
cleanup() {
  fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null || true
  rm -f "$IMG"
  rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -r "$SRC" ] || fail "source image not readable: $SRC"
[ -x "$CLI" ] || fail "ffs-cli not executable: $CLI (build with: env -u CARGO_TARGET_DIR cargo build -p ffs-cli)"

echo "source : $SRC"
echo "cli    : $CLI"
cp "$SRC" "$IMG"
mkdir -p "$MNT"

# EVERY wait carries a deadline AND a liveness check on the writer. A file- or
# state-sentinel loop with neither can spin forever on a producer that already died;
# that has cost this fleet hours.
wait_for_mount() {
  local pid="$1" deadline=$((SECONDS + 60))
  until mountpoint -q "$MNT"; do
    kill -0 "$pid" 2>/dev/null || { echo "--- daemon output ---"; tail -20 "$LOG"; fail "daemon exited before mounting"; }
    [ $SECONDS -lt $deadline ] || { echo "--- daemon output ---"; tail -20 "$LOG"; fail "mount deadline"; }
    sleep 0.5
  done
}

LOG="$(mktemp -t whgpv-daemon-XXXXXX.log)"
trap 'cleanup; rm -f "$LOG"' EXIT

echo "== mount, write+fsync A then B =="
"$CLI" mount --rw --btrfs-rw-ephemeral-ok "$IMG" "$MNT" >>"$LOG" 2>&1 &
DAEMON=$!
wait_for_mount "$DAEMON"

python3 - "$MNT" <<'PY'
import os, sys
mnt = sys.argv[1]
for name, size in (("whgpv-A.bin", 4096), ("whgpv-B.bin", 8192)):
    p = os.path.join(mnt, name)
    fd = os.open(p, os.O_CREAT | os.O_RDWR, 0o644)
    os.pwrite(fd, b"\xA5" * size, 0)
    os.fsync(fd)            # returns SUCCESS: this is what must survive
    os.close(fd)
    print(f"  fsynced {name} size={os.stat(p).st_size}")
PY

echo "== kill -9 (crash, NOT unmount) =="
kill -9 "$DAEMON" 2>/dev/null || true
DEADLINE=$((SECONDS + 30))
while kill -0 "$DAEMON" 2>/dev/null && [ $SECONDS -lt $DEADLINE ]; do sleep 0.2; done
kill -0 "$DAEMON" 2>/dev/null && fail "daemon survived SIGKILL"
fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null || true

echo "== remount and read back =="
"$CLI" mount --rw --btrfs-rw-ephemeral-ok "$IMG" "$MNT" >>"$LOG" 2>&1 &
D2=$!
wait_for_mount "$D2"

rc=0
b=$(stat -c %s "$MNT/whgpv-B.bin" 2>/dev/null || echo missing)
[ "$b" = "8192" ] || { echo "FAIL: B is $b, expected 8192 — the LAST fsync'd inode surviving is the part that already worked, so this is NOT bd-dm01m"; rc=1; }
a=$(stat -c %s "$MNT/whgpv-A.bin" 2>/dev/null || echo missing)
[ "$a" = "4096" ] || { echo "FAIL: A is $a, expected 4096 — an fsync that returned SUCCESS was lost"; rc=1; }

if grep -q 'tree-log replay failed' "$LOG"; then
  echo "NOTE: replay reported a failure — the reason is the diagnosis:"
  grep -o 'tree-log replay failed.*' "$LOG" | head -1
  rc=1
fi

kill "$D2" 2>/dev/null || true
if [ "$rc" -eq 0 ]; then
  echo "PASS: A=$a B=$b, both acknowledged fsyncs survived the crash"
else
  echo "--- daemon output ---"; tail -30 "$LOG"
fi
exit "$rc"
