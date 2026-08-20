#!/usr/bin/env bash
# bd-dm01m acceptance step 3, MOUNTED half: drive the tree-log leaf-overflow
# fallback against a real FUSE mount.
#
# The accumulator re-serializes items for EVERY inode fsync'd since the last full
# commit, so it grows without bound until one leaf can no longer hold it. At that
# point btrfs_write_tree_log_for_sync must refuse, the fsync path must convert the
# refusal into a FULL TRANSACTION COMMIT (commit_strategy=
# full_commit_log_overflow_fallback), and NOTHING may be lost -- neither the
# inodes already in the log nor the one whose fsync tripped the overflow.
#
# The in-process pin (221bb2539) fires after 10 fsync'd inodes on the csum
# fixture. Do NOT treat 10 as a contract on a real image; this measures it.
set -uo pipefail

S="${LOGDIR:-${TMPDIR:-/tmp}/dm01m-overflow}"
mkdir -p "$S"
LOG=$S/dm01m_overflow.log
DLOG=$S/dm01m_overflow_daemon.log
DLOG2=$S/dm01m_overflow_daemon2.log
CLI="${CLI:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/ffs-cli}"
IMG=$HOME/dm01m-overflow-throwaway.img
MNT=$HOME/dm01m-overflow-mnt
N=${N:-200}

cleanup() {
  fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null || true
}

{
  echo "===== SETUP ====="
  df -BG / | tail -1 | awk '{print "AVAIL: "$4}'
  awk '{print "loadavg: "$1" "$2" "$3}' /proc/loadavg
  cleanup
  rm -f "$DLOG" "$DLOG2"
  cp "${FIXTURE:-$HOME/btrfs-5vis3.img}" "$IMG"
  mkdir -p "$MNT"
  echo "image: $IMG $(stat -c %s "$IMG") bytes; N=$N inodes"

  echo "===== MOUNT (rw + ephemeral tree log) ====="
  RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$IMG" "$MNT" >>"$DLOG" 2>&1 &
  DAEMON=$!
  echo "daemon pid=$DAEMON"
  DEADLINE=$((SECONDS+90))
  until mountpoint -q "$MNT"; do
    kill -0 "$DAEMON" 2>/dev/null || { echo "!! daemon exited before mounting"; tail -30 "$DLOG"; exit 1; }
    [ $SECONDS -lt $DEADLINE ] || { echo "!! mount deadline"; tail -30 "$DLOG"; cleanup; exit 1; }
    sleep 0.5
  done
  echo "mounted after ${SECONDS}s"

  echo "===== WRITE + FSYNC $N DISTINCT INODES ====="
  python3 - "$MNT" "$N" <<'PY'
import os, sys
mnt, n = sys.argv[1], int(sys.argv[2])
for i in range(n):
    p = os.path.join(mnt, f"ovf-{i:04d}.bin")
    fd = os.open(p, os.O_CREAT | os.O_RDWR, 0o644)
    os.pwrite(fd, bytes([i & 0xFF]) * 4096, 0)
    os.fsync(fd)          # every one of these returns SUCCESS
    os.close(fd)
print(f"  fsynced {n} inodes, 4096 bytes each")
PY

  echo "===== FALLBACK EVIDENCE (daemon log) ====="
  FB=$(grep -c 'full_commit_log_overflow_fallback' "$DLOG" 2>/dev/null || true)
  FAST=$(grep -c 'tree_log_fast_fsync' "$DLOG" 2>/dev/null || true)
  echo "  commit_strategy=full_commit_log_overflow_fallback : $FB"
  echo "  commit_strategy=tree_log_fast_fsync               : $FAST"
  echo "  first fallback at fsync ordinal (1-based over sync lines):"
  grep -n 'commit_strategy' "$DLOG" 2>/dev/null | grep -n 'full_commit_log_overflow_fallback' | head -1
  echo "  tree_log_items high-water:"
  grep -o 'tree_log_items=[0-9]*' "$DLOG" 2>/dev/null | sed 's/.*=//' | sort -n | tail -1

  echo "===== KILL -9 (crash, NOT unmount) ====="
  kill -9 "$DAEMON" 2>/dev/null || true
  DEADLINE=$((SECONDS+30))
  while kill -0 "$DAEMON" 2>/dev/null && [ $SECONDS -lt $DEADLINE ]; do sleep 0.2; done
  kill -0 "$DAEMON" 2>/dev/null && echo "!! daemon survived SIGKILL" || echo "daemon dead"
  cleanup

  echo "===== REMOUNT AND READ BACK ALL $N ====="
  RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$IMG" "$MNT" >>"$DLOG2" 2>&1 &
  D2=$!
  DEADLINE=$((SECONDS+90))
  until mountpoint -q "$MNT"; do
    kill -0 "$D2" 2>/dev/null || { echo "!! remount daemon exited"; tail -30 "$DLOG2"; exit 1; }
    [ $SECONDS -lt $DEADLINE ] || { echo "!! remount deadline"; tail -30 "$DLOG2"; cleanup; exit 1; }
    sleep 0.5
  done
  python3 - "$MNT" "$N" <<'PY'
import os, sys
mnt, n = sys.argv[1], int(sys.argv[2])
missing, wrong_size, bad_bytes, ok = [], [], [], 0
for i in range(n):
    p = os.path.join(mnt, f"ovf-{i:04d}.bin")
    if not os.path.exists(p):
        missing.append(i); continue
    st = os.stat(p)
    if st.st_size != 4096:
        wrong_size.append((i, st.st_size)); continue
    with open(p, "rb") as fh:
        data = fh.read()
    if data != bytes([i & 0xFF]) * 4096:
        bad_bytes.append(i); continue
    ok += 1
print(f"  survived intact : {ok}/{n}")
print(f"  MISSING         : {len(missing)} {missing[:12]}")
print(f"  WRONG SIZE      : {len(wrong_size)} {wrong_size[:12]}")
print(f"  WRONG CONTENT   : {len(bad_bytes)} {bad_bytes[:12]}")
PY
  echo "  replay lines:"
  grep -i 'replay' "$DLOG2" 2>/dev/null | tail -5

  kill "$D2" 2>/dev/null || true
  cleanup
  echo "image kept for inspection: $IMG"
  echo "OVERFLOW_TEST_DONE"
} >> "$LOG" 2>&1
