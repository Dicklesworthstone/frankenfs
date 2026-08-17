#!/usr/bin/env bash
# One command that answers bd-xfe7z, for whenever the host is usable again.
#
# WHY IT EXISTS AS A SCRIPT. The measurement itself is seconds long and
# load-independent -- it is a COUNT, not a ratio -- but assembling it takes a
# mount, a workload, a pid, an strace and an unmount in the right order. This
# host has spent two days oscillating between loadavg 12 and 525, and windows
# have repeatedly closed while a command was being composed. So it is composed
# now, during a hard stop, and the window only has to be long enough to run it.
#
#   scripts/run_crossing_count.sh <image> [entries]
#
# WHAT IT DECIDES. With the capability probe suppressed, readdir+stat still sits
# 1.143 us/op above the client floor while warm stat sits at it. If that residue
# is TRANSPORT, crossings per entry land near 0.157 (one per 6.4 entries) and the
# lever is reply sizing. If it is DAEMON work, crossings per entry land far
# below that and the lever is in the format layer. One count falsifies one of
# them.
#
# ⚠️ NOT A CERTIFICATION. strace stops the world it traces, so every duration
# printed here is meaningless. Only the count is a result, and the count is what
# bd-xfe7z asks for. Do not bank a ratio from this script.
#
# ⚠️ /data is mounted nosuid, so the setuid fusermount3 is refused there. The
# mountpoint lives under $HOME.
set -u

IMG=${1:?usage: run_crossing_count.sh <image> [entries]}
ENTRIES=${2:-0}
CLI=${FFS_CLI:-/data/projects/frankenfs/target/debug/ffs-cli}
WORK=${FFS_WORK:-$HOME/ffs-crossing-count}
HERE=$(cd "$(dirname "$0")" && pwd)

[ -x "$CLI" ] || { echo "FATAL: no ffs-cli at $CLI (build it when builds are permitted)"; exit 2; }
[ -f "$IMG" ] || { echo "FATAL: no image at $IMG"; exit 2; }
command -v strace >/dev/null || { echo "FATAL: strace is required; it is the whole instrument"; exit 2; }

mkdir -p "$WORK/mnt"
LOG="$WORK/daemon.log"

# The suppressed arm, because that is the arm whose residue is unexplained. The
# control arm's crossings are already counted and known (bd-ha71t).
# FFS_MOUNT_BENCH_EVIDENCE=1 is REQUIRED, not decoration: the
# `xattr_suppression=...` line the check below greps for is emitted only under
# it (`emit_xattr_suppression_evidence`, ffs-fuse). Without it the daemon
# suppresses correctly and says nothing, the check finds no match, and this
# script exits 4 claiming the lever is inactive -- a false NEGATIVE in the one
# guard that exists to prevent a false positive.
env FFS_FUSE_XATTR_NO_SUPPORT=auto FFS_MOUNT_BENCH_EVIDENCE=1 \
  "$CLI" mount "$IMG" "$WORK/mnt" >> "$LOG" 2>&1 &
DAEMON=$!
for _ in $(seq 1 150); do mountpoint -q "$WORK/mnt" && break; sleep 0.05; done
mountpoint -q "$WORK/mnt" || { echo "FATAL: mount did not appear"; tail -3 "$LOG"; exit 3; }

# Confirm the arm is what it claims BEFORE counting anything. An arm that
# silently ran the control is how a btrfs certification reported a null on
# 2026-08-17; the harness now fails closed on exactly this and so does this.
if ! sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -q "xattr_suppression=active"; then
  echo "FATAL: suppression is not active on this mount, so the residue being"
  echo "       counted is not the residue bd-xfe7z is about."
  sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -o "xattr_suppression=[a-z]*" | head -1
  fusermount3 -u "$WORK/mnt" 2>/dev/null
  exit 4
fi

# Warm the caches first: the count must describe the steady state, not the cold
# walk that populated it.
find "$WORK/mnt" -maxdepth 1 -type f -printf '' 2>/dev/null
COUNTED=$(find "$WORK/mnt" -maxdepth 1 -type f 2>/dev/null | wc -l)
[ "$ENTRIES" = "0" ] && ENTRIES=$COUNTED

# strace the daemon while the client does one readdir+stat pass over the whole
# directory -- the workload whose residue is in question.
strace -c -f -e trace=read -p "$DAEMON" -o "$WORK/strace.out" &
STRACE=$!
sleep 1
find "$WORK/mnt" -maxdepth 1 -type f -exec stat -c %s {} + > /dev/null 2>&1
sleep 1
kill -INT $STRACE 2>/dev/null
wait $STRACE 2>/dev/null

fusermount3 -u "$WORK/mnt" 2>/dev/null
wait $DAEMON 2>/dev/null

echo "entries walked: $ENTRIES"
python3 - "$WORK/strace.out" "$ENTRIES" <<'PY'
import sys
sys.path.insert(0, "/data/projects/frankenfs/scripts")
from fuse_crossing_count import parse_syscall_counts, crossings_per_entry, verdict
text = open(sys.argv[1]).read()
entries = int(sys.argv[2])
reads = parse_syscall_counts(text).get("read", 0)
per_entry = crossings_per_entry(reads, entries)
print(f"reads on the fuse device: {reads}")
print(f"crossings per entry:      {per_entry:.4f}")
print(verdict(per_entry))
print("NOTE: durations under strace are meaningless. Only the count is a result.")
PY
