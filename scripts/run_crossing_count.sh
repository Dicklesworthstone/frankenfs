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
# 120s, not the 7.5s this used to allow. `auto` PROVES the image carries no
# xattrs by walking the whole inode table at mount, before it serves a request,
# and on a debug ELF that is slow: measured 13.5s to reach "suppression ACTIVE"
# on a 512MB / 32768-inode image. The old bound gave up first and reported
# "mount did not appear" while the daemon was still scanning -- and then left it
# running, so the next attempt raced a live mount. This is a fail-closed wait,
# not a latency budget, so it is sized far above the slowest arm rather than
# near it.
for _ in $(seq 1 1200); do mountpoint -q "$WORK/mnt" && break; sleep 0.1; done
mountpoint -q "$WORK/mnt" || {
  echo "FATAL: mount did not appear within 120s"
  tail -3 "$LOG"
  kill "$DAEMON" 2>/dev/null
  exit 3
}

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
# `kernel.yama.ptrace_scope=1` (this host) lets a process trace only its own
# DESCENDANTS. strace here is a SIBLING of the daemon -- both are children of
# this script -- so a plain attach is refused with
# `ptrace(PTRACE_SEIZE): Operation not permitted`. sudo lifts that.
#
# This is not a convenience. Observed: the attach failed, strace wrote an empty
# syscall table, `reads` parsed as 0, and the classifier printed a CONFIDENT
# verdict -- "far below the transport prediction, the residue is NOT crossings"
# -- from an instrument that never ran. An absent measurement is not a
# measurement of zero.
STRACE_PREFIX=()
if [ "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)" != "0" ]; then
  if sudo -n true 2>/dev/null; then
    STRACE_PREFIX=(sudo -n)
  else
    echo "FATAL: ptrace_scope is restricted and passwordless sudo is unavailable,"
    echo "       so strace cannot attach to the daemon. Refusing to emit a count"
    echo "       that would be the absence of a measurement rather than a result."
    fusermount3 -u "$WORK/mnt" 2>/dev/null
    exit 5
  fi
fi

# `-y` annotates each fd with its path, and the count below keeps only reads on
# /dev/fuse. WITHOUT this the count is every read() in all 66 daemon threads --
# including reads of the BACKING IMAGE -- while being reported as "reads on the
# fuse device". That inflated the first real run to 1.9926 crossings/entry,
# which is arithmetically impossible as a crossing count: at ~7.29us each it
# would be 14.5us/entry against a measured 4.048us/op for the whole operation.
# `-c` is dropped because a summary table cannot carry fd paths.
"${STRACE_PREFIX[@]}" strace -f -y -e trace=read -p "$DAEMON" \
  -o "$WORK/strace.out" 2> "$WORK/strace.err" &
STRACE=$!
sleep 1
# Match the FAILURE strings only. strace announces SUCCESS on stderr too --
# "Process N attached with 66 threads" -- and a bare `attach` matched that, so
# the first version of this guard aborted every successful run. A fail-closed
# check that fires on success is just as broken as one that never fires; it
# only fails in the direction that looks responsible.
if grep -qE "attach: ptrace|Operation not permitted|could not attach" \
    "$WORK/strace.err" 2>/dev/null; then
  echo "FATAL: strace did not attach to the daemon:"
  sed 's/^/       /' "$WORK/strace.err"
  "${STRACE_PREFIX[@]}" kill -INT "$STRACE" 2>/dev/null
  fusermount3 -u "$WORK/mnt" 2>/dev/null
  exit 5
fi
find "$WORK/mnt" -maxdepth 1 -type f -exec stat -c %s {} + > /dev/null 2>&1
sleep 1
"${STRACE_PREFIX[@]}" kill -INT "$STRACE" 2>/dev/null
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
# Only reads whose fd resolves to the fuse device are crossings. Everything
# else the daemon reads (the backing image, above all) is not.
reads = sum(
    1
    for line in text.splitlines()
    if "/dev/fuse" in line and " read(" in line and "= -1 " not in line
)
# A daemon that served this walk MUST have read the fuse device. Zero is not a
# count of zero crossings, it is the signature of an instrument that did not
# run -- a failed ptrace attach produces exactly this, and the classifier will
# happily turn it into "the residue is NOT crossings" if allowed to.
if reads == 0:
    print("FATAL: strace recorded ZERO reads while the daemon served this walk.")
    print("       That is an instrument failure, not a result. No verdict emitted.")
    raise SystemExit(6)
per_entry = crossings_per_entry(reads, entries)
print(f"reads on the fuse device: {reads}")
print(f"crossings per entry:      {per_entry:.4f}")
print(verdict(per_entry))
print("NOTE: durations under strace are meaningless. Only the count is a result.")
PY
