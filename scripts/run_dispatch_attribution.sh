#!/usr/bin/env bash
# Attribute the readdir+stat daemon residue to an OPCODE (bd-xfe7z follow-on).
#
# WHY THIS EXISTS. bd-xfe7z settled that the 1.143 us/op residue on readdir+stat
# is 96.6% daemon work and 3.4% transport: 0.0053 crossings per entry, one per
# ~187 entries, which killed the reply-sizing lever. That says where the cost is
# NOT. This says which opcode owns it, which is the next thing anyone needs
# before writing a format-layer lever.
#
#   scripts/run_dispatch_attribution.sh <image> [entries]
#
# HOW IT DIFFERS FROM run_crossing_count.sh. That script counts crossings and
# must strace the daemon to do it. strace serialises the traced process, so its
# durations are meaningless -- the script says so and discards them. This one
# takes NO strace: it reads the daemon's own per-opcode dispatch counters, which
# it emits at clean shutdown under FFS_MOUNT_BENCH_EVIDENCE. Those are measured
# inside the daemon around the handler body, so they exclude transport by
# construction, which is exactly the 96.6% in question.
#
# ⚠️ SHARES ARE THE RESULT, NOT NANOSECONDS. On a debug ELF the absolute
# per-entry times are inflated several fold and are not comparable to any banked
# row. What survives build mode is which opcode dominates. Do not bank a
# us/op figure from this script; bank the attribution.
set -u

IMG=${1:?usage: run_dispatch_attribution.sh <image> [entries]}
ENTRIES=${2:-0}
CLI=${FFS_CLI:-/data/projects/frankenfs/target/debug/ffs-cli}
WORK=${FFS_WORK:-$HOME/ffs-dispatch-attr}
HERE=$(cd "$(dirname "$0")" && pwd)

[ -x "$CLI" ] || { echo "FATAL: no ffs-cli at $CLI"; exit 2; }
[ -f "$IMG" ] || { echo "FATAL: no image at $IMG"; exit 2; }

mkdir -p "$WORK/mnt"
LOG="$WORK/daemon.log"
: > "$LOG"

# Same arm as the crossing count: the suppressed one, because that is the arm
# whose residue is unexplained. FFS_MOUNT_BENCH_EVIDENCE=1 is what makes the
# daemon emit both its suppression self-report and the dispatch metrics.
env FFS_FUSE_XATTR_NO_SUPPORT=auto FFS_MOUNT_BENCH_EVIDENCE=1 \
  "$CLI" mount "$IMG" "$WORK/mnt" >> "$LOG" 2>&1 &
DAEMON=$!

# `auto` walks the inode table before serving, which took 13.5s on a debug ELF
# over a 32768-inode image. Fail-closed wait sized far above that.
for _ in $(seq 1 1200); do mountpoint -q "$WORK/mnt" && break; sleep 0.1; done
mountpoint -q "$WORK/mnt" || {
  echo "FATAL: mount did not appear within 120s"
  tail -3 "$LOG"
  kill "$DAEMON" 2>/dev/null
  exit 3
}

if ! sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -q "xattr_suppression=active"; then
  echo "FATAL: suppression is not active, so this is not the arm with the residue."
  sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -o "xattr_suppression=[a-z]*" | head -1
  fusermount3 -u "$WORK/mnt" 2>/dev/null
  exit 4
fi

# The client is the measurement (bd-xfe7z): `find -exec stat` batches its stats
# after the walk, which teaches FUSE_READDIRPLUS_AUTO that plus is not useful and
# swings the counted result by 376x. Use the client the certified row ran.
CLIENT_BIN="$WORK/readdir_stat_client"
gcc -O2 -o "$CLIENT_BIN" "$HERE/abba_clients/readdir_stat_client.c" || {
  echo "FATAL: could not build the readdir+stat client"
  fusermount3 -u "$WORK/mnt" 2>/dev/null
  exit 6
}

COUNTED=$(find "$WORK/mnt" -maxdepth 1 -type f 2>/dev/null | wc -l)
[ "$ENTRIES" = "0" ] && ENTRIES=$COUNTED

# Warm, then the measured pass. Both run; the counters are cumulative, so the
# report divides by 2 passes' worth of entries rather than pretending the warm
# pass did not happen.
"$CLIENT_BIN" "$WORK/mnt" >/dev/null 2>&1
"$CLIENT_BIN" "$WORK/mnt" >/dev/null 2>&1
PASSES=2

# Clean unmount is what makes the daemon print its counters. A kill would not.
fusermount3 -u "$WORK/mnt" 2>/dev/null
wait $DAEMON 2>/dev/null

echo "entries walked: $ENTRIES x $PASSES passes"
sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -o "mount_dispatch_metrics,[^ ]*" | tail -1 \
  > "$WORK/metrics.txt"
# bd-xfe7z: the THREE-WAY split, from the daemon's own crossings line. This is
# a DIFFERENT counter family from mount_dispatch_metrics above -- dispatch_ns is
# the whole handler, ops_ns is the FsOps call inside it, reply_ns is reply
# construction, and the remainder is per-entry handler bookkeeping. Captured to
# its own file because the two families do NOT share a denominator; mixing them
# already produced a 645.98% share once.
sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -o "mount_candidate_crossings,.*" | tail -1 \
  > "$WORK/crossings.txt"

python3 - "$WORK/metrics.txt" "$ENTRIES" "$PASSES" <<'PY'
import sys

path, entries, passes = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
text = open(path).read().strip()
if not text:
    print("FATAL: the daemon emitted no mount_dispatch_metrics line.")
    print("       Without it there is nothing to attribute; refusing to guess.")
    raise SystemExit(7)

fields = {}
for part in text.split(",")[1:]:
    if "=" in part:
        k, v = part.split("=", 1)
        fields[k] = v

def num(key):
    try:
        return int(fields.get(key, "0"))
    except ValueError:
        return 0

total_ops = entries * passes

opcodes = ["getattr", "lookup", "readdir", "getxattr", "mutation", "other"]
rows = []
for op in opcodes:
    c, n = num(f"{op}_dispatch_count"), num(f"{op}_dispatch_nanos")
    rows.append((op, c, n))
rows.sort(key=lambda r: -r[2])

# The denominator is the SUM of the per-opcode counters, NOT handler_total_nanos.
# First version used handler_total and printed shares up to 646%: the daemon
# reported `handler total: 43 calls` while getattr alone had 40407, so the two
# families do not measure the same thing and cannot be divided into each other.
# A share above 100% is the arithmetic announcing a mismatched denominator, and
# the zero-check that was supposed to guard this passed happily on 43.
total_nanos = sum(n for _, n, in ((op, n) for op, _, n in rows))
total_calls = sum(c for _, c, _ in rows)
if total_nanos == 0 or total_calls == 0:
    print("FATAL: every per-opcode counter is zero, so the daemon served nothing it")
    print("       counted. That is an instrument failure, not an attribution.")
    raise SystemExit(8)

ht_c, ht_n = num("handler_total_count"), num("handler_total_nanos")
print(f"per-opcode total: {total_calls} calls, {total_nanos} ns  <- denominator")
print(f"handler_total_*:  {ht_c} calls, {ht_n} ns", end="")
if ht_c != total_calls:
    print("  <- DISAGREES with the per-opcode sum; not used, and worth a look")
else:
    print()
print(f"{'opcode':<10} {'calls':>10} {'ns':>14} {'share':>8} {'ns/entry':>10}")
for op, c, n in rows:
    share = 100.0 * n / total_nanos
    print(f"{op:<10} {c:>10} {n:>14} {share:>7.2f}% {n/total_ops:>10.1f}")

top_op, top_c, top_n = rows[0]
print()
print(f"readdirplus memo: remembers={num('readdirplus_memo_remembers')} "
      f"hits={num('readdirplus_memo_hits')}")
print(f"ATTRIBUTION: {top_op} owns {100.0*top_n/total_nanos:.1f}% of daemon handler time "
      f"({top_n/total_ops:.1f} ns/entry over {total_ops} entry-visits).")
print("NOTE: shares are the result. Absolute ns on a debug ELF are inflated and")
print("      must not be compared against any banked row.")
PY

# Three-way decomposition of readdirplus (bd-xfe7z): dispatch = ops + reply +
# remainder. The remainder is the current target (60.0% on a debug ELF), and
# repeating this split on release-perf is the stated prerequisite before writing
# a lever against it -- so it is a command, not a paragraph.
python3 - "$WORK/crossings.txt" <<'PYSPLIT'
import sys

text = open(sys.argv[1]).read().strip()
if not text:
    print()
    print("three-way split: no mount_candidate_crossings line "
          "(ELF predates it, or FFS_MOUNT_BENCH_EVIDENCE was unset)")
    raise SystemExit(0)

fields = {}
for part in text.replace(",", " ").split():
    if "=" in part:
        k, v = part.split("=", 1)
        try:
            fields[k] = int(v)
        except ValueError:
            pass

dispatch = fields.get("dispatch_ns_readdirplus", 0)
if dispatch == 0:
    print()
    print("three-way split: dispatch_ns_readdirplus=0, so readdirplus never ran or")
    print("was never timed. No split emitted -- a zero denominator is not a result.")
    raise SystemExit(0)

ops_getattr = fields.get("ops_ns_getattr", 0)
ops_readdir = fields.get("ops_ns_readdir", 0)
reply = fields.get("reply_ns_readdirplus", 0)
remainder = dispatch - ops_getattr - ops_readdir - reply

# The getattr OpsTimer lives ONLY inside the prefetch path, which is gated on
# FFS_FUSE_READDIRPLUS_INODE_ORDER. With the knob unset that timer never runs,
# ops_ns_getattr reads 0, and the format-layer attribute work silently lands in
# the remainder -- which then reads 95.58% instead of 55.90% and points the next
# lever at bookkeeping that is mostly getattr. Measured both ways on the same
# ELF, 2026-08-17. A zero here is a CONFIGURATION artifact, not a finding.
if ops_getattr == 0:
    print()
    print("REFUSING to print a split: ops_ns_getattr=0.")
    print("  The getattr timer is gated on FFS_FUSE_READDIRPLUS_INODE_ORDER, so")
    print("  with that knob unset the attribute work is absorbed into the")
    print("  remainder and every share below it is wrong. Re-run with")
    print("  FFS_FUSE_READDIRPLUS_INODE_ORDER=1 to get a split that adds up.")
    raise SystemExit(9)

print()
print("readdirplus three-way split (dispatch_ns_readdirplus = %d):" % dispatch)
for label, value in (
    ("ops_ns_getattr      ", ops_getattr),
    ("ops_ns_readdir      ", ops_readdir),
    ("reply_ns_readdirplus", reply),
    ("remainder           ", remainder),
):
    print("  %s %14d  %6.2f%%" % (label, value, 100.0 * value / dispatch))
if remainder < 0:
    print("  WARNING: negative remainder -- the parts exceed the whole, so these")
    print("           timers are not nested the way this split assumes. Do NOT")
    print("           quote these shares; fix the nesting first.")
PYSPLIT
