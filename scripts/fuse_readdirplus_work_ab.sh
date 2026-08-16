#!/usr/bin/env bash
# bd-q0xnl acceptance instrument: how much DAEMON WORK does readdirplus cost?
#
# The worst vs-incumbent row (btrfs readdir+stat 7.728937x) was measured to be
# daemon-work-bound, not round-trip-bound: forcing readdirplus cuts real boundary
# crossings ~33% and wall moved +0.1%. So the quantity that matters for the next
# lever is not crossings — it is `ops.getattr` calls per entry, which the
# readdirplus handler pays once per entry per readdir (lib.rs ~3583).
#
# This script measures that quantity directly, by DECOMPOSITION rather than by
# subtraction-from-wall. Three arms, and the third is the one that decides:
#
#   A. `ls -U`  with readdirplus FORCED   -> the client never stats, so every
#      getattr is OURS. Isolates the handler's own cost.
#   B. `ls -lU` with readdirplus FORCED   -> ours PLUS whatever the kernel asks.
#      B minus A is the kernel's contribution.
#   C. TWO `ls -lU` passes in ONE mount, AUTO vs FORCED. Pass 2 under AUTO is
#      served from the kernel's attribute cache and costs almost nothing; if
#      FORCED costs a second full sweep of getattr, the handler is re-deriving
#      attributes the kernel already holds.
#
# Measured 2026-08-16 on a 20001-entry ext4 fixture, for regression reference:
#   A  AUTO    197 getattr (0.010/entry)   FORCED 20106 (1.005/entry)
#   B  FORCED 40107 = ours 20106 + kernel ~20001
#   C  AUTO   20394 getattr / 19808 lookup   FORCED 60212 getattr / 0 lookup
# i.e. forcing readdirplus costs 2.95x the daemon getattr work for identical
# output. A lever that reuses attributes the readdir walk already materialised
# should move arm A's FORCED number toward arm A's AUTO number without moving B's
# kernel component.
#
# NOTE ON THE COUNTER: `requests_total` counts request SCOPES, not FUSE boundary
# crossings — record_ok() increments it from with_request_scope, which readdirplus
# invokes once per entry INTERNALLY (lib.rs:1156). Use the per-op dispatch counts
# here, not requests_total, or nested scopes will be double-read as crossings.
#
# CONFOUND THIS SCRIPT AVOIDS DELIBERATELY: never enumerate the directory in the
# same mount you are measuring. An earlier hand-run did `ls -U | head -200` for a
# name list in the measured mount; the pipe SIGPIPE'd and the partial enumeration
# landed in the same counters, making that run's per-entry figures unusable.
# Each arm here mounts fresh and runs exactly one workload.
set -u

CLI=${FFS_CLI:-/data/projects/frankenfs/target/release-perf/ffs-cli}
IMG=${FFS_IMG:-/data/tmp/ffs-pgo-train.img}
MNT=${FFS_MNT:-/tmp/ffs-rdpwork-mnt}
OUT=${FFS_OUT:-/tmp/ffs-rdpwork}
DAEMON_CPU=${FFS_DAEMON_CPU:-8}
CLIENT_CPU=${FFS_CLIENT_CPU:-40}

[ -x "$CLI" ] || { echo "FATAL: no ffs-cli at $CLI"; exit 2; }
[ -f "$IMG" ] || { echo "FATAL: no image at $IMG"; exit 2; }
mkdir -p "$MNT" "$OUT"

# Entry count comes from its OWN throwaway mount, never the measured one.
count_entries() {
  local log="$OUT/prep.log"
  : > "$log"
  FFS_AUTO_UNMOUNT=0 taskset -c "$DAEMON_CPU" "$CLI" mount --runtime-mode managed \
    --no-background-scrub "$IMG" "$MNT" >> "$log" 2>&1 &
  local mp=$!
  sleep 7
  ls -U "$MNT" 2>/dev/null | wc -l
  kill -INT $mp 2>/dev/null; wait $mp 2>/dev/null; sleep 2
}

arm() { # $1 tag  $2 knob ("" = AUTO)  $3 workload  $4 passes  $5 entries
  local tag="$1" knob="$2" work="$3" passes="$4" entries="$5"
  local log="$OUT/$tag.log"
  : > "$log"
  if [ -n "$knob" ]; then
    FFS_FUSE_READDIRPLUS_AUTO="$knob" FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 \
      FFS_MOUNT_BENCH_EVIDENCE=1 FFS_AUTO_UNMOUNT=0 taskset -c "$DAEMON_CPU" \
      "$CLI" mount --runtime-mode managed --no-background-scrub "$IMG" "$MNT" >> "$log" 2>&1 &
  else
    FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 \
      FFS_MOUNT_BENCH_EVIDENCE=1 FFS_AUTO_UNMOUNT=0 taskset -c "$DAEMON_CPU" \
      "$CLI" mount --runtime-mode managed --no-background-scrub "$IMG" "$MNT" >> "$log" 2>&1 &
  fi
  local mp=$! i
  sleep 7
  mountpoint -q "$MNT" || { echo "FATAL: $tag mount did not come up; see $log"; exit 3; }
  for i in $(seq 1 "$passes"); do
    taskset -c "$CLIENT_CPU" $work "$MNT" > /dev/null 2>&1
  done
  kill -INT $mp 2>/dev/null; wait $mp 2>/dev/null; sleep 2

  local m; m=$(grep -oE "mount_dispatch_metrics[^\"]{0,300}" "$log" | tail -1)
  [ -n "$m" ] || { echo "FATAL: $tag emitted no dispatch metrics; see $log"; exit 4; }
  python3 - "$tag" "$m" "$entries" "$passes" <<'PY'
import sys, re
tag, m, n, passes = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
d = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', m)}
g, l = d.get('getattr_dispatch_count', 0), d.get('lookup_dispatch_count', 0)
print(f"{tag:26} getattr {g:7} ({g/(n*passes):.3f}/entry/pass)   lookup {l:7} ({l/(n*passes):.3f})")
PY
}

N=$(count_entries)
echo "entries: $N"
arm "A_auto_ls-U"      ""  "ls -U"  1 "$N"
arm "A_forced_ls-U"    "0" "ls -U"  1 "$N"
arm "B_forced_ls-lU"   "0" "ls -lU" 1 "$N"
arm "C_auto_2x_ls-lU"  ""  "ls -lU" 2 "$N"
arm "C_forced_2x_ls-lU" "0" "ls -lU" 2 "$N"
fusermount3 -u "$MNT" 2>/dev/null
echo "READDIRPLUS WORK A/B DONE"
