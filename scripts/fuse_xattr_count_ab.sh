#!/usr/bin/env bash
# bd-biwl4 acceptance step 3: does FUSE_POSIX_ACL cut the REQUEST COUNT?
#
# The lever aims at the campaign's worst vs-incumbent ratio (btrfs readdir+stat
# 7.728937x), whose largest component is 4.00 getxattr per entry. Two of those four
# are system.posix_acl_access / system.posix_acl_default, and FUSE_POSIX_ACL asks
# the kernel to cache ACL answers instead of forwarding each one as a round trip.
#
# THIS SCRIPT DELIBERATELY DOES NOT TIME ANYTHING. The prediction is exact and
# countable — 7.00 -> 5.00 requests per entry — and a count is decidable in one run
# where a wall-clock ratio needs pinning, replication, nulls and a worst-bound
# quote. If the count does not move, the kernel is not caching what this flag was
# expected to make it cache and the lever is DEAD: record it and stop. Chasing wall
# time before the count moves is how this campaign has produced retracted rows.
#
# Ordering rule, learned the expensive way: correctness gates the count. See the
# bead's acceptance step 2 — if the kernel is caching an ACL answer we generate
# incorrectly, the lever is void no matter what it does to the count.
set -u

CLI=${FFS_CLI:-/data/projects/frankenfs/target/release-perf/ffs-cli}
IMG=${FFS_IMG:-/data/tmp/ffs-pgo-train.img}
MNT=${FFS_MNT:-/tmp/ffs-aclab-mnt}
OUT=${FFS_OUT:-/tmp/ffs-aclab}
DAEMON_CPU=${FFS_DAEMON_CPU:-8}
CLIENT_CPU=${FFS_CLIENT_CPU:-40}
REPS=${FFS_REPS:-3}

[ -x "$CLI" ] || { echo "FATAL: no ffs-cli at $CLI (build it, then re-run)"; exit 2; }
[ -f "$IMG" ] || { echo "FATAL: no image at $IMG"; exit 2; }
mkdir -p "$MNT" "$OUT"

# Daemon pinned, client pinned to its SMT sibling. NOT co-located: co-location is a
# warm-stat-only effect that measured NULL on readdir+stat and inverts under
# concurrency (bd-4ypbv scope row). Pinning at all is required because an UNPINNED
# mounted measurement is unstable to 1.4875x on its own A/A null (bd-plt79); it
# matters less for counts than for wall, but the arms must still be alike.
start() { # $1 log  $2 acl-knob-value ("" = unset)
  : > "$1"
  if [ -n "$2" ]; then
    FFS_FUSE_POSIX_ACL="$2" FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 \
      FFS_MOUNT_BENCH_EVIDENCE=1 FFS_AUTO_UNMOUNT=0 \
      taskset -c "$DAEMON_CPU" "$CLI" mount --runtime-mode managed \
      --no-background-scrub "$IMG" "$MNT" >> "$1" 2>&1 &
  else
    FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 \
      FFS_MOUNT_BENCH_EVIDENCE=1 FFS_AUTO_UNMOUNT=0 \
      taskset -c "$DAEMON_CPU" "$CLI" mount --runtime-mode managed \
      --no-background-scrub "$IMG" "$MNT" >> "$1" 2>&1 &
  fi
  MP=$!
  sleep 7
  mountpoint -q "$MNT" || { echo "FATAL: mount did not come up; see $1"; exit 3; }
}
stop() { kill -INT "$MP" 2>/dev/null; wait "$MP" 2>/dev/null; sleep 2; }

# An arm that silently failed to enable the knob would "pass" while measuring the
# control twice — the all-failing-workload trap. The daemon logs an explicit line
# when it negotiates FUSE_POSIX_ACL, so require it in the ON arm and require its
# ABSENCE in the OFF arm. Fail closed either way.
assert_knob() { # $1 log  $2 expected(on|off)
  local seen=0
  grep -q "FUSE_POSIX_ACL negotiated" "$1" && seen=1
  if [ "$2" = on ] && [ "$seen" -ne 1 ]; then
    echo "FATAL: ON arm never negotiated FUSE_POSIX_ACL (kernel declined, or the"
    echo "       knob is not wired). Refusing to report a comparison of two OFF arms."
    exit 4
  fi
  if [ "$2" = off ] && [ "$seen" -ne 0 ]; then
    echo "FATAL: OFF arm negotiated FUSE_POSIX_ACL; the env is leaking into the control."
    exit 4
  fi
}

arm() { # $1 tag  $2 knob-value  $3 expect(on|off)
  local tag="$1" knob="$2" expect="$3"
  local log="$OUT/$tag.log"
  start "$log" "$knob"
  assert_knob "$log" "$expect"

  # Rep 1 after every mount is COLD and runs 2-3x the warm reps; it skews counts
  # less than wall but still adds first-touch lookups. Discarded, as in
  # scripts/fuse_placement_workload_sweep.sh where it was found.
  local i
  for i in $(seq 1 "$REPS"); do
    taskset -c "$CLIENT_CPU" ls -lU "$MNT" > /dev/null 2>&1
    if [ "$i" = 1 ]; then
      RT_WARM_START=$(sed 's/\x1b\[[0-9;]*m//g' "$log" \
        | grep -oE "requests_total=[0-9]+" | tail -1 | cut -d= -f2)
      RT_WARM_START=${RT_WARM_START:-0}
    fi
  done
  stop

  local rt entries
  rt=$(sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -oE "requests_total=[0-9]+" | tail -1 | cut -d= -f2)
  entries=$(grep -oE "^[0-9]+$" "$OUT/entries" 2>/dev/null | tail -1)
  python3 - "$tag" "${rt:-0}" "${RT_WARM_START:-0}" "${entries:-0}" "$REPS" <<'PY'
import sys
tag, rt, warm_start, entries, reps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
warm_reqs = rt - warm_start          # requests issued by the WARM reps only
warm_reps = max(reps - 1, 1)
per_entry = warm_reqs / (entries * warm_reps) if entries else 0.0
print(f"{tag:4}  requests_total={rt:<9} warm_requests={warm_reqs:<9} "
      f"entries={entries:<7} reps_counted={warm_reps}  -> {per_entry:.3f} requests/entry")
open('/tmp/ffs-aclab/result.tsv','a').write(f"{tag}\t{per_entry:.6f}\n")
PY
  # Per-name attribution, so a moved count can be ATTRIBUTED rather than assumed.
  # If the total drops but posix_acl probes did not, something else changed.
  grep -oE "mount_xattr_probe_census[^ ]*" "$log" | tail -1 || true
}

: > "$OUT/result.tsv"
# Entry count, from a throwaway mount so it is not attributed to either arm.
start "$OUT/prep.log" ""
ls -U "$MNT" 2>/dev/null | wc -l > "$OUT/entries"
stop
echo "directory entries: $(cat "$OUT/entries")"

arm off ""     off
arm on  "1"    on

python3 - <<'PY'
vals = dict(l.split('\t') for l in open('/tmp/ffs-aclab/result.tsv').read().strip().split('\n'))
off, on = float(vals['off']), float(vals['on'])
print(f"\nOFF {off:.3f} requests/entry -> ON {on:.3f} requests/entry   delta {off-on:+.3f}")
print(f"prediction was 7.00 -> 5.00 (a drop of 2.00, the two system.posix_acl_* probes)")
if off - on < 0.5:
    print("VERDICT: count did NOT move. The kernel is not caching what this flag was")
    print("         expected to make it cache. The lever is DEAD -- record the negative")
    print("         and STOP. Do not proceed to wall-clock measurement.")
else:
    print(f"VERDICT: count moved by {off-on:.3f}/entry. Proceed to acceptance step 4:")
    print("         correctness re-check, then WALL with the daemon pinned, two runs,")
    print("         worst bound quoted, absolute medians alongside the ratio.")
PY
fusermount3 -u "$MNT" 2>/dev/null
echo "ACL COUNT A/B DONE"
