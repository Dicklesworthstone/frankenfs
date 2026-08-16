#!/usr/bin/env bash
# bd-4ypbv LEVER: is the 16-18 us FUSE round trip a PLACEMENT cost?
#
# A round trip carries 0.4 us of daemon work and costs 16-18 us. That gap is far
# larger than a FUSE request needs to be, which points at wakeup + cache-migration
# cost between client and daemon rather than at anything either one computes.
# Placement is a RUNTIME lever, so it is measurable with the existing ELF under
# the no-new-builds directive.
#
# Warm stat (same file repeated) is a near-pure round-trip generator at ~1.0
# requests/stat, so wall/stat IS round-trip cost. 5 placements on a 5975WX
# (SMT siblings are n,n+32; 4 CCDs of 8 cores):
#   unpin  : no pinning at all (the baseline every banked row was measured under)
#   same   : daemon and client on ONE logical CPU  (max locality, forced switch)
#   smt    : SMT siblings 8/40                     (shared L1/L2, no switch)
#   ccd    : same CCD, different core 8/12         (shared L3)
#   xccd   : different CCD 8/30                    (cross-L3)
#
# Drift guard: the arm order is run FORWARD then REVERSED, so any monotone drift
# in the box loads both halves of every arm symmetrically. 5 reps per mount, 2
# mounts per arm = 10 reps; report the MEDIAN and the min/max.
set -u
CLI=/data/projects/frankenfs/target/release-perf/ffs-cli
IMG=/data/tmp/ffs-pgo-train.img
MNT=/tmp/ffs-probe-mnt
OUT=/tmp/ffs-place
OPS=20000
mkdir -p "$MNT" "$OUT"
: > "$OUT/raw.tsv"

daemon_cpu() { case "$1" in unpin) echo "" ;; same) echo 8 ;; smt) echo 8 ;; ccd) echo 8 ;; xccd) echo 8 ;; esac; }
client_cpu() { case "$1" in unpin) echo "" ;; same) echo 8 ;; smt) echo 40 ;; ccd) echo 12 ;; xccd) echo 30 ;; esac; }

run_arm() {
  local arm="$1" pass="$2"
  local dcpu ccpu log
  dcpu=$(daemon_cpu "$arm"); ccpu=$(client_cpu "$arm")
  log="$OUT/$arm.$pass.log"; : > "$log"

  if [ -n "$dcpu" ]; then
    FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 FFS_MOUNT_BENCH_EVIDENCE=1 FFS_AUTO_UNMOUNT=0 \
      taskset -c "$dcpu" "$CLI" mount --runtime-mode managed --no-background-scrub "$IMG" "$MNT" >> "$log" 2>&1 &
  else
    FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 FFS_MOUNT_BENCH_EVIDENCE=1 FFS_AUTO_UNMOUNT=0 \
      "$CLI" mount --runtime-mode managed --no-background-scrub "$IMG" "$MNT" >> "$log" 2>&1 &
  fi
  local mp=$!
  sleep 7

  local i s e
  for i in 1 2 3 4 5; do
    s=$EPOCHREALTIME
    if [ -n "$ccpu" ]; then
      ( cd "$MNT" && taskset -c "$ccpu" xargs -a /tmp/ffs-place-same stat -c '%s' >/dev/null 2>&1 )
    else
      ( cd "$MNT" && xargs -a /tmp/ffs-place-same stat -c '%s' >/dev/null 2>&1 )
    fi
    e=$EPOCHREALTIME
    printf "%s\t%s\t%s\n" "$arm" "$pass" \
      "$(python3 -c "print((${e}-${s})*1e6/${OPS})")" >> "$OUT/raw.tsv"
  done

  kill -INT "$mp" 2>/dev/null; wait "$mp" 2>/dev/null; sleep 2
  local rt
  rt=$(sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -oE "requests_total=[0-9]+" | tail -1 | cut -d= -f2)
  echo "  $arm pass$pass  requests=${rt:-?} ($(python3 -c "print(f'{${rt:-0}/(5*$OPS):.3f}')")/stat)"
}

# Build the warm list from a throwaway mount.
FFS_AUTO_UNMOUNT=0 "$CLI" mount --runtime-mode managed --no-background-scrub "$IMG" "$MNT" >/dev/null 2>&1 &
PREP=$!; sleep 7
ONE=$(ls -U "$MNT" 2>/dev/null | head -1)
kill -INT $PREP 2>/dev/null; wait $PREP 2>/dev/null; sleep 2
python3 -c "open('/tmp/ffs-place-same','w').write(('$ONE\n')*$OPS)"

for a in unpin same smt ccd xccd; do run_arm "$a" fwd; done
for a in xccd ccd smt same unpin; do run_arm "$a" rev; done

fusermount3 -u "$MNT" 2>/dev/null
echo "=== us per warm stat == us per FUSE round trip (${OPS} stats/rep, 10 reps/arm) ==="
python3 - <<'PY'
import statistics, collections
d=collections.defaultdict(list)
for line in open('/tmp/ffs-place/raw.tsv'):
    a,p,v=line.split('\t'); d[a].append(float(v))
base=statistics.median(d['unpin'])
print(f"{'arm':6} {'median':>9} {'min':>9} {'max':>9} {'vs unpin':>10}")
for a in ['unpin','same','smt','ccd','xccd']:
    v=sorted(d[a]); m=statistics.median(v)
    print(f"{a:6} {m:8.2f}u {v[0]:8.2f}u {v[-1]:8.2f}u {base/m:9.4f}x")
PY
echo "PLACE DONE"
