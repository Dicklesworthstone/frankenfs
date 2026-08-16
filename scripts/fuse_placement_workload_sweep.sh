#!/usr/bin/env bash
# bd-btrfs-warm-stat-5x-9pxn1 / bd-4ypbv: does the co-location win SURVIVE the real
# workload, and does it INVERT under concurrency?
#
# The banked placement result (>= 1.2210x co-located vs SMT-sibling) was measured on
# warm stat: one client, one file, ~1.000 FUSE requests/stat. That is a near-pure
# round-trip generator and deliberately so. It leaves two things unproven, and both
# are falsification tests of my own published scope rule rather than confirmations:
#
#   A. READDIR+STAT, one client. The actual 8x-vs-kernel row is `ls -lU`, ~7 requests
#      per entry with a mixed opcode stream, not a single repeated getxattr. If
#      co-location only helps the degenerate case it is not a lever for that row.
#   B. FOUR CONCURRENT CLIENTS. I published "co-location would SERIALISE a concurrent
#      workload". That is a prediction, and it is cheap to test: if four clients pinned
#      onto the daemon's own CPU do NOT lose, my scope rule is wrong and the caveat on
#      the banked row is mis-stated.
#
# Arms are deliberately only the three with tight A/A nulls in the banked sweep
# (same 1.018/1.024, smt 1.024/1.005, xccd 1.095/1.012). `unpin` is excluded on
# purpose: its own null is 1.4875x, so it cannot serve as a baseline (bd-plt79).
#
# Drift guard: forward then reversed arm order, as in the banked sweep.
#
# WARM-UP, and it is load-bearing rather than cosmetic. The FIRST timed rep after
# every mount runs 2-3x the warm reps. With 4 mounts per arm that puts 4 cold values
# into a 12-rep arm, which does not merely add noise: it produced a spurious 1.5630x
# readdir+stat "win" that sign-flipped to 0.9013x on the replicate, and it inflated
# the bootstrap interval on a concurrency effect whose distributions are in fact
# fully disjoint. Every rep is therefore recorded with its index and rep 1 of each
# mount is excluded from the statistics. Observed and fixed 2026-08-16.
set -u
CLI=/data/projects/frankenfs/target/release-perf/ffs-cli
IMG=/data/tmp/ffs-pgo-train.img
MNT=/tmp/ffs-probe-mnt
OUT=/tmp/ffs-wl
mkdir -p "$MNT" "$OUT"
: > "$OUT/raw.tsv"

dcpu() { echo 8; }
ccpu() { case "$1" in same) echo 8 ;; smt) echo 40 ;; xccd) echo 30 ;; esac; }
# Four-client sets: co-located piles all four onto the daemon's CPU; the others get
# four distinct cores so only the daemon relationship differs.
cset() { case "$1" in same) echo "8 8 8 8" ;; smt) echo "40 41 42 43" ;; xccd) echo "30 31 28 29" ;; esac; }

start() {
  : > "$1"
  FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 FFS_MOUNT_BENCH_EVIDENCE=1 FFS_AUTO_UNMOUNT=0 \
    taskset -c "$(dcpu)" "$CLI" mount --runtime-mode managed --no-background-scrub \
    "$IMG" "$MNT" >> "$1" 2>&1 &
  MP=$!
  sleep 7
}
stop() { kill -INT "$MP" 2>/dev/null; wait "$MP" 2>/dev/null; sleep 2; }

run_arm() {
  local arm="$1" pass="$2"
  local log="$OUT/$arm.$pass.log"
  local s e i

  # --- workload A: readdir+stat, ONE client ---
  start "$log"
  for i in 1 2 3; do
    s=$EPOCHREALTIME
    taskset -c "$(ccpu "$arm")" ls -lU "$MNT" > /dev/null 2>&1
    e=$EPOCHREALTIME
    printf "A\t%s\t%s\t%s\t%s\n" "$arm" "$pass" "$i" "$(python3 -c "print((${e}-${s})*1e3)")" >> "$OUT/raw.tsv"
  done
  stop

  # --- workload B: distinct-file stat, FOUR concurrent clients ---
  start "$log.b"
  for i in 1 2 3; do
    s=$EPOCHREALTIME
    local n=0
    local pids=()
    for c in $(cset "$arm"); do
      n=$((n + 1))
      ( cd "$MNT" && taskset -c "$c" xargs -a "/tmp/ffs-wl-part$n" stat -c '%s' >/dev/null 2>&1 ) &
      pids+=($!)
    done
    # Wait on the CLIENT pids only. A bare `wait` also waits on the mount daemon,
    # which `start` backgrounds in this same shell and which does not exit until
    # `stop` signals it — that deadlocks the sweep forever. Observed 2026-08-16.
    wait "${pids[@]}"
    e=$EPOCHREALTIME
    printf "B\t%s\t%s\t%s\t%s\n" "$arm" "$pass" "$i" "$(python3 -c "print((${e}-${s})*1e3)")" >> "$OUT/raw.tsv"
  done
  stop
  echo "  $arm/$pass done"
}

# Build four disjoint 2000-name partitions from a throwaway mount.
start "$OUT/prep.log"
ls -U "$MNT" 2>/dev/null | head -8000 > /tmp/ffs-wl-all
stop
python3 -c "
ns=[l.strip() for l in open('/tmp/ffs-wl-all') if l.strip()]
for i in range(4):
    open(f'/tmp/ffs-wl-part{i+1}','w').write('\n'.join(ns[i::4])+'\n')
"

for a in same smt xccd; do run_arm "$a" fwd; done
for a in xccd smt same; do run_arm "$a" rev; done
fusermount3 -u "$MNT" 2>/dev/null

python3 - <<'PY'
import statistics as st, collections
d=collections.defaultdict(lambda: collections.defaultdict(list))
for line in open('/tmp/ffs-wl/raw.tsv'):
    w,a,p,rep,v=line.strip().split('\t')
    if rep=='1': continue   # cold first rep after each mount: warm-up, excluded
    d[w][(a,p)].append(float(v))
names={'A':'readdir+stat, ONE client (ls -lU, 20003 entries)',
       'B':'distinct stat, FOUR concurrent clients (8000 files)'}
for w in ('A','B'):
    print(f"\n=== workload {w}: {names[w]} ===")
    med={}
    for a in ('same','smt','xccd'):
        f=st.median(d[w][(a,'fwd')]); r=st.median(d[w][(a,'rev')])
        allv=sorted(d[w][(a,'fwd')]+d[w][(a,'rev')])
        med[a]=st.median(allv)
        print(f"  {a:5} median {med[a]:9.1f} ms   fwd {f:8.1f}  rev {r:8.1f}   A/A null {max(f,r)/min(f,r):.4f}x")
    print(f"  co-location vs smt  = {med['smt']/med['same']:.4f}x   (>1 means co-location WINS)")
    print(f"  co-location vs xccd = {med['xccd']/med['same']:.4f}x")
PY
echo "WL DONE"
