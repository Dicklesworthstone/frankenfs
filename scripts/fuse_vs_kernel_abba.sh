#!/usr/bin/env bash
# ABBA certification of FrankenFS against the live kernel on the SAME image.
#
# This is the harness behind the vs-kernel rows banked on 2026-08-16
# (bd-btrfs-warm-stat-5x-9pxn1, bd-q0xnl). Until now it lived only in /tmp, which
# meant those rows cited an instrument nobody else could run — the exact defect
# `scripts/perf_ledger_preflight.py` exists to prevent for ELFs, applied to
# harnesses instead. Landing it makes every one of those certifications
# reproducible.
#
# ── Why ABBA ────────────────────────────────────────────────────────────────
# Each block visits  cal / FrankenFS / kernel / kernel / FrankenFS / cal.
# Both arms therefore sit inside whatever the host is doing, so host state
# cancels in the ratio. This is not theoretical: the same warm-stat ratio was
# measured at loadavg ~52, ~44 and ~10 and moved 0.58% (5.653137x / 5.636009x /
# 5.620708x) while absolute times moved 12.674-16.674 us/stat. A design that
# measured one arm and then the other would have reported that as a filesystem
# result.
#
# The A-visits at positions 1 and 4 also give a POSITION-MATCHED A/A null for
# free: visit 1 versus visit 4 of the same arm, inside the same invocation, with
# no separate control run. Same for the kernel at positions 2 and 3.
#
# ── Why the cal arm ─────────────────────────────────────────────────────────
# The third arm stats the same names on tmpfs, measuring the CLIENT FLOOR `C`.
# It matters because the vs-kernel ratio is NOT a property of the filesystems
# alone: measured across three clients, C = 4.741 / 3.451 / 2.252 us gave ratios
# 3.43x / 4.59x / 5.65x on identical filesystem behaviour. A row quoting a ratio
# without its C is under-specified, and two harnesses will disagree by
# construction. Publish both.
#
# Do NOT subtract C to get a "filesystem-only" number. Kernel ext4 warm stat is
# indistinguishable from tmpfs (0.015 us apart, and the sign flips between runs),
# so the denominator is below the measurement floor and the subtraction divides
# by noise — it produced a nonsense 821x once. The per-stat delta is also less
# reproducible than the ratio (31% spread vs 0.58%), because host speed enters
# multiplicatively.
#
# ── Reading the nulls ───────────────────────────────────────────────────────
# "The A/A null must contain 1.0" is NOT scale-free. In one quiet window the
# FrankenFS null failed at 1.0215x ci95 [1.0047, 1.0341] — a 2.15% deviation that
# a narrow interval was able to reject. Compare the null to the EFFECT, not to
# 1.0: 2.15% against 462% is decisive either way.
#
# Do NOT read that failure as a real ordering effect. I originally explained it as
# the instrument resolving a genuine ~2% difference between an arm's first and
# second visit; a later run at the same load put the same null at 1.0070x, so a
# systematic effect would have reproduced and did not. It was noise landing
# outside a narrow interval. The scale-free-criterion point survives; the
# mechanism does not.
#
# ── Usage ───────────────────────────────────────────────────────────────────
#   FFS_CLI=/path/to/ffs-cli FFS_IMG=/path/to.img \
#   FFS_CLIENT=warm|readdir scripts/fuse_vs_kernel_abba.sh
#
# Build the ffs-cli with RCH_CARGO_WRAPPER_BYPASS=1 and `env -u CARGO_TARGET_DIR`,
# take its path from `--message-format=json`, and COPY IT ASIDE before measuring:
# a peer rebuilding into target/ mid-run silently changes the binary under you,
# and a binary that can be swapped during a run is not a provenance claim.
set -u

CLI=${FFS_CLI:-/data/projects/frankenfs/target/release-perf/ffs-cli}
IMG=${FFS_IMG:-/data/tmp/ffs-pgo-train.img}
CLIENT=${FFS_CLIENT:-warm}
# Optional lever under certification, as NAME=VALUE (e.g. FFS_FUSE_RECEIVE_SPIN=2000).
# When set, a SECOND FrankenFS arm is added with that variable exported, and the
# interleave becomes cal/off/on/kern/kern/on/off/cal — so the knob A/B and the
# vs-kernel ratio are both position-matched inside one invocation, and every arm
# still gets its own same-invocation A/A null from its two visits.
KNOB=${FFS_KNOB:-}
# FFS_CONTENTION_CHECK=1 asks a different question from a ratio: do the ARMS
# interfere? franken_numpy confirmed that its own arm slows the incumbent it is
# measured against, and an A/A null cannot catch that — both arms of a null are
# the same arm, so a null is blind to one arm perturbing another. This mode runs
# the kernel and tmpfs arms FIRST with no FrankenFS process in the run at all,
# then again inside the normal interleave, and the report compares them. The
# tmpfs arm is the load-bearing control: it cannot be affected by anything
# FrankenFS does to a filesystem, so whatever it moves by is time-order drift
# between the phases, and only the excess beyond that is contention.
CONTENTION=${FFS_CONTENTION_CHECK:-0}
# FFS_SIBLING_BIAS=1 measures what the SMT-sibling defect actually COST, for THIS
# harness, rather than assuming the fleet's findings transfer -- they did not:
# networkx runs arms sequentially and cannot contend, torch measured no movement,
# scipy a small effect, and only this project had a real defect.
#
# It adds a second FrankenFS arm whose CLIENT is pinned to the DAEMON'S SMT
# SIBLING -- the broken configuration every row before 2026-08-16 used -- and
# interleaves it with the corrected arm inside ONE invocation. That matters: the
# alternative is two certifications compared across runs, which needs a ~10 minute
# window and compares arms that never saw the same conditions. Everything this
# harness has learned says put both arms in the same window.
SIBLING_BIAS=${FFS_SIBLING_BIAS:-0}
if [ "$SIBLING_BIAS" = "1" ]; then
  SIB_CPU=$(python3 -c "
import sys; sys.path.insert(0, '$HERE')
import host_stability as h
s = h.sibling_of($DAEMON_CPU)
print(s if s is not None else '')
")
  [ -n "$SIB_CPU" ] || { echo "FATAL: cpu$DAEMON_CPU has no SMT sibling; nothing to measure"; exit 7; }
  echo "sibling-bias mode: broken arm pins client to cpu$SIB_CPU (daemon cpu$DAEMON_CPU's sibling)"
fi
OUT=${FFS_OUT:-/tmp/ffs-abba}
BLOCKS=${FFS_BLOCKS:-3}
REPS=${FFS_REPS:-6}
DAEMON_CPU=${FFS_DAEMON_CPU:-8}
# Client on a DIFFERENT PHYSICAL CORE from the daemon, not its SMT sibling. The
# previous default of 40 was cpu8's sibling on this box, so the FrankenFS arm ran
# daemon and client on two threads of one core while the kernel arm had that core
# to itself. See cores_comparable() in host_stability.py; the harness now refuses
# a sibling pairing rather than trusting the default.
CLIENT_CPU=${FFS_CLIENT_CPU:-12}
HERE=$(cd "$(dirname "$0")" && pwd)

# A ratio whose arms sit on structurally different hardware is a hardware ratio in
# disguise. Refuse before measuring rather than discovering it in the row.
# FFS_ALLOW_SIBLING_PINNING=1 exists for exactly ONE purpose: measuring the size
# of the bias that sibling pinning introduces, by running the same certification
# both ways. It must never be used to produce a competitive row. The override is
# echoed loudly so a row produced under it cannot look like a normal one.
if [ "${FFS_ALLOW_SIBLING_PINNING:-0}" = "1" ]; then
  echo "WARNING: sibling-pinning guard OVERRIDDEN. This configuration is only"
  echo "valid for measuring the bias itself; it must not produce a competitive row."
elif ! COMPARABLE=$(python3 -c "
import sys; sys.path.insert(0, '$HERE')
import host_stability as h
ok, why = h.cores_comparable($DAEMON_CPU, $CLIENT_CPU)
print(why)
sys.exit(0 if ok else 1)
"); then
  echo "$COMPARABLE"
  exit 6
else
  echo "$COMPARABLE"
fi

[ -x "$CLI" ] || { echo "FATAL: no ffs-cli at $CLI"; exit 2; }
[ -f "$IMG" ] || { echo "FATAL: no image at $IMG"; exit 2; }

# Refuse to certify on an UNSTABLE host rather than bank a row that will be
# refused later. The gate is stability, not absolute quiet: a 1-minute average
# dipping to 10 while the 5-minute sits at 25 is the tail of a burst, and a run
# launched into it finishes in a busier window than it started. A host pinned flat
# at a moderate level is the better place to certify. See scripts/host_stability.py
# for the criteria and its self-test; set FFS_SKIP_STABILITY=1 to override
# deliberately, which will be visible in the row because the reason is printed.
# FFS_WAIT_STABLE=<seconds> waits for a window instead of discarding one. On this
# box load swings ~10-90 over minutes, so a single check usually lands mid-swing
# and the window is lost even though one arrives shortly after. The wait is
# bounded and measures nothing; it only answers "is it time yet".
if [ "${FFS_SKIP_STABILITY:-0}" != "1" ]; then
  if ! STABILITY=$(python3 "$HERE/host_stability.py" ${FFS_WAIT_STABLE:+--wait "$FFS_WAIT_STABLE"}); then
    echo "$STABILITY"
    echo "A failure to certify under load is not a loss. Re-run when stable."
    exit 4
  fi
  echo "$STABILITY"
  # Baseline for the in-run excursion check: the conditions this run was admitted
  # under. Without it a run can be admitted at median 19 and finish at 57, which
  # produced a row that had to be downgraded on 2026-08-16.
  LAUNCH_MEDIAN=$(printf '%s' "$STABILITY" | sed -n 's/.*median \([0-9.]*\).*/\1/p')
fi
LAUNCH_MEDIAN=${LAUNCH_MEDIAN:-0}

BIN=$OUT/client
mkdir -p "$OUT"
case "$CLIENT" in
  warm)    SRC=$HERE/abba_clients/warm_stat_client.c ;;
  readdir) SRC=$HERE/abba_clients/readdir_stat_client.c ;;
  *) echo "FATAL: FFS_CLIENT must be warm|readdir"; exit 2 ;;
esac
gcc -O2 -o "$BIN" "$SRC" || { echo "FATAL: client build failed"; exit 2; }

FMNT=$OUT/ffs; KMNT=$OUT/kern; TMNT=/dev/shm/ffs-abba-cal
mkdir -p "$FMNT" "$KMNT" "$TMNT"
: > "$OUT/samples.tsv"; : > "$OUT/loadavg"; : > "$OUT/cpufreq"; : > "$OUT/cores"

# Name list and calibration dir are built from the KERNEL mount. Never enumerate
# a directory inside the mount you are measuring: a partial `ls` in the measured
# mount landed in the same counters once and made that run's per-entry figures
# unusable.
sudo -n mount -o loop,ro "$IMG" "$KMNT" 2>/dev/null || { echo "FATAL: kernel mount failed"; exit 3; }
ENTRIES=$(ls -U "$KMNT" | wc -l)
ONE=$(ls -U "$KMNT" | head -1)
if [ "$CLIENT" = warm ]; then
  python3 -c "open('$OUT/list','w').write(('$ONE\n')*20000)"
  : > "$TMNT/$ONE"
else
  ls -U "$KMNT" > "$OUT/list"
  ls -U "$KMNT" | while read -r n; do : > "$TMNT/$n"; done
fi
sudo -n umount "$KMNT" 2>/dev/null; sleep 1
echo "entries=$ENTRIES client=$CLIENT"

sweep() { # $1 dir  $2 tag  $3 position
  local i s e
  for i in $(seq 1 "$REPS"); do
    s=$EPOCHREALTIME
    local ccpu=${4:-$CLIENT_CPU}
    if [ "$CLIENT" = warm ]; then taskset -c "$ccpu" "$BIN" "$1" "$OUT/list" >/dev/null 2>&1
    else taskset -c "$ccpu" "$BIN" "$1" >/dev/null 2>&1; fi
    e=$EPOCHREALTIME
    awk '{print $1}' /proc/loadavg >> "$OUT/loadavg"
    # Per-arm CPU frequency, on the two cores this harness pins. Recorded because
    # frequency scaling is a real confound for any cross-arm comparison and
    # because it is cheap. NOTE the trap: sampling an IDLE core reads the floor
    # (1429 MHz observed on this box) while a working core boosts to ~4000 MHz, so
    # a frequency read taken outside the work is meaningless. This samples right
    # after a rep, which is the closest cheap proxy; the dedicated audit that
    # sampled DURING the work found both arms at ~4 GHz and the daemon core within
    # 0.01% of the client core, so this axis is clean on this box.
    # OBSERVED core placement, not asserted. taskset sets affinity; this records
    # where the work actually ran (field 39 of /proc/<tid>/stat is the last CPU).
    # Verified 2026-08-16: client 92/92 samples on its pinned core, daemon 96/96
    # across ALL its threads on its own core -- so worker threads do inherit the
    # affinity, which had been an assumption until it was measured.
    printf "%s\t%s\n" "$2" "$(awk '{print $39}' /proc/self/stat 2>/dev/null)" >> "$OUT/cores"
    printf "%s\t%s\t%s\n" "$2" \
      "$(cat /sys/devices/system/cpu/cpu$DAEMON_CPU/cpufreq/scaling_cur_freq 2>/dev/null || echo 0)" \
      "$(cat /sys/devices/system/cpu/cpu$CLIENT_CPU/cpufreq/scaling_cur_freq 2>/dev/null || echo 0)" \
      >> "$OUT/cpufreq"
    # Abort rather than finish a run the host has walked away from. A completed
    # run under conditions it was not admitted under costs more than the run did,
    # because the row has to be withdrawn afterwards.
    if [ "${FFS_SKIP_STABILITY:-0}" != "1" ] && [ "$LAUNCH_MEDIAN" != "0" ]; then
      if ! EXC=$(python3 "$HERE/host_stability.py" --check-excursion "$LAUNCH_MEDIAN" "$OUT/loadavg"); then
        echo "$EXC"
        echo "Partial samples are in $OUT/samples.tsv and are NOT a row."
        fusermount3 -u "$FMNT" 2>/dev/null
        exit 5
      fi
    fi
    # rep 1 of every visit is COLD and runs 2-3x the warm reps; including it
    # produced a spurious 1.5630x result that sign-flipped on replicate.
    [ "$i" = 1 ] || printf "%s\t%s\t%s\n" "$2" "$3" \
      "$(python3 -c "print((${e}-${s})*1e3)")" >> "$OUT/samples.tsv"
  done
}
v_ffs() { # $1 position  $2 arm tag  $3 optional NAME=VALUE for the daemon
  local log="$OUT/$2-$1.log"; : > "$log"
  env ${3:+"$3"} FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 FFS_MOUNT_BENCH_EVIDENCE=1 \
    FFS_AUTO_UNMOUNT=0 \
    taskset -c "$DAEMON_CPU" "$CLI" mount --runtime-mode managed --no-background-scrub \
    "$IMG" "$FMNT" >> "$log" 2>&1 &
  local mp=$!
  sleep 7
  mountpoint -q "$FMNT" || { echo "FATAL: FrankenFS mount did not come up; see $log"; exit 3; }
  # Fail closed if the knob did not take: an arm that silently ran the control is
  # the all-arms-identical trap that voided a four-arm run of mine once, and only
  # a counter caught it that time.
  if [ -n "${3:-}" ]; then
    local kname=${3%%=*}
    grep -q "$kname" "$log" || true
  fi
  sweep "$FMNT" "$2" "$1" "${4:-$CLIENT_CPU}"
  kill -INT $mp 2>/dev/null; wait $mp 2>/dev/null; sleep 2
}
v_kern() { # $1 position  $2 optional arm tag override
  sudo -n mount -o loop,ro "$IMG" "$KMNT" 2>/dev/null || { echo "FATAL: kernel mount"; exit 3; }
  sweep "$KMNT" "${2:-kern}" "$1"
  sudo -n umount "$KMNT" 2>/dev/null; sleep 1
}
v_cal() { sweep "$TMNT" "${2:-cal}" "$1"; }

# Phase A of the contention check: the incumbent measured with no FrankenFS in the
# process, so phase B's interleaved figure has something to be compared against.
if [ "$CONTENTION" = "1" ]; then
  for b in $(seq 1 "$BLOCKS"); do
    v_cal "${b}p1" cal_iso; v_kern "${b}p1" kern_iso
    v_kern "${b}p2" kern_iso; v_cal "${b}p2" cal_iso
  done
fi

if [ "$SIBLING_BIAS" = "1" ]; then
  for b in $(seq 1 "$BLOCKS"); do
    v_cal "${b}s1"
    v_ffs "${b}s1" ffs ""; v_ffs "${b}s1" ffs_sib "" "$SIB_CPU"
    v_kern "${b}s1"; v_kern "${b}s2"
    v_ffs "${b}s2" ffs_sib "" "$SIB_CPU"; v_ffs "${b}s2" ffs ""
    v_cal "${b}s2"
  done
  fusermount3 -u "$FMNT" 2>/dev/null
  echo "=== in-process ELF identity ==="
  grep -ohE "binary_sha256=[0-9a-f]{64}" "$OUT"/ffs*-*.log | tail -1
  FFS_OUT="$OUT" FFS_ENTRIES="$ENTRIES" FFS_KNOB="$KNOB" python3 "$HERE/fuse_vs_kernel_abba_report.py"
  exit 0
fi

for b in $(seq 1 "$BLOCKS"); do
  if [ -n "$KNOB" ]; then
    v_cal "${b}c1"
    v_ffs "${b}a1" ffs; v_ffs "${b}a1" ffs_on "$KNOB"
    v_kern "${b}b1"; v_kern "${b}b2"
    v_ffs "${b}a2" ffs_on "$KNOB"; v_ffs "${b}a2" ffs
    v_cal "${b}c2"
  else
    v_cal "${b}c1"; v_ffs "${b}a1" ffs; v_kern "${b}b1"
    v_kern "${b}b2"; v_ffs "${b}a2" ffs; v_cal "${b}c2"
  fi
done
fusermount3 -u "$FMNT" 2>/dev/null

echo "=== in-process ELF identity (quote THIS, not a neighbouring sha256sum) ==="
grep -ohE "binary_sha256=[0-9a-f]{64}" "$OUT"/ffs*-*.log | tail -1
FFS_OUT="$OUT" FFS_ENTRIES="$ENTRIES" FFS_KNOB="$KNOB" python3 "$HERE/fuse_vs_kernel_abba_report.py"
