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
OUT=${FFS_OUT:-/tmp/ffs-abba}
BLOCKS=${FFS_BLOCKS:-3}
REPS=${FFS_REPS:-6}
DAEMON_CPU=${FFS_DAEMON_CPU:-8}
CLIENT_CPU=${FFS_CLIENT_CPU:-40}
HERE=$(cd "$(dirname "$0")" && pwd)

[ -x "$CLI" ] || { echo "FATAL: no ffs-cli at $CLI"; exit 2; }
[ -f "$IMG" ] || { echo "FATAL: no image at $IMG"; exit 2; }

# Refuse to certify on an UNSTABLE host rather than bank a row that will be
# refused later. The gate is stability, not absolute quiet: a 1-minute average
# dipping to 10 while the 5-minute sits at 25 is the tail of a burst, and a run
# launched into it finishes in a busier window than it started. A host pinned flat
# at a moderate level is the better place to certify. See scripts/host_stability.py
# for the criteria and its self-test; set FFS_SKIP_STABILITY=1 to override
# deliberately, which will be visible in the row because the reason is printed.
if [ "${FFS_SKIP_STABILITY:-0}" != "1" ]; then
  if ! STABILITY=$(python3 "$HERE/host_stability.py"); then
    echo "$STABILITY"
    echo "A failure to certify under load is not a loss. Re-run when stable."
    exit 4
  fi
  echo "$STABILITY"
fi

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
: > "$OUT/samples.tsv"; : > "$OUT/loadavg"

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
    if [ "$CLIENT" = warm ]; then taskset -c "$CLIENT_CPU" "$BIN" "$1" "$OUT/list" >/dev/null 2>&1
    else taskset -c "$CLIENT_CPU" "$BIN" "$1" >/dev/null 2>&1; fi
    e=$EPOCHREALTIME
    awk '{print $1}' /proc/loadavg >> "$OUT/loadavg"
    # rep 1 of every visit is COLD and runs 2-3x the warm reps; including it
    # produced a spurious 1.5630x result that sign-flipped on replicate.
    [ "$i" = 1 ] || printf "%s\t%s\t%s\n" "$2" "$3" \
      "$(python3 -c "print((${e}-${s})*1e3)")" >> "$OUT/samples.tsv"
  done
}
v_ffs() {
  local log="$OUT/ffs-$1.log"; : > "$log"
  FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 FFS_MOUNT_BENCH_EVIDENCE=1 FFS_AUTO_UNMOUNT=0 \
    taskset -c "$DAEMON_CPU" "$CLI" mount --runtime-mode managed --no-background-scrub \
    "$IMG" "$FMNT" >> "$log" 2>&1 &
  local mp=$!
  sleep 7
  mountpoint -q "$FMNT" || { echo "FATAL: FrankenFS mount did not come up; see $log"; exit 3; }
  sweep "$FMNT" ffs "$1"
  kill -INT $mp 2>/dev/null; wait $mp 2>/dev/null; sleep 2
}
v_kern() {
  sudo -n mount -o loop,ro "$IMG" "$KMNT" 2>/dev/null || { echo "FATAL: kernel mount"; exit 3; }
  sweep "$KMNT" kern "$1"
  sudo -n umount "$KMNT" 2>/dev/null; sleep 1
}
v_cal() { sweep "$TMNT" cal "$1"; }

for b in $(seq 1 "$BLOCKS"); do
  v_cal "${b}c1"; v_ffs "${b}a1"; v_kern "${b}b1"; v_kern "${b}b2"; v_ffs "${b}a2"; v_cal "${b}c2"
done
fusermount3 -u "$FMNT" 2>/dev/null

echo "=== in-process ELF identity (quote THIS, not a neighbouring sha256sum) ==="
grep -ohE "binary_sha256=[0-9a-f]{64}" "$OUT"/ffs-*.log | tail -1
FFS_OUT="$OUT" FFS_ENTRIES="$ENTRIES" python3 "$HERE/fuse_vs_kernel_abba_report.py"
