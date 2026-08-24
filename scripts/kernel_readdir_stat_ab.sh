#!/usr/bin/env bash
# bd-zpc3q follow-on: is the INCUMBENT the reason btrfs readdir+stat reads worse
# than ext4 readdir+stat?
#
# WHY THIS EXISTS. The banked rows are `7.728937x` (btrfs) and `2.791429x` (ext4),
# both ours-vs-kernel. 450923993 measured OUR side of both and found no
# btrfs-specific daemon excess: per entry the daemon costs 0.944x on btrfs against
# ext4, INSIDE that run's own A/A nulls. If our side costs the same on both, then
# an ours-vs-kernel ratio that differs by ~2.8x has to differ on the KERNEL side —
# or the two banked rows are not comparable to each other. This measures the
# kernel side directly and says which.
#
# NO FRANKENFS ARM AT ALL. Both arms here are the kernel: kernel btrfs and kernel
# ext4, same client, same entry count. So this is not a vs-incumbent claim about
# us and nothing it prints belongs in the scorecard. It is a property of the
# INCUMBENTS, measured to interpret two rows we already have.
#
# READABLE UNDER LOAD, WHICH IS WHY IT RUNS NOW. The prediction from 450923993 is
# a ~2.8x separation. That is far larger than this instrument's null, so a loaded
# host can still decide it — the same argument bd-xfe7z used for taking counts at
# loadavg 24-34 rather than waiting. If the effect comes back SMALL, it is inside
# the null and this prints UNDECIDABLE rather than a number.
#
#   scripts/kernel_readdir_stat_ab.sh <btrfs-image> <ext4-image> [rounds]
#
# The two images MUST hold the same number of entries, for the same reason as
# scripts/fuse_dispatch_split_ab.sh: directory size changes tree height.
#
# Needs passwordless sudo for the loop mounts. Mountpoint lives under $HOME
# because /data is nosuid.
set -u

BTRFS_IMG=${1:?usage: kernel_readdir_stat_ab.sh <btrfs-image> <ext4-image> [rounds]}
EXT4_IMG=${2:?usage: kernel_readdir_stat_ab.sh <btrfs-image> <ext4-image> [rounds]}
ROUNDS=${3:-3}
CLI=${FFS_CLI:-/data/projects/frankenfs/target/debug/ffs-cli}
WORK=${FFS_WORK:-$HOME/ffs-kernel-ab}
HERE=$(cd "$(dirname "$0")" && pwd)

sudo -n true 2>/dev/null || { echo "FATAL: passwordless sudo required for loop mounts"; exit 2; }
for img in "$BTRFS_IMG" "$EXT4_IMG"; do
  [ -f "$img" ] || { echo "FATAL: no image at $img"; exit 2; }
done

mkdir -p "$WORK/mnt"
CLIENT="$WORK/readdir_stat_client"
# The SAME client the certified rows used. A per-file stat walk is a different
# request mix and would answer a different question (bd-xfe7z).
gcc -O2 -o "$CLIENT" "$HERE/abba_clients/readdir_stat_client.c" \
  || { echo "FATAL: cannot build the readdir+stat client"; exit 3; }

# One visit: mount read-only, warm, time one pass, unmount.
# WARM, not cold: the banked rows are steady-state metadata enumeration, and a
# cold arm would measure the backing file's page-cache population instead.
visit() {
  local img=$1
  local tag=$2
  sudo -n mount -o loop,ro "$img" "$WORK/mnt" 2>/dev/null || { echo "FATAL: $tag mount failed" >&2; exit 4; }
  local entries
  entries=$(find "$WORK/mnt" -maxdepth 1 -type f | wc -l)
  "$CLIENT" "$WORK/mnt" > /dev/null 2>&1
  local t0 t1
  t0=$(date +%s%N)
  "$CLIENT" "$WORK/mnt" > /dev/null 2>&1
  t1=$(date +%s%N)
  sudo -n umount "$WORK/mnt" 2>/dev/null
  echo "$tag $(( (t1 - t0) )) $entries"
}

# The FUSE arm of the same workload, so the ours-vs-kernel RATIO can be formed on
# each filesystem inside ONE window. That ratio is the quantity the banked rows
# report, and forming both here is the only way to ask whether their difference is
# a property of the filesystems or of the two runs that produced them.
fuse_visit() {
  local img=$1
  local tag=$2
  # Optional third argument: extra environment for the daemon. Used for the
  # SUPPRESSED arm, which is a MEASUREMENT PROBE and not a shipping
  # configuration -- it answers `getxattr` with ENOSYS, which is a semantic
  # change, and exists here only because it removes almost exactly one boundary
  # crossing per entry (counted: 1.0052 -> 0.0052 crossings/entry, 9ffd33dec).
  # Timing both arms therefore PRICES the round trip directly instead of
  # inferring it from a per-crossing constant.
  local extra=${3:-}
  local log="$WORK/$tag-fuse.log"
  : >> "$log"
  # shellcheck disable=SC2086
  env $extra "$CLI" mount "$img" "$WORK/mnt" >> "$log" 2>&1 &
  local daemon=$!
  local i
  for i in $(seq 1 600); do mountpoint -q "$WORK/mnt" && break; sleep 0.2; done
  if ! mountpoint -q "$WORK/mnt"; then
    echo "FATAL: $tag fuse mount failed" >&2; tail -3 "$log" >&2; kill "$daemon" 2>/dev/null; exit 5
  fi
  local entries
  entries=$(find "$WORK/mnt" -maxdepth 1 -type f | wc -l)
  "$CLIENT" "$WORK/mnt" > /dev/null 2>&1
  local t0 t1
  t0=$(date +%s%N)
  "$CLIENT" "$WORK/mnt" > /dev/null 2>&1
  t1=$(date +%s%N)
  fusermount3 -u "$WORK/mnt" 2>/dev/null
  wait "$daemon" 2>/dev/null
  echo "$tag $(( (t1 - t0) )) $entries"
}

for r in $(seq 1 "$ROUNDS"); do
  # ABBA within the round, so each arm visits an early and a late position.
  visit "$BTRFS_IMG" kern-btrfs
  visit "$EXT4_IMG"  kern-ext4
  fuse_visit "$BTRFS_IMG" fuse-btrfs
  fuse_visit "$EXT4_IMG"  fuse-ext4
  fuse_visit "$BTRFS_IMG" supp-btrfs FFS_FUSE_XATTR_NO_SUPPORT=auto
  fuse_visit "$EXT4_IMG"  supp-ext4  FFS_FUSE_XATTR_NO_SUPPORT=auto
  fuse_visit "$EXT4_IMG"  supp-ext4  FFS_FUSE_XATTR_NO_SUPPORT=auto
  fuse_visit "$BTRFS_IMG" supp-btrfs FFS_FUSE_XATTR_NO_SUPPORT=auto
  fuse_visit "$EXT4_IMG"  fuse-ext4
  fuse_visit "$BTRFS_IMG" fuse-btrfs
  visit "$EXT4_IMG"  kern-ext4
  visit "$BTRFS_IMG" kern-btrfs
done | python3 -c '
import sys, collections, statistics

per = collections.defaultdict(list)
counts = collections.defaultdict(set)
for line in sys.stdin:
    parts = line.split()
    if len(parts) != 3:
        continue
    fs, ns, entries = parts[0], int(parts[1]), int(parts[2])
    if entries:
        per[fs].append(ns / entries)
        counts[fs.split("-", 1)[1]].add(entries)

# FAIL CLOSED ON A FIXTURE MISMATCH. Directory size changes tree height, so
# comparing a 20k btrfs against a 40k ext4 would attribute a FIXTURE difference to
# a filesystem. That is not hypothetical here: it is the exact confound this run
# exists to test for in the banked rows, and reproducing it silently would be the
# worst possible outcome. Per-entry normalisation hides it in the units, so the
# check has to be explicit.
sizes = {fs: sorted(v) for fs, v in counts.items()}
if len(sizes) == 2 and len({tuple(v) for v in sizes.values()}) != 1:
    print("FATAL: the two images do not hold the same entry count: %s" % sizes)
    print("       tree height would differ and this would measure the fixture.")
    raise SystemExit(2)

need = ("kern-btrfs", "kern-ext4", "fuse-btrfs", "fuse-ext4", "supp-btrfs", "supp-ext4")
missing = [a for a in need if len(per.get(a, [])) < 2]
if missing:
    print("arms with fewer than 2 visits, nothing decidable: %s" % ", ".join(missing))
    raise SystemExit(1)

med = {a: statistics.median(per[a]) for a in need}
# The within-arm null: same configuration, different position in the round.
spread = {a: max(per[a]) / min(per[a]) for a in need}
null = max(spread.values())

for a in need:
    print("%-11s %8.0f ns/entry   (%d visits, spread %.3fx)"
          % (a, med[a], len(per[a]), spread[a]))

# THE QUANTITY THE BANKED ROWS REPORT, formed on each filesystem inside this one
# window so the two are comparable to each other by construction.
r_btrfs = med["fuse-btrfs"] / med["kern-btrfs"]
r_ext4 = med["fuse-ext4"] / med["kern-ext4"]
print("")
print("ours-vs-kernel  btrfs %.3fx   ext4 %.3fx   btrfs/ext4 of the RATIOS %.3fx"
      % (r_btrfs, r_ext4, r_btrfs / r_ext4))
sep = (r_btrfs / r_ext4) if r_btrfs > r_ext4 else (r_ext4 / r_btrfs)
verdict = "DECIDABLE" if sep > null else "UNDECIDABLE (inside the A/A null)"
print("A/A null (worst arm spread) %.3fx  ->  %s" % (null, verdict))
print("NOTE: matched fixtures, one window. The per-filesystem RATIOS are the")
print("      comparable quantity; the absolute ns/entry are not a scorecard row.")

# IS THE GAP THE ROUND TRIP, OR THE DAEMON? The suppressed arm removes almost
# exactly one boundary crossing per entry (1.0052 -> 0.0052, counted in 9ffd33dec)
# and changes nothing else about the daemon, so the control-minus-suppressed
# difference PRICES that crossing instead of inferring it from a per-crossing
# constant. What is left above the kernel after removing it is daemon work.
#
# This decides a question that has been answered by assertion in both directions:
# "structural / round-trip-bound" versus "daemon-work-bound".
for fs in ("btrfs", "ext4"):
    ctl, sup, ker = "fuse-" + fs, "supp-" + fs, "kern-" + fs
    if any(len(per.get(a, [])) < 2 for a in (ctl, sup, ker)):
        continue
    c, s, k = med[ctl], med[sup], med[ker]
    gap = c - k
    if gap <= 0:
        continue
    trip = c - s
    daemon = s - k
    print("")
    print("%s decomposition of the %.0f ns/entry gap over the kernel:" % (fs, gap))
    print("    round trip (control - suppressed) %8.0f ns/entry  %5.1f%%"
          % (trip, 100.0 * trip / gap))
    print("    daemon     (suppressed - kernel)  %8.0f ns/entry  %5.1f%%"
          % (daemon, 100.0 * daemon / gap))
    print("    suppressed arm is a MEASUREMENT PROBE, not a shipping configuration.")
'
