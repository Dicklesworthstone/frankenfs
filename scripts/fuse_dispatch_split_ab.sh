#!/usr/bin/env bash
# bd-zpc3q: WHERE does the daemon spend readdir+stat time, and how much of it is
# filesystem-SPECIFIC?
#
# WHY THIS EXISTS. The bead's premise is that mounted btrfs large-directory
# readdir+stat (7.73x) carries a btrfs-SPECIFIC mount-path excess, while the
# in-process btrfs path is faster than ext4. The per-filesystem dispatch-time
# diagnostic landed in 251bf45a and covers getattr / getxattr / lookup / readdir
# end to end, but nobody had actually run the two format layers side by side and
# read the split. This does that.
#
# WHAT IT IS AND IS NOT. This is ATTRIBUTION, exactly as bd-zpc3q says: it
# compares two of OUR OWN mounts and carries no kernel arm, so nothing it prints
# is a performance claim and it must never be banked as a ratio. What it can
# decide is whether the daemon costs materially more per operation on btrfs than
# on ext4 for the same workload -- which is what "btrfs-specific excess" would
# have to mean at this layer.
#
# ABBA, NOT A->B. The arms alternate btrfs,ext4,ext4,btrfs so each visits an early
# and a late position and a monotone drift in host load loads both symmetrically.
# The two same-filesystem visits also give a free within-run null: if btrfs's two
# visits disagree by more than the btrfs-vs-ext4 gap, the gap is not readable.
#
#   scripts/fuse_dispatch_split_ab.sh <btrfs-image> <ext4-image> [rounds]
#
# The two images MUST hold the same number of entries. Directory size changes
# tree height, and comparing a 20k btrfs against a 40k ext4 would attribute a
# fixture difference to a format layer.
#
# ⚠️ /data is mounted nosuid, so the setuid fusermount3 is refused there. The
# mountpoint lives under $HOME.
set -u

BTRFS_IMG=${1:?usage: fuse_dispatch_split_ab.sh <btrfs-image> <ext4-image> [rounds]}
EXT4_IMG=${2:?usage: fuse_dispatch_split_ab.sh <btrfs-image> <ext4-image> [rounds]}
ROUNDS=${3:-1}
CLI=${FFS_CLI:-/data/projects/frankenfs/target/debug/ffs-cli}
WORK=${FFS_WORK:-$HOME/ffs-dispatch-split}
CLIENT_SRC=$(cd "$(dirname "$0")" && pwd)/abba_clients/readdir_stat_client.c

[ -x "$CLI" ] || { echo "FATAL: no ffs-cli at $CLI"; exit 2; }
for img in "$BTRFS_IMG" "$EXT4_IMG"; do
  [ -f "$img" ] || { echo "FATAL: no image at $img"; exit 2; }
done

mkdir -p "$WORK/mnt"
CLIENT="$WORK/readdir_stat_client"
# THE CLIENT IS PART OF THE MEASUREMENT (bd-xfe7z): a per-file stat walk issues a
# LOOKUP and a GETATTR per entry and never uses readdirplus, which is a different
# request mix and so a different question. The certified row's client enumerates
# once and lets the kernel batch attributes into the readdir reply.
gcc -O2 -o "$CLIENT" "$CLIENT_SRC" || { echo "FATAL: cannot build the readdir+stat client"; exit 3; }

# One visit: mount, warm, measure, unmount, print the raw evidence line.
# FFS_MOUNT_BENCH_EVIDENCE=1 is REQUIRED -- `mount_dispatch_metrics` is emitted
# only under it, and without it this silently measures nothing.
visit() {
  local img=$1
  local tag=$2
  # Separate statements deliberately: `local a=$1 b=$a` does not see `a` yet, and
  # under `set -u` that surfaces as an unbound-variable abort rather than an empty
  # path, which is the good failure but only if the declaration is split.
  local log="$WORK/$tag.log"
  : >> "$log"
  env FFS_MOUNT_BENCH_EVIDENCE=1 "$CLI" mount "$img" "$WORK/mnt" >> "$log" 2>&1 &
  local daemon=$!
  local i
  for i in $(seq 1 600); do mountpoint -q "$WORK/mnt" && break; sleep 0.2; done
  if ! mountpoint -q "$WORK/mnt"; then
    echo "FATAL: $tag did not mount within 120s"; tail -3 "$log"; kill "$daemon" 2>/dev/null; exit 4
  fi
  # Warm pass discarded: the count must describe the steady state, not the cold
  # walk that populated the caches.
  "$CLIENT" "$WORK/mnt" > /dev/null 2>&1
  "$CLIENT" "$WORK/mnt" > /dev/null 2>&1
  fusermount3 -u "$WORK/mnt" 2>/dev/null
  wait "$daemon" 2>/dev/null
  grep -o "mount_dispatch_metrics.*" "$log" | tail -1
}

for r in $(seq 1 "$ROUNDS"); do
  # ABBA within the round.
  visit "$BTRFS_IMG" "btrfs-a-$r"
  visit "$EXT4_IMG"  "ext4-a-$r"
  visit "$EXT4_IMG"  "ext4-b-$r"
  visit "$BTRFS_IMG" "btrfs-b-$r"
done | python3 -c '
import sys, collections, statistics

# Per-op nanoseconds is the comparable quantity: the two images hold the same
# number of entries, but the op COUNTS still differ by a handful (root, lost+found)
# and totals would carry that difference into the ratio.
BUCKETS = ("getattr", "getxattr", "lookup", "readdir")
rows = collections.defaultdict(list)
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("mount_dispatch_metrics"):
        continue
    kv = dict(p.split("=", 1) for p in line.split(",")[1:] if "=" in p)
    fs = kv.get("filesystem", "?")
    per = {}
    entries = 0
    total_ns = 0
    for op in BUCKETS:
        c = int(kv.get(op + "_dispatch_count", 0))
        n = int(kv.get(op + "_dispatch_nanos", 0))
        per[op] = (n / c) if c else 0.0
        total_ns += n
        # getattr fires once per ENTRY on a readdirplus workload (the scope the
        # handler opens per entry), so it is the entry count this run walked.
        if op == "getattr":
            entries = c
    # THE AGGREGATE IS BUILT FROM THE BUCKETS, deliberately, and NOT from
    # handler_total. `handler_total_*` times WHOLE HANDLER invocations while the
    # buckets count request SCOPES that NEST inside them, so the two are different
    # granularities and handler_total/handler_total_count is nanoseconds per
    # HANDLER CALL, not per operation. On a readdirplus workload the two counts
    # come out nearly equal (40207 vs 40201 on one 20k mount), which is what makes
    # the mistake easy and invisible. Pinned by
    # `handler_total_accounts_for_every_dispatch_bucket_bd_zpc3q`.
    per["daemon_per_entry"] = (total_ns / entries) if entries else 0.0
    rows[fs].append(per)

OPS = BUCKETS + ("daemon_per_entry",)

if len(rows) < 2:
    print("only one filesystem produced evidence; nothing to compare")
    raise SystemExit(1)

print("%-14s%14s%14s%12s   visits" % ("op", "btrfs ns/op", "ext4 ns/op", "btrfs/ext4"))
for op in OPS:
    b = [r[op] for r in rows.get("btrfs", []) if r[op]]
    e = [r[op] for r in rows.get("ext4", []) if r[op]]
    if not b or not e:
        continue
    mb, me = statistics.median(b), statistics.median(e)
    print(f"{op:<14}{mb:>14.0f}{me:>14.0f}{mb/me:>12.3f}   {len(b)}/{len(e)}")

# The free within-run null: same filesystem, different position. An effect
# smaller than this is not readable, and saying so is the point of printing it.
for fs, vals in rows.items():
    tot = [r["daemon_per_entry"] for r in vals if r["daemon_per_entry"]]
    if len(tot) >= 2:
        print(f"A/A null {fs:<6} daemon_per_entry spread {max(tot)/min(tot):.3f}x over {len(tot)} visits")
print("NOTE: attribution only -- two of OUR mounts, no kernel arm, not a ratio to bank.")
'
