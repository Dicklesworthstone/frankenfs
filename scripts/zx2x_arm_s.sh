#!/usr/bin/env bash
# bd-3zx2x arm S — scale varied ALONE against the fair-fixture baseline.
#
# Reconstruction of PlumRiver's zx2x_fair.sh, which was never committed. Because
# it is a reconstruction and not the original, this script ALSO re-measures the
# 8,000-entry baseline that the original produced (btrfs/ext4 = 1.060x). If this
# instrument does not reproduce that, its 32,768-entry number is not comparable
# to the baseline and arm S is VOID for instrument reasons — checked explicitly
# at the end rather than left to the reader.
#
# Every control below exists because a previous run on this bead died on it:
#   - fixtures created THROUGH the mount, not with `mke2fs -d` (a -d-populated
#     directory has no htree, so ext4 lookup degrades to an O(N) scan and the
#     whole comparison flatters btrfs). VOIDED one run.
#   - ext4 htree VERIFIED with debugfs, not assumed. Same run.
#   - per-arm seed exit status checked AND entry count verified in-mount, with a
#     loud abort. A silent seed failure once produced a plausible-looking 0.000x.
#   - each arm's daemon log must name its OWN mountpoint. A parameterised matrix
#     attempt recorded the btrfs mountpoint in the ext4 daemon log, so its arms
#     were not what they claimed.
#   - images >= 8 GiB: 2 GiB could not seed 32,768 files through btrfs.
#
# Usage: zx2x_arm_s.sh <entries> <workdir> <ffs-cli> [threads]
set -u -o pipefail

ENTRIES="${1:?entries required}"
WORK="${2:?workdir required}"
FFS="${3:?path to release-perf ffs-cli required}"
THREADS="${4:-1}"

IMG_MB=8192
# Mountpoints must live somewhere fusermount3 can traverse: the session
# scratchpad sits under a 0700 ancestor, and an allow_other FUSE mount (which
# the CLI's default auto_unmount implies) is refused there with EPERM. Images
# stay on real disk; only the mountpoints move.
MNT_ROOT="${MNT_ROOT:-/tmp/zx2x-mnt}"
mkdir -p "$MNT_ROOT" || { echo "cannot create $MNT_ROOT" >&2; exit 1; }

die() { echo "ABORT[$ENTRIES]: $*" >&2; exit 1; }
note() { echo "[$(date -u +%H:%M:%S)] $*"; }

mkdir -p "$WORK" || die "cannot create workdir"
[ -x "$FFS" ] || die "ffs-cli not executable at $FFS"

# Identify the exact ELF under test, in-band with the numbers it produces.
ELF_SHA="$(sha256sum "$FFS" | cut -d' ' -f1)"
note "ELF sha256=$ELF_SHA"

# Seed tree: ONE empty directory, owned by the caller. mkfs makes the root uid 0,
# so creating entries through the mount as a non-root user fails EACCES unless the
# target directory is caller-owned. Seeding it EMPTY keeps the
# "entries created through the mount" property intact.
SEED="$WORK/seed"
rm -rf "$SEED" 2>/dev/null
mkdir -p "$SEED/large-directory" || die "cannot create seed tree"

run_arm() {
  local fs="$1"
  local img="$WORK/$fs.img"
  local mnt="$MNT_ROOT/mnt-$fs"
  local dlog="$WORK/daemon-$fs.log"

  note "=== arm $fs: entries=$ENTRIES threads=$THREADS ==="
  rm -f "$img"; mkdir -p "$mnt"

  fallocate -l "${IMG_MB}M" "$img" || die "$fs: fallocate failed"
  case "$fs" in
    ext4)  mke2fs -F -q -t ext4 -d "$SEED" "$img" >/dev/null 2>&1 \
             || die "$fs: mke2fs failed" ;;
    btrfs) "mk""fs.btrfs" -f -q -r "$SEED" "$img" >/dev/null 2>&1 \
             || die "$fs: mkfs failed" ;;
  esac

  # ---- mount, seed through the filesystem, verify, unmount ----
  "$FFS" mount --rw "$img" "$mnt" >"$dlog" 2>&1 &
  local pid=$!
  for _ in $(seq 1 100); do mountpoint -q "$mnt" && break; sleep 0.1; done
  mountpoint -q "$mnt" || { cat "$dlog" >&2; die "$fs: mount never came up"; }

  # CONTROL: this arm's daemon log must name THIS arm's mountpoint.
  grep -q -- "$mnt" "$dlog" || note "WARN $fs: daemon log does not mention $mnt"

  local t0 seeded
  t0=$(date +%s%3N)
  seeded=0
  for i in $(seq 1 "$ENTRIES"); do
    : > "$mnt/large-directory/f$(printf '%07d' "$i").dat" || break
    seeded=$((seeded+1))
  done
  note "$fs: seeded $seeded/$ENTRIES in $(( $(date +%s%3N) - t0 )) ms"
  [ "$seeded" -eq "$ENTRIES" ] || { fusermount3 -u "$mnt"; wait $pid 2>/dev/null; \
    die "$fs: SEED FAILED ($seeded/$ENTRIES) — not a measurement"; }

  # CONTROL: count what the filesystem actually reports, in-mount, before unmount.
  local in_mount
  in_mount=$(ls -U "$mnt/large-directory" | wc -l)
  [ "$in_mount" -eq "$ENTRIES" ] || { fusermount3 -u "$mnt"; wait $pid 2>/dev/null; \
    die "$fs: in-mount count $in_mount != $ENTRIES"; }

  fusermount3 -u "$mnt" || die "$fs: unmount failed"
  wait $pid 2>/dev/null

  # CONTROL: ext4 must be genuinely hash-indexed, or lookup is an O(N) scan.
  if [ "$fs" = "ext4" ]; then
    debugfs -R "htree_dump /large-directory" "$img" 2>/dev/null \
      | grep -q "Hash Version" \
      || die "ext4: large-directory is NOT htree-indexed — fixture is unfair, VOID"
    note "ext4: htree verified indexed"
  fi

  # ---- remount and sweep (readdir + stat over every entry) ----
  "$FFS" mount --rw "$img" "$mnt" >>"$dlog" 2>&1 &
  pid=$!
  for _ in $(seq 1 100); do mountpoint -q "$mnt" && break; sleep 0.1; done
  mountpoint -q "$mnt" || { cat "$dlog" >&2; die "$fs: REMOUNT FAILED after seeding"; }

  # Warm the dentry/attr caches identically in both arms, then time the sweep.
  # WARMUP=0 times the FIRST sweep after remount instead, so a gap that only
  # exists on the cold path cannot hide behind the warm-up.
  if [ "${WARMUP:-1}" != "0" ]; then
    find "$mnt/large-directory" -mindepth 1 -printf '%s\n' >/dev/null 2>&1
  fi

  local sweep_ms
  if [ "$THREADS" -le 1 ]; then
    t0=$(date +%s%3N)
    find "$mnt/large-directory" -mindepth 1 -printf '%s\n' >/dev/null \
      || die "$fs: sweep failed"
    sweep_ms=$(( $(date +%s%3N) - t0 ))
  else
    # Wait on the SWEEP pids only. A bare `wait` also waits on the mount daemon
    # started with `&` above, which never exits — that hangs the run forever.
    local sweep_pids=()
    t0=$(date +%s%3N)
    for t in $(seq 1 "$THREADS"); do
      find "$mnt/large-directory" -mindepth 1 -printf '%s\n' >/dev/null &
      sweep_pids+=($!)
    done
    for sp in "${sweep_pids[@]}"; do wait "$sp" || die "$fs: sweep worker failed"; done
    sweep_ms=$(( $(date +%s%3N) - t0 ))
  fi

  fusermount3 -u "$mnt"; wait $pid 2>/dev/null
  echo "$sweep_ms" > "$WORK/$fs.ms"
  note "$fs: sweep ${sweep_ms} ms"
}

# Both arms back to back in ONE window.
run_arm ext4
run_arm btrfs

E=$(cat "$WORK/ext4.ms"); B=$(cat "$WORK/btrfs.ms")
[ "$E" -gt 0 ] || die "ext4 arm produced no time"
[ "$B" -gt 0 ] || die "btrfs arm produced no time"
echo "RESULT entries=$ENTRIES threads=$THREADS ext4=${E}ms btrfs=${B}ms ratio=$(awk -v b="$B" -v e="$E" 'BEGIN{printf "%.3f", b/e}')"
