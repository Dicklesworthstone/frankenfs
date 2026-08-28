#!/bin/bash
# Do the invalidation knobs that cheapen the unlink phase leave the kernel serving
# STALE entries? A crossing count can never answer that, and these knobs exist for
# cache coherence, so the count is meaningless without this.
#
# The oracle is deliberately behavioural, not a log grep: after unlink, a path must
# be gone by every route a client can ask —
#   1. stat(path)            -> must fail with ENOENT
#   2. open(path, O_RDONLY)  -> must fail with ENOENT
#   3. readdir(parent)       -> must not list it
#   4. re-create then stat   -> must succeed and see the NEW inode
#
# Checked against the SAME mount with the knob on and off, so a failure is
# attributable to the knob rather than to the filesystem.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
FENV=${FENV:-}
MNT=/home/ubuntu/inval-f
DEV=""

cleanup() {
  fusermount3 -u "$MNT" 2>/dev/null || true
  [ -n "$DEV" ] && sudo -n losetup -d "$DEV" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$MNT"

DEV=$(sudo -n losetup --find --show "$W/simgb-f.btrfs")
sudo -n losetup --direct-io=on "$DEV" 2>/dev/null || true
sudo -n chown "$(id -u)" "$DEV"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn $FENV \
  taskset -c 18 "$ELF" mount --rw "$DEV" "$MNT" >> "$W/inval-fuse.log" 2>&1 &
pid=$!
for _ in $(seq 1 300); do mountpoint -q "$MNT" && break; kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
mountpoint -q "$MNT" || { echo "mount never came up"; tail -8 "$W/inval-fuse.log"; exit 1; }

echo "  attested: $(grep -o 'entry_inval=[a-z]*\|fuse_create_inval=[a-z]*\|parent_inval=[a-z]*' "$W/inval-fuse.log" | tail -3 | tr '\n' ' ')"

fail=0
for i in $(seq 1 200); do
  f="$MNT/storm/stale-$i"
  : > "$f"
  rm -f "$f"
  # 1 + 2: gone by stat and by open
  if [ -e "$f" ]; then echo "  STALE: [ -e ] true after unlink ($f)"; fail=$((fail+1)); fi
  if cat "$f" >/dev/null 2>&1; then echo "  STALE: open succeeded after unlink ($f)"; fail=$((fail+1)); fi
  # 3: gone from the directory listing
  if ls -U "$MNT/storm" 2>/dev/null | grep -qx "stale-$i"; then
    echo "  STALE: readdir still lists stale-$i"; fail=$((fail+1))
  fi
  # 4: re-create must be visible again
  : > "$f"
  if [ ! -e "$f" ]; then echo "  MISSING: re-created file not visible ($f)"; fail=$((fail+1)); fi
  rm -f "$f"
done

fusermount3 -u "$MNT"; wait "$pid" 2>/dev/null || true
echo "  staleness failures: $fail / 800 checks"
[ "$fail" -eq 0 ] || exit 1
