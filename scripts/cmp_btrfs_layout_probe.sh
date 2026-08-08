#!/usr/bin/env bash
# bd-ws9dg / bd-c5210: does moving the btrfs parallel-read fixture from the mkfs
# `-r` seed to through-the-mount creation change the on-disk EXTENT LAYOUT?
#
# This is cause 3 of three in bd-ws9dg, and it is the only one that can be settled
# without a quiet window — it is a structural question, not a timing one.
#
# The ext4 twin of this question is already answered: scripts/cmp_extent_layout_probe.sh
# showed one contiguous 64-block extent per file under BOTH constructions, so on
# ext4 the fixture change touches only the directory index. That result does NOT
# transfer: `debugfs` is ext4-only, btrfs is copy-on-write with its own allocator,
# and the `-r` seeder and the kernel's write path are different code entirely.
#
# Method: build both images, mount each read-only, and compare `filefrag -v` —
# extent COUNT per file (fragmentation) and whether consecutive files are laid out
# consecutively. A read benchmark is sensitive to both.
#
# Needs sudo (loop mount) and btrfs-progs. Writes to a fresh mktemp -d and deletes
# nothing; remove the printed directory by hand when done.
set -u -o pipefail

BASE=$(mktemp -d "${TMPDIR:-/data/tmp}/ffs-btrfs-layout-XXXXXX")
echo "scratch: $BASE"
cd "$BASE"

FILES=8
BYTES=262144   # PARALLEL_READ_FILE_BYTES

mkdir -p fix/parallel-read mnt_baked mnt_seeded
i=0
while [ "$i" -lt "$FILES" ]; do
  head -c "$BYTES" /dev/urandom > "fix/parallel-read/read-$(printf '%06d' "$i").bin"
  i=$((i + 1))
done

fallocate -l 1024M baked.img
fallocate -l 1024M seeded.img

# BAKED: verbatim the shape create_base_image used before bd-c5210 — seed the tree
# straight into the image at format time.
mkfs.btrfs -f -q -r fix baked.img || { echo "baked mkfs failed"; exit 1; }

# SEEDED: empty filesystem, then create the identical files through a kernel mount,
# which is what seed_fixture_through_mount now does.
mkfs.btrfs -f -q seeded.img || { echo "seeded mkfs failed"; exit 1; }
sudo mount -o loop seeded.img mnt_seeded || exit 1
sudo mkdir -p mnt_seeded/parallel-read
sudo cp fix/parallel-read/*.bin mnt_seeded/parallel-read/
sync
sudo umount mnt_seeded

report() {                 # report <label> <image> <mountpoint>
  local label="$1" image="$2" mnt="$3"
  sudo mount -o loop,ro "$image" "$mnt" 2>/dev/null || { echo "$label: mount failed"; return; }
  echo "=== $label ==="
  local total=0
  for f in "$mnt"/parallel-read/read-*.bin; do
    local n
    n=$(sudo filefrag "$f" 2>/dev/null | grep -oE '[0-9]+ extents?' | grep -oE '^[0-9]+')
    total=$((total + ${n:-0}))
    printf '  %-20s %s extent(s)\n' "$(basename "$f")" "${n:-?}"
  done
  echo "  TOTAL extents across $FILES files: $total"
  echo "  physical start blocks (first extent of each file, in name order):"
  for f in "$mnt"/parallel-read/read-*.bin; do
    printf '    %-20s %s\n' "$(basename "$f")" \
      "$(sudo filefrag -v "$f" 2>/dev/null | awk '/^ *0:/{print $4; exit}')"
  done
  sudo umount "$mnt"
}

report "BAKED  (mkfs -r seed)"   baked.img  mnt_baked
report "SEEDED (through mount)"  seeded.img mnt_seeded
