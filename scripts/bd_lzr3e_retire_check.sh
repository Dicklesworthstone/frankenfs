#!/usr/bin/env bash
# bd-lzr3e: bd-mogn1's log_root retirement faces the independent readers.
#
# Per entry-count (2000/5000/20000, --commits 20, SERIALIZED builds):
#   1. sound kernel-created base -> make_btrfs_fixture.py population
#   2. mount --rw --btrfs-rw-ephemeral-ok
#   3. write A + fsync            -> tree log published (log_root != 0)
#   4. overflow batch (fsync per inode) -> full commit -> log_root RETIRED
#   5. write B + fsync            -> fresh log tail
#   6. clean unmount              -> full commit again, log retired
#   7. INDEPENDENT READERS on the stored bytes:
#      - btrfs inspect-internal dump-super: log_root == 0 (cleared at 0x60)
#      - btrfs check --readonly: rc=0
#      - kernel loop-mount readback: A == A's content AND B == B's content
set -uo pipefail

CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
HERE="$(cd "$(dirname "$0")" && pwd)"
GEN="$HERE/make_btrfs_fixture.py"
export FFS_AUTO_UNMOUNT=0
WORK="${WORK:-$HOME/bd-lzr3e-work}"
mkdir -p "$WORK"

A_CONTENT="bd-lzr3e-A-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
B_CONTENT="bd-lzr3e-B-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

make_base() {
    local base="$1" size_mib="$2"
    rm -f "$base"
    fallocate -l "${size_mib}M" "$base"
    mkfs.btrfs -q "$base"
    local kmnt="$WORK/kmnt-$(basename "$base")"
    mkdir -p "$kmnt"
    sudo -n mount -o loop "$base" "$kmnt"
    sudo -n chown "$(id -u):$(id -g)" "$kmnt"
    sudo -n umount "$kmnt"
    rm -rf "$kmnt"
}

run_one() {
    local count="$1" size_mib="$2"
    local base="$WORK/base-$count.img"
    local fixture="$WORK/fixture-$count-c20.img"
    local img="$WORK/retire-$count.img"
    local mnt="$WORK/mnt-$count"
    local dlog="$WORK/daemon-$count.log"
    echo "=========$count entries: fixture (serialized) ========="
    rm -f "$base" "$fixture" "$img"; rm -rf "$mnt"
    make_base "$base" "$size_mib" || return 1
    python3 "$GEN" --source "$base" --count "$count" --commits 20 \
        --out "$fixture" --cli "$CLI" --work-dir "$WORK/gen-$count" || return 1
    btrfs check --readonly "$fixture" || { echo "FATAL: fixture not sound"; return 1; }

    echo "=========$count entries: ephemeral fsync -> full commit ========="
    cp "$fixture" "$img"
    mkdir -p "$mnt"
    RUST_LOG=info "$CLI" mount --rw --btrfs-rw-ephemeral-ok "$img" "$mnt" >>"$dlog" 2>&1 &
    local daemon=$!
    local deadline=$((SECONDS+120))
    until mountpoint -q "$mnt"; do
        kill -0 "$daemon" 2>/dev/null || { echo "FATAL: daemon died before mount"; tail -20 "$dlog"; return 1; }
        [ $SECONDS -lt $deadline ] || { echo "FATAL: mount deadline"; return 1; }
        sleep 0.5
    done

    printf '%s' "$A_CONTENT" > "$mnt/A-file.bin"
    sync -f "$mnt/A-file.bin" 2>/dev/null || python3 -c "
import os, sys
fd = os.open(os.path.join(sys.argv[1], 'A-file.bin'), os.O_RDONLY)
os.fsync(fd); os.close(fd)" "$mnt"
    # Overflow batch: each fsync past the leaf boundary forces the fallback
    # FULL TRANSACTION COMMIT, which is what retires log_root (bd-mogn1).
    python3 - "$mnt" <<'PY'
import os, sys
mnt = sys.argv[1]
for i in range(40):
    p = os.path.join(mnt, f"ovf-{i:03d}.bin")
    fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, b"x" * 4096)
    os.fsync(fd)
    os.close(fd)
PY
    printf '%s' "$B_CONTENT" > "$mnt/B-file.bin"
    python3 -c "
import os, sys
fd = os.open(os.path.join(sys.argv[1], 'B-file.bin'), os.O_RDONLY)
os.fsync(fd); os.close(fd)" "$mnt"

    fusermount3 -u "$mnt" || { echo "FATAL: unmount failed"; kill -9 "$daemon"; return 1; }
    wait "$daemon" 2>/dev/null

    echo "--------=$count: daemon evidence ========="
    echo "  tree_log_fast_fsync        : $(grep -c 'tree_log_fast_fsync' "$dlog" 2>/dev/null || true)"
    echo "  full_commit_log_overflow   : $(grep -c 'full_commit_log_overflow_fallback' "$dlog" 2>/dev/null || true)"

    echo "=========$count: READER 1: dump-super log_root ========="
    local super
    super=$(btrfs inspect-internal dump-super "$img")
    echo "$super" | grep -E "^log_root" | sed 's/^/  /'
    if echo "$super" | grep -qE '^log_root\s+0($|\s)'; then
        echo "  RETIRED: log_root is 0 in the stored superblock"
    else
        echo "  FATAL: log_root is non-zero after the retiring commit"
        return 1
    fi

    echo "=========$count: READER 2: btrfs check AS STORED ========="
    btrfs check --readonly "$img" || { echo "FATAL: btrfs check rejected the stored image"; return 1; }

    echo "=========$count: READER 3: kernel readback of A and B ========="
    local kmnt="$WORK/rd-$count"
    mkdir -p "$kmnt"
    sudo -n mount -o loop,ro "$img" "$kmnt" || { echo "FATAL: the kernel refused the stored image"; return 1; }
    local ra rb
    ra=$(cat "$kmnt/A-file.bin")
    rb=$(cat "$kmnt/B-file.bin")
    sudo -n umount "$kmnt"; rm -rf "$kmnt"
    [ "$ra" = "$A_CONTENT" ] || { echo "FATAL: A does not survive (got: $ra)"; return 1; }
    [ "$rb" = "$B_CONTENT" ] || { echo "FATAL: B does not survive (got: $rb)"; return 1; }
    echo "  A and B both survive with their own contents: OK"
    return 0
}

overall=0
for spec in "2000 256" "5000 256" "20000 1024"; do
    set -- $spec
    run_one "$1" "$2" || overall=1
done
echo "===== OVERALL: overall_rc=$overall ====="
exit "$overall"
