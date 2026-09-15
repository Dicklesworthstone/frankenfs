#!/usr/bin/env bash
# bd-f3fsg / bd-dm01m step 4: sound fixture matrix at the recorded entry counts,
# populated through our read-write mount with --commits 20 (the bd-yknl4
# multi-commit block-reuse surface), each validated by `btrfs check` AS STORED.
set -uo pipefail

CLI="${CLI:-/data/tmp/cargo-target/debug/ffs-cli}"
HERE="$(cd "$(dirname "$0")" && pwd)"
GEN="$HERE/make_btrfs_fixture.py"
# bd-087wt-era default: auto_unmount pulls in allow_other, which this host's
# fusermount3 refuses (no user_allow_other in /etc/fuse.conf). The harness
# unmounts its own arms, so the flag is off and the mount succeeds.
export FFS_AUTO_UNMOUNT=0
WORK="${WORK:-$HOME/bd-f3fsg-work}"
# make_btrfs_fixture populates through our rw mount as the invoking user; a
# uid-0 fs root EPERMs those creates. Each base gets one kernel round-trip to
# rewrite ownership before population (clean unmount keeps it sound).

make_one() {
    local count="$1" size_mib="$2" commits="$3"
    local base="$WORK/base-$count.img"
    local out="$WORK/fixture-$count-c$commits.img"
    echo "----- fixture count=$count commits=$commits base=${size_mib}MiB -----"
    rm -f "$base" "$out"
    fallocate -l "${size_mib}M" "$base"
    mkfs.btrfs -q "$base" || { echo "FATAL: base create failed for $count"; return 1; }
    local kmnt="$WORK/kmnt-$count"
    mkdir -p "$kmnt"
    sudo -n mount -o loop "$base" "$kmnt" || { echo "FATAL: kernel mount failed"; return 1; }
    sudo -n chown "$(id -u):$(id -g)" "$kmnt"
    sudo -n umount "$kmnt" || { echo "FATAL: kernel unmount failed"; return 1; }

    python3 "$GEN" \
        --source "$base" \
        --count "$count" \
        --commits "$commits" \
        --out "$out" \
        --cli "$CLI" \
        --work-dir "$WORK/gen-$count" || { echo "FATAL: population failed for $count"; return 1; }

    echo "----- btrfs check AS STORED (count=$count commits=$commits) -----"
    btrfs check --readonly "$out"
    local rc=$?
    echo "RESULT count=$count commits=$commits check_rc=$rc"
    return "$rc"
}

overall=0
for spec in "2000 256" "5000 256" "20000 1024"; do
    set -- $spec
    make_one "$1" "$2" 20 || overall=1
done
echo "===== OVERALL: overall_rc=$overall ====="
exit "$overall"
