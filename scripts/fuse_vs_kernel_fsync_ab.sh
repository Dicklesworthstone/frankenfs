#!/usr/bin/env bash
# fsync write+fsync A/B rig: live kernel ext4 vs mounted FrankenFS on the SAME
# tmpfs-backed, journal-stripped, direct-I/O loop device.
#
# This is the instrument behind the bd-6tw2s row. The read-only rows certify
# through scripts/fuse_vs_kernel_abba.sh; the ffs-mounted-kernel-bench gate
# refuses this mutating workload shape, so — like that rig before it landed —
# this script exists so the fsync numbers cite a runnable instrument instead of
# a hand-driven session.
#
# ── Protocol (mirrors the bd-6tw2s hand rig) ────────────────────────────────
# mkfs.ext4 -O ^has_journal on a tmpfs image, attached with
# `losetup --direct-io=on`; the kernel ext4 arm and the FrankenFS daemon BOTH
# address that one loop device, so both arms share transport and durability
# class (unjournaled: with no journal inode, mount attaches no JBD2 writer).
# Each rep is FFS_PAIRS pwrite(4 KiB, offset 0)+fsync pairs on one file after
# FFS_WARM warm pairs, timed with CLOCK_MONOTONIC. Arms alternate every round
# so drift lands on both; the per-round kernel/fs ratio is the result.
#
# ── Why one image, both arms ─────────────────────────────────────────────────
# The original fsync "win" decomposed into a journal-class asymmetry (2.96x)
# and a transport asymmetry (2.20x: buffered image file vs loop direct-I/O)
# before the residual was a null. Every asymmetry must be removed BEFORE
# measuring, not argued away after.
#
# ── Reading the numbers ──────────────────────────────────────────────────────
# Report median ratio and per-round spread. A ratio inside the round-to-round
# noise (bd-w5ok5 measured +/-15% on mutating workloads even with a kernel arm
# on both sides) is a NULL, not a win or a loss in either direction.
#
# ── Lever A/B ────────────────────────────────────────────────────────────────
# FFS_LEVER_NAME=FFS_READ_PARALLELISM FFS_LEVER_VALUE=1 adds a second
# FrankenFS session with that env set on the daemon; each session re-baselines
# against its own kernel rounds, and the ffs/ffs-lever comparison rides on the
# kernel medians agreeing across sessions.
#
# ── Usage ────────────────────────────────────────────────────────────────────
#   FFS_CLI=/path/to/ffs-cli scripts/fuse_vs_kernel_fsync_ab.sh
#   FFS_LEVER_NAME=FFS_READ_PARALLELISM FFS_LEVER_VALUE=1 \
#       FFS_CLI=... scripts/fuse_vs_kernel_fsync_ab.sh
#
# Requires: sudo -n (mount/umount/losetup), mkfs.ext4, a quiet host (the
# host_stability gate used by fuse_vs_kernel_abba.sh runs first).
set -u

CLI=${FFS_CLI:?FATAL: set FFS_CLI to the ffs-cli binary to certify}
ROUNDS=${FFS_ROUNDS:-8}
PAIRS=${FFS_PAIRS:-200}
WARM=${FFS_WARM:-20}
IMG_MB=${FFS_IMG_MB:-64}
LEVER_NAME=${FFS_LEVER_NAME:-}
LEVER_VALUE=${FFS_LEVER_VALUE:-}
DAEMON_CPU=${FFS_DAEMON_CPU:-8}
CLIENT_CPU=${FFS_CLIENT_CPU:-12}
OUT=${FFS_OUT:-/tmp/ffs-fsync-ab}
HERE=$(cd "$(dirname "$0")" && pwd)

[ -x "$CLI" ] || { echo "FATAL: no ffs-cli at $CLI"; exit 2; }
command -v mkfs.ext4 >/dev/null || { echo "FATAL: mkfs.ext4 missing"; exit 2; }
command -v losetup >/dev/null || { echo "FATAL: losetup missing"; exit 2; }
command -v fusermount3 >/dev/null || { echo "FATAL: fusermount3 missing"; exit 2; }

# Same stability gate the read-only ABBA certification uses: refuse to bank a
# row from an unstable window (a burst tail is worse than a busy plateau).
if [ "${FFS_SKIP_STABILITY:-0}" != "1" ]; then
  if ! STABILITY=$(python3 "$HERE/host_stability.py" ${FFS_WAIT_STABLE:+--wait "$FFS_WAIT_STABLE"}); then
    echo "$STABILITY"
    echo "A failure to certify under load is not a loss. Re-run when stable."
    exit 4
  fi
  echo "$STABILITY"
fi

# 4 KiB pwrite+fsync pairs on one file; the timed block excludes the warm
# pairs. Pinned to CLIENT_CPU (a non-SMT-sibling of the daemon's core — the
# pairing host_stability.cores_comparable enforces for the read-only rows).
CLIENT=$OUT/fsync_client
mkdir -p "$OUT"
cat > "$OUT/fsync_client.c" <<'EOF'
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: %s <file> <pairs> <warm>\n", argv[0]); return 2; }
    const char *path = argv[1];
    int pairs = atoi(argv[2]);
    int warm = atoi(argv[3]);
    char buf[4096];
    memset(buf, 0xAB, sizeof buf);
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) { perror("open"); return 3; }
    for (int i = 0; i < warm; i++) {
        if (pwrite(fd, buf, sizeof buf, 0) != (ssize_t)sizeof buf) { perror("warm pwrite"); return 4; }
        if (fsync(fd) != 0) { perror("warm fsync"); return 4; }
    }
    long long start = now_ns();
    for (int i = 0; i < pairs; i++) {
        if (pwrite(fd, buf, sizeof buf, 0) != (ssize_t)sizeof buf) { perror("pwrite"); return 4; }
        if (fsync(fd) != 0) { perror("fsync"); return 4; }
    }
    long long elapsed = now_ns() - start;
    close(fd);
    printf("%lld\n", elapsed / pairs);
    return 0;
}
EOF
gcc -O2 -o "$CLIENT" "$OUT/fsync_client.c" || { echo "FATAL: client build failed"; exit 2; }

IMG=/dev/shm/ffs-fsync-ab.img
rm -f "$IMG" "$IMG.kern"
truncate -s "${IMG_MB}M" "$IMG"
cp "$IMG" "$IMG.kern"
# root_owner hands the ext4 root directory to the invoking user, so the
# unprivileged client can create its target file on BOTH arms without any
# root chmod through the FUSE mount (a root setattr on a non-allow_other
# FUSE mount tears the session down — bd-k1738 rig debugging).
mkfs.ext4 -q -F -b 4096 -O ^has_journal -E root_owner="$(id -u):$(id -g)" "$IMG" || { echo "FATAL: mkfs failed"; exit 2; }
mkfs.ext4 -q -F -b 4096 -O ^has_journal -E root_owner="$(id -u):$(id -g)" "$IMG.kern" || { echo "FATAL: mkfs failed"; exit 2; }

# TWO loop devices over two identical images — one per arm. A single shared
# device was tried and is WRONG: the kernel ext4 mount and the FrankenFS
# daemon each hold an independent filesystem instance whose writes are
# invisible to the other's cache, so every open after the first fsync fails
# with EIO. Same tmpfs mkfs, same direct-I/O loop transport, same window —
# without the coherence hazard.
KLOOP=$(sudo -n losetup --direct-io=on -f --show "$IMG.kern") || { echo "FATAL: losetup failed"; exit 2; }
FLOOP=$(sudo -n losetup --direct-io=on -f --show "$IMG") || { echo "FATAL: losetup failed"; exit 2; }
# The loop nodes are root:disk 660; the FrankenFS daemon runs unprivileged.
sudo -n chmod a+rw "$KLOOP" "$FLOOP" || { echo "FATAL: chmod loop failed"; sudo -n losetup -d "$KLOOP" "$FLOOP"; exit 2; }
echo "kloop=$KLOOP floop=$FLOOP"

KMNT=$OUT/kern
FMNT=$OUT/ffs
mkdir -p "$KMNT" "$FMNT"
cleanup() {
    fusermount3 -u "$FMNT" 2>/dev/null
    sudo -n umount "$KMNT" 2>/dev/null
    sleep 1
    sudo -n losetup -d "$KLOOP" "$FLOOP" 2>/dev/null
}
sudo -n mount -t ext4 -o rw,relatime "$KLOOP" "$KMNT" || { echo "FATAL: kernel mount failed"; sudo -n losetup -d "$KLOOP" "$FLOOP"; exit 3; }

LF=$OUT/samples.tsv
: > "$LF"
printf 'session\tround\tarm\tus_per_op\n' >> "$LF"

# One session = one FrankenFS daemon configuration, interleaved against the
# kernel arm (which stays mounted for the whole run and re-baselines every
# session). $1 session tag, $2 daemon env as NAME=VALUE (empty for none).
#
# The FIRST round of a fresh daemon is cold (page faults, lazy pools, ext4
# first-touch) and is measured but NOT quoted blindly: sessions run in
# FFS_CYCLES control/lever cycles so the lever is compared against a control
# that saw the same position in the run. A lever run only after a control
# inherits the warm-up — the exact confound the first lever A/B had.
run_session() {
    local session="$1" daemon_env="$2"
    local log="$OUT/mount-$session.log"
    : > "$log"
    # shellcheck disable=SC2086
    env ${daemon_env:+"$daemon_env"} FFS_FUSE_CAPABILITY_MEMO_SLOTS=65536 \
        FFS_MOUNT_BENCH_EVIDENCE=1 FFS_AUTO_UNMOUNT=0 \
        taskset -c "$DAEMON_CPU" "$CLI" mount --runtime-mode managed \
        --no-background-scrub "$FLOOP" "$FMNT" --rw >> "$log" 2>&1 &
    local mp=$!
    sleep 7
    if ! mountpoint -q "$FMNT"; then
        echo "FATAL: FrankenFS mount did not come up; see $log"
        kill "$mp" 2>/dev/null
        cleanup
        exit 3
    fi

    local round us
    for round in $(seq 0 "$ROUNDS"); do
        if ! us=$(taskset -c "$CLIENT_CPU" "$CLIENT" "$KMNT/fsync-target" "$PAIRS" "$WARM"); then
            echo "FATAL: kernel-arm client failed (round $round)"
            fusermount3 -u "$FMNT" 2>/dev/null
            cleanup
            exit 5
        fi
        [ "$round" = 0 ] || printf '%s\t%s\tkern\t%s\n' "$session" "$round" "$us" >> "$LF"
        if ! us=$(taskset -c "$CLIENT_CPU" "$CLIENT" "$FMNT/fsync-target" "$PAIRS" "$WARM"); then
            echo "FATAL: ffs-arm client failed (round $round)"
            fusermount3 -u "$FMNT" 2>/dev/null
            cleanup
            exit 5
        fi
        [ "$round" = 0 ] || printf '%s\t%s\tffs\t%s\n' "$session" "$round" "$us" >> "$LF"
    done

    fusermount3 -u "$FMNT" 2>/dev/null
    wait "$mp" 2>/dev/null
}

CYCLES=${FFS_CYCLES:-2}
for cycle in $(seq 1 "$CYCLES"); do
    run_session "control-$cycle" ""
    if [ -n "$LEVER_NAME" ] && [ -n "$LEVER_VALUE" ]; then
        run_session "lever-$cycle" "$LEVER_NAME=$LEVER_VALUE"
    fi
done

cleanup

# Report: per-session median ffs/kernel ratio and spread; with a lever, also
# the lever/control comparison normalized by each session's own kernel median.
python3 - "$LF" <<'EOF'
import statistics as st
import sys

sessions = {}
def med(xs):
    return st.median(xs)
with open(sys.argv[1]) as fh:
    next(fh)
    for line in fh:
        session, round_, arm, us = line.rstrip("\n").split("\t")
        sessions.setdefault(session, {}).setdefault(arm, {})[int(round_)] = int(us)

medians = {}
for session in sorted(sessions):
    arms = sessions[session]
    kern = arms["kern"]
    ffs = arms["ffs"]
    ratios = [ffs[r] / kern[r] for r in sorted(ffs) if r in kern]
    medians[session] = med(list(kern.values()))
    print(
        f"[{session}] ffs/kernel median {st.median(ratios):.4f} "
        f"spread {min(ratios):.4f}-{max(ratios):.4f} rounds={len(ratios)} | "
        f"kern {st.median(list(kern.values())):.2f} us/op "
        f"ffs {st.median(list(ffs.values())):.2f} us/op"
    )

controls = sorted(k for k in medians if k.startswith("control"))
levers = sorted(k for k in medians if k.startswith("lever"))
for control, lever in zip(controls, levers):
    kern_drift = medians[lever] / medians[control]
    ctl = sessions[control]["ffs"]
    lev = sessions[lever]["ffs"]
    paired = [ctl[r] / lev[r] for r in sorted(ctl) if r in lev]
    print(
        f"cycle {control}->{lever}: kernel-arm drift {kern_drift:.4f} | "
        f"ffs control/lever median {st.median(paired):.4f} "
        f"spread {min(paired):.4f}-{max(paired):.4f} (>1 means the lever is faster)"
    )
EOF
report_rc=$?
echo "samples: $LF"
exit "$report_rc"
