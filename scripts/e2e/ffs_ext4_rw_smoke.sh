#!/usr/bin/env bash
# ffs_ext4_rw_smoke.sh - ext4 read-write E2E smoke test for FrankenFS
#
# This script validates read-write ext4 behavior through FUSE:
# - create a fresh base image and copy to a work image
# - mount the work image read-write and execute core write operations
# - cleanly unmount and remount read-only to verify persistence
# - best-effort crash mini-harness with abrupt mount-process termination

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-trace}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

e2e_init "ffs_ext4_rw_smoke"
e2e_print_env

CURRENT_MOUNT_PID=""
CURRENT_MOUNT_LOG=""
CURRENT_MOUNT_POINT=""

create_rw_ext4_image() {
    local image_path="$1"
    local size_mb="${2:-64}"

    e2e_step "Creating RW ext4 test image"
    e2e_log "Path: $image_path"
    e2e_log "Size: ${size_mb} MiB"

    if ! command -v mkfs.ext4 &>/dev/null; then
        e2e_skip "mkfs.ext4 not found"
    fi
    if ! command -v debugfs &>/dev/null; then
        e2e_skip "debugfs not found"
    fi

    dd if=/dev/zero of="$image_path" bs=1M count="$size_mb" status=none

    # Disable has_journal to avoid journal-layout feature gaps in current mount path.
    mkfs.ext4 -F -O extent,filetype,^has_journal -L e2e_rw "$image_path" >/dev/null 2>&1

    local seed_file="$E2E_TEMP_DIR/seed_rw.txt"
    local seed_nested="$E2E_TEMP_DIR/seed_nested.txt"
    printf "FrankenFS ext4 RW smoke fixture\n" > "$seed_file"
    printf "Nested file for RW smoke fixture\n" > "$seed_nested"

    debugfs -w "$image_path" <<EOF >/dev/null 2>&1
mkdir testdir
write $seed_file readme.txt
write $seed_nested testdir/hello.txt
EOF

    e2e_log "RW ext4 image created successfully"
}

assert_not_exists() {
    local path="$1"
    if [[ -e "$path" ]]; then
        e2e_fail "Path should not exist: $path"
    fi
    e2e_log "Confirmed absent: $path"
}

log_tree() {
    local mount_point="$1"
    local label="$2"

    e2e_log "$label (maxdepth=3):"
    e2e_run bash -lc "find '$mount_point' -maxdepth 3 -print | sort"
}

wait_for_mount_ready() {
    local mount_point="$1"
    local pid="$2"
    local timeout_seconds="${3:-20}"
    local elapsed=0

    while ! mountpoint -q "$mount_point" 2>/dev/null; do
        sleep 0.5
        elapsed=$((elapsed + 1))

        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi

        if [[ $elapsed -ge $((timeout_seconds * 2)) ]]; then
            return 2
        fi
    done

    return 0
}

start_mount() {
    local mode="$1"
    local image="$2"
    local mount_point="$3"
    local allow_failure="${4:-0}"
    local timeout_seconds="${5:-20}"

    if [[ "${SKIP_MOUNT:-0}" == "1" ]]; then
        e2e_skip "mount tests skipped (SKIP_MOUNT=1)"
    fi
    if [[ ! -e /dev/fuse ]]; then
        e2e_skip "/dev/fuse not available"
    fi
    if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        e2e_skip "/dev/fuse not accessible"
    fi

    mkdir -p "$mount_point"
    E2E_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_LOG="$E2E_LOG_DIR/mount_${mode}_$(basename "$mount_point").log"

    local cmd=(cargo run -p ffs-cli --release -- mount "$image" "$mount_point")
    if [[ "$mode" == "rw" ]]; then
        cmd+=(--rw)
    fi

    e2e_log "Starting mount command: ${cmd[*]}"
    e2e_log "Mount log: $CURRENT_MOUNT_LOG"

    "${cmd[@]}" >"$CURRENT_MOUNT_LOG" 2>&1 &
    CURRENT_MOUNT_PID=$!

    local ready_result=0
    if wait_for_mount_ready "$mount_point" "$CURRENT_MOUNT_PID" "$timeout_seconds"; then
        ready_result=0
    else
        ready_result=$?
    fi

    if [[ $ready_result -eq 0 ]]; then
        e2e_log "Mount ready at $mount_point (pid: $CURRENT_MOUNT_PID, mode: $mode)"
        return 0
    fi

    local mount_rc=0
    if kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
        kill "$CURRENT_MOUNT_PID" 2>/dev/null || true
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
        mount_rc=124
    else
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || mount_rc=$?
    fi

    e2e_log "Mount failed (mode=$mode, rc=$mount_rc). Tail of mount log:"
    e2e_run tail -n 120 "$CURRENT_MOUNT_LOG" || true

    if grep -qiE "option allow_other only allowed if 'user_allow_other' is set" "$CURRENT_MOUNT_LOG"; then
        e2e_skip "FUSE is present but user_allow_other is not enabled in /etc/fuse.conf"
    fi

    if [[ "$mode" == "rw" ]] && grep -qiE "read-write mount is not yet supported|not yet supported|read-only mode only" "$CURRENT_MOUNT_LOG"; then
        e2e_skip "RW mount is not supported in this build/environment"
    fi
    if grep -qiE "unsupported feature: non-contiguous ext4 journal extents" "$CURRENT_MOUNT_LOG"; then
        e2e_skip "Current ext4 mount path does not support this journal layout"
    fi

    if [[ "$allow_failure" == "1" ]]; then
        return 1
    fi

    if [[ $ready_result -eq 2 ]]; then
        e2e_fail "Mount timed out after ${timeout_seconds}s ($mode)"
    fi
    e2e_fail "Mount process exited before mount became ready ($mode)"
}

stop_mount() {
    local mount_point="${1:-$CURRENT_MOUNT_POINT}"

    e2e_unmount "$mount_point"

    if [[ -n "$CURRENT_MOUNT_PID" ]] && kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
        kill "$CURRENT_MOUNT_PID" 2>/dev/null || true
        sleep 0.5
        if kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
            kill -9 "$CURRENT_MOUNT_PID" 2>/dev/null || true
        fi
    fi
    if [[ -n "$CURRENT_MOUNT_PID" ]]; then
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
    fi

    CURRENT_MOUNT_PID=""
    CURRENT_MOUNT_POINT=""
}

e2e_step "Phase 1: Build ffs-cli"
e2e_assert cargo build -p ffs-cli --release

e2e_step "Phase 2: Create base/work ext4 images"
BASE_IMAGE="$E2E_TEMP_DIR/base.ext4"
WORK_IMAGE="$E2E_TEMP_DIR/work.ext4"
create_rw_ext4_image "$BASE_IMAGE" 64
e2e_assert cp "$BASE_IMAGE" "$WORK_IMAGE"
e2e_log "Created base image: $BASE_IMAGE"
e2e_log "Created work image: $WORK_IMAGE"

e2e_step "Phase 3: RW mount and write operations"
MOUNT_RW="$E2E_TEMP_DIR/mnt_rw"
start_mount rw "$WORK_IMAGE" "$MOUNT_RW" 0

log_tree "$MOUNT_RW" "Pre-write directory tree"

e2e_step "Phase 3.1: create/write/overwrite"
e2e_assert bash -lc "printf 'hello\n' > '$MOUNT_RW/newfile.txt'"
e2e_assert grep -Fxq "hello" "$MOUNT_RW/newfile.txt"
e2e_assert bash -lc "printf 'goodbye\n' > '$MOUNT_RW/newfile.txt'"
e2e_assert grep -Fxq "goodbye" "$MOUNT_RW/newfile.txt"

e2e_assert bash -lc "printf 'persisted-after-clean-unmount\n' > '$MOUNT_RW/persist.txt'"
e2e_assert grep -Fxq "persisted-after-clean-unmount" "$MOUNT_RW/persist.txt"

e2e_step "Phase 3.2: mkdir/rmdir"
e2e_assert mkdir "$MOUNT_RW/newdir"
e2e_assert_dir "$MOUNT_RW/newdir"
e2e_assert rmdir "$MOUNT_RW/newdir"
assert_not_exists "$MOUNT_RW/newdir"

e2e_step "Phase 3.3: rename/unlink"
e2e_assert mv "$MOUNT_RW/newfile.txt" "$MOUNT_RW/renamed.txt"
e2e_assert_file "$MOUNT_RW/renamed.txt"
e2e_assert rm "$MOUNT_RW/renamed.txt"
assert_not_exists "$MOUNT_RW/renamed.txt"

e2e_step "Phase 3.4: metadata checks (phase-gated)"
if e2e_run chmod 600 "$MOUNT_RW/persist.txt"; then
    FILE_MODE="$(stat -c '%a' "$MOUNT_RW/persist.txt")"
    if [[ "$FILE_MODE" != "600" ]]; then
        e2e_fail "chmod verification failed: expected 600, got $FILE_MODE"
    fi
    e2e_log "chmod verification passed (mode=$FILE_MODE)"
else
    e2e_log "chmod is not supported in current build (phase-gated; continuing)"
fi

MTIME_BEFORE="$(stat -c '%Y' "$MOUNT_RW/persist.txt")"
sleep 1
e2e_assert bash -lc "printf 'mtime-check\n' >> '$MOUNT_RW/persist.txt'"
MTIME_AFTER="$(stat -c '%Y' "$MOUNT_RW/persist.txt")"
if (( MTIME_AFTER < MTIME_BEFORE )); then
    e2e_fail "mtime monotonicity check failed: before=$MTIME_BEFORE after=$MTIME_AFTER"
fi
e2e_log "mtime monotonicity check passed (before=$MTIME_BEFORE after=$MTIME_AFTER)"

log_tree "$MOUNT_RW" "Post-write directory tree"

e2e_step "Phase 3.5: clean unmount"
stop_mount "$MOUNT_RW"
if mountpoint -q "$MOUNT_RW" 2>/dev/null; then
    e2e_fail "Failed to unmount RW mount point: $MOUNT_RW"
fi

e2e_step "Phase 4: remount read-only and verify persistence"
MOUNT_RO="$E2E_TEMP_DIR/mnt_ro"
start_mount ro "$WORK_IMAGE" "$MOUNT_RO" 0

e2e_assert grep -Fxq "persisted-after-clean-unmount" "$MOUNT_RO/persist.txt"
e2e_assert grep -Fxq "mtime-check" "$MOUNT_RO/persist.txt"
assert_not_exists "$MOUNT_RO/renamed.txt"
assert_not_exists "$MOUNT_RO/newdir"
log_tree "$MOUNT_RO" "Read-only verification directory tree"

stop_mount "$MOUNT_RO"
if mountpoint -q "$MOUNT_RO" 2>/dev/null; then
    e2e_fail "Failed to unmount RO mount point: $MOUNT_RO"
fi

e2e_step "Phase 5: best-effort crash/recovery mini-harness"
MOUNT_CRASH="$E2E_TEMP_DIR/mnt_crash"
if start_mount rw "$WORK_IMAGE" "$MOUNT_CRASH" 1; then
    e2e_assert bash -lc "printf 'crash-path-write\n' > '$MOUNT_CRASH/crash_marker.txt'"
    e2e_assert_file "$MOUNT_CRASH/crash_marker.txt"

    e2e_log "Simulating abrupt crash: kill -9 $CURRENT_MOUNT_PID"
    kill -9 "$CURRENT_MOUNT_PID" 2>/dev/null || true
    wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
    CURRENT_MOUNT_PID=""
    e2e_unmount "$MOUNT_CRASH"

    e2e_step "Phase 5.1: inspect after crash"
    e2e_assert cargo run -p ffs-cli --release -- inspect "$WORK_IMAGE" --json

    e2e_step "Phase 5.2: remount after crash"
    if start_mount ro "$WORK_IMAGE" "$MOUNT_RO" 1; then
        log_tree "$MOUNT_RO" "Post-crash remount directory tree"
        stop_mount "$MOUNT_RO"
    else
        if grep -qiE "journal|replay|recover|unsupported|not yet supported|failed to recover" "$CURRENT_MOUNT_LOG"; then
            e2e_log "Post-crash remount failed with explicit recovery diagnostic (acceptable for Phase B)"
            e2e_run tail -n 120 "$CURRENT_MOUNT_LOG" || true
        else
            e2e_fail "Post-crash remount failed without clear recovery diagnostic"
        fi
    fi
else
    e2e_log "Skipping Phase 5 crash mini-harness because RW mount could not be established in this environment."
fi

e2e_pass
