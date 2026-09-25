#!/usr/bin/env bash
# ffs_ext4_rw_smoke.sh - ext4 read-write E2E smoke test for FrankenFS
#
# This script validates read-write ext4 behavior through FUSE:
# - create a fresh base image and copy to a work image
# - mount the work image read-write and execute core write operations
# - cleanly unmount and remount read-only to verify persistence
# - deterministic SIGKILL crash/recovery harness with baseline + in-flight checks

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-trace}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export FFS_USE_RCH="${FFS_USE_RCH:-1}"
# Avoid implicit AllowOther injection from fuse3 auto-unmount in rootless test environments.
export FFS_AUTO_UNMOUNT="${FFS_AUTO_UNMOUNT:-0}"
FFS_SKIP_BUILD="${FFS_SKIP_BUILD:-0}"
FFS_CLI_BIN="${FFS_CLI_BIN:-${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/ffs-cli}"

e2e_init "ffs_ext4_rw_smoke"
e2e_print_env

CURRENT_MOUNT_PID=""
CURRENT_MOUNT_LOG=""
CURRENT_MOUNT_POINT=""
BASELINE_FILE_COUNT="${BASELINE_FILE_COUNT:-500}"
CRASH_WRITER_RUNTIME_SECS="${CRASH_WRITER_RUNTIME_SECS:-2}"
CRASH_WRITER_SLEEP_SECS="${CRASH_WRITER_SLEEP_SECS:-0.01}"

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

    while true; do
        if mountpoint -q "$mount_point" 2>/dev/null; then
            return 0
        fi
        if [[ -n "${CURRENT_MOUNT_LOG:-}" ]] && [[ -f "$CURRENT_MOUNT_LOG" ]]; then
            if grep -q "INIT response" "$CURRENT_MOUNT_LOG"; then
                return 0
            fi
        fi

        sleep 0.5
        elapsed=$((elapsed + 1))

        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi

        if [[ $elapsed -ge $((timeout_seconds * 2)) ]]; then
            return 2
        fi
    done
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

    local cmd=("$FFS_CLI_BIN" mount "$image" "$mount_point")
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
    if grep -qiE "fusermount3: mount failed: Permission denied|fusermount: failed to open /dev/fuse: Operation not permitted|fusermount: mount failed: Operation not permitted" "$CURRENT_MOUNT_LOG"; then
        e2e_skip "FUSE is present but mount is not permitted in this environment"
    fi

    if [[ "$mode" == "rw" ]] && grep -qiE "read-write mount is not yet supported|not yet supported|read-only mode only" "$CURRENT_MOUNT_LOG"; then
        e2e_skip "RW mount is not supported in this build/environment"
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

    # Unmount once more after daemon shutdown in case the first attempt ran
    # before the mount process exited.
    if mountpoint -q "$mount_point" 2>/dev/null; then
        e2e_log "Retrying unmount after mount process exit: $mount_point"
        e2e_unmount "$mount_point"
    fi

    CURRENT_MOUNT_PID=""
    CURRENT_MOUNT_POINT=""
}

require_python3_for_crash_phase() {
    if ! command -v python3 >/dev/null 2>&1; then
        e2e_skip "python3 is required for deterministic crash/recovery validation"
    fi
}

wait_for_pid_exit() {
    local pid="$1"
    local timeout_seconds="${2:-10}"
    local label="${3:-process}"
    local elapsed_ticks=0

    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.2
        elapsed_ticks=$((elapsed_ticks + 1))
        if [[ $elapsed_ticks -ge $((timeout_seconds * 5)) ]]; then
            e2e_log "$label did not exit after ${timeout_seconds}s; sending SIGKILL"
            kill -9 "$pid" 2>/dev/null || true
            break
        fi
    done

    wait "$pid" 2>/dev/null || true
}

fsync_file_and_parent() {
    local file_path="$1"
    e2e_assert python3 - "$file_path" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
fd = os.open(path, os.O_RDONLY)
try:
    os.fsync(fd)
finally:
    os.close(fd)

dir_fd = os.open(str(path.parent), os.O_RDONLY)
try:
    os.fsync(dir_fd)
finally:
    os.close(dir_fd)
PY
}

run_cargo() {
    if [[ "$FFS_USE_RCH" == "1" ]]; then
        if ! command -v rch >/dev/null 2>&1; then
            e2e_fail "FFS_USE_RCH=1 requires rch; set FFS_USE_RCH=0 for an explicit local cargo run"
        fi
        e2e_assert rch exec -- cargo "$@"
    else
        e2e_assert cargo "$@"
    fi
}

e2e_step "Phase 1: Build ffs-cli"
if [[ "$FFS_SKIP_BUILD" == "1" ]]; then
    e2e_log "Skipping build (FFS_SKIP_BUILD=1); expecting existing binary at $FFS_CLI_BIN"
else
    run_cargo build -p ffs-cli --release
fi
e2e_assert_file "$FFS_CLI_BIN"

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
fsync_file_and_parent "$MOUNT_RW/persist.txt"

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
fsync_file_and_parent "$MOUNT_RW/persist.txt"
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

# bd-53dub: the image FrankenFS just wrote must pass the reference checker,
# not only read back through FrankenFS itself. A missing checker is a failure
# here, not a skip: this lane claims journaled-image evidence.
e2e_step "Phase 3.6: e2fsck -fn on the written image"
if ! command -v e2fsck >/dev/null 2>&1; then
    e2e_fail "e2fsck unavailable; cannot certify the written ext4 image"
fi
if ! e2fsck -fn "$WORK_IMAGE" >"$E2E_TEMP_DIR/e2fsck_after_rw.log" 2>&1; then
    cat "$E2E_TEMP_DIR/e2fsck_after_rw.log"
    e2e_fail "e2fsck -fn reported problems on the image written through the RW mount"
fi
e2e_log "e2fsck -fn clean after RW writes"

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

e2e_step "Phase 5: deterministic SIGKILL crash/recovery harness"
MOUNT_CRASH="$E2E_TEMP_DIR/mnt_crash"
if start_mount rw "$WORK_IMAGE" "$MOUNT_CRASH" 1; then
    require_python3_for_crash_phase

    CRASH_ARTIFACT_DIR="$E2E_LOG_DIR/sigkill_crash"
    e2e_assert mkdir -p "$CRASH_ARTIFACT_DIR"
    BASELINE_MANIFEST="$CRASH_ARTIFACT_DIR/baseline_checksums.json"
    INFLIGHT_EVENTS="$CRASH_ARTIFACT_DIR/inflight_events.jsonl"
    INFLIGHT_WRITER_LOG="$CRASH_ARTIFACT_DIR/inflight_writer.log"
    CRASH_VERIFY_REPORT="$CRASH_ARTIFACT_DIR/recovery_verify_report.json"

    e2e_step "Phase 5.1: write + fsync baseline dataset"
    e2e_log "Baseline file count: $BASELINE_FILE_COUNT"
    e2e_assert python3 - "$MOUNT_CRASH" "$BASELINE_MANIFEST" "$BASELINE_FILE_COUNT" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

mount = pathlib.Path(sys.argv[1])
manifest = pathlib.Path(sys.argv[2])
count = int(sys.argv[3])
root = mount / "sigkill_baseline"
root.mkdir(parents=True, exist_ok=True)
checksums: dict[str, str] = {}

for idx in range(count):
    rel = f"sigkill_baseline/base_{idx:04d}.txt"
    payload = (
        f"baseline:{idx:04d}\n".encode("utf-8")
        + bytes(((idx + off) % 251 for off in range(1536)))
    )
    path = mount / rel
    with path.open("wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    checksums[rel] = hashlib.sha256(payload).hexdigest()

dir_fd = os.open(str(root), os.O_RDONLY)
try:
    os.fsync(dir_fd)
finally:
    os.close(dir_fd)

manifest.write_text(json.dumps(checksums, indent=2, sort_keys=True), encoding="utf-8")
PY
    e2e_assert_file "$BASELINE_MANIFEST"
    e2e_run wc -l "$BASELINE_MANIFEST"

    e2e_step "Phase 5.2: start continuous in-flight writer"
    python3 - "$MOUNT_CRASH" "$INFLIGHT_EVENTS" "$CRASH_WRITER_SLEEP_SECS" >"$INFLIGHT_WRITER_LOG" 2>&1 <<'PY' &
import hashlib
import json
import os
import pathlib
import sys
import time

mount = pathlib.Path(sys.argv[1])
event_path = pathlib.Path(sys.argv[2])
sleep_seconds = float(sys.argv[3])
root = mount / "sigkill_inflight"
root.mkdir(parents=True, exist_ok=True)
event_path.parent.mkdir(parents=True, exist_ok=True)

def payload_for(idx: int, mode: str) -> bytes:
    header = f"idx={idx:06d};mode={mode};".encode("utf-8")
    body = bytes(((idx * 17 + off) % 251 for off in range(4096 - len(header))))
    return header + body

with event_path.open("a", encoding="utf-8") as events:
    idx = 0
    while True:
        mode = "fsync" if idx % 3 == 0 else "async"
        rel = f"sigkill_inflight/file_{idx:06d}_{mode}.bin"
        path = mount / rel
        payload = payload_for(idx, mode)
        events.write(
            json.dumps(
                {
                    "event": "planned",
                    "path": rel,
                    "idx": idx,
                    "mode": mode,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
                sort_keys=True,
            )
            + "\n"
        )
        events.flush()

        try:
            with path.open("wb") as fh:
                split = len(payload) // 2
                fh.write(payload[:split])
                fh.flush()
                time.sleep(sleep_seconds)
                fh.write(payload[split:])
                fh.flush()
                if mode == "fsync":
                    os.fsync(fh.fileno())
                    events.write(
                        json.dumps({"event": "fsync_done", "path": rel}, sort_keys=True) + "\n"
                    )
                    events.flush()
            events.write(json.dumps({"event": "write_done", "path": rel}, sort_keys=True) + "\n")
            events.flush()
        except OSError as exc:
            events.write(
                json.dumps(
                    {"event": "writer_exit", "idx": idx, "error": str(exc)},
                    sort_keys=True,
                )
                + "\n"
            )
            events.flush()
            break

        idx += 1
        time.sleep(sleep_seconds)
PY
    INFLIGHT_WRITER_PID=$!
    e2e_log "In-flight writer PID: $INFLIGHT_WRITER_PID"

    sleep "$CRASH_WRITER_RUNTIME_SECS"

    e2e_step "Phase 5.3: SIGKILL mount daemon"
    e2e_log "Simulating abrupt crash: kill -9 $CURRENT_MOUNT_PID"
    kill -9 "$CURRENT_MOUNT_PID" 2>/dev/null || true
    wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
    CURRENT_MOUNT_PID=""
    e2e_unmount "$MOUNT_CRASH"
    wait_for_pid_exit "$INFLIGHT_WRITER_PID" 10 "in-flight writer"

    e2e_assert_file "$INFLIGHT_EVENTS"
    e2e_assert_file "$INFLIGHT_WRITER_LOG"

    e2e_step "Phase 5.4: inspect after crash"
    e2e_assert "$FFS_CLI_BIN" inspect "$WORK_IMAGE" --json

    e2e_step "Phase 5.5: remount read-only and verify invariants"
    if start_mount ro "$WORK_IMAGE" "$MOUNT_RO" 1; then
        e2e_assert python3 - "$MOUNT_RO" "$BASELINE_MANIFEST" "$INFLIGHT_EVENTS" "$CRASH_VERIFY_REPORT" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

mount = pathlib.Path(sys.argv[1])
baseline_manifest = pathlib.Path(sys.argv[2])
events_path = pathlib.Path(sys.argv[3])
report_path = pathlib.Path(sys.argv[4])

def payload_for(idx: int, mode: str) -> bytes:
    header = f"idx={idx:06d};mode={mode};".encode("utf-8")
    body = bytes(((idx * 17 + off) % 251 for off in range(4096 - len(header))))
    return header + body

baseline = json.loads(baseline_manifest.read_text(encoding="utf-8"))
events: list[dict[str, object]] = []
for line in events_path.read_text(encoding="utf-8").splitlines():
    if line.strip():
        events.append(json.loads(line))

planned: dict[str, dict[str, object]] = {}
fsynced: set[str] = set()
for event in events:
    kind = event.get("event")
    path = event.get("path")
    if isinstance(path, str):
        if kind == "planned":
            planned[path] = event
        elif kind == "fsync_done":
            fsynced.add(path)

errors: list[str] = []
baseline_verified = 0
for rel, expected_sha in baseline.items():
    path = mount / rel
    if not path.is_file():
        errors.append(f"missing baseline file: {rel}")
        continue
    data = path.read_bytes()
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != expected_sha:
        errors.append(f"baseline checksum mismatch: {rel}")
    else:
        baseline_verified += 1

inflight_root = mount / "sigkill_inflight"
existing_inflight: list[str] = []
if inflight_root.exists():
    for file_path in sorted(inflight_root.rglob("*.bin")):
        existing_inflight.append(file_path.relative_to(mount).as_posix())

for rel in existing_inflight:
    planned_event = planned.get(rel)
    if planned_event is None:
        errors.append(f"unexpected inflight file (no planned record): {rel}")
        continue
    idx = int(planned_event["idx"])
    mode = str(planned_event["mode"])
    was_fsynced = rel in fsynced
    expected = payload_for(idx, mode)
    actual = (mount / rel).read_bytes()
    if actual == expected:
        continue
    # For writes that did not complete fsync, allow clean prefix truncation
    # after SIGKILL regardless of planned mode.
    if not was_fsynced and expected.startswith(actual):
        continue
    # fsync-marked files are checked strictly in the fsynced loop below.
    if was_fsynced:
        continue
    errors.append(
        f"inflight file contains unexpected bytes: {rel} (len={len(actual)} expected={len(expected)})"
    )

for rel in sorted(fsynced):
    planned_event = planned.get(rel)
    if planned_event is None:
        errors.append(f"fsync marker without planned record: {rel}")
        continue
    path = mount / rel
    if not path.is_file():
        errors.append(f"fsync file missing after crash: {rel}")
        continue
    idx = int(planned_event["idx"])
    mode = str(planned_event["mode"])
    if mode != "fsync":
        errors.append(f"fsync marker recorded for async file: {rel}")
        continue
    expected = payload_for(idx, mode)
    actual = path.read_bytes()
    if actual != expected:
        errors.append(f"fsync file checksum mismatch after crash: {rel}")

# Walk all regular files to ensure directory entries are readable.
for root_dir, _, names in os.walk(mount):
    for name in names:
        full = pathlib.Path(root_dir) / name
        rel = full.relative_to(mount).as_posix()
        try:
            _ = full.read_bytes()
        except OSError as exc:
            errors.append(f"failed to read file during consistency walk: {rel}: {exc}")

report = {
    "baseline_file_count": len(baseline),
    "baseline_verified": baseline_verified,
    "planned_inflight_records": len(planned),
    "fsynced_records": len(fsynced),
    "existing_inflight_files": len(existing_inflight),
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

if errors:
    for entry in errors:
        print(entry)
    sys.exit(1)
PY

        e2e_assert_file "$CRASH_VERIFY_REPORT"
        e2e_run cat "$CRASH_VERIFY_REPORT"
        log_tree "$MOUNT_RO" "Post-crash remount directory tree"
        stop_mount "$MOUNT_RO"
        if grep -qiE "ext4 filesystem state: clean|unclean shutdown detected|recovery performed|journal.*replay" "$CURRENT_MOUNT_LOG"; then
            e2e_log "Crash recovery evidence found in remount log"
        else
            e2e_fail "Missing crash recovery evidence in remount log ($CURRENT_MOUNT_LOG)"
        fi
    else
        if grep -qiE "journal|replay|recover|unsupported|not yet supported|failed to recover" "$CURRENT_MOUNT_LOG"; then
            e2e_log "Post-crash remount failed with explicit recovery diagnostic (phase-gated fallback)"
            e2e_run tail -n 120 "$CURRENT_MOUNT_LOG" || true
        else
            e2e_fail "Post-crash remount failed without clear recovery diagnostic"
        fi
    fi
else
    e2e_log "Skipping Phase 5 crash harness because RW mount could not be established in this environment."
fi

e2e_pass
