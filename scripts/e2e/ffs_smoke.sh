#!/usr/bin/env bash
# ffs_smoke.sh - End-to-end smoke test for FrankenFS
#
# This script exercises the main user-facing workflows:
# - Build the workspace
# - Run CLI commands (inspect, scrub, parity)
# - Mount ext4 image via FUSE (if available)
# - Validate basic file operations through the mount
#
# Usage: ./scripts/e2e/ffs_smoke.sh
#
# Exit codes:
#   0 - All tests passed (or skipped)
#   1 - Test failure
#
# Environment:
#   RUST_LOG - Log level (default: info)
#   RUST_BACKTRACE - Backtrace (default: 1)
#   SKIP_MOUNT - Set to 1 to skip FUSE mount tests
#   FFS_USE_RCH - Defaults to 1; 0 permits Cargo on a provisioned GitHub Actions runner

set -euo pipefail

# Navigate to repo root
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

# Source shared helpers
source "$REPO_ROOT/scripts/e2e/lib.sh"

# Set Rust logging
export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_smoke}"
RCH_BIN="${RCH_BIN:-rch}"
FFS_USE_RCH="${FFS_USE_RCH:-1}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CLIENT_RUST_LOG="${RCH_CLIENT_RUST_LOG:-info}"
FFS_CLI_BIN="${FFS_CLI_BIN:-$REPO_ROOT/target/release/ffs-cli}"

for rch_env_var in CARGO_TARGET_DIR RUST_BACKTRACE; do
    case ",${RCH_ENV_ALLOWLIST:-}," in
        *",${rch_env_var},"*) ;;
        *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}${rch_env_var}" ;;
    esac
done

scenario_result() {
    local scenario_id="$1"
    local status="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${status}|detail=${detail}"
}

cancel_matching_rch_queue_entry() {
    local command_text="$*"
    local queue_json
    local ids
    if ! command -v jq >/dev/null 2>&1; then
        return 0
    fi
    queue_json="$("$RCH_BIN" queue --json 2>/dev/null || true)"
    if [[ -z "$queue_json" ]]; then
        return 0
    fi
    ids="$(jq -r --arg cmd "$command_text" '
        .data.active_builds[]?
        | select(.project_id | startswith("frankenfs-"))
        | select(.command == $cmd)
        | .id
    ' <<<"$queue_json" || true)"
    for id in $ids; do
        if "$RCH_BIN" cancel "$id" >/dev/null 2>&1; then
            e2e_log "RCH_STALE_QUEUE_CANCELLED|id=${id}|command=${command_text}"
        fi
    done
}

run_rch_capture() {
    local output_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local required_artifact="${RCH_REQUIRED_ARTIFACT:-}"
    local wait_status
    shift

    case "$FFS_USE_RCH" in
        0)
            if [[ "${CI:-}" != "true" || "${GITHUB_ACTIONS:-}" != "true" ]]; then
                e2e_log "CI_CARGO_EXECUTION_REJECTED|reason=GitHub_Actions_runner_required"
                return 99
            fi
            e2e_log "CI_CARGO_EXECUTION|command=$*|log=$output_path"
            if timeout "$RCH_COMMAND_TIMEOUT_SECS" "$@" >"$output_path" 2>&1; then
                return 0
            else
                return "$?"
            fi
            ;;
        1) ;;
        *)
            e2e_log "CARGO_EXECUTION_MODE_REJECTED|FFS_USE_RCH=$FFS_USE_RCH"
            return 99
            ;;
    esac

    : >"$output_path"
    set +e
    RUST_LOG="$RCH_CLIENT_RUST_LOG" RCH_VISIBILITY="$RCH_VISIBILITY" "$RCH_BIN" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    set -e

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" && -n "$required_artifact" && -e "$required_artifact" ]]; then
            e2e_log "RCH_REQUIRED_ARTIFACT_READY|artifact=${required_artifact}|output=${output_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            cancel_matching_rch_queue_entry "$@"
            break
        fi
        if [[ -n "$remote_exit" && -z "$required_artifact" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                cancel_matching_rch_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            cancel_matching_rch_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    set -e
    if [[ $status -eq 0 ]]; then
        if [[ -n "$remote_exit" ]]; then
            status="$remote_exit"
        else
            status="$wait_status"
        fi
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    return "$status"
}

print_rch_log() {
    local output_path="$1"
    if [[ -s "$output_path" ]]; then
        tee -a "$E2E_LOG_FILE" <"$output_path"
    fi
}

run_rch_lane() {
    local scenario_id="$1"
    local output_path="$2"
    local detail="$3"
    shift 3

    if run_rch_capture "$output_path" "$@"; then
        scenario_result "$scenario_id" "PASS" "${detail}; log=${output_path}"
    else
        print_rch_log "$output_path"
        scenario_result "$scenario_id" "FAIL" "${detail} failed; log=${output_path}"
        e2e_fail "${detail} failed"
    fi
}

run_rch_cargo_capture() {
    local output_path="$1"
    shift
    run_rch_capture "$output_path" cargo "$@"
}

run_exact_harness_test() {
    local output_path="$1"
    local test_name="$2"
    if run_rch_cargo_capture "$output_path" test -p ffs-harness --lib -- --exact "$test_name" --color=never; then
        if python3 - "$output_path" "$test_name" <<'PY'
import json
from pathlib import Path
import re
import sys

lines = Path(sys.argv[1]).read_text().splitlines()
name = sys.argv[2]
events = []
for line in lines:
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if isinstance(event, dict) and event.get("type") in ("suite", "test"):
        events.append(event)
if events:
    suites = [e for e in events if e["type"] == "suite"]
    tests = [e for e in events if e["type"] == "test"]
    valid = (
        len(suites) == 2 and suites[0].get("event") == "started"
        and suites[0].get("test_count") == 1 and suites[1].get("event") == "ok"
        and all(suites[1].get(k) == v for k, v in (("passed", 1), ("failed", 0), ("ignored", 0)))
        and len(tests) == 2 and all(e.get("name") == name for e in tests)
        and [e.get("event") for e in tests] == ["started", "ok"]
    )
else:
    valid = lines.count(f"test {name} ... ok") == 1 and sum(
        re.match(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", line) is not None
        for line in lines
    ) == 1
sys.exit(0 if valid else 1)
PY
        then
            return 0
        fi
        e2e_log "LIBTEST_SELECTION_REJECTED|expected=$test_name|log=$output_path"
        print_rch_log "$output_path"
        return 1
    else
        return "$?"
    fi
}

run_remote_cli_capture() {
    local output_path="$1"
    shift
    run_rch_cargo_capture "$output_path" run -p ffs-cli -- "$@"
}

run_remote_cli_assert() {
    local output_path="$1"
    local detail="$2"
    local status
    shift 2

    if run_remote_cli_capture "$output_path" "$@"; then
        return 0
    else
        status=$?
        print_rch_log "$output_path"
        e2e_fail "$detail failed with exit code $status"
    fi
}

run_local_cli_capture() {
    local output_path="$1"
    shift
    env RUST_LOG=off "$FFS_CLI_BIN" "$@" >"$output_path" 2>&1
}

# Sourcing exposes the helpers without launching builds or mounts.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

# Initialize test
e2e_init "ffs_smoke"

# Print environment
e2e_print_env

if [[ "$FFS_USE_RCH" == "1" ]] && ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    e2e_skip "rch not found; this suite requires offloaded cargo execution"
fi

#######################################
# Phase 0: Scenario catalog contract validation
#######################################
e2e_validate_scenario_catalog "$REPO_ROOT/scripts/e2e/scenario_catalog.json"

#######################################
# Phase 1: Build
#######################################
e2e_step "Phase 1: Build"

run_rch_lane \
    "cli_smoke_workspace_build" \
    "$E2E_LOG_DIR/workspace_build.log" \
    "workspace build" cargo build --workspace

#######################################
# Phase 2: Create test image
#######################################
e2e_step "Phase 2: Create Test Image"

RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")"
mkdir -p "$RCH_INPUT_DIR"
TEST_IMAGE="$RCH_INPUT_DIR/e2e_test.ext4"
e2e_create_ext4_image "$TEST_IMAGE" 16

#######################################
# Phase 3: CLI Commands
#######################################
e2e_step "Phase 3: CLI Commands"

# Inspect
e2e_log "Testing: ffs inspect"
INSPECT_OUT="$E2E_LOG_DIR/inspect.json"
run_remote_cli_assert "$INSPECT_OUT" "ffs inspect" inspect "$TEST_IMAGE" --json

# Scrub
# Note: scrub returns exit code 2 if findings are detected, which is normal
# for test images. We check that it runs (doesn't crash) rather than asserting exit 0.
e2e_log ""
e2e_log "Testing: ffs scrub"
SCRUB_OUT="$E2E_LOG_DIR/scrub.json"
if run_remote_cli_capture "$SCRUB_OUT" scrub "$TEST_IMAGE" --json; then
    scrub_rc=0
else
    scrub_rc=$?
fi
if [[ $scrub_rc -eq 0 ]]; then
    e2e_log "Scrub completed: no findings"
elif [[ $scrub_rc -eq 2 ]]; then
    e2e_log "Scrub completed: findings detected (expected for test images)"
else
    print_rch_log "$SCRUB_OUT"
    e2e_fail "Scrub failed with unexpected exit code: $scrub_rc"
fi

# Parity
e2e_log ""
e2e_log "Testing: ffs parity"
PARITY_OUT="$E2E_LOG_DIR/parity.json"
run_remote_cli_assert "$PARITY_OUT" "ffs parity" parity --json

#######################################
# Phase 3b: Runtime-mode contract
#######################################
e2e_step "Phase 3b: Mount Runtime Mode CLI Contract"

RUNTIME_HELP_OUT="$E2E_LOG_DIR/mount_runtime_help.txt"
RUNTIME_INVALID_STD_OUT="$E2E_LOG_DIR/mount_runtime_invalid_standard_timeout.txt"

# Scenario 1: help output documents runtime controls
run_remote_cli_assert "$RUNTIME_HELP_OUT" "ffs mount --help" mount --help
if grep -q -- "--runtime-mode" "$RUNTIME_HELP_OUT" \
    && grep -q -- "--managed-unmount-timeout-secs" "$RUNTIME_HELP_OUT"; then
    scenario_result "cli_mount_runtime_help_contract" "PASS" "runtime flags documented in help"
else
    scenario_result "cli_mount_runtime_help_contract" "FAIL" "missing runtime flag docs in mount help"
    e2e_fail "mount --help missing runtime mode controls"
fi

# Scenario 2: invalid flag combination fails with actionable error
if run_remote_cli_capture \
    "$RUNTIME_INVALID_STD_OUT" \
    mount \
    --runtime-mode standard \
    --managed-unmount-timeout-secs 10 \
    "$TEST_IMAGE" \
    "$RCH_INPUT_DIR/runtime_invalid_mountpoint"; then
    invalid_std_rc=0
else
    invalid_std_rc=$?
fi
if [[ $invalid_std_rc -eq 0 ]]; then
    scenario_result "cli_mount_runtime_invalid_standard_timeout" "FAIL" "invalid combo unexpectedly succeeded"
    e2e_fail "invalid runtime flag combination unexpectedly succeeded"
fi
if grep -q -- "--managed-unmount-timeout-secs requires --runtime-mode managed or per-core" \
    "$RUNTIME_INVALID_STD_OUT"; then
    scenario_result "cli_mount_runtime_invalid_standard_timeout" "PASS" "invalid combo rejected with actionable error"
else
    scenario_result "cli_mount_runtime_invalid_standard_timeout" "FAIL" "actionable validation text missing"
    e2e_fail "invalid runtime combination did not emit expected error text"
fi

# Scenario 3: managed mode is wired but fails on invalid mountpoint
RUNTIME_MANAGED_BAD_MP_OUT="$E2E_LOG_DIR/mount_runtime_managed_bad_mountpoint.txt"
if run_remote_cli_capture \
    "$RUNTIME_MANAGED_BAD_MP_OUT" \
    mount \
    --runtime-mode managed \
    "$TEST_IMAGE" \
    "$RCH_INPUT_DIR/runtime_nonexistent_mountpoint"; then
    managed_mode_rc=0
else
    managed_mode_rc=$?
fi
if [[ $managed_mode_rc -eq 0 ]]; then
    scenario_result "cli_mount_runtime_managed_bad_mountpoint" "FAIL" "managed mode with bad mountpoint unexpectedly succeeded"
    e2e_fail "managed runtime mode with bad mountpoint unexpectedly succeeded"
fi
# Managed mode is wired — the error should come from mountpoint validation or
# FUSE mount, not from an "unwired" rejection.
if grep -q -- "FUSE managed mount failed\|mountpoint.*does not exist\|failed to open" "$RUNTIME_MANAGED_BAD_MP_OUT"; then
    scenario_result "cli_mount_runtime_managed_bad_mountpoint" "PASS" "managed mode wired and fails on bad mountpoint"
else
    print_rch_log "$RUNTIME_MANAGED_BAD_MP_OUT"
    scenario_result "cli_mount_runtime_managed_bad_mountpoint" "FAIL" "expected mount rejection missing"
    e2e_fail "managed runtime mode did not reach the expected mount rejection"
fi

# Scenario 4: benchmark taxonomy covers mount runtime mode operations
e2e_log ""
e2e_log "Testing: benchmark taxonomy mount runtime mode coverage"
RUNTIME_BENCH_TAXONOMY_OUT="$E2E_LOG_DIR/mount_runtime_benchmark_taxonomy.txt"
if run_exact_harness_test "$RUNTIME_BENCH_TAXONOMY_OUT" benchmark_taxonomy::tests::mount_runtime_mode_benchmarks_registered; then
    bench_taxonomy_rc=0
else
    bench_taxonomy_rc=$?
fi
if [[ $bench_taxonomy_rc -eq 0 ]]; then
    scenario_result "cli_mount_runtime_benchmark_taxonomy_coverage" "PASS" "all mount runtime benchmark ops registered in taxonomy"
else
    scenario_result "cli_mount_runtime_benchmark_taxonomy_coverage" "FAIL" "mount runtime benchmark taxonomy test failed"
    e2e_fail "mount runtime benchmark taxonomy coverage test failed"
fi

# Scenario 5: benchmark taxonomy covers degraded throughput operations
e2e_log ""
e2e_log "Testing: benchmark taxonomy degraded throughput coverage"
DEGRADED_BENCH_TAXONOMY_OUT="$E2E_LOG_DIR/degraded_throughput_benchmark_taxonomy.txt"
if run_exact_harness_test "$DEGRADED_BENCH_TAXONOMY_OUT" benchmark_taxonomy::tests::degraded_throughput_benchmarks_registered; then
    degraded_taxonomy_rc=0
else
    degraded_taxonomy_rc=$?
fi
if [[ $degraded_taxonomy_rc -eq 0 ]]; then
    scenario_result "cli_degraded_throughput_benchmarks_taxonomy_coverage" "PASS" "all degraded throughput benchmark ops registered in taxonomy"
else
    scenario_result "cli_degraded_throughput_benchmarks_taxonomy_coverage" "FAIL" "degraded throughput benchmark taxonomy test failed"
    e2e_fail "degraded throughput benchmark taxonomy coverage test failed"
fi

# Scenario 6: triage module covers all taxonomy families
e2e_log ""
e2e_log "Testing: triage module family coverage"
TRIAGE_FAMILIES_OUT="$E2E_LOG_DIR/triage_module_family_coverage.txt"
if run_exact_harness_test "$TRIAGE_FAMILIES_OUT" benchmark_taxonomy::tests::triage_module_covers_all_taxonomy_families; then
    triage_families_rc=0
else
    triage_families_rc=$?
fi
if [[ $triage_families_rc -eq 0 ]]; then
    scenario_result "cli_triage_module_covers_all_families" "PASS" "triage module covers all taxonomy families"
else
    scenario_result "cli_triage_module_covers_all_families" "FAIL" "triage module family coverage test failed"
    e2e_fail "triage module family coverage test failed"
fi

# Scenario 7: triage runbook file exists
e2e_log ""
e2e_log "Testing: triage runbook file exists"
if [[ -f "$REPO_ROOT/docs/runbooks/perf-regression-triage.md" ]]; then
    scenario_result "cli_triage_runbook_exists" "PASS" "triage runbook exists at expected path"
else
    scenario_result "cli_triage_runbook_exists" "FAIL" "triage runbook missing"
    e2e_fail "triage runbook missing at docs/runbooks/perf-regression-triage.md"
fi

#######################################
# Phase 4: FUSE Mount (optional)
#######################################
e2e_step "Phase 4: FUSE Mount"

if [[ "${SKIP_MOUNT:-}" == "1" ]]; then
    scenario_result "cli_smoke_mount_probe" "SKIP" "SKIP_MOUNT=1"
    e2e_skip "mount probe disabled by SKIP_MOUNT=1"
elif [[ ! -e /dev/fuse ]]; then
    scenario_result "cli_smoke_mount_probe" "SKIP" "/dev/fuse not available"
    e2e_skip "/dev/fuse not available"
elif [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
    scenario_result "cli_smoke_mount_probe" "SKIP" "/dev/fuse not accessible"
    e2e_skip "/dev/fuse not accessible"
elif [[ ! -x "$FFS_CLI_BIN" ]]; then
    scenario_result "cli_smoke_mount_probe" "SKIP" "local ffs-cli unavailable at $FFS_CLI_BIN"
    e2e_skip "local ffs-cli unavailable at $FFS_CLI_BIN"
else
    MOUNT_POINT="$E2E_TEMP_DIR/mnt"
    MOUNT_LOG="$E2E_LOG_DIR/smoke_mount.log"
    mkdir -p "$MOUNT_POINT"

    e2e_log "Mounting $TEST_IMAGE to $MOUNT_POINT"

    # Start mount in background
    run_local_cli_capture "$MOUNT_LOG" mount "$TEST_IMAGE" "$MOUNT_POINT" &
    MOUNT_PID=$!
    E2E_MOUNT_POINT="$MOUNT_POINT"

    # Wait for mount
    e2e_log "Waiting for mount to be ready..."
    TIMEOUT=15
    ELAPSED=0
    while ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; do
        sleep 0.5
        ELAPSED=$((ELAPSED + 1))
        if ! kill -0 "$MOUNT_PID" 2>/dev/null; then
            e2e_log "Mount process exited before readiness; tail follows:"
            e2e_run tail -n 120 "$MOUNT_LOG" || true
            if grep -qiE "Permission denied|Operation not permitted" "$MOUNT_LOG"; then
                scenario_result "cli_smoke_mount_probe" "SKIP" "FUSE mount not permitted; log=${MOUNT_LOG}"
                e2e_skip "FUSE mount not permitted in this environment"
            fi
            scenario_result "cli_smoke_mount_probe" "FAIL" "mount exited before readiness; log=${MOUNT_LOG}"
            e2e_fail "Mount exited before becoming ready"
        fi
        if [[ $ELAPSED -ge $((TIMEOUT * 2)) ]]; then
            kill "$MOUNT_PID" 2>/dev/null || true
            scenario_result "cli_smoke_mount_probe" "FAIL" "mount timeout; log=${MOUNT_LOG}"
            e2e_fail "Mount did not become ready within ${TIMEOUT}s"
        fi
    done
    e2e_log "Mount ready (PID: $MOUNT_PID)"

    # Test file operations
    e2e_log ""
    e2e_log "Testing file operations through mount:"

    e2e_log "  ls -la $MOUNT_POINT"
    ls -la "$MOUNT_POINT" 2>&1 | while IFS= read -r line; do e2e_log "    $line"; done

    e2e_log ""
    e2e_log "  find $MOUNT_POINT -maxdepth 2 -type f"
    find "$MOUNT_POINT" -maxdepth 2 -type f 2>&1 | while IFS= read -r line; do e2e_log "    $line"; done

    e2e_log ""
    e2e_run python3 - "$MOUNT_POINT" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
for name, expected in (
    ("readme.txt", b"FrankenFS E2E Test File\n"),
    ("testdir/hello.txt", b"Hello from E2E test!\n"),
):
    actual = (root / name).read_bytes()
    if actual != expected:
        raise SystemExit(f"mounted payload mismatch: {name}: {actual!r}")
    print(f"MOUNTED_READBACK|path={name}|bytes={len(actual)}|matched=true")
PY

    # Unmount
    e2e_log ""
    e2e_log "Unmounting..."
    e2e_unmount "$MOUNT_POINT"

    # Verify unmounted
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        e2e_fail "Failed to unmount $MOUNT_POINT"
    fi
    e2e_log "Unmounted successfully"
    scenario_result "cli_smoke_mount_probe" "PASS" "mount probe completed; log=${MOUNT_LOG}"
fi

#######################################
# Done
#######################################
e2e_pass
