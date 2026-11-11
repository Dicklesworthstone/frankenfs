#!/usr/bin/env bash
# ffs_v12_program_gate_e2e.sh - V1.2 program acceptance rollup (bd-ckivp).
#
# Writes structured per-scenario JSONL plus a program gate manifest under
# artifacts/release_gate/v12/. Cargo-bearing checks route through `rch` when
# `FFS_GATE_EXECUTOR` resolves to `rch`, or through portable local `cargo`
# execution on GitHub-hosted runners when `FFS_GATE_EXECUTOR=local`.

set -euo pipefail

GATE_EXECUTOR="${FFS_GATE_EXECUTOR:-auto}"
SMOKE_MODE="${FFS_V12_PROGRAM_GATE_SMOKE:-0}"
RCH_SELF_CHECK="${FFS_V12_PROGRAM_GATE_RCH_SELF_CHECK:-0}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)
            GATE_EXECUTOR="local"
            shift
            ;;
        --rch)
            GATE_EXECUTOR="rch"
            shift
            ;;
        --executor)
            [[ $# -ge 2 ]] || { echo "missing value for --executor" >&2; exit 2; }
            GATE_EXECUTOR="$2"
            shift 2
            ;;
        --smoke)
            SMOKE_MODE="1"
            shift
            ;;
        --rch-self-check)
            RCH_SELF_CHECK="1"
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

case "$GATE_EXECUTOR" in
    auto)
        if command -v "${RCH_BIN:-rch}" >/dev/null 2>&1; then
            RESOLVED_GATE_EXECUTOR="rch"
        else
            RESOLVED_GATE_EXECUTOR="local"
        fi
        ;;
    rch)
        if [[ "$RCH_SELF_CHECK" != "1" ]] && ! command -v "${RCH_BIN:-rch}" >/dev/null 2>&1; then
            echo "FFS_GATE_EXECUTOR=rch requested, but rch is not installed in PATH" >&2
            exit 2
        fi
        RESOLVED_GATE_EXECUTOR="rch"
        ;;
    local)
        RESOLVED_GATE_EXECUTOR="local"
        ;;
    *)
        echo "invalid FFS_GATE_EXECUTOR='${GATE_EXECUTOR}'; expected auto, rch, or local" >&2
        exit 2
        ;;
esac
export FFS_GATE_EXECUTOR="$RESOLVED_GATE_EXECUTOR"
if [[ "$RESOLVED_GATE_EXECUTOR" == "local" ]]; then
    export FFS_USE_RCH="${FFS_USE_RCH:-0}"
fi

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
if [[ "$RESOLVED_GATE_EXECUTOR" == "rch" ]]; then
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/projects/.cargo-target-frankenfs-v12-program-gate}"
    e2e_rch_add_env_allowlist CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE
else
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${RUNNER_TEMP:-/tmp}/cargo-target-frankenfs-v12-program-gate}"
fi
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"

ARTIFACT_DIR="${FFS_V12_PROGRAM_GATE_ARTIFACT_DIR:-$REPO_ROOT/artifacts/release_gate/v12}"
SCENARIO_DIR="$ARTIFACT_DIR/scenarios"
MANIFEST_JSON="$ARTIFACT_DIR/program_gate_manifest.json"
COMMAND_LOG="$ARTIFACT_DIR/command_transcript.tsv"
DEFAULT_BUDGET_SECS="${FFS_V12_PROGRAM_GATE_SCENARIO_TIMEOUT_SECS:-300}"

PASS_COUNT=0
FAIL_COUNT=0
TIMEOUT_COUNT=0
SKIP_COUNT=0
TOTAL=0
SCENARIO_RECORDS=()

mkdir -p "$SCENARIO_DIR"
printf 'started_at\tscenario\tname\texit_code\tcommand\tstdout\tstderr\n' >"$COMMAND_LOG"

json_quote() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

iso_now() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

tail_text() {
    local path="$1"
    if [[ -f "$path" ]]; then
        tail -c 200 "$path" | tr '\n' ' '
    fi
}

scenario_result() {
    local scenario_id="$1"
    local status="$2"
    local detail="$3"

    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${status}|detail=${detail}"
    if [[ "$status" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

count_active_waiver_rows() {
    local waiver_doc="$1"
    if [[ ! -f "$waiver_doc" ]]; then
        printf '0\n'
        return
    fi
    python3 - "$waiver_doc" <<'PY'
from __future__ import annotations

import pathlib
import sys

path = pathlib.Path(sys.argv[1])
in_active_section = False
count = 0
for line in path.read_text(encoding="utf-8").splitlines():
    stripped = line.strip()
    if stripped == "## Active Waivers":
        in_active_section = True
        continue
    if in_active_section and stripped.startswith("## "):
        break
    if not in_active_section or not stripped.startswith("|"):
        continue
    cells = [cell.strip() for cell in stripped.strip("|").split("|")]
    if not cells or cells[0].lower() == "failure":
        continue
    if all(set(cell) <= {"-", ":", " "} for cell in cells):
        continue
    count += 1
print(count)
PY
}

write_scenario_record() {
    local number="$1"
    local name="$2"
    local status="$3"
    local started_at="$4"
    local finished_at="$5"
    local duration_ms="$6"
    local budget_ms="$7"
    local child_gate_bead="$8"
    local exit_code="$9"
    local stdout_path="${10}"
    local stderr_path="${11}"
    local evidence_paths="${12}"
    local stderr_tail
    stderr_tail="$(tail_text "$stderr_path")"

    local scenario_file="$SCENARIO_DIR/scenario_${number}.jsonl"
    local record_file="$E2E_LOG_DIR/scenario_${number}.json"
    python3 - "$record_file" "$number" "$name" "$status" "$started_at" "$finished_at" \
        "$duration_ms" "$budget_ms" "$child_gate_bead" "$exit_code" "$stderr_tail" \
        "$stdout_path" "$stderr_path" "$evidence_paths" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

(
    record_file,
    number,
    name,
    status,
    started_at,
    finished_at,
    duration_ms,
    budget_ms,
    child_gate_bead,
    exit_code,
    stderr_tail,
    stdout_path,
    stderr_path,
    evidence_paths,
) = sys.argv[1:]

record = {
    "scenario": int(number),
    "name": name,
    "status": status,
    "duration_ms": int(duration_ms),
    "budget_ms": int(budget_ms),
    "started_at": started_at,
    "finished_at": finished_at,
    "evidence_paths": [item for item in evidence_paths.split(";") if item],
    "child_gate_bead": child_gate_bead,
    "exit_code": int(exit_code),
    "stdout_path": stdout_path,
    "stderr_path": stderr_path,
    "stderr_tail": stderr_tail,
}
pathlib.Path(record_file).write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
PY
    cat "$record_file" >>"$scenario_file"
    cat "$record_file"
    SCENARIO_RECORDS+=("$record_file")

    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        TIMEOUT) TIMEOUT_COUNT=$((TIMEOUT_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
        *) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    esac
    TOTAL=$((TOTAL + 1))
    e2e_log "SCENARIO_RESULT|scenario_id=v12_program_gate_${number}|outcome=${status}|detail=${name}"
}

run_scenario_command() {
    local number="$1"
    local name="$2"
    local child_gate_bead="$3"
    local budget_secs="${4:-$DEFAULT_BUDGET_SECS}"
    shift 4

    local stdout_path="$ARTIFACT_DIR/scenario_${number}.stdout"
    local stderr_path="$ARTIFACT_DIR/scenario_${number}.stderr"
    local started_at finished_at started_s finished_s duration_ms budget_ms status exit_code
    local command_text
    started_at="$(iso_now)"
    started_s="$(date +%s)"
    command_text="$*"
    e2e_step "Scenario ${number}: ${name}"

    set +e
    timeout "${budget_secs}s" "$@" >"$stdout_path" 2>"$stderr_path"
    exit_code=$?
    set -e

    finished_at="$(iso_now)"
    finished_s="$(date +%s)"
    duration_ms=$(((finished_s - started_s) * 1000))
    budget_ms=$((budget_secs * 1000))
    if [[ "$exit_code" -eq 0 ]]; then
        status="PASS"
    elif [[ "$exit_code" -eq 124 ]]; then
        status="TIMEOUT"
    else
        status="FAIL"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$started_at" "$number" "$name" "$exit_code" "$command_text" "$stdout_path" "$stderr_path" >>"$COMMAND_LOG"
    write_scenario_record "$number" "$name" "$status" "$started_at" "$finished_at" \
        "$duration_ms" "$budget_ms" "$child_gate_bead" "$exit_code" "$stdout_path" "$stderr_path" \
        "$stdout_path;$stderr_path"
}

run_rch_scenario_command() {
    if [[ "$RESOLVED_GATE_EXECUTOR" == "local" ]]; then
        run_scenario_command "$@"
        return
    fi

    local number="$1"
    local name="$2"
    local child_gate_bead="$3"
    local budget_secs="${4:-$DEFAULT_BUDGET_SECS}"
    shift 4

    local stdout_path="$ARTIFACT_DIR/scenario_${number}.stdout"
    local stderr_path="$ARTIFACT_DIR/scenario_${number}.stderr"
    local started_at finished_at started_s finished_s duration_ms budget_ms status exit_code
    local command_text saved_timeout
    started_at="$(iso_now)"
    started_s="$(date +%s)"
    command_text="$*"
    e2e_step "Scenario ${number}: ${name}"
    : >"$stderr_path"

    saved_timeout="${RCH_COMMAND_TIMEOUT_SECS:-}"
    set +e
    RCH_COMMAND_TIMEOUT_SECS="$budget_secs" e2e_rch_capture "$stdout_path" "$@"
    exit_code=$?
    set -e
    if [[ -n "$saved_timeout" ]]; then
        RCH_COMMAND_TIMEOUT_SECS="$saved_timeout"
    else
        unset RCH_COMMAND_TIMEOUT_SECS
    fi

    finished_at="$(iso_now)"
    finished_s="$(date +%s)"
    duration_ms=$(((finished_s - started_s) * 1000))
    budget_ms=$((budget_secs * 1000))
    if [[ "$exit_code" -eq 0 ]]; then
        status="PASS"
    elif [[ "$exit_code" -eq 124 ]]; then
        status="TIMEOUT"
    else
        status="FAIL"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$started_at" "$number" "$name" "$exit_code" "$command_text" "$stdout_path" "$stderr_path" >>"$COMMAND_LOG"
    write_scenario_record "$number" "$name" "$status" "$started_at" "$finished_at" \
        "$duration_ms" "$budget_ms" "$child_gate_bead" "$exit_code" "$stdout_path" "$stderr_path" \
        "$stdout_path;$stderr_path"
}

run_scenario_check() {
    local number="$1"
    local name="$2"
    local child_gate_bead="$3"
    local expression="$4"
    local started_at finished_at started_s finished_s duration_ms
    local stdout_path="$ARTIFACT_DIR/scenario_${number}.stdout"
    local stderr_path="$ARTIFACT_DIR/scenario_${number}.stderr"
    started_at="$(iso_now)"
    started_s="$(date +%s)"
    e2e_step "Scenario ${number}: ${name}"
    set +e
    bash -c "$expression" >"$stdout_path" 2>"$stderr_path"
    local exit_code=$?
    set -e
    finished_at="$(iso_now)"
    finished_s="$(date +%s)"
    duration_ms=$(((finished_s - started_s) * 1000))
    local status="FAIL"
    [[ "$exit_code" -eq 0 ]] && status="PASS"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$started_at" "$number" "$name" "$exit_code" "$expression" "$stdout_path" "$stderr_path" >>"$COMMAND_LOG"
    write_scenario_record "$number" "$name" "$status" "$started_at" "$finished_at" \
        "$duration_ms" "$((DEFAULT_BUDGET_SECS * 1000))" "$child_gate_bead" "$exit_code" \
        "$stdout_path" "$stderr_path" "$stdout_path;$stderr_path"
}

run_smoke_mode() {
    run_scenario_check 1 "synthetic PASS fixture" "bd-ckivp" "printf 'synthetic pass\n'"
    if [[ "${FFS_V12_PROGRAM_GATE_SMOKE_EXPECT_FAIL:-0}" == "1" ]]; then
        run_scenario_check 2 "synthetic FAIL fixture" "bd-ckivp" "printf 'synthetic fail\n' >&2; exit 42"
    else
        run_scenario_check 2 "synthetic second PASS fixture" "bd-ckivp" "printf 'synthetic pass 2\n'"
    fi
}

write_fake_rch() {
    local fake_rch="$1"
    cat >"$fake_rch" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

mode="${FFS_V12_PROGRAM_GATE_FAKE_RCH_MODE:-complete}"

if [[ "${1:-}" == "exec" && "${2:-}" == "--" ]]; then
    case "$mode" in
        complete)
            printf '[RCH] remote worker=fake-v12-program-gate\n'
            printf 'Remote command finished: exit=0\n'
            exit 0
            ;;
        local_fallback)
            printf '[RCH] local (remote execution failed)\n'
            printf 'Remote command finished: exit=0\n'
            exit 0
            ;;
        missing_remote_evidence)
            printf 'fake rch completed without remote proof\n'
            exit 0
            ;;
        *)
            printf 'unsupported fake rch mode: %s\n' "$mode" >&2
            exit 2
            ;;
    esac
fi

if [[ "${1:-}" == "queue" && "${2:-}" == "--json" ]]; then
    printf '{"data":{"active_builds":[]}}\n'
    exit 0
fi

if [[ "${1:-}" == "cancel" ]]; then
    exit 0
fi

printf 'unsupported fake rch invocation: %s\n' "$*" >&2
exit 2
SH
    chmod +x "$fake_rch"
}

run_rch_fixture_probe() {
    local scenario_id="$1"
    local mode="$2"
    local expected_status="$3"
    local expected_marker="$4"
    local probe_dir="$E2E_TEMP_DIR/v12_rch_${mode}_probe"
    local fake_rch="$probe_dir/rch"
    local output_path="$probe_dir/rch_capture.log"
    local status=0

    mkdir -p "$probe_dir"
    write_fake_rch "$fake_rch"

    set +e
    FFS_V12_PROGRAM_GATE_FAKE_RCH_MODE="$mode" \
        RCH_BIN="$fake_rch" \
        RCH_COMMAND_TIMEOUT_SECS=15 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=0 \
        e2e_rch_capture "$output_path" cargo test -p fake-v12-program-gate --lib
    status=$?
    set -e

    if [[ "$status" -eq "$expected_status" ]] && grep -Fq "$expected_marker" "$output_path"; then
        scenario_result "$scenario_id" "PASS" "mode=${mode} status=${status} output=${output_path}"
    else
        scenario_result "$scenario_id" "FAIL" "mode=${mode} status=${status} expected=${expected_status} marker=${expected_marker} output=${output_path}"
    fi
}

run_rch_self_check() {
    local forbidden_pattern

    forbidden_pattern='${RCH_BIN:-rch}'
    forbidden_pattern="\"${forbidden_pattern}\" exec -- cargo"
    e2e_step "V1.2 RCH capture fixture self-check"
    if grep -F "$forbidden_pattern" "$0" | grep -v "forbidden_pattern" >/dev/null; then
        scenario_result "v12_program_gate_uses_shared_rch_capture" "FAIL" "cargo-bearing lanes still call rch exec directly"
    else
        scenario_result "v12_program_gate_uses_shared_rch_capture" "PASS" "cargo-bearing lanes use run_rch_scenario_command"
    fi
    run_rch_fixture_probe "v12_program_gate_fixture_complete_self_check" \
        "complete" 0 "Remote command finished: exit=0"
    run_rch_fixture_probe "v12_program_gate_fixture_local_fallback_self_check" \
        "local_fallback" 99 "RCH_LOCAL_FALLBACK_REJECTED"
    run_rch_fixture_probe "v12_program_gate_fixture_missing_remote_evidence_self_check" \
        "missing_remote_evidence" 99 "RCH_REMOTE_EVIDENCE_MISSING"
}

run_full_mode() {
    run_rch_scenario_command 1 "bd-m5wf.1.7 performance optimization gate" "bd-m5wf.1.7" "$DEFAULT_BUDGET_SECS" \
        cargo test -p ffs-harness --lib perf_comparison -- --nocapture
    run_rch_scenario_command 2 "bd-m5wf.2.5 writeback-cache gate" "bd-m5wf.2.5" "$DEFAULT_BUDGET_SECS" \
        cargo test -p ffs-core writeback -- --nocapture
    run_rch_scenario_command 3 "bd-m5wf.3.5 safe-merge high-contention gate" "bd-m5wf.3.5" "$DEFAULT_BUDGET_SECS" \
        cargo test -p ffs-mvcc --test mvcc_stress_suite verification_gate_safe_merge_correctness_under_high_contention -- --nocapture
    run_rch_scenario_command 4 "bd-m5wf.4.5 adaptive refresh gate" "bd-m5wf.4.5" "$DEFAULT_BUDGET_SECS" \
        cargo test -p ffs-repair verification_gate_hybrid -- --nocapture
    run_scenario_command 5 "bd-m5wf.5.5 multi-host repair gate" "bd-m5wf.5.5" "$DEFAULT_BUDGET_SECS" \
        ./scripts/e2e/ffs_repair_recovery_smoke.sh
    run_rch_scenario_command 6 "bd-m5wf.6.5 btrfs multi-device and subvolume gate" "bd-m5wf.6.5" "$DEFAULT_BUDGET_SECS" \
        cargo test -p ffs-core btrfs_subvolume -- --nocapture
    run_scenario_command 7 "bd-m5wf.7.5 xfstests conformance regression gate" "bd-m5wf.7.5" "$DEFAULT_BUDGET_SECS" \
        ./scripts/e2e/ffs_xfstests_regression_gate.sh
    run_scenario_command 8 "bd-m5wf.8.7 observability metrics and dashboard gate" "bd-m5wf.8.7" "$DEFAULT_BUDGET_SECS" \
        ./scripts/e2e/ffs_operator_tooling_gate_e2e.sh
    run_scenario_command 9 "bd-m5wf.9.5 coverage hardening gate" "bd-m5wf.9.5" "$DEFAULT_BUDGET_SECS" \
        ./scripts/e2e/ffs_verification_gate_e2e.sh
    run_rch_scenario_command 10 "workspace format gate" "bd-ckivp" "$DEFAULT_BUDGET_SECS" \
        cargo fmt --check
    run_rch_scenario_command 11 "workspace clippy gate" "bd-ckivp" "$DEFAULT_BUDGET_SECS" \
        cargo clippy --workspace --all-targets -- -D warnings
    run_rch_scenario_command 12 "workspace tests no-fail-fast gate" "bd-ckivp" "$DEFAULT_BUDGET_SECS" \
        cargo test --workspace --no-fail-fast
    run_scenario_check 13 "CLI ergonomics evidence" "bd-ckivp" \
        "grep -q '\"mount\"' crates/ffs-cli/src/main.rs && grep -q '\"repair\"' crates/ffs-cli/src/main.rs && grep -q '\"evidence\"' crates/ffs-cli/src/main.rs && grep -q '\"mkfs\"' crates/ffs-cli/src/main.rs"
    run_scenario_check 14 "structured logging traceability evidence" "bd-ckivp" \
        "grep -q 'degradation_transition' crates/ffs-core/src/degradation.rs && grep -q 'wal_replay_start' crates/ffs-mvcc/src/wal_replay.rs && grep -q 'repair_complete' crates/ffs-cli/src/cmd_repair.rs && grep -q 'evidence_preset' crates/ffs-cli/src/cmd_evidence.rs"
}

write_manifest() {
    local recommendation="PROCEED"
    local reason="all scenarios passed"
    local waiver_path="docs/release/V1.2_test_waivers.md"
    local active_waiver_count
    active_waiver_count="$(count_active_waiver_rows "$REPO_ROOT/$waiver_path")"
    if [[ "$FAIL_COUNT" -gt 0 || "$TIMEOUT_COUNT" -gt 0 ]]; then
        recommendation="NO-PROCEED"
        reason="${FAIL_COUNT} failed, ${TIMEOUT_COUNT} timed out"
    elif [[ "$active_waiver_count" -gt 0 ]]; then
        recommendation="PASS-WITH-WAIVERS"
        reason="all scenarios passed with ${active_waiver_count} active waiver(s)"
    fi

    local records_json="$E2E_LOG_DIR/scenario_records.json"
    python3 - "$records_json" "${SCENARIO_RECORDS[@]}" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

records = []
for item in sys.argv[2:]:
    records.append(json.loads(pathlib.Path(item).read_text(encoding="utf-8")))
pathlib.Path(sys.argv[1]).write_text(json.dumps(records, sort_keys=True), encoding="utf-8")
PY

    local git_head kernel rustc cargo_version package_version
    git_head="$(git rev-parse HEAD)"
    kernel="$(uname -srmo 2>/dev/null || uname -a)"
    rustc="$("${RUSTC_BIN:-rustc}" --version 2>/dev/null || printf 'rustc unavailable')"
    cargo_version="$("${CARGO_BIN:-cargo}" --version 2>/dev/null || printf 'cargo unavailable')"
    package_version="$(sed -n 's/^version = \"\\(.*\\)\"/\\1/p' crates/ffs-harness/Cargo.toml | head -1)"

    python3 - "$MANIFEST_JSON" "$records_json" "$recommendation" "$reason" "$git_head" \
        "$kernel" "$rustc" "$cargo_version" "$package_version" "$RESOLVED_GATE_EXECUTOR" \
        "$COMMAND_LOG" "$waiver_path" "$active_waiver_count" "$PASS_COUNT" "$FAIL_COUNT" \
        "$TIMEOUT_COUNT" "$SKIP_COUNT" "$TOTAL" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timezone

(
    out_path,
    records_path,
    recommendation,
    reason,
    git_head,
    kernel,
    rustc,
    cargo_version,
    package_version,
    executor_mode,
    command_log,
    waiver_path,
    active_waiver_count,
    pass_count,
    fail_count,
    timeout_count,
    skip_count,
    total,
) = sys.argv[1:]

records = json.loads(pathlib.Path(records_path).read_text(encoding="utf-8"))
payload = {
    "schema_version": 1,
    "gate_id": "bd-ckivp-v12-program-gate",
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "git_head": git_head,
    "environment": {
        "kernel": kernel,
        "rustc": rustc,
        "cargo": cargo_version,
        "ffs_harness_version": package_version,
        "executor_mode": executor_mode,
    },
    "scenario_count": int(total),
    "pass_count": int(pass_count),
    "fail_count": int(fail_count),
    "timeout_count": int(timeout_count),
    "skip_count": int(skip_count),
    "scenarios": records,
    "release_recommendation": recommendation,
    "release_recommendation_reason": reason,
    "command_transcript": command_log,
    "waiver_document": waiver_path,
    "active_waiver_count": int(active_waiver_count),
}
pathlib.Path(out_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    e2e_log "V1.2 program gate manifest: $MANIFEST_JSON"
    e2e_log "RELEASE RECOMMENDATION: $recommendation"
    e2e_log "Reason: $reason"
}

e2e_init "ffs_v12_program_gate"
e2e_print_env

if [[ "$RCH_SELF_CHECK" == "1" ]]; then
    run_rch_self_check
    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        e2e_fail "ffs_v12_program_gate RCH self-check failed: ${FAIL_COUNT} failed"
    else
        e2e_pass "ffs_v12_program_gate RCH self-check completed"
    fi
    exit 0
fi

if [[ "$SMOKE_MODE" == "1" ]]; then
    run_smoke_mode
else
    run_full_mode
fi

write_manifest

if [[ "$FAIL_COUNT" -gt 0 || "$TIMEOUT_COUNT" -gt 0 ]]; then
    e2e_fail "ffs_v12_program_gate NO-PROCEED: ${FAIL_COUNT} failed, ${TIMEOUT_COUNT} timed out"
else
    e2e_pass "ffs_v12_program_gate completed"
fi
