#!/usr/bin/env bash
# ffs_xfstests_e2e.sh - xfstests subset planning/execution for FrankenFS
#
# This suite tracks a curated generic/ext4 subset for FrankenFS and can:
# - plan mode: validate list files + emit subset artifacts
# - run mode: invoke xfstests `check` against the selected subset
#
# Defaults are intentionally CI-safe:
# - `XFSTESTS_MODE=auto` resolves to plan mode unless a usable xfstests tree is found.
# - `XFSTESTS_STRICT=0` causes missing prerequisites to skip (exit 0) with artifacts.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

e2e_init "ffs_xfstests_e2e"
e2e_print_env

XFSTESTS_MODE="${XFSTESTS_MODE:-auto}"        # auto | plan | run
XFSTESTS_STRICT="${XFSTESTS_STRICT:-0}"       # 0 | 1
XFSTESTS_DRY_RUN="${XFSTESTS_DRY_RUN:-1}"     # 0 | 1 (run mode only)
XFSTESTS_FILTER="${XFSTESTS_FILTER:-all}"     # all | generic | ext4 | btrfs
XFSTESTS_DIR="${XFSTESTS_DIR:-}"
XFSTESTS_GENERIC_LIST="${XFSTESTS_GENERIC_LIST:-$REPO_ROOT/scripts/e2e/xfstests_generic.list}"
XFSTESTS_EXT4_LIST="${XFSTESTS_EXT4_LIST:-$REPO_ROOT/scripts/e2e/xfstests_ext4.list}"
XFSTESTS_BTRFS_LIST="${XFSTESTS_BTRFS_LIST:-$REPO_ROOT/scripts/e2e/xfstests_btrfs.list}"
XFSTESTS_REGRESSION_GUARD_JSON="${XFSTESTS_REGRESSION_GUARD_JSON:-$REPO_ROOT/scripts/e2e/xfstests_regression_guard.json}"
XFSTESTS_ALLOWLIST_JSON="${XFSTESTS_ALLOWLIST_JSON:-$REPO_ROOT/scripts/e2e/xfstests_allowlist.json}"
XFSTESTS_BASELINE_JSON="${XFSTESTS_BASELINE_JSON:-}"
XFSTESTS_PREFLIGHT_SCRIPT="${XFSTESTS_PREFLIGHT_SCRIPT:-$REPO_ROOT/scripts/e2e/ffs_xfstests_preflight_e2e.sh}"
XFSTESTS_PREFLIGHT_MAX_AGE_SECS="${XFSTESTS_PREFLIGHT_MAX_AGE_SECS:-3600}"
XFSTESTS_INVOKE_CHECK_DRY_RUN="${XFSTESTS_INVOKE_CHECK_DRY_RUN:-0}"
XFSTESTS_REAL_RUN_ACK="${XFSTESTS_REAL_RUN_ACK:-}"
XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE="${XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE:-0}"
FFS_HARNESS_BIN="${FFS_HARNESS_BIN:-$REPO_ROOT/target/debug/ffs-harness}"

ARTIFACT_DIR="$E2E_LOG_DIR/xfstests"
SELECTED_FILE="$ARTIFACT_DIR/selected_tests.txt"
SUMMARY_JSON="$ARTIFACT_DIR/summary.json"
RESULTS_JSON="$ARTIFACT_DIR/results.json"
JUNIT_FILE="$ARTIFACT_DIR/junit.xml"
CHECK_LOG="$ARTIFACT_DIR/check.log"
POLICY_PLAN_JSON="$ARTIFACT_DIR/policy_plan.json"
POLICY_REPORT_MD="$ARTIFACT_DIR/policy_report.md"
BASELINE_MANIFEST_JSON="$ARTIFACT_DIR/baseline_manifest.json"
BASELINE_REPORT_MD="$ARTIFACT_DIR/baseline_report.md"
FAILURE_TRIAGE_JSON="$ARTIFACT_DIR/failure_triage.json"
FAILURE_TRIAGE_REPORT_MD="$ARTIFACT_DIR/failure_triage.md"
SYNTHETIC_TRIAGE_DIR="$ARTIFACT_DIR/synthetic_failure_triage"
XFSTESTS_PREFLIGHT_JSON="${XFSTESTS_PREFLIGHT_JSON:-$ARTIFACT_DIR/preflight.json}"
mkdir -p "$ARTIFACT_DIR"
if [[ -n "${XFSTESTS_RESULTS_PATH_OUT:-}" ]]; then
    printf '%s\n' "$RESULTS_JSON" >"$XFSTESTS_RESULTS_PATH_OUT"
fi
RESULT_BASE="${RESULT_BASE:-$ARTIFACT_DIR/raw_xfstests}"
export RESULT_BASE
XFSTESTS_CLEANUP_STATUS="not_started"
XFSTESTS_PARTIAL_RUN_STATUS="not_started"
XFSTESTS_PREFLIGHT_ACCEPTED="0"
XFSTESTS_SUBSET_VERSION="${XFSTESTS_SUBSET_VERSION:-xfstests-curated-v1}"
XFSTESTS_BASELINE_ID="${XFSTESTS_BASELINE_ID:-xfstests-baseline-$(basename "$E2E_LOG_DIR")}"

declare -a GENERIC_TESTS=()
declare -a EXT4_TESTS=()
declare -a BTRFS_TESTS=()
declare -a SELECTED_TESTS=()
EFFECTIVE_MODE="$XFSTESTS_MODE"
LAST_CHECK_RC="null"

harness_supports_xfstests_report() {
    [[ -x "$FFS_HARNESS_BIN" ]] || return 1
    "$FFS_HARNESS_BIN" help 2>&1 | grep -Fq "xfstests-report"
}

harness_supports_xfstests_failure_triage() {
    [[ -x "$FFS_HARNESS_BIN" ]] || return 1
    "$FFS_HARNESS_BIN" help 2>&1 | grep -Fq "xfstests-failure-triage"
}

resolve_xfstests_dir() {
    if [[ -n "$XFSTESTS_DIR" ]]; then
        return 0
    fi

    local candidate
    for candidate in \
        "$REPO_ROOT/third_party/xfstests-dev" \
        "/opt/xfstests-dev" \
        "$HOME/src/xfstests-dev"; do
        if [[ -x "$candidate/check" ]]; then
            XFSTESTS_DIR="$candidate"
            return 0
        fi
    done
}

write_summary() {
    local status="$1"
    local mode="$2"
    local reason="${3:-}"
    local check_rc="${4:-null}"
    local safe_reason="${reason//\"/\\\"}"
    local safe_dir="${XFSTESTS_DIR//\"/\\\"}"
    local safe_guard="${XFSTESTS_REGRESSION_GUARD_JSON//\"/\\\"}"
    local safe_allowlist="${XFSTESTS_ALLOWLIST_JSON//\"/\\\"}"
    local safe_baseline="${XFSTESTS_BASELINE_JSON//\"/\\\"}"
    local safe_results="${RESULTS_JSON//\"/\\\"}"
    local safe_junit="${JUNIT_FILE//\"/\\\"}"
    local safe_selected="${SELECTED_FILE//\"/\\\"}"
    local safe_check_log="${CHECK_LOG//\"/\\\"}"
    local safe_policy_plan="${POLICY_PLAN_JSON//\"/\\\"}"
    local safe_policy_report="${POLICY_REPORT_MD//\"/\\\"}"
    local safe_baseline_manifest="${BASELINE_MANIFEST_JSON//\"/\\\"}"
    local safe_baseline_report="${BASELINE_REPORT_MD//\"/\\\"}"
    local safe_failure_triage="${FAILURE_TRIAGE_JSON//\"/\\\"}"
    local safe_failure_triage_report="${FAILURE_TRIAGE_REPORT_MD//\"/\\\"}"
    local safe_synthetic_triage_dir="${SYNTHETIC_TRIAGE_DIR//\"/\\\"}"
    local safe_preflight="${XFSTESTS_PREFLIGHT_JSON//\"/\\\"}"
    local safe_summary="${SUMMARY_JSON//\"/\\\"}"
    local safe_result_base="${RESULT_BASE//\"/\\\"}"
    local safe_run_log="${E2E_LOG_FILE//\"/\\\"}"
    local safe_stdout="${ARTIFACT_DIR//\"/\\\"}/stdout.log"
    local safe_stderr="${ARTIFACT_DIR//\"/\\\"}/stderr.log"
    local safe_preflight_stdout="${ARTIFACT_DIR//\"/\\\"}/preflight.stdout"
    local safe_preflight_stderr="${ARTIFACT_DIR//\"/\\\"}/preflight.stderr"
    local safe_fstyp="${FSTYP:-}"
    safe_fstyp="${safe_fstyp//\"/\\\"}"
    local safe_test_dev="${TEST_DEV:-}"
    safe_test_dev="${safe_test_dev//\"/\\\"}"
    local safe_scratch_dev="${SCRATCH_DEV:-}"
    safe_scratch_dev="${safe_scratch_dev//\"/\\\"}"
    local safe_test_dir="${TEST_DIR:-}"
    safe_test_dir="${safe_test_dir//\"/\\\"}"
    local safe_scratch_mnt="${SCRATCH_MNT:-}"
    safe_scratch_mnt="${safe_scratch_mnt//\"/\\\"}"
    local safe_mount_options="${MOUNT_OPTIONS:-}"
    safe_mount_options="${safe_mount_options//\"/\\\"}"
    local safe_cleanup="${XFSTESTS_CLEANUP_STATUS//\"/\\\"}"
    local safe_partial="${XFSTESTS_PARTIAL_RUN_STATUS//\"/\\\"}"
    local worker_identity="${RCH_WORKER_IDENTITY:-${RCH_WORKER:-local:$(hostname -s 2>/dev/null || printf unknown)}}"
    local safe_worker="${worker_identity//\"/\\\"}"
    local command_plan="./check"
    if [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        command_plan+=" -n"
    fi
    command_plan+=" ${SELECTED_TESTS[*]}"
    local safe_command_plan="${command_plan//\"/\\\"}"
    local repro_command="XFSTESTS_MODE=$XFSTESTS_MODE XFSTESTS_FILTER=$XFSTESTS_FILTER XFSTESTS_DRY_RUN=$XFSTESTS_DRY_RUN XFSTESTS_STRICT=$XFSTESTS_STRICT ./scripts/e2e/ffs_xfstests_e2e.sh"
    local safe_repro_command="${repro_command//\"/\\\"}"
    local side_effect_policy="permissioned_real_xfstests_may_mutate_test_and_scratch_devices"
    if [[ "$XFSTESTS_DRY_RUN" == "1" && "$XFSTESTS_INVOKE_CHECK_DRY_RUN" != "1" ]]; then
        side_effect_policy="safe_dry_run_no_xfstests_check_no_mount_no_mkfs"
    elif [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        side_effect_policy="legacy_check_n_may_validate_mount_or_mkfs_prereqs"
    fi

    cat >"$SUMMARY_JSON" <<EOF
{
  "status": "$status",
  "mode": "$mode",
  "filter": "$XFSTESTS_FILTER",
  "dry_run": $XFSTESTS_DRY_RUN,
  "strict": $XFSTESTS_STRICT,
  "check_rc": $check_rc,
  "xfstests_dir": "$safe_dir",
  "regression_guard_json": "$safe_guard",
  "allowlist_json": "$safe_allowlist",
  "baseline_json": "$safe_baseline",
  "selected_file": "$safe_selected",
  "results_json": "$safe_results",
  "junit_xml": "$safe_junit",
  "check_log": "$safe_check_log",
  "preflight_json": "$safe_preflight",
  "policy_plan_json": "$safe_policy_plan",
  "policy_report_md": "$safe_policy_report",
  "baseline_manifest_json": "$safe_baseline_manifest",
  "baseline_report_md": "$safe_baseline_report",
  "failure_triage_json": "$safe_failure_triage",
  "failure_triage_report_md": "$safe_failure_triage_report",
  "synthetic_failure_triage_dir": "$safe_synthetic_triage_dir",
  "run_log": "$safe_run_log",
  "stdout_log": "$safe_stdout",
  "stderr_log": "$safe_stderr",
  "preflight_stdout": "$safe_preflight_stdout",
  "preflight_stderr": "$safe_preflight_stderr",
  "raw_xfstests_result_base": "$safe_result_base",
  "worker_identity": "$safe_worker",
  "cleanup_status": "$safe_cleanup",
  "partial_run_preservation": "$safe_partial",
  "side_effect_policy": "$side_effect_policy",
  "image_setup": {
    "fstyp": "$safe_fstyp",
    "test_dev": "$safe_test_dev",
    "scratch_dev": "$safe_scratch_dev",
    "test_dir": "$safe_test_dir",
    "scratch_mnt": "$safe_scratch_mnt",
    "mount_options": "$safe_mount_options",
    "result_base": "$safe_result_base"
  },
  "command_plan": "$safe_command_plan",
  "reproduction_command": "$safe_repro_command",
  "artifact_paths": {
    "selected_file": "$safe_selected",
    "results_json": "$safe_results",
    "junit_xml": "$safe_junit",
    "check_log": "$safe_check_log",
    "preflight_json": "$safe_preflight",
    "policy_plan_json": "$safe_policy_plan",
    "policy_report_md": "$safe_policy_report",
    "baseline_manifest_json": "$safe_baseline_manifest",
    "baseline_report_md": "$safe_baseline_report",
    "failure_triage_json": "$safe_failure_triage",
    "failure_triage_report_md": "$safe_failure_triage_report",
    "synthetic_failure_triage_dir": "$safe_synthetic_triage_dir",
    "summary_json": "$safe_summary",
    "run_log": "$safe_run_log",
    "stdout_log": "$safe_stdout",
    "stderr_log": "$safe_stderr",
    "raw_xfstests_result_base": "$safe_result_base"
  },
  "generic_count": ${#GENERIC_TESTS[@]},
  "ext4_count": ${#EXT4_TESTS[@]},
  "btrfs_count": ${#BTRFS_TESTS[@]},
  "selected_count": ${#SELECTED_TESTS[@]},
  "reason": "$safe_reason"
}
EOF
}

write_policy_plan() {
    if ! command -v python3 >/dev/null 2>&1; then
        e2e_fail "python3 is required to validate and emit xfstests policy plan"
    fi

    python3 - "$SELECTED_FILE" "$XFSTESTS_ALLOWLIST_JSON" "$POLICY_PLAN_JSON" "$POLICY_REPORT_MD" "$ARTIFACT_DIR" "$XFSTESTS_FILTER" "$XFSTESTS_DRY_RUN" "$XFSTESTS_MODE" "$XFSTESTS_DIR" <<'PY'
import json
import pathlib
import sys
from collections import Counter

selected_file = pathlib.Path(sys.argv[1])
policy_file = pathlib.Path(sys.argv[2])
policy_plan = pathlib.Path(sys.argv[3])
policy_report = pathlib.Path(sys.argv[4])
artifact_dir = pathlib.Path(sys.argv[5])
xfstests_filter = sys.argv[6]
dry_run = sys.argv[7]
requested_mode = sys.argv[8]
xfstests_dir = sys.argv[9]

selected = [line.strip() for line in selected_file.read_text(encoding="utf-8").splitlines() if line.strip()]
policy_entries = json.loads(policy_file.read_text(encoding="utf-8"))
policy_by_id = {}
errors = []
required_fields = [
    "policy_row_id",
    "test_id",
    "filesystem_flavor",
    "v1_scope_mapping",
    "expected_operation_class",
    "user_risk_category",
    "expected_outcome",
    "selection_decision",
    "status",
    "classification",
    "failure_reason",
    "tracker_id",
    "repro_command",
]
required_artifacts = {
    "selected_tests.txt",
    "policy_plan.json",
    "policy_report.md",
    "summary.json",
    "results.json",
    "junit.xml",
    "check.log",
}
allowed_plan_lanes = {
    "dry_run_only",
    "fixture_only",
    "permissioned_real",
    "host_skip",
    "unsupported_by_scope",
}
allowed_plan_privileges = {
    "none",
    "user_mount",
    "fuse_mount",
    "root_required",
    "cap_sys_admin",
    "scratch_device",
    "host_tooling",
}
allowed_plan_outcomes = {
    "dry_run_only",
    "fixture_only",
    "permissioned_real",
    "host_skip",
    "unsupported_by_scope",
    "product_failure",
    "harness_failure",
    "cleanup_failure",
}

def is_temp_path(value):
    return isinstance(value, str) and (
        value.startswith("${TMPDIR:-/tmp}/frankenfs-xfstests/")
        or value.startswith("$TMPDIR/frankenfs-xfstests/")
        or value.startswith("/tmp/frankenfs-xfstests/")
    )

def is_broad_shell_token(value):
    return value in {"sh", "bash", "zsh", "-c", "shell"} or any(
        token in value for token in ["&&", ";", "*"]
    )

def command_plan_test_fragment(test_id):
    return test_id.replace("/", "-")

def has_unsafe_cleanup_action(value):
    if not isinstance(value, str):
        return True
    lower = value.lower()
    return any(
        token in lower
        for token in ["rm ", "rm-", "rm\t", "rm -", "delete /", "remove /", "/*", "$(", "`", "&&", "||"]
    )

def validate_temp_path(test_id, field, value):
    if not is_temp_path(value):
        return f"policy {test_id} command plan has non-temporary {field}"
    test_fragment = command_plan_test_fragment(test_id)
    if test_fragment not in value:
        return f"policy {test_id} command plan {field} lacks test id fragment {test_fragment}"
    return None

def validate_command_plan(test_id, plan):
    plan_errors = []
    if not isinstance(plan, dict):
        return [f"policy {test_id} missing command_plan"]

    for field in [
        "plan_id",
        "execution_lane",
        "image_path",
        "scratch_path",
        "mountpoint",
        "test_device",
        "scratch_device",
        "image_hash",
        "helper_binaries",
        "required_privileges",
        "mutation_surface",
        "cleanup_action",
        "argv",
        "expected_plan_outcome",
        "command_summary",
    ]:
        value = plan.get(field)
        if value is None or value == "":
            plan_errors.append(f"policy {test_id} command plan missing {field}")

    if not str(plan.get("plan_id", "")).startswith("xfstests-plan-"):
        plan_errors.append(f"policy {test_id} command plan has malformed plan_id")
    if plan.get("execution_lane") not in allowed_plan_lanes:
        plan_errors.append(f"policy {test_id} command plan has unknown execution_lane")
    for field in ["image_path", "scratch_path", "mountpoint", "test_device", "scratch_device"]:
        path_error = validate_temp_path(test_id, field, plan.get(field))
        if path_error:
            plan_errors.append(path_error)
    if not str(plan.get("image_hash", "")).startswith("sha256:"):
        plan_errors.append(f"policy {test_id} command plan missing image_hash")

    helpers = plan.get("helper_binaries", [])
    if not isinstance(helpers, list) or not helpers:
        plan_errors.append(f"policy {test_id} command plan missing helper_binaries")
        helpers = []
    for helper in helpers:
        if not isinstance(helper, str) or not helper or "<" in helper or is_broad_shell_token(helper):
            plan_errors.append(f"policy {test_id} command plan has unresolved helper binary")

    privileges = plan.get("required_privileges", [])
    if not isinstance(privileges, list) or not privileges:
        plan_errors.append(f"policy {test_id} command plan missing required_privileges")
        privileges = []
    for privilege in privileges:
        if privilege not in allowed_plan_privileges:
            plan_errors.append(f"policy {test_id} command plan has unknown privilege {privilege}")

    if has_unsafe_cleanup_action(plan.get("cleanup_action")):
        plan_errors.append(f"policy {test_id} command plan has unsafe cleanup_action")

    argv = plan.get("argv", [])
    if not isinstance(argv, list) or not argv:
        plan_errors.append(f"policy {test_id} command plan missing argv")
        argv = []
    if test_id not in argv:
        plan_errors.append(f"policy {test_id} command plan argv does not name the test id")
    for arg in argv:
        if not isinstance(arg, str) or is_broad_shell_token(arg):
            plan_errors.append(f"policy {test_id} command plan has broad shell command token")

    if plan.get("expected_plan_outcome") not in allowed_plan_outcomes:
        plan_errors.append(f"policy {test_id} command plan has unknown expected_plan_outcome")
    if plan.get("destructive") and plan.get("execution_lane") != "permissioned_real":
        plan_errors.append(f"policy {test_id} command plan marks destructive action outside permissioned_real lane")

    return plan_errors

for entry in policy_entries:
    test_id = entry.get("test_id")
    if not isinstance(test_id, str) or not test_id:
        errors.append("policy entry missing test_id")
        continue
    if test_id in policy_by_id:
        errors.append(f"duplicate policy id: {test_id}")
    policy_by_id[test_id] = entry
    for field in required_fields:
        value = entry.get(field)
        if value is None or value == "":
            errors.append(f"policy {test_id} missing {field}")
    artifacts = entry.get("artifact_requirements")
    if not isinstance(artifacts, list):
        errors.append(f"policy {test_id} missing artifact_requirements")
        artifacts = []
    missing_artifacts = sorted(required_artifacts - {item for item in artifacts if isinstance(item, str)})
    for artifact in missing_artifacts:
        errors.append(f"policy {test_id} missing artifact requirement: {artifact}")
    errors.extend(validate_command_plan(test_id, entry.get("command_plan")))

selected_set = set(selected)
for test_id in selected:
    if test_id not in policy_by_id:
        errors.append(f"selected xfstests id lacks policy metadata: {test_id}")

for test_id in sorted(policy_by_id):
    if xfstests_filter == "all" and test_id not in selected_set:
        errors.append(f"policy references unselected xfstests id: {test_id}")

check_argv = ["./check"]
if dry_run == "1":
    check_argv.append("-n")
check_argv.extend(selected)

tests = []
capabilities = set()
status_counts = Counter()
classification_counts = Counter()
outcome_counts = Counter()
operation_counts = Counter()
flavor_counts = Counter()
lane_counts = Counter()
plan_outcome_counts = Counter()
command_plans = []
artifact_paths = {
    "selected_file": str(artifact_dir / "selected_tests.txt"),
    "results_json": str(artifact_dir / "results.json"),
    "junit_xml": str(artifact_dir / "junit.xml"),
    "check_log": str(artifact_dir / "check.log"),
    "summary_json": str(artifact_dir / "summary.json"),
    "policy_plan_json": str(policy_plan),
    "policy_report_md": str(policy_report),
    "failure_triage_json": str(artifact_dir / "failure_triage.json"),
    "failure_triage_report_md": str(artifact_dir / "failure_triage.md"),
}
for test_id in selected:
    entry = policy_by_id.get(test_id, {})
    command_plan = entry.get("command_plan", {})
    required = [cap for cap in entry.get("required_capabilities", []) if isinstance(cap, str)]
    capabilities.update(required)
    status = entry.get("status", "missing_policy")
    classification = entry.get("classification")
    expected_outcome = entry.get("expected_outcome")
    operation_class = entry.get("expected_operation_class")
    filesystem_flavor = entry.get("filesystem_flavor", test_id.split("/", 1)[0])
    status_counts[status] += 1
    classification_counts[classification or "missing"] += 1
    outcome_counts[expected_outcome or "missing"] += 1
    operation_counts[operation_class or "missing"] += 1
    flavor_counts[filesystem_flavor or "missing"] += 1
    lane_counts[command_plan.get("execution_lane", "missing")] += 1
    plan_outcome_counts[command_plan.get("expected_plan_outcome", "missing")] += 1
    command_plans.append(command_plan)
    for tag in entry.get("operation_class_tags", []):
        if isinstance(tag, str):
            operation_counts[tag] += 1
    skip_reason = None if status == "expected_pass" else entry.get("failure_reason")
    tests.append({
        "policy_row_id": entry.get("policy_row_id"),
        "test_id": test_id,
        "filesystem_flavor": filesystem_flavor,
        "v1_scope_mapping": entry.get("v1_scope_mapping"),
        "expected_operation_class": operation_class,
        "operation_class_tags": entry.get("operation_class_tags", []),
        "user_risk_category": entry.get("user_risk_category"),
        "expected_outcome": expected_outcome,
        "selection_decision": entry.get("selection_decision"),
        "status": status,
        "classification": classification,
        "required_capabilities": required,
        "artifact_requirements": entry.get("artifact_requirements", []),
        "skip_decision": {
            "status": status,
            "reason": skip_reason,
        },
        "scope_reference": entry.get("scope_reference"),
        "tracker_id": entry.get("tracker_id"),
        "repro_command": entry.get(
            "repro_command",
            f"XFSTESTS_MODE=run XFSTESTS_DRY_RUN={dry_run} ./scripts/e2e/ffs_xfstests_e2e.sh",
        ),
        "command_plan": command_plan,
        "log_fields": {
            "source_xfstests_id": test_id,
            "command_plan_id": command_plan.get("plan_id"),
            "policy_row_id": entry.get("policy_row_id"),
            "filesystem_flavor": filesystem_flavor,
            "risk_category": entry.get("user_risk_category"),
            "selected_or_skipped": entry.get("selection_decision"),
            "capability_requirement": required,
            "image_path": command_plan.get("image_path"),
            "image_hash": command_plan.get("image_hash"),
            "test_device": command_plan.get("test_device"),
            "scratch_device": command_plan.get("scratch_device"),
            "helper_versions": {
                helper: "not_resolved_in_plan_mode"
                for helper in command_plan.get("helper_binaries", [])
                if isinstance(helper, str)
            },
            "required_privileges": command_plan.get("required_privileges"),
            "mutation_surface": command_plan.get("mutation_surface"),
            "execution_lane": command_plan.get("execution_lane"),
            "command_summary": command_plan.get("command_summary"),
            "cleanup_status": "not_started_plan_mode",
            "linked_artifact_or_bead": entry.get("tracker_id"),
            "docs_scope_citation": entry.get("v1_scope_mapping") or entry.get("scope_reference"),
            "artifact_paths": artifact_paths,
            "reproduction_command": entry.get("repro_command"),
        },
    })

payload = {
    "requested_mode": requested_mode,
    "filter": xfstests_filter,
    "dry_run": dry_run == "1",
    "xfstests_dir": xfstests_dir,
    "command_plan": {
        "working_directory": xfstests_dir or "<resolved xfstests checkout>",
        "argv": check_argv,
        "display": " ".join(check_argv),
    },
    "reproduction_command": (
        f"XFSTESTS_MODE={requested_mode} XFSTESTS_FILTER={xfstests_filter} "
        f"XFSTESTS_DRY_RUN={dry_run} ./scripts/e2e/ffs_xfstests_e2e.sh"
    ),
    "artifact_paths": artifact_paths,
    "capability_checks": [
        {"capability": capability, "required": True, "source": "xfstests_policy"}
        for capability in sorted(capabilities)
    ],
    "status_counts": dict(sorted(status_counts.items())),
    "classification_counts": dict(sorted(classification_counts.items())),
    "expected_outcome_counts": dict(sorted(outcome_counts.items())),
    "operation_class_counts": dict(sorted(operation_counts.items())),
    "filesystem_flavor_counts": dict(sorted(flavor_counts.items())),
    "command_plan_lane_counts": dict(sorted(lane_counts.items())),
    "command_plan_outcome_counts": dict(sorted(plan_outcome_counts.items())),
    "command_plan_proof": {
        "default_non_destructive": all(not plan.get("destructive") for plan in command_plans),
        "default_developer_validation_mutates_host": requested_mode == "run"
        and dry_run != "1"
        and any(plan.get("execution_lane") == "permissioned_real" for plan in command_plans),
        "temp_root": "${TMPDIR:-/tmp}/frankenfs-xfstests",
        "paths_verified_temp_scoped": all(
            is_temp_path(plan.get("image_path"))
            and is_temp_path(plan.get("scratch_path"))
            and is_temp_path(plan.get("mountpoint"))
            and is_temp_path(plan.get("test_device"))
            and is_temp_path(plan.get("scratch_device"))
            for plan in command_plans
        ),
        "paths_verified_per_test": all(
            command_plan_test_fragment(test.get("test_id", "")) in (test.get("command_plan", {}).get("image_path") or "")
            and command_plan_test_fragment(test.get("test_id", "")) in (test.get("command_plan", {}).get("scratch_path") or "")
            and command_plan_test_fragment(test.get("test_id", "")) in (test.get("command_plan", {}).get("mountpoint") or "")
            and command_plan_test_fragment(test.get("test_id", "")) in (test.get("command_plan", {}).get("test_device") or "")
            and command_plan_test_fragment(test.get("test_id", "")) in (test.get("command_plan", {}).get("scratch_device") or "")
            for test in tests
        ),
        "cleanup_actions_safe": all(
            not has_unsafe_cleanup_action(plan.get("cleanup_action")) for plan in command_plans
        ),
        "broad_shell_commands_rejected": True,
        "permissioned_destructive_lane_required": True,
        "representative_ext4_and_btrfs_present": all(
            flavor in flavor_counts for flavor in ["ext4", "btrfs"]
        ),
        "plans": command_plans,
    },
    "tests": tests,
    "validation_errors": errors,
}

policy_plan.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
report_lines = [
    "# xfstests subset policy report",
    "",
    "This report is a planning artifact. It counts product failures, environment blockers, harness blockers, expected unsupported rows, and not-run rows separately from passes.",
    "",
    "## Counts",
    "",
]
for label, counter in [
    ("Status", status_counts),
    ("Classification", classification_counts),
    ("Expected outcome", outcome_counts),
    ("Filesystem flavor", flavor_counts),
    ("Operation class", operation_counts),
    ("Command plan lane", lane_counts),
    ("Command plan outcome", plan_outcome_counts),
]:
    report_lines.append(f"### {label}")
    report_lines.append("")
    for key, value in sorted(counter.items()):
        report_lines.append(f"- {key}: {value}")
    report_lines.append("")

report_lines.extend([
    "## Rows",
    "",
    "| Policy row | Plan | Test id | Flavor | Operation | Risk | Outcome | Lane | Summary | Decision | Capability requirement | Artifact/bead | Scope | Reproduction |",
    "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
])
for test in tests:
    capability = ", ".join(test["required_capabilities"])
    plan = test.get("command_plan", {})
    report_lines.append(
        "| {policy_row_id} | {plan_id} | {test_id} | {filesystem_flavor} | {operation} | {risk} | {outcome} | {lane} | {summary} | {decision} | {capability} | {artifact} | {scope} | `{repro}` |".format(
            policy_row_id=test.get("policy_row_id") or "",
            plan_id=plan.get("plan_id") or "",
            test_id=test["test_id"],
            filesystem_flavor=test.get("filesystem_flavor") or "",
            operation=test.get("expected_operation_class") or "",
            risk=test.get("user_risk_category") or "",
            outcome=test.get("expected_outcome") or "",
            lane=plan.get("execution_lane") or "",
            summary=plan.get("command_summary") or "",
            decision=test.get("selection_decision") or "",
            capability=capability,
            artifact=test.get("tracker_id") or "",
            scope=test.get("v1_scope_mapping") or test.get("scope_reference") or "",
            repro=test.get("repro_command") or "",
        )
    )
report_lines.append("")
policy_report.write_text("\n".join(report_lines), encoding="utf-8")
if errors:
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)
PY
}

write_uniform_results() {
    local status="$1"
    local note="${2:-}"
    local note_safe="${note//\"/\\\"}"

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$SELECTED_FILE" "$RESULTS_JSON" "$JUNIT_FILE" "$status" "$note_safe" <<'PY'
import json
import pathlib
import sys
import xml.sax.saxutils

selected_file = pathlib.Path(sys.argv[1])
results_json = pathlib.Path(sys.argv[2])
junit_xml = pathlib.Path(sys.argv[3])
status = sys.argv[4]
note = sys.argv[5]

selected = [line.strip() for line in selected_file.read_text(encoding="utf-8").splitlines() if line.strip()]
tests = [{"id": tid, "status": status} for tid in selected]

counts = {"passed": 0, "failed": 0, "skipped": 0, "not_run": 0, "planned": 0}
if status in counts:
    counts[status] = len(selected)
else:
    counts["not_run"] = len(selected)

pass_rate = 0.0
if selected and counts["passed"] > 0:
    pass_rate = counts["passed"] / len(selected)

payload = {
    "source": "uniform",
    "status": status,
    "note": note,
    "total": len(selected),
    "passed": counts["passed"],
    "failed": counts["failed"],
    "skipped": counts["skipped"],
    "not_run": counts["not_run"],
    "planned": counts["planned"],
    "pass_rate": pass_rate,
    "tests": tests,
}
results_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with junit_xml.open("w", encoding="utf-8") as fh:
    failures = counts["failed"]
    skipped = counts["skipped"] + counts["not_run"] + counts["planned"]
    fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fh.write(f'<testsuite name="ffs_xfstests_e2e" tests="{len(selected)}" failures="{failures}" skipped="{skipped}">\n')
    for tid in selected:
        esc = xml.sax.saxutils.escape(tid, {'"': "&quot;", "'": "&apos;"})
        fh.write(f'  <testcase name="{esc}" time="0.000">')
        if status == "failed":
            msg = xml.sax.saxutils.escape(note or "failed", {'"': "&quot;", "'": "&apos;"})
            fh.write(f'<failure message="{msg}">{msg}</failure>')
        elif status in {"skipped", "not_run", "planned"}:
            msg = xml.sax.saxutils.escape(note or status, {'"': "&quot;", "'": "&apos;"})
            fh.write(f'<skipped message="{msg}"/>')
        fh.write("</testcase>\n")
    fh.write("</testsuite>\n")
PY
        return 0
    fi

    local fallback_passed=0
    local fallback_failed=0
    local fallback_skipped=0
    local fallback_not_run=0
    local fallback_planned=0
    case "$status" in
        passed) fallback_passed=${#SELECTED_TESTS[@]} ;;
        failed) fallback_failed=${#SELECTED_TESTS[@]} ;;
        skipped) fallback_skipped=${#SELECTED_TESTS[@]} ;;
        planned) fallback_planned=${#SELECTED_TESTS[@]} ;;
        *) fallback_not_run=${#SELECTED_TESTS[@]} ;;
    esac

    # Fallback without python3: write minimal JSON and omit JUnit.
    cat >"$RESULTS_JSON" <<EOF
{
  "source": "uniform",
  "status": "$status",
  "note": "$note_safe",
  "total": ${#SELECTED_TESTS[@]},
  "passed": $fallback_passed,
  "failed": $fallback_failed,
  "skipped": $fallback_skipped,
  "not_run": $fallback_not_run,
  "planned": $fallback_planned,
  "pass_rate": 0.0,
  "tests": []
}
EOF
}

write_baseline_manifest_artifacts() {
    if ! command -v python3 >/dev/null 2>&1; then
        e2e_log "python3 not found; unable to emit xfstests baseline manifest"
        return 0
    fi

    local command_transcript="./check"
    if [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        command_transcript+=" -n"
    fi
    command_transcript+=" ${SELECTED_TESTS[*]}"
    local resume_command="XFSTESTS_MODE=run XFSTESTS_DRY_RUN=$XFSTESTS_DRY_RUN XFSTESTS_FILTER=$XFSTESTS_FILTER RESULT_BASE=$RESULT_BASE ./scripts/e2e/ffs_xfstests_e2e.sh"
    local reproduction_command="XFSTESTS_MODE=$XFSTESTS_MODE XFSTESTS_DRY_RUN=$XFSTESTS_DRY_RUN XFSTESTS_FILTER=$XFSTESTS_FILTER ./scripts/e2e/ffs_xfstests_e2e.sh"
    local checkpoint_id="checkpoint:$(basename "$ARTIFACT_DIR")"
    local environment_manifest_id="preflight:missing"
    local environment_age_secs="$((XFSTESTS_PREFLIGHT_MAX_AGE_SECS + 1))"
    local environment_max_age_secs="$XFSTESTS_PREFLIGHT_MAX_AGE_SECS"
    local environment_freshness_verdict="missing"
    if [[ -f "$XFSTESTS_PREFLIGHT_JSON" ]]; then
        environment_manifest_id="sha256:$(sha256sum "$XFSTESTS_PREFLIGHT_JSON" | awk '{print $1}')"
        if [[ "$XFSTESTS_PREFLIGHT_ACCEPTED" == "1" ]]; then
            environment_age_secs="0"
            environment_freshness_verdict="fresh"
        else
            environment_freshness_verdict="blocked"
        fi
    fi

    local -a raw_artifacts=()
    local candidate
    for candidate in \
        "$SELECTED_FILE" \
        "$RESULTS_JSON" \
        "$JUNIT_FILE" \
        "$CHECK_LOG" \
        "$POLICY_PLAN_JSON" \
        "$POLICY_REPORT_MD" \
        "$XFSTESTS_PREFLIGHT_JSON" \
        "$ARTIFACT_DIR/stdout.log" \
        "$ARTIFACT_DIR/stderr.log"; do
        if [[ -f "$candidate" ]]; then
            raw_artifacts+=("$candidate")
        fi
    done

    python3 - \
        "$SELECTED_FILE" \
        "$RESULTS_JSON" \
        "$BASELINE_MANIFEST_JSON" \
        "$BASELINE_REPORT_MD" \
        "$XFSTESTS_BASELINE_ID" \
        "$XFSTESTS_SUBSET_VERSION" \
        "$environment_manifest_id" \
        "$command_transcript" \
        "$checkpoint_id" \
        "$resume_command" \
        "$XFSTESTS_CLEANUP_STATUS" \
        "$reproduction_command" \
        "$SUMMARY_JSON" \
        "$XFSTESTS_ALLOWLIST_JSON" \
        "$environment_age_secs" \
        "$environment_max_age_secs" \
        "$environment_freshness_verdict" \
        "${raw_artifacts[@]}" <<'PY'
import hashlib
import json
import pathlib
import sys
from collections import Counter

(
    selected_path,
    results_path,
    manifest_path,
    report_path,
    baseline_id,
    subset_version,
    environment_manifest_id,
    command_transcript,
    checkpoint_id,
    resume_command,
    cleanup_status,
    reproduction_command,
    summary_path,
    allowlist_path,
    environment_age_secs,
    environment_max_age_secs,
    environment_freshness_verdict,
    *raw_paths,
) = sys.argv[1:]

selected = [
    line.strip()
    for line in pathlib.Path(selected_path).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
results = json.loads(pathlib.Path(results_path).read_text(encoding="utf-8"))
case_by_id = {case.get("id"): case for case in results.get("tests", [])}
policy_by_id = {
    row.get("test_id"): row
    for row in json.loads(pathlib.Path(allowlist_path).read_text(encoding="utf-8"))
    if isinstance(row, dict)
}
status_vocabulary = [
    "passed",
    "failed",
    "skipped",
    "not_run",
    "unsupported",
    "host_blocked",
    "harness_failed",
    "interrupted",
    "resumed",
]

def sha256_file(path):
    data = pathlib.Path(path).read_bytes()
    return "sha256:" + hashlib.sha256(data).hexdigest()

raw_artifacts = [
    {"path": path, "sha256": sha256_file(path), "immutable": True}
    for path in raw_paths
    if pathlib.Path(path).is_file()
]
combined = hashlib.sha256()
for artifact in raw_artifacts:
    combined.update(artifact["path"].encode())
    combined.update(b"\0")
    combined.update(artifact["sha256"].encode())
    combined.update(b"\0")
raw_log_hash = "sha256:" + combined.hexdigest()
raw_refs = [artifact["path"] for artifact in raw_artifacts]

def row_status(case):
    status = case.get("status", "not_run")
    classification = case.get("classification")
    if "interrupted" in cleanup_status:
        return "interrupted"
    if "resumed" in cleanup_status:
        return "resumed"
    if status in {"passed", "failed", "skipped"}:
        return status
    if classification == "unsupported_by_v1":
        return "unsupported"
    if classification == "environment_blocked":
        return "host_blocked"
    if classification == "harness_blocked":
        return "harness_failed"
    return "not_run"

cases = []
for test_id in selected:
    case = case_by_id.get(test_id, {"id": test_id, "status": "not_run"})
    policy = policy_by_id.get(test_id, {})
    status = row_status(case)
    classification = case.get("classification") or policy.get("classification") or "unclassified"
    remediation = None
    if status in {"not_run", "interrupted", "host_blocked", "harness_failed"}:
        remediation = resume_command
    elif status == "unsupported":
        remediation = "document unsupported scope rationale before failure triage"
    cases.append({
        "test_id": test_id,
        "status": status,
        "raw_artifact_refs": raw_refs,
        "raw_log_hash": raw_log_hash,
        "command": command_transcript,
        "not_run_reason": case.get("output_snippet") or case.get("failure_reason") or policy.get("failure_reason"),
        "partial_run_checkpoint": checkpoint_id,
        "resume_command": resume_command,
        "cleanup_status": cleanup_status,
        "immutable_raw_artifacts": True,
        "classification": classification,
        "remediation": remediation,
    })

counts = dict(sorted(Counter(case["status"] for case in cases).items()))
manifest = {
    "schema_version": 1,
    "baseline_id": baseline_id,
    "bead_id": "bd-rchk3.3",
    "subset_version": subset_version,
    "environment": {
        "manifest_id": environment_manifest_id,
        "age_secs": int(environment_age_secs),
        "max_age_secs": int(environment_max_age_secs),
        "freshness_verdict": environment_freshness_verdict,
    },
    "status_vocabulary": status_vocabulary,
    "raw_artifact_policy": "raw artifacts are immutable inputs; summaries are derived and may not rewrite raw logs",
    "generated_summary_path": summary_path,
    "command_transcript": command_transcript,
    "checkpoint_id": checkpoint_id,
    "resume_command": resume_command,
    "cleanup_status": cleanup_status,
    "output_paths": {
        "summary_json": summary_path,
        "results_json": results_path,
        "baseline_manifest_json": manifest_path,
        "baseline_report_md": report_path,
        "failure_triage_json": str(pathlib.Path(manifest_path).with_name("failure_triage.json")),
        "failure_triage_report_md": str(pathlib.Path(manifest_path).with_name("failure_triage.md")),
    },
    "reproduction_command": reproduction_command,
    "disposition_counts": counts,
    "raw_artifacts": raw_artifacts,
    "cases": cases,
}
pathlib.Path(manifest_path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    f"# xfstests baseline manifest `{baseline_id}`",
    "",
    f"- subset version: `{subset_version}`",
    f"- environment manifest: `{environment_manifest_id}`",
    f"- checkpoint: `{checkpoint_id}`",
    f"- resume command: `{resume_command}`",
    f"- cleanup status: `{cleanup_status}`",
    "",
    "## Dispositions",
    "",
]
for key, value in counts.items():
    lines.append(f"- {key}: {value}")
lines.extend([
    "",
    "## Cases",
    "",
    "| Test | Status | Classification | Raw hash | Resume |",
    "|---|---|---|---|---|",
])
for case in cases:
    lines.append(
        f"| {case['test_id']} | {case['status']} | {case['classification']} | `{case['raw_log_hash']}` | `{case['resume_command']}` |"
    )
pathlib.Path(report_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

    write_failure_triage_artifacts "$reproduction_command"
    write_synthetic_failure_triage_fixture_artifacts "$reproduction_command"
}

write_failure_triage_artifacts() {
    local reproduction_command="$1"
    local triage_id="xfstests-triage-$(basename "$E2E_LOG_DIR")"
    local triage_stderr="$ARTIFACT_DIR/failure_triage.stderr"

    if [[ ! -f "$BASELINE_MANIFEST_JSON" ]]; then
        e2e_log "xfstests baseline manifest missing; unable to emit failure triage artifacts"
        return 0
    fi

    if harness_supports_xfstests_failure_triage; then
        if ! "$FFS_HARNESS_BIN" xfstests-failure-triage \
            --baseline-manifest "$BASELINE_MANIFEST_JSON" \
            --triage-out "$FAILURE_TRIAGE_JSON" \
            --summary-out "$FAILURE_TRIAGE_REPORT_MD" \
            --triage-id "$triage_id" \
            --reproduction-command "$reproduction_command" >/dev/null 2>"$triage_stderr"; then
            if [[ "$XFSTESTS_PREFLIGHT_ACCEPTED" == "1" ]]; then
                cat "$triage_stderr" >&2
                return 1
            fi
            e2e_log "xfstests failure triage not emitted because baseline evidence is not consumable; stderr=$triage_stderr"
        fi
        return 0
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        e2e_log "python3 not found; unable to emit xfstests failure triage artifacts"
        return 0
    fi

    if ! python3 - \
        "$BASELINE_MANIFEST_JSON" \
        "$FAILURE_TRIAGE_JSON" \
        "$FAILURE_TRIAGE_REPORT_MD" \
        "$triage_id" \
        "$reproduction_command" 2>"$triage_stderr" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
from collections import OrderedDict

(
    baseline_manifest_path,
    triage_path,
    report_path,
    triage_id,
    reproduction_command,
) = sys.argv[1:]

baseline_manifest_path = pathlib.Path(baseline_manifest_path)
triage_path = pathlib.Path(triage_path)
report_path = pathlib.Path(report_path)
manifest = json.loads(baseline_manifest_path.read_text(encoding="utf-8"))


def sha256_file(path):
    return "sha256:" + hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def hash_raw_artifact_set(artifacts):
    digest = hashlib.sha256()
    for artifact in artifacts:
        digest.update(str(artifact["path"]).encode())
        digest.update(b"\0")
        digest.update(str(artifact["sha256"]).encode())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def filesystem_flavor(test_id):
    return test_id.split("/", 1)[0] if "/" in test_id else "generic"


def suspected_boundary(test_id):
    if test_id.startswith("ext4/"):
        return "ffs-ext4"
    if test_id.startswith("btrfs/"):
        return "ffs-btrfs"
    return "ffs-core"


def normalize_fragment(value):
    parts = [part for part in re.sub(r"[^A-Za-z0-9]+", "-", value).lower().split("-") if part]
    return "-".join(parts[:12])


def xfstests_id_fragment(test_id):
    parts = [part for part in re.sub(r"[^A-Za-z0-9]+", "-", test_id).lower().split("-") if part]
    return "-".join(parts)


KNOWN_XFSTESTS_ENV_PREFIXES = (
    "XFSTESTS_MODE=",
    "XFSTESTS_FILTER=",
    "XFSTESTS_DRY_RUN=",
    "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=",
)


def trim_known_xfstests_env_assignments(command):
    parts = command.strip().split()
    while parts and any(parts[0].startswith(prefix) for prefix in KNOWN_XFSTESTS_ENV_PREFIXES):
        parts = parts[1:]
    return " ".join(parts)


def validation_command_for(flavor, reproduction_command):
    invocation = trim_known_xfstests_env_assignments(reproduction_command)
    if "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1" in reproduction_command.split():
        return (
            "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1 XFSTESTS_MODE=plan "
            f"XFSTESTS_DRY_RUN=1 XFSTESTS_FILTER=all {invocation}"
        )
    return f"XFSTESTS_MODE=run XFSTESTS_FILTER={flavor} XFSTESTS_DRY_RUN=0 {invocation}"


def fixture_recipe(case, flavor, boundary, expected_behavior, actual_behavior, validation_command):
    test_id = case.get("test_id", "")
    fragment = xfstests_id_fragment(test_id)
    proposed_path = f"conformance/fixtures/xfstests/{fragment}.json"
    return {
        "schema_version": 1,
        "recipe_id": f"xfstests-sparse-fixture-{fragment}",
        "source_xfstests_id": test_id,
        "related_test_ids": [test_id],
        "filesystem_flavor": flavor,
        "suspected_crate_boundary": boundary,
        "fixture_manifest_kind": "sparse_fixture_generation_recipe",
        "proposed_fixture_path": proposed_path,
        "source_raw_log_refs": list(case.get("raw_artifact_refs", [])),
        "source_raw_log_hash": case.get("raw_log_hash", ""),
        "minimized_reproducer_command": case.get("command", ""),
        "expected_behavior": expected_behavior,
        "actual_behavior": actual_behavior,
        "validation_command": validation_command,
        "dependency_hints": [
            "bd-rchk3.4",
            "review immutable xfstests baseline before live bead creation",
            f"suspected boundary: {boundary}",
        ],
        "recipe_steps": [
            f"replay the single xfstests row with `{case.get('command', '')}`",
            "capture the smallest failing filesystem image or metadata region after reproducing the failure",
            f"convert the minimized bytes into `{proposed_path}` using `ffs-harness generate-fixture <image> region <offset> <len>` when a bounded region is known",
            "add a fixture-driven harness assertion before changing product code",
        ],
        "promotion_status": "dry_run_recipe_only",
        "live_fixture_write_enabled": False,
    }


def sh_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def proposed_command(bead):
    description = (
        f"xfstests={bead['failing_test_id']} "
        f"expected={bead['expected_behavior']} "
        f"actual={bead['actual_behavior']} "
        f"validation={bead['validation_command']} "
        f"raw_hash={bead['raw_log_hash']} "
        f"duplicate_key={bead['duplicate_key']}"
    )
    return (
        "DRY_RUN br create "
        f"--title {sh_quote(bead['title'])} "
        "--type bug --priority 1 "
        f"--labels {sh_quote(','.join(bead['labels']))} "
        f"--description {sh_quote(description)} "
        f"--depends-on {sh_quote(','.join(bead['dependency_beads']))} "
        "--no-db --json"
    )


def excluded_row(case):
    status = case.get("status", "")
    classification = case.get("classification", "")
    reasons = {
        "passed": "passed rows do not create failure beads",
        "skipped": "skipped rows require no product bead",
        "not_run": "not-run rows require remediation or rerun first",
        "unsupported": "unsupported-scope rows must not pollute product backlog",
        "host_blocked": "host-blocked rows are environment work",
        "harness_failed": "harness failures are harness work",
        "interrupted": "interrupted rows need resume before failure triage",
        "resumed": "resumed rows are evidence metadata, not product failures",
    }
    reason = reasons.get(status)
    if reason is None and status == "failed":
        reason = {
            "environment_blocked": "environment failure excluded from product backlog",
            "harness_blocked": "harness failure excluded from product backlog",
            "unsupported_by_v1": "unsupported failure excluded from product backlog",
        }.get(classification, "failed row is not classified product_actionable")
    if reason is None:
        reason = "row is outside product failure triage scope"
    return {
        "test_id": case.get("test_id", ""),
        "status": status,
        "classification": classification,
        "reason": reason,
        "raw_log_hash": case.get("raw_log_hash", ""),
        "remediation": case.get("remediation"),
    }


errors = []
if manifest.get("schema_version") != 1:
    errors.append("xfstests baseline manifest schema_version must be 1")
expected_baseline_bead_id = "bd-rchk3.3"
if manifest.get("bead_id") != expected_baseline_bead_id:
    errors.append(f"xfstests baseline manifest bead_id must be {expected_baseline_bead_id}")

environment = manifest.get("environment", {})
if not isinstance(environment, dict):
    errors.append("xfstests baseline environment must be an object")
    environment = {}
environment_manifest_id = str(environment.get("manifest_id", ""))
if not environment_manifest_id:
    errors.append("xfstests baseline manifest missing environment.manifest_id")
if environment_manifest_id == "preflight:missing":
    errors.append("xfstests baseline environment manifest is missing preflight proof")
try:
    environment_age_secs = int(environment.get("age_secs", 0))
    environment_max_age_secs = int(environment.get("max_age_secs", 0))
except (TypeError, ValueError):
    errors.append("xfstests baseline environment age fields must be integers")
    environment_age_secs = 0
    environment_max_age_secs = 0
if (
    environment_age_secs > environment_max_age_secs
    or environment.get("freshness_verdict") != "fresh"
):
    errors.append(
        "xfstests baseline environment manifest is stale: "
        f"age_secs={environment.get('age_secs')} "
        f"max_age_secs={environment.get('max_age_secs')} "
        f"verdict={environment.get('freshness_verdict')}"
    )

raw_by_path = {}
for artifact in manifest.get("raw_artifacts", []):
    path = str(artifact.get("path", ""))
    if not path:
        errors.append("xfstests baseline raw artifact missing path")
        continue
    if artifact.get("immutable") is not True:
        errors.append(f"xfstests baseline raw artifact {path} is not immutable")
    expected = str(artifact.get("sha256", ""))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        errors.append(f"xfstests baseline raw artifact {path} has malformed sha256")
    else:
        try:
            actual = sha256_file(path)
        except OSError as exc:
            errors.append(f"xfstests baseline raw artifact missing: {path} ({exc})")
        else:
            if actual != expected:
                errors.append(
                    f"xfstests baseline raw artifact hash changed: {path} "
                    f"expected={expected} actual={actual}"
                )
    raw_by_path[path] = artifact

for case in manifest.get("cases", []):
    artifacts = []
    refs = case.get("raw_artifact_refs", [])
    if not refs:
        errors.append(f"xfstests triage case {case.get('test_id', '')} has no consumable raw artifacts")
        continue
    for raw_ref in refs:
        artifact = raw_by_path.get(str(raw_ref))
        if artifact is None:
            errors.append(
                f"xfstests triage case {case.get('test_id', '')} references unknown raw artifact {raw_ref}"
            )
        elif artifact.get("immutable") is not True:
            errors.append(
                f"xfstests triage case {case.get('test_id', '')} references mutable raw artifact {raw_ref}"
            )
        else:
            artifacts.append(artifact)
    if artifacts:
        actual_hash = hash_raw_artifact_set(artifacts)
        if case.get("raw_log_hash") != actual_hash:
            errors.append(
                f"xfstests triage case {case.get('test_id', '')} raw_log_hash does not match "
                f"referenced immutable artifacts: expected={case.get('raw_log_hash')} actual={actual_hash}"
            )

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)

proposed_by_key = OrderedDict()
excluded_rows = []
for case in manifest.get("cases", []):
    status = case.get("status", "")
    classification = case.get("classification", "")
    test_id = case.get("test_id", "")
    if status == "failed" and classification == "product_actionable":
        flavor = filesystem_flavor(test_id)
        boundary = suspected_boundary(test_id)
        actual_behavior = case.get("not_run_reason") or f"xfstests row {test_id} ended with normalized status {status}"
        expected_behavior = (
            f"{case.get('command', '')} should satisfy Linux xfstests row {test_id} "
            f"for the {flavor} compatibility surface"
        )
        duplicate_key = f"{boundary}:{status}:{normalize_fragment(actual_behavior)}"
        existing = proposed_by_key.get(duplicate_key)
        if existing is None:
            index = len(proposed_by_key) + 1
            validation_command = validation_command_for(flavor, reproduction_command)
            existing = {
                "proposed_id_placeholder": f"dry-run-xfstests-product-failure-{index:04}",
                "title": f"xfstests {test_id} product failure in {boundary}",
                "failing_test_id": test_id,
                "related_test_ids": [test_id],
                "filesystem_flavor": flavor,
                "exact_command": case.get("command", ""),
                "normalized_outcome": status,
                "expected_behavior": expected_behavior,
                "actual_behavior": actual_behavior,
                "suspected_crate_boundary": boundary,
                "minimized_repro_command": case.get("command", ""),
                "minimization_status": "command_is_single_xfstests_row",
                "duplicate_key": duplicate_key,
                "labels": ["xfstests", "conformance", "product-bug", flavor],
                "dependency_beads": ["bd-rchk3.4", manifest.get("baseline_id", "")],
                "dependency_rationale": (
                    "proposed product bead depends on reviewed xfstests triage policy "
                    "and immutable baseline artifacts"
                ),
                "validation_command": validation_command,
                "raw_log_refs": list(case.get("raw_artifact_refs", [])),
                "raw_log_hash": case.get("raw_log_hash", ""),
                "fixture_recipe": fixture_recipe(
                    case,
                    flavor,
                    boundary,
                    expected_behavior,
                    actual_behavior,
                    validation_command,
                ),
                "live_create": False,
            }
            proposed_by_key[duplicate_key] = existing
        else:
            if test_id not in existing["related_test_ids"]:
                existing["related_test_ids"].append(test_id)
            if test_id not in existing["fixture_recipe"]["related_test_ids"]:
                existing["fixture_recipe"]["related_test_ids"].append(test_id)
            for raw_ref in case.get("raw_artifact_refs", []):
                if raw_ref not in existing["raw_log_refs"]:
                    existing["raw_log_refs"].append(raw_ref)
                if raw_ref not in existing["fixture_recipe"]["source_raw_log_refs"]:
                    existing["fixture_recipe"]["source_raw_log_refs"].append(raw_ref)
    else:
        excluded_rows.append(excluded_row(case))

proposed_beads = list(proposed_by_key.values())
fixture_recipes = [bead["fixture_recipe"] for bead in proposed_beads]
duplicate_groups = [
    {
        "duplicate_key": bead["duplicate_key"],
        "primary_test_id": bead["failing_test_id"],
        "merged_test_ids": bead["related_test_ids"],
    }
    for bead in proposed_beads
    if len(bead["related_test_ids"]) > 1
]
for bead in proposed_beads:
    if not bead["minimized_repro_command"]:
        bead["minimized_repro_command"] = None

report = {
    "schema_version": 1,
    "triage_id": triage_id,
    "baseline_id": manifest.get("baseline_id", ""),
    "subset_version": manifest.get("subset_version", ""),
    "source_baseline_manifest": str(baseline_manifest_path),
    "live_bead_creation_enabled": False,
    "disposition_counts": manifest.get("disposition_counts", {}),
    "duplicate_groups": duplicate_groups,
    "proposed_beads": proposed_beads,
    "fixture_recipes": fixture_recipes,
    "excluded_rows": excluded_rows,
    "proposed_br_commands": [proposed_command(bead) for bead in proposed_beads],
    "reproduction_command": reproduction_command,
}
triage_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    f"# xfstests failure triage `{triage_id}`",
    "",
    f"- baseline: `{report['baseline_id']}`",
    f"- subset version: `{report['subset_version']}`",
    "- live bead creation enabled: `false`",
    "",
    "## Proposed Product Beads",
    "",
    "| Placeholder | Tests | Flavor | Boundary | Expected | Actual | Raw hash | Validation | Dependencies |",
    "|---|---|---|---|---|---|---|---|---|",
]
for bead in proposed_beads:
    lines.append(
        f"| {bead['proposed_id_placeholder']} | {', '.join(bead['related_test_ids'])} | "
        f"{bead['filesystem_flavor']} | {bead['suspected_crate_boundary']} | "
        f"{bead['expected_behavior']} | {bead['actual_behavior']} | "
        f"`{bead['raw_log_hash']}` | `{bead['validation_command']}` | "
        f"{', '.join(bead['dependency_beads'])} |"
    )
lines.extend([
    "",
    "## Sparse Fixture Recipes",
    "",
    "| Recipe | Tests | Proposed fixture | Status | Steps |",
    "|---|---|---|---|---|",
])
for recipe in fixture_recipes:
    lines.append(
        f"| {recipe['recipe_id']} | {', '.join(recipe['related_test_ids'])} | "
        f"`{recipe['proposed_fixture_path']}` | {recipe['promotion_status']} | "
        f"{'<br>'.join(recipe['recipe_steps'])} |"
    )
lines.extend([
    "",
    "## Excluded Rows",
    "",
    "| Test | Status | Classification | Reason |",
    "|---|---|---|---|",
])
for row in excluded_rows:
    lines.append(f"| {row['test_id']} | {row['status']} | {row['classification']} | {row['reason']} |")
lines.extend(["", "## Dry-Run br Commands", ""])
for command in report["proposed_br_commands"]:
    lines.append(f"- `{command}`")
report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
    then
        if [[ "$XFSTESTS_PREFLIGHT_ACCEPTED" == "1" ]]; then
            cat "$triage_stderr" >&2
            return 1
        fi
        e2e_log "xfstests failure triage not emitted because baseline evidence is not consumable; stderr=$triage_stderr"
    fi
}

write_synthetic_failure_triage_fixture_artifacts() {
    local reproduction_command="$1"

    if [[ "$XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE" != "1" ]]; then
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        e2e_fail "python3 is required for XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1"
    fi

    mkdir -p "$SYNTHETIC_TRIAGE_DIR"
    local synthetic_raw="$SYNTHETIC_TRIAGE_DIR/check.log"
    local synthetic_baseline="$SYNTHETIC_TRIAGE_DIR/baseline_manifest.json"
    local synthetic_triage="$SYNTHETIC_TRIAGE_DIR/failure_triage.json"
    local synthetic_summary="$SYNTHETIC_TRIAGE_DIR/failure_triage.md"
    local synthetic_reproduction="XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1 XFSTESTS_MODE=plan XFSTESTS_DRY_RUN=1 XFSTESTS_FILTER=all ./scripts/e2e/ffs_xfstests_e2e.sh"

    python3 - "$synthetic_raw" "$synthetic_baseline" "$synthetic_triage" "$synthetic_summary" <<'PY'
import hashlib
import json
import pathlib
import sys
from collections import Counter

raw_path = pathlib.Path(sys.argv[1])
baseline_path = pathlib.Path(sys.argv[2])
triage_path = pathlib.Path(sys.argv[3])
summary_path = pathlib.Path(sys.argv[4])
raw_path.write_text(
    "\n".join(
        [
            "generic/001 failed EIO after fsync boundary",
            "generic/002 passed",
            "generic/003 skipped missing scratch capability",
            "generic/004 interrupted after checkpoint",
            "generic/005 resumed from checkpoint",
            "ext4/001 host blocked by missing fuse",
            "btrfs/001 harness failed before product verdict",
        ]
    )
    + "\n",
    encoding="utf-8",
)

def sha256_file(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

artifact = {
    "path": str(raw_path),
    "sha256": sha256_file(raw_path),
    "immutable": True,
}
combined = hashlib.sha256()
combined.update(artifact["path"].encode())
combined.update(b"\0")
combined.update(artifact["sha256"].encode())
combined.update(b"\0")
raw_log_hash = "sha256:" + combined.hexdigest()
cases = [
    {
        "test_id": "generic/001",
        "status": "failed",
        "classification": "product_actionable",
        "not_run_reason": "EIO after fsync boundary",
        "remediation": None,
    },
    {
        "test_id": "generic/002",
        "status": "passed",
        "classification": "product_actionable",
        "not_run_reason": None,
        "remediation": None,
    },
    {
        "test_id": "generic/003",
        "status": "skipped",
        "classification": "environment_blocked",
        "not_run_reason": "missing scratch capability",
        "remediation": None,
    },
    {
        "test_id": "generic/004",
        "status": "interrupted",
        "classification": "product_actionable",
        "not_run_reason": "interrupted after checkpoint",
        "remediation": "resume xfstests fixture run",
    },
    {
        "test_id": "generic/005",
        "status": "resumed",
        "classification": "product_actionable",
        "not_run_reason": "resumed row records checkpoint continuity",
        "remediation": None,
    },
    {
        "test_id": "ext4/001",
        "status": "host_blocked",
        "classification": "environment_blocked",
        "not_run_reason": "missing fuse",
        "remediation": "restore FUSE capability before real xfstests",
    },
    {
        "test_id": "btrfs/001",
        "status": "harness_failed",
        "classification": "harness_blocked",
        "not_run_reason": "parser failed before product verdict",
        "remediation": "fix harness runner before product triage",
    },
]
materialized = []
for case in cases:
    item = {
        "test_id": case["test_id"],
        "status": case["status"],
        "raw_artifact_refs": [str(raw_path)],
        "raw_log_hash": raw_log_hash,
        "command": f"./check {case['test_id']}",
        "partial_run_checkpoint": "checkpoint:synthetic-fixture",
        "resume_command": "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1 ./scripts/e2e/ffs_xfstests_e2e.sh",
        "cleanup_status": "synthetic_fixture_no_xfstests_check_invoked",
        "immutable_raw_artifacts": True,
        "classification": case["classification"],
    }
    if case["not_run_reason"] is not None:
        item["not_run_reason"] = case["not_run_reason"]
    if case["remediation"] is not None:
        item["remediation"] = case["remediation"]
    materialized.append(item)

manifest = {
    "schema_version": 1,
    "baseline_id": "xfstests-baseline-synthetic-fixture",
    "bead_id": "bd-rchk3.3",
    "subset_version": "xfstests-curated-v1-synthetic-fixture",
    "environment": {
        "manifest_id": "sha256:synthetic-preflight",
        "age_secs": 0,
        "max_age_secs": 3600,
        "freshness_verdict": "fresh",
    },
    "status_vocabulary": [
        "passed",
        "failed",
        "skipped",
        "not_run",
        "unsupported",
        "host_blocked",
        "harness_failed",
        "interrupted",
        "resumed",
    ],
    "raw_artifact_policy": "raw artifacts are immutable inputs; summaries are derived and may not rewrite raw logs",
    "generated_summary_path": str(summary_path),
    "command_transcript": "./check synthetic fixture rows",
    "checkpoint_id": "checkpoint:synthetic-fixture",
    "resume_command": "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1 ./scripts/e2e/ffs_xfstests_e2e.sh",
    "cleanup_status": "synthetic_fixture_no_xfstests_check_invoked",
    "output_paths": {
        "baseline_manifest_json": str(baseline_path),
        "baseline_report_md": str(summary_path.with_name("baseline_report.md")),
        "failure_triage_json": str(triage_path),
        "failure_triage_report_md": str(summary_path),
    },
    "reproduction_command": "XFSTESTS_SYNTHETIC_TRIAGE_FIXTURE=1 ./scripts/e2e/ffs_xfstests_e2e.sh",
    "disposition_counts": dict(sorted(Counter(case["status"] for case in materialized).items())),
    "raw_artifacts": [artifact],
    "cases": materialized,
}
baseline_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

    local saved_baseline="$BASELINE_MANIFEST_JSON"
    local saved_triage="$FAILURE_TRIAGE_JSON"
    local saved_summary="$FAILURE_TRIAGE_REPORT_MD"
    BASELINE_MANIFEST_JSON="$synthetic_baseline"
    FAILURE_TRIAGE_JSON="$synthetic_triage"
    FAILURE_TRIAGE_REPORT_MD="$synthetic_summary"
    write_failure_triage_artifacts "$synthetic_reproduction"
    BASELINE_MANIFEST_JSON="$saved_baseline"
    FAILURE_TRIAGE_JSON="$saved_triage"
    FAILURE_TRIAGE_REPORT_MD="$saved_summary"

    python3 - "$synthetic_triage" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
statuses = {row["status"] for row in report.get("excluded_rows", [])}
recipes = report.get("fixture_recipes", [])
errors = []
if not report.get("proposed_beads"):
    errors.append("synthetic fixture did not emit a dry-run proposed bead")
if not recipes:
    errors.append("synthetic fixture did not emit sparse fixture recipes")
if {"passed", "skipped", "interrupted", "resumed"} - statuses:
    errors.append(f"synthetic fixture excluded statuses incomplete: {sorted(statuses)}")
for recipe in recipes:
    if recipe.get("promotion_status") != "dry_run_recipe_only":
        errors.append("sparse fixture recipe is not dry-run only")
    if recipe.get("live_fixture_write_enabled"):
        errors.append("sparse fixture recipe enabled live fixture writes")
    if not str(recipe.get("proposed_fixture_path", "")).startswith("conformance/fixtures/xfstests/"):
        errors.append("sparse fixture recipe proposed path outside xfstests fixture root")
if errors:
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)
PY

    e2e_log "Synthetic xfstests failure triage fixture written to: $SYNTHETIC_TRIAGE_DIR"
}

prepare_safe_dry_run_config() {
    if [[ "$XFSTESTS_DRY_RUN" != "1" || "$XFSTESTS_INVOKE_CHECK_DRY_RUN" == "1" ]]; then
        return 0
    fi

    FSTYP="${FSTYP:-fuse}"
    TEST_DEV="${TEST_DEV:-frankenfs-dryrun-test}"
    SCRATCH_DEV="${SCRATCH_DEV:-frankenfs-dryrun-scratch}"
    TEST_DIR="${TEST_DIR:-$ARTIFACT_DIR/dryrun_test_dir}"
    SCRATCH_MNT="${SCRATCH_MNT:-$ARTIFACT_DIR/dryrun_scratch_mnt}"
    mkdir -p "$TEST_DIR" "$SCRATCH_MNT"
    if [[ -d "$TEST_DIR" ]]; then
        TEST_DIR="$(cd "$TEST_DIR" && pwd)"
    fi
    if [[ -d "$SCRATCH_MNT" ]]; then
        SCRATCH_MNT="$(cd "$SCRATCH_MNT" && pwd)"
    fi
    export FSTYP TEST_DEV SCRATCH_DEV TEST_DIR SCRATCH_MNT
}

write_safe_dry_run_artifacts() {
    local note="safe dry-run plan only; upstream xfstests ./check -n is not invoked because it can mount, mkfs, or unmount while validating TEST_DEV/SCRATCH_DEV"
    LAST_CHECK_RC=0
    XFSTESTS_CLEANUP_STATUS="no_xfstests_check_invoked_no_mount_no_mkfs"
    XFSTESTS_PARTIAL_RUN_STATUS="selected_policy_summary_results_junit_check_log_preserved"

    {
        echo "safe dry-run: xfstests check was not invoked"
        echo "reason: upstream ./check -n validates TEST_DEV/SCRATCH_DEV and can call mount/mkfs/unmount before listing tests"
        echo "planned command:"
        echo "  ./check -n ${SELECTED_TESTS[*]}"
        echo "xfstests_dir: $XFSTESTS_DIR"
        echo "result_base: $RESULT_BASE"
        echo "test_dir: ${TEST_DIR:-}"
        echo "scratch_mnt: ${SCRATCH_MNT:-}"
        echo
        echo "selected tests:"
        printf '  %s planned\n' "${SELECTED_TESTS[@]}"
    } >"$CHECK_LOG"
    {
        echo "safe dry-run stdout marker"
        echo "planned command: ./check -n ${SELECTED_TESTS[*]}"
    } >"$ARTIFACT_DIR/stdout.log"
    : >"$ARTIFACT_DIR/stderr.log"

    if harness_supports_xfstests_report; then
        "$FFS_HARNESS_BIN" xfstests-report \
            --selected "$SELECTED_FILE" \
            --results-json "$RESULTS_JSON" \
            --junit-xml "$JUNIT_FILE" \
            --allowlist-json "$XFSTESTS_ALLOWLIST_JSON" \
            --uniform-status planned \
            --uniform-note "$note"
    else
        write_uniform_results "planned" "$note"
    fi
}

skip_or_fail() {
    local reason="$1"
    if [[ ! -f "$CHECK_LOG" ]]; then
        {
            echo "xfstests subset not executed"
            echo "reason: $reason"
            echo "planned command: ./check ${SELECTED_TESTS[*]}"
        } >"$CHECK_LOG"
    fi
    if [[ ! -f "$ARTIFACT_DIR/stdout.log" ]]; then
        : >"$ARTIFACT_DIR/stdout.log"
    fi
    if [[ ! -f "$ARTIFACT_DIR/stderr.log" ]]; then
        : >"$ARTIFACT_DIR/stderr.log"
    fi
    if [[ ! -f "$RESULTS_JSON" ]]; then
        write_uniform_results "not_run" "$reason"
    fi
    write_baseline_manifest_artifacts
    write_summary "skipped" "$EFFECTIVE_MODE" "$reason" "$LAST_CHECK_RC"
    if [[ "$XFSTESTS_STRICT" == "1" ]]; then
        e2e_fail "$reason"
    fi
    e2e_skip "$reason"
}

ensure_xfstests_preflight() {
    e2e_step "xfstests prerequisite preflight"

    if [[ ! -f "$XFSTESTS_PREFLIGHT_JSON" ]]; then
        if [[ ! -f "$XFSTESTS_PREFLIGHT_SCRIPT" ]]; then
            skip_or_fail "xfstests prerequisite preflight script missing: $XFSTESTS_PREFLIGHT_SCRIPT"
        fi
        if ! "$XFSTESTS_PREFLIGHT_SCRIPT" --out "$XFSTESTS_PREFLIGHT_JSON" >"$ARTIFACT_DIR/preflight.stdout" 2>"$ARTIFACT_DIR/preflight.stderr"; then
            skip_or_fail "xfstests prerequisite preflight failed to emit proof (stdout=$ARTIFACT_DIR/preflight.stdout stderr=$ARTIFACT_DIR/preflight.stderr)"
        fi
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        skip_or_fail "python3 is required to validate xfstests prerequisite proof"
    fi

    local preflight_reason
    if ! preflight_reason="$(python3 - "$XFSTESTS_PREFLIGHT_JSON" "$XFSTESTS_PREFLIGHT_MAX_AGE_SECS" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

manifest_path = pathlib.Path(sys.argv[1])
max_age_secs = int(sys.argv[2])
required = {
    "xfs_headers",
    "libaio",
    "ltp_fsstress",
    "xfstests_helpers",
    "mkfs_mount_helpers",
    "dev_fuse",
    "fusermount3",
    "user_namespace_or_mount_permissions",
    "scratch_test_directories",
    "dpkg_lock_state",
    "rch_ci_worker_identity",
}
side_effect_policy = "read_only_probe_no_install_no_mount_no_host_mutation"
status_values = {
    "present",
    "missing",
    "blocked-by-host",
    "blocked-by-lock",
    "unsupported-locally",
    "available-on-worker",
}
risk_values = {"satisfied", "blocking", "advisory"}
lane_impacts = {
    "none",
    "blocks_permissioned_real_xfstests",
    "release_evidence_requires_worker",
}
package_manager_commands = {"apt", "apt-get", "dnf", "yum", "pacman", "zypper", "brew"}
persistent_mutation_commands = {"cp", "dd", "install", "mkdir", "mv", "rm", "rmdir", "tee", "touch", "truncate"}
version_only_commands = {"mkfs.ext4", "mkfs.xfs", "mount", "umount", "fusermount", "fusermount3"}
version_args = {"--version", "-V", "-v", "-h", "--help"}


def risk_level_for(status, blocks):
    if blocks and status != "present":
        return "blocking"
    if status in {"unsupported-locally", "available-on-worker"}:
        return "advisory"
    return "satisfied"


def lane_impact_for(name, status, blocks):
    if blocks and status != "present":
        return "blocks_permissioned_real_xfstests"
    if name == "rch_ci_worker_identity" and status == "unsupported-locally":
        return "release_evidence_requires_worker"
    return "none"


def safe_probe_argv(argv):
    if not isinstance(argv, list) or not argv:
        return False
    command = pathlib.Path(str(argv[0])).name
    args = [str(arg) for arg in argv[1:]]
    if command in package_manager_commands or command in persistent_mutation_commands:
        return False
    if command in version_only_commands:
        return bool(args) and all(arg in version_args for arg in args)
    return True

if not manifest_path.exists():
    print(f"missing preflight manifest: {manifest_path}")
    sys.exit(1)

try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"invalid preflight manifest JSON: {exc}")
    sys.exit(1)

created_at = manifest.get("created_at")
try:
    created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
except ValueError:
    print(f"invalid preflight created_at: {created_at}")
    sys.exit(1)
age = (datetime.now(timezone.utc) - created).total_seconds()
if age < 0:
    print(f"future preflight created_at: {created_at}")
    sys.exit(1)
if age > max_age_secs:
    print(f"stale preflight manifest: age_secs={age:.0f} max_age_secs={max_age_secs}")
    sys.exit(1)

if manifest.get("schema_version") != 1:
    print("preflight manifest schema_version must be 1")
    sys.exit(1)
if manifest.get("bead_id") != "bd-rchk3.1.1":
    print("preflight manifest bead_id must be bd-rchk3.1.1")
    sys.exit(1)
if set(manifest.get("status_vocabulary", [])) != status_values:
    print("preflight manifest status_vocabulary does not match required statuses")
    sys.exit(1)
if set(manifest.get("risk_vocabulary", [])) != risk_values:
    print("preflight manifest risk_vocabulary does not match required risk levels")
    sys.exit(1)
if set(manifest.get("authoritative_lane_impact_vocabulary", [])) != lane_impacts:
    print("preflight manifest lane-impact vocabulary does not match required values")
    sys.exit(1)

for field in [
    "host",
    "worker_identity",
    "paths",
    "transcript_dir",
    "stdout_path",
    "stderr_path",
    "cleanup_status",
    "reproduction_command",
]:
    if field not in manifest:
        print(f"preflight manifest missing {field}")
        sys.exit(1)
if manifest.get("cleanup_status") != "no_mounts_or_temp_files_created":
    print("preflight manifest cleanup_status does not prove read-only preflight cleanup")
    sys.exit(1)
for field in ["stdout_path", "stderr_path"]:
    path = pathlib.Path(str(manifest.get(field)))
    if not path.is_file():
        print(f"preflight manifest {field} does not exist: {path}")
        sys.exit(1)
transcript_dir = pathlib.Path(str(manifest.get("transcript_dir")))
if not transcript_dir.is_dir():
    print(f"preflight manifest transcript_dir does not exist: {transcript_dir}")
    sys.exit(1)
links = manifest.get("links", {})
if links.get("selected_test_policy_bead") != "bd-rchk3.2":
    print("preflight manifest must link selected-test policy bead bd-rchk3.2")
    sys.exit(1)
if links.get("real_execution_bead") != "bd-rchk3.3":
    print("preflight manifest must link real execution bead bd-rchk3.3")
    sys.exit(1)

prereqs = manifest.get("prerequisites")
if not isinstance(prereqs, list):
    print("preflight manifest prerequisites must be a list")
    sys.exit(1)
names = {row.get("name") for row in prereqs if isinstance(row, dict)}
missing_names = sorted(required - names)
if missing_names:
    print(f"preflight manifest missing prerequisite probes: {', '.join(missing_names)}")
    sys.exit(1)

safety = manifest.get("remediation_safety")
if not isinstance(safety, dict):
    print("preflight manifest missing remediation_safety")
    sys.exit(1)
if safety.get("side_effect_policy") != side_effect_policy:
    print("preflight manifest has unsupported side-effect policy")
    sys.exit(1)
for field in [
    "runner_executes_remediation",
    "auto_install",
    "mounts_or_unmounts",
    "creates_persistent_paths",
]:
    if safety.get(field) is not False:
        print(f"preflight remediation_safety {field} must be false")
        sys.exit(1)
if safety.get("requires_fresh_follow_up_probe") is not True:
    print("preflight remediation_safety must require a fresh follow-up probe")
    sys.exit(1)

blocking = manifest.get("blocking_prerequisites", [])
if manifest.get("verdict") != "pass" or blocking:
    blocking_text = ", ".join(blocking) if isinstance(blocking, list) else str(blocking)
    print(f"preflight verdict={manifest.get('verdict')} blocking={blocking_text}")
    sys.exit(1)

for row in prereqs:
    if not isinstance(row, dict):
        print("preflight prerequisite row must be an object")
        sys.exit(1)
    name = str(row.get("name"))
    status = str(row.get("status"))
    blocks = bool(row.get("blocks_real_xfstests"))
    if blocks and status != "present":
        print(f"blocking prerequisite is not present: {name} status={status}")
        sys.exit(1)
    if status not in status_values:
        print(f"preflight prerequisite {name} has invalid status")
        sys.exit(1)
    if row.get("risk_level") not in risk_values:
        print(f"preflight prerequisite {name} has invalid risk_level")
        sys.exit(1)
    if row.get("risk_level") != risk_level_for(status, blocks):
        print(f"preflight prerequisite {name} has inconsistent risk_level")
        sys.exit(1)
    if row.get("authoritative_lane_impact") not in lane_impacts:
        print(f"preflight prerequisite {name} has invalid authoritative_lane_impact")
        sys.exit(1)
    if row.get("authoritative_lane_impact") != lane_impact_for(name, status, blocks):
        print(f"preflight prerequisite {name} has inconsistent authoritative_lane_impact")
        sys.exit(1)
    if row.get("side_effect_policy") != side_effect_policy:
        print(f"preflight prerequisite {name} has unsupported side-effect policy")
        sys.exit(1)
    safe = row.get("safe_remediation")
    if not isinstance(safe, dict) or safe.get("automation") != "manual_only":
        print(f"preflight prerequisite {name} missing manual-only remediation contract")
        sys.exit(1)
    for field in [
        "runner_executes_remediation",
        "auto_install",
        "mounts_or_unmounts",
        "creates_persistent_paths",
    ]:
        if safe.get(field) is not False:
            print(f"preflight prerequisite {name} safe_remediation {field} must be false")
            sys.exit(1)
    if not str(row.get("remediation_text_id", "")).startswith("xfstests-preflight-"):
        print(f"preflight prerequisite {name} missing remediation_text_id")
        sys.exit(1)
    if not row.get("reproduction_command"):
        print(f"preflight prerequisite {name} missing reproduction_command")
        sys.exit(1)
    for probe in row.get("probes", []):
        if isinstance(probe, dict) and not safe_probe_argv(probe.get("argv")):
            print(f"preflight prerequisite {name} has mutating probe argv: {probe.get('argv')}")
            sys.exit(1)
        if isinstance(probe, dict):
            for field in ["stdout_path", "stderr_path"]:
                raw = probe.get(field)
                if raw and not pathlib.Path(str(raw)).is_file():
                    print(f"preflight prerequisite {name} probe {field} does not exist: {raw}")
                    sys.exit(1)

print("preflight passed")
PY
)"; then
        skip_or_fail "xfstests prerequisite proof unavailable for product baseline: $preflight_reason"
    fi

    XFSTESTS_PREFLIGHT_ACCEPTED="1"
    e2e_log "Preflight manifest accepted: $XFSTESTS_PREFLIGHT_JSON ($preflight_reason)"
}

load_test_list() {
    local list_path="$1"
    local kind="$2"
    local -n output_ref="$3"

    if [[ ! -f "$list_path" ]]; then
        e2e_fail "Test list not found: $list_path"
    fi

    mapfile -t output_ref < <(awk '{
        line = $0
        sub(/#.*/, "", line)
        gsub(/^[ \t]+|[ \t]+$/, "", line)
        if (line != "") print line
    }' "$list_path")

    if [[ ${#output_ref[@]} -eq 0 ]]; then
        e2e_fail "Test list is empty: $list_path"
    fi

    local test_id
    for test_id in "${output_ref[@]}"; do
        if [[ ! "$test_id" =~ ^${kind}/[0-9]{3}$ ]]; then
            e2e_fail "Invalid test id '$test_id' in $list_path (expected ${kind}/NNN)"
        fi
    done
}

build_selection() {
    local -a raw_selection=()
    case "$XFSTESTS_FILTER" in
        all)
            raw_selection=("${GENERIC_TESTS[@]}" "${EXT4_TESTS[@]}" "${BTRFS_TESTS[@]}")
            ;;
        generic)
            raw_selection=("${GENERIC_TESTS[@]}")
            ;;
        ext4)
            raw_selection=("${EXT4_TESTS[@]}")
            ;;
        btrfs)
            raw_selection=("${BTRFS_TESTS[@]}")
            ;;
        *)
            e2e_fail "Invalid XFSTESTS_FILTER='$XFSTESTS_FILTER' (expected all|generic|ext4|btrfs)"
            ;;
    esac

    declare -A seen=()
    local test_id
    for test_id in "${raw_selection[@]}"; do
        if [[ -z "${seen[$test_id]+x}" ]]; then
            seen[$test_id]=1
            SELECTED_TESTS+=("$test_id")
        fi
    done

    if [[ ${#SELECTED_TESTS[@]} -eq 0 ]]; then
        e2e_fail "No tests selected after applying filter '$XFSTESTS_FILTER'"
    fi
}

verify_tests_exist() {
    local -a missing=()
    local test_id
    for test_id in "${SELECTED_TESTS[@]}"; do
        if [[ ! -f "$XFSTESTS_DIR/tests/$test_id" ]]; then
            missing+=("$test_id")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        e2e_log "Missing tests in $XFSTESTS_DIR/tests:"
        printf '%s\n' "${missing[@]}" | while IFS= read -r line; do
            e2e_log "  $line"
        done
        e2e_fail "Selected xfstests ids missing from xfstests checkout"
    fi
}

generate_results_from_check_log() {
    local check_rc="$1"
    LAST_CHECK_RC="$check_rc"

    if harness_supports_xfstests_report; then
        local -a harness_args=(
            xfstests-report
            --selected "$SELECTED_FILE"
            --check-log "$CHECK_LOG"
            --results-json "$RESULTS_JSON"
            --junit-xml "$JUNIT_FILE"
            --check-rc "$check_rc"
            --dry-run "$XFSTESTS_DRY_RUN"
            --allowlist-json "$XFSTESTS_ALLOWLIST_JSON"
        )
        if [[ -n "$XFSTESTS_BASELINE_JSON" ]]; then
            harness_args+=(--baseline-json "$XFSTESTS_BASELINE_JSON")
        fi
        "$FFS_HARNESS_BIN" "${harness_args[@]}"
        return 0
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        e2e_log "python3 not found; writing fallback not_run result artifacts"
        write_uniform_results "not_run" "python3 unavailable; unable to parse check output"
        return 0
    fi

    python3 - "$SELECTED_FILE" "$CHECK_LOG" "$RESULTS_JSON" "$JUNIT_FILE" "$check_rc" "$XFSTESTS_DRY_RUN" <<'PY'
import json
import pathlib
import re
import sys
import xml.sax.saxutils

selected_file = pathlib.Path(sys.argv[1])
check_log = pathlib.Path(sys.argv[2])
results_json = pathlib.Path(sys.argv[3])
junit_xml = pathlib.Path(sys.argv[4])
check_rc = int(sys.argv[5])
dry_run = int(sys.argv[6])

selected = [line.strip() for line in selected_file.read_text(encoding="utf-8").splitlines() if line.strip()]
status = {tid: "not_run" for tid in selected}
rank = {"not_run": 1, "planned": 1, "skipped": 2, "passed": 3, "failed": 4}

def line_mentions_test_id(line: str, test_id: str) -> bool:
    return any(part == test_id for part in line.split())

if check_log.exists():
    for line in check_log.read_text(encoding="utf-8", errors="replace").splitlines():
        low = line.lower()
        for tid in selected:
            if not line_mentions_test_id(line, tid):
                continue
            candidate = None
            if "not run" in low or "notrun" in low:
                candidate = "not_run"
            elif "skipped" in low:
                candidate = "skipped"
            elif re.search(r"\b(fail|failed|error)\b", low):
                candidate = "failed"
            elif re.search(r"\b(pass|passed|ok|success)\b", low):
                candidate = "passed"
            if candidate and rank[candidate] >= rank[status[tid]]:
                status[tid] = candidate

tests = [{"id": tid, "status": status[tid]} for tid in selected]
counts = {"passed": 0, "failed": 0, "skipped": 0, "not_run": 0, "planned": 0}
for rec in tests:
    key = rec["status"]
    counts[key] = counts.get(key, 0) + 1

total = len(selected)
pass_rate = (counts["passed"] / total) if total else 0.0

payload = {
    "source": "check-log",
    "check_rc": check_rc,
    "dry_run": dry_run,
    "total": total,
    "passed": counts["passed"],
    "failed": counts["failed"],
    "skipped": counts["skipped"],
    "not_run": counts["not_run"],
    "planned": counts["planned"],
    "pass_rate": pass_rate,
    "tests": tests,
}
results_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with junit_xml.open("w", encoding="utf-8") as fh:
    failures = counts["failed"]
    skipped = counts["skipped"] + counts["not_run"] + counts["planned"]
    fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fh.write(f'<testsuite name="ffs_xfstests_e2e" tests="{total}" failures="{failures}" skipped="{skipped}">\n')
    for rec in tests:
        tid = xml.sax.saxutils.escape(rec["id"], {'"': "&quot;", "'": "&apos;"})
        test_status = rec["status"]
        fh.write(f'  <testcase name="{tid}" time="0.000">')
        if test_status == "failed":
            fh.write('<failure message="xfstests failure">xfstests failure</failure>')
        elif test_status in {"skipped", "not_run", "planned"}:
            msg = xml.sax.saxutils.escape(test_status, {'"': "&quot;", "'": "&apos;"})
            fh.write(f'<skipped message="{msg}"/>')
        fh.write("</testcase>\n")
    fh.write("</testsuite>\n")
PY
}

enforce_regression_guard() {
    if [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        e2e_log "Skipping regression guard in dry-run mode"
        return 0
    fi

    if [[ ! -f "$XFSTESTS_REGRESSION_GUARD_JSON" ]]; then
        e2e_log "Regression guard file not found; skipping guard: $XFSTESTS_REGRESSION_GUARD_JSON"
        return 0
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        if [[ "$XFSTESTS_STRICT" == "1" ]]; then
            e2e_fail "python3 is required to enforce xfstests regression guard in strict mode"
        fi
        e2e_log "python3 not found; skipping regression guard"
        return 0
    fi

    if ! python3 - "$RESULTS_JSON" "$XFSTESTS_REGRESSION_GUARD_JSON" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
guard_path = pathlib.Path(sys.argv[2])
results = json.loads(results_path.read_text(encoding="utf-8"))
guard = json.loads(guard_path.read_text(encoding="utf-8"))

status_by_test = {rec.get("id"): rec.get("status") for rec in results.get("tests", [])}
passed = int(results.get("passed", 0))
pass_rate = float(results.get("pass_rate", 0.0))

must_pass = [t for t in guard.get("must_pass", []) if isinstance(t, str)]
min_pass_count = int(guard.get("min_pass_count", 0))
min_pass_rate = float(guard.get("min_pass_rate", 0.0))

failures = []
for tid in must_pass:
    if status_by_test.get(tid) != "passed":
        failures.append(f"must-pass test did not pass: {tid} (status={status_by_test.get(tid)})")

if passed < min_pass_count:
    failures.append(f"passed={passed} below min_pass_count={min_pass_count}")
if pass_rate < min_pass_rate:
    failures.append(f"pass_rate={pass_rate:.4f} below min_pass_rate={min_pass_rate:.4f}")

if failures:
    print("xfstests regression guard failures:", file=sys.stderr)
    for item in failures:
        print(f"  - {item}", file=sys.stderr)
    sys.exit(1)
PY
    then
        e2e_fail "xfstests regression guard failed"
    fi
}

run_xfstests_subset() {
    local -a check_args=()
    if [[ "$XFSTESTS_DRY_RUN" == "1" ]]; then
        check_args+=("-n")
    fi
    check_args+=("${SELECTED_TESTS[@]}")

    e2e_log "Running xfstests command from $XFSTESTS_DIR:"
    e2e_log "  ./check ${check_args[*]}"

    local rc=0
    (cd "$XFSTESTS_DIR" && ./check "${check_args[@]}") >"$ARTIFACT_DIR/stdout.log" 2>"$ARTIFACT_DIR/stderr.log" || rc=$?
    {
        cat "$ARTIFACT_DIR/stdout.log"
        cat "$ARTIFACT_DIR/stderr.log"
    } >"$CHECK_LOG"
    generate_results_from_check_log "$rc"

    if [[ $rc -ne 0 ]]; then
        # Only a check that never started a test is a prerequisite problem. Once
        # xfstests prints its "Ran:" summary, a "Permission denied" in the log is
        # test output (e.g. a failing setfattr), and treating it as a skip
        # would report real product failures as a green skip.
        if ! grep -q '^Ran:' "$CHECK_LOG" \
            && grep -qiE "not found or executable|must be run as root|Permission denied" "$CHECK_LOG"; then
            skip_or_fail "xfstests prerequisites unavailable for execution (see $CHECK_LOG)"
        fi
        e2e_log "xfstests check failed; tailing log:"
        e2e_run tail -n 120 "$CHECK_LOG" || true
        XFSTESTS_CLEANUP_STATUS="xfstests_check_failed_artifacts_preserved"
        XFSTESTS_PARTIAL_RUN_STATUS="summary_results_junit_check_log_preserved_after_failure"
        write_baseline_manifest_artifacts
        write_summary "failed" "$EFFECTIVE_MODE" "xfstests check failed with exit code $rc; artifacts preserved" "$LAST_CHECK_RC"
        e2e_fail "xfstests check failed with exit code $rc"
    fi

    enforce_regression_guard
    e2e_log "xfstests check completed successfully"
}

e2e_step "Load curated xfstests subsets"
load_test_list "$XFSTESTS_GENERIC_LIST" "generic" GENERIC_TESTS
load_test_list "$XFSTESTS_EXT4_LIST" "ext4" EXT4_TESTS
load_test_list "$XFSTESTS_BTRFS_LIST" "btrfs" BTRFS_TESTS
build_selection

printf '%s\n' "${SELECTED_TESTS[@]}" >"$SELECTED_FILE"
e2e_log "Selected tests written to: $SELECTED_FILE"
e2e_log "Selected test count: ${#SELECTED_TESTS[@]}"
write_policy_plan
e2e_log "Policy plan written to: $POLICY_PLAN_JSON"
e2e_log "Policy report written to: $POLICY_REPORT_MD"

resolve_xfstests_dir
EFFECTIVE_MODE="$XFSTESTS_MODE"
if [[ "$EFFECTIVE_MODE" == "auto" ]]; then
    if [[ -n "$XFSTESTS_DIR" ]] && [[ -x "$XFSTESTS_DIR/check" ]]; then
        EFFECTIVE_MODE="run"
    else
        EFFECTIVE_MODE="plan"
    fi
fi

if [[ "$EFFECTIVE_MODE" == "plan" ]]; then
    e2e_step "Plan mode"
    ensure_xfstests_preflight
    if harness_supports_xfstests_report; then
        "$FFS_HARNESS_BIN" xfstests-report \
            --selected "$SELECTED_FILE" \
            --results-json "$RESULTS_JSON" \
            --junit-xml "$JUNIT_FILE" \
            --allowlist-json "$XFSTESTS_ALLOWLIST_JSON" \
            --uniform-status planned \
            --uniform-note "subset materialized; execution not requested"
    else
        write_uniform_results "planned" "subset materialized; execution not requested"
    fi
    XFSTESTS_CLEANUP_STATUS="plan_mode_no_xfstests_check_invoked"
    XFSTESTS_PARTIAL_RUN_STATUS="selected_policy_summary_results_junit_check_log_preserved"
    {
        echo "plan mode: xfstests check was not invoked"
        echo "planned command:"
        echo "  ./check -n ${SELECTED_TESTS[*]}"
        echo
        echo "selected tests:"
        printf '  %s planned\n' "${SELECTED_TESTS[@]}"
    } >"$CHECK_LOG"
    {
        echo "plan mode stdout marker"
        echo "planned command: ./check -n ${SELECTED_TESTS[*]}"
    } >"$ARTIFACT_DIR/stdout.log"
    : >"$ARTIFACT_DIR/stderr.log"
    write_baseline_manifest_artifacts
    write_summary "planned" "$EFFECTIVE_MODE" "subset materialized; execution not requested" "null"
    e2e_log "Plan summary: $SUMMARY_JSON"
    e2e_pass
    exit 0
fi

if [[ "$EFFECTIVE_MODE" != "run" ]]; then
    e2e_fail "Invalid XFSTESTS_MODE='$XFSTESTS_MODE' (expected auto|plan|run)"
fi

prepare_safe_dry_run_config
ensure_xfstests_preflight

if [[ -z "$XFSTESTS_DIR" ]]; then
    skip_or_fail "XFSTESTS_DIR is not set and no default xfstests checkout was found"
fi
if [[ ! -x "$XFSTESTS_DIR/check" ]]; then
    skip_or_fail "xfstests check runner not found at $XFSTESTS_DIR/check"
fi

if [[ "$XFSTESTS_DRY_RUN" == "1" && "$XFSTESTS_INVOKE_CHECK_DRY_RUN" != "1" ]]; then
    e2e_step "Safe xfstests dry-run artifacts"
    e2e_log "XFSTESTS_DIR: $XFSTESTS_DIR"
    e2e_log "XFSTESTS_DRY_RUN: $XFSTESTS_DRY_RUN"
    e2e_log "Not invoking upstream ./check -n because it performs mount/mkfs validation before listing tests"
    verify_tests_exist
    write_safe_dry_run_artifacts
    write_baseline_manifest_artifacts
    write_summary "planned" "$EFFECTIVE_MODE" "safe dry-run artifacts emitted without invoking xfstests check" "$LAST_CHECK_RC"
    e2e_log "Run summary: $SUMMARY_JSON"
    e2e_pass
    exit 0
fi

if [[ "$XFSTESTS_DRY_RUN" == "0" && "$XFSTESTS_REAL_RUN_ACK" != "xfstests-may-mutate-test-and-scratch-devices" ]]; then
    XFSTESTS_CLEANUP_STATUS="real_run_not_started_missing_ack"
    XFSTESTS_PARTIAL_RUN_STATUS="selected_policy_artifacts_preserved_before_real_execution"
    write_uniform_results "not_run" "real xfstests execution requires XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices"
    skip_or_fail "real xfstests execution requires XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices"
fi

e2e_step "Run xfstests subset"
e2e_log "XFSTESTS_DIR: $XFSTESTS_DIR"
e2e_log "XFSTESTS_DRY_RUN: $XFSTESTS_DRY_RUN"
verify_tests_exist
run_xfstests_subset

XFSTESTS_CLEANUP_STATUS="xfstests_check_completed"
XFSTESTS_PARTIAL_RUN_STATUS="selected_policy_summary_results_junit_check_log_preserved"
write_baseline_manifest_artifacts
write_summary "passed" "$EFFECTIVE_MODE" "xfstests subset check completed" "$LAST_CHECK_RC"
e2e_log "Run summary: $SUMMARY_JSON"
e2e_pass
exit 0
