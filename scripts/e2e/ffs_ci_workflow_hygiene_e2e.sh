#!/usr/bin/env bash
# ffs_ci_workflow_hygiene_e2e.sh - E2E verification for CI workflow hygiene,
# benchmark target registration (173 == 173), portable V1.2 local gate mode,
# and strict parity evidence enforcement (bd-fix-broken-ci-workflows-and-benches-h5t78).

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"

source "$REPO_ROOT/scripts/e2e/lib.sh"

EXECUTOR="${FFS_GATE_EXECUTOR:-auto}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)
            EXECUTOR="local"
            shift
            ;;
        --rch)
            EXECUTOR="rch"
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

run_cargo() {
    if [[ "$EXECUTOR" == "local" ]]; then
        cargo "$@"
    elif [[ "$EXECUTOR" == "rch" ]] || command -v rch >/dev/null 2>&1; then
        if [[ -n "${RCH_WORKER:-}" ]]; then
            rch exec --worker "$RCH_WORKER" -- cargo "$@"
        else
            rch exec -- cargo "$@"
        fi
    else
        cargo "$@"
    fi
}

e2e_init "ffs_ci_workflow_hygiene"
e2e_print_env

PASS_COUNT=0
FAIL_COUNT=0

record_check() {
    local id="$1"
    local status="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${id}|outcome=${status}|detail=${detail}"
    if [[ "$status" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

e2e_step "1. Verify portable V1.2 program gate smoke mode without rch"
V12_TMP_DIR="$E2E_TEMP_DIR/v12_local_smoke"
mkdir -p "$V12_TMP_DIR"
if env \
    FFS_GATE_EXECUTOR=local \
    FFS_V12_PROGRAM_GATE_SMOKE=1 \
    FFS_V12_PROGRAM_GATE_ARTIFACT_DIR="$V12_TMP_DIR/artifacts" \
    RUNNER_TEMP="$V12_TMP_DIR/runner_temp" \
    ./scripts/e2e/ffs_v12_program_gate_e2e.sh --local >"$V12_TMP_DIR/stdout.log" 2>"$V12_TMP_DIR/stderr.log" \
    && jq -e '.release_recommendation == "PROCEED" and .environment.executor_mode == "local" and .pass_count == 2 and .fail_count == 0' \
        "$V12_TMP_DIR/artifacts/program_gate_manifest.json" >/dev/null; then
    record_check "v12_program_gate_portable_local_smoke" "PASS" "manifest=$V12_TMP_DIR/artifacts/program_gate_manifest.json"
else
    record_check "v12_program_gate_portable_local_smoke" "FAIL" "stderr=$V12_TMP_DIR/stderr.log"
fi

e2e_step "2. Verify V1.2 program gate RCH fixture self-check still passes"
if env \
    FFS_V12_PROGRAM_GATE_RCH_SELF_CHECK=1 \
    FFS_V12_PROGRAM_GATE_ARTIFACT_DIR="$V12_TMP_DIR/rch_self_check" \
    ./scripts/e2e/ffs_v12_program_gate_e2e.sh --rch >"$V12_TMP_DIR/rch_self_check.stdout" 2>"$V12_TMP_DIR/rch_self_check.stderr"; then
    record_check "v12_program_gate_rch_self_check" "PASS" "stdout=$V12_TMP_DIR/rch_self_check.stdout"
else
    record_check "v12_program_gate_rch_self_check" "FAIL" "stderr=$V12_TMP_DIR/rch_self_check.stderr"
fi

e2e_step "3. Run ci_workflow_contracts integration suite"
if run_cargo test -p ffs-harness --test ci_workflow_contracts -- --nocapture; then
    record_check "ci_workflow_contracts_suite" "PASS" "all workflow and bench contracts verified"
else
    record_check "ci_workflow_contracts_suite" "FAIL" "ci_workflow_contracts failed"
fi

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    e2e_fail "ffs_ci_workflow_hygiene failed: ${FAIL_COUNT} scenario(s) failed"
else
    e2e_pass "ffs_ci_workflow_hygiene passed (${PASS_COUNT} scenarios)"
fi
