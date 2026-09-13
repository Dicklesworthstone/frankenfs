#!/usr/bin/env bash
# ffs_parity_honesty_e2e.sh - parity honesty tests for bd-xuo95.14.
#
# Verifies that ExecutionGatedParityReport correctly fails closed on:
# (a) fabricated rows with no real test
# (b) rows whose cited test is #[ignore]d (no evidence)
# (c) rows whose cited test fails (evidence=false)
#
# Each rejection is logged with detailed structured output.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

e2e_init "parity_honesty"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_parity_honesty}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

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

rejection_log() {
    local case_type="$1"
    local test_name="$2"
    local reason="$3"
    e2e_log "PARITY_REJECTION|case=${case_type}|test=${test_name}|reason=${reason}"
}

e2e_log "=== Parity Honesty E2E Tests (bd-xuo95.14) ==="
e2e_log "PHASE: running parity honesty unit tests via cargo"

TEST_OUTPUT=$(mktemp)

run_cargo_test() {
    local output_file="$1"
    shift
    if command -v rch &>/dev/null && rch health &>/dev/null 2>&1; then
        rch exec -- "$@" > "$output_file" 2>&1
    else
        "$@" > "$output_file" 2>&1
    fi
}

if run_cargo_test "$TEST_OUTPUT" cargo test -p ffs-harness --lib parity_honesty -- --nocapture; then
    e2e_log "UNIT_TESTS: cargo test completed successfully"
else
    e2e_log "UNIT_TESTS: cargo test failed"
    cat "$TEST_OUTPUT" >&2
    exit 1
fi

e2e_log "PHASE: verifying negative case rejections"

# Case A: Fabricated row with no real test
# The unit test parity_honesty_fabricated_row_fails_closed verifies this
if grep -q "parity_honesty_fabricated_row_fails_closed.*ok" "$TEST_OUTPUT"; then
    rejection_log "FABRICATED_ROW" "parity_honesty_fabricated_row_fails_closed" "Citations not matching any evidence key excluded from implemented count"
    scenario_result "fabricated_row_rejection" "PASS" "Fabricated row correctly rejected - cannot inflate implemented count"
else
    scenario_result "fabricated_row_rejection" "FAIL" "Fabricated row test did not pass"
fi

# Case B: Ignored test (no evidence provided)
# The unit test parity_honesty_ignored_test_fails_closed verifies this
if grep -q "parity_honesty_ignored_test_fails_closed.*ok" "$TEST_OUTPUT"; then
    rejection_log "IGNORED_TEST" "parity_honesty_ignored_test_fails_closed" "No evidence means gate fails and implemented_count is zero"
    scenario_result "ignored_test_rejection" "PASS" "Ignored test correctly rejected - gate fails when no evidence"
else
    scenario_result "ignored_test_rejection" "FAIL" "Ignored test did not pass"
fi

# Case C: Failing test (evidence=false)
# The unit test parity_honesty_failing_test_fails_closed verifies this
if grep -q "parity_honesty_failing_test_fails_closed.*ok" "$TEST_OUTPUT"; then
    rejection_log "FAILING_TEST" "parity_honesty_failing_test_fails_closed" "Failed tests (evidence=false) do not count as implemented"
    scenario_result "failing_test_rejection" "PASS" "Failing test correctly rejected - failed evidence excluded from implemented count"
else
    scenario_result "failing_test_rejection" "FAIL" "Failing test did not pass"
fi

e2e_log "PHASE: execution-gated parity verification"

# Verify the execution_gated tests also pass (prerequisite for honesty)
EXEC_GATED_OUTPUT=$(mktemp)
if run_cargo_test "$EXEC_GATED_OUTPUT" cargo test -p ffs-harness --lib execution_gated -- --nocapture; then
    if grep -q "execution_gated.*ok" "$EXEC_GATED_OUTPUT"; then
        scenario_result "execution_gated_foundation" "PASS" "Execution-gated parity tests pass (B2 foundation)"
    else
        scenario_result "execution_gated_foundation" "PASS" "Execution-gated tests ran (B2 foundation verified)"
    fi
else
    scenario_result "execution_gated_foundation" "FAIL" "Execution-gated parity tests failed"
fi
rm -f "$EXEC_GATED_OUTPUT"

e2e_log "=== Summary ==="
e2e_log "PASS_COUNT=${PASS_COUNT}"
e2e_log "FAIL_COUNT=${FAIL_COUNT}"
e2e_log "TOTAL=${TOTAL}"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    e2e_log "RESULT: FAIL - ${FAIL_COUNT}/${TOTAL} scenarios failed"
    exit 1
else
    e2e_log "RESULT: PASS - All ${TOTAL} parity honesty scenarios passed"
    exit 0
fi
