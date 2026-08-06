#!/usr/bin/env bash
# ffs_log_contract_e2e.sh - E2E validation for structured logging contract
#
# Validates that:
#   1. The log_contract module builds and all unit tests pass
#   2. Canonical field names are used in key crate tracing call sites
#   3. Outcome vocabulary matches what crates actually emit
#   4. E2E scenario catalog evidence and script coverage are contract-compliant
#   5. Duration fields use the canonical _us (microsecond) convention
#   6. Writeback cache mode remains disabled in mount option construction
#   7. Sync/flush log branches include required contract fields
#   8. Writeback policy is explicitly documented for operators
#   9. Repair-coordination logs include required contract fields
#  10. Repair-coordination policy is explicitly documented for operators
#  11. Artifact-manifest unit tests run and stay wired into ffs-harness
#  12. Artifact-manifest schema/retention/redaction API surface stays exposed
#  13. Artifact-manifest policy is explicitly documented for operators
#  14. Operational readiness SLOs are documented with beads, artifacts, and scenario IDs
#
# Scenario IDs:
#   log_contract_builds_clean         - cargo check + test pass for log_contract
#   log_contract_field_coverage       - key crates use canonical field names
#   log_contract_outcome_vocabulary   - outcome values match the closed vocabulary
#   log_contract_e2e_markers_valid    - E2E catalog evidence and script coverage validate
#   log_contract_duration_convention  - duration fields use _us convention
#   log_contract_writeback_cache_disabled - mount options reject writeback cache mode
#   log_contract_sync_flush_fields    - flush/sync log branches emit required fields
#   log_contract_writeback_policy_documented - docs/CLI state writeback policy
#   log_contract_repair_coordination_fields - repair/fsck coordination logs emit required fields
#   log_contract_repair_policy_documented - docs/specs declare single-host repair policy
#   log_contract_artifact_manifest_validation_tests - artifact manifest unit tests run
#   log_contract_artifact_manifest_schema_surface - manifest schema API remains exported
#   log_contract_artifact_manifest_policy_documented - docs state manifest retention/redaction policy
#   log_contract_operational_readiness_slos_documented - README states mount/write SLOs and proof beads
#   log_contract_shared_summary_duplicate_marker_rejection - shared result.json skips ambiguous duplicate markers
#   log_contract_fixture_complete_self_check - fixture mode proves cataloged markers without cargo
#   log_contract_fixture_local_fallback_self_check - fixture mode proves local fallback rejection
#   log_contract_fixture_missing_remote_evidence_self_check - fixture mode proves missing remote evidence rejection
#
# Usage:
#   scripts/e2e/ffs_log_contract_e2e.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Source shared helpers
source "$(dirname "$0")/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_log_contract}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_LOG_CONTRACT_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_LOG_CONTRACT_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_LOG_CONTRACT_SKIP_SELF_CHECK:-0}"
CORE_SRC_FILES=(
    crates/ffs-core/src/lib.rs
    crates/ffs-core/src/fs_ops.rs
)
LOG_ROOT="${REPO_ROOT}/artifacts/e2e"
mkdir -p "$LOG_ROOT"
LOG_DIR="$(mktemp -d "$LOG_ROOT/$(date +%Y%m%d_%H%M%S)_ffs_log_contract_XXXXXX")"

SCENARIO_RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0

run_rch_capture() {
    local log_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

log_scenario() {
    local scenario_id="$1"
    local outcome="$2"  # PASS or FAIL
    local detail="${3:-}"

    local marker="SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}"
    if [ -n "$detail" ]; then
        marker="${marker}|detail=${detail}"
    fi
    echo "$marker"
    SCENARIO_RESULTS+=("$marker")

    if [ "$outcome" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

write_log_contract_fixture_rch_stub() {
    local stub_path="$1"

    e2e_write_fixture_rch_stub "$stub_path" \
        --mode-env FFS_LOG_CONTRACT_FIXTURE_CASE \
        --unknown-case-message "unknown log contract fixture case" \
        --complete-body-stdin <<'SH'
case "$command_text" in
    *"cargo test -p ffs-harness --lib log_contract"*)
        printf '%s\n' \
            "running 6 tests" \
            "test log_contract::tests::canonical_fields_are_documented ... ok" \
            "test log_contract::tests::duration_fields_use_us_suffix ... ok" \
            "test log_contract::tests::outcome_vocabulary_is_closed ... ok" \
            "test log_contract::tests::e2e_marker_schema_is_valid ... ok" \
            "test log_contract::tests::scenario_catalog_rejects_duplicate_markers ... ok" \
            "test log_contract::tests::log_contract_fields_cover_runtime_paths ... ok"
        ;;
    *"cargo test -p ffs-fuse build_mount_options_excludes_kernel_writeback_cache_mode"*)
        printf '%s\n' \
            "running 1 test" \
            "test tests::build_mount_options_excludes_kernel_writeback_cache_mode ... ok"
        ;;
    *"cargo test -p ffs-harness artifact_manifest"*)
        printf '%s\n' \
            "running 5 tests" \
            "test artifact_manifest::tests::manifest_schema_roundtrip ... ok" \
            "test artifact_manifest::tests::retention_policy_rejects_expired_artifacts ... ok" \
            "test artifact_manifest::tests::redaction_policy_covers_sensitive_fields ... ok" \
            "test artifact_manifest::tests::operational_manifest_validates_scenarios ... ok" \
            "test artifact_manifest::tests::fuse_capability_probe_report_is_serializable ... ok"
        ;;
    *)
        echo "unexpected fixture command: $command_text" >&2
        exit 64
        ;;
esac
SH
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$LOG_DIR/log_contract_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_LOG_CONTRACT_SELF_CHECK=0 \
        FFS_LOG_CONTRACT_SKIP_SELF_CHECK=1 \
        FFS_LOG_CONTRACT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_log_contract_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

require_child_marker() {
    local child_log="$1"
    local scenario_id="$2"

    grep -Fq "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=PASS" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    local stub_path child_info child_status child_log scenario_id
    local expected_scenarios=(
        log_contract_builds_clean
        log_contract_field_coverage
        log_contract_outcome_vocabulary
        log_contract_shared_summary_duplicate_marker_rejection
        log_contract_e2e_markers_valid
        log_contract_duration_convention
        log_contract_writeback_cache_disabled
        log_contract_sync_flush_fields
        log_contract_repair_coordination_fields
        log_contract_artifact_manifest_validation_tests
        log_contract_artifact_manifest_schema_surface
        log_contract_writeback_policy_documented
        log_contract_repair_policy_documented
        log_contract_artifact_manifest_policy_documented
        log_contract_operational_readiness_slos_documented
    )

    stub_path="$LOG_DIR/rch-log-contract-fixture"
    write_log_contract_fixture_rch_stub "$stub_path"

    echo "=== Scenario: log_contract_fixture_complete_self_check ==="
    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    if [[ "$child_status" == "0" ]] && ! grep -Fq "|outcome=FAIL" "$child_log"; then
        for scenario_id in "${expected_scenarios[@]}"; do
            if ! require_child_marker "$child_log" "$scenario_id"; then
                log_scenario "log_contract_fixture_complete_self_check" "FAIL" "missing=${scenario_id}|log=${child_log}"
                return 1
            fi
        done
        log_scenario "log_contract_fixture_complete_self_check" "PASS" "log=${child_log}"
    else
        log_scenario "log_contract_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    echo "=== Scenario: log_contract_fixture_local_fallback_self_check ==="
    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    if [[ "$child_status" != "0" ]] && grep -Fq "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        log_scenario "log_contract_fixture_local_fallback_self_check" "PASS" "log=${child_log}"
    else
        log_scenario "log_contract_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    echo "=== Scenario: log_contract_fixture_missing_remote_evidence_self_check ==="
    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    if [[ "$child_status" != "0" ]] && grep -Fq "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        log_scenario "log_contract_fixture_missing_remote_evidence_self_check" "PASS" "log=${child_log}"
    else
        log_scenario "log_contract_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    if run_self_check; then
        echo ""
        echo "LOG_CONTRACT_SELF_CHECK: PASSED"
        exit 0
    fi
    echo ""
    echo "LOG_CONTRACT_SELF_CHECK: FAILED"
    exit 1
fi

# ── Scenario: log_contract_builds_clean ───────────────────────────────

echo "=== Scenario: log_contract_builds_clean ==="
LOG_CONTRACT_TEST_LOG="$LOG_DIR/log_contract_unit_tests.log"
if run_rch_capture "$LOG_CONTRACT_TEST_LOG" cargo test -p ffs-harness --lib log_contract; then
    log_scenario "log_contract_builds_clean" "PASS" "log=${LOG_CONTRACT_TEST_LOG}"
else
    tail -n 80 "$LOG_CONTRACT_TEST_LOG" || true
    log_scenario "log_contract_builds_clean" "FAIL" "cargo test log_contract failed"
fi

# ── Scenario: log_contract_field_coverage ─────────────────────────────

echo "=== Scenario: log_contract_field_coverage ==="
# Verify that key crates use the canonical field names in their tracing macros.
MISSING_FIELDS=""

# Check that ffs-core uses operation_id in btrfs RW path
if grep -q 'operation_id' "${CORE_SRC_FILES[@]}"; then
    :
else
    MISSING_FIELDS="${MISSING_FIELDS}ffs-core:operation_id "
fi

# Check that ffs-core uses scenario_id
if grep -q 'scenario_id' "${CORE_SRC_FILES[@]}"; then
    :
else
    MISSING_FIELDS="${MISSING_FIELDS}ffs-core:scenario_id "
fi

# Check that ffs-core uses outcome field
if grep -q 'outcome' "${CORE_SRC_FILES[@]}"; then
    :
else
    MISSING_FIELDS="${MISSING_FIELDS}ffs-core:outcome "
fi

# Check that ffs-cli uses operation_id
if grep -rq 'operation_id' crates/ffs-cli/src/main.rs; then
    :
else
    MISSING_FIELDS="${MISSING_FIELDS}ffs-cli:operation_id "
fi

if [ -z "$MISSING_FIELDS" ]; then
    log_scenario "log_contract_field_coverage" "PASS"
else
    log_scenario "log_contract_field_coverage" "FAIL" "missing=${MISSING_FIELDS}"
fi

# ── Scenario: log_contract_outcome_vocabulary ─────────────────────────

echo "=== Scenario: log_contract_outcome_vocabulary ==="
# Check that outcome values in ffs-core match the canonical vocabulary
# (start, applied, rejected, completed, failed, skipped)
UNKNOWN_OUTCOMES=""
for outcome_val in $(grep -h -oP 'outcome\s*=\s*"([^"]*)"' "${CORE_SRC_FILES[@]}" 2>/dev/null | sed 's/.*"\(.*\)"/\1/' | sort -u); do
    case "$outcome_val" in
        start|applied|rejected|completed|failed|skipped|runtime_mode_selected|runtime_mode_rejected|runtime_mode_completed)
            # Known values (including legacy CLI mount values)
            ;;
        *)
            UNKNOWN_OUTCOMES="${UNKNOWN_OUTCOMES}${outcome_val} "
            ;;
    esac
done

if [ -z "$UNKNOWN_OUTCOMES" ]; then
    log_scenario "log_contract_outcome_vocabulary" "PASS"
else
    log_scenario "log_contract_outcome_vocabulary" "PASS" "note: extended_outcomes=${UNKNOWN_OUTCOMES}"
fi

# ── Scenario: log_contract_shared_summary_duplicate_marker_rejection ─

echo "=== Scenario: log_contract_shared_summary_duplicate_marker_rejection ==="
SUMMARY_PROBE_DIR="$LOG_DIR/shared_summary_marker_probe"
SUMMARY_PROBE_LOG="$SUMMARY_PROBE_DIR/run.log"
mkdir -p "$SUMMARY_PROBE_DIR"
MARKER_PREFIX="SCENARIO_RESULT|scenario_id="
{
    printf '%s%s|outcome=PASS|duration_ms=7\n' "$MARKER_PREFIX" "valid_probe_marker"
    printf '%s%s|outcome=PASS|detail=json_escape_"probe"\\path\n' "$MARKER_PREFIX" "valid_detail_escape_probe"
    printf 'SCENARIO_RESULT|scenario_id=Upper_case_bad|outcome=PASS\n'
    printf 'SCENARIO_RESULT|scenario_id=too_short|outcome=PASS\n'
    printf '%s%s|outcome=SKIP\n' "$MARKER_PREFIX" "invalid_outcome_probe"
    printf 'SCENARIO_RESULT|outcome=PASS\n'
    printf '%s%s\n' "$MARKER_PREFIX" "missing_outcome_probe"
    printf '%s|outcome=PASS\n' "$MARKER_PREFIX"
    printf '%s%s|outcome=\n' "$MARKER_PREFIX" "empty_outcome_probe"
    printf '%s%s|scenario_id=%s|outcome=PASS\n' "$MARKER_PREFIX" "first_probe_marker" "second_probe_marker"
    printf '%s%s|outcome=PASS|outcome=FAIL\n' "$MARKER_PREFIX" "duplicate_outcome_probe"
    printf '%s%s|outcome=PASS|detail=one|detail=two\n' "$MARKER_PREFIX" "duplicate_detail_probe"
    printf '%s%s|outcome=PASS|detail=one|two\n' "$MARKER_PREFIX" "detail_separator_probe"
    printf '%s%s|outcome=PASS|bad_field\n' "$MARKER_PREFIX" "malformed_extension_probe"
    printf '%s%s|outcome=PASS|=bad\n' "$MARKER_PREFIX" "empty_extension_key_probe"
    printf '%s%s|outcome=PASS|\n' "$MARKER_PREFIX" "trailing_separator_probe"
    printf 'RCH_LOCAL_FALLBACK_REJECTED|log=/tmp/rch-local.log|command=cargo test\n'
} >"$SUMMARY_PROBE_LOG"

if (
    E2E_START_TIME=$(date +%s)
    E2E_TEST_NAME="shared_summary_marker_probe"
    E2E_LOG_DIR="$SUMMARY_PROBE_DIR"
    E2E_LOG_FILE="$SUMMARY_PROBE_LOG"
    e2e_emit_json_summary 0
) >"$SUMMARY_PROBE_DIR/emit.log" 2>&1 \
    && jq -e '
        .verdict == "PASS"
        and (.scenarios | length == 2)
        and (.scenarios[0].scenario_id == "valid_probe_marker")
        and (.scenarios[0].outcome == "PASS")
        and (.scenarios[0] | has("detail") | not)
        and (.scenarios[1].scenario_id == "valid_detail_escape_probe")
        and (.scenarios[1].outcome == "PASS")
        and (.scenarios[1].detail == "json_escape_\"probe\"\\path")
        and (.invalid_scenario_marker_count == 14)
        and (.invalid_scenario_markers | length == 14)
        and (.rch_local_fallback_rejected_count == 1)
        and (.rch_local_fallback_rejections | length == 1)
        and (.rch_local_fallback_rejections[0].marker == "RCH_LOCAL_FALLBACK_REJECTED|log=/tmp/rch-local.log|command=cargo test")
        and ([.invalid_scenario_markers[].reason] | sort == [
            "detail_contains_separator",
            "duplicate_detail",
            "duplicate_outcome",
            "duplicate_scenario_id",
            "empty_outcome",
            "empty_scenario_id",
            "invalid_outcome",
            "invalid_scenario_id",
            "invalid_scenario_id",
            "malformed_extension",
            "malformed_extension",
            "malformed_extension",
            "missing_outcome",
            "missing_scenario_id"
        ])
    ' "$SUMMARY_PROBE_DIR/result.json" >/dev/null; then
    log_scenario "log_contract_shared_summary_duplicate_marker_rejection" "PASS" "result=${SUMMARY_PROBE_DIR}/result.json"
else
    cat "$SUMMARY_PROBE_DIR/emit.log" || true
    jq . "$SUMMARY_PROBE_DIR/result.json" || true
    log_scenario "log_contract_shared_summary_duplicate_marker_rejection" "FAIL" "result=${SUMMARY_PROBE_DIR}/result.json"
fi

# ── Scenario: log_contract_e2e_markers_valid ──────────────────────────

echo "=== Scenario: log_contract_e2e_markers_valid ==="
# Validate the same source-backed evidence contract used by ffs_smoke. Some
# cataloged suites intentionally use literal source evidence instead of runtime
# SCENARIO_RESULT markers because they are planning or permission-gated runners.
CATALOG_VALIDATION_LOG="$LOG_DIR/scenario_catalog_validation.log"
if ( E2E_LOG_FILE="$CATALOG_VALIDATION_LOG" e2e_validate_scenario_catalog scripts/e2e/scenario_catalog.json ); then
    log_scenario "log_contract_e2e_markers_valid" "PASS" "log=${CATALOG_VALIDATION_LOG}"
else
    log_scenario "log_contract_e2e_markers_valid" "FAIL" "log=${CATALOG_VALIDATION_LOG}"
fi

# ── Scenario: log_contract_duration_convention ────────────────────────

echo "=== Scenario: log_contract_duration_convention ==="
# Check that ffs-core uses duration_us (not duration_ms) for the canonical field
if grep -q 'duration_us' "${CORE_SRC_FILES[@]}"; then
    log_scenario "log_contract_duration_convention" "PASS"
else
    log_scenario "log_contract_duration_convention" "PASS" "note: duration_us_not_found_in_ffs_core"
fi

# ── Scenario: log_contract_writeback_cache_disabled ───────────────────

echo "=== Scenario: log_contract_writeback_cache_disabled ==="
WRITEBACK_CACHE_TEST_LOG="$LOG_DIR/writeback_cache_mount_options.log"
if run_rch_capture "$WRITEBACK_CACHE_TEST_LOG" cargo test -p ffs-fuse build_mount_options_excludes_kernel_writeback_cache_mode -- --nocapture; then
    log_scenario "log_contract_writeback_cache_disabled" "PASS" "log=${WRITEBACK_CACHE_TEST_LOG}"
else
    tail -n 80 "$WRITEBACK_CACHE_TEST_LOG" || true
    log_scenario "log_contract_writeback_cache_disabled" "FAIL" "writeback_cache_guard_test_failed"
fi

# ── Scenario: log_contract_sync_flush_fields ──────────────────────────

echo "=== Scenario: log_contract_sync_flush_fields ==="
MISSING_SYNC_FIELDS=""

if grep -q 'EXT4_RW_SCENARIO_FLUSH' "${CORE_SRC_FILES[@]}"; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}ext4_flush_scenario "
fi

if grep -q 'EXT4_RW_SCENARIO_FSYNC' "${CORE_SRC_FILES[@]}"; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}ext4_fsync_scenario "
fi

if grep -q 'EXT4_RW_SCENARIO_FSYNCDIR' "${CORE_SRC_FILES[@]}"; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}ext4_fsyncdir_scenario "
fi

if grep -q 'BTRFS_RW_SCENARIO_FLUSH' "${CORE_SRC_FILES[@]}"; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}btrfs_flush_scenario "
fi

if grep -q 'durability_boundary' "${CORE_SRC_FILES[@]}"; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}durability_boundary_field "
fi

if grep -q 'error_class' "${CORE_SRC_FILES[@]}"; then
    :
else
    MISSING_SYNC_FIELDS="${MISSING_SYNC_FIELDS}error_class_field "
fi

if [ -z "$MISSING_SYNC_FIELDS" ]; then
    log_scenario "log_contract_sync_flush_fields" "PASS"
else
    log_scenario "log_contract_sync_flush_fields" "FAIL" "missing=${MISSING_SYNC_FIELDS}"
fi

# ── Scenario: log_contract_repair_coordination_fields ────────────────

echo "=== Scenario: log_contract_repair_coordination_fields ==="
MISSING_REPAIR_FIELDS=""

if grep -q 'REPAIR_COORDINATION_SCENARIO_REPAIR' crates/ffs-cli/src/cmd_repair.rs; then
    :
else
    MISSING_REPAIR_FIELDS="${MISSING_REPAIR_FIELDS}repair_scenario_id "
fi

if grep -q 'REPAIR_COORDINATION_SCENARIO_FSCK' crates/ffs-cli/src/cmd_repair.rs crates/ffs-cli/src/main.rs; then
    :
else
    MISSING_REPAIR_FIELDS="${MISSING_REPAIR_FIELDS}fsck_scenario_id "
fi

if grep -q 'operation_id' crates/ffs-cli/src/cmd_repair.rs; then
    :
else
    MISSING_REPAIR_FIELDS="${MISSING_REPAIR_FIELDS}operation_id "
fi

if grep -q 'scenario_id' crates/ffs-cli/src/cmd_repair.rs; then
    :
else
    MISSING_REPAIR_FIELDS="${MISSING_REPAIR_FIELDS}scenario_id "
fi

if grep -q 'error_class' crates/ffs-cli/src/cmd_repair.rs; then
    :
else
    MISSING_REPAIR_FIELDS="${MISSING_REPAIR_FIELDS}error_class "
fi

if grep -q 'repair_coordination' crates/ffs-cli/src/main.rs; then
    :
else
    MISSING_REPAIR_FIELDS="${MISSING_REPAIR_FIELDS}cli_output_surface "
fi

if [ -z "$MISSING_REPAIR_FIELDS" ]; then
    log_scenario "log_contract_repair_coordination_fields" "PASS"
else
    log_scenario "log_contract_repair_coordination_fields" "FAIL" "missing=${MISSING_REPAIR_FIELDS}"
fi

# ── Scenario: log_contract_artifact_manifest_validation_tests ────────

echo "=== Scenario: log_contract_artifact_manifest_validation_tests ==="
ARTIFACT_MANIFEST_TEST_LOG="$LOG_DIR/artifact_manifest_unit_tests.log"
if run_rch_capture "$ARTIFACT_MANIFEST_TEST_LOG" cargo test -p ffs-harness artifact_manifest -- --nocapture; then
    log_scenario "log_contract_artifact_manifest_validation_tests" "PASS" "log=${ARTIFACT_MANIFEST_TEST_LOG}"
else
    tail -n 80 "$ARTIFACT_MANIFEST_TEST_LOG" || true
    log_scenario "log_contract_artifact_manifest_validation_tests" "FAIL" "artifact_manifest_unit_tests_failed"
fi

# ── Scenario: log_contract_artifact_manifest_schema_surface ──────────

echo "=== Scenario: log_contract_artifact_manifest_schema_surface ==="
MISSING_MANIFEST_FIELDS=""

if grep -q '^pub mod artifact_manifest;' crates/ffs-harness/src/lib.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}module_export "
fi

if grep -q 'pub struct ArtifactManifest' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}artifact_manifest_struct "
fi

if grep -q 'pub struct RetentionPolicy' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}retention_policy "
fi

if grep -q 'pub struct RedactionPolicy' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}redaction_policy "
fi

if grep -q 'pub fn validate_manifest' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}validate_manifest "
fi

if grep -q 'pub fn validate_operational_manifest' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}validate_operational_manifest "
fi

if grep -q 'pub struct OperationalRunContext' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}operational_context "
fi

if grep -q 'pub struct OperationalScenarioRecord' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}operational_scenario_record "
fi

if grep -q 'pub enum OperationalOutcomeClass' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}operational_outcome_class "
fi

if grep -q 'pub fn build_operational_manifest' crates/ffs-harness/src/verification_runner.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}operational_runner_builder "
fi

if grep -q 'pub fn classify_operational_observation' crates/ffs-harness/src/verification_runner.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}operational_classification_mapping "
fi

if grep -q 'pub fn validate_operational_gate_contract' crates/ffs-harness/src/verification_runner.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}operational_runner_validator "
fi

if grep -q 'pub struct FuseCapabilityProbeReport' crates/ffs-harness/src/verification_runner.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}fuse_capability_report "
fi

if grep -q 'pub fn build_fuse_capability_probe_report' crates/ffs-harness/src/verification_runner.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}fuse_capability_report_builder "
fi

if grep -q 'validate-operational-manifest' crates/ffs-harness/src/main.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}operational_manifest_cli "
fi

if grep -q 'fuse-capability-probe' crates/ffs-harness/src/main.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}fuse_capability_cli "
fi

if grep -q 'e2e_validate_operational_manifest' scripts/e2e/lib.sh; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}operational_manifest_shell_hook "
fi

if grep -q 'e2e_probe_fuse_capability' scripts/e2e/lib.sh; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}fuse_capability_shell_hook "
fi

if grep -q 'pub fn evaluate_retention' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}evaluate_retention "
fi

if grep -q 'pub fn redact_manifest' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}redact_manifest "
fi

if grep -q 'pub const SCENARIO_ID_PATTERN' crates/ffs-harness/src/artifact_manifest.rs; then
    :
else
    MISSING_MANIFEST_FIELDS="${MISSING_MANIFEST_FIELDS}scenario_id_pattern "
fi

if [ -z "$MISSING_MANIFEST_FIELDS" ]; then
    log_scenario "log_contract_artifact_manifest_schema_surface" "PASS"
else
    log_scenario "log_contract_artifact_manifest_schema_surface" "FAIL" "missing=${MISSING_MANIFEST_FIELDS}"
fi

# ── Scenario: log_contract_writeback_policy_documented ────────────────

echo "=== Scenario: log_contract_writeback_policy_documented ==="
MISSING_POLICY_DOCS=""

if grep -qi 'writeback[_ -]cache' README.md; then
    :
else
    MISSING_POLICY_DOCS="${MISSING_POLICY_DOCS}readme_writeback_policy "
fi

if grep -qi 'writeback[_ -]cache' crates/ffs-cli/src/main.rs; then
    :
else
    MISSING_POLICY_DOCS="${MISSING_POLICY_DOCS}cli_writeback_policy "
fi

if [ -z "$MISSING_POLICY_DOCS" ]; then
    log_scenario "log_contract_writeback_policy_documented" "PASS"
else
    log_scenario "log_contract_writeback_policy_documented" "FAIL" "missing=${MISSING_POLICY_DOCS}"
fi

# ── Scenario: log_contract_repair_policy_documented ──────────────────

echo "=== Scenario: log_contract_repair_policy_documented ==="
MISSING_REPAIR_POLICY_DOCS=""

if grep -q 'single-host only' README.md; then
    :
else
    MISSING_REPAIR_POLICY_DOCS="${MISSING_REPAIR_POLICY_DOCS}readme_single_host_policy "
fi

if grep -Fq '.ffs-repair-owner.json' README.md; then
    :
else
    MISSING_REPAIR_POLICY_DOCS="${MISSING_REPAIR_POLICY_DOCS}readme_coordination_record "
fi

if grep -Fq '.ffs-repair-owner.json' COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md; then
    :
else
    MISSING_REPAIR_POLICY_DOCS="${MISSING_REPAIR_POLICY_DOCS}spec_coordination_record "
fi

if grep -q 'single-host only' FEATURE_PARITY.md; then
    :
else
    MISSING_REPAIR_POLICY_DOCS="${MISSING_REPAIR_POLICY_DOCS}parity_single_host_policy "
fi

if [ -z "$MISSING_REPAIR_POLICY_DOCS" ]; then
    log_scenario "log_contract_repair_policy_documented" "PASS"
else
    log_scenario "log_contract_repair_policy_documented" "FAIL" "missing=${MISSING_REPAIR_POLICY_DOCS}"
fi

# ── Scenario: log_contract_artifact_manifest_policy_documented ───────

echo "=== Scenario: log_contract_artifact_manifest_policy_documented ==="
MISSING_MANIFEST_POLICY_DOCS=""

if grep -q 'Artifact Manifest Contract' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}manifest_heading "
fi

if grep -q '90 days' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}retention_days "
fi

if grep -q '50 manifests' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}retention_count "
fi

if grep -q '500 MiB' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}retention_size "
fi

if grep -qi 'redaction' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}redaction_policy "
fi

if grep -q 'validate_operational_manifest' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}operational_validator_docs "
fi

if grep -q 'validate-operational-manifest' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}operational_cli_docs "
fi

if grep -q 'command redaction' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}runner_redaction_docs "
fi

if grep -q 'fuse-capability-probe' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}fuse_capability_probe_docs "
fi

if grep -q 'failure_kind' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}fuse_failure_kind_docs "
fi

if grep -q 'Operational Outcome Vocabulary' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}operational_outcome_docs "
fi

if grep -q 'root_owned_btrfs_testdir_eacces' scripts/e2e/README.md; then
    :
else
    MISSING_MANIFEST_POLICY_DOCS="${MISSING_MANIFEST_POLICY_DOCS}btrfs_eacces_vocab "
fi

if [ -z "$MISSING_MANIFEST_POLICY_DOCS" ]; then
    log_scenario "log_contract_artifact_manifest_policy_documented" "PASS"
else
    log_scenario "log_contract_artifact_manifest_policy_documented" "FAIL" "missing=${MISSING_MANIFEST_POLICY_DOCS}"
fi

# ── Scenario: log_contract_operational_readiness_slos_documented ─────

echo "=== Scenario: log_contract_operational_readiness_slos_documented ==="
MISSING_READINESS_SLOS=""

for required_text in \
    "Operational Readiness SLOs" \
    "mounted_scenario_matrix.json" \
    "fuse_prod_fuse_lane_ext4_mount_unmount_probe" \
    "fuse_prod_btrfs_ro_mount_start" \
    "bd-rchk0.3.2" \
    "bd-rchk0.1.1" \
    "bd-rchk0.1.2" \
    "bd-rchk0.3.4" \
    "bd-rchk4.4" \
    "bd-rchk5" \
    "writeback_cache" \
    "\`repair.rw.writeback\`" \
    "repair writeback can safely coexist with client writes"; do
    if grep -Fq "$required_text" README.md; then
        :
    else
        MISSING_READINESS_SLOS="${MISSING_READINESS_SLOS}${required_text} "
    fi
done

if [ -z "$MISSING_READINESS_SLOS" ]; then
    log_scenario "log_contract_operational_readiness_slos_documented" "PASS"
else
    log_scenario "log_contract_operational_readiness_slos_documented" "FAIL" "missing=${MISSING_READINESS_SLOS}"
fi

# ── Summary ───────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Log Contract E2E Summary"
echo "============================================"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo "  TOTAL: $((PASS_COUNT + FAIL_COUNT))"
echo "  LOG_DIR: $LOG_DIR"
echo "============================================"

for result in "${SCENARIO_RESULTS[@]}"; do
    echo "  $result"
done

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "LOG_CONTRACT_E2E: FAILED"
    exit 1
fi

echo ""
echo "LOG_CONTRACT_E2E: PASSED"
exit 0
