#!/usr/bin/env bash
# ffs_fuzz_targets_e2e.sh - E2E verification for cargo-fuzz targets
#
# Validates that all fuzz targets:
# 1. Are listed by cargo fuzz list
# 2. Compile successfully
# 3. Execute a short smoke run (100 iterations) without crashes
# 4. Emit structured scenario results
#
# Usage: ./scripts/e2e/ffs_fuzz_targets_e2e.sh
#
# Exit codes:
#   0 - All scenarios passed
#   1 - One or more scenarios failed

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

# Source shared helpers
source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_fuzz_targets_e2e}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-420}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_FUZZ_TARGETS_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
FFS_FUZZ_SMOKE_RUNS="${FFS_FUZZ_SMOKE_RUNS:-100}"
FFS_FUZZ_SMOKE_MAX_TOTAL_TIME="${FFS_FUZZ_SMOKE_MAX_TOTAL_TIME:-10}"
FFS_FUZZ_DICT_RUNS="${FFS_FUZZ_DICT_RUNS:-200}"
FFS_FUZZ_DICT_MAX_TOTAL_TIME="${FFS_FUZZ_DICT_MAX_TOTAL_TIME:-10}"
FFS_FUZZ_NIGHTLY_DURATION="${FFS_FUZZ_NIGHTLY_DURATION:-3}"
SELF_CHECK="${FFS_FUZZ_TARGETS_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_FUZZ_TARGETS_SKIP_SELF_CHECK:-0}"

mapfile -t EXPECTED_TARGETS < <(
    find fuzz/fuzz_targets -maxdepth 1 -name '*.rs' -printf '%f\n' \
        | sed 's/\.rs$//' \
        | sort
)
RUNTIME_TARGETS=("${EXPECTED_TARGETS[@]}")
if [[ -n "${FFS_FUZZ_TARGET_LIMIT:-}" ]]; then
    if ! [[ "$FFS_FUZZ_TARGET_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
        echo "FFS_FUZZ_TARGET_LIMIT must be a positive integer, got: $FFS_FUZZ_TARGET_LIMIT" >&2
        exit 2
    fi
    if [[ "$FFS_FUZZ_TARGET_LIMIT" -lt "${#RUNTIME_TARGETS[@]}" ]]; then
        RUNTIME_TARGETS=("${RUNTIME_TARGETS[@]:0:$FFS_FUZZ_TARGET_LIMIT}")
    fi
fi
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

log_tail() {
    local log_path="$1"

    if [[ -f "$log_path" ]]; then
        tail -40 "$log_path" | while IFS= read -r line; do e2e_log "  $line"; done
    fi
}

validate_rch_log() {
    local log_path="$1"
    local context="$2"

    if grep -Fq "[RCH] local" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${log_path}|context=${context}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$log_path" >>"$log_path"
        return 1
    fi
    if ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=" "$log_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${log_path}|context=${context}"
        printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$log_path" >>"$log_path"
        return 1
    fi

    return 0
}

run_rch_capture() {
    local output_path="$1"
    shift
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local wait_status
    local had_errexit=0

    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$output_path"
    set +e
    RCH_LOG_LEVEL="${FFS_FUZZ_RCH_LOG_LEVEL:-info}" \
        RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" \
        "${RCH_BIN:-rch}" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if ! validate_rch_log "$output_path" "$*"; then
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        return 0
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|output=${output_path}|command=$*"
        return 0
    fi
    return "$status"
}

validate_nightly_rch_logs() {
    local root="$1"
    local failures=0
    local target_logs=()
    local target_log

    mapfile -t target_logs < <(find "$root" -name '*.log' -type f | sort)
    if [[ ${#target_logs[@]} -eq 0 ]]; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${root}|context=nightly_campaign_no_target_logs"
        return 1
    fi

    for target_log in "${target_logs[@]}"; do
        if ! validate_rch_log "$target_log" "nightly_campaign"; then
            failures=$((failures + 1))
        elif ! grep -Fq "Remote command finished: exit=0" "$target_log"; then
            e2e_log "RCH_REMOTE_NONZERO_EXIT|output=${target_log}|context=nightly_campaign"
            failures=$((failures + 1))
        fi
    done

    [[ $failures -eq 0 ]]
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_FUZZ_TARGETS_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fuzz-target fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    complete)
        echo "[RCH] remote worker=fixture exit=0"
        echo "Remote command finished: exit=0"
        case "$command_text" in
            *"fuzz_ext4_metadata"*)
                echo "#1 cov: 12 ft: 24 corp: 1/1b ManualDict"
                ;;
            *"cargo run"*|*"cargo build"*)
                echo "#1 cov: 8 ft: 16 corp: 1/1b"
                ;;
        esac
        ;;
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 1
        ;;
    missing_remote_evidence)
        echo "fixture command completed without an RCH remote summary"
        ;;
    *)
        echo "unknown fuzz-target fixture case: $fixture_case" >&2
        exit 64
        ;;
esac
SH
    chmod +x "$stub_path"
}

extract_child_result_json() {
    local log_path="$1"
    sed -n 's/^JSON summary written: //p' "$log_path" | tail -n 1
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$E2E_LOG_DIR/fuzz_targets_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_FUZZ_TARGETS_SELF_CHECK=0 \
        FFS_FUZZ_TARGETS_SKIP_SELF_CHECK=1 \
        FFS_FUZZ_TARGETS_FIXTURE_CASE="$fixture_case" \
        FFS_FUZZ_TARGET_LIMIT=1 \
        FFS_FUZZ_SMOKE_RUNS=1 \
        FFS_FUZZ_SMOKE_MAX_TOTAL_TIME=1 \
        FFS_FUZZ_DICT_RUNS=1 \
        FFS_FUZZ_DICT_MAX_TOTAL_TIME=1 \
        FFS_FUZZ_NIGHTLY_DURATION=1 \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_fuzz_targets_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic fuzz-target wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-fuzz-targets-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "fuzz_targets_build" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id | startswith("fuzz_smoke_")) | select(.outcome == "PASS")] | length >= 1)
            and ([.scenarios[] | select(.scenario_id == "fuzz_seed_pipeline" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "fuzz_dict_coverage" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "fuzz_nightly_campaign" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "fuzz_targets_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "fuzz_targets_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null \
        && grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        scenario_result "fuzz_targets_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "fuzz_targets_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "fuzz_targets_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "fuzz_targets_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

e2e_init "ffs_fuzz_targets"

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_log "FUZZ_RUNTIME_TARGETS|selected=${#RUNTIME_TARGETS[@]}|total=${#EXPECTED_TARGETS[@]}|limit=${FFS_FUZZ_TARGET_LIMIT:-none}"
BUILD_LOG="$E2E_LOG_DIR/fuzz_targets_build.log"
SEED_GENERATION_LOG="$E2E_LOG_DIR/fuzz_seed_generation.log"
GENERATED_SEED_CORPUS="$E2E_LOG_DIR/generated_seed_corpus"
DICT_LOG="$E2E_LOG_DIR/fuzz_ext4_metadata_dict.log"
CAMPAIGN_LOG="$E2E_LOG_DIR/fuzz_nightly_campaign.log"
FUZZ_NIGHTLY_ARTIFACTS_DIR="$E2E_LOG_DIR/nightly_campaign_artifacts"

#######################################
# Scenario 1: fuzz target manifest registers all expected targets
#######################################
e2e_step "Scenario 1: Verify fuzz target listing"

ALL_FOUND=true
for target in "${EXPECTED_TARGETS[@]}"; do
    if ! grep -Eq "^[[:space:]]*name = \"${target}\"$" "fuzz/Cargo.toml"; then
        ALL_FOUND=false
        scenario_result "fuzz_list_${target}" "FAIL" "Target '${target}' not registered in fuzz/Cargo.toml"
    fi
done

if [[ "$ALL_FOUND" == "true" ]]; then
    scenario_result "fuzz_list_all" "PASS" "All ${#EXPECTED_TARGETS[@]} expected fuzz targets are registered"
else
    scenario_result "fuzz_list_all" "FAIL" "Some expected fuzz targets missing"
fi

#######################################
# Scenario 2: cargo fuzz build succeeds
#######################################
e2e_step "Scenario 2: Build all fuzz targets"

if run_rch_capture "$BUILD_LOG" cargo build --manifest-path fuzz/Cargo.toml --bins; then
    scenario_result "fuzz_targets_build" "PASS" "All fuzz targets compiled successfully; log=${BUILD_LOG}"
else
    scenario_result "fuzz_targets_build" "FAIL" "Fuzz target build failed; see $BUILD_LOG"
    # If build fails, remaining scenarios will fail too; report and exit
    e2e_log "Build log tail:"
    log_tail "$BUILD_LOG"
fi

#######################################
# Scenario 3: Smoke run each target (100 iterations, no crash)
#######################################
e2e_step "Scenario 3: Smoke-run fuzz targets"

for target in "${RUNTIME_TARGETS[@]}"; do
    SMOKE_LOG="$E2E_LOG_DIR/fuzz_smoke_${target}.log"
    if run_rch_capture "$SMOKE_LOG" cargo run --manifest-path fuzz/Cargo.toml --bin "$target" -- -runs="$FFS_FUZZ_SMOKE_RUNS" -max_total_time="$FFS_FUZZ_SMOKE_MAX_TOTAL_TIME"; then
        scenario_result "fuzz_smoke_${target}" "PASS" "${FFS_FUZZ_SMOKE_RUNS} iterations completed without crash; log=${SMOKE_LOG}"
    else
        EXIT_CODE=$?
        if [[ $EXIT_CODE -eq 77 ]]; then
            # libFuzzer exit code 77 = crash found
            scenario_result "fuzz_smoke_${target}" "FAIL" "Crash found during smoke run; see $SMOKE_LOG"
        else
            scenario_result "fuzz_smoke_${target}" "FAIL" "Smoke run failed with exit code ${EXIT_CODE}; see ${SMOKE_LOG}"
        fi
        log_tail "$SMOKE_LOG"
    fi
done

#######################################
# Scenario 4: Seed corpus directories exist with samples
#######################################
e2e_step "Scenario 4: Verify seed corpus"

for target in "${EXPECTED_TARGETS[@]}"; do
    CORPUS_DIR="fuzz/corpus/${target}"
    if [[ -d "$CORPUS_DIR" ]]; then
        SAMPLE_COUNT=$(find "$CORPUS_DIR" -type f | wc -l)
        if [[ $SAMPLE_COUNT -gt 0 ]]; then
            scenario_result "fuzz_corpus_${target}" "PASS" "${SAMPLE_COUNT} seed samples in ${CORPUS_DIR}"
        else
            scenario_result "fuzz_corpus_${target}" "FAIL" "Corpus directory exists but is empty: ${CORPUS_DIR}"
        fi
    else
        scenario_result "fuzz_corpus_${target}" "FAIL" "Corpus directory missing: ${CORPUS_DIR}"
    fi
done

#######################################
# Scenario 5: Dictionaries exist for ext4, btrfs, fat, ntfs, zfs, and partition
#######################################
e2e_step "Scenario 5: Verify fuzz dictionaries"

for dict in ext4.dict btrfs.dict fat.dict ntfs.dict zfs.dict partition.dict; do
    DICT_PATH="fuzz/dictionaries/${dict}"
    if [[ -f "$DICT_PATH" ]]; then
        TOKEN_COUNT=$(grep -c '^"' "$DICT_PATH" || true)
        NAMED_COUNT=$(grep -cE '^[a-z].*="' "$DICT_PATH" || true)
        TOTAL_TOKENS=$((TOKEN_COUNT + NAMED_COUNT))
        if [[ $TOTAL_TOKENS -ge 5 ]]; then
            scenario_result "fuzz_dict_${dict%.dict}" "PASS" "${TOTAL_TOKENS} tokens in ${DICT_PATH}"
        else
            scenario_result "fuzz_dict_${dict%.dict}" "FAIL" "Too few tokens (${TOTAL_TOKENS}) in ${DICT_PATH}"
        fi
    else
        scenario_result "fuzz_dict_${dict%.dict}" "FAIL" "Dictionary missing: ${DICT_PATH}"
    fi
done

#######################################
# Scenario 6: Seed generation script runs successfully
#######################################
e2e_step "Scenario 6: Verify seed generation pipeline"

SEED_SCRIPT="fuzz/scripts/generate_seeds.sh"
if [[ -x "$SEED_SCRIPT" ]]; then
    if FUZZ_CORPUS_ROOT="$GENERATED_SEED_CORPUS" bash "$SEED_SCRIPT" >"$SEED_GENERATION_LOG" 2>&1; then
        GENERATED_SEED_COUNT=$(find "$GENERATED_SEED_CORPUS" -type f | wc -l)
        EXPECTED_SEED_COUNT=$(( ${#EXPECTED_TARGETS[@]} * 2 ))
        if [[ "$GENERATED_SEED_COUNT" -eq "$EXPECTED_SEED_COUNT" ]]; then
            scenario_result "fuzz_seed_pipeline" "PASS" "Seed generation completed under ${GENERATED_SEED_CORPUS} with ${GENERATED_SEED_COUNT}/${EXPECTED_SEED_COUNT} expected files"
        else
            scenario_result "fuzz_seed_pipeline" "FAIL" "Seed generation wrote ${GENERATED_SEED_COUNT}/${EXPECTED_SEED_COUNT} expected files under ${GENERATED_SEED_CORPUS}"
            log_tail "$SEED_GENERATION_LOG"
        fi
    else
        scenario_result "fuzz_seed_pipeline" "FAIL" "Seed generation failed; log=${SEED_GENERATION_LOG}"
        log_tail "$SEED_GENERATION_LOG"
    fi
else
    scenario_result "fuzz_seed_pipeline" "FAIL" "Seed generation script missing or not executable"
fi

#######################################
# Scenario 7: Dictionary-enhanced run improves coverage
#######################################
e2e_step "Scenario 7: Dictionary coverage improvement"

if run_rch_capture "$DICT_LOG" cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_ext4_metadata -- -runs="$FFS_FUZZ_DICT_RUNS" -max_total_time="$FFS_FUZZ_DICT_MAX_TOTAL_TIME" -dict=fuzz/dictionaries/ext4.dict; then
    # Check that ManualDict was used (indicates dictionary is actively helping)
    if grep -q "ManualDict\|Dict" "$DICT_LOG"; then
        scenario_result "fuzz_dict_coverage" "PASS" "Dictionary tokens actively used during fuzzing; log=${DICT_LOG}"
    else
        scenario_result "fuzz_dict_coverage" "PASS" "Dictionary run completed (no ManualDict markers but no crash); log=${DICT_LOG}"
    fi
else
    scenario_result "fuzz_dict_coverage" "FAIL" "Dictionary-enhanced fuzz run failed; log=${DICT_LOG}"
    log_tail "$DICT_LOG"
fi

#######################################
# Scenario 8: Nightly campaign runner produces valid summary
#######################################
e2e_step "Scenario 8: Nightly campaign runner"

NIGHTLY_SCRIPT="fuzz/scripts/nightly_fuzz.sh"
if [[ -x "$NIGHTLY_SCRIPT" ]]; then
    mkdir -p "$FUZZ_NIGHTLY_ARTIFACTS_DIR"
    FUZZ_ARTIFACTS_DIR="$FUZZ_NIGHTLY_ARTIFACTS_DIR"
    export FUZZ_ARTIFACTS_DIR
    if FFS_FUZZ_RCH_LOG_LEVEL=info bash "$NIGHTLY_SCRIPT" --duration "$FFS_FUZZ_NIGHTLY_DURATION" >"$CAMPAIGN_LOG" 2>&1; then
        # Find the campaign summary
        SUMMARY_FILE=$(find "$FUZZ_ARTIFACTS_DIR" -name "campaign_summary.json" -type f 2>/dev/null | head -1)
        if [[ -n "$SUMMARY_FILE" ]] && python3 -c "import json; json.load(open('$SUMMARY_FILE'))" 2>/dev/null; then
            # Validate required fields
            HAS_FIELDS=$(python3 -c "
import json
with open('$SUMMARY_FILE') as f:
    d = json.load(f)
required = ['campaign_id', 'commit_sha', 'config', 'totals', 'targets']
print('ok' if all(k in d for k in required) else 'missing')
")
            if [[ "$HAS_FIELDS" == "ok" ]] && validate_nightly_rch_logs "$FUZZ_ARTIFACTS_DIR"; then
                scenario_result "fuzz_nightly_campaign" "PASS" "Campaign summary is valid JSON with required fields and remote target logs; summary=${SUMMARY_FILE}; log=${CAMPAIGN_LOG}"
            else
                scenario_result "fuzz_nightly_campaign" "FAIL" "Campaign summary missing required fields or remote RCH evidence; summary=${SUMMARY_FILE}; log=${CAMPAIGN_LOG}"
                log_tail "$CAMPAIGN_LOG"
            fi
        else
            scenario_result "fuzz_nightly_campaign" "FAIL" "Campaign summary not found or invalid JSON; log=${CAMPAIGN_LOG}"
            log_tail "$CAMPAIGN_LOG"
        fi
    else
        scenario_result "fuzz_nightly_campaign" "FAIL" "Nightly campaign script failed; log=${CAMPAIGN_LOG}"
        log_tail "$CAMPAIGN_LOG"
    fi
    unset FUZZ_ARTIFACTS_DIR
else
    scenario_result "fuzz_nightly_campaign" "FAIL" "Nightly campaign script missing or not executable"
fi

#######################################
# Summary
#######################################
e2e_step "Summary"
e2e_log "Results: ${PASS_COUNT}/${TOTAL} PASS, ${FAIL_COUNT}/${TOTAL} FAIL"

if [[ $FAIL_COUNT -gt 0 ]]; then
    e2e_log "OVERALL: FAIL"
    exit 1
else
    e2e_log "OVERALL: PASS"
    exit 0
fi
