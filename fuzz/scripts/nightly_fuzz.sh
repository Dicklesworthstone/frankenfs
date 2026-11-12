#!/usr/bin/env bash
# nightly_fuzz.sh - Run all fuzz targets for a campaign and produce JSON summary.
#
# Usage: ./fuzz/scripts/nightly_fuzz.sh [--duration <seconds>] [duration_per_target_secs]
#
# Default: 300 seconds (5 minutes) per target.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$FUZZ_DIR/.." && pwd)"
cd "$REPO_ROOT"

usage() {
    cat <<'EOF'
Usage: nightly_fuzz.sh [--duration <seconds>] [duration_per_target_secs]

Runs every registered cargo-fuzz target and writes a campaign summary JSON.
EOF
}

DURATION="300"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration)
            DURATION="${2:?--duration requires a value}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            DURATION="$1"
            shift
            ;;
    esac
done

CAMPAIGN_ID="nightly_$(date +%Y%m%d_%H%M%S)"
RESULTS_ROOT="${FUZZ_ARTIFACTS_DIR:-$FUZZ_DIR/campaigns}"
RESULTS_DIR="$RESULTS_ROOT/$CAMPAIGN_ID"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_nightly_fuzz}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
mkdir -p "$RESULTS_DIR"

run_remote_cargo_capture() {
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
        RCH_VISIBILITY="${FFS_FUZZ_RCH_VISIBILITY:-none}" \
        "${RCH_BIN:-rch}" exec -- cargo "$@" >"$output_path" 2>&1 &
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
                printf 'RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=%s|output=%s|command=cargo %s\n' "$remote_exit" "$output_path" "$*" | tee -a "$output_path"
                kill -TERM "$pid" >/dev/null 2>&1 || true
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            printf 'RCH_TIMEOUT|seconds=%s|output=%s|command=cargo %s\n' "$RCH_COMMAND_TIMEOUT_SECS" "$output_path" "$*" | tee -a "$output_path"
            kill -TERM "$pid" >/dev/null 2>&1 || true
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

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" | tee -a "$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
        printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" | tee -a "$output_path"
        return 99
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        printf 'RCH_ARTIFACT_RETRIEVAL_TIMEOUT_ACCEPTED|output=%s\n' "$output_path" | tee -a "$output_path"
        return 0
    fi
    return "$status"
}

mapfile -t TARGETS < <(
    find fuzz/fuzz_targets -maxdepth 1 -name '*.rs' -printf '%f\n' \
        | sed 's/\.rs$//' \
        | sort
)
if [[ -n "${FFS_FUZZ_TARGET_LIMIT:-}" ]]; then
    if ! [[ "$FFS_FUZZ_TARGET_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
        echo "FFS_FUZZ_TARGET_LIMIT must be a positive integer, got: $FFS_FUZZ_TARGET_LIMIT" >&2
        exit 2
    fi
    if [[ "$FFS_FUZZ_TARGET_LIMIT" -lt "${#TARGETS[@]}" ]]; then
        TARGETS=("${TARGETS[@]:0:$FFS_FUZZ_TARGET_LIMIT}")
    fi
fi

echo "=== Nightly Fuzz Campaign: $CAMPAIGN_ID ==="
echo "Targets: ${#TARGETS[@]}"
echo "Duration per target: ${DURATION}s"
echo "Results: $RESULTS_DIR"
echo ""

SUMMARY_JSON="$RESULTS_DIR/campaign_summary.json"
RESULTS=()
TOTAL_CRASHES=0
TOTAL_COVERAGE=0
TOTAL_RUNS=0
CAMPAIGN_START=$(date +%s)

for target in "${TARGETS[@]}"; do
    echo "--- Running: $target ---"
    TARGET_LOG="$RESULTS_DIR/${target}.log"
    TARGET_START=$(date +%s)
    TARGET_RC=0

    DICT_ARGS=()
    if [[ "$target" == *ext4* ]]; then
        DICT_ARGS=(-dict=fuzz/dictionaries/ext4.dict)
    elif [[ "$target" == *btrfs* ]]; then
        DICT_ARGS=(-dict=fuzz/dictionaries/btrfs.dict)
    elif [[ "$target" == *fat* ]]; then
        DICT_ARGS=(-dict=fuzz/dictionaries/fat.dict)
    elif [[ "$target" == *ntfs* ]]; then
        DICT_ARGS=(-dict=fuzz/dictionaries/ntfs.dict)
    elif [[ "$target" == *zfs* ]]; then
        DICT_ARGS=(-dict=fuzz/dictionaries/zfs.dict)
    elif [[ "$target" == *partition* ]]; then
        DICT_ARGS=(-dict=fuzz/dictionaries/partition.dict)
    fi

    run_remote_cargo_capture "$TARGET_LOG" run --manifest-path fuzz/Cargo.toml --bin "$target" \
        -- \
        -max_total_time="$DURATION" \
        -max_len=65536 \
        "${DICT_ARGS[@]}" || TARGET_RC=$?

    TARGET_END=$(date +%s)
    TARGET_DURATION=$((TARGET_END - TARGET_START))

    # Count crashes in the artifacts directory
    CRASH_COUNT=0
    CRASH_DIR="$FUZZ_DIR/artifacts/$target"
    if [[ -d "$CRASH_DIR" ]]; then
        CRASH_COUNT=$(find "$CRASH_DIR" -name "crash-*" -type f 2>/dev/null | wc -l)
        TOTAL_CRASHES=$((TOTAL_CRASHES + CRASH_COUNT))
    fi

    # Extract corpus size
    CORPUS_SIZE=0
    CORPUS_DIR="$FUZZ_DIR/corpus/$target"
    if [[ -d "$CORPUS_DIR" ]]; then
        CORPUS_SIZE=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l)
    fi

    # Extract best-effort libFuzzer metrics from the target log. These are
    # intentionally fail-soft so an early harness error still produces a
    # dashboard-consumable summary with zeroed metric fields.
    TOTAL_RUNS_FOR_TARGET=$(grep -Eo '#[0-9]+' "$TARGET_LOG" 2>/dev/null \
        | tr -d '#' \
        | sort -n \
        | tail -1 || true)
    TOTAL_RUNS_FOR_TARGET="${TOTAL_RUNS_FOR_TARGET:-0}"
    COVERAGE_FOR_TARGET=$(grep -Eo 'cov: *[0-9]+' "$TARGET_LOG" 2>/dev/null \
        | awk '{print $2}' \
        | sort -n \
        | tail -1 || true)
    COVERAGE_FOR_TARGET="${COVERAGE_FOR_TARGET:-0}"
    NEW_INPUTS=$(grep -Ec '(^|[[:space:]])NEW($|[[:space:]])' "$TARGET_LOG" 2>/dev/null || true)
    NEW_INPUTS="${NEW_INPUTS:-0}"

    TOTAL_RUNS=$((TOTAL_RUNS + TOTAL_RUNS_FOR_TARGET))
    TOTAL_COVERAGE=$((TOTAL_COVERAGE + COVERAGE_FOR_TARGET))

    STATUS="ok"
    if [[ $TARGET_RC -ne 0 ]] && [[ $CRASH_COUNT -gt 0 ]]; then
        STATUS="crashes_found"
    elif [[ $TARGET_RC -ne 0 ]]; then
        STATUS="error"
    fi

    echo "  Status: $STATUS (rc=$TARGET_RC, crashes=$CRASH_COUNT, corpus=$CORPUS_SIZE, ${TARGET_DURATION}s)"

    RESULTS+=("{\"target\":\"$target\",\"status\":\"$STATUS\",\"exit_code\":$TARGET_RC,\"coverage\":$COVERAGE_FOR_TARGET,\"total_runs\":$TOTAL_RUNS_FOR_TARGET,\"corpus_size\":$CORPUS_SIZE,\"crash_count\":$CRASH_COUNT,\"new_inputs\":$NEW_INPUTS,\"elapsed_seconds\":$TARGET_DURATION}")
done

CAMPAIGN_END=$(date +%s)
CAMPAIGN_DURATION=$((CAMPAIGN_END - CAMPAIGN_START))

# Build results array
RESULTS_ARRAY="["
for i in "${!RESULTS[@]}"; do
    if [[ $i -gt 0 ]]; then
        RESULTS_ARRAY+=","
    fi
    RESULTS_ARRAY+="${RESULTS[$i]}"
done
RESULTS_ARRAY+="]"

# Write summary
CAMPAIGN_TIMESTAMP="$(date -Iseconds)"
cat > "$SUMMARY_JSON" <<EOF
{
  "schema_version": 1,
  "campaign_id": "$CAMPAIGN_ID",
  "timestamp": "$CAMPAIGN_TIMESTAMP",
  "created_at": "$CAMPAIGN_TIMESTAMP",
  "duration_per_target_secs": $DURATION,
  "commit_sha": "$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "config": {
    "duration_per_target": $DURATION,
    "jobs": 1,
    "target_count": ${#TARGETS[@]}
  },
  "totals": {
    "elapsed_seconds": $CAMPAIGN_DURATION,
    "total_crashes": $TOTAL_CRASHES,
    "total_coverage": $TOTAL_COVERAGE,
    "total_runs": $TOTAL_RUNS
  },
  "targets": $RESULTS_ARRAY
}
EOF

echo ""
echo "=== Campaign Summary ==="
echo "Campaign: $CAMPAIGN_ID"
echo "Duration: ${CAMPAIGN_DURATION}s"
echo "Total crashes: $TOTAL_CRASHES"
echo "Summary: $SUMMARY_JSON"

if [[ $TOTAL_CRASHES -gt 0 ]]; then
    echo ""
    echo "WARNING: $TOTAL_CRASHES crash(es) found! Check artifacts/ for details."
    exit 1
fi

exit 0
