#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

WARMUP=3
RUNS=10
COMPARE=0
VERIFY_GOLDEN=1
DATE_TAG="$(date -u +%Y%m%d)"
OP_FILTER=""
REF_IMAGE="conformance/golden/ext4_8mb_reference.ext4"
P99_WARN_THRESHOLD=10
P99_FAIL_THRESHOLD=20
P99_FAIL_THRESHOLD_OVERRIDE=""
FFS_USE_RCH="${FFS_USE_RCH:-1}"
FORCE_REMOTE="${FFS_BENCH_FORCE_REMOTE:-0}"
BENCH_PROFILE="${FFS_BENCH_PROFILE:-release-perf}"
MOUNT_PROBE_USE_SUDO="${FFS_MOUNT_PROBE_USE_SUDO:-0}"
MOUNT_PROBE_IMAGE_OVERRIDE="${FFS_MOUNT_PROBE_IMAGE:-}"
MOUNT_RECOVERY_PROBE_IMAGE_OVERRIDE="${FFS_MOUNT_RECOVERY_PROBE_IMAGE:-}"
PERF_BASELINE_PATH="artifacts/baselines/perf_baseline.json"
THRESHOLDS_PATH="benchmarks/thresholds.toml"
BENCHMARK_BASELINE_LATEST_PATH="benchmarks/baselines/latest.json"
BENCHMARK_BASELINE_HISTORY_PATH=""
declare -A OP_WARN_THRESHOLDS=()
declare -A OP_FAIL_THRESHOLDS=()
CACHE_WORKLOAD_METRICS_JSON='[]'
WROTE_BENCHMARK_BASELINE_LATEST=0

have_rch() {
    [[ "$FFS_USE_RCH" == "1" ]] && command -v rch >/dev/null 2>&1
}

cargo_exec() {
    if have_rch; then
        rch exec -- cargo "$@"
    else
        cargo "$@"
    fi
}

cargo_cmd_prefix() {
    if have_rch; then
        printf 'rch exec -- cargo'
    else
        printf 'cargo'
    fi
}

cargo_run_cmd() {
    local package="$1"
    shift
    printf '%s run -p %s --profile %s --quiet -- %s' \
        "$(cargo_cmd_prefix)" "$package" "$BENCH_PROFILE" "$*"
}

cargo_bench_cmd() {
    printf '%s bench --profile %s %s' \
        "$(cargo_cmd_prefix)" "$BENCH_PROFILE" "$*"
}

command_benchmarks_needed() {
    if [ -z "$OP_FILTER" ]; then
        return 0
    fi

    case "$OP_FILTER" in
        metadata_parity_cli|metadata_parity_harness|fixture_validation)
            return 0
            ;;
        read_metadata_inspect_ext4_reference|read_metadata_scrub_ext4_reference)
            return 0
            ;;
        mount_cold|mount_warm|mount_recovery)
            return 0
            ;;
        ffs_cli_*|ffs_harness_*|ffs-cli*|ffs-harness*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

extract_cache_report_from_log() {
    local log_file="$1"
    local report_tsv="$2"
    awk -F'\t' '
        $1 == "policy" && $2 == "workload" {
            print;
            saw_header = 1;
            next;
        }
        saw_header && ($1 == "arc" || $1 == "s3fifo") {
            print;
            row_count += 1;
        }
        END {
            if (!saw_header || row_count == 0) {
                exit 1;
            }
        }
    ' "$log_file" > "$report_tsv"
}

usage() {
    cat <<'USAGE'
Usage:
  scripts/benchmark_record.sh [--date YYYYMMDD] [--op OPERATION] [--warmup N] [--runs N] [--compare] [--skip-verify-golden] [--thresholds PATH] [--p99-fail-threshold N] [--profile PROFILE] [--force-remote] [--mount-probe-use-sudo] [--mount-probe-image PATH] [--mount-recovery-probe-image PATH] [--out-json PATH]

Options:
  --date YYYYMMDD          Override date-tag for output paths (default: today)
  --op OPERATION           Run only the exact benchmark operation, label, or JSON stem
  --warmup N               Hyperfine warmup runs (default: 3)
  --runs N                 Hyperfine measured runs (default: 10)
  --compare                Compare current p99 against latest prior baseline (warn >10%, fail >20%)
  --compare-baseline       Alias for --compare used by perf triage follow-up commands
  --skip-verify-golden     Skip scripts/verify_golden.sh preflight
  --thresholds PATH        Read warn/fail thresholds from TOML (default: benchmarks/thresholds.toml)
  --p99-fail-threshold N   Fail compare if p99 regression exceeds N percent (default: 20)
  --profile PROFILE        Cargo profile for build/run/bench commands (default: release-perf)
  --force-remote           Disable local release-binary execution and use cargo run via the configured cargo executor
  --mount-probe-use-sudo   Run mount probe helper via `sudo -n` (or set FFS_MOUNT_PROBE_USE_SUDO=1)
  --mount-probe-image PATH Reuse an existing ext4 image for cold/warm mount probes (or set FFS_MOUNT_PROBE_IMAGE)
  --mount-recovery-probe-image PATH
                           Reuse an existing journaled ext4 image for recovery mount probes (or set FFS_MOUNT_RECOVERY_PROBE_IMAGE)
  --out-json PATH          Structured baseline JSON output path (default: artifacts/baselines/perf_baseline.json)
  -h, --help               Show this help
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --date)
            [ $# -ge 2 ] || { echo "missing value for --date" >&2; exit 2; }
            DATE_TAG="$2"
            shift 2
            ;;
        --op)
            [ $# -ge 2 ] || { echo "missing value for --op" >&2; exit 2; }
            OP_FILTER="$2"
            shift 2
            ;;
        --warmup)
            [ $# -ge 2 ] || { echo "missing value for --warmup" >&2; exit 2; }
            WARMUP="$2"
            shift 2
            ;;
        --runs)
            [ $# -ge 2 ] || { echo "missing value for --runs" >&2; exit 2; }
            RUNS="$2"
            shift 2
            ;;
        --compare|--compare-baseline)
            COMPARE=1
            shift
            ;;
        --skip-verify-golden)
            VERIFY_GOLDEN=0
            shift
            ;;
        --p99-fail-threshold)
            [ $# -ge 2 ] || { echo "missing value for --p99-fail-threshold" >&2; exit 2; }
            P99_FAIL_THRESHOLD_OVERRIDE="$2"
            shift 2
            ;;
        --profile)
            [ $# -ge 2 ] || { echo "missing value for --profile" >&2; exit 2; }
            BENCH_PROFILE="$2"
            shift 2
            ;;
        --force-remote)
            FORCE_REMOTE=1
            shift
            ;;
        --mount-probe-use-sudo)
            MOUNT_PROBE_USE_SUDO=1
            shift
            ;;
        --mount-probe-image)
            [ $# -ge 2 ] || { echo "missing value for --mount-probe-image" >&2; exit 2; }
            MOUNT_PROBE_IMAGE_OVERRIDE="$2"
            shift 2
            ;;
        --mount-recovery-probe-image)
            [ $# -ge 2 ] || { echo "missing value for --mount-recovery-probe-image" >&2; exit 2; }
            MOUNT_RECOVERY_PROBE_IMAGE_OVERRIDE="$2"
            shift 2
            ;;
        --thresholds)
            [ $# -ge 2 ] || { echo "missing value for --thresholds" >&2; exit 2; }
            THRESHOLDS_PATH="$2"
            shift 2
            ;;
        --out-json)
            [ $# -ge 2 ] || { echo "missing value for --out-json" >&2; exit 2; }
            PERF_BASELINE_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required but not installed" >&2
    exit 2
fi

if ! command -v hyperfine >/dev/null 2>&1; then
    echo "hyperfine is required but not installed" >&2
    exit 2
fi

load_thresholds() {
    if [ ! -f "$THRESHOLDS_PATH" ]; then
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo "warning: python3 unavailable; skipping thresholds file ${THRESHOLDS_PATH}" >&2
        return 0
    fi

    local threshold_json
    if ! threshold_json="$(
        python3 - "$THRESHOLDS_PATH" <<'PY'
import json
import sys
import tomllib

path = sys.argv[1]
with open(path, "rb") as fh:
    data = tomllib.load(fh)

defaults = data.get("default", {})
warn = defaults.get("warn_percent", 10)
fail = defaults.get("fail_percent", 20)
ops = data.get("operation_thresholds", {})

out = {
    "default": {"warn_percent": warn, "fail_percent": fail},
    "operations": {},
}
for name, cfg in ops.items():
    if isinstance(cfg, dict):
        out["operations"][name] = {
            "warn_percent": cfg.get("warn_percent"),
            "fail_percent": cfg.get("fail_percent"),
        }
print(json.dumps(out))
PY
    )"; then
        echo "warning: failed to parse thresholds file ${THRESHOLDS_PATH}; using defaults" >&2
        return 0
    fi

    P99_WARN_THRESHOLD="$(jq -r '.default.warn_percent // 10' <<<"$threshold_json")"
    P99_FAIL_THRESHOLD="$(jq -r '.default.fail_percent // 20' <<<"$threshold_json")"

    while IFS=$'\t' read -r operation warn fail; do
        [ -n "$operation" ] || continue
        if [ "$warn" != "null" ] && [ -n "$warn" ]; then
            OP_WARN_THRESHOLDS["$operation"]="$warn"
        fi
        if [ "$fail" != "null" ] && [ -n "$fail" ]; then
            OP_FAIL_THRESHOLDS["$operation"]="$fail"
        fi
    done < <(
        jq -r '
            .operations
            | to_entries[]
            | [.key, (.value.warn_percent // "null"), (.value.fail_percent // "null")]
            | @tsv
        ' <<<"$threshold_json"
    )
}

load_thresholds
if [ -n "$P99_FAIL_THRESHOLD_OVERRIDE" ]; then
    P99_FAIL_THRESHOLD="$P99_FAIL_THRESHOLD_OVERRIDE"
fi

OUT_DIR="baselines/hyperfine/${DATE_TAG}"
REPORT_PATH="baselines/baseline-${DATE_TAG}.md"
BENCHMARK_BASELINE_HISTORY_PATH="benchmarks/baselines/history/${DATE_TAG}.json"
if [[ "$PERF_BASELINE_PATH" == *.json ]]; then
    PERF_BASELINE_DATED_PATH="${PERF_BASELINE_PATH%.json}-${DATE_TAG}.json"
else
    PERF_BASELINE_DATED_PATH="${PERF_BASELINE_PATH}-${DATE_TAG}.json"
fi

mkdir -p \
    "$OUT_DIR" \
    "$(dirname "$PERF_BASELINE_PATH")" \
    "$(dirname "$BENCHMARK_BASELINE_LATEST_PATH")" \
    "$(dirname "$BENCHMARK_BASELINE_HISTORY_PATH")"

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    TARGET_DIR="${CARGO_TARGET_DIR}"
else
    TARGET_DIR="$(cargo metadata --format-version=1 --no-deps | jq -r '.target_directory')"
fi

if [ "$VERIFY_GOLDEN" -eq 1 ]; then
    echo "=== Golden Verification Gate ==="
    scripts/verify_golden.sh
    echo ""
fi

echo "=== FrankenFS Baseline Recorder (${DATE_TAG}) ==="
echo "Output directory: ${OUT_DIR}"
echo ""

CLI_BIN="${TARGET_DIR}/${BENCH_PROFILE}/ffs-cli"
HARNESS_BIN="${TARGET_DIR}/${BENCH_PROFILE}/ffs-harness"
COMMAND_BENCHMARKS_NEEDED=0
USE_LOCAL_RELEASE_BINS=0
if command_benchmarks_needed; then
    COMMAND_BENCHMARKS_NEEDED=1
    echo "Building release binaries once..."
    cargo_exec build -p ffs-cli --profile "$BENCH_PROFILE" --quiet
    cargo_exec build -p ffs-harness --profile "$BENCH_PROFILE" --quiet
    echo ""

    USE_LOCAL_RELEASE_BINS=1
fi

if [ "$COMMAND_BENCHMARKS_NEEDED" -eq 0 ]; then
    echo "Skipping release binary prebuild for --op ${OP_FILTER}; selected operation does not use CLI/harness binaries."
elif [ "$FORCE_REMOTE" -eq 1 ]; then
    USE_LOCAL_RELEASE_BINS=0
elif [ ! -x "$CLI_BIN" ] || [ ! -x "$HARNESS_BIN" ]; then
    # In environments with a non-default CARGO_TARGET_DIR, rch artifact
    # retrieval often materializes under ./target. Prefer that local path
    # before degrading to remote cargo run per benchmark sample.
    local_target_dir="target"
    local_cli_fallback="${local_target_dir}/${BENCH_PROFILE}/ffs-cli"
    local_harness_fallback="${local_target_dir}/${BENCH_PROFILE}/ffs-harness"
    if [ -x "$local_cli_fallback" ] && [ -x "$local_harness_fallback" ]; then
        TARGET_DIR="$local_target_dir"
        CLI_BIN="$local_cli_fallback"
        HARNESS_BIN="$local_harness_fallback"
        echo "warning: missing local profile binaries under original target directory; using ${TARGET_DIR}/${BENCH_PROFILE} fallback" >&2
    else
        USE_LOCAL_RELEASE_BINS=0
        echo "warning: missing local profile binaries under ${TARGET_DIR}; falling back to cargo run commands" >&2
    fi
fi

declare -a BENCH_LABELS=()
declare -a BENCH_COMMANDS=()
declare -a BENCH_FILES=()
declare -a BENCH_OPERATIONS=()
declare -a BENCH_PAYLOAD_MB=()
declare -a BENCH_RUNNERS=()
declare -a SKIPPED_LABELS=()
declare -a CACHE_WORKLOAD_REPORT_PATHS=()
declare -a CACHE_WORKLOAD_REPORT_POLICIES=()
declare -A PENDING_REASONS=(
    ["mount_cold"]="mount latency benchmark requires a FUSE-capable CI runner and automated mount lifecycle probe"
    ["mount_warm"]="warm mount benchmark requires repeated FUSE mount lifecycle automation in benchmark_record.sh"
    ["mount_recovery"]="recovery mount benchmark requires journal-enabled probe image mount automation"
)
declare -A PENDING_SOURCE_JSON=()

MOUNT_BENCH_IMAGE=""
MOUNT_RECOVERY_IMAGE=""
MOUNT_BENCH_ROOT=""

bench_runner_for_command() {
    case " $1 " in
        *" cargo bench "*)
            printf 'criterion_once'
            ;;
        *)
            printf 'hyperfine'
            ;;
    esac
}

add_bench() {
    BENCH_LABELS+=("$1")
    BENCH_COMMANDS+=("$2")
    BENCH_FILES+=("$3")
    BENCH_OPERATIONS+=("$4")
    BENCH_PAYLOAD_MB+=("${5:-0}")
    BENCH_RUNNERS+=("$(bench_runner_for_command "$2")")
}

bench_entry_matches_filter() {
    local index="$1"
    local filter="$2"
    local json_stem="${BENCH_FILES[$index]%.json}"

    [ "${BENCH_OPERATIONS[$index]}" = "$filter" ] \
        || [ "${BENCH_LABELS[$index]}" = "$filter" ] \
        || [ "$json_stem" = "$filter" ]
}

print_available_ops() {
    local i
    for i in "${!BENCH_LABELS[@]}"; do
        printf '  - %s (%s, %s)\n' \
            "${BENCH_OPERATIONS[$i]}" \
            "${BENCH_LABELS[$i]}" \
            "${BENCH_FILES[$i]%.json}"
    done
}

pending_entry_matches_filter() {
    local operation="$1"

    [ -z "$OP_FILTER" ] || [ "$operation" = "$OP_FILTER" ]
}

recovery_mount_benchmark_needed() {
    [ -z "$OP_FILTER" ] || [ "$OP_FILTER" = "mount_recovery" ]
}

mount_image_creation_needs_mkfs() {
    [ -z "$MOUNT_PROBE_IMAGE_OVERRIDE" ] \
        || { recovery_mount_benchmark_needed && [ -z "$MOUNT_RECOVERY_PROBE_IMAGE_OVERRIDE" ]; }
}

apply_op_filter() {
    [ -n "$OP_FILTER" ] || return 0

    local -a filtered_labels=()
    local -a filtered_commands=()
    local -a filtered_files=()
    local -a filtered_operations=()
    local -a filtered_payload_mb=()
    local -a filtered_runners=()
    local matched=0
    local i

    for i in "${!BENCH_LABELS[@]}"; do
        if bench_entry_matches_filter "$i" "$OP_FILTER"; then
            filtered_labels+=("${BENCH_LABELS[$i]}")
            filtered_commands+=("${BENCH_COMMANDS[$i]}")
            filtered_files+=("${BENCH_FILES[$i]}")
            filtered_operations+=("${BENCH_OPERATIONS[$i]}")
            filtered_payload_mb+=("${BENCH_PAYLOAD_MB[$i]}")
            filtered_runners+=("${BENCH_RUNNERS[$i]}")
            matched=1
        fi
    done

    if [ "$matched" -ne 1 ]; then
        if [ -n "${PENDING_REASONS[$OP_FILTER]:-}" ]; then
            BENCH_LABELS=()
            BENCH_COMMANDS=()
            BENCH_FILES=()
            BENCH_OPERATIONS=()
            BENCH_PAYLOAD_MB=()
            BENCH_RUNNERS=()
            return 0
        fi
        echo "unknown benchmark operation for --op: ${OP_FILTER}" >&2
        echo "available operations:" >&2
        print_available_ops >&2
        echo "pending operations:" >&2
        local operation
        for operation in mount_cold mount_warm mount_recovery; do
            if [ -n "${PENDING_REASONS[$operation]:-}" ]; then
                printf '  - %s (pending: %s)\n' "$operation" "${PENDING_REASONS[$operation]}" >&2
            fi
        done
        exit 2
    fi

    BENCH_LABELS=("${filtered_labels[@]}")
    BENCH_COMMANDS=("${filtered_commands[@]}")
    BENCH_FILES=("${filtered_files[@]}")
    BENCH_OPERATIONS=("${filtered_operations[@]}")
    BENCH_PAYLOAD_MB=("${filtered_payload_mb[@]}")
    BENCH_RUNNERS=("${filtered_runners[@]}")
}

single_line_text() {
    tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//'
}

scrub_probe_is_acceptable() {
    local exit_code="$1"
    local stdout_file="$2"
    if [ "$exit_code" -eq 0 ]; then
        return 0
    fi
    # `ffs-cli scrub --json` returns exit 2 when integrity findings are present.
    # Treat that as benchmarkable if structured scrub JSON was emitted.
    if [ "$exit_code" -eq 2 ]; then
        local scrub_json
        scrub_json="$(
            sed -n '/^[[:space:]]*{/,${p;}' "$stdout_file" \
                | sed '/^[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}T/,$d'
        )"
        if [ -n "$scrub_json" ] && jq -e 'has("blocks_scanned") and has("findings")' >/dev/null 2>&1 <<<"$scrub_json"; then
            return 0
        fi
    fi
    return 1
}

set_mount_pending_reasons() {
    local reason="$1"
    local recovery_reason="$2"
    PENDING_REASONS["mount_cold"]="$reason"
    PENDING_REASONS["mount_warm"]="$reason"
    PENDING_REASONS["mount_recovery"]="$recovery_reason"
}

record_mount_pending_labels() {
    local operation
    for operation in mount_cold mount_warm mount_recovery; do
        if [ -n "${PENDING_REASONS[$operation]:-}" ]; then
            if ! pending_entry_matches_filter "$operation"; then
                continue
            fi
            SKIPPED_LABELS+=("${operation} (pending: ${PENDING_REASONS[$operation]})")
        fi
    done
}

configure_mount_benchmarks() {
    local recovery_reason
    recovery_reason="mount recovery benchmark requires journal-enabled ext4 probe image + automated recovery mount probe"
    local -a mount_probe_prefix=()
    local mount_probe_prefix_str=""

    if [ "$MOUNT_PROBE_USE_SUDO" -eq 1 ]; then
        if ! command -v sudo >/dev/null 2>&1; then
            set_mount_pending_reasons \
                "FFS_MOUNT_PROBE_USE_SUDO=1 requested but sudo is unavailable" \
                "$recovery_reason"
            return
        fi
        if ! sudo -n true >/dev/null 2>&1; then
            set_mount_pending_reasons \
                "FFS_MOUNT_PROBE_USE_SUDO=1 requested but sudo -n is not permitted on this host" \
                "$recovery_reason"
            return
        fi
        mount_probe_prefix=(sudo -n)
        mount_probe_prefix_str="sudo -n "
    fi

    if [ "$USE_LOCAL_RELEASE_BINS" -ne 1 ] || [ ! -x "$CLI_BIN" ]; then
        set_mount_pending_reasons \
            "mount benchmarks require a local ${BENCH_PROFILE} ffs-cli binary at ${CLI_BIN} (remote cargo execution cannot mount local FUSE)" \
            "$recovery_reason"
        return
    fi

    if [ ! -e /dev/fuse ] || [ ! -r /dev/fuse ] || [ ! -w /dev/fuse ]; then
        set_mount_pending_reasons \
            "/dev/fuse is unavailable or lacks rw access on this host" \
            "$recovery_reason"
        return
    fi

    if mount_image_creation_needs_mkfs && ! command -v mkfs.ext4 >/dev/null 2>&1; then
        set_mount_pending_reasons \
            "mkfs.ext4 is required for mount probe image generation" \
            "$recovery_reason"
        return
    fi

    if ! command -v mountpoint >/dev/null 2>&1; then
        set_mount_pending_reasons \
            "mountpoint utility is required for FUSE readiness checks" \
            "$recovery_reason"
        return
    fi

    if [ ! -x "scripts/mount_benchmark_probe.sh" ]; then
        set_mount_pending_reasons \
            "scripts/mount_benchmark_probe.sh is missing or not executable" \
            "$recovery_reason"
        return
    fi

    if [ -n "$MOUNT_PROBE_IMAGE_OVERRIDE" ]; then
        MOUNT_BENCH_IMAGE="$MOUNT_PROBE_IMAGE_OVERRIDE"
    else
        MOUNT_BENCH_IMAGE="${OUT_DIR}/mount_probe.ext4"
    fi
    if [ -n "$MOUNT_RECOVERY_PROBE_IMAGE_OVERRIDE" ]; then
        MOUNT_RECOVERY_IMAGE="$MOUNT_RECOVERY_PROBE_IMAGE_OVERRIDE"
    else
        MOUNT_RECOVERY_IMAGE="${OUT_DIR}/mount_recovery_probe.ext4"
    fi
    MOUNT_BENCH_ROOT="${OUT_DIR}/mount_probe_mounts"
    mkdir -p "$MOUNT_BENCH_ROOT"

    if [ -n "$MOUNT_PROBE_IMAGE_OVERRIDE" ]; then
        if [ ! -f "$MOUNT_BENCH_IMAGE" ]; then
            set_mount_pending_reasons \
                "mount probe image override does not exist: ${MOUNT_BENCH_IMAGE}" \
                "$recovery_reason"
            return
        fi
    else
        if ! dd if=/dev/zero of="$MOUNT_BENCH_IMAGE" bs=1M count=16 status=none; then
            set_mount_pending_reasons \
                "failed to create mount probe image at ${MOUNT_BENCH_IMAGE}" \
                "$recovery_reason"
            return
        fi

        if ! mkfs.ext4 -F -O extent,filetype,^has_journal -L ffs_mount_probe "$MOUNT_BENCH_IMAGE" >/dev/null 2>&1; then
            set_mount_pending_reasons \
                "mkfs.ext4 failed while preparing mount probe image" \
                "$recovery_reason"
            return
        fi
    fi

    if recovery_mount_benchmark_needed; then
        if [ -n "$MOUNT_RECOVERY_PROBE_IMAGE_OVERRIDE" ]; then
            if [ ! -f "$MOUNT_RECOVERY_IMAGE" ]; then
                PENDING_REASONS["mount_recovery"]="recovery mount probe image override does not exist: ${MOUNT_RECOVERY_IMAGE}"
                return
            fi
        else
            if ! dd if=/dev/zero of="$MOUNT_RECOVERY_IMAGE" bs=1M count=32 status=none; then
                set_mount_pending_reasons \
                    "failed to create recovery mount probe image at ${MOUNT_RECOVERY_IMAGE}" \
                    "$recovery_reason"
                return
            fi

            if ! mkfs.ext4 -F -O extent,filetype -L ffs_mount_recovery_probe "$MOUNT_RECOVERY_IMAGE" >/dev/null 2>&1; then
                set_mount_pending_reasons \
                    "mkfs.ext4 failed while preparing recovery mount probe image" \
                    "$recovery_reason"
                return
            fi
        fi
    fi

    local probe_err
    probe_err="${OUT_DIR}/ffs_cli_mount_probe.stderr"
    local cold_probe_report warm_probe_report recovery_probe_report
    cold_probe_report="${OUT_DIR}/ffs_cli_mount_cold_probe_report.json"
    warm_probe_report="${OUT_DIR}/ffs_cli_mount_warm_probe_report.json"
    recovery_probe_report="${OUT_DIR}/ffs_cli_mount_recovery_probe_report.json"
    PENDING_SOURCE_JSON["mount_cold"]="$cold_probe_report"
    PENDING_SOURCE_JSON["mount_warm"]="$cold_probe_report"
    PENDING_SOURCE_JSON["mount_recovery"]="$recovery_probe_report"
    if "${mount_probe_prefix[@]}" scripts/mount_benchmark_probe.sh \
        --bin "$CLI_BIN" \
        --image "$MOUNT_BENCH_IMAGE" \
        --mount-root "$MOUNT_BENCH_ROOT" \
        --mode cold \
        --out-json "$cold_probe_report" \
        >/dev/null 2>"$probe_err"; then
        local cmd_base
        cmd_base="${mount_probe_prefix_str}scripts/mount_benchmark_probe.sh --bin $(printf '%q' "$CLI_BIN") --image $(printf '%q' "$MOUNT_BENCH_IMAGE") --mount-root $(printf '%q' "$MOUNT_BENCH_ROOT")"

        add_bench "ffs-cli mount cold ext4 probe (fuse)" \
            "${cmd_base} --mode cold --out-json $(printf '%q' "$cold_probe_report")" \
            "ffs_cli_mount_cold_probe.json" \
            "mount_cold" \
            "0"
        add_bench "ffs-cli mount warm ext4 probe (fuse)" \
            "${cmd_base} --mode warm --out-json $(printf '%q' "$warm_probe_report")" \
            "ffs_cli_mount_warm_probe.json" \
            "mount_warm" \
            "0"

        unset 'PENDING_REASONS[mount_cold]'
        unset 'PENDING_REASONS[mount_warm]'
        unset 'PENDING_SOURCE_JSON[mount_cold]'
        unset 'PENDING_SOURCE_JSON[mount_warm]'

        if recovery_mount_benchmark_needed; then
            local recovery_probe_err
            recovery_probe_err="${OUT_DIR}/ffs_cli_mount_recovery_probe.stderr"
            local recovery_cmd_base
            recovery_cmd_base="${mount_probe_prefix_str}scripts/mount_benchmark_probe.sh --bin $(printf '%q' "$CLI_BIN") --image $(printf '%q' "$MOUNT_RECOVERY_IMAGE") --mount-root $(printf '%q' "$MOUNT_BENCH_ROOT")"
            if "${mount_probe_prefix[@]}" scripts/mount_benchmark_probe.sh \
                --bin "$CLI_BIN" \
                --image "$MOUNT_RECOVERY_IMAGE" \
                --mount-root "$MOUNT_BENCH_ROOT" \
                --mode recovery \
                --out-json "$recovery_probe_report" \
                >/dev/null 2>"$recovery_probe_err"; then
                add_bench "ffs-cli mount recovery ext4 probe (journal replay)" \
                    "${recovery_cmd_base} --mode recovery --out-json $(printf '%q' "$recovery_probe_report")" \
                    "ffs_cli_mount_recovery_probe.json" \
                    "mount_recovery" \
                    "0"
                unset 'PENDING_REASONS[mount_recovery]'
                unset 'PENDING_SOURCE_JSON[mount_recovery]'
            else
                local recovery_probe_reason
                recovery_probe_reason="$(single_line_text < "$recovery_probe_err")"
                if [ -z "$recovery_probe_reason" ]; then
                    recovery_probe_reason="mount recovery probe failed with unknown error"
                fi
                PENDING_REASONS["mount_recovery"]="mount recovery probe failed on this host: ${recovery_probe_reason} (set FFS_MOUNT_PROBE_USE_SUDO=1 or --mount-probe-use-sudo if passwordless sudo is available)"
            fi
        fi
    else
        local probe_reason
        probe_reason="$(single_line_text < "$probe_err")"
        if [ -z "$probe_reason" ]; then
            probe_reason="mount benchmark probe failed with unknown error"
        fi
        set_mount_pending_reasons \
            "mount benchmark probe failed on this host: ${probe_reason} (set FFS_MOUNT_PROBE_USE_SUDO=1 or --mount-probe-use-sudo if passwordless sudo is available)" \
            "$recovery_reason"
    fi
}

if [ "$COMMAND_BENCHMARKS_NEEDED" -eq 1 ]; then
if [ "$USE_LOCAL_RELEASE_BINS" -eq 1 ]; then
    add_bench "ffs-cli parity --json" \
        "${CLI_BIN} parity --json" \
        "ffs_cli_parity.json" \
        "metadata_parity_cli" \
        "0"

    add_bench "ffs-harness parity" \
        "${HARNESS_BIN} parity" \
        "ffs_harness_parity.json" \
        "metadata_parity_harness" \
        "0"

    add_bench "ffs-harness check-fixtures" \
        "${HARNESS_BIN} check-fixtures" \
        "ffs_harness_check_fixtures.json" \
        "fixture_validation" \
        "0"
else
    add_bench "ffs-cli parity --json" \
        "$(cargo_run_cmd ffs-cli "parity --json")" \
        "ffs_cli_parity.json" \
        "metadata_parity_cli" \
        "0"

    add_bench "ffs-harness parity" \
        "$(cargo_run_cmd ffs-harness "parity")" \
        "ffs_harness_parity.json" \
        "metadata_parity_harness" \
        "0"

    add_bench "ffs-harness check-fixtures" \
        "$(cargo_run_cmd ffs-harness "check-fixtures")" \
        "ffs_harness_check_fixtures.json" \
        "fixture_validation" \
        "0"
fi

if [ -f "$REF_IMAGE" ]; then
    probe_stderr="${OUT_DIR}/ffs_cli_inspect_probe.stderr"
    scrub_probe_stderr="${OUT_DIR}/ffs_cli_scrub_probe.stderr"
    scrub_probe_stdout="${OUT_DIR}/ffs_cli_scrub_probe.stdout"
    if [ "$USE_LOCAL_RELEASE_BINS" -eq 1 ]; then
        if "$CLI_BIN" inspect "$REF_IMAGE" --json >/dev/null 2>"$probe_stderr"; then
            add_bench "ffs-cli inspect ext4_8mb_reference.ext4 --json" \
                "${CLI_BIN} inspect ${REF_IMAGE} --json" \
                "ffs_cli_inspect_ext4_8mb_reference.json" \
                "read_metadata_inspect_ext4_reference" \
                "8"
            scrub_probe_exit=0
            if "$CLI_BIN" scrub "$REF_IMAGE" --json >"$scrub_probe_stdout" 2>"$scrub_probe_stderr"; then
                scrub_probe_exit=0
            else
                scrub_probe_exit=$?
            fi
            if scrub_probe_is_acceptable "$scrub_probe_exit" "$scrub_probe_stdout"; then
                add_bench "ffs-cli scrub ext4_8mb_reference.ext4 --json" \
                    "bash -lc '\"${CLI_BIN}\" scrub \"${REF_IMAGE}\" --json >/dev/null || [ \$? -eq 2 ]'" \
                    "ffs_cli_scrub_ext4_8mb_reference.json" \
                    "read_metadata_scrub_ext4_reference" \
                    "8"
            else
                scrub_probe_reason="$(single_line_text < "$scrub_probe_stderr")"
                if [ -z "$scrub_probe_reason" ]; then
                    scrub_probe_reason="scrub probe returned non-zero with no stderr output"
                fi
                SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (scrub probe failed with exit ${scrub_probe_exit}: ${scrub_probe_reason})")
            fi
        else
            probe_reason="$(tr '\n' ' ' < "$probe_stderr" | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
            SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (inspect probe failed: ${probe_reason})")
            SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (skipped because inspect probe failed)")
        fi
    else
        if cargo_exec run -p ffs-cli --profile "$BENCH_PROFILE" --quiet -- inspect "$REF_IMAGE" --json >/dev/null 2>"$probe_stderr"; then
            add_bench "ffs-cli inspect ext4_8mb_reference.ext4 --json" \
                "$(cargo_run_cmd ffs-cli "inspect ${REF_IMAGE} --json")" \
                "ffs_cli_inspect_ext4_8mb_reference.json" \
                "read_metadata_inspect_ext4_reference" \
                "8"
            scrub_probe_exit=0
            if cargo_exec run -p ffs-cli --profile "$BENCH_PROFILE" --quiet -- scrub "$REF_IMAGE" --json >"$scrub_probe_stdout" 2>"$scrub_probe_stderr"; then
                scrub_probe_exit=0
            else
                scrub_probe_exit=$?
            fi
            if scrub_probe_is_acceptable "$scrub_probe_exit" "$scrub_probe_stdout"; then
                add_bench "ffs-cli scrub ext4_8mb_reference.ext4 --json" \
                    "bash -lc '$(cargo_run_cmd ffs-cli "scrub ${REF_IMAGE} --json") >/dev/null || [ \$? -eq 2 ]'" \
                    "ffs_cli_scrub_ext4_8mb_reference.json" \
                    "read_metadata_scrub_ext4_reference" \
                    "8"
            else
                scrub_probe_reason="$(single_line_text < "$scrub_probe_stderr")"
                if [ -z "$scrub_probe_reason" ]; then
                    scrub_probe_reason="scrub probe returned non-zero with no stderr output"
                fi
                SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (scrub probe failed with exit ${scrub_probe_exit}: ${scrub_probe_reason})")
            fi
        else
            probe_reason="$(tr '\n' ' ' < "$probe_stderr" | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
            SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (inspect probe failed: ${probe_reason})")
            SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (skipped because inspect probe failed)")
        fi
    fi
else
    SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (missing ${REF_IMAGE})")
    SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (missing ${REF_IMAGE})")
fi
fi

add_bench "ffs-harness metadata parse (criterion)" \
    "$(cargo_bench_cmd "-p ffs-harness --bench metadata_parse -- metadata_parse")" \
    "ffs_harness_metadata_parse.json" \
    "cli_metadata_parse_conformance" \
    "0"

add_bench "ffs-block arc sequential scan (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- block_cache_arc_sequential_scan")" \
    "ffs_block_arc_sequential_scan.json" \
    "block_cache_arc_sequential_scan" \
    "0"

add_bench "ffs-block arc zipf distribution (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- block_cache_arc_zipf_distribution")" \
    "ffs_block_arc_zipf_distribution.json" \
    "block_cache_arc_zipf_distribution" \
    "0"

add_bench "ffs-block arc mixed seq70 hot30 (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- block_cache_arc_mixed_seq70_hot30")" \
    "ffs_block_arc_mixed_seq70_hot30.json" \
    "block_cache_arc_mixed_seq70_hot30" \
    "0"

add_bench "ffs-block arc concurrent hot read 64 threads (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- block_cache_arc_concurrent_hot_read_64threads")" \
    "ffs_block_arc_concurrent_hot_read_64threads.json" \
    "block_cache_arc_concurrent_hot_read_64threads" \
    "512"

add_bench "ffs-block sharded arc concurrent hot read 64 threads (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- block_cache_sharded_arc_concurrent_hot_read_64threads")" \
    "ffs_block_sharded_arc_concurrent_hot_read_64threads.json" \
    "block_cache_sharded_arc_concurrent_hot_read_64threads" \
    "512"

add_bench "ffs-block arc compile-like (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- block_cache_arc_compile_like")" \
    "ffs_block_arc_compile_like.json" \
    "block_cache_arc_compile_like" \
    "0"

add_bench "ffs-block arc database-like (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- block_cache_arc_database_like")" \
    "ffs_block_arc_database_like.json" \
    "block_cache_arc_database_like" \
    "0"

add_bench "ffs-block s3fifo sequential scan (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_sequential_scan")" \
    "ffs_block_s3fifo_sequential_scan.json" \
    "block_cache_s3fifo_sequential_scan" \
    "0"

add_bench "ffs-block s3fifo zipf distribution (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_zipf_distribution")" \
    "ffs_block_s3fifo_zipf_distribution.json" \
    "block_cache_s3fifo_zipf_distribution" \
    "0"

add_bench "ffs-block s3fifo mixed seq70 hot30 (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_mixed_seq70_hot30")" \
    "ffs_block_s3fifo_mixed_seq70_hot30.json" \
    "block_cache_s3fifo_mixed_seq70_hot30" \
    "0"

add_bench "ffs-block s3fifo concurrent hot read 64 threads (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_concurrent_hot_read_64threads")" \
    "ffs_block_s3fifo_concurrent_hot_read_64threads.json" \
    "block_cache_s3fifo_concurrent_hot_read_64threads" \
    "512"

add_bench "ffs-block sharded s3fifo concurrent hot read 64 threads (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --features s3fifo --bench arc_cache -- block_cache_sharded_s3fifo_concurrent_hot_read_64threads")" \
    "ffs_block_sharded_s3fifo_concurrent_hot_read_64threads.json" \
    "block_cache_sharded_s3fifo_concurrent_hot_read_64threads" \
    "512"

add_bench "ffs-block s3fifo compile-like (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_compile_like")" \
    "ffs_block_s3fifo_compile_like.json" \
    "block_cache_s3fifo_compile_like" \
    "0"

add_bench "ffs-block s3fifo database-like (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --features s3fifo --bench arc_cache -- block_cache_s3fifo_database_like")" \
    "ffs_block_s3fifo_database_like.json" \
    "block_cache_s3fifo_database_like" \
    "0"

add_bench "ffs-block writeback write seq 4k (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- writeback_write_seq_4k")" \
    "ffs_block_writeback_write_seq_4k.json" \
    "write_seq_4k" \
    "0.00390625"

add_bench "ffs-block writeback write random 4k (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- writeback_write_random_4k")" \
    "ffs_block_writeback_write_random_4k.json" \
    "write_random_4k" \
    "0.00390625"

add_bench "ffs-block writeback fsync single write (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- writeback_sync_single_4k")" \
    "ffs_block_writeback_sync_single_4k.json" \
    "fsync_single_write" \
    "0.00390625"

add_bench "ffs-block writeback fsync batch 100x4k (criterion)" \
    "$(cargo_bench_cmd "-p ffs-block --bench arc_cache -- writeback_sync_100x4k")" \
    "ffs_block_writeback_sync_100x4k.json" \
    "fsync_batch_100" \
    "0.390625"

# ── WAL / MVCC expanded (criterion, ffs-mvcc) ─────────────────────────

add_bench "ffs-mvcc WAL commit 4k sync (criterion)" \
    "$(cargo_bench_cmd "-p ffs-mvcc --bench wal_throughput -- wal_commit_4k_sync")" \
    "ffs_mvcc_wal_commit_4k_sync.json" \
    "wal_commit_4k_sync" \
    "0.00390625"

add_bench "ffs-mvcc WAL write amplification 1-block (criterion)" \
    "$(cargo_bench_cmd "-p ffs-mvcc --bench wal_throughput -- wal_write_amplification_1block")" \
    "ffs_mvcc_wal_write_amplification_1block.json" \
    "wal_write_amplification_1block" \
    "0.00390625"

add_bench "ffs-mvcc WAL write amplification 16-block (criterion)" \
    "$(cargo_bench_cmd "-p ffs-mvcc --bench wal_throughput -- wal_write_amplification_16block")" \
    "ffs_mvcc_wal_write_amplification_16block.json" \
    "wal_write_amplification_16block" \
    "0.0625"

add_bench "ffs-mvcc contention 2 writers (criterion)" \
    "$(cargo_bench_cmd "-p ffs-mvcc --bench wal_throughput -- mvcc_contention_2writers")" \
    "ffs_mvcc_contention_2writers.json" \
    "mvcc_contention_2writers" \
    "0"

add_bench "ffs-mvcc contention 4 writers (criterion)" \
    "$(cargo_bench_cmd "-p ffs-mvcc --bench wal_throughput -- mvcc_contention_4writers")" \
    "ffs_mvcc_contention_4writers.json" \
    "mvcc_contention_4writers" \
    "0"

add_bench "ffs-mvcc merge-proof append-only success rate (criterion)" \
    "FFS_MVCC_MERGE_PROOF_REPORT=artifacts/benchmarks/mvcc_merge_proof_success_rate.json $(cargo_bench_cmd "-p ffs-mvcc --bench wal_throughput -- mvcc_merge_proof_append_only_success_rate")" \
    "ffs_mvcc_merge_proof_append_only_success_rate.json" \
    "mvcc_merge_proof_append_only_success_rate" \
    "0"

add_bench "ffs-mvcc contention 8 writers (criterion)" \
    "$(cargo_bench_cmd "-p ffs-mvcc --bench wal_throughput -- mvcc_contention_8writers")" \
    "ffs_mvcc_contention_8writers.json" \
    "mvcc_contention_8writers" \
    "0"

# ── Scrub / RaptorQ codec (criterion, ffs-repair) ─────────────────────

add_bench "ffs-repair scrub clean 256 blocks (criterion)" \
    "$(cargo_bench_cmd "-p ffs-repair --bench scrub_codec -- scrub_clean_256blocks")" \
    "ffs_repair_scrub_clean_256blocks.json" \
    "scrub_clean_256blocks" \
    "0"

add_bench "ffs-repair scrub corrupted 256 blocks (criterion)" \
    "$(cargo_bench_cmd "-p ffs-repair --bench scrub_codec -- scrub_corrupted_256blocks")" \
    "ffs_repair_scrub_corrupted_256blocks.json" \
    "scrub_corrupted_256blocks" \
    "0"

add_bench "ffs-repair raptorq encode 16-block group (criterion)" \
    "$(cargo_bench_cmd "-p ffs-repair --bench scrub_codec -- raptorq_encode_group_16blocks")" \
    "ffs_repair_raptorq_encode_group_16blocks.json" \
    "raptorq_encode_group_16blocks" \
    "0"

add_bench "ffs-repair raptorq decode 16-block group (criterion)" \
    "$(cargo_bench_cmd "-p ffs-repair --bench scrub_codec -- raptorq_decode_group_16blocks")" \
    "ffs_repair_raptorq_decode_group_16blocks.json" \
    "raptorq_decode_group_16blocks" \
    "0"

add_bench "ffs-repair symbol refresh staleness latency (criterion)" \
    "$(cargo_bench_cmd "-p ffs-repair --bench scrub_codec -- repair_symbol_refresh_staleness_latency")" \
    "ffs_repair_symbol_refresh_staleness_latency.json" \
    "repair_symbol_refresh_staleness_latency" \
    "0"

if [ "$COMMAND_BENCHMARKS_NEEDED" -eq 1 ]; then
    configure_mount_benchmarks
    record_mount_pending_labels
fi
apply_op_filter

json_mean() {
    jq -r '.results[0].mean' "$1"
}

json_stddev() {
    jq -r '.results[0].stddev' "$1"
}

json_percentile() {
    local json_file="$1"
    local percentile="$2"
    jq -r --argjson p "$percentile" '
        if (.benchmark_mode == "criterion_once" and .measurement_source == "criterion_estimate") then
              if $p >= 0.95 then
                  .results[0].max
              else
                  .results[0].median
              end
          else
              .results[0].times as $times
              | ($times | length) as $n
              | if $n == 0 then
                    0
                else
                    ($times | sort) as $sorted
                    | ((($n - 1) * $p) | floor) as $idx
                    | $sorted[$idx]
                end
          end
    ' "$json_file"
}

json_p50() {
    json_percentile "$1" 0.50
}

json_p95() {
    json_percentile "$1" 0.95
}

json_p99() {
    json_percentile "$1" 0.99
}

valid_number() {
    awk -v v="$1" 'BEGIN {
        if (v ~ /^-?[0-9]+([.][0-9]+)?([eE][-+]?[0-9]+)?$/) {
            exit 0;
        }
        exit 1;
    }'
}

sec_to_ms() {
    awk -v v="$1" 'BEGIN { printf "%.3f", v * 1000.0 }'
}

sec_to_us() {
    awk -v v="$1" 'BEGIN { printf "%.0f", v * 1000000.0 }'
}

ops_per_sec() {
    awk -v v="$1" 'BEGIN {
        if (v <= 0) {
            printf "0";
        } else {
            printf "%.6f", 1.0 / v;
        }
    }'
}

mb_per_sec() {
    awk -v mb="$1" -v sec="$2" 'BEGIN {
        if (mb <= 0 || sec <= 0) {
            printf "0";
        } else {
            printf "%.6f", mb / sec;
        }
    }'
}

pct_change() {
    awk -v base="$1" -v cur="$2" 'BEGIN {
        if (base == 0) {
            printf "0.00";
        } else {
            printf "%.2f", ((cur - base) / base) * 100.0;
        }
    }'
}

run_cache_workload_report() {
    local policy="$1"
    local report_tsv="$2"
    local log_file="${report_tsv%.tsv}.txt"
    local -a command

    if [ "$policy" = "s3fifo" ]; then
        if have_rch; then
            command=(
                rch exec -- env "FFS_BLOCK_CACHE_WORKLOAD_REPORT=-" cargo bench -p ffs-block --features s3fifo --bench arc_cache --profile "$BENCH_PROFILE" -- block_cache_s3fifo_sequential_scan
            )
        else
            command=(
                env "FFS_BLOCK_CACHE_WORKLOAD_REPORT=-" cargo bench -p ffs-block --features s3fifo --bench arc_cache --profile "$BENCH_PROFILE" -- block_cache_s3fifo_sequential_scan
            )
        fi
    else
        if have_rch; then
            command=(
                rch exec -- env "FFS_BLOCK_CACHE_WORKLOAD_REPORT=-" cargo bench -p ffs-block --bench arc_cache --profile "$BENCH_PROFILE" -- block_cache_arc_sequential_scan
            )
        else
            command=(
                env "FFS_BLOCK_CACHE_WORKLOAD_REPORT=-" cargo bench -p ffs-block --bench arc_cache --profile "$BENCH_PROFILE" -- block_cache_arc_sequential_scan
            )
        fi
    fi

    echo ""
    echo "--- ffs-block cache metrics (${policy}) ---"
    if "${command[@]}" >"$log_file" 2>&1; then
        if [ -s "$report_tsv" ] || extract_cache_report_from_log "$log_file" "$report_tsv"; then
            CACHE_WORKLOAD_REPORT_PATHS+=("$report_tsv")
            CACHE_WORKLOAD_REPORT_POLICIES+=("$policy")
        else
            SKIPPED_LABELS+=("ffs-block cache metrics (${policy}) missing report TSV; see ${log_file}")
        fi
    else
        SKIPPED_LABELS+=("ffs-block cache metrics (${policy}) failed; see ${log_file}")
    fi
}

collect_cache_workload_metrics_json() {
    local json_chunks='[]'
    local report_json
    for report_tsv in "${CACHE_WORKLOAD_REPORT_PATHS[@]}"; do
        if [ ! -f "$report_tsv" ]; then
            continue
        fi
        report_json="$(jq -Rn --arg source_tsv "$report_tsv" '
            [inputs
            | select(length > 0)
            | split("\t")
            | select(.[0] != "policy")
            | {
                policy: .[0],
                workload: .[1],
                accesses: (.[2] | tonumber),
                hits: (.[3] | tonumber),
                misses: (.[4] | tonumber),
                hit_rate: (.[5] | tonumber),
                resident: (.[6] | tonumber),
                capacity: (.[7] | tonumber),
                b1_len: (.[8] | tonumber),
                b2_len: (.[9] | tonumber),
                memory_overhead_per_cached_block: (.[10] | tonumber),
                seed: (.[11] | tonumber),
                source_tsv: $source_tsv
              }
            ]
        ' < "$report_tsv")"
        json_chunks="$(jq -n --argjson lhs "$json_chunks" --argjson rhs "$report_json" '$lhs + $rhs')"
    done

    printf '%s\n' "$json_chunks"
}

should_collect_cache_workload_metrics() {
    if [ -z "$OP_FILTER" ]; then
        return 0
    fi

    local operation
    for operation in "${BENCH_OPERATIONS[@]}"; do
        case "$operation" in
            block_cache_*)
                return 0
                ;;
        esac
    done
    return 1
}

if should_collect_cache_workload_metrics; then
    run_cache_workload_report "arc" "${OUT_DIR}/ffs_block_cache_workloads_arc.tsv"
    run_cache_workload_report "s3fifo" "${OUT_DIR}/ffs_block_cache_workloads_s3fifo.tsv"
else
    SKIPPED_LABELS+=("ffs-block cache metrics skipped by --op ${OP_FILTER}")
fi
CACHE_WORKLOAD_METRICS_JSON="$(collect_cache_workload_metrics_json)"

run_hyperfine_benchmark() {
    local label="$1"
    local cmd="$2"
    local json_file="$3"
    local txt_file="$4"

    echo "--- ${label} ---"
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --export-json "$json_file" \
        "$cmd" | tee "$txt_file"
}

scale_criterion_time_seconds() {
    local value="$1"
    local unit="$2"
    awk -v value="$value" -v unit="$unit" 'BEGIN {
        if (unit == "s") {
            scale = 1.0;
        } else if (unit == "ms") {
            scale = 0.001;
        } else if (unit == "us" || unit == "µs" || unit == "μs") {
            scale = 0.000001;
        } else if (unit == "ns") {
            scale = 0.000000001;
        } else if (unit == "ps") {
            scale = 0.000000000001;
        } else {
            exit 2;
        }
        printf "%.12f", value * scale;
    }'
}

criterion_time_estimates() {
    local output_file="$1"
    local line
    line="$(grep -E '(^|[[:space:]])time:[[:space:]]+\[' "$output_file" | tail -n 1 || true)"
    [ -n "$line" ] || return 1

    local low
    local low_unit
    local mean
    local mean_unit
    local high
    local high_unit
    read -r low low_unit mean mean_unit high high_unit < <(
        printf '%s\n' "$line" | awk '
            {
                for (i = 1; i <= NF; i += 1) {
                    gsub(/\[/, "", $i);
                    gsub(/\]/, "", $i);
                }
                for (i = 1; i <= NF; i += 1) {
                    if ($i == "time:") {
                        print $(i + 1), $(i + 2), $(i + 3), $(i + 4), $(i + 5), $(i + 6);
                        exit;
                    }
                }
            }
        '
    )

    [ -n "${low:-}" ] && [ -n "${low_unit:-}" ] \
        && [ -n "${mean:-}" ] && [ -n "${mean_unit:-}" ] \
        && [ -n "${high:-}" ] && [ -n "${high_unit:-}" ] || return 1
    valid_number "$low" && valid_number "$mean" && valid_number "$high" || return 1

    printf '%s\t%s\t%s\n' \
        "$(scale_criterion_time_seconds "$low" "$low_unit")" \
        "$(scale_criterion_time_seconds "$mean" "$mean_unit")" \
        "$(scale_criterion_time_seconds "$high" "$high_unit")"
}

run_criterion_once_benchmark() {
    local label="$1"
    local cmd="$2"
    local json_file="$3"
    local txt_file="$4"
    local stdout_file="${json_file%.json}.stdout"
    local stderr_file="${json_file%.json}.stderr"
    local started_at
    local finished_at
    local start_ns
    local end_ns
    local duration_s
    local exit_status
    local criterion_estimates
    local criterion_source
    local result_min_s
    local result_mean_s
    local result_max_s
    local result_stddev_s
    local measurement_source

    echo "--- ${label} ---"
    echo "Criterion benchmark detected; running once and preserving Criterion's own sample report."

    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    start_ns="$(date +%s%N)"
    exit_status=0
    : >"$stdout_file"
    : >"$stderr_file"
    bash -lc "$cmd" >>"$stdout_file" 2>>"$stderr_file" || exit_status=$?
    end_ns="$(date +%s%N)"
    finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    duration_s="$(awk -v start="$start_ns" -v end="$end_ns" 'BEGIN { printf "%.9f", (end - start) / 1000000000.0 }')"
    criterion_estimates=""
    criterion_source=""
    if criterion_estimates="$(criterion_time_estimates "$stderr_file" 2>/dev/null)"; then
        criterion_source="$stderr_file"
    elif criterion_estimates="$(criterion_time_estimates "$stdout_file" 2>/dev/null)"; then
        criterion_source="$stdout_file"
    fi

    if [ -n "$criterion_estimates" ]; then
        read -r result_min_s result_mean_s result_max_s <<<"$criterion_estimates"
        measurement_source="criterion_estimate"
    else
        result_min_s="$duration_s"
        result_mean_s="$duration_s"
        result_max_s="$duration_s"
        measurement_source="wall_time_fallback"
    fi
    result_stddev_s="$(awk -v low="$result_min_s" -v high="$result_max_s" 'BEGIN { printf "%.12f", (high - low) / 3.92 }')"

    {
        echo "benchmark_mode: criterion_once"
        echo "command: ${cmd}"
        echo "started_at_utc: ${started_at}"
        echo "finished_at_utc: ${finished_at}"
        echo "wall_time_seconds: ${duration_s}"
        echo "measurement_source: ${measurement_source}"
        if [ -n "$criterion_source" ]; then
            echo "criterion_estimate_source: ${criterion_source}"
            echo "criterion_estimate_seconds: [${result_min_s}, ${result_mean_s}, ${result_max_s}]"
        fi
        echo "exit_status: ${exit_status}"
        echo ""
        echo "## stdout"
        if [ -f "$stdout_file" ]; then
            cat "$stdout_file"
        fi
        echo ""
        echo "## stderr"
        if [ -f "$stderr_file" ]; then
            cat "$stderr_file"
        fi
    } > "$txt_file"

    jq -n \
        --arg command "$cmd" \
        --arg benchmark_mode "criterion_once" \
        --arg stdout_file "$stdout_file" \
        --arg stderr_file "$stderr_file" \
        --arg text_report "$txt_file" \
        --arg started_at "$started_at" \
        --arg finished_at "$finished_at" \
        --arg measurement_source "$measurement_source" \
        --arg criterion_source "$criterion_source" \
        --argjson wall_time_seconds "$duration_s" \
        --argjson result_min_seconds "$result_min_s" \
        --argjson result_mean_seconds "$result_mean_s" \
        --argjson result_max_seconds "$result_max_s" \
        --argjson result_stddev_seconds "$result_stddev_s" \
        --argjson exit_status "$exit_status" \
        '{
            results: [{
                command: $command,
                mean: $result_mean_seconds,
                stddev: $result_stddev_seconds,
                median: $result_mean_seconds,
                min: $result_min_seconds,
                max: $result_max_seconds,
                times: [$result_min_seconds, $result_mean_seconds, $result_max_seconds],
                exit_codes: [$exit_status]
            }],
            benchmark_mode: $benchmark_mode,
            measurement_source: $measurement_source,
            criterion_estimate_source: $criterion_source,
            wall_time_seconds: $wall_time_seconds,
            command_stdout: $stdout_file,
            command_stderr: $stderr_file,
            text_report: $text_report,
            started_at: $started_at,
            finished_at: $finished_at
        }' > "$json_file"

    if [ "$exit_status" -ne 0 ]; then
        echo "criterion command failed with exit ${exit_status}; see ${stderr_file}" >&2
        return "$exit_status"
    fi
}

echo "Running benchmarks..."
for i in "${!BENCH_LABELS[@]}"; do
    label="${BENCH_LABELS[$i]}"
    cmd="${BENCH_COMMANDS[$i]}"
    json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
    txt_file="${json_file%.json}.txt"
    runner="${BENCH_RUNNERS[$i]}"

    echo ""
    case "$runner" in
        hyperfine)
            run_hyperfine_benchmark "$label" "$cmd" "$json_file" "$txt_file"
            ;;
        criterion_once)
            run_criterion_once_benchmark "$label" "$cmd" "$json_file" "$txt_file"
            ;;
        *)
            echo "unknown benchmark runner for ${label}: ${runner}" >&2
            exit 2
            ;;
    esac
done
echo ""

build_pending_json() {
    local pending_json
    pending_json='[]'
    local operation
    for operation in mount_cold mount_warm mount_recovery; do
        local reason
        reason="${PENDING_REASONS[$operation]:-}"
        if [ -z "$reason" ]; then
            continue
        fi
        if ! pending_entry_matches_filter "$operation"; then
            continue
        fi
        local source_json
        source_json="${PENDING_SOURCE_JSON[$operation]:-}"
        pending_json="$(
            jq -n \
                --argjson prior "$pending_json" \
                --arg operation "$operation" \
                --arg reason "$reason" \
                --arg source_json "$source_json" \
                '$prior + [{
                    operation: $operation,
                    metric: "latency",
                    command: "",
                    source_json: $source_json,
                    p50_us: 0,
                    p95_us: 0,
                    p99_us: 0,
                    throughput_ops_sec: 0,
                    throughput_mb_sec: 0,
                    status: "pending",
                    probe_report_json: $source_json,
                    reason: $reason
                }]'
        )"
    done
    echo "$pending_json"
}

write_perf_baseline_json() {
    local measured_json
    measured_json='[]'
    for i in "${!BENCH_LABELS[@]}"; do
        local json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
        local mean_s
        local p50_s
        local p95_s
        local p99_s
        local p50_us
        local p95_us
        local p99_us
        local throughput_ops_sec
        local throughput_mb_sec
        local benchmark_mode
        local measurement_json
        mean_s="$(json_mean "$json_file")"
        p50_s="$(json_p50 "$json_file")"
        p95_s="$(json_p95 "$json_file")"
        p99_s="$(json_p99 "$json_file")"
        p50_us="$(sec_to_us "$p50_s")"
        p95_us="$(sec_to_us "$p95_s")"
        p99_us="$(sec_to_us "$p99_s")"
        throughput_ops_sec="$(ops_per_sec "$mean_s")"
        throughput_mb_sec="$(mb_per_sec "${BENCH_PAYLOAD_MB[$i]}" "$mean_s")"
        benchmark_mode="${BENCH_RUNNERS[$i]}"

        measurement_json="$(jq -n \
            --arg operation "${BENCH_OPERATIONS[$i]}" \
            --arg metric "latency" \
            --arg command "${BENCH_COMMANDS[$i]}" \
            --arg benchmark_mode "$benchmark_mode" \
            --arg source_json "$json_file" \
            --argjson p50_us "$p50_us" \
            --argjson p95_us "$p95_us" \
            --argjson p99_us "$p99_us" \
            --argjson throughput_ops_sec "$throughput_ops_sec" \
            --argjson throughput_mb_sec "$throughput_mb_sec" \
            '{
                operation: $operation,
                metric: $metric,
                command: $command,
                benchmark_mode: $benchmark_mode,
                source_json: $source_json,
                p50_us: $p50_us,
                p95_us: $p95_us,
                p99_us: $p99_us,
                throughput_ops_sec: $throughput_ops_sec,
                throughput_mb_sec: $throughput_mb_sec,
                status: "measured"
            }')"
        measured_json="$(jq -n --argjson prior "$measured_json" --argjson next "$measurement_json" '$prior + [$next]')"
    done

    local measurements_json
    local pending_json
    pending_json="$(build_pending_json)"
    measurements_json="$(jq -n --argjson measured "$measured_json" --argjson pending "$pending_json" '$measured + $pending')"

    jq -n \
        --arg generated_at "$date_iso" \
        --arg date_tag "$DATE_TAG" \
        --arg commit "$git_sha" \
        --arg branch "$git_branch" \
        --arg thresholds_file "$THRESHOLDS_PATH" \
        --arg hostname "$host_name" \
        --arg cpu_model "$cpu_model" \
        --arg kernel "$kernel_ver" \
        --arg cargo_target_dir "$cargo_target_dir" \
        --arg rustc "$rustc_ver" \
        --arg cargo "$cargo_ver" \
        --arg hyperfine "$hyperfine_ver" \
        --argjson memory_total_kib "$memory_total_kib" \
        --argjson memory_total_gib "$memory_total_gib" \
        --argjson warmup_runs "$WARMUP" \
        --argjson measured_runs "$RUNS" \
        --argjson p99_warn_threshold_percent "$P99_WARN_THRESHOLD" \
        --argjson p99_fail_threshold_percent "$P99_FAIL_THRESHOLD" \
        --argjson measurements "$measurements_json" \
        --argjson cache_workload_metrics "$CACHE_WORKLOAD_METRICS_JSON" \
        --argjson measured_count "$(jq 'map(select(.status == "measured")) | length' <<<"$measurements_json")" \
        --argjson pending_count "$(jq 'map(select(.status == "pending")) | length' <<<"$measurements_json")" \
        --argjson cache_workload_metric_count "$(jq 'length' <<<"$CACHE_WORKLOAD_METRICS_JSON")" \
        '{
            generated_at: $generated_at,
            date_tag: $date_tag,
            commit: $commit,
            branch: $branch,
            environment: {
                hostname: $hostname,
                cpu_model: $cpu_model,
                kernel: $kernel,
                memory_total_kib: $memory_total_kib,
                memory_total_gib: $memory_total_gib,
                cargo_target_dir: $cargo_target_dir,
                rustc: $rustc,
                cargo: $cargo,
                hyperfine: $hyperfine
            },
            warmup_runs: $warmup_runs,
            measured_runs: $measured_runs,
            thresholds_file: $thresholds_file,
            p99_warn_threshold_percent: $p99_warn_threshold_percent,
            p99_fail_threshold_percent: $p99_fail_threshold_percent,
            measurement_coverage: {
                measured_count: $measured_count,
                pending_count: $pending_count,
                cache_workload_metric_count: $cache_workload_metric_count
            },
            measurements: $measurements,
            cache_workload_metrics: $cache_workload_metrics
        }' > "$PERF_BASELINE_PATH"

    cp "$PERF_BASELINE_PATH" "$PERF_BASELINE_DATED_PATH"
    if [ -z "$OP_FILTER" ]; then
        cp "$PERF_BASELINE_PATH" "$BENCHMARK_BASELINE_LATEST_PATH"
        WROTE_BENCHMARK_BASELINE_LATEST=1
    else
        WROTE_BENCHMARK_BASELINE_LATEST=0
    fi
    cp "$PERF_BASELINE_PATH" "$BENCHMARK_BASELINE_HISTORY_PATH"
}

cpu_model="$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
if [ -z "${cpu_model}" ]; then
    cpu_model="unknown"
fi

host_name="$(hostname 2>/dev/null || true)"
if [ -z "${host_name}" ]; then
    host_name="unknown"
fi

memory_total_kib="$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null || true)"
if ! valid_number "${memory_total_kib:-}"; then
    memory_total_kib=0
fi
memory_total_gib="$(awk -v kib="$memory_total_kib" 'BEGIN { printf "%.3f", kib / 1048576.0 }')"

cargo_target_dir="${CARGO_TARGET_DIR:-target}"

git_sha="$(git rev-parse HEAD)"
git_branch="$(git branch --show-current)"
rustc_ver="$(rustc --version)"
cargo_ver="$(cargo --version)"
hyperfine_ver="$(hyperfine --version)"
kernel_ver="$(uname -srmo)"
date_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
    echo "# FrankenFS Baseline — ${DATE_TAG}"
    echo ""
    echo "## Metadata"
    echo ""
    echo "- Date (UTC): \`${date_iso}\`"
    echo "- Commit: \`${git_sha}\`"
    echo "- Branch: \`${git_branch}\`"
    echo "- Hostname: \`${host_name}\`"
    echo "- Host kernel: \`${kernel_ver}\`"
    echo "- CPU: \`${cpu_model}\`"
    echo "- Memory: \`${memory_total_gib} GiB (${memory_total_kib} KiB)\`"
    echo "- rustc: \`${rustc_ver}\`"
    echo "- cargo: \`${cargo_ver}\`"
    echo "- hyperfine: \`${hyperfine_ver}\`"
    echo "- Cargo profile: \`${BENCH_PROFILE}\`"
    echo "- Cargo executor: \`$(cargo_cmd_prefix)\`"
    echo "- Cargo target dir: \`${cargo_target_dir}\`"
    echo "- Benchmark runners: \`hyperfine\` for command probes, \`criterion_once\` for \`cargo bench\` workloads"
    if [ -n "$OP_FILTER" ]; then
        echo "- Operation filter: \`${OP_FILTER}\`"
        echo "- Baseline latest update: skipped for targeted operation run"
    fi
    echo "- Warmup runs: \`${WARMUP}\`"
    echo "- Measured runs: \`${RUNS}\`"
    echo "- Thresholds file: \`${THRESHOLDS_PATH}\`"
    echo "- Warn threshold (default): \`${P99_WARN_THRESHOLD}%\`"
    echo "- Fail threshold (default): \`${P99_FAIL_THRESHOLD}%\`"
    echo ""
    echo "## Preflight Conformance Gate"
    echo ""
    if [ "$VERIFY_GOLDEN" -eq 1 ]; then
        echo "- \`scripts/verify_golden.sh\`: **PASS**"
    else
        echo "- \`scripts/verify_golden.sh\`: SKIPPED (\`--skip-verify-golden\`)"
    fi
    echo ""
    echo "## Commands"
    echo ""
    for i in "${!BENCH_LABELS[@]}"; do
        echo "- \`${BENCH_COMMANDS[$i]}\`"
    done
    if [ "${#CACHE_WORKLOAD_REPORT_PATHS[@]}" -gt 0 ]; then
        echo ""
        echo "### Cache Metrics Reports"
        echo ""
        for i in "${!CACHE_WORKLOAD_REPORT_PATHS[@]}"; do
            echo "- policy \`${CACHE_WORKLOAD_REPORT_POLICIES[$i]}\` -> \`${CACHE_WORKLOAD_REPORT_PATHS[$i]}\`"
        done
    fi
    if [ "${#SKIPPED_LABELS[@]}" -gt 0 ]; then
        echo ""
        echo "### Skipped"
        echo ""
        for skipped in "${SKIPPED_LABELS[@]}"; do
            echo "- ${skipped}"
        done
    fi
    echo ""
    echo "## Benchmark Summary"
    echo ""
    echo "| Command | Runner | Mean (ms) | Stddev (ms) | p50 (ms) | p95 (ms) | p99 (ms) | JSON |"
    echo "|---|---|---:|---:|---:|---:|---:|---|"
    for i in "${!BENCH_LABELS[@]}"; do
        json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
        mean_s="$(json_mean "$json_file")"
        std_s="$(json_stddev "$json_file")"
        p50_s="$(json_p50 "$json_file")"
        p95_s="$(json_p95 "$json_file")"
        p99_s="$(json_p99 "$json_file")"
        mean_ms="$(sec_to_ms "$mean_s")"
        std_ms="$(sec_to_ms "$std_s")"
        p50_ms="$(sec_to_ms "$p50_s")"
        p95_ms="$(sec_to_ms "$p95_s")"
        p99_ms="$(sec_to_ms "$p99_s")"
        echo "| ${BENCH_LABELS[$i]} | ${BENCH_RUNNERS[$i]} | ${mean_ms} | ${std_ms} | ${p50_ms} | ${p95_ms} | ${p99_ms} | \`${json_file}\` |"
    done
    echo ""
    echo "## Cache Workload Metrics (ArcCache::metrics)"
    echo ""
    if [ "$(jq 'length' <<<"$CACHE_WORKLOAD_METRICS_JSON")" -eq 0 ]; then
        echo "No cache workload metrics were captured."
    else
        echo "| Policy | Workload | Accesses | Hit Rate | Memory Overhead / Cached Block | Hits | Misses | Resident | Capacity | Ghost (B1+B2) | Source |"
        echo "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|"
        while IFS=$'\t' read -r policy workload accesses hit_rate overhead hits misses resident capacity ghost source_tsv; do
            echo "| ${policy} | ${workload} | ${accesses} | ${hit_rate} | ${overhead} | ${hits} | ${misses} | ${resident} | ${capacity} | ${ghost} | \`${source_tsv}\` |"
        done < <(
            jq -r '
                .[]
                | [
                    .policy,
                    .workload,
                    .accesses,
                    .hit_rate,
                    .memory_overhead_per_cached_block,
                    .hits,
                    .misses,
                    .resident,
                    .capacity,
                    (.b1_len + .b2_len),
                    .source_tsv
                ]
                | @tsv
            ' <<<"$CACHE_WORKLOAD_METRICS_JSON"
        )
    fi
} > "$REPORT_PATH"

write_perf_baseline_json

COMPARE_STATUS=0
COMPARE_SUMMARY=""
if [ "$COMPARE" -eq 1 ]; then
    compared_count=0
    fallback_baseline_json=""
    for candidate_baseline_json in "benchmarks/baselines/perf_baseline.json" "$BENCHMARK_BASELINE_LATEST_PATH"; do
        if [ -s "$candidate_baseline_json" ]; then
            fallback_baseline_json="$candidate_baseline_json"
            break
        fi
    done

    COMPARE_SUMMARY+="## Regression Check"$'\n\n'
    COMPARE_SUMMARY+="Threshold defaults: warn if p99 regresses >${P99_WARN_THRESHOLD}%; fail if >${P99_FAIL_THRESHOLD}%."$'\n\n'
    COMPARE_SUMMARY+="| Command | Source | Baseline p99 (ms) | Current p99 (ms) | Delta % | Warn % | Fail % | Status |"$'\n'
    COMPARE_SUMMARY+="|---|---|---:|---:|---:|---:|---:|---|"$'\n'

    for i in "${!BENCH_LABELS[@]}"; do
        cur_json="${OUT_DIR}/${BENCH_FILES[$i]}"
        op="${BENCH_OPERATIONS[$i]}"
        warn_threshold="${OP_WARN_THRESHOLDS[$op]:-$P99_WARN_THRESHOLD}"
        fail_threshold="${OP_FAIL_THRESHOLDS[$op]:-$P99_FAIL_THRESHOLD}"
        prev_p99_s=""
        prev_source=""

        if [ -d "baselines/hyperfine" ]; then
            while IFS= read -r candidate_tag; do
                [ -n "$candidate_tag" ] || continue
                candidate_file="baselines/hyperfine/${candidate_tag}/${BENCH_FILES[$i]}"
                if [ -f "$candidate_file" ]; then
                    prev_p99_s="$(json_p99 "$candidate_file" 2>/dev/null || true)"
                    prev_source="hyperfine/${candidate_tag}"
                    break
                fi
            done < <(find baselines/hyperfine -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -r | grep -v "^${DATE_TAG}\$" || true)
        fi

        if { [ -z "$prev_p99_s" ] || ! valid_number "$prev_p99_s"; } && [ -n "$fallback_baseline_json" ]; then
            prev_p99_s="$(
                jq -r --arg op "$op" '
                    ([.measurements[]? | select(.operation == $op and .status == "measured" and (.p99_us // 0) > 0) | (.p99_us / 1000000.0)] | first) // empty
                ' "$fallback_baseline_json" 2>/dev/null || true
            )"
            if [ -n "$prev_p99_s" ]; then
                prev_source="$fallback_baseline_json"
            fi
        fi

        cur_p99_s="$(json_p99 "$cur_json" 2>/dev/null || true)"
        if [ -z "$cur_p99_s" ] || [ -z "$prev_p99_s" ] || ! valid_number "$cur_p99_s" || ! valid_number "$prev_p99_s"; then
            COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | n/a | ${warn_threshold} | ${fail_threshold} | FAIL (missing or invalid baseline) |"$'\n'
            COMPARE_STATUS=1
            continue
        fi
        if awk -v base="$prev_p99_s" 'BEGIN { exit !(base <= 0.0) }'; then
            COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | ${prev_source} | n/a | n/a | n/a | ${warn_threshold} | ${fail_threshold} | FAIL (baseline p99 <= 0) |"$'\n'
            COMPARE_STATUS=1
            continue
        fi

        compared_count=$((compared_count + 1))
        cur_p99_ms="$(sec_to_ms "$cur_p99_s")"
        prev_p99_ms="$(sec_to_ms "$prev_p99_s")"
        delta_pct="$(pct_change "$prev_p99_s" "$cur_p99_s")"

        status="OK"
        if awk -v d="$delta_pct" -v threshold="$fail_threshold" 'BEGIN { exit !(d > threshold) }'; then
            status="FAIL"
            COMPARE_STATUS=1
        elif awk -v d="$delta_pct" -v threshold="$warn_threshold" 'BEGIN { exit !(d > threshold) }'; then
            status="WARN"
        fi
        COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | \`${prev_source}\` | ${prev_p99_ms} | ${cur_p99_ms} | ${delta_pct}% | ${warn_threshold} | ${fail_threshold} | ${status} |"$'\n'
    done

    if [ "$compared_count" -eq 0 ]; then
        COMPARE_SUMMARY+=$'\n'"ERROR: zero operations were compared against a committed baseline."$'\n'
        COMPARE_STATUS=1
    fi

    {
        echo ""
        echo "${COMPARE_SUMMARY}"
    } >> "$REPORT_PATH"
fi

echo "Wrote baseline report: ${REPORT_PATH}"
echo "Wrote structured baseline JSON: ${PERF_BASELINE_PATH}"
echo "Wrote dated structured baseline JSON: ${PERF_BASELINE_DATED_PATH}"
if [ "$WROTE_BENCHMARK_BASELINE_LATEST" -eq 1 ]; then
    echo "Wrote baseline latest JSON: ${BENCHMARK_BASELINE_LATEST_PATH}"
else
    echo "Skipped baseline latest JSON for targeted --op run: ${BENCHMARK_BASELINE_LATEST_PATH}"
fi
echo "Wrote baseline history JSON: ${BENCHMARK_BASELINE_HISTORY_PATH}"
echo "Wrote benchmark exports:"
for i in "${!BENCH_LABELS[@]}"; do
    echo "  - ${OUT_DIR}/${BENCH_FILES[$i]}"
done
if [ "${#CACHE_WORKLOAD_REPORT_PATHS[@]}" -gt 0 ]; then
    echo "Wrote cache workload metric reports:"
    for report_path in "${CACHE_WORKLOAD_REPORT_PATHS[@]}"; do
        echo "  - ${report_path}"
    done
fi
if [ "${#SKIPPED_LABELS[@]}" -gt 0 ]; then
    echo "Skipped commands:"
    for skipped in "${SKIPPED_LABELS[@]}"; do
        echo "  - ${skipped}"
    done
fi

if [ "$COMPARE" -eq 1 ]; then
    echo ""
    echo "Regression check summary:"
    echo "${COMPARE_SUMMARY}"
fi

exit "$COMPARE_STATUS"
