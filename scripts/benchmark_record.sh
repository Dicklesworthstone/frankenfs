#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

WARMUP=3
RUNS=10
COMPARE=0
VERIFY_GOLDEN=1
DATE_TAG="$(date -u +%Y%m%d)"
REF_IMAGE="conformance/golden/ext4_8mb_reference.ext4"

usage() {
    cat <<'USAGE'
Usage:
  scripts/benchmark_record.sh [--date YYYYMMDD] [--warmup N] [--runs N] [--compare] [--skip-verify-golden]

Options:
  --date YYYYMMDD          Override date-tag for output paths (default: today)
  --warmup N               Hyperfine warmup runs (default: 3)
  --runs N                 Hyperfine measured runs (default: 10)
  --compare                Compare current p95 against latest prior baseline (warn >10%, fail >25%)
  --skip-verify-golden     Skip scripts/verify_golden.sh preflight
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
        --compare)
            COMPARE=1
            shift
            ;;
        --skip-verify-golden)
            VERIFY_GOLDEN=0
            shift
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

OUT_DIR="baselines/hyperfine/${DATE_TAG}"
REPORT_PATH="baselines/baseline-${DATE_TAG}.md"

mkdir -p "$OUT_DIR"

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

echo "Building release binaries once..."
cargo build -p ffs-cli --release --quiet
cargo build -p ffs-harness --release --quiet
echo ""

CLI_BIN="${TARGET_DIR}/release/ffs-cli"
HARNESS_BIN="${TARGET_DIR}/release/ffs-harness"

[ -x "$CLI_BIN" ] || { echo "missing executable: ${CLI_BIN}" >&2; exit 1; }
[ -x "$HARNESS_BIN" ] || { echo "missing executable: ${HARNESS_BIN}" >&2; exit 1; }

declare -a BENCH_LABELS=()
declare -a BENCH_COMMANDS=()
declare -a BENCH_FILES=()
declare -a SKIPPED_LABELS=()

add_bench() {
    BENCH_LABELS+=("$1")
    BENCH_COMMANDS+=("$2")
    BENCH_FILES+=("$3")
}

add_bench "ffs-cli parity --json" \
    "${CLI_BIN} parity --json" \
    "ffs_cli_parity.json"

add_bench "ffs-harness parity" \
    "${HARNESS_BIN} parity" \
    "ffs_harness_parity.json"

add_bench "ffs-harness check-fixtures" \
    "${HARNESS_BIN} check-fixtures" \
    "ffs_harness_check_fixtures.json"

if [ -f "$REF_IMAGE" ]; then
    probe_stderr="${OUT_DIR}/ffs_cli_inspect_probe.stderr"
    if "$CLI_BIN" inspect "$REF_IMAGE" --json >/dev/null 2>"$probe_stderr"; then
        add_bench "ffs-cli inspect ext4_8mb_reference.ext4 --json" \
            "${CLI_BIN} inspect ${REF_IMAGE} --json" \
            "ffs_cli_inspect_ext4_8mb_reference.json"
        add_bench "ffs-cli scrub ext4_8mb_reference.ext4 --json" \
            "${CLI_BIN} scrub ${REF_IMAGE} --json" \
            "ffs_cli_scrub_ext4_8mb_reference.json"
    else
        probe_reason="$(tr '\n' ' ' < "$probe_stderr" | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
        SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (unsupported by current parser: ${probe_reason})")
        SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (skipped because inspect probe failed)")
    fi
else
    SKIPPED_LABELS+=("ffs-cli inspect ext4_8mb_reference.ext4 --json (missing ${REF_IMAGE})")
    SKIPPED_LABELS+=("ffs-cli scrub ext4_8mb_reference.ext4 --json (missing ${REF_IMAGE})")
fi

json_mean() {
    jq -r '.results[0].mean' "$1"
}

json_stddev() {
    jq -r '.results[0].stddev' "$1"
}

json_p95() {
    jq -r '
        .results[0].times as $times
        | ($times | length) as $n
        | if $n == 0 then
              0
          else
              ($times | sort) as $sorted
              | ((($n - 1) * 0.95) | floor) as $idx
              | $sorted[$idx]
          end
    ' "$1"
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

pct_change() {
    awk -v base="$1" -v cur="$2" 'BEGIN {
        if (base == 0) {
            printf "0.00";
        } else {
            printf "%.2f", ((cur - base) / base) * 100.0;
        }
    }'
}

echo "Running hyperfine benchmarks..."
for i in "${!BENCH_LABELS[@]}"; do
    label="${BENCH_LABELS[$i]}"
    cmd="${BENCH_COMMANDS[$i]}"
    json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
    txt_file="${json_file%.json}.txt"

    echo ""
    echo "--- ${label} ---"
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --export-json "$json_file" \
        "$cmd" | tee "$txt_file"
done
echo ""

cpu_model="$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
if [ -z "${cpu_model}" ]; then
    cpu_model="unknown"
fi

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
    echo "- Host kernel: \`${kernel_ver}\`"
    echo "- CPU: \`${cpu_model}\`"
    echo "- rustc: \`${rustc_ver}\`"
    echo "- cargo: \`${cargo_ver}\`"
    echo "- hyperfine: \`${hyperfine_ver}\`"
    echo "- Warmup runs: \`${WARMUP}\`"
    echo "- Measured runs: \`${RUNS}\`"
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
    if [ "${#SKIPPED_LABELS[@]}" -gt 0 ]; then
        echo ""
        echo "### Skipped"
        echo ""
        for skipped in "${SKIPPED_LABELS[@]}"; do
            echo "- ${skipped}"
        done
    fi
    echo ""
    echo "## Hyperfine Summary"
    echo ""
    echo "| Command | Mean (ms) | Stddev (ms) | p95 (ms) | JSON |"
    echo "|---|---:|---:|---:|---|"
    for i in "${!BENCH_LABELS[@]}"; do
        json_file="${OUT_DIR}/${BENCH_FILES[$i]}"
        mean_s="$(json_mean "$json_file")"
        std_s="$(json_stddev "$json_file")"
        p95_s="$(json_p95 "$json_file")"
        mean_ms="$(sec_to_ms "$mean_s")"
        std_ms="$(sec_to_ms "$std_s")"
        p95_ms="$(sec_to_ms "$p95_s")"
        echo "| ${BENCH_LABELS[$i]} | ${mean_ms} | ${std_ms} | ${p95_ms} | \`${json_file}\` |"
    done
} > "$REPORT_PATH"

COMPARE_STATUS=0
COMPARE_SUMMARY=""
if [ "$COMPARE" -eq 1 ]; then
    if [ -d "baselines/hyperfine" ]; then
        previous_tag="$(find baselines/hyperfine -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | grep -v "^${DATE_TAG}\$" | tail -n1 || true)"
    else
        previous_tag=""
    fi

    if [ -n "$previous_tag" ]; then
        previous_dir="baselines/hyperfine/${previous_tag}"
        COMPARE_SUMMARY+="## Regression Check (vs ${previous_tag})"$'\n\n'
        COMPARE_SUMMARY+="Thresholds: warn if p95 regresses >10%; fail if >25%."$'\n\n'
        COMPARE_SUMMARY+="| Command | Baseline p95 (ms) | Current p95 (ms) | Delta % | Status |"$'\n'
        COMPARE_SUMMARY+="|---|---:|---:|---:|---|"$'\n'

        for i in "${!BENCH_LABELS[@]}"; do
            cur_json="${OUT_DIR}/${BENCH_FILES[$i]}"
            prev_json="${previous_dir}/${BENCH_FILES[$i]}"
            if [ ! -f "$prev_json" ]; then
                COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | SKIP (no prior file) |"$'\n'
                continue
            fi

            cur_p95_s="$(json_p95 "$cur_json" 2>/dev/null || true)"
            prev_p95_s="$(json_p95 "$prev_json" 2>/dev/null || true)"
            if [ -z "$cur_p95_s" ] || [ -z "$prev_p95_s" ] || ! valid_number "$cur_p95_s" || ! valid_number "$prev_p95_s"; then
                COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | SKIP (invalid hyperfine JSON) |"$'\n'
                continue
            fi
            if awk -v base="$prev_p95_s" 'BEGIN { exit !(base <= 0.0) }'; then
                COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | n/a | n/a | n/a | SKIP (baseline p95 <= 0) |"$'\n'
                continue
            fi

            cur_p95_ms="$(sec_to_ms "$cur_p95_s")"
            prev_p95_ms="$(sec_to_ms "$prev_p95_s")"
            delta_pct="$(pct_change "$prev_p95_s" "$cur_p95_s")"

            status="OK"
            if awk -v d="$delta_pct" 'BEGIN { exit !(d > 25.0) }'; then
                status="FAIL"
                COMPARE_STATUS=1
            elif awk -v d="$delta_pct" 'BEGIN { exit !(d > 10.0) }'; then
                status="WARN"
            fi
            COMPARE_SUMMARY+="| ${BENCH_LABELS[$i]} | ${prev_p95_ms} | ${cur_p95_ms} | ${delta_pct}% | ${status} |"$'\n'
        done
    else
        COMPARE_SUMMARY+="## Regression Check"$'\n\n'
        COMPARE_SUMMARY+="No prior baseline directory found under \`baselines/hyperfine/\`; compare skipped."$'\n'
    fi

    {
        echo ""
        echo "${COMPARE_SUMMARY}"
    } >> "$REPORT_PATH"
fi

echo "Wrote baseline report: ${REPORT_PATH}"
echo "Wrote hyperfine exports:"
for i in "${!BENCH_LABELS[@]}"; do
    echo "  - ${OUT_DIR}/${BENCH_FILES[$i]}"
done
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
