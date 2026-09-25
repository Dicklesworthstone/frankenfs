#!/usr/bin/env bash
# lib.sh - Shared helpers for E2E tests
#
# Source this file in E2E scripts:
#   source "$(dirname "$0")/lib.sh"

# Strict mode
set -euo pipefail
# Note: We intentionally don't set IFS to avoid command parsing issues

# Colors (if terminal supports them)
if [[ -t 1 ]] && command -v tput &>/dev/null; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    RESET=$(tput sgr0)
else
    RED="" GREEN="" YELLOW="" BLUE="" RESET=""
fi

# Global state
E2E_START_TIME=""
E2E_LOG_DIR=""
E2E_LOG_FILE=""
E2E_TEMP_DIR=""
E2E_MOUNT_POINT=""
E2E_CLEANUP_ITEMS=()

#######################################
# Initialize E2E test environment
# Creates log directory and temp directory
# Arguments:
#   $1 - Test name (used for directory naming)
#######################################
e2e_init() {
    local test_name="${1:-e2e}"
    local artifact_root log_template timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)

    E2E_START_TIME=$(date +%s)
    E2E_TEST_NAME="$test_name"

    # Create a collision-resistant log directory. Concurrent agents can start
    # the same E2E script in the same second.
    artifact_root="${REPO_ROOT:-$(pwd)}/artifacts/e2e"
    mkdir -p "$artifact_root"
    log_template="${artifact_root}/${timestamp}_${test_name}_XXXXXX"
    E2E_LOG_DIR=$(mktemp -d "$log_template")
    E2E_LOG_FILE="$E2E_LOG_DIR/run.log"

    # Create temp directory
    E2E_TEMP_DIR=$(mktemp -d -t "ffs_e2e_XXXXXX")
    E2E_CLEANUP_ITEMS+=("$E2E_TEMP_DIR")

    # Set up cleanup trap (emits JSON summary before cleanup).
    # Set FFS_E2E_DISABLE_TEMP_CLEANUP=1 to preserve temp artifacts for
    # operator inspection or no-delete agent sessions.
    trap e2e_cleanup EXIT

    # Start logging
    e2e_log "=============================================="
    e2e_log "E2E Test: $test_name"
    e2e_log "=============================================="
    e2e_log "Started: $(date -Iseconds)"
    e2e_log "Log directory: $E2E_LOG_DIR"
    e2e_log "Temp directory: $E2E_TEMP_DIR"
    e2e_log ""
}

#######################################
# Log message to both stdout and log file
# Arguments:
#   $* - Message to log
#######################################
e2e_log() {
    local msg="$*"
    echo "$msg"
    [[ -n "${E2E_LOG_FILE:-}" ]] && echo "$msg" >> "$E2E_LOG_FILE"
}

#######################################
# Log a step with timestamp
# Arguments:
#   $1 - Step description
#######################################
e2e_step() {
    local step="$1"
    e2e_log ""
    e2e_log "=== $step ==="
    e2e_log "Time: $(date -Iseconds)"
}

#######################################
# Check that a scenario-catalog evidence marker is backed by a script.
# Literal evidence markers are preferred. For SCENARIO_RESULT rows, also
# accept the project-standard helper calls that build the marker at runtime.
# Arguments:
#   $1 - Evidence marker from scenario_catalog.json
#   $2 - Script path to inspect
#######################################
e2e_catalog_evidence_present() {
    local evidence="$1"
    local script_path="$2"

    if grep -Fq "$evidence" "$script_path"; then
        return 0
    fi

    local scenario_id outcome
    if [[ "$evidence" =~ ^SCENARIO_RESULT\|scenario_id=([^|]+)\|outcome=([^|]+) ]]; then
        scenario_id="${BASH_REMATCH[1]}"
        outcome="${BASH_REMATCH[2]}"
        local helper
        for helper in scenario_result log_scenario; do
            if grep -Fq "${helper} \"${scenario_id}\" \"${outcome}\"" "$script_path"; then
                return 0
            fi
            if grep -Fq "${helper} '${scenario_id}' '${outcome}'" "$script_path"; then
                return 0
            fi
            if grep -Fq "\"${scenario_id}\"" "$script_path" \
                && grep -Fq "${helper} \"\$scenario_id\" \"${outcome}\"" "$script_path"; then
                return 0
            fi
        done
        if grep -Fq "\"${scenario_id}\"" "$script_path" \
            && grep -Fq 'SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}' "$script_path"; then
            return 0
        fi
    fi

    return 1
}

#######################################
# Generate a representative scenario ID from a catalog id_pattern.
# Arguments:
#   $1 - Anchored Bash ERE pattern from scenario_catalog.json
#######################################
e2e_catalog_id_pattern_sample() {
    local pattern="$1"
    local body sample index length char end_index class atom repeat quant_end repeat_index

    [[ "$pattern" == \^* && "$pattern" == *\$ ]] || return 1

    body="${pattern#^}"
    body="${body%\$}"
    sample=""
    index=0
    length=${#body}

    while ((index < length)); do
        char="${body:index:1}"
        if [[ "$char" =~ [A-Za-z0-9_] ]]; then
            sample+="$char"
            index=$((index + 1))
            continue
        fi

        if [[ "$char" != "[" ]]; then
            return 1
        fi

        end_index=$((index + 1))
        while ((end_index < length)) && [[ "${body:end_index:1}" != "]" ]]; do
            end_index=$((end_index + 1))
        done
        ((end_index < length)) || return 1

        class="${body:index + 1:end_index - index - 1}"
        case "$class" in
            a-z0-9 | a-z0-9_)
                atom="sample"
                ;;
            0-9)
                atom="0"
                ;;
            A-Z)
                atom="A"
                ;;
            *)
                return 1
                ;;
        esac

        index=$((end_index + 1))
        repeat=1
        if ((index < length)) && [[ "${body:index:1}" == "+" ]]; then
            index=$((index + 1))
        elif ((index < length)) && [[ "${body:index:1}" == "{" ]]; then
            quant_end=$((index + 1))
            while ((quant_end < length)) && [[ "${body:quant_end:1}" != "}" ]]; do
                quant_end=$((quant_end + 1))
            done
            ((quant_end < length)) || return 1
            repeat="${body:index + 1:quant_end - index - 1}"
            [[ "$repeat" =~ ^[0-9]+$ ]] || return 1
            index=$((quant_end + 1))
        fi

        for ((repeat_index = 0; repeat_index < repeat; repeat_index++)); do
            sample+="$atom"
        done
    done

    [[ -n "$sample" ]] || return 1
    printf '%s\n' "$sample"
}

#######################################
# Validate E2E scenario catalog contract
# Arguments:
#   $1 - Catalog path (default: $REPO_ROOT/scripts/e2e/scenario_catalog.json)
#######################################
e2e_validate_scenario_catalog() {
    local repo_root catalog_path
    repo_root="${REPO_ROOT:-$(pwd)}"
    catalog_path="${1:-$repo_root/scripts/e2e/scenario_catalog.json}"

    e2e_step "Scenario Catalog Validation"

    if [[ ! -f "$catalog_path" ]]; then
        e2e_fail "Scenario catalog missing: $catalog_path"
    fi
    if ! command -v jq >/dev/null 2>&1; then
        e2e_fail "jq is required for scenario catalog validation"
    fi

    local id_regex
    id_regex="$(jq -r '.scenario_id_regex // empty' "$catalog_path")"
    if [[ -z "$id_regex" ]]; then
        e2e_fail "scenario_id_regex missing from $catalog_path"
    fi

    local duplicate_taxonomy
    duplicate_taxonomy="$(jq -r '.taxonomy[]' "$catalog_path" | sort | uniq -d || true)"
    if [[ -n "$duplicate_taxonomy" ]]; then
        e2e_fail "Duplicate taxonomy categories in scenario catalog: $duplicate_taxonomy"
    fi

    local missing_suite_identity
    missing_suite_identity="$(
        jq -r '
            .suites
            | to_entries[]
            | select(((.value.suite_id // "") == "") or ((.value.script // "") == ""))
            | "index=\(.key) suite_id=\(.value.suite_id // "<missing>") script=\(.value.script // "<missing>")"
        ' "$catalog_path"
    )"
    if [[ -n "$missing_suite_identity" ]]; then
        e2e_fail "Scenario catalog suite missing suite_id or script: $missing_suite_identity"
    fi

    local duplicate_suite_ids
    duplicate_suite_ids="$(jq -r '.suites[].suite_id' "$catalog_path" | sort | uniq -d || true)"
    if [[ -n "$duplicate_suite_ids" ]]; then
        e2e_fail "Duplicate suite IDs in scenario catalog: $duplicate_suite_ids"
    fi

    local duplicate_suite_scripts
    duplicate_suite_scripts="$(jq -r '.suites[].script' "$catalog_path" | sort | uniq -d || true)"
    if [[ -n "$duplicate_suite_scripts" ]]; then
        e2e_fail "Duplicate suite scripts in scenario catalog: $duplicate_suite_scripts"
    fi

    local duplicate_ids
    duplicate_ids="$(
        jq -r '
            .suites[].scenarios[]
            | select((.status // "active") == "active" and has("id"))
            | .id
        ' "$catalog_path" | sort | uniq -d || true
    )"
    if [[ -n "$duplicate_ids" ]]; then
        e2e_fail "Duplicate active scenario IDs in scenario catalog: $duplicate_ids"
    fi

    local ambiguous_active_ids
    ambiguous_active_ids="$(
        jq -r '
            .suites[] as $suite
            | ($suite.scenarios // [])
            | to_entries[]
            | select((.value.status // "active") == "active" and (.value | has("id")) and (.value | has("id_pattern")))
            | "suite=\($suite.suite_id // "<missing>") index=\(.key) id=\(.value.id) id_pattern=\(.value.id_pattern)"
        ' "$catalog_path"
    )"
    if [[ -n "$ambiguous_active_ids" ]]; then
        e2e_fail "Scenario catalog active scenario defines both id and id_pattern: $ambiguous_active_ids"
    fi

    local unknown_statuses
    unknown_statuses="$(
        jq -r '
            .suites[] as $suite
            | ($suite.scenarios // [])
            | to_entries[]
            | (.value.status // "active") as $status
            | select($status != "active" and $status != "inactive")
            | "suite=\($suite.suite_id // "<missing>") index=\(.key) status=\($status)"
        ' "$catalog_path"
    )"
    if [[ -n "$unknown_statuses" ]]; then
        e2e_fail "Scenario catalog uses unknown scenario status (expected active or inactive): $unknown_statuses"
    fi

    local pattern_suite literal_pattern literal_id regex_status pattern_sample
    while IFS=$'\t' read -r pattern_suite literal_pattern; do
        [[ -n "$literal_pattern" ]] || continue
        if [[ "$literal_pattern" != \^* || "$literal_pattern" != *\$ ]]; then
            e2e_fail "Suite '$pattern_suite' id_pattern must be anchored with ^ and $: $literal_pattern"
        fi
        if [[ "__ffs_catalog_regex_probe__" =~ $literal_pattern ]] 2>/dev/null; then
            :
        else
            regex_status=$?
            if [[ "$regex_status" -eq 2 ]]; then
                e2e_fail "Suite '$pattern_suite' id_pattern is not valid Bash ERE: $literal_pattern"
            fi
        fi
        if [[ "$literal_pattern" =~ ^\^([A-Za-z0-9_]+)\$$ ]]; then
            literal_id="${BASH_REMATCH[1]}"
            if [[ ! "$literal_id" =~ $id_regex ]]; then
                e2e_fail "Suite '$pattern_suite' literal id_pattern does not match scenario_id_regex: $literal_pattern"
            fi
        fi
        if ! pattern_sample="$(e2e_catalog_id_pattern_sample "$literal_pattern")"; then
            e2e_fail "Suite '$pattern_suite' id_pattern is not sample-compatible with scenario_id_regex: $literal_pattern"
        fi
        if [[ ! "$pattern_sample" =~ $literal_pattern ]]; then
            e2e_fail "Suite '$pattern_suite' generated id_pattern sample does not match pattern: pattern=$literal_pattern sample=$pattern_sample"
        fi
        if [[ ! "$pattern_sample" =~ $id_regex ]]; then
            e2e_fail "Suite '$pattern_suite' generated id_pattern sample does not match scenario_id_regex: pattern=$literal_pattern sample=$pattern_sample"
        fi
    done < <(
        jq -r '
            .suites[] as $suite
            | ($suite.scenarios // [])[]
            | select((.status // "active") == "active" and has("id_pattern"))
            | [$suite.suite_id, .id_pattern]
            | @tsv
        ' "$catalog_path"
    )

    local -A catalog_scripts=()
    while IFS= read -r script_rel; do
        [[ -n "$script_rel" ]] || continue
        catalog_scripts["$script_rel"]=1
    done < <(jq -r '.suites[].script' "$catalog_path")

    local missing_scripts=()
    local script_path script_rel
    local -A expected_script_seen=()
    local catalog_script_globs=(
        "$repo_root"/scripts/e2e/*_e2e.sh
        "$repo_root"/scripts/e2e/ffs_*.sh
        "$repo_root"/scripts/e2e/validate_br_dotted_id_roundtrip.sh
    )
    for script_path in "${catalog_script_globs[@]}"; do
        [[ -f "$script_path" ]] || continue
        script_rel="${script_path#$repo_root/}"
        if [[ -n "${expected_script_seen[$script_rel]:-}" ]]; then
            continue
        fi
        expected_script_seen["$script_rel"]=1
        if [[ -z "${catalog_scripts[$script_rel]:-}" ]]; then
            missing_scripts+=("$script_rel")
        fi
    done
    if ((${#missing_scripts[@]} > 0)); then
        e2e_fail "Scenario catalog missing E2E scripts: ${missing_scripts[*]}"
    fi

    while IFS=$'\t' read -r suite_id script_rel; do
        [[ -n "$suite_id" ]] || continue
        script_path="$repo_root/$script_rel"
        if [[ ! -f "$script_path" ]]; then
            e2e_fail "Scenario catalog suite '$suite_id' references missing script: $script_rel"
        fi

        local -A seen_categories=()
        local -A active_scenario_ids=()
        local -a active_scenario_patterns=()
        local active_count=0

        while IFS= read -r scenario_b64; do
            [[ -n "$scenario_b64" ]] || continue
            local scenario_json
            scenario_json="$(printf '%s' "$scenario_b64" | base64 --decode)"

            local status category evidence scenario_id scenario_pattern
            status="$(jq -r '.status // "active"' <<<"$scenario_json")"
            category="$(jq -r '.category // empty' <<<"$scenario_json")"
            evidence="$(jq -r '.evidence // empty' <<<"$scenario_json")"
            scenario_id="$(jq -r '.id // empty' <<<"$scenario_json")"
            scenario_pattern="$(jq -r '.id_pattern // empty' <<<"$scenario_json")"

            if [[ -z "$category" ]]; then
                e2e_fail "Suite '$suite_id' has scenario without category"
            fi
            if ! jq -e --arg category "$category" '.taxonomy | index($category)' "$catalog_path" >/dev/null; then
                e2e_fail "Suite '$suite_id' uses unknown category '$category'"
            fi

            if [[ "$status" != "active" ]]; then
                continue
            fi

            active_count=$((active_count + 1))
            seen_categories["$category"]=1

            if [[ -z "$scenario_id" && -z "$scenario_pattern" ]]; then
                e2e_fail "Suite '$suite_id' active scenario must define id or id_pattern"
            fi
            if [[ -n "$scenario_id" && ! "$scenario_id" =~ $id_regex ]]; then
                e2e_fail "Suite '$suite_id' scenario ID does not match regex: $scenario_id"
            fi
            if [[ -z "$evidence" ]]; then
                e2e_fail "Suite '$suite_id' active scenario is missing evidence marker"
            fi
            if ! e2e_catalog_evidence_present "$evidence" "$script_path"; then
                e2e_fail "Suite '$suite_id' evidence marker not found in $script_rel: $evidence"
            fi
            if [[ -n "$scenario_id" ]]; then
                active_scenario_ids["$scenario_id"]=1
            fi
            if [[ "$evidence" =~ ^SCENARIO_RESULT\|scenario_id=([^|]+)\|outcome= ]]; then
                active_scenario_ids["${BASH_REMATCH[1]}"]=1
            fi
            if [[ -n "$scenario_pattern" ]]; then
                active_scenario_patterns+=("$scenario_pattern")
            fi
        done < <(
            jq -r --arg suite_id "$suite_id" '
                .suites[]
                | select(.suite_id == $suite_id)
                | .scenarios[]
                | @base64
            ' "$catalog_path"
        )

        local emitted_id pattern matched
        local -a uncataloged_ids=()
        while IFS= read -r emitted_id; do
            [[ -n "$emitted_id" ]] || continue
            if [[ -n "${active_scenario_ids[$emitted_id]:-}" ]]; then
                continue
            fi

            matched=0
            for pattern in "${active_scenario_patterns[@]}"; do
                if [[ "$emitted_id" =~ $pattern ]]; then
                    matched=1
                    break
                fi
            done

            if ((matched == 0)); then
                uncataloged_ids+=("$emitted_id")
            fi
        done < <(
            grep -v '^[[:space:]]*#' "$script_path" \
                | sed -n -E \
                    -e 's/^[[:space:]]*(scenario_result|log_scenario)[[:space:]]+"([A-Za-z0-9_]+)".*/\2/p' \
                    -e "s/^[[:space:]]*(scenario_result|log_scenario)[[:space:]]+'([A-Za-z0-9_]+)'.*/\2/p" \
                    -e 's/^[[:space:]]*SCENARIO_RESULT\|scenario_id=([A-Za-z0-9_]+)\|outcome=.*/\1/p' \
                | sort -u
        )
        if ((${#uncataloged_ids[@]} > 0)); then
            e2e_fail "Suite '$suite_id' script emits uncataloged static scenario IDs: ${uncataloged_ids[*]}"
        fi

        if (( active_count == 0 )); then
            e2e_fail "Suite '$suite_id' has no active scenarios in catalog"
        fi

        while IFS= read -r required_category; do
            [[ -n "$required_category" ]] || continue
            if [[ -z "${seen_categories[$required_category]:-}" ]]; then
                e2e_fail "Suite '$suite_id' missing required active category '$required_category'"
            fi
        done < <(
            jq -r --arg suite_id "$suite_id" '
                .suites[]
                | select(.suite_id == $suite_id)
                | .required_categories[]?
            ' "$catalog_path"
        )

        e2e_log "Scenario catalog suite validated: $suite_id (active_scenarios=$active_count)"
    done < <(jq -r '.suites[] | [.suite_id, .script] | @tsv' "$catalog_path")

    local missing_gate_minimum_identity
    missing_gate_minimum_identity="$(
        jq -r '
            (.gate_minimums // [])
            | to_entries[]
            | select(((.value.gate_id // "") == "") or (((.value.required_categories // []) | length) == 0))
            | "index=\(.key) gate_id=\(.value.gate_id // "<missing>") required_category_count=\((.value.required_categories // []) | length)"
        ' "$catalog_path"
    )"
    if [[ -n "$missing_gate_minimum_identity" ]]; then
        e2e_fail "Scenario catalog gate minimum missing gate_id or required_categories: $missing_gate_minimum_identity"
    fi

    local duplicate_gate_ids
    duplicate_gate_ids="$(jq -r '.gate_minimums[]?.gate_id // empty' "$catalog_path" | sort | uniq -d || true)"
    if [[ -n "$duplicate_gate_ids" ]]; then
        e2e_fail "Duplicate gate minimum IDs in scenario catalog: $duplicate_gate_ids"
    fi

    while IFS=$'\t' read -r gate_id category; do
        [[ -n "$gate_id" && -n "$category" ]] || continue
        if ! jq -e --arg category "$category" '.taxonomy | index($category)' "$catalog_path" >/dev/null; then
            e2e_fail "Gate '$gate_id' uses unknown required category '$category'"
        fi
    done < <(
        jq -r '
            .gate_minimums[]? as $gate
            | $gate.required_categories[]?
            | [$gate.gate_id, .]
            | @tsv
        ' "$catalog_path"
    )

    e2e_log "Scenario catalog validation passed: $catalog_path"
}

#######################################
# Validate a readiness-grade operational artifact manifest.
# Uses the Rust schema validator so shell orchestration cannot drift from the
# canonical manifest contract.
# Arguments:
#   $1 - Manifest path
#######################################
e2e_validate_operational_manifest() {
    local manifest_path="$1"

    e2e_step "Operational Artifact Manifest Validation"

    if [[ ! -f "$manifest_path" ]]; then
        e2e_fail "Operational manifest missing: $manifest_path"
    fi

    local harness_cmd=()
    if [[ -n "${FFS_HARNESS_BIN:-}" && -x "${FFS_HARNESS_BIN:-}" ]]; then
        harness_cmd=("$FFS_HARNESS_BIN")
    else
        e2e_fail "FFS_HARNESS_BIN must point to an executable ffs-harness binary built through RCH"
    fi

    if ! e2e_run "${harness_cmd[@]}" validate-operational-manifest "$manifest_path"; then
        e2e_fail "Operational manifest validation failed: $manifest_path"
    fi

    e2e_log "Operational manifest validation passed: $manifest_path"
}

#######################################
# Emit a structured FUSE capability report artifact.
# Arguments:
#   $1 - Output JSON path
#   $@ - Optional ffs-harness fuse-capability-probe flags
#######################################
e2e_probe_fuse_capability() {
    if [[ $# -lt 1 ]]; then
        e2e_fail "e2e_probe_fuse_capability requires an output path"
    fi

    local report_path="$1"
    shift

    e2e_step "FUSE Capability Probe"

    local harness_cmd=()
    if [[ -n "${FFS_HARNESS_BIN:-}" && -x "${FFS_HARNESS_BIN:-}" ]]; then
        harness_cmd=("$FFS_HARNESS_BIN")
    else
        e2e_fail "FFS_HARNESS_BIN must point to an executable ffs-harness binary built through RCH"
    fi

    if ! e2e_run "${harness_cmd[@]}" fuse-capability-probe --out "$report_path" "$@"; then
        e2e_fail "FUSE capability probe failed to emit report: $report_path"
    fi

    e2e_log "FUSE capability report: $report_path"
}

#######################################
# Read a top-level string field from a structured FUSE capability report.
# This intentionally avoids jq/python so skip-path classification works on
# minimal workers where the probe artifact is the primary diagnostic.
# Arguments:
#   $1 - Report JSON path
#   $2 - Top-level field name
#######################################
e2e_fuse_capability_field() {
    local report_path="$1"
    local field="$2"

    if [[ ! -f "$report_path" ]]; then
        return 1
    fi

    sed -nE \
        "s/^[[:space:]]*\"${field}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\\1/p" \
        "$report_path" | head -n 1
}

#######################################
# Return success when a FUSE capability report proves the lane is available.
# Arguments:
#   $1 - Report JSON path
#######################################
e2e_fuse_capability_available() {
    local report_path="$1"
    [[ "$(e2e_fuse_capability_field "$report_path" result)" == "available" ]]
}

#######################################
# Remove or preserve a temporary file according to the E2E cleanup policy.
# Arguments:
#   $1 - Temp file path
#######################################
e2e_cleanup_tmp_file() {
    local path="$1"

    [[ -z "$path" ]] && return 0

    if [[ "${FFS_E2E_DISABLE_TEMP_CLEANUP:-0}" == "1" ]]; then
        if [[ -e "$path" ]]; then
            e2e_log "Temp cleanup disabled; preserving temp file: $path"
        fi
    else
        rm -f "$path"
    fi
}

#######################################
# Remove or preserve a temporary directory according to the E2E cleanup policy.
# Arguments:
#   $1 - Temp directory path
#######################################
e2e_cleanup_tmp_dir() {
    local path="$1"

    [[ -z "$path" ]] && return 0

    if [[ "${FFS_E2E_DISABLE_TEMP_CLEANUP:-0}" == "1" ]]; then
        if [[ -d "$path" ]]; then
            e2e_log "Temp cleanup disabled; preserving temp directory: $path"
        fi
    else
        rm -rf "$path" 2>/dev/null || true
    fi
}

#######################################
# Add variables to the RCH remote environment allowlist.
# Arguments:
#   $@ - Environment variable names
#######################################
e2e_rch_add_env_allowlist() {
    local rch_env_var

    for rch_env_var in "$@"; do
        case ",${RCH_ENV_ALLOWLIST:-}," in
            *",${rch_env_var},"*) ;;
            *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}${rch_env_var}" ;;
        esac
    done
}

#######################################
# Return result.json-compatible git cleanliness for a repository.
# Uses porcelain status so staged index changes and untracked files are not
# mistaken for clean artifacts.
# Arguments:
#   $1 - Repository root (default: $REPO_ROOT or current directory)
#######################################
e2e_git_context_clean() {
    local repo_root="${1:-${REPO_ROOT:-.}}"
    local git_status

    if ! git_status=$(git -C "$repo_root" status --porcelain --untracked-files=normal 2>/dev/null); then
        printf 'false\n'
        return 0
    fi

    if [[ -z "$git_status" ]]; then
        printf 'true\n'
    else
        printf 'false\n'
    fi
}

#######################################
# Cancel stale RCH queue entries matching a command.
# Arguments:
#   $@ - Command previously passed to rch exec
#######################################
e2e_rch_cancel_matching_queue_entry() {
    local command_text="$*"
    local rch_bin="${RCH_BIN:-rch}"
    local queue_json
    local ids

    if ! command -v jq >/dev/null 2>&1; then
        return 0
    fi
    if ! command -v "$rch_bin" >/dev/null 2>&1; then
        return 0
    fi

    queue_json="$("$rch_bin" queue --json 2>/dev/null || true)"
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
        if "$rch_bin" cancel "$id" >/dev/null 2>&1; then
            e2e_log "RCH_STALE_QUEUE_CANCELLED|id=${id}|command=${command_text}"
        fi
    done
}

#######################################
# Find the latest preserved RCH capacity preflight report.
# The helper is intentionally read-only: it does not run rch and does not
# create capacity artifacts. Callers should run ffs_rch_capacity_preflight_e2e.sh
# explicitly when they need a fresh report.
#######################################
e2e_rch_capacity_preflight_latest_report() {
    local explicit_report="${FFS_RCH_CAPACITY_PREFLIGHT_REPORT:-}"
    local artifacts_root="${REPO_ROOT:-.}/artifacts/e2e"

    if [[ -n "$explicit_report" && -f "$explicit_report" ]]; then
        printf '%s\n' "$explicit_report"
        return 0
    fi

    if [[ ! -d "$artifacts_root" ]]; then
        return 0
    fi

    find "$artifacts_root" -maxdepth 2 -type f -name rch_capacity_preflight_report.json \
        -printf '%T@ %p\n' 2>/dev/null \
        | sort -nr \
        | awk 'NR == 1 {print $2}'
}

#######################################
# Emit a closeout-friendly pointer to the latest capacity preflight artifact.
# Arguments:
#   $1 - reason token, e.g. local_fallback or missing_remote_evidence
#   $2 - RCH command log path to append the marker to
#######################################
e2e_rch_capacity_preflight_reference() {
    local reason="$1"
    local log_path="$2"
    local report_path result_path capacity_verdict probe_verdict admissible_workers
    local marker

    report_path="$(e2e_rch_capacity_preflight_latest_report || true)"
    if [[ -n "$report_path" && -f "$report_path" ]]; then
        result_path="$(dirname "$report_path")/result.json"
        capacity_verdict="$(jq -r '.capacity_verdict // "unknown"' "$report_path" 2>/dev/null || printf 'unknown\n')"
        probe_verdict="$(jq -r '.probe.verdict // "not_recorded"' "$report_path" 2>/dev/null || printf 'unknown\n')"
        admissible_workers="$(jq -r '.worker_counts.admissible // "unknown"' "$report_path" 2>/dev/null || printf 'unknown\n')"
        if [[ ! -f "$result_path" ]]; then
            result_path="missing"
        fi
        marker="RCH_CAPACITY_PREFLIGHT_REFERENCE|reason=${reason}|report=${report_path}|result=${result_path}|capacity_verdict=${capacity_verdict}|probe_verdict=${probe_verdict}|admissible_workers=${admissible_workers}"
    else
        marker="RCH_CAPACITY_PREFLIGHT_REFERENCE_MISSING|reason=${reason}|run=FFS_E2E_DISABLE_TEMP_CLEANUP=1 ./scripts/e2e/ffs_rch_capacity_preflight_e2e.sh"
    fi

    e2e_log "$marker"
    if [[ -n "$log_path" ]]; then
        printf '%s\n' "$marker" >>"$log_path"
    fi
}

#######################################
# Run a command through RCH and fail closed on non-authoritative evidence.
# Arguments:
#   $1 - Log path
#   $@ - Command to run through rch exec
# Environment:
#   RCH_BIN, RCH_VISIBILITY, RCH_COMMAND_TIMEOUT_SECS,
#   RCH_ARTIFACT_RETRIEVAL_GRACE_SECS, RCH_REQUIRED_ARTIFACT,
#   RCH_CLIENT_RUST_LOG
# Returns:
#   Remote command exit code, 99 for rejected local/missing evidence, 124 on timeout
#######################################
e2e_rch_capture() {
    if [[ $# -lt 2 ]]; then
        e2e_log "RCH_CAPTURE_USAGE_ERROR|expected=log_path_and_command"
        return 2
    fi

    local log_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local required_artifact="${RCH_REQUIRED_ARTIFACT:-}"
    local required_artifact_deadline=0
    local wait_status
    local had_errexit=0
    local rch_bin="${RCH_BIN:-rch}"
    local timeout_secs="${RCH_COMMAND_TIMEOUT_SECS:-900}"
    local grace_secs="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
    local capacity_reference_marker="RCH_CAPACITY_PREFLIGHT_REFERENCE"
    local capacity_missing_marker="RCH_CAPACITY_PREFLIGHT_REFERENCE_MISSING"
    shift

    : "$capacity_reference_marker" "$capacity_missing_marker"

    e2e_log "RCH command: $*"
    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$log_path"
    set +e
    RUST_LOG="${RCH_CLIENT_RUST_LOG:-${RUST_LOG:-info}}" \
        RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" \
        RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        "$rch_bin" exec -- "$@" >"$log_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + timeout_secs))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$log_path" | tail -n 1)"
        if [[ -n "$remote_exit" && -n "$required_artifact" && -e "$required_artifact" ]]; then
            e2e_log "RCH_REQUIRED_ARTIFACT_READY|artifact=${required_artifact}|log=${log_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            break
        fi
        if [[ -n "$remote_exit" && -n "$required_artifact" && "$required_artifact_deadline" -eq 0 ]]; then
            required_artifact_deadline=$((SECONDS + grace_secs))
        fi
        if [[ -n "$remote_exit" && -n "$required_artifact" && "$required_artifact_deadline" -gt 0 ]] \
            && ((SECONDS >= required_artifact_deadline)); then
            e2e_log "RCH_REQUIRED_ARTIFACT_MISSING|artifact=${required_artifact}|log=${log_path}|command=$*"
            printf 'RCH_REQUIRED_ARTIFACT_MISSING|artifact=%s|log=%s\n' "$required_artifact" "$log_path" >>"$log_path"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=99
            break
        fi
        if [[ -n "$remote_exit" && -z "$required_artifact" ]]; then
            sleep "$grace_secs"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|log=${log_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${timeout_secs}|log=${log_path}|command=$*"
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
    if [[ $status -eq 0 && -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local (" "$log_path" || grep -Fq "exec called with non-compilation command" "$log_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|log=${log_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|log=%s\n' "$log_path" >>"$log_path"
        # Emits RCH_CAPACITY_PREFLIGHT_REFERENCE or RCH_CAPACITY_PREFLIGHT_REFERENCE_MISSING.
        e2e_rch_capacity_preflight_reference "local_fallback" "$log_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$log_path" && ! grep -Fq "Remote command finished: exit=0" "$log_path"; then
        e2e_log "RCH_REMOTE_EVIDENCE_MISSING|log=${log_path}|command=$*"
        printf 'RCH_REMOTE_EVIDENCE_MISSING|log=%s\n' "$log_path" >>"$log_path"
        # Emits RCH_CAPACITY_PREFLIGHT_REFERENCE or RCH_CAPACITY_PREFLIGHT_REFERENCE_MISSING.
        e2e_rch_capacity_preflight_reference "missing_remote_evidence" "$log_path"
        return 99
    fi
    return "$status"
}

#######################################
# Write a deterministic fixture rch binary for wrapper self-checks.
# This helper is only for local fixture lanes; live proof still goes through
# e2e_rch_capture and the real rch binary.
# Arguments:
#   $1 - Stub path to write
# Options:
#   --mode-env NAME                      Environment variable controlling mode
#   --default-mode MODE                  Default mode, default complete
#   --unexpected-invocation-message TEXT Prefix for bad rch argv
#   --unknown-case-message TEXT          Prefix for unknown fixture case
#   --local-fallback-stream stdout|stderr
#   --remote-evidence-stream stdout|stderr
#   --local-fallback-message TEXT
#   --remote-evidence-message TEXT
#   --complete-body-stdin                Append complete-mode body from stdin
#######################################
e2e_write_fixture_rch_stub() {
    if [[ $# -lt 1 ]]; then
        e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|expected=stub_path"
        return 2
    fi

    local stub_path="$1"
    local mode_env="E2E_RCH_FIXTURE_CASE"
    local default_mode="complete"
    local unexpected_invocation_message="unexpected fixture rch invocation"
    local unknown_case_message="unknown fixture case"
    local local_fallback_stream="stderr"
    local remote_evidence_stream="stderr"
    local local_fallback_message="[RCH] local (fixture forced local fallback)"
    local remote_evidence_message="[RCH] remote worker=fixture exit=0"
    local complete_body="exit 0"
    local read_complete_body=0
    local arg

    shift
    while [[ $# -gt 0 ]]; do
        arg="$1"
        shift
        case "$arg" in
            --mode-env)
                [[ $# -gt 0 ]] || {
                    e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|missing=mode_env"
                    return 2
                }
                mode_env="$1"
                shift
                ;;
            --default-mode)
                [[ $# -gt 0 ]] || {
                    e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|missing=default_mode"
                    return 2
                }
                default_mode="$1"
                shift
                ;;
            --unexpected-invocation-message)
                [[ $# -gt 0 ]] || {
                    e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|missing=unexpected_invocation_message"
                    return 2
                }
                unexpected_invocation_message="$1"
                shift
                ;;
            --unknown-case-message)
                [[ $# -gt 0 ]] || {
                    e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|missing=unknown_case_message"
                    return 2
                }
                unknown_case_message="$1"
                shift
                ;;
            --local-fallback-stream)
                [[ $# -gt 0 ]] || {
                    e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|missing=local_fallback_stream"
                    return 2
                }
                local_fallback_stream="$1"
                shift
                ;;
            --remote-evidence-stream)
                [[ $# -gt 0 ]] || {
                    e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|missing=remote_evidence_stream"
                    return 2
                }
                remote_evidence_stream="$1"
                shift
                ;;
            --local-fallback-message)
                [[ $# -gt 0 ]] || {
                    e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|missing=local_fallback_message"
                    return 2
                }
                local_fallback_message="$1"
                shift
                ;;
            --remote-evidence-message)
                [[ $# -gt 0 ]] || {
                    e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|missing=remote_evidence_message"
                    return 2
                }
                remote_evidence_message="$1"
                shift
                ;;
            --complete-body-stdin)
                read_complete_body=1
                ;;
            *)
                e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|unknown_option=${arg}"
                return 2
                ;;
        esac
    done

    if [[ ! "$mode_env" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|invalid_mode_env=${mode_env}"
        return 2
    fi
    if [[ ! "$default_mode" =~ ^[A-Za-z0-9_-]+$ ]]; then
        e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|invalid_default_mode=${default_mode}"
        return 2
    fi
    case "$local_fallback_stream" in
        stdout | stderr) ;;
        *)
            e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|invalid_local_fallback_stream=${local_fallback_stream}"
            return 2
            ;;
    esac
    case "$remote_evidence_stream" in
        stdout | stderr) ;;
        *)
            e2e_log "E2E_FIXTURE_RCH_STUB_USAGE_ERROR|invalid_remote_evidence_stream=${remote_evidence_stream}"
            return 2
            ;;
    esac

    if [[ "$read_complete_body" -eq 1 ]]; then
        complete_body="$(cat)"
    fi

    local unexpected_q unknown_q local_stream_q remote_stream_q local_message_q remote_message_q
    printf -v unexpected_q '%q' "$unexpected_invocation_message"
    printf -v unknown_q '%q' "$unknown_case_message"
    printf -v local_stream_q '%q' "$local_fallback_stream"
    printf -v remote_stream_q '%q' "$remote_evidence_stream"
    printf -v local_message_q '%q' "$local_fallback_message"
    printf -v remote_message_q '%q' "$remote_evidence_message"

    cat >"$stub_path" <<SH
#!/usr/bin/env bash
set -euo pipefail

fixture_case="\${${mode_env}:-${default_mode}}"
unexpected_invocation_message=${unexpected_q}
unknown_case_message=${unknown_q}
local_fallback_stream=${local_stream_q}
remote_evidence_stream=${remote_stream_q}
local_fallback_message=${local_message_q}
remote_evidence_message=${remote_message_q}

emit_fixture_rch_line() {
    local stream="\$1"
    shift
    if [[ "\$stream" == "stdout" ]]; then
        printf '%s\n' "\$*"
    else
        printf '%s\n' "\$*" >&2
    fi
}

if [[ "\${1:-}" != "exec" || "\${2:-}" != "--" ]]; then
    emit_fixture_rch_line stderr "\${unexpected_invocation_message}: \$*"
    exit 64
fi
shift 2
command_text="\$*"
emit_remote_evidence=1

case "\$fixture_case" in
    local_fallback)
        emit_fixture_rch_line "\$local_fallback_stream" "\$local_fallback_message"
        exit 1
        ;;
    missing_remote_evidence)
        emit_remote_evidence=0
        ;;
    complete)
        ;;
    *)
        emit_fixture_rch_line stderr "\${unknown_case_message}: \$fixture_case"
        exit 64
        ;;
esac

if [[ "\$emit_remote_evidence" -eq 1 ]]; then
    emit_fixture_rch_line "\$remote_evidence_stream" "\$remote_evidence_message"
fi
${complete_body}
SH
    chmod +x "$stub_path"
}

#######################################
# Hermetic self-test for e2e_write_fixture_rch_stub.
# Does not run cargo or live rch.
#######################################
e2e_write_fixture_rch_stub_self_test() {
    local work_dir stub_path out_path err_path status
    local failures=0
    local had_errexit=0

    case $- in
        *e*) had_errexit=1 ;;
    esac

    work_dir="$(mktemp -d -t ffs_fixture_rch_stub_self_test_XXXXXX)"
    stub_path="$work_dir/rch-fixture"

    e2e_write_fixture_rch_stub "$stub_path" \
        --mode-env FFS_FIXTURE_RCH_STUB_SELF_TEST_MODE \
        --unexpected-invocation-message "unexpected self-test fixture rch invocation" \
        --unknown-case-message "unknown self-test fixture case" \
        --local-fallback-stream stdout \
        --remote-evidence-stream stderr \
        --complete-body-stdin <<'SH'
case "$command_text" in
    *"cargo test -p fake-fixture"*)
        printf '%s\n' "fixture complete body stdout"
        exit 0
        ;;
    *)
        echo "unexpected self-test fixture command: $command_text" >&2
        exit 64
        ;;
esac
SH

    out_path="$work_dir/complete.out"
    err_path="$work_dir/complete.err"
    if ! "$stub_path" exec -- cargo test -p fake-fixture >"$out_path" 2>"$err_path"; then
        printf 'E2E_FIXTURE_RCH_STUB_SELF_TEST|case=complete|outcome=FAIL|work_dir=%s\n' "$work_dir"
        failures=1
    elif ! grep -Fq "fixture complete body stdout" "$out_path" \
        || ! grep -Fq "[RCH] remote worker=fixture exit=0" "$err_path"; then
        printf 'E2E_FIXTURE_RCH_STUB_SELF_TEST|case=complete_markers|outcome=FAIL|work_dir=%s\n' "$work_dir"
        failures=1
    fi

    out_path="$work_dir/local_fallback.out"
    err_path="$work_dir/local_fallback.err"
    set +e
    FFS_FIXTURE_RCH_STUB_SELF_TEST_MODE=local_fallback "$stub_path" exec -- cargo test -p fake-fixture >"$out_path" 2>"$err_path"
    status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ "$status" -ne 1 ]] || ! grep -Fq "[RCH] local (fixture forced local fallback)" "$out_path"; then
        printf 'E2E_FIXTURE_RCH_STUB_SELF_TEST|case=local_fallback|outcome=FAIL|status=%s|work_dir=%s\n' "$status" "$work_dir"
        failures=1
    fi

    out_path="$work_dir/missing_remote.out"
    err_path="$work_dir/missing_remote.err"
    if ! FFS_FIXTURE_RCH_STUB_SELF_TEST_MODE=missing_remote_evidence "$stub_path" exec -- cargo test -p fake-fixture >"$out_path" 2>"$err_path"; then
        printf 'E2E_FIXTURE_RCH_STUB_SELF_TEST|case=missing_remote_evidence|outcome=FAIL|work_dir=%s\n' "$work_dir"
        failures=1
    elif grep -Fq "[RCH] remote" "$out_path" || grep -Fq "[RCH] remote" "$err_path"; then
        printf 'E2E_FIXTURE_RCH_STUB_SELF_TEST|case=missing_remote_evidence_marker|outcome=FAIL|work_dir=%s\n' "$work_dir"
        failures=1
    fi

    out_path="$work_dir/unexpected_invocation.out"
    err_path="$work_dir/unexpected_invocation.err"
    set +e
    "$stub_path" bad -- cargo test -p fake-fixture >"$out_path" 2>"$err_path"
    status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ "$status" -ne 64 ]] || ! grep -Fq "unexpected self-test fixture rch invocation" "$err_path"; then
        printf 'E2E_FIXTURE_RCH_STUB_SELF_TEST|case=unexpected_invocation|outcome=FAIL|status=%s|work_dir=%s\n' "$status" "$work_dir"
        failures=1
    fi

    if [[ "$failures" -ne 0 ]]; then
        return 1
    fi

    printf 'E2E_FIXTURE_RCH_STUB_SELF_TEST|outcome=PASS|work_dir=%s\n' "$work_dir"
}

#######################################
# Guard the phased migration away from local write_fixture_rch_stub definitions.
# The baseline is intentionally updated downward after migration batches.
# Arguments:
#   $1 - Repository root (default: $REPO_ROOT or current directory)
# Environment:
#   E2E_FIXTURE_RCH_STUB_BASELINE - allowed local definition count, default 79
#######################################
e2e_fixture_rch_stub_duplicate_guard() {
    local repo_root="${1:-${REPO_ROOT:-$(pwd)}}"
    local baseline="${E2E_FIXTURE_RCH_STUB_BASELINE:-79}"
    local scripts_dir="$repo_root/scripts/e2e"
    local matches=()
    local count
    local path
    local baseline_update_recommended=false

    if [[ ! "$baseline" =~ ^[0-9]+$ ]]; then
        printf 'E2E_FIXTURE_RCH_STUB_DUPLICATE_GUARD|outcome=FAIL|reason=invalid_baseline|baseline=%s\n' "$baseline"
        return 2
    fi
    if [[ ! -d "$scripts_dir" ]]; then
        printf 'E2E_FIXTURE_RCH_STUB_DUPLICATE_GUARD|outcome=FAIL|reason=missing_scripts_dir|path=%s\n' "$scripts_dir"
        return 2
    fi

    if command -v rg >/dev/null 2>&1; then
        mapfile -t matches < <(rg -l '^write_fixture_rch_stub\(\)' "$scripts_dir"/*.sh 2>/dev/null | sort || true)
    else
        mapfile -t matches < <(grep -lE '^write_fixture_rch_stub\(\)' "$scripts_dir"/*.sh 2>/dev/null | sort || true)
    fi
    count="${#matches[@]}"

    if ((count < baseline)); then
        baseline_update_recommended=true
    fi

    if ((count > baseline)); then
        printf 'E2E_FIXTURE_RCH_STUB_DUPLICATE_GUARD|outcome=FAIL|count=%s|baseline=%s|reason=count_increased\n' "$count" "$baseline"
        for path in "${matches[@]}"; do
            printf 'E2E_FIXTURE_RCH_STUB_DUPLICATE_GUARD_ENTRY|path=%s\n' "$path"
        done
        return 1
    fi

    printf 'E2E_FIXTURE_RCH_STUB_DUPLICATE_GUARD|outcome=PASS|count=%s|baseline=%s|baseline_update_recommended=%s\n' \
        "$count" "$baseline" "$baseline_update_recommended"
}

#######################################
# List canonical RCH guardrail markers used by fixture-matrix tests.
#######################################
e2e_rch_capture_fixture_matrix_markers() {
    cat <<'EOF'
RCH_LOCAL_FALLBACK_REJECTED
RCH_REMOTE_EVIDENCE_MISSING
RCH_TIMEOUT
RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT
RCH_REQUIRED_ARTIFACT_MISSING
RCH_CAPACITY_PREFLIGHT_REFERENCE
RCH_CAPACITY_PREFLIGHT_REFERENCE_MISSING
Remote command finished: exit=
exec called with non-compilation command
[RCH] local
EOF
}

#######################################
# Verify the fixture matrix marker vocabulary still matches e2e_rch_capture.
#######################################
e2e_rch_capture_fixture_matrix_self_test() {
    local helper_source
    local accepted_prefix="RCH_ARTIFACT_RETRIEVAL_"
    local accepted_suffix="ACCEPTED"
    local marker
    local marker_count=0
    local missing=0

    helper_source="$(declare -f e2e_rch_capture)"

    if [[ "$helper_source" == *"$accepted_prefix"*"$accepted_suffix"* ]]; then
        printf 'RCH_FIXTURE_MATRIX_SELF_TEST|outcome=FAIL|forbidden_marker=%s*%s\n' \
            "$accepted_prefix" "$accepted_suffix"
        return 1
    fi

    while IFS= read -r marker; do
        [[ -n "$marker" ]] || continue
        marker_count=$((marker_count + 1))
        if [[ "$helper_source" != *"$marker"* ]]; then
            printf 'RCH_FIXTURE_MATRIX_SELF_TEST|outcome=FAIL|missing_marker=%s\n' "$marker"
            missing=1
        fi
    done < <(e2e_rch_capture_fixture_matrix_markers)

    if [[ "$missing" -ne 0 ]]; then
        return 1
    fi

    printf 'RCH_FIXTURE_MATRIX_SELF_TEST|outcome=PASS|markers=%s\n' "$marker_count"
    e2e_rch_capture_fixture_matrix_markers
}

#######################################
# Run a command and log output
# Arguments:
#   $* - Command to run
# Returns:
#   Exit code of command (stored in E2E_LAST_EXIT_CODE)
#######################################
e2e_run() {
    local start_time end_time duration
    local output_file

    e2e_log "Running: $*"
    start_time=$(date +%s.%N)

    output_file=$(mktemp)

    # Run command and capture exit code without triggering set -e
    # Use a subshell to capture the real exit code before || true masks it
    E2E_LAST_EXIT_CODE=0
    "$@" > "$output_file" 2>&1 || E2E_LAST_EXIT_CODE=$?

    # Log output (limit to reasonable size)
    head -500 "$output_file" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    e2e_cleanup_tmp_file "$output_file"

    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "N/A")

    e2e_log "Exit code: $E2E_LAST_EXIT_CODE (duration: ${duration}s)"
    return "$E2E_LAST_EXIT_CODE"
}

#######################################
# Assert a command succeeds
# Arguments:
#   $* - Command to run
#######################################
e2e_assert() {
    if ! e2e_run "$@"; then
        e2e_fail "Assertion failed: $*"
    fi
}

#######################################
# Assert a file exists
# Arguments:
#   $1 - File path
#######################################
e2e_assert_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        e2e_fail "File not found: $file"
    fi
    e2e_log "File exists: $file"
}

#######################################
# Assert a directory exists
# Arguments:
#   $1 - Directory path
#######################################
e2e_assert_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        e2e_fail "Directory not found: $dir"
    fi
    e2e_log "Directory exists: $dir"
}

#######################################
# Skip test with message (exit 0)
# Arguments:
#   $1 - Skip reason
#######################################
e2e_skip() {
    local reason="$1"
    # bd-53dub: a lane that claims mounted/oracle evidence must not turn a
    # missing capability into a pass.
    if [[ "${FFS_REQUIRE_FUSE:-}" == "1" || "${FFS_REQUIRE_ORACLES:-}" == "1" ]]; then
        e2e_fail "FFS_REQUIRE_FUSE/FFS_REQUIRE_ORACLES=1 but the test would skip: $reason"
    fi
    # Recorded so result.json says SKIP, not PASS: a skipped run proved nothing.
    E2E_SKIPPED_REASON="$reason"
    e2e_log ""
    e2e_log "${YELLOW}SKIPPED${RESET}: $reason"
    e2e_log ""
    exit 0
}

#######################################
# Fail test with message (exit 1)
# Arguments:
#   $1 - Failure reason
#######################################
e2e_fail() {
    local reason="$1"
    e2e_log ""
    e2e_log "${RED}FAILED${RESET}: $reason"
    e2e_log ""
    e2e_log "Log file: $E2E_LOG_FILE"
    e2e_log ""
    e2e_log "Last 50 lines of log:"
    tail -50 "$E2E_LOG_FILE" 2>/dev/null | while IFS= read -r line; do
        echo "  $line"
    done
    exit 1
}

#######################################
# Pass test with summary
#######################################
e2e_pass() {
    local end_time duration

    end_time=$(date +%s)
    duration=$((end_time - E2E_START_TIME))

    e2e_log ""
    e2e_log "=============================================="
    e2e_log "${GREEN}PASSED${RESET}"
    e2e_log "=============================================="
    e2e_log "Duration: ${duration}s"
    e2e_log "Log file: $E2E_LOG_FILE"
    e2e_log ""
}

#######################################
# Print environment information
#######################################
e2e_print_env() {
    e2e_step "Environment"

    e2e_log "System:"
    e2e_log "  $(uname -a)"
    e2e_log "  User: $(id)"
    e2e_log ""

    e2e_log "Rust toolchain:"
    if command -v rustc &>/dev/null; then
        rustc -Vv 2>&1 | while IFS= read -r line; do e2e_log "  $line"; done
        cargo -V 2>&1 | while IFS= read -r line; do e2e_log "  $line"; done
    else
        e2e_log "  rustc not found"
    fi
    e2e_log ""

    e2e_log "FUSE:"
    if [[ -e /dev/fuse ]]; then
        ls -l /dev/fuse 2>&1 | while IFS= read -r line; do e2e_log "  $line"; done
    else
        e2e_log "  /dev/fuse not found"
    fi
    if command -v fusermount3 &>/dev/null; then
        e2e_log "  $(fusermount3 --version 2>&1 | head -1)"
    elif command -v fusermount &>/dev/null; then
        e2e_log "  $(fusermount --version 2>&1 | head -1)"
    else
        e2e_log "  fusermount not found"
    fi
    e2e_log ""

    e2e_log "Filesystem tools:"
    for tool in mkfs.ext4 debugfs; do
        if command -v "$tool" &>/dev/null; then
            e2e_log "  $tool: $(which "$tool")"
        else
            e2e_log "  $tool: not found"
        fi
    done
    e2e_log ""
}

#######################################
# Create a test ext4 image
# Arguments:
#   $1 - Output image path
#   $2 - Size in MiB (default: 16)
#######################################
e2e_create_ext4_image() {
    local img_path="$1"
    local size_mb="${2:-16}"

    e2e_step "Creating ext4 test image"
    e2e_log "Path: $img_path"
    e2e_log "Size: ${size_mb} MiB"

    # Check tools
    if ! command -v mkfs.ext4 &>/dev/null; then
        e2e_skip "mkfs.ext4 not found"
    fi
    if ! command -v debugfs &>/dev/null; then
        e2e_skip "debugfs not found"
    fi

    # Create image
    dd if=/dev/zero of="$img_path" bs=1M count="$size_mb" status=none

    # Format
    mkfs.ext4 -F -O extent,filetype -L e2e_test "$img_path" >/dev/null 2>&1

    # Populate with debugfs
    local tmp_dir
    tmp_dir=$(mktemp -d)

    echo "FrankenFS E2E Test File" > "$tmp_dir/readme.txt"
    echo "Hello from E2E test!" > "$tmp_dir/hello.txt"

    debugfs -w "$img_path" <<EOF >/dev/null 2>&1
mkdir testdir
write $tmp_dir/readme.txt readme.txt
write $tmp_dir/hello.txt testdir/hello.txt
EOF

    e2e_cleanup_tmp_dir "$tmp_dir"

    e2e_log "Image created successfully"
}

#######################################
# Mount an image via ffs mount
# Arguments:
#   $1 - Image path
#   $2 - Mount point
#######################################
e2e_mount() {
    local img_path="$1"
    local mnt_point="$2"
    local ffs_cli_bin="${FFS_CLI_BIN:-}"

    # Check FUSE availability
    if [[ ! -e /dev/fuse ]]; then
        e2e_skip "/dev/fuse not available"
    fi
    if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        e2e_skip "/dev/fuse not accessible"
    fi

    mkdir -p "$mnt_point"
    E2E_MOUNT_POINT="$mnt_point"

    if [[ -z "$ffs_cli_bin" ]]; then
        e2e_fail "FFS_CLI_BIN must point to an executable ffs-cli binary built through RCH before e2e_mount runs"
    fi
    if [[ ! -x "$ffs_cli_bin" ]]; then
        e2e_fail "FFS_CLI_BIN is not executable: $ffs_cli_bin"
    fi

    e2e_log "Mounting: $img_path -> $mnt_point"
    e2e_log "E2E_MOUNT_PREBUILT_CLI|binary=${ffs_cli_bin}|build_proof=required_rch"
    e2e_log "E2E_MOUNT_LOCAL_EXECUTION|binary=${ffs_cli_bin}|image=${img_path}|mount_point=${mnt_point}"
    RUST_LOG="${RUST_LOG:-off}" "$ffs_cli_bin" mount "$img_path" "$mnt_point" &
    local mount_pid=$!

    # Wait for mount to be ready
    local timeout=10
    local elapsed=0
    while ! mountpoint -q "$mnt_point" 2>/dev/null; do
        sleep 0.5
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $((timeout * 2)) ]]; then
            kill "$mount_pid" 2>/dev/null || true
            e2e_fail "Mount timed out after ${timeout}s"
        fi
    done

    e2e_log "Mount ready (PID: $mount_pid)"
}

#######################################
# Unmount a FUSE mount
# Arguments:
#   $1 - Mount point (optional, uses E2E_MOUNT_POINT if not provided)
#######################################
e2e_unmount() {
    local mnt_point="${1:-$E2E_MOUNT_POINT}"

    if [[ -z "$mnt_point" ]]; then
        return 0
    fi

    if ! mountpoint -q "$mnt_point" 2>/dev/null; then
        e2e_log "Not mounted: $mnt_point"
        return 0
    fi

    e2e_log "Unmounting: $mnt_point"

    if command -v fusermount3 &>/dev/null; then
        fusermount3 -u "$mnt_point" 2>/dev/null || true
    elif command -v fusermount &>/dev/null; then
        fusermount -u "$mnt_point" 2>/dev/null || true
    else
        umount "$mnt_point" 2>/dev/null || true
    fi

    # Fallback for orphaned/stuck FUSE mounts where fusermount fails.
    if mountpoint -q "$mnt_point" 2>/dev/null; then
        umount "$mnt_point" 2>/dev/null || umount -l "$mnt_point" 2>/dev/null || true
    fi

    # Give it a moment
    sleep 0.5

    if mountpoint -q "$mnt_point" 2>/dev/null; then
        e2e_log "WARNING: Mount point still mounted after unmount attempt"
    fi
}

#######################################
# Count exact field-key occurrences inside a marker line.
# Arguments:
#   $1 - Marker line
#   $2 - Field token including separator, e.g. "|scenario_id="
#######################################
e2e_marker_field_count() {
    local haystack="$1"
    local needle="$2"
    local count=0

    while [[ "$haystack" == *"$needle"* ]]; do
        haystack="${haystack#*"$needle"}"
        count=$((count + 1))
    done

    printf '%s\n' "$count"
}

#######################################
# Escape a single-line string for JSON.
# Arguments:
#   $1 - Value to escape
#######################################
e2e_json_escape() {
    local value="$1"

    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\b'/\\b}"
    value="${value//$'\f'/\\f}"
    value="${value//$'\t'/\\t}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\n'/\\n}"

    local control_code control_char control_escape
    for control_code in {1..31}; do
        printf -v control_char '%b' "\\$(printf '%03o' "$control_code")"
        printf -v control_escape '\\u%04x' "$control_code"
        value="${value//$control_char/$control_escape}"
    done

    printf '%s\n' "$value"
}

#######################################
# Return true when a scenario_id matches the E2E log contract.
# Arguments:
#   $1 - scenario_id value
#######################################
e2e_marker_scenario_id_is_valid() {
    local value="$1"

    [[ "$value" =~ ^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$ ]]
}

#######################################
# Return true when an outcome matches the E2E log contract.
# Arguments:
#   $1 - outcome value
#######################################
e2e_marker_outcome_is_valid() {
    local value="$1"

    [[ "$value" == "PASS" || "$value" == "FAIL" ]]
}

#######################################
# Return invalid reason for malformed marker extension fields, if any.
# Arguments:
#   $1 - full SCENARIO_RESULT marker line
#######################################
e2e_marker_extension_invalid_reason() {
    local line="$1"
    local -a fields
    local idx field key

    if [[ "$line" == *"|" ]]; then
        printf '%s\n' "malformed_extension"
        return 0
    fi

    IFS='|' read -r -a fields <<<"$line"
    for ((idx = 1; idx < ${#fields[@]}; idx++)); do
        field="${fields[$idx]}"
        case "$field" in
            scenario_id=*|outcome=*)
                ;;
            detail=*)
                # Detail finality and embedded separators are validated by the
                # detail_count/detail_contains_separator checks.
                break
                ;;
            *=*)
                key="${field%%=*}"
                if [[ -z "$key" ]]; then
                    printf '%s\n' "malformed_extension"
                    return 0
                fi
                ;;
            *)
                printf '%s\n' "malformed_extension"
                return 0
                ;;
        esac
    done

    printf '\n'
}

#######################################
# Emit a machine-parseable JSON summary alongside run.log
# Reads SCENARIO_RESULT markers from the log and writes result.json
# Arguments: (none — uses globals)
#######################################
e2e_emit_json_summary() {
    [[ -z "${E2E_LOG_FILE:-}" ]] && return 0
    [[ ! -f "$E2E_LOG_FILE" ]] && return 0

    local script_exit_code="${1:-0}"
    local json_path json_tmp merge_tmp
    json_path="$E2E_LOG_DIR/result.json"
    json_tmp="${json_path}.tmp.$$"
    merge_tmp="${json_path}.merged.$$"
    local end_time duration_secs
    end_time=$(date +%s)
    duration_secs=$((end_time - E2E_START_TIME))

    # Capture environment
    local hostname_val cpu_count kernel_ver rustc_ver cargo_ver
    hostname_val=$(hostname 2>/dev/null || echo "unknown")
    cpu_count=$(nproc 2>/dev/null || echo "0")
    kernel_ver=$(uname -r 2>/dev/null || echo "unknown")
    rustc_ver=$(rustc --version 2>/dev/null || echo "unknown")
    cargo_ver=$(cargo --version 2>/dev/null || echo "unknown")

    # Capture git context
    local git_commit git_branch git_clean
    git_commit=$(git -C "${REPO_ROOT:-.}" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    git_branch=$(git -C "${REPO_ROOT:-.}" branch --show-current 2>/dev/null || echo "unknown")
    git_clean=$(e2e_git_context_clean "${REPO_ROOT:-.}")

    # Extract scenario results from log
    local scenarios_json="["
    local invalid_scenario_markers_json="["
    local rch_local_fallback_rejections_json="["
    local rch_capacity_preflight_references_json="["
    local invalid_scenario_marker_count=0
    local rch_local_fallback_rejected_count=0
    local rch_capacity_preflight_reference_count=0
    local first=true
    local invalid_first=true
    local rch_first=true
    local rch_capacity_first=true
    while IFS= read -r line; do
        # Parse: SCENARIO_RESULT|scenario_id=X|outcome=Y[|detail=Z]
        local scenario_id outcome detail
        local scenario_id_count outcome_count detail_count
        scenario_id_count=$(e2e_marker_field_count "$line" "|scenario_id=")
        outcome_count=$(e2e_marker_field_count "$line" "|outcome=")
        detail_count=$(e2e_marker_field_count "$line" "|detail=")

        scenario_id=$(echo "$line" | sed -n 's/.*scenario_id=\([^|]*\).*/\1/p')
        outcome=$(echo "$line" | sed -n 's/.*outcome=\([^|]*\).*/\1/p')

        local invalid_reason extension_invalid_reason
        invalid_reason=""
        if [[ "$scenario_id_count" -eq 0 ]]; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}missing_scenario_id"
        elif [[ "$scenario_id_count" -gt 1 ]]; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}duplicate_scenario_id"
        elif [[ -z "$scenario_id" ]]; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}empty_scenario_id"
        elif ! e2e_marker_scenario_id_is_valid "$scenario_id"; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}invalid_scenario_id"
        fi
        if [[ "$outcome_count" -eq 0 ]]; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}missing_outcome"
        elif [[ "$outcome_count" -gt 1 ]]; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}duplicate_outcome"
        elif [[ -z "$outcome" ]]; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}empty_outcome"
        elif ! e2e_marker_outcome_is_valid "$outcome"; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}invalid_outcome"
        fi
        if [[ "$detail_count" -gt 1 ]]; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}duplicate_detail"
        elif [[ "$detail_count" -eq 1 ]]; then
            detail="${line#*|detail=}"
            if [[ "$detail" == *"|"* ]]; then
                invalid_reason="${invalid_reason}${invalid_reason:+,}detail_contains_separator"
            fi
        fi
        extension_invalid_reason=$(e2e_marker_extension_invalid_reason "$line")
        if [[ -n "$extension_invalid_reason" ]]; then
            invalid_reason="${invalid_reason}${invalid_reason:+,}${extension_invalid_reason}"
        fi

        if [[ -n "$invalid_reason" ]]; then
            local marker_preview

            marker_preview="$line"
            if ((${#marker_preview} > 240)); then
                marker_preview="${marker_preview:0:240}..."
            fi
            marker_preview=$(e2e_json_escape "$marker_preview")

            if [[ "$invalid_first" == "true" ]]; then
                invalid_first=false
            else
                invalid_scenario_markers_json+=","
            fi
            invalid_scenario_markers_json+="{\"reason\":\"$invalid_reason\",\"marker\":\"$marker_preview\"}"
            invalid_scenario_marker_count=$((invalid_scenario_marker_count + 1))
            continue
        fi

        if [[ "$detail_count" -eq 1 ]]; then
            detail="${line#*|detail=}"
        else
            detail=""
        fi

        if [[ "$first" == "true" ]]; then
            first=false
        else
            scenarios_json+=","
        fi

        # Escape JSON special characters in accepted marker fields.
        scenario_id=$(e2e_json_escape "$scenario_id")
        outcome=$(e2e_json_escape "$outcome")
        detail=$(e2e_json_escape "$detail")

        if [[ -n "$detail" ]]; then
            scenarios_json+="{\"scenario_id\":\"$scenario_id\",\"outcome\":\"$outcome\",\"detail\":\"$detail\"}"
        else
            scenarios_json+="{\"scenario_id\":\"$scenario_id\",\"outcome\":\"$outcome\"}"
        fi
    done < <(grep "^SCENARIO_RESULT|" "$E2E_LOG_FILE" 2>/dev/null || true)
    scenarios_json+="]"
    invalid_scenario_markers_json+="]"

    while IFS= read -r line; do
        local marker_preview

        marker_preview="$line"
        if ((${#marker_preview} > 240)); then
            marker_preview="${marker_preview:0:240}..."
        fi
        marker_preview=$(e2e_json_escape "$marker_preview")

        if [[ "$rch_first" == "true" ]]; then
            rch_first=false
        else
            rch_local_fallback_rejections_json+=","
        fi
        rch_local_fallback_rejections_json+="{\"marker\":\"$marker_preview\"}"
        rch_local_fallback_rejected_count=$((rch_local_fallback_rejected_count + 1))
    done < <(grep "^RCH_LOCAL_FALLBACK_REJECTED|" "$E2E_LOG_FILE" 2>/dev/null || true)
    rch_local_fallback_rejections_json+="]"

    while IFS= read -r line; do
        local marker_preview

        marker_preview="$line"
        if ((${#marker_preview} > 360)); then
            marker_preview="${marker_preview:0:360}..."
        fi
        marker_preview=$(e2e_json_escape "$marker_preview")

        if [[ "$rch_capacity_first" == "true" ]]; then
            rch_capacity_first=false
        else
            rch_capacity_preflight_references_json+=","
        fi
        rch_capacity_preflight_references_json+="{\"marker\":\"$marker_preview\"}"
        rch_capacity_preflight_reference_count=$((rch_capacity_preflight_reference_count + 1))
    done < <(grep "^RCH_CAPACITY_PREFLIGHT_REFERENCE" "$E2E_LOG_FILE" 2>/dev/null || true)
    rch_capacity_preflight_references_json+="]"

    # Determine verdict
    local verdict="PASS"
    if echo "$scenarios_json" | grep -q '"outcome":"FAIL"'; then
        verdict="FAIL"
    fi
    if [[ "$script_exit_code" -ne 0 ]]; then
        verdict="FAIL"
    elif [[ -n "${E2E_SKIPPED_REASON:-}" ]]; then
        verdict="SKIP"
    fi

    local gate_id_json run_id_json created_at_json git_commit_json git_branch_json
    local hostname_json kernel_json rustc_json cargo_json verdict_json log_file_json
    gate_id_json=$(e2e_json_escape "${E2E_TEST_NAME:-unknown}")
    run_id_json=$(e2e_json_escape "$(basename "$E2E_LOG_DIR")")
    created_at_json=$(e2e_json_escape "$(date -Iseconds)")
    git_commit_json=$(e2e_json_escape "$git_commit")
    git_branch_json=$(e2e_json_escape "$git_branch")
    hostname_json=$(e2e_json_escape "$hostname_val")
    kernel_json=$(e2e_json_escape "$kernel_ver")
    rustc_json=$(e2e_json_escape "$rustc_ver")
    cargo_json=$(e2e_json_escape "$cargo_ver")
    verdict_json=$(e2e_json_escape "$verdict")
    log_file_json=$(e2e_json_escape "$E2E_LOG_FILE")

    # Write the generic summary to a temporary file first. Some E2E scripts emit
    # suite-specific fields to result.json before exit; preserve those fields
    # while keeping this generic summary authoritative for shared keys.
    cat > "$json_tmp" <<ENDJSON
{
  "schema_version": 1,
  "runner_contract_version": 1,
  "gate_id": "$gate_id_json",
  "run_id": "$run_id_json",
  "created_at": "$created_at_json",
  "git_context": {
    "commit": "$git_commit_json",
    "branch": "$git_branch_json",
    "clean": $git_clean
  },
  "environment": {
    "hostname": "$hostname_json",
    "cpu_count": $cpu_count,
    "kernel": "$kernel_json",
    "rustc_version": "$rustc_json",
    "cargo_version": "$cargo_json"
  },
  "scenarios": $scenarios_json,
  "invalid_scenario_marker_count": $invalid_scenario_marker_count,
  "invalid_scenario_markers": $invalid_scenario_markers_json,
  "rch_local_fallback_rejected_count": $rch_local_fallback_rejected_count,
  "rch_local_fallback_rejections": $rch_local_fallback_rejections_json,
  "rch_capacity_preflight_reference_count": $rch_capacity_preflight_reference_count,
  "rch_capacity_preflight_references": $rch_capacity_preflight_references_json,
  "verdict": "$verdict_json",
  "exit_code": $script_exit_code,
  "duration_secs": $duration_secs,
  "log_file": "$log_file_json"
}
ENDJSON

    if [[ -s "$json_path" ]] \
        && command -v jq >/dev/null 2>&1 \
        && jq -e 'type == "object"' "$json_path" >/dev/null 2>&1 \
        && jq -e 'type == "object"' "$json_tmp" >/dev/null 2>&1 \
        && jq -s '.[0] * .[1]' "$json_path" "$json_tmp" >"$merge_tmp"; then
        mv "$merge_tmp" "$json_path"
        e2e_cleanup_tmp_file "$json_tmp"
    else
        mv "$json_tmp" "$json_path"
        e2e_cleanup_tmp_file "$merge_tmp"
    fi

    e2e_log "JSON summary written: $json_path"
}

#######################################
# Retry a command with configurable attempts.
# Intended for CI mode where flaky tests can be retried.
# Arguments:
#   $1 - Max attempts
#   $2.. - Command to retry
# Returns: exit code of the last attempt
#######################################
e2e_retry() {
    local max_attempts="$1"
    shift
    local attempt=1
    local exit_code=0

    while (( attempt <= max_attempts )); do
        e2e_log "Attempt $attempt/$max_attempts: $*"
        exit_code=0
        "$@" || exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            return 0
        fi
        if (( attempt < max_attempts )); then
            e2e_log "Attempt $attempt failed (exit=$exit_code), retrying..."
            sleep 1
        fi
        attempt=$((attempt + 1))
    done

    e2e_log "All $max_attempts attempts failed (last exit=$exit_code)"
    return "$exit_code"
}

# Store test name for JSON emission
E2E_TEST_NAME=""

#######################################
# Cleanup function (called on EXIT)
#######################################
e2e_cleanup() {
    local exit_code=$?

    # Emit JSON summary before cleanup (best-effort)
    e2e_emit_json_summary "$exit_code" 2>/dev/null || true

    # Unmount any active mount
    e2e_unmount "${E2E_MOUNT_POINT:-}" 2>/dev/null || true

    for item in "${E2E_CLEANUP_ITEMS[@]:-}"; do
        e2e_cleanup_tmp_dir "$item"
    done

    return "$exit_code"
}
