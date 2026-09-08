#!/usr/bin/env bash
# ffs_tracker_source_hygiene_e2e.sh - non-mutating tracker source hygiene report.
#
# This suite reads the Beads JSONL store, classifies FrankenFS-local issue IDs
# separately from foreign-looking rows, and writes an artifact for agent triage.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

# Graph authority establishes a complete projection, not permission to execute
# its recommendations. Claimability still comes from the source-aware report.
bv_projection_valid() {
    jq -e --slurpfile projection "$BV_SOURCE_AWARE_PROJECTION_JSON" \
        --argjson local_open "$LOCAL_OPEN_COUNT" \
        --argjson local_in_progress "$LOCAL_IN_PROGRESS_COUNT" '
        (.source_authority.state == "complete")
        and (.source_authority.claim_safe == true)
        and (.source_authority.errors == 0)
        and (.source_authority.skipped == 0)
        and (.source_authority.read_errors == 0)
        and (.triage.meta.issue_count == ($projection[0].graph_rows | length))
        and (.triage.project_health.counts.total == ($projection[0].graph_rows | length))
        and (.triage.quick_ref.open_count == $local_open)
        and ((.triage.quick_ref.in_progress_count // 0) == $local_in_progress)
        and ([
            (.triage.quick_ref.top_picks[]?.id // empty),
            (.triage.recommendations[]?.id // empty),
            (.triage.quick_wins[]?.id // empty),
            (.triage.blockers_to_clear[]?.id // empty)
        ] | all(test("^(bd|frankenfs)-")))
    ' "$1" >/dev/null
}

e2e_init "ffs_tracker_source_hygiene"

ISSUES_JSONL="${TRACKER_SOURCE_HYGIENE_ISSUES:-$REPO_ROOT/.beads/issues.jsonl}"
REPORT_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_report.json"
REPORT_CANONICAL_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_report.canonical.json"
REPORT_MISMATCH_GOLDEN_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_report.mismatched_golden.json"
LOCAL_OPEN_JSONL="${E2E_LOG_DIR}/tracker_source_hygiene_local_open.jsonl"
SOURCE_AWARE_READY_JSONL="${E2E_LOG_DIR}/tracker_source_hygiene_source_aware_ready.jsonl"
LOCAL_NONCLAIMABLE_JSONL="${E2E_LOG_DIR}/tracker_source_hygiene_local_nonclaimable.jsonl"
LOCAL_OPEN_SHA256="${LOCAL_OPEN_JSONL}.sha256"
SOURCE_AWARE_READY_SHA256="${SOURCE_AWARE_READY_JSONL}.sha256"
LOCAL_NONCLAIMABLE_SHA256="${LOCAL_NONCLAIMABLE_JSONL}.sha256"
BV_SOURCE_AWARE_ROOT="${E2E_TEMP_DIR}/tracker_source_hygiene_bv_source_aware"
BV_SOURCE_AWARE_BEADS_DIR="${BV_SOURCE_AWARE_ROOT}/.beads"
BV_SOURCE_AWARE_ISSUES_JSONL="${BV_SOURCE_AWARE_BEADS_DIR}/issues.jsonl"
BV_SOURCE_AWARE_IMPORT_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_bv_source_aware_import.json"
BV_SOURCE_AWARE_TRIAGE_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_bv_source_aware_triage.json"
BV_SOURCE_AWARE_PROJECTION_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_bv_projection.json"
SOURCE_SHA256="${E2E_LOG_DIR}/tracker_source_hygiene_source.sha256"
STRICT_MODE=0
STRICT_JSON=false
STALE_IN_PROGRESS_SECONDS="${TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS:-21600}"
REPORT_NOW_EPOCH="${TRACKER_SOURCE_HYGIENE_NOW_EPOCH:-$(date -u +%s)}"
EXPECTED_GOLDEN="${TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN:-}"
EXPECT_GOLDEN_MISMATCH=0
DEFAULT_FIXTURE_SELF_CHECK=1
DEFAULT_FIXTURE_ISSUES="$REPO_ROOT/tests/fixtures/tracker_source_hygiene.jsonl"
DEFAULT_FIXTURE_GOLDEN="$REPO_ROOT/tests/fixtures/tracker_source_hygiene_report.golden.json"
FIXTURE_SELF_CHECK_LOG="${E2E_LOG_DIR}/tracker_source_hygiene_fixture_self_check.log"
NON_MUTATING_FALLBACK_SELF_CHECK=1
NON_MUTATING_FALLBACK_FIXTURE="$E2E_TEMP_DIR/tracker_source_hygiene_non_mutating_fallback.jsonl"
NON_MUTATING_FALLBACK_SELF_CHECK_LOG="${E2E_LOG_DIR}/tracker_source_hygiene_non_mutating_fallback_self_check.log"
PERMISSION_GATED_BLOCKED_SELF_CHECK=1
PERMISSION_GATED_BLOCKED_FIXTURE="$E2E_TEMP_DIR/tracker_source_hygiene_permission_gated_blocked.jsonl"
PERMISSION_GATED_BLOCKED_SELF_CHECK_LOG="${E2E_LOG_DIR}/tracker_source_hygiene_permission_gated_blocked_self_check.log"
PERMISSION_ACK_SELF_CHECK=1
PERMISSION_ACK_XFSTESTS_SELF_CHECK_LOG="${E2E_LOG_DIR}/tracker_source_hygiene_permission_ack_xfstests_self_check.log"
PERMISSION_ACK_SWARM_FIXTURE="$E2E_TEMP_DIR/tracker_source_hygiene_permission_ack_swarm.jsonl"
PERMISSION_ACK_SWARM_SELF_CHECK_LOG="${E2E_LOG_DIR}/tracker_source_hygiene_permission_ack_swarm_self_check.log"
RELEASE_READY_P0_SELF_CHECK=1
RELEASE_READY_P0_FIXTURE="$E2E_TEMP_DIR/tracker_source_hygiene_release_ready_p0.jsonl"
RELEASE_READY_P0_SELF_CHECK_LOG="${E2E_LOG_DIR}/tracker_source_hygiene_release_ready_p0_self_check.log"

case "${TRACKER_SOURCE_HYGIENE_STRICT:-0}" in
    1|true|TRUE|yes|YES)
        STRICT_MODE=1
        STRICT_JSON=true
        ;;
esac
case "${TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN_MISMATCH:-0}" in
    1|true|TRUE|yes|YES)
        EXPECT_GOLDEN_MISMATCH=1
        ;;
esac
case "${TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK:-1}" in
    0|false|FALSE|no|NO)
        DEFAULT_FIXTURE_SELF_CHECK=0
        ;;
esac
case "${TRACKER_SOURCE_HYGIENE_NON_MUTATING_FALLBACK_SELF_CHECK:-1}" in
    0|false|FALSE|no|NO)
        NON_MUTATING_FALLBACK_SELF_CHECK=0
        ;;
esac
case "${TRACKER_SOURCE_HYGIENE_PERMISSION_GATED_BLOCKED_SELF_CHECK:-1}" in
    0|false|FALSE|no|NO)
        PERMISSION_GATED_BLOCKED_SELF_CHECK=0
        ;;
esac
case "${TRACKER_SOURCE_HYGIENE_PERMISSION_ACK_SELF_CHECK:-1}" in
    0|false|FALSE|no|NO)
        PERMISSION_ACK_SELF_CHECK=0
        ;;
esac
case "${TRACKER_SOURCE_HYGIENE_RELEASE_READY_P0_SELF_CHECK:-1}" in
    0|false|FALSE|no|NO)
        RELEASE_READY_P0_SELF_CHECK=0
        ;;
esac

e2e_step "Preflight"
if ! command -v jq >/dev/null 2>&1; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "jq not found"
    e2e_fail "jq is required for tracker source hygiene reporting"
fi
if [[ ! -f "$ISSUES_JSONL" ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "issues JSONL missing: $ISSUES_JSONL"
    e2e_fail "issues JSONL missing: $ISSUES_JSONL"
fi
if [[ ! "$STALE_IN_PROGRESS_SECONDS" =~ ^[0-9]+$ ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "invalid stale threshold: $STALE_IN_PROGRESS_SECONDS"
    e2e_fail "TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS must be a non-negative integer"
fi
if [[ ! "$REPORT_NOW_EPOCH" =~ ^[0-9]+$ ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "invalid report epoch: $REPORT_NOW_EPOCH"
    e2e_fail "TRACKER_SOURCE_HYGIENE_NOW_EPOCH must be a non-negative integer"
fi
if [[ -n "$EXPECTED_GOLDEN" && ! -f "$EXPECTED_GOLDEN" ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "golden missing: $EXPECTED_GOLDEN"
    e2e_fail "TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN does not exist: $EXPECTED_GOLDEN"
fi
if [[ "$EXPECT_GOLDEN_MISMATCH" -eq 1 && -z "$EXPECTED_GOLDEN" ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "golden mismatch self-test requires TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN"
    e2e_fail "TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN_MISMATCH requires TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN"
fi

e2e_step "Parse tracker JSONL and emit report"
if jq -s \
    --arg run_id "$(basename "$E2E_LOG_DIR")" \
    --arg issues_path "$ISSUES_JSONL" \
    --arg local_open_jsonl "$LOCAL_OPEN_JSONL" \
    --arg source_aware_ready_jsonl "$SOURCE_AWARE_READY_JSONL" \
    --arg local_nonclaimable_jsonl "$LOCAL_NONCLAIMABLE_JSONL" \
    --arg local_open_sha256 "$LOCAL_OPEN_SHA256" \
    --arg source_aware_ready_sha256 "$SOURCE_AWARE_READY_SHA256" \
    --arg local_nonclaimable_sha256 "$LOCAL_NONCLAIMABLE_SHA256" \
    --arg xfstests_ack "${XFSTESTS_REAL_RUN_ACK:-}" \
    --arg swarm_enable "${FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD:-}" \
    --arg swarm_ack "${FFS_SWARM_WORKLOAD_REAL_RUN_ACK:-}" \
    --argjson strict "$STRICT_JSON" \
    --argjson stale_in_progress_seconds "$STALE_IN_PROGRESS_SECONDS" \
    --argjson report_now_epoch "$REPORT_NOW_EPOCH" \
    '
    . as $issues
    | def issue_status($id):
        ([$issues[] | select(.id == $id) | .status][0] // "missing");
    def local_issue:
        ((.id // "") | test("^(bd|frankenfs)-"));
    def foreign_issue:
        (local_issue | not);
    def open_issue:
        ((.status // "open") == "open");
    def in_progress_issue:
        ((.status // "open") == "in_progress");
    def normalized_iso8601:
        if type == "string" then
            sub("\\.[0-9]+Z$"; "Z")
        else
            null
        end;
    def foreign_franken_project_prefix:
        (.id // "") as $id
        | [
            "franken_networkx",
            "franken_numpy",
            "frankenjax",
            "frankenlibc",
            "frankenpandas",
            "frankenredis",
            "frankenscipy",
            "frankentorch"
        ]
        | map(. as $prefix | select($id | startswith($prefix + "-")))
        | .[0] // null;
    def foreign_franken_project_text_hint($text):
        [
            "franken_networkx",
            "franken_numpy",
            "frankenjax",
            "frankenlibc",
            "frankenpandas",
            "frankenredis",
            "frankenscipy",
            "frankentorch"
        ]
        | map(. as $prefix | select($text | contains($prefix)))
        | .[0] // null;
    def activity_epoch:
        ((.updated_at // .created_at // null) | normalized_iso8601 | fromdateiso8601?);
    def issue_prefix:
        foreign_franken_project_prefix as $project_prefix
        | (.id // "") as $id
        | if $project_prefix != null then
            $project_prefix
        else
            ($id | capture("^(?<prefix>[^-]+(?:-[^-]+)?)").prefix // "unknown")
        end;
    def owner_hint:
        ([(.id // ""), (.title // ""), (.description // "")] | join(" ") | ascii_downcase) as $text
        | foreign_franken_project_prefix as $project_prefix
        | foreign_franken_project_text_hint($text) as $project_hint
        | if $project_prefix != null then
            $project_prefix
        elif $project_hint != null then
            $project_hint
        elif ($text | contains("networkx")) then
            "franken_networkx"
        elif ($text | contains("scipy")) then
            "frankenscipy"
        elif (($text | contains("frankenfs")) or ((.id // "") | test("^(bd|frankenfs)-"))) then
            "frankenfs"
        else
            "unknown"
        end;
    def issue_text:
        [
            (.id // ""),
            (.title // ""),
            (.description // ""),
            (.notes // ""),
            ((.labels // []) | join(" "))
        ] | join(" ");
    def blocking_dependencies:
        (.dependencies // [])
        | map(select((.type // "") == "blocks"))
        | map(.depends_on_id as $dep_id | {id: $dep_id, status: issue_status($dep_id)})
        | map(select(.status != "closed"));
    def xfstests_ack_present:
        $xfstests_ack == "xfstests-may-mutate-test-and-scratch-devices";
    def swarm_ack_present:
        ($swarm_enable == "1")
        and ($swarm_ack == "swarm-workload-may-use-permissioned-large-host");
    def explicit_non_permissioned_guard:
        issue_text as $text
        | (($text | test("non-permissioned|read-only|non-mutating|nonmutating"; "i"))
            and ($text | test("must not (run|execute)|does not (run|execute)|without running|no xfstests|no large-host|no large host|no permissioned|not run[^.]*xfstests|not run[^.]*large-host|not run[^.]*large host|not run[^.]*swarm"; "i")));
    def permission_gate:
        issue_text as $text
        | if explicit_non_permissioned_guard then
            null
        elif (($text | test("XFSTESTS_REAL_RUN_ACK|xfstests-may-mutate-test-and-scratch-devices|real xfstests run|execute[^.]*xfstests baseline|run[^.]*xfstests baseline"; "i")) and (xfstests_ack_present | not)) then
            {
                gate_kind: "xfstests_real_run",
                required_env: "XFSTESTS_REAL_RUN_ACK",
                required_value: "xfstests-may-mutate-test-and-scratch-devices",
                present: false
            }
        elif (($text | test("FFS_SWARM_WORKLOAD_REAL_RUN_ACK|swarm-workload-may-use-permissioned-large-host|large-host|large host|permissioned[ -]+swarm|swarm[ -]+permissioned"; "i")) and (swarm_ack_present | not)) then
            {
                gate_kind: "large_host_swarm_real_run",
                required_env: "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD,FFS_SWARM_WORKLOAD_REAL_RUN_ACK",
                required_value: "1,swarm-workload-may-use-permissioned-large-host",
                present: false
            }
        else
            null
        end;
    def ready_issue:
        local_issue
        and open_issue
        and ((.issue_type // "") != "epic")
        and ((blocking_dependencies | length) == 0)
        and ((permission_gate // null) == null);
    def issue_sample:
        {
            id: (.id // ""),
            title: (.title // ""),
            status: (.status // "open"),
            priority: (.priority // null),
            issue_type: (.issue_type // null),
            source_repo: (.source_repo // null)
        };
    def issue_work_row:
        issue_sample + {
            assignee: (.assignee // .owner // null),
            blocked_by: blocking_dependencies
        };
    def nonclaimable_row($reason; $gate):
        issue_work_row + {
            reason: $reason,
            permission_gate: $gate
        };
    def issue_progress_row:
        activity_epoch as $activity_epoch
        | issue_work_row + {
            created_at: (.created_at // null),
            updated_at: (.updated_at // null),
            last_activity_epoch: $activity_epoch,
            age_seconds: (
                if $activity_epoch == null then
                    null
                else
                    (($report_now_epoch - $activity_epoch) | floor)
                end
            ),
            stale_after_seconds: $stale_in_progress_seconds,
            stale: (
                if $activity_epoch == null then
                    true
                else
                    (($report_now_epoch - $activity_epoch) >= $stale_in_progress_seconds)
                end
            )
        };
    def foreign_group_row:
        issue_sample + {
            prefix: issue_prefix,
            owner_hint: owner_hint
        };
    def foreign_open_count:
        ([.[] | select(foreign_issue and open_issue)] | length);
    def local_open_rows_arr:
        [.[] | select(local_issue and open_issue) | issue_work_row] | sort_by(.priority, .id);
    def source_aware_ready_rows_arr:
        [.[] | select(ready_issue) | issue_work_row] | sort_by(.priority, .id);
    def permission_gated_rows_arr:
        [.[] | select(local_issue and open_issue and ((.issue_type // "") != "epic") and ((permission_gate // null) != null)) | issue_work_row + {permission_gate: permission_gate}]
        | sort_by(.priority, .id);
    def blocked_local_rows_arr:
        [.[] | select(local_issue and open_issue and ((.issue_type // "") != "epic") and ((blocking_dependencies | length) > 0)) | issue_work_row]
        | sort_by(.priority, .id);
    def local_epic_rows_arr:
        [.[] | select(local_issue and open_issue and ((.issue_type // "") == "epic")) | issue_sample]
        | sort_by(.priority, .id);
    def local_nonclaimable_rows_arr:
        [.[] | select(local_issue and open_issue) |
            if ((.issue_type // "") == "epic") then
                nonclaimable_row("epic"; null)
            elif ((permission_gate // null) != null) then
                nonclaimable_row("permission_gated"; permission_gate)
            elif ((blocking_dependencies | length) > 0) then
                nonclaimable_row("blocked"; null)
            else
                empty
            end
        ]
        | sort_by(.priority, .id);
    def local_in_progress_rows_arr:
        [.[] | select(local_issue and in_progress_issue) | issue_progress_row]
        | sort_by(.priority, .id);
    def stale_in_progress_rows_arr:
        [local_in_progress_rows_arr[] | select(.stale)]
        | sort_by(.priority, .id);
    def foreign_in_progress_rows_arr:
        [.[] | select(foreign_issue and in_progress_issue) | issue_progress_row]
        | sort_by(.priority, .id);
    def foreign_stale_in_progress_rows_arr:
        [foreign_in_progress_rows_arr[] | select(.stale)]
        | sort_by(.priority, .id);
    {
        schema_version: 1,
        run_id: $run_id,
        created_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
        issues_path: $issues_path,
        strict: $strict,
        report_now_epoch: $report_now_epoch,
        status: (if ($strict and (foreign_open_count > 0)) then "fail" else "pass" end),
        mutation_policy: "report-only; this command never deletes, rewrites, closes, or edits tracker rows",
        classifier: {
            local_id_regex: "^(bd|frankenfs)-",
            local_rule: "FrankenFS-local rows use bd-* or frankenfs-* issue IDs",
            foreign_rule: "Rows with other issue ID prefixes are reported as foreign-looking"
        },
        total_rows: length,
        local_total: ([.[] | select(local_issue)] | length),
        foreign_total: ([.[] | select(foreign_issue)] | length),
        open_total: ([.[] | select(open_issue)] | length),
        local_open: ([.[] | select(local_issue and open_issue)] | length),
        foreign_open: foreign_open_count,
        foreign_in_progress: (foreign_in_progress_rows_arr | length),
        excluded_foreign_open_count: foreign_open_count,
        excluded_foreign_in_progress_count: (foreign_in_progress_rows_arr | length),
        excluded_foreign_stale_in_progress_count: (foreign_stale_in_progress_rows_arr | length),
        excluded_foreign_by_prefix: (
            [.[] | select(foreign_issue and open_issue) | issue_prefix]
            | group_by(.)
            | map({prefix: .[0], count: length})
            | sort_by(.prefix)
        ),
        foreign_group_summaries: (
            [.[] | select(foreign_issue and open_issue) | foreign_group_row]
            | sort_by(.prefix, .id)
            | group_by(.prefix)
            | map({
                prefix: .[0].prefix,
                count: length,
                owner_hints: (
                    ([.[].owner_hint] | unique) as $hints
                    | if (($hints | length) > 1 and ($hints | index("unknown"))) then
                        ($hints | map(select(. != "unknown")))
                    else
                        $hints
                    end
                ),
                sample_ids: ([.[].id] | .[0:10]),
                sample_titles: ([.[].title] | .[0:3])
            })
            | sort_by(.prefix)
        ),
        foreign_reconciliation_plan: (
            [.[] | select(foreign_issue and open_issue) | foreign_group_row]
            | sort_by(.prefix, .id)
            | group_by(.prefix)
            | map({
                prefix: .[0].prefix,
                count: length,
                owner_hints: (
                    ([.[].owner_hint] | unique) as $hints
                    | if (($hints | length) > 1 and ($hints | index("unknown"))) then
                        ($hints | map(select(. != "unknown")))
                    else
                        $hints
                    end
                ),
                sample_ids: ([.[].id] | .[0:10])
            })
            | sort_by(.prefix)
            | . as $groups
            | {
                schema_version: 1,
                mutation_policy: "owner-handoff-required; this report never deletes, rewrites, closes, or moves tracker rows",
                authorization_required: (($groups | length) > 0),
                conservation_check_required: (($groups | length) > 0),
                groups: (
                    $groups
                    | map({
                        prefix: .prefix,
                        count: .count,
                        owner_hints: .owner_hints,
                        sample_ids: .sample_ids,
                        recommended_thread_id: "tracker-hygiene",
                        recommended_subject: ("[tracker-hygiene] Foreign row ownership check: " + .prefix),
                        proposed_action: "ask hinted owner project to confirm authority before any move, removal, rewrite, or project-field backfill",
                        authorization_required: true,
                        conservation_rule: "before authorized mutation, preserve pre/post snapshots and prove total row conservation across affected stores"
                    })
                ),
                next_steps: (
                    if ($groups | length) > 0 then
                        [
                            "capture this source-scoped report artifact before proposing mutation",
                            "message owner_hints on Agent Mail thread tracker-hygiene with sample_ids",
                            "wait for explicit owner authorization before removing, moving, or rewriting foreign rows",
                            "if authorized, use pre/post snapshots and row-count conservation checks",
                            "if authorization is absent, continue using source_aware_queue_state and local graph exports"
                        ]
                    else
                        ["strict mode can be considered after a fresh zero-foreign report"]
                    end
                )
            }
        ),
        local_open_ids: ([.[] | select(local_issue and open_issue) | .id] | sort),
        local_open_rows: local_open_rows_arr,
        source_aware_ready_rows: source_aware_ready_rows_arr,
        source_aware_queue_state: (
            source_aware_ready_rows_arr as $ready_rows
            | permission_gated_rows_arr as $permission_gated
            | blocked_local_rows_arr as $blocked_rows
            | local_epic_rows_arr as $epic_rows
            | local_nonclaimable_rows_arr as $nonclaimable_rows
            | local_in_progress_rows_arr as $in_progress_rows
            | stale_in_progress_rows_arr as $stale_rows
            | foreign_in_progress_rows_arr as $foreign_in_progress_rows
            | foreign_stale_in_progress_rows_arr as $foreign_stale_rows
            | {
                schema_version: 1,
                verdict: (
                    if ($ready_rows | length) > 0 then
                        "ready"
                    elif ($stale_rows | length) > 0 then
                        "stale_in_progress"
                    elif (($permission_gated | length) > 0 and ($blocked_rows | length) > 0) then
                        "blocked_or_permission_gated"
                    elif ($permission_gated | length) > 0 then
                        "permission_gated"
                    elif ($blocked_rows | length) > 0 then
                        "blocked"
                    elif ($epic_rows | length) > 0 then
                        "epic_only"
                    elif ($foreign_stale_rows | length) > 0 then
                        "foreign_stale_in_progress"
                    else
                        "empty"
                    end
                ),
                claimable_count: ($ready_rows | length),
                local_open_count: (local_open_rows_arr | length),
                local_epic_count: ($epic_rows | length),
                blocked_local_count: ($blocked_rows | length),
                permission_gated_count: ($permission_gated | length),
                local_nonclaimable_count: ($nonclaimable_rows | length),
                local_in_progress_count: ($in_progress_rows | length),
                stale_in_progress_count: ($stale_rows | length),
                excluded_foreign_open_count: foreign_open_count,
                excluded_foreign_in_progress_count: ($foreign_in_progress_rows | length),
                excluded_foreign_stale_in_progress_count: ($foreign_stale_rows | length),
                excluded_foreign_stale_in_progress_ids: ($foreign_stale_rows | map(.id)),
                claimable_ids: ($ready_rows | map(.id)),
                local_epic_ids: ($epic_rows | map(.id)),
                blocked_local_ids: ($blocked_rows | map(.id)),
                permission_gated_ids: ($permission_gated | map(.id)),
                local_nonclaimable_ids: ($nonclaimable_rows | map(.id)),
                local_in_progress_ids: ($in_progress_rows | map(.id)),
                stale_in_progress_ids: ($stale_rows | map(.id)),
                next_safe_actions: (
                    if ($ready_rows | length) > 0 then
                        ["claim one source_aware_ready row before creating fallback work"]
                    elif ($stale_rows | length) > 0 then
                        ["inspect stale_in_progress_ids and Agent Mail before reopening stalled claims"]
                    elif (($permission_gated | length) > 0 and ($blocked_rows | length) > 0) then
                        ["inspect blocked_local_ids and unblock prerequisites first", "request the exact permission ACK before running permissioned rows", "create or claim only non-mutating fallback work"]
                    elif ($permission_gated | length) > 0 then
                        ["request the exact permission ACK before running permissioned rows", "create or claim only non-mutating fallback work"]
                    elif ($blocked_rows | length) > 0 then
                        ["inspect blocked_local_ids and unblock prerequisites first"]
                    elif ($epic_rows | length) > 0 then
                        ["create a narrow child bead under the open epic before editing code"]
                    elif ($foreign_stale_rows | length) > 0 then
                        ["inspect excluded_foreign_stale_in_progress_ids and Agent Mail before reopening stale foreign claims", "avoid claiming foreign rows as FrankenFS work"]
                    else
                        ["run idea-wizard or a testing skill to create a new narrow bead"]
                    end
                )
            }
        ),
        local_graph_exports: {
            schema_version: 1,
            mutation_policy: "report-only; exports copy matching source rows without editing tracker state",
            local_open: {
                path: $local_open_jsonl,
                checksum_path: $local_open_sha256,
                row_count: (local_open_rows_arr | length),
                id_count: ([.[] | select(local_issue and open_issue) | .id] | unique | length),
                consumer_hint: "Use this JSONL as a local-only tracker input when br or bv output is polluted by foreign rows."
            },
            source_aware_ready: {
                path: $source_aware_ready_jsonl,
                checksum_path: $source_aware_ready_sha256,
                row_count: (source_aware_ready_rows_arr | length),
                id_count: ([.[] | select(ready_issue) | .id] | unique | length),
                consumer_hint: "Use this JSONL for claimable FrankenFS rows; it excludes epics, blocked rows, foreign rows, and permission-gated rows without the required ACK."
            },
            local_nonclaimable: {
                path: $local_nonclaimable_jsonl,
                checksum_path: $local_nonclaimable_sha256,
                row_count: (local_nonclaimable_rows_arr | length),
                id_count: (local_nonclaimable_rows_arr | map(.id) | unique | length),
                consumer_hint: "Use this JSONL to explain why local open rows are not claimable; reasons are epic, permission_gated, or blocked."
            }
        },
        permission_gated_rows: permission_gated_rows_arr,
        blocked_local_rows: blocked_local_rows_arr,
        local_nonclaimable_rows: local_nonclaimable_rows_arr,
        local_in_progress_rows: local_in_progress_rows_arr,
        stale_in_progress_rows: stale_in_progress_rows_arr,
        foreign_open_samples: ([.[] | select(foreign_issue and open_issue) | issue_sample] | sort_by(.id) | .[0:20]),
        foreign_in_progress_samples: (foreign_in_progress_rows_arr | .[0:20]),
        foreign_stale_in_progress_samples: (foreign_stale_in_progress_rows_arr | .[0:20]),
        reproduction_commands: [
            "./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh",
            "jq -s '\''[.[] | select(((.id // \"\") | test(\"^(bd|frankenfs)-\") | not) and ((.status // \"open\") == \"open\")) | {id,title,status,priority,source_repo}]'\'' .beads/issues.jsonl",
            "jq -s '\''[.[] | select(((.id // \"\") | test(\"^(bd|frankenfs)-\")) and ((.status // \"open\") == \"open\")) | {id,title,status,priority,issue_type,assignee,owner}] | sort_by(.priority, .id)'\'' .beads/issues.jsonl",
            "jq -c '\''select(((.id // \"\") | test(\"^(bd|frankenfs)-\")) and ((.status // \"open\") == \"open\"))'\'' .beads/issues.jsonl > tracker_source_hygiene_local_open.jsonl",
            "mkdir -p /data/tmp/ffs-source-aware-bv/.beads && jq -c '\''select((.id // \"\") | test(\"^(bd|frankenfs)-\"))'\'' .beads/issues.jsonl > /data/tmp/ffs-source-aware-bv/.beads/issues.jsonl && BEADS_DIR=/data/tmp/ffs-source-aware-bv/.beads br --db /data/tmp/ffs-source-aware-bv/.beads/beads.db sync --import-only --orphans allow --json && bv --no-cache --db /data/tmp/ffs-source-aware-bv/.beads --robot-triage",
            "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh",
            "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh",
            "TRACKER_SOURCE_HYGIENE_STRICT=1 ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh"
        ]
    }
    ' "$ISSUES_JSONL" >"$REPORT_JSON"; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "PASS" "parsed $ISSUES_JSONL"
else
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "jq could not parse $ISSUES_JSONL"
    e2e_fail "tracker JSONL parse failed: $ISSUES_JSONL"
fi

if jq -e '
    .schema_version == 1
    and (.total_rows | type == "number")
    and (.open_total | type == "number")
    and (.local_open | type == "number")
    and (.foreign_open | type == "number")
    and (.foreign_in_progress | type == "number")
    and (.excluded_foreign_open_count | type == "number")
    and (.excluded_foreign_in_progress_count | type == "number")
    and (.excluded_foreign_stale_in_progress_count | type == "number")
    and (.local_open_ids | type == "array")
    and (.local_open_rows | type == "array")
    and (.source_aware_ready_rows | type == "array")
    and (.source_aware_queue_state.schema_version == 1)
    and (.source_aware_queue_state.verdict as $verdict | (["ready", "stale_in_progress", "blocked_or_permission_gated", "permission_gated", "blocked", "epic_only", "foreign_stale_in_progress", "empty"] | index($verdict)) != null)
    and (.source_aware_queue_state.claimable_count == (.source_aware_ready_rows | length))
    and (.source_aware_queue_state.local_open_count == .local_open)
    and (.source_aware_queue_state.permission_gated_count == (.permission_gated_rows | length))
    and (.source_aware_queue_state.local_nonclaimable_count == (.local_nonclaimable_rows | length))
    and (.source_aware_queue_state.local_in_progress_count == (.local_in_progress_rows | length))
    and (.source_aware_queue_state.stale_in_progress_count == (.stale_in_progress_rows | length))
    and (.source_aware_queue_state.excluded_foreign_in_progress_count == .excluded_foreign_in_progress_count)
    and (.source_aware_queue_state.excluded_foreign_stale_in_progress_count == .excluded_foreign_stale_in_progress_count)
    and (.source_aware_queue_state.excluded_foreign_stale_in_progress_ids | type == "array")
    and (.source_aware_queue_state.blocked_local_ids | type == "array")
    and (.source_aware_queue_state.local_nonclaimable_ids | type == "array")
    and (.source_aware_queue_state.stale_in_progress_ids | type == "array")
    and (.source_aware_queue_state.next_safe_actions | type == "array")
    and (.local_graph_exports.schema_version == 1)
    and (.local_graph_exports.local_open.path | test("tracker_source_hygiene_local_open\\.jsonl$"))
    and (.local_graph_exports.source_aware_ready.path | test("tracker_source_hygiene_source_aware_ready\\.jsonl$"))
    and (.local_graph_exports.local_nonclaimable.path | test("tracker_source_hygiene_local_nonclaimable\\.jsonl$"))
    and (.local_graph_exports.local_open.checksum_path | test("\\.sha256$"))
    and (.local_graph_exports.source_aware_ready.checksum_path | test("\\.sha256$"))
    and (.local_graph_exports.local_nonclaimable.checksum_path | test("\\.sha256$"))
    and (.permission_gated_rows | type == "array")
    and (.local_nonclaimable_rows | type == "array")
    and (.foreign_open_samples | type == "array")
    and (.foreign_in_progress_samples | type == "array")
    and (.foreign_stale_in_progress_samples | type == "array")
    and (.excluded_foreign_by_prefix | type == "array")
    and (.foreign_group_summaries | type == "array")
    and (.reproduction_commands | type == "array")
    and (.mutation_policy | test("report-only"))
' "$REPORT_JSON" >/dev/null; then
    scenario_result "tracker_source_hygiene_report_emitted" "PASS" "report=$REPORT_JSON"
else
    scenario_result "tracker_source_hygiene_report_emitted" "FAIL" "report schema check failed"
fi

e2e_step "Emit local-only tracker graph artifacts"
if jq -c --slurpfile report "$REPORT_JSON" \
    '(.id // "") as $issue_id | select(($report[0].local_open_ids | index($issue_id)) != null)' \
    "$ISSUES_JSONL" >"$LOCAL_OPEN_JSONL" \
    && jq -c --slurpfile report "$REPORT_JSON" \
        '(.id // "") as $issue_id | ($report[0].source_aware_ready_rows | map(.id)) as $ready_ids | select(($ready_ids | index($issue_id)) != null)' \
        "$ISSUES_JSONL" >"$SOURCE_AWARE_READY_JSONL" \
    && jq -c '.local_nonclaimable_rows[]' "$REPORT_JSON" >"$LOCAL_NONCLAIMABLE_JSONL" \
    && sha256sum "$LOCAL_OPEN_JSONL" >"$LOCAL_OPEN_SHA256" \
    && sha256sum "$SOURCE_AWARE_READY_JSONL" >"$SOURCE_AWARE_READY_SHA256" \
    && sha256sum "$LOCAL_NONCLAIMABLE_JSONL" >"$LOCAL_NONCLAIMABLE_SHA256"; then
    scenario_result "tracker_source_hygiene_local_graph_exports_written" "PASS" "local_open=$LOCAL_OPEN_JSONL ready=$SOURCE_AWARE_READY_JSONL"
else
    scenario_result "tracker_source_hygiene_local_graph_exports_written" "FAIL" "failed to write local graph exports"
fi

FOREIGN_OPEN_COUNT="$(jq -r '.foreign_open' "$REPORT_JSON")"
FOREIGN_IN_PROGRESS_COUNT="$(jq -r '.foreign_in_progress' "$REPORT_JSON")"
FOREIGN_STALE_IN_PROGRESS_COUNT="$(jq -r '.excluded_foreign_stale_in_progress_count' "$REPORT_JSON")"
LOCAL_OPEN_COUNT="$(jq -r '.local_open' "$REPORT_JSON")"
READY_COUNT="$(jq -r '.source_aware_ready_rows | length' "$REPORT_JSON")"
LOCAL_NONCLAIMABLE_COUNT="$(jq -r '.local_nonclaimable_rows | length' "$REPORT_JSON")"
LOCAL_IN_PROGRESS_COUNT="$(jq -r '.source_aware_queue_state.local_in_progress_count' "$REPORT_JSON")"
if [[ "$FOREIGN_OPEN_COUNT" =~ ^[0-9]+$ && "$LOCAL_OPEN_COUNT" =~ ^[0-9]+$ ]]; then
    scenario_result "tracker_source_hygiene_foreign_rows_classified" "PASS" "local_open=${LOCAL_OPEN_COUNT} source_aware_ready=${READY_COUNT} foreign_open=${FOREIGN_OPEN_COUNT}"
else
    scenario_result "tracker_source_hygiene_foreign_rows_classified" "FAIL" "invalid open counts in $REPORT_JSON"
fi
if [[ "$FOREIGN_IN_PROGRESS_COUNT" =~ ^[0-9]+$ && "$FOREIGN_STALE_IN_PROGRESS_COUNT" =~ ^[0-9]+$ ]]; then
    scenario_result "tracker_source_hygiene_foreign_in_progress_classified" "PASS" "foreign_in_progress=${FOREIGN_IN_PROGRESS_COUNT} foreign_stale_in_progress=${FOREIGN_STALE_IN_PROGRESS_COUNT}"
else
    scenario_result "tracker_source_hygiene_foreign_in_progress_classified" "FAIL" "invalid foreign in-progress counts in $REPORT_JSON"
fi

if jq -s --slurpfile report "$REPORT_JSON" '
    def local_issue:
        ((.id // "") | test("^(bd|frankenfs)-"));
    def open_issue:
        ((.status // "open") == "open");
    def sorted_ids:
        map(.id // "") | sort;
    (length == $report[0].local_graph_exports.local_open.row_count)
    and (sorted_ids == ($report[0].local_open_ids | sort))
    and all(.[]; local_issue and open_issue)
' "$LOCAL_OPEN_JSONL" >/dev/null \
    && jq -s --slurpfile report "$REPORT_JSON" '
        def local_issue:
            ((.id // "") | test("^(bd|frankenfs)-"));
        def open_issue:
            ((.status // "open") == "open");
        def sorted_ids:
            map(.id // "") | sort;
        (length == $report[0].local_graph_exports.source_aware_ready.row_count)
        and (sorted_ids == ($report[0].source_aware_ready_rows | map(.id) | sort))
        and all(.[]; local_issue and open_issue)
    ' "$SOURCE_AWARE_READY_JSONL" >/dev/null \
    && sha256sum -c "$LOCAL_OPEN_SHA256" >/dev/null \
    && sha256sum -c "$SOURCE_AWARE_READY_SHA256" >/dev/null \
    && sha256sum -c "$LOCAL_NONCLAIMABLE_SHA256" >/dev/null; then
    scenario_result "tracker_source_hygiene_local_graph_exports_valid" "PASS" "local_open=${LOCAL_OPEN_COUNT} source_aware_ready=${READY_COUNT}"
else
    scenario_result "tracker_source_hygiene_local_graph_exports_valid" "FAIL" "local graph export validation failed"
fi

e2e_step "Verify source-aware bv triage"
if command -v br >/dev/null 2>&1 && command -v bv >/dev/null 2>&1; then
    if sha256sum "$ISSUES_JSONL" >"$SOURCE_SHA256" \
        && mkdir -p "$BV_SOURCE_AWARE_BEADS_DIR" \
        && jq -c -s '
            def local_id($id):
                (($id // "") | test("^(bd|frankenfs)-"));
            def supported_status:
                (.status // "open") as $status
                | (["open", "in_progress", "blocked", "deferred", "closed", "tombstone"] | index($status)) != null;
            def normalize_row:
                (.id // "") as $issue_id
                | .description = (.description // .notes // "")
                | .status = (.status // "open")
                | .priority = (.priority // 2)
                | .issue_type = (.issue_type // "task")
                | .created_at = (.created_at // "2026-01-01T00:00:00Z")
                | .created_by = (.created_by // "tracker-source-hygiene-e2e")
                | .updated_at = (.updated_at // .created_at)
                | .source_repo = (.source_repo // ".")
                | .compaction_level = (.compaction_level // 0)
                | .original_size = (.original_size // 0)
                | .labels = (.labels // [])
                | .dependencies = (
                    (.dependencies // [])
                    | map(
                        select(local_id(.depends_on_id))
                        | .issue_id = (.issue_id // $issue_id)
                        | .created_at = (.created_at // "2026-01-01T00:00:00Z")
                        | .created_by = (.created_by // "tracker-source-hygiene-e2e")
                        | .metadata = (.metadata // "{}")
                        | .thread_id = (.thread_id // "")
                    )
                );
            def synthetic_dependency($id):
                {
                    id: $id,
                    title: "Synthetic local dependency placeholder for source-aware bv import",
                    description: "Unresolved dependency placeholder in the temporary graph. Its source row is missing or excluded; it is not completed work.",
                    status: "blocked",
                    priority: 4,
                    issue_type: "task",
                    created_at: "2026-01-01T00:00:00Z",
                    created_by: "tracker-source-hygiene-e2e",
                    updated_at: "2026-01-01T00:00:00Z",
                    source_repo: ".",
                    compaction_level: 0,
                    original_size: 0,
                    labels: ["tracker-source-hygiene", "synthetic-temp"],
                    dependencies: []
                };
            . as $source_rows
            | ([.[] | select(local_id(.id) and supported_status)] | sort_by(.id)) as $local_rows
            | ($local_rows | map(.id) | unique) as $local_ids
            | ($local_rows | [ .[] | (.dependencies // [])[]? | .depends_on_id // empty | select(local_id(.)) ] | unique) as $dependency_ids
            | ($dependency_ids - $local_ids) as $missing_ids
            | {
                included_source_rows: $local_rows,
                excluded_source_rows: [
                    $source_rows[]
                    | if (local_id(.id) | not) then {reason: "foreign_id", row: .}
                      elif (supported_status | not) then {reason: "unsupported_bv_status", row: .}
                      else empty end
                ],
                synthetic_dependency_ids: $missing_ids,
                graph_rows: (($local_rows | map(normalize_row)) + ($missing_ids | map(synthetic_dependency(.))))
            }
            ' "$ISSUES_JSONL" >"$BV_SOURCE_AWARE_PROJECTION_JSON" \
        && jq -e --slurpfile source "$ISSUES_JSONL" '
            ((.included_source_rows + [.excluded_source_rows[].row] | sort_by(.id)) == ($source | sort_by(.id)))
            and ((.graph_rows | map(.id) | unique | length) == (.graph_rows | length))
            and ([.included_source_rows[] | {id, status: (.status // "open")}] as $included
                | [.graph_rows[] | select(.id as $id | ($included | map(.id) | index($id)) != null)
                    | {id, status}] | sort_by(.id) == ($included | sort_by(.id)))
            ' "$BV_SOURCE_AWARE_PROJECTION_JSON" >/dev/null \
        && jq -c '.graph_rows[]' "$BV_SOURCE_AWARE_PROJECTION_JSON" >"$BV_SOURCE_AWARE_ISSUES_JSONL" \
        && BEADS_DIR="$BV_SOURCE_AWARE_BEADS_DIR" br --db "$BV_SOURCE_AWARE_BEADS_DIR/beads.db" sync --import-only --orphans allow --json >"$BV_SOURCE_AWARE_IMPORT_JSON" \
        && bv --no-cache --db "$BV_SOURCE_AWARE_BEADS_DIR" --robot-triage >"$BV_SOURCE_AWARE_TRIAGE_JSON" \
        && bv_projection_valid "$BV_SOURCE_AWARE_TRIAGE_JSON" \
        && sha256sum -c "$SOURCE_SHA256" >/dev/null; then
        scenario_result "tracker_source_hygiene_bv_source_aware_triage_clean" "PASS" "triage=$BV_SOURCE_AWARE_TRIAGE_JSON local_open=${LOCAL_OPEN_COUNT} local_in_progress=${LOCAL_IN_PROGRESS_COUNT}"
        PARTIAL_TRIAGE_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_bv_partial_negative.json"
        if jq '.source_authority.state = "partial" | .source_authority.claim_safe = false' \
            "$BV_SOURCE_AWARE_TRIAGE_JSON" >"$PARTIAL_TRIAGE_JSON" \
            && ! bv_projection_valid "$PARTIAL_TRIAGE_JSON"; then
            scenario_result "tracker_source_hygiene_partial_graph_rejected" "PASS" "partial graph cannot pass projection validation"
        else
            scenario_result "tracker_source_hygiene_partial_graph_rejected" "FAIL" "partial graph accepted"
        fi
    else
        scenario_result "tracker_source_hygiene_bv_source_aware_triage_clean" "FAIL" "source-aware bv triage failed"
    fi
else
    scenario_result "tracker_source_hygiene_bv_source_aware_triage_clean" "FAIL" "br or bv not found"
fi

if jq -s --slurpfile report "$REPORT_JSON" '
    def sorted_ids:
        map(.id // "") | sort;
    (length == $report[0].local_graph_exports.local_nonclaimable.row_count)
    and (sorted_ids == ($report[0].local_nonclaimable_rows | map(.id) | sort))
    and all(.[]; (.reason as $reason | (["epic", "permission_gated", "blocked"] | index($reason)) != null))
    and all(.[] | select(.reason == "permission_gated"); (.permission_gate.present == false))
    and all(.[] | select(.reason == "blocked"); (.blocked_by | length) > 0)
    and all(.[] | select(.reason == "epic"); ((.issue_type // "") == "epic"))
' "$LOCAL_NONCLAIMABLE_JSONL" >/dev/null; then
    scenario_result "tracker_source_hygiene_local_nonclaimable_exports_valid" "PASS" "local_nonclaimable=${LOCAL_NONCLAIMABLE_COUNT}"
else
    scenario_result "tracker_source_hygiene_local_nonclaimable_exports_valid" "FAIL" "local nonclaimable export validation failed"
fi

if jq -e '
    (.local_open_rows | type == "array")
    and (.source_aware_ready_rows | type == "array")
    and (.permission_gated_rows | type == "array")
    and (.blocked_local_rows | type == "array")
    and (.local_nonclaimable_rows | type == "array")
    and (.local_in_progress_rows | type == "array")
    and (.stale_in_progress_rows | type == "array")
    and (.foreign_in_progress_samples | type == "array")
    and (.foreign_stale_in_progress_samples | type == "array")
    and ((.foreign_reconciliation_plan.groups | length) == (.foreign_group_summaries | length))
    and (.foreign_reconciliation_plan.authorization_required == ((.foreign_group_summaries | length) > 0))
    and (.foreign_reconciliation_plan.conservation_check_required == ((.foreign_group_summaries | length) > 0))
    and all(.foreign_reconciliation_plan.groups[]; .authorization_required == true and .recommended_thread_id == "tracker-hygiene")
    and all(.source_aware_ready_rows[]; (.blocked_by | length) == 0)
    and all(.source_aware_ready_rows[]; has("permission_gate") | not)
    and all(.permission_gated_rows[]; (.permission_gate.present == false))
    and all(.blocked_local_rows[]; (.blocked_by | length) > 0)
    and all(.local_nonclaimable_rows[]; (.reason as $reason | (["epic", "permission_gated", "blocked"] | index($reason)) != null))
    and all(.local_in_progress_rows[]; .status == "in_progress")
    and all(.stale_in_progress_rows[]; .status == "in_progress" and .stale == true)
    and all(.foreign_in_progress_samples[]; .status == "in_progress")
    and all(.foreign_stale_in_progress_samples[]; .status == "in_progress" and .stale == true)
    and (.source_aware_queue_state.claimable_ids == (.source_aware_ready_rows | map(.id)))
    and (.source_aware_queue_state.permission_gated_ids == (.permission_gated_rows | map(.id)))
    and (.source_aware_queue_state.blocked_local_ids == (.blocked_local_rows | map(.id)))
    and (.source_aware_queue_state.local_nonclaimable_ids == (.local_nonclaimable_rows | map(.id)))
    and (.source_aware_queue_state.local_in_progress_ids == (.local_in_progress_rows | map(.id)))
    and (.source_aware_queue_state.stale_in_progress_ids == (.stale_in_progress_rows | map(.id)))
    and (
        if .source_aware_queue_state.verdict == "blocked_or_permission_gated" then
            ((.source_aware_queue_state.next_safe_actions | index("inspect blocked_local_ids and unblock prerequisites first")) != null)
            and ((.source_aware_queue_state.next_safe_actions | index("request the exact permission ACK before running permissioned rows")) != null)
            and ((.source_aware_queue_state.next_safe_actions | index("create or claim only non-mutating fallback work")) != null)
        else
            true
        end
    )
    and any(.reproduction_commands[]; contains("bd|frankenfs"))
' "$REPORT_JSON" >/dev/null; then
    scenario_result "tracker_source_hygiene_source_aware_wrapper" "PASS" "ready_rows=${READY_COUNT} excluded_foreign=${FOREIGN_OPEN_COUNT}"
else
    scenario_result "tracker_source_hygiene_source_aware_wrapper" "FAIL" "source-aware wrapper fields missing or inconsistent"
fi

if [[ -n "$EXPECTED_GOLDEN" ]]; then
    if jq -S '
        .run_id = "[RUN_ID]"
        | .created_at = "[TIMESTAMP]"
        | .issues_path = "[ISSUES_JSONL]"
        | .local_graph_exports.local_open.path = "[LOCAL_OPEN_JSONL]"
        | .local_graph_exports.local_open.checksum_path = "[LOCAL_OPEN_SHA256]"
        | .local_graph_exports.source_aware_ready.path = "[SOURCE_AWARE_READY_JSONL]"
        | .local_graph_exports.source_aware_ready.checksum_path = "[SOURCE_AWARE_READY_SHA256]"
        | .local_graph_exports.local_nonclaimable.path = "[LOCAL_NONCLAIMABLE_JSONL]"
        | .local_graph_exports.local_nonclaimable.checksum_path = "[LOCAL_NONCLAIMABLE_SHA256]"
    ' "$REPORT_JSON" >"$REPORT_CANONICAL_JSON" \
        && diff -u "$EXPECTED_GOLDEN" "$REPORT_CANONICAL_JSON" >"${REPORT_CANONICAL_JSON}.diff"; then
        scenario_result "tracker_source_hygiene_golden_report_matches" "PASS" "golden=$EXPECTED_GOLDEN"
    else
        scenario_result "tracker_source_hygiene_golden_report_matches" "FAIL" "golden mismatch diff=${REPORT_CANONICAL_JSON}.diff"
    fi
fi

if [[ "$EXPECT_GOLDEN_MISMATCH" -eq 1 ]]; then
    if jq '.source_aware_queue_state.verdict = "intentional-mismatch-for-fail-closed-test"' \
        "$EXPECTED_GOLDEN" >"$REPORT_MISMATCH_GOLDEN_JSON" \
        && ! diff -u "$REPORT_MISMATCH_GOLDEN_JSON" "$REPORT_CANONICAL_JSON" >"${REPORT_MISMATCH_GOLDEN_JSON}.diff"; then
        scenario_result "tracker_source_hygiene_golden_mismatch_fails_closed" "PASS" "diff=${REPORT_MISMATCH_GOLDEN_JSON}.diff"
    else
        scenario_result "tracker_source_hygiene_golden_mismatch_fails_closed" "FAIL" "mismatched golden was not rejected"
    fi
fi

EXPECTATION_DETAIL=""
EXPECTATION_FAILED=0

check_expected_count() {
    local field_name="$1"
    local actual="$2"
    local expected="$3"

    if [[ -z "$expected" ]]; then
        return 0
    fi

    EXPECTATION_DETAIL="${EXPECTATION_DETAIL}${field_name}=${actual}/${expected} "
    if [[ "$actual" != "$expected" ]]; then
        EXPECTATION_FAILED=1
    fi
}

EXPECTED_LOCAL_OPEN="${TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN:-}"
EXPECTED_FOREIGN_OPEN="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN:-}"
EXPECTED_READY="${TRACKER_SOURCE_HYGIENE_EXPECT_READY:-}"
EXPECTED_PERMISSION_GATED="${TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED:-}"
EXPECTED_LOCAL_NONCLAIMABLE="${TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE:-}"
EXPECTED_IN_PROGRESS="${TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS:-}"
EXPECTED_STALE_IN_PROGRESS="${TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS:-}"
EXPECTED_FOREIGN_IN_PROGRESS="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_IN_PROGRESS:-}"
EXPECTED_FOREIGN_STALE_IN_PROGRESS="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_STALE_IN_PROGRESS:-}"
EXPECTED_FOREIGN_SAMPLE_COUNT="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT:-}"
EXPECTED_FOREIGN_GROUP_COUNT="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_GROUP_COUNT:-}"
FOREIGN_SAMPLE_COUNT="$(jq -r '.foreign_open_samples | length' "$REPORT_JSON")"
FOREIGN_GROUP_COUNT="$(jq -r '.foreign_group_summaries | length' "$REPORT_JSON")"
PERMISSION_GATED_COUNT="$(jq -r '.permission_gated_rows | length' "$REPORT_JSON")"
IN_PROGRESS_COUNT="$(jq -r '.local_in_progress_rows | length' "$REPORT_JSON")"
STALE_IN_PROGRESS_COUNT="$(jq -r '.stale_in_progress_rows | length' "$REPORT_JSON")"

check_expected_count "local_open" "$LOCAL_OPEN_COUNT" "$EXPECTED_LOCAL_OPEN"
check_expected_count "foreign_open" "$FOREIGN_OPEN_COUNT" "$EXPECTED_FOREIGN_OPEN"
check_expected_count "source_aware_ready" "$READY_COUNT" "$EXPECTED_READY"
check_expected_count "permission_gated" "$PERMISSION_GATED_COUNT" "$EXPECTED_PERMISSION_GATED"
check_expected_count "local_nonclaimable" "$LOCAL_NONCLAIMABLE_COUNT" "$EXPECTED_LOCAL_NONCLAIMABLE"
check_expected_count "local_in_progress" "$IN_PROGRESS_COUNT" "$EXPECTED_IN_PROGRESS"
check_expected_count "stale_in_progress" "$STALE_IN_PROGRESS_COUNT" "$EXPECTED_STALE_IN_PROGRESS"
check_expected_count "foreign_in_progress" "$FOREIGN_IN_PROGRESS_COUNT" "$EXPECTED_FOREIGN_IN_PROGRESS"
check_expected_count "foreign_stale_in_progress" "$FOREIGN_STALE_IN_PROGRESS_COUNT" "$EXPECTED_FOREIGN_STALE_IN_PROGRESS"
check_expected_count "foreign_sample_count" "$FOREIGN_SAMPLE_COUNT" "$EXPECTED_FOREIGN_SAMPLE_COUNT"
check_expected_count "foreign_group_count" "$FOREIGN_GROUP_COUNT" "$EXPECTED_FOREIGN_GROUP_COUNT"

if [[ -n "$EXPECTATION_DETAIL" ]]; then
    if [[ "$EXPECTATION_FAILED" -eq 0 ]]; then
        scenario_result "tracker_source_hygiene_expected_fixture_counts" "PASS" "${EXPECTATION_DETAIL% }"
    else
        scenario_result "tracker_source_hygiene_expected_fixture_counts" "FAIL" "${EXPECTATION_DETAIL% }"
    fi
fi

if [[ "$DEFAULT_FIXTURE_SELF_CHECK" -eq 1 \
    && -z "${TRACKER_SOURCE_HYGIENE_ISSUES:-}" \
    && -z "$EXPECTED_GOLDEN" \
    && "$STRICT_MODE" -eq 0 ]]; then
    e2e_step "Default fixture/golden self-check"
    if TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_ISSUES="$DEFAULT_FIXTURE_ISSUES" \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=6 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=27 \
        TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=4 \
        TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_IN_PROGRESS=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_STALE_IN_PROGRESS=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT=20 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_GROUP_COUNT=4 \
        TRACKER_SOURCE_HYGIENE_NOW_EPOCH=2000000000 \
        TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS=3600 \
        TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN="$DEFAULT_FIXTURE_GOLDEN" \
        TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN_MISMATCH=1 \
        "$REPO_ROOT/scripts/e2e/ffs_tracker_source_hygiene_e2e.sh" \
        >"$FIXTURE_SELF_CHECK_LOG" 2>&1; then
        scenario_result "tracker_source_hygiene_default_fixture_golden_self_check" "PASS" "log=$FIXTURE_SELF_CHECK_LOG"
    else
        scenario_result "tracker_source_hygiene_default_fixture_golden_self_check" "FAIL" "log=$FIXTURE_SELF_CHECK_LOG"
    fi
fi

if [[ "$PERMISSION_ACK_SELF_CHECK" -eq 1 \
    && -z "${TRACKER_SOURCE_HYGIENE_ISSUES:-}" \
    && -z "$EXPECTED_GOLDEN" \
    && "$STRICT_MODE" -eq 0 ]]; then
    e2e_step "Permission ACK fixture self-check"
    PERMISSION_ACK_CHECK_FAILED=0
    PERMISSION_ACK_DETAIL=""

    if TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_NON_MUTATING_FALLBACK_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_PERMISSION_GATED_BLOCKED_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_PERMISSION_ACK_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_ISSUES="$DEFAULT_FIXTURE_ISSUES" \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=6 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=27 \
        TRACKER_SOURCE_HYGIENE_EXPECT_READY=3 \
        TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=0 \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=3 \
        TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_IN_PROGRESS=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_STALE_IN_PROGRESS=1 \
        TRACKER_SOURCE_HYGIENE_NOW_EPOCH=2000000000 \
        TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS=3600 \
        XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices \
        "$REPO_ROOT/scripts/e2e/ffs_tracker_source_hygiene_e2e.sh" \
        >"$PERMISSION_ACK_XFSTESTS_SELF_CHECK_LOG" 2>&1; then
        PERMISSION_ACK_XFSTESTS_REPORT="$(
            awk -F'detail=report=' \
                '/scenario_id=tracker_source_hygiene_report_emitted/ && /outcome=PASS/ { print $2; exit }' \
                "$PERMISSION_ACK_XFSTESTS_SELF_CHECK_LOG"
        )"
        if [[ -n "$PERMISSION_ACK_XFSTESTS_REPORT" ]] \
            && jq -e '
                (.source_aware_queue_state.claimable_ids == [
                    "bd-fixture-permissioned",
                    "bd-fixture-ready",
                    "bd-fixture-blocker"
                ])
                and (.source_aware_queue_state.permission_gated_ids == [])
                and (.source_aware_queue_state.blocked_local_ids == [
                    "bd-fixture-permissioned-blocked",
                    "bd-fixture-blocked"
                ])
                and (.source_aware_queue_state.local_nonclaimable_ids == [
                    "bd-fixture-epic",
                    "bd-fixture-permissioned-blocked",
                    "bd-fixture-blocked"
                ])
                and ([
                    .local_nonclaimable_rows[]
                    | select(.id == "bd-fixture-permissioned-blocked")
                    | .reason
                ] == ["blocked"])
            ' "$PERMISSION_ACK_XFSTESTS_REPORT" >/dev/null; then
            PERMISSION_ACK_DETAIL="${PERMISSION_ACK_DETAIL}xfstests_report=$PERMISSION_ACK_XFSTESTS_REPORT "
        else
            PERMISSION_ACK_CHECK_FAILED=1
            PERMISSION_ACK_DETAIL="${PERMISSION_ACK_DETAIL}xfstests_report=${PERMISSION_ACK_XFSTESTS_REPORT:-missing} "
        fi
    else
        PERMISSION_ACK_CHECK_FAILED=1
        PERMISSION_ACK_DETAIL="${PERMISSION_ACK_DETAIL}xfstests_log=$PERMISSION_ACK_XFSTESTS_SELF_CHECK_LOG "
    fi

    cat >"$PERMISSION_ACK_SWARM_FIXTURE" <<'JSONL'
{"id":"bd-swarm","title":"permissioned large-host swarm campaign","description":"requires FFS_SWARM_WORKLOAD_REAL_RUN_ACK before using a large host","status":"open","priority":1}
JSONL

    if TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_NON_MUTATING_FALLBACK_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_PERMISSION_GATED_BLOCKED_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_PERMISSION_ACK_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_ISSUES="$PERMISSION_ACK_SWARM_FIXTURE" \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=0 \
        TRACKER_SOURCE_HYGIENE_EXPECT_READY=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=0 \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=0 \
        FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 \
        FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host \
        "$REPO_ROOT/scripts/e2e/ffs_tracker_source_hygiene_e2e.sh" \
        >"$PERMISSION_ACK_SWARM_SELF_CHECK_LOG" 2>&1; then
        PERMISSION_ACK_SWARM_REPORT="$(
            awk -F'detail=report=' \
                '/scenario_id=tracker_source_hygiene_report_emitted/ && /outcome=PASS/ { print $2; exit }' \
                "$PERMISSION_ACK_SWARM_SELF_CHECK_LOG"
        )"
        if [[ -n "$PERMISSION_ACK_SWARM_REPORT" ]] \
            && jq -e '
                (.source_aware_queue_state.claimable_ids == ["bd-swarm"])
                and (.source_aware_queue_state.permission_gated_ids == [])
                and (.permission_gated_rows == [])
                and (.source_aware_queue_state.verdict == "ready")
            ' "$PERMISSION_ACK_SWARM_REPORT" >/dev/null; then
            PERMISSION_ACK_DETAIL="${PERMISSION_ACK_DETAIL}swarm_report=$PERMISSION_ACK_SWARM_REPORT"
        else
            PERMISSION_ACK_CHECK_FAILED=1
            PERMISSION_ACK_DETAIL="${PERMISSION_ACK_DETAIL}swarm_report=${PERMISSION_ACK_SWARM_REPORT:-missing}"
        fi
    else
        PERMISSION_ACK_CHECK_FAILED=1
        PERMISSION_ACK_DETAIL="${PERMISSION_ACK_DETAIL}swarm_log=$PERMISSION_ACK_SWARM_SELF_CHECK_LOG"
    fi

    if [[ "$PERMISSION_ACK_CHECK_FAILED" -eq 0 ]]; then
        scenario_result "tracker_source_hygiene_permission_ack_self_check" "PASS" "${PERMISSION_ACK_DETAIL% }"
    else
        scenario_result "tracker_source_hygiene_permission_ack_self_check" "FAIL" "${PERMISSION_ACK_DETAIL% }"
    fi
fi

if [[ "$NON_MUTATING_FALLBACK_SELF_CHECK" -eq 1 \
    && -z "${TRACKER_SOURCE_HYGIENE_ISSUES:-}" \
    && -z "$EXPECTED_GOLDEN" \
    && "$STRICT_MODE" -eq 0 ]]; then
    e2e_step "Non-mutating fallback fixture self-check"
    cat >"$NON_MUTATING_FALLBACK_FIXTURE" <<'JSONL'
{"id":"bd-fallback","title":"Add a non-mutating fallback validator","description":"This is non-mutating fallback work for blocked queues. It must not run xfstests baseline execution, mounted mutation, or a large-host swarm campaign; it only validates local-safe report text.","status":"open","priority":1}
{"id":"bd-real-xfstests","title":"execute xfstests baseline","description":"requires real xfstests run before publishing pass/fail artifacts","status":"open","priority":1}
{"id":"bd-real-swarm","title":"permissioned large-host swarm campaign","description":"requires FFS_SWARM_WORKLOAD_REAL_RUN_ACK before using a large host","status":"open","priority":1}
JSONL

    if TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_NON_MUTATING_FALLBACK_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_ISSUES="$NON_MUTATING_FALLBACK_FIXTURE" \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=3 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=0 \
        TRACKER_SOURCE_HYGIENE_EXPECT_READY=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=2 \
        "$REPO_ROOT/scripts/e2e/ffs_tracker_source_hygiene_e2e.sh" \
        >"$NON_MUTATING_FALLBACK_SELF_CHECK_LOG" 2>&1; then
        FALLBACK_REPORT="$(
            awk -F'detail=report=' \
                '/scenario_id=tracker_source_hygiene_report_emitted/ && /outcome=PASS/ { print $2; exit }' \
                "$NON_MUTATING_FALLBACK_SELF_CHECK_LOG"
        )"
        if [[ -n "$FALLBACK_REPORT" ]] \
            && jq -e '
                (.source_aware_queue_state.claimable_ids == ["bd-fallback"])
                and (
                    [.permission_gated_rows[] | {id, gate_kind: .permission_gate.gate_kind}]
                    | sort_by(.id)
                ) == [
                    {id: "bd-real-swarm", gate_kind: "large_host_swarm_real_run"},
                    {id: "bd-real-xfstests", gate_kind: "xfstests_real_run"}
                ]
            ' "$FALLBACK_REPORT" >/dev/null; then
            scenario_result "tracker_source_hygiene_non_mutating_fallback_self_check" "PASS" "log=$NON_MUTATING_FALLBACK_SELF_CHECK_LOG report=$FALLBACK_REPORT"
        else
            scenario_result "tracker_source_hygiene_non_mutating_fallback_self_check" "FAIL" "log=$NON_MUTATING_FALLBACK_SELF_CHECK_LOG report=${FALLBACK_REPORT:-missing}"
        fi
    else
        scenario_result "tracker_source_hygiene_non_mutating_fallback_self_check" "FAIL" "log=$NON_MUTATING_FALLBACK_SELF_CHECK_LOG"
    fi
fi

if [[ "$PERMISSION_GATED_BLOCKED_SELF_CHECK" -eq 1 \
    && -z "${TRACKER_SOURCE_HYGIENE_ISSUES:-}" \
    && -z "$EXPECTED_GOLDEN" \
    && "$STRICT_MODE" -eq 0 ]]; then
    e2e_step "Permission-gated blocked fixture self-check"
    cat >"$PERMISSION_GATED_BLOCKED_FIXTURE" <<'JSONL'
{"id":"bd-real-xfstests","title":"execute xfstests baseline after dependency triage","description":"requires real xfstests run before publishing pass/fail artifacts","status":"open","priority":1,"dependencies":[{"type":"blocks","depends_on_id":"bd-missing-prereq"}]}
JSONL

    if TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_NON_MUTATING_FALLBACK_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_PERMISSION_GATED_BLOCKED_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_ISSUES="$PERMISSION_GATED_BLOCKED_FIXTURE" \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=0 \
        TRACKER_SOURCE_HYGIENE_EXPECT_READY=0 \
        TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=1 \
        "$REPO_ROOT/scripts/e2e/ffs_tracker_source_hygiene_e2e.sh" \
        >"$PERMISSION_GATED_BLOCKED_SELF_CHECK_LOG" 2>&1; then
        PERMISSION_GATED_BLOCKED_REPORT="$(
            awk -F'detail=report=' \
                '/scenario_id=tracker_source_hygiene_report_emitted/ && /outcome=PASS/ { print $2; exit }' \
                "$PERMISSION_GATED_BLOCKED_SELF_CHECK_LOG"
        )"
        if [[ -n "$PERMISSION_GATED_BLOCKED_REPORT" ]] \
            && jq -e '
                (.source_aware_queue_state.verdict == "blocked_or_permission_gated")
                and (.source_aware_queue_state.local_open_count == 1)
                and (.source_aware_queue_state.blocked_local_ids == ["bd-real-xfstests"])
                and (.source_aware_queue_state.permission_gated_ids == ["bd-real-xfstests"])
                and (.blocked_local_rows[0].blocked_by == [{"id": "bd-missing-prereq", "status": "missing"}])
                and (.permission_gated_rows[0].blocked_by == [{"id": "bd-missing-prereq", "status": "missing"}])
                and (.local_nonclaimable_rows[0].reason == "permission_gated")
                and (.local_nonclaimable_rows[0].permission_gate.gate_kind == "xfstests_real_run")
                and ((.source_aware_queue_state.next_safe_actions | index("inspect blocked_local_ids and unblock prerequisites first")) != null)
                and ((.source_aware_queue_state.next_safe_actions | index("request the exact permission ACK before running permissioned rows")) != null)
                and ((.source_aware_queue_state.next_safe_actions | index("create or claim only non-mutating fallback work")) != null)
            ' "$PERMISSION_GATED_BLOCKED_REPORT" >/dev/null; then
            scenario_result "tracker_source_hygiene_permission_gated_blocked_self_check" "PASS" "log=$PERMISSION_GATED_BLOCKED_SELF_CHECK_LOG report=$PERMISSION_GATED_BLOCKED_REPORT"
        else
            scenario_result "tracker_source_hygiene_permission_gated_blocked_self_check" "FAIL" "log=$PERMISSION_GATED_BLOCKED_SELF_CHECK_LOG report=${PERMISSION_GATED_BLOCKED_REPORT:-missing}"
        fi
    else
        scenario_result "tracker_source_hygiene_permission_gated_blocked_self_check" "FAIL" "log=$PERMISSION_GATED_BLOCKED_SELF_CHECK_LOG"
    fi
fi

if [[ "$RELEASE_READY_P0_SELF_CHECK" -eq 1 \
    && -z "${TRACKER_SOURCE_HYGIENE_ISSUES:-}" \
    && -z "$EXPECTED_GOLDEN" \
    && "$STRICT_MODE" -eq 0 ]]; then
    e2e_step "Release-ready P0 blocker self-check"
    cat >"$RELEASE_READY_P0_FIXTURE" <<'JSONL'
{"id":"bd-p0-live","title":"P0 data-loss bug still open","description":"Any public release-ready or readiness claim must stay blocked while this row is open.","status":"open","priority":0,"issue_type":"bug"}
{"id":"bd-release-ready-claim","title":"publish release-ready readiness claim","description":"This claim is only safe after every open P0 row is closed.","status":"open","priority":2,"issue_type":"docs"}
{"id":"bd-p0-closed","title":"closed P0 should not block release-ready wording","status":"closed","priority":0,"issue_type":"bug"}
{"id":"frankenredis-p0","title":"foreign P0 belongs to another tracker","status":"open","priority":0,"issue_type":"bug"}
JSONL

    if TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_NON_MUTATING_FALLBACK_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_PERMISSION_GATED_BLOCKED_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_PERMISSION_ACK_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_RELEASE_READY_P0_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_ISSUES="$RELEASE_READY_P0_FIXTURE" \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=0 \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=0 \
        "$REPO_ROOT/scripts/e2e/ffs_tracker_source_hygiene_e2e.sh" \
        >"$RELEASE_READY_P0_SELF_CHECK_LOG" 2>&1; then
        RELEASE_READY_P0_REPORT="$(
            awk -F'detail=report=' \
                '/scenario_id=tracker_source_hygiene_report_emitted/ && /outcome=PASS/ { print $2; exit }' \
                "$RELEASE_READY_P0_SELF_CHECK_LOG"
        )"
        if [[ -n "$RELEASE_READY_P0_REPORT" ]] \
            && jq -e '
                ([.local_open_rows[] | select((.priority // 999) == 0) | .id] == ["bd-p0-live"])
                and any(.local_open_rows[]; .id == "bd-release-ready-claim" and ((.title + " " + (.description // "")) | test("release-ready|readiness"; "i")))
                and (.source_aware_queue_state.claimable_ids == ["bd-p0-live", "bd-release-ready-claim"])
                and (.foreign_open_samples | map(.id) == ["frankenredis-p0"])
            ' "$RELEASE_READY_P0_REPORT" >/dev/null; then
            scenario_result "tracker_source_hygiene_release_readiness_blocked_by_open_p0" "PASS" "log=$RELEASE_READY_P0_SELF_CHECK_LOG report=$RELEASE_READY_P0_REPORT p0_blocker=bd-p0-live"
        else
            scenario_result "tracker_source_hygiene_release_readiness_blocked_by_open_p0" "FAIL" "log=$RELEASE_READY_P0_SELF_CHECK_LOG report=${RELEASE_READY_P0_REPORT:-missing}"
        fi
    else
        scenario_result "tracker_source_hygiene_release_readiness_blocked_by_open_p0" "FAIL" "log=$RELEASE_READY_P0_SELF_CHECK_LOG"
    fi
fi

if [[ -z "${TRACKER_SOURCE_HYGIENE_ISSUES:-}" && -z "$EXPECTED_GOLDEN" && "$STRICT_MODE" -eq 0 ]]; then
    e2e_step "Unsupported-status and unresolved-dependency fixture self-check"
    PROJECTION_FIXTURE="$E2E_TEMP_DIR/tracker_source_hygiene_projection.jsonl"
    PROJECTION_CHECK_LOG="$E2E_LOG_DIR/tracker_source_hygiene_projection_self_check.log"
    cat >"$PROJECTION_FIXTURE" <<'JSONL'
{"id":"bd-ready","title":"ordinary ready work","status":"open","priority":2}
{"id":"bd-active","title":"owned work","status":"in_progress","priority":2}
{"id":"bd-refused","title":"explicitly not implemented","status":"wont_fix","priority":2,"notes":"preserve this disposition"}
{"id":"bd-unknown","title":"future status must not become ready","status":"future_terminal","priority":2}
{"id":"bd-dependent","title":"depends on refused work","status":"open","priority":2,"dependencies":[{"depends_on_id":"bd-refused","type":"blocks"}]}
{"id":"bd-missing-dependent","title":"depends on absent work","status":"open","priority":2,"dependencies":[{"depends_on_id":"bd-missing","type":"blocks"}]}
{"id":"bd-permission","title":"real xfstests run","description":"requires XFSTESTS_REAL_RUN_ACK","status":"open","priority":2}
{"id":"frankenredis-foreign","title":"foreign work","status":"open","priority":2}
JSONL
    if TRACKER_SOURCE_HYGIENE_ISSUES="$PROJECTION_FIXTURE" \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=4 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_READY=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=3 \
        TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS=1 \
        XFSTESTS_REAL_RUN_ACK= \
        "$REPO_ROOT/scripts/e2e/ffs_tracker_source_hygiene_e2e.sh" >"$PROJECTION_CHECK_LOG" 2>&1; then
        PROJECTION_CHECK_REPORT="$(awk -F'detail=report=' \
            '/scenario_id=tracker_source_hygiene_report_emitted/ && /outcome=PASS/ {print $2; exit}' \
            "$PROJECTION_CHECK_LOG")"
        PROJECTION_CHECK_ARTIFACT="${PROJECTION_CHECK_REPORT%/*}/tracker_source_hygiene_bv_projection.json"
        if jq -e '
            .source_aware_queue_state.claimable_ids == ["bd-ready"]
            and .source_aware_queue_state.permission_gated_ids == ["bd-permission"]
            and (.source_aware_queue_state.blocked_local_ids | sort) == ["bd-dependent", "bd-missing-dependent"]
            ' "$PROJECTION_CHECK_REPORT" >/dev/null \
            && jq -e '
                (.included_source_rows | length) == 5
                and (.excluded_source_rows | length) == 3
                and any(.excluded_source_rows[]; .row.id == "bd-refused" and .row.status == "wont_fix"
                    and .row.notes == "preserve this disposition" and .reason == "unsupported_bv_status")
                and any(.excluded_source_rows[]; .row.id == "bd-unknown" and .row.status == "future_terminal")
                and .synthetic_dependency_ids == ["bd-missing", "bd-refused"]
                and ([.graph_rows[] | select(.id == "bd-missing" or .id == "bd-refused") | .status] == ["blocked", "blocked"])
                ' "$PROJECTION_CHECK_ARTIFACT" >/dev/null; then
            scenario_result "tracker_source_hygiene_lossless_projection_self_check" "PASS" "report=$PROJECTION_CHECK_REPORT projection=$PROJECTION_CHECK_ARTIFACT"
        else
            scenario_result "tracker_source_hygiene_lossless_projection_self_check" "FAIL" "projection accounting or claimability mismatch; log=$PROJECTION_CHECK_LOG"
        fi
    else
        scenario_result "tracker_source_hygiene_lossless_projection_self_check" "FAIL" "log=$PROJECTION_CHECK_LOG"
    fi
fi

if [[ "$STRICT_MODE" -eq 1 && "$FOREIGN_OPEN_COUNT" -gt 0 ]]; then
    scenario_result "tracker_source_hygiene_strict_mode" "FAIL" "strict mode found foreign_open=${FOREIGN_OPEN_COUNT}"
else
    if [[ "$STRICT_MODE" -eq 1 ]]; then
        scenario_result "tracker_source_hygiene_strict_mode" "PASS" "strict mode found no foreign open rows"
    else
        scenario_result "tracker_source_hygiene_strict_mode" "PASS" "default_non_destructive foreign_open=${FOREIGN_OPEN_COUNT}"
    fi
fi

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    e2e_pass
else
    e2e_fail "Tracker source hygiene failed ${FAIL_COUNT}/${TOTAL} scenarios; report=$REPORT_JSON"
fi
