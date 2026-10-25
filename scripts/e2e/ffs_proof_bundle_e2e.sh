#!/usr/bin/env bash
# ffs_proof_bundle_e2e.sh - smoke gate for bd-rchk0.5.4.1.
#
# Builds an offline proof bundle with every release-readiness lane, validates
# links and SHA-256 hashes, emits JSON/Markdown reports, and proves fail-closed
# handling for stale or corrupted evidence.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_proof_bundle}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
RCH_CAPTURE_VISIBILITY="${FFS_PROOF_BUNDLE_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
SELF_CHECK="${FFS_PROOF_BUNDLE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_PROOF_BUNDLE_SKIP_SELF_CHECK:-0}"

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

run_rch_capture() {
    local log_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

extract_json_object() {
    local input_path="$1"
    local output_path="$2"
    local object_index="${3:-0}"
    python3 - "$input_path" "$output_path" "$object_index" <<'PY'
import json
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
target_index = int(sys.argv[3])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
seen = 0
pos = 0
while pos < len(text):
    idx = text.find("{", pos)
    if idx < 0:
        break
    try:
        _, end = decoder.raw_decode(text[idx:])
    except json.JSONDecodeError:
        pos = idx + 1
        continue
    if seen == target_index:
        dest.write_text(text[idx:idx + end].rstrip() + "\n", encoding="utf-8")
        raise SystemExit(0)
    seen += 1
    pos = idx + end
raise SystemExit(f"JSON object {target_index} not found in {source}")
PY
}

extract_markdown_report() {
    local input_path="$1"
    local output_path="$2"
    python3 - "$input_path" "$output_path" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
text = source.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
start = text.find("# FrankenFS Proof Bundle")
if start < 0:
    raise SystemExit(f"proof-bundle markdown report not found in {source}")
end = text.find("\n[RCH]", start)
if end < 0:
    end = text.find("\nRemote command finished:", start)
if end < 0:
    end = len(text)
dest.write_text(text[start:end].rstrip() + "\n", encoding="utf-8")
PY
}

e2e_init "ffs_proof_bundle"

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_PROOF_BUNDLE_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected proof-bundle fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    missing_remote_evidence)
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0" >&2
        ;;
    *)
        echo "unknown proof-bundle fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0" >&2
    fi
    exit 0
}

finish_failure() {
    local status="$1"
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=${status}" >&2
    fi
    exit "$status"
}

emit_validation_report() {
    python3 - <<'PY'
import json

lanes = [
    "conformance",
    "xfstests",
    "fuse",
    "differential_oracle",
    "repair_lab",
    "crash_replay",
    "performance",
    "swarm_workload_harness",
    "swarm_tail_latency",
    "writeback_cache",
    "scrub_repair_status",
    "known_deferrals",
    "release_gates",
    "adaptive_runtime",
]
statuses = ["pass", "fail", "skip", "error"]
report = {
    "valid": True,
    "totals": {"pass": 4, "fail": 4, "skip": 3, "error": 3},
    "artifact_hash_chain": {
        "artifact_hash_chain_sha256": "a" * 64,
        "redaction_policy_version": "redaction-v1",
    },
    "lanes": [],
    "artifact_reports": [],
    "swarm_evidence": [],
    "adaptive_runtime_evidence": [],
    "lane_provenance": [],
    "executed_evidence": [],
}

for index, lane in enumerate(lanes):
    status = "pass" if lane == "adaptive_runtime" else statuses[index % len(statuses)]
    report["lanes"].append(
        {
            "lane_id": lane,
            "status": status,
            "raw_log_path": f"logs/{lane}.log",
            "summary_path": f"summaries/{lane}.md",
        }
    )
    report["artifact_reports"].append(
        {
            "lane_id": lane,
            "path": f"artifacts/{lane}.json",
            "sha256": "b" * 64,
            "role": (
                "swarm_validator_report"
                if lane in {"swarm_workload_harness", "swarm_tail_latency"}
                else "adaptive_runtime_validator_report"
                if lane == "adaptive_runtime"
                else "primary_evidence"
            ),
        }
    )
    provenance_class = "executed_product_evidence"
    claim_effect = "context_only"
    if lane == "conformance":
        claim_effect = "strengthens_public_claim"
    if lane == "swarm_workload_harness":
        provenance_class = "small_host_smoke"
    if lane == "known_deferrals":
        provenance_class = "unsupported_future_scope"
    report["lane_provenance"].append(
        {
            "lane_id": lane,
            "provenance_class": provenance_class,
            "claim_effect": claim_effect,
            "source_command": f"cargo run -p ffs-harness -- validate-{lane}",
            "raw_log_path": f"logs/{lane}.log",
        }
    )
    if lane in {"conformance", "fuse", "repair_lab", "crash_replay"}:
        report["executed_evidence"].append(
            {
                "lane_id": lane,
                "command": "printf",
                "args": [f"{lane} executed\n"],
                "exit_code": 0,
                "stdout_sha256": "1" * 64,
                "stderr_sha256": "2" * 64,
                "duration_ms": 1,
                "ran_at": 1770000000,
                "git_sha": "fixture-git-sha",
                "host_class": "rch_worker",
                "outcome": "success",
            }
        )

report["artifact_reports"].extend(
    [
        {
            "lane_id": "swarm_tail_latency",
            "path": "artifacts/swarm_tail_latency_p99_attribution.json",
            "sha256": "c" * 64,
            "role": "p99_attribution_ledger",
        },
        {
            "lane_id": "adaptive_runtime",
            "path": "artifacts/adaptive_runtime_runner.json",
            "sha256": "d" * 64,
            "role": "adaptive_runtime_runner_report",
        },
    ]
)
report["swarm_evidence"] = [
    {
        "lane_id": "swarm_workload_harness",
        "host_class": "developer_smoke",
        "manifest_hash": "e" * 64,
    },
    {
        "lane_id": "swarm_tail_latency",
        "host_class": "developer_smoke",
        "manifest_hash": "f" * 64,
    },
]
report["adaptive_runtime_evidence"] = [
    {
        "lane_id": "adaptive_runtime",
        "release_claim_state": "accepted_large_host",
        "runner_report": "artifacts/adaptive_runtime_runner.json",
    }
]
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_markdown_report() {
    python3 - <<'PY'
lanes = [
    "conformance",
    "xfstests",
    "fuse",
    "differential_oracle",
    "repair_lab",
    "crash_replay",
    "performance",
    "swarm_workload_harness",
    "swarm_tail_latency",
    "writeback_cache",
    "scrub_repair_status",
    "known_deferrals",
    "release_gates",
    "adaptive_runtime",
]
print("# FrankenFS Proof Bundle")
print()
print("Reproduce with `cargo run -p ffs-harness -- validate-proof-bundle`.")
print()
print("## Lanes")
for lane in lanes:
    print(f"- {lane}: logs/{lane}.log summaries/{lane}.md")
print()
print("## Artifact hash chain")
print("Artifact hash chain: valid")
print()
print("## Lane Provenance")
print("conformance strengthens_public_claim")
print("known_deferrals unsupported_future_scope")
print()
print("## Executed Evidence")
print("conformance success stdout_sha256")
print("fuse success stdout_sha256")
print()
print("## Swarm Evidence")
print("swarm_tail_latency p99_attribution available")
print()
print("## Adaptive Runtime Evidence")
print("adaptive_runtime_runner available")
PY
}

case "$command_text" in
    *"cargo test -p ffs-harness --lib proof_bundle"*)
        printf '%s\n' \
            "running 49 tests" \
            "test proof_bundle::tests::sample_bundle_validates ... ok" \
            "test proof_bundle::tests::executable_lanes_attach_process_run_evidence ... ok" \
            "test proof_bundle::tests::render_proof_bundle_markdown_sample_bundle_snapshot ... ok" \
            "test proof_bundle::tests::redaction_policy_failures_are_evidence_production_failures ... ok" \
            "test result: ok. 49 passed; 0 failed; 0 ignored"
        finish_success
        ;;
    *"proof_bundle_bad_hash.json"*)
        echo "artifact hash mismatch for artifacts/conformance.json"
        finish_failure 1
        ;;
    *"proof_bundle_stale_sha.json"*)
        echo "stale git_sha: stale-sha-for-e2e"
        finish_failure 1
        ;;
    *"proof_bundle_missing_artifact.json"*)
        echo "broken link: artifacts/does_not_exist.json"
        finish_failure 1
        ;;
    *"proof_bundle_bad_hash_chain.json"*)
        echo "artifact hash-chain mismatch"
        finish_failure 1
        ;;
    *"proof_bundle_redaction_leak.json"*)
        echo "redaction leak: SECRET_TOKEN"
        finish_failure 1
        ;;
    *"proof_bundle_missing_placeholder.json"*)
        echo "redacted artifact lacks placeholder"
        finish_failure 1
        ;;
    *"proof_bundle_bad_raw_log_hash.json"*)
        echo "raw log hash mismatch"
        finish_failure 1
        ;;
    *"proof_bundle_traversal_path.json"*)
        echo "parent traversal rejected"
        finish_failure 1
        ;;
    *"proof_bundle_env_secret.json"*)
        echo "AWS_SECRET_ACCESS_KEY=unredacted"
        finish_failure 1
        ;;
    *"proof_bundle_missing_redaction.json"*)
        echo "redaction.reproduction_command missing"
        echo "evidence_production_failure"
        finish_failure 1
        ;;
    *"validate-proof-bundle"*"--format markdown"*)
        emit_markdown_report
        finish_success
        ;;
    *"validate-proof-bundle"*)
        emit_validation_report
        finish_success
        ;;
    *)
        echo "unexpected proof-bundle fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/proof_bundle_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_PROOF_BUNDLE_SELF_CHECK=0 \
        FFS_PROOF_BUNDLE_SKIP_SELF_CHECK=1 \
        FFS_PROOF_BUNDLE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_proof_bundle_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic proof bundle wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-proof-bundle-fixture"
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
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_cli_wired" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_sample_validates" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_summary_links" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_hash_drift_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_stale_sha_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_missing_artifact_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_hash_chain_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_redaction_leak_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_redaction_placeholder_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_raw_log_hash_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_traversal_path_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_env_secret_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_missing_redaction_rejected" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "proof_bundle_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "proof_bundle_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "proof_bundle_fixture_complete_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "proof_bundle_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "proof_bundle_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
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
        scenario_result "proof_bundle_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "proof_bundle_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

GIT_SHA="$(git rev-parse HEAD)"
RCH_OUTPUT_DIR="$REPO_ROOT/artifacts/rch/proof_bundle/$(basename "$E2E_LOG_DIR")"
BUNDLE_DIR="$RCH_OUTPUT_DIR/proof_bundle"
MANIFEST_JSON="$BUNDLE_DIR/manifest.json"
REPORT_JSON="$E2E_LOG_DIR/proof_bundle_report.json"
SUMMARY_MD="$E2E_LOG_DIR/proof_bundle_summary.md"
VALIDATE_RAW="$E2E_LOG_DIR/proof_bundle_validate.raw"
SUMMARY_RAW="$E2E_LOG_DIR/proof_bundle_summary.raw"
BAD_HASH_MANIFEST="$BUNDLE_DIR/proof_bundle_bad_hash.json"
BAD_HASH_RAW="$E2E_LOG_DIR/proof_bundle_bad_hash.raw"
BAD_STALE_MANIFEST="$BUNDLE_DIR/proof_bundle_stale_sha.json"
BAD_STALE_RAW="$E2E_LOG_DIR/proof_bundle_stale_sha.raw"
BAD_LINK_MANIFEST="$BUNDLE_DIR/proof_bundle_missing_artifact.json"
BAD_LINK_RAW="$E2E_LOG_DIR/proof_bundle_missing_artifact.raw"
BAD_CHAIN_MANIFEST="$BUNDLE_DIR/proof_bundle_bad_hash_chain.json"
BAD_CHAIN_RAW="$E2E_LOG_DIR/proof_bundle_bad_hash_chain.raw"
BAD_REDACTION_MANIFEST="$BUNDLE_DIR/proof_bundle_redaction_leak.json"
BAD_REDACTION_RAW="$E2E_LOG_DIR/proof_bundle_redaction_leak.raw"
BAD_PLACEHOLDER_MANIFEST="$BUNDLE_DIR/proof_bundle_missing_placeholder.json"
BAD_PLACEHOLDER_RAW="$E2E_LOG_DIR/proof_bundle_missing_placeholder.raw"
BAD_RAW_LOG_HASH_MANIFEST="$BUNDLE_DIR/proof_bundle_bad_raw_log_hash.json"
BAD_RAW_LOG_HASH_RAW="$E2E_LOG_DIR/proof_bundle_bad_raw_log_hash.raw"
BAD_TRAVERSAL_MANIFEST="$BUNDLE_DIR/proof_bundle_traversal_path.json"
BAD_TRAVERSAL_RAW="$E2E_LOG_DIR/proof_bundle_traversal_path.raw"
BAD_ENV_MANIFEST="$BUNDLE_DIR/proof_bundle_env_secret.json"
BAD_ENV_RAW="$E2E_LOG_DIR/proof_bundle_env_secret.raw"
BAD_MISSING_REDACTION_MANIFEST="$BUNDLE_DIR/proof_bundle_missing_redaction.json"
BAD_MISSING_REDACTION_RAW="$E2E_LOG_DIR/proof_bundle_missing_redaction.raw"
UNIT_LOG="$E2E_LOG_DIR/proof_bundle_unit_tests.log"

mkdir -p "$BUNDLE_DIR"

e2e_step "Scenario 1: proof bundle module and CLI are wired"
if grep -q "pub mod proof_bundle" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-proof-bundle" crates/ffs-harness/src/main.rs; then
    scenario_result "proof_bundle_cli_wired" "PASS" "module and CLI command exported"
else
    scenario_result "proof_bundle_cli_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: sample proof bundle validates"
if python3 - "$BUNDLE_DIR" "$MANIFEST_JSON" "$GIT_SHA" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

bundle_dir = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
git_sha = sys.argv[3]

lanes = [
    "conformance",
    "xfstests",
    "fuse",
    "differential_oracle",
    "repair_lab",
    "crash_replay",
    "performance",
    "swarm_workload_harness",
    "swarm_tail_latency",
    "writeback_cache",
    "scrub_repair_status",
    "known_deferrals",
    "release_gates",
    "adaptive_runtime",
]
statuses = ["pass", "fail", "skip", "error"]

records = []
for index, lane in enumerate(lanes):
    raw_log = pathlib.Path("logs") / f"{lane}.log"
    summary = pathlib.Path("summaries") / f"{lane}.md"
    gate_input = pathlib.Path("inputs") / f"{lane}.json"
    artifact = pathlib.Path("artifacts") / f"{lane}.json"
    p99_artifact = pathlib.Path("artifacts") / f"{lane}_p99_attribution.json"
    runner_artifact = pathlib.Path("artifacts") / f"{lane}_runner.json"
    lane_status = "pass" if lane == "adaptive_runtime" else statuses[index % len(statuses)]
    redacted = index % 2 == 0
    artifact_payload = {"lane": lane, "artifact": "primary"}
    if redacted:
        artifact_payload["redacted_value"] = "[REDACTED]"
    for relative, text in [
        (raw_log, f"lane={lane}\nstatus={lane_status}\n"),
        (summary, f"# {lane}\n\nSummary for {lane}.\n"),
        (gate_input, json.dumps({"lane": lane, "gate": "bd-rchk0.5.4.1"}, sort_keys=True) + "\n"),
        (artifact, json.dumps(artifact_payload, sort_keys=True) + "\n"),
    ]:
        path = bundle_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    raw_log_digest = hashlib.sha256((bundle_dir / raw_log).read_bytes()).hexdigest()
    digest = hashlib.sha256((bundle_dir / artifact).read_bytes()).hexdigest()
    artifacts = [
        {
            "path": artifact.as_posix(),
            "sha256": digest,
            "redacted": redacted,
            "role": (
                "adaptive_runtime_validator_report"
                if lane == "adaptive_runtime"
                else "swarm_validator_report"
                if lane in {"swarm_workload_harness", "swarm_tail_latency"}
                else "primary_evidence"
            ),
        }
    ]
    metadata = {}
    if lane in {"swarm_workload_harness", "swarm_tail_latency"}:
        status = lane_status
        metadata = {
            "freshness": "fresh",
            "manifest_hash": "a" * 64,
            "validator_report": artifact.as_posix(),
        }
        if status == "pass":
            metadata["host_class"] = "permissioned_large_host"
            metadata["release_claim"] = "authoritative_large_host"
        elif status == "skip":
            metadata["host_class"] = "developer_smoke"
            metadata["release_claim"] = "small_host_smoke"
            metadata["downgrade_reason"] = (
                "small host smoke cannot support release wording"
            )
        elif status == "fail":
            metadata["host_class"] = "developer_smoke"
            metadata["release_claim"] = "failed"
            metadata["downgrade_reason"] = "swarm evidence failed release checks"
        else:
            metadata["host_class"] = "developer_smoke"
            metadata["release_claim"] = "error"
            metadata["downgrade_reason"] = "swarm evidence errored during collection"
    if lane == "swarm_tail_latency":
        p99_payload = {"lane": lane, "artifact": "p99_attribution"}
        p99_path = bundle_dir / p99_artifact
        p99_path.parent.mkdir(parents=True, exist_ok=True)
        p99_path.write_text(json.dumps(p99_payload, sort_keys=True) + "\n", encoding="utf-8")
        p99_digest = hashlib.sha256(p99_path.read_bytes()).hexdigest()
        metadata["p99_attribution_artifact"] = p99_artifact.as_posix()
        artifacts.append(
            {
                "path": p99_artifact.as_posix(),
                "sha256": p99_digest,
                "redacted": False,
                "role": "p99_attribution_ledger",
            }
        )
    if lane == "adaptive_runtime":
        runner_payload = {"lane": lane, "artifact": "adaptive_runtime_runner"}
        runner_path = bundle_dir / runner_artifact
        runner_path.parent.mkdir(parents=True, exist_ok=True)
        runner_path.write_text(json.dumps(runner_payload, sort_keys=True) + "\n", encoding="utf-8")
        runner_digest = hashlib.sha256(runner_path.read_bytes()).hexdigest()
        metadata = {
            "scenario_id": "adaptive_runtime_accepted_large_host",
            "run_id": "adaptive-runtime-run-20260508T000000Z",
            "freshness": "fresh",
            "release_claim_state": "accepted_large_host",
            "host_classification": "accepted_large_host",
            "cleanup_status": "clean",
            "validator_report": artifact.as_posix(),
            "runner_report": runner_artifact.as_posix(),
        }
        artifacts.append(
            {
                "path": runner_artifact.as_posix(),
                "sha256": runner_digest,
                "redacted": False,
                "role": "adaptive_runtime_runner_report",
            }
        )
    metadata["source_command"] = f"cargo run -p ffs-harness -- validate-{lane}"
    allowlisted_lane_args = {
        "conformance": ["run", "--quiet", "-p", "ffs-harness", "--", "check-fixtures"],
        "fuse": ["run", "--quiet", "-p", "ffs-harness", "--", "validate-mounted-write-matrix"],
        "repair_lab": ["run", "--quiet", "-p", "ffs-harness", "--", "validate-chaos-replay-lab"],
        "crash_replay": ["run", "--quiet", "-p", "ffs-harness", "--", "crash-replay-suite"],
    }
    if lane in allowlisted_lane_args:
        metadata["executed_evidence_command"] = "cargo"
        metadata["executed_evidence_args_json"] = json.dumps(allowlisted_lane_args[lane])
    records.append(
        {
            "lane_id": lane,
            "status": lane_status,
            "raw_log_path": raw_log.as_posix(),
            "raw_log_sha256": raw_log_digest,
            "summary_path": summary.as_posix(),
            "scenario_ids": [f"{lane}_proof_bundle_primary"],
            "gate_inputs": [gate_input.as_posix()],
            "artifacts": artifacts,
            "metadata": metadata,
        }
    )

def hash_chain_part(hasher: "hashlib._Hash", value: str) -> None:
    encoded = value.encode("utf-8")
    hasher.update(str(len(encoded)).encode("utf-8"))
    hasher.update(b":")
    hasher.update(encoded)
    hasher.update(b";")

def artifact_hash_chain_sha256(bundle_records: list[dict[str, object]]) -> str:
    hasher = hashlib.sha256()
    for record in bundle_records:
        hash_chain_part(hasher, "lane")
        hash_chain_part(hasher, str(record["lane_id"]))
        hash_chain_part(hasher, "raw_log")
        hash_chain_part(hasher, str(record["raw_log_path"]))
        hash_chain_part(hasher, str(record["raw_log_sha256"]))
        for artifact_record in record["artifacts"]:
            hash_chain_part(hasher, "artifact")
            hash_chain_part(hasher, str(artifact_record["path"]))
            hash_chain_part(hasher, str(artifact_record["sha256"]))
            hash_chain_part(hasher, "redacted" if artifact_record["redacted"] else "clear")
            hash_chain_part(hasher, str(artifact_record["role"]))
    return hasher.hexdigest()

manifest = {
    "schema_version": 1,
    "bundle_id": "bd-rchk0.5.4.1-proof-bundle",
    "generated_at": "2026-05-01T00:00:00Z",
    "git_sha": git_sha,
    "toolchain": "rust-nightly-2024",
    "kernel": "linux-proof-bundle-e2e",
    "mount_capability": "available",
    "required_lanes": lanes,
    "lanes": records,
    "redaction": {
        "redacted_fields": ["hostname", "api_key", "token"],
        "preserved_fields": [
            "reproduction_command",
            "git_sha",
            "bundle_id",
            "artifact_paths",
            "scenario_ids",
        ],
        "reproduction_command": (
            "cargo run -p ffs-harness -- validate-proof-bundle "
            "--bundle proof_bundle/manifest.json"
        ),
        "policy_version": "redaction-v1",
        "redacted_value_placeholder": "[REDACTED]",
        "forbidden_unredacted_markers": ["SECRET_TOKEN", "/home/ubuntu", "host-prod"],
        "require_placeholder_in_redacted_artifacts": True,
    },
    "integrity": {
        "artifact_hash_chain_sha256": artifact_hash_chain_sha256(records),
        "artifact_count": sum(len(record["artifacts"]) for record in records),
        "redaction_policy_version": "redaction-v1",
    },
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
then
    if run_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
        --bundle "$MANIFEST_JSON" \
        --current-git-sha "$GIT_SHA" \
        --max-age-days 10000 \
        --execute-configured-lanes \
        && extract_json_object "$VALIDATE_RAW" "$REPORT_JSON" \
        && run_rch_capture "$SUMMARY_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
            --bundle "$MANIFEST_JSON" \
            --current-git-sha "$GIT_SHA" \
            --max-age-days 10000 \
            --format markdown \
            --execute-configured-lanes \
        && extract_markdown_report "$SUMMARY_RAW" "$SUMMARY_MD"; then
        scenario_result "proof_bundle_sample_validates" "PASS" "validation JSON and summary captured from RCH"
    else
        [[ -s "$VALIDATE_RAW" ]] && cat "$VALIDATE_RAW"
        [[ -s "$SUMMARY_RAW" ]] && cat "$SUMMARY_RAW"
        scenario_result "proof_bundle_sample_validates" "FAIL" "validator rejected generated sample bundle"
    fi
else
    scenario_result "proof_bundle_sample_validates" "FAIL" "failed to generate sample proof bundle"
fi

e2e_step "Scenario 3: generated summary preserves lane links and totals"
if python3 - "$REPORT_JSON" "$SUMMARY_MD" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
required_lanes = {
    "conformance",
    "xfstests",
    "fuse",
    "differential_oracle",
    "repair_lab",
    "crash_replay",
    "performance",
    "swarm_workload_harness",
    "swarm_tail_latency",
    "writeback_cache",
    "scrub_repair_status",
    "known_deferrals",
    "release_gates",
    "adaptive_runtime",
}
observed_lanes = {lane["lane_id"] for lane in report["lanes"]}
if observed_lanes != required_lanes:
    raise SystemExit(f"unexpected lanes: {sorted(observed_lanes)}")
if report["totals"]["pass"] < 1 or report["totals"]["fail"] < 1:
    raise SystemExit("pass/fail totals not captured")
if not report.get("artifact_hash_chain"):
    raise SystemExit("artifact hash-chain report missing")
if report["artifact_hash_chain"]["redaction_policy_version"] != "redaction-v1":
    raise SystemExit("redaction policy version was not preserved in hash-chain report")
artifact_rows = report.get("artifact_reports", [])
if len(artifact_rows) != len(required_lanes) + 2:
    raise SystemExit(f"unexpected artifact report count: {len(artifact_rows)}")
if not all(row.get("sha256") and row.get("path") for row in artifact_rows):
    raise SystemExit("artifact report rows did not preserve path and hash")
if not any(row.get("role") == "p99_attribution_ledger" for row in artifact_rows):
    raise SystemExit("p99 attribution ledger artifact was not preserved")
if not any(row.get("role") == "adaptive_runtime_runner_report" for row in artifact_rows):
    raise SystemExit("adaptive runtime runner artifact was not preserved")
swarm_rows = report.get("swarm_evidence", [])
if len(swarm_rows) != 2:
    raise SystemExit(f"unexpected swarm evidence rows: {len(swarm_rows)}")
if not all(row.get("host_class") and row.get("manifest_hash") for row in swarm_rows):
    raise SystemExit("swarm evidence did not preserve host class and manifest hash")
adaptive_rows = report.get("adaptive_runtime_evidence", [])
if len(adaptive_rows) != 1:
    raise SystemExit(f"unexpected adaptive runtime evidence rows: {len(adaptive_rows)}")
if adaptive_rows[0].get("release_claim_state") != "accepted_large_host":
    raise SystemExit("adaptive runtime release claim state was not preserved")
provenance_rows = report.get("lane_provenance", [])
if len(provenance_rows) != len(required_lanes):
    raise SystemExit(f"unexpected lane provenance rows: {len(provenance_rows)}")
provenance_by_lane = {row["lane_id"]: row for row in provenance_rows}
if provenance_by_lane["conformance"]["claim_effect"] != "strengthens_public_claim":
    raise SystemExit("passing conformance lane did not strengthen a public claim")
if provenance_by_lane["swarm_workload_harness"]["provenance_class"] != "small_host_smoke":
    raise SystemExit("small-host swarm lane was not classified as smoke evidence")
if provenance_by_lane["known_deferrals"]["provenance_class"] != "unsupported_future_scope":
    raise SystemExit("known deferrals lane did not stay unsupported future-scope context")
if not all(row.get("source_command") and row.get("raw_log_path") for row in provenance_rows):
    raise SystemExit("lane provenance did not preserve source command and raw log path")
executed_rows = report.get("executed_evidence", [])
expected_executed_lanes = {"conformance", "fuse", "repair_lab", "crash_replay"}
executed_by_lane = {row["lane_id"]: row for row in executed_rows}
if set(executed_by_lane) != expected_executed_lanes:
    raise SystemExit(f"unexpected executed evidence lanes: {sorted(executed_by_lane)}")
for lane, evidence in executed_by_lane.items():
    if evidence.get("command") != "cargo":
        raise SystemExit(f"{lane} executed evidence command was not recorded")
    if evidence.get("exit_code") != 0 or evidence.get("outcome") != "success":
        raise SystemExit(f"{lane} executed evidence did not record a successful run")
    if len(evidence.get("stdout_sha256", "")) != 64:
        raise SystemExit(f"{lane} stdout hash was not preserved")
lane_by_id = {row["lane_id"]: row for row in report["lanes"]}
if lane_by_id["conformance"]["status"] != "pass":
    raise SystemExit("conformance lane did not remain pass after successful execution")
for lane in required_lanes:
    if f"logs/{lane}.log" not in summary:
        raise SystemExit(f"missing raw log link for {lane}")
    if f"summaries/{lane}.md" not in summary:
        raise SystemExit(f"missing summary link for {lane}")
if "validate-proof-bundle" not in summary:
    raise SystemExit("summary did not preserve reproduction command")
if "Artifact hash chain" not in summary:
    raise SystemExit("summary did not preserve hash-chain diagnostics")
if "Lane Provenance" not in summary or "strengthens_public_claim" not in summary:
    raise SystemExit("summary did not preserve lane provenance diagnostics")
if "Executed Evidence" not in summary or "Stdout SHA-256" not in summary:
    raise SystemExit("summary did not preserve executed evidence diagnostics")
if "Swarm Evidence" not in summary or "p99_attribution" not in summary:
    raise SystemExit("summary did not preserve swarm evidence diagnostics")
if "Adaptive Runtime Evidence" not in summary or "adaptive_runtime_runner" not in summary:
    raise SystemExit("summary did not preserve adaptive runtime diagnostics")
PY
then
    scenario_result "proof_bundle_summary_links" "PASS" "summary contains totals and raw log links"
else
    scenario_result "proof_bundle_summary_links" "FAIL" "summary/report contract check failed"
fi

e2e_step "Scenario 4: validator rejects artifact hash drift"
python3 - "$MANIFEST_JSON" "$BAD_HASH_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data["lanes"][0]["artifacts"][0]["sha256"] = "0" * 64
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_HASH_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_HASH_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_hash_drift_rejected" "FAIL" "validator accepted corrupted artifact"
elif grep -q "artifact hash mismatch" "$BAD_HASH_RAW"; then
    scenario_result "proof_bundle_hash_drift_rejected" "PASS" "hash drift rejected"
else
    scenario_result "proof_bundle_hash_drift_rejected" "FAIL" "validator failed without hash mismatch diagnostic"
fi

e2e_step "Scenario 5: validator rejects stale git SHA"
python3 - "$MANIFEST_JSON" "$BAD_STALE_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_STALE_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_STALE_MANIFEST" \
    --current-git-sha "stale-sha-for-e2e" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_stale_sha_rejected" "FAIL" "validator accepted stale git SHA"
elif grep -q "stale git_sha" "$BAD_STALE_RAW"; then
    scenario_result "proof_bundle_stale_sha_rejected" "PASS" "stale git SHA rejected"
else
    scenario_result "proof_bundle_stale_sha_rejected" "FAIL" "validator failed without stale git diagnostic"
fi

e2e_step "Scenario 6: validator rejects missing artifact links"
python3 - "$MANIFEST_JSON" "$BAD_LINK_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data["lanes"][1]["artifacts"][0]["path"] = "artifacts/does_not_exist.json"
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_LINK_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_LINK_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_missing_artifact_rejected" "FAIL" "validator accepted missing artifact link"
elif grep -q "broken link" "$BAD_LINK_RAW"; then
    scenario_result "proof_bundle_missing_artifact_rejected" "PASS" "missing artifact link rejected"
else
    scenario_result "proof_bundle_missing_artifact_rejected" "FAIL" "validator failed without broken link diagnostic"
fi

e2e_step "Scenario 7: validator rejects artifact hash-chain tampering"
python3 - "$MANIFEST_JSON" "$BAD_CHAIN_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data["integrity"]["artifact_hash_chain_sha256"] = "f" * 64
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_CHAIN_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_CHAIN_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_hash_chain_rejected" "FAIL" "validator accepted tampered hash chain"
elif grep -q "artifact hash-chain mismatch" "$BAD_CHAIN_RAW"; then
    scenario_result "proof_bundle_hash_chain_rejected" "PASS" "hash-chain tamper rejected"
else
    scenario_result "proof_bundle_hash_chain_rejected" "FAIL" "validator failed without hash-chain diagnostic"
fi

e2e_step "Scenario 8: validator rejects unredacted sensitive markers"
python3 - "$MANIFEST_JSON" "$BAD_REDACTION_MANIFEST" "$BUNDLE_DIR" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path, bundle_dir = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
leaky_summary = pathlib.Path("summaries") / "conformance_leaky.md"
(pathlib.Path(bundle_dir) / leaky_summary).write_text(
    "# conformance\n\nhost-prod leaked SECRET_TOKEN\n",
    encoding="utf-8",
)
data["lanes"][0]["summary_path"] = leaky_summary.as_posix()
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_REDACTION_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_REDACTION_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_redaction_leak_rejected" "FAIL" "validator accepted unredacted sensitive marker"
elif grep -q "redaction leak" "$BAD_REDACTION_RAW"; then
    scenario_result "proof_bundle_redaction_leak_rejected" "PASS" "unredacted sensitive marker rejected"
else
    scenario_result "proof_bundle_redaction_leak_rejected" "FAIL" "validator failed without redaction leak diagnostic"
fi

e2e_step "Scenario 9: validator rejects redacted artifacts without placeholders"
python3 - "$MANIFEST_JSON" "$BAD_PLACEHOLDER_MANIFEST" "$BUNDLE_DIR" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

manifest_path, out_path, bundle_dir = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
artifact_path = pathlib.Path("artifacts") / "conformance_no_placeholder.json"
artifact_abs = pathlib.Path(bundle_dir) / artifact_path
artifact_abs.write_text(json.dumps({"redacted": "missing-placeholder"}, sort_keys=True) + "\n", encoding="utf-8")
data["lanes"][0]["artifacts"][0]["path"] = artifact_path.as_posix()
data["lanes"][0]["artifacts"][0]["sha256"] = hashlib.sha256(artifact_abs.read_bytes()).hexdigest()
data["lanes"][0]["artifacts"][0]["redacted"] = True
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_PLACEHOLDER_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_PLACEHOLDER_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_redaction_placeholder_rejected" "FAIL" "validator accepted redacted artifact without placeholder"
elif grep -q "lacks placeholder" "$BAD_PLACEHOLDER_RAW"; then
    scenario_result "proof_bundle_redaction_placeholder_rejected" "PASS" "missing redaction placeholder rejected"
else
    scenario_result "proof_bundle_redaction_placeholder_rejected" "FAIL" "validator failed without placeholder diagnostic"
fi

e2e_step "Scenario 10: validator rejects raw-log hash drift"
python3 - "$MANIFEST_JSON" "$BAD_RAW_LOG_HASH_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data["lanes"][0]["raw_log_sha256"] = "0" * 64
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_RAW_LOG_HASH_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_RAW_LOG_HASH_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_raw_log_hash_rejected" "FAIL" "validator accepted raw-log hash drift"
elif grep -q "raw log hash mismatch" "$BAD_RAW_LOG_HASH_RAW"; then
    scenario_result "proof_bundle_raw_log_hash_rejected" "PASS" "raw-log hash drift rejected"
else
    scenario_result "proof_bundle_raw_log_hash_rejected" "FAIL" "validator failed without raw-log hash diagnostic"
fi

e2e_step "Scenario 11: validator rejects relative path traversal"
python3 - "$MANIFEST_JSON" "$BAD_TRAVERSAL_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data["lanes"][0]["summary_path"] = "../outside-summary.md"
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_TRAVERSAL_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_TRAVERSAL_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_traversal_path_rejected" "FAIL" "validator accepted relative traversal"
elif grep -q "parent traversal" "$BAD_TRAVERSAL_RAW"; then
    scenario_result "proof_bundle_traversal_path_rejected" "PASS" "relative traversal rejected"
else
    scenario_result "proof_bundle_traversal_path_rejected" "FAIL" "validator failed without traversal diagnostic"
fi

e2e_step "Scenario 12: validator rejects env-like secret markers"
python3 - "$MANIFEST_JSON" "$BAD_ENV_MANIFEST" "$BUNDLE_DIR" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path, bundle_dir = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
leaky_summary = pathlib.Path("summaries") / "conformance_env_secret.md"
(pathlib.Path(bundle_dir) / leaky_summary).write_text(
    "# conformance\n\nAWS_SECRET_ACCESS_KEY=unredacted\n",
    encoding="utf-8",
)
data["lanes"][0]["summary_path"] = leaky_summary.as_posix()
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_ENV_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_ENV_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_env_secret_rejected" "FAIL" "validator accepted env-like secret marker"
elif grep -q "AWS_SECRET_ACCESS_KEY=" "$BAD_ENV_RAW"; then
    scenario_result "proof_bundle_env_secret_rejected" "PASS" "env-like secret marker rejected"
else
    scenario_result "proof_bundle_env_secret_rejected" "FAIL" "validator failed without env-secret diagnostic"
fi

e2e_step "Scenario 13: validator rejects missing redaction policy as evidence production failure"
python3 - "$MANIFEST_JSON" "$BAD_MISSING_REDACTION_MANIFEST" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

manifest_path, out_path = sys.argv[1:]
data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
data.pop("redaction", None)
pathlib.Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if run_rch_capture "$BAD_MISSING_REDACTION_RAW" cargo run --quiet -p ffs-harness -- validate-proof-bundle \
    --bundle "$BAD_MISSING_REDACTION_MANIFEST" \
    --current-git-sha "$GIT_SHA" \
    --max-age-days 10000; then
    scenario_result "proof_bundle_missing_redaction_rejected" "FAIL" "validator accepted missing redaction policy"
elif grep -q "redaction.reproduction_command" "$BAD_MISSING_REDACTION_RAW" \
    && grep -q "evidence_production_failure" "$BAD_MISSING_REDACTION_RAW"; then
    scenario_result "proof_bundle_missing_redaction_rejected" "PASS" "missing redaction policy rejected as evidence-production failure"
else
    scenario_result "proof_bundle_missing_redaction_rejected" "FAIL" "validator failed without redaction/provenance diagnostic"
fi

e2e_step "Scenario 14: proof bundle unit tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib proof_bundle -- --nocapture; then
    cat "$UNIT_LOG"
    scenario_result "proof_bundle_unit_tests" "PASS" "proof_bundle unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "proof_bundle_unit_tests" "FAIL" "proof_bundle unit tests failed"
fi

e2e_log "Proof bundle manifest: $MANIFEST_JSON"
e2e_log "Proof bundle validation report: $REPORT_JSON"
e2e_log "Proof bundle summary: $SUMMARY_MD"

if ((FAIL_COUNT == 0)); then
    e2e_log "Proof bundle scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Proof bundle scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
