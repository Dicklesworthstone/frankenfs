#!/usr/bin/env bash
# Execute the same evidence consumer used by both public parity commands.
# The self-check exercises real passing/failing/ignored/empty child processes;
# it grants no filesystem capability or canonical readiness credit (bd-wh1xk).

set -euo pipefail

cd "$(dirname "$0")/../.." || exit 1
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

e2e_init "parity_honesty"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_parity_honesty}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR

# The outer RCH command builds/runs the CLI on a worker. --local keeps its
# child Cargo execution on that same worker instead of dispatching recursively.
# This checks the worker-local consumer; it does not certify the local source.
# Strict RCH source isolation omits the Git metadata these self-checks need.
export RCH_REQUIRE_REMOTE=1
if rch exec -- cargo -Z checksum-freshness run -p ffs-harness -- \
    parity --verify parity-honesty --local; then
    e2e_log "SCENARIO_RESULT|scenario_id=parity_honesty_exact_self_check|outcome=PASS|detail=all exact self-checks executed and passed; product_evidence_claim=none"
else
    e2e_log "SCENARIO_RESULT|scenario_id=parity_honesty_exact_self_check|outcome=FAIL|detail=evidence consumer rejected the run; see command diagnostics"
    exit 1
fi
