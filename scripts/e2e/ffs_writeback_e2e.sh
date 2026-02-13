#!/usr/bin/env bash
# ffs_writeback_e2e.sh - Deterministic write-back durability E2E suite

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

e2e_init "ffs_writeback_e2e"
e2e_print_env

e2e_step "Write-back cache durability scenarios"
e2e_log "Running deterministic scenarios from crates/ffs-block/tests/writeback_e2e.rs"
e2e_assert cargo test -p ffs-block --test writeback_e2e -- --nocapture

e2e_pass
