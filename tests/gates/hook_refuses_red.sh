#!/usr/bin/env bash
# End-to-end verification that the installed pre-push hook refuses unformatted,
# non-compiling, and undocumented-bypass pushes (via real `rch`) while admitting
# clean commits and documented `Gate-Bypass: <reason>` trailer pushes (bd-ys3wb).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$REPO_ROOT/scripts/install_gate_hooks.sh"
GATE_SCRIPT="$REPO_ROOT/scripts/verify_pre_push_gates.sh"

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${FFS_HOOK_TEST_LOG_DIR:-$REPO_ROOT/artifacts/gates/${RUN_TS}_hook_refuses_red}"
mkdir -p "$LOG_DIR"
SUMMARY_LOG="$LOG_DIR/hook_refuses_red.log"
RECEIPTS_JSONL="$LOG_DIR/receipts.jsonl"

# Place the isolated sandbox repositories under artifacts/gates/ (gitignored,
# inside /data/projects/frankenfs) so the real RCH daemon syncs and compiles
# the probe crate on remote workers without any mock or wrapper bypass.
WORK_REPO="$LOG_DIR/work"
ORIGIN_BARE="$LOG_DIR/origin.git"

log() {
    printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$SUMMARY_LOG"
}

log " Step 0: verify_pre_push_gates.sh --self-test "
"$GATE_SCRIPT" --self-test | tee -a "$SUMMARY_LOG"

log " Step 1: initialize isolated git workspace + bare origin + install hook "
git init --bare --initial-branch=main "$ORIGIN_BARE" >/dev/null
git init --initial-branch=main "$WORK_REPO" >/dev/null
git -C "$WORK_REPO" config user.name "FrankenFS Gate Test"
git -C "$WORK_REPO" config user.email "gate-test@frankenfs.invalid"
git -C "$WORK_REPO" remote add origin "$ORIGIN_BARE"

mkdir -p "$WORK_REPO/src"
cat >"$WORK_REPO/Cargo.toml" <<'TOML'
[package]
name = "ffs_gate_hook_probe"
version = "0.1.0"
edition = "2024"

[workspace]
TOML

# Scenario 1: Deliberately unformatted Rust commit MUST be refused by git push.
log " Scenario 1: deliberately unformatted commit must be refused on git push "
cat >"$WORK_REPO/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]
pub fn   badly_formatted(  x:u32 )->u32{x+1}
RS
cargo generate-lockfile --manifest-path "$WORK_REPO/Cargo.toml" >/dev/null
"$INSTALLER" --repo "$WORK_REPO" --pre-push-only | tee -a "$SUMMARY_LOG"
if [[ ! -x "$WORK_REPO/.git/hooks/pre-push" ]]; then
    log "FAIL: pre-push hook not installed or not executable"
    exit 1
fi
git -C "$WORK_REPO" add Cargo.toml Cargo.lock src/lib.rs
git -C "$WORK_REPO" commit -m "test: deliberately unformatted commit" >/dev/null

set +e
PUSH1_OUT="$(
    FFS_PRE_PUSH_SKIP_SBH=1 \
    FFS_PRE_PUSH_RECEIPT="$RECEIPTS_JSONL" \
        git -C "$WORK_REPO" push -u origin main 2>&1
)"
PUSH1_RC=$?
set -e
printf '%s\n' "$PUSH1_OUT" >>"$SUMMARY_LOG"
if [[ "$PUSH1_RC" -eq 0 ]]; then
    log "FAIL: Scenario 1 pushed unformatted commit (expected refusal)"
    exit 1
fi
if git --git-dir="$ORIGIN_BARE" rev-parse --verify refs/heads/main >/dev/null 2>&1; then
    log "FAIL: Scenario 1 updated origin/main despite refusal"
    exit 1
fi
log "PASS: Scenario 1 refused unformatted push (rc=$PUSH1_RC)"

# Scenario 2: Properly formatted but non-compiling Rust commit MUST be refused by git push (via rch).
log " Scenario 2: deliberately non-compiling commit must be refused on git push "
cat >"$WORK_REPO/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]

#[must_use]
pub fn broken_return_type() -> u32 {
    "this string does not compile as u32"
}
RS
git -C "$WORK_REPO" add src/lib.rs
git -C "$WORK_REPO" commit -m "test: formatted but non-compiling commit" >/dev/null

set +e
PUSH2_OUT="$(
    FFS_PRE_PUSH_SKIP_SBH=1 \
    FFS_PRE_PUSH_RECEIPT="$RECEIPTS_JSONL" \
        git -C "$WORK_REPO" push -u origin main 2>&1
)"
PUSH2_RC=$?
set -e
printf '%s\n' "$PUSH2_OUT" >>"$SUMMARY_LOG"
if [[ "$PUSH2_RC" -eq 0 ]]; then
    log "FAIL: Scenario 2 pushed non-compiling commit (expected refusal)"
    exit 1
fi
if git --git-dir="$ORIGIN_BARE" rev-parse --verify refs/heads/main >/dev/null 2>&1; then
    log "FAIL: Scenario 2 updated origin/main despite refusal"
    exit 1
fi
log "PASS: Scenario 2 refused non-compiling push (rc=$PUSH2_RC)"

# Scenario 3: Bypass requested via env WITHOUT `Gate-Bypass:` commit trailer MUST be refused.
log " Scenario 3: FFS_PRE_PUSH_BYPASS=1 without Gate-Bypass trailer must be refused "
set +e
PUSH3_OUT="$(
    FFS_PRE_PUSH_BYPASS=1 \
    FFS_PRE_PUSH_SKIP_SBH=1 \
    FFS_PRE_PUSH_RECEIPT="$RECEIPTS_JSONL" \
        git -C "$WORK_REPO" push -u origin main 2>&1
)"
PUSH3_RC=$?
set -e
printf '%s\n' "$PUSH3_OUT" >>"$SUMMARY_LOG"
if [[ "$PUSH3_RC" -eq 0 ]]; then
    log "FAIL: Scenario 3 allowed bypass without Gate-Bypass commit trailer"
    exit 1
fi
log "PASS: Scenario 3 refused undocumented bypass (rc=$PUSH3_RC)"

# Scenario 4: Formatted, compiling, clippy-clean commit MUST succeed on git push (via rch).
log " Scenario 4: clean formatted + compiling commit must be accepted on git push "
cat >"$WORK_REPO/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]

#[must_use]
pub const fn gate_probe_answer() -> u32 {
    42
}
RS
git -C "$WORK_REPO" add src/lib.rs
git -C "$WORK_REPO" commit -m "fix: restore formatted and compiling crate" >/dev/null

FFS_PRE_PUSH_SKIP_SBH=1 \
FFS_PRE_PUSH_RECEIPT="$RECEIPTS_JSONL" \
    git -C "$WORK_REPO" push -u origin main >>"$SUMMARY_LOG" 2>&1

EXPECTED_SHA="$(git -C "$WORK_REPO" rev-parse HEAD)"
ACTUAL_REMOTE_SHA="$(git --git-dir="$ORIGIN_BARE" rev-parse refs/heads/main)"
if [[ "$EXPECTED_SHA" != "$ACTUAL_REMOTE_SHA" ]]; then
    log "FAIL: Scenario 4 remote SHA $ACTUAL_REMOTE_SHA != local HEAD $EXPECTED_SHA"
    exit 1
fi
log "PASS: Scenario 4 accepted clean push ($ACTUAL_REMOTE_SHA)"

# Scenario 5: Commit with `Gate-Bypass:` trailer still fails normal push if red,
# and succeeds ONLY when FFS_PRE_PUSH_BYPASS=1 is explicitly supplied.
log " Scenario 5: Gate-Bypass commit trailer requires explicit FFS_PRE_PUSH_BYPASS=1 and logs receipt "
cat >"$WORK_REPO/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]
pub fn   emergency_unformatted()->u32{7}
RS
git -C "$WORK_REPO" add src/lib.rs
git -C "$WORK_REPO" commit -m $'fix: emergency hotfix drill\n\nGate-Bypass: emergency-hotfix-drill-bd-ys3wb' >/dev/null

set +e
PUSH5A_OUT="$(
    FFS_PRE_PUSH_SKIP_SBH=1 \
    FFS_PRE_PUSH_RECEIPT="$RECEIPTS_JSONL" \
        git -C "$WORK_REPO" push origin main 2>&1
)"
PUSH5A_RC=$?
set -e
printf '%s\n' "$PUSH5A_OUT" >>"$SUMMARY_LOG"
if [[ "$PUSH5A_RC" -eq 0 ]]; then
    log "FAIL: Scenario 5a bypassed gates without FFS_PRE_PUSH_BYPASS=1"
    exit 1
fi

FFS_PRE_PUSH_BYPASS=1 \
FFS_PRE_PUSH_BYPASS_REASON="emergency-hotfix-drill-bd-ys3wb" \
FFS_PRE_PUSH_SKIP_SBH=1 \
FFS_PRE_PUSH_RECEIPT="$RECEIPTS_JSONL" \
    git -C "$WORK_REPO" push origin main >>"$SUMMARY_LOG" 2>&1

BYPASS_SHA="$(git -C "$WORK_REPO" rev-parse HEAD)"
REMOTE_AFTER_BYPASS="$(git --git-dir="$ORIGIN_BARE" rev-parse refs/heads/main)"
if [[ "$BYPASS_SHA" != "$REMOTE_AFTER_BYPASS" ]]; then
    log "FAIL: Scenario 5b remote SHA $REMOTE_AFTER_BYPASS != local HEAD $BYPASS_SHA"
    exit 1
fi

python3 - "$RECEIPTS_JSONL" <<'PY'
import json, sys

rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
assert any(r["gate_name"] == "cargo_fmt_check" and r["exit_code"] != 0 for r in rows), rows
assert any(r["gate_name"] == "cargo_check" and r["exit_code"] != 0 and "mismatched types" in r["first_diagnostic"] for r in rows), rows
assert any(r["gate_name"] == "gate_bypass_refused" and r["exit_code"] == 1 for r in rows), rows
assert any(r["gate_name"] == "cargo_clippy" and r["exit_code"] == 0 for r in rows), rows
assert any(
    r["gate_name"] == "gate_bypass_authorized"
    and r["exit_code"] == 0
    and "Gate-Bypass: emergency-hotfix-drill-bd-ys3wb" in r["first_diagnostic"]
    for r in rows
), rows
PY
log "PASS: Scenario 5 verified trailer-gated bypass + JSON audit receipts"
log "ALL 5 SCENARIOS PASSED — logs: $SUMMARY_LOG | receipts: $RECEIPTS_JSONL"
