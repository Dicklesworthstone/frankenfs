#!/usr/bin/env bash
# RCH-aware pre-push verification gate for FrankenFS (bd-fix-c7fc0ddc4-clippy-red-main-fj1rz).
# Fails closed on formatting, whitespace, workspace check, or clippy --all-targets -D warnings errors.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RCH_BIN="${FFS_PRE_PUSH_RCH_BIN:-rch}"
CARGO_BIN="${FFS_PRE_PUSH_CARGO_BIN:-cargo}"
SBH_BIN="${FFS_PRE_PUSH_SBH_BIN:-sbh}"
GIT_BIN="${FFS_PRE_PUSH_GIT_BIN:-git}"
RCH_WORKERS="${FFS_PRE_PUSH_RCH_WORKERS:-auto vmi1149989 vmi1227854 vmi1153651}"
RECEIPT_PATH="${FFS_PRE_PUSH_RECEIPT:-}"

now_ms() {
    python3 -c 'import time; print(int(time.monotonic() * 1000))'
}

json_escape() {
    python3 -c 'import json,re,sys; s=re.sub(r"\x1b\[[0-9;]*m","",sys.stdin.read()).strip(); print(json.dumps(s))'
}

emit_receipt() {
    local gate_name="$1"
    local worker_id="$2"
    local exit_code="$3"
    local duration_ms="$4"
    local diag="$5"

    local git_head="unknown"
    local dirty_tree="false"
    if "$GIT_BIN" -C "$REPO_ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
        git_head="$("$GIT_BIN" -C "$REPO_ROOT" rev-parse HEAD)"
    fi
    if [[ -n "$("$GIT_BIN" -C "$REPO_ROOT" status --porcelain --untracked-files=no 2>/dev/null || true)" ]]; then
        dirty_tree="true"
    fi

    local escaped_diag
    escaped_diag="$(printf '%s' "$diag" | json_escape)"
    local payload
    payload="$(printf '{"git_head":"%s","dirty_tree":%s,"worker_id":"%s","gate_name":"%s","exit_code":%d,"duration_ms":%d,"first_diagnostic":%s}' \
        "$git_head" "$dirty_tree" "$worker_id" "$gate_name" "$exit_code" "$duration_ms" "$escaped_diag")"

    if [[ -n "$RECEIPT_PATH" ]]; then
        mkdir -p "$(dirname "$RECEIPT_PATH")"
        printf '%s\n' "$payload" >>"$RECEIPT_PATH"
    fi
    printf '%s\n' "$payload"
}

run_local_gate() {
    local gate_name="$1"
    shift
    local start_ms end_ms rc out first_diag
    start_ms="$(now_ms)"
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e
    end_ms="$(now_ms)"
    first_diag="$(printf '%s\n' "$out" | grep -E 'error|FAIL|refused' | head -n 1 || true)"
    if [[ -z "$first_diag" && "$rc" -ne 0 ]]; then
        first_diag="$(printf '%s\n' "$out" | head -n 1 || true)"
    fi
    emit_receipt "$gate_name" "local" "$rc" "$((end_ms - start_ms))" "$first_diag"
    if [[ "$rc" -ne 0 ]]; then
        printf '%s\n' "$out" >&2
        return "$rc"
    fi
}

run_rch_cargo_gate() {
    local gate_name="$1"
    shift
    local start_ms end_ms rc out first_diag
    local -a workers
    read -r -a workers <<<"$RCH_WORKERS"

    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        start_ms="$(now_ms)"
        set +e
        out="$("$CARGO_BIN" "$@" 2>&1)"
        rc=$?
        set -e
        end_ms="$(now_ms)"
        first_diag="$(printf '%s\n' "$out" | grep -E '^error(\[|:)' | head -n 1 || true)"
        emit_receipt "$gate_name" "local-cargo" "$rc" "$((end_ms - start_ms))" "$first_diag"
        if [[ "$rc" -ne 0 ]]; then
            printf '%s\n' "$out" >&2
            return "$rc"
        fi
        return 0
    fi

    local last_rc=1
    local last_out=""
    local last_worker="none"
    for worker in "${workers[@]}"; do
        last_worker="$worker"
        start_ms="$(now_ms)"
        set +e
        if [[ "$worker" == "auto" ]]; then
            out="$("$RCH_BIN" exec -- "$CARGO_BIN" "$@" 2>&1)"
        else
            out="$("$RCH_BIN" exec --worker "$worker" -- "$CARGO_BIN" "$@" 2>&1)"
        fi
        rc=$?
        set -e
        end_ms="$(now_ms)"
        last_rc="$rc"
        last_out="$out"

        if [[ "$rc" -eq 0 ]]; then
            emit_receipt "$gate_name" "$worker" 0 "$((end_ms - start_ms))" ""
            return 0
        fi

        # Retry next worker ONLY on RCH admission/capacity refusal (e.g. RCH-E330 disk headroom or RCH-I001 queue_timeout / expired probe).
        if printf '%s\n' "$out" | grep -qE 'RCH-E330|RCH-E32|RCH-I001|no admissible workers|queue_timeout|disk reservation|no healthy workers|slots remaining: 0|requires a probe'; then
            if printf '%s\n' "$out" | grep -qE 'requires a probe|capacity sample expired'; then
                if [[ "$worker" == "auto" ]]; then
                    "$RCH_BIN" workers probe --all >/dev/null 2>&1 || true
                else
                    "$RCH_BIN" workers probe "$worker" >/dev/null 2>&1 || true
                fi
            fi
            first_diag="$(printf '%s\n' "$out" | grep -E 'RCH-(E|I)[0-9]+|no admissible workers|disk reservation|refused' | head -n 1 || true)"
            emit_receipt "${gate_name}_admission_retry" "$worker" "$rc" "$((end_ms - start_ms))" "$first_diag"
            continue
        fi

        first_diag="$(printf '%s\n' "$out" | grep -E '^error(\[|:)' | head -n 1 || true)"
        if [[ -z "$first_diag" ]]; then
            first_diag="$(printf '%s\n' "$out" | tail -n 5 | head -n 1 || true)"
        fi
        emit_receipt "$gate_name" "$worker" "$rc" "$((end_ms - start_ms))" "$first_diag"
        printf '%s\n' "$out" >&2
        return "$rc"
    done

    first_diag="$(printf '%s\n' "$last_out" | grep -E 'RCH-E[0-9]+|error' | head -n 1 || true)"
    emit_receipt "$gate_name" "$last_worker" "$last_rc" 0 "${first_diag:-all_rch_workers_refused_admission}"
    printf '%s\n' "$last_out" >&2
    return "${last_rc:-1}"
}

install_hook() {
    local hook_path="$REPO_ROOT/.git/hooks/pre-push"
    cat >"$hook_path" <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel)"
exec "$REPO_ROOT/scripts/verify_pre_push_gates.sh"
HOOK
    chmod +x "$hook_path"
    printf 'Installed pre-push gate hook at %s\n' "$hook_path"
}

run_self_test() {
    local tmpdir
    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/ffs-pre-push-selftest.XXXXXX")"

    cat >"$tmpdir/mock_sbh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat >"$tmpdir/mock_cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat >"$tmpdir/mock_git" <<'EOF'
#!/usr/bin/env bash
if [[ "${2:-}" == "rev-parse" ]]; then
    echo "c7fc0ddc48fd09e3699b793a2317d511995d427a"
    exit 0
fi
exit 0
EOF
    chmod +x "$tmpdir/mock_sbh" "$tmpdir/mock_cargo" "$tmpdir/mock_git"

    # Case 1: Worker 1 returns RCH-E330 (exit 120), worker 2 succeeds (exit 0) -> overall PASS + valid JSON receipts.
    cat >"$tmpdir/mock_rch_retry_ok" <<'EOF'
#!/usr/bin/env bash
if [[ "${2:-}" == "--worker" && "${3:-}" == "w1" ]]; then
    echo "RCH-E330: disk reservation refused on worker w1" >&2
    exit 120
fi
exit 0
EOF
    chmod +x "$tmpdir/mock_rch_retry_ok"

    FFS_PRE_PUSH_SBH_BIN="$tmpdir/mock_sbh" \
    FFS_PRE_PUSH_CARGO_BIN="$tmpdir/mock_cargo" \
    FFS_PRE_PUSH_GIT_BIN="$tmpdir/mock_git" \
    FFS_PRE_PUSH_RCH_BIN="$tmpdir/mock_rch_retry_ok" \
    FFS_PRE_PUSH_RCH_WORKERS="w1 w2" \
    FFS_PRE_PUSH_RECEIPT="$tmpdir/pass_receipts.jsonl" \
        "$0" >/dev/null

    python3 - "$tmpdir/pass_receipts.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
assert any(r["gate_name"] == "cargo_check_admission_retry" and r["worker_id"] == "w1" for r in rows), rows
assert any(r["gate_name"] == "cargo_clippy" and r["worker_id"] == "w2" and r["exit_code"] == 0 for r in rows), rows
PY

    # Case 2: Simulated clippy failure (exit 101) MUST fail closed and capture first_diagnostic.
    cat >"$tmpdir/mock_rch_clippy_fail" <<'EOF'
#!/usr/bin/env bash
for arg in "$@"; do
    if [[ "$arg" == "clippy" ]]; then
        echo "error: used \`assert!\` to check that a value is empty" >&2
        exit 101
    fi
done
exit 0
EOF
    chmod +x "$tmpdir/mock_rch_clippy_fail"

    set +e
    FFS_PRE_PUSH_SBH_BIN="$tmpdir/mock_sbh" \
    FFS_PRE_PUSH_CARGO_BIN="$tmpdir/mock_cargo" \
    FFS_PRE_PUSH_GIT_BIN="$tmpdir/mock_git" \
    FFS_PRE_PUSH_RCH_BIN="$tmpdir/mock_rch_clippy_fail" \
    FFS_PRE_PUSH_RCH_WORKERS="w1" \
    FFS_PRE_PUSH_RECEIPT="$tmpdir/fail_clippy.jsonl" \
        "$0" >/dev/null 2>&1
    local rc_clippy=$?
    set -e
    if [[ "$rc_clippy" -ne 101 ]]; then
        echo "self-test failed: expected clippy failure rc=101, got $rc_clippy" >&2
        exit 1
    fi
    python3 - "$tmpdir/fail_clippy.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
clippy_rows = [r for r in rows if r["gate_name"] == "cargo_clippy"]
assert len(clippy_rows) == 1 and clippy_rows[0]["exit_code"] == 101, rows
assert "used `assert!` to check that a value is empty" in clippy_rows[0]["first_diagnostic"], clippy_rows
PY

    # Case 3: All workers refuse admission with RCH-E330 -> MUST fail closed (nonzero exit).
    cat >"$tmpdir/mock_rch_all_refuse" <<'EOF'
#!/usr/bin/env bash
echo "RCH-E330: disk reservation refused on worker" >&2
exit 120
EOF
    chmod +x "$tmpdir/mock_rch_all_refuse"

    set +e
    FFS_PRE_PUSH_SBH_BIN="$tmpdir/mock_sbh" \
    FFS_PRE_PUSH_CARGO_BIN="$tmpdir/mock_cargo" \
    FFS_PRE_PUSH_GIT_BIN="$tmpdir/mock_git" \
    FFS_PRE_PUSH_RCH_BIN="$tmpdir/mock_rch_all_refuse" \
    FFS_PRE_PUSH_RCH_WORKERS="w1 w2" \
    FFS_PRE_PUSH_RECEIPT="$tmpdir/fail_admission.jsonl" \
        "$0" >/dev/null 2>&1
    local rc_adm=$?
    set -e
    if [[ "$rc_adm" -eq 0 ]]; then
        echo "self-test failed: expected nonzero exit when all RCH workers refuse admission" >&2
        exit 1
    fi

    echo "verify_pre_push_gates.sh --self-test: PASS (3/3 scenarios verified)"
}

case "${1:-}" in
    --self-test)
        run_self_test
        exit 0
        ;;
    --install-hook)
        install_hook
        exit 0
        ;;
esac

cd "$REPO_ROOT"
if command -v "$SBH_BIN" >/dev/null 2>&1; then
    run_local_gate "sbh_check" "$SBH_BIN" check --need 20G
fi
run_local_gate "git_diff_check" "$GIT_BIN" diff --check
run_local_gate "cargo_fmt_check" "$CARGO_BIN" fmt --check
run_rch_cargo_gate "cargo_check" check --workspace --all-targets
run_rch_cargo_gate "cargo_clippy" clippy --workspace --all-targets -- -D warnings
