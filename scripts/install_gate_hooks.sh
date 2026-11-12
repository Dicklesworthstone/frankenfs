#!/usr/bin/env bash
# Checked-in gate hook installer for FrankenFS (bd-ys3wb).
#
# Installs:
#   1. .git/hooks/pre-push   -> scripts/verify_pre_push_gates.sh
#      (runs sbh check, git diff --check, cargo fmt --check, and via rch:
#       cargo check --workspace --all-targets + cargo clippy --workspace --all-targets -- -D warnings)
#   2. .git/hooks/pre-commit -> scripts/perf_ledger_preflight.py --lint --staged
#      (when installing into the FrankenFS repository root unless --pre-push-only is passed)
#
# Documented emergency pre-push bypass:
#   Add `Gate-Bypass: <reason (>= 8 chars)>` trailer to the pushed commit message
#   AND invoke `FFS_PRE_PUSH_BYPASS=1 git push ...`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_REPO="$DEFAULT_REPO_ROOT"
PRE_PUSH_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo)
            if [[ -z "${2:-}" ]]; then
                echo "error: --repo requires a path argument" >&2
                exit 64
            fi
            TARGET_REPO="$(cd "$2" && pwd)"
            shift 2
            ;;
        --pre-push-only)
            PRE_PUSH_ONLY=1
            shift
            ;;
        -h|--help)
            cat <<'USAGE'
Usage: scripts/install_gate_hooks.sh [--repo <git-repo>] [--pre-push-only]

Installs the FrankenFS pre-push merge-gate hook (fmt + workspace check + clippy
via rch, with commit-trailer-audited bypass) and, when run on the FrankenFS
checkout without --pre-push-only, the perf-ledger pre-commit hook.
USAGE
            exit 0
            ;;
        *)
            echo "error: unknown argument '$1'" >&2
            exit 64
            ;;
    esac
done

"$SCRIPT_DIR/verify_pre_push_gates.sh" --install-hook --repo "$TARGET_REPO"

if [[ "$PRE_PUSH_ONLY" -eq 0 && -f "$TARGET_REPO/scripts/perf_ledger_preflight.py" && -f "$TARGET_REPO/docs/NEGATIVE_EVIDENCE.md" ]]; then
    PYTHONDONTWRITEBYTECODE=1 python3 "$TARGET_REPO/scripts/perf_ledger_preflight.py" --install-hook
fi
