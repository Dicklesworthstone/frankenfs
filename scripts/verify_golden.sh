#!/usr/bin/env bash
# verify_golden.sh — Verify golden output integrity + run conformance checks.
#
# Usage:
#   scripts/verify_golden.sh           # verify all
#   scripts/verify_golden.sh --update  # regenerate checksums after intentional changes
#   scripts/verify_golden.sh --checksums-only
#   scripts/verify_golden.sh --self-check
#
# Exit codes:
#   0 — all golden outputs intact
#   1 — checksum mismatch (behavioral change detected)
#
# This script is the canonical verification gate for the isomorphism
# proof protocol, including legacy summary/structural fixture goldens.
# Any optimization PR MUST run this and demonstrate no checksum changes
# (or provide an isomorphism proof explaining why changes are acceptable).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $1"; }
fail() { echo -e "${RED}FAIL${NC} $1"; FAILED=1; }
warn() { echo -e "${YELLOW}WARN${NC} $1"; }

FAILED=0
CHECKSUMS_ONLY=0
SELF_CHECK=0

cargo_exec() {
    rch exec -- cargo "$@"
}

usage() {
    cat <<'EOF'
Usage:
  scripts/verify_golden.sh
  scripts/verify_golden.sh --update
  scripts/verify_golden.sh --checksums-only
  scripts/verify_golden.sh --self-check

Options:
  --update          Regenerate checksum manifests after intentional changes.
  --checksums-only  Verify checksum manifests, git-tracked entries, and
                    tracked artifact coverage only.
  --self-check      Run local fail-closed checks for --checksums-only using
                    temporary copied fixtures. Does not run cargo.
EOF
}

write_json_checksums() {
    local dir="$1"
    local out="$2"
    (
        cd "$dir"
        # Recurse into nested fixture subdirectories (`%P` = path relative to
        # the start dir) so the manifest covers every tracked .json, matching
        # the recursive `git ls-files` coverage contract enforced below.
        mapfile -t files < <(find . -type f -name '*.json' -printf '%P\n' | sort)
        if [[ ${#files[@]} -eq 0 ]]; then
            echo "no JSON checksum inputs found in $dir" >&2
            return 1
        fi
        sha256sum "${files[@]}" > "$out"
    )
}

write_conformance_golden_checksums() {
    (
        cd conformance/golden
        # Recurse (path-relative `%P`) so nested golden artifacts stay covered,
        # consistent with the recursive coverage check.
        mapfile -t files < <(
            find . -type f \( -name '*.json' -o -name '*.txt' \) -printf '%P\n' | sort
        )
        if [[ ${#files[@]} -eq 0 ]]; then
            echo "no conformance golden checksum inputs found" >&2
            return 1
        fi
        sha256sum "${files[@]}" > checksums.sha256
    )
}

verify_manifest_entries_tracked() {
    local dir="$1"
    local manifest="$2"
    local label="$3"
    local line digest file path
    local untracked=0

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        digest="${line%% *}"
        file="${line#*  }"
        if [ "$file" = "$line" ]; then
            file="${line#* }"
        fi
        file="${file#\*}"

        if [ -z "$digest" ] || [ -z "$file" ] || [ "$file" = "$line" ]; then
            fail "$label checksum manifest has malformed entry: $line"
            untracked=1
            continue
        fi

        if [[ "$file" = /* || "$file" = ".." || "$file" = ../* || "$file" = */../* || "$file" = */.. ]]; then
            fail "$label checksum manifest references path outside its directory: $file"
            untracked=1
            continue
        fi

        path="$dir/$file"
        if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
            fail "$label checksum manifest references untracked or ignored file: $file"
            untracked=1
        fi
    done < "$dir/$manifest"

    if [ "$untracked" -eq 0 ]; then
        pass "$label checksum entries are tracked by git"
    fi
}

checksum_manifest_tracks_extension() {
    local file="$1"
    shift

    local extension="${file##*.}"
    if [ "$extension" = "$file" ]; then
        return 1
    fi

    local tracked
    for tracked in "$@"; do
        if [ "${extension,,}" = "${tracked,,}" ]; then
            return 0
        fi
    done

    return 1
}

verify_tracked_artifacts_listed() {
    local dir="$1"
    local manifest="$2"
    local label="$3"
    shift 3
    local tracked_extensions=("$@")
    local line digest file tracked_path artifact_file
    local unlisted=0
    local -A listed_files=()

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        digest="${line%% *}"
        file="${line#*  }"
        if [ "$file" = "$line" ]; then
            file="${line#* }"
        fi
        file="${file#\*}"

        if [ -z "$digest" ] || [ -z "$file" ] || [ "$file" = "$line" ]; then
            continue
        fi

        listed_files["$file"]=1
    done < "$dir/$manifest"

    while IFS= read -r tracked_path; do
        artifact_file="${tracked_path#"$dir"/}"
        if [ "$artifact_file" = "$tracked_path" ]; then
            continue
        fi
        if ! checksum_manifest_tracks_extension "$artifact_file" "${tracked_extensions[@]}"; then
            continue
        fi
        if [ -z "${listed_files[$artifact_file]+x}" ]; then
            fail "$label tracked artifact is missing from checksum manifest $manifest: $artifact_file"
            unlisted=1
        fi
    done < <(git ls-files -- "$dir")

    if [ "$unlisted" -eq 0 ]; then
        pass "$label tracked artifacts are listed in checksum manifest"
    fi
}

copy_self_check_workspace() {
    local case_name="$1"
    local root

    root="$(mktemp -d -t "ffs_verify_golden_${case_name}_XXXXXX")"
    mkdir -p "$root/scripts" "$root/conformance" "$root/tests/fixtures"

    cp scripts/verify_golden.sh "$root/scripts/verify_golden.sh"
    cp -a conformance/fixtures "$root/conformance/fixtures"
    cp -a conformance/golden "$root/conformance/golden"
    cp -a tests/fixtures/golden "$root/tests/fixtures/golden"

    git -C "$root" init -q
    git -C "$root" add \
        scripts/verify_golden.sh \
        conformance/fixtures \
        conformance/golden \
        tests/fixtures/golden

    printf '%s\n' "$root"
}

run_self_check_clean_copy() {
    local root log

    root="$(copy_self_check_workspace clean)"
    log="$root/verify_golden_clean.log"

    if (cd "$root" && bash scripts/verify_golden.sh --checksums-only >"$log" 2>&1); then
        pass "self-check clean copied checksum workspace passes"
    else
        fail "self-check clean copied checksum workspace failed; log=$log"
    fi
    echo "  preserved: $root"
}

run_self_check_corrupted_artifact() {
    local root log

    root="$(copy_self_check_workspace corrupt)"
    log="$root/verify_golden_corrupt.log"
    printf '\n# self-check checksum corruption\n' >>"$root/conformance/fixtures/ext4_superblock_sparse.json"

    if (cd "$root" && bash scripts/verify_golden.sh --checksums-only >"$log" 2>&1); then
        fail "self-check corrupted listed artifact was accepted; log=$log"
    elif grep -q "MISMATCH" "$log"; then
        pass "self-check corrupted listed artifact fails checksum gate"
    else
        fail "self-check corrupted listed artifact failed without mismatch diagnostic; log=$log"
    fi
    echo "  preserved: $root"
}

run_self_check_untracked_manifest_entry() {
    local root log

    root="$(copy_self_check_workspace untracked)"
    log="$root/verify_golden_untracked.log"
    (
        cd "$root/conformance/fixtures"
        printf '{"self_check":"untracked"}\n' > untracked_self_check.json
        sha256sum untracked_self_check.json >> checksums.sha256
    )

    if (cd "$root" && bash scripts/verify_golden.sh --checksums-only >"$log" 2>&1); then
        fail "self-check untracked manifest entry was accepted; log=$log"
    elif grep -q "untracked or ignored file" "$log"; then
        pass "self-check untracked manifest entry fails tracked-entry gate"
    else
        fail "self-check untracked manifest entry failed without tracked-entry diagnostic; log=$log"
    fi
    echo "  preserved: $root"
}

run_self_check() {
    echo "=== Golden Checksum Gate Self-Check ==="
    echo ""
    echo "Temporary workspaces are preserved for inspection."
    echo ""

    run_self_check_clean_copy
    run_self_check_corrupted_artifact
    run_self_check_untracked_manifest_entry

    echo ""
    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}Golden checksum gate self-check passed.${NC}"
        exit 0
    fi
    echo -e "${RED}Golden checksum gate self-check FAILED.${NC}"
    exit 1
}

case "${1:-}" in
    "")
        ;;
    "--checksums-only")
        CHECKSUMS_ONLY=1
        ;;
    "--self-check")
        SELF_CHECK=1
        ;;
    "--update")
        echo "Updating checksums..."
        write_json_checksums conformance/fixtures checksums.sha256
        write_conformance_golden_checksums
        write_json_checksums tests/fixtures/golden checksums.txt
        echo "Checksums updated. Review and commit."
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if [ "$SELF_CHECK" -eq 1 ]; then
    run_self_check
fi

echo "=== Golden Output Verification ==="
echo ""

# ── 1. Fixture checksums ────────────────────────────────────────
echo "--- Fixture checksums ---"
if (cd conformance/fixtures && sha256sum -c checksums.sha256 --quiet 2>/dev/null); then
    pass "conformance/fixtures/ checksums match"
else
    fail "conformance/fixtures/ checksums MISMATCH"
    echo "  Run: scripts/verify_golden.sh --update  (after verifying changes are correct)"
fi
verify_manifest_entries_tracked conformance/fixtures checksums.sha256 "conformance/fixtures"
verify_tracked_artifacts_listed conformance/fixtures checksums.sha256 "conformance/fixtures" json

# ── 2. Golden reference checksums ────────────────────────────────
echo "--- Golden reference checksums ---"
if (cd conformance/golden && sha256sum -c checksums.sha256 --quiet 2>/dev/null); then
    pass "conformance/golden/ checksums match"
else
    fail "conformance/golden/ checksums MISMATCH"
    echo "  Run: scripts/verify_golden.sh --update  (after verifying changes are correct)"
fi
verify_manifest_entries_tracked conformance/golden checksums.sha256 "conformance/golden"
verify_tracked_artifacts_listed conformance/golden checksums.sha256 "conformance/golden" json txt

# ── 3. Legacy fixture checksums ───────────────────────────────────
echo "--- Legacy fixture checksums ---"
if (cd tests/fixtures/golden && sha256sum -c checksums.txt --quiet 2>/dev/null); then
    pass "tests/fixtures/golden/ checksums match"
else
    fail "tests/fixtures/golden/ checksums MISMATCH"
    echo "  Run: scripts/verify_golden.sh --update  (after verifying changes are correct)"
fi
verify_manifest_entries_tracked tests/fixtures/golden checksums.txt "tests/fixtures/golden"
verify_tracked_artifacts_listed tests/fixtures/golden checksums.txt "tests/fixtures/golden" json

if [ "$CHECKSUMS_ONLY" -eq 1 ]; then
    echo ""
    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}All checksum manifest checks passed.${NC}"
        exit 0
    fi
    echo -e "${RED}Checksum manifest verification FAILED.${NC}"
    exit 1
fi

# ── 4. Parity report consistency ─────────────────────────────────
echo "--- Parity report ---"
if cargo_exec test -p ffs-harness -- parity_report_matches_feature_parity_md --quiet; then
    pass "ParityReport matches FEATURE_PARITY.md"
else
    fail "ParityReport vs FEATURE_PARITY.md mismatch"
fi

if cargo_exec run -p ffs-harness -- parity --verify ext4-journal --local; then
    pass "current external and internal journal contracts executed"
else
    fail "journal parity execution failed, skipped, stale, or selected no tests"
fi

# ── 5. Conformance fixture validation ────────────────────────────
echo "--- Conformance fixtures ---"
if cargo_exec test -p ffs-harness --test conformance --quiet; then
    pass "all conformance fixtures validate"
else
    fail "conformance fixture validation failed"
fi

# ── 6. Golden JSON structural validation ─────────────────────────
echo "--- Golden JSON validation ---"
if cargo_exec test -p ffs-harness --test kernel_reference golden_json_parses_and_is_consistent --quiet; then
    pass "golden JSON parses and is consistent"
else
    fail "golden JSON validation failed"
fi

# ── 7. Summary ───────────────────────────────────────────────────
echo ""
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All golden output checks passed.${NC}"
    echo "Safe to proceed with optimization — behavior is unchanged."
else
    echo -e "${RED}Golden output verification FAILED.${NC}"
    echo ""
    echo "If changes are intentional, provide an isomorphism proof:"
    echo "  1. Copy docs/templates/ISOMORPHISM_PROOF_TEMPLATE.md into your PR description"
    echo "  2. Fill out each field"
    echo "  3. Run: scripts/verify_golden.sh --update"
    echo "  4. Commit the updated checksums"
    exit 1
fi
