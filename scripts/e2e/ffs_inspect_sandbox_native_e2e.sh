#!/usr/bin/env bash
# ffs_inspect_sandbox_native_e2e.sh - real FrankenFS readers under the isolated
# inspection launcher (scripts/ffs_inspect_sandbox.py), on images built by
# independent tools where they exist.
#
# Each image is populated from a known source tree: ext4 by `mke2fs -d`, btrfs
# by `mkfs.btrfs --rootdir`, FAT16/FAT32 by `ffs-fat format --source-dir` and
# then checked by `fsck.fat -n`. A sandboxed native reader extracts a payload,
# and its stdout must match the source bytes. Hostile images must fail inside
# the sandbox without hanging and without changing the input.
#
# NTFS and ZFS are not exercised: no independent image builder (mkntfs, zpool)
# is assumed on the host.
#
# Requires prebuilt readers: FFS_BIN_DIR must contain ffs-cli and ffs-fat.
# FFS_REQUIRE_SANDBOX=1 turns a missing bubblewrap or tool into a failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/lib.sh"
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
e2e_init "ffs_inspect_sandbox_native"
exec > >(tee -a "$E2E_LOG_FILE") 2>&1

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
LAUNCHER="$PROJECT_ROOT/scripts/ffs_inspect_sandbox.py"
RUNS="$E2E_LOG_DIR/runs"
WORK="$E2E_TEMP_DIR/work"
mkdir -p "$RUNS" "$WORK"

scenario_result() {
    local scenario_id="$1" outcome="$2" detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

require_or_skip() {
    local reason="$1"
    if [[ "${FFS_REQUIRE_SANDBOX:-}" == "1" ]]; then
        e2e_fail "FFS_REQUIRE_SANDBOX=1 but $reason"
    fi
    e2e_skip "$reason"
}

# Run the launcher; prints nothing, leaves evidence in $RUNS/$1.
sandboxed() {
    local name="$1" tool="$2" image="$3"
    shift 3
    python3 -I "$LAUNCHER" --tool "$tool" --binary "$FFS_BIN_DIR/$tool" \
        --input "disk=$image" --output "$RUNS/$name" --wall-seconds 120 -- "$@" \
        >"$RUNS/$name.launcher.log" 2>&1 || true
}

# Field of result.json (python literal), or MISSING.
result_field() {
    python3 -I - "$RUNS/$1/result.json" "$2" <<'EOF'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get(sys.argv[2], "MISSING"))
except (OSError, ValueError):
    print("MISSING")
EOF
}

sha() { sha256sum "$1" | cut -d' ' -f1; }

expect_extraction() {
    local id="$1" run="$2" source_file="$3"
    local success unchanged confirmed
    success=$(result_field "$run" success)
    unchanged=$(result_field "$run" reader_and_inputs_unchanged)
    confirmed=$(result_field "$run" execution_confirmed)
    if [[ "$success" == "True" && "$unchanged" == "True" && "$confirmed" == "True" ]] \
        && [[ "$(sha "$RUNS/$run/stdout.bin")" == "$(sha "$source_file")" ]]; then
        scenario_result "$id" "PASS" "sandboxed extraction matches source sha256; input unchanged"
    else
        scenario_result "$id" "FAIL" "success=$success unchanged=$unchanged confirmed=$confirmed stderr=$(head -c 300 "$RUNS/$run/stderr.bin" 2>/dev/null | tr '\n' ' ')"
    fi
}

expect_refusal() {
    local id="$1" run="$2"
    local success unchanged termination
    success=$(result_field "$run" success)
    unchanged=$(result_field "$run" reader_and_inputs_unchanged)
    termination=$(result_field "$run" termination)
    if [[ "$success" == "False" && "$unchanged" == "True" && "$termination" == "None" ]]; then
        scenario_result "$id" "PASS" "hostile image refused inside the sandbox; completed result; input unchanged"
    else
        scenario_result "$id" "FAIL" "success=$success unchanged=$unchanged termination=$termination"
    fi
}

e2e_step "Preflight"
FFS_BIN_DIR="${FFS_BIN_DIR:-}"
[[ -n "$FFS_BIN_DIR" && -x "$FFS_BIN_DIR/ffs-cli" && -x "$FFS_BIN_DIR/ffs-fat" ]] \
    || require_or_skip "FFS_BIN_DIR must contain executable ffs-cli and ffs-fat"
[[ -x /usr/bin/bwrap ]] || require_or_skip "bubblewrap is not installed"
for tool in mke2fs mkfs.btrfs fsck.fat; do
    command -v "$tool" >/dev/null || require_or_skip "$tool is not installed"
done
e2e_log "readers: $FFS_BIN_DIR (ffs-cli $(sha "$FFS_BIN_DIR/ffs-cli" | head -c 16), ffs-fat $(sha "$FFS_BIN_DIR/ffs-fat" | head -c 16))"

SRC="$WORK/source"
mkdir -p "$SRC/docs"
head -c 200000 /dev/urandom >"$SRC/payload.bin"
printf 'sandboxed native read\n' >"$SRC/docs/note.txt"

e2e_step "ext4 built by mke2fs -d"
truncate -s 64M "$WORK/ext4.img"
mke2fs -q -F -t ext4 -d "$SRC" "$WORK/ext4.img"
sandboxed ext4_inspect ffs-cli "$WORK/ext4.img" inspect @disk --json
if [[ "$(result_field ext4_inspect success)" == "True" ]] && grep -qi ext4 "$RUNS/ext4_inspect/stdout.bin"; then
    scenario_result ext4_inspect PASS "sandboxed inspect identified ext4"
else
    scenario_result ext4_inspect FAIL "$(head -c 300 "$RUNS/ext4_inspect/stderr.bin" 2>/dev/null)"
fi
sandboxed ext4_read ffs-cli "$WORK/ext4.img" read @disk /payload.bin
expect_extraction ext4_read_matches_source ext4_read "$SRC/payload.bin"

e2e_step "btrfs built by mkfs.btrfs --rootdir"
truncate -s 160M "$WORK/btrfs.img"
mkfs.btrfs -q -f --rootdir "$SRC" "$WORK/btrfs.img" >/dev/null
sandboxed btrfs_read ffs-cli "$WORK/btrfs.img" read @disk /payload.bin
expect_extraction btrfs_read_matches_source btrfs_read "$SRC/payload.bin"

for kind in fat16 fat32; do
    e2e_step "$kind built by ffs-fat format, checked by fsck.fat -n"
    "$FFS_BIN_DIR/ffs-fat" format "$WORK/$kind.img" --kind "$kind" --size-mib 64 --source-dir "$SRC" \
        >"$WORK/$kind.format.log" 2>&1
    if fsck.fat -n "$WORK/$kind.img" >"$WORK/$kind.fsck.log" 2>&1; then
        scenario_result "${kind}_independent_check" PASS "fsck.fat -n accepted the image"
    else
        scenario_result "${kind}_independent_check" FAIL "$(tail -3 "$WORK/$kind.fsck.log" | tr '\n' ' ')"
    fi
    sandboxed "${kind}_cat" ffs-fat "$WORK/$kind.img" cat @disk /payload.bin
    expect_extraction "${kind}_cat_matches_source" "${kind}_cat" "$SRC/payload.bin"
done

e2e_step "Hostile images"
head -c 8388608 /dev/urandom >"$WORK/random.img"
sandboxed random_inspect ffs-cli "$WORK/random.img" inspect @disk --json
expect_refusal random_bytes_refused random_inspect
head -c 1048576 "$WORK/fat32.img" >"$WORK/truncated_fat32.img"
sandboxed truncated_fat_ls ffs-fat "$WORK/truncated_fat32.img" ls @disk /
expect_refusal truncated_fat32_refused truncated_fat_ls

e2e_step "Evidence records the enforced policy"
policy_ok=1
for run in "$RUNS"/*/; do
    python3 -I - "$run/request.json" <<'EOF' || policy_ok=0
import json, sys
request = json.load(open(sys.argv[1]))
assert request["policy"] == "ffs-offline-reader-v2", request["policy"]
assert len(request["seccomp"]["sha256"]) == 64
assert "socket" in request["seccomp"]["denied_syscalls"]
EOF
done
if [[ "$policy_ok" == 1 ]]; then
    scenario_result evidence_records_policy PASS "every request.json records policy v2 and the seccomp filter"
else
    scenario_result evidence_records_policy FAIL "a request.json lacks the policy or filter record"
fi

e2e_log ""
e2e_log "Summary: ${PASS_COUNT}/${TOTAL} passed, ${FAIL_COUNT} failed; evidence in $RUNS"
if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_fail "${FAIL_COUNT} scenario(s) failed"
fi
e2e_pass
