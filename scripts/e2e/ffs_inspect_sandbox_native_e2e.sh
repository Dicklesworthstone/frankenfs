#!/usr/bin/env bash
# ffs_inspect_sandbox_native_e2e.sh - real FrankenFS readers under the isolated
# inspection launcher (scripts/ffs_inspect_sandbox.py), across all six supported
# filesystem formats (ext4, btrfs, FAT16/FAT32, NTFS, ZFS) plus multi-partition
# GPT slices, hostile/corrupted images, and aggregate cgroup v2 quotas.
#
# Each image is populated from a known source tree or deterministic builder:
# - ext4 by `mke2fs -d`,
# - btrfs by `mkfs.btrfs --rootdir`,
# - FAT16/FAT32 by `ffs-fat format --source-dir` checked by `fsck.fat -n`,
# - NTFS & ZFS via `ffs-cli synthesize-six-format-fixtures` (always) PLUS
#   independent `mkntfs`/`ntfscp`/`ntfscat` (`FFS_REQUIRE_NTFS_TOOLS=1`) and
#   independent `zpool create -d`/`zfs` (`FFS_ZFS_LIVE_POOL_IMAGE` or live
#   `/dev/zfs`, required when `FFS_REQUIRE_ZFS_TOOLS=1`).
#
# Requires prebuilt readers: FFS_BIN_DIR must contain ffs-cli, ffs-fat,
# ffs-ntfs, and ffs-zfs.
# FFS_REQUIRE_SANDBOX=1 turns a missing bubblewrap or tool into a failure.
# FFS_REQUIRE_CGROUP=1 turns missing cgroup v2 / systemd-run scope into a failure.

set -euo pipefail

export PATH="$PATH:/usr/sbin:/sbin"
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

CGROUP_ACTIVE=0
CGROUP_ARGS=()
probe_cgroup_scope() {
    local uid bus
    uid="$(id -u)"
    bus="/run/user/${uid}/bus"
    if [[ -f /sys/fs/cgroup/cgroup.controllers && -x /usr/bin/systemd-run && -S "$bus" ]]; then
        if env PATH="/usr/bin:/bin" LANG=C LC_ALL=C XDG_RUNTIME_DIR="/run/user/${uid}" \
            /usr/bin/systemd-run --user --scope --quiet --collect \
            -p MemoryMax=67108864 -p MemorySwapMax=0 -p TasksMax=16 -p CPUQuota=100% \
            -- /usr/bin/true >/dev/null 2>&1; then
            CGROUP_ACTIVE=1
            CGROUP_ARGS=(--cgroup-memory-mib 512 --cgroup-pids-max 32 --cgroup-cpu-quota-pct 200)
            return 0
        fi
    fi
    if [[ "${FFS_REQUIRE_CGROUP:-}" == "1" ]]; then
        e2e_fail "FFS_REQUIRE_CGROUP=1 but systemd-run --user --scope cgroup v2 enforcement is unavailable"
    fi
    return 0
}

# Run the launcher; prints nothing, leaves evidence in $RUNS/$1.
sandboxed() {
    local name="$1" tool="$2" image="$3"
    shift 3
    python3 -I "$LAUNCHER" --tool "$tool" --binary "$FFS_BIN_DIR/$tool" \
        --input "disk=$image" --output "$RUNS/$name" --wall-seconds 120 \
        "${CGROUP_ARGS[@]}" -- "$@" \
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

expect_ok() {
    local id="$1" run="$2" detail="${3:-sandboxed command succeeded; input unchanged}"
    local success unchanged confirmed
    success=$(result_field "$run" success)
    unchanged=$(result_field "$run" reader_and_inputs_unchanged)
    confirmed=$(result_field "$run" execution_confirmed)
    if [[ "$success" == "True" && "$unchanged" == "True" && "$confirmed" == "True" ]]; then
        scenario_result "$id" "PASS" "$detail"
    else
        scenario_result "$id" "FAIL" "success=$success unchanged=$unchanged confirmed=$confirmed stderr=$(head -c 300 "$RUNS/$run/stderr.bin" 2>/dev/null | tr '\n' ' ')"
    fi
}

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
for reader_bin in ffs-cli ffs-fat ffs-ntfs ffs-zfs; do
    [[ -n "$FFS_BIN_DIR" && -x "$FFS_BIN_DIR/$reader_bin" ]] \
        || require_or_skip "FFS_BIN_DIR must contain executable $reader_bin"
done
[[ -x /usr/bin/bwrap ]] || require_or_skip "bubblewrap is not installed"
for tool in mke2fs mkfs.btrfs fsck.fat; do
    command -v "$tool" >/dev/null || require_or_skip "$tool is not installed"
done
probe_cgroup_scope
e2e_log "readers: $FFS_BIN_DIR (ffs-cli $(sha "$FFS_BIN_DIR/ffs-cli" | head -c 16), ffs-fat $(sha "$FFS_BIN_DIR/ffs-fat" | head -c 16), ffs-ntfs $(sha "$FFS_BIN_DIR/ffs-ntfs" | head -c 16), ffs-zfs $(sha "$FFS_BIN_DIR/ffs-zfs" | head -c 16)); cgroup_active=$CGROUP_ACTIVE"

SRC="$WORK/source"
mkdir -p "$SRC/docs"
head -c 200000 /dev/urandom >"$SRC/payload.bin"
printf 'sandboxed native read\n' >"$SRC/docs/note.txt"
printf 'hello from fat16\n' >"$WORK/expected_fat16.txt"
printf 'hello from ext4\n' >"$WORK/expected_ext4.txt"
printf 'hello from ntfs\n' >"$WORK/expected_ntfs.txt"
printf 'secret alternate stream\n' >"$WORK/expected_ntfs_ads.txt"
printf 'hello from zfs\n' >"$WORK/expected_zfs.txt"

e2e_step "Synthesize deterministic six-format + GPT fixtures"
"$FFS_BIN_DIR/ffs-cli" synthesize-six-format-fixtures "$WORK/synth" --json >"$WORK/synth.json"

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

e2e_step "NTFS native reader (ffs-ntfs + ffs-cli) inside sandbox"
sandboxed ntfs_inspect ffs-ntfs "$WORK/synth/ntfs.img" inspect @disk --offline-image
expect_ok ntfs_inspect_ok ntfs_inspect "ffs-ntfs inspect verified NTFS 3.1 geometry and MFT mirror"
sandboxed ntfs_read ffs-ntfs "$WORK/synth/ntfs.img" read @disk /hello.txt --offline-image
expect_extraction ntfs_read_matches_source ntfs_read "$WORK/expected_ntfs.txt"
sandboxed ntfs_ads ffs-ntfs "$WORK/synth/ntfs.img" read @disk /hello.txt --offline-image --stream note
expect_extraction ntfs_ads_matches_source ntfs_ads "$WORK/expected_ntfs_ads.txt"
sandboxed ntfs_alloc ffs-ntfs "$WORK/synth/ntfs.img" check-allocation @disk --offline-image
expect_ok ntfs_check_allocation_ok ntfs_alloc "ffs-ntfs check-allocation reconciled volume bitmap"
sandboxed ntfs_cli_streams ffs-cli "$WORK/synth/ntfs.img" streams @disk /hello.txt --offline-image --stream note
expect_extraction ntfs_cli_streams_matches_source ntfs_cli_streams "$WORK/expected_ntfs_ads.txt"

if command -v mkntfs >/dev/null && command -v ntfscp >/dev/null && command -v ntfscat >/dev/null; then
    e2e_step "NTFS built by independent mkntfs + ntfscp, checked by ntfscat"
    truncate -s 32M "$WORK/mkntfs.img"
    mkntfs -F -Q -s 512 -c 4096 -L FFSNTFS "$WORK/mkntfs.img" >"$WORK/mkntfs.log" 2>&1
    ntfscp "$WORK/mkntfs.img" "$SRC/payload.bin" /payload.bin
    ntfscp -N note "$WORK/mkntfs.img" "$SRC/docs/note.txt" /payload.bin
    ntfscat "$WORK/mkntfs.img" /payload.bin >"$WORK/mkntfs.ntfscat.payload"
    ntfscat -n note "$WORK/mkntfs.img" /payload.bin >"$WORK/mkntfs.ntfscat.note"
    if [[ "$(sha "$WORK/mkntfs.ntfscat.payload")" == "$(sha "$SRC/payload.bin")" ]] \
        && [[ "$(sha "$WORK/mkntfs.ntfscat.note")" == "$(sha "$SRC/docs/note.txt")" ]]; then
        scenario_result mkntfs_independent_check PASS "ntfscat verified unnamed DATA and ADS on mkntfs image"
    else
        scenario_result mkntfs_independent_check FAIL "ntfscat verification failed on mkntfs image"
    fi
    sandboxed mkntfs_read ffs-ntfs "$WORK/mkntfs.img" read @disk /payload.bin --offline-image
    expect_extraction mkntfs_read_matches_source mkntfs_read "$SRC/payload.bin"
    sandboxed mkntfs_ads ffs-ntfs "$WORK/mkntfs.img" read @disk /payload.bin --offline-image --stream note
    expect_extraction mkntfs_ads_matches_source mkntfs_ads "$SRC/docs/note.txt"
    sandboxed mkntfs_cli_read ffs-cli "$WORK/mkntfs.img" read @disk /payload.bin --offline-image
    expect_extraction mkntfs_cli_read_matches_source mkntfs_cli_read "$SRC/payload.bin"
elif [[ "${FFS_REQUIRE_NTFS_TOOLS:-}" == "1" ]]; then
    e2e_fail "FFS_REQUIRE_NTFS_TOOLS=1 but mkntfs/ntfscp/ntfscat are not installed"
else
    e2e_log "mkntfs/ntfscp/ntfscat not installed on this host; synthesized NTFS suite ran"
fi

e2e_step "ZFS native reader (ffs-zfs + ffs-cli) inside sandbox"
sandboxed zfs_inspect ffs-zfs "$WORK/synth/zfs.img" inspect @disk --offline-image
expect_ok zfs_inspect_ok zfs_inspect "ffs-zfs inspect inventoried 4 checksum-valid labels"
sandboxed zfs_datasets ffs-zfs "$WORK/synth/zfs.img" datasets @disk --offline-image --auto-import
expect_ok zfs_datasets_ok zfs_datasets "ffs-zfs datasets enumerated MOS head datasets"
sandboxed zfs_snapshots ffs-zfs "$WORK/synth/zfs.img" snapshots @disk --offline-image --auto-import
expect_ok zfs_snapshots_ok zfs_snapshots "ffs-zfs snapshots enumerated @snap1"
sandboxed zfs_read ffs-zfs "$WORK/synth/zfs.img" read @disk /hello.txt --offline-image --auto-import
expect_extraction zfs_read_matches_source zfs_read "$WORK/expected_zfs.txt"
sandboxed zfs_snap_read ffs-zfs "$WORK/synth/zfs.img" read @disk /hello.txt --offline-image --auto-import --snapshot snap1
expect_extraction zfs_snapshot_read_matches_source zfs_snap_read "$WORK/expected_zfs.txt"
sandboxed zfs_scrub ffs-zfs "$WORK/synth/zfs.img" scrub @disk --offline-image --auto-import
expect_ok zfs_scrub_ok zfs_scrub "ffs-zfs scrub verified DMU checksums"
sandboxed zfs_cli_read ffs-cli "$WORK/synth/zfs.img" read @disk /hello.txt --offline-image --zfs-auto-import
expect_extraction zfs_cli_read_matches_source zfs_cli_read "$WORK/expected_zfs.txt"

ZFS_LIVE_IMAGE="${FFS_ZFS_LIVE_POOL_IMAGE:-}"
ZFS_LIVE_PAYLOAD="${FFS_ZFS_LIVE_PAYLOAD:-}"
ZFS_LIVE_DATASET="${FFS_ZFS_LIVE_DATASET:-data}"
if [[ -n "$ZFS_LIVE_IMAGE" && -f "$ZFS_LIVE_IMAGE" && -n "$ZFS_LIVE_PAYLOAD" && -f "$ZFS_LIVE_PAYLOAD" ]]; then
    e2e_step "ZFS pool built by independent OpenZFS zpool/zfs"
    sandboxed zpool_live_inspect ffs-zfs "$ZFS_LIVE_IMAGE" inspect @disk --offline-image
    expect_ok zpool_live_inspect_ok zpool_live_inspect "ffs-zfs inspect validated OpenZFS 4-label pool"
    sandboxed zpool_live_read ffs-zfs "$ZFS_LIVE_IMAGE" read @disk /payload.bin --offline-image --auto-import --dataset "$ZFS_LIVE_DATASET"
    expect_extraction zpool_live_read_matches_source zpool_live_read "$ZFS_LIVE_PAYLOAD"
    sandboxed zpool_live_scrub ffs-zfs "$ZFS_LIVE_IMAGE" scrub @disk --offline-image --auto-import --dataset "$ZFS_LIVE_DATASET"
    expect_ok zpool_live_scrub_ok zpool_live_scrub "ffs-zfs scrub verified OpenZFS DMU blocks"
    sandboxed zpool_live_alloc ffs-zfs "$ZFS_LIVE_IMAGE" allocation @disk --offline-image --auto-import
    expect_ok zpool_live_allocation_ok zpool_live_alloc "ffs-zfs allocation verified OpenZFS metaslab space maps"
    sandboxed zpool_live_cli_read ffs-cli "$ZFS_LIVE_IMAGE" read @disk /payload.bin --offline-image --zfs-auto-import --zfs-dataset "$ZFS_LIVE_DATASET"
    expect_extraction zpool_live_cli_read_matches_source zpool_live_cli_read "$ZFS_LIVE_PAYLOAD"
elif [[ "${FFS_REQUIRE_ZFS_TOOLS:-}" == "1" ]]; then
    e2e_fail "FFS_REQUIRE_ZFS_TOOLS=1 but FFS_ZFS_LIVE_POOL_IMAGE / FFS_ZFS_LIVE_PAYLOAD was not supplied"
else
    e2e_log "OpenZFS live pool image not supplied on this host; synthesized ZFS suite ran"
fi

e2e_step "GPT multi-partition whole-disk extraction inside sandbox"
sandboxed gpt_parts ffs-cli "$WORK/synth/gpt_multi.img" partitions @disk --json
expect_ok gpt_partitions_enumerated gpt_parts "ffs-cli partitions enumerated 4 GPT slices"
sandboxed gpt_p1 ffs-cli "$WORK/synth/gpt_multi.img" read @disk /hello.txt --partition 1
expect_extraction gpt_p1_fat16_matches_source gpt_p1 "$WORK/expected_fat16.txt"
sandboxed gpt_p2 ffs-cli "$WORK/synth/gpt_multi.img" read @disk /hello.txt --partition 2
expect_extraction gpt_p2_ext4_matches_source gpt_p2 "$WORK/expected_ext4.txt"
sandboxed gpt_p3 ffs-cli "$WORK/synth/gpt_multi.img" read @disk /hello.txt --partition 3 --offline-image
expect_extraction gpt_p3_ntfs_matches_source gpt_p3 "$WORK/expected_ntfs.txt"
sandboxed gpt_p4 ffs-cli "$WORK/synth/gpt_multi.img" read @disk /hello.txt --partition 4 --offline-image --zfs-auto-import
expect_extraction gpt_p4_zfs_matches_source gpt_p4 "$WORK/expected_zfs.txt"

e2e_step "Hostile and corrupted images across formats"
head -c 8388608 /dev/urandom >"$WORK/random.img"
sandboxed random_inspect ffs-cli "$WORK/random.img" inspect @disk --json
expect_refusal random_bytes_refused random_inspect
head -c 1048576 "$WORK/fat32.img" >"$WORK/truncated_fat32.img"
sandboxed truncated_fat_ls ffs-fat "$WORK/truncated_fat32.img" ls @disk /
expect_refusal truncated_fat32_refused truncated_fat_ls
head -c 8192 "$WORK/synth/ntfs.img" >"$WORK/truncated_ntfs.img"
sandboxed truncated_ntfs_ls ffs-ntfs "$WORK/truncated_ntfs.img" ls @disk / --offline-image
expect_refusal truncated_ntfs_refused truncated_ntfs_ls
cp "$WORK/synth/zfs.img" "$WORK/corrupt_zfs.img"
dd if=/dev/urandom of="$WORK/corrupt_zfs.img" bs=4096 seek=1040 count=8 conv=notrunc status=none
sandboxed corrupt_zfs_read ffs-zfs "$WORK/corrupt_zfs.img" read @disk /hello.txt --offline-image --auto-import
expect_refusal corrupted_zfs_refused corrupt_zfs_read

e2e_step "Evidence records the enforced policy and cgroup quotas"
policy_ok=1
for run in "$RUNS"/*/; do
    python3 -I - "$run/request.json" "$run/result.json" "$CGROUP_ACTIVE" <<'EOF' || policy_ok=0
import json, sys
request = json.load(open(sys.argv[1]))
result = json.load(open(sys.argv[2]))
cgroup_active = sys.argv[3] == "1"
assert request["policy"] == "ffs-offline-reader-v2", request["policy"]
assert len(request["seccomp"]["sha256"]) == 64
assert "socket" in request["seccomp"]["denied_syscalls"]
assert "cgroup" in request and "cgroup" in result
if cgroup_active:
    assert request["cgroup"]["enabled"] is True, request["cgroup"]
    assert request["cgroup"]["memory_bytes"] == 512 * 1024 * 1024, request["cgroup"]
    assert request["cgroup"]["swap_max"] == 0, request["cgroup"]
    assert request["cgroup"]["pids_max"] == 32, request["cgroup"]
    assert request["cgroup"]["cpu_quota_pct"] == 200, request["cgroup"]
    assert request["cgroup"]["scope_unit"].endswith(".scope"), request["cgroup"]
    assert len(request["cgroup"]["systemd_run_sha256"]) == 64, request["cgroup"]
    assert result["cgroup"]["enabled"] is True, result["cgroup"]
    assert result["cgroup"]["scope_unit"] == request["cgroup"]["scope_unit"], result["cgroup"]
EOF
done
if [[ "$policy_ok" == 1 ]]; then
    scenario_result evidence_records_policy PASS "every request.json and result.json records policy v2, seccomp, and cgroup state (cgroup_active=$CGROUP_ACTIVE)"
else
    scenario_result evidence_records_policy FAIL "a request.json or result.json lacks the policy, seccomp, or cgroup record"
fi

e2e_log ""
e2e_log "Summary: ${PASS_COUNT}/${TOTAL} passed, ${FAIL_COUNT} failed; evidence in $RUNS"
if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_fail "${FAIL_COUNT} scenario(s) failed"
fi
e2e_pass
