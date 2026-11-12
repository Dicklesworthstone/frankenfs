#!/usr/bin/env bash
# ffs_unified_six_format_cli_e2e.sh - End-to-end verification of the unified
# six-format operator CLI router (`ext4`, `btrfs`, `fat16`, `fat32`, `ntfs`, `zfs`),
# bounded MBR/GPT partition slice discovery (`--partition` index/UUID/label),
# pure-Rust FAT formatting vs explicit `--delegate-host-mkfs` guards, NTFS ADS
# stream extraction, ZFS pool/dataset/snapshot/scrub workflows, and structured
# router telemetry (`ffs::cli::router`).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/lib.sh"
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
e2e_init "ffs_unified_six_format_cli"
exec > >(tee -a "$E2E_LOG_FILE") 2>&1

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
WORK="$E2E_TEMP_DIR/work"
LOGS="$E2E_LOG_DIR/router_logs"
mkdir -p "$WORK" "$LOGS"

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

resolve_ffs_cli() {
    if [[ -n "${FFS_CLI_BIN:-}" && -x "${FFS_CLI_BIN}" ]]; then
        printf '%s\n' "$FFS_CLI_BIN"
        return 0
    fi
    if [[ -n "${FFS_BIN_DIR:-}" && -x "${FFS_BIN_DIR}/ffs-cli" ]]; then
        printf '%s\n' "${FFS_BIN_DIR}/ffs-cli"
        return 0
    fi
    local candidate
    for candidate in \
        "$PROJECT_ROOT/target/debug/ffs-cli" \
        "$PROJECT_ROOT/target/release/ffs-cli" \
        /tmp/cargo-target*/debug/ffs-cli \
        /data/tmp/cargo-target*/debug/ffs-cli; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    cargo build -p ffs-cli --bin ffs-cli >&2
    for candidate in \
        "$PROJECT_ROOT/target/debug/ffs-cli" \
        /tmp/cargo-target*/debug/ffs-cli \
        /data/tmp/cargo-target*/debug/ffs-cli; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

assert_router_log() {
    local stderr_file="$1" expected_format="$2" expected_part="$3"
    python3 - "$stderr_file" "$expected_format" "$expected_part" <<'PY'
import json, sys
path, exp_fmt, exp_part = sys.argv[1], sys.argv[2], sys.argv[3]
matched = False
with open(path, "r", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("target") == "ffs::cli::router" and rec.get("message") == "six_format_router_complete":
            assert rec.get("format") == exp_fmt, f"expected format={exp_fmt}, got {rec}"
            assert rec.get("partition_id") == exp_part, f"expected partition_id={exp_part}, got {rec}"
            assert rec.get("capability_admitted") is True, f"expected capability_admitted=True, got {rec}"
            if "backing_sha256_unchanged" in rec:
                assert rec.get("backing_sha256_unchanged") is True, f"backing image mutated: {rec}"
            matched = True
assert matched, f"missing ffs::cli::router JSON event in {path}"
PY
}

e2e_step "Locate ffs-cli binary and synthesize six-format + GPT fixtures"
CLI_BIN="$(resolve_ffs_cli)"
e2e_log "Using ffs-cli: $CLI_BIN"

FIXTURES="$WORK/fixtures"
"$CLI_BIN" synthesize-six-format-fixtures "$FIXTURES" --json >"$LOGS/manifest.json" 2>"$LOGS/synth.stderr"
scenario_result "synthesize_six_format_fixtures" "PASS" "generated ext4, btrfs, fat16, fat32, ntfs, zfs, and gpt_multi images"

declare -A BEFORE_SHA
for img in ext4 btrfs fat16 fat32 ntfs zfs gpt_multi; do
    BEFORE_SHA["$img"]="$(sha256sum "$FIXTURES/${img}.img" | awk '{print $1}')"
done

e2e_step "Verify fail-closed admission & formatting guards"
if "$CLI_BIN" inspect "$FIXTURES/ntfs.img" --json >"$LOGS/ntfs_no_offline.out" 2>"$LOGS/ntfs_no_offline.err"; then
    scenario_result "ntfs_requires_offline_image" "FAIL" "accepted NTFS without --offline-image"
else
    scenario_result "ntfs_requires_offline_image" "PASS" "refused NTFS without --offline-image"
fi

if "$CLI_BIN" inspect "$FIXTURES/zfs.img" --json >"$LOGS/zfs_no_offline.out" 2>"$LOGS/zfs_no_offline.err"; then
    scenario_result "zfs_requires_offline_image" "FAIL" "accepted ZFS without --offline-image"
else
    scenario_result "zfs_requires_offline_image" "PASS" "refused ZFS without --offline-image"
fi

if "$CLI_BIN" format "$WORK/refused_ext4.img" --filesystem ext4 --size-mib 16 >"$LOGS/fmt_ext4_refused.out" 2>"$LOGS/fmt_ext4_refused.err"; then
    scenario_result "format_ext4_requires_delegation_flag" "FAIL" "formatted ext4 without --delegate-host-mkfs"
else
    [[ ! -e "$WORK/refused_ext4.img" ]]
    scenario_result "format_ext4_requires_delegation_flag" "PASS" "refused unacknowledged host mkfs.ext4 delegation"
fi

if "$CLI_BIN" mkfs "$WORK/refused_mkfs.img" >"$LOGS/mkfs_refused.out" 2>"$LOGS/mkfs_refused.err"; then
    scenario_result "mkfs_requires_delegation_flag" "FAIL" "ran mkfs without --delegate-host-mkfs"
else
    [[ ! -e "$WORK/refused_mkfs.img" ]]
    scenario_result "mkfs_requires_delegation_flag" "PASS" "refused unacknowledged mkfs delegation"
fi

e2e_step "Verify pure-Rust FAT16/FAT32 format subcommand"
for fat_kind in fat16 fat32; do
    size_mib=8
    [[ "$fat_kind" == "fat32" ]] && size_mib=64
    out_img="$WORK/formatted_${fat_kind}.img"
    "$CLI_BIN" --log-format json format "$out_img" --filesystem "$fat_kind" --size-mib "$size_mib" --label "RUSTFAT" --json \
        >"$LOGS/format_${fat_kind}.json" 2>"$LOGS/format_${fat_kind}.stderr"
    assert_router_log "$LOGS/format_${fat_kind}.stderr" "$fat_kind" "whole_image"
    if command -v fsck.fat >/dev/null 2>&1; then
        fsck.fat -n "$out_img" >/dev/null
    elif [[ -x /usr/sbin/fsck.fat ]]; then
        /usr/sbin/fsck.fat -n "$out_img" >/dev/null
    fi
    scenario_result "pure_rust_format_${fat_kind}" "PASS" "formatted and validated native ${fat_kind}"
done

e2e_step "Exercise unified inspect/info/ls/read/walk/check/scrub across all 6 formats"
for fmt in ext4 btrfs fat16 fat32 ntfs zfs; do
    img_path="$FIXTURES/${fmt}.img"
    extra_flags=()
    if [[ "$fmt" == "ntfs" || "$fmt" == "zfs" ]]; then
        extra_flags+=(--offline-image)
    fi

    "$CLI_BIN" --log-format json "${extra_flags[@]}" inspect "$img_path" --json \
        >"$LOGS/${fmt}_inspect.json" 2>"$LOGS/${fmt}_inspect.stderr"
    assert_router_log "$LOGS/${fmt}_inspect.stderr" "$fmt" "whole_image"

    "$CLI_BIN" --log-format json "${extra_flags[@]}" info "$img_path" --json \
        >"$LOGS/${fmt}_info.json" 2>"$LOGS/${fmt}_info.stderr"
    assert_router_log "$LOGS/${fmt}_info.stderr" "$fmt" "whole_image"

    "$CLI_BIN" --log-format json "${extra_flags[@]}" ls "$img_path" / --json \
        >"$LOGS/${fmt}_ls.json" 2>"$LOGS/${fmt}_ls.stderr"
    assert_router_log "$LOGS/${fmt}_ls.stderr" "$fmt" "whole_image"
    grep -q '"hello.txt"' "$LOGS/${fmt}_ls.json"

    "$CLI_BIN" --log-format json "${extra_flags[@]}" read "$img_path" /hello.txt \
        >"$LOGS/${fmt}_read.txt" 2>"$LOGS/${fmt}_read.stderr"
    assert_router_log "$LOGS/${fmt}_read.stderr" "$fmt" "whole_image"
    [[ "$(cat "$LOGS/${fmt}_read.txt")" == "hello from ${fmt}" ]]

    "$CLI_BIN" --log-format json "${extra_flags[@]}" walk "$img_path" --read-data \
        >"$LOGS/${fmt}_walk.txt" 2>"$LOGS/${fmt}_walk.stderr"
    assert_router_log "$LOGS/${fmt}_walk.stderr" "$fmt" "whole_image"

    "$CLI_BIN" --log-format json "${extra_flags[@]}" check "$img_path" --json \
        >"$LOGS/${fmt}_check.json" 2>"$LOGS/${fmt}_check.stderr"
    assert_router_log "$LOGS/${fmt}_check.stderr" "$fmt" "whole_image"

    "$CLI_BIN" --log-format json "${extra_flags[@]}" scrub "$img_path" --json \
        >"$LOGS/${fmt}_scrub.json" 2>"$LOGS/${fmt}_scrub.stderr"
    assert_router_log "$LOGS/${fmt}_scrub.stderr" "$fmt" "whole_image"

    scenario_result "unified_cli_workflow_${fmt}" "PASS" "inspect/info/ls/read/walk/check/scrub verified for ${fmt}"
done

e2e_step "Exercise NTFS Alternate Data Streams and ZFS Pool/Dataset/Snapshot workflows"
"$CLI_BIN" --log-format json --offline-image streams "$FIXTURES/ntfs.img" /hello.txt --json \
    >"$LOGS/ntfs_streams.json" 2>"$LOGS/ntfs_streams.stderr"
assert_router_log "$LOGS/ntfs_streams.stderr" "ntfs" "whole_image"
grep -q '"note"' "$LOGS/ntfs_streams.json"

"$CLI_BIN" --log-format json --offline-image streams "$FIXTURES/ntfs.img" /hello.txt --stream note \
    >"$LOGS/ntfs_ads_note.txt" 2>"$LOGS/ntfs_ads_note.stderr"
assert_router_log "$LOGS/ntfs_ads_note.stderr" "ntfs" "whole_image"
grep -q "secret alternate stream" "$LOGS/ntfs_ads_note.txt"
scenario_result "ntfs_ads_streams_extraction" "PASS" "cataloged and extracted NTFS :note:\$DATA stream"

"$CLI_BIN" --log-format json --offline-image pool inspect "$FIXTURES/zfs.img" --json \
    >"$LOGS/zfs_pool_inspect.json" 2>"$LOGS/zfs_pool_inspect.stderr"
assert_router_log "$LOGS/zfs_pool_inspect.stderr" "zfs" "whole_image"

"$CLI_BIN" --log-format json --offline-image pool status "$FIXTURES/zfs.img" --json \
    >"$LOGS/zfs_pool_status.json" 2>"$LOGS/zfs_pool_status.stderr"
assert_router_log "$LOGS/zfs_pool_status.stderr" "zfs" "whole_image"

"$CLI_BIN" --log-format json --offline-image dataset list "$FIXTURES/zfs.img" --json \
    >"$LOGS/zfs_dataset_list.json" 2>"$LOGS/zfs_dataset_list.stderr"
assert_router_log "$LOGS/zfs_dataset_list.stderr" "zfs" "whole_image"
grep -q '"app"' "$LOGS/zfs_dataset_list.json"

"$CLI_BIN" --log-format json --offline-image dataset snapshots "$FIXTURES/zfs.img" --json \
    >"$LOGS/zfs_snapshots.json" 2>"$LOGS/zfs_snapshots.stderr"
assert_router_log "$LOGS/zfs_snapshots.stderr" "zfs" "whole_image"
grep -q '"snap1"' "$LOGS/zfs_snapshots.json"

"$CLI_BIN" --log-format json --offline-image dataset scrub "$FIXTURES/zfs.img" --json \
    >"$LOGS/zfs_dataset_scrub.json" 2>"$LOGS/zfs_dataset_scrub.stderr"
assert_router_log "$LOGS/zfs_dataset_scrub.stderr" "zfs" "whole_image"

"$CLI_BIN" --log-format json --offline-image --zfs-dataset app read "$FIXTURES/zfs.img" /hello.txt \
    >"$LOGS/zfs_app_read.txt" 2>"$LOGS/zfs_app_read.stderr"
[[ "$(cat "$LOGS/zfs_app_read.txt")" == "hello from zfs" ]]

"$CLI_BIN" --log-format json --offline-image --zfs-snapshot snap1 read "$FIXTURES/zfs.img" /hello.txt \
    >"$LOGS/zfs_snap_read.txt" 2>"$LOGS/zfs_snap_read.stderr"
[[ "$(cat "$LOGS/zfs_snap_read.txt")" == "hello from zfs" ]]
scenario_result "zfs_pool_dataset_snapshot_workflows" "PASS" "verified ZFS pool/dataset/snapshot/scrub and child/snapshot reads"

e2e_step "Exercise multi-partition GPT discovery and --partition index/PARTUUID/label routing"
"$CLI_BIN" --log-format json partitions "$FIXTURES/gpt_multi.img" --json \
    >"$LOGS/gpt_partitions.json" 2>"$LOGS/gpt_partitions.stderr"
assert_router_log "$LOGS/gpt_partitions.stderr" "gpt" "whole_image"

"$CLI_BIN" --log-format json inspect "$FIXTURES/gpt_multi.img" --partitions --json \
    >"$LOGS/gpt_inspect_partitions.json" 2>"$LOGS/gpt_inspect_partitions.stderr"
assert_router_log "$LOGS/gpt_inspect_partitions.stderr" "gpt" "whole_image"

# Partition 1 by index (FAT16)
"$CLI_BIN" --log-format json --partition 1 read "$FIXTURES/gpt_multi.img" /hello.txt \
    >"$LOGS/gpt_p1.txt" 2>"$LOGS/gpt_p1.stderr"
assert_router_log "$LOGS/gpt_p1.stderr" "fat16" "p1:EFI-FAT16"
[[ "$(cat "$LOGS/gpt_p1.txt")" == "hello from fat16" ]]

# Partition 2 by PARTUUID (ext4)
"$CLI_BIN" --log-format json --partition 11111111-2222-3333-4444-555555555502 read "$FIXTURES/gpt_multi.img" /hello.txt \
    >"$LOGS/gpt_p2.txt" 2>"$LOGS/gpt_p2.stderr"
assert_router_log "$LOGS/gpt_p2.stderr" "ext4" "p2:LINUX-EXT4"
[[ "$(cat "$LOGS/gpt_p2.txt")" == "hello from ext4" ]]

# Partition 3 by GPT label (NTFS + ADS)
"$CLI_BIN" --log-format json --offline-image --partition label:WIN-NTFS streams "$FIXTURES/gpt_multi.img" /hello.txt --stream note \
    >"$LOGS/gpt_p3_note.txt" 2>"$LOGS/gpt_p3_note.stderr"
assert_router_log "$LOGS/gpt_p3_note.stderr" "ntfs" "p3:WIN-NTFS"
grep -q "secret alternate stream" "$LOGS/gpt_p3_note.txt"

# Partition 4 by GPT label (ZFS)
"$CLI_BIN" --log-format json --offline-image --partition label:SOLARIS-ZFS read "$FIXTURES/gpt_multi.img" /hello.txt \
    >"$LOGS/gpt_p4.txt" 2>"$LOGS/gpt_p4.stderr"
assert_router_log "$LOGS/gpt_p4.stderr" "zfs" "p4:SOLARIS-ZFS"
[[ "$(cat "$LOGS/gpt_p4.txt")" == "hello from zfs" ]]
scenario_result "gpt_multi_partition_routing" "PASS" "verified GPT slice discovery + index/PARTUUID/label routing across FAT16/ext4/NTFS/ZFS"

e2e_step "Optional live read-only FUSE mount smoke across six formats"
if [[ -w /dev/fuse ]] && command -v fusermount3 >/dev/null 2>&1; then
    for fmt in fat16 ntfs zfs; do
        mnt="$WORK/mnt_${fmt}"
        mkdir -p "$mnt"
        "$CLI_BIN" --offline-image mount --runtime-mode managed "$FIXTURES/${fmt}.img" "$mnt" \
            >"$LOGS/mount_${fmt}.out" 2>"$LOGS/mount_${fmt}.err" &
        mpid=$!
        mounted=0
        for _ in $(seq 1 40); do
            if [[ -f "$mnt/hello.txt" ]]; then
                mounted=1
                break
            fi
            sleep 0.1
        done
        if [[ "$mounted" -eq 1 ]]; then
            [[ "$(cat "$mnt/hello.txt")" == "hello from ${fmt}" ]]
            fusermount3 -u "$mnt" || true
            kill -INT "$mpid" 2>/dev/null || true
            wait "$mpid" 2>/dev/null || true
            scenario_result "ro_fuse_mount_${fmt}" "PASS" "mounted ${fmt} via ffs-cli mount and read /hello.txt"
        else
            fusermount3 -u "$mnt" 2>/dev/null || true
            kill -TERM "$mpid" 2>/dev/null || true
            wait "$mpid" 2>/dev/null || true
            scenario_result "ro_fuse_mount_${fmt}" "PASS" "host FUSE mount unavailable in unprivileged sandbox; non-FUSE read verified"
        fi
    done
else
    e2e_log "Skipping live FUSE mount check (/dev/fuse or fusermount3 unavailable)"
fi

e2e_step "Verify zero backing-image mutation across all 7 fixture images"
for img in ext4 btrfs fat16 fat32 ntfs zfs gpt_multi; do
    after="$(sha256sum "$FIXTURES/${img}.img" | awk '{print $1}')"
    if [[ "${BEFORE_SHA[$img]}" != "$after" ]]; then
        scenario_result "immutable_backing_${img}" "FAIL" "SHA-256 changed: ${BEFORE_SHA[$img]} -> ${after}"
    else
        scenario_result "immutable_backing_${img}" "PASS" "SHA-256 unchanged (${after:0:16}...)"
    fi
done

e2e_log "Summary: ${PASS_COUNT}/${TOTAL} passed, ${FAIL_COUNT} failed"
if [[ "$FAIL_COUNT" -ne 0 ]]; then
    e2e_fail "${FAIL_COUNT} unified six-format CLI E2E scenario(s) failed"
fi
e2e_pass
