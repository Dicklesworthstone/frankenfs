#!/usr/bin/env bash
set -euo pipefail

assets="$GITHUB_WORKSPACE/.task-validation/ffs-durability-20261125"
work="$RUNNER_TEMP/prepared-ffs"
mode="$1"
case "$mode" in
    gates|tests) ;;
    *) echo "Unsupported validation mode: $mode" >&2; exit 2 ;;
esac
base="$FFS_EXPECTED_MAIN"

test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
git merge-base --is-ancestor "$base" HEAD
while read -r sha file; do
    test "$(git hash-object "$assets/$file")" = "$sha"
done <<'PATCHES'
164e11bd9230b542f82cc3b193e2f75b354226c7 base-format.patch
34d206495785c36ba879c599acc116da7557c268 fuse.patch
d15911a1d86a122c08f4907ea76f063fdf0c2844 block-tests.patch
7685b9b9382ce8b1901d635e847a8e24c20071ee block-barrier.patch
45178d7dd5c2663725dc1f43fbc8a72104c70c95 block-serialization.patch
cde63c4f46579e7d58e9830dbe57886db09ffc07 block-serialization-tests.patch
a87814bc243e3a81c49160377c7ba3e9e5c61c32 quota-tests.patch
d1427713bab01aac3e7490de6b78b70eeaae27ad quota-impl.patch
b4226566cee692d45e255c7b7c9e114150d576d2 parity.patch
PATCHES
git worktree add --detach "$work" "$base"
cd "$work"

apply_patch() {
    git apply --check "$assets/$1"
    git apply "$assets/$1"
}

expect_red() {
    local label="$1" name="$2" result
    shift 2
    set +e
    "$@" > "$RUNNER_TEMP/$label.log" 2>&1
    result=$?
    set -e
    cat "$RUNNER_TEMP/$label.log"
    test "$result" -eq 101
    grep -Fq "test $name ... FAILED" "$RUNNER_TEMP/$label.log"
    grep -Fq "test result: FAILED. 0 passed; 1 failed;" "$RUNNER_TEMP/$label.log"
    echo "FFS_EXPECTED_REGRESSION_FAILURE|$name"
}

apply_stage() {
    case "$1" in
        1)
            apply_patch base-format.patch
            apply_patch fuse.patch
            ;;
        2)
            apply_patch block-tests.patch
            if test "$mode" = tests; then
                expect_red block-barrier-red tests::arc_cache_flush_barrier_precedes_persistence_and_keeps_versions_pinned \
                    cargo test --locked -p ffs-block --lib tests::arc_cache_flush_barrier_precedes_persistence_and_keeps_versions_pinned -- --exact
                expect_red block-sync-red tests::arc_cache_failed_sync_retains_retryable_dirty_blocks_without_notifications \
                    cargo test --locked -p ffs-block --lib tests::arc_cache_failed_sync_retains_retryable_dirty_blocks_without_notifications -- --exact
            fi
            apply_patch block-barrier.patch
            apply_patch block-serialization-tests.patch
            if test "$mode" = tests; then
                expect_red block-overlap-red tests::arc_cache_overlapping_flushes_cannot_overwrite_a_newer_durable_version \
                    cargo test --locked -p ffs-block --lib tests::arc_cache_overlapping_flushes_cannot_overwrite_a_newer_durable_version -- --exact
            fi
            apply_patch block-serialization.patch
            ;;
        3)
            apply_patch quota-tests.patch
            if test "$mode" = tests; then
                expect_red quota-limits-red quota_profile::received_space_properties_reject_invalid_effective_limits_without_writes \
                    cargo test --locked -p ffs-zfs --test persistence_prefix quota_profile::received_space_properties_reject_invalid_effective_limits_without_writes -- --exact
                expect_red quota-ancestor-red quota_profile::received_space_reservations_respect_ancestor_quotas_before_publication \
                    cargo test --locked -p ffs-zfs --test persistence_prefix quota_profile::received_space_reservations_respect_ancestor_quotas_before_publication -- --exact
            fi
            apply_patch quota-impl.patch
            apply_patch parity.patch
            ;;
    esac
}

stage_paths() {
    case "$1" in
        1) printf '%s\n' crates/ffs-fuse/src/lib.rs crates/ffs-ondisk/src/zfs/crypto.rs crates/ffs-zfs/tests/persistence_prefix/send_recv.rs crates/ffs-zfs/tests/persistence_prefix/writable_fs.rs ;;
        2) printf '%s\n' crates/ffs-block/src/cache.rs crates/ffs-block/src/lib.rs ;;
        3) printf '%s\n' crates/ffs-zfs/src/transaction/dsl_ops.rs crates/ffs-zfs/tests/persistence_prefix/quota_profile.rs FEATURE_PARITY.md ;;
    esac
}

record_tree() {
    python3 - "$1" "$base" <<'PY'
import subprocess, sys
stage = int(sys.argv[1])
expected = {
    "crates/ffs-fuse/src/lib.rs",
    "crates/ffs-ondisk/src/zfs/crypto.rs",
    "crates/ffs-zfs/tests/persistence_prefix/send_recv.rs",
    "crates/ffs-zfs/tests/persistence_prefix/writable_fs.rs",
}
if stage >= 2:
    expected.update({"crates/ffs-block/src/cache.rs", "crates/ffs-block/src/lib.rs"})
if stage >= 3:
    expected.update({
        "crates/ffs-zfs/src/transaction/dsl_ops.rs",
        "crates/ffs-zfs/tests/persistence_prefix/quota_profile.rs",
        "FEATURE_PARITY.md",
    })
changed = set(subprocess.check_output(
    ["git", "diff", "--name-only", sys.argv[2]], text=True
).splitlines())
assert changed == expected, (changed, expected)
assert not subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"])
subprocess.run(["git", "add", "--", *sorted(expected)], check=True)
PY
    git diff --check "$base"
    tree="$(git write-tree)"
    expected_name="FFS_TREE_$1"
    echo "FFS_TREE_CHECK|$1|actual=$tree|expected=${!expected_name}"
    test "$tree" = "${!expected_name}"
    echo "tree_$1=$tree" >> "$GITHUB_OUTPUT"
    echo "FFS_PREPARED_TREE|$1|$tree"
}

for stage in 1 2 3; do
    apply_stage "$stage"
    record_tree "$stage"
    case "$mode" in
        gates)
            mapfile -t scan_paths < <(stage_paths "$stage" | grep '\.rs$')
            UBS_SKIP_RUST_BUILD=1 "$GITHUB_WORKSPACE/.validation-ubs/ubs" --only=rust "${scan_paths[@]}"
            cargo fmt --check
            cargo check --locked --workspace --all-targets
            cargo clippy --locked --workspace --all-targets -- -D warnings
            ;;
        tests)
            case "$stage" in
                1) cargo test --locked -p ffs-fuse --lib bd_in31y -- --test-threads=1 ;;
                2) cargo test --locked -p ffs-block --all-features --lib -- --test-threads=1 ;;
                3) cargo test --locked -p ffs-zfs --test persistence_prefix quota_profile:: -- --test-threads=1 ;;
            esac
            ;;
        *) exit 2 ;;
    esac
    git diff --exit-code
    test "$(git write-tree)" = "$tree"
done

