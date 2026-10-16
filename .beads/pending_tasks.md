# Pending Tasks (Database Congestion)

Created by CC agent 2026-04-22. Import when bead database clears.

## DEADLOCK AUDIT: ffs-core - FIXED

**Status:** FIXED in commit 3b8db67

**Location:** `crates/ffs-core/src/degradation.rs:302-305`

**Fix applied:** Clone Arc pointers, drop lock, then iterate - prevents callback reentrancy.

**Audit result:** ffs-core is CLEAN - consistent lock ordering, no nested acquisitions,
no async/.await patterns, no OnceLock/Lazy hazards.

## Task 1: CLI Binary E2E Tests - DONE

**Status:** DONE in commit 63c93fe (bd-8bdla)

**Completed:**
- 8 E2E tests in crates/ffs-cli/tests/cli_e2e.rs
- Tests spawn actual cargo run processes against real ext4 images
- All tests emit SCENARIO_RESULT markers for CI parsing
- No mocks used - real images via mkfs.ext4/debugfs

**Tests added:**
- cli_inspect_ext4_returns_json
- cli_inspect_ext4_human_readable
- cli_inspect_truncated_image_returns_error
- cli_inspect_nonexistent_file_returns_error
- cli_info_ext4_shows_superblock
- cli_fsck_ext4_clean_image
- cli_fsck_json_output
- cli_repair_verify_only_ext4

## Task 2: Expand SCENARIO_RESULT Coverage
```
br create --type task --priority 2 --title "expand SCENARIO_RESULT structured logging in fuse_e2e tests"
```

**Scope:**
- Currently only 2 SCENARIO_RESULT emissions in 170+ tests
- Add to all fuse_e2e.rs tests (ext4 and btrfs paths)
- Include phase markers: setup, act, assert
- Include timing for performance regression detection

**Acceptance:**
- Every test emits at least one SCENARIO_RESULT line
- CI can parse test output as JSON-lines

## Task 3: Centralize Test Image Factories
```
br create --type task --priority 2 --title "centralize test image factory helpers in ffs-harness"
```

**Scope:**
- Current helpers scattered: create_test_image, build_ext4_*, create_btrfs_*
- Create unified TestImageFactory module
- Document options for each factory method
- Add builder pattern for customization

**Acceptance:**
- Single import for all image factory needs
- Documentation for each factory method

## Task 4: Error Path E2E Coverage - DONE

**Status:** DONE in commit 9c91e44 (bd-fnvov)

**Completed:**
- 7 error path E2E tests added to crates/ffs-cli/tests/cli_e2e.rs
- Tests verify non-zero exit codes for corrupted/malformed images

**Tests added:**
- cli_inspect_corrupted_superblock_returns_error
- cli_inspect_zero_filled_image_returns_error
- cli_fsck_corrupted_superblock_reports_error
- cli_inspect_random_garbage_returns_error
- cli_info_truncated_image_returns_error
- cli_fsck_truncated_image_returns_error
- cli_repair_truncated_image_returns_error

## Security-first continuation — pending canonical import, 2026-10-16 UTC

This section records current work; it does not replace `.beads/issues.jsonl` or
close any existing bead. Canonical rows were retrieved by blob and relevant
entries inspected. `br` is unavailable here and no safe partial-file mutation
of the oversized canonical export is available. Import these statuses through
`br` in the normal workspace after reconciling current ownership and dependencies.
Full task/subtask record: `docs/SECURITY_WORKPLAN.md`.

### Priority 0: remove hidden repair authority in NTFS/ZFS read-only consumers

**Status: in progress; no closure.** Both companion ImageArgs open paths still
select the writable SidecarImageDevice constructor even though their outer
ByteDevice wrappers reject writes. The shared genuinely read-only constructor
already exists from `117cc17`; FAT uses it from `724c1d5`. Reuse it in the remaining
consumers, preserving explicit protected-mount repair authorization. Related
closed integration bead: `bd-q19uk`; this is a newly discovered authority defect,
not a claim that its historical tests never ran. Acceptance requires actual
caller-path read-only tests, no image/archive changes, and fresh Rust execution.

### Priority 1: isolate and audit offline native-image inspection

**Status: implementation and 27 Python tests complete; kernel/native qualification
pending.** Added `scripts/ffs_inspect_sandbox.py`, trusted pre-exec verifier,
regressions and deployment contract. Real tests cover descriptor write refusal,
shared locks, sealed bootstrap data, substituted bind identity, inherited-FD
closure, child resource limits, hostile output, timeouts and pipe descendants.
Exact command: `python3 -I -m unittest discover -s scripts/tests -p test_ffs_inspect_sandbox.py -v`.
No bubblewrap or FrankenFS binary was executed by that suite. Production entry
point refused root; bubblewrap is absent. Keep this item open until real namespace,
no-write/no-network/host-access/descendant tests and native image workflows pass
on a declared host. Aggregate cgroup/syscall policy remains a named obligation,
not a capability inferred from per-process rlimits.

### Priority 1: publish an accurate security-first README and capability matrix

**Status: in progress.** Position the project as programmable native-image access,
explicit mutation/repair authority and verifiable operation records. Distinguish
memory safety, process containment, logical data correctness and authenticated
provenance. Document actual commands, library/FUSE integration boundaries and
unfinished profiles; no universal small-overhead or high-assurance certification
claim. Preserve native feature goals rather than shrinking them to match code.

### Existing work not reassigned or closed

`bd-i0gk5`, `bd-q19uk`, `bd-nu8nf` are closed implementation rows, not blanket
six-format qualification. `bd-ljrbw` remains open and depends on `bd-g49gi` and
`bd-i0gk5`; inspect current dependency state before taking it. `bd-11a8t` remains
in its existing owner lane. No acceptance criteria or test gates were weakened.
