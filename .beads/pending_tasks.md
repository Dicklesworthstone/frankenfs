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


## Comprehensive reality-check bridge — staged import packet, 2026-10-20

Audit: `bd-16kxp`; source `944903e78abdffcafbbb79ff17360b973c32989c`.
**These are staged proposals, not canonical task state or completed filesystem work.**
The canonical `br` path refuses possible committed WAL frames and malformed implicit-index/pending-merge inspection. Preserve the database, WAL, SHM, JSONL and all current owners. Never replace or rebuild them from this packet. The independent full-source graph is at `artifacts/reality-check/20261020/bridge/.beads/` and the findings are in `docs/reality-check-bridge-writeup.md`.

Before import, the owning engine must safely reconcile committed state. Compare the captured canonical JSONL SHA-256 `e5d359ec158f3943d6784b166883d8be4e94cf57aba115cf409e9bc39bbb4e64` with current source and resolve every intervening change. Then use `br` to import/recreate the proposed records and add only the stated dependencies/comments/notes, mapping IDs if necessary. Retain the original four owner lanes' status, owner, descriptions and existing notes. A validated staged graph does not authorize a canonical overwrite or recover unknown database-only commits.

The packet contains nineteen planned work records (seventeen tasks and two epics), plus the separately tracked audit. Every implementation includes its unit/integration/fault/native tests; qualification records do not permit premature implementation closure. Three ambition and five refinement passes are recorded in the staged audit notes/comments. All planned work remains open. Original `bd-z5bav` scope is preserved; `bd-8vjaj` is the complete six-format roadmap aggregate. Older sections above are historical: `bd-ljrbw` is now closed, but its executed synthetic gate receipts do not prove the remaining mounted/full-stack criteria.

### bd-50neb — Qualify and complete FAT maintenance and tail-relocating resize

Proposed type: `task`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-uzt72` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V9: plan FAT-06 requires checker/repair/formatting and validated offline resize. Current ffs-fat checker/recovery/formatter are substantial; resize.rs creates a new standalone image, preserves cluster IDs and permits shrink only across a completely free tail. That restricted feature is useful and must remain; it does not relocate live high clusters or complete the planned maintenance surface.
Work: inventory missing FAT-06 cases against current checker, mirror/boot recovery, formatter population and resize. Complete explicit repair choices only when native ownership/reachability is proven. Add source-preserving cluster relocation/compaction for a declared shrink profile with exact chain, directory first-cluster and dot-parent updates; keep source O_RDONLY and create-new output. Preserve raw names/aliases/times, preallocation, bad clusters, dialect/active-FAT/high-bit semantics and selected-volume boundaries. Never change partition tables implicitly or infer a rightful cross-link owner from traversal order.
Acceptance: both dialects pass independent native read/write/check/reopen for grow, free-tail shrink and relocation shrink; retained source and adjacent-volume sentinels are byte-identical on success, cancellation, source race, ENOSPC and every failed publication cut. Invalid geometry/dialect conversion and unsupported bad-cluster relocation refuse before destination publication. Unit/fault/integration tests and CLI diagnostics ship with changes; publish actual executed counts and retained partial outputs, not only test source. Native vs stronger external recovery remains explicit.

Acceptance refinements and source/test anchors:

Refinement4 implementation anchors: crates/ffs-cli/src/bin/ffs-fat/main.rs dispatch; filesystem.rs plus filesystem/{lifetime,health,exchange}.rs; reader/replacement.rs with creation/mkdir/ranges/metadata children; reader/{check,recovery}.rs; formatter.rs and resize.rs. Reuse scripts/verify_fat_read.py and extend its actual native workload, not a new wrapper around modeled results. Run the full current companion suite with RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-fat; after library extraction keep the same corpus in the owning crate and companion dispatch tests. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-5osex — Implement native NTFS journal publication and allocator/MFT transactions

Proposed type: `task`; priority: `P1`; status: `open`; unassigned.

Dependencies: `bd-native-image-library-s4tde` (blocks), `bd-ofjn7` (blocks), `bd-vuzzq` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V12, plan NTFS-04/05: current ffs-ntfs offers read-only FsOps, clean-log mount admission and a restricted semantic volatile FILE recovery overlay. No general native writer exists. bd-ofjn7 owns read-overlay redo/undo and remains a prerequisite; do not close it on the writer's scaffolding or confuse overlay success with Windows recovery.
Work: implement an explicitly admitted NTFS 3.1 native transaction engine. Derive supported native LogFile records, restart/checkpoint and compensation behavior from pinned independent native fixtures; reserve journal, cluster Bitmap and MFT resources before metadata edits. Add valid FILE/INDX fixups, sequence-aware allocation, MFT/MFTMirr growth and updates, initialized-length discipline and explicit native durable token/outcome. Unknown log operations, hibernation/Fast Startup, unsupported active metadata and uncertain ownership refuse writable admission before mutation.
Acceptance: native Windows and declared NTFS3/NTFS-3G consumers reopen clean results and recover admitted interrupted transactions; committed redo, loser undo, wrap/restart competition, torn FILE/INDX, log-full/ENOSPC and replay-idempotence cases run with fresh engines. Acknowledged native durability survives loss of unflushed writes; required flush failure never returns success. No stale allocation is exposed and no double allocation occurs. Include production code plus unit/planted-red/fault/native integration tests, detailed LSN/transaction/ack/cut logs without keys, exact binaries/OS/fixtures and test counts. A private FrankenFS WAL is not a substitute. Missing Windows evidence keeps interchange unqualified.

Acceptance refinements and source/test anchors:

Refinement3 test model: capture a partial order of native persistence/publication events and an independent acknowledged-operation prefix; explore reordered/torn/failed pending writes only within the declared device guarantee. Keep independent devices separately faultable. Reduce redundant schedules only when independence is demonstrated, retain minimized counterexamples and compare against native recovered allowed states. Never model arbitrary post-successful-flush loss as ordinary filesystem power-loss behavior. Distinguish not committed, durably committed and uncertain outcomes so retries cannot duplicate a committed namespace operation. This is a validation proposal, not a formal-proof or live-power-cut claim.
Refinement4 implementation anchors: current engine lives under crates/ffs-cli/src/bin/ffs-ntfs/reader.rs and reader/{attributes,namespace,compression,wof,security,ea,source,recovery_apply}.rs; mounted admission is reader/filesystem/recovery.rs with record/preflight/redo; low-level native edits belong in crates/ffs-ondisk/src/ntfs and its recovery modules. Extend these owners or their extracted library without duplicating parser/recovery logic. Baseline commands: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-ntfs; RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ondisk. Reuse scripts/verify_ntfs_read.py and scripts/verify_ntfs_mount.py for independent consumers; extend actual native scenarios. After extraction retarget the owner package while retaining public dispatch coverage. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-8bacs — Deliver NTFS structural checking, native formatting and offline resize

Proposed type: `task`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-wmzge` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V13, plan NTFS-07: the existing NTFS reader is not a maintenance engine. Native checking, formatting and relocation-safe resize are not covered by the read-overlay bead despite historical NTFS workpackage numbering drift.
Work: implement a bounded non-mutating checker for record/sequence/reference/link/cluster/index/metadata-file invariants; distinguish uncertain ownership, damage, unsupported metadata and missing external oracle. Repair requires precise target authority and a reviewable plan; do not auto-select an ambiguous owner. Native formatting initializes required metadata files, UpCase/security defaults, allocation, journal and mirror/backup structures on fresh explicit targets. Source-preserving offline grow/shrink must relocate/account correctly before native publication; no partition-table edits or BPB-only resize.
Acceptance: fresh formatted volumes consumed, modified, checked and reopened by Windows; checker source hashes unchanged; invalid and adversarial metadata bounded; native grow/shrink preserving streams/names/security and outside-volume sentinels; every relocation/publication cut, I/O error, ENOSPC and cancellation. Test code plus implementation ship together and retain failed output. ntfsfix alone is not complete Windows chkdsk evidence. Advanced metadata not safely maintainable blocks that writer/resize profile rather than being discarded.

Acceptance refinements and source/test anchors:

Refinement4 implementation anchors: current engine lives under crates/ffs-cli/src/bin/ffs-ntfs/reader.rs and reader/{attributes,namespace,compression,wof,security,ea,source,recovery_apply}.rs; mounted admission is reader/filesystem/recovery.rs with record/preflight/redo; low-level native edits belong in crates/ffs-ondisk/src/ntfs and its recovery modules. Extend these owners or their extracted library without duplicating parser/recovery logic. Baseline commands: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-ntfs; RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ondisk. Reuse scripts/verify_ntfs_read.py and scripts/verify_ntfs_mount.py for independent consumers; extend actual native scenarios. After extraction retarget the owner package while retaining public dispatch coverage. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-8vjaj — Deliver the complete declared six-format native roadmap with independent evidence

Proposed type: `epic`; priority: `P1`; status: `open`; unassigned.

Dependencies: `bd-50neb` (blocks), `bd-8bacs` (blocks), `bd-8c9u0` (blocks), `bd-9rutw` (blocks), `bd-c18h5` (blocks), `bd-enpwq` (blocks), `bd-in31y` (blocks), `bd-jtk24` (blocks), `bd-ofjn7` (blocks), `bd-qjqc4` (blocks), `bd-udh2o` (blocks), `bd-us87k` (blocks), `bd-uz4m0` (blocks), `bd-uzt72` (blocks), `bd-w2u82` (blocks), `bd-wlfpt` (blocks), `bd-z5bav` (blocks).

STAGED ONLY: canonical tracker writes are guarded; apply through br after owning-engine reconciliation and source comparison, never replace database/JSONL. Baseline 944903e78, 2026-10-20. This epic retains every original V1 and multi-format plan obligation without expanding the existing bd-z5bav narrower release scope.
Target: complete every obligation of the declared FAT16/32, NTFS and pinned ZFS end-state profiles alongside preserved ext4/btrfs behavior: native reads, mutation, recovery, bidirectional interchange, CLI/library/FUSE operation, maintenance/creation/evolution, typed native durable identity, MVCC/protection, resource bounds, telemetry and truthful executed release proof. Restricted profiles remain useful milestones, not full-roadmap closure.
Dependencies are coherent implementation/qualification packages; each owns its code plus unit/integration/fault/native E2E tests. NTFS/ZFS readers and log overlays do not count as native writers; detection does not count as six-format OpenFs; synthetic gate5/gate7 smoke does not count as mounted/full-stack proof. Existing P0 source-read authority, repair freshness, MVCC semantics, sandbox qualification and pinned-toolchain gate work retain their original owners and acceptance.
Acceptance: all dependencies pass their exact native behavior and negative controls on cited source/build/options/fixture/tool identities; missing required tools, zero selection, skipped mounts, failed flush/crash/ownership state or known storage-corrupting defect prevents completion. Run actual current consumer/release artifact checks through the approved release route. No automatic release during planning and no universal percent inferred from 97 parser/contract rows. Logs retain ack/cut/native generation and outcomes, including losses, unsupported profiles and unresolved work.

Acceptance refinements and source/test anchors:

Refinement4 final completeness: workspace baseline includes RCH_REQUIRE_REMOTE=1 rch exec -- cargo test --workspace in addition to all-targets check/strict Clippy/fmt and focused/native campaigns. Preserve every V1..V24 mapped goal including explicit asupersync request budgets and cancel-correct synchronization, writable-only authority, source-preserving maintenance, current-format command documentation and delivered-artifact consumers. The full-roadmap aggregate does not change bd-z5bav's original restricted release scope.
Refinement4 graph-closure check: explicit full-roadmap blockers now include bd-9rutw (request namespace semantics), bd-in31y (remaining structured lifecycle), bd-jtk24 (independent evidence authority), and pre-existing active local P0s bd-8c9u0/bd-w2u82. The read-authority P0 already lies on FAT/TUI prerequisites. Every local P0 blocks release-ready wording until executed closure or evidence-backed reprioritization under the existing tracker rule; a graph path through a partially scoped release aggregate is not enough. This adds prerequisites without altering any original owner, status or acceptance.

### bd-c18h5 — Complete pinned ZFS advanced topology, encryption and pool lifecycle

Proposed type: `epic`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-f71fc` (blocks), `bd-k5jk6` (blocks), `bd-l6gty` (blocks), `bd-lc4bg` (blocks), `bd-oscdu` (blocks), `bd-w4sht` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V17, plan ZFS-04/08/09: present mirror/RAIDZ extraction, allocation/properties inspection and readonly zvol export leave a large native end-state gap. Preserve those useful restricted profiles.
Work: explicitly pin the complete target feature manifest; implement advanced dRAID/expanded RAIDZ/indirect and allocation-class mappings as native algorithms, ownership/multihost and pool create/import/export/attach/replace/detach/online/offline/spares, scrub/heal/resilver/TRIM/checkpoint/rewind/removal/expansion. Add authenticated encryption/key-root load/unload and raw/plain boundaries, separate send vs receive including incremental/raw/resume, and a real zvol block frontend with lifecycle/flush semantics. Use resumable pool-owned progress; no libzfs runtime replacement or automatic force import/MMP bypass.
Acceptance: independent pinned native oracle for each layout and tolerated erasure set, mixed corrupt/missing members, all-copy failure and cache isolation; native import after lifecycle cuts under foreground writes, correct shared/space accounting, wrong-base/hostile receive, missing log/special vs optional cache, wrong/missing keys, native encrypted/raw interchange, zvol block/flush/snapshot operation. No key logging. Each implementation feature carries inline/integration/fault and native E2E tests with detailed identities, ack/cut/result logs. Keep unimplemented profile obligations visible; no parser or readonly support credit for writer/recovery behavior.

Acceptance refinements and source/test anchors:

Ambition round2: execution aggregate only, not a second implementation. Concrete coherent subtasks (each code+unit/fault/native E2E): bd-l6gty, bd-oscdu, bd-lc4bg, bd-k5jk6. Close this aggregate only after every named native obligation is executed, with individual profile limits retained; no types/implementation/tests mini-closures.

### bd-enpwq — Recover tracker write authority without losing WAL commits and restore source-aware triage

Proposed type: `task`; priority: `P1`; status: `open`; unassigned.

Dependencies: none.

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Context: 2026-10-20 audit at 944903e78 finds canonical br ready refusing possible committed uncheckpointed WAL frames; br --no-db create --dry-run also refuses pending sync-merge inspection because issues implicit autoindex slot 1 is malformed. scripts/e2e/ffs_tracker_source_hygiene_e2e.sh parses the source but installed bv lacks --no-cache and --db; 6/15 scenarios fail. This blocks safe canonical work-graph refinement, not filesystem parsing.
Work: preserve database, WAL, SHM, source JSONL, source witnesses and current ownership; have the owning database engine establish a non-destructive reconciled state under its authority. Never delete/replace WAL, rebuild from JSONL, force-export a partial store, or pretend JSONL contains unknown database-only commits. Diagnose CLI version/interface mismatch without relaxing source-authority or permission gates. Reconcile the staged full-source graph only after exact source comparison and current-owner review; use br for all graph mutations.
Acceptance: canonical read and guarded dry-run mutation succeed; all pre-existing issue rows, events and committed WAL state are conserved with cited engine receipts; source-aware E2E passes its live and negative projection/permission cases with zero skipped input rows; br dep cycles stays empty. Record source hashes, tools/versions, selected counts, commands and actual exits. Unit regressions for actual recovery/interface defect and an end-to-end tracker probe belong with any fix. No filesystem-readiness credit follows. Do not restart shared Agent Mail or mutate foreign records.

### bd-f71fc — Implement ZFS native allocation, TXG publication and durable tokens

Proposed type: `task`; priority: `P1`; status: `open`; unassigned.

Dependencies: `bd-native-image-library-s4tde` (blocks), `bd-ofjn7` (related), `bd-vuzzq` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V16, plan ZFS-05/06: ffs-zfs reads MOS/DMU/ZPL, reconstructs allocation reports and offers volatile ZIL recovery. It has no native allocator/TXG writer. Automatic read-only uberblock selection is not writable pool ownership, and COW alone is not native durability.
Work: implement an admitted simple-topology pool owner and transaction engine with metaslab/space-map reservation, dirty DMU state, data/metadata COW, checksums, dependent-write ordering, accounting/deferred frees, synchronized root/uberblock publication and a native durable token. Reconcile committed ZIL intent with TXG state without discarding required SLOG. Full TXG synchronization per fsync is a valid first implementation; optimize native ZIL writing only after correctness. Explicitly refuse unknown active feature, unresolved log/special device, multihost ownership or unsupported writable topology.
Acceptance: pinned OpenZFS imports/checks/reads/writes clean results and every admitted crash cut; children durable before referenced parents; deterministic independently faulted member/flush/ENOSPC schedules; coherent restart selection and no freeing blocks reachable from live/snapshot/clone/incomplete transactions. Record identity/topology/birth/TXG/ack/cut, native tools/kernel/ELF and executed counts. Preserve zero writes on read-only paths and do not use a private WAL as a substitute. Unit, storage-model and native E2E tests belong with implementation.

Acceptance refinements and source/test anchors:

Refinement2: do not serialize development of a correct clean-pool full-TXG writer behind the combined NTFS/ZFS overlay bead. That bead is related here and remains a hard blocker of the full-roadmap epic. An initial explicitly clean-only native writer must refuse pending ZIL, missing required log devices and unsupported native recovery before any write; no dirty-pool support or full-roadmap closure follows. Native recovery remains essential under bd-ofjn7 and the full native campaign.
Refinement3 test model: capture a partial order of native persistence/publication events and an independent acknowledged-operation prefix; explore reordered/torn/failed pending writes only within the declared device guarantee. Keep independent devices separately faultable. Reduce redundant schedules only when independence is demonstrated, retain minimized counterexamples and compare against native recovered allowed states. Never model arbitrary post-successful-flush loss as ordinary filesystem power-loss behavior. Distinguish not committed, durably committed and uncertain outcomes so retries cannot duplicate a committed namespace operation. This is a validation proposal, not a formal-proof or live-power-cut claim.
Refinement4 implementation anchors: current engine under crates/ffs-cli/src/bin/ffs-zfs/reader/pool.rs and pool/{import,raidz,missing_mirror,gang}.rs, reader/dmu.rs and dmu/{allocation,properties,zap,zpl,zil,zvol}.rs; filesystem.rs is the readonly mount adapter. Pure formats/checksums remain in crates/ffs-ondisk/src/zfs*. Baseline command: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-zfs. Reuse scripts/verify_zfs_root.py, verify_zfs_files.py and verify_zfs_snapshots.py with native OpenZFS fixtures; extend them to native mutations/recovery after the engine exists. New transaction/lifecycle modules belong with the extracted pool engine, not a second binary-local parser. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-k5jk6 — Deliver native ZFS zvol block frontend and writable lifecycle

Proposed type: `task`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-f71fc` (blocks), `bd-w4sht` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Source 944903e78, 2026-10-20. Preserve all original source/ownership. Do not import by replacing canonical files.

Vision V17 and parent bd-c18h5. Existing zvol-info/read/extract are useful readonly object access; exporting a regular ZPL file is not a block-volume frontend.
Specify an explicit safe host block transport compatible with first-party forbid(unsafe_code) and approved runtime, then implement native zvol create/destroy/resize, block read/write, discard if admitted, flush/fdatasync outcomes, snapshots and ownership. Share the pool engine and native TXG/ZIL durability; do not create an independent writer per view or equate a buffered block reply with durable acknowledgment. Keep destructive target authority and exact volume identity explicit.
Acceptance: actual block client through the declared frontend, native OpenZFS consumes/modifies/reopens its zvol and snapshots, unaligned/boundary/sparse/size-change errors, flush and crash cuts, ENOSPC/readonly/cancel/stale handle, snapshot/reference isolation. Unit/fault/frontend/native E2E tests and source/ELF/transport/native-token/ack logs ship with code. Report host-specific unavailability as missing evidence, never a green skip.

Acceptance refinements and source/test anchors:

Refinement4 implementation anchors: current engine under crates/ffs-cli/src/bin/ffs-zfs/reader/pool.rs and pool/{import,raidz,missing_mirror,gang}.rs, reader/dmu.rs and dmu/{allocation,properties,zap,zpl,zil,zvol}.rs; filesystem.rs is the readonly mount adapter. Pure formats/checksums remain in crates/ffs-ondisk/src/zfs*. Baseline command: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-zfs. Reuse scripts/verify_zfs_root.py, verify_zfs_files.py and verify_zfs_snapshots.py with native OpenZFS fixtures; extend them to native mutations/recovery after the engine exists. New transaction/lifecycle modules belong with the extracted pool engine, not a second binary-local parser. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-l6gty — Implement native ZFS advanced topologies and resumable pool lifecycle

Proposed type: `task`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-f71fc` (blocks), `bd-w4sht` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Source 944903e78, 2026-10-20. Preserve all original source/ownership. Do not import by replacing canonical files.

Vision V17 and parent bd-c18h5. Current ffs-zfs has restricted mirror/RAIDZ readers, not native writable pool administration. Preserve existing extraction profiles.
Implement independently admitted dRAID/expanded RAIDZ/indirect/allocation-class geometry and physical/asize mapping, plus pool ownership/import/export/create, attach/replace/detach/online/offline/spares, scrub/heal/resilver/TRIM/checkpoint/rewind/removal/expansion. Reuse one pool transaction owner and persist long-running progress. Missing special/log storage is not optional cache; no MMP/force-import bypass. Every admitted operation must preserve birth/reference/space accounting and correct recovery.
Acceptance: pinned OpenZFS native mapping/reconstruction and import after every lifecycle crash cut; mixed corrupt/missing members and all tolerated erasure combinations; foreground writes during replacement/resilver, wrong-GUID/config-generation refusal, interruption/cancellation/ENOSPC/flush failure and resumed progress. Verify cache isolation and native read/write/check/reopen in both directions. Include implementation, inline/unit, storage-model, mounted/native E2E tests and detailed source/ELF/tool/topology/TXG/birth/ack/cut logs in each logical feature. Missing native evidence means unqualified. Do not grant all advanced layouts from a simple RAIDZ test.

Acceptance refinements and source/test anchors:

Refinement4 implementation anchors: current engine under crates/ffs-cli/src/bin/ffs-zfs/reader/pool.rs and pool/{import,raidz,missing_mirror,gang}.rs, reader/dmu.rs and dmu/{allocation,properties,zap,zpl,zil,zvol}.rs; filesystem.rs is the readonly mount adapter. Pure formats/checksums remain in crates/ffs-ondisk/src/zfs*. Baseline command: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-zfs. Reuse scripts/verify_zfs_root.py, verify_zfs_files.py and verify_zfs_snapshots.py with native OpenZFS fixtures; extend them to native mutations/recovery after the engine exists. New transaction/lifecycle modules belong with the extracted pool engine, not a second binary-local parser. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-lc4bg — Implement native ZFS send/receive with incremental, raw and resumable semantics

Proposed type: `task`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-oscdu` (blocks), `bd-w4sht` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Source 944903e78, 2026-10-20. Preserve all original source/ownership. Do not import by replacing canonical files.

Vision V17 and parent bd-c18h5. Snapshot reads are not send/receive, and one direction does not prove the other. Implement separately advertised native stream generation and bounded receiving, with full/incremental/raw/resumable feature admission, snapshot/base identity and pool-owned transactions.
Preserve names/ACLs/properties/native transforms and shared-reference accounting; untrusted stream metadata never chooses host paths, devices, keys or force imports. Stage incomplete receives and publish only valid native state; retain restart/progress records. Unknown stream feature, wrong base, invalid checksum or uncertain generation must fail precisely without publishing corrupt success.
Acceptance: bidirectional interchange with pinned native OpenZFS, exact data/namespace/properties before and after receive/reopen; full vs incremental/base mismatch, corrupt/truncated/oversized/reordered streams, duplicate records, encrypted raw/keyless case, interruption and resume at every commit boundary, quota/ENOSPC/cancellation. Implementation plus parser/unit/fault/native E2E tests and bounded resource/stream/source/TXG/ack logs ship together. Raw encrypted acceptance waits for zfscrypto; ordinary clean full/incremental development can proceed as an explicitly restricted subprofile before raw support.

Acceptance refinements and source/test anchors:

Refinement4 implementation anchors: current engine under crates/ffs-cli/src/bin/ffs-zfs/reader/pool.rs and pool/{import,raidz,missing_mirror,gang}.rs, reader/dmu.rs and dmu/{allocation,properties,zap,zpl,zil,zvol}.rs; filesystem.rs is the readonly mount adapter. Pure formats/checksums remain in crates/ffs-ondisk/src/zfs*. Baseline command: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-zfs. Reuse scripts/verify_zfs_root.py, verify_zfs_files.py and verify_zfs_snapshots.py with native OpenZFS fixtures; extend them to native mutations/recovery after the engine exists. New transaction/lifecycle modules belong with the extracted pool engine, not a second binary-local parser. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-oscdu — Implement authenticated ZFS encryption, transforms and key lifecycle

Proposed type: `task`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-f71fc` (blocks), `bd-w4sht` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Source 944903e78, 2026-10-20. Preserve all original source/ownership. Do not import by replacing canonical files.

Vision V17 and parent bd-c18h5. Existing native compression/checksum decoding and raw locked metadata are not authenticated encrypted read/write support. Pin every required feature/algorithm and native representation.
Implement native authenticated data/metadata transform ordering, encryption roots, wrapped keys, nonce/IV constraints, explicit trusted key sources, load/unload and raw/plain access under shared views. Include writes, recovery, snapshots/clones, DDT/BRT interactions and secure key absence, not just a decrypting decoder. Never read a key path supplied by an untrusted property; never log or sidecar-store keys. Retain keyless immutable ciphertext protection only where the exact version/provenance is validated.
Acceptance: authentic pinned OpenZFS encrypted fixtures, native modify/check/reopen both directions and after crash/ENOSPC/flush failure; corrupt ciphertext/authentication metadata, wrong/missing key, unload with active handles, root inheritance and transformed/shared blocks. Unit/known-answer/adversarial/fault/native E2E tests ship with code and log redacted identities/outcomes/ack boundaries. No successful plaintext from unauthenticated bytes and no completion from metadata inspection alone.

Acceptance refinements and source/test anchors:

Refinement4 implementation anchors: current engine under crates/ffs-cli/src/bin/ffs-zfs/reader/pool.rs and pool/{import,raidz,missing_mirror,gang}.rs, reader/dmu.rs and dmu/{allocation,properties,zap,zpl,zil,zvol}.rs; filesystem.rs is the readonly mount adapter. Pure formats/checksums remain in crates/ffs-ondisk/src/zfs*. Baseline command: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-zfs. Reuse scripts/verify_zfs_root.py, verify_zfs_files.py and verify_zfs_snapshots.py with native OpenZFS fixtures; extend them to native mutations/recovery after the engine exists. New transaction/lifecycle modules belong with the extracted pool engine, not a second binary-local parser. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-qjqc4 — Implement continuous standalone live telemetry with real refresh and cancellation

Proposed type: `task`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-read-means-read-xpx37` (blocks), `bd-vuzzq` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V21, canonical spec sections 23.5 and gate7: tui_cmd in crates/ffs-cli/src/main.rs builds one snapshot, renders ASCII or JSON once and exits. refresh_ms is only logged. Mount-console sampling is separate; parsing --refresh-ms and seeing an ASCII header do not prove one-Hz live monitoring.
Work: retain explicit snapshot-json one-shot behavior and add an actual continuous interactive telemetry path driven by the approved structured runtime. Reuse Dashboard/LiveTelemetryCollector and mount_console where appropriate; refresh real cache/MVCC/repair/I/O counters from the selected live source without reopening with hidden write authority. Define source ownership, terminal/noninteractive behavior, staleness and shutdown. Use inherited Cx/budgets and joined regions, never orphan render/scrub tasks.
Acceptance: time-controlled tests show at least multiple distinct timestamped samples and changing real counters across operations, refresh interval respected, snapshot mode returns once, cancellation/terminal error drains and restores terminal state. An actual terminal/headless E2E runs continuously for the promised interval; log sample source and cadence, not fabricated counters. Measure idle CPU <1% target and sample overhead after correctness; absence of fresh measurement is unproven. Code/tests ship together; gate7 needs sustained mounted qualification separately.

### bd-udh2o — Complete NTFS writable transforms, security and secondary metadata

Proposed type: `task`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-wmzge` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V13: plan NTFS-06 retains advanced native obligations. Existing LZNT1/WOF XPRESS/LZX readers, streams and raw security/EA inspection do not implement compressed writes, native ACL/security updates, EFS or secondary-index maintenance.
Work: add compressed/sparse stream lifecycle and recovery; native Secure descriptor/SID/deny/inheritance preserving edits; alternate stream create/rename/delete; UsnJrnl, ObjId, Quota and Reparse index consistency. Keep reparse provider decoding separate from host traversal and WOF/EFS access separate from raw preservation. Implement explicitly authorized EFS key roots and read/write only from authentic test fixtures; keys never enter logs/sidecars. A format feature needs allocation/accounting/deletion/recovery/native interoperability, not just a decoder.
Acceptance: native Windows mutation and chkdsk/reopen across compressed unit/EOF edges, resident transitions, security inheritance and deny rules, alternate streams and active secondary metadata; missing/wrong-key and unsupported-provider negatives; crash/ENOSPC/cancellation at associated updates; exact source profiles and executed counts. Keep previously admitted restricted readers available. Do not remove advanced goals from the denominator or silently drop security meaning in POSIX projection. Unit/fault/integration/E2E tests and diagnostic logs are part of the implementation.

Acceptance refinements and source/test anchors:

Refinement1 coverage: retain the explicit NTFS3.x target including separately admitted native3.0 compatibility where promised, while the current3.1 reader remains honestly scoped. Independently qualify revisions and feature interactions; never broaden writable admission from a version byte or remove EFS/security/secondary-index obligations from the full plan.
Refinement4 implementation anchors: current engine lives under crates/ffs-cli/src/bin/ffs-ntfs/reader.rs and reader/{attributes,namespace,compression,wof,security,ea,source,recovery_apply}.rs; mounted admission is reader/filesystem/recovery.rs with record/preflight/redo; low-level native edits belong in crates/ffs-ondisk/src/ntfs and its recovery modules. Extend these owners or their extracted library without duplicating parser/recovery logic. Baseline commands: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-ntfs; RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ondisk. Reuse scripts/verify_ntfs_read.py and scripts/verify_ntfs_mount.py for independent consumers; extend actual native scenarios. After extraction retarget the owner package while retaining public dispatch coverage. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-us87k — Qualify six-format native interchange, recovery and workflow cost on one current build

Proposed type: `task`; priority: `P2`; status: `open`; unassigned.

Dependencies: `bd-native-image-library-s4tde` (blocks), `bd-sandbox-native-readers-qx2om` (blocks), `bd-uzt72` (blocks), `bd-w4sht` (blocks), `bd-wh1xk` (blocks), `bd-wmzge` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Source 944903e78, 2026-10-20. Preserve all original source/ownership. Do not import by replacing canonical files.

Vision V20/V22/V24: parser and native roundtrip tests do not establish full mounted/native product behavior, and August kernel scorecards are not current six-format proof. Reuse the existing harness, exact mappings and campaign receipts, not a new framework. Completion is per explicitly admitted profile; unresolved advanced obligations remain visible and must not become blanket support.
Run a shared fixed corpus through actual library/CLI/FUSE paths and independent native producers/consumers in both directions: fragmented/empty/large/sparse/compressed data, Unicode aliases, directories/cookies/handles, rename-overwrite/open-unlink, full storage/reuse, permissions/metadata and declared native features. Execute no-write clean/dirty/failure/cancel controls, process-death remount plus separate pending/durable storage-fault cuts, wrong-sidecar/native generation and missing-feature/device refusals. Windows is required for a Windows interchange claim; ntfsfix is not chkdsk. Use exact permission ACKs/device manifests for restricted lanes; no authorization is implied here.
Measure cold/warm read/write/namespace/fsync/replay/degraded performance and peak/steady memory, CPU and protection/hash overhead under equivalent native features, authority, durability and file/loop transport. The incumbent runs in the SAME invocation; report A/A nulls, cross-window variability, executed ELF hash, actual threads, absolute arm times, correctness and failures/losses. A self-speedup is maintenance, never an incumbent win. No invented universal latency target.
Acceptance: one current source/build/dirty digest and per-profile source/binary/options/native tool/OS/fixture identities, exact selected/pass/fail/skip counts and retained raw logs; failed/missing mandatory cases remain failing. Bind release artifact hashes to consumer smoke tests through the repository's approved release path, without triggering any release during planning. Substantive tests/logging ship with fixes; native campaign success cannot hide an open data-safety defect.

Acceptance refinements and source/test anchors:

Refinement4 resource/publication contract: report independent physical-read bytes, decoded bytes, retained memory, depth/record/replica-attempt counts and wall budget where measured; a metadata-count cap alone is not a complete process/physical-I/O bound. Include planted decompression/reference/retry explosions and a final-element failure that cannot become successful partial structured output. For strict read-only paths assert no backing write or synchronization authority through real call recording plus source/archive hashes. Preserve partial stdout/retained failure artifacts as errors, not fabricated atomic output guarantees. Update README/profiles from actual source and executed scope while retaining every end-state goal; docs changes alone close no functional requirement.
Refinement4 campaign commands: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-harness -- --nocapture; RCH_REQUIRE_REMOTE=1 rch exec -- cargo bench -p ffs-harness plus the exact public companion/native scripts named by each admitted profile. Existing comparator scripts/mounted_kernel_ab.py and mounted scorecard admission retain their same-invocation incumbent/null/correctness requirements. Permissioned xfstests requires exact XFSTESTS_REAL_RUN_ACK and declared TEST/SCRATCH/RESULT identities; no inferred approval. Release consumer/artifact checks use the user's approved release path, not a new CI/release system. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-uz4m0 — Fuzz native FAT/NTFS/ZFS traversals and replay through bounded public engines

Proposed type: `task`; priority: `P1`; status: `open`; unassigned.

Dependencies: `bd-native-image-library-s4tde` (blocks), `bd-vuzzq` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V23: the checked 63-target cargo-fuzz inventory has ext4/btrfs and infrastructure targets, but no named FAT/NTFS/ZFS traversal targets. First-party unsafe forbids direct unsafe operations; it does not bound hostile allocation/decompression/recovery or prove logical safety. Reuse existing fuzz infrastructure.
Work: seed independently produced FAT chains/directories/LFN, NTFS fragmented MFT/attribute/index/recovery and compressed/WOF data, ZFS labels/DVA/gang/topology/MOS/DMU/ZAP/ZPL/snapshot/ZIL/encrypted-admission cases. Exercise complete bounded engine calls, not just signature parsing. Supply deterministic byte/read/depth/decoded-output limits and fresh cache/view identity; malformed input returns errors, no panic/partial successful data, source writes or unbounded host allocation. Library extraction is needed for engine calls, not for standalone pure-parser fuzzing.
Acceptance: actual bounded sanitizer/fuzz campaigns with toolchain/target/seed/corpus/hash/duration/resource/coverage receipts; minimize and retain each finding without deleting old corpus; fix every defect with unit/planted-red regression and preserve negative no-write/unsupported controls. Include cancellation and corrupt replicas followed by cache reads. No arbitrary data-as-key paths or host traversal. Real sandbox/native qualification stays with bd-sandbox-native-readers-qx2om; passing parser fuzz alone does not certify containment or native recovery.

Acceptance refinements and source/test anchors:

Refinement4 resource/publication contract: report independent physical-read bytes, decoded bytes, retained memory, depth/record/replica-attempt counts and wall budget where measured; a metadata-count cap alone is not a complete process/physical-I/O bound. Include planted decompression/reference/retry explosions and a final-element failure that cannot become successful partial structured output. For strict read-only paths assert no backing write or synchronization authority through real call recording plus source/archive hashes. Preserve partial stdout/retained failure artifacts as errors, not fabricated atomic output guarantees. Update README/profiles from actual source and executed scope while retaining every end-state goal; docs changes alone close no functional requirement.

### bd-uzt72 — Qualify native FAT16/FAT32 writable mounts and ordered crash semantics

Proposed type: `task`; priority: `P1`; status: `open`; unassigned.

Dependencies: `bd-read-means-read-xpx37` (blocks), `bd-vuzzq` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V8: the six-format plan requires real ordinary native writes and interchange. At 944903e78 ffs-fat main.rs exposes mount --rw plus mkdir/unlink/rmdir/rename, filesystem.rs implements create/range write/truncate, mount-local identities, operation gate, open-handle lifetime and failure health. Closed bd-nu8nf's 134 unit tests are bounded implementation evidence, not complete mounted/native qualification. README still says writable mounts and unlink/rename are unfinished.
Work: inspect the existing writer rather than implementing a duplicate. Execute both dialects through public mount/syscall paths and independent native consumers. Cover alias/case/UTF-16 collisions, full fixed root versus growing directories, same/cross-parent rename, replacement, directory cycles, open-unlink/open-overwrite, stale handles and cookie resume, positioned writes/truncate/gaps, allocator exhaustion/reuse, active/mirrored FAT32 bits, metadata and final clean-state flush errors. Fix actual production defects and add their substantive regressions together.
Fault acceptance: separate pending/durable bytes; inject write/flush/torn-prefix/lost-pending cuts at native allocation, data initialization, namespace and clean publication stages. Reopen fresh instances. Preserve all acknowledged bytes and unrelated names; allowed leaks/dirty outcomes must match the declared ordered native contract. Do not claim general crash-atomic FAT transactions or silently weaken the checker.
Evidence: fsck.fat/mtools and native OS read-modify-reopen in both directions, exact image/ELF/options/tool versions, before/after hashes, structured phase/error/ack/cut logs, real selected counts. Missing mandatory tools/mounts are unqualified, never green skips. Use isolated copied images and the established authorization for mounted/device lanes; this task grants none. Existing immutable reads and dry runs remain zero-write.

Acceptance refinements and source/test anchors:

Refinement4 implementation anchors: crates/ffs-cli/src/bin/ffs-fat/main.rs dispatch; filesystem.rs plus filesystem/{lifetime,health,exchange}.rs; reader/replacement.rs with creation/mkdir/ranges/metadata children; reader/{check,recovery}.rs; formatter.rs and resize.rs. Reuse scripts/verify_fat_read.py and extend its actual native workload, not a new wrapper around modeled results. Run the full current companion suite with RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-fat; after library extraction keep the same corpus in the owning crate and companion dispatch tests. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-w4sht — Complete ZFS writable datasets, ZPL operations and shared-block lifecycle

Proposed type: `task`; priority: `P1`; status: `open`; unassigned.

Dependencies: `bd-f71fc` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V16: real committed-view and snapshot readers do not implement writable datasets, shared-reference accounting or lifecycle. Build on native TXG ownership rather than editing the reader's serialized blocks.
Work: create/write/truncate/rename/unlink/mkdir/rmdir/links/metadata through ZPL/DMU transactions; maintain SA/spill/ZAP, object generations, dataset properties and native ACLs. Implement dataset/snapshot/clone create/destroy/rename, holds/bookmarks, quotas/reservations/deadlists/deferred frees, DDT and BRT under explicit separate capabilities. Views share one pool owner while cache/handle identity includes dataset, snapshot, generation and birth. Persist resumable destruction work; no freeing from a reader-only shared-block interpretation.
Acceptance: native OpenZFS creates/modifies/reopens both directions; live/snapshot/clone content isolation, hard-link and open-unlink/rename races, destroy in every reference order, reclaimed-space accounting after restart, quota/ENOSPC/flush failures and deterministic crash cuts. Mounted and library operations execute with exact tool/profile/fixture/source identities and structured transaction/ack logs. Code and substantive unit/integration/fault tests ship together. Reading snapshots or changing a synthetic property is not lifecycle completion.

Acceptance refinements and source/test anchors:

Refinement4 implementation anchors: current engine under crates/ffs-cli/src/bin/ffs-zfs/reader/pool.rs and pool/{import,raidz,missing_mirror,gang}.rs, reader/dmu.rs and dmu/{allocation,properties,zap,zpl,zil,zvol}.rs; filesystem.rs is the readonly mount adapter. Pure formats/checksums remain in crates/ffs-ondisk/src/zfs*. Baseline command: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-zfs. Reuse scripts/verify_zfs_root.py, verify_zfs_files.py and verify_zfs_snapshots.py with native OpenZFS fixtures; extend them to native mutations/recovery after the engine exists. New transaction/lifecycle modules belong with the extracted pool engine, not a second binary-local parser. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-wlfpt — Bind multi-format protection to native durable views and complete device sets

Proposed type: `task`; priority: `P1`; status: `open`; unassigned.

Dependencies: `bd-11a8t` (blocks), `bd-uzt72` (blocks), `bd-w4sht` (blocks), `bd-wmzge` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V19: ffs-protected-mount is substantive, but Ntfs/Zfs variants are readonly and one-image sidecars do not establish coherent whole-pool protection. Reuse existing SidecarImageDevice state, archive and ownership mechanisms.
Work: define exact storage/view identity and native durable token for FAT, NTFS and ZFS. Capture only immutable/coherently owned sets; include required data/log/special members, topology, geometry and selected native generation. Persist affected-group invalidation before native writes, commit through native recovery, refresh from the stable view and seal a new protection generation. Native-durable acknowledgments may expose explicit lag; protected-durable acknowledgments wait for their required seal. Use native recovery and verified native redundancy before external repair.
Acceptance: independently faulted source/sidecar/member writes and flushes at every invalidation/native-commit/symbol/seal/ack prefix, stale/wrong image/serial/topology/view/token, foreign legitimate writes vs corruption, cancellation and restart. No stale restoration or parity regeneration from known corruption; no partial set treated as whole-pool protection. Verify native handoff/check/reopen and both acknowledgment policies. Implementation plus state-machine/unit/fault/mounted/native tests and detailed group/generation/native-token/ack logs ship together. Extend existing schema only when necessary; no redundant framework.

Acceptance refinements and source/test anchors:

Refinement3 test model: capture a partial order of native persistence/publication events and an independent acknowledged-operation prefix; explore reordered/torn/failed pending writes only within the declared device guarantee. Keep independent devices separately faultable. Reduce redundant schedules only when independence is demonstrated, retain minimized counterexamples and compare against native recovered allowed states. Never model arbitrary post-successful-flush loss as ordinary filesystem power-loss behavior. Distinguish not committed, durably committed and uncertain outcomes so retries cannot duplicate a committed namespace operation. This is a validation proposal, not a formal-proof or live-power-cut claim.
Refinement4 implementation anchors: crates/ffs-repair/src/sidecar.rs and sidecar/live.rs state; crates/ffs-core/src/native_repair.rs and existing durability/lifecycle hooks; crates/ffs-cli/src/bin/ffs-protected-mount/main.rs and scrub.rs; CLI mount_worker.rs owns structured drain/join. Run RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-repair and cargo test -p ffs-cli --bin ffs-protected-mount through the same remote admission. Reuse current archives/fault devices, preserving byte identity and permissions; do not widen private native tail ownership or make protected NTFS/ZFS variants writable before their native writers exist. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### bd-wmzge — Complete NTFS native namespace, streams and writable FsOps

Proposed type: `task`; priority: `P1`; status: `open`; unassigned.

Dependencies: `bd-5osex` (blocks).

STAGED PROPOSAL ONLY; canonical tracker guard unresolved. Audit source 944903e78, 2026-10-20. Preserve all original ownership and source; do not import by replacing canonical files.

Vision V12: once native NTFS transactions and recovery exist, deliver real user operations rather than serializer helpers. Current NtfsFs is immutable; FAT/ext4 commit ordering cannot implement NTFS semantics.
Work: route create/mkdir/write/positioned-write/truncate/hard-link/rename-overwrite/unlink/rmdir and metadata through the native writer. Implement Bitmap/MFT resources, resident-to-nonresident transitions, attribute-list growth, I30 index split/merge with volume UpCase collation, aliases and every parent/name/link/sequence invariant. Define open-unlink, handle reuse, directory cookies and negative cache invalidation. Maintain initialized vs logical size, MFTMirr-covered records and all active secondary metadata obligations; refuse a writable profile whose active indexes cannot be preserved.
Acceptance: actual public writable FUSE syscalls and library operations on Windows-created fragmented/sparse/large-index images; native consumer changes then FrankenFS reopen and reverse direction; concurrent allocators and rename/open-handle races; full-volume resource failure; poisoned reused clusters; every metadata/journal publication cut. Test identities, data, names, allocation and stale errors independently. Include inline/integration tests and structured operation, transaction, ack and error logs in the same logical change. Preserve read-only no-write controls and exact refusal for unsupported profiles. No Windows/interchange or mounted claim from modeled tests alone.

Acceptance refinements and source/test anchors:

Refinement4 implementation anchors: current engine lives under crates/ffs-cli/src/bin/ffs-ntfs/reader.rs and reader/{attributes,namespace,compression,wof,security,ea,source,recovery_apply}.rs; mounted admission is reader/filesystem/recovery.rs with record/preflight/redo; low-level native edits belong in crates/ffs-ondisk/src/ntfs and its recovery modules. Extend these owners or their extracted library without duplicating parser/recovery logic. Baseline commands: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-ntfs; RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ondisk. Reuse scripts/verify_ntfs_read.py and scripts/verify_ntfs_mount.py for independent consumers; extend actual native scenarios. After extraction retarget the owner package while retaining public dispatch coverage. Required Rust regression commands after disk/fleet admission: RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets; RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings; cargo fmt --check. These are necessary, not native/mounted proof. Preserve cleanup-disabled/no-delete fixture behavior and authorize any destructive device lane separately.

### Additive proposals for existing owner lanes

Apply these only after source comparison and owner reconciliation. They do not reopen, close, reassign or shorten existing work.

#### bd-wh1xk — add comment

2026-10-20 source audit at 944903e78, STAGED ADDITION ONLY: bd-ljrbw is closed with executed smoke receipts but gate5_fuse_mount_and_posix_operations (ffs-fuse lib.rs:26829) uses a handcrafted image, skip_validation=true, OpenFs calls and RecordingSender; no /dev/fuse mount, kernel syscalls, native ext4 consumer or actual process death. gate7_full_conformance_and_tools (cli_e2e.rs:3478) runs inspect/info/fsck/tui once but no mount/umount, prior gates1-6 aggregate, sustained one-Hz samples or hour-load leak check. PARITY_CONTRACTS multi-format OpenFs auto-detection and read-only VFS mount maps only detect_all_filesystems_identifies_fat16_fat32_ntfs_and_rejects_ambiguity_bd_i0gk5. Preserve smoke tests, classify only what they witness and complete the named actual mounted/full-stack criteria in the independent gate-owner lane. Never relax a gate/criterion or count detector coverage as mounted backend support. Plant a missing-mount/zero-sample/native-consumer negative and prove exact failures. Current 97 row count is structurally correct (78 prior table rows plus19 added), not six-format completeness. Qualification needs fresh source/ELF/options, real selected counts, immutable native fixtures, crash/reopen and independent checker evidence.

#### bd-native-image-library-s4tde — add comment

2026-10-20 audit refinement, STAGED ONLY: preserve exact native code units/aliases and compound view identity when extracting engines; detection vocabulary already has six variants but FsFlavor/OpenFs has only2 and protected-mount compiles binary trees via #[path]. The current parity row maps detection only. Acceptance requires actual public-facade opens of independently created FAT16, FAT32, NTFS and ZFS files, lookup/read/readdir/getattr with full source hashes unchanged, offset/length/ambiguous-profile negatives, native snapshot/stream selection, and unsupported writer refusal. Do not add a wrapper around an inadmissible source-open path. Keep pure parser fuzzing independent; engine traversal fuzzing can follow the extracted API. Preserve no-delete policy and active owner surfaces during any module relocation.

#### bd-z5bav — append notes

2026-10-20 audit STAGED ONLY: retain this original delivery scope and existing dependencies. A separate full six-format roadmap aggregate now tracks the missing native NTFS/ZFS and advanced work; no restricted ext4/btrfs release need wait for every advanced ZFS feature unless it claims them. Current acceptance must include actual mounted/native/crash evidence and artifact-to-consumer binding. Latest listed public release was v0.2.0 (2026-07-11); current companion source is not established as shipped by that artifact. See additive bd-wh1xk notes for synthetic gate5/gate7 and detector-only mapping gaps.

#### bd-in31y — append notes

2026-10-20 source audit, STAGED ONLY: the old title/description is no longer literally true for every production worker. mount_worker.rs now opens child regions, uses Cx::spawn_blocking, reserves a oneshot completion before I/O, and drains actual completion before releasing resources. vendor/fuser/request.rs handles Interrupt through a registry, and MountOptions auto resolves up to8 workers. Preserve these improvements and verify remaining request budget/cancellation and lifecycle gaps instead of reimplementing already landed worker/interrupt changes. New FAT/NTFS/ZFS adapters still contain standard synchronization; audit their actual cancellation/resource ownership against the asupersync requirement. Namespace atomicity remains bd-9rutw and default repair bd-11a8t; no blanket completion from these source connections.

### Executed audit evidence and retained limits

`br --no-db dep cycles --json` reports zero active cycles. Supported cwd-based `bv --robot-triage` loads 4,343/4,343 staged source rows with zero errors/skips/read errors. All nineteen planned work records and fourteen named existing critical lanes are reachable from the full-roadmap aggregate; no dependency target is missing. All 4,323 original IDs remain, and the canonical JSONL is byte-identical to the captured source. Equivalent timestamp normalization in five staged historical rows is not an import proposal.

`cargo fmt --check` fails in seven distinct initial-snapshot source files. `sbh check --need 20G` fails its configured pressure threshold and `rch check` is not ready, so workspace check, strict Clippy, Rust tests, native/mounted/crash campaigns and benchmarks were not freshly run. The source-aware wrapper fails 6/15 scenarios because its `bv` flag interface is unsupported; its data export still succeeds. Canonical tracker import remains guarded. None of these failures is waived by this planning packet.

### Post-refinement source refresh — FAT work landed during the audit

Shared `main` advanced after the initial `944903e78` snapshot. Commit `e2d47b0ec` adds explicit `--relocate` live-tail compaction through `resize/relocation.rs` and eleven authored regression functions; `525e8309b` adds aligned native `FALLOC_FL_COLLAPSE_RANGE` without retained-payload copies or spare allocation. Existing remote changes are retained in local merge `4b0b22161`; other audited production paths are unchanged.

The staged `bd-50neb` title and its notes, and the notes of `bd-uzt72`, were revised through `br`. Their initial-snapshot missing-relocation paragraphs above are historical and superseded: qualify/fix the landed implementations, do not reimplement them. `bd-50neb` still needs native maintenance/interchange and source-preserving shrink/fault evidence. `bd-uzt72` must include actual mounted collapse, full-volume/fragmented/preallocation and dropped/torn/flush/cancel/cache-publication cases under the declared non-atomic contract. Neither authored tests nor inspected source closes these tasks. This is the additive source-refresh proposal for both records; their existing acceptance and dependencies are retained. Refreshed formatting at `4b0b22161` fails in nine distinct source files, including the landed relocation/collapse paths; the retained log is `artifacts/reality-check/20261020/fmt-refreshed.log`.
