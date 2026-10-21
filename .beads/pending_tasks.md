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

### Implementation TODO — native library integration, 2026-10-21

Work item: `bd-native-image-library-s4tde`, staged `in_progress`, assignee
OliveCreek. Canonical claim was attempted and refused by the WAL/schema guard;
canonical owner/status data is unchanged. This checklist is the operator-requested
working TODO, not completion evidence. Retire it as an active checklist when the
original task's complete acceptance is executed and verified; retain its history.

Creation-gate worksheet: runtime does not consume this checklist. Consumer and
gate: the user's explicit request for granular TODO tracking during this work.
Observed defect: the audit found finished engines inaccessible through the
facade and essential implementation absent from the active graph. Retirement:
verified task acceptance, without deleting the file. No integrity exception is
invoked. Highest-value ready work is this native API integration; keep checklist
maintenance to minutes and spend the work block on executable integration.

- [x] Read current instructions/README and refresh HEAD, dirty paths and leases.
- [x] Recheck source-aware claimability; preserve canonical database/WAL refusal.
- [x] Attempt canonical claim and mark the same item in progress in staged Beads.
- [x] Ask the read-authority P0's recorded owner for a handoff; preserve ownership.
- [x] Extract NTFS reader, FsOps and exact stream-name selector into a library.
- [x] Keep every NTFS regression enabled and keep CLI-only tests in the binary.
- [x] Connect ordinary and protected NTFS binaries to the same library instance.
- [x] Extract ZFS pool/DMU/ZPL/FsOps engine without changing admission policy.
- [x] Keep ZFS native fixtures/regressions and both consumers connected.
- [x] Separate FAT engine/runtime boundaries; retain the shared pure clap schema.
- [x] Preserve FAT mutation/health/lifetime/recovery tests and explicit authority.
- [x] Connect FAT binary and protected mount to the same FAT library engine.
- [x] Add explicit six-format read-only options and ambiguity-checked dispatch.
- [x] Enforce read-only backing authority before detection/recovery; no write options.
- [x] Preserve explicit volume offsets, bounds, OEM names and ZFS view identity.
- [x] Author facade native-image and adversarial authority controls.
- [x] Statically verify no module duplication, package cycles or lost old tests.
- [x] Update architecture/parity documentation and nonempty library test commands.
- [x] Pass workspace formatting; inspect normalized source and integration diffs.
- [x] Fix FAT cancellation-test imports exposed by the first remote check.
- [x] Remove protected-mount's production partial `Deref`; retain test assertions.
- [x] Prevent FIFO blocking before regular-image admission; author real FD controls.
- [x] Preserve shared-main library commit and merge with FAT insertion/ZFS scrub.
- [x] Format six merged files; verify normalized source and test attributes unchanged.
- [x] Execute the facade suite at frozen `3b464766e`: 40 passed, no skips.
- [x] Fix seven production FAT Clippy findings without changing publication checks.
- [x] Fix remaining known all-target Clippy findings, preserving every test condition.
- [x] Independently diagnose the two FAT dropped-write probe failures.
- [x] Bind both probes to actual publication bytes and assert fault injection occurred.
- [x] Execute both corrected dropped-write controls with their original assertions.
- [x] Pass remote workspace/all-target compilation with exact source receipt.
- [x] Pass remote workspace/all-target strict Clippy without suppressions (`ff3dca7ec`, then `919ad4caa`).
- [x] Execute required harness test and benchmark commands through RCH; preserve the four test failures and both benchmark build deadlines. Passing these gates remains outstanding.
- [x] Execute all three merged engine suites with every retained regression at `f844f950a`.
- [x] Execute facade controls, external FAT consumer controls and public doctests at `f844f950a`.
- [x] Execute regular-image/OS-RO/FIFO block-device controls and reader regressions.
- [x] Execute NTFS/ZFS companion and protected-mount tests with nonempty selections (21/39/61 at `bd2fac9c4`).
- [x] Exercise built public consumers and retain their source/build identity (CSD FAT and ZFS evidence below; new NTFS stream consumer still pending).
- [x] Run native FAT/NTFS read profiles with real oracle tools; preserve original checks through the independently reviewed locale/raw-MFT fixture corrections.
- [x] Author an executable public-facade consumer with caller-owned runtime.
- [x] Compile and execute that consumer against independently produced FAT16 and ZFS images; native NTFS named-stream followthrough remains listed below.
- [x] Author direct public-facade native-producer FAT16/FAT32/NTFS acceptance.
- [x] Execute native producer comparisons; retain original images and oracle logs.
- [x] Reproduce NTFS facade admission failure with a real mkntfs/ntfscp image.
- [x] Independently review native FILE flag definitions and exact admission split.
- [x] Implement native metadata/view flag preservation with exhaustive unknown-bit controls.
- [x] Execute parser regressions and rerun the unchanged native-producer test.
- [x] Diagnose external dirty-image fixture's reserved-cluster address error.
- [x] Re-execute both external FAT consumer tests with proven dirty-bit planting.
- [x] Wire unchanged native FAT/NTFS profiles to explicit Cargo integration tests.
- [ ] Execute both native companion integration tests against actual binaries.
- [x] Choose and preflight a trusted OpenZFS host with sufficient scratch storage.
- [x] Run unchanged native ZFS file and snapshot profiles on fresh exported pools.
- [x] Identify the native MOS mixed-value ZAP failure without changing scalar validation.
- [x] Fix typed MOS root selection, retain malformed-reference rejection and verify natively (`d7a534c6f`, then complete native profiles at `bd2fac9c4`).
- [x] Diagnose native FAT Unicode-name failure against actual stored name bytes.
- [x] Independently review the fixture locale correction with all 80 old checks retained.
- [x] Execute all six corrected native FAT scenarios from a C-locale parent on CSD.
- [x] Execute the mixed-MOS ZFS correction: 304 unit tests and one compiled doctest.
- [x] Retain the next native ZFS failure: uninitialized `$ORIGIN` head and native raw bytes.
- [x] Model uninitialized heads explicitly; preserve initialized-root validation and read refusal.
- [x] Execute uninitialized-head controls: 305 ZFS tests at `bd2fac9c4`.
- [x] Execute current companion tests: NTFS 21, protected mount 61, ZFS 39 at `bd2fac9c4`.
- [x] Rerun native ZFS profiles/public consumers after the uninitialized-head correction: both ZPL versions, plain/bounded files and snapshots passed at `bd2fac9c4`.
- [x] Preserve and standard-format peer striped-mirror source and all ten new tests.
- [x] Qualify merged striped-mirror source at immutable `ff3dca7ec`: workspace check, strict Clippy, 315 ZFS unit tests and one compiled doctest passed. Native striped-mirror qualification remains open.
- [x] Execute the standalone public consumer on a native FAT16 Unicode file on CSD.
- [x] Verify worker artifact availability: completed RCH source workspaces are removed; old printed native artifact paths are unavailable. Preserve executed logs, award no current retention credit. CSD artifacts remain available.
- [x] Pass immutable merged-source workspace check and strict Clippy at `ff3dca7ec` after native fixes.
- [x] Rerun the NTFS native companion profile after the executed FILE-flag correction: all 203 commands passed on CSD, retained in `ffs-ntfs-native-crowbc55`.
- [x] Diagnose NTFS compression oracle failure against primary ntfs-3g source; request raw MFT bytes, independently reviewed with all 47 assertions unchanged (`9f45c1478`).
- [x] Retrieve the merged-source NTFS CLI consumer and prepare the exact CSD native rerun command (`ff3dca7ec`, SHA256 recorded below).
- [x] Resolve the actual formatter approval rejection before new NTFS formatting: subsequent user approval applied only to the concrete pending scratch-file command.
- [ ] Diagnose remote harness Git-source-identity failures without weakening its gates.
- [ ] Complete original native public-facade FAT16/32, NTFS and ZFS acceptance.
- [x] Review UBS findings and resolve actual production defects; retain test traps.
- [ ] Re-execute acceptance in a fresh verification pass; keep unproved items open.
- [ ] Record exact results in staged Beads, sync, commit and publish coherent work.

Shared-main update: the source increment landed in `93b8ca751`, then merged
with peer FAT range-insertion and ZFS redundancy-scrub work in `a03f7feee`.
Both remote refs were at that merge when checked. The source commit explicitly
keeps compiler/runtime acceptance pending. Six merged files needed standard
formatting; each now equals rustfmt's output from its committed source and
retains every test attribute. Workspace formatting passes on the merged tree.
The running remote check captured an earlier source snapshot; final acceptance
must use the merged source including the regular-image opener and peer work.
Canonical `br sync --import-only` was retried after the merge and again refused
the potentially committed WAL; no database/WAL replacement or deletion occurred.

Verification source is now frozen at `3b464766e84456184fb46ff444bf514a033a8c26`
with `RCH_REQUIRE_REMOTE=1 rch exec --base <that SHA> --clean-overlay --no-overlay
-- cargo check -j 1 --workspace --all-targets`. This includes peer FAT truncate
publication and NTFS allocation checking. RCH makes clean-baseline mode mutually
exclusive with `--source-content-receipt`; this run uses committed-tree authority,
not a dirty-source manifest. The preceding mutable-source run was superseded and
cancelled (remote exit 143, not a pass); its final guard also rejected 20 source
deltas introduced during execution. Its wrapper stopped, but two recovery
attempts reported a remote source-retention error; the retained job record is
`rchw-ee4eea67-ff44-419c-a562-550c1561e40e`. No shared daemon restart, lock removal,
manual source cleanup or local fallback was attempted. The new pinned run is
admitted on `vmi1152480` and remains pending.

Ten local Rust files now have formatting-only differences from committed source;
normalization and test-attribute equality were checked for each. Workspace fmt
passes. UBS on these ten files completed (exit 1): two deliberate test traps
rejecting allocation-check writes/flushes, 1,046 warnings and 310 info findings.
The traps and assertions remain unchanged. No clean UBS result is claimed.

Parallel remote gates, all at the same frozen revision: full workspace check on
`vmi1152480`; strict workspace Clippy (`-D warnings`) on `hz2`; complete
`ffs`/`ffs-fat`/`ffs-ntfs`/`ffs-zfs` test selection on `vmi1264463`. All use
`RCH_REQUIRE_REMOTE=1`, ordinary admission and `-j 1`. Runtime test threads are
bounded to two. These jobs are pending, not passes.

Native FAT oracle setup completed on `vmi1152480`: Ubuntu's signed Noble
`InRelease` and matching package-index SHA256 verified an isolated mtools
`4.0.43-1build1` archive. Package SHA256 is
`deb50411c17b001c2400dd8a0146f39d12070a2fe5e92d734b1c6d0e73119262`.
It was unpacked into `/data/tmp/frankenfs-native-oracle-8d_3rpbv/unpacked`, with
no system package installation. `mcopy -V` executed successfully; both mcopy/mmd
resolve to ELF SHA256
`4c8364b843223f44f008fa48f97ce48cce615799ac3d254069cff777d9110e0b`.
This supplies required real oracle tools, not a FAT profile pass. Raw setup and
signature/provenance files are retained with the private tool directory, and
the local transcript is `~/Library/Logs/frankenfs-verification/native-oracle-setup.log`.

Acceptance update (2026-10-21 02:42 UTC): the baseline workspace check hit its
configured 3,600-second deadline (exit 137), so it is not a pass. A warm-cache
candidate check now uses committed baseline `f7984bc153218737ecdf14a85a75b955e65fb9cf`
plus 15 explicit file overlays. The local baseline/overlay SHA256 declaration is
`a68779f108668d86785052d42f6176c950cf1c339e3f255af42aafd0e1d2a61e`;
it is a source declaration, not a worker-verified dirty-source receipt.
Candidate Clippy executed and failed additional production/test findings; all
are being fixed with equivalent expressions and no suppression. Its keep-going
run completed exit 101. The full native-library runtime job at `3b464766e`
executed the facade suite: **40 passed, 0 failed, 0 ignored**, including all five
new facade controls. Its complete FAT suite is running (430 selected tests);
NTFS/ZFS, external consumers and doctests remain pending. Current-tree runtime
acceptance still requires re-execution after the lint fixes. Full logs remain
outside the transferred workspace in `~/Library/Logs/frankenfs-verification/`.

Runtime update (03:06 UTC): the baseline FAT suite completed **428 passed,
2 failed, 0 ignored**, taking 1,582.31 seconds after compilation. Cargo stopped
before the NTFS/ZFS selections. The failures are
`cancelled_or_dropped_spelling_publication_is_never_reported_as_success` and
`native_copy_fault_cuts_preserve_source_and_never_admit_partial_clean_output`.
Independent source traces agree that both hardcode dropped write number 5,
which is now a sync: `set_dirty` internally writes three FAT16 sectors and
syncs/readbacks before the caller's retained outer sync. Neither probe actually
injected its intended write loss. The independent test-owner lane is replacing
ordinal targeting with actual byte-address targeting and explicit drop evidence;
all production barriers, cut loops and original failure assertions remain.
No filesystem correctness defect or green corrected test is claimed yet.

Final Clippy candidate currently uses baseline `f7984bc15` plus 24 explicit
Rust overlays, local declaration
`a761bb65bf2f6f51f309436bb9df2638ed355d0d717fb3354f1be9b3bf40235d`.
All five later CLI/facade Clippy findings have equivalent source fixes. The
chosen-worker attempt refused no free slots; ordinary selection admitted a new
run on `vmi1152480`. Two earlier pinned test selections refused queue timeout
and executed no tests. A newer full engine/block selection captured the old
fault probes and is superseded for final acceptance. Its exact cancellation
request (`rchw-88824dea-cd6b-4958-bb31-ee3154099894`) returned RCH-E504 daemon
timeout; no shared daemon restart, lock clearing or manual process kill followed.
The final source cut must include and re-execute the corrected probes.

The original native public-facade acceptance includes NTFS/ZFS and remains
unmet. Ordinary CLI profiles, constructed fixtures, static conservation and
compiler results cannot close that requirement. No acceptance condition has
been moved to another task. Available read-only inventories on `vmi1153651` and
`vmi1264463` found neither OpenZFS tools nor a loaded ZFS module; three other
direct probes refused unknown host keys and establish no tool-absence claim.

The new `crates/ffs/examples/native_reader.rs` is an independent application
entry point for the library, not another engine implementation. Creation gate:
the native public-facade acceptance needs an executable consumer, and library
users need a runnable example; no existing facade example entry point exists.
It directly calls public lookup/getattr/readdir/read/write-refusal operations,
owns its asupersync runtime, preserves raw directory names and supplies volume
bounds plus explicit ZFS dataset/snapshot selections. It remains uncompiled and
unexecuted until its named remote gates and native-image comparisons pass.
The unchanged ordinary companion profiles remain separate acceptance controls.

Executed result update, resumed 2026-10-21 15:05 UTC: the final v4 FAT library
suite passed **438/438**, zero ignored, in 1,515.89 seconds, including both
corrected dropped-write probes. Its external `library_api` target then had one
pass and one failure: the new dirty-image fixture called `entry_offset(copy,1)`,
but that API intentionally admits only data clusters. It failed before planting
the intended dirty state. The independent test owner corrected reserved FAT[1]
addressing through checked subtraction from FAT[2], preserving every original
assertion and adding three native-byte checks proving only the clean bit changes.
That external target is being re-executed; the earlier whole command is exit 101.

The v4 non-FAT job completed exit 0: facade **40**, NTFS **336**, ZFS **296**;
block unit **348 passed/1 ignored**, integration targets **6+2+6 passed**;
facade and block doctests **1+1 passed** (NTFS/ZFS have zero doctests).
The ignored block test requires a separately supplied loop device and sudo;
it receives no coverage credit. Both actual OS-RO/FIFO controls passed.
These are library/constructed-image tests, not native or mounted proof.

Strict workspace/all-target Clippy at v3 completed exit 0, source overlay
`b8975905988cc3194d1b34af2343035ca512bbecda9d6e24925614cdea591811`.
Later corrected probes, external fixture and example require a final lint pass.
The v4 check and v2 Linux consumer build timed out at the configured one-hour
limit (exit 137). The companion test link failed with linker SIGBUS, not a test
pass. All three are being retried through normal admission and warm caches.
The example actually compiled and executed `--help` remotely (exit 0), but RCH
then refused the foreign Linux ELF for the macOS output tree (delivery 102).
No foreign-artifact guard override was used; a new build explicitly targets
`x86_64-unknown-linux-gnu`. Help output does not prove native image consumption.

The v6 external FAT consumer target completed exit 0: **2 passed, 0 failed,
0 ignored**, including the corrected reserved FAT-entry fixture and its three
byte-level planting checks. Its full transcript is `tests-library-api-v6.log`.
The final v6 Clippy run found one style lint in the new example's directory
loop; the equivalent reference iteration is fixed without a suppression, and
the final strict gate remains pending. Two explicit ignored integration tests
now run the unchanged FAT/NTFS native Python profiles against Cargo's actual
companion executables. They retain stdout/stderr/status and require native
tools; ordinary ignored selections earn no credit. A v8 workspace check,
harness suite and explicit native-profile selection are admitted or queued
through RCH at 29 explicit Rust overlays (local declaration
`b1c17cd5f11523022e4956cf3a849987853f6fa19a17933e544985e0c81fb214`).
The subsequent one-line example iteration fix requires a final lint pass.

The v8 check refused before Cargo because the example changed during transfer;
no check credit is taken. Its harness/native-profile requests timed out in
admission and executed zero tests. A later concurrent merge of four peer
commits changed four overlay paths, so the v9 Clippy/harness requests also
correctly refused source drift. The v9 check/native-facade job had already
transferred their earlier cut; their results cannot qualify the merged tree.
The obsolete waiting v7 job was cancelled through the supported exact-wrapper
command and terminal-acknowledged, exit 1; no manual process/lock removal.
The independently reviewed FAT probes and dirty fixture are separately
committed as `12069daf0`, citing the 438-unit/2-external evidence and the
zero-to-one fault-injection split. Merge `d83c460fb` preserves the four peer
commits. Two working files retained merge markers; manual resolution preserves
native NTFS ownership checks and ZFS gang audit, plus both prior lint fixes.
Standard formatting and diff checks pass. Qualification will use an immutable
committed-source cut rather than dirty overlays, with no acceptance closure.

The v9 native-producer test actually executed one test and failed (exit 101).
FAT16 and FAT32 completed both plain/bounded scenarios with exact payload,
metadata, directory, refusal and unchanged-image checks. NTFS then failed during
open: `Corruption { block: 18, detail: "invalid field: ntfs.file_record (unknown
record flags)" }`. Evidence remains at the printed worker path ending in
`.rch-tmp/ffs-facade-native-KjVEG9`. This is a real native reader defect, not a
reason to filter metadata records or weaken the test. Linux v6.19 and ntfs-3g
2022.10.3 both define flags 1, 2, 4 and 8. Independent read-only review agrees
the parser must retain these bits, preserve directory/in-use masks, and reject
all 65,520 higher-bit encodings. Two new unit controls cover all 16 recognized
encodings, all unknown encodings, identity/payload/raw bytes and torn metadata
records. The unchanged native-producer test must rerun after this correction.
Native view-index content does not become unnamed DATA or writable authority.
No native NTFS/ZFS/mounted claim or functional closure is made.

The pre-merge companion job completed exit 0 with NTFS 18, protected-mount 61
and ZFS 39 tests; FAT's binary has zero tests because its tests live in the
library, so that empty target earns no coverage credit. The delivered five
Linux files total 2,886,229,368 bytes; 448,933,447 is the reported transfer byte
count, not their uncompressed total. Their actual SHA256s and file identities
are retained in `delivered-consumers-v6.json`.

The explicit Linux consumer build completed exit 0 and retrieved all five
requested ELFs (four companions plus the public example), 448,933,447 bytes.
This is build/delivery proof, not native-image execution. The new example's
static UBS scan completed with zero critical/warning findings. Native-test
scans retain one deliberate fixture failure trap; new merged production files
have zero critical findings and 19 warnings (bounded indexing and diagnostic
allocation), while merged tests retain three deliberate fixture failure traps.
No suppression, partial override, golden regeneration or clean-scanner claim
was introduced. All existing test/assertion counts survive the merged source;
six newly formatted peer files are byte-equal to standard formatting of HEAD.

The direct native-producer test in `native/tests.rs` creates only fresh retained
regular scratch images with dosfstools/ntfs-3g, populates them with mtools/ntfscp,
and checks independent extraction. It then exercises the public API on plain
and bounded-container images, including exact full/ranged/EOF bytes, metadata,
directory names, write refusal and unchanged whole images. It is explicitly
ignored by ordinary suites because tools are required; the named `--ignored`
invocation is required for credit and missing tools fail. It is now running
with serial tests and the provenance-checked private mtools directory supplied
explicitly. No ZFS/native/mounted/Windows inference is permitted from it.

The checks above mark **source work**, not executed acceptance. All 181 relocated
Rust files are accounted for; 166 equal the original after standard formatting,
12 have reviewed extraction/visibility/signal-boundary changes, and three add
explicit imports required by their retained cancellation tests. All
1,022 original engine test attributes remain enabled, with eight additional
facade/FAT consumer/regular-image controls authored. NTFS/ZFS CLI tests remain in their binaries;
FAT command-schema tests move with the shared library schema. All existing
assertions are retained. Cargo dependency resolution and workspace formatting
pass; external dependency versions are unchanged. Full staged UBS exceeded its
diagnostic output cap and is incomplete. Four smaller static scans completed:
73 FAT files (28 critical), 114 NTFS/ZFS files (49), one core file (zero), and
ten integration files (one). Critical findings are test-only traps (including
zero-write assertions) and two public NTFS magic comparisons, not secret
comparisons. The actual protected-mount production `Deref` panic was removed.
Scans still return findings; no scanner pass, suppression or partial override
is claimed. Rust build phases run separately through RCH.

The first remote compiler attempt executed and found six FAT test import errors;
those source errors are fixed, with verification pending. The original wrapper
lost SSH completion confirmation and was recovered/acknowledged (delivery exit
255); it is not a passing receipt. Clippy and runtime acceptance are unexecuted. The local disk
preflight fails its configured pressure ratio. The user replied "OK" to the
specific remote-only verification request and instructed continued execution;
that authorizes remote verification while local compilation remains disabled.
RCH worker-pressure admission remains in force. A new workspace/all-target check
was admitted on `vmi1152480` with `RCH_REQUIRE_REMOTE=1` and a source-content
receipt. Later FIFO source changes also require a fresh final verification.
Changing logs are retained outside the transferred workspace under
`~/Library/Logs/frankenfs-verification/`. No functional Bead is closed.

Remaining roadmap work stays under the 19 planned records above and the existing
critical owner lanes. Native NTFS/ZFS writers are not implied by library access.

Latest executed evidence (2026-10-21 16:04 UTC): immutable `dcdc37e37` passed
workspace/all-target `cargo check` remotely (exit 0). Its NTFS parser selection
passed **13 tests**, including exhaustive flag rejection and torn-record controls.
The unchanged explicit native-producer facade test passed **1 test**, containing
FAT16, FAT32 and NTFS plain/bounded native-image comparisons, exact full/ranged/EOF
reads, write refusal and unchanged image/sentinel hashes. Native artifacts remain
on `vmi1152480` at `.rch-tmp/ffs-facade-native-G4fgEu`; transcripts are
`check-committed-dcdc.log`, `tests-ntfs-flags-dcdc.log` and
`tests-native-producer-dcdc.log` in the external verification-log directory.
This proves those native image cases; mounted, NTFS named-stream facade and ZFS
acceptance remain open.

The unchanged companion profiles at pre-fix `f844f950a` executed two tests and
both failed: FAT16 Unicode lookup at command 014, NTFS root listing at command
041. Preserve both failures pending diagnosis/rerun. On trusted CSD, OpenZFS
2.4.1 created/populated/exported only fresh random scratch file pools beneath
`/data/ssd/tmp/ffs-native-verification-7CWV8iQw`. The v6 companion failed both
unchanged file and snapshot profiles before native payload comparison because
MOS object 1 contains legitimate typed arrays (TXG history and checksum salt),
while dataset discovery coerces the entire map to scalar references. Retained
file/snapshot roots end in `ffs-zpl-native-qdvh13i4` and
`ffs-snapshots-native-xxf0rk1_`. Existing pools were untouched; `buildpool` is the
only remaining imported pool. No native ZFS pass is claimed.

The harness command at `dcdc37e37` executed **2072 passed, 4 failed, 1 ignored**;
four failures report missing Git source identity in the RCH workspace. Its gates
remain unchanged. Full strict Clippy at `686206c79` failed on two equivalent
NTFS ownership diagnostics and thirteen test-style findings, now manually fixed.
The two test files retain all assertions and deliberate no-write/no-flush traps;
UBS reports three such traps, 219 warnings and 26 informational findings, not a
clean scan. Final strict lint and current-source verification remain pending.

Native continuation (2026-10-21 16:38 UTC): the fully executed merged engine job
at immutable `f844f950a` passed facade **40** (one separately required native test
ignored), FAT **452**, external FAT consumer **2**, NTFS **344** and ZFS **303**.
The facade and ZFS compiled doctests passed one each; zero-doctest targets earn
no credit. Transcript: `tests-engines-committed-f844.log`, exit 0. At `d7a534c6f`,
ZFS **304** runtime tests plus one compiled doctest passed. At `bd2fac9c4`, ZFS
**305** runtime tests and NTFS/protected/ZFS companion **21/61/39** passed,
including both-order uninitialized-head/accounting/born-hole controls. None of
these is native mounted or current striped-mirror acceptance.

The same actual v6 FAT executable and unchanged profile failed from a C locale,
storing `Native cafÃ©.bin`, then passed all six scenarios under UTF-8. The corrected
profile `f16528a32`, SHA256 `63723f42640bcb7be95e4e2c65c42d06eadac4b2f2411fa2d40d4f676fc33f82`,
passed all six scenarios even when launched from `LC_ALL=C`. Its 80 original
checks remain unchanged; installed UTF-8 and Python argv-encoding preflights
were added after independent gate review. CSD evidence remains beneath
`ffs-fat-native-6kcxwkz4`, with the locale recorded as `C.UTF-8`. The built public
consumer from `d7a534c6f` then actually read `/nested/Native café.bin`, returned
regular-file size 8452, matched the native source byte-for-byte, required typed
write refusal and verified the unchanged image SHA256. Transcript:
`fat-csd-standalone-public-d7a.log`; consumer SHA256
`fb081d4583a4a0d4b3ca6d396010f728886ced8bad1e55468aa706f953a7de12`.

The native ZFS rerun at `d7a534c6f` passed mixed-MOS selection, then exposed the
zero-root `$ORIGIN` head. Raw native records 32/35/38/42/45/54 are retained in the
external logs, with exact native head45 zero pointer/accounting. `bd2fac9c4`
models it as an explicit null object-set kind without read authority. Native
requalification remains pending. Peer `80bbed0a6` added ten source-only striped
mirror tests; background merge `90bb5c29d` retained both lines of work. All five
formatted files in `ff3dca7ec` equal standard rustfmt output from that merge,
with every test attribute retained. Its full check/Clippy/ZFS runs are pending.

The optional fresh NTFS standalone-image formatter was rejected by automatic
approval review (`mkntfs` classified as disk formatting). The empty prepared
image/source under `ntfs-consumer.RJSOS0a1` remain untouched; no formatter retry
or policy bypass occurred. Existing native library proof and already-running
companion verification remain separate. A later RCH FAT inspection could not
find the old printed worker image path (ENOENT); that failed inspection earns
no credit, and worker retention paths need verification before claiming current
availability. CSD's independent retained FAT/native artifacts remain available.
Cancellation of obsolete pre-merge Clippy wrapper
`rchw-4cefe619-fd4f-4fbc-a6c4-40c3b11d9086` was not acknowledged; its slots/state
were left intact. No manual lock/process cleanup or local compilation occurred.

Native execution update, 2026-10-21 17:03 UTC: both OpenZFS profiles passed
with `bd2fac9c4` consumers, SHA256
`1a6544a12f5dde8f14d0660e4a9875c3e5cce8ba04295ab64b0116160e9029f1`
and `41e55bd78bae93298a3ecdd11a0784fa88b155c4f070848c64ffa21e316cf0f3`.
The file profile root is `ffs-zpl-native-5v585dlk`; snapshots are retained in
`ffs-snapshots-native-wxggvr7a`, under the existing CSD private root. Both ZPL
versions passed plain and bounded images, companion and facade reads, native
metadata/names/bytes, sparse tails and unchanged hashes. Snapshot before/head/
after/before selections preserve the three native payloads and named historical
roots. These are separate processes; example EOF clamping does not certify a
direct EOF request to `FsOps`. The only pool remaining imported is the original
`buildpool`; no scratch pool was destroyed or evidence removed.

Merged `ff3dca7ec` passed all 315 ZFS tests and one compiled doctest, with zero
failed/ignored/filtered tests, on `ovh-b`; transcript `tests-zfs-merged-ff3.log`.
The full workspace/all-target check and strict Clippy also passed, with receipt
tree `ce0dc1724323bd7903604e19ab3abc3031f1f72d`. No native striped-mirror credit
is inferred from those ten new constructed tests. Completed RCH workspaces,
including the old native facade artifacts, were confirmed absent by read-only
inspection through the preconfigured worker SSH alias. Prior executed tests
remain executed evidence; printed worker paths are not current retained evidence.
The unsuccessful old-artifact readback build spent roughly 35 minutes and earns
no capability credit. Future native probes must explicitly retrieve their
artifacts or place them outside managed source workspaces before completion.

The companion NTFS native profile at `4ab22d1d7` reached its native namespace,
32 actual extension-record streams and bounded-image comparisons, then failed
the compression oracle's raw USA test. ntfs-3g 2022.10.3 `ntfscat.c:339-353`
confirms ordinary MFT output is already MST-deprotected. `9f45c1478` requests
`--raw` for that MFT call only. All 47 `require` ASTs and the complete allocation
validator remain identical; independent gate review found no relaxation. Raw
torn tails, malformed metadata, absent allocation savings and payload/hash
mismatches remain refused. This correction is source-reviewed, not a native
pass; the fresh NTFS consumer is building remotely. No new formatting has been
attempted after the actual automatic-approval rejection.

Named-stream followthrough, 2026-10-21:

- [x] Expose the immutable admitted NTFS volume through the facade, retaining
  the same `Arc<NtfsFs>` and bounded locked OS-read-only descriptor (`98006aa33`).
- [x] Reuse exact UTF-16 selectors and the selected DATA stream's own length in
  the standalone consumer; retain ordinary unnamed `FsOps` semantics.
- [x] Extend the actual native producer test with distinct native named DATA,
  plain/bounded full/range/EOF/beyond-EOF, wrong-case/missing and cancel controls.
- [x] Extend the existing native profile with the public consumer and all 32
  actual extension streams; keep all 47 old checks and 29 old commands.
- [x] Independently review source/authority/gate conservation. Compression and
  extension validators/scenarios remain AST-identical; 14 checks were added.
- [x] Execute the new-source regular library selections at `c51d483b5`: facade
  40 passed/one explicit native test ignored; NTFS 344 passed, no failures.
- [x] Fix two strict Clippy EOF diagnostic findings without changing the checked
  conditions; all-target workspace Clippy passes at `919ad4caa`, receipt tree
  `db5f4fdb5ad358a599150bedef0034b00e042182`.
- [x] Finish the current workspace/all-target check at `c51d483b5`: remote exit 0,
  receipt tree `d040847cf0dcb5a572e39b9a413cc476baa2cae2`.
- [x] Retrieve and hash the new public consumer from its exact RCH build:
  `c555bb45e`, clean tree `1200ffd8fbf2f567c6ed96dd0b81f4ecf7ccaab2`, Linux ELF
  SHA256 `f60197490727d5182a678e9ee67160e23f2a7df4102048013430daf1d62f17e9`.
- [x] Receive approval for the staged CSD native NTFS run: the user's subsequent
  "OK, so please do everything you think is advisable based on all of that" was
  applied to the concrete pending three-new-scratch-file command only.
- [x] Execute that corrected native NTFS profile: remote exit 0, 203 commands
  all exit 0, retained native images and logs in `ffs-ntfs-native-crowbc55`.
- [x] Exercise the new public stream consumer on those native images, including
  both exact selectors, extension streams, bounded ranges and typed refusals.
- [x] Collect the warm harness benchmark: exit 137 at its configured 3600-second
  build deadline, without benchmark measurements. Both attempts failed; no win.
- [ ] Resolve full harness source-identity execution separately from native
  functionality. No missing-Git fallback, skip or gate change has been made.

The obsolete pre-merge Clippy wrapper was subsequently recovered through the
supported `rch jobs recover`: original job completed exit 0, terminal acknowledged.
No manual slot/lock cleanup occurred. New-source UBS reports remain findings,
not clean scans: four Rust files have one pre-existing test-construction panic,
115 warnings and 58 information items. The native Python profile has four
critical heuristics (three public fixture-hash comparisons and an explicitly
chosen subprocess executable), no warnings and 20 information items; argv is
passed without a shell. No suppression was added. Native formatting is still
waiting on the explicit approval request following the real automatic rejection.

Bounded real-work audit: this continuation, 16:53–17:18 UTC, plus inherited
claims relied on here. Purpose from README: native filesystem behavior in Rust
through FUSE and offline-image tools. Actual five-commit inventory: `9f45c1478`
oracle input correction (ENABLER), `7f190d931` current user-facing native profile
documentation (USER), `98006aa33` same-descriptor named-stream API/example (USER),
`c51d483b5` stream boundary qualification/documentation (ENABLER), `919ad4caa`
retained assertion diagnostics (ENABLER). Executed native ZFS qualification is
another ENABLER work item; this requested TODO/Beads maintenance is PROCESS.
Tally: USER 2, ENABLER 4, PROCESS 1, UNKNOWN 0; this is a diagnostic, not a quota.
The demo is real head/before/after native ZFS bytes through the public consumer.
Without PROCESS, code and runtime outcomes are identical; it only preserves the
user-requested tracking. Actual consumers exercised the shared ZFS engine and
facade; NTFS stream access is compiled/unit-checked but native proof is pending.
The read-authority P0 remains an active owner lane with no handoff; this work
addresses the claimable library integration critical path. Every agent has zero
functional closes here. No plan/spec edit or follow-up replaces unmet acceptance.
Verdict: HEALTHY capability work, with avoidable verification cost disclosed;
finish positive native acceptance before expanding into another feature.

Honesty inventory for that same bounded window (not a project-wide certificate):

1. No (checked all current Rust/test/profile diffs: original assertions remain,
   new cases added, existing opt-in ignore retained, no new skip or bypass).
2. No (checked production getters/dispatch and new native producer controls:
   no fixture-specific production branch or mock supplies successful data).
3. No (checked changed paths and commit stats: no goldens regenerated).
4. Yes, oracle/gate code changed: `9f45c1478` corrects raw MFT input; optional
   public comparisons retain every old check. Independent source review and
   exact admitted/refused split are on record; no tolerance/timeout relaxation.
5. No (checked same-descriptor Arc ownership and selector/range code: no demo
   path hardcoding, ambient runtime, invented bytes or narrowed native corpus).
6. No (checked actual test counts: 40/344 and 315 are nonempty; compiled doctests
   are identified separately; the ignored native test earns zero pass credit).
7. An inherited extra ZFS compiled doctest was previously mislabeled integration
   proof. It was explicitly corrected in commentary and Beads; no extra test
   capability credit remains. Every new pass here has an observed command result.
8. No (checked native profile transcripts and independent verifier limits:
   retained-artifact replay, live producer execution, unit and mounted classes
   remain distinct; no FrankenFS mount or field claim).
9. Retention required correction: completed RCH workspaces and old native paths
   are gone. This is now explicit above and in Beads. Four harness failures,
   benchmark deadline, initial native failures and the new Clippy failure remain
   visible. No overall complete/verified or release claim was made.
10. No (checked cited commands: stdout/stderr retained in named external logs;
    failed inspections and admission refusals receive no credit).
11. No (checked staged status/comments: original item remains in_progress;
    no original acceptance moved into a new closure/follow-up).
12. No (checked docs diffs: original goals remain; evidence and API contracts
    updated without lowering the native/mounted/writer requirements).
13. No (checked agent reports/tracker: zero subagent or parent functional closes).
14. No (checked review dispatches: concrete positive/negative/authority criteria
    and explicit source-only/native-artifact/no-closure limits were supplied).
15. No (checked reviewed diffs personally and executed own gates; the independent
    ZFS verifier's 64 executions/22 comparisons are bounded extra runtime proof,
    not a replacement for native producer or full-bead acceptance).
16. No (checked agent output: reviews support positive file/stream capabilities;
    no refusal/error closure credits or new process framework).
17. No (checked claims: shared-source agreement is source review, not independent
    runtime proof. The separate CSD runtime check is labeled retained-artifact).
18. No (checked predeclared test selections and original 47-check/29-command
    conservation baselines; no after-the-fact performance success denominator).
19. Yes: the failed old-artifact readback spent roughly 35 minutes before current
    worker-path availability was verified. That waste is disclosed, earns no
    credit and motivates explicit pre-completion artifact retrieval. An oversized
    process inventory was also unnecessary; subsequent output was scoped to the
    FrankenFS job. No peer process, lock or SSH trust setting was changed.
20. Strongest result: both native OpenZFS file/snapshot profile runs, with exact
    binary/source hashes, retained images/native oracles/command logs, plus the
    independently re-executed bounded public-consumer comparisons. Re-executable
    within the documented native/tool/admission limits; no whole-project claim.

Older-context check: healthy/fresh Cass index; a bounded six-term query (including
the session-specific native allocation helper) returned nine matches. Followed
both returned session sources and inspected readable matched entries, excluding
encrypted reasoning. They show explicit native failure retention and independent
gate-conservation review; several are this same work and are not new evidence.
No comprehensive older-session honesty conclusion is inferred from that search.

Disposition: the raw-input gate change was separately reviewed, and original
conditions remain. The doctest/retention claims were corrected on record and
disclosed. RH-2 proof inflation is countered by separate doctest/native/mounted
labels and explicit current artifact availability; RH-7/RH-9 are countered by
keeping the original item open. Avoid further artifact readback before checking
existence/retrieval. No hidden failure, golden regeneration or functional close
was found in this bounded review; native permission and full harness remain open.

Approval handoff state, 2026-10-21 17:27 UTC: the corrected CSD profile is
`verify_ntfs_read-e730.py`, SHA256
`e73031b25c9c72a197013809b2678fa7716df713c99045ea69722580879d8f63`.
The already retrieved NTFS CLI at `ff3dca7ec` is `ffs-ntfs-ff3`, SHA256
`c0f6fc71775ca63c2ef17367446437f84163df1367da9ae67b75d15eedf36f9d`.
Both were verified on CSD beneath the established private root. The exact
command was presented in the pending approval question. It creates only three
new exclusive 64 MiB regular files and retains all evidence. No response or
permission has been inferred, and nothing has been formatted after rejection.
The later named-stream public consumer build and same-source warm harness
benchmark remain running in external transcripts
`build-native-stream-consumers-c51.log` and `harness-bench-dcdc-warm.log`;
collect their actual completion before any claim. The full `c51d483b5`
workspace/all-target check subsequently completed remote exit 0 at 17:27 UTC;
transcript `check-native-stream-c51.log`, receipt tree
`d040847cf0dcb5a572e39b9a413cc476baa2cae2`. Strict Clippy at `919ad4caa`
completed exit 0. The canonical import refusal and zero staged graph cycles
were rechecked; no canonical database mutation occurred.

Native NTFS continuation, 2026-10-21 19:15–19:19 UTC:

The exact approved command executed at approximately 19:15 UTC was:

```sh
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes csd 'sudo -n env TMPDIR=/data/ssd/tmp/ffs-native-verification-7CWV8iQw PATH=/usr/sbin:/usr/bin:/sbin:/bin python3 /data/ssd/tmp/ffs-native-verification-7CWV8iQw/verify_ntfs_read-e730.py --binary /data/ssd/tmp/ffs-native-verification-7CWV8iQw/ffs-ntfs-ff3'
```

Authorization text is quoted in the checklist above. This formatted only the
three new exclusive 64 MiB regular files named by the presented profile; it
did not authorize deletion, existing images/devices or broader formatting.
Transcript `ntfs-csd-profile-approved-1915.log` and the native `result.json`
both report `passed`. All 203 retained command statuses are zero. The candidate
and profile SHA256 values remain those in the approval handoff above.

Actual native coverage includes resident, empty and nonresident unnamed files,
directory/path reads, the `note` stream and 32 other named streams. The native
ATTRIBUTE_LIST identifies extension records 68–93 for base record 64, digest
`b0575bbd813e47e7435c98f9e98c6b6c0c9d0fd65e464bb8f87a4ba6058b5fef`.
Plain image SHA256 is
`2e5c0a7fe0518bbf4283f9f3d4703cc8a87e36ea30425fdf96fc0a4e6c36647d`;
bounded image SHA256 is
`45dca5ac01f6dd0d3e0842aec7aaa3517f5d6e134abcce48eb6ebb4cc38bcef4`.
Both compressed profiles passed their unchanged raw-MFT, actual storage-saving,
native-oracle, candidate full/range and unchanged-image checks: 512-byte clusters
(dense allocation 2048 bytes, image SHA256
`6ff7b9112f96ac969110e0f636f2591ee1b8e2e93ef513cc29e40e82e923222f`)
and 4096-byte clusters (16384 bytes,
`815c0b055e4a230e91163e461c38aac3c418849562014fce53eaa927e9520b83`).
The new public consumer was not supplied to this initial run; its subsequent
native pass is recorded below. This is native-produced offline-image execution, not a
FrankenFS mount, Windows interoperability or crash/recovery qualification.

The `c51d483b5` consumer build failed with ENOSPC while writing `ffs-repair`
incremental data. Its SSH completion was initially unconfirmed. The build
service later cancelled original build `30074357740994722`, wrapper
`rchw-2c6908d8-e121-47fe-a22d-69b85de511a7`, and recorded exit 130 with completed
remote cleanup. The normal recovery command found no remaining lease; a fresh
identity-qualified daemon status request confirms that same completed tuple.
Evidence: `recover-c51-wrapper-1919.log` and `c51-build-completion-1920.json`.
No lock, slot, process, cache or peer work was manually cleared. A smaller
example-only build at immutable `c555bb45e` waited for normal admission on
high-free-space `vmi1264463`, then refused with exit 103 at the queue deadline;
no remote execution or local fallback occurred. Retried only that example
through normal admission on `ts1`.
The exact example-only job is `30074357740994769`, transcript
`build-native-reader-c555-ts1-1924.log`. It completed remote exit 0 at 19:30 UTC;
the earlier queue-only refusal is `build-native-reader-c555-1921.log`.

`harness-bench-dcdc-warm.log` ended exit 137 at 17:44 UTC while building release
code, without measurements. Repeating the same cold/pressure-bound build again
is not justified. The four missing-Git harness failures remain open; source
binding, negative cases and gates are unchanged. Staged graph cycles were
rechecked empty. No functional Bead has been closed.

Documentation-only verification: workspace formatting and `git diff --check`
passed. UBS detected no supported language in these three Markdown paths and
exited 3 without scanning; that is not a scanner pass. No repository Rust code,
gate, assertion, fixture or golden changed in this continuation. The prior full
workspace check and strict Clippy therefore remain source-applicable. The new
native CLI execution adds offline qualification; source identity, performance,
mounted behavior and the public named-stream acceptance remain distinct.

Independent NTFS read-only execution subsequently passed on the same retained
inputs: 141 commands (63 candidate, 14 native `ntfscat`, three native `ntfsls`,
61 `cmp`), with 137 zero exits and four expected missing/wrong-case stream
refusals that emitted no stdout. Fifty comparisons involved nonempty bytes;
eleven checked empty/EOF results with explicit lengths. Native ATTRIBUTE_LIST
inspection independently identified `extension-06/19/31` in records 68/81/93,
sizes 1792/5120/8192. Plain/bounded full/range reads and 16 compressed boundary
reads matched native output and original payloads. Independent raw-MFT USA and
physical-compression checks passed; all four image hashes stayed unchanged.
Raw receipts are separate from frozen producer evidence:
`ffs-ntfs-independent-odwj800a`, result SHA256
`6f48b2d0569d303929ba0c0c2d578877298bbd9501868d08ee29fe4b18396af7`.
Root read the report and actual status/negative argv/stdout/stderr receipts.
This independently verifies the supplied binary identity and runtime results;
the verifier did not independently build-attest `ff3dca7ec`. No new production,
public named-stream or mounted claim is inferred.

Public native acceptance followthrough, 2026-10-21 19:30–19:40 UTC:

- [x] Retrieve the new Linux ELF, wait for completed transfer and verify matching
  local/CSD SHA256 `f60197490727d5182a678e9ee67160e23f2a7df4102048013430daf1d62f17e9`.
  Build source is immutable `c555bb45e`; RCH source tree
  `1200ffd8fbf2f567c6ed96dd0b81f4ecf7ccaab2`. No production source changed.
- [x] Execute the public NTFS consumer against existing native inputs without
  reformatting: 162 commands, including 120 public calls and 152 byte comparisons
  over payloads, metadata and EOF; three expected typed zero-output `NotFound`
  refusals. All 32 extension streams passed text selection; `note` and
  `extension-31` also passed exact UTF-16 selection. Plain/bounded ranges,
  compressed reads and typed write refusal passed; four whole-image hashes
  unchanged. Transcript `ntfs-csd-public-c555-retained.log`; raw CSD root
  `ntfs-public-retained-exy0n47m`, result SHA256
  `b0f9c462e2f037f33b33b7ce1dc4db83685da741167ab848f9076548754d67eb`.
- [x] Obtain separate public NTFS execution: 112 commands, including 58 public
  calls, ten native `ntfscat`, three `ntfsls` and 41 `cmp` (38 nonempty, three
  empty). Statuses 108 zero/four expected nonzero. Native catalog placement,
  exact selectors, bounded reads, compressed boundaries, metadata and refusal
  were checked. All four hashes unchanged. Root
  `ffs-ntfs-public-independent-n76gqh06`, result SHA256
  `f82fa134c7384a7f8595df47a1100f91d6a18250c969eefa096e5076ebdd0a2c`.
- [x] Read actual receipts, then re-execute all 112 cited commands at the supplied
  build, requiring matching stdout/status and typed, empty-output negatives.
  Remote exit 0; root `ntfs-public-root-recheck-zdccmfkg`, transcript
  `ntfs-public-independent-root-recheck.log`. This parent repetition is not
  another independent origin or new native production.
- [x] Independently execute the same C555 public ELF on native FAT16/32 plain
  and bounded images and retained native ZFS files/snapshots: 164 commands,
  108 public calls, six native FAT extractions and 50 `cmp` (40 nonempty/ten
  empty). Statuses 158 zero/six expected typed zero-output negatives. FAT
  Unicode names, full/ranges/stat/list/write-refusal passed. ZPL4 plain and
  ZPL5 bounded files and separate-process before/head/after/before snapshot
  selections passed. Eight complete image hashes stayed unchanged. Exactly
  one new exclusive FAT32 wrapped copy was made; no formatting/import/mount.
  Root `ffs-fat-zfs-public-independent-lndhzz5p`, result SHA256
  `c86e0dd49c4ca9c424de4fdc14a928a97ce4de154b5777fa96d184cc1049b26f`.
- [x] Re-execute all 164 cited commands after inspecting program/argument scope,
  requiring matching stdout/status and exact negative stderr. Verify all eight
  hashes before/after. Remote exit 0; root `fat-zfs-public-root-recheck-wsxbet6f`,
  transcript `fat-zfs-public-independent-root-recheck.log`.
- [x] Preserve the supplemental FAT probe failure: shell quoting removed quotes
  from a Python dictionary key, causing `NameError` before any child command.
  Root `fat-public-c555-0aiw3huk` and failed result are retained unchanged. Its
  completed FAT16 wrapped scratch copy was reused read-only. The independent
  valid probe and parent's re-execution provide the actual FAT results.
- [ ] Execute the still-ignored native Rust producer test's newly added body
  and the two explicit native Cargo integration wrappers; direct external
  producer/public executions do not make those Rust selections executed.
- [ ] Obtain a passing full harness in a genuine source-bound Git environment.
  Four failures in the clean archive remain; no Git fallback or gate edit.
- [ ] Complete required benchmark execution under supported resource/deadline
  conditions; both prior builds hit 3600 seconds, without measurements.
- [ ] Complete full task acceptance and independent closure; original staged
  Bead remains `in_progress`, canonical WAL/database guarded and unchanged.

The EOF results above are consumer-clamped; they do not establish direct backend
EOF requests. The independent verifier checked the supplied binary identity and
runtime behavior, not its build provenance. Existing native image inputs are
shared origins; repeated reads do not constitute independent native production.
Only the original `buildpool` remains imported on CSD. No mounted, writable,
crash-recovery, field-performance or whole-project readiness claim is made.

Bounded worksheets for this continuation (19:15–19:40 UTC):

Creation gate: these receipts/probes and this requested tracking are PROCESS or
ENABLER, not new production features. Running the product does not read them.
Consumer: the operator and verifier of `bd-native-image-library-s4tde`. Gate:
its original public native stream/view acceptance. Observed defect: the newly
exposed stream API had only compiled/unit evidence and the formatter rerun had
actually been rejected. Retirement: stop active probes/checklist when original
acceptance is independently complete; retain evidence without file deletion.
No integrity exception is needed (Part 3's four questions are inapplicable).
Highest-value ready item is this library integration; an hour on unexecuted
native acceptance beats another reporting framework. Verdict: minimal legitimate
gate; retire these one-off probes after acceptance, add no framework.

Real-work inventory from current diff and executed commands: no new production
commits or functional closes in this window. Two user-facing documentation
updates are USER, native producer/public execution and the necessary build
recovery are two ENABLER units, requested TODO/Beads maintenance is one PROCESS
unit; UNKNOWN zero. Ratios are diagnostic, not credit. Core purpose remains
native filesystem behavior in memory-safe Rust through offline tools and FUSE.
The two-minute demo is actual native extension-only NTFS bytes through the public
facade; it now runs. Without PROCESS, runtime outcomes are identical. The public
consumer actually exercised the integration; no speculative infrastructure was
added. Read-authority P0 stays with its named owner without handoff, so work
continued on this claimable critical path. Agent closes are zero; the verifier
ran positive reads plus negatives. No plan edit or follow-up replaced unmet
acceptance. Verdict: useful qualification, with bounded operational waste from
oversized recovery reads and the avoidable shell-quoting failure. Keep the next
block on remaining executed gates, not further evidence machinery.

Honesty inventory, same window:
1. No (checked all three repository diffs: Markdown only; no test/gate removal,
   skip, ignore, suppression or history rewrite).
2. No (checked probes invoke actual supplied ELF/native tools against retained
   native images; wrapper copies preserve input bytes, no special product path).
3. No (checked status/diff: no golden or fixture regeneration).
4. No (checked repository/config diffs and commands: no gate/configuration,
   tolerance, timeout or retry-budget relaxation; only normal RCH admission).
5. No (checked all invoked operations and evidence: no fake Git environment,
   hardcoded success or release-gate bypass; full harness failures stay failed).
6. No (checked raw status counts and nonempty comparison counters; UBS exit 3
   explicitly earns no scan credit, and ignored Rust selections earn none).
7. No (checked completion sessions, transcripts and retained argv/status files;
   the failed FAT probe is explicitly not an executed child command).
8. No (checked documentation/claims: native-produced offline reads, repeated
   retained inputs, consumer-clamped EOF and supplied build provenance are named).
9. No (checked current TODO/report: ENOSPC, queue refusal, both benchmark
   deadlines, four harness failures, ignored native tests and wrapper error retained).
10. No (checked subprocess capture and external logs: cited stderr is retained).
11. No (checked staged Bead comments/status: original remains in progress;
    no new follow-up carries away an essential unmet condition).
12. No (checked docs: evidence improved, promised scope was not reduced).
13. No (checked agent reports: no tracker mutations or closes).
14. No (checked all verifier dispatches: positive bytes, explicit negative,
    unchanged hashes and no-claim boundaries were supplied).
15. No (checked raw reports/negative receipts and independently re-executed
    all 112 public NTFS and 164 FAT/ZFS cited commands with matching results).
16. No (checked actual command classes: positive reads dominate, zero closes).
17. No (checked report wording: independent runtime execution is distinguished
    from shared inputs/source provenance; parent repetitions count once).
18. No (checked counts enumerate every command in each declared probe; expected
    nonzero outcomes and empty comparisons are separately disclosed, no cherry-picked rate).
19. Explain the quoting mistake and oversized recovery output before replay:
    both were avoidable operational waste, not product defects or passing proof.
20. Strongest evidence: the C555 ELF/source receipt, fresh native oracles and
    retained exact outputs, independently executed then re-executed by parent,
    with whole backing hashes unchanged. A skeptic can rerun the retained argv.
Older-session scope remains the bounded Cass followthrough recorded above; no
new comprehensive historical claim is made. Disposition: no hidden gate change,
false close or inflated proof found. The wrapper error is preserved/disclosed;
RH-2 and RH-7/RH-9 countermeasures are explicit proof limits and the still-open
original Bead. Avoid inline shell-embedded dictionary quoting in future probes.
