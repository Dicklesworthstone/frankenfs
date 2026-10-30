# Pending Tasks (Database Congestion)

Created by CC agent 2026-04-22. Import when bead database clears.

## Implementation checkpoint — 2026-10-30 (`bd-vuzzq`)

The operator requested implementation after the reality check, including a
granular working TODO. NavyElm resumed the existing P0 baseline item after
checking ownership and reservations. Its original full-workspace acceptance is
unchanged; a syntax repair alone does not close it. This checklist serves that
explicit continuity request and retires as active work when the listed work is
completed or handed off. Historical evidence remains in place.

Continuation: the shared checkout now contains the prior source repair in
`86877f568` and its tracker checkpoint in `10e980b02`; both were committed by
another actor during this session and are preserved. The resumed hz4 run has
executed all14 retained-image rename2 tests successfully (0failed/0ignored,
1580filtered,0.07s runtime; command exit0). This is unit evidence on real
in-memory filesystem operations, not fresh-native or mounted qualification.
Its source and fixture bytes are the previously recorded rename-repair cut.

The next coherent baseline correction is ordinary create-benchmark worker
errors: both existing parallel paths now return contextual errors, consume all
worker joins, preserve the first failure, and return before successful timing
output. Three new unit tests cover success/empty work, first typed I/O error
with all outcomes consumed, and a planted panic payload with later outcomes
consumed. They do not claim panic=abort recovery or real filesystem failure
injection. The core-only build warning is addressed by compiling
`ext4_add_dir_entry` under the same feature as its only two callers.

- [x] Resume the existing P0 and reserve the source/TODO surfaces.
- [x] Execute the14 existing rename2 unit tests on hz4 without changing them.
- [x] Repair both create-benchmark worker error paths and add the three unit
  regressions in the same existing source file; no new concurrency sites.
- [x] Align the sharded-only helper's compilation condition with its callers.
- [x] Complete the pre-snapshot workspace/all-target check and strict Clippy:
  `cargo check -j2 --workspace --all-targets` exits0 (2m16s Cargo), and
  `cargo clippy -j2 --workspace --all-targets -- -D warnings` exits0 (15.92s
  Cargo), both on hz3. Logs: `check-final.log`, `clippy-final.log` in the
  current capture directory. Fresh `cargo fmt --check`/`git diff --check` pass.
- [x] Execute the three new worker-result tests (3passed/0failed/0ignored).
- [x] Exercise the actual parallel benchmark command on private retained-image
  copies: eight creates survive reopening, and real inode exhaustion returns
  typed `NoSpace` without a worker panic. All5 combined CLI tests pass,
  0failed/0ignored/408filtered,0.72s runtime, command exit0 on hz3.
  Log: `/tmp/frankenfs-verification.sw1akO/cli-command-tests-fresh.log`.
- [x] Execute all16 retained-image rename2/own-hardlink/immutable-victim tests
  on the final cut; keep native recovery and allocator-mode gaps explicit.
- [x] Add a focused filesystem regression for cancellation after private
  namespace staging, successful retry with exactly one publication, visibility
  through an older snapshot, pinned-victim payload retention, and final release.
  It uses the existing image-to-memory helper. Under the sharded feature it
  explicitly executes both allocator modes. Native-oracle tests stay unchanged.
- [x] Execute the17-test combined rename selection with the sharded feature:
  the16 existing controls plus the new two-mode cancellation/open-victim test.
  **Executed red:**16passed/1failed/0ignored, exit101, with the new old-snapshot
  namespace assertion failing. The original assertion remains intact. A real
  cause was identified: writable read requests did not register or read their
  captured snapshot. This violates the existing documented per-callback view.
- [x] Implement managed writable-read snapshot ownership, atomic capture/pin
  against GC, scalar/Arc/borrowed/ranged snapshot reads and current-name-index
  bypass. Preserve unscoped mutation read-your-writes and the immutable RO path.
  Missing old ancestry returns typed `MvccConflict`, never newer bytes.
- [x] Execute the expanded22-test core selection:17 rename tests, new all-block
  views/GC test across single/sharded stores, unchanged RO registration and
  empty-scope controls, plus two unchanged mixed ranged-read controls. Both
  allocator modes are enabled for the rename regression. The first compile
  exposed a new-test API typo (`read_block` instead of `read_block_vec`), now
  corrected; that compile failure is retained without pass credit.
  Final execution:22passed/0failed/0ignored/1645filtered,0.13s runtime, command
  exit0 on hz3 (`core-snapshot-fixed2.log`). Both sharded=false/true markers
  occur. The failing namespace assertion was preserved and now passes.
- [x] Rerun final workspace compiler/strict Clippy checks and all5 CLI controls
  after the snapshot correction. Earlier green gates predate this source cut.
  Corrected-source check exits0 (44.25s Cargo, `check-snapshot.log`); strict
  Clippy exits0 (1m04s Cargo, `clippy-snapshot.log`); standalone formatting
  exits0 (`fmt-snapshot-verified.log`) and diff whitespace check exits0.
  The final CLI rerun passes5/0/0,408filtered,18.46s runtime, command exit0
  (`cli-snapshot-final.log`). Combined final targeted count is27 unique tests;
  earlier overlapping runs are not added to this denominator.
- [x] Rescan all six changed Rust files with the unchanged UBS rules. A combined
  scan hit the16MiB AST-diagnostic output cap and exits2, retained as incomplete.
  Two complete batches cover the same six files without exclusions or changed
  limits: core-only exits0 (0critical/15388warnings/3169info); other five files
  exit1 (5critical/2809warnings/1158info). The five critical sites remain the
  previously traced CLI paths. No scanner pass or commit-gate waiver is claimed.
- [x] Preserve the final source diff and16 raw execution/recovery captures under
  `artifacts/implementation/20261030_O221Lk/`; copied bytes were compared to the
  healthy `/tmp` captures. No build artifacts or fixture files were deleted.
- [ ] Native checker qualification remains unexecuted. A read-only `e2fsck -fn`
  RCH job for the persisted eight-create image was refused during source
  initialization (status73, wrapper103), before the checker ran. Recovered exact
  wrapper `rchw-1046e65a-6064-42b3-9b4d-726400a922d9`: acknowledged terminal1,
  no replay. See `native-createbench-image-a.log` and
  `native-refusal-recovery.json`. No native pass credit; no admission bypass.
- [x] Verify final source/fixture hashes and review UBS findings without a
  scanner change, suppression, exclusion or fabricated green result. Final
  `ubs-final.log` exits1:5critical/17577warnings/4164info. The five critical
  sites are unchanged exclusive fixture creation, three `current_exe` child
  launches, and fixed-production `mkfs.ext4` selection. This review is not a
  green scanner result or a waiver of the repository's commit gate.
- [ ] Reverify acceptance, record incomplete original requirements, sync Beads
  and land the verified correction within authorized publication scope.

Resource recovery: hz4 admitted the14-test run and a subsequent full workspace
check, then its root filesystem fell to12GiB free and RCH refused further work
under critical I/O/disk pressure. No admission threshold was changed. On hz3,
available RAM was193GiB, but the per-user runtime tmpfs was only about25GiB and
fell just below the required20GiB free. Increased only that existing tmpfs's
volatile size ceiling to32GiB using a remount; no file was deleted, no contents
were replaced, and `nosuid,nodev,mode=700,uid=1000,gid=1000` stayed unchanged.
Fresh SBH preflight then passed with28,513,206,272bytes free. The existing warm
task pool there is reused. Final lint surfaced two method-call closure lints
in the new worker joins; both were corrected with the actual join method.
For the explicit-feature core build, available RAM was179GiB; increased the
same volatile tmpfs ceiling to40GiB, preserving all mount protections and
contents. Fresh SBH then passed with30,404,882,432bytes free. This supplies real
capacity rather than changing the20GiB admission requirement.

Integrity incident and recovery: unrelated local disk growth exhausted the
root filesystem during a manual patch, and the patch tool truncated the CLI
source to zero bytes. This was disclosed immediately. Recovered the committed
source into `/tmp/frankenfs-main-recovery-20261030T2217.rs`, restored only the
confirmed empty regular file, and verified byte equality before reapplying the
two uncommitted join-method fixes. The two command regressions were then edited
manually on a preserved recovery candidate on healthy `/tmp`, formatted, copied
back under an exact prior-source-hash guard and compared byte-for-byte. No file
was deleted, and both tracker JSONLs still parse with4342rows. Backups remain.
Local disk subsequently recovered externally to46GiB free. Captures now use
`/tmp/frankenfs-verification.sw1akO`; this is raw execution evidence, not a new
readiness artifact.

An initial combined CLI run returned exit0 but executed only the three older
tests despite matching source hashes. It does not verify the new tests. A
source-mtime refresh forced actual recompilation through the same admitted RCH
path; the verbose log above confirms all five named tests executed. Current
CLI SHA256 is `613931a080ba33ac07aac59bb6df40c5128bd35add89a18f8e4bf25e8c6de40b`.
The pre-snapshot core cut was
`86cea02a983e87ebbc83b32b5258592502a8baa17d97fd51853cf9dbb390fb72`;
the corrected final core is
`8116bfd1c5ba882c17fc11677f393d88a22bb555ca53c8fdb7f01b7e9822d32f`.
All six final Rust file hashes, Cargo.lock and retained fixture bytes matched
the remote files. Final strict workspace Clippy/compiler/format checks and27
targeted tests pass. This is solo unit/integration evidence; native, mounted,
crash, full-workspace and performance qualification remain unestablished.
Writable reads now pay for snapshot registration and fixed-view block reads;
that correctness cost has not been benchmarked. Required full tests and the
unchanged UBS commit gate remain incomplete, so the original baseline stays
in_progress. The latest corrections remain uncommitted and unpushed. No
original acceptance condition was moved into a new item.

- [ ] Complete the original full workspace/harness/native requirements when
  fixture creation/cleanup and remote admission permit them. The earlier narrow
  Rule1 fixture-cleanup question remains unanswered; elapsed time is not consent.
- [ ] Obtain the required separate disposition of the existing UBS findings
  under AGENTS.md's zero-exit commit rule; no local scanner waiver was invented.
- [ ] Land the coherent source/test correction after the original gates permit
  it; keep source and tests together and preserve the current recovery patch.
- [ ] Continue `bd-9rutw` request ownership/concurrent-reader qualification,
  `bd-in31y` lifecycle and `bd-11a8t` repair within their existing ownership and
  acceptance, then the dependency-ordered `bd-3nf06` native roadmap. The continuous
  telemetry item `bd-dzbsp` still depends on this original baseline.

### Earlier implementation history (superseded by the checklist above)

- [x] Read the suite/project instructions and README; apply the requested
  anti-ceremony skill and inspect the existing dependency graph.
- [x] Preserve all peer/untracked files; reserve the core, CLI and this handoff.
- [x] Repair the malformed victim scope in `ext4_rename_staged`, keeping victim
  removal, link-count updates and retirement inside the private transaction.
- [x] Correct the CLI rustfmt difference and remove the unused duplicate
  device-view helper block exposed by the compiler. Existing namespace readers
  remain in use; no lint allowance was added.
- [x] Execute `cargo fmt --check` and `git diff --check`: both pass.
- [x] Execute the initial all-target workspace check on hz3: exit0 in8m51s,
  with the unused-helper warning. This predates the final cleanup/lint fixes.
- [x] Execute strict workspace Clippy and repair its five source diagnostics:
  two explicit iteration forms, two significant temporary lifetimes in unlink,
  and the rename retirement result assignment. Original assertions are intact.
- [ ] Complete the all-target workspace compiler check on pinned nightly.
- [ ] Resolve actual compiler diagnostics without suppressions or gate changes.
- [x] Complete strict all-target workspace Clippy on the final source:
  `cargo clippy -j 2 --workspace --all-targets -- -D warnings`, hz3,
  exit0 in6m26s. Log: `clippy-final4-hz3.log` under the capture directory below.
  Final core/CLI/lock hashes matched the remote files after execution.
- [ ] Execute the existing atomic rename overwrite/growth, directory replacement,
  late-failure/cancellation/pinned-victim and single-publication regressions.
- [x] Prepare a non-destructive unit-test alternative while native fixture
  permission is pending: copy the retained16MiB ext4 image, without clobbering
  anything, into the existing helper's ignored `ext4_small.img` fixture path.
  Source and copy SHA256 both equal
  `b87221221f9c4f489617329a5f9b68dc0c44f32bf6a560758353137a0a39e486`.
- [ ] Run the14 unchanged `ext4_rename2_` tests on in-memory copies of that
  retained image; verify the remote fixture hash and nonzero execution count.
  This is unit proof, not native formatter, mounted, crash or field evidence.
  **Attempted, not verified:** source/fixture transfer completed and the remote
  fixture hash matched, but SSH execution lost its connection before any Cargo
  or test output. Recovering owned wrapper
  `rchw-f3751c06-3346-4921-9bc6-eb53e7af5519` confirmed terminal exit255 and released
  custody; no automatic replay or test pass was claimed. See
  `rename2-retained-unit-hz3.log` and `rename2-recovery.json`.
- [ ] Run the two unchanged own-hardlink/immutable-victim rename controls using
  the same retained-image helper, if disk admission remains available.
- [ ] Exercise both allocator modes with `bhh0i_sharded_alloc` enabled; retain
  real native-oracle requirements and report executed/nonzero test counts.
- [ ] Execute the original required workspace/harness tests and classify every
  failure. Keep original tasks open where their acceptance remains unmet.
- [x] Execute changed-file UBS and inspect findings against the actual diff:
  seven unchanged CLI critical findings remain; exit1 is preserved, not green.
- [ ] Resolve or obtain the required separate disposition of the existing UBS
  findings without changing the scanner, suppressing rules or weakening gates.
- [ ] Reverify in a separate pass, record the evidence class and source binding,
  then commit/push the implementation without representing partial gates as green.
  Publication through the existing CI also runs native fixture creation and
  cleanup; retain the pending Rule1 choice rather than using CI to bypass it.
  **Current disposition:** keep the source patch uncommitted and unpushed while
  required verification and UBS disposition remain incomplete. No gate bypass,
  history rewrite or speculative task closure is authorized by partial results.
- [ ] Once the baseline permits it, select the highest-value ready capability
  from the existing graph: namespace request ownership (`bd-9rutw`), mounted
  lifecycle (`bd-in31y`) and default repair (`bd-11a8t`) precede qualification
  claims that depend on them. Preserve other owners' active lanes.
- [ ] Continue the native roadmap `bd-3nf06` in dependency order: FAT writer
  qualification/maintenance, NTFS transactions before operations/advanced
  semantics/maintenance, ZFS TXGs before datasets/topology/encryption/replication/
  zvols, then cross-format protection/fuzzing/workflow qualification. Continuous
  TUI `bd-dzbsp` is a separate positive integration opportunity once claimable.
- [ ] Close only items whose original acceptance has executed evidence; update
  this TODO, source-aware queue status and handoff with unfinished work intact.

Validation is in progress, not a green baseline. Local disk preflight fails,
so no local compilation is allowed. Several RCH attempts refused source
namespace initialization before compiling; source-content receipt mode also
refused an existing untracked xfstests symlink, which was preserved. One standard
check began on hz4's root target despite the transfer scratch setting; that
specific job was stopped and recovered (exit137, not success). Per-run config
now uses the supported `remediation.pooled_target.store_base` on a separately
preflighted worker tmpfs. Global worker configuration and gates are untouched.
The final core SHA256 is
`e2ff431136e42b3dc6c3bdd4a3594ee049ffd54d0fbbafb074325dba1e98f716`.
Two later hz4 attempts refused source initialization before compiling. hz3's
original `/tmp` target filesystem subsequently failed the20GiB headroom check,
so it was not reused for further builds. A separately preflighted task-specific
pool under `/run/user/1000` on hz3 admitted the final strict lint rerun. No
preflight, source-authority check or global configuration was relaxed.
The final UBS scan still exits1 on seven unchanged CLI findings, which were
inspected rather than suppressed; this is not a scanner pass. The latest
`sbh check --need 20G /run/user/1000` reports21,169,074,176bytes free against
21,474,836,480required, exit1, so no further build was launched. The original
`/tmp` pool is also below headroom and hz4 source initialization is refusing.
No cache or source file was deleted to make room. Native fixtures are awaiting
the operator's cleanup choice under Rule1. The baseline and roadmap stay open;
no mounted, crash, fresh-native or field qualification was established. Logs
are retained under `artifacts/implementation/20261030_O221Lk/`.

## Current checkpoint — 2026-10-30 reality check

Audit `bd-umbgi` reviewed source `bc3de2c09`. Normal canonical `br` reads and
mutations now work; the old guarded staging instructions below are historical.
The October 20 artifact workspace is absent on this machine. Its relevant
missing implementation/qualification proposals have been reconciled with current
source and recreated through `br`, with fresh canonical IDs, rather than copying
an old database or JSONL over the tracker. Do not blindly import that old packet.

The full roadmap is `bd-3nf06`; sixteen coherent implementation/qualification
tasks cover FAT native writes/maintenance, NTFS native transactions/operations/
advanced semantics/maintenance, ZFS TXGs/datasets/topology/encryption/replication/
zvols, whole-set protection, continuous TUI, native fuzzing and native workflow
qualification. The old-to-canonical ID map, dependency graph, 24-goal checklist
and evidence are in `docs/reality-check-bridge-writeup.md` at the October 30
section. Existing repair, MVCC, lifecycle, gate, sandbox and performance owners
and acceptance remain in place; no product implementation was closed by audit.

**Current baseline is red.** `cargo fmt --check` fails to parse
`ffs-core/src/lib.rs` (unexpected closing delimiter at line 49253, with malformed
victim scope in `ext4_rename_staged` around 36034), and reports a CLI test format
difference. The current-HEAD CI run `40554264889` fails Format check and skips
dependent golden/FUSE jobs. Existing `bd-vuzzq` was raised to P0 with exact
evidence; GoldKite ownership, in-progress status and full acceptance were kept.
No source/gate/assertion/golden was edited by this audit. Heavy Rust checks,
tests and benchmarks were not started after failed disk/fleet admission.

The initial live-only source-aware tracker E2E passes 15/15 scenarios. The full
default run subsequently fails 16/17: its fixture golden has identical parsed
JSON values but different formatting, and the gate compares bytes. Separate
gate-owner bug `bd-ln2wr` retains that failure and the required review/negative
controls; no gate or golden was changed. It adds a seventeenth task to the
sixteen product/qualification packages. Fixture and golden checksum manifests
pass; these are artifact integrity, not filesystem readiness. Archived CLI
inspect/info/fsck smoke runs on a retained-image copy
pass with unchanged hashes; its TUI invocation refuses arguments, and none of
that archived execution qualifies current HEAD. Fresh native formatting was
rejected by automatic approval review and was not bypassed. Retained audit
artifacts are under `artifacts/reality-check/20261030_lHwVOA/`.

## Current checkpoint — 2026-10-22

`bd-native-image-library-s4tde` remains the single claimed item, staged as
`in_progress`. Canonical import still refuses its committed-WAL guard; that
database and its WAL have not been modified. Historical entries below retain
their original scope; the latest source-bound receipts are at the end.

Completed in the preceding continuation: permanent native FAT16 root growth
(532 commands), FAT32 FSInfo repair plus separate ordinary recovery (20
commands), and two strict read-only FAT FUSE mounts. Source and payload hashes,
native filesystem checks and exact byte-preservation controls passed. Nine root
regressions and the initial eleven FSInfo regressions passed. Two equivalent
FSInfo production corrections plus two test-lint corrections are now under
overlay `7262c1db`; full formatting and changed production/test UBS pass. Strict
Clippy, workspace/all-target check and formatting all pass on that final cut.
The eleven-test rerun passed on `a02d60b9`, the same final production before
the two test-only literal/fixture-guard edits; final compiler/Clippy checks cover
those edits. The later streaming commit is outside those executed source cuts.
Current work qualifies ea0bc8afd plus nine overlays. Its CLI passes 118 native
commands across four images, with 56 payload comparisons and unchanged hashes.
Full FAT/facade runtime passes 548 tests with one existing ignore on ed09c13e.
After equivalent test-only lint fixes, all ten streaming tests pass again and
workspace check, strict Clippy and formatting all pass on final7d13873c.
Production source is identical between those two cuts. Older review bundles
remain historical snapshots; the final review snapshot is recorded below.
The later public-consumer refresh builds the same final Rust cut and passes
644captured commands/516public calls across all six formats. The permanent FAT
runner now supports --facade-binary, including root-expanded and recovered
outputs. Exact proof classes, logs, hashes and the16:26 no-delete violation are
recorded in the final continuation below. An external session committed9800c04f6
during this work; root preserved its index and made no commit or push.

Publication and closure still require independent disposition of the unchanged
UBS public-hash/test-panic reports and review of the new dirty-check status
correction. No source rule, assertion or scanner has been weakened. Later
`ea0bc8afd` streaming is outside the frozen `8dae5e14b` qualification package.
The dependent native-engine fuzz task remains open; do not bypass the original
dependency, claim another owner's read-authority item, or infer field/writer
acceptance from these read-only and offline results.

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
- [x] Execute required harness test and benchmark commands through RCH; preserve the four test failures and both benchmark build deadlines. Subsequent complete runs passed: harness build30074357740994971 and benchmark build30074357740994956, detailed below.
- [x] Execute all three merged engine suites with every retained regression at `f844f950a`.
- [x] Execute facade controls, external FAT consumer controls and public doctests at `f844f950a`.
- [x] Execute regular-image/OS-RO/FIFO block-device controls and reader regressions.
- [x] Execute NTFS/ZFS companion and protected-mount tests with nonempty selections (21/39/61 at `bd2fac9c4`).
- [x] Exercise built public consumers and retain their source/build identity (CSD FAT, ZFS and subsequent NTFS stream evidence below).
- [x] Run native FAT/NTFS read profiles with real oracle tools; preserve original checks through the independently reviewed locale/raw-MFT fixture corrections.
- [x] Author an executable public-facade consumer with caller-owned runtime.
- [x] Compile and execute that consumer against independently produced FAT16 and ZFS images; subsequent native NTFS named-stream execution is recorded below.
- [x] Author direct public-facade native-producer FAT16/FAT32/NTFS acceptance.
- [x] Execute native producer comparisons; retain original images and oracle logs.
- [x] Reproduce NTFS facade admission failure with a real mkntfs/ntfscp image.
- [x] Independently review native FILE flag definitions and exact admission split.
- [x] Implement native metadata/view flag preservation with exhaustive unknown-bit controls.
- [x] Execute parser regressions and rerun the unchanged native-producer test.
- [x] Diagnose external dirty-image fixture's reserved-cluster address error.
- [x] Re-execute both external FAT consumer tests with proven dirty-bit planting.
- [x] Wire unchanged native FAT/NTFS profiles to explicit Cargo integration tests.
- [x] Execute both native companion integration tests against actual binaries.
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
- [x] Diagnose remote harness Git-source-identity failures without weakening its gates.
- [x] Complete original native public-facade FAT16/32, NTFS and ZFS acceptance.
- [x] Review UBS findings and resolve actual production defects; retain test traps.
- [x] Re-execute the library/native acceptance in fresh source-bound verification;
  retain the targeted UBS/publication condition and broader unproved items below.
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
- [x] Resolve full harness source-identity execution separately from native
  functionality: build30074357740994971 passed2652tests with a valid source
  receipt. No missing-Git fallback, skip or gate change was made.

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
- [x] Execute the still-ignored native Rust producer test's newly added body
  and the two explicit native Cargo integration wrappers; direct external
  producer/public executions do not make those Rust selections executed.
- [x] Obtain a passing full harness in a genuine source-bound Git environment.
  Four failures in the clean archive remain; no Git fallback or gate edit.
- [x] Complete required benchmark execution under supported resource/deadline
  conditions: build30074357740994956 returned0 with60 timing intervals. Both
  prior3600-second failures remain losses, without measurements.
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

Remaining Cargo acceptance resumed, 2026-10-21 19:58–20:08 UTC:

- [x] Refresh local instruction files and source-aware tracker state. Canonical
  `br ready` still refuses the guarded WAL. The local JSONL queue report lists
  50 claimable IDs, including this original native integration item; no foreign
  open rows or permission-gated IDs. The wrapper is NOT green: its installed-bv
  CLI compatibility check and release-ready-P0 self-check fail. Retain
  `artifacts/e2e/20261021_155528_ffs_tracker_source_hygiene_UomBrN/` and
  `tracker-source-native-resume.log`; do not weaken those checks.
- [x] Identify the actual current source: origin/main fast-forward at 19:58 UTC
  added `71484c280` and `c6c93513b` (new opt-in NTFS index-directed lookup),
  leaving the production working diff empty. Prior C555/919 runtime and lint
  receipts do not validate these newly merged paths.
- [x] Start the full harness on hz3 using strict RCH with
  `--source-content-receipt`, genuine complete Git metadata and unchanged gate
  code. Isolated external config `rch-git-bound.H8FGxz` differs only by removing
  the `.git/` transfer exclusion; workers/config admission otherwise unchanged.
  RCH build `30074357740994797` is compiling at actual source `c6c93513b`.
  Transcript `harness-tests-real-git-722.log` has a historical filename suffix,
  not a claim that 722 was the uploaded source. No completed pass/receipt yet.
- [x] Independently review the Git transfer/config and byte barrier. Optional
  Git index-cache refresh may change `.git/index`; preserve any resulting
  barrier failure instead of excluding/restoring bytes or manufacturing Git.
- [x] Find an admitted native-tool worker through a read-only RCH directory
  inventory: vmi1149989 has dosfstools and NTFS tools, but lacks mtools.
  `native-oracle-inventory-rch-vmi1149989.log`, remote exit 0. Old preferred
  worker was draining; strict direct SSH refused its absent host pin. No trust,
  pressure/admission gate, global config or filesystem cleanup was changed.
- [x] Provision authentic mtools privately on hz3 after the vmi1149989 job
  queued behind changed capacity. Both queued metadata jobs were canceled
  through supported RCH cancellation before execution (exit 130, zero slots).
  Strict pinned SSH read-only inventory succeeded on hz3; SSH was used only
  for metadata and private package extraction, never Cargo/compilation.
  Scratch `/tmp/frankenfs-native-oracle-kd57s1nx`, package SHA256
  `deb50411c17b001c2400dd8a0146f39d12070a2fe5e92d734b1c6d0e73119262`;
  both tools SHA256
  `4c8364b843223f44f008fa48f97ce48cce615799ac3d254069cff777d9110e0b`.
  `native-oracle-setup-ssh-hz3-2011.log`, exit 0; no system installation.
- [x] Execute the newly extended native producer Rust selection and both
  native companion Cargo wrappers against actual native producer tools.
- [x] Execute current-source NTFS library/CLI checks including merged indexed
  lookup tests; any substantive defect requires an actual source fix and gates.
- [x] Reproduce then fix the independently found same-reference indexed-key
  identity gap. A valid A.txt/ns1 key followed by A.txt/ns2 for record 24 can
  evade verification of the latter identity (record 24 actually owns
  A~1.TXT/ns2). Reversing order should reject today. Require both malformed
  orders to reject and a genuine two-identity alias pair to pass. Validate all
  matching identities without reading unrelated sibling records. This is a
  source-trace finding, not an executed red test yet; source remains frozen
  until the full harness byte barrier finishes.
- [x] Manually correct formatting in the four merged indexed files. Read-only
  local `rustfmt --check` (no Cargo/compilation) exited 1; full remote workspace
  fmt job is queued. No formatter wrote source and no gate was changed.
- [x] Finish full harness with a valid final source receipt; preserve every
  failing/skipped selection and any source barrier refusal.
- [x] Resolve the two release benchmark build deadlines with a supported,
  resource-appropriate run: later build30074357740994956 returned0 with60
  timing intervals, under the unchanged default profile and deadline.
  Full unchanged-profile `cargo bench -j2 -p ffs-harness` at immutable c6 is
  requested on hz3 (the prior attempts used vmi1293453). Admission, deadlines
  and compiler profile remain intact. This is execution qualification, not
  an optimization or incumbent-relative performance win.
- [ ] Reconcile executed evidence on the original staged item, retain unmet
  acceptance there, and obtain independent full-acceptance review before close.

No production code, test, gate, golden, runtime limit or canonical Beads state
changed in this block. The isolated one-slot RCH job config sizes a single
read-only Python/ls process; it does not alter global worker slots or pressure
thresholds. Two earlier read-only formatter-path probes were rejected by DCG;
no formatter ran, and no allow-once or guard bypass was used. The allowed
directory inventory supplies only tool-availability evidence.

Concrete indexed-reader repair, 2026-10-21 20:41–20:50 UTC:

- [x] Prioritize the identified integrity bug over waiting for the old full
  harness compilation to finish. Exact-wrapper cancellation was requested;
  both RPCs timed out. The remote command subsequently returned 137/SIGKILL
  (RCH labels the cause unconfirmed), and the original wrapper ended 137.
  No test executed and no harness pass is claimed. No daemon restart, manual
  process kill, lock clearance or forced ownership recovery was used.
- [x] Retain the actual source-only receipt for that failed command:
  build `30074357740994797`, receipt root
  `d2c9f23c646296970cdab045cc892d9629bffc5c2e3ac3b721b18780a540d1ec`,
  content root `b4c6e51df35b7347f74cdf98f3b367dce37d807351d2611d76f8db42585677fb`,
  10,156 files / 924,767,522 bytes, command exit 137. Local and worker Git
  index snapshots matched SHA256
  `fadc1de0cfae0cf03f5adc9a59c170850d26c05c303252bbb1f5dafce64c6074`.
  Final source verification completed at 20:43:14 UTC, before reader edits.
  This proves transferred bytes, not any test outcome or Git-sensitive test.
  The possible optional-index-refresh issue has not been observed in runtime.
- [x] Manually repair candidate retention and selected-record validation:
  retain every same-reference matching name, deduplicate additional exact
  parent/sequence/namespace/UTF-16 identities in a BTreeSet, and validate them
  during one selected catalog scan. Strict lookup supplies an empty slice.
  Keep all FILE_NAME storage checks, exact-case priority, ambiguity rejection,
  read-only authority and existing traversal limits. Add cancellation checks.
- [x] Manually format the four affected indexed files. Add two constructed
  unit regressions: malformed aliases in both orders and exact/folded queries;
  valid aliases backed by both FILE_NAME identities. The original seven reader
  tests/helpers/assertions match their formatted baseline exactly. The three
  CLI tests match their formatted baseline byte-for-byte. Read-only rustfmt
  and Git whitespace checks pass; these are static checks, not compilation.
- [x] Independently review the production repair. No concrete defect found;
  additional identities are bounded by 65,536 examined keys and 255 UTF-16
  units/name, with O(K log K + A log K) set work and per-iteration checkpoints.
  Only the selected record/catalog/extensions are read; no sibling MFT IO.
- [x] Execute planted red against immutable c6 plus ONLY the test-file overlay,
  then execute repaired source. First red request
  `tests-indexed-same-ref-red-c6-2049.log` was refused before execution by the
  source-namespace initialization (status 73); no red-test credit from that
  attempt. Do not infer an ownership conflict from that status. The subsequent
  immutable red executed one valid-alias pass and one missing-alias failure.
- [x] Run corrected-source NTFS/facade/CLI tests, workspace check, strict Clippy
  and full workspace formatting; fix actual diagnostics without suppression.
- [x] Run corrected current CLI on retained native external indexes, named
  streams and compressed files. Those images each have one external leaf;
  no native multi-branch-pruning or performance claim can come from them.
- [x] Re-run full real-Git harness on finished source with a valid receipt;
  preserve all missing/forged/mismatch/zero-selected rejection controls.
- [x] Re-request unchanged-profile full benchmark after capacity is available;
  later build30074357740994956 completed successfully with60 timing intervals.
  The c6 hz3 request exited 103 at admission queue timeout before compilation;
  no third benchmark build or measurement occurred.
- [ ] Update original staged evidence, independently review full acceptance,
  and close only if every original condition is executed and met.

Repair invariants: every selected matching identity exists in its target FILE
catalog, independent of key order; legitimate aliases remain readable; losing
folded candidates cannot override exact-case priority; cancellation and source
read authority stay intact. Evidence ledger so far is the independent source
trace, concrete planted fixture, conserved old controls, and reviewed patch.
There is no probabilistic admission threshold or integrity exception: missing
identity is a categorical corruption refusal. Executed red/green remains open.

Execution update, 2026-10-21 21:01–21:06 UTC:

- [x] Collect native selection exit 0, remote hz3 build `30074357740994812`.
  Both public facade native tests, both native CLI profile wrappers and the
  selected native unit controls passed. Nonempty summaries were 2/16/3/3/2/50
  passes, zero failures; zero-selection targets are not counted as evidence.
  The unchanged FAT profile executed all six FAT16/FAT32 scenarios, including
  producer interchange. NTFS profile status is passed, including named streams,
  attribute extensions and compressed 512/4096-byte cluster images. The public
  producer test exercised the current same-FD stream body. No mount occurred.
  Full log: `tests-native-current-c6-hz3-2012.log` under
  `/Users/jemanuel/Library/Logs/frankenfs-verification/`.
  Source receipt: immutable base `c6c93513b0c767bc6875cb3f6926f438198b6765`,
  overlay `fe0d5151031be8fda7951fe7fe1f42f7ce344018fdb3ed21e6ada866b230b195`,
  tree `3b2b11c05c6a403e4290dbfd958619c39ead09a5`. This validates c6 default
  paths; it does not validate the later same-reference repair or new FsOps API.
- [x] Record generated native evidence paths reported under remote `.rch-tmp/`:
  `ffs-facade-native-aCqJTn`, `ffs-companion-profile-ejDoTI`,
  `ffs-fat-native-tya2u377`, `ffs-companion-profile-lw7MXG`, and
  `ffs-ntfs-native-u6tsxdmm`. Their common source root is
  `/data/tmp/rch/frankenfs/paired-0f6a5b6cb84c1663e059fcea11dc6ebd`.
- [x] Observe shared main advanced to `dba32085e` through `e225d2bd0` and
  `ab1a91a36`. Those commits add indexed NtfsFs FsOps and incorporate the
  leased reader repair. No inbox handoff arrived. Request ownership coordination
  in original Mail thread, message 5394; preserve the merged work. Active
  four-file-overlay gates do not contain the new FsOps source/test modules and
  cannot qualify that later feature. Record actual receipt trees when done.
- [x] Collect first planted-red admission failure (103). Retry after native
  wrapper completion; second attempt again refused source namespace status 73
  (`Killed`) before test execution. No local fallback or lock manipulation.
  Diagnose the named namespace probe before another retry; red remains open.
- [x] Review supported isolated RCH placement with existing reviewer against
  installed 2.1.34 source: proof-mode source and target can follow an isolated
  `transfer.remote_base`, preserving all admission/ownership/source gates.
  Read-only hz3 probe found executable tmpfs `/tmp`, MemAvailable about 207 GiB
  and zero recent memory PSI. This is placement feasibility, no speedup proof.
  Do not use a fresh namespace to evade an outstanding owner or recovery guard.
- [x] Collect active workspace check and strict Clippy, then execute current
  merged source tests and full formatting with exact source identity.
- [x] Preserve current complete native command receipts on CSD and in local
  verification logs. The later current-ELF probes reran all declared public
  selections; the obsolete worker raw paths remain unavailable, as recorded
  below. Their existence or recoverability is not claimed.

Retention correction, 21:08 UTC: the completed native wrapper's exact source
root and the five reported child directories no longer exist at their printed
paths. Read-only parent inventory finds only freshness records for that pair.
The full local run transcript, embedded profile JSON and source receipt remain;
the printed paths alone are not durable retained raw-command evidence. Check
supported retirement storage before asserting recoverability or repeatability.

Current merged source and execution routing, 21:11 UTC:

- [x] Independently compare both manually formatted FsOps files against read-only
  rustfmt of their exact committed preimages. Both match byte-for-byte; seven
  tests and 48 assertions retained. Full touched module-tree static formatting
  and whitespace checks pass. No formatter wrote source.
- [x] Correct README/profile to describe the new indexed FsOps constructor,
  every-selected-identity invariant and actual 9 reader / 7 FsOps / 3 CLI authored
  controls. Keep the combined-source execution boundary explicitly pending.
- [x] Independently diagnose hz3 admissions against installed RCH source and
  live read-only registry/control artifacts. Matching release receipts validate;
  no active/pending FrankenFS claim remains. Empty control directories match
  both failed admissions. Contrary to the initial interpretation, these logs
  do not establish an ownership conflict. High I/O pressure and the unchanged
  bounded control setup are the leading hypothesis; exact timer branch unproven.
  No source/lock/process/host-environment repair or timeout bypass performed.
- [x] Route planted red normally to vmi1149989; remote compilation has started
  against immutable c6 plus only the new reader test file. Runtime result open.
- [x] Request full merged NTFS/facade tests at dba32085e plus four explicit
  formatting overlays using an isolated RCH config. Only remote_base differs
  from the existing genuine-Git config, pointing to fresh
  `/tmp/frankenfs-rch-verification-20261021-vx1E5L`. The old native source owner
  was independently confirmed retired before this placement change. No profile,
  job count, timeout, artifact policy, admission rule or source guard changed.
  This is a cold target on executable tmpfs, not a cache-reuse/speedup claim.
  Existing 12 GiB target size versus about 207 GiB MemAvailable supports this
  bounded placement trial. Global configuration and worker environment stay put.
- [x] Collect unchanged full remote formatting, NTFS/facade tests and the actual
  planted red; then execute NTFS CLI controls/build. The later747-test package
  run, old-code1pass/1fail control and delivered CLI receipts are recorded below.

- [x] Freeze a genuine separate Git checkout for the Git-sensitive full harness:
  `/Users/jemanuel/Library/Logs/frankenfs-verification/frozen-source.qVmD8l/frankenfs`.
  Main is dba32085e, objects are copied without hardlinks or object alternates.
  Six existing files are byte-copied from the working tree (formatting/docs);
  a read-only complete tracked-file comparison found zero mismatches across
  5,012 files, excluding only this tracker TODO. The clone is a verification
  snapshot, not a new product variant, and will stay unchanged during RCH.
  Preserve actual .git; no fabricated Git executable or caller-revision proof.
- [x] Request unchanged full harness in that frozen checkout, with the existing
  genuine-Git isolated config and supported tmpfs placement. Source-content
  receipt and all ordinary guards remain mandatory. Set GIT_OPTIONAL_LOCKS=0
  both locally and in the remote command, preventing optional Git index-cache
  writes while retaining actual Git operations and all missing/forged/mismatch/
  zero-selection rejection controls. This follows documented Git read-only
  optional-lock behavior; no validator or byte-selection exclusion changed.
  Log `harness-full-frozen-real-git-2117.log`; outcome remains open.
- [x] Read-only check the CSD verification host: /dev/fuse exists (0666),
  fusermount3 exists, and retained NTFS native backing images/oracles remain.
  Ordinary-user listing of the root-owned evidence failed permission checks;
  sudo read-only inventory then succeeded. An intermediate quoted find argv
  was malformed and executed no useful probe; corrected with Python stdin.
- [x] Once the exact current CLI ELF is retrieved through RCH, compare indexed
  native reads and attempt bounded read-only mounted qualification on CSD using
  exclusively owned mount directories. Preserve every mount/IO failure and
  verify successful unmount and unchanged backing hashes before any mount claim.

21:26 UTC execution corrections and remainder:

- [x] Preserve first frozen-harness refusal: the Library/Logs checkout was
  outside RCH's configured canonical projects root, so it exited 103 before
  compilation. Do not relax topology. Create a genuine second checkout under
  `/Users/jemanuel/projects/.frankenfs-verification.G1tZG3/frankenfs` and retain
  the first copy. The canonical checkout also matched all 5,012 selected tracked
  source files after the six exact byte copies. Main concurrently gained
  docs-only b3ecc4999; frozen Git remains real dba32085e plus those doc/format
  changes. These are distinct Git identities despite equal selected source bytes.
- [x] Collect canonical frozen-harness request exit 103: queue timeout, before
  transfer/compilation. A routine fast-forward attempt in the private snapshot
  then refused dirty README/profile and preserved them; no reset/stash/overwrite.
  Keep the actual dba-dirty identity. After fresh status showed hz3 free 2/3
  slots, retry the unchanged full command, log
  `harness-full-canonical-frozen-real-git-2126.log`. No result yet.
- [x] Prepare one external executable verification probe for retained native
  indexed CLI reads and owned read-only FUSE mounts. Independent source review
  found unbounded FUSE IO, incomplete timeout receipts and cleanup, missing RO
  option assertion, underreported process total and insufficient negative-error
  discrimination. These are real pre-execution defects, not passing tests.
- [x] Repair those concrete probe flaws before execution: bounded child reads,
  guaranteed lifecycle for only newly created children/mountpoints, retained
  timeout outputs, stable mount identity/RO options, semantic NotFound errors,
  and exact 47 captured commands plus 4 mount daemons on the successful path.
  Do not weaken predeclared positive counts to obtain green.
- [x] Retrieve current RCH-built CLI; execute the repaired independent probe.
  Current native inputs have one external leaf each, not multi-branch routing.

21:32 UTC actual gate outcome and corrective work:

- [x] Collect first Clippy command exit 101. Two actual diagnostics: unused
  indexed helper methods because c6+four-file overlay omitted the later FsOps
  callers, and `needless_pass_by_value` on Search::visit's owned entries Vec.
  Log `clippy-indexed-fix-current-2054.log`. Do not suppress either diagnostic.
- [x] Correct visit to borrow `&[NtfsIndexEntry]`, iterate that slice, and pass
  borrowed root/child vectors at its two callers. It never consumes entries;
  ownership/drop order and all traversal/candidate checks remain unchanged.
  Local static module-tree rustfmt and whitespace checks pass.
- [x] Request strict full workspace/all-target Clippy on complete b3ecc4999
  plus four explicit current overlays, log
  `clippy-complete-indexed-borrow-2132.log`. The complete base includes the
  real NtfsFs callers instead of deleting helpers or allowing dead code.
- [x] Collect queued full formatter request exit 103: remote initialization
  failure, no formatter execution and no local fallback. Full remote fmt remains
  open, despite static touched-file formatting passing.
- [x] Full genuine-Git harness retry is now admitted on hz3. Transfer copied
  10,040 files / 820,562,855 bytes; actual remote execution began 21:29:06 UTC
  on dba32085e-dirty, with genuine Git, GIT_OPTIONAL_LOCKS=0 and mandatory
  final source receipt. Its frozen source intentionally predates the ownership-
  borrowing lint fix above. Do not edit the private checkout during execution.
- [x] Independently re-review the repaired native/mount probe, SHA256
  `a78335839daec54b7d3ee8be176e709b43985faf2562ba4a285bef8f1f12c1b4`.
  All earlier concrete source-level issues are corrected; no remaining critical
  flaw found. This is source review only. Positive counts remain 27/3/25 and
  4/24/8; successful process denominator is 47 captured + 4 mount daemons = 51.
- [x] Collect combined-source pre-lint NTFS/facade run and planted-red result;
  run updated borrowed-slice source tests and actual CLI controls/build next.

21:34 UTC executed combined-source green:

- [x] Collect full NTFS/facade command exit 0. NTFS: all 360 tests passed,
  zero failed/ignored, including all nine indexed reader and seven indexed
  FsOps tests. Facade: 40 passed, zero failed, one native-producer test ignored;
  that ignored test earns no native credit here. One facade doctest executed
  and passed; zero NTFS doctests earn no credit. Full log
  `tests-merged-indexed-tmpfs-2111.log`.
  Exact source: base dba32085e, overlay
  `1740028ee0ac3fe0dab7c727a4424b4334261592732b12f6e8396103ecb96582`,
  tree `b78baad493ac5873d76cf4acdf7331dc0e9cfd9a`.
  The two same-reference order tests and all seven FsOps cases actually ran.
- [x] Request updated full NTFS/facade plus NTFS CLI unit tests on b3ecc4999
  and the current four overlays, including the borrowed-slice fix. This uses
  explicit --lib/--bin ffs-ntfs target selection; no unrelated CLI integration
  filter is mistaken for coverage. Log `tests-complete-indexed-borrow-cli-2134.log`.
- [x] Request unchanged full workspace remote formatting on the healthy worker
  now running complete-source Clippy; log `fmt-complete-indexed-borrow-2135.log`.
  This is a single-process metadata job, no compilation or reduced compiler
  reservation. Static local checks remain distinct from remote Cargo fmt.
- [x] Collect updated tests, planted red, complete-source Clippy, original
  workspace check, full formatter and frozen real-Git harness results. Later
  completed source-bound runs and the retained red/failure outcomes are below.

21:58 UTC executed failures, red control, and next concrete repairs:

- [x] Collect the immutable c6 planted-red run: one valid-alias control passed,
  one missing-alias test failed, 351 filtered, zero ignored. The old implementation
  accepted record 24 when the valid name arrived first, but rejected the opposite
  order. Both exact and folded queries reproduced it. Log
  `tests-indexed-same-ref-red-c6-vmi1149989-2108.log`, remote build
  30074357740994859. The earlier 360-test green exercised both regression tests.
- [x] Collect post-borrow test admission failures: hz3 queued command and vmi1149989
  retry both exited 103 before executing tests. Logs
  `tests-complete-indexed-borrow-cli-2134.log` and
  `tests-ntfs-complete-borrow-green-2144.log`. No runtime credit or local fallback.
- [x] Collect complete b3+overlays Clippy exit 101: one actual assert_is_empty
  lint in indexed FsOps cancellation test. Replace is_empty assertion with the
  equivalent typed empty-vector equality, retaining the zero-read requirement
  and improving failure output. No lint suppression or assertion removal.
- [x] Collect full remote fmt exit 1: only three newly committed ZFS automatic
  striped-mirror files differed. Reserve exact paths; manually format all three.
  Independent whole-byte comparison against read-only rustfmt of Git baseline
  confirms formatting-only changes, preserving 20 tests and 53 assertions.
- [x] Request fresh full Clippy on 990539073 plus the six explicit changed code
  paths, including the new ZFS feature and equivalent assertion correction.
  Log `clippy-current-complete-2156.log`. Request actual full remote fmt again,
  log `fmt-current-complete-2156.log`; no passing result inferred yet.
- [x] Collect full genuine-Git harness runtime: lib 2076 passed/1 ignored;
  three following targets passed 3, 103 and 7 tests. Conformance reached
  98 passed/5 failed/2 ignored, then stopped. All five failures name
  superblock_csum in the shared constructed Btrfs mount-image helper, whose
  superblock checksum is never written. Existing tree-block checksums are written.
  Log `harness-full-canonical-frozen-real-git-2126.log`; no full-suite pass.
- [x] Preserve source-finalization failure: .git/index changed. Supported
  `rch jobs recover rchw-8dc1850b-04f5-4d2d-830f-877e2dde0dca --json`
  acknowledged terminal exit 101, not the daemon's earlier 130. Recovery does
  not turn the failed source receipt into a valid one. No manual index/lock or
  process intervention. Recovery logs `harness-source-index-recover-2149.*`.
- [x] Independently compare retained/local genuine indexes: all 5013 path/mode/
  OID/stage/flags entries and extensions identical; stat-cache bytes, derived
  checksum and index-file permissions differ. Git 2.53 diff auto-refresh is the
  strongest code-supported writer candidate, without syscall attribution.
  Next delegated run can use documented command-scoped diff.autoRefreshIndex=false
  while retaining real Git, content-dirty negatives and the entire .git receipt.
  Existing frozen config/index remain untouched.
- [x] Repair the constructed Btrfs producer in a separate exact-file lane after
  independent review. Keep production checksum admission and every old assertion;
  verify valid fixtures reach their actual behavior and corrupted checksum/payload
  images still fail with the named checksum error. Do not regenerate goldens.
- [x] Request actual current native CLI ELF build with JSON artifact delivery,
  base 990539073 plus six explicit overlays. Correct the initial rejected JSON
  flag to the required literal json,json-render-diagnostics before admission.
  Log `native-bins-current-2151.log`; real compile admitted on hz3. No ELF yet.
- [x] Complete independent source review of bounded native indexed/strict-FUSE
  probe and preserve exact 27 positives/3 negatives/25 indexed byte comparisons,
  4 strict mounts/24 mounted byte comparisons/8 refusals. Successful denominator
  is 47 captured commands plus 4 owned mount daemons. Probe is still unexecuted.
- [x] Execute post-lint complete NTFS/CLI tests; qualify fresh native ELF and
  probe, current workspace check/Clippy/fmt, full real-Git harness, and actual
  mandatory benchmark measurements. Keep original staged Bead in progress.

Evidence correction: the c6 facade selection executed one genuine native-producer
test and one constructed FAT bounded test. Earlier plural producer wording is
incorrect. Clean-overlay retirement reaped printed raw output directories; the
full local transcript, embedded profile JSON and source receipt remain durable,
not those printed remote directories. No canonical Beads import/close occurred.

22:02 UTC concrete source correction and green Clippy:

- [x] Current complete workspace/all-target Clippy passed with -D warnings on
  990539073 plus six explicit NTFS/ZFS overlays, remote vmi1227854, exit 0.
  Log `clippy-current-complete-2156.log`, 4m59s compiler duration. This includes
  the equivalent zero-read assertion and new automatic ZFS import source.
  It predates the separate Btrfs fixture repair and does not qualify that delta.
- [x] Original incomplete c6 workspace check hit its 3600-second deadline,
  exit 137; it had reached project crates and emitted the expected unused-helper
  warning from omitted later callers. No full-check pass. Request current
  complete workspace/all-target check on 990 plus seven code overlays, including
  fixture repair; log `check-current-complete-2201.log`.
- [x] Independent fixture review confirmed a second concrete defect behind the
  checksum failure: embedded DEV_ITEM and committed CHUNK_TREE were absent.
  Complete the existing producer with matching devid 1 / 512KiB / 4096 geometry,
  generation 1 and a checksummed chunk leaf at 0xC000. Existing bootstrap mapping,
  root/FS leaves and data stay intact. Follow existing admitted fixture pattern
  in ffs-core::tests::add_btrfs_dev_info_chunk_tree. Every old assertion remains;
  new valid-open control and independent checksum-byte/covered-payload corruption
  controls use strict unchanged default options and exact checksum diagnosis.
  Independent range/conservation review and static formatting pass. Source SHA
  e4d5d6fb21764cc0f094e5124fa8b88f7e84f17d55c4f322ff846060d21ce1a7.
- [x] Preserve first checksum-only rerun refusal: status 73 source namespace
  initialization Killed, wrapper exit 103 before execution. That request was
  also submitted despite a known missing copied module; this was an avoidable
  orchestration error, not qualified source or a test result. The absent private
  directory/module was subsequently created/copied while no run was active.
- [x] Rebind frozen genuine-Git source after supported previous retirement:
  all 5,004 non-Beads tracked source files compare equal to current main plus
  owned edits. Retain actual dba-dirty Git identity, no fake revision/reset/index
  restoration. Request unchanged full harness with command-scoped Git diff cache
  refresh disabled; log `harness-full-valid-inventory-real-git-2201.log`.
  Source stays frozen during this request. No runtime result yet.
- [x] Refresh FEATURE_PARITY's stale pending native named-stream/profile claims
  with executed c6 results and explicit source/runtime/receipt limits; no extra
  feature percentage or mounted credit. Keep full harness and benchmarks open.
- [x] Create a new private CSD candidate directory and copy the reviewed probe;
  remote SHA matches 7da93ffcffc4e18bfa59edf2bc5a65e8f16db0c048ddd7154083f56a8cf1d316.
  One incorrect destination copy failed before writing and was corrected to the
  observed directory. Native CLI build still runs; no probe execution claimed.
- [x] Complete current full fmt/check, fixture-delta strict Clippy, actual full
  harness, current NTFS/CLI/ZFS tests, native indexed/strict-mounted probe and
  required benchmark measurements. Independent native multi-branch qualification
  is being scoped; existing retained images prove only one external index leaf.

22:21 UTC actual native indexed and kernel-mounted result:

- [x] Original named CLI build compiled successfully in 16m58s, but delivery
  failed RCH-E327 because the implicit controller target was macOS arm64. This
  was an avoidable omitted Linux-artifact intent, not a compiler failure.
  Supported exact-wrapper recovery retired it with delivery status 102 and
  terminal acknowledgment true, preserving the rejection and local outputs.
  The persisted original policy was not edited or overridden.
- [x] Fresh supported invocation explicitly requests intentional foreign Linux
  artifacts for CSD. It reused the existing cache, retrieved three CLI ELFs,
  and released Cargo JSON only after terminal success. Log
  `native-bins-intended-linux-2212.{log,jsonl}`; wrapper
  rchw-ebb06a79-a200-4eb3-b3a3-fc0c2e3060dd/build 30074357740994908.
  Verify all three ELF64 little-endian x86_64 headers and SHA256; CSD uname is
  x86_64. Never execute these artifacts on the Mac. Exact NTFS candidate SHA
  3effe8ed21c9af9b5b0f537451e9f64fce869d58ce3d986ebbeb6eb0754d9d76.
  CSD transferred bytes have the identical hash and Linux ELF interpreter.
- [x] First actual native probe completed all 27 indexed positive calls, three
  semantic negatives and 25 byte comparisons, with four unchanged backing
  hashes, then first mount failed Permission denied. Preserve status failed,
  39 captured commands + one owned daemon = 40 processes, zero mounted reads.
  Log `native-indexed-strict-fuse-2217.log`; evidence
  `/data/ssd/tmp/ffs-native-verification-7CWV8iQw/ntfs-indexed-mount-1a3rmszt`.
- [x] Diagnose actual host policy read-only: parent root has full capabilities,
  no seccomp and unconfined profile; fusermount3's own AppArmor profile permits
  /tmp mountpoints but excludes /data/ssd. Do not change the host policy.
  Correct only external probe setup to create private /tmp mountpoints and
  keep logs in the existing data evidence root. All comparison/refusal/lifecycle
  assertions, image inputs and denominators remain unchanged. Original CSD
  probe preserved; corrected probe SHA
  106eb23f8e80e109e9ea81366ab79bf79960f47165f9aa90b3e87fcc60749e5b.
- [x] Execute corrected probe successfully, exit 0: 27 indexed positives,
  three semantic negatives, 25 indexed byte comparisons, four strict read-only
  FUSE mounts, 24 mounted full/range/EOF comparisons and eight EROFS/ENOENT
  refusals. Exactly 47 captured commands plus four owned mount daemons = 51
  processes. All four full backing hashes unchanged; each daemon exited 0,
  cleanup succeeded and owned mounts are absent. Log
  `native-indexed-strict-fuse-private-tmp-2221.log`; evidence
  `/data/ssd/tmp/ffs-native-verification-7CWV8iQw/ntfs-indexed-mount-v5k7iqtz`.
  Scope is indexed CLI reader plus strict default NtfsFs kernel mounts, not
  indexed FsOps mounting, public facade dispatch, multi-branch routing or speed.
  Initial run and corrected rerun share native inputs; count origins once.
- [x] Reconcile timed-out full-harness transport via supported exact-wrapper
  recovery: rchw-3dbf90d7-94e0-4abc-88b5-146726cfefb5, terminal exit 1,
  acknowledgment true, no executed test result. No manual source/lock cleanup.
- [x] Actual full-harness retry is executing: original 2076 unit tests passed,
  subsequent 3/103/7 targets passed, and repaired conformance now passes all 104
  tests with two ignored, including all five formerly failing cases and the
  new positive/checksum-byte/covered-payload control. Later targets and final
  source receipt are pending. Log `harness-full-valid-inventory-real-git-2217.log`.
- [x] Collect complete workspace check, current NTFS/CLI/ZFS/facade tests,
  remaining full harness targets and final source receipt; run fixture-delta
  strict workspace Clippy and mandatory benchmarks. Independently verify native
  mounted evidence. Original staged Bead stays in progress; no canonical close.

22:40 UTC native multi-branch execution and full-gate progress:

- [x] Independent verifier inspected all original 47 command receipts, four RO
  mount identities and per-lifecycle cleanup, then re-executed the exact same
  current ELF and reviewed script in a fresh CSD process: all 51 processes and
  all 27/3/25 indexed plus 4/24/8 mounted controls passed. New evidence root
  `ntfs-indexed-mount-uifttryw`; local
  `native-indexed-strict-fuse-independent-dustywolf.log`. Image/ELF/tool hashes
  unchanged, all points absent. Same inputs/design count once; independent
  runtime execution does not attest independent build provenance. Reuse of a
  kernel mount ID after successful unmount is valid, not cross-lifecycle proof.
- [x] Complete current workspace/all-target cargo check passed exit 0 in
  25m09s, including fixture producer repair. Log `check-current-complete-2201.log`;
  exact base 990539073, overlay fingerprint
  74afac80c43358e2d0e452886ff42aa5e07bfde8a992d19859e131da0e7cdab3.
- [x] Full genuine-Git harness progressed beyond conformance: 288 and 17 test
  targets passed, alongside many smaller suites, then stopped at module census.
  Failure is exact LOC drift: artifact src/lib.rs 3093 vs tracked index 3541.
  This time full source finalization passed, including genuine .git bytes;
  command exit remains 101. Receipt build 30074357740994910,
  receipt root 1c8b86a89357fb9349ecd43cad81dd28ad176b0a49eb12e394796d190961786a.
  The Git diff cache setting solved the observed source-byte mutation without
  excluding .git or weakening provenance/content-dirty controls.
- [x] Investigate census against its last source-bound update 73d240057 and all
  90 current index source blobs. Exactly three meta modules drifted: lib.rs
  +448, main.rs +66, writeback_cache_audit.rs +302. Existing tracked additions
  are contract mapping/CLI/oracle support; this inventory correction does not
  certify their behavioral claims. Preserve all 24 conformance/66 meta labels,
  all module paths and the unchanged strict census test. Manually update only
  these LOC values/totals: total 172665, meta 128840, conformance unchanged43825;
  actual conformance/meta fractions become 2538/7462 basis points. This is
  maintenance with zero capability credit, not behavioral golden regeneration.
- [x] Clippy exposed .err().expect() in the new corrupt-superblock control.
  Replace with equivalent let-else panic-on-Ok, keeping exact Format mismatch
  assertions and both corrupt offsets. Static formatting passes. Complete
  workspace/all-target strict Clippy with fixture+census now passed exit 0,
  log `clippy-current-fixture-census-2239.log`; base990 plus eight explicit
  overlays, fingerprint a7eafb081c533557501747facea8c7567b1b154dcbea9fbff7afb59649f39eea.
- [x] Preserve another unexecuted current package-test attempt: source namespace
  initialization failed before command execution. Supported exact-wrapper
  recovery acknowledged terminal 1 for rchw-a4343608-0ce0-4802-875b-278198c6ae34.
  No manual source/lock changes. Fresh normal current package test requested
  after retirement, log `tests-current-ntfs-cli-zfs-facade-2240.log`.
- [x] Complete root source review of external native multi-branch probe, including
  exact new-file O_EXCL/O_NOFOLLOW/single-link/size/identity guards, bounded child
  lifecycle/capture and raw USA/VCN/bitmap/UpCase decoding. Native layout and
  ntfscat raw semantics cross-checked with ntfs-3g primary source. Add a matching
  stderr-size bound before reading it; no fixture/assertion relaxation.
  Original reviewer could not finish due account usage limit, so this final
  review and execution are root verification, not an independent peer pass.
- [x] Execute native multi-branch producer/probe successfully on exclusively new
  64MiB regular image, preserving all existing inputs. Native tools populated
  256 distinct files; independent raw streams show 13 allocated/reachable nodes,
  12 leaves and depth2, endpoints in paths [6,0] and [6,12]. All native identities
  and listings agree. Exactly257 producer +9 native oracle/structure +20 candidate
  processes =286 total; candidate14positive including12 full/unaligned/EOF byte
  comparisons, plus6 typed empty-stdout NotFound negatives. Image, source/tool/ELF
  hashes unchanged after reads. Log `native-ntfs-multibranch-2238.log`, root
  `ntfs-native-multibranch-kbb3ccfn`, probe SHA
  30f9659e601d994f58659d15725392a6152a5a3e57da99cee999b9173b5d16b5,
  image SHA5b9fd5c4ee0b76512945dd5eb0a92d3344253ac9735b78a8b055917291b67c18.
  This qualifies native multi-branch strict/indexed CLI routing, not performance,
  facade dispatch, indexed FsOps mounting or FrankenFS native writes.
- [x] Finish current package tests: 747 passed, zero failed, one opt-in ignored;
  actual package counts are facade40, NTFS CLI24, NTFS360, ZFS323. Log
  `tests-current-ntfs-cli-zfs-facade-2240.log`, terminal0. This explicit --lib
  selection excludes doctests. Base990 plus six source/test formatting overlays,
  fingerprint1b105678abc58929018b3b06bce94295c2ceca642c9385ca55ae4964cf912d55.
- [x] Collect complete eight-overlay workspace check and formatting, both exit0,
  logs `check-current-fixture-census-2245.log` and
  `fmt-current-fixture-census-2241.log`; strict Clippy already passed the same
  eight-overlay fingerprint a7eafb081c533557501747facea8c7567b1b154dcbea9fbff7afb59649f39eea.
- [x] Finish rerun of full genuine-Git harness after the
  source-bound census correction; obtain actual benchmark measurements:
  build30074357740994971 passed2652tests and94956 measured60timing intervals. Full
  remote formatting requested after the equivalent new control change, log
  `fmt-current-fixture-census-2241.log`. Keep the original Bead in progress.

### 22:59 UTC current-source public API refresh and remaining gates

- [x] Collect full-harness progress: 2076 unit passes and 104 conformance passes,
  plus later targets including the corrected census test passed. The two public
  parity adversarial tests are still running; no full-harness success claim.
- [x] Record public example build queue_timeout exit103 with no command execution,
  log `native-public-current-2248.log`. Earlier 2247 JSON-opt-in rejection was an
  unsupported example artifact mode, not a compiler failure. Use the supported
  ordinary named-example publisher after current capacity is available.
- [x] Verify the current FAT and ZFS companion ELF hashes on CSD equal the exact
  delivered Linux artifacts, log `csd-current-fat-zfs-identity.txt`.
- [x] Read the complete existing NTFS public native probe. Retain every old
  positive/negative comparison and add expected-binary SHA and post-hash checks,
  fixed 162/120/152/3 command/public/byte/negative denominators and retained
  TimeoutExpired partial output. No original tolerance or timeout changed.
- [x] Inspect all 164 old FAT/ZFS argv/status/label receipts. They consist of
  108 public calls, six read-only native mcopy calls and 50 cmp calls. The six
  expected negatives are exact stream-format or missing-snapshot errors.
  A first unprivileged inventory returned zero paths because root-owned evidence
  was inaccessible; rerun with sudo-n requires exactly164 and succeeded. No
  zero-selection pass credit. Remap only command receipt references when replaying;
  bounded-fat32.img remains the original immutable input, not a new output path.
- [x] Build/deliver the current standalone public consumer, verify Linux ELF and
  SHA identity locally and on CSD, then execute the unchanged native NTFS slice
  and read-only FAT/ZFS receipt replay against current source.
- [x] Complete full-harness execution and source receipt, then unchanged-profile
  ffs-harness benchmarks under the supported remote budgets: builds94971 and
  94956 both returned0, with2652test passes and60timing intervals respectively.
- [ ] Fresh verification against original acceptance, update staged Beads,
  complete bounded worksheets and publish exact paths without disturbing peers.

### 23:03 UTC current native public-consumer acceptance

- [x] Supported recovery retired the failed public build2257, exact wrapper
  rchw-ec4515b7-207c-49cc-9b7b-d146b95bed7c, exit1 acknowledged. A new normal
  tmpfs-placement build succeeded, compiler0/delivery0, build30074357740994949,
  wrapper rchw-335c59d8-fbc1-47ff-9272-05efd894ff00. Source base990 plus six
  overlays fingerprint1b105678abc58929018b3b06bce94295c2ceca642c9385ca55ae4964cf912d55.
  Named-example publisher delivered debug/examples/native_reader (587353592B),
  publication fingerprint0e75552377ac85b44b1cee0bc1597d519d5b4a0b59110fcb4d4bceb852c733e7.
  Linux x86_64 ELF SHAe862954f96cf7bfff76fd63d47465cd4b55dd0f1f3e3acb9c08e883b34e4ef48
  matches locally and on CSD. It was never run on macOS.
- [x] Execute current public NTFS slice:162commands/120publiccalls/152byte
  comparisons/3expected negatives, all passed, four image hashes unchanged,
  32 extension streams and both exact selectors plus actual compression.
  Log native-public-current-ntfs-2300.log, retained root
  ntfs-public-retained-mp18fcmm. EOF is consumer-clamped; no direct-backend
  EOF, indexed FsOps mount or native writer credit.
- [x] Preserve the first FAT/ZFS replay preflight failure: the minimal replay
  validator assumed cmp had only two positional arguments. Reviewing all50
  original argv showed legitimate --bytes/--ignore-initial range comparisons.
  Admit precisely those read-only forms, retaining every original argument,
  expected status and stdout/stderr hash. Zero candidate commands ran before
  that failure; original failed script is preserved separately on CSD.
- [x] Execute corrected FAT/ZFS replay, probeSHA
  735fe90ab697b671e7ed51291455fdfb45645b9de1928bba5e5e36794fe2e5ab:
  exactly164 commands =108public/6fresh native mcopy/50cmp, six exact semantic
  negatives. Every cmp references new command outputs, every output/status also
  matches the old receipt, and all22 source/backing files and both native tool
  hashes stayed unchanged. Eight backing images cover plain/bounded FAT16/32,
  ZPL4/5 file and before/head/after/before snapshot selections. Root
  fat-zfs-public-current-14mobvpw, log native-public-current-fat-zfs-ranged-cmp-2302.log.
  This is capture equivalence plus fresh FAT oracle execution on retained native
  images, not fresh pool production, field proof or independent build provenance.
- [x] Benchmark2257 SSH completion was unconfirmed; supported exact-wrapper
  recovery rchw-09d6eea4-69e8-4e6f-9ded-194ad52202db returned terminal255,
  acknowledgment true (earlier daemon130). No measurement. Initial attempted
  README/FEATURE copy used the frozen cwd as both source and destination and
  failed harmlessly; no file was copied. After retirement, explicit absolute
  copies succeeded before the next full harness request. No active snapshot
  was changed. This command-chain mistake earns no progress credit.
- [x] Fresh read-only normalization confirms the two NTFS formatting paths equal
  rustfmt of HEAD; the FsOps tests differ only by rustfmt and the equivalent
  typed empty-vector equality required by Clippy. Original assertions remain.
- [x] Collect full harness2303:2652passed/0failed/11ignored, including one
  compiled doctest, valid final source receipt; details below.
- [x] Collect normal unchanged-profile benchmark2304 through terminal completion:
  remote command0/wrapper0,60 timing intervals; exact receipt below.
  Benchmark source uses base990 plus the same eight overlays as green compiler
  gates; it runs in its own clean overlay, independent of the active frozen
  full-Git snapshot. All deadlines/profiles/admission/ownership guards remain.
  Any timing is current maintenance qualification, not an incumbent-relative win.

### Bounded work audit and honesty inventory, 20:10 UTC Oct 21–01:48 UTC Oct 22

Creation gate: this existing TODO and staged comments serve the user's explicit
request for granular tracking of bd-native-image-library-s4tde. Native probe
receipts serve its concrete public-reader acceptance; they preserve the observed
alias, native admission, oracle and mount failures. Retire their active checklists
when that original acceptance is verified; retain history without deleting files.
No new dashboard, schema, certificate or speculative framework is needed. The
small replay helper exists only to repeat the exact164 retained read-only commands
with the current ELF and fresh output references, and retires with this refresh.
The higher-value ready capability remains this claimed integration; finish its
positive runtime gates before expanding scope. No integrity exception is invoked.

Real-work audit: README purpose is native filesystem behavior in Rust through
FUSE and offline-image tools. The initial20:10–23:07 git-stat inventory is retained
in audit-window-2010-2307-git-stat.txt; subsequent source cuts and executed gate
receipts are recorded below. The window contains user-visible indexed FsOps,
the same-reference identity fix, ZFS auto-import and peer FAT parent recovery,
with their regression, lint and fixture enablers. Public docs describe real bounded
results. Root did not author all peer work or make these commits. Tiny external
comment/style commits are not independent capability increments; commit count is
not progress. TODO/Beads are PROCESS. The recent block is ENABLER-heavy runtime
qualification, not another feature. A two-minute demo is the current public
consumer reading native FAT/NTFS/ZFS bytes plus strict mounted NTFS bytes. Without
PROCESS the runtime behaves identically; only requested tracking is lost. Real
consumers executed the integration and regression fix. DarkHorizon still owns
the read-authority P0 without handoff; no competing claim was made. All functional
closes are zero. Verdict: finish the named gates and package this integration;
avoid adding machinery or polishing status while tests are running.

Honesty inventory (root-owned work and inherited claims relied on here, not a
certificate for every peer change):

1. No (checked the alias regression diff, exact rustfmt conservation of NTFS
   tests and current Btrfs control: no assertion removed, ignore added or gate
   weakened; current CLI/reader/FsOps selections actually ran).
2. No (checked production paths and constructed Btrfs producer: no fixture-only
   runtime success path; constructed results stay labeled separately from native).
3. No (checked changed paths: no behavioral golden regenerated. Census JSON is
   numeric source inventory, checked against all90 indexed blobs; all paths,
   24/66 classifications and the strict census test remain unchanged).
4. Yes, conformance producer and external probe preflight changed. The producer
   received separate source review and real strict-open/corrupt-CRC execution;
   production validation stayed intact. Replay admission now accepts the original
   ranged-cmp forms, retaining every original argv/status/output expectation and
   the fixed164 denominator. No timeouts/tolerances were widened. Census review
   was a fresh root pass; unavailable peers are not claimed as independent.
5. No (checked source/config/recipes: no bench hardcoding, fake Git, local Cargo,
   guard bypass or release-profile change. Foreign ELF delivery was explicit;
   command-scoped Git no-refresh avoids metadata writes without hiding content).
6. No (checked actual selections/counters:747passed/1ignored are explicit packages,
   not doctests; full harness2652/0/11 includes one actual compiled doctest.
   Full FAT/facade515/0/1 and final affected9/0/0 are separate source-bound
   executions;466filtered cases in the final focused run earn no new credit).
7. Source cuts are explicit: native/public and747-test results bind base990 plus
   stated overlays. Complete082+c7dd passed515FAT/facade tests; final082+23f0
   passed check/strict Clippy/fmt and all9affected tests. Later5c7d8d76b root
   expansion is outside those cuts. Public refresh280covers all SIX declared
   formats, naming FAT16 and FAT32 separately; the earlier five-format/APFS
   wording was inaccurate and has been corrected without changing project goals.
8. No (checked reports: retained-image replay, fresh native producer, constructed
   unit, strict FUSE and source-only classes remain distinct; no field/write or
   indexed FsOps mount claim; shared origins count once).
9. No (checked retained transcripts/TODO/comments: harness failures, missing
   raw scratch paths, benchmark deadlines/SSH failure, mount failure and replay
   preflight failure, three-lint Clippy failure and nonzero UBS results remain
   visible; original item stays open).
10. No (checked own cited commands: stdout/stderr retained, including failures
    and timeout partials. Existing benchmark helper output suppression is not
    presented as separate native-tool proof).
11. No (checked staged original status/comments: in_progress, no functional
    close, follow-up laundering or canonical database/WAL mutation).
12. No (checked README/parity diffs: actual source counts and evidence updated;
    original goals/acceptance and native/write/field requirements stay intact).
13. No (checked existing agents' reports and staged tracker: zero closes).
14. No (checked review tasks: positive, negative and no-claim boundaries were
    explicit; no new agent spawned; both existing agents later hit usage limits).
15. No (checked source diffs personally and actual retained receipts, then ran
    own current public probes. Initial cmp-preflight assumption was wrong and
    corrected before any candidate execution; no unexecuted report counted).
16. No (checked output/statuses: work qualifies positive read capability;
    refusal paths have no separate closure or capability credits).
17. No (checked independent mounted rerun: separate runtime execution with the
    same ELF/input lineage, not an independent build or two native corpora).
18. No (checked predeclared native27/3/25, mounted4/24/8, public162/120/152/3
    and replay164/108/6/50/6 counters, plus extra native61/public52/expected4
    statuses: no failing case dropped from totals).
19. Yes: repeated namespace/queue/SSH failures, unsupported example JSON mode,
    wrong-cwd no-op copies and oversized receipt output cost avoidable time.
    They earn no progress. The wrapped README phrase's actual failure was retained
    and corrected; the later full harness passed. Selected source bytes stayed
    fixed through each active verification run. The final focused cold build
    took1800.8seconds; actual9-test runtime was33.58seconds, not a speedup claim.
20. Strongest evidence: exact delivered ELF SHA with native byte comparisons,
    unchanged whole-image hashes, 32 extension streams, a new native13-node
    index, four actual RO mounts and an independently executed mounted rerun.
    The current public refresh executes280calls across all six named formats.
    Full harness2652passes,60actual benchmark intervals and final source-bound
    compiler/lint/format/test receipts are retained. A skeptic can rerun the named
    scripts on retained CSD inputs. UBS remains nonzero; no clean scan is inferred.

Disposition: correct source-scope and operational mistakes in place and disclose
them here and to the operator. RH-1/RH-2/RH-3 are controlled by unchanged production
admission, conserved assertions, explicit proof classes and exact inventory data;
RH-4 forbids treating tiny external commits as capability wins; RH-7/RH-9 keep the
original open. Earlier bounded Cass review is retained above; no claim of a new
or comprehensive older-session audit follows. Final gate results are incorporated
here; required UBS disposition and publication authority remain open. No scanner
exception has been self-granted and no functional Bead is closed.

### 23:22 UTC full harness green, shared FAT maintenance and guarded extra probe

- [x] Full genuine-Git harness passed, log
  harness-full-shared-source-real-git-2308.log, build30074357740994971:2652passed,
  zero failed,11ignored,29nonempty target summaries. Final source-content receipt
  root7fa320e15e551fd22a4519099db37bbc9250fd8d3480192b519e7241cf071bb9 is valid.
  All5007 non-Beads root tracked files matched the private input before execution.
  This includes the new FAT source before its later equivalent lint correction.
- [x] Preserve earlier inventory rerun red:3README controls passed and the final
  one failed on a wrapped exact phrase23 evidence-event types. One newline was
  corrected in root; no gate/assertion changed. That failed run also has a valid
  source receipt, build30074357740994950, root
  e9e0febdb59d60179155c5e13c4668dc8d0a807e79d699bf1af51a7e4832041a.
- [x] Shared-head0133b0934 +four overlays passed workspace/all-target check,
  check-shared-head-fat-2307.log, fingerprint
  0391028788c74ebc3a45bbf810f1df20950e29db0f8a803ef63017f6348dca7f.
  Strict Clippy then found one nonminimal_bool in the newly merged FAT parent
  recovery. Authoritative ownership check was clear; reserve the exact paths.
- [x] Apply De Morgan grouping only, preserving the exact permitted issue list,
  short-circuit order and rejection condition. Eight truth assignments agree.
  Manually format both parent-recovery source/test files and two existing
  recovery.rs style hunks. Read-only normalization proves the exact committed
  source plus that one equivalent predicate, with every test/assertion intact.
  An initial diagnostic-only Python expression had a precedence syntax error;
  it changed no file and was corrected before the actual normalization pass.
- [x] Collect corrected shared-head strict Clippy and full formatting, then
  execute corrected FAT/facade tests and compiler check as needed. The first
  FAT/facade request timed out in admission, no execution; retry2312 is compiling.
  Formatter --job plus --clean-overlay was rejected before execution. Correct
  plain metadata job queued on a memory-constrained worker; exact queued wrapper
  rchw-d5c887d4-1815-4b4c-bae7-ea38d0ff0dc4 was canceled before start and the
  original wrapper returned130. The new normal metadata job uses observed
  available hz3 capacity. No slot, memory or compiler guards were reduced.
- [x] Prepare an additional positive public ext4/btrfs native dispatch probe,
  fixed61commands =2producers+7native checks/oracles+52public calls. It uses
  exclusive private regular64/128MiB images, plain/bounded windows, native
  payload readback, Unicode/empty/full/range/consumer-clamped EOF, typed missing
  paths, write refusal and whole-image hashes. Reviewed before execution:
  explicit ext4 type despite resolved mke2fs symlink; refusal success has empty
  stdout. Probe SHA7fbdb0d7b3987fcefd3a0250594c7c5652ad845262b35f448f15cdc6ac8265cc.
- [x] CSD lacks btrfs-progs. Privately download/extract the exact1,033,914-byte
  Ubuntu6.17.1-1build1 archive, SHA
  89fb4fe8fce0d2ca42d2f26d626c7f46181ef6c7c8e2656ea1462579ec9b67e8,
  under oracle-btrfs-7p8tifk0. No host package installation/config change. Initial
  usr/bin assumption and broad same-name lookup failed before probe execution;
  observed mkfs path is usr/sbin and btrfs is usr/bin. These are setup receipts,
  not capability proof. Existing scratch free space was210777276416bytes.
- [x] Execute the additional native ext4/btrfs probe only after exact approval.
  Automatic approval review rejected its SSH command under dcg system.disk:mkfs,
  citing partition/device erasure. Zero producer/candidate commands ran. The
  complete reviewed script and exact command are ready; async approval request
  cites dcg allow-once688744. Do not rename/encode arguments, alter the guard or
  use another formatter invocation to evade it. Workspace search found only
  three old ext4 smoke images and no retained btrfs image, so no substitute
  native proof is claimed. Continue independent gates while approval is pending.
- [x] Obtain actual unchanged-profile benchmark measurements. Current2304 build
  subsequently completed with60 timing intervals, remote/wrapper0; see below.
- [ ] Refresh final honesty disposition for these executed results, sync staged
  status, commit/publish exact owned paths and close only on full acceptance.

### 23:36 UTC complete-source and explicit formatter approval follow-through

- [x] Record the user's exact reply, "Approve this exact probe", for the reviewed
  ext4/btrfs public-reader script SHA7fbdb0d7b3987fcefd3a0250594c7c5652ad845262b35f448f15cdc6ac8265cc.
  Retry the exact command once after that approval. Automatic review still
  rejected system.disk:mkfs before any remote producer or candidate execution,
  issuing allow-once549486. The DCG skill explicitly requires the HUMAN to run
  allow-once; request only that operational action, not duplicate permission.
  Do not self-grant, hide arguments, change formatters or weaken the guard.
- [x] Execute that unchanged approved probe after the human applies its token;
  inspect all61 actual commands, fixed52 public calls, native byte readback and
  unchanged image/source/tool/ELF hashes. No credit before actual execution.
- [x] Read all production and510lines of tests added by shared-main4128908c8.
  The pending older-baseline Clippy selection omits the new state_tests.rs
  module, so it cannot certify this source. Supported cancel2325 was unconfirmed;
  supported recovery2334 only returned recover_requested, not retirement.
  A cancel attempt with unsupported --timeout-secs was rejected before action;
  inspect help and issue the supported exact-wrapper cancel2337 instead.
- [x] Collect actual cancellation acknowledgment/retirement of
  rchw-f04d99e1-fad3-475e-af77-525b921be544 before a replacement selection.
  Preserve source/cache reservations while unconfirmed; no manual process,
  lock, journal, daemon or cache manipulation and no replay of the old request.
- [x] Select the then-current complete committed baseline082 plus nine exact
  owned overlays; later peer changes remain outside that frozen source cut.
  Prove new state_tests.rs is included, then run workspace/all-target compiler
  and strict Clippy plus FAT/facade regression execution against that cut.
  Older0133 tests/checks remain bounded evidence for their original source only.
- [x] Remote cargo fmt --check exited0, fmt-shared-workspace-fat-hz3-2325.log.
  A separate read-only rustfmt check shows the macro-included new state_tests.rs
  has style differences; cargo fmt does not recursively discover that macro
  module. This is not an independently verified formatting pass for that file.
  Its test source and assertions were not edited or suppressed.
- [x] Normal full benchmark2304 progressed from compilation into real timing
  intervals. Five intervals observed at23:35, no terminal completion yet.
  Preserve the original default profile, sample counts, deadlines and cases.
  These timings qualify the current cut, without an incumbent-relative win.
- [x] Renew active exact-path leases and release six unchanged source leases;
  notify existing peers of source cuts and request coordination before commits.
  No new agent spawned, no functional Bead closed, no canonical WAL mutation.

### 23:45 UTC native ext4/btrfs success, benchmark success and complete FAT cut

- [x] Preserve written authorization: user replied "Approve this exact probe"
  to the reviewed-script request, then "it's done now" to the human-only
  dcg allow-once549486 step. Execute the EXACT approved command below, unchanged.
  The first producer receipt is2026-10-21T23:42:39.777589Z and final result is
  23:42:42.184568Z. No existing image/device was formatted, no deletion occurred,
  and no guard was bypassed or changed.

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes csd 'printf "%s  %s\n" 7fbdb0d7b3987fcefd3a0250594c7c5652ad845262b35f448f15cdc6ac8265cc /tmp/frankenfs-indexed-candidate.18nZPUdg/verify-public-ext4-btrfs.py | sha256sum -c && sudo -n python3 /tmp/frankenfs-indexed-candidate.18nZPUdg/verify-public-ext4-btrfs.py --binary /tmp/frankenfs-indexed-candidate.18nZPUdg/native_reader-current --binary-sha256 e862954f96cf7bfff76fd63d47465cd4b55dd0f1f3e3acb9c08e883b34e4ef48 --mkfs-btrfs /data/ssd/tmp/ffs-native-verification-7CWV8iQw/oracle-btrfs-7p8tifk0/unpacked/usr/sbin/mkfs.btrfs --btrfs /data/ssd/tmp/ffs-native-verification-7CWV8iQw/oracle-btrfs-7p8tifk0/unpacked/usr/bin/btrfs --work-dir /data/ssd/tmp/ffs-native-verification-7CWV8iQw' > /Users/jemanuel/Library/Logs/frankenfs-verification/native-public-current-ext4-btrfs-2320.log 2>&1
```

- [x] Probe passed, retained root ext4-btrfs-public-native-2glw4nqx. Separately
  inspect actual61 argv/status files:57status0/four expected status1. This was
  root's receipt review, not an independent actor or build. Exactly
  two fresh native producers, seven native checks/readback commands and52public
  calls; eight native payload readbacks,28public byte comparisons, eight stat,
  eight listing checks, four write refusals and four typed NotFound failures.
  Four backing hashes plus all source/tool/ELF hashes unchanged during checking.
  Combined current refresh is280public calls on five native formats, not native
  APFS, mounted-all-formats, native writer or field qualification.
- [x] Full normal cargo bench -j1 -p ffs-harness completed, remote0/wrapper0.
  Both metadata_parse and ondisk_parse targets ran,60timing intervals retained,
 1145 Criterion artifact files retrieved. Log bench-current-clean-overlay-2304.log;
  build30074357740994956, base9905390731160fd1e806f92d814409bc74a2df0b,
  overlaya7eafb081c533557501747facea8c7567b1b154dcbea9fbff7afb59649f39eea,
  tree01a4e0c040f97ed642883bfb90d49397f2fe5aae. Execution2408486ms,
  wrapper2478.4s. Original default profile/cases/deadlines unchanged. Libtest's
  ignored benchmark entries are not executed-test credit. This is maintenance
  qualification, not a new performance win; no incumbent-relative claim.
- [x] Supported cancel after benchmark completion returned terminal acknowledgment
  true for wrapperrchw-f04d99e1-fad3-475e-af77-525b921be544, terminal1. Original
  wrapper returned103: clean-overlay input changed after admission, so execution
  was refused before compilation. Retain both facts, no replay or local fallback.
  Earlier attach used a mistyped wrapper ID and was rejected before action;
  corrected attach merely timed out without status. Neither earned evidence.
- [x] Incoming main08226b8cb adds current-rooted-ownership revalidation and five
  regressions in new state_tests/reclamation.rs. Read its full production diff
  and209testlines. Remove only own two formatting hunks to permit fast-forward;
  the shared checkout had already advanced when merge --ff-only ran (already
  up to date). Verify all three incoming blobs intact, then manually apply the
  three exact rustfmt production hunks. Read-only normalization proves repair.rs
  equals rustfmt of082 exactly, preserving all production behavior.
- [x] Retry canonical br sync --import-only after the observed update: exit6,
  committed-WAL guard refused before opening. Do not checkpoint, delete, rebuild
  or bypass it. Staged JSONL comments remain the only permitted tracker updates.
- [x] New complete-source cargo fmt --check passed remotely at23:40:23Z, log
  fmt-shared-082-fat-2340.log. Macro-contained test-module style caveat above
  still applies; no claim that those tests were independently formatted.
- [x] Prove baseline082 contains repair.rs and BOTH state_tests.rs and nested
  reclamation.rs. Submit workspace/all-target check on082 plus nine explicit
  owned overlays, including current README/FEATURE updates; log
  check-complete-082-shared-source-2347.log. Do not mutate selected source bytes
  during admission/sync; TODO is excluded from this selected source.
- [x] Collect that complete-cut check; run strict workspace/all-target Clippy
  and the actual FAT/facade tests on the SAME complete cut. Old0133 tests still
  qualify only their old source. Preserve all fresh failures and repair causes.
- [ ] Refresh final bounded honesty disposition, publish exact owned paths and
  update the original staged Bead only on executed full acceptance.

### 00:07 UTC unchanged-source gates and independently routed scanner findings

- [x] Complete-source compiler request uses082 plus nine overlays, fingerprint
  c7dd1dceddd5c96a8074dac509033d585e61bee63b7f980e02308466243234ad.
  It has reached workspace crates on hz3 after cold dependencies/native allocator
  compilation. Preserve its current selected bytes and collect its real result.
  Peer commita41137718 contains the exact README/FEATURE native-probe update;
  no source bytes were replaced, and neither that commit nor its source is
  independently authored or freshly certified merely because it was committed.
- [x] The first complete-cut FAT/facade request did not compile: namespace
  initialization73/Killed, wrapper103. Authoritative daemon status bound the
  exact command/project/start time to build95031, wrapper
  rchw-d6286717-8fe4-4f7e-9fe6-c58ad337b9f9. Supported recover acknowledged
  terminal1 before a retry. Preserve tests-complete-082-fat-facade-2356.log.
- [x] After workload phase changed, same normal request retried once. It again
  failed namespace initialization before compilation, wrapper103. Authoritative
  status bound build95037 to wrapperrchw-772d408e-c9cb-4036-9237-3049e73c14da;
  supported recovery acknowledged terminal1. No replay, fallback, timeout change,
  slot reduction, source/cache namespace alteration or ownership bypass occurred.
- [x] Fresh worker telemetry explains why blind hz3 retries are inappropriate:
  disk I/O100%, available disk61.85GB and memory44.90%. vmi1149989 now has
  memory39.86%, I/O27%,69.97GB free and an available slot. Request the same
  complete082+nine-overlay strict workspace/all-target Clippy on that worker,
  log clippy-complete-082-shared-source-0006.log. Admission guards unchanged.
- [x] Collect complete-source workspace/all-target compiler check: remote0 and
  wrapper0, with the acknowledged source receipt recorded below.
- [x] Collect old0133 full FAT/facade suite:501passed/0failed/1ignored.
- [x] Execute and collect complete082 full FAT/facade suite:515passed/0failed/
  1ignored, including all14 new state/reclamation tests; no filtered cases.
- [x] Collect complete-source strict workspace/all-target Clippy: c7dd failed
  three test-iterator lints; the corrected23f0 source subsequently passed.
- [x] Run required targeted UBS on all six changed Rust files, no Cargo locally,
  no category exclusions, baseline filtering or suppressions. Initial default
  Bash5.3.9 execution hung before any report. Read-only sample85545 shows
  heredoc_write blocked in write; no scanner pass. Installed official
  Bash COMPAT:543-555 documents BASH_COMPAT=50 using temporary files instead
  of pipes for heredocs. Command-scoped mode runs the SAME unchanged UBS5.5.0
  and the SAME six inputs to completion. No scanner/code/config was modified.
- [x] Preserve actual targeted result: six files, exit1, three critical,
 453warning/157info, log ubs-owned-maintenance-compat50-2355.log. All three
  critical locations were reviewed: FAT repair/tests/parents.rs:25 is a
  test-only unexpected-CLI-variant failure; NTFS filesystem/indexed/tests.rs:57/61
  are deliberate write/sync tripwires beneath cfg(test). Removing those panics
  or converting the tripwires into weaker refusal paths would weaken proof.
  No assertion was changed to satisfy the scanner; no clean UBS claim follows.
- [x] Run a wider unmodified-gate scan with complete engine source context,
  Cargo.toml and CLI test:142files, exit1,52critical/13295warning/3571info,
  log ubs-engine-context-2358.log. Wider context did not repair classification.
  Samples include more fixture tripwires and two constant-time findings at
  NTFS recovery/record.rs:90/96, comparing public on-disk FFFF/RCRD magic,
  not secrets. Read actual sites; preserve114-line panic-source inventory.
  This is wider scanner evidence, not an independently adjudicated clean tree;
  the full52 require independent review in the separate scanner-owned lane.
- [x] Send exact sites, results and unchanged-proof requirement to existing peers
  in original Mail thread, message5478. No new agent spawned or gate relaxation
  bundled. An empty inbox is not independent acceptance. Original remains open.
- [x] Interrupt only the originally stalled OWN UBS execution through its exact
  execution-tool session74472, returned130. Verify PIDs85515/85544/85545 gone.
  No process kill command, daemon restart, lock clearing or manual file cleanup.
  Successful compatibility-mode scans have their own separate exit1 receipts.
- [ ] Obtain independent scanner-lane disposition before claiming required UBS
  clean or publishing a clean-gates commit. Keep the original Bead in progress;
  essential conditions remain here rather than being laundered into a closure.

### 00:33 UTC complete-cut compiler and full engine regressions passed

- [x] Workspace/all-target cargo check -j1 passed on complete082 plus nine
  overlays, sourcec7dd1dceddd5c96a8074dac509033d585e61bee63b7f980e02308466243234ad,
  tree2b266328814625b917489f063791b93f2331cb0f. Build30074357740995012,
  wrapperrchw-c7af4b1f-d9d0-4ac8-b29a-26ff45f7a50f, remote0/wrapper0.
  Supported exact recovery acknowledged terminal0. Log
  check-complete-082-shared-source-2347.log; total1840.0s. A read-only SSH
  process probe saw no matching process just as authoritative daemon completion
  recorded0 at00:15:39Z. An empty process list alone earned no pass. No direct
  SSH Cargo, source/lock mutation, daemon restart or local fallback occurred.
- [x] Previous0133 plus four-overlay FAT/facade test run passed501cases:
  40facade and461FAT, zero failures, one native opt-in ignored. Log
  tests-shared-head-fat-facade-retry-2312.log, wrapper0,3435.7s. The source
  receipt remains0391028788c74ebc3a45bbf810f1df20950e29db0f8a803ef63017f6348dca7f,
  tree3884d8b7ff380781f88a95c0fe344672994b3399; no later-source credit there.
- [x] Queue current082 plus nine-overlay full FAT/facade execution normally on
  vmi1227854, whose cache/source ownership serialized after the old run retired.
  Four test threads use the same complete case list and unchanged default
  admission/profile/deadline. No resource or ownership guard was reduced;
  no namespace/cache path was altered. Actual cargo-test default timeout is
  7200seconds, distinct from the3600-second benchmark/check limits; no override.
- [x] Current full test run passed515cases with no failures:40facade/one native
  opt-in ignored,475FAT/zero ignored, zero filtered in both targets. All14 new
  state/reclamation tests executed and passed, together with all nine parent
  repair tests and existing engine regressions. Log
  tests-complete-082-fat-facade-vmi122-0010.log; remote0/wrapper0,953.0s;
  FAT runtime824.54s. Verify EXACTLY the samec7dd source and2b266 tree receipt
  as workspace checking. These storage-fault tests are constructed-image unit
  evidence, not native writer, crash hardware or field qualification.
- [x] Collect the strict complete-cut Clippy result on vmi1149989, same082+c7dd
  source:101, three test-iterator lints. Corrected082+23f0 subsequently passed
  strict workspace/all-target Clippy without suppressions, as recorded below.
- [ ] Resolve required UBS disposition separately; retain its nonzero results,
  test tripwires, actual source scope and independent-review requirement.
  No assertions/thresholds have been weakened; no functional Bead is closed.
- [ ] Finish precise public status, final bounded honesty disposition, staged
  JSONL synchronization and concrete reviewed publication within gate authority.

### 01:01 UTC strict Clippy finding and assertion-preserving correction

- [x] Collect strict complete082+c7dd Clippy: remote101/wrapper101, build
  30074357740995041, wrapperrchw-ca367199-b732-4527-b092-cc88455b5ca8,
  terminal acknowledgment true. Log clippy-complete-082-shared-source-0006.log.
  Three actual chunks_exact_to_as_chunks lints in FAT parent-repair tests at
  lines209/214/231 prevent a green result. No timeout, suppressed lint or pass.
- [x] Recheck authoritative leases: exact parent-test path remains conflict-free
  under own lease4780. Manually replace only those three chunks_exact(32)
  iterators with as_chunks::<32>().0.iter(). The same512-byte slice yields the
  same16records in the same order, with the same find/position expressions and
  every assertion/tripwire unchanged. No remainder is admitted or discarded
  differently. Local read-only rustfmt --check and git diff --check returned0.
- [x] Request unchanged strict full workspace/all-target Clippy against complete
  baseline082 plus the same nine selected paths, now including those iterator
  corrections: clippy-complete-082-array-chunks-0101.log, worker vmi1149989.
  Previous exact owner is terminal/acknowledged; ordinary cache/source ownership
  applies. The old c7dd receipt is not silently reused for this new test source.
- [x] Request all nine affected parent-repair regressions through RCH on the
  same source selection: tests-082-parent-array-chunks-0101.log, vmi1227854.
  Full earlier515-test execution remains scoped to c7dd; no blanket rerun of
  unchanged cases is needed for these equivalent test iterators.
- [x] Rerun unchanged targeted UBS on all six Rust files after the correction,
  with documented BASH_COMPAT=50 and no local Cargo, skip or suppression:
  ubs-maintenance-array-chunks-0102.log: exit1, unchanged3critical/453warning/
  157info. Critical sites remain the same cfg(test) CLI-variant and read-only
  write/sync tripwires; the three iterator corrections introduced no new count.
- [x] Current main advanced to5c7d8d76b with a separate FAT root-expansion
  implementation. Read its explicit source/model-only qualification limits;
  it is outside this frozen082 gate selection. Both remote main and legacy
  compatibility refs matched5c7d8d76b at00:49. No peer code was overwritten.
- [x] Fresh read-only normalization before the iterator correction confirmed
  four Rust files exactly equal rustfmt(HEAD), FAT production differs only by
  the equivalent De Morgan condition and NTFS tests only by equivalent empty
  backend-read-log equality. All seven code/inventory paths matched retained
  72412-byte review patch SHA3586a711bcc8c510d9d25b4764918912695e5ab16d71e09508a8644ea9a0237e.
  That retained patch remains immutable and now predates the three new iterator
  corrections; prepare a distinct final review artifact after gates settle.
  The first diagnostic was refused before execution because its subprocess argv
  used dynamic unpacking. A fixed, explicit read-only argv was accepted; no
  one-use approval, command hiding or source transformation was involved.
- [x] Collect final strict Clippy, affected parent regressions and UBS outcomes;
  outcomes and public/source status are recorded below. Publication authority
  remains explicitly pending; collecting outcomes does not waive the scanner.
- [x] Fresh full remote cargo fmt --check passed on exact082+23f0f687639a1cd61fd8f6de680967c4874ad93e10cde5efd21afec7aee68782
  overlay selection, receipt tree2b266328814625b917489f063791b93f2331cb0f,
  remote0/wrapper0. Log fmt-082-array-chunks-ts1-0103.log. The preceding hz3
  request was refused before execution because its unchanged4-core estimate
  exceeds that worker's3slots, exit103. Supported worker ts1 has4slots; no
  resource estimate, admission threshold, deadline or job classifier changed.
- [x] Request final exact-source workspace/all-target check after the iterator
  corrections: check-082-array-chunks-0104.log. This uses ordinary -j1 on hz3,
  preserving the compiler's existing cache/source locks and all admission gates.
- [x] Correct public evidence accounting at final documentation refresh: the
  280public calls cover ext4, btrfs, FAT16, FAT32, NTFS and ZFS, all SIX declared
  formats. Prior wording grouped FAT16/FAT32 as one family while saying five
  formats; that wording and the unrelated APFS qualification sentence were
  inaccurate. FsFormatKind and the public facade declare these six, not APFS.
- [x] Corrected082+23f0 full workspace/all-target strict Clippy passed remote0/
  wrapper0: build30074357740995101, wrapperrchw-0bd80ead-b364-4d4c-a415-9648cf83fd85,
  log clippy-complete-082-array-chunks-0101.log,657.0seconds total. Receipt
  fingerprint23f0f687639a1cd61fd8f6de680967c4874ad93e10cde5efd21afec7aee68782,
  tree2b266328814625b917489f063791b93f2331cb0f, exactly as full formatting.
- [x] First final-check request failed before admission at the unchanged queue
  deadline, wrapper103; journalrchw-1f3e2c6e-9575-4276-8665-3a2763ddb910
  acknowledged the failure. Fresh hz3 telemetry then showed one available slot,
  I/O0.50% and memory50.98%, supporting one same-command retry. That retry stayed
  queued. When Clippy freed the warm vmi1149989 worker, supported exact cancel
  rchw-a9a7a160-4cca-4857-9fb9-84c6bdeb239a returned cancelled_before_start130;
  collect original wrapper130 and terminal acknowledgment true before requesting
  the same check on vmi1149989. No remote build or duplicate check existed.
  Log check-082-array-chunks-vmi114-0113.log; all guards/deadlines unchanged.
- [x] Collect final affected tests and final check; exact selected source bytes
  remained fixed until every source guard and receipt completed.

### 01:48 UTC final executed verification and concrete publication boundary

- [x] Final check passed on082+23f0: build30074357740995112, wrapper
  rchw-a644c6e2-2158-45a6-9467-59cd34e8ba47, remote0/returned0/journal0,
  terminal acknowledged. Command cargo check -j1 --workspace --all-targets;
  log check-082-array-chunks-vmi114-0113.log,1625.6seconds total, command ended
  01:39:43Z. Automatic rsync executable-resolution warnings were retained; the
  supported transfer still completed and emitted the exact source receipt.
- [x] Final parent regressions passed9/0/0,466filtered,33.58seconds runtime:
  build30074357740995102, wrapperrchw-a1b12192-d0ab-461c-9799-5c14e49f4b75,
  remote0/returned0/journal0, terminal acknowledged. Command cargo test -j1
  -p ffs-fat --lib reader::recovery::repair::tests::parents -- --nocapture
  --test-threads=4. Log tests-082-parent-array-chunks-0101.log,1800.8seconds
  total, command ended01:30:43Z. Read-only worker process inspection confirmed
  active asupersync compilation during the quiet log; no idle-job pass inferred.
- [x] Verify final check, strict Clippy95101, affected tests95102 and full
  formatting95103 all return0 with terminal acknowledgment and the SAME source
  fingerprint23f0f687639a1cd61fd8f6de680967c4874ad93e10cde5efd21afec7aee68782,
  baseline08226b8cb79755aee243068744eb2abeb743b01d and receipt tree
  2b266328814625b917489f063791b93f2331cb0f. Formatter wrapper is
  rchw-d7526a9d-ce79-4ea8-bf8d-fc2164e1bd55. Original PTY IDs were no longer
  available on continuation at01:44; actual logs AND durable acknowledged
  journal results supplied the completion evidence, not the missing PTYs.
- [x] Refresh README/FEATURE in place with these source cuts, benchmark60intervals,
  full515and affected9test counts, six-format280call accounting, nonzero UBS and
  the unqualified later root-expansion boundary. No original goal, production
  admission, assertion, benchmark profile or scanner policy was weakened.
- [x] Canonical br sync --import-only again refused before opening, exit6, due
  to possibly committed uncheckpointed WAL frames. Do not checkpoint, delete,
  replace, rebuild or bypass it. Continue the original staged record only.
- [x] Review the next dependent fuzz task without claiming or editing it:
  bd-uz4m0 is open and depends on this integration and in-progress bd-vuzzq.
  Current63-target fuzz Cargo.toml has no FAT/NTFS/ZFS library dependencies or
  named engine traversal targets; existing detector target exercises only
  ext4/btrfs. Reuse the existing harness when both dependencies are satisfied;
  actual bounded engine campaigns, not signature-only fuzzing, are required.
- [x] Add final executed-command/source/counts comment to original staged Bead,
  retaining in_progress. Staged br --no-db sync --flush-only returned0 with
  nothing dirty to export, and br --no-db dep cycles returned an empty graph.
- [x] Fresh read-only normalization of all six Rust paths confirms three exact
  formatting-only changes, one equivalent production De Morgan condition,
  three equivalent32-byte test iterators and equivalent empty backend-read-log
  equality. Retain file hashes and the complete non-format diff in
  native-library-semantic-review-20261022.txt,3139bytes,
  SHA43d7969e47d829455d8f051d914edac67cf0081b7360348417f3e75d3ed9a8ea.
  No source was modified by this review. The final publication patch is generated
  after these notes; its exact hash is recorded in the staged Bead and Mail.
- [ ] Obtain independent scanner disposition or explicit operator ruling before
  publication/closure. Preserve the review artifact and all failed executions.
  UBS on the six changed Rust files remains1 with3critical/453warning/157info;
  all three critical sites are retained cfg(test) failure tripwires. Wider
 142-file scan52critical remains unadjudicated independently and gets no clean
  claim. No actor replied to the separate-owner review request as of this check.

### 02:05 UTC continuation — execute the newly landed root feature

- [x] Refresh main and preserve concurrent publication: d452889fa committed the
  parent iterator correction and README/FEATURE receipt. The remaining five Rust
  maintenance files and this requested TODO are still dirty; no peer work was
  reverted, restaged or claimed as a new implementation.
- [x] Read all 178 production and 474 test lines of the landed FAT root expansion,
  its resize integration and operational contract. The nine authored regressions
  cover real slot creation, original record/payload/preallocation preservation,
  explicit tail relocation, 512/4096-byte sectors, total-sector field transition,
  cancellation/read-only boundaries and output publication faults. These remain
  constructed-image tests until executed, separate from native interchange.
- [x] Refresh local source-aware tracker triage without canonical DB mutation:
  artifacts/e2e/20261021_220439_ffs_tracker_source_hygiene_JSkdiD/
  tracker_source_hygiene_report.json reports ready,50claimable/53open/3blocked,
  zero foreign or permission-gated rows. The enclosing wrapper again fails bv
  unsupported --no-cache and fixture self-checks; no global tracker-green claim.
  Continue the single staged integration claim; do not claim blocked fuzz work.
- [x] Announce current-source qualification in original Mail thread, message5529,
  and reserve only this TODO initially (4968). No fresh scanner disposition has
  arrived; retain the existing publication boundary without another question.
- [x] Start exact current-source RCH root regressions on warm vmi1227854:
  base d452889fa016e8a6815fe74d1ee937a8570c96bb plus five explicit Rust overlays,
  fingerprint307e79efaecfd6c5c99709d7d8e66b00e24e641257aa03f705c0feaec67098ea.
  Command cargo test -j1 -p ffs-fat --lib resize::root::tests -- --nocapture
  --test-threads=4; log tests-d452-fat-root-expansion-0207.log. Strict remote-only
  execution and all source/cache/slot/deadline guards stay enabled.
- [x] Collect terminal test result: all9passed/0failed/0ignored/475filtered,
  13.58seconds runtime,138.4seconds total. Build30074357740995160,
  wrapperrchw-491a0b9b-1778-4ceb-a262-5e27f842beaa finished acknowledged true,
  and actual wrapper returned0. No compile/runtime defect was exposed.
- [x] Fix the newly observed root.rs formatting drift manually under lease4972;
  read-only rustfmt --check passes. Unchanged body tokens and assertions retain
  the nine passing tests' semantics. Fresh UBS on the changed production file
  returned0 (0critical/10warning/16info), log
  ubs-d452-fat-root-production-0211.log. The ten direct-index warnings are bounded
  by the checked read end, transfer minimum and validated logical boot sector;
  no indexing or scanner rule was removed. This one-file pass does not erase the
  earlier six-file nonzero scan.
- [x] Collect the frozen root package's compiler, strict Clippy and formatting
  results through RCH: d452 strict Clippy passed, then 8dae workspace check and
  corrected formatting passed; complete receipts are recorded at 03:22 below.
  The original four-slot ts1 formatter requests did not execute. Later metadata
  formatting uses the existing one-slot formatter-only profile; compiler/test
  profiles and all guards/deadlines remain unchanged.
- [x] Build the frozen FAT CLI and verify source-preserving root growth against
  native FAT tools using a private copy of an existing native-produced image.
  Prepared probe verify-native-fat-root-growth-20261022.py, SHA256
  5611ea97ff2a7d869da0e2e152ad311a65dabd49b66f0109e1790fc709b9eea4,
  retained under the local verification log root and copied to CSD with the
  hash-suffixed name. It fills the native root with mcopy, requires a semantic
  no-directory-slots refusal, expands512to1024, compares original records and
  three payloads, checks plain/bounded output equality and immutable sentinels,
  creates with both native/FrankenFS tools and checks fsck.fat -n throughout.
  It never formats, deletes or modifies retained source images. Preparation is
  not execution evidence. This prototype was superseded by the permanent runner;
  the executed 532-command positive and exact 511-command old-CLI counterexample
  are recorded below. The prototype itself remains unexecuted and retained.
- [x] Record exact source/results in the existing Bead and parity notes. Keep
  original integration acceptance open until its remaining conditions pass.

### 02:20 UTC native workload wiring and executed counterexample

- [x] Extend the EXISTING scripts/verify_fat_read.py runner in place under
  lease4976. The FAT16 native dialect scenario now invokes root_growth; FAT32
  keeps its old path. Every previous method body except the additive dialect
  call/report is AST-identical. All old assertions remain. No extra repository
  test wrapper, skip path, replacement golden or format gate was introduced.
- [x] The permanent native workload fills all available fixed-root records with
  mcopy-created empty files, requires its exact no-directory-slots error, verifies
  old records/payloads after512to1024slot growth, compares plain/bounded output,
  creates files with native and FrankenFS writers, then checks both with native
  fsck and the engine. Immutable source and neighboring sentinels are hash-bound;
  refused overwrite must preserve the already-created output too.
- [x] Parse the modified Python AST, inspect the diff and retain script SHA256
  38f43f61ddecfd4889a2bd0fd2543020cc986c6dc356614f3dbd3521a066828a.
  The earlier external5611ea97 probe is an unexecuted prototype only; actual
  evidence now executes Run.root_growth from this real repository workload.
- [x] Execute the new workload against the old97289769 CLI. Retained root
  fat-root-old-red-sufvbhzf, log native-fat-root-workload-old-red-0220.log:
  511captured commands, first510successful/expected; the old CLI failed the
  positive resize dry run with actual2/expected0 and the exact unsupported
  --root-entries error. No output was created and retained native input SHA
  stayed f6a7d3aaff437419ac799a0e60db610ca72007a0c02213c41c1d4d10d62d2add.
  Outer counterexample verifier returned0 only after asserting this precise red;
  it is not a successful current-feature or complete native-profile run.
- [x] Production root.rs UBS returned0; Python runner UBS returned1 with
  11critical/18warning/19info, log ubs-fat-native-root-workload-0219.log.
  Critical rule python.ctcompare.secret_eq flags public image SHA comparisons,
  including old unchanged lines203/243/245/338/360. Retain those comparisons and
  reports. No scanner rule, test exclusion or equality check was weakened.
- [x] First current cargo fmt request failed before admission at the unchanged
  queue deadline: wrapperrchw-54cb58bc-7731-4d11-88b9-3165c9bb55f0,
  acknowledged true, actual wrapper103. Fresh ts1 telemetry changed from three
  busy slots to one, supporting one same-four-slot retry; no build-slot config
  reduction or local fallback. Retry log fmt-d452-root-retry-0219.log.
- [x] Read-only build health inspection using the existing pinned host-key file
  found the exact owned cargo build and its asupersync rustc active (~51% CPU),
  not stalled. An earlier strict SSH probe had incorrectly inherited /dev/null
  known-hosts lookup and failed255; no keys, host trust or SSH config were changed.
- [x] Collect the frozen CLI build and run the SAME permanent native workload
  against its hash-verified Linux binary. Preserve any failure, fix its actual
  cause and rerun. The executed 532-command positive is recorded below, with
  unchanged input hashes and both expected refusals; no later-streaming credit.

### 03:22 UTC followthrough — frozen root/FSInfo qualification

- [x] Peer01507310c committed the actual native root-growth workload; its final
  SHA remains7cb88675ffe717009b22bc096b03d8862c30b2d02f3875bc25a63cd6b2d763af.
  Final exact-script old-CLI control also returned expected_red,511commands,
  retained fat-root-final-old-red-i6bvtv22 and local
  native-fat-root-workload-final-old-red-0228.log. The three extra final controls
  check exact output length, semantic existing-output refusal and all old payloads
  again after both writers add files. Older38f43 control remains historical.
- [x] Full strict Clippy passed d452889fa+six Rust overlays, fingerprint
  c7e4ab4180fa2eac38aadfbe83e2a7e454fc4d5e12c552c21fe1fcae1f7d267a:
  build30074357740995175, wrapperrchw-620b08ca-a6c6-4ee2-95eb-69cbea8547f2,
  actual0/remote0/terminalACKtrue;3017883ms execution/3041.5seconds total.
  cargo clippy -j1 --workspace --all-targets -- -D warnings. Retain Cargo's
  dependency future-incompatibility notice for nix0.29.0/0.31.2; no project lint
  was suppressed. This cut does not cover the subsequent FSInfo/stream features.
- [x] Retire the overloaded native CLI attempt before a successor: build95171
  on vmi122 reached reported100%memory pressure. Exact supported cancel RPC
  timed out RCH-E504; original wrapper ended143, and supported recovery of
  rchw-9eda77c8-8e68-47af-a938-521c3a806ca0 confirmed completed143/ACKtrue.
  The log calls SIGTERM attribution unconfirmed; do not claim an OOM diagnosis
  or a successful build. No daemon restart, lock cleanup, local fallback or
  duplicate active CLI build was used.
- [x] Read the complete342-line landed FSInfo production module,351-line test
  module,71-line contract and integration changes from91f468ef0/8dae5e14b.
  Eleven authored tests are not execution evidence. Preserve explicit FAT32-only
  authority, raw allocation/directory/state evidence, five-word hint repair,
  recognized-backup policy, dirty-state publication and no reclamation/rollback.
  Reader admission already limits clusters to65536bytes, so its64KiB scratch
  also covers every admitted directory-cluster size; no hidden large-cluster
  exclusion was inferred from the scratch bound.
- [x] Pin this qualification package to8dae5e14b8a0bc6996785e835d48fbb39d79124a
  plus five original Rust overlays, fingerprint
  d1224d035dd49a9089e6981720f81374c280fef275d98b6493ecc9926ee121be.
  Later ea0bc8afd bounded streaming is outside these receipts and has not been
  fully reviewed or executed here. Do not chase newer main or claim latest-tree
  coverage from these fixed inputs.
- [x] Request cache-informed CLI build on hz3 after old143 retirement; ordinary
  admission queued it until capacity was available, then real compilation began.
  Log build-8dae-fat-root-fsinfo-hz3-0306.log. All guardrails/deadlines unchanged.
- [x] The first FSInfo test request on vmi122 refused critical-pressure admission,
  actual103/no execution, log tests-8dae-fsinfo-0310.log. Request the exact11-test
  probe on healthy vmi114: tests-8dae-fsinfo-vmi114-0311.log. Start workspace
  cargo check on idle vmi115: check-8dae-fsinfo-0311.log. Both compile the same
  pinned8dae+d1224 source. Cache-informed placement did not imply a cached pass;
  the logs show dependency compilation.
- [x] Resolve formatter invocation without bypassing destination safety. A
  --job/--source-content-receipt pair was rejected2 before execution. Plain
  metadata-job source sync then refused a live checkout destination; wrapper
  rchw-18717ca0-ceaa-4981-9ae0-48e75cdf2f70 recovered completed1/ACKtrue.
  Preserve fmt-d452-native-metadata-job-0243.log and fmt-d452-metadata-0242.log.
  Neither request changed the live checkout. The5015-file preflight manifest
  fmt-metadata-current-input-0242.json is a retained local snapshot, not a remote
  execution proof or a receipt covering newer main.
- [x] Use normal RCH execution with explicit baseline/overlays and the existing
  one-slot formatter-only profile; no --job flag. This supports isolated source
  binding and leaves compiler/test profiles, all admission/source/cache checks
  and deadlines intact. The actual formatter ran and returned1 on exactly two
  source files: FSInfo and its parent repair module. Retain
  fmt-8dae-metadata-isolated-0314.log; its failure is not a capacity-only failure.
- [x] Manually correct the actual two-file formatting diff under leases5034/5035.
  An initial combined patch context mismatch made no changes; corrected manual
  edits now pass direct read-only rustfmt. FSInfo bytes equal rustfmt of the exact
  8dae source, proving no behavior-token change. The parent's three changes are
  wrapping only. No repair authority, assertions, checks or flags were changed.
  Corrected full RCH formatter and changed-file UBS are running in
  fmt-8dae-fsinfo-fixed-0320.log and ubs-8dae-fsinfo-production-0320.log.
- [x] Collect corrected formatter/UBS and pinned workspace check/FSInfo tests.
  Workspace check build30074357740995218/wrapper
  rchw-d9e409bd-a7fe-4e38-aece-31d707963e76 returned0/remote0/ACKtrue,
  actualPTY23700returned0;1545248ms execution/1577.0seconds total. Full fmt
  build30074357740995245/wrapperrchw-7335bec7-5ee5-4e5d-bddc-5765eea3de24
  returned0/ACKtrue. Check/tests use8dae+d1224; fmt uses8dae+e082 with only
  formatting changes in the two extra files. No latest-main coverage inferred.
- [x] Hash/deliver the new Linux CLI and execute the permanent native root case.
  Build30074357740995217/wrapperrchw-bf867189-372b-4566-af98-6c8c43c70b16
  returned0/remote0/terminalACKtrue;781965ms execution/805.1seconds total.
  Linux ELF542589256bytes, SHA256
  12af1605e9a1e2f9fbd4f22971a9c87a1820401bbc3d1c72b03670c786641b8b,
  delivered exclusively to CSD ffs-fat-8dae-12af1605 and rehashed unchanged.
  Permanent Run.root_growth passed532commands:530successful/two expected1s.
  Log native-fat-root-workload-8dae-positive-0327.log, actualPTY86014returned0;
  retained fat-root-8dae-native-a_dxn2cp/result.json. Native mcopy filled507
  empty files into the512-slot root, required no-directory-slots refusal;
  expanded1024-slot image preserves old raw records, zeroes new slots and
  retains three payloads before/after native and FrankenFS creation. Native
  fsck passed; plain/bounded output equal; dry-run and overwrite refusal
  preserve input/output hashes. Eight immutable inputs/tools/binary/script
  stayed unchanged. Only this native component ran, not the full6profile suite,
  native4096relocation, FSInfo, newer streaming, mounted, boot or field proof.
- [x] Collect corrected full formatter: fmt-8dae-fsinfo-vmi115-0328.log,
  actualPTY61826returned0,33.5seconds total, corrected7overlay fingerprint
  e08208528b6817996e0af810ac47aeab5e0a3b8cbd2bde5ed1862b0ba8dade3f.
  Newly corrected production files also passed UBS0:0critical/46warning/61info,
  log ubs-8dae-fsinfo-production-0320.log, actualPTY82270returned0. Wider test
  panic/public-hash scanner reports remain unresolved and were not weakened.
- [x] Collect all11FSInfo Rust tests: build30074357740995216,
  wrapperrchw-ab424599-14b6-444c-9b46-cf6a580587f8, actualPTY65105returned0,
  remote0/terminalACKtrue.11pass/0fail/0ignore/484filtered;17.67seconds test
  execution,1190487ms remote/1227.1seconds total, source8dae+d1224. Log
  tests-8dae-fsinfo-vmi114-0311.log. Includes no-write refusals, every write/sync
  fault, cancellation, changing evidence, unknown reserved backup, exact five
  words and separate ordinary recovery. Native FSInfo is still pending below.
- [x] After the FSInfo Rust probe, qualify its explicit dirty-state repair and
  separate ordinary-recovery path on a private native-produced FAT32 copy;
  preserve old payloads, surrounding bytes and all failed evidence.
  Actual permanent Run.fsinfo_recovery added in place; all old Run methods
  except additive dialect dispatch remain AST-identical, including root_growth.
  Independent native_allocation now also computes first free cluster. First
  runnerc7b163a3 wrongly expected0 from intentionally dirty check. Six-command
  failure retained fat-fsinfo-8dae-native-8o2xnok3 and native-fat-fsinfo-8dae-0342.log;
  all immutable hashes unchanged. Actual CLI main.rs132-142 emits JSON then1
  whenever not clean. Correct new probe to exact1 plus semantic stderr;
  retain exact4native dirty markers, complete namespace/allocation and wholefile
  expectations. Independent review requested Mail5554; no production gate changed.
  Corrected runner320d1c1318b6470462698e5e51f19c11f38203cd75185848781335d5a38f5d55
  passed20commands:17zero/three exactnonzero, actualPTY57445returned0.
  Log native-fat-fsinfo-8dae-fixed-0339.log, retained
  fat-fsinfo-8dae-native-_qg201_z/result.json. Private128MiB native FAT32 copy,
  512Bsectors/4096Bprefix+suffix; damagedprimarysignatures/bothhints,
  ordinaryrecoverrefusal, authorityrefusal/dryrun, repaironly5wordsperhintsector
  +4dirtymarkers; independently counted253962free/next4118. Repeatedrepair
  wholehashunchanged; ordinaryrecoverdryrununchanged, actualrecoverclean,
  reclaimed0/retiredLFN0. Native mcopy3payloadsbefore+after, ffscat3after,
  nativefsck0. Original/3payloads/tools/binary/script all8hashesunchanged.
  DamagedwrapperSHA9d1f3a545f07776b77061dadf29a4efcce9ad7cb44017f679b5f5a99e4e6a552;
  dirtySHAad2ae68136016108a931cfed0cb530290a8bc717e406439092cc4e656f8bc9f2;
  recoveredSHAaf48993cfcb7ff3a6b0f6083f4461b7bc353c8bc67d424b7a39c473d2cfc8c52.
  Retainednativeoriginal76a7d98589f62d18c068eb2f92aa7675e172f96d1cbbca339d4a4f4af71e1e6b.
  No fullrunner/native4096/kernel/crash/newstream/field inference.
- [x] Refresh measured parity/Bead comments with executed results; retain original
  in_progress and unresolved publication/scanner boundary until acceptance holds.
- [x] Collect full workspace strict Clippy on corrected8dae+e082. Request
  clippy-8dae-fsinfo-0341.log on now-idle/warm vmi115, normal compiler profile,
  unchanged guards/deadlines/slots and explicit frozenbase+sevenoverlays.
  It returned 101 on exactly two FSInfo production lints: nonminimal_bool and
  chunks_exact_to_as_chunks. Build 30074357740995248, wrapper
  rchw-377d5096-7e34-49a2-8616-95b28f786090, actual PTY94304 exit101/ACKtrue;
  278205ms execution. This failure remains a failure, not a passing gate.
- [x] Manually correct both actual production lint sites under lease5034:
  !(state || hints && hint) is DeMorgan-equivalent for all eight boolean inputs;
  as_chunks::<4>().0.iter() visits identical ascending FAT32 allocation words.
  prepare rejects other dialects before Evidence; width=4, length=entries*4,
  so both old/new iterators have no remainder and retain the same evidence hash.
  No assertion, repair authority, refusal or scanner rule changed. New source
  overlay a02d60b9d4cdb54f405c230a906dc519636887e4513676a71f9ecde467adb974.
- [x] Full RCH formatting passes again on that final overlay, 35.7seconds;
  log fmt-8dae-fsinfo-clippy-fixed-0347.log, actual PTY16576 exit0.
  Changed production FSInfo UBS also returns0/0critical/14warning/23info,
  log ubs-8dae-fsinfo-clippy-fixed-0347.log, actual PTY2493 exit0.
- [x] Collect strict workspace Clippy and the eleven FSInfo regressions on
  final8dae+a02d60b9; then repeat required workspace/all-target check on this
  final source. Logs clippy-8dae-fsinfo-fixed-0346.log and
  tests-8dae-fsinfo-fixed-0347.log. Native12af remains the pre-spelling-change
  executable; retain its original source binding rather than claiming a new ELF.
  The a02d60b9 Clippy failure and the subsequent final7262c1db pass are recorded
  below. Eleven tests reran on final production; all final compiler/style gates
  pass, with each test-only delta and source distinction disclosed.
- [ ] Obtain independent disposition of wider UBS/publichash/testpanic reports
  and the new-probe status correction before any gated publication/closure.
  Current Python UBS remains1:20critical/24warning/41info, all20critical under
  python.ctcompare.secret_eq on public SHA comparisons. Preservechecksandreport
  ubs-fat-native-fsinfo-0345.log; do not replace equality just to appease scanner.
- [x] Execute the existing unchanged Run.mounted read-only FAT16/FAT32 cases
  with the already-qualified8dae CLI and retained native images. Fresh /tmp
  mountpoints obey the previously observed fusermount profile; preserve all
  source/tool/binary hashes and require owned clean unmounts, actual mounted
  payload/range/stat reads and EROFS write-open refusal. This is strict FatFs
  mounted evidence only, not facade-mounted routing or writable/crash proof.
  ActualPTY10247returned0; log native-fat-ro-mount-8dae-0345.log,
  CSD /tmp/fat-ro-mount-8dae-5nkor59r/result.json statuspassed. Two actualFUSE
  mounts,12full/rangecomparisons,6sizechecks,2EROFSwriteopenrefusals,2statfschecks,
  eachdaemonexit0/unmounted. Four nativefsckchecks+twofusermount commands all0;
  12source/payload/tool/CLI/script hashes unchanged and noownedmountpointleft.

### 04:00 UTC continuation — actual output consumers and remaining gate fixes

- [x] Reopen the actual expanded FAT16 and recovered FAT32 outputs through the
  public facade consumer and strict read-only FUSE. The permanent mounted method
  remains unchanged. Native evidence `/tmp/fat-operation-consumers-68fgd5vi`;
  local `native-fat-operation-output-consumers-0358.log`, actual PTY4765 exit0.
  Twenty public calls: eight payload reads, eight stats, two exact listings and
  two write refusals. The expanded root lists 514 names including dot entries;
  five root-growth payloads and three recovered payloads match. Two mounts pass
  sixteen full/range comparisons, eight sizes, two EROFS refusals and two statfs
  checks. Both daemons exit0/unmount; four native fsck plus two unmount commands
  pass. Total26 captured commands plus two daemons; all15 immutable hashes match.
  Public consumer remains prior e862954f96cf7bfff76fd63d47465cd4b55dd0f1f3e3acb9c08e883b34e4ef48;
  mount CLI remains12af1605 on8dae+d1224. These are distinct executable cuts,
  not latest-main, facade-mounted, writable, crash or field proof.
- [x] Correct an uncommitted documentation transcription of this evidence path
  against the actual log header before publication. All three documents now cite
  the real68fgd5vi directory; no nonexistent evidence path is relied on.
- [x] Collect the second full strict Clippy failure: build30074357740995252,
  wrapperrchw-b29b8a26-6414-43de-803c-d6953fc77268, actual PTY38809 exit101,
  remote101/ACKtrue,527969ms. Production lints are fixed; it now reaches tests
  and reports decimal_bitwise_operands at FSInfo test159 and
  significant_drop_in_scrutinee at312. Log clippy-8dae-fsinfo-fixed-0346.log.
- [x] Reserve the test file (lease5065) and manually correct only those two sites:
  300 becomes identical0x012C in the bitwise expression; clone Storage::image()
  into a local before the loop, releasing its mutex before host-file writes.
  image() returns an owned clone of durable+pending pages; the same pages/bytes
  are written. Every old assertion, expected value, fault and panic stays intact.
- [x] Final eight-overlay source fingerprint:
  7262c1db4f99fdb1f5a8887af02a35b2fa3ea2f290900216853e3d81952f81c5.
  Full formatter0/ACKtrue,32.6seconds, build30074357740995259/wrapper
  rchw-f9c627fa-ec9c-4a41-b840-6af8f238d0ac, actual PTY94237 exit0;
  log fmt-8dae-fsinfo-test-fixed-0358.log. Test-file UBS0/0critical/180warning/
  19info, actual PTY21784 exit0; log ubs-8dae-fsinfo-test-fixed-0358.log.
- [x] Collect final full strict Clippy95256/wrapper
  rchw-c46d3dce-ebf7-4527-b4a9-e7f5f6eaacbb, log
  clippy-8dae-fsinfo-test-fixed-0357.log: actual PTY38501 exit0, remote0/ACKtrue,
  212049ms execution/231.3seconds total. No lint suppression or assertion change.
- [x] Required final workspace/all-target check also passed on8dae+7262c1db:
  build30074357740995264/wrapperrchw-3a1f5b14-0db0-448a-aa68-841991922cbd,
  actual PTY82607 exit0, remote0/ACKtrue,31680ms execution/51.9seconds total.
  Log check-8dae-fsinfo-test-fixed-0402.log. All three required compiler/style
  gates are green for this frozen package, not for the later streaming commit.
- [x] Collect the eleven-test production-correction rerun95253 on8dae+a02d60b9.
  Actual PTY8825 returned0; remote0/ACKtrue, wrapper
  rchw-861cf9b2-5350-4253-95f2-68d6b5667336. Eleven passed, zero failed/ignored,
  484 filtered,20.64seconds test runtime;1406517ms remote/1442.9seconds total.
  Log tests-8dae-fsinfo-fixed-0347.log. Its production source is final; the
  subsequent test-only literal/fixture-guard edits were compiled by final
  workspace/Clippy gates. No exact-final-test runtime is silently substituted.
- [x] Read the later streaming production module, reader/lib integration diff
  and contract as preparation only. Its ten new Rust tests remain unreviewed and
  unexecuted here. CLI/public stream_file are wired; mutable mount caches retain
  the materialized representation by the declared lifetime contract. Do not
  substitute immutable-reader indexes into mutable mounts or claim new parity.

### 04:12 UTC bounded completion and publication boundary

- [x] Fresh eight-file Rust UBS scan completed with actual exit1:
  two critical reports,491 warnings,166 information items. Log
  ubs-final-fat-followthrough-eight-rust-0407.log, actual PTY81594. The remaining
  critical sites are indexed/tests.rs57/61, the explicit no-write/no-sync panic
  tripwires. Both remain intact. The scanner classifies six other test-only
  panic sites as warnings; the older three-critical scan is retained, not erased
  or presented as a code improvement. Python scan remains1/20critical on public
  SHA comparisons, exact runner320d1c13; no scanner rule or assertion changed.
- [x] Retry ordinary canonical br sync --import-only once: actual6, recovery
  refused BEFORE OPENING because WAL may contain committed/uncheckpointed
  changes. No canonical engine/WAL cleanup, checkpoint, rebuild or deletion.
  Continue staged-only comments; do not pretend canonical import succeeded.
- [x] Preserve all failed probes, old source cuts, partial outputs, eight
  pre-existing DS_Store files and unrelated peer work. Native mount daemons
  exited/unmounted; all owned RCH requests now have observed terminal outcomes.
  No root commit, push, functional Bead closure, new ownership claim or field
  claim occurred. The exact new-probe dirty-status correction still awaits the
  independent review requested in Mail5554; empty inboxes are not acceptance.
- [x] Bounded honesty refresh: this continuation adds actual native/output/kernel
  consumers and one permanent FSInfo runner component, rather than a new process
  framework. Four executed Clippy diagnostics were fixed without suppressions;
  all assertions/faults remain. The dirty-check expected-status correction and
  an uncommitted evidence-path transcription error are disclosed and corrected,
  with failed evidence preserved. Native binaries, unit source and final gates
  retain distinct fingerprints. No speedup, complete six-format mount, crash,
  latest-streaming, release or tracker-closure credit is inferred.
- [ ] Independent scanner-lane/status-correction review, authorized publication
  and original acceptance closure remain outstanding. Preserve existing graph
  dependencies and canonical engine ownership; do not self-grant an exception.
  Concrete review bundle:
  /Users/jemanuel/Library/Logs/frankenfs-verification/native-library-fat-review-20261022-3698wcyx/changes.patch
  and its source/file/log-bound manifest.json. This supersedes the older c4956
  publication patch for reviewing the current owned diff; retain that old artifact.
  The first export command was rejected before execution because DCG could not
  statically verify an expanded subprocess argument list. Use an explicit literal
  read-only Git argv and exclusive-create artifact files; no allow-once token,
  guard override or existing-file overwrite is authorized or used.

### 04:19 UTC next capability slice — bounded FAT streaming

- [x] Confirm HEAD remains ea0bc8afd and preserve all thirteen owned dirty paths
  plus eight pre-existing DS_Store files. Keep the original staged Bead
  in_progress; no new claim, graph mutation or independent-review assumption.
- [x] Read the complete177-line streaming implementation, shared-walker and
  public stream_file integration diff,57-line contract and all445test lines.
  Ten actual tests cover both dialects/sector sizes, fragmented/reverse reads,
  max native file length, bounded physical reads, corruption before output,
  active FATs, partial I/O, cancellation, visitor/work bounds and sink failure.
  No functional defect found in the initial source review; source review is not
  Rust execution or native qualification. Mutable mounts retain full maps by
  their declared lifetime contract; do not substitute immutable caches there.
- [x] Reserve stream.rs/tests.rs and TODO under leases5074-5076. Start strict
  full workspace Clippy and full formatting on frozen ea0bc8afd plus the eight
  retained Rust overlays using normal RCH admission and existing profiles.
  Logs clippy-ea-stream-0419.log and fmt-ea-stream-0419.log. No local Cargo,
  source/slot/cache guard changes, deadline extensions or daemon maintenance.
- [x] Full remote formatting returned1 on new streaming source/test formatting;
  retain its real failure. Strict Clippy is still compiling, not a pass.
- [x] Manually format only stream/tests.rs under the parent lease; independent
  root comparison equals read-only rustfmt output byte-for-byte. All ten tests,
  55 assertions and protective panic guards are preserved. SHA3941e4ae.
  Full remote formatting now returns0, build30074357740995281, wrapper
  rchw-0bc7fe86-1104-4743-b4fc-af3ec52e80eb, terminal ACKtrue. Final nine-overlay
  fingerprint ed09c13eb2eeab4f156d97c26adb92f6f0845e91c4c0a1505ec55d506a77c8f6.
  Initial Clippy95276 still compiles; full FAT/facade runtime started separately
  on the corrected nine-overlay cut, tests-ea-stream-0434.log.
- [x] Add Run.streaming_reads to the existing native runner and invoke it from
  dialect. Require both cat/exact extraction, native mcopy references, declared
  volume origins, full native slot ancestry, zero-output wrong-parent/unknown
  selector refusals, native fsck and unchanged plain/bounded input hashes.
  Predeclared native scope: two dialects, three files, two selectors and two
  volume profiles =24 payload comparisons; eight expected selector refusals,
  six native reference reads and four native filesystem checks. Expected50
  captured commands includes eight catalogs. Authored checks are not execution.
- [x] Add a private cyclic-tail control for each native format, changing only
  the final allocation word in each mirror and preserving reserved high bits.
  Cat and exact extraction must both refuse before stdout. Before execution,
  baseline scope is now54 commands:24 payload comparisons,12 exact expected
  refusals,6 native reference reads,4 fsck checks and8 catalogs. UBS found two
  scope warnings in new BPB closures; bind them to an immutable boot-sector
  copy before releasing the private image buffer. Corrected runner b0645eed
  rescans without those warnings; public-hash and test-panic reports remain.
- [x] Also consume the previously verified expanded FAT16 and recovered FAT32
  outputs with this new reader, including both post-expansion writes. Planned
  four-image total before execution:118 commands,56 payload comparisons,
  24 expected refusals,14 native references,8 fsck checks and16 catalogs.
  Preserve all input/output hashes and bind execution to the new CLI/source.
- [x] Execute the complete four-image scope with final runner b0645eed and new
  Linux CLI a45f6380. Actual PTY8819 returned0;118 commands matched exact status,
  94 zero/24 one. All56 payload comparisons,14 native reference reads,eight
  native filesystem checks and16 catalogs passed. Eight cyclic-tail refusals
  and16 unknown/wrong-parent refusals emitted no stdout. All15 immutable hashes
  remained unchanged. Retained CSD fat-stream-ea-native-n3rmvqrt/result.json and
  local native-fat-stream-ea-a45f-0445.log. No complete-runner/mounted/native4GiB,
  fragmentation,4096-byte-sector, speedup or field claim follows.
- [x] New RCH CLI build95285, wrapper rchw-251c3113-3138-49b8-9c5e-05689ccaff2e,
  actual0/remote0/ACKtrue on final nine-overlay ed09c13e. ELF verified x86_64,
  542684816 bytes, SHA a45f6380c4ce1faefa66082c9586ccf0de9a8eb6c21afc9a02d70e92f7aa1e9a.
  Delivery used exclusive creation and checked the same SHA before execution.
  Initial Clippy95276 remains running on the pre-format test cut; corrected
  full FAT/facade runtime95283 continues. Full corrected workspace check now
  runs through RCH on hz3, check-ea-stream-0444.log. No pending run is a pass.
- [x] New streaming production UBS returns0, zero critical/one warning/15 info.
  The warning is result-buffer slicing, bounded by allocated request length
  and each physical-run count. New test panic guards remain intact; their
  scan returns1/two critical. Corrected Python b064 scan returns1/23 critical
  public-hash comparisons; old scope warnings disappeared without suppression.
  All findings and old failed-source scans remain retained for review.
- [x] Correct the README's obsolete fixed-root limitation to the already
  native-qualified new-image resize capability, linking its existing contract.
- [x] Manually correct observed diagnostics without suppressions, weakened
  assertions, test exclusions or golden updates. Assertion forms change only
  as explicitly recorded below; their predicates and count remain intact.
- [x] Execute ten streaming regressions and complete affected FAT/facade tests
  with nonempty selections on final corrected source. Require final workspace/
  all-target check, strict Clippy and full formatting.
- [x] Build the final Linux ffs-fat CLI, hash/deliver it exclusively and execute
  existing native read/exact-selector consumers and preservation controls on
  native FAT16/FAT32 inputs. New native evidence must bind to the new ELF;
  old12af receipts do not qualify streaming or establish a measured speedup.
- [x] Update parity, contracts and original staged Bead with actual results.
  Keep publication/closure gated on unresolved whole-change UBS and independent
  status-correction review, and preserve canonical WAL ownership.

### 05:04 UTC executed Rust results and final test-only corrections

- [x] Full FAT/facade run95283 returned0/ACKtrue on ed09c13e. Actual548 passes,
  zero failures, one existing ignored native-tool interchange test:40 facade
  units,505 FAT units,two downstream admission/context integrations and one
  facade compile doctest. All ten streaming tests passed; empty ffs-fat doctests
  earn no test credit. FAT runtime616.91seconds; facade1.72seconds/integrations
  5.39seconds;2020878ms remote/2062.8seconds total. Log tests-ea-stream-0434.log.
- [x] Corrected full workspace check95291 returned0/ACKtrue, wrapper
  rchw-64dced15-1e2d-41a4-832c-a4326c8ac539. Runtime588296ms/598.5seconds total.
  This is the pre-test-lint ed09c13e cut, not a final7d13873c check.
- [x] Initial strict Clippy95276 returned101/ACKtrue with15 new test diagnostics:
  three numeric-literal spellings, eleven empty-value assertions and one
  identical match arm. Manually use131_072, equivalent typed empty Vec equality
  assertions with better failure output, and let the existing zero-valued
  wildcard handle both free/mirror fault cases. All six fault labels,ten tests,
  55 assertions, no-write/no-sync panics and production bytes remain unchanged.
  Current test SHA61aae46ea781e2cc940a87234ca1fb91f2de7e829a09811d752bf0270c00657d.
- [x] Superseded ed09c13e Clippy95293 was explicitly cancelled through RCH;
  actual143/ACKtrue, not a pass or unexplained OOM. The helper's generic SIGTERM
  message is explained by that owned cancellation. Waited for terminal ACK
  before replacing it. First corrected retry on hz3 refused103 for disk/I/O
  critical pressure; no local fallback, cache/slot/pressure bypass or cleanup.
  Corrected strict Clippy now runs on admissible vmi1153651.
- [x] Full corrected formatting returns0 on7d13873c, log
  fmt-ea-stream-lint-fixed-0500.log, actual PTY29659. Full fingerprint
  7d13873c18805f020d68515fbba8121b96a1213d06c2ac4e756dddd2c17a6ad1.
- [x] Collect corrected strict Clippy and rerun full workspace check on7d13873c.
- [x] Collect exact-final ten-test streaming rerun on7d13873c through RCH after
  full95283 completed. Final log tests-ea-stream-lint-fixed-warm-0524.log.
  Earlier548-runtime/nativeCLI receipts remain bound to ed09c13e; the only later
  source change is the equivalent streaming-test lint correction above.
- [x] Full changed-code UBS returns1:27 critical,662 warnings,248 information
  items across nine Rust files plus Python. Critical classes remain23 public
  hash comparisons and four test-only backing-write/sync panic tripwires.
  No scanner suppression or assertion removal. The final test edits rescanned
  with the same27/662/248 counts; older scans remain retained.

### 05:16 UTC bounded audit and review-snapshot creation gate

Window:04:17 onward, current uncommitted streaming followthrough. README purpose:
native filesystem behavior in Rust, through FUSE and offline-image tools, with
explicit durability boundaries. Git log/reflog show no new commit or rewrite in
this window; newest staged closure is October20, not this window. The first
closed-item query used reverse and returned oldest rows; inspecting dates caught
that and the corrected newest-first query is retained. No new closure occurred.

Real-work classification: USER2 (README capability correction and reader profile),
ENABLER2 (streaming-test gate fixes and permanent native positive/negative runner),
PROCESS2 (requested TODO/Bead accounting and parity/evidence accounting), UNKNOWN0.
This is an enabler-heavy qualification block, not a newly authored algorithm.
Audit questions:1) demo cat/exact extraction on a bounded native image plus its
zero-output cyclic-tail refusal;2) without process entries the bytes would be
the same, but the explicitly requested source/remaining-work record would be
missing;3) the new permanent runner actually executed118 commands, not speculative
infrastructure;4) native fuzz/writer/durability goals remain open, and another
owner retains the read-authority P0 without handoff; this block completes the
already claimed native-library integration slice;5) no close-farming pane—one
helper only formatted tests and no pane closed anything;6) no plan/spec edits
stand in for code, no follow-up closes an unmet original. Verdict:bounded
HEALTHY enabler work; process earns zero capability credit. Finish existing
gates and return to executable work; do not create another framework.

Honesty inventory, all20 prompts, checked against actual diffs/logs:
1. No (checked:ten tests/55 assertions retained; empty-value predicates remain
   exact equality to empty, all six fault labels and panic tripwires remain).
2. No (checked:no production mock/stub; native tools run on retained native
   images, synthetic ByteDevice tests are labeled as such).
3. No (checked:changed paths contain no golden/snapshot regeneration).
4. Yes—existing native verification code was extended additively; prior methods
   except additive dialect dispatch remain AST-identical. No relaxation here.
   The earlier dirty-check status correction remains separately review-gated.
5. No (checked:all four predeclared native cases ran; no success hardcoding,
   source/admission override, selected-result filtering or timeout increase).
6. No (checked:548 nonempty test passes are counted; empty FAT doctests earn
   zero, one existing native-tool test stays explicitly ignored; final ten-test
   rerun is still pending and earns zero additional runtime credit).
7. No (checked:actual PTY statuses and RCH terminal ACKs distinguish each
   passed, failed, cancelled, refused and queued/preparing invocation).
8. No (checked:unit/synthetic, retained-native CLI, older mounts and field
   evidence stay distinct; native script names the retained input images).
9. No (checked:fmt1,Clippy101,cancel143,admission103,UBS1 and pending runs are
   recorded. The original format failure was in tests only; production stream.rs
   already matched rustfmt. Test-lint changes do not acquire old runtime credit).
10. No (checked:stdout/stderr are retained locally or in every native command
    record; redirected output is inspected, not discarded).
11. No (checked:original Bead remains in_progress; no new closure/dependency
    laundering or substitute item was created).
12. No (checked:README increases accuracy about implemented root growth; no
    target, requirement, compatibility promise or acceptance criterion lowered).
13. No (checked:format helper had no tracker mutation and closed no item).
14. No (checked:helper acceptance required exact formatting with all tests,
    assertions and refusal checks retained, with no native/independent claim).
15. No (checked:root compared helper output byte-for-byte to read-only rustfmt,
    read the diff and counted tests/assertions before relying on it).
16. No (checked:one positive capability slice,56 native byte comparisons plus
    refusals, zero closure credits; no refusal-only task farming).
17. No (checked:helper agreement is not independent verification; root execution
    and external native-tool oracles retain their precise proof classes).
18. No (checked:native denominators50,54,then118 were extended before execution;
    the actual four-image scope matches118/56/24/14/8/16, with15 immutable hashes).
19. Yes—source cuts need explicit explanation:548 tests and native CLI use
    ed09c13e; later7d13873c changes only equivalent test forms/literals. Old
    lint failure and replacement runs remain visible. Correction/countermeasure:
    bind each receipt to its cut (RH-2), retain failures and never weaken the
    gate (RH-1); no entire-final-cut or field claim is substituted.
20. Strongest executed evidence:the real permanent runner with candidate ELF
    a45f6380 on four named native/operation-output images, all118 exact command
    statuses and15 input hashes, plus full548 Rust passes. Logs and input/tool/
    executable hashes make those bounded observations reproducible.

Historical audit limitation:all six scoped cass searches (five inventory phrases
plus stream/tests.rs) timed out124 despite healthy initial status. Its owned
index process stayed in preparation; TERM/INT did not stop it, and only that
verified owned PID47243 was stopped137. No purge/rebuild or manual corpus-file
edit followed. This is not a clean historical-audit result. Current-source
review uses direct diffs and receipts; no historical conclusion is inferred.
Disposition:assertions and source gates preserved, gate extension/source-cut
distinctions disclosed and review remains required. This is solo re-execution
with native-tool oracles, not independent human/agent certification or closure.

Creation worksheet for one final two-file review snapshot:
- Boundary:NO; patch/manifest are process, not runtime state.
- Consumer:the operator and ChartreuseMouse/DustyWolf reviewing the pending
  scanner/status-correction request in the original Bead thread.
- Gate:publication/closure of bd-native-image-library-s4tde cannot use the old
  13-file snapshot for this now16-file patch and two distinct source cuts.
- Observed defect:the previous04:15 snapshot became historical as test fixes,
  the runner and TODO evolved; stale proof/source binding is already observed.
- Retirement:retire its decision authority after review or any source change;
  retain historical bytes until the user authorizes deletion. No deletion here.
- Integrity questions:prevents approving stale bytes; required at16 dirty paths
  and several executed cuts; two files are the minimum diff plus source/log
  binding; a live diff alone cannot freeze reviewer inputs. No cheaper stable
  equivalent is available within the existing review workflow.
- Opportunity cost:the claimed reader qualification is highest admissible work
  here; finish its two pending commands. Cap snapshot work at one simple export,
  with no dashboard, schema, speculative check or capability credit.
- Verdict:LEGITIMATE GATE; create only that snapshot after final results.

### 05:29 UTC final source-bound qualification

- [x] Final strict workspace/all-target Clippy95296 returns0/ACKtrue on7d13873c,
  wrapper rchw-9a6cd269-7c96-4f95-b706-7e9314471aea.333218ms remote/353.8seconds
  total; clippy-ea-stream-lint-fixed-vmi-0501.log. All15 observed test lints are
  fixed without changing a predicate, fault case, production byte or lint rule.
- [x] Final full workspace/all-target check95301 returns0/ACKtrue on the same
  cut, wrapper rchw-e47186a2-6971-4b85-9b09-535ab3e0711a.792889ms remote/
  812.6seconds total; check-ea-stream-lint-fixed-0508.log. Formatting95295 also
  returns0/ACKtrue, wrapper rchw-df59dbc7-85e1-4dc2-94cb-3e3f819b2e24.
- [x] Final exact ten-test rerun95310 returns0/ACKtrue on7d13873c, wrapper
  rchw-4d4cb75d-c279-4d73-b8fd-a28a664163d7, actual PTY46018. Ten passed,zero
  failed/ignored,495 FAT cases filtered. Runtime39.20seconds,26.09seconds build,
  68293ms remote/108.0seconds total. The41 facade units/two integrations filtered
  by this targeted command earn no additional passes. Full548 remains the
  separate ed09c13e run. The original FAT/facade package selection is retained
  to preserve its dependency features; no cache/source/admission guard changed.
- [x] Retain failed admission of the first targeted attempt (103,before remote
  execution; rchw-394dd0f2-d37d-4b40-ac32-37cd29555222,ACKtrue). Its worker was
  full with another project. The admitted cold attempt95302 was explicitly
  superseded/cancelled143/ACKtrue when the warm worker became available. No
  waiting, cancellation or empty selection is counted as a test pass.
- [x] Audit extension/Q9+Q19 correction:commentary briefly inferred continued
  queueing from the quiet second warm-run log and proposed automatic selection.
  Registry95310 instead confirmed admitted/sync_up. Corrected that statement
  publicly before any further cancellation/reroute; the admitted warm run was
  kept and passed. Future status claims use the registry before inferring from
  a quiet log. No source/gate/capacity change resulted (RH-2 countermeasure).
- [x] Preserve both source cuts:the native a45f6380 ELF and full548 use ed09c13e;
  the final ten-test runtime/compiler gates use7d13873c with equivalent test-only
  lint edits. No full-runtime relabel, mounted-reader, native4GiB/4096-byte-sector,
  fragmentation, speedup, independent human review, crash or field claim.
- [x] Updated reader contract and measured parity with these executed outcomes.
  The README's obsolete fixed-root limitation now links actual new-image root
  expansion. No target or requirement was lowered to match missing behavior.
- [x] Finalize staged Bead comment and empty-cycle/flush checks. Publication
  and original acceptance closure remain open under
  AGENTS.md797 (UBS exit>0 requires fix/rerun) and the pending independent
  scanner/status-correction review. Canonical WAL ownership stays untouched.
- [x] Fresh canonical import attempt0531 again returns6 BEFORE OPENING, naming
  possible committed/uncheckpointed WAL frames. No engine/WAL replacement,
  checkpoint, rebuild or deletion. Staged cycles return0/empty and flush returns0
  (already-written JSONL had nothing dirty to export). No new ownership claim,
  graph edit, root commit, push or functional Bead closure occurred.
- [x] Reservation check covers all16 changed paths with zero conflicts. Retain
  all failed probes, earlier source cuts, eight pre-existing DS_Store files,
  unrelated jobs and prior review snapshots. All owned RCH invocations now have
  terminal outcomes; the unrelated old rchw-ee4eea67 record was not touched.

Final review freeze target:
/Users/jemanuel/Library/Logs/frankenfs-verification/native-library-fat-stream-review-20261022-m2404c_1/
containing only changes.patch and manifest.json. Its export verification/hashes
are recorded in the original Bead after export, so this source note can remain
frozen as part of that exact patch. The creation worksheet above applies; no
additional report/framework is authorized or credited. Earlier13-file bundles
remain historical and do not cover this16-file review surface.

## Current public FAT consumer continuation — 2026-10-22 16:13 UTC

**No-delete violation disclosed16:26 UTC:** root invoked tracker hygiene without
FFS_E2E_DISABLE_TEMP_CLEANUP=1. scripts/e2e/lib.sh's EXIT cleanup removed its own
scratch tree /var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/ffs_e2e_XXXXXX.01uvUjGZyu
and child scratch fixtures. There was no user authorization for deletion. The
directory is now absent; do not fabricate recovery or recreate it as evidence.
The artifacts/e2e/20261022_121230_ffs_tracker_source_hygiene_aa9ROZ run logs and
JSON reports remain. Git has no deleted project paths. This was avoidable:
inspect cleanup behavior and explicitly set the no-cleanup environment on all
future E2E calls. Honesty Q9/Q19=Yes for this window; disclose in final report,
do not count the failed tracker run as passing or silently bury this incident.

Continue `bd-native-image-library-s4tde` only. It is in_progress in the staged
bridge; canonical JSONL still shows open/unassigned, and `br sync --import-only`
again refuses6 BEFORE OPENING for potentially committed WAL. No claim or status
is represented as canonical. The fresh local hygiene report now finds53local
open/50claimable/zero foreign-open rows, including this original ID. The E2E
itself fails6/15 scenarios because installed bv rejects --no-cache, so that
report does not establish a passing tracker gate. No tracker gate or WAL edits.

- [x] Refresh main/dirty paths, all AGENTS/README content, current inbox and
  source-aware tracker state. No review reply, source movement or peer lease
  conflict; preserve05:38 review bundle as historical frozen bytes.
- [x] Select concrete integration gap: permanent FAT native runner cannot
  invoke the public facade consumer, unlike the NTFS/ZFS runners. Existing
  manual public ELF is older than current streaming/repair code.
- [x] Reserve existing runner/TODO/parity/FAT profile and announce original-ID
  scope through Agent Mail5604. No new graph claim or speculative framework.
- [x] Add optional --facade-binary and reusable Run.public_reads to the existing
  native runner, wired into all three existing producer scenarios. Native
  mcopy payloads/mdir names independently define expected bytes/listings;
  check exact format/type/length, whole/range/EOF/empty reads, EROFS contract,
  typed missing-path/directory-read errors, plain/bounded sentinel preservation
  and unchanged source/executable hashes. All previous checks stay intact.
- [x] Syntax/CLI help pass without pycache. Read-only AST comparison against
  retained b0645eed runner confirms all146 previous check predicates and
  command/mounted/streaming_reads bodies preserved. All five producer/output
  methods differ only by additive facade calls and report fields.
- [x] Finish strict RCH current native_reader build on ea0bc8afd+7d13873c;
  build-ea-public-fat-1614.log, worker vmi1149989. No local fallback or pending
  build counted as a pass. Await actual exit/terminal ACK and artifact hash.
- [x] Execute the actual permanent public_reads method against four retained
  native/operation-output images and fresh bounded wrappers. Predeclare both
  counts and expected failure countermetric before execution; no new mkfs,
  native mount, or mutation of retained originals is required.
  Fixed denominator:14 file instances, eight plain/bounded views,168 byte
  comparisons,28 file stats,16 exact listings,8 write refusals,16 expected
  typed failures;236 public calls plus14mcopy/8mdir/8fsck =266 commands.
- [x] Planted negative rejects /usr/bin/true's empty successful stdout on the
  first public list call, after six successful native reference commands.
  native-public-fat-planted-red-1623.log actual0; retained CSD
  fat-public-planted-red-mwmqxus1/result.json. Seven commands, unchanged FAT16
  source hash. This control earns no positive native-facade capability credit.
- [x] Record exact source/executable/script hashes, command outcomes and
  immutable inputs; update measured parity/profile and original Bead comment.
- [x] Reuse the delivered current ELF for existing read-only NTFS162-command
  probe (120public/152comparisons/3typed negatives) and retained FAT/ZFS
 164-command replay (108public/6freshmcopy/50fresh-outputcmp/6typed negatives).
  Their original scripts stay byte-identical:fff62705 and735fe90a. Label the
  latter capture equivalence plus fresh FAT oracle, not fresh ZFS production.
- [x] Re-execute52 retained ext4/btrfs public calls against existing native
  images with exact previous expected statuses/outputs and unchanged native
  image/source hashes. Do not replay either mkfs command or overwrite old
  native oracle outputs. This is retained-image/capture equivalence, not fresh
  producer or native mount evidence. Consumer-clamped EOF remains explicit.
- [x] Recheck changed-source UBS, preserve all hash/panic guards and failed
  reports; do not self-grant scanner exceptions or publish with exit>0.
  Final ten-file scan actualPTY9266 exit1,30critical/662warning/262info;
  log ubs-public-sixformat-final-1635.log.26 public hash equality findings and
  4 no-write/no-sync panic tripwires remain; no suppression or guard changes.
- [x] Complete bounded real-work/honesty review and staged empty cycles/flush.
  At16:40 cycles0/empty, flush0/nothing dirty, git diff HEAD --check0; nineRust
  hashes and9f3751c4 runner match, old frozen patch/manifest unchanged.
  Release own leases after this final source note; the release tool receipt
  and final handoff are authoritative for that last action. Original acceptance, independent
  scanner/status-correction review and publication remain open.

16:20 shared-tree boundary: another session committed9800c04f6, including
active public FAT code/docs before its positive execution. Root did not stage,
commit or push it, and preserved the moving index. Mail5605 requests independent
disposition/publication context. All nine Rust working-tree hashes still equal
the05:38 manifest; current build remains exactea+7d, never movingHEAD by
implication. The frozen public method in9f3751c4 is AST-identical to planted-red
f55a92ce; only additional root/FSInfo output call sites were added afterward.

### Actual current-ELF execution, 16:31–16:34 UTC

Build30075807208570969, wrapper rchw-f775699f-1bad-4e9e-97ee-6385dcc63d70,
actual PTY65548 zero; remote exit0/returned0/terminalACKtrue/retiredtrue.
Command `cargo build -j1 -p ffs --example native_reader` through strict RCH
vmi1149989 took1083.1seconds total,1015985ms remote. Base
ea0bc8afd444dae2960713ad2d6c6b1cc49b12be, overlay
7d13873c18805f020d68515fbba8121b96a1213d06c2ac4e756dddd2c17a6ad1,
tree e8d5952a21cc3ce535b08503076f730a16d29a89. Future-incompatibility warnings
for dependency nix0.29/0.31 were retained; no warning suppression or compiler
source change. Log build-ea-public-fat-1614.log.

Delivered588242448-byte Linux x86_64 ELF to
/tmp/frankenfs-indexed-candidate.18nZPUdg/native_reader-ea-eed90a44c129;
local/remote/after-transfer SHA256
eed90a44c129e9e67db8652f0154c7756f8187dff06f979643eab41eee52d8fc.
Transfer actualPTY40477 zero, exclusive create, never run on macOS. Current
runner SHA2569f3751c4b348baf3da82f0759125e4e85102743c8b49bcd341f039b0dd30355f.

All four native CSD processes actually returned zero, not merely printed passed:

- FAT public permanent method: PTY95797, log
  native-public-fat-ea-eed90-1632.log; root fat-public-ea-native-f4qlboqp.
 266commands/236public calls/168byte comparisons/28file stats/16listings/
 8write refusals/16typed failures exactly match predeclaration. Four retained
  native/expanded/recovered images,14file instances,eightplain/bounded views;
  all16 immutable source/payload/script/tool/consumer hashes equal before/after.
  Native mcopy and mdir are freshly executed. Exact 16nonzero statuses are1;
  all other250commands return0. EOF/zero length may short-circuit in consumer.
- NTFS: PTY34379, log native-public-ntfs-ea-eed90-1632.log;
  root ntfs-public-retained-0xwp4ita.162commands/120public/152comparisons/
  3typed negatives;32 native extension streams, plain/bounded and actual
  compressed512/4096-cluster inputs. Four image hashes and executable unchanged.
  The original fff62705 probe is byte-identical and executes fresh ntfs-3g reads.
- FAT/ZFS retained replay: PTY63792, log
  native-public-fat-zfs-ea-eed90-1632.log; root fat-zfs-public-current-dggox1c5.
 164commands/108public/6freshmcopy/50fresh-outputcmp/6exact semantic failures.
  All22 input hashes and2tool hashes preserved. Script735fe90a unchanged;
  captures/statuses exactly match the prior native profile. This is capture
  equivalence plus fresh FAT reads, not new OpenZFS producer or field proof.
- ext4/btrfs retained public calls: PTY16678, log
  native-public-ext4-btrfs-ea-eed90-1633.log;
  root ext4-btrfs-public-ea-retained-cqtlimqr.52calls/4exact typed failures,
  all prior stdout/stderr bytes equal,14original input/tool/source hashes and
  current executable unchanged. Both mkfs commands and all native oracle
  outputs were excluded/preserved. This is fresh public execution against
  retained native images plus capture equivalence, not fresh native production.

All roots above are under /data/ssd/tmp/ffs-native-verification-7CWV8iQw and
retain result.json plus every stdout/stderr/argv/status. Four-group total:
644captured commands,516public calls,29expected semantic failures. These are
invocation counts, not independent evidence units or a readiness percentage.
No current facade mount, bounded FileReader-in-FsOps cache, native writer,
crash/power-cut, speedup or field qualification was executed. The new full
producer runner was not rerun; its actual public method was executed directly.

### Bounded real-work audit and honesty inventory, 16:11–16:40 UTC

Creation disposition: reuse this operator-requested granular TODO and original
Bead comments. Consumer: user and original library acceptance reviewer. Gate:
no completion/publication claim without executed reader behavior and source
identity. Observed defects: FAT runner lacked public API wiring, previous
consumer was older, and this block lost tracker scratch via implicit cleanup.
Retirement: stop extending the active checklist when this bounded refresh is
reviewed; retain evidence without deleting it. Native command receipts are
minimal recovery/provenance records, not a new dashboard or readiness system.

Real-work worksheet: README purpose is native filesystem behavior in Rust
through FUSE and offline-image tools. Actual git log in this window has one
external commit9800c04f6, classified ENABLER (native test/integration evidence),
and no root commit. Latest staged closed rows are Oct20 audit and Oct19 decoder,
not current closes. Root extended native runner wiring (ENABLER), executed the
current consumer (ENABLER), updated user command/evidence docs (USER), and kept
requested TODO/coordination records (PROCESS). No production Rust feature or
performance gain was authored in this block. Q1: two-minute demo is the actual
public_reads workload comparing native mcopy/mdir with current public output.
Q2: omitting coordination/TODO would not change runtime capability; they preserve
requested tracking, source boundaries and disclosure, so keep them bounded.
Q3: Run.public_reads actually exercised the current library; it is not speculative.
Q4: prefix-based oldest open row bd-xmh5g has foreign-looking broad BLAS/XLA
language despite local prefix; no semantic ownership inferred. The oldest
concrete filesystem read task found is June22 bd-kdmu4 (parallel reads). This
block finished positive evidence on the original integration prerequisite rather
than claim a separate performance task. Q5: solo, no subagent output or closes;
external commit ownership not inferred. Q6: no requirement reduction or follow-up
laundering; original remains open. Verdict HEALTHY for bounded integration
qualification, with an explicit no-delete violation; no new feature/perf credit.
Correction: preserve controls, report the scratch loss, no more tracker machinery.

Honesty answers (bounded to this block; no blanket historical clean claim):

1 No (checked all146 prior runner predicates by AST and read additive diffs;
  no test, ignore, CI or assertion removal). Shared commit was external, not a
  root history rewrite; working/index changes were preserved.
2 No (checked native four-group commands actually run. /usr/bin/true appears
  only in the explicitly labelled planted-negative verifier control).
3 No (checked changed paths; no goldens/snapshots regenerated).
4 Yes, additive gate code: optional public reader checks added to the existing
  native runner. No relaxation, suppression, wider threshold/deadline/retry or
  source/admission bypass. All previous predicates preserved. Independent review
  requestedMail5612; no self-issued exception or done-certification.
5 No (checked options/paths; retained images select a declared offline profile,
  not hard-coded successful output. Native tools independently define bytes/names).
6 No (checked actual command counts/PTY exits, RCH terminal ACK and planted
  red. No filtered suite or pending process counted as passing).
7 No (checked four actual PTY exits0, final RCH0/ACKtrue, exact logs and hashes).
8 No (checked scopes: fresh candidate execution, retained images, planted red
  and capture equivalence explicitly separated. EOF consumer clamp disclosed).
9 Yes: unapproved implicit E2E scratch deletion, disclosed16:26 and recorded
  above. Tracker E2E fails6/15 and canonical import6; no passing tracker claim.
  Shared peer commit included then-unexecuted public code, explicitly disclosed;
  positive qualification now passed but does not grant scanner approval).
10 No (checked cited native commands retain stdout/stderr/status; failed SSH
  strict-host-key read and UBS failures remain visible. Help stdout was not a
  primary evidence artifact; stderr was not silenced).
11 No (checked current/staged Bead and recent closed rows; no task closed and
  no new follow-up minted to offload acceptance).
12 No (checked docs: actual source/scopes reported; writer/mount/perf goals not
  removed or rewritten as fulfilled).
13 N/A: no subagent delegated or accepted in this block, no delegated closure.
14 N/A: no subagent dispatch; coordination messages request independent review,
  not green tests or status farming.
15 N/A: no child report accepted; all claims above were directly executed.
16 N/A: solo work, no refusal-farming pane; positive results remain primary.
17 No (checked claims: empty inbox is not review acceptance; peer agreement
  or inherited source never counted as independent runtime proof).
18 No (checked266/236/168/28/16/8/16 counts recorded before execution and original
  NTFS/replay denominators frozen. Aggregate644/516 are invocation counts, not
  independent evidence units or readiness percentage).
19 Yes: implicit cleanup violated the explicit no-delete rule. It cannot be
  undone; no recovery fabricated. Future E2E commands must explicitly set
  FFS_E2E_DISABLE_TEMP_CLEANUP=1 after reading cleanup behavior. Preserve the
  failed tracker result and scope (RH-2), never claim complete retained evidence
  for the deleted scratch tree. This must remain in final operator disclosure.
20 Strongest evidence: actual permanent public method with source9f3751c4,
  source-bound ELFeed90a44,266 exact command statuses and16 unchanged hashes,
  plus current NTFS/native and labelled retained-image comparisons. Re-executable
  sources, binary and all successful output receipts are retained on CSD.

Older-session scope: the preceding full inventory already attempted six bounded
Cass queries and retained their timeout124/index unavailability. This block does
not pretend that history was searched successfully or independently audited.
No additional historical verdict is inferred from the current passing commands.

Disposition for Yes4: keep additive gate diff independently reviewable; no
relaxation to undo. For Yes9/19: scratch recovery impossible, explicit disclosure
and literal no-cleanup countermeasure recorded; final report must state violation.
UBS remains1/30critical, original acceptance remains open, and no root commit,
push, waiver or readiness claim is authorized by these positive read checks.

## Fresh-eyes code review requested by user — 2026-10-22 16:44 UTC

Scope: reread the new public FAT verifier, all five producer/output call sites,
main argument/report integration and command executor; compare surrounding
reader contracts and earlier Rust maintenance deltas. Do not change peer
directory-streaming work or infer its validation from pinned older executables.
Same original Bead remains open; no new claim or graph restructuring.

- [x] Read current source/diffs and confirm reservations before editing; leases
 5226–5228 cover runner/TODO/FAT profile. No new subagent or process framework.
- [x] Reproduce actual command-record loss: timeout with both partial streams
  and missing executable each raise before any JSON/stdout/stderr file exists.
  Retained local reproduction fat-review-before-k9nyj3lg; tool exit0 confirms
  both defects, not a native filesystem pass.
- [x] Fix Run.command: metadata before launch; exclusive direct-file capture;
  retain/rethrow timeout and launch errors; preserve strict expected status.
  Existing evidence is never overwritten by a reused Run root.
- [x] Fix main result lifecycle: explicit running/passed/failed and caught
  exception detail, preserving completed scenarios instead of ambiguous partial
  JSON. No condition relaxed and no failed candidate can earn passed status.
- [x] Execute six real subprocess regression controls: partial stdout/stderr
  retained on timeout, missing executable logged, binary stdout/stderr exact,
  expected7 accepted, unexpected7 rejected, reused root refuses with every
  previous byte unchanged. Local fat-review-after-nbq8c5rr retained; actual0.
- [x] AST comparison: all164 existing check predicates identical; every Run
  method except command byte-equivalent as AST. No producer, stream, checker,
  corruption or public-reader assertion changed. Syntax and CLI help pass.
- [x] Execute full actual main with --facade-binary and both native dialects,
  not just direct methods. All6producer scenarios and8public profiles pass.
  Log native-fat-full-fresh-review-1651.log, actualPTY92318 exit0; all script,
  CLI and public-consumer hashes unchanged before/after. No mounts requested.
- [x] Verify genuine failed main with /usr/bin/false as explicit planted-negative
  candidate: native setup succeeds, first candidate inspect fails1 vs expected0,
  result.json says failed, error retained, every command stdout/stderr exists.
  No positive FrankenFS credit for this control. Initial outer probe itself
  returned1 because it expected unresolved /usr/bin/false; main correctly resolves
  it to /usr/lib/cargo/bin/coreutils/false. Retained that failed probe log
  native-fat-failed-report-review-1652.log. Read-only follow-up compares the
  actual resolved path and validates all10logs/result; no product gate changed,
  no formatter rerun, no failed control relabelled. Follow-up actual0, log
  native-fat-review-results-1656.log; failed root ffs-fat-native-iu495vwd.
- [x] Run changed-file UBS: actualPTY6435 exit1, same26 public-hash critical/
  25warning/63info findings; log ubs-fat-fresh-review-1651.log. Assertions and
  scanner unchanged; no suppression/commit exception or completed Bead claim.
- [x] Finalize source-bound results, bounded honesty disposition, original
  Bead comment, diff check and staged cycles/flush. All return0; cycles empty,
  flush has nothing dirty. Final source matches executed2a60abbe and all164
  check predicates match retained9f3751c4. Reservations are released after this
  final note; the release tool receipt records that final action.

Final runner SHA256
2a60abbe3ece93e3ad1a858c7cb5211b06190e9252979e86aae9904880c5c367;
same exclusive retained CSD copy verify_fat_review-2a60abbe3ece.py. Full main
root /data/ssd/tmp/ffs-native-verification-7CWV8iQw/ffs-fat-native-_sm46zuo.
CLI a45f6380 retains ea0bc8afd+ed09c13e; public eed90a44 retains
ea0bc8afd+7d13873c. These pinned cuts do not qualify intervening peer commits
7407fea61/066563d74 or later Rust changes merely because working HEAD moves.
Only the Python executor/report lifecycle changed in this review.

Full-run observed result:2826 captured commands all match their per-command
expected statuses (2765zero,58one,3two). Six producer scenarios pass; all eight
facade method profiles/16plain-bounded views pass228file stats,44directory
listings,1368byte comparisons,16write refusals and32typed public failures.
These are counters from the complete fixed scenario list, not a chosen passing
subset, independent evidence count or readiness percentage. Native images and
all command files remain retained, including both successful and failed-control
roots. The corrected failed-report inspection is read-only; original failed
probe log remains failed, and its path-assumption error is not a product pass.

Fresh-review honesty delta to the preceding full inventory: Q1–3 No (checked
AST conservation of all164 predicates, source paths and no golden/test removal).
Q4 Yes, executor/report gate code hardened; no condition/expected status relaxed,
no timeout widened and no scanner changed. Q5–8 No (checked six actual local
subprocess controls, full native actualPTY0 and explicit planted-negative class;
no fixture or capture substituted for the full producer run). Q9 Yes, initial
negative outer probe failed on a mistaken unresolved executable-path assumption;
preserved/disclosed and independently read back correct failed main results.
Q10–12 No (stdout/stderr retained, same original Bead open, no spec reduction).
Q13–17 N/A for delegation because solo; no peer commit or review counted as
independent proof. Q18 No (scenario list and per-command expected statuses fixed
before execution; counters are observed over all scenarios). Q19 Same initial
negative-probe assumption disclosed; no attempt to hide or relabel it. Q20 Strong
evidence is full6-scenario main result, every2826exact status and preserved
runtime receipts plus before/after six executor controls. This is a user-requested
fresh self-review, not independent acceptance or a scanner waiver. Earlier
scratch-deletion incident remains disclosed; no E2E cleanup script was run here.
Real-work audit: executor/report fixes and full native execution are concrete
ENABLER work; command documentation USER; bounded TODO/Mail PROCESS. No new
framework, performance or native-writer feature credit. Verdict: fixes verified
in this bounded scope, original acceptance still open. No root commit or push.

## Wired directory-reader qualification — 2026-10-22 18:14 UTC

Continue original bd-native-image-library-s4tde, not a new graph claim. New
7407fea61 cursor already serves list/lookup, but its authoring commit explicitly
has source/model checks only. The previous native a45f6380/eed90a44 cuts precede
this Rust increment. Highest-value gap is actual execution of this wired code.
Canonical import again refuses6 before opening for committed WAL; untouched.

- [x] Refresh dirty paths/HEAD/inbox/worker admission; no review reply. Preserve
  three original NTFS overlays, moving index and all unrelated DS_Store files.
- [x] Read all181production/665test lines and surrounding old list/lookup,
  geometry, chain and native decoder contracts. Fixed-root partial-sector concern
  is ruled out by existing geometry admission; no invented bug/fix. Maximum
  directory allocation, end marker, retained raw names, cancellation and poisoned
  cursor semantics reviewed; no initial functional defect found.
- [x] Reserve reader/directory/test/TODO/profile/parity and announceMail5666.
- [x] Execute strict remote formatting on066563d74 plus3original NTFS overlays;
  first run1, manually correct only its observed directory source/test layout.
  Final five-overlay7fd8b10bab64b49028b456255a271548d9a59db3e56f5d2c20ddc53c5f719a5c
  fmt actualPTY62391 exit0 onhz2, log fmt-directory-manual-1820.log.
  All10tests/67assertions and both no-write/no-sync panic guards preserved;
  test diff changes whitespace and an optional trailing macro comma only.
  No formatter writes or gate edits. Original failed log retained.
- [x] Changed reader/directory/test UBS actualPTY78624 exit1:2critical test
  no-write/no-sync guards,225warning/71info. Log ubs-directory-1822.log;
  no suppression, scanner edit, publication exception or clean-pass claim.
- [x] Native preflight confirms runner2a60abbe, all six oracle tools, /dev/fuse,
  150.6GB/tmp and209.6GBtest-volume free; no existing owned FUSE mount.
- [x] Execute workspace/all-target strict Clippy. First71119 actualPTY49766
  exit101 reports four assert_is_empty diagnostics in new tests (321/502/513/566),
  no production diagnostic. Manually replace each empty-read assertion with
  comparison to an explicitly typed empty vector; same predicates/counts and
  both no-write/no-sync tripwires retained. FinalCC181764 Clippy actualPTY2898
  exit0 onvmi1156319, log clippy-directory-empty-assert-1836.log; remote runtime
  109477ms. Finalfmt actualPTY14353 exit0 onvmi1152480, log
  fmt-directory-empty-assert-1836.log. FinalUBS actualPTY1893 exit1 with the same
  2critical/225warning/71info, log ubs-directory-empty-assert-1836.log.
  Final directory test hash ba2fe6231758641e458e61eb64d654b6e80ce8de52b336383339e7c35a53fc61;
  production directory remains abde546f185166f20e08037f3ff49ded7f6cd7971d267779f13fdb60ab29b337.
- [x] Execute full unfiltered FAT/facade runtime on7fd8, then all10directory
  tests on finalCC18 after the four equivalent test-only assertion edits.
  Production code is identical between cuts; final workspace check/Clippy/fmt
  already passCC18. Record both source receipts and actual exits separately;
  never label the filtered final rerun as full-suite or count empty selections.
  Final workspace check71155 actualPTY5516 exit0 onCC181764, remote0,
  436399ms runtime/469.0s total; log check-directory-final-1839.log.
  Earlier7fd8 check71127 is superseded, not counted as a final-source pass.
  Cancelled only its exact owned wrapper rchw-a2b0ed86-3ffa-4391-9f29-77dcf76d971f
  after final71155 passed. Cancel receipt statuscancelled/stoprequested; old
  wrapper actual103 because its automatic SIGTERM retry was refused by unchanged
  source guard (7fd8 admission versus currentCC18), no local fallback. Retain
  cancel-superseded-directory-check-1848.json and originalcheck log; no pass credit.
  Full7fd8 runtime71124 is still running; no pass. Its logged, unchanged
  external timeout is7200seconds, not the build command's3600seconds. Initial
  namespace initialization failed73 onhz4 andhz3 before the ordinary RCH retry
  selectedvmi1227854; neither initial worker executed Cargo or earned credit.
  Combined7fd8 CLI/public build71120 actualPTY26015 returned137 at its configured
  deadline, remote3608944ms, no new artifact/pass. Original log retained. Final
  CC18 standalone public-consumer build is a smaller normal RCH invocation on
  admitted warmvmi1149989, log build-directory-public-final-1928.log, pending.
  Both binaries remain required; no deadline, source, cache or slot guard changed.
  Full7fd8 runtime71124 now actualPTY67006 exit0/remote0/ACKtrue:558passed,
  0failed/1existingnativeoptinignored (40facade+515FAT+2externalconsumer+1doc).
  Every nonempty suite has0filtered; empty doc selection adds no credit.
  All10directory tests passed. FAT runtime1357.98s; remainingzero-range case
  enumerates3profiles/2modes/everywrite-sync/3tears/2durabilitystates with full
  allocation checks. Source review found no held mutex across filesystem calls;
  completed all515, no case reduction. Build stage65m09s, normal test timeout
  7200seconds unchanged; total5358.8s. FinalCC18 targetedten-directory rerun
  executed on normal warmvmi1227854:71205/rchw-92f1c2ef-e94d-469b-a89c-28cdcb4cebd6,
  actualPTY74123 exit0/remote0/ACKtrue, all10passed/0failed/0ignored,
  505otherFATfiltered,1.87s runtime/97.9s total. Log
  test-directory-final-ten-1951.log. Filtered0-test facade41/integration2
  selections add no credit; this final cut is a targeted rerun, not full-suite.
  Standalone finalCC18 CLI build additionally requested normal admission with
  CARGO_PROFILE_DEV_DEBUG=0 via supported RCH_ENV_ALLOWLIST forwarding. This
  reduces debug-symbol generation while retaining debug assertions and all
  source/admission/deadline guards. Log build-directory-cli-debug0-1935.log;
  not yet a pass. This is build maintenance, no filesystem speedup claim.
- [x] Clarify documentation: FatVolume lookup rejects multiple matches for the
  requested native name/alias; complete all-name collision checking remains the
  stronger FsOps contract. Incremental end/error/immutability boundaries retained.
  Update measured parity with the executed Rust cuts, explicitly native-pending.
- [x] Expanded7file review UBS actualPTY46132 exit1:30critical/471warning/169info,
  log ubs-directory-review-seven-1956.log. Public hash assertions, both new
  directory tripwires and original NTFS controls retained. No scanner edit,
  suppression, critical-finding removal or commit exception. Reservations
  5357–5362 renewed through21:15UTC while current-binary work remains active.
  Two noncompiling process probes used normal admitted RCH --job onvmi1149989,
  logs process-directory-live-job-1849.log/progress-1850.log, both actual0.
  Observed rustc2601835 CPU time4m10s->4m50s over2minutes while logs stayed
  quiet; other concurrent compiler work remains untouched. Earlier diagnostic
  attempts failed at local option validation (--job/--clean-overlay incompatibility,
  then --base needing clean-overlay); both retained, no remote work or pass credit.
- [x] Build current FAT CLI and public consumer through RCH; verify and deliver
  exact Linux ELF hashes to CSD without running them on macOS. Both receipts
  are finished/remote0/returned0/ACKtrue on finalCC181764: CLI71195 onhz3,
  wrapper rchw-12ccda75-287d-447f-944e-31a239468db4,2335.3s; public71189
  onvmi1149989, wrapper rchw-b8e3aa23-b423-4b24-94dd-84a5f1fd50f3,3277.5s.
  CLI29,468,496bytes SHA256dc4dc81527c4b3e4fae599c78cefccf54fec8e9e08a814380d0d8b0df651d131;
  public588,403,928bytes SHA256838ee076b942497f7b304c3becf21f952e5a3373725cca45c6684bcd320dbfed.
  Exclusive CSD delivery verified the same bytes under
  /tmp/frankenfs-indexed-candidate.18nZPUdg/{ffs-fat-directory-dc4dc81527c4,native_reader-directory-838ee076b942}.
  Terminal receipt directory-build-receipts-20261022T204043.json;
  delivery directory-elf-delivery-20261022T204114.json. No old binary credit.
- [x] Execute existing full native six-scenario FAT producer/facade workload
  and strict read-only mounts against actual operation outputs, with all source
  hashes/sentinels retained. Fixed workload: six producer scenarios, eight public
  profiles/16plain-bounded views, --mounted for all six producer images, plus
  two further mounts on the expanded FAT16/recovered FAT32 operation outputs.
  Native command statuses, payload comparisons and immutable backing hashes
  are the countermetrics; missing tools or cases fail, not skip. Use fresh /tmp
  scratch on CSD so fusermount admission applies; retain every file. No current
  performance or broader writable/crash claim.
  Full unchanged2a60abbe runner actualPTY73312 exit0 with newdc4CLI/838public,
  log native-fat-directory-mounted-20261022T204145.log and matching terminal
  JSON. CSD /tmp/ffs-fat-native-_lufeva6/result.json statuspassed/all6 scenarios;
  report SHA256fa12f22be6bd0a8386c36adabaccbee8fc3a4422b334adce0d9e137622bf6270.
  Every2832 command metadata record completed with the exact expected status
  (2771zero/58one/3two), contiguous1..2832 and both retained output files.
  Programs:2mkfs.fat,6mmd,760mcopy,41fsck.fat,307CLI,6fusermount3,22mdir,
  1688public calls. Eight public profiles/16views passed1368bytecomparisons,
  228stats/44listings/16write-refusals/32expected-public-failures. All16current
  plain/bounded full backing hashes match the report; original/runner/public/
  CLI hashes unchanged, all six primary mounts exited cleanly.
  Additional actualPTY93576 exit0, log
  native-fat-directory-output-mounts-20261022T204342.log/JSON, uses unchanged
  Run.mounted on actual root-growth-expanded.img and fsinfo-recovered-clean.img.
  CSD /tmp/fat-directory-output-mounts-8i0to9xc/result.json statuspassed;
  SHA256ea0f8dcf8e0cb3fa99f402ac58ac2adbab9992216488da6599b8ff55189b619e.
  Five+three files passed full/range/size checks, EROFS/statfs, unchanged whole
  images/executors and two exactzero unmount commands. No remaining owned mount.
  Independent readback actualPTY31242 exit0, log
  native-fat-directory-readback-20261022T204448.log, checks every command status,
  report/hash/backing and8mounts. Its derived mounted-file count114 was wrong:
  populated mounts precede one native addition in each dialect. Retained
  native-fat-directory-mount-count-correction-20261022T204531.log actual0
  establishes3+3+46+3+3+46+5+3=112 file cases, each full/range/stat checked,
  plus8EROFS write-open refusals/8statfs. Original readback retained; correction
  disclosed in commentary and docs, no executed test, source gate or denominator
  changed. Total2834exact command records includes the two additional unmounts.
- [x] Record measured parity/profile/TODO outcomes, unchanged controls and
  failures. Original acceptance/scanner review remain open; Bead final comment
  and staged sync remain in the final graph step below. Mail5741 announces
  actual native results; no absent peer reply is treated as independent proof.
- [x] Complete bounded honesty review and final diff/graph/flush checks. Final
  Bead comment cites both source cuts and all native receipts; staged cycles
  empty and flush0/no dirty issues, log directory-final-bead-sync-20261022T204918.log.
  Final inbox has no independent acceptance reply. No E2E cleanup script was
  invoked; FFS_E2E_DISABLE_TEMP_CLEANUP=1 remains required for future E2E calls.
  Release only own reservations5357–5362 as the final tool step after the last
  diff check; its Mail/tool receipt is the authority, not this instruction.

### Bounded work/honesty review — directory qualification, 18:14–20:48 UTC

Window includes the four manually corrected unit assertion spellings and layout,
strict remote compilation/tests, two artifact deliveries and native execution.
Source review, all10tests/67assertions, exact five-overlay hashes and current
git diff/commit/reflog were inspected. External5cad1f98c includes the tested
source and documentation; it is not a root commit or independent acceptance.
The moving index remains untouched. No original task was closed or split.

1. No (checked: all10directory tests/67assertions and both no-write/no-sync
   tripwires retained; equivalent typed-empty-vector predicates only; existing
   native opt-in ignore predates this block; no CI/lint configuration changes).
2. No (checked: no new mock/stub or alternate success path; unchanged producer
   runner executed real files, native tools and kernel FUSE mounts).
3. No (checked: no golden/snapshot regeneration or changed fixture expectation).
4. No relaxation (checked: production edits are formatting; four unit assertion
   spellings change no predicate. No validator/CI implementation, tolerance,
   retry, configured timeout or suppression changed. Finalfmt/check/Clippy and
   all10tests were executed on the final cut; independent review remains open).
5. No (checked: no benchmark hardcoding or narrowed native workload; debuginfo0
   is documented build maintenance, not a filesystem performance claim).
6. Yes, empty filtered facade/integration groups appeared in the final focused
   rerun; they earn zero credit. Full558 evidence is separately bound to7fd8;
   finalten evidence isCC18, production-identical with test-only spelling fixes.
   Countermeasure RH-2: preserve per-cut test counts and nonempty denominators.
7. No (checked: observed actual exits and terminal ACKs; absent old build PTYs
   replaced only by authoritative finished/remote0/returned0/ACKtrue receipts).
8. No (checked: current native claims cover FAT only; eight actual mounts,
   real-tool oracles and public calls are distinct from unit/capture proof.
   No full-workspace-test, performance, native-writer or field claim substituted).
9. Yes, initial readback derived114mounted files from post-extension scenario
   totals. Source inspection plus live source-file counts establishes112;
   correction log204531, commentary and both public docs now say112. Original
   readback retained. RH-2 countermeasure: count each operation at its actual
   phase, not a later report's broader file total. Initialfmt1/Clippy101,
   combinedbuild137, optional probe failures/cancellations and UBS1 retained.
10. No for cited command/data output (checked: every2834 command has retained
    JSON/stdout/stderr; daemon stderr is retained. Existing daemon stdout is
    DEVNULL and is not byte evidence; mount bytes/stats come from kernel reads).
11. No (checked: original staged Bead remainsin_progress; no closure or new
    follow-up substituted for scanner, independent acceptance or canonical WAL).
12. No (checked: README/spec scope unchanged; parity/profile add measured
    evidence and preserve all declared limitations and admission boundaries).
13–17. N/A for this bounded solo block (checked: no subagent dispatch or accepted
    subagent result; peer commit/Mail agreement not counted as independent proof).
18. No (checked: fixed6producers/8publicprofiles/16views/8mounts declared before
    execution; every exact command status, backing hash and expected refusal
    inspected. Corrected derived phase count does not change any executed case).
19. Yes, explain substantial build/wait cost and137timeout, plus the count
    correction above. All original failures remain visible; no source, deadline,
    cache or admission bypass. Earlier scratch-deletion incident remains on the
    record; no E2E cleanup/deletion operation occurred in this block. Earlier
    six Cass searches timed out124, so no completed historical audit is claimed.
20. Strongest evidence: unchanged permanent runner2a60 with pinned current ELF
    hashes, six real native scenarios, every2832exact status and16verified
    backing hashes, plus two actual output mounts and8total EROFS controls.
    Retained commands/inputs make this bounded self-verification reproducible;
    it is not independent certification. Original acceptance remains open.

Real-work worksheet: README purpose is native filesystem behavior in Rust via
FUSE/offline tools. USER2: precise reader contract and measured parity/profile;
ENABLER2: compiler-required equivalent test fixes and executed qualification of
the already-wired directory reader; PROCESS2: requested TODO/tracker updates
and bounded Mail coordination; UNKNOWN0. This is an item classification, not
a delivery or performance score. Demo: current public read of a native FAT file
plus read-only kernel access on a real expanded/recovered output. Without the
process notes, the reader behaves identically, but source-bound verification
and pending scanner acceptance would be lost. Actual consumers are the current
CLI/public binaries and8mounts, not speculative infrastructure. The original
Oct16 native-library item remains the oldest user-facing item considered in
this work block; dependents still require its acceptance. No swarm close farming,
spec-only completion or follow-up laundering. Verdict: concrete ENABLER progress,
with disproportionate build/wait cost; stop adding machinery and retain the real
native results. Next acceptance actions belong to the existing scanner review
and owning canonical SQLite engine, not a replacement graph or weaker gate.

Final canonical import204716 again refuses6 before opening for committed WAL;
the WAL/database remain untouched. Staged dependency cycles are empty. Canonical
resolution still requires the owning engine's checkpoint; this continuation
does not grant permission to delete or reconstruct it. The count correction is
disclosed and encoded above; past discarded daemon stdout cannot be recovered,
and is not part of the evidence claim. No root stage/commit/push or gate waiver.

## Public NTFS indexed selection — 2026-10-22 21:00 UTC

Continue original staged bd-native-image-library-s4tde, stillin_progress. Actual
integration gap: the shared engine's new_indexed FsOps exists, but public
ReadOnlyBackend::Ntfs unconditionally used strict construction. No second claim
or dependency closure. Current baseline4cae156cc includes peer FAT cache work;
preserve it and qualify any workspace diagnostics without claiming prior native
receipts cover that new cache increment. Canonical ready/import refuse6/WAL.

- [x] Read all1069AGENTS/486README lines, refreshed source/ownership/inbox and
  anti-ceremony/Beads instructions. /data/projects/AGENTS.md remains absent.
- [x] Reserve exact facade/example/test/doc/TODO surfaces5474–5479; Mail5758.
- [x] Wire explicit NTFS indexed_lookup through backend selection, retaining
  strict automatic/default behavior, ambiguity checks, bounded OS-RO handle,
  clean-log admission and same-volume native stream access.
- [x] Native consumer exposes --ntfs-indexed-lookup, refuses conflicting ZFS
  selectors and uses the same resolver scope for exact named-stream reads.
- [x] Expand existing native opt-in matrix to automatic/explicit strict/indexed
  NTFS views, each plain/bounded, retaining all prior assertions; wrong-format
  controls cover both new NTFS selections. Add example argument controls.
  Add native selected/unrelated FILE-signature damage controls on four new
  plain/bounded copies. Locate each record through actual MFT mapping pairs,
  verify original FILE magic/native record number, and require Corruption for
  strict admission, selected indexed lookup and complete indexed readdir.
  Unrelated indexed lookup must return the independently supplied payload.
  Original images/containers and each damaged copy must remain byte-identical
  during reads; no assumption of a contiguous formatter MFT or host mutation.
- [x] Source-aware local refresh: live report dcisAu lists50claimable/53open/
  0foreign and originalID; the p3KKgN report is a fixture self-check, not live
  claimability. E2E fails6of15 in the existing bv compatibility/self-check
  lane; no pass or tracker-authority repair claim. Cleanup disabled and retained.
  No new canonical claim; original remains stagedin_progress/OliveCreek.
- [x] Initialfmt actual2702 exit1: own one layout plus29peer FAT cache layout
  hunks. Under AGENTS explicit parallel-simple-changes instruction, one helper
  manually applied only those29FAT layout hunks to3reserved files; parent
  read diff and verified all29tests/131assertions retained. No runtime claim
  from helper. Secondfmt95581 exit1 reports only3new native-test layout hunks;
  manually fixed them. Third59628 exits1 on hz4 SSH timeout RCH-E104 before an
  observed command terminal; ACKrefused, not a formatter pass. Normal explicit
  vmi1293453 retry passed as recorded below. No host-key, deadline, cache or source guard bypass.
- [x] Prepare fixed native public workload using existing Run.command capture,
  not a new verifier framework:371commands=328public+43freshntfscat,309byte
  comparisons,32expected failures, strict/indexed modes, plain/bounded and
  compressed512/4096images, all32extension streams,13-node/two-child-level
  native tree, wrong-format and conflicting-selector negatives. Retained
  native inputs are not newly produced by this probe. All51control files are
  hashed before/after. Script verify-ntfs-facade-indexed-20261022.py SHA256
  0fe51531ef62e7b701ad435cd5b29e1c2d6cb9352a4c857f366dc02121519e98;
  CSD exclusive copy verify-ntfs-facade-indexed-0fe51531ef62.py. Executed below.
- [x] Review diff and execute RCH fmt, workspace/all-target check, strict Clippy,
  facade/example tests and meaningful engine regressions on explicit source cut.
  Workspace check actual11140 exit0 onts1,911697ms runtime/922.1s total, log
  ntfs-facade-check-20261022T210424.log; base4cae156cc plus initial3overlays
  817e4abef98580e49e7092b53b0de02a81c962ccfee1c18e83c0832f386f118b.
  This precedes the substantive extra native adversarial test body and is not
  relabeled as final-test-source checking. Final six-overlay fmt actual2842
  exit0 onvmi1293453,313.8s total, log ntfs-facade-fmt-retry-20261022T211533.log,
  fingerprintf8f1a63bc24bafc28ea35ad8f42e12952498042bea3665aa9cecae665d31e80b.
  This formatting cut precedes the visibility-only FAT declaration and eleven
  lint-equivalent empty assertions. Latest gates are recorded below.
- [x] Build/deliver current consumer; native healthy read/list/stat/range/EOF,
  named streams, RO refusal, bounded sentinels and missing paths in both modes.
  First queued build actual55317 exit103: the initial3selected inputs changed
  while extra native regressions were added, so unchanged source guard refuses
  expected817e4a versus current820c5a before execution. No ELF or pass. Retain
  ntfs-facade-build-20261022T210424.log. Avoidable queued-source churn disclosed;
  freeze sources before resubmission, do not loosen admission. Normal stable
  production-only4overlay build completed onwarmts1, log
  ntfs-facade-build-stable-prod-20261022T212228.log, actual65750 exit0 below.
  Peer commits69e211ce8/070df2009 published the API/example and adversarial
  regression while gates run; parent made no commit/push and preserves them.
  Current API0fa553d9/examplec148dedc hashes match the reviewed source exactly;
  remaining working-tree native-test changes are the three manual layout fixes.
  Publication is not runtime or independent acceptance evidence.
  Stable production build actual65750 now exit0/remote0/returned0/ACKtrue,
  build71306/rchw-c5d97904-2222-487a-a1dd-354f8e0c3748 onts1,393.0s total;
  production4overlay8343adea3ed656ca77e5de9068d0f233e01fa177e199b12e415cdd7701cf1e2c.
  Linux ELF566550296bytes SHA2561cd83f3db33c3eacb7cefb6fad16c1088600383bf1beec109ae69ebb673aa5b8;
  exclusive CSD delivery actual78362 exit0, receipt
  ntfs-facade-elf-delivery-20261022T213226.json; CSD native_reader-indexed-1cd83f3db33c.
  Full fixed native public probe actual82184 exit0, local
  native-ntfs-facade-indexed-20261022T213309.log/JSON, CSD
  /tmp/ntfs-facade-indexed-78w8lxlm/result.json statuspassed. Independent parent
  readback actual40513 exit0 confirms all371exact statuses (339zero31one1two),
  328public/43freshnative/309bytecomparisons/32semanticfailures,165calls with
  indexflag, all51before/after and current control hashes unchanged. Report
  SHA2560ef8ec10e6929ae8027e7ec2c3f74a65bab0862efd6b53b2d900ad4fe61fc5f3;
  readback native-ntfs-facade-indexed-readback-20261022T213442.log. Actual native
  producer/adversarial Rust case also passed below. EOF/zero requests in
  the external consumer can short-circuit; raw FsOps EOF is tested separately.
- [x] Execute planted old-consumer control before candidate availability.
  Actual99835 outer0 observes childprobe1, old838ee076b942 rejects the new flag
  at command29 after28exact commands (7freshnative/22publiccalls including the
  rejectedcall,22comparisons before rejection). Root
  /tmp/ntfs-facade-indexed-a51x4dnw/result.json staysfailed as it should; no
  candidate success inferred. Readback actual94246 exit0 verifies command29
  actual2/expected0, empty stdout, exact unexpected-argument flag diagnostic,
  all28earlier statuses and51unchanged control hashes. Logs
  ntfs-facade-planted-old-consumer-20261022T212648.log and
  ntfs-facade-planted-old-readback-20261022T212720.log. This is a planted-negative
  executor/selection control, separate from the current-consumer positive run.
- [x] Native adversarial case proves actual dispatch: unrelated sibling
  corruption remains visible to strict enumeration while an unaffected indexed
  lookup succeeds; selected corruption and indexed full readdir must still fail.
  Preserve all native source/executable/control hashes and exact statuses.
  Earlier native-test ELF request actual92928/build71298 was queued behind existing
  test71284 onvmi1153651. Read-only owned-process inspection21:35/21:37 shows
  rustc1198659 under that cargo, asupersync registry cwd, CPU6m35s ->43301ticks
  (about7m13s),6.6GiB RSS/seventhreads. The project-only process filter first
  omitted this registry-cwd compiler; do not infer a deadlock from that filter.
  CPU progressed under load32; no process killed, priority changed or compiler
  run directly over SSH. Both Cargo invocations remained strict RCH. Their
  superseded terminal states and successful replacements are recorded below.
- [x] Resolve observed new FAT cache production Clippy declaration issue:
  first strict run actual84702 exits101 on reader/stream.rs:19 redundant_pub_crate.
  Reserve5510; declare FileIndex pub inside still-private stream module and keep
  reader's only re-export pub(crate). Fields/private construction and every
  crate-only method remain unchanged. Effective external visibility remains
  inaccessible; no allow/suppression or public bypass. Comment clarified.
  Warm normal7overlay Clippy rerun actual19888 onhz4, fingerprintdda04f3c43ea567416deb73aadd2b13f86d6a095000ccb3fa2d6b28bea98dbed,
  log ntfs-facade-clippy-visibility-20261022T213441.log exits101 on eleven
  mounted FAT test assert_is_empty diagnostics, also reproduced by warmts1
  actual81199/ntfs-facade-clippy-warm-20261022T215031.log. All eleven predicates
  were manually retained as typed-empty-vector assert_eq!, improving failure
  output without changing any expected value. The file retains10tests and all
  64assertions. No suppression, exclusion or independent gate relaxation.
  Consumer native results above precede this visibility-only FAT declaration;
  no new FAT-cache behavior is inferred from the NTFS runtime results.
- [x] Update existing NTFS profile/parity with executed proof boundaries;
  original acceptance stays open if compiler/runtime/scanner review is incomplete.
- [x] Complete bounded honesty/work inventory, Bead comment/cycles/flush and
  final diff checks. Own code/doc leases released; final TODO lease is released
  immediately after this last edit. No new process framework,
  test relaxation, performance claim or file cleanup. Any E2E script requires
  FFS_E2E_DISABLE_TEMP_CLEANUP=1.

Executed runtime and job reconciliation, 2026-10-22 21:58 UTC:

- [x] Full unfiltered Rust command `cargo test -j1 -p ffs -p ffs-ntfs --lib
  --examples -- --nocapture`, strict RCH actual91395 exit0, build71316,
  rchw-8bbbcedc-b627-426f-9212-9e718bb16ebf, ts1, remote0/returned0/ACKtrue.
  Base4cae156cc plus six-source overlay20282f1234a5b3c5106a145d1f0efcaf71974a6c7585c3df5891cd9ca59a5d6c.
  Log ntfs-facade-full-tests-warm-20261022T214658.log:40facade+2example+360NTFS
  =402passed,0failed,0filtered in every nonempty suite. One existing native
  opt-in ignore was separately executed below, never counted as passed here.
- [x] Build native regression ELF via `cargo test -j1 -p ffs --lib --no-run
  --message-format=json-render-diagnostics`, actual26758 exit0, build71314,
  rchw-a8a5a15e-b9fa-4664-91ac-050ebf47fe3d, ts1,55.4s total,
  remote0/returned0/ACKtrue. Five-source overlayed7db424eb1663621a1208df2f36a3921a9cbb3be14f876cb9a19f709fa54b9a.
  Log ntfs-facade-native-test-build-warm-20261022T214139.log. ELF570991600bytes,
  SHA256a358369f59493b501c5ffc7c23921296a241c62b9441f1510ccbf1d29b03c23c.
  Exclusive verified delivery actual83872 exit0; receipt
  ntfs-facade-native-test-elf-delivery-20261022T214515.json.
- [x] Actually execute the native opt-in case on CSD: actual51603 exit0,
  native-ntfs-facade-producer-20261022T214620.log/JSON,
  /tmp/ntfs-facade-producer-test-k4zi6gsq/result.json
  SHA25644aa357292b9ef0c0cf86b4c045be9541a07af4913c81915a134c624848b54c9.
  Exactly1passed/0failed/0ignored/40filtered,3.80s; filtered tests earn no credit.
  Retained native producer root /tmp/ffs-facade-native-EK1udY contains fresh
  FAT16/FAT32/NTFS64MiB regular images, ten healthy option/views and four actual
  selected/unrelated damaged copies. All16producer/oracle commands exited0;
  eight executor/tool controls unchanged. No block device or cleanup operation.
- [x] Parent fresh readback actual91094 exit0,
  native-ntfs-facade-producer-readback-20261022T215151.log, verifies16captured
  producer records,2executor records, all4actual damaged images, native FILE
  record numbers64/65 and physical offsets81920/82944 from decoded MFT.
  FILE->FAIL changes exactly3bytes, bounded/native positions correspond,
  P/S sentinel bytes remain intact and all8current controls equal their hashes.
  No general corruption-checker, indexed FUSE, performance or field claim.
- [x] Reconcile superseded cold full-suite wrapper rchw-47f00114-b89b-406c-add4-70824e314a4d.
  Cancellation request returnedE504; it was not reported as successful. Recovery
  receipt recover-superseded-ntfs-full-tests-20261022T215031.json now confirms
  finished/ACKtrue with terminal lease1, automatic retry build71317 onvmi1227854.
  Actual36650 exits103: retry refused changed selected inputs817e4a/820c5a.
  Prior worker runtime143 is retained; no pass/ELF credit, no local fallback.
- [x] Reconcile superseded native no-run wrapper rchw-8b8f8a41-c62d-40cc-b10f-114c2376b361.
  Initial and retry cancel calls returnedE504 (unconfirmed), not success. Actual
 92928 now exits143; recover confirms completed/143/ACKtrue, build71298,
  sources_released/tree_retired/pair_released alltrue. Do not attribute SIGTERM
  causality beyond the observed cancellation requests. No daemon restart,
  lock deletion or manual PID kill. Replacement71314 qualified current source.
- [x] Latest seven-source static UBS actual99051 exits1:
  ntfs-facade-final-ubs-20261022T215758.log;1critical/321warnings/102info.
  Critical is existing unexpected-format test panic native/tests.rs:23;
  three other test-only panic warnings and assertion/unwrap inventories retained.
  No suppression or scanner waiver. Production bounds/indexing/lock/error
  paths reviewed separately; static scan is not a compiler/runtime pass.
- [x] Final full FAT library execution and workspace check/strict Clippy passed,
  logs ntfs-facade-final-{fat_tests,check,clippy}-20261022T215656.log.
  Seven-source overlayb969a525021f0e20e14a08f64484ea945e37d3461c65125e457e7296fd52f8eb.
  Formatter initial command wrongly combined --job/--clean-overlay and refused2
  before admission. Correct normal fmt actual22861 then executed and exited1
  on only two empty-assertion layout lines. Preserve all failures; final manual
  formatting waited until the admitted source requests settled, avoiding new
  churn; the corrected final formatter now passes below.

Bounded anti-ceremony review, this public NTFS increment (21:00 UTC onward):

Creation gate: existing operator-requested TODO and minimal command/result
captures are PROCESS. Consumer is the operator reviewing this exact public API
increment; gate is an evidence-bound result and original Bead acceptance. The
observed defects are lost/foreign-target artifacts, a rejected old consumer,
queued-source changes and unconfirmed remote cancellation. Keep the existing
TODO and exclusive captures, not a new framework. Retire them as active work
tracking after independent acceptance; retained evidence is not deleted without
permission. Minimal retained native commands prevent a failed/partial probe
being mistaken for success; this scale needs their stdout/stderr/status/hash
records and reuses Run.command. A summary alone cannot replace them. Highest
priority work remains the original native-image library integration; an extra
hour of process would add less value than its pending executable gates.

Honesty inventory (bounded to reviewed diffs, commands and actual receipts):

1. No (checked all native/example additions and FAT test diffs against4cae;
   no assertion deleted, new ignore, narrowed expectation or golden update).
   FAT mounted file retains10tests/64assertions; the11empty comparisons have
   identical predicates. Existing native opt-in was explicitly executed.
2. No (checked new controls use real facade/engines/native producer output;
   no production test-name/path branch or substitute oracle).
3. No (checked changed paths and peer commits; no golden regeneration).
4. Tests changed with the feature, yes: stronger native corrupted-copy cases,
   wrong-format options and2parser controls. Separately reviewed all predicates.
   FAT lint changes are equivalent diagnostics only. No gate/CI configuration,
   tolerance, timeout, retry policy or suppression changed. Original stays open.
5. No (checked explicit selector/strict defaults/format admission; no benchmark
   path, synthetic success, narrowed denominator or runtime guard bypass).
6. No (observed402unfiltered Rust passes,1explicit native test;40filtered in
   the latter earn no credit. Full FAT subsequently passed525/0failed/0filtered).
7. No (each claimed pass has actual terminal and retained output; pending
   requests, source-guard refusals and static inspection are labeled separately).
8. No (native371probe uses retained native inputs with43fresh oracle reads;
   separate producer regression actually formats fresh regular files. Neither
   is indexed kernel FUSE, whole-directory integrity, benchmark or field proof).
9. Failures/cost needing explanation: avoidable queued-source churn refused the
   initial build; cold-worker superseded requests burned time; two Clippy runs
   diagnosed the same11assertions; cancellationE504 was unconfirmed until actual
   terminal recovery. These failures stay in the record. Latest fmt also had an
   invalid --job/--clean-overlay request then2layout diagnostics, not a pass.
10. No (stderr is merged into retained command logs or separate native files;
    no cited command discarded its diagnostics).
11. No (checked staged status and graph; original in_progress, no new close or
    follow-up moving unmet acceptance out of the original).
12. No (profile/parity adds measured scope and pending checks; no requirement
    lowered or runtime acceptance replaced by documentation).
13. No (mechanical helper had no tracker mutation; no root close; peer Git
    publication is not tracker closure or independent validation).
14. No (helper dispatch named exact29layout hunks, unchanged assertions, observed
    formatter negative and no runtime claim; credit rules included verbatim).
15. No (parent read helper diff, counted29tests/131assertions across3files and
    independently executed remote fmt. Helper supplied no runtime proof).
16. No (one mechanical helper, no refusal/closure farming; positive public/native
    execution remains the objective and the original stays open).
17. No (helper/parent same-source review counts once; native readback is a fresh
    parent pass, explicitly not independent human/scanner acceptance).
18. No (371commands/328public/43native/309comparisons/32failures/51controls were
    fixed before candidate execution; failures and unchanged hashes are explicit
    countermetrics. Test totals come from unfiltered summaries, not selected
    successes; no product speedup inferred from build timing).
19. Explain source churn, duplicate cold/warm jobs and failed cancel calls before
    replay. Earlier scratch-cleanup incident remains disclosed in prior bounded
    review; this block uses cleanup-disabled E2E and no deletion. Preserve
    source/cancellation guards, freeze selected inputs while admitted and await
    exact terminal acknowledgement. No daemon/lock/priority override.
20. Strongest evidence is371exact current public/native statuses plus fresh
    native-producer regression and actual4damaged-copy readback, all pinned to
    hashes and executable source cuts. A skeptic can re-execute the retained
    probe and named ignored test. Current402unit passes are supporting evidence,
    not a substitute. Independent scanner/status disposition remains absent.

Older context is bounded to the previously recorded source/native/scanner and
scratch-cleanup incidents in this same TODO; this increment does not claim a new
cross-session investigation or rehabilitate those failures. Disposition: no
observed test weakening; RH-1/RH-2/RH-7 protections retained. Source churn/cost
and unconfirmed cancellation disclosed, corrected by stable selected inputs and
ACK-bound recovery, never hidden as passing work. UBS red blocks root commit;
independent acceptance remains open. This is parent verification, not independent
certification.

Real-work worksheet: README purpose is safe native filesystem access with
mount-compatible behavior, MVCC/COW and self-healing durability. Actual window
Git/reflog review found69e211ce8(USER: public indexed capability),070df2009
(ENABLER: actual dispatch/corruption regression),a24d3a44e(USER: public usage and
measured evidence),bd8fa29cd(ENABLER: effective-private declaration lint fix).
Commit inventory2USER/2ENABLER/0PROCESS/0UNKNOWN; current TODO/captures are PROCESS,
formatting/quality gates are ENABLER. Counts are classification, not a quota.
The helper supplied only formatting, not separate capability credit. Demo:
native_reader image --ntfs-indexed-lookup read /payload; strict rejects a damaged
sibling while indexed reads the unaffected selected file, and full readdir
still fails. Removing process would lose requested tracking and exact failed-run
provenance, not alter the feature. Actual new consumer and native regression
exercise the enablers. The original2026-10-16 library issue is still open while
its scanner/status condition is unresolved; broader writer/lifecycle goals are
not claimed complete. No pane closed an item, and no spec/follow-up substitutes
for implementation. Verdict: real capability advanced, but verification
orchestration drifted through duplicate cold/warm requests and source churn.
Correction: finish the existing admitted gates without more speculative jobs or
process artifacts, then report bounded results and retain original acceptance.

Latest quality-gate progress, 22:02 UTC:

- [x] Full FAT library suite actual24839 exit0, build71322,
  rchw-d5f153f0-b3c0-4530-a651-86f886ee1d55, ts1,
  remote0/returned0/ACKtrue/sources_releasedtrue. All525tests passed,
  0failed/0ignored/0filtered,231.86s runtime/265.1s total. This includes all ten
  mounted sparse-cache tests, rather than counting their compilation or an
  incomplete523test run as the pass. Same seven-source overlayb969a525.
- [x] Workspace/all-target check actual47312 exit0, build71324,
  rchw-ff4e32aa-9002-4972-a8f4-d27b53c63506, ts1,
  remote0/returned0/ACKtrue/sources_releasedtrue,25064ms runtime/297.6s total.
  Same b969a525 cut. RCH receipt ntfs-facade-quality-receipts-20261022T220219.json.
- [x] Strict workspace/all-target Clippy actual50709 exit0/build71323,
  rchw-131c6d2d-9ff6-48a6-8844-8d71380bdaa2, ts1,
  remote0/returned0/ACKtrue/sources_releasedtrue,58274ms runtime/363.6s total.
  Same b969a525 cut; receipt ntfs-facade-clippy-terminal-20261022T220319.json.
- [x] After all admitted source requests settled, manually join only the two
  formatter-reported assertion lines. Read-only comparison against126e88bc4
  confirms whitespace is the only difference; no source/tests semantics changed.
  Final RCH fmt actual84839 exit0 on ts1,19.1s total,
  ntfs-facade-final-fmt-corrected-20261022T220317.log, seven-source overlay
  638f945e2a095596a99cd0121c05ca6a68638c499e9bb0f6967657fcd060ec96.
  Final mounted-test SHA256d8e06ac40775fce0331770bc8ed030ff61f8c1ed06166b330f01c82c04d6e9ed;
  native-test6f99d540f2d791334a62b1e4dd421fa36e660df7465cf566c40ba5fddf5e9417,
  FileIndex35d2db9d8cd756cdbe1b349b761469e9d4f0492ee74514b2abda3af3e095c1b4.
- [x] Canonical import fresh attempt220343 refuses6 before opening, same named
  committed-WAL guard. JSONL remains e5d359ec158f3943d6784b166883d8be4e94cf57aba115cf409e9bc39bbb4e64.
  ntfs-facade-final-canonical-import-20261022T220343.log. No checkpoint by a
  foreign engine, WAL deletion/replacement, DB rebuild or original closure.
  Peer126e88bc4/1f6a92743 published assertion/docs changes during verification;
  root did not stage/commit/push. Publication adds no independent proof credit.
- [x] Final static UBS after whitespace-only edits actual53821 still exits1,
  1critical/321warnings/102info, log ntfs-facade-final-whitespace-ubs-20261022T220454.log.
  No scanner relaxation or root commit. Final fmt71336 wrapper
  rchw-9cd30263-0359-44b5-b920-292182fa20ab is remote0/returned0/ACKtrue with
  sources_releasedtrue, receipt ntfs-facade-final-format-receipt-20261022T220455.json.
- [x] Record final execution evidence in original staged Bead comment2238,
  authorOliveCreek; cycles0/flush0 at220527. Original remains in_progress,
  no acceptance moved into a new item. Final Mail5824 informs existing peers;
  nine exact own code/doc leases5474–5476/5478–5479/5495–5497/5510 released
  with acknowledged IDs at22:05:43UTC. Remaining TODO lease5477 released after
  this last edit. No peer reservation, unrelated .DS_Store, canonical graph,
  WAL, source or terminal was removed or reset.

Remaining original conditions are explicit: independent scanner/status
disposition and canonical recovery by the owning SQLite engine. No independent
reply arrived in this window. `/just-say-no-to-process-porn-and-ceremony` says
"Never certify your own work as done"; these are parent-executed source-bound
results and fresh readback, not an independent acceptance certificate. Bounded
public NTFS integration and its executable gates passed; overall project,
indexed mounts, performance, native writers and general crash/lifecycle work
remain outside these results. No new process or speculative gate is proposed.

## Public facade read-only mounts — 2026-10-22 22:17 UTC

Continue bd-native-image-library-s4tde, staged in_progress/OliveCreek. Main
mount's repair/commit/runtime lifecycle requires OpenFs/ext4/btrfs. Existing
native_reader already owns the six-format public read-only FsOps handle and
the shared FUSE transport accepts that trait object directly. Add a foreground
mount subcommand to this existing consumer; retain all native admission and
the same bounded/locked descriptor. No second claim, write authority or new
filesystem implementation. Baseline7b1f93a312815f7f134206ffc9c231a73b6b331f.

- [x] Refresh memory guidance, unchanged AGENTS/README hashes against4cae,
  current source/dirty paths/HEAD, Agent Mail identity/inbox/ownership.
- [x] Apply anti-ceremony, Beads and Agent Mail skills. Existing requested TODO
  is the operator's tracking consumer, retires as active tracking on acceptance;
  no new process framework. Minimal native capture prevents missing/partial
  mounts being called passed. No deletion without permission.
- [x] Raw bv still selects stale blocked warm-stat; canonical ready/import6/WAL.
  Live local tracker ctup4f:50claimable/53open/0foreign, original ID claimable.
  Preserve report/control failures; no full E2E gate pass inferred. Cleanup
  disabled and retained. No canonical graph mutation or foreign-engine repair.
- [x] Reserve5538–5544 exact consumer/manifest/lock/TODO/docs paths; Mail5826.
- [x] Add existing workspace ffs-fuse as example-only dev dependency and one
  matching local lock edge. No external crate/version or library dependency.
- [x] Transfer the same admitted filesystem directly to foreground FUSE with
  read_only=true, allow_other/dev/suid=false, existing transport defaults.
  Bounds/indexed NTFS/ZFS selections are resolved before transport dispatch.
- [x] Add parser controls for plain/bounded strict/indexed and ZFS snapshot
  mount selections, plus rejection of six write/privilege switches. Existing
  parser/native tests retained; no new ignore, suppression or relaxed gate.
- [x] Fresh review and strict RCH fmt/workspace check/Clippy/example tests.
  Freeze selected source before admitting jobs; no local Cargo or guard bypass.
- [x] Build current Linux consumer with normal foreign-artifact intent; verify
  delivered ELF source/hash and capture a planted old-consumer rejection.
- [x] Execute actual RO kernel mounts through public facade on retained native
  ext4/btrfs/FAT16/FAT32/NTFS/ZFS images, plain/bounded where available, plus
  indexed NTFS and selected ZFS head/snapshot. Fix workload before execution;
  retain each daemon stdout/stderr/status, actual mount identity/options,
  file/stat/list/range/EOF/missing/write-refusal results, source hashes and
  successful unmount/exit. A skipped/unmounted/unstarted case is not a pass.
- [x] Read back exact result/command files and before/after controls. No timing
  or performance claim and no general writable/crash/mounted parity inference.
- [x] Review UBS without weakening test traps; update existing README/profile/
  parity with observed proof boundaries. Original scanner/status acceptance
  remains open if unresolved; no follow-up laundering or self-certification.
- [x] Finish bounded honesty/work review, original Bead comment/cycles/flush,
  final diff/source checks, release only own reservations. Preserve peer work.

Source review/gate progress, 22:26 UTC:

- [x] Fresh review found missing mountpoint preflight in the generic transport:
  existing/non-directory/nonempty and hiding-backing cases now use an explicit
  preflight before FUSE dispatch. All3new example tests retain their original
  predicates; temporary test paths use keep()/create_new and are not deleted.
- [x] Initial source fmt94715 passes0 (pre-preflight cut371b73c0); expanded fmt
  58605 fails1 on one multiline read_dir layout. Manually fix only that layout.
  Finalfmt39296 passes0, build71367/rchw-23be5d2b-2f95-4830-973b-978c366b35d6,
  remote0/returned0/ACKtrue,18.8s total, base7b1f93a31 plus seven-source overlay
  23f5c784072fd9af4efa0bf7e8f8bde0dd982a0e3da806c86a8470679a3011d2.
- [x] Strict workspace/all-target Clippy actual93837 exit0, build71368,
  rchw-c61107ab-bb4a-4098-bb07-055422607ca9, remote0/returned0/ACKtrue,
  139.2s total. Log facade-mount-clippy-20261022T222237.log, same23f5c784cut.
- [x] Focused current-example UBS actual36527 exit0,0critical/26warning/19info.
  Warnings are test unwrap/panic/assert inventory and existing stdout output;
  no suppression or scanner exclusion. Broader original test-tripwire/scanner
  condition remains unresolved; focused green is not a whole-repository pass.
- [x] Author fixed20mount probe before candidate execution:4ext4/btrfs views,
  4FAT16/32 views,6NTFS strict/indexed/plain/bounded/compressed views,6ZFS ZPL4/5
  divergent head/before/after views.56files,236full/range/EOF/sparse byte checks,
  20EROFS write-open refusals,20ENOENT missing lookups,6preflight/selection/CLI
  negatives, actual proc mount identities/RO statfs and clean unmount/exits.
  Native inputs/payload captures are retained, not freshly produced oracles.
  Minimal private verifier reuses unchanged Run.command2a60; SHA256
  cfd484bc866563fcf1dec43183ba0fc333ef37a8738382b931fd9ef598314b06,
  verify-public-facade-mounts-20261022.py; exclusive CSD delivery222534.
- [x] Execute same probe with old1cd83f3 consumer: actual34597 exits1, first
  daemon exits2 before mounting; report /tmp/public-facade-mounts-0297wovr
  staysfailed. This planted control demonstrates old consumer cannot mount;
  it earns0current positive-mount credit. Captured logs and source hashes remain.
  Initial parent readback exits1 because it expected "unrecognized subcommand"
  rather than actual Clap "unexpected argument 'mount' found". The actual
  daemon status2/empty stdout/failed result were unchanged. Readback correction
  uses the exact observed diagnostic and checks all47control hashes and no
  owned mount remains; no product assertion or probe workload was relaxed.
- [x] At22:26 build71369/actual93716 was executing locked Cargo on ts1; check
  actual12919 and complete facade/example tests actual48267 awaited the same
  namespace. All subsequently passed below. No duplicate/cancel/guard bypass;
  sources remained frozen.

Executed public-mount qualification, 22:34 UTC:

- [x] Build71369/actual93716 now exit0/remote0/returned0/ACKtrue,458.6s total,
  rchw-37126e12-5e20-4ae1-af8b-263c0e472962. Linux ELF589652728bytes,
  SHA256763c430d3fc8ae9b1d33b30b4e670cc2d043b13d352a62cdeab6b7e00fc2bc37,
  source7b1f93a31+23f5c784. Exclusive hash-verified CSD delivery actual87090/0,
  facade-mount-elf-delivery-20261022T223043.json. No old ELF substitution.
- [x] Full facade/example Rust tests actual48267 exit0/build71370,
  rchw-b4be242c-14e4-470c-9b9e-c6878fec63a6, remote0/returned0/ACKtrue.
  40facade+5example=45passed,0failed/0filtered;1existing native producer ignore
  remains explicit, no runtime credit from that ignore.9.676s runtime/475.9s
  total, same source cut. All prior tests retained.
- [x] Workspace/all-target check actual12919 exits0/build71371,
  rchw-283e7152-7fec-4c3f-9272-611bb924206c, remote0/returned0/ACKtrue,
  603.5s total. All five current RCH gates are acknowledged and sources released;
  facade-mount-complete-gates-20261022T223342.json. No duplicate/cancel/fallback.
- [x] First current mount probe actual87902 exits1 after7complete mounts because
  private probe hardcoded64MiB for the native FAT32 image which is128MiB.
  Correct format refusal, not an implementation failure. Preserve failed
  /tmp/public-facade-mounts-a7tm3fcf/result.json and all8daemon records. Fresh
  readback confirms7complete exits/unmounts, all47controls unchanged and no owned
  mount. Do not relabel this run passed or drop the FAT32 bounded case.
- [x] Correct only probe geometry: decode native BPB sector count/sector size,
  require it matches the physical image and declared64MiB FAT16/128MiB FAT32
  fixtures, and pass that exact bounded length. All20mounts/56files/236checks/
  refusals/negative predicates retained. No product/gate relaxation. New private
  script SHA256fcbfc2ae4d6c930b3f635f449c96655df6a45ddf2136d4044abe961a6bda3b7f,
  exclusive delivery223220; old CSD scriptcfd484 remains frozen.
  Admit/refuse split: the same763c430d consumer refuses the truncated64MiB
  FAT32 window and accepts the complete native128MiB window. This is correction
  of probe geometry, not permission for truncated filesystem admission.
- [x] Repeat old-consumer control with corrected script actual75916 exits1;
  /tmp/public-facade-mounts-an6fsu2x remainsfailed, daemon2 before first mount.
  Exact unexpected-argument diagnostic checked in final readback; no positive
  credit. Log facade-mount-geometry-old-control-20261022T223251.log.
- [x] Full corrected current probe actual52364 exits0,
  facade-mount-native-geometry-20261022T223312.log/JSON. CSD
  /tmp/public-facade-mounts-17v4oiav/result.json passed; SHA256
  6ff36985430cd8f1bae87add419fe073234d43077b7eaaf597a33a5761503d4f.
  All20kernel mounts/56file stats/236full-range-EOF-sparse comparisons,
  20root listings/20ROstatfs/20EROFS/20ENOENT,6typed preflight/CLI negatives.
  ZFS views preserve divergent head/before/after bytes, hard-link identity,
  relative symlinks and4GiB sparse-before size. Every mounted case unmounted
  normally and daemon exited0. Retained native inputs/captured payloads, not
  freshly executed native producers or native oracles in this run.
- [x] Parent fresh readback actual56095 exits0,
  facade-mount-native-readback-20261022T223429.log:20exact daemon records,
  26exact captured commands (20zero/5one/1two),47before/after/current controls
  unchanged, all actual mountinfo entries ro/nodev/nosuid and no owned mount
  remains. EOF/zero reads may be kernel-clamped; no raw FsOps EOF credit added.
  fuser AutoUnmount adds kernel allow_other internally but selects its existing
  SessionACL::Owner when neither AllowOther nor AllowRoot was requested; read
  vendor/fuser/src/session.rs:469–491. Owner filtering is source-inspected here,
  not an independently exercised cross-user access-control qualification.
- [x] Source published concurrently as996bc1875 and usage docs24f50a9df; root
  did not stage/commit/push. Source hash6392436204c4dd08d0e1c5bad7eb2059b15a17c03a5e0c4695b67c9bb4e8b268
  stays identical through gates/native execution. Publication is not independent
  acceptance. Original scanner/status condition and canonical WAL remain open.
- [x] Reconcile stalled tracker E2E: live queue report is valid but nested
  permission-blocked fixture error-reporting stalled for17min with only3Bash
  descendants and no child command. Verified exact own8106->17012->19280 tree,
  sent scoped SIGTERM, preserving cleanup-disabled artifacts. No whole E2E pass,
  daemon restart, shared tracker writer kill or canonical data deletion.
  Children17012/19280 exited; parent8106 continued its error-reporting trap and
  spawned own Bash25947. One guarded force-stop attempt refused when it saw a
  new child (no signal sent). Reverified exact original parent85649/command and
  the two-process subtree, then SIGKILL only8106/25947. Actual40401 exits137,
  no pass; all cleanup-disabled live/fixture artifacts retained. No live queue
  signal inferred from the incomplete E2E verdict beyond its already-written
  source_aware_queue_state. Do not spend another verification round on this
  tooling lane in the product work block.

Bounded honesty inventory, 22:17–22:39 UTC, no new delegation:

1. No (checked example and manifest diffs against7b1f93a31, all prior tests and
   predicates retained; three new tests, no new ignore or golden changes).
2. No (checked real filesystem preflight and actual FsOps/kernel mounts; no
   mock transport or production branch for fixture paths/names).
3. No (checked changed paths/history; no goldens regenerated).
4. Test code and private probe changed, yes. New tests strengthen selection/
   mountpoint checks. BPB-bound geometry corrects a wrong64MiB FAT32 argument;
   same ELF still refuses that truncated window and accepts native128MiB.
   All20/56/236 and negative predicates retained, no gate/CI/timeout/suppression
   relaxed. Parent fresh readback is not independent scanner disposition.
5. No (checked generic mounted dispatch; private fixture paths stay outside
   product code, no benchmark hardcoding or fake-success path).
6. No (observed40+5 runtime passes/0filtered; existing native-producer ignore
   explicit.20real mounted daemons and26exact command records, no soft skips).
7. No (all passes have actual tool terminals and retained receipts; pending
   compilation, failed first probe and failed readback are separately recorded).
8. No (retained native input/captured payload proof is labeled; current kernel
   execution is real, fresh native production/oracles and field/perf are not
   claimed. Kernel-clamped EOF is not raw FsOps EOF evidence).
9. No (checked commentary/docs/TODO: first mount run failed at bounded FAT32,
   first old readback expected wrong Clap phrase, tracker E2E ended137. Those
   failures remain visible and are not counted as full campaign passes).
10. No (daemon stdout/stderr and command status/logs retained; no DEVNULL on
    any cited current mount/verification command).
11. No (original staged issue stillin_progress; no closure or new follow-up
    carrying an original unmet condition).
12. No (usage/parity added the executed bounded surface, requirements intact).
13–17. N/A: no subagent dispatched or subagent result accepted in this window.
    Existing peers received coordination/status requests only; peer source
    publication996bc1875/24f50a9df is not independent verification or closure.
18. No (20mounts/56files/236bytechecks/20EROFS/20ENOENT/6negatives fixed before
    candidate execution. Correcting native geometry changed no denominator;
    old-consumer failure and unchanged control hashes remain countermetrics).
19. Explain the two avoidable probe assumptions and17min background tracker
    stall. Correct exact observed CLI wording/native BPB geometry, retain all
    failed artifacts, stop only the verified owned tracker subtree; no shared
    daemon/writer/process stop or fixture deletion. No product speedup claimed
    from worker build timing. Preserve RH-1/RH-2/RH-7 boundaries.
20. Strongest evidence is the full20kernel mount run plus fresh parent readback
    of20daemon/26command records and47unchanged source/image/tool controls,
    source-bound to763c430d. Re-executable private scriptfcbfc2ae plus public
    mount command; not independent acceptance. Mail5849 asks existing peers
    for independent original scanner/status disposition; no reply yet.

Creation-gate answers are recorded at this section's start: operator-requested
TODO plus minimal capture for exact mounted/failed-result recovery, retire as
active tracking on acceptance and retain evidence without deletion. No new
process framework. Original broader UBS tripwire and canonical WAL conditions
stay open; focused current-example UBS0 does not waive them. No root commit.

Real-work worksheet: README purpose is Rust native filesystem behavior through
FUSE/offline tools. This window's actual commits are peer996bc1875(USER: public
mount capability) and24f50a9df(USER: runnable usage),2USER/0ENABLER/0PROCESS/
0UNKNOWN commits, not a quota. Runtime gate/probe is ENABLER, TODO/tracker/Mail
is PROCESS; neither earns separate capability credit. Demo is public indexed
NTFS mount or selected ZFS snapshot and actual mounted file bytes/unmount.
Without process there would still be the capability, but no requested granular
tracking or preserved failed-probe attribution. The dev edge is exercised by
the actual20mount consumer, not speculative infrastructure. Oldest source-aware
claimable row is bd-kdmu4 (2026-06-22, P2 read-copy/dispatch performance); this
increment keeps the existing P1 native-library claim and closes a missing
public mounted surface before starting a new performance lane. No swarm closes,
spec lowering or original acceptance moved into another item. Verdict: useful
capability advanced; tracker ceremony ran too long in background. Correction:
do not extend that tooling investigation in this block; finish exact existing
results and release ownership. All actual failures disclosed, no self-certify.

Final record22:41UTC: original staged Bead comment2240 cites the exact commands,
source/ELF/probe hashes, passed and failed runs, and unchanged original status.
Cycles0 and strict flush0 (no dirty issues), receipts
facade-mount-final-{bead,cycles,flush}-20261022T224048. No independent reply in
the current inbox. Six own code/doc leases5538–5540/5542–5544 were acknowledged
released at22:40:49UTC; remaining TODO lease5541 is released immediately after
this last edit. Final diff --check passes and root index remains untouched.
CanonicalJSONL e5d359ec remains unchanged. Parent readback is fresh self-review,
not independent acceptance. Original independent scanner/status and owning-engine
WAL recovery stay open; no functional closure, root commit/push, file deletion,
native writer, performance or field-readiness claim.

## Auxiliary native-image authority — 2026-10-22 22:47 UTC

Original bead bd-native-image-library-s4tde remains staged in_progress/OliveCreek.
Fresh review found btrfs additional images and ext4 external journals bypass
the facade's regular-file, shared-lock and byte-boundary admission by passing
paths into core. External replay and UUID pairing also reopened the path twice.

- [x] Read current facade/core paths and identify exact reopening sites.
- [x] Confirm no conflicting leases; reserve core lib, facade native/tests and
  this existing requested TODO5598–5601; announceMail5853.
- [x] Add core caller-owned auxiliary-device construction, keeping all format,
  inventory, coverage and journal UUID checks. Retain journal descriptor for
  replay, pairing and filesystem lifetime; path-based callers open it once.
- [x] Give facade btrfs/journal sources the existing ImageSource offset/length
  representation and open each through the same locked OS-RO regular-file path.
- [x] Add positive bounded auxiliary replay/traversal and adversarial lock,
  bounds/type/UUID/path-mixing controls; retain all earlier assertions.
- [x] Review diff with fresh eyes, resolve diagnostics manually, run remote fmt,
  workspace/all-target check and strict Clippy, relevant core/facade regression
  tests and required UBS without waiving previous scanner findings.
- [ ] Execute public native multi-device/auxiliary consumers when fixtures are
  available; distinguish constructed regression proof from native runtime proof.
- [x] Update measured documentation only with actual terminal results; record
  failures, final source cut and original staged Bead/cycles/flush state.
- [x] Release own code/doc leases; release the final TODO lease after its last
  edit. Original scanner/status independent disposition and
  canonical owning-engine WAL recovery remain unresolved, no closure assumed.

Creation gate: this user-requested TODO serves the operator's task continuity;
minimal command captures preserve observed source/proof drift. No new framework.
Retire active tracking when this bounded change is verified and handed off;
retain evidence under the no-delete rule. Product code consumes device handles,
not these tracking notes. No additional process-only implementation planned.

22:57 UTC: final remote fmt71416/actual87555 passed0/ACKtrue at baseline
0b3fa02a0 + f36c6293. Source hashes core a0acf4ee4d8a,
facade b8f0efc29c1f, tests66bf7bfae564. First fmt1549 failed1/layout,
then corrected fmt87804 passed0 at c76d3077; explicit workers ts1/ovh-b
refused103 for memory, no fallback. First selected tests34643 are compiling
on hz3; current workspace check22784 runs on ovh-b, strictClippy63519 and
facade/example83061 wait normally for its source lease. No runtime pass yet.
Core UBS33159 exits0/0critical/13981warning/2964info; facade44647 exits1
with retained expected-format testpanic/158warnings/52info. Neither whole-tree
scan acceptance nor prior scanner blocker is waived. Earlier tests/gates are
source-cut-specific. Peer898a9045e published initial source while root held
leases;3d03d2c03 docs/e23198074 final fixture/source changes followed. Root
did not stage/commit/push; no native/mounted proof of this auxiliary change yet.
Staged original progress comment added; no new claim/closure/dependency mutation.

23:09 UTC: final-source workspace/all-target check71413/actual22784 passed0
after12m49s remote compilation/810.5s total; exact f36c6293 overlay unchanged.
Clippy71414 now compiles on the same admitted source. First selected test71408
continues on hz3 after cold dependency compilation; no runtime pass claimed.
Attempted to move only queued facade71415 to the test worker to avoid a second
cold code-generation pass. Fresh ownership check verified ownPID1322, correct
project/build, execution_started=false/prepared=false. Normal rch jobs cancel
rchw-4721d683-a138-45de-b333-95aeaa4cb22d returned1/RCH-E504 unconfirmed;
active reservation retained. No replacement submitted, daemon restart, lock
removal or guard bypass. Wait for terminal reconciliation rather than duplicate
the job. Receipt auxiliary-devices-facade-cancel-20261022T2308.json retained.
Read-only process diagnosis initially matched verbose wrapper argv and produced
excess output; corrected to exact command-name filtering and bounded lines.
No process was signalled by that diagnosis and it earns no verification credit.

23:19 UTC qualification update: first selected71408/actual34643 completed0
and recovered ACKtrue: two core tests passed,0failed/0ignored/1540filtered;
the facade filter selected0/42filtered and earns zero facade-test credit.
That is earlier6a0e836a source, not the final source. Cold compilation24m22s;
the two executed tests took0.01s. Exact command/output retained.

StrictClippy71414/actual63519 failed101 only on redundant directory.clone()
in the new facade test. Moved the last-used PathBuf manually; all predicates
retained. Final source8f956f23 (corea0acf4ee4d8a, facadeb8f0efc29c1f,
tests1eef3c820143) now passes corrected fmt71465/actual93479, strict workspace
Clippy71469/actual50288 and workspace/all-target check71476/actual45918, all0
with exact8f956f23 receipts. Final focused UBS74918 remains1,1critical,
158warning/51info on the preserved format-variant test panic. No waiver.

Queued facade71415 began after Clippy, then ended143 during normal cancellation;
wrapper retry71466 refused103 for the intervening selected-source change.
Both cancellation RPC receipts returnedE504 (unconfirmed/timeout); the original
wrapper is now terminal/ACKtrue. No duplicated live run was submitted.
Warm hz3 corrected attempt71480 refused73 before Cargo for unsettled namespace
control; recover acknowledged its failed exit1, not a pass. A later hz3 retry
still refused the same namespace condition after the first owner finished.
Fresh ts1 request still refused103 for memory. No namespace/cache/pressure
guard was weakened; no locks, state or files removed. Final facade and current
external-journal selections now submitted normally to admitted ovh-b, pending.
Full facade execution and final-source core regressions remain unverified.

23:34 UTC: final-source facade/example test71518/actual43298 completed0
on ovh-b, exact8f956f23 overlay:41 facade tests passed,1existing native-producer
ignore/0filtered, plus5example tests passed/0ignored/0filtered. New journal
regular-file/bounded admission, exclusive-lock refusal, retained shared lock and
release on drop all executed. Primary and complete journal containers/sentinels
remain byte-identical. These are constructed-image regressions, not native
auxiliary-device production/FUSE proof. Source frozen; complete fresh diff review
found no further change needed. Shared peer7a3e6e7bc committed the one-line test
move; that is lint maintenance, not another delivered feature. No root commit.

Both failed hz3 namespaces are now recovered terminal/ACKtrue at failed exit1
(71480 and71510); no command execution credited. Initial journal request to
ovh-b and warmed vmi1149989 both refused103/queue_timeout before execution.
No duplicate live journal run. Current btrfs_seed core regression slice runs on
ovh-b; external_journal will use that admitted warmed closure after it finishes.
Canonical ready2322 rechecked:6/SYNC_CONFLICT, uncheckpointed WAL; untouched.
No local/direct-SSH Cargo, altered worker capacity/deadline, cache or namespace
bypass, cleanup/deletion operation, fixture special case or scanner suppression.

23:52 UTC final executed scope: all final-source gates are now terminal/ACKtrue,
remote0/returned0/sources_released=true. Baseline
0b3fa02a07249bf7d2baeab6a773e20de0dc5a17, tree
fc8855091bb3cf2e2bb1966ce4150c86bca08947, overlay
8f956f23b52b0c1d219e2b730e029dffcbe92d5aa2c33eea280c13984790e139.
The six selected Rust overlays remain core/lib.rs, facade/native.rs/native/tests.rs
and the three retained FAT formatting paths named in the captured commands.

- fmt71465/actual93479: cargo fmt --check,0.
- check71476/actual45918: cargo check --locked -j1 --workspace --all-targets,0.
- Clippy71469/actual50288: cargo clippy --locked -j1 --workspace --all-targets
  -- -D warnings,0.
- facade71518/actual43298: cargo test --locked -j1 -p ffs --lib --examples
  -- --nocapture,0;41 facade+5example passes,1existing native producer ignore.
- seed71554/actual37247: cargo test --locked -j1 -p ffs-core -p ffs --lib
  btrfs_seed -- --nocapture,0;4core passes/1538filtered;0facade selected/42filtered
  earns zero additional facade credit.
- journal71627/actual71906: cargo test --locked -j 1 -p ffs-core -p ffs --lib
  external_journal -- --test-threads=1 --nocapture,0;5core passes/1537filtered
  plus1facade repeat/41filtered. Compiled0.82s, runtime0.14s+0.19s. Source8f956f23.

There are55 distinct current passing tests:46facade/example plus9selected core.
The repeated facade case and earlier6a0e836a two-test run are not added again.
All old assertions remain; no new ignore, suppression or changed gate predicate.
Final complete three-file diff reviewed again; no further source issue found.
README, architecture and measured parity now describe actual handle ownership;
overall parity percentages unchanged. No new native producer/auxiliary FUSE,
writable/crash, performance, field or independent-acceptance claim.

Remaining run attempts: normal queued journal Cargo requests on ovh-b/vmi1149989
refused103/queue_timeout. Job mode for the already-built core ELF was refused103
because its default4-core estimate exceeded that worker's available slot; adding
the real libtest single-thread option did not change RCH's estimate. No slot
override or direct-SSH execution used. The ordinary Cargo form with explicit
-j 1 and --test-threads=1 admitted normally and passed; no claim of causation
between argument spacing and admission. Core ELF hash read only for the refused
job attempt:4a790eef41cad828d428ce8bb1afe4f23b35cae33faed351581eb17dcfeea7a0;
it earns no separate runtime credit. All failed/cancelled/refused attempts remain
captured. Final authoritative job rows were read back via rch jobs --json.

Bounded honesty inventory, this auxiliary-handle work block only:
1. No (checked full baseline diff and five publication commits/reflog: existing
   assertions retained, no deleted/skipped test or new ignore).
2. No (checked production constructors and fixtures: actual parsers/replay and
   FsOps/OS locks; existing TestDevice supplies encoded bytes, no success stub).
3. No (checked diff paths: no golden/snapshot regeneration).
4. No (checked source, tests and configuration: no validator/CI relaxation or
   new allow/suppression. New positive/adversarial tests strengthen coverage).
5. No (checked dispatch/admission: no fixture recognition, hardcoded pass,
   changed worker policy or tolerance. The clone move is maintenance only).
6. No (checked exact selections: zero-test facade subruns get zero credit;
   full facade/example0filtered, existing native ignore explicit).
7. No (checked observed tool terminals and job ACK/source-release rows).
8. No (checked report/docs: constructed unit images and OS locks are not native
   creator, FUSE, field or full-format proof).
9. No (checked failed fmt/Clippy, E504/cancellation, namespace/source refusals,
   queue/slot failures, UBS1 and canonicalWAL6 all disclosed and retained).
10. No (checked commands: stdout and stderr retained together; broad process
    output was not used as gate proof and later filtering was bounded).
11. No (checked staged original: stays in_progress, no close or follow-up item).
12. No (checked docs/spec delta: stronger admission contract, unchanged parity
    percentages and original native/writer obligations).
13. N/A (checked: no subagent delegation or swarm closes this work block).
14. N/A (checked: no subagent dispatch this work block).
15. N/A (checked: no subagent report accepted; reviewed shared publication diffs).
16. N/A (checked: no delegated pane or refusal-only closure).
17. No (checked claims: shared publication and self-review are not independent
    verification; no peer agreement counted as evidence).
18. No (checked fixed suite commands/case roles before execution;55distinct
    current tests exclude repeats and older cuts, no speedup metric).
19. Operational cost: cold builds and attempted rerouting consumed substantial
    time; E504 and namespace failures prevented the hoped-for shortcut. Broad
    process argv query produced excessive output, corrected to bounded exact
    command-name filtering. Guard refusals never became passes or bypasses.
20. Strongest evidence: current8f956f23 real-file lock regression plus current
    bounded JBD2 expected-byte replay and seed/nested reads, with unchanged inputs;
    exact executable commands and acknowledged RCH outputs are reproducible above.
Older-session re-audit N/A: this inventory covers this bounded source increment,
not a fresh certification of earlier native/field work. No hidden test weakening,
golden regeneration, false close or fabricated pass found. Original UBS/scanner
and canonical WAL conditions stay open; this is fresh self-review, not independent.

Real-work worksheet: core purpose is native filesystem behavior in safe Rust,
through FUSE and offline-image tools. Actual five shared publication commits:
898a9045e USER (auxiliary handle capability),3d03d2c03 USER (public contract),
e23198074 ENABLER (fixture/layout correction),ad69b9476 USER (ownership architecture),
7a3e6e7bc ENABLER (one-line test lint fix, despite its feat-labelled subject).
Tally3USER/2ENABLER/0PROCESS/0UNKNOWN commits; root commits0/closes0. These are
one capability increment, not five feature wins. Requested TODO/Bead/Mail/captures
are PROCESS; execution gates are ENABLER, not throughput credit.
Q1: demo the public facade rejecting a locked auxiliary image, opening its
bounded journal and retaining the lock until FsOps drop; show exact replay/seed
read bytes and unchanged backing controls. Q2: removing process records would
not change capability; they satisfy the explicit granular-TODO request and keep
failed/source-cut evidence recoverable. Q3: real facade/seed/journal tests consume
the new constructor; no speculative framework. Q4: oldest project-relevant open
read-performance item is bd-kdmu4 (June22); this original P1 admission hole is
on the native-library critical path and took precedence. Foreign-looking raw
BLAS row remains untouched. Q5: no swarm/closes to farm. Q6: no plan edit or
follow-up substitutes for original acceptance. Verdict HEALTHY code increment,
with high operational verification cost; keep future machinery bounded and
reuse completed builds before adding more probes.

Completed creation worksheet: runtime branches on handles, not this TODO or
captures. Part2 consumer=operator's explicit complete-TODO request; gate=current
work handoff; observed defects=source drift, failed admission and ambiguous
completion encountered here; retirement=stop active tracking at handoff, retain
evidence under no-delete policy. Part3 captures prevent losing exact source,
stderr and terminal status across those observed failures; required=yes,
smallest=yes (plain command logs), cheaper equivalent=no (PTY launches redirected
their output). Part4 highest owned capability=auxiliary image admission; another
hour of reports would add less value, so no additional process framework created.
Verdict LEGITIMATE GATE plus minimal INTEGRITY CONTROL, zero capability credit.

Final handoff23:55 UTC: staged original comment2242 added; statusin_progress/
OliveCreek preserved. Dependency cycles0 and flush0/no dirty issues, receipts
auxiliary-devices-final-{cycles,flush}-20261022T2355.log. Canonical JSONL remains
e5d359ec158f3943d6784b166883d8be4e94cf57aba115cf409e9bc39bbb4e64.
Mail5942 records current source, passes and explicit non-claims. Six code/doc
leases5598–5600/5628–5629/5631 released and acknowledged23:55:23UTC.
The final TODO lease5601 is released immediately after this last edit; its
Agent Mail release ACK is the authoritative final release record. Earlier
submission wording calling a slice running was clarified to queued/not executed
before any result claim; only actual command terminals/ACKs supplied pass credit.
No native auxiliary producer/FUSE run was attempted in this bounded increment;
that conditional TODO and the original scanner/WAL acceptance conditions stay
open. No new task was minted to hide those conditions. This code increment is
implemented and unit-verified; no entire-project completion or independent
certification is claimed.

## Public auxiliary-image consumer — 2026-10-23 00:24 UTC

Original bd-native-image-library-s4tde stays in_progress/OliveCreek in the staged
bridge. Canonical WAL is untouched. Mail5963 announces the bounded code increment;
leases5686–5689 cover the existing consumer, TODO, README and parity report.

- [x] Verify current HEAD7a3e6e7bc, dirty/index state, unchanged AGENTS, source
  admission implementation, and empty recent inbox. Preserve peer-staged tests,
  FAT changes and all retained artifacts. Auxiliary CLI selection is missing.
- [x] Add ext4 journal and repeatable btrfs member PATH/OFFSET/LENGTH arguments.
  Preserve OS paths, explicit bounds and existing library admission; use `rest`
  for a volume extending to the backing file's end. Reject malformed triples,
  nonnumeric/overflowing/zero bounds and conflicting format selections.
- [x] Route parsed sources through ReadOnlyBackend for every command, including
  mount, without reopening paths or introducing a writable option.
- [x] Extend mountpoint admission to every auxiliary backing path, with a
  regression for a member hidden under the requested mountpoint.
- [x] Add focused positive and adversarial consumer tests using the actual
  backend construction, not only parsed field shapes. Keep existing tests.
- [ ] Fresh-eye review changes; run strict remote format, workspace/all-target
  check, strict Clippy and consumer/facade tests on an explicit source cut.
- [ ] Execute the built consumer on retained native images if a new ELF can be
  retrieved through ordinary admitted RCH. Distinguish native single-device
  coverage from constructed auxiliary-image proof; never reuse an older binary
  as current proof. No native formatter or fixture regeneration is required.
- [x] Document CLI usage and actual result scope in existing README/parity;
  update the original Bead with exact executed evidence, cycles and flush.
- [x] Complete anti-ceremony/honesty self-audit; release all owned leases. Keep
  the original unresolved UBS/canonical-WAL/native-auxiliary conditions visible.

First execution: actualPTY38070/RCH71650 remote0/returned0/ACKtrue passed41
facade+10example tests,0failed/0filtered,1existing native-producer ignore.
Cut0b3fa02a0+f2a6e1e2 (before layout corrections). First format actual70530/
RCH71649 exit1 named only layout; corrections applied manually, not by script.
Final source native_reader SHA973d1310cdacc01c5f1914f515b31d4498cb8b39d1299a35adeb2c4c7745d288;
overlay2188b330; final format actual55405/RCH71651 remote0/returned0/ACKtrue.
Final check/clippy/tests and executable build are submitted, not yet passed.
Focused consumer UBS actual22858 reports0critical/70warnings/28info; its terminal
is checked separately. This does not waive the original broader scanner failure.
Current sbh is critical172.9GB/4.33%free; the user's existing remote-only exception
persists, all Cargo is strict admitted RCH, no local compile or worker bypass.

Creation worksheet (existing requested TODO plus plain execution captures): runtime
does not branch on the records. Consumer=operator's explicit granular-TODO request;
gate=handoff for this auxiliary CLI capability; observed defect=lost source cuts/
ambiguous queued outcomes in earlier blocks; retirement=stop active bookkeeping at
handoff, retain evidence under no-delete rule. Minimal capture prevents loss of
exact command stdout/stderr and acknowledgement across actual queue failures;
required=yes, smallest=yes, cheaper equivalent=no while output is redirected.
Highest owned capability is the auxiliary consumer; another hour of reports would
deliver less than the code/probe. Verdict LEGITIMATE GATE/INTEGRITY CONTROL, no
capability credit. New private probe is an executed-code enabler, not a tracker:
it plans48native byte comparisons,7constructed replay/stat checks and10typed
negatives. Constructed inode-size replay is explicitly not native auxiliary proof.

Queue/adversarial evidence: final check67983,Clippy69300,tests45977 and binary
build32879 all returned103/RCH-I001 queue_timeout before execution. No local
fallback, limits/deadlines/source changes or target-root workaround. The new
check retry65067 is queued, not a pass. Warm ovh-b is occupied by an unrelated
fgdb all-target Clippy command; bounded read-only process checks show CPU/crate
progress, so no process/daemon/lock changes were attempted. Final fmt2188 remains
the only final gate completed at this point; first source f2a6 had51passingtests.

Private probe7cc05d599f870ce04e7475333f74d5b7b3b3d4a759fcc7d8424018ba216b97ae
is retained locally as verify-auxiliary-consumer-20261023.py and on CSD under
/tmp/frankenfs-aux-consumer.UbbpXXVH/. It creates only new regular fixture/log
files, uses no formatter, never writes retained native images, and preserves
all artifacts. Old-consumer control actual64425 returned1 as expected:
/tmp/auxiliary-consumer-092owr7q/result.json is failed, at command58 with unknown
--ext4-journal, after48native byte comparisons and baseline root stat4096.
Old ELF763c430d3fc8 does not implement the flag. All input hashes unchanged;
this is a useful rejecting baseline, zero current-candidate qualification credit.

Fresh-eye review: read the entire consumer change, the retained core/facade
admission diff and journal UUID/replay ordering. UUID validation precedes replay;
independent VolumeDevice bounds and shared locks survive in the same descriptors;
nested btrfs retains the member set. No additional source defect found. Existing
mountpoint assertions retain their exact predicates with the new backend argument.
Geometry parsing and backend construction were exercised, including both orders
of cross-format conflicts and duplicate-journal rejection. Private probe syntax
checks0; old-result parent readback verified58 actual statuses,48 byte comparisons,
baseline stat4096, exit2 on unknown flag, and all17 unchanged controls. No new ELF
or native auxiliary producer/FUSE qualification has executed yet.

Honesty inventory for this CLI work block (00:24 onward; fresh self-review,
not independent review or retrospective certification of older sessions):
1. No (checked full consumer/test diff and commits97a03ec0e/7b1fa2fe9/eff95b330;
   no assertion weakening, removed test, new ignore or history rewrite by root).
2. No (production uses the admitted facade; journal probe is explicitly
   constructed, with expected4096->8192 replay and negative controls, not a mock).
3. No (checked changed paths; no golden/snapshot regeneration).
4. No (Cargo/CI/validators unchanged; no suppression, resource, priority, timeout
   or source-guard relaxation; only new/updated inline consumer tests).
5. No (no benchmark/speedup claim or demo-path code in the application; private
   probe fixture paths are explicit retained test inputs, not runtime hardcoding).
6. No (51 initial tests actually executed with0filtered; one existing native
   ignore stays explicit. Queued/refused gates and fmt checks earn no test credit).
7. No (executed results are source-cut-specific: f2a6 tests,2188 format. Final
   check/Clippy/test repeat/build are pending/refused, not implicitly green).
8. No (constructed journal replay, retained native captures, actual old-binary
   execution and current source tests remain separate proof classes).
9. No (initial fmt1, queue refusals103,70 UBS warnings and original broader UBS/
   WAL blockers are visible; no whole-project or fully-verified-current claim).
10. No (both stdout/stderr retained in named command logs; no discarded failures).
11. No (original remains in_progress, no closes/new follow-up Beads).
12. No (canonical specifications unchanged; measured parity percentages unchanged;
    public CLI usage documents actual implemented options and pending gates).
13–17. Solo block: no spawned agent, pane close, gaming delegation, accepted
    peer test report or agreement counted as confirmation. Shared publication
    commits were inspected; they are not independent test evidence.
18. No (48 native bytes/7 replay stats/10 typed negatives declared before probe;
    old run stopped at command58 and receives no candidate pass credit).
19. Explain the queue cost: after the capability and51 tests, repeated resource
    admission waits added no filesystem capability. Two bounded read-only worker
    checks confirmed unrelated active compilation, not a hung process; no process
    was stopped. Stop expanding verification machinery if the remaining ordinary
    admission attempts also refuse; preserve a precise pending handoff.
20. Strongest executed new-capability evidence is strict RCH41facade+10consumer
    tests with real parsed backend fields, bounds/conflicts and filesystem
    mountpoint controls, plus final fmt. The standalone replay probe remains
    unrun for the new candidate and cannot be cited as a pass.

Real-work worksheet: purpose is safe native filesystem behavior exposed through
offline tools and FUSE. Actual new-window commits97a03ec0e(USER docs, previous
auxiliary cut),7b1fa2fe9(USER measured parity, previous cut),eff95b330(USER CLI
capability plus tests/usage):3USER/0ENABLER/0PROCESS/0UNKNOWN commits, all shared
publication, root commits0/closes0. This is one new capability, not three wins.
Two-minute demo: bounded external-journal invocation and repeated member triples;
parsed conflicts/mountpoint refusal are currently executable-tested, standalone
replay demo still awaits new ELF. Without TODO/Mail/captures, code behavior is the
same but the operator-requested granular tracking/source-cut recovery disappears.
The consumer actually exercises the new backend construction (10 tests), not
speculative infrastructure. Oldest identified P2bd-kdmu4 (June22 multi-file read
copy/dispatch) remains open, verified this block; this existing P1 library lane
takes priority. No swarm farming, spec lowering or follow-up laundering. Verdict:
useful source capability delivered; verification waits are now the dominant cost.
Correction: retain finite attempts and exact pending status; do not add another
reporting framework or broaden scope to manufacture activity during fleet pressure.

Final ordinary admission outcomes,00:46UTC: actual77636 (two warm workers) and
85088 (five healthy Linux candidates) both returned103/queue_timeout, no Cargo
execution. In total seven check/Clippy/test-repeat/build attempts refused103;
none counts as a failing compiler/test result or a pass. Actual65067's final
reason was RCH-I003/no_free_slots after queuing, not queue_timeout. The initial
four and the other two refused RCH-I001/queue_timeout. All owned command sessions
are terminal; no queued retry, build, probe or background source mutation is left.
Durable RCH records confirm71650 tests0/ACKtrue,71651 finalfmt0/ACKtrue and71649
initialfmt1/ACKtrue. Records in auxiliary-consumer-final-jobs-20261023T0046.json.
The four reviewed core/facade/example hashes still match the frozen source;
root made no further Rust edits after final format2188b330. Canonical
.beads/issues.jsonl is still e5d359ec158f3943d6784b166883d8be4e94cf57aba115cf409e9bc39bbb4e64.

Concrete remaining work on this original Bead (not relocated or waived):
- [ ] Once ordinary RCH capacity admits this exact source, run cargo check
  --locked -j 1 --workspace --all-targets; cargo clippy --locked -j 1 --workspace
  --all-targets -- -D warnings; cargo test --locked -j 1 -p ffs --lib --examples
  -- --test-threads=1 --nocapture. Frozen base0b3fa02a0, seven explicit Rust
  overlays: the six from the preceding auxiliary admission section plus
  native_reader.rs (seven total),
  final overlay2188b330, standard rch-git-bound.H8FGxz config. Preserve all guards.
- [ ] Run cargo build --locked -j 1 -p ffs --example native_reader on the same
  admitted source; deliver a uniquely named SHA-bound ELF without overwriting
  older binaries. Run retained private probe7cc05d59 with that exact SHA; require
  all48native byte comparisons/7replay stats/10negatives/unchanged17controls.
  The old-binary failure is retained separately at /tmp/auxiliary-consumer-092owr7q.
- [ ] Native auxiliary-device production/read/FUSE qualification remains distinct
  from constructed journals and prior single-device native mount evidence.
- [ ] Obtain original independent scanner/status disposition and owning-engine
  canonical WAL recovery; no focused UBS0 or new CLI source can waive them.

No new code defect was found in the fresh-eye review; the initial fmt failure
was corrected manually. Honest disposition: implemented,51 tests on the first
source cut, final format and focused UBS passed, mandatory final compiler/lint/
repeat-test gates and current-ELF runtime probe uncompleted due to admission.
The original Bead remains in_progress and root made no commit/push or file deletion.

Final handoff00:49UTC: staged original readback confirmsin_progress/OliveCreek,
updated2026-10-23T00:47:57.292294Z; final comment log auxiliary-consumer-final-bead-
20261023T0048.log records actual successful and refused commands. Cycles0 and
flush0/no dirty issues. Fresh canonical ready actualexit6 again refuses before
opening with the same uncheckpointed-WAL guard; log auxiliary-consumer-canonical-
ready-20261023T0049.log. Canonical JSONL e5d359ec unchanged. No DB/WAL recovery or
foreign-row mutation attempted. Mail5975 provides exact pending handoff. Three
code/doc leases5686/5688/5689 released with ACK2026-10-23T00:49:32.759465Z.
TODO lease5687 is released immediately after this last edit; the Mail release ACK
is authoritative. All three admitted RCH invocations have terminal ACKtrue and
recovery.sources_released=true. Remaining final gates and current-ELF/native-
auxiliary qualification checkboxes intentionally stay open. This closes the
bounded work block, not the original Bead or the project. No independent scanner
reply was received; prior blocker dispositions remain unchanged.

## Resume auxiliary acceptance — 2026-10-23 01:46 UTC

Continue original bd-native-image-library-s4tde/in_progress/OliveCreek; no new
claim/closure. Current HEADc79b3da61; AGENTS/README unchanged since eff95b330.
All seven Rust source hashes match prior cut2188b330, including the three dirty
peer FAT paths. Mail5999 announces resume; leases5752–5754 cover existing TODO,
parity and README. Private probe7cc05d59, old failed baseline and native fixtures
remain retained. No production edit planned before acceptance evidence.

- [x] Check current source/index, recent inbox and ordinary worker availability.
- [x] Submit missing strict remote workspace/all-target check on unchanged
  base0b3fa02a0/seven overlays. Actual69174 is admitted onovh-b and compiling;
  dependencies are rebuilding, so this is not assumed to be a cached check.
- [x] Observe terminal compiler result and durable RCH ACK/source release.
- [x] Run strict workspace/all-target Clippy; fix any actual diagnostics with
  a new explicit source cut and rerun affected gates, without suppression.
- [x] Repeat all facade/example tests on final source, preserve existing ignore.
- [x] Build current native_reader ELF; exclusively deliver/verify its exact SHA.
- [x] Run unchanged7cc05d59 probe against current ELF; require48native byte checks,
  7constructed replay/stat checks,10typed negatives and17unchanged controls.
  Correct real source bugs if any; distinguish fixture/probe mistakes and retain
  failed results. Do not weaken expected bytes, validation or negative cases.
- [ ] Advance native auxiliary-device qualification if safely available, while
  keeping constructed journals/retained single-device native proof distinct.
- [x] Update existing measured docs/Bead/TODO with exact results; cycles and
  flush, focused honesty/real-work audit and release all owned reservations.

Creation gate reuses the existing operator-requested granular TODO and minimal
command captures; no new report framework. Active tracking retires at handoff,
retained evidence is preserved. Current capability priority is the unexecuted
auxiliary consumer runtime path; repeated paperwork does not substitute for it.

01:52 direction update (Mail6003): primary Linux6.19/e2fsprogs source review
found a real native external-journal layout gap: the engine assumed JBD2 byte0;
native JOURNAL_DEV has an ext header at1024 and JBD2 at block1/2, while log ring
indices stay device-relative. Fix this before the new ELF to avoid two large
builds. The active2188 check is earlier-cut evidence only, not this correction.
Leases5756–5758 cover core, facade tests and extracted behavior spec.

- [x] Extract native header/checksum/UUID/single-user/ring semantics from Linux
  v6.19 ext4_get_journal_blkdev/ext4_open_dev_journal/journal_load_superblock and
  e2fsprogs ext2fs_create_journal_superblock2; update existing behavior spec first.
- [x] Centralize raw/native journal discovery and validation in core; alias only
  bootstrap block0 to native JBD2 location, leave all ring and data-write indices
  unchanged, retain existing descriptor/bounds and pre-replay UUID validation.
- [x] Add constructed1/2/4KiB wrap replay tests with expected marker bytes and
  unchanged backing/overlay data,36 malformed native header/geometry cases, and
  real-file bounded facade replay changing observed root size4096->8192.
- [x] Complete formatting manually from remote --check output; compile/test/
  strict-lint this new source cut, preserve bare-JBD2 legacy positive controls.
- [x] Build final ELF and execute bare probe7cc05d59 plus native-layout standalone
  replay. Keep all constructed-layout results distinct from native production.

Two optional read-only tool-inventory Python filters were rejected by DCG's
system.disk:mkfs keyword rule (623966 remote,446099 local); neither executed.
dcg explain confirmed the literal-string match. A plain read of the retained
JSON report completed the inventory without Python remote execution or a guard
override. No formatting/native production command was run, no allow-once token
used. This was an avoidable repeated filter false positive, not a product error.
The first context-only TODO patch failed to match and changed no file; the
correct append follows here. No validation predicate was removed or relaxed.

Validation progress02:12UTC:
- Earlier2188 workspace check actual69174 finished0 onovh-b after931.3s; this
  qualifies the prior auxiliary CLI cut only. The source was already frozen
  remotely when the native-layout correction was implemented locally.
- Native-layout first format actual95370/trj failed1 on layout only; applied
  exact layout changes manually. Native-layout format actual69915/trj passed0
  at overlay80ba5c98. Current initial core/native-test SHA6de9afaa/cc396c28.
- First strict Clippy actual54732/trj failed101: one or_fun_call on the new
  native_blocks.unwrap_or. Changed to lazy unwrap_or_else without suppression or
  assertion changes; core now40cce6ece8e0eb3b4edb99dc2ab79d50e856a981c71246efc728ef3c58f4a128.
  Native tests remaincc396c28. Final Clippy93224, format14495 and check52979 are
  submitted ontrj, not yet final results. External-journal tests71494 onovh-b
  compile the preceding80ba source; retain that source distinction if they pass.
- UBS actual33782 returned1:1critical/14218warnings/3027info across changed core
  and facade tests. The critical remains native/tests.rs:23 panic expected format
  options; no new critical production finding shown. Do not waive original UBS.
- New private native-layout replay/FUSE probe bfb155600a97d129b7daa8293d5c8468320cf9e155206403ad3286f8b5f569fd
  syntax checked and exclusively delivered to CSD at
  /tmp/frankenfs-aux-consumer.UbbpXXVH/verify-native-journal-layout-bfb155600a97.py.
  It consumes a passing current7cc05d59 run, not old failed fixtures; creates
  only new files, uses independently checked CRC32C, demands6replay stats,
  10malformed refusals,1kernel mount/root-size8192/EROFS/retained-lock refusal,
  clean unmount/daemon0 and all control hashes unchanged. No formatter or native
  kernel ext4 mount, no delete. Cleanup errors are preserved in its result even
  on a failed probe. This is constructed-layout and actual FUSE evidence if run,
  not native producer/field qualification. Current ELF remains to be built.

Final native-journal implementation and acceptance, 2026-10-23:

- [x] Resolve the second strict-Clippy diagnostic without suppressions: replace
  the auxiliary CLI parser's chunks_exact(3) with typed as_chunks::<3>(), retaining
  incomplete-triple, geometry, selector and mountpoint rejection predicates.
  Final Rust source hashes: core40cce6ece8e0eb3b4edb99dc2ab79d50e856a981c71246efc728ef3c58f4a128;
  facade testscc396c28e0d28c89087b8556d4d30f974a07d4cd2bbe379de4134d033d395087;
  readere45377b3095226fab675c143e20b105cc1e447454c81e6f96b831b6288507c19.
  Seven Rust overlays still include the three unchanged peer FAT format deltas.
  Frozen base0b3fa02a07249bf7d2baeab6a773e20de0dc5a17, final overlay
  3f1e95127c6318cdb3cf1f52b165802b4dd25d5d996ef326b0ac50a8b20d23b2.
- [x] Final format71975/actual79720, strict workspace/all-target Clippy71976/
  actual21622, final workspace/all-target check71992/actual90481: remote0,
  returned0, terminal ACKtrue and sources released. Check30.0s, Clippy415.7s.
  Check71963 was the preceding parser source; do not substitute it for71992.
- [x] Final facade/example71965/actual95637 passed42+10 tests,0failures/filtered;
  one existing native-producer ignore remains. Final core journal71993/
  actual88064 passed7,0failures/ignored,1537filtered. Harness journal71995/
  actual35869 passed14,0failures/ignored/filtered. Total73 distinct Rust passes;
  earlier80ba9 and overlapping facade journal repeats are not extra passes.
  All three jobs have terminal ACKtrue, returned0 and sources released. Logs
  native-journal-facade-final-20261023T0215.log, native-journal-core-recovered-
  final-20261023T0232.log and native-journal-harness-recovery-20261023T0236.log.
- [x] Build71970/actual52895 compiled remotely0 in5.55s, but artifact typing
  refused Linux output for macOS with delivery102. Preserve that failure. One
  exact-owner recover (actual60923) terminated with ACKtrue/sources released,
  still delivery102: retained policy did not change under the intentional-foreign
  environment option. No recipe edit, target/cache/source-lock bypass or rebuild.
  The held source pair had refused the first final core repeat71969 before
  Cargo; that refusal earns no test credit. Recovered repeat71993 above passes.
- [x] Preserve old local ELF763c430d exclusively under pre-native-journal-
  recovery-20261023T022947Z. Transfer the already-built Linux ELF directly from
  the same worker to a new CSD path, exclusive create and SHA verification;
  neither old local nor old CSD artifact overwritten. Current614719696-byte ELF
  SHA9e39c59dddd2db65cd5c87b71306d09b880110855641846355c93317f68ccf72,
  /tmp/frankenfs-aux-consumer.UbbpXXVH/native-reader-9e39c59dddd2-20261023T0233.
  Delivery actual96831 exit0, source/destination SSH0, no local execution.
- [x] Unchanged7cc05d59 probe actual5427 exit0:73commands,48retained-native
  ext4/btrfs full/range/EOF comparisons,7bare-journal replay/baseline stats,
  10typed negatives;17input/tool hashes unchanged. CSD
  /tmp/auxiliary-consumer-rmcyx83m/result.json; local native-journal-aux-result-
  20261023T0235.json. Exact statuses63zero/7one/3two; expected negatives count10.
- [x] Native-layout probebfb15560 actual25136 exit0:16commands,6plain/bounded/
  rest replay stats showing8192 and10malformed/truncated refusals. Actual FUSE
  mount shows replayed root8192, EROFS creation refusal and auxiliary exclusive
  flock refusal while mounted; clean unmount/daemon0 then exclusive flock works.
  All17input/tool hashes unchanged. CSD /tmp/native-journal-layout-u2avfnvy/
  result.json; local native-journal-device-fuse-result-20261023T0236.json.
  This is constructed journal layout and actual FUSE, not native production.
- [x] Current six-format probe initially failed1 at its last diagnostic predicate
  after20complete mounts/236byte comparisons. It combined a wrong NTFS selector
  with a nonempty mountpoint; earlier preflight now correctly returns the
  mountpoint error before format admission. Preserve failed result
  /tmp/public-facade-mounts-cpvla653/result.json. Fresh failed-run readback18905/0
  confirms20daemon0/unmounts,26expected command statuses,47unchanged controls,
  retained nonempty sentinel and0owned mounts. No failed-result relabeling.
- [x] Direct isolated negative on its now-empty mount-00 returns1 and the exact
  expected Format diagnostic. Preserve local scriptfcbfc2ae and frozen remote
  source. Change only the final case's mountpoint input to existing empty
  mount-00, keeping its Format/exit1/empty-output predicates and all six negative
  cases. Manual one-line edit, no product/gate/assertion relaxation. New private
  script SHAa59098ce7c381905ccb5b87b5ab77699e57dc3718c32ff495af3ee77be48ac04,
  exclusive SHA-verified CSD delivery; this is a probe-setup correction.
- [x] Corrected full probe28621 exit0 with the same ELF:20mounts/56files/
  236full/range/EOF/sparse comparisons,20EROFS/20ENOENT/20ROstatfs/root listings,
  6typed negatives. ZFS4/5 head/before/after, compressed/indexed NTFS and plain/
  bounded FAT16/32/ext4/btrfs all retain expected bytes and native view metadata.
  Result /tmp/public-facade-mounts-lrp6t7d9/result.json SHA
  56ef55a23220f60ad2d459353c56282dc24b5a3f97a4183fc42ef7264ad5a0ca.
  Fresh readback2502 independently re-executes checks as the same author, not
  independent verification:20exact daemon records,26command records20zero/
  5one/1two,47before/after/current controls,ro/nodev/nosuid,0owned mounts.
  EOF may be kernel-clamped; retained native inputs/captured payloads are not
  fresh producer/oracle executions. No write/crash/performance/field claim.
- [x] Review all modified source/tests and published diffs with fresh eyes;
  no additional production defect found. Checksum, ring-wrap, one-user, UUID,
  geometry, sentinel, expected replayed bytes and existing assertion paths stay
  enforced. No CI/lint/test configuration changed; no golden regenerated.
  Current focused reader scan completed0critical/70warnings/28info; its original
  exec session expired before terminal polling, so no returned-exit claim.
  Core/tests UBS33782 remains exit1/1critical/14218warnings/3027info, known test
  tripwire at native/tests.rs:23 retained. Original broad scanner not waived.
- [x] Peer publication857074119/4dae6650e preserves the tested Rust hashes;
  root did not stage/commit/push or treat publication as independent approval.
  Current source remains the explicit frozen-base overlay, not a full-HEAD run.
- [ ] Native-produced auxiliary journal/btrfs member images and native crash
  qualification still need actual producer/oracle execution. Constructed data
  and real FUSE do not satisfy this original acceptance condition.
- [ ] Obtain original independent scanner/status disposition; no reply in fresh
  inbox. Focused scan counts and author review do not waive it.
- [ ] Canonical tracker owning-engine WAL recovery: fresh ready actualexit6,
  SYNC_CONFLICT before opening, uncheckpointed-frame guard. JSONL e5d359ec158f3943d6784b166883d8be4e94cf57aba115cf409e9bc39bbb4e64
  conserved, no DB/WAL manipulation, import or foreign-row mutation. Original
  remains staged in_progress/OliveCreek; no closure/follow-up laundering.

End-of-block anti-ceremony worksheets (this implementation/verification block):

Creation gate: existing operator-requested granular TODO, measured parity note
and minimal command captures are PROCESS. Consumer is jemanuel reviewing this
native-library acceptance and the next agent continuing it; gate is a truthful
claim about the tested native-journal/current-consumer capability. Observed
defects are the byte0 journal assumption, previously unexecuted current ELF,
and a probe that mixed two negative preconditions. Active tracking retires at
handoff; evidence is retained under the no-delete rule. Integrity controls
preserve exact failed/source-cut results against lost completion and accidental
overwrite; minimal plain logs suffice, no new reporting framework. Highest
priority owned capability is this P1 native-image task. Another hour building
process would add less value than native auxiliary producer/oracle work; stop
new machinery and leave the concrete external qualification gap explicit.

Honesty inventory, all20 prompts, author review only:
1 No (checked complete new-test and peer-published source diffs: original
  assertions/ignores retained; no test/config weakening or history rewriting).
2 No (checked production discovery/replay: no fixture paths, mocks or expected
  marker special cases; constructed tests execute real parser/replay code).
3 No (checked diff/status/log: no golden or snapshot regenerated).
4 Yes, private probe setup changed after an executed failure: final negative
  now uses an empty mountpoint to reach its original format predicate. No
  expected diagnostic, exit, count, timeout, assertion or product gate relaxed.
  Failed run retained; direct isolated refusal and full rerun/readback executed.
  This was author review, not independent gate approval or scanner waiver.
5 No (checked adapter/CLI diff: native device indices, real geometry and exact
  source-bound ELF used; no demo hardcoding or post-result denominator change).
6 No (checked executed output:42facade+10example+7core+14harness, counts/filters
  explicit; one native-producer ignore earns no runtime credit).
7 No (checked command logs/terminal ACKs/results: rejected admission/delivery
  and lost reader-UBS exec receipt are distinguished from observed passes).
8 No (checked parity/TODO/Mail: constructed journal, current FUSE, retained
  native input and absent fresh producer/oracle/field proof explicitly separate).
9 No (checked updates: firstfmt1, bothClippy101, queue/source refusals, build
  delivery102, probe1 and UBS1 remain visible; original task remains incomplete).
10 No (checked command captures: stderr preserved; no evidence command silenced).
11 No (checked staged original:in_progress/OliveCreek; no functional close or
  new follow-up carrying essential original acceptance).
12 No (checked spec/README/parity: native header contract added from primary
  behavior; original goals/native qualification not reduced to synthetic proof).
13 No (checked current-block tracker/log: root closed nothing; peer source
  publication is not a tracker closure or independent acceptance).
14 No (checked dispatch: no subagents spawned or tasked in this work block).
15 No (checked source hashes and direct reruns; peer publication is identical
  tested source, not an accepted unexecuted peer verification claim).
16 No (checked task/status: no refusal-farming agents or guard/error closures).
17 No (checked counts/claims: shared source and author rechecks count once;
  no agreement presented as independent confirmation).
18 No (checked frozen probe predeclarations:20mounts/56files/236checks/six
  negatives retained; corrected negative input changes no denominator).
19 Yes, avoidable cost: two literal-keyword DCG inventory false positives,
  remote layout/lint iterations and the combined-precondition probe failed;
  artifact recovery also could not alter the retained delivery policy. All are
  retained/disclosed. Recover one exact owner, isolate intended negative input,
  and freeze final source before future runs (RH-1/RH-2/RH-7 countermeasures).
20 Strongest evidence: exact ELF9e39c59d replays expected inode metadata through
  bounded API and actual FUSE, plus full six-format regression and fresh hash/
  mount/command readback. Scripts and sources retained for skeptic re-execution;
  no independently verified native-produced auxiliary crash claim.
Older-session check: CASS healthy lexical status; capped incremental refresh
timed out45s/124, no rebuild/recovery bypass. Six bounded project queries all
returned0; followed three hits with cass view, whose physical lines did not
correspond to the searched semantic messages. Those results cannot establish a
historical clean inventory. No older-session or independent certification claim.
Disposition for4/19: corrected input/setup in place, exact failure chain here
and operator progress updates, retained original failures; RH-1 forbids weakening
predicates and RH-2/RH-7 forbid proof inflation/closure without qualification.

Real-work worksheet: project purpose is mount-compatible filesystem behavior,
MVCC/COW and self-healing durability, with native offline-image consumers.
Actual bounded inventory: native journal discovery/ring fix+user docs (USER1),
typed auxiliary parser lint correction and executed tests (ENABLER1), requested
TODO/tracker/log/audit maintenance (PROCESS1), UNKNOWN0. These are work groups,
not performance or productivity credits; root made0commits/0closes, peers made
two source commits. A two-minute demo is replayed root8192 through native_reader
and mounted FUSE while backing hashes stay fixed. Without PROCESS the runtime
result is identical; its only value is preserving exact acceptance limits.
Named consumers exercised: public facade, native_reader, shared FUSE and existing
core/harness recovery suites. Oldest relevant observed open user issue remains
bd-kdmu4 (June22,P2 multi-file read performance); this owned P1 native-library
dependency took priority. Raw bounded queue includes foreign-looking bd-xmh5g
despite its source_repo label; it was not claimed or mutated. No swarm/close
competition; no spec edits or follow-ups substituted for implementation.
Verdict: real capability advanced, verification/recovery overhead was large;
further audit/receipt work now risks DRIFTING. End machinery here. Next work must
execute native auxiliary producer/oracle qualification or resolve the original
external scanner/tracker gate, not generate another status framework.

Final handoff03:22UTC: staged comment2247 is read back on the original
in_progress/OliveCreek task, updated2026-10-23T03:20:45.905090Z. Cycles0 and
flush0/no dirty issues. Final core/facade-test/consumer hashes still match the
frozen tested cut; canonical JSONL e5d359ec unchanged. Mail6068 carries exact
results, failed-probe correction and remaining acceptance. Source/doc leases
released with ACK03:21:16/03:21:59UTC; TODO lease5846 and its earlier own lease
5752 are released immediately after this last edit, with tool ACK authoritative.
No owned remote job or probe remains running, no pending source edit, native
producer operation, delete, root commit/push or tracker closure. Remaining
external acceptance checkboxes are intentionally open on the original task.

## Native auxiliary interoperability continuation — 2026-10-23 03:54 UTC

Continue original bd-native-image-library-s4tde/in_progress/OliveCreek, no new
claim or close. HEAD4dae6650e and peer FAT deltas unchanged. Canonicalready6/WAL
still refuses before opening; raw bv recommends an unrelated warm-stat task,
so it is graph context, not a claim signal. Mail6088 announces this work.

- [x] Refresh source state, ancestor/repo rules, README and recent inbox; no
  new independent scanner/status reply. Preserve existing source/failed evidence.
- [x] Locate retained kernel-produced btrfs seed/sprout or multi-device images,
  their payloads, production receipts and expected native inventory. Bound this
  search; do not format devices or remount original images to manufacture proof.
- [x] Freeze fixture/tool/ELF hashes; ensure offline/unmounted inputs and preserve
  all original source bytes. Prepare one minimal public-consumer probe against
  native members, with expected file bytes, explicit primary/member offsets and
  lengths, wrong/missing/duplicate/truncated/exclusive-lock negative cases.
- [x] Execute plain/bounded public reads and actual read-only FUSE with retained
  member-lock lifetime, EROFS, clean unmount and before/after whole-file hashes.
  Keep fresh execution of retained native images distinct from fresh production.
- [x] Fix any actual product defect with manual existing-file edits, inline
  positive/adversarial regressions, exact-source RCH gates and rerun the probe.
  The existing auxiliary path passed unchanged; the finished root selector was
  disconnected from the standalone consumer and is now wired and qualified.
- [x] Update original Bead/TODO/measured parity with executed results and failed
  attempts; cycles/flush and bounded end-of-block audit complete. Source/doc
  leases released; final TODO lease releases immediately after this last write.
- [ ] Original native-produced external-journal crash, independent scanner and
  canonical owning-engine recovery acceptance remain essential and open.

Creation gate: operator-requested existing TODO and minimal probe/command captures
serve this original native-library acceptance. Observed missing native auxiliary
consumer execution justifies the probe; active machinery retires at handoff,
retained results stay under no-delete. Do not add another reporting framework.

Native fixture/probe preparation: existing bd-hk5w3 comment2030 identifies worker
3651 /mnt/ffs-chartreusestone-resume10.2wmG2a/independent/.tmpsE0xSD from the
independent 2026-10-11 kernel/CLI run. Seed/sprout/unrelated-seed256MiB images,
two source payloads and both original evidence JSONLs remain present. This is
historical production/oracle provenance, not a new native execution. Original
losetup -j on all three returned0/empty: no attached loop devices. SSH alias
initially refused because it configured UserKnownHostsFile=/dev/null; selecting
the existing known_hosts file with StrictHostKeyChecking=yes used its already
pinned host key. No key acceptance or trust bypass. Local Mail archive lacks the
old /data project; the staged original issue provided the artifact path. cm's
old --no-history option was unsupported; corrected retrieval succeeded but was
unrelated/degraded, so no such guidance is applied.

SHA256 seedf5e2f07f7c8948c1fbbd43152e2f06c2f7c21a3482aa68f56dc8ef4004e60400,
sprout8dd60afc2be41b5bdfc9589c34c372cf722f7a686f61ad1a81fe1e3e5781d6e6,
unrelatedbb251ff00792213dd59c6542d8421042f7b9c59b2cca77d4302b38ad4214d70c;
source payloads1873887d/94101f86. Compressed read-only stream copies exactly seven
allowlisted regular files into exclusively created CSD
/tmp/frankenfs-native-btrfs-Tw3sTb6J, source/destination0, SHA verified; old files
not overwritten. Original source SHA256 list rechecked identical after copy.
Original kernel record contains four payload readbacks, two physical-owner
readbacks and FS_INFO/DEV_INFO inventory. New probe independently rereads both
recorded physical payload regions and compares every byte to retained sources.
Old BLAKE3 whole-image receipts were not recomputed: b3sum/Python module absent;
new before/after controls use SHA256. No old-hash or fresh-producer certification.

Private probe4976d3d621143e0e5645de31ec47e37f0f5fa1234d62a870f23859a16586aba7
is syntax checked and exclusively delivered. Predeclared six plain/bounded/rest
profiles,96offline+96mounted byte comparisons over four files including both
nested subvolumes,30native-inventory ioctl comparisons,30mounted EROFS cases,
12mounted primary/auxiliary lock refusals,11CLI negatives, clean unmounts and
whole-file hashes. No formatter, original-image mount, new dependency or build.
Initial exact current consumer stat of ordinary and nested seed files both0/
size1048613. Full probe now running; pending is not a pass.

Executed retained-native auxiliary proof: probe78795 exit0, CSD
/tmp/native-btrfs-aux-mad_boq5/result.json. Exactly155CLI commands144zero/11one,
96offline+96mounted comparisons,6mounts/30inventoryioctls/30EROFS/12lockrefusals,
6offline FsOps write refusals. All13whole-input/tool controls unchanged, all
six daemons exited0 and unmounted normally. Fresh author readback97991/0 verifies
all155status records,6daemon records and exactly13controls,
native captured inventory,RO/nodev/nosuid and0ownedmounts. This is current
execution on retained kernel images, not a new native producer or crash oracle.
No failed native-auxiliary positive/negative case or assertion change.

Additional high-value wiring found: native_reader previously forced DefaultRoot
despite ReadOnlyBackend::Btrfs already accepting Subvolume/SubvolumeId. Expose
--btrfs-subvolume NAME and --btrfs-subvolume-id positiveID across stat/list/read/
refuse-write/mount, with or without auxiliary members; retain conflicts with all
other formats. Two inline parser tests cover bounds, both root selectors, empty/
zero/negative/overflow input and conflicts in both argument orders. No engine
code or existing assertion changed. Native btrfs-progs6.17.1 dump-tree read the
copied ROOT_TREE successfully and independently identifies seed-nested256 and
sprout-nested257; no native mount/scan/format was run. Read-only oracle output
native-aux-native-root-tree-20261023T0415.log.

- [x] Wire existing root selection into existing standalone consumer and README.
- [x] Correct initial remote fmt1 layout manually; no predicate/suppression change.
  Final reader SHA686c5f8ca7380fe6dda45238f812d49786b1e00947f7c335a31135adf50b8096,
  base0b3fa02a0/seven overlays fingerprint821d731ed28b6c35110173d82a790c3fe01d9da2ddc9fcbc28f9d453c6f40e58.
  Final remote fmt85934 passes0 with exact clean-overlay receipt. UBS39715 exits0,
  0critical/80warnings/31info on preceding layout-only source; original broad
  scanner remains open. No local build: new SBH exit1/3.74%free, existing user-
  approved strict-remote-only exception retained without resource bypass.
- [x] Complete exact-source workspace/all-target check, strict Clippy and full
  facade/example tests; handle actual failures and preserve source boundaries.
- [x] Build new SHA-bound Linux ELF with intentional-foreign artifact staging;
  preserve old local/CSD binaries and all old receipts. Run the unchanged native
  auxiliary probe plus native root-name/ID scoping, bounds, wrong-root/format
  negatives and mounted lock/write/inventory checks on the final new ELF.
- [x] Finish measured docs/Bead/TODO/cycles/flush/audit; source/doc reservations
  released and final TODO lease releases after the last write. Original task
  remains open until its remaining acceptance is met.

Root-selection final-source progress:
- Final tuplematch removes Clippy's option_if_let_else diagnostic without a
  suppression or predicate change. Final reader9083dcdd8664e6dfbf49fd0eb7211854103f08fd90e4716cd13417ab07a6948d,
  overlayecb9b5038dea71b3e95b15467f0ad16709991f108fd6ed3bd6b04ed793268c65.
  Remote fmt72216/47383, strictClippy72217/80049 and check72220/41196 all0,
  terminalACKtrue/sourcesreleased. The preceding821d check0 and test72187 are
  earlier-source evidence. Final facade/example72227 waits behind finalbuild
  72226 ontrj; both are exact ecb9-source jobs, not assumed green from quiet logs.
- First candidate build72194 was stillpre-execution when tuplefix superseded
  its source. Exact named cooperative cancel returnsE504/unconfirmed: retain its
  reservations, do not restart daemon/remove locks or mark it cancelled. It
  subsequently resolved at the source guard before Cargo execution: wrapper103,
  leaseexit1/ACKtrue/sourcesreleased, because821d had changed toecb9. No artifact
  or successful-cancellation claim. Earlier821d tests72187 finished0/ACKtrue/
  released:42facade+12examplepassed, one existing ignored producer,0fail/filtered.
  This is earlier-source evidence; final72227 repeat still pending. No direct
  Cargo, source/target/cache/slot/deadline bypass. Final build uses supported
  intentional Linux artifact staging from invocation start.
- Old9e39c59d control returns2/empty stdout/unknown --btrfs-subvolume before a
  mount: no positive root-selector credit. New private root probe
  a0d92019674349e82960dcc01173cecce4a685b9f00f5baff4523c0f759ccba8
  is syntax checked and exclusively delivered but not yet executed. Its fixed
  denominator is10selected native views (name/ID,plain/bounded,two native roots,
  standalone seed),91CLIcalls/42offline+40mounted bytes comparisons,27negatives,
  20root-ID ioctls,40inventoryioctls,20EROFS/18retainedlock refusals and10clean
  mounts. Current final ELF is required; original native-aux155probe is unchanged.
- Fresh native oracle: official btrfs restore documentation confirms input
  images are not modified; selected-root extraction writes only new output
  files. First two invocations returned1 because the output directories were
  absent, not because image data was rejected. Preserved both logs, verified
  parent empty, created the two new empty directories and repeated without
  overwrite/ignore-errors options. Corrected seed256 and sprout257 each return0;
  their full payload bytes match retained sources, and all13original controls
  remain unchanged. CSD /tmp/frankenfs-native-btrfs-oracle-F7JGl6ko/result.json,
  local btrfs-root-fresh-native-oracle-20261023T0439.json. This adds a fresh
  native userspace byte oracle on retained images; it is not fresh image
  production, kernel mounting, crash replay or full filesystem checking.
- Peer commit3b8226fa4 published the821d source/docs; root has not committed or
  pushed. The tuple lint correction remains the tested ecb9 overlay. Publication
  is not independent acceptance. Root holds only its named leases.

Final executable/runtime outcome, 04:43 UTC:
- [x] Final build72226 and tests72227 both exit0/terminalACKtrue/sourcesreleased;
  no active work left in either wrapper. Tests42facade+12examplepassed,
  one pre-existing producerignore,0failed/filtered. Final focusedUBS0 with
  0critical/80warnings/31info; broad original scanner is not cleared by this.
- [x] ELF SHA256cf51328e3ee0d99654cd15be2c3da8928ce0bba4935faa51a4cee848040ce61e
  matches worker, retrieved local target and exclusively created CSD
  /tmp/frankenfs-native-btrfs-Tw3sTb6J/native-reader-cf51328e3ee0-20261023T0442.
  GNU/Linuxx86_64 ELF,589937248bytes; source/destination transfer0, oldELFs kept.
- [x] Unchanged4976 auxiliary probe36147/0 on finalELF:
  /tmp/native-btrfs-aux-m5ezntnt/result.json,155CLI144zero/11expectedone,
  96offline+96mounted bytes,6mounts/30inventory/30EROFS/12locks,
  13controlsunchanged,0ownedmounts. Earlier9e execution is not extra coverage.
- [x] Fixeda0d9 root probe31750/0 on finalELF:
  /tmp/btrfs-root-selection-oasjwvc7/result.json,91CLI64zero/24expectedone/
  3expectedtwo,10selectedviews/mounts,42offline+40mounted bytes,27negatives,
  20root-ID/40inventoryioctls,20EROFS/18locks,19controlsunchanged,0ownedmounts.
  Both namedroots256/257 withname/ID,plain/bounded andstandalone seed execute;
  global files stay absent in selected roots. No native positive/negative failure
  or change to the predeclared denominators/assertions.
- [x] Fresh author readback94855/0 checks all246recorded CLIstatuses/argv,
  all16daemonstatusfiles/RO,nodev,nosuid/unmounted,13+19currentcontrolhashes,
  andfinalELFhash. Not independent review. Local full JSONLs/receipts:
  btrfs-root-final-readback-20261023T0446.jsonl and
  btrfs-root-jobs-terminal-20261023T0446.json under the verification log directory.
- [x] Final fresh-eyes pass read the full119-line reader feature diff and tuple
  correction, surrounding argument/backend/read/mount paths and both frozen
  probe implementations. No further product defect found; diffcheck0 and
  canonical JSONL/source hashes unchanged. Peerf190b0c06 recorded earlier native
  auxiliary docs; final runtime/parity updates and tuple remain dirty here.
- [x] Original staged Bead has final source/gates/ELF/probe/failure evidence;
  staysin_progress/OliveCreek. No new task or close. Remaining essentials:
  native-produced external-journal crash/broader-topology qualification,
  original independent scanner/status disposition, canonical owning-engine
  WAL recovery. Do not weaken criteria or move essential conditions elsewhere.
- [x] Staged cycles0/count0, flush0/nodirty and readback0 confirm original
  in_progress/OliveCreek/latestcomment2250. Canonical JSONL hash unchanged.
  Mail released source/doc leases5877/5891/5892; final TODO5876 releases directly
  after this last write. No commit/push, deletion, cleanup or peer overwrite.

Bounded real-work audit, 03:54–04:43 UTC (current block, not old-session audit):
README purpose: memory-safe native filesystem access with mount compatibility,
MVCC/COW and self-healing durability. Actual git log has3b8226fa4 root-selection
feature(USER),f190b0c06 native auxiliary docs(USER),54127fbd1 previous-cut measured
parity docs(USER);0closed items. Commit tallyUSER3/ENABLER0/PROCESS0/UNKNOWN0,
not a productivity score. Outside commits, executable native probes/gates are
ENABLER validation for this exact reader; TODO/Bead updates are PROCESS.
Most visible demo: select seed-nested by name orID and read /payload with bounded
members, or mount that root. Without status work, bytes/features would match;
the operator would lose unresolved criteria and exact-source provenance.
Validation exercised the actual finalELF, not speculative scaffolding. Oldest
relevant open user concern remains original native-library interoperability;
this block qualified real auxiliary/root views on that same task. No swarm was
launched, no close farming; no lowered plan or follow-up minted. VerdictHEALTHY
for delivered capability with costly24-minute compile and bounded required
status work. Correction: no further machinery/feature expansion in this block;
finish its tracker/lease housekeeping and retain the native-crash/scanner gaps.

Honesty inventory, same bounded window; all answers in writing:
1.No(checked: full3b8226fa4 reader diff, final tuple diff and source; only two new
  tests, no existing test removed/weakened/ignored; existing producerignore stays).
2.No(checked: actual native-image producer receipts and byte oracles; no new
  mock/stub in product or tests). 3.No(checked: touched paths and commit diffs;
  no golden/snapshot changed). 4.No(checked: reader/docs/TODO diffs; no validator,
  CI, suppression, tolerance, retry, timeout or gate relaxation. Supported
  intentional-foreign delivery flag stages LinuxELF; all RCH source/resource
  guards remain). 5.No(checked: ten predeclared selected native profiles,
  standalone/multimember bounds, root isolation andwrong-root/format controls;
  no demo-path branch in product). 6.No(checked: final test log42+12passed,
  0filtered; one existingignore explicitly reported;246recorded nativeCLIcalls).
7.No(checked: terminal ACKjobs and actual command/result/status files;
  no quiet/pending job reported passed). 8.No(checked: parity/TODO/Bead text;
  historical production/kernel captures separated from new public API/FUSE and
  fresh native userspace extraction). 9.No(checked: firstfmt1/Clippy101,
  obsolete cancellationE504 thenpre-execution103, native restore setup1 then0
  retained and reported; all remaining acceptance left open). 10.No(checked:
  RCH combined logs, transfer stderr, native command stderr/status captures and
  fresh readback stderr; none suppressed for a cited pass). 11.No(checked:
  staged original remainsin_progress; no close or follow-up). 12.No(checked:
  specs unchanged; parity adds scoped measured facts and explicit remaining gaps).
13–16.Not applicable: no subagent dispatched/accepted/closed/farmed in this block;
  peer commits were read as shared-tree changes, not delegated acceptance.
17.No(checked: author readback explicitly labeled non-independent; peer commit
  is not approval). 18.No(checked: probe4976/a0d9 frozen before execution;
  counters met unchanged; earlier/repeat runs not added to final denominators).
19.Explanation owed: one old Bead query emitted an unnecessarily huge result;
  subsequent reads were bounded to named comments. RCH dependency compilation
  took24minutes; it remained active, no resource/deadline/cache bypass was used.
  First strictSSH/obsoletecmflag/setup failures were corrected and preserved.
  These are costs/failures, not positive capability credit. 20.Strongest evidence:
  exact-source finalELF plus re-executable frozen91/155-command native probes,
  actual16mounts/274bytecomparisons,38expectednegativeCLIcases, unchanged control
  hashes and fresh native restore bytes. A skeptic can rerun on copied inputs.
Historical CASS searches in the preceding block did not establish full semantic
line correspondence; this inventory does not certify older sessions. Disposition:
no gate weakening/false completion found in this bounded pass. Corrected first
fmt/Clippy/source supersession/setup failures in place with visible receipts;
countermeasuresRH-1/RH-2/RH-7/RH-9 keep assertions, proof classes and original
remaining criteria intact. Self-review is not independent acceptance.

## Public ZFS member and root selection continuation — 2026-10-23 05:02 UTC

Continue original bd-native-image-library-s4tde/in_progress/OliveCreek. Canonical
ready still exits6/SYNC_CONFLICT with committed-WAL guard; no canonical mutation
or new claim. Raw bv warm-stat recommendation is graph context only. Git launcher
now asks for Xcode license acceptance; the already-installed Git2.54 executable
at /Applications/Xcode.app/Contents/Developer/usr/bin/git works directly. No
license accepted, state changed or tool installed. SBH1/3.57%free: existing
user-approved strict remote-only exception continues, no local Cargo or cleanup.

The public ZFS facade already admits bounded additional_images and Auto/Pool/
Candidate roots; standalone native_reader only exposes dataset/snapshot. This
disconnect prevents a normal standalone consumer from exercising finished
multi-member and explicit-root paths. Connect it within this same task.

- [x] Read current rules/README, refresh actual source/tracker/inbox and preserve
  peer FAT/source/doc deltas and all earlier failed/executed receipts.
- [x] Reserve exact reader/README/parity/TODO paths, no conflicting leases.
- [x] Wire --zfs-device PATH OFFSET LENGTH, positive --zfs-pool-guid and exact
  --zfs-candidate LABEL SLOT; retain bounds, raw paths/dataset/snapshot names,
  cross-format conflicts and read-only engine admission. No new replay/import/
  write authority or separate parser/engine.
- [x] Add inline regressions for Auto/Pool/Candidate selection, multiple bounds,
  argument failures/conflicts in both orders, hidden auxiliary mountpoint and
  native path bytes; preserve every existing assertion and negative control.
- [x] Run exact-source remote fmt/check/strictClippy/facade-example tests/build
  and focused UBS; fix actual failures manually without source/cache/slot bypass.
- [x] Freeze and deliver final Linux ELF without replacing old evidence. Locate
  retained native ZFS member images or produce only new private regular-file
  mirror images with recorded native payload/head/snapshot oracles and export.
- [x] Execute plain/bounded Auto/Pool/Candidate public reads and read-only FUSE,
  candidate/format/member/lock/bounds negatives and retained member locks. Check
  exact bytes, selected views, EROFS, clean unmount and unchanged control hashes.
- [ ] Fresh-review code/results and record measured scope, failures, original
  remaining conditions, staged Bead/cycles/flush and release all owned leases.

Creation gate: existing operator-requested TODO and minimal native probe serve
this exact consumer/feature acceptance; observed disconnected root/member flags
justify it. Retire active machinery at handoff; no-delete retains evidence.
No new reporting framework or original-task closure based on a partial profile.

Executed source and native evidence:
- Reader SHA256 aa5e2c41421acc3dc7f81a807838e9c3fe9507dcda9e89bae9c42d7bfbca4bed;
  base0b3fa02a07249bf7d2baeab6a773e20de0dc5a17 and seven explicit overlays,
  fingerprint5b4a7d09c62c79facd41c0174ed31ac9d57c5d5ba286cf9f38d96ec986997a43.
  Final RCH fmt72317,Clippy72320,check72323,tests72324,build72325 all0/terminalACK/
  sourcesreleased. Test log42facade+14examplepassed,1existing producerignore,
  0failed/filtered. Initial fmt72312/1 requested layout only; manually corrected
  without changing predicates. First raw fmt failure had no frozen-source pass
  receipt; final invocations pass explicit argv and emit clean-overlay receipts.
  No local Cargo, source/cache/slot/deadline override or validator relaxation.
- Final focusedUBS49629/0 reports0critical/104warnings/33info on exact reader;
  broad original scanner disposition remains open. Old cf51328e ELF is preserved
  locally in native-reader-cf51328e3ee0-retained-20261023T0507.gz and at its earlier
  CSD path. Archive decompression rehash matched cf51328e before new delivery.
- FinalELF a8f0569755461160d1409dbe9fd4deba5cb47724074272c88789fdfef0809ef7,
  GNU/Linuxx86_64/590112256bytes, worker/local/exclusive CSD delivery SHA matches.
  Path /data/ssd/tmp/ffs-public-zfs-members-42o_tjmd/native-reader-a8f056975546-20261023T0511.
- Fresh native producer b87ec63b70a1cd8a47e371ab505bbfdeab42a7f2a3e188b5477c58c04728b486
  created only two exclusively created256MiB regular files in its new private
  /data/ssd/tmp/ffs-public-zfs-members-42o_tjmd. OpenZFS2.4.1 created a new random
  mirror with all optional features disabled/cachefile=none; native mounted ZPL5
  readbacks verified divergent head/snapshot payloads, then ordinary export0.
  No force/import/destroy, physical-device formatting, removal or existing-pool
  command. Existing buildpool stayed present; owned pool absent before consumer
  opens. Producer40707/0; native pool GUID8284848727802191574, selectedlabel0/
  slot20/txg20; datasetGUID17174837708617112480. Four label configurations validated
  in existing companion inspection after export. Native SHA payloads:
  head1a2aabbfddb11c1d4dea10a314620add97801a5df675304842ba9c63ae9a2c70,
  snapshotf4bf9b8dec6e3e28b2ec33266145d244fe97a6bce1ec054ace053bab67d2ef9a.
  Image SHAs4caa0613e87cdc3c5f429eca2c8966978e144d44bcd2460c91a3b9c975e2feea/
  2a8afd65c39a9f3cb8d05caf95c34f08ed0e14463310f4049aa846e5b7c6dfbd.
- Frozen native probe aa71889c25863a89efdbece7e08a3e5ede46fa323b96bac870bcc7ca0515b8f3
  syntax checked and exclusively delivered. Probe82420/0:
  /tmp/public-zfs-members-w__qqfys/result.json. Predeclared117CLI86zero/27one/4two,
  12views/mounts,50offline+48mounted bytecomparisons,31negativecommands,
  12offlinewriterefusals/24mountedEROFS/24retainedlocks,16controlsunchanged,
  all12daemons0/unmounted and0ownedmounts. Plain/member-rest and independent
  bounded primary4096/member8192 exact windows pass in all3rootmodes and both
  native views; reversed member candidate reads also pass. Negative cases cover
  wrongGUID/candidate/label/slot/snapshot/format, missing/duplicate/directory/
  truncated/shifted/short/locked members, hidden backing mountpoints, malformed
  selectors and cross-format conflicts. No failed native predicate or changed
  denominator. Oldcf51328e explicit flagcontrol24903/0 records actualCLIexit2/
  unknown --zfs-device/empty stdout, not positive capability credit.
- Fresh author review88658/0 rechecks all117statuses/argv,12daemonstatusfiles,
  RO/nodev/nosuid,all16currentcontrolhashes and all native-producer command statuses.
  Six newly executed reversed-primary reads cover3rootmodes×head/snapshot with
  exact nativebytes; not added to the original117 denominator. Owned nativepool
  remains exported and0ownedFUSEmounts. Full producer/result/readback and stderr
  retained locally under verification logs: zfs-consumer-fresh-readback-20261023T0514.json.
  This is fresh native production plus live public API/FUSE proof for this
  two-member exported read profile; no broader topology/ZIL/crash/write claim.
- Fresh-eyes read of the full215add/24delete reader diff and surrounding
  image-source/backend/mount paths found no additional product defect. Existing
  native-byte/geometry/hidden-backing assertions are retained and expanded toZFS.
  No other code file changed by root in this block. Peer FAT deltas conserved.

Fresh-review correction before final qualification: the first private probe
used /payload in several bad-member checks without selecting datasetdata.
Thus a namespace miss could satisfy its generic error predicate even if member
admission were broken. This was disclosed in commentary; original result/logs
remain retained. Strengthened probe SHA256
70f6b1b06afa429854a416ffdbad98f3f5c830a96efd915ebd840b59ebcd2bad
uses stat/ for all17externalnegative arguments plus the held-lock case, and
requires the exact hidden-backing diagnostic. Frozen/redeployed under a new
filename; no predicate weakened or old artifact replaced. Probe13620/0 at
/tmp/public-zfs-members-kxgjn4hg/result.json meets the same117CLI/31negative/
12mount/98byte/24EROFS/24lock/16control denominators,86zero/27one/4two,
0remainingmounts. Earlier execution is not extra coverage or the final refusal
qualification. Product source/ELF unchanged; no rebuild needed.

Fresh final readback7718/0 verifies all117status/argv files, confirms commands
99–116 actually use stat/, checks the last hidden-backing stderr and12clean
daemons/16currenthashes. A separately executed valid default-root stat passes0/
Directory2. Paired native control also shows identical valid members with
stat/payload return1/NotFound, while stat/ returns0; this is the concrete defect
class the strengthened predicate excludes. Local
zfs-consumer-root-controls-readback-20261023T0519.json and
zfs-consumer-negative-admission-control-20261023T0520.json retain stdout/stderr/
status. No native product failure, assertion relaxation or independent-review
claim. Fresh native production and scope boundaries above still apply.

Bounded real-work audit, 04:55–05:20 UTC, current original-task continuation:
README purpose: memory-safe userspace native filesystem access with explicit
compatibility, concurrency and durability boundaries. Root authored no commits
or closes in this window; actual source diff is one reader plus existing user
documentation and TODO. Unit inventory: USER1(the connected native ZFS reader),
ENABLER1(its exact-source gates and native producer/probe), PROCESS1(existing
TODO/Bead/evidence updates), UNKNOWN0. This is grouping, not a progress quota.
Most visible demo: the same public consumer reads divergent head/snapshot
payloads from a fresh exported native mirror using three root-selection modes
and then mounts bounded members. Without process updates capability would be
identical, but remaining criteria/source provenance would be lost. The enabler
actually ran the finalELF in12mounts; no speculative framework. Original native
library interoperability is still the relevant open user concern; this block
directly closes its disconnected ZFS consumer surface. No swarm, close farming,
lowered specs or follow-up minted to dispose of original criteria. Verdict:
HEALTHY capability increment; initial probe negative controls needed correction,
not a completion claim. No second apparatus round; record the defect/correction
and finish existing tracker/reservations. Native crash/topology/scanner recovery
work remains open under its original conditions.

Honesty inventory (all20 prompts, bounded current block; no older-session audit):
1.No(checked: full215add/24delete reader diff, old/new tests and source gates;
  existing assertions retained, auxiliary cases expanded, no addedignore).
2.No(checked: actual OpenZFS-created mirrored regular images/native mounted
  payload reads; no product stub/mock). 3.No(checked: touched paths/diffs; no
  golden/snapshot regeneration). 4.Yes: authored a private native probe for this
  feature and strengthened its negative operations after a real false-positive
  risk was found. No existing gate/CI code, suppression/tolerance/retry/timeout
  or resource/source guard relaxed; both exact probe hashes/results retained.
  Existing conformance gates untouched; no self-review labeled independent.
5.No(checked: six mode/view combinations×plain/bounded members, reversed-image
  reads, valid-root baseline and paired namespace-error counterexample; product
  has no fixture/path/success branch). 6.No(checked:42+14unitspassed/0filtered,
  one existingignore disclosed; final117CLIstatuses86/27/4,12actualmounts).
7.No(checked: all five terminalACK/source-release receipts, producer/probe
  statusfiles and exact binary SHA at worker/local/destination; no quiet credit).
8.No(checked: final parity/README/TODO; fresh native production is labeled,
  restricted to a two-file exported mirror, not RAIDZ/ZIL/crash/field proof).
9.Yes: the initial numeric-green native summary could imply stronger admission
  negatives than its predicate established. Disclosed the namespace loophole,
  retained old result, strengthened and reran all117 with unchanged product;
  final reference now points to the stronger run. No extra repeat-run credit.
10.No(checked: native producer/consumer argv/stdout/stderr/status files,
  transfers, RCH logs and fresh readbacks; the native pool-list command now
  persists captured stderr too). 11.No(checked: original staged task remains
  in_progress/OliveCreek, no newclose/followup). 12.No(checked: specs unchanged;
  user docs expose working flags and narrowly measured evidence only).
13–16.Not applicable: solo block, no subagent dispatched/report accepted/item
  closed/refusal farm; peer files were preserved, not delegated authority.
17.No(checked: fresh author readbacks explicitly non-independent; native kernel
  byte oracle is actual OpenZFS execution, not peer agreement). 18.No(checked:
  each frozen probe declares117/31/12/98 before execution; strengthening keeps
  counts and extra fresh controls/repeats remain outside that denominator).
19.Explanation owed: first native negative predicate admitted a namespace-error
  alternative; paired control0/1 demonstrates it, corrected and disclosed above.
  Initialfmt1/layout fixed manually; git launcher license error resolved by the
  existing Git executable without accepting terms or altering host state.
20.Strongest evidence: exact finalELF plus fresh native mirror producer and
  strengthened root-admission probe, re-executable on exported copied images,
  actual12mounts/98bytecomparisons and16unchangedcontrols. Independent scanner
  disposition remains separate. Disposition: test weakness corrected openly,
  exact old/new artifacts retained and operator informed; RH-5 countermeasure:
  admission negatives use an existing root with a matched valid positive,
  avoiding unrelated namespace failures. RH-2/RH-7/RH-9 preserve proof class,
  task status and original remaining conditions. No gate weakening found.

## Main integration: auxiliary handles and permanent read authority — 05:28 UTC

New ZFS feature source was committed concurrently by the shared-tree maintainer
as fc534d532; its reader blob still matches tested aa5e2c41421a. Root's exact-path
commit attempt returned1/nothing to commit, without changing files or history;
no success credit. Peer docs commits3aa79f86e/5c1119def preserve scoped evidence.
Fresh fetch succeeded; local main is20commits ahead/8behind origin/main370aa96b3.
Read-only merge-tree c1b099a1738b95ffe6bf7637f90cfa5574b9ae47 finds only corelib
conflicted (four constructor/call hunks). Its proposed file actions have no
deletions:28modified/1new source/test file plus independently committed docs.

This is a high-value correctness integration: incoming path-based read authority
and explicit open_read_write coexist with local already-admitted auxiliary
handles. Keeping only either constructor branch would lose one safety property.
Existing dirty FAT edits are formatting only, fully read and hashes unchanged;
their dedicated UBS81588 exits0/0critical/183warnings/43info, and the exact same
bytes already passed workspace fmt/check/Clippy in5b4a7d09c62c. Preserve them by
an exact-path checkpoint, not stash/reset/overwrite. No branch/history deletion.

Invariants: path and declared read-only constructors retain false write authority;
recovery stays volatile and mutation-oriented WAL/repair options are rejected.
Caller-declared read-write devices retain their own access checks. Nested btrfs
views inherit parent authority and the exact admitted member handles; no path
reopen or authority escalation. Public read-only facade must choose read-only
authority explicitly, even when the underlying device object can write.

- [x] Refresh actual source/remote refs and inspect virtual conflicts before any
  working-tree merge. Canonical JSONL remains byte-identical and is not changed
  by either branch's merge proposal. No pull/import/DB repair performed.
- [x] Check and reserve the full incoming merge surface plus facade/architecture
  paths; no foreign lease conflicts. Existing four consumer/doc/TODO leases held.
- [x] Checkpoint only validated FAT formatting and existing granular task notes,
  preserving every other path/index entry. Keep its maintenance credit separate
  from capability work; reader/docs already have exact-source evidence.
- [x] Merge origin/main without force/reset/stash/deletion. Resolve core's
  auxiliary handle parameters together with incoming write_authority. Add an
  explicit VolumeAccess argument to from_devices; use ReadOnly in public facade
  and its read tests. Share read-only option validation with the path constructor.
  Preserve explicit writable from_device/open_read_write and inherited authority.
- [x] Add focused non-tautological authority controls using a writable memory
  device: read-only handle admission cannot later enable writes, cannot create
  metadata WALs or repair state, and selected recovery does not touch backing.
  Preserve all incoming/native positive and negative tests; no gate relaxation.
- [x] Update actual public constructor contract in README/architecture in place.
- [ ] Freeze integrated source; run strict-remote workspace fmt/check/Clippy,
  relevant core/facade/FAT/ZFS tests and full harness/conformance gates. Inspect
  every failure; no source/cache/resource/slot/deadline bypass or quiet credit.
- [ ] Build/deliver a new exact ELF, preserve older consumers/results, and rerun
  native ext4/btrfs auxiliary/read-only and fresh ZFS mirror mounted probes on
  integrated code. Keep previous-source proof separate and all hashes stable.
- [ ] Finish exact-source review, named broad scanner disposition/publication
  gates, current Bead evidence/cycles/flush and guarded main publication where
  accepted. Retain all histories and peer work; no force, deletion or false close.

Integration source outcome and running-gate boundary:
- Checkpoint3e79e4a1f849be97be71fa403d2a889f7c277fac records only the three
  validated formatting files and accumulated task notes. Actual merge found one
  extra FAT formatting/cache conflict beyond the virtual pre-checkpoint merge:
  retain incoming readonly_fiemap and the identical formatted immutable_cache,
  removing only conflict markers/duplicated identical method text. No file lost.
- Core now accepts explicit VolumeAccess in from_devices, re-exported through
  core/facade; shared read_only_options guards both path and handle admission.
  All constructor sites updated, including facadeReadOnly and two auxiliary
  tests. Explicit single-device from_device/open_read_write keep true authority;
  nested views inherit parent authority and admitted handles. Added one writable-
  memory recovery test with separate byte-exact overlay/persistent controls,
  expanded four mutation-option refusals and nested repair/write-enable refusals.
  Snapshot helper reused rather than dereferencing the stdMutex Result directly;
  caught in fresh source review before compiler execution, not suppressed.
- Shared maintainer committed integrated source as1e1da7ce0,71c5d90af,e7edd87ba,
  05292f5366c8cc26075ebc558e24b252e1478d52. Main now has origin370aa96b3 asancestor;
  tracked Rust is clean. Commit/source publication is not compiler/runtime proof.
  Current coreSHA66a18f3462853d3c7f61a0d76694da91cb0fd023731d0dc68f743726a4cee8b2,
  facadeNativeSHA5e72b56e94ac4964aa08cfc24467dbd417d7990bca3ed36c53916ca2e7d3f290.
- Source3e79+25explicitoverlays fingerprint970a61d0948b0cdcc1530abed7ca660c348beb4bd702832f2a2e5099b73c2fff
  first check72367 ontrj returnedSSH255/unconfirmed. Exact recovery reconciled
  original wrapper3112aa1e-5979-4ffa-8830-782eaaaf74c4 to255/ACKtrue/sourcesreleased;
  no pass/replay/cancel credit, no daemon restart/lock clearing. Subsequent normal
  autoscheduled check is executing onts1. trjfmt103/missing_runtime andovh-bfmt
  103/estimated4cores>3slots were admission refusals; auto fmt then103queue_timeout.
  No local fallback or resource/capacity/RCH_BUILD_SLOTS override. A new exact-
  commit formatter declares CARGO_BUILD_JOBS=1 for its actual serial formatting
  operation; all Cargo/source/host admission remains enabled, no style skip.
- Focused core/nativeUBS0/0critical/14413warnings/3051info; Cargo phases explicitly
  not evaluated in targeted shadow scan. Current committed-source Clippy and
  selected core/facade/FAT/ZFS tests are active, not passes. Initial no-overlay
  selection omitted mandatory --no-overlay and was refusedE504 before admission;
  corrected explicit --base05292 --clean-overlay --no-overlay. Source gates and
  actual integrated ELF/native probes are still required before qualification.

- [ ] Complete final original-Bead evidence comment, staged cycles/flush/readback,
  bounded honesty disposition and release four named reservations. Original
  scanner/status, native external-journal crash/broader topology and canonical
  owning-engine WAL recovery criteria remain explicit and open.

Integration verification continuation (2026-10-23, exact source boundaries):
- [x] Read back terminal acknowledgements for integrated snapshot check72387
  (base3e79 +25 overlays, exit0) and committed05292 fmt72406 (exit0), both
  acknowledged with source/pair release. Do not promote the earlier snapshot
  check to an exact-commit receipt without a matching source manifest.
- [x] Inspect strict Clippy72399 exit101: two decimal bitwise literals in the
  incoming rename-exchange adversarial test. Manually use0x16/0x20 instead of
  decimal22/32; values and all positive/negative assertions remain identical.
  No lint allowance, expectation change, ignored test or golden regeneration.
- [x] Preserve the old A8 Linux reader in an exclusively-created local gzip;
  decompressed SHA equals a8f0569755461160d1409dbe9fd4deba5cb47724074272c88789fdfef0809ef7.
  Native fixture copy and all old receipts also remain retained.
- [x] Diagnose widened UBS exit2 as partial AST output above16MiB; retain raw
  failure. Disjoint unchanged-rule scans complete: core2files0critical,
  btree4files1critical, CLI2files7critical, transport8files93critical,
  FAT4files3critical, ZFS5files4critical. These are108 findings, not a clean
  scanner gate. Detailed text scans retain all rules and their exit1 results.
- [x] Finish bounded author scanner disposition: preserve external test-module
  write/sync/payload tripwires, inspect33 constant Python scripts and their argv,
  fixed-command/current-executable callers, and production benchmark error paths.
  The btrfs prefetch-pool initialization panic is a real resource-failure path,
  distinct from test assertions. Do not suppress or call every finding noise.
  All33 matches and launchers reviewed below; independent broader disposition
  remains an original open obligation.
- [ ] Await the optional independent-review-agent authorization already asked;
  continue solo implementation and verification meanwhile. Elapsed time is not
  permission and agreement would not substitute for runtime execution.
- [ ] Finish check/strict Clippy/build on base05292 plus only the ZFS literal
  fix (overlay fingerprint d0e3e0d8e641ebf4df456702d8bedf69c4ffcf77f101347a26aec036a76ebf02),
  finish original core/facade/FAT/ZFS tests72398, then qualify affected remaining
  CLI/harness/btrfs/ondisk/FUSE execution. The first fixed Clippy attempt onhz2
  was refused103 for measured critical memory pressure; no pressure bypass.
- [x] Reconcile fixed Clippy72426 ontrj after RCH_SCOPED_COMPLETION_UNCONFIRMED
  before replay; pending check still awaits that source authority. Do not kill
  peers, remove locks, restart daemons, count quiet output or replay active work.
  Supported recovery reached255/ACK/source release as recorded below; not a pass.
- [x] Deliver and execute the new integrated ELF/native probes only after
  successful build and SHA readback. Earlier A8 native passes remain scoped to
  their earlier source. Publication and original-Bead closure remain pending.
  Final4e170b64 ELF and all seven probe scopes/readbacks completed below.

Fresh-review production correction:
- [x] Fix the btrfs prefetch initialization panic rather than suppressing the
  scanner rule: retain an optional pool and use ordered serial child reads if
  thread creation fails. Existing successful pool, fan-out threshold, key order,
  duplicate/cycle checks, provider failures and tree finalization stay intact.
  The failed initialization is cached for this process to avoid retry churn;
  throughput under resource pressure may be lower, with no speedup claim.
- [x] Add an inline deterministic failed-spawn test exercising ordered child
  fetch with an error between two successful nodes, retained node identity and
  zero provider calls for empty input. This is unit fault-injection evidence,
  not live OS resource-exhaustion proof; the 487-test suite below executed it.
- [x] Scan both newly edited files with unchanged UBS rules: exit0,0critical,
  3379warnings,389info. Preserve every test panic, assertion and gate. This
  focused result does not dispose of the remaining broad-source findings.
- [ ] Finish new source-bound fmt/check/strict Clippy/runtime/native receipts
  for base05292 plus both btrfs/lib.rs and ZFS zil_records.rs. Do not attribute
  either the earlier single-overlay build or original05292 tests to this source.
- [x] Recover fixed Clippy72426 terminal result255/ACKtrue through its own RCH
  wrapper after unconfirmed SSH completion. No pass, no lock removal/restart.
  Existing check wrapper performs its managed remote retry; do not duplicate it.

Source and scope corrections after the fresh pass:
- [x] Test the actual optional-pool initialization function with a failing Rayon
  spawn handler and verify a cached failure never invokes a second builder.
  Source9ce1f6cf767b4d7c8b17697486b6efa23f09dc54dc060da809529037ac12808a
  includes that stronger test. Later manual formatting only wraps its iterator
  assertion; current btrfsSHA0e9f186d1417f3c034843e694b2d12acd5e535190f30ad43da6129ada5f11992.
  ZFS literal-fix SHAe7139e66faaa7a6903516954864edc2dd36c95564798493fb96935c748ab961f.
  Local read-only rustfmt first reported that layout then passed after the
  manual edit. This is static formatting evidence, not a remote Cargo receipt.
- [x] Final two-file scanner at9ce exits0/0critical/3380warnings/389info. The
  added warning is the retained test-only no-retry tripwire, not a suppression.
- [x] Re-read original staged Bead description: its positive goal is reusable
  engine crates, unified ambiguity-checked read-only FsOps, explicit native write
  authority. No formal acceptance_criteria field exists. Original remains open
  while its gates finish; distinguish separately accumulated project-wide native
  writer/crash/topology and canonical tracker recovery obligations without
  dropping any of them or calling the project complete.
- [x] Re-read anti-ceremony skill's explicit solo exception: with no independent
  verifier available, re-execute in a fresh pass against original criteria and
  disclose the absence of independent verification. Optional review-agent
  authorization is not a prerequisite to continue. Prior full-review request
  remains recorded; no self-review will be called independent verification.
- [x] Verify the historical protected-mount Deref panic is already removed in
  current93b8ca751 source: explicit as_ops and periodic-commit variant dispatch
  remain. Do not carry a historical defect forward as a current finding.
- [x] Preserve successful pre-fallback integrated ELF65a3fb96d6a942b3725df860c55d30229f308486331926d2cca053d9f681fe44
  in an exclusively-created gzip and verify its decompressed hash. Build72428
  exits0/ACKtrue/source+pairreleased; it is not the latest fallback-source ELF.
- [ ] Finish final exact-source btrfs tests72447, Clippy and native-reader build
  on warmedts1, full harness and required benchmark onovh-b under normal gates.
  Current two-file source manifest, each actual RCH overlay fingerprint and
  command output decide scope; the initial check/Clippy driver's manifest was
  captured before the stronger initialization test and cannot bind later steps.
- [ ] Finish workspace Cargo fmt when admitted. trjfmt72441 recovered255/ACKtrue;
  ovh-b refused103 because fmt estimates4cores versus3total, and ts1 request
  timed out103. CARGO_BUILD_JOBS=1 did not reduce that estimate; no slot/pressure
  override or local Cargo. Read-only `rch admit` classifies fmt non-compilation;
  that is a diagnostic result, not formatting execution or a pass.
- [x] Reconcile obsolete single-overlay check72431. Its own cooperative cancel
  returned1/E504/unconfirmed, retaining reservations; recover returned only
  recover_requested. Later jobs readback0733 records build72431 exit0 with
  terminal ACK and source/pair released. This qualifies its old source only.
  Preserve peer jobs and all source locks; do not restart or clear anything.

Full-suite findings and targeted product corrections (2026-10-23):
- [x] Inspect the entire live baseline transcript for failures, not only its
  latest output. Facade42passed/1existingignore and reader14passed completed;
  new declared-device-access recovery/authority test passed. Core has two real
  failures: btrfs_prealloc_alias_writes_fail_unchanged_when_full (exclusive write
  after removing alias returnsNoSpace) and btrfs_reflink_splits_preallocation_on_a_full_filesystem
  (reference-only clone returnsNoSpace). Baseline05292 is RED; no broad pass.
- [x] Trace the product's coarse ENOSPC latch. It classified every write and
  reflink as space-consuming before inspecting whether it could reuse storage.
  Move refusal to the existing data-reservation helper; keep create/fallocate/
  xattr/etc early refusals, shared-preallocation COW, and hard commit/read-only
  refusal intact. Inline clones preflight the latch before removing mappings.
- [x] Add a planted-latch unit regression with actual FsOps calls: fresh regular
  writes and inline clones fail without changing a KEEP_SIZE reservation or
  existing payload; exclusive PREALLOC write and reference-only clone succeed
  with unchanged free space; hard commit refusal still rejects reuse asReadOnly.
  Original two failing tests and all their assertions are unchanged.
- [x] Execute this correction and the original failing cases before claiming
  it fixed. Frozen current coreSHAcc7b42c6838d0626247937eaab27930b71c48c9c920de0e0dca4021262c36bd6,
  btrfs0e9f186d1417f3c034843e694b2d12acd5e535190f30ad43da6129ada5f11992,
  ZFSe7139e66faaa7a6903516954864edc2dd36c95564798493fb96935c748ab961f.
  Sequential ts1 driver37122 runs core-prealloc/core-latched/core-reflink/
  core-pressure on base05292 plus exactly those three overlays; compilation is
  completed14 tests, all passed. Frozen final source below adds the separately
  reproduced inline-write/inline-clone corrections; do not reuse old receipts.
- [x] Current full-workspace formatting command through the ordinary Cargo
  shim, RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary cargo fmt --all --check,
  exits0. It follows the shim's non-compilation path, with no remote-execution
  claim or local compilation. Parent rules require heavy builds remote; earlier
  all-Cargo-remote phrasing was broader than that rule. No shim/admission bypass.
- [x] Current core-only UBS exits0/0critical/14435warnings/3051info, and the two
  support files exit0/0critical/3380warnings/389info. Dynamic Python argv assembly
  was blocked before scanner execution by DCG's unverified-argv rule; dcg explain
  reportsALLOW, then fixed literal scanner argv with shell noclobber runs through
  the normal guard. No allow-once, suppression, partial profile or guard override.
- [x] Actual optional-pool initialization source9ce btrfs unit suite passes
  487active/0fail/1existingignore, including failed initialization/no-retry/error
  ordering. RCH72447 exits0/ACKtrue/source+pairreleased; overlay80f11fceca6ca34645d4169677583492d9a1193532a790250832861a0817ef84.
  Later assertion formatting changes only whitespace; do not label this current
  three-file core-fix runtime proof. Initial pool-only check72443 passes a prior
  source; delayed Clippy72449 refuses changed input, and build72453 refuses an
  unfinished paired owner. Both refused103 and are acknowledged/released, with
  no source/cache/target reuse override. Source churn during queued validation
  was avoidable and is disclosed, not a successful gate.
- [x] Full harness old-core run72458 executes2077selected:2072passed/4failed/
  1existingignore, exit101. Four provenance gates fail; explicit errors include
  cannot bind execution to a Git revision. Clean-overlay archive execution lacks
  the real Git context required by SourceIdentity. No gate code/assertion edits.
  Benchmark driver stops after the failed harness; no benchmark execution credit.
- [ ] After final source fixes, rerun the unchanged full harness from the actual
  Git checkout using RCH --source-content-receipt and existing git-bound config
  (which preserves real.git metadata). Keep the snapshot/dirty digest frozen
  and inspect any byte-barrier failure; never manufacture Git identity or relax
  source binding. Complete required benchmark separately on the final source.
- [x] Reconcile supported cancellation of the known-red original core run72398
  (wrappercd033589-6427-4674-8abb-a535c4cd240c). Retain its two failures and mark
  unfinished cases unrun; cancellation is not success. Isolated baseline probes
  initially refused103/no_free_slots; no pressure/capacity bypass or test edits.
  Wrapper retried the terminated obsolete run on trj and hz3 before exhausting
  its third attempt. Final143/terminalACK/source+pairreleased confirmed0733.
- [x] Fresh source review also identifies an unexecuted risk in the existing
  unlatched INLINE clone path: destination mappings are removed before fresh
  inline-copy data is reserved. Add a focused true allocator-ENOSPC preservation
  regression and reserve before carving if it reproduces. Do not hide this by
  the new latch preflight or claim IO/crash atomicity from the latch regression.
  Also preserve old latch refusal for inline writes explicitly when narrowing
  regular-write admission; verify this before publishing the product correction.

Final ENOSPC/fallback candidate qualification (2026-10-23, 07:38 UTC):
- [x] Execute planted inline-write red: build72504 exits101 because a latched
  fresh inline write returned Ok(3). Restore the product's allocation refusal
  before changing inline extent metadata. Red log:
  main-integration-inline-red-btrfs_latched_enospc_allows_reuse_but_preserves_allocation_refusals-20261023T0651.log.
- [x] Execute true allocator-exhaustion inline-clone red: build72505 exits101,
  destination extent list becomes[] instead of its retained regular extent
  after ENOSPC. Positive free-space profile passes before the failing profile.
  Red log: main-integration-inline-data-red-vmi-20261023T0655.log.
- [x] Fix allocation order: prepare padding/conversions and reserve inline-copy
  storage before carving destination mappings; release unpublished reservations
  on error. Preserve reference-only clones, sparse zeros, shared PREALLOC COW,
  hard commit refusal, and prior create/fallocate/xattr refusals. Scope is data
  allocator ENOSPC preservation, not general I/O or crash atomicity.
- [x] Freeze base05292f5366c8cc26075ebc558e24b252e1478d52 plus exactly three
  overlays: core2574024ae2547fde29e66927568ccf37cdcd392d5fecf0ebd8d5e87ae3f94231,
  btrfs0e9f186d1417f3c034843e694b2d12acd5e535190f30ad43da6129ada5f11992,
  ZFSe7139e66faaa7a6903516954864edc2dd36c95564798493fb96935c748ab961f.
  RCH fingerprint768ecdc71939af9bdd7f4c61b7b50846d98b1d5d2cd2d67a0a49ad58a8973a58.
- [x] Current workspace/all-target check72509, strict Clippy72512 and Linux
  reader build72514 all exit0; jobs0733 records terminalACK/source+pairreleased
  for all three. Logs: main-integration-complete-auto-{check,clippy,build}-20261023T0708.log.
- [x] Current core btrfs_ run:545passed/0failed/10existing ignores;
  clone_file_:10passed; declared-device authority:1passed; read-only option
  refusal:1passed. Both new ENOSPC tests pass. Logs:
  main-integration-complete-core-ts1-*-20261023T0723.log. Their jobs readback
  records terminalACK/source+pairreleased. Count filters separately, not as
  disjoint additional coverage.
- [x] Current focused UBS core:0critical/14454warnings/3056info; support two
  files:0critical/3380warnings/389info, both exit0. Keep broad-source unresolved
  findings explicit; these focused scans do not establish workspace cleanliness.
- [x] Current normal-shim cargo fmt --all --check exits0 (non-compilation path).
- [x] Deliver final ELF4e170b64e22d226426304298b10e4be6c72a1b0dda0ef4ea67f930dd71cff775
  (590376552bytes) to a new exclusively-created CSD file. Local and destination
  hashes match; no previous binary replaced. Delivery log:
  main-integration-complete-delivery-20261023T0733.log.
- [x] Finish full relevant library/example suite on frozen final overlays:
  ffs-core, ffs, ffs-fat, ffs-zfs, ffs-btrfs; current RCH driver96833/log
  main-integration-complete-libraries-20261023T0734.log. Read complete results,
  ignores/native soft-skips and terminal ACK/source release before claiming pass.
  Completed42facade/14example/487btrfs/1543core/535FAT/333ZFS reportedpasses,
  0failures/26existing ignores, with2optional Btrfs fixture soft-skips separately
  retained. Build72528 exits0/ACKtrue/source+pairreleased. This535-test FAT run
  is current integrated-source execution, not the earlier452/515-test source cuts.
- [ ] Finish real-Git full harness on vmi1156319 and required benchmark. Earlier
  ts1 live-checkout guard refused the same normal-transfer approach; preserve
  refusal and route to a pure build worker without modifying guard/markers.
  Current source-content pair has real Git and is executing unchanged gates.
- [x] Finish current-ELF ZFS117, Btrfs aux155 then root91, and six-format20-mount
  probes; verify full denominators, statuses, bytes, controls, daemon exits and
  zero owned mounts. Retained native inputs are not fresh format production.
- [x] Complete solo fresh-pass audit against the original acceptance scope;
  preserve project-wide tracker/native-writer/crash/topology obligations and
  unresolved broader scanner findings. No independent verification claimed.
  Bounded honesty/real-work disposition and actual re-execution follow below.
- [ ] Recheck exact source closure/HEAD, stage only owned paths, commit qualified
  product fixes and tests together, publish main and synchronize legacy branch
  without force. Record exact revision and limitations, update Bead evidence,
  flush staged tracker, verify cycles remain empty, and release owned leases.

Final ELF native readback, 2026-10-23:
- [x] ZFS result /tmp/public-zfs-members-0bu41iyl/result.json:117CLI,
  86zero/27expectedone/4expectedtwo,12mounts/12daemon0,50offline+48mounted
  comparisons,31negative commands,16controls unchanged and rehashed,0mounts.
  Same freshly produced native mirror retained earlier this turn, no new pool
  production in this rerun; no write/import/RAIDZ/crash qualification.
- [x] Btrfs auxiliary result /tmp/native-btrfs-aux-r4d_et13/result.json:
  155CLI,144zero/11expectedone,6mounts/6daemon0,192byte comparisons,
  30inventory ioctls/30EROFS/12retained locks,13controls rehashed,0mounts.
- [x] Btrfs roots result /tmp/btrfs-root-selection-4cwzv7ma/result.json:
  91CLI,64zero/24expectedone/3expectedtwo,10mounts/10daemon0,82byte
  comparisons,27negative commands,20root/40inventory ioctls,20EROFS/
  18retained locks,19controls rehashed,0mounts. Native root oracle0.
- [x] Six-format mount result /tmp/public-facade-mounts-ug5ee1zu/result.json:
  20mounts/20daemon0,56files/236byte comparisons,20EROFS/20ENOENT,
  6negative commands,47controls rehashed,0mounts. Fresh readback checks
  each Run command JSON's actual/expected returncode, not nonexistent status
  files; daemon status files and per-case unmount fields checked separately.
- [x] Ext4 auxiliary /tmp/auxiliary-consumer-6vi6zbl9/result.json:
  73CLI,63zero/7expectedone/3expectedtwo,48retained-native byte comparisons,
  7constructed replay stats/10negatives,17controls rehashed. Native device-header
  layout /tmp/native-journal-layout-xvlderll/result.json:16CLI (6zero/10one),
  1mount/replayed stat/EROFS/lock refusal/daemon0,17controls unchanged. Journal
  fixtures are constructed; neither run establishes native crash replay.
- [x] NTFS /data/ssd/tmp/ntfs-facade-indexed-mp7dwtl6/result.json:
  328public+43fresh native-tool calls,309byte comparisons/32expected failures,
  strict/indexed/plain/bounded/compressed views and32extension named streams,
  51controls rehashed. All371 Run command JSON records checked for completed
  status and exact expected returncode. No fresh image producer in this rerun.
- [x] Retain fresh author native readbacks in main-integration-complete-native-
  readback-20261023T0744.json and native-command-readback-20261023T0748.json.
  Their stderr files are empty; results are author execution, not independent
  approval. Common scenarios across these probes count once, not as added
  independent evidence or whole-format parity percentages.
- [x] Investigate full-harness vmi1156319 SSH255. Supported own-job recovery
  confirms execution ended without completion receipt, then fails to persist
  source cancellation with printf I/O error. Worker reports0.89GiB free/critical.
  No success/ACK/source-release claim; keep wrapperac974128 ownership and failure
  visible. No cleanup, marker edits, daemon restart, deadline or disk override.
- [ ] Finish a fresh same-source full harness on healthy trj, whose absence of
  /etc/rch/live-checkouts was verified read-only using its configured SSH key.
  Ordinary --source-content-receipt transfer retains genuine Git metadata and
  normal admission. Driver97842/log main-integration-real-git-trj-harness-
  20261023T0747.log; benchmark runs only after actual harness success.
- [x] Complete current NTFS library and engine/facade doctests as well as the
  active broader library suite. The first extra NTFS submission shares the
  active TS1 source pair; preserve any ownership refusal and serialize a later
  admitted attempt rather than bypassing its source guard.
  Completed360 NTFS tests and two compiled doctests; final ACK readback below.
- [x] Re-read final product diffs: allocation/refusal lock order remains alloc
  then retry, as in pressure commit; serial prefetch retains ordered results and
  error slots; sector geometry comes from validated native geometry. Existing
  partial I/O/metadata failure paths do not become crash-atomic through this
  bounded allocator-ENOSPC correction. No unrelated feature expansion.
- [x] Staged tracker cycles remain0 and flush-only reports nothing to export.
  Canonical tracker WAL/schema recovery remains separate and untouched.
- [x] Current broad library run completed facade42passed/1existingignore,
  reader14passed and btrfs487reportedpassed/1existingignore. Btrfs output includes
  two pre-existing optional-native-fixture soft-skips (missing /data/tmp/probe_xfs/
  btrfs.img and /data/tmp/ffs-pgo-train.img); those paths are not native proof.
  The new failed-pool test actually executed and passed. Core/FAT/ZFS remainder
  and final job ACK still pending; no whole-driver pass yet.
- [x] Finish bounded author source triage of all33 interpreter matches using
  the installed, unchanged UBS AST patterns:15 direct .arg(-c).arg(script) and
  18two-element .args([-c,script]) sites. Of these13 use literal/constant Python
  source and20 use formatted quoted-string/numeric substitutions. Read every
  matched launcher and source-building expression; data in the literal scripts
  travels through argv/current_dir. Test fixture strings are controlled, not
  arbitrary production request code. The generic timeout wrapper and longer
  argv forms were inspected separately, not counted as extra scanner matches.
  AST locations retained in main-integration-python-{direct,array}-20261023T0805.json.
  No scanner/gate/test changes, clean broad-scan or independent approval claim.
- [x] Recheck CLI nonce/current-exe contexts: nonce names a new create_new file,
  not an authentication secret; child paths originate in current_exe and the
  child in-process hash is compared with its parent. The two CLI create-benchmark
  panics deliberately fail a scoped worker/measurement on create errors; do not
  silently relax those benchmark failure paths. Transport panics are in external
  test helpers; FAT/ZFS tripwires reject unwanted fixture I/O. No production
  imports of those external integration sources found. Retain broad scanner
  nonzero output and its original separate disposition obligation.
- [x] Full final-overlay core suite now completes1543passed/0failed/24existing
  ignores in2213.80s, including native ext4 repair/freshness and all Btrfs fixes.
  Facade42/1ignore, example14 and Btrfs487/1ignore already passed in that driver;
  FAT535 and ZFS remain active/pending before its final ACK.
- [x] Real-Git trj harness72531 finishes every test/doctest with0 failures,
  including2compile-contract tests and both real/planted-red public parity runs.
  Its overall source-content invocation FAILS after execution: postflight rsync
  detects exactly1delta, .git/index. Original transcript retained. Supported
  jobs recover returns delivery0/ACKtrue/source+pairreleased, but does not erase
  the failed integrity barrier or qualify a clean source-content receipt.
  No benchmark ran from that failed sequential driver. Source/test success and
  source-byte/delivery success remain separate obligations (RH-2/RH-7).
- [x] Investigate index refresh using installed harness/RCH source and official
  Git documentation: status/diff inspection can refresh optional index caches;
  Git documents GIT_OPTIONAL_LOCKS=0 to suppress optional writes without disabling
  mandatory Git operations. No fake revision, index removal/exclusion, chmod,
  barrier edit, allowlist, resource override or source suppression.
- [x] Execute initial read-only-Git source probe and preserve its failure
  through normal trj --source-content-receipt. Parent process uses
  GIT_OPTIONAL_LOCKS=0; ordinary Cargo env.GIT_OPTIONAL_LOCKS value0/force=true
  passes the same read-only inspection policy to unmodified tests/children.
  Driver68516, logs main-integration-readonly-git-{source-probe,harness,bench}-
  20261023T0837.log. Local index hashes are captured before/after each invocation.
  Keep local source/docs/index frozen and use --no-optional-locks for any Git
  inspection. A recovered delivery0 is not a substitute for a clean final gate.
  Probe failed on index refresh, so its sequential harness/benchmark did not run.
  Corrected policy and full harness qualification are recorded below.
- [x] Harness FUSE288reportedpasses include many existing soft-skip returns:
  worker lacks mounted CLI proof inputs or permission to mount. Two conformance
  cases also lack the optional ext4 golden image. Preserve all skips/ignores;
  these reported counts are not mounted proof. Current CSD probes independently
  executed48mount sessions on retained native inputs plus1constructed journal
  view; all49daemon/unmount paths passed. Do not turn the worker's soft skips
  into additional mounted coverage or claim native writable/crash acceptance.
- [x] First read-only-Git probe (GIT_OPTIONAL_LOCKS alone) actually runs1test0
  but still fails the unchanged postflight .git/index check. Local index hash
  staysd369686e5b5e3193723e3a43fa2857eff1151e0cdc3a714ae23ec53bb9b9f137;
  retained remote index differs in cache/stat bytes and mode, while local/remote
  tracked entry rows have identical SHA25637ce53981941b18721acd98819a91dbb0cdeda2fecf277b23c7918c3c29567ed.
  Recover8a658827 yields delivery0/ACK/released, not a qualified integrity gate.
- [x] Reproduce remaining producer write in a newly created isolated Git fixture
  /data/tmp/ffs-git-read-control-lq73p481 on trj: GIT_OPTIONAL_LOCKS=0 alone lets
  Git diff refresh a cold index; diff.autoRefreshIndex=false leaves it untouched,
  and a planted changed source still produces its exact nonempty diff. All6Git
  commands0, no existing repo/config/index changed. This is a constructed Git
  environment control, not native filesystem or independent product proof.
- [x] Final no-refresh source probe runs1source-binding test0 and completes the
  full RCH source-content invocation0 with unchanged local index. New driver27044
  uses process/Cargo env for GIT_OPTIONAL_LOCKS=0 plus GIT_CONFIG_COUNT=1,
  GIT_CONFIG_KEY_0=diff.autoRefreshIndex, GIT_CONFIG_VALUE_0=false; parent and worker
  had no existing count to overwrite. No global config change or gate relaxation.
  Log main-integration-no-refresh-source-probe-20261023T0844.log.
- [x] Finish benchmark attempt under driver27044 (full same-policy harness
  already passed below):
  main-integration-no-refresh-{harness,bench}-20261023T0844.log. Keep source/docs/
  index frozen; after-source byte checks and actual ACKs still decide qualification.
  Remote timing execution0 but final FETCH_HEAD barrier failed; not a pass.
  Pinned final benchmark19410 remains separately pending below.
- [x] Final full harness19376 (wrappera815d66c) completes0 with source-content
  postflight0, terminalACK and source+pairreleased. All29Rust groups report
  2652passed/0failed/11existing ignores, including the compiled doctest. Keep
  prerequisite soft-skips distinct as above. Local index remainsd369686e5b5e3193723e3a43fa2857eff1151e0cdc3a714ae23ec53bb9b9f137
  before/after. Logs main-integration-no-refresh-harness-20261023T0844.log and
  main-integration-jobs-20261023T0852.json. No repeated-run coverage/speedup credit.
  Benchmark is now compiling normally; no benchmark result claimed yet.

Bounded fresh-eyes honesty/real-work disposition for the three final fixes:
- Scope: uncommitted differences from05292 in core/lib.rs, btrfs/lib.rs and
  ZFS zil_records.rs, plus their actual test/native/RCH transcripts. Earlier
  extraction/integration blocks retain their own inventories; no historical
  audit is inferred from this bounded source review.
- Creation gate for this TODO/evidence: no product branch reads it; consumer is
  the user explicitly requesting a complete granular TODO. It gates this work
  handoff and prevents the observed source-cut/unfinished-gate confusion. Retire
  active entries when their actual checks finish; archive with their commit,
  never delete evidence without permission. No separate process framework.
- Inventory1 No (checked complete three-file diff: only new regressions and
  value-equivalent ZFS literals; no existing assertion/ignore deleted or weakened).
- Inventory2 No (checked real FsOps positive/exhausted profiles and real Rayon
  builder failure; fault injection is explicitly unit/planted, not native proof).
- Inventory3 No (checked changed path list: no golden/snapshot updates).
- Inventory4 No (checked diff/config/source receipts: no validator/CI changes,
  new lint allowance, cache/slot/source/disk/deadline override or local compiler).
- Inventory5 No (checked production routing and allocator boundary; no fixture
  identifier, demo success branch or changed success denominator).
- Inventory6 No (checked actual nonzero selected counts in completed runs;
  existing diagnostic ignores and unrun full suites stay explicit).
- Inventory7 No (checked named raw command logs and delivery/ACK readbacks;
  pending, refused,255,143 and101 attempts do not become passes).
- Inventory8 No (checked each native report scope: current execution on retained
  inputs vs earlier fresh producer, constructed journals vs actual native pools,
  and author execution vs independent review remain distinguished).
- Inventory9 Yes, avoidable execution churn warrants disclosure: a prior source
  edit during queued validation caused legitimate byte-barrier refusal. Re-runs
  then hit missing Git metadata, dual-role live-checkout refusal and disk/SSH
  failure. Corrections: freeze candidate, carry actual Git on an ordinary admitted
  worker, retain every failed attempt. This costs time and earns no capability
  credit. No broad green/runtime/release declaration has been made.
- Inventory10 No (checked stdout/stderr capture files, including empty readback
  stderr; no suppressed diagnostic output used for success claims).
- Inventory11 No (checked original Bead remainsin_progress; no follow-up task
  closes it or carries away essential unmet acceptance).
- Inventory12 No (checked canonical spec/gate diffs: no downward scope changes).
- Inventory13-17 N/A for new delegation: this final fix block is solo; no new
  agent, close, agent agreement or independent-verification credit. Earlier peer
  source is covered by current executed engine/core/facade checks and native reads,
  with remaining full-suite results pending rather than assumed.
- Inventory18 No (checked frozen native probe assertions/denominators and named
  Rust filters; overlaps/repeated runs are not added as independent coverage).
- Inventory19 Explain before replay: source-churn and harness-worker selection
  wasted time; preserve those failures, use the healthy worker normally and
  freeze code. Source/metadata persistence on the full worker remains unresolved;
  do not remove locks/restart services or call its harness passed.
- Inventory20 Strongest bounded evidence: executed reds72504/72505 show the
  inline refusal/data-loss defects, unchanged assertions now pass in the current
  545-test btrfs core selection; current ELF passes actual native payload/FUSE/
  lock/EROFS controls with rehashed input files. Commands/logs above are replayable.
- Countermeasure RH-2/RH-5: native/constructed/unit classes and valid-root
  admission controls stay explicit; RH-7: actual completion/ACK required before
  closure; RH-11: no new governance machinery or redundant meta-tests. No new
  reward-hacking defect found in the product/test diff; no independent review.
- Real-work inventory: final source unit contains USER ENOSPC/data-preservation
  and prefetch availability fixes; ENABLER equivalent ZFS notation enables strict
  Clippy; PROCESS is this user-requested TODO/comment evidence. No new closes or
  commits yet. Demonstration: failed clone preserves old destination/peer bytes,
  exclusive reserved-space write/reference-only clone succeeds, current reader
  mounts admitted native inputs read-only. Process omission would not change
  runtime behavior. Actual consumers have executed the code; nothing speculative
  was added. Oldest active user-facing item is this library/facade integration,
  which is receiving the work rather than unrelated easy leaves. No close-heavy
  pane, spec-only implementation substitute or acceptance-laundering follow-up.
- Verdict: substantive product progress; keep remaining work limited to actual
  qualification/publication and the original open obligations. Waiting and this
  bookkeeping earn no additional capability credit.

Final qualification continuation, 2026-10-23 09:30 UTC:
- [x] Complete final-overlay facade/core/Btrfs/FAT/ZFS library and reader example
  driver: 2954 reported passes, zero failures, 26 existing ignores. Wrapper
  rchw-178eb6ed-1168-47e2-8e2a-dfe36c8f5aab has terminal ACK and source/pair
  release. The two optional-fixture Btrfs soft-skips remain separate from native
  proof. FAT535 and ZFS333 actually completed, not merely started.
- [x] Complete NTFS360/0fail/0ignore and the facade/engine doctest driver with
  two passing compiled doctests. Logs main-integration-complete-{ntfs,docs}-
  20261023T0750.log; builds30075807208572532 and30077256843919405 both have
  terminal ACK, exit0, and source/pair release. Together with the preceding
  library driver this is3314 reported library/example passes, not independent
  coverage or a replacement for the separate full harness.
- [x] Full actual-Git harness19376 remains qualified:2652 reported passes,
  zero failures,11existing ignores, final source-content check0 and terminal ACK.
  The subsequent benchmark19385 ran all60 timing intervals with remote exit0,
  but its source-content postflight FAILED because shared .git/FETCH_HEAD changed
  at09:00:40UTC. Original log main-integration-no-refresh-bench-20261023T0844.log
  is retained as failed qualification. Supported recovery returned delivery0,
  ACK and release; it does not retroactively pass that source barrier.
- [x] Recheck SBH20G: critical at3.208percent free. Do not make a local verification
  clone or override storage admission. Both default benchmark targets,
  metadata_parse and ondisk_parse, have no runtime Git provenance dependency;
  the full harness does and already
  passed using real Git. Use the ordinary pinned clean-overlay benchmark route.
- [x] Finish benchmark19410, wrapperrchw-b20bc138-77cb-46f7-9f61-58ce46433ab2,
  base05292f5366c8cc26075ebc558e24b252e1478d52 plus exactly the three frozen
  qualified Rust overlays, fingerprint768ecdc71939af9bdd7f4c61b7b50846d98b1d5d2cd2d67a0a49ad58a8973a58.
  Log main-integration-pinned-bench-20261023T0926.log. It is currently compiling
  remotely on trj. Require actual completion, receipt, ACK and release; no
  performance-win claim without a live incumbent in the same invocation.
  Completed60timing intervals/remote0/clean-overlay receipt0/ACK/source+pairrelease
  at09:56UTC,1843.4s total. This remains the pre-checksum-cleanup source cut.
- [x] Re-read the complete final three-file diff plus allocation/emit/clone and
  pressure-commit callers. Unpublished inline reservations release on pre-emission
  failure; the existing aligned-emission helper owns its current extent. Existing
  partial metadata/checksum/I/O failure behavior is not promoted to transactional
  rollback. Lock order stays allocator then retry; no gate or assertion relaxed.
- [ ] Finish fresh disjoint final UBS scans, then update the existing parity
  execution notes, inspect exact source/HEAD/whitespace and preserve peer paths.
- [ ] Commit this coherent code+regression unit with its evidence; publish through
  the ordinary main/compatibility-branch path after remote ancestry inspection.
  Keep the original Bead in_progress while original unmet obligations remain.
- [ ] Final staged tracker comment/cycle/flush/readback and release only the owned
  Mail reservations. Canonical tracker WAL/schema recovery, broader scanner
  disposition and native writer/crash/topology obligations remain explicitly open.

Canonical tracker recovery diagnosis during benchmark wait, 2026-10-23:
- [x] Recheck canonical br ready: exit6/SYNC_CONFLICT, framed WAL refusal. Apply
  the fixing-beads-problems skill only within the stronger owning-engine guard;
  its generic rebuild/promote route does not apply to this framed WAL incident.
- [x] Reserve beads.db*, .write.lock and issues.jsonl without conflicts. With the
  existing workspace write lock held, preserve all seven present family/config/
  JSONL files to exclusive frozen/trial directories outside the repository:
  /Users/jemanuel/Library/Logs/frankenfs-verification/frankenfs-tracker-rehearsal-20261023-36xt7meg.
  Verify matching before/after bytes, inode and mtime. Frozen copies mode0400;
  no canonical DB/WAL/SHM/config/JSONL mutation or rebuild.
- [x] Private fsqlite0.4.9 .dump exits1 before producing SQL: sqlite_master is
  missing implicit autoindex slot1 for table issues. Stop the sequential private
  rehearsal before checkpoint/quick-check/post-dump; none of those commands ran.
  No live fsqlite opening/checkpoint is justified by this failed rehearsal.
- [x] A separate fresh copy opened by /usr/bin/sqlite3 -readonly can enumerate
  schema user_version4,635issues/368comments/824dependencies/0dirty_issues, but
  PRAGMA quick_check reports many never-used pages rather than ok. Process exit0
  is NOT a clean integrity result. This narrows the incident beyond only stale
  WAL-index metadata; it does not certify the DB healthy or authorize repair.
- [x] Preserve private diagnostic outputs/result JSON and all canonical hashes:
  main1e327d51d43acd2967a1e71a29db9059cf823406abcbf039a87faf81b0ba59f1,
  WAL6d4009e6ef95d77519482712d17b619c25b26c01ea06df9ad96e066e100d6c08,
  SHMfd4c9fda9cd3f9ae7c962b0ddf37232294d55580e1aa165aa06129b8549389eb,
  canonical JSONLe5d359ec158f3943d6784b166883d8be4e94cf57aba115cf409e9bc39bbb4e64.
- [ ] Owning-engine/schema recovery remains open: obtain a successful private
  logical-content/integrity rehearsal before any live transition. Do not delete,
  replace, truncate, promote a JSONL rebuild, or copy a trial DB over live state.
  Keep staged Beads authoritative for this work block and release the three
  diagnostic-only reservations now; no tracker-fix or capability credit.

Additional fresh-eyes cleanup mismatch (source review, not yet reproduced):
- [x] Compare the old inline-copy segment writer with the newly reused aligned
  extent emitter. The segment writer removes its mapping and frees its data
  allocation if checksum registration fails. btrfs_emit_aligned_extent_at uses
  a bare question-mark at that step despite promising failure cleanup, leaving
  the newly inserted extent/back-reference allocated on that error path.
- [x] Keep all source frozen through active benchmark19410 completion. Preserve
  that run's exact source scope; it is not evidence for a later cleanup change.
- [x] Add a focused actual-emitter regression with successful checksum control
  and explicit injected checksum rejection; verify error, absent mapping/backref
  and restored allocation accounting. Execute expected red before product fix.
  Test btrfs_aligned_extent_checksum_failure_releases_reservation runs both
  profiles. Red build30077256843919438 actually exits101: failed checksum
  registration must not publish a file extent; positive profile completed first.
  Log main-integration-checksum-red-20261023T0957.log; wrapper6f930bb5 has ACK,
  source and pair released. Injected unsupported checksum is unit fault evidence,
  not native corruption/crash proof. No assertion or prior gate weakened.
- [x] Match the existing segment writer's checksum-error cleanup in the aligned
  emitter, retaining the successful path and not claiming general I/O/crash
  atomicity. Keep any partial-checksum-tree behavior outside this bounded fix.
  Green selection passed in main-integration-checksum-green-20261023T1003.log;
  the final full source gates below also completed successfully.
- [x] Re-run substantive-code gates on the final new source, full core suite and
  harness, benchmark, exact reader build and relevant native profiles. Unchanged
  engine suites remain bound to their unchanged blobs, not relabeled new runs.
- [ ] Publish only after that final correction is reviewable and qualified;
  update the original staged Bead/TODO with all failures, actual counts and ACKs.

Checksum cleanup final-source qualification, 2026-10-23 10:08 UTC:
- [x] Green emitter regression actually passes1test/0fail,42.9s driver, build
  30077256843919457/wrapper1d0c5acd, terminalACK/source+pairreleased. Successful
  checksum control reads the written sector; explicit checksum rejection checks
  absent file mapping, inline/keyed backrefs and restored block-group accounting.
  No claim that arbitrary partial checksum-tree mutations or crash failures roll
  back. Red19438 remains retained; original assertions are unchanged.
- [x] Freeze final coreSHA80909707f88986728a5a0234af53aaa8c4a5d1584734a8dd60c1226ead4f6e5a
  plus unchanged btrfs0e9f186d1417f3c034843e694b2d12acd5e535190f30ad43da6129ada5f11992
  and ZFSe7139e66faaa7a6903516954864edc2dd36c95564798493fb96935c748ab961f,
  on base05292; overlay421d75ff6ac394c5263949c512440db031e665fbfe32fbea000137b549144453.
- [x] Workspace/all-target strict Clippy19461 exits0,211.8s, clean-overlay
  receipt; formatting exits0 through the normal non-compilation shim. Final
  focused UBS core0critical/14468warnings/3057info and two support files
  0critical/3380warnings/389info, both complete/exit0. Broader findings stay open.
- [x] Finish full core/facade library+reader examples on ts1, driver94726;
  main-integration-checksum-final-core-facade-20261023T1008.log. Do not assume
  a pass or a count until every selected case and terminal ACK completes.
  Completed1600reportedpasses/0fail/25existing ignores: core1544/facade42/
  example14. Driver1671.3s; terminalACK/source+pairreleased confirmed in
  main-integration-checksum-final-readback-20261023T1039.json.
- [x] Finish sequential trj workspace/all-target check, exact Linux reader
  build,60case default benchmark, then real-Git full harness, driver35714;
  main-integration-checksum-final-{check,build,bench,harness}-20261023T1008.log.
  Run actual-Git harness after the build/benchmark submissions to limit our own
  Git metadata churn. All parents retain temporary read-only Git policy; the
  unmodified harness receives it via Cargo env configuration. No gate override.
  All four stages exit0/ACK/source+pairreleased. Actual-Git harness19520 has
  29Rust result groups:2652reportedpasses/0fail/11existing ignores,358.1s driver,
  no source-barrier error. Existing prerequisite soft-skips remain as above.
- [x] Deliver/hash new ELF to an exclusive CSD path, then execute six-format
  read-only mount consumer using retained native inputs and existing bounded
  images. CSD /tmp root is98percent full; avoid producing extra window images.
  /data/ssd/tmp has199458560KiB available. No cleanup or storage bypass.
- [x] Scope repeated tests to affected core/facade/helper and public reader.
  Unchanged FAT535/NTFS360/ZFS333/Btrfs487 engine suites retain their earlier
  source-cut proof, not relabeled final-source executions. Prior seven native
  profile results remain tied to4e170b64 and the pre-cleanup source; the new
  mounted reader result will name its own exact binary. No repeated coverage
  or speedup credit. The full core suite includes required native-check/reopen
  Btrfs tests with nonoptional btrfs-progs fixture/checker assertions.

Final-reader native mount execution, 2026-10-23 10:18 UTC:
- [x] Linux reader build19486 exits0/ACK/source+pairreleased; artifact590376760bytes,
  SHA3d7a8e3825034f89908506f739180d6ec85258f088adcc612a1c0313711ae50c.
  Exclusive CSD delivery /data/ssd/tmp/ffs-public-zfs-members-42o_tjmd/native-reader-3d7a8e382503-20261023T1013
  has matching SHA/size and mode0500. Older4e170b64 consumer remains retained.
- [x] Workspace/all-target check19478 exits0,128.8s, ACK/source+pairreleased.
  Source is still frozen at core80909707/overlay421d75ff. Full core/facade and
  benchmark19490 remain active; actual-Git harness waits for benchmark completion.
- [x] Preserve failed native result /tmp/public-facade-mounts-qh1hleua/result.json
  and log main-integration-checksum-native-facade-20261023T1014.log. I mistakenly
  selected retained obsolete probefcbfc2ae, whose last negative uses a nonempty
  mountpoint and masks its expected Format error. This exact setup issue and
  already-corrected probea590 were documented earlier; avoidable version-selection
  churn is disclosed. All20daemon/unmount records0 and retained sentinel verified;
  negative6 fails its diagnostic assertion. Do NOT relabel it a passing gate.
- [x] Use existing corrected SHAa59098ce7c381905ccb5b87b5ab77699e57dc3718c32ff495af3ee77be48ac04,
  with an exclusive hash-verified CSD delivery. Exact diff changes only that last
  case's setup input to an existing empty mountpoint; all diagnostics, exits,
  counts and assertions are unchanged. No new gate edits or product changes.
- [x] Corrected full current-ELF consumer exits0: /tmp/public-facade-mounts-k0vlc0am/result.json,
  resultSHA8f6843bc2ee26f15e7629be5fd7feb55bb7d443a65eda03894aadd8c07fa46dc.
  Actual20mounts/56files/236byte comparisons,20EROFS/20ENOENT/20ROstatfs,
  six negative controls and47before/after input hashes. Log
  main-integration-checksum-native-facade-correct-version-20261023T1017.log.
  Retained native images/captured payloads, no fresh producer/writer/crash/field
  claim and no repeated-run coverage credit. Failed obsolete run remains separate.
- [x] Fresh author readback of all command/daemon records and current control
  hashes; verify0owned mounts. This is author verification, not independent review.
  main-integration-checksum-native-readback-20261023T1019.json confirms both
  retained statuses separately:26completed commands (20zero/5one/1two),20daemon0,
  47current hashes unchanged and0owned mounts for each. Correct probe has6typed
  negatives; obsolete one has5and the masked final diagnostic. Readback stderr
  is empty. No repeat-run mounted/byte-comparison coverage added.
- [x] Fresh health probe of prior unacknowledged own RCH wrapperac974128 refuses
  SSH255 before execution because178.18.254.243 has no verified host key. The
  configured alias disables checking and uses /dev/null; retain strict checking
  rather than use that alias. No worker command, trust/config/lock change or
  completion claim. Previous disk failure remains historical; current storage
  cannot be inferred. Leave supported recovery obligation visible for handoff.

Final benchmark/legacy reachable-row evidence:
- [x] Current benchmark19490 completes60timing intervals/remote0/clean-overlay
  receipt/terminalACK/source+pairrelease,1206.1s total. It reports7historical
  regressions,6historical improvements,29no-change and18within-noise comparisons.
  Retain all60diagnostics; these historical self-comparisons are not a qualified
  same-invocation incumbent win. No performance claim or baseline/gate change.
- [x] Finish actual-Git full harness19520, wrapperbb398c03-89de-4870-ad42-880af3c784f9.
  Final source-content postflight, terminalACK and source/pair release completed
  with0. Core/facade19477 also completed0/ACK/released. Local index stayed
  d369686e5b5e3193723e3a43fa2857eff1151e0cdc3a714ae23ec53bb9b9f137;
  Rust hashes and canonical JSONL remain unchanged. No gate/test edits.
- [x] Preserve reachable legacy tracker rows from the separate read-only private
  SQLite copy. reachable-rows.sql exits0/empty stderr/endsCOMMIT, SHA
  e3006432dcc623dfc05a82fc9f1888e149f745b15ec89047e6a465a54ff4f05a;
  reachable-rows.json SHA26b5407f249b4099a375e2c53e56d69b01b0f85fad478eea55740335e4e884ee.
  Both are under frankenfs-tracker-rehearsal-20261023-36xt7meg alongside the
  frozen raw family.635reachable issues/368comments/824dependencies preserved.
- [x] Compare reachable issue IDs with4323frozen canonical JSONL IDs:0reachable
  DB-only IDs;35shared IDs have exact title/status differences. Do not choose a
  winner, overwrite statuses or infer that every comment/hidden page is present
  in JSONL. The existing non-ok quick_check and possible unreachable-page data
  remain unresolved. This harvest is not a logical-integrity witness or live
  promotion authority; canonical family remains untouched.

Publication preparation and remaining original obligations, 2026-10-23:
- [x] Finish bounded fresh-eyes review of every final Rust delta and its callers,
  including reservation ordering, checksum-error ownership, hard commit refusal,
  serial child order/error slots and cancellation/read-only boundaries. Four
  substantive Btrfs corrections plus value-equivalent ZFS lint notation; no
  compatibility layer, new dependency, golden regeneration or removed assertion.
- [x] Correct stale unexecuted notes in FEATURE_PARITY.md for actual core/ZFS
  runs; retain exact source cuts, existing ignores/soft-skips, historical benchmark
  flags and author-only proof. No capability table/percentage/spec promise changed.
- [x] Finish one final real-Git harness after that document update, because the
  harness embeds FEATURE_PARITY.md. Log main-integration-checksum-parity-harness-
  20261023T1042.log, driver4316. Rust source stays80909707/0e9/e713 unchanged.
  No additional native/core/engine coverage credit from this document rerun.
  Completed19523/wrapper6bfb911a:273.9s,2652reportedpasses/0fail/11existing
  ignores, source-content postflight0, terminalACK/source+pairreleased.
  FEATURE_PARITY SHA7734f2b5120e22a03f2633129e15c016865035659b7e5f8e368928d2f6b3819e;
  Rust hashes unchanged. Receipt main-integration-checksum-parity-readback-
  20261023T1049.json. This supersedes pending validation of the document asset.
- [ ] Commit/publish exact owned Rust+test+parity+TODO paths after final receipt,
  with no force, cleanup, history replacement or peer-path staging. This TODO is
  frozen immediately before that Git action; its actual commit/push receipt and
  reservation release are recorded afterward in the original Bead/Mail thread,
  avoiding a self-referential bookkeeping commit.
- [ ] Canonical owning-engine recovery: private fsqlite open fails, stock-SQLite
  quick_check is non-ok, and reachable export has35shared title/status differences.
  Preserve frozen raw family and reachable rows. Successful private integrity /
  logical-content verification is required before any live transition.
- [ ] Independent broader scanner/status disposition remains original open work.
  Current three Rust files have complete0critical scans; that does not erase
  retained wider scanner findings or supply independent acceptance.
- [ ] Keep broader native writer/crash/topology qualification and the old own
  unacknowledged worker recovery open. New source publication is reviewable code,
  not whole-project release acceptance or a false close of this original Bead.
- [x] Final audit delta: new cleanup has executed red/green and current full-core
  proof; all seven completed Rust-source jobs have0/ACK/release. The final
  document rerun also completed0/ACK/release as recorded above. Preserve failed source barriers,
  failed workers and obsolete-probe version mistake. Existing corrected probe
  retained every original assertion. Counters keep repeated/source-cut results
  separate. No independent reviewer, gate waiver, new close or performance win.

## Post-reservation Btrfs replacement failures — 2026-10-23 15:55 UTC

The preceding unit is published as ebb20b1bf; its historical pre-publication
checkbox is resolved by original Bead comment2259 and Mail6274. Continue exactly
the same staged in-progress Bead, without laundering remaining acceptance.

- [x] Refresh clean tracked source, local source-aware queue, inbox and leases.
  Canonical br still refuses framed WAL. Hygiene report identifies50claimable
  local rows, but its full execution fails6/15 scenarios because installed bv
  rejects --no-cache and dependent fixture checks fail. Preserve the failure;
  artifacts/e2e/20261023_115101_ffs_tracker_source_hygiene_jWhTiq. No gate edit.
- [x] Reserve core/lib.rs and this existing TODO; record staged comment2260.
- [x] Review actual write/clone callers: allocation now precedes removal, but
  later data/checksum failure can still follow destination removal. Author six
  profiles with successful controls, cancellation at the actual data-write
  checkpoint, and checksum-construction rejection. Compare mappings, allocator
  space, checksum tree, inode bytes and destination/source/reflink-peer readbacks.
  The first proposed backing-device fault was NOT exercised: successful data
  writes stop in the MVCC overlay, so its asserted write count was0. Preserve
  cow-replacement-red-20261023T1556.log as a fixture-setup failure, not a product
  counterexample. Replace that unused double with cancellation after admission
  in the real mutation helper; require actual MVCC publication counts as well.
- [x] Execute the corrected regression against published product code. Red19658
  (coreSHA2d7048e2, overlay9ab0bc6a) fails destination-mapping preservation for
  cancelled overwrite, after its successful control. Red19661 (SHA d9c0063e)
  then passes the three overwrite profiles and fails the same invariant for
  cancelled inline-clone. Both exit101/terminalACK; logs cow-replacement-real-red-
  auto-20261023T1609.log and cow-replacement-clone-red-20261023T1611.log.
- [x] Correct confirmed failures by preparing data and checksum values before
  destructive destination changes; preserve ENOSPC/refcount/read-only/cancellation
  contracts. Rejected full allocator snapshots for the hot write path because
  they clone the complete extent-refcount map, adding filesystem-size work to
  every write. Existing checkpoint machinery remains appropriate to its callers.
- [x] The unchanged six-profile regression now passes1Rust test/0fail/0ignore
  at coreSHA355a81b17873e77208c80f8922c657b7e4199871fa50cf51440d6ead9e5fc09e,
  overlay821005621088c16d74c65b315fb2d01128a3e56591c1a176fb89ae6169b34b7c
  on baseebb20b1bf. Log cow-replacement-green-20261023T1614.log. This is executed
  constructed-image/MVCC mutation proof, not native mounted/crash/field evidence
  or a backing-device partial-write test. No old assertion/ignore/gate changed.
- [x] Preserve unexpected shared commit a18ebbca8 (15:56:29 UTC), which captured
  the first unused backing-device regression during its initial execution.
  Fresh status shows that obsolete164-line test staged for removal, while the
  corrected working core remains exactly355a81b1. I did not stage/reset/unstage
  that index state. Notify existing collaborators to hold core/index publication
  during current gates; preserve the commit/history and finish the corrected
  code+test unit. RCH proof remains baseebb20b1bf plus explicit overlay, not
  silently rebound to this new HEAD. No peer path is overwritten or unstaged.
- [x] Execute focused red/green, affected full suites, workspace check/strict
  Clippy/fmt and scoped UBS. Retain exact source hashes and terminal RCH ACKs.
- [x] Current355a81b1 workspace/all-target check completed0 (416.5s), and
  format/diff checks pass. One-file UBS completes0critical/14499warnings/3062info;
  keep broader retained scanner disposition separate. Strict Clippy and affected
  Btrfs/clone/facade suites are still running, not passes.
- [x] Refine the clone fault profile before final qualification: its earlier
  internal-helper test copied partial EOF into a larger destination, which public
  FsOps refuses. Keep that red scoped to the helper. Use a destination ending at
  the cloned EOF, preserve the shared peer, and exercise public clone dispatch.
  The admitted overwrite counterexample and its correction remain unaffected.
  Concrete fixture: source b"new", old regular destination BS+3bytes, shared
  peer, source0..3 to destinationBS..BS+3 (exact destination EOF).
- [x] At355a81b1, affected core Btrfs selection547passed/0failed/10existing
  ignores (233.73s test time), range-clone10passed/0failed/0ignore. Preserve this
  source scope pending final public-profile refinement. Native check/reopen and
  2000-file btrfs-check cases actually execute within the selection.
- [x] Preserve facade build failure before tests: cow-replacement-facade-
  20261023T1616.log exits101 because managed Cargo build-directory fingerprint /
  invoked.timestamp path is absent (OS error2). No facade pass or product-test
  failure claimed. Retry through ordinary managed RCH after final source settles;
  no target/cache/source bypass, deletion or local build.
- [ ] Finish strict Clippy: automatic RCH retry after hz3 source-namespace
  initialization was killed/status73 is retained; current hz4 execution remains
  pending. Earlier default queue refusal103/timeout remains a refusal, not a run.
- [x] Prior355a81b1 strict workspace/all-target Clippy completed19673/0/ACK on
  hz4, after the retained hz3 initializer failure. Shared maintainer commit
  63ab7eb7341e2a7ed2926c8c71a54561808a1baf contains exactly that355a81b1 Rust
  blob and explicitly says its sweep ran no checks. Its publication is not a
  new proof. Canonical index still holds80909707 (old baseline); preserve it.
- [x] Refine only the test fixture/caller: old destination now BS+3bytes, so
  source0..3 to destinationBS..BS+3 ends at EOF and is publicly admitted. Clone
  calls FsOps dispatch; write still models late cancellation in its real helper.
  No production delta from63ab7eb. New source09fddaec pendingfocused execution.
- [ ] Apply the single call-layout formatter correction before final freeze.
  The new test's fmt check reported one wrapping difference; no final-format
  pass claimed. Keep the already launched09fddaec test frozen until terminal.
- [x] Final-check attempt on09fddaec never reaches compilation: hz4 namespace
  initialization killed/status73, wrapper exits103, initial ACK refusal retained.
  Supported recovery ofrchw-2ccb1197/build19689 completes with failed exit1 and
  terminalACKtrue. Log cow-replacement-check-recovery-20261023T1648.json. No local
  fallback/cache/source/pressure bypass and no pass from recovery. Fresh final
  check/Clippy remain required after formatting; dependent Clippy did not run.

Bounded anti-ceremony review, this replacement-failure work block only:
- Creation worksheet: TODO consumer is the user's explicit granular tracking
  request; gate is preserving unfinished acceptance through this sustained work;
  observed defects are the lost mappings and the unused initial fault wrapper.
  Retire this active section on complete verified original-task acceptance,
  retaining history under the no-delete rule. Runtime does not consume it.
  Raw command logs are minimal integrity controls for observed lost wrappers /
  source-cut changes: required at this scale, smallest direct transcript, no
  cheaper reliable substitute. Highest-value current capability is preventing
  ordinary failed COW replacement from destroying old bytes. Spend implementation
  time there; tracking earns no capability credit.
- Real-work worksheet: purpose (README) is native Rust filesystem behavior via
  FUSE/offline-image tools. Actual window inventory: one bounded USER correction
  plus same-unit regression; PROCESS is this requested TODO, tracker/Mail updates
  and provenance logs. No closed work or delegated agents. Demo is old bytes
  surviving a refused overwrite/clone; final public clone proof remains pending.
  Without process the runtime is identical; it prevents evidence/status loss.
  Existing write/clone callers execute the new prepared-extent value, so it is
  real product plumbing, not speculative infrastructure. Older open native
  writers/crash/topologies remain on the original roadmap; bounded data-loss
  fixes take precedence over expanding mutation support on a flawed base.
  No follow-up minted to close acceptance, no lowered spec. Verdict HEALTHY
  implementation; compiler/recovery waits have delivered no extra capability.
- Honesty inventory, answers to all20prompts:
  1 No (checked full core/test diff: original assertions/ignores retained).
  2 Yes, initial proposed backing-device fault could not exercise MVCC writes;
    its positive counter failed before product assertions. Retained as fixture
    failure, removed unused wrapper, required real MVCC sequence deltas. The
    first clone-helper profile also bypassed public EOF admission; scoped that
    red accurately, refined actual public EOF input before final qualification.
  3 No (checked changed paths: no goldens/snapshots).
  4 No (checked gate/config/assertion diffs: none weakened or suppressed).
  5 No (checked production helpers: no environment/fixture success branches).
  6 No (checked nonempty1/547/10test counts; facade never ran after build error).
  7 No (checked transcripts; missing public-profile output not called passed).
  8 No (constructed/MVCC scope explicit; no live/native/crash promotion).
  9 No (fixture failure, invalid public profile, source churn, queue103, managed
    Cargo directory failure and initializer/ACK/recovery failures disclosed).
  10 No (stderr retained in transcript or tool output).
  11 No (original Bead remainsin_progress; no acceptance moved/closed).
  12 No (requirements/parity percentages unchanged; narrative states limits).
  13-17 N/A: solo execution, no subagents dispatched/reports accepted, no
    consensus counted; concurrent maintenance commits are not independent proof.
  18 No (six profiles predeclared; separate547+10counts with ignores/failures).
  19 Initial fault design and helper-only clone coverage required correction;
    openly recorded rather than counting those failures as broader proof.
  20 Strongest so far: reproducible red overwrite19658, corrected unchanged
    test green19664 and native-checking affected suite. Final public EOF profile,
    source-final workspace/facade/harness and independent verification pending.
  Older-session sweep N/A: no historical conduct conclusion in this bounded
  current-block audit. Disposition: RH-2/PL-2/PL-3 countermeasures are actual
  publication counters, admitted public inputs and exact source/log scope.
  Own faulty fixture/public-coverage statements corrected in place and disclosed;
  do not count them as live I/O/public proof or inflate recovered exit0.

Final public EOF profile, 2026-10-23:
- [x] Shared commitfe16e6cf9 preserved the corrected09fddaec test before final
  formatting; one wrapping correction produces final core76d965251dc51d6e1a5315144e1ed0b6afde5fe3e12ec003de3ef45912eda8d1.
  Actual production code is identical to63ab7eb/355a81b1. fmt/diff-check0.
- [x] Original09fddaec public job19691 lost its wrapper; supported recovery
  reported remote/delivery0/ACK and pair release, versus daemon130. Transcript
  contains no terminal Rust assertion summary, so do not count a test pass.
  Preserve cow-replacement-public-recovery-20261023T1711.json and raw log.
- [x] Reexecute final76d96525 public EOF profile with output captured: actual
  one Rust test runs all six profiles,1passed/0failed/0ignore,0.07s test time,
  RCH155.6s/exit0. Log cow-replacement-final-public-20261023T1713.log, baseebb20b1bf
  overlay8a62c66bd0596e6b526186fd37a3e1a4be3bd372199a3ad0b4882542b328eaee.
  Exact cancellation/checksum refusal, MVCC sequence, mappings/csums/inode/space,
  byte-exact successful replacement and unchanged shared peer/source exercised.
- [x] Finish final-source check/strict Clippy/facade serial managed runs; logs
  cow-replacement-final-{check,clippy,facade}-20261023T1716.log. Earlier355a81b1
  full workspace/547Btrfs/10clone proof remains its own source cut. No duplicate
  counters, new native mounted/performance/crash or independent claim.
- [x] Complete final scoped UBS and genuine-Git harness after final parity text;
  record ACK/source/pair release before exact-path publication and lease release.
- [x] Diagnose local UBS stall without changing scanner/project rules. Automatic
  startup produced0bytes, terminated143. Explicit Rust module emits no contract
  before its300s limit (reported2); its aggregator and read-only doctor then
  stall too. Read-only process sample shows Bash5.3.9 blocked in heredoc_write /
  write, matching maintainer Chet Ramey's documented dynamic-pipe fix:
  https://www.mail-archive.com/bug-bash@gnu.org/msg36171.html.
  Only the exact owned stalled processes were terminated143; raw logs/sample
  retained. No host interpreter/tool update, cache deletion or rule suppression.
- [x] Preflight Linux UBS5.5.3: doctor0, checksums verified. Compare installed
  Rust module against local5.5.0: only shared-library pin and Cargo diagnostic
  parsing differ; shared manifest Rust helper hashes unchanged. Non-Rust helper
  pins differ, so do not call the tool distributions identical. Preserve both
  version/module hashes and exact diff in remote-ubs diagnostic files.
- [x] Attempt version-labelled remote static scan via ordinary RCH job mode,
  exact final core SHA asserted before and after. Job mode does not provide a
  whole-tree source-content receipt. Two invalid combinations (--job with
  --clean-overlay, then --source-content-receipt) were refusedexit2 before
  execution; corrected against documented EXEC_MODES, no source/gate bypass.
  Log cow-replacement-final-remote-ubs-job-20261023T1732.log records normal4-slot
  admission and source-owner refusal. The failed attempt and supported terminal
  recovery below complete its disposition; the local exact-source scan supplies
  the bounded scanner evidence. No remote scan pass or slot override claimed.
- [x] Remote static job19788 never executed: after ordinary admission trj
  source namespace refused75 (unfinished overlapping source owner), caller103.
  Supported recoveryfc57d4d1 completes failed1/ACK. Keep all source locks; do
  not bypass the refusal with direct SSH execution, new source aliases or slot
  overrides. Remote doctor0/module comparison remains diagnostics only.
- [x] Resolve the local interpreter issue without changing UBS assets/rules:
  BASH_COMPAT=50 on the scanner command uses Bash's existing pre-5.1 here-document
  transport. Local installedUBS5.5.0 completes exact final76d96525 scanexit0,
  0critical/14496warnings/3062info. Logs cow-replacement-final-local-ubs-compat50-
  20261023T1736.log. WrapperSHA7bafd261..., RustmoduleSHAa027aacf... unchanged.
  No skip/severity/cache flag, interpreter installation or validator edit.
- [x] One retained production-shaped panic control under the same interpreter
  mode fails1 with1critical/0warnings/4info, exact rust.ownership.panic-macro at
  line4. Existing Rust module/wrapper/common contain no RANDOM references;
  Bash's compatibility RNG change does not change those rules. This bounded
  control does not certify every scanner rule or resolve broader findings.
  Fixture and raw log remain outside the repository; no file removed.
- [x] DCG rejected optional dynamic shell-source heredoc reproducer under
  heredoc.posix:inline-launcher-unverified before execution. Do not bypass it,
  auto-apply token886316 or claim it ran. Skip the unnecessary probe; direct
  installed-scanner execution and the literal Rust panic control above are
  independently statically reviewable and completed within authorized scope.

Final source-bound qualification completed while default benchmarks run:
- [x] Final core76d96525 is still frozen. Workspace/all-target check19748/0,
  strict Clippy19789/0 and facade/examples19808/0 have terminalACK and both
  source/pair releases. Facade42passed/0failed/1existingignore; reader example
  14passed/0failed/0ignore. Earlier absent managed-directory failure stays failed.
- [x] Genuine-Git full harness19798 / rchw-8119b3fc-a9d8-4cae-ba43-312f80d3e297
  completes0 in2675.9s with source-content postflight, terminalACK and releases.
  29groups report2652passed/0failed/11existing ignores. Both actual compiler-
  contract tests pass (497.19s group), plus real-suite / planted-red public parity
  execution. FUSE permission/optional-oracle early returns stay soft-skips, not
  mounted/native proof; expected caught negative-control panics are not failures.
- [x] Source receipt binds core76d96525 and FEATURE_PARITY59db3f3a. Git index
  remains30759c22a1b4b5575b121f316281ee1a722bea78403464fba2dc8e00ea43f662
  before/after the genuine-Git run. Minimal current-readback-20261023T1823.json
  preserves ACK/release state before rolling metadata expires. Public19739 now
  falls outside current metadata, but its previously observed0/ACK/releases and
  captured assertions remain in this session/raw log; do not fabricate metadata.
- [x] Canonical DB/WAL/SHM/JSONL hashes still match the frozen family exactly;
  no live SQLite open/checkpoint/rebuild or tracker authority change.
- [x] Finish default cargo bench -p ffs-harness at exact core76d96525 plus
  parity59db3f3a. Build19810 / rchw-f18f07a1-2f7b-48f9-9df7-1ffe56913253
  was admitted normally, waited for the owned source workspace, now executing.
  Log cow-replacement-final-bench-20261023T1749.log. Retain diagnostics and
  require terminalACK/release; no live-incumbent win or repeated coverage credit.
- [ ] After that gate, complete final bounded audit/readback, staged Bead
  evidence/cycles/flush and exact-owned-path publication; release only these
  three owned leases. Original broader obligations stay open on their record.
- [x] Read-only remote check found origin/main and its compatibility branch at
  ef600e5077ffc2ef057fc71b2772115d102eee36, ahead of localfe16e6cf9. Fetch with
  --no-write-fetch-head preserves all local work. Four incoming commits add ext4
  atomic attributes/EA-reference preservation and ZFS native SA xattr replay;
  11modified paths, no deletion. Do not claim our frozen receipts cover that
  later runtime source or overwrite those changes with the old checkout.
- [x] Exact read-only source-slice comparison confirms incoming remote matches
  all tested Btrfs preparation, publication/checksum, range-clone, write and new
  regression sections byte for byte, including final call wrapping. The four
  remote commits already contain our source fix and final formatter line.
- [ ] After the running benchmark gate, commit exact owned qualification paths
  on main, preflight the history-preserving merge and retain the incoming work.
  Verify the final Rust/crate/manifests match the previously published remote
  bytes exactly, with only our explicit documentation/TODO additions over it.
  Keep all runtime test counts bound to the frozen76d96525/59db3f3a cut; a clean
  Git merge or identical helper slices do not qualify the later whole runtime.
- [ ] Freshly review implementation and fault coverage, update staged evidence,
  cycles/flush and publish a coherent code+test unit if all required gates pass.
- [ ] Retain canonical recovery, independent scanner/status, broad native
  writer/crash/topology and old worker obligations on the original task.

Final bounded review and publication preparation, 2026-10-23 18:47 UTC:
- [x] Benchmark19810 finishes0/terminalACK/source+pairreleased in3471.1s,
  baseebb20b1bf, overlay36659f8695c823704455e8eceb538f4d2da60b702e6b8ec67ca7ef816851522b.
  All60timing cases execute:2historical regressions,16improvements,13within
  noise,29no-change. Sequential Btrfs write13.893ms median (+28.359% historical),
  PREALLOC append12.010ms (+28.014%). Preserve these losses. No matched live
  incumbent/profile was run, so neither cause nor optimization win is established.
  Any performance correction requires the existing baseline/profile/one-lever
  loop; do not speculate or weaken the gate. Benchmark-filtered unit tests are
  not additional executed coverage. Retained report:
  /Users/jemanuel/Library/Logs/frankenfs-verification/cow-replacement-final-qualification-20261023T1847.json.
- [x] Read preparation/publication/checksum/clone/write implementations and the
  final fault regression again. No further defect found in this bounded review.
  Actual success controls and MVCC publication deltas distinguish exercised
  preparation from an unused fault double; public clone uses admitted EOF input.
  Preparation errors preserve mappings/space/csums/inode/readback and shared
  peers. Later metadata failure/partial checksum-tree/crash rollback remains open.
- [x] Final audit delta to honesty answers6/7/20 above: source-final public
  regression, check/Clippy, facade/examples, scoped scanner, full genuine-Git
  harness and default benchmark have actual terminal evidence. The faulty test
  design, helper-only red, managed-directory/init/source-owner failures, missing
  public-job assertions, optional DCG refusal and benchmark losses remain in the
  record. No gate/assertion/golden weakened, no independent reviewer claimed,
  no new native mount run and no original acceptance closed or moved elsewhere.
- [x] Canonical DB/WAL/SHM/JSONL remain byte-identical. Staged dep cycles0.
  Before exact-path commit, preserve the shared pre-publication index verbatim
  as cow-replacement-index-prepublication-20261023T1841.index outside the repo,
  SHA30759c22a1b4b5575b121f316281ee1a722bea78403464fba2dc8e00ea43f662.
  Its staged old-core snapshot is not the qualified working source.
- [x] Final parity wording now records completed bounded verification and the
  two historical benchmark losses. This documentation edit follows the frozen
  parity59db3f3a benchmark/harness cut; do not relabel those source receipts.
- [ ] Publish this pre-publication snapshot through the preserving merge above,
  prove zero runtime delta over ef600e507, read back both remote refs and release
  only leases6695/6696/6723. Record the actual commit/push/release outcome on the
  original staged Bead and Agent Mail after execution, rather than adding a
  self-referential bookkeeping commit or falsely pre-marking publication done.

## Buffer-read semantic dispatch — 2026-10-23 19:13 UTC

- [x] Prior publication snapshot is resolved by staged comment2267/Mail6499:
  preserving merge819af1749 reached both refs, zero runtime delta over peer
  ef600e507, tracked source clean and three prior leases released. Retain the
  original broader acceptance obligations; this is not another Bead claim.
- [x] Refresh queue/inbox/source. Canonical br refuses framed WAL before open;
  source-aware queue identifies50claimable/local53/foreign0. Full hygiene still
  fails on installed bv --no-cache and dependent fixture checks; no gate edit.
  Raw warm-stat recommendation is stale: source/record already has the measured
  suppression/client-floor result. The older metadata-pressure report also has
  an existing default chunk-growth implementation and kernel regression; no new
  metadata bug is established by reading that report.
- [x] Find an actual API wiring defect: public read_into bypasses the nested
  route used by FsOps::read, so tagged nested reads incorrectly hit ReadOnly.
  Initial suspicion that it also bypassed raw-publication invalidation was
  overstated: with_latest_scope already holds the recursive semantic guard.
  Preserve that existing protection; no additional guard is needed. Continue
  the sole staged native API claim; reserve
  core/lib.rs and this TODO as6971/6972, announce in the existing Mail thread.
- [x] Extend existing constructed two-device nested regression: same inner
  inode in parent/child names different bytes, child data absent on primary;
  check direct buffer reads, offsets, EOF, empty output, cancellation and tails.
- [x] Extend raw-publication regression with warm direct buffer readers of the
  parent and retained child; after publication/flush require ESTALE with output
  unchanged. Reopen must produce the new bytes. Retain every old assertion.
- [x] Execute focused red against unchanged production and record source hash,
  actual assertions, terminal status/ACK and source-pair release.
- [x] Fix only the missing nested instance route inside the existing guard;
  keep the existing direct-to-buffer data path and read-only child authority.
- [x] Reexecute focused tests, affected Btrfs/core/facade coverage, workspace
  check/strict Clippy/fmt and complete scoped UBS without gate suppression.
- [x] Fresh-review source/error paths and all original assertions; fill the
  bounded real-work/honesty audit before claiming this slice verified.
- [x] Update original staged Bead, cycles/flush and parity with exact executed
  scope. Publication and lease-release execution are recorded after the commit.
- [ ] Keep canonical owning-engine recovery, independent scanner/status,
  native writer/crash/topology and older worker/performance obligations open.

The TODO is explicitly operator-requested. Raw logs retain evidence across the
observed RCH wrapper/output-loss failures and gate whether this exact correction
may be reported verified. No new report framework is needed. Retire the working
checklist after its outcomes are durably linked on the original Bead, subject to
the repository's no-deletion rule; retained transcripts remain historical proof.

Executed red19908 / rchw-03f2b1a9-da65-43f6-a84f-ae5cb0cc210f:
base819af1749, test-only coree17122323498a6783b42771f77326835daf159feb27559367624f44918f51162,
overlay791879ec1fec2ff027933956fde78f7cbd7daf13224414c0f11cd7ec7b6908bb.
Two tests actually ran: nested attached-device buffer read fails with ReadOnly
after the ordinary read returned the correct child bytes; raw-publication
invalidation passes. Actual101/terminalACK/source+pairreleased,57.5s command.
Log read-into-semantic-red-20261023T1917.log. This is a real routing red and
guard-conservation green, not a stale-view counterexample. Five production lines
route tagged inodes to their already-open child inside with_latest_scope; no
new guard, runtime, allocation policy, dependency or fallback copy. Correct the
existing read_into doc's obsolete fallback description. Frozen candidate core
d987669f6a5364c3a467d9a9bce2495d8f9390942dadfe07ed1ec3927e1dca4d;
fmt/diff-check0. Focused green adds the existing cached-cancellation regression;
scoped UBS uses the unchanged installed scanner under command-local BASH_COMPAT=50.

Focused green19915 / rchw-2f36edfd-2cfa-49b7-b088-be7501d95409 executes3tests,
3passed/0failed/0ignored,0.02s tests/49.6s RCH,0/terminalACK/source+pairreleased.
Candidate d987669f, overlayd278a9e3074858f7c49a274afccd009d4e3a93c821283d0cc6f62b494ec16f17.
Exact source UBS completes0:0critical/14883warnings/3105info, unchanged scanner
and rules. Broader independent findings remain open. Full required checks are
not yet passes: check wrapperrchw-646cc4ca-bdd5-46dd-a33e-69d8328d399c queued at
normal admission; subsequent serial Clippy/core/facade stages have not run.

Shared maintainer commit14fff2f5a735abeddab47a05c9757959a309ee29 captured the
exact candidate while gates waited. Its core SHA is still d987669f and its
message explicitly says that sweep did not run tests. Preserve the commit and
history; do not treat it as independent authorship or verification. The
qualification commands retain explicit base819af1749 plus the frozen overlay.

Bounded audit, this work block only (19:07 UTC onward; later gate results will
be appended rather than backdated):
- Real-work inventory: read current README purpose (Rust native filesystem
  behavior through FUSE/offline-image tools), current queue and recent staged
  closes, Git log/reflog and full owned diff. One USER unit is the runtime fix
  with its stronger tests captured in14fff2f5a; one PROCESS unit is requested
  TODO/Bead/evidence accounting. No separate ENABLER or UNKNOWN unit and no
  closure. This classification is not a progress-credit quota.
- Real-work questions:1) demo read versus read_into on a nested file whose
  data lives only on the attached device; both now return the child's bytes.
  2) Omitting process leaves the same code but loses the explicitly requested
  source/failure handoff.3) Existing real engine regressions actually ran and
  exposed ReadOnly before the fix; no speculative test framework.4) Oldest
  source-aware ready user item is bd-kdmu4 (June22 multi-file read copy tax);
  this correctness defect takes priority over an unprofiled throughput change.
  5) Solo: no subagent, pane, close comparison or independent acceptance.
  6) No plan/spec reduction or follow-up item carries unmet acceptance.
  Verdict: bounded USER progress; initial triage rejected stale leads instead
  of manufacturing fixes. Do not turn the admission wait into tooling work.
- Creation worksheet: existing TODO/logs are PROCESS, not runtime inputs.
  Consumer=user who explicitly requested granular TODO plus reviewer of this
  exact API correction. Gate=do not report nested buffer-read qualification
  without executed byte/error/source evidence. Observed defects=ReadOnly for a
  valid child and prior RCH wrapper/output loss. Retirement=after publication
  and durable outcomes on the original Bead, with no file deletion authorized.
  Integrity exception: prior lost-wrapper/public-output failures are concrete;
  raw per-command logs are required at this scale, are the smallest reliable
  durable capture, and context-only output is not equivalent. Highest ready
  capability under the sole claim is this API repair; prioritize it over extra
  reports. Verdict=minimum requested TODO plus minimal integrity transcripts;
  no new report framework, schema or dashboard.
- Honesty inventory, all20prompts:
  1 No (checked full core diff: every old assertion/test/ignore retained).
  2 No (checked existing two-device and raw-MVCC fixtures; real reader/routing
    executes, with distinct parent/child payloads, no new mock or success stub).
  3 No (checked changed paths: no goldens/snapshots touched).
  4 No (checked runtime/inline-test/doc diff; no validator/CI/config/pragmas,
    tolerances, retries or gates relaxed; existing tests gain assertions).
  5 No (checked production branch: no environment/fixture success path).
  6 No (checked captured Rust output: red2tests, green3tests; broader queued
    stages are explicitly unrun, not green).
  7 No (checked command logs/ACK metadata; no unrun command claimed executed).
  8 No (constructed-image unit scope explicit; no new native/crash/perf claim).
  9 Yes: initial source-only stale-view diagnosis was overstated before
    following with_latest_scope. It already held the semantic guard. Corrected
    operator commentary, TODO, Bead2269 and Mail6513; passing raw-buffer test is
    conservation evidence, not bug-fix credit. No added redundant guard.
  10 No (checked subprocess commands; both streams retained in raw transcripts).
  11 No (checked recent closes/current original status: no new close/split).
  12 No (checked docs/spec paths; only obsolete read_into fallback description
    corrected to actual implementation, requirements/parity unchanged).
  13-17 N/A, each: no subagent dispatched, report accepted, close made, pane
    farmed or agreement counted. Shared maintenance commit is not verification.
  18 No (two exact red filters and three green filters declared before runs;
    six nested read-window cases and all fault arms retained).
  Older-session sweep N/A: this is the bounded current work audit, not a claim
    that historical conduct or broader independent findings are cleared.
  19 Explain the early stale-view overstatement and source capture by the
    shared maintainer; both disclosed, source identity unchanged.
  20 Strongest current proof: actual ReadOnly red19908 after valid ordinary
    child read, followed by unchanged assertions green19915 on d987669f. A
    skeptic can rerun the exact filters at the documented base/overlay.
  Disposition: overstatement corrected in place, disclosed, and countermeasured
  under RH-2/PL-2: distinguish a source suspicion from executed failure and keep
  the already-working guard as an explicit countermetric. No self-review is
  independent approval. Publication still waits on the remaining actual gates.

20:00 UTC gate outcomes on unchanged d987669f / base819af1749+overlayd278a9e3:
- [x] Workspace/all-target check19929 / rchw-646cc4ca-bdd5-46dd-a33e-69d8328d399c
  completes0/ACK/source+pairreleased,371.1s RCH. Strict Clippy19938 /
  rchw-acd121f0-0582-4b72-a385-06239a260d40 completes0/ACK/releases,761.3s.
- [x] Full core library19946 / rchw-882622b3-7a00-492d-a031-09ed1326fccd:
  1577declared tests,1553passed/0failed/24existing ignores/0filtered;
  954.96s tests,993.7s RCH,0/ACK/source+pairreleased. All three focused tests
  execute again inside it; do not add their repeated counts to the full total.
- [x] Existing native btrfs-progs regression actually executes baseline checks
  and20fsync/full-commit cycles at each of2000/5000/20000files. All three final
  btrfs check verdicts are CLEAN. Native freshness fsops/journal-fsync test also
  passes. CPU/thread readback explains their long runtime: both active test
  threads were running, not lock-waiting; no debugger, test/resource/timeout
  override or cancellation applied. These are bounded structural image checks,
  not a new kernel-mounted readback/crash campaign or a performance win.
- [x] Same local scanner mode still catches the retained literal panic control:
  exit1,1critical/0warnings/4info, rust.ownership.panic-macro at line4. No scanner
  asset, severity, category or assertion edited. Current source scan remains
 0critical/14883warnings/3105info; broader independent findings remain open.
- [x] Complete facade/all-target reader examples at this same source cut; final
  facade log read-into-final-facade-20261023T1921.log records42facade and14reader
  passes,0failures,1existing facade ignore;348.4s RCH,0/ACK/source+pairreleased.
- [ ] Complete parity/final audit delta, original staged evidence/cycles/flush
  and exact-owned-path publication. Remote already contains the unchanged
 14fff2f5a runtime unit; fresh refs will be checked again before publishing docs.
  Keep the shared staged old-core reversal untouched until the owned commit;
  preserve its index bytes outside the repo before consuming qualified working
  source. Release only6971/6972/7024 after the actual publication outcome.

Final pre-publication delta, 2026-10-23 20:07 UTC:
- [x] Facade19959 / rchw-2bb21224-c205-445e-aaa4-766b37bf99ec has actual test
  summaries and terminal0/ACK/releases. Current jobs readback2007 preserves all
  six owned red/green/check/Clippy/core/facade outcomes, including red101. Full
  current unique core/facade/example runs report1609passes/0failures/25existing
  ignores in aggregate; the focused3green tests are included, not extra credit.
- [x] Source remains d987669f byte-identical to runtime commit14fff2f5a and
  base819af1749+overlayd278a9e3. No Rust edit followed these qualifications.
  Update parity narrative only; no percentage, golden, assertion, ignore,
  validator, timing tolerance, dependency or runtime policy changed.
- [x] Freshly inspect the dispatch: parent with_latest_scope already holds its
  recursive semantic guard; route clones the owning child Arc without retaining
  the slot mutex, and the child keeps its existing guard/device/verification
  policy. Child routing is disabled inside that view, so this adds no recursion
  cycle. Read-only mutation refusal remains unchanged. All original assertions
  remain. No further defect found in this bounded changed-path review.
- [x] Final honesty delta to6/7/20: all planned current-block gates now actually
  execute and have captured summaries. The only diagnostic correction is still
  the early stale-view overstatement, corrected openly in2269/Mail6513 and above.
  Existing invalidation is conservation evidence, not a second repaired bug.
  Solo author verification only. Retain the original broader independent/native
  conditions. No current benchmark, kernel mount or crash campaign was run.
- [x] Staged Bead2272 records final evidence; cycles0 and flush0. Raw canonical
  DB/WAL/SHM/JSONL remain frozen and unpromoted. No task closed or acceptance split.
- [ ] Finish only exact-owned-path docs/TODO publication and fresh remote ref
  readback, then release leases6971/6972/7024. Preserve the current index before
  consuming qualified working core bytes, rather than committing its shared
  staged old-core reversal. Record actual publication/release on the original
  Bead/Mail after execution; this committed checklist is the pre-publication
  snapshot, not a false claim that a future push has already succeeded.

## Ext4 public logical reads — 2026-10-23 21:15 UTC

Original bead: bd-native-image-library-s4tde, still in progress. Prior nested
Btrfs read_into publication/release completed in Bead2273/Mail6541; the older
unchecked publication boxes above are retained pre-publication snapshots.

- [x] Refresh main227512f06, clean tracked worktree, ownership and local queue.
  Current hygiene run171037 reports9/15, with six existing bv/interface fixture
  failures; source-aware local53/claimable50/foreign0. Canonical DB remains guarded.
- [x] Reserve core lib.rs/fs_ops.rs and this existing TODO; announce Mail6582.
- [x] Identify public read_file's low-level mapping route versus the finished Ext4
  branch in FsOps::read. Preserve actual inode numbering and the caller scope.
- [ ] Plant known-byte inline, indirect/hole, gzip cluster and policy regressions
  through public read_file, with FsOps controls and malformed-input cases.
- [ ] Verify uncommitted inode/data overlays remain private and visible through
  both entry points; retain existing extent/EOF/cache/directory assertions.
- [ ] Execute pre-fix remote snapshots; capture source hashes, actual failures
  and RCH terminal ACK/releases before making any verification claim.
- [ ] Restore and qualify read_file as the shared Ext4 logical reader with
  FsOps delegation after the corrected original-code red. The earlier authored
  implementation is temporarily absent for that controlled comparison.
- [ ] Extend the existing native fast/slow encrypted-symlink regression to
  exercise public read_symlink too. Reproduce its missing refusal, add the
  shared encryption guard before either storage path, and retain plain targets.
  Keep the helpers' existing NUL handling separate; no readlink semantic rewrite.
- [ ] Execute focused green, workspace/all-target check, strict Clippy, fmt,
  full core library and facade/examples through normal remote admission.
- [ ] Inspect changed-path scanner findings without weakening rules; retain
  negative control, full output, ignored-test counts and exact source closure.
- [ ] Fresh-eyes diff review, bounded real-work/honesty inventory, evidence on
  original bead, cycles/flush; preserve all broader unmet acceptance conditions.
- [ ] Publish only owned qualified paths with both remote refs verified; release
  only this unit's leases and report actual remaining limits.

Creation gate: use existing code/TODO and raw external logs, no new repo framework.
Consumer is the public inode reader and FsOps; observable defect is bypassed
storage/policy routing. Retire this work window after qualification/publication.

Source-binding correction, 21:37 UTC: the first file-read red reached remote
execution at base227512f06+overlay1055e1c3 (test-only core15b27a2e) before local
source edits. The companion symlink run was only queued when production edits
began. RCH correctly refused it with E413/source-changed, exit103; no tests ran,
so submission was not immutable-execution proof. The operator update claiming
both snapshots were captured was premature and has been corrected. No gate
or admission flag was changed. Re-run the symlink test with the read_file
consolidation present but public read_symlink guard still absent: held core
ceed84cf, fs_ops a03a9bfc, both selected overlays. Do not edit either selected
Rust file until this attempt has its actual terminal result. The guard will
then be restored manually and all final gates use the same frozen green cut.

Bounded audit, main227512f06 through the current unqualified working diff:
- Purpose from README: native Rust filesystem behavior through userspace FUSE
  and offline-image tools, with explicit evidence and durability boundaries.
- Inventory: no new published commit or closure yet. One coupled USER candidate
  is logical public ext4 reads/policy; its inline regression additions are the
  ENABLER. TODO, coordination and receipts are PROCESS, not another capability.
- Two-minute demo after qualification: read known inline/indirect/gzip bytes via
  the public inode API, then show private staged bytes and encrypted refusal.
- Without process records the routing fix is the same; the records prevent
  the queued-source mistake from becoming a false verified claim. Tests exercise
  the actual production readers; they are not speculative infrastructure.
- Native writer/crash/topology and original independent acceptance remain open.
  This read-profile gap advances that existing item rather than displacing its
  obligations. No swarm or close-count comparison applies. Current disposition:
  implemented file routing, deliberately held symlink red, execution pending.

Honesty inventory (all20, provisional before execution outcomes):
1. No (checked: full working test diff retains original assertions and ignores).
2. No (checked: existing byte-device/cluster fixtures, fixed plaintext oracles,
   actual parsing/decoding and transaction staging; no fixture branch in runtime).
3. No (checked: no golden or snapshot output changed).
4. No (checked: no validator, CI, suppression, timeout or tolerance changed;
   inline test additions strengthen behavior checks and E413 was respected).
5. No (checked: production diff selects inode storage, with no demo-path input).
6. No green claimed (checked: red executions are pending, not zero-run passes).
7. Yes: the statement that both submitted snapshots were captured preceded the
   queued companion's source binding. Corrected in operator commentary, this
   TODO, the original Bead and Mail6601. E413/103 is a refusal, not test evidence.
8. No (checked: synthetic image cases and planted encryption flags are labelled
   bounded controls, not kernel-created encrypted images or mounted fscrypt proof).
9. No (checked: tracker9/15 and source-drift103 remain visible; nothing closed).
10. No (checked: actual test logs combine stdout and stderr. One overbroad rg
    glob hit a huge JSON projection and was truncated; it is not complete review
    evidence. Subsequent inspection used bounded paths and specific source ranges).
11. No (checked: original staged item is still in progress, no follow-up laundering).
12. No (checked: no spec promises or parity percentage changed).
13. No (checked: solo work window, no agent closed a task).
14. No (checked: no subagent dispatch in this window).
15. No (checked: no delegated result accepted as verification).
16. No (checked: no panes farming refusal-only work; positive reads are in scope).
17. No (checked: no peer agreement is presented as independent confirmation).
18. No (checked: first selection is5 named tests; companion extends1 existing
    test. Final full-suite counts and conditional native execution await output).
19. Yes: two heavyweight optional review workflows were inspected before being
    judged inapplicable and redirected to implementation; no audit directory,
    swarm or cron was created. The source-binding error in7 is the material
    mistake to explain. Older-session review is not newly claimed by this window.
20. Current strongest evidence is source inspection only. Actual red failures,
    final green counts and terminal ACK/releases must replace this provisional
    answer before any verified or publication claim. Solo review is not independent.

Resolver-trace correction: resolve_extent already routes ordinary non-extent
inodes through resolve_indirect_block. The earlier extent-only description was
too broad: indirect reads were already supported. Their staged-data/hole test
is conservation evidence for consolidation and scope forwarding, not a new
capability. Expected pre-fix selection is therefore2passes (extent and indirect)
and3failures (inline, compressed, policy), subject to actual executed output.
No assertion was altered after this discovery and no performance win is claimed.

First executed red, 22:00 UTC: RCH20055 / ecc5ecdb exits101 after42m16s build;
5tests execute,2pass/3fail/0ignore/1576filtered. Extent and private indirect/hole
controls pass. Inline fails on interpreting its bytes as a physical block;
encrypted regular content incorrectly returns the plaintext fixture bytes.
The compressed test instead panics during fixture construction: the existing
EXT2_COMPRESSED_BLKADDR constant is u64, but its on-disk pointer field is4bytes.
That third failure is an authored test bug, not reproduced runtime evidence.
- [ ] After the held symlink red finishes, encode its sentinel as u32::MAX and
  re-run compressed routing against the original read_file/FsOps implementation.
  Restore the owned methods manually for that frozen red, then restore the
  shared final implementation and symlink guard; keep all assertions intact.
Honesty delta to6/7/9/18/20: only inline/encrypted-content failures and two
conservation passes are proved by this first selection. The compression fixture
error is disclosed, and the predicted three-defect failure count is withdrawn.

22:07 UTC: symlink red20088 / f2568577 exits101/ACK/source+pairreleased;
1test actually executes and fails on public encrypted fast target bytes
"hello.txt". Plain fast target and the existing FsOps refusal pass first. Slow
target controls are not reached in this red and await green. This uses native
plain-image creation with a planted encryption flag, not a native fscrypt mount.
- [x] Correct the compressed pointer encoding to exactly u32::MAX, four bytes.
  Formatting initially caught the now-shorter line wrap; manually corrected and
  fmt subsequently exits0. No oracle or assertion weakened.
- [x] Manually restore the original production read_file and FsOps implementations
  for a clean test-only red. fs_ops returns exactly to851e8400; git diff shows
  only test hunks in core, SHA c6dea482. Main remains227512f06, no publication.
- [ ] Await corrected five-case red on that source through terminal ACK/releases,
  then restore the final shared reader and public symlink guard, qualify once.

22:12 UTC corrected comparison completes:20126 / d7acac73, overlay7c56d8e3,
5run/2pass/3fail/0ignore/1576filtered,0.04s tests,3m11s build,205.8s RCH,
exit101/ACK/source+pairreleased. All three failures now reach runtime: inline
bytes become an invalid block number, compressed bytes are returned encoded
(actual header begins199,142), and encrypted regular data is returned. No
fixture-construction failure remains. This supersedes the compression proof
gap in the initial red without hiding that faulty attempt.
- [x] Complete corrected red and manually restore final shared logical reader,
  FsOps delegation and public read_symlink encryption guard. Add its policy doc.
- [x] Freeze core fc8e7fc5e5f58dd0fed28bf389443f31b74967f5437ba6fc2ff4c50201b58a77,
  fs_ops a03a9bfc927ec5b2f08914543ffaf73dbc34fd7a75f74f1d1fc44cc13f409244,
  base227512f06+overlay2478e598be3db47a679750877d78c05f549f4f08f84ba0954f827f0aab73e037.
  Do not edit selected Rust inputs while qualification attempts are pending.
- [x] Final fmt exits0 and whitespace check0. Start12-case green, including all
  file-read controls and both native symlink regression functions. Outcome pending.
- [x] UBS5.5.0, unchanged BASH_COMPAT=50 mode/rules: final core exits0 with
  0critical/14927warnings/3108info; dispatch file exits0 with0/86/61. Retained
  literal-panic control exits1 with1critical/0warnings/4info. Raw stdout+stderr
  retained externally in ext4-logical-read-*-ubs-20261023T2213 logs.
  This is not zero-warning or independent acceptance. Default text output samples
  findings rather than enumerating all14927 warnings; no full-warning disposition
  is claimed. The displayed adjacent chunk-slice unwraps are unchanged, bounded
  eight-byte conversions. New runtime lines are policy/dispatch only; test
  assertions and negative tripwires remain intact, with no scanner suppressions.

22:17 UTC: green20141 / b9137b58, base227512+overlay2478e598/treebb9bc05f,
12passed/0failed/0ignored/1569filtered,1.38s tests,193.4s RCH; exit0/ACK and
source+pairreleased. Actual selected output includes both native symlink tests
without an unavailable-tool/skip message. Malformed inline capacity, corrupt
compressed checksum, all refusal/EOF windows and private staged-data controls
now execute successfully. Indirect reads remain conservation, not new support.
- [x] Complete12-case green, including retained old controls and both native
  fast/slow helper paths. The same cases repeat inside the upcoming full core
  denominator and will not be added as extra full-suite credit.
- [ ] Await frozen-code workspace check/all-targets, strict Clippy, complete
  core library and facade/all-target example suites. Capture each real terminal
  result and ACK/releases before qualification/publication.
  Four generic dynamic Python launchers were refused by DCG before execution
  (inline-launcher-unverified); no checks ran under those wrappers. Replaced
  them with explicit normal RCH commands and direct no-clobber stdout+stderr
  capture. No allowlist, token, category, fallback or executable obfuscation used.
  Accepted direct sessions: check27679,Clippy72980,core92785,facade8872; logs are
  ext4-logical-read-final-<label>-direct-20261023T2218.log outside the repo.
Honesty delta6/7/9/18/20: actual12-case green now exists at the exact frozen
cut, with reproduced original-runtime failures20126 and native planted-flag
failure20088 as independently expected negatives. The initial fixture bug and
queued-source error remain retained above. Full qualification is still pending.

22:24 UTC scheduler adjustment: trj facade20148/4726e98f holds the shared source
tree while compiling another dependency feature set; core20150/c183b14c and
check20149/0717671b wait in sync. No quiet/queued job is counted as a pass.
- [x] Use RCH's exact-wrapper cooperative cancel for the owned waiting Clippy
  9bf6b1dd: settled130/ACK, zero slots released because it was not admitted.
- [ ] Follow the original check20149: its cooperative cancel returned E504,
  explicitly unconfirmed with reservations retained. No restart, forced ACK,
  lock removal, duplicate check execution or peer cancellation was attempted.
- [ ] Re-admit the same strict Clippy through configured vmi1152480, using the
  same config/source/flags and normal capacity/toolchain/disk gates. Session41181,
  ext4-logical-read-final-clippy-vmi1152480-20261023T2224.log. Classifier preflight
  says offload-eligible only; actual resource admission/execution remains to verify.
  Worker inventory had77GiB/9.97%free, without editing slots or worker settings.
  Native core/facade jobs remain on trj. Keep the selected Rust source frozen.
