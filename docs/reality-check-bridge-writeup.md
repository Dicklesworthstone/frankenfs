# Reality-Check Bridge: Closing the Gap Between Claims and Code

## Delivery progress — 2026-09-08, 06:41 UTC

The audit below is the starting point, not a claim that its diagnosed defects
remain unchanged. Implementation has advanced; the complete delivery contract
is still unproven.

- **Fast-commit recovery:** supported operations now apply or return an error;
  incomplete directory/extent recovery cannot be counted as success. Overlay
  recovery preserves the base image, and recovered ranges are checked against
  committed mappings. Inode records outside the configured valid size range are
  rejected before writes, rather than partially copied or silently truncated.
  Independent kernel/e2fsck crash-image certification remains
  pending (`bd-gqsnh`, `bd-9m84h`).
- **Repair lifecycle:** failed/cancelled refresh batches retain unprocessed
  groups for retry. FCW, SSI and mounted request commits pass explicit `Cx`
  through both FUSE adapters. Attached-lifecycle failures propagate with an
  explicit warning that the transaction is already committed; they do not imply
  rollback. This does not establish default repair, safe native reservation,
  persistent freshness or region-scoped worker ownership (`bd-11a8t`, `bd-j7a4e`).
- **Tracker:** `bd-09urx` and `bd-24ydx` are closed on 17 passing scenarios,
  conserved source rows/statuses, unchanged original goldens and an acyclic
  dependency graph. Unsupported statuses remain intact in exclusion accounting;
  unresolved dependencies stay blocked. Missing timestamps no longer erase
  in-progress rows.
- **Documentation:** signatures, dependencies, capability boundaries and
  quantitative terminology were corrected. Four count/negative-drift tests pass.
  Actual source dispatch implements four merge algorithms, including bitmap OR
  and bitmap delta; the earlier two-algorithm assessment was incorrect.
  Compilation of every README example remains outstanding (`bd-3kpkz`, `bd-ed3i5`).

Current executed checks: workspace check, Clippy with warnings denied, and fmt
pass. The combined core recovery run selected **39 tests, all passing**; repair
queue tests **9/9**, FUSE context/error-path tests **9/9**, README count tests
**4/4**, CLI rate-boundary test **1/1**, and the benchmark admission guard test
**1/1** also passed. The two new queue regressions and the malformed-inode-size
regression failed before their implementation fixes. These are bounded tests, not
a complete workspace or mounted-service run. Logs are retained in `/tmp` under
`ffs-fc-repair-reviewed-build-20260908`, `ffs-delivery-reviewed-clippy-20260908`,
`ffs-delivery-reviewed-check-20260908`, `ffs-repair-queue-{before,after}-20260908`,
`ffs-repair-fuse-context-test-20260908`, `ffs-readme-counts-test-current-20260908`
`ffs-cli-rate-test-correct-20260908`, and
`ffs-bench-admission-guard-test-correct-20260908` (all `.log`). Tracker evidence is
`artifacts/e2e/20260908_020721_ffs_tracker_source_hygiene_1Cloc3/`.

UBS remains red: the completed scan reported 244 critical findings, including
sampled false positives but also findings not yet individually resolved.
No clean scanner or release result is claimed. Commits created elsewhere in the
shared workspace captured earlier changes while validation was ongoing; their
existence is not evidence that these gates passed.

Remaining delivery TODOs are kept in the original beads and the granular notes
on `bd-z5bav`. In particular, public execution-bound parity, mounted RAID
routing, native repair storage/worker lifecycle, external crash/xfstests tests,
and aggregate release acceptance remain open. Do not enable automatic repair
symbol writes merely by connecting the queue: current CLI tail-layout arithmetic
does not itself establish ownership of that space against filesystem allocation.

## Initial assessment — 2026-09-08

**Audit:** `bd-e34ey`, source revision
`260833046b1e7bc01a51fb8aa9e8f2d96118a8a2`.
The May writeup below is historical. Its statements that parity is now
execution-derived and that no overclaims remain are **not valid current
conclusions**.

**Verdict:** FrankenFS contains substantial filesystem implementation, including
durable mutation machinery. It has not demonstrated delivery of the complete
advertised filesystem contract on the current build. The principal problems are
an unreliable completion signal, gaps between helper capability and mounted
behavior, incomplete lifecycle integration, and missing current external proof.
Neither `97/97` nor the fraction of closed tracker rows measures readiness.

### Scope and evidence discipline

The local AGENTS.md and README.md were read in full, along with the suite-wide
instructions. The review traced the high-risk public claims through the canonical
specification, port plan, architecture, parity tables, current call paths, inline
tests, kernel-reference tests, release machinery, operational reports and live
tracker. This is a requirements-led audit of those paths, **not an exhaustive
line-by-line audit of every Rust file or every historical design document**.
Source inspection establishes implementation, not successful execution. Historical
artifacts establish only the source/configuration and cases they actually tested.

The installed suite AGENTS.md does not contain the two named sections referenced
by local Rule 0.5. The explicit local prohibitions on self-certified speedups,
weakened gates and tracker manipulation remain binding. No requirements or
acceptance thresholds were relaxed during this audit.

### Vision checklist and current reality

| # | Testable promise | Assessment | Evidence and remaining delivery work |
|---|---|---|---|
| 1 | Parse and inspect real ext4/btrfs images safely | Implemented; current execution evaluated separately below | `ffs-ondisk`, `OpenFs::open`, CLI inspect, and kernel-reference suites contain real parsers and external-tool comparisons. Parser fixtures alone do not certify mounted mutation. |
| 2 | Mount ext4 with correct writes and acknowledged durability | Implemented, external closeout incomplete | CLI now attaches the internal JBD2 writer before requiring mount durability (`ffs-cli/src/main.rs:8222`). The old “never attaches” claim is obsolete. `bd-4zjkz`, `bd-hyysq`, and `bd-y2t0r` retain durability/accounting/allocator closeout work. |
| 3 | Persist btrfs writes across reopen and crashes | Implemented, high-risk proof incomplete | Full commit, accumulated tree logs, overflow fallback and log retirement exist in `ffs-core`; this is no longer the May in-memory facade. `bd-dm01m`, `bd-0ajub`, `bd-lzr3e`, `bd-f3fsg` require current clean-fixture external validation. |
| 4 | Grow btrfs allocation when existing chunks fill | Partial/default-disabled | Chunk-growth planning and application exist, controlled by `FFS_BTRFS_GROW_CHUNKS` (`ffs-core/src/lib.rs:2391`). `bd-a136s` owns delivery; do not describe this as absent code or established default behavior. |
| 5 | Serve the advertised multi-device RAID profiles through mounts | Integration gap | Mounted core uses `map_logical_to_physical`; `chunk_physical` explicitly rejects all profiles except Single/Dup (`ffs-ondisk/src/btrfs.rs:1123`). Standalone device-set/stripe helpers do not prove the README RAID RW matrix. |
| 6 | Recover ext4 fast commits | Partial; incomplete recovery can continue | `apply_fast_commit_operations` applies directory/inode operations and coordinated extent recovery; it is more than logging. But its caller warns and continues after errors (`ffs-core/src/lib.rs:5933`), and directory insertion's `Ok(false)` is discarded before incrementing the verified count. Unsupported growth/no-room/casefold cases need fail-closed recovery and independent crash-image tests (`bd-gqsnh`, `bd-9m84h`). |
| 7 | Match namespace, xattr, extent and casefold semantics | Substantial implementation, scoped gaps | Parity includes real success and deterministic rejection contracts. Full Unicode 12.1/kernel hash validation remains blocked in `bd-vsuni.3`; broad Unicode equivalence claims are premature. Unsupported operations are contract coverage, not supported functionality. |
| 8 | Provide MVCC/SSI and useful same-block merge proofs | Implemented primitives and mounted wiring; benefit unproven | Ext4 writes stage `NonOverlappingExtents` proofs (`ffs-core/src/lib.rs:26718`), contradicting stale “all Unsafe” text. Correction from 2026-09-08 source inspection: `MergeProof::merge_bytes` implements four mechanisms (`AppendOnly`, `RangeOverlay`, `BitmapOr`, `BitmapDelta`), with five enum outcomes including refusal. This implementation inventory does not establish the headline expected-loss benefit on mounted workloads. |
| 9 | Make repair a default, fresh, persistent durability substrate | Partial integration | Canonical spec §0.4 says default/continuous. CLI scrub remains opt-in, repair lifecycle is optional, and flush notification uses ambient `Cx::current` (`ffs-core/src/lib.rs:8701`). Codec recovery is real; default mounted freshness is a separate requirement. |
| 10 | Propagate cancellation and bound worker lifetime | Partial architectural conformance | Explicit Cx APIs coexist with ambient context and std-thread workers. A joined thread is meaningful lifecycle handling, but it is not proof of the stipulated asupersync structured cancellation contract. |
| 11 | Offer working serial/parallel/per-core FUSE modes | Implemented transport; operational evidence incomplete | `mount_managed_per_core` calls the real vendored per-core worker spawn (`ffs-fuse/src/lib.rs:7964`). `bd-28mw2` wording predates this implementation. Performance and cancellation need current mode-specific evidence. |
| 12 | Report feature completion from actual tests | Wrong evidence path | Public parity calls `ParityReport::current`, which sums compiled Markdown. The separate execution report is not wired into those commands and trusts boolean substring matches. No current execution-derived 97/97 result was established. |
| 13 | Pass the canonical conformance and release gates | Unproven on current build | Spec §22 uses `gate1`…`gate7` Cargo filters; matching test functions were not found in the searched source. Zero-selected Cargo success must be rejected. Current baseline and tracker failures are recorded below. |
| 14 | Demonstrate real xfstests, crash, repair and soak readiness | Missing aggregate proof | The cited xfstests baseline has 17 planned cases and zero executed cases. Its former execution task was closed without a real run. Old crash/soak artifacts cannot certify this revision. |
| 15 | Compete with live kernel ext4/btrfs under equivalent semantics | Unproven as a blanket claim | Existing scorecards and active tasks contain losses, invalidated configurations and failed A/A admission. Internal self-speedups and contended/blocked ratios do not establish incumbent wins. |
| 16 | Give users accurate installation/API/safety documentation | Drift | Workspace has 22 members including `tools/ffs-ops`; manifests specify Rust 1.95, asupersync 0.3.9 and fuser ABI 7.42. Tutorial signatures/exports disagree with the facade. First-party `forbid(unsafe_code)` does not cover vendored unsafe FUSE transport. |

### Why the completion signal is unsound

`ParityReport::current` in `crates/ffs-harness/src/lib.rs:140` parses the coverage
summary in `FEATURE_PARITY.md`. The harness command (`src/main.rs:720`) and user
CLI (`ffs-cli/src/main.rs:9430`) both use it. This describes a declared contract;
it does not report which tests ran or which behaviors worked.

The separate `ExecutionGatedParityReport::from_evidence` accepts
`HashMap<String, bool>` and an optional SHA. Its substring check allows an empty
passing key to match every cited row; an unrelated nonempty map satisfies
`require_evidence` even when no capability has green evidence. Neither test
selection nor source freshness is enforced there. The observed uses are local
tests, not the public parity path. The remedy is exact capability mappings and
actual runner results shared by CLI and CI, with negative tests at that boundary.

The denominator also needs care: the 97 summary units differ from the detailed
operation/scenario rows, and successful rejection is intentionally included.
Keep **declared contract coverage**, **implemented supported behavior**, and
**current verified behavior** distinct. Do not invent a replacement overall
completion percentage from this audit.

### Executed checks and their limits

| Check | Observed outcome | What it proves |
|---|---|---|
| `rch exec -- cargo test -p ffs-types --lib` | PASS: 142 passed, 0 failed, 0 ignored, 0 filtered | Current filesystem-type unit/property tests passed on `vmi1227854`. This does not certify mounted behavior or the rest of the workspace. |
| `cargo fmt --check` | FAIL, exit 1; diffs in 23 files | Current committed baseline is not formatting-clean. Captured in `/tmp/ffs-reality-fmt-20260908.log`; no formatting changes applied. |
| `rch exec -- cargo check --workspace --all-targets` | Incomplete, exit 137 after 301 seconds on `vmi1153651` | Worker command was killed at the configured approximately five-minute limit. No successful workspace check and no demonstrated Rust compiler error from this run. RCH's resource-exhaustion suggestion is not a confirmed diagnosis. |
| Selected harness conformance/kernel-reference tests | Cancelled before test execution, exit 143 | Compilation reached core/FUSE/harness, with duplicate `#[must_use]` warning at `ffs-fuse/src/lib.rs:421`. The test sources contain unconditional `remove_file` and `TempDir` cleanup; the still-building run was cancelled via RCH to honor the no-deletion rule. No test pass/fail result was produced. |
| Local tracker source-hygiene E2E | FAIL, 12/14 scenarios | Source-aware bv triage rejects `wont_fix`; the ACK fixture also fails through that path. Artifact directory: `artifacts/e2e/20260908_002904_ffs_tracker_source_hygiene_tmvfyq/`. |
| Archived CLI `parity --json` | Exit 0, reports 97/97 without running tests | Runtime reproduction on an existing historical binary, **not current-source build validation**. SHA256 `b0c2a6699ce2c589192b7d605714f1c71d9f50cb6dca9a10634eed6ba01f9c64`, path `.rch-artifacts/bd-warm-stat-memo-capacity/ffs-cli`. |
| Archived CLI `--version` | Rejected option | That artifact does not expose this conventional version flag; source identity must come from build provenance. |
| Archived CLI `inspect` on an existing ext4 image | PASS, exit 0; image unchanged | `/data/tmp/ffs-e2e-setversion-2995323-ThreadId(1024).img`: 4096-byte blocks, 4096 blocks/inodes, volume `ffs_gen`. SHA256 before/after: `3dafcaf27fa3e999a79745515b7aee1e9000e24da78d1eff494117f8fbe0adc3`. This is an archived-binary smoke test, not mounted or current-source proof. |
| Fresh ext4 fixture creation | Blocked before execution | DCG rejected `mkfs.ext4` under `system.disk:mkfs` because formatting can erase existing data. Used the read-only existing-image alternative; no bypass or formatting occurred. |
| Self-healing demo | Not executed | Build attempt stopped with SIGINT before demo execution after discovering unconditional temporary-image deletion, incompatible with the no-delete instruction. This is not a recovery test result. |
| Real xfstests, mounted destructive crash/corruption runs, soak and competitive benchmarks | Not executed in this audit | No device mutation ACK was supplied. No runtime or performance success is claimed for these lanes. |

Workspace Clippy, the full workspace test suite and benchmarks were not completed
in this audit. The existing formatting failure, incomplete workspace check and
unexecuted mounted lanes prevent a green-baseline or release-readiness claim.
For this documentation/tracker-only change, `git diff --check` passed and JSONL
was parsed and checked for ID/status conservation. UBS `--diff` exited 3 because
Markdown/JSONL have no supported scanner; that is **not a passing code scan**.
No scanner bypass, ignored diagnostic or filesystem source change was introduced.

Tracked-file census: 173 Rust benchmark files, 125 E2E shell scripts, 226 snapshots
and 63 fuzz-target Rust files. `cargo metadata --no-deps --locked --offline`
independently reports 22 workspace members and 173 bench targets, plus 61 test
targets and 11 example targets. These are inventories, not successful test counts
or independent requirements proven. The README's 92 benchmark figure is stale.

### Backlog coverage and delivery order

Before this audit's additions, JSONL contained 4,213 rows: 4,134 closed, 68
in-progress, 7 open, 3 blocked and one `wont_fix`. The local source-aware report
marked all 68 existing in-progress rows stale under its six-hour rule. Staleness
does not authorize stealing their ownership. Raw bv loaded 4,212 valid rows and
one error and correctly withheld claimability. Prefix classification alone also
does not settle ownership of semantically foreign-looking tasks.

**Completing the pre-existing open backlog would not finish the vision.** It is
heavily weighted toward performance and known correctness closeout. It had no
remaining execution-bound public parity task or real xfstests successor, and did
not close the mounted RAID/default-repair integration gaps identified here.

The new `reality-check-20260908` tasks have self-contained descriptions, acceptance
criteria and separate behavioral test work. Existing owners retain their tasks.

| Delivery gap | Implementation / execution task | Companion verification |
|---|---|---|
| Public parity and canonical gate binding | `bd-wh1xk` | `bd-lc132` |
| Mounted btrfs device routing | `bd-hk5w3` | `bd-mjxxk` |
| Current documentation and runtime boundaries | `bd-3kpkz` | `bd-ed3i5` |
| Default repair and cancellation lifecycle | `bd-11a8t` | `bd-j7a4e` |
| Complete-or-reject fast-commit recovery | `bd-gqsnh` | `bd-9m84h` |
| Permissioned real xfstests successor | `bd-vngdq` (blocked pending authorization) | Per-case external evidence required in the execution task |
| Lossless tracker interoperability | `bd-09urx` | `bd-24ydx` |
| Green pinned-nightly workspace | `bd-vuzzq`, depending on existing lint tasks | Completed fmt/check/clippy/test evidence |
| Combined current-build delivery | `bd-z5bav` | Depends on the above test lanes and ten existing correctness/configuration tasks |

1. Restore truthful observation: public parity/gate binding and its adversarial
   tests; lossless tracker interoperability; a completed pinned-nightly baseline.
2. Finish correctness closeout already owned: clean fixtures, JBD2/GDT accounting,
   btrfs accumulated fsync logs and retirement. Measure acknowledged data with an
   external reader/checker, not only FrankenFS reopening its own output.
3. Complete missing mounted device routing and repair lifecycle, with independent
   end-to-end tests. Finish existing chunk-growth and Unicode scope work.
4. Run the explicitly permission-gated xfstests successor and the combined
   current-build crash/repair/soak acceptance lane.
5. Re-measure the existing performance surface with equivalent durability,
   checksum policy, device transport and accepted A/A controls. Only then optimize
   a profiled lever, preserve behavior and compare a live incumbent in the same
   invocation. A loss is a useful result; a rejected measurement has no win ratio.

This ordering is risk-based, not an instruction to serialize every independent
task. Correctness and executable evidence have higher delivery value than another
dashboard, synthetic ratio or mechanically closed issue. Capability matrices
must remain precise without quietly editing away promised functionality.

### Design review of the bridge

The ambition reviews strengthened three aspects of the plan: (1) connect claims
to public execution rather than another internal report; (2) follow acknowledged
writes through journal/COW, repair freshness and restart; (3) evaluate actual
mounted device routing and matched-incumbent behavior rather than isolated helper
capabilities. Deterministic crash schedules, byte-identity oracles and bounded
resource invariants are more useful here than adding speculative policy math.

Five refinement passes checked: (1) coverage, adding the incomplete-FC-recovery
gap; (2) ordering/ownership, wiring existing closeout tasks without claiming them;
(3) test completeness, adding runnable-documentation verification and making test
companions prerequisites of delivery; (4) permission and conservation semantics,
explicitly blocking xfstests and clarifying source-aware tracker projection;
(5) the final goal-to-task map and graph, with no further scope change required.
They preserve current implementations even where old ticket titles disagree.
The audit task closes on this reviewable assessment and work graph; delivery
tasks close only on their named executed evidence.

Final graph validation: **15 delivery tasks, 27 new blocking edges, no active
cycles** (`br --no-db dep cycles --json`). All 4,213 pre-existing IDs and statuses
were preserved. Final bv triage sees 4,228 valid rows plus the existing invalid
`wont_fix` row; it remains `partial`, `claim_safe=false`, despite reporting no
cycles. A successful bv process exit is therefore not a clean-tracker result.
The xfstests successor is explicitly blocked. No delivery task was closed by
this assessment.

---

## Historical May 2026 writeup

> Engineering writeup on the bd-xuo95 epic (2026-05-20 to 2026-05-21)

---

## 1. The Gap: What the Reality Check Exposed

On 2026-05-20, a systematic reality check audited FrankenFS against its README claims. The audit used four code-investigation agents, a clean `cargo check --workspace`, CLI runs on real ext4 images, and the kernel-differential test suite (17/17 ext4, 7/7 btrfs). The findings were uncomfortable.

### G-A: btrfs RW Was a Silent Data-Loss Facade (P0)

The headline problem was that btrfs metadata mutations (`create`, `mkdir`, `unlink`, `write`) executed against an in-memory `InMemoryCowBtrfsTree` (`ffs-core/src/lib.rs:560`) with **no serializer back to disk**. The `btrfs_sync_with_logging` function logged `outcome="applied"` while flushing only the ext4 MVCC store, which held no btrfs metadata. Every btrfs RW change evaporated on unmount.

The README described this as "Supported (experimental) — Deterministic success/error."

### G-B: "100% Parity (97/97)" Was Self-Certified

The 97/97 parity number was summed from a hand-written table in `FEATURE_PARITY.md`. The "enforcing" test `parity_report_matches_feature_parity_md` parsed that same table twice, which is a tautology. No test execution fed the number. Rows could claim "implemented" without any corresponding green test.

### G-C: Release Gates Validated JSON Against JSON

Proof-bundle lanes hashed project-authored JSON against project-authored policy JSON. Zero `Command::new` calls. The gates were a closed loop that certified nothing executable.

### G-D: Harness Size

`ffs-harness` was ~132K LOC, a significant fraction of the workspace. The "80% meta-machinery" framing from the original reality check overstates the concern. A more accurate breakdown:
- ~35% real conformance testing (xfstests infrastructure, kernel differential)
- ~35% release-gate machinery (proof bundles, readiness labs)
- ~30% operational tooling (artifact manifests, campaign runners)

The harness IS large relative to core, but it is testing infrastructure, not pure bureaucracy. The question was whether tests actually run and gate releases, and they do (E2E scripts, CI gates). The concern was valid for the tautology tests, less valid for the overall harness.

### G-E: README Inaccuracies

- Claimed `ffs-btrfs` was "not on the runtime path", which is false: `ffs-core` depends on and calls it
- Count drift: fuzz targets 60 vs 64, "6 merge-proof variants" when there were 2 real mechanisms
- Quantitative claims untethered from source

### G-F: MVCC Overstatements

The "six MergeProof variants" collapsed to 2 mechanisms (AppendOnly and range overlay) plus 3 aliased names plus 2 no-ops. SSI was a single-edge antidependency abort, not true two-edge dangerous-structure detection. ~~The FUSE write path always staged `MergeProof::Unsafe`, so the adaptive policy never saw real merge proofs in production, and the headline "9.5× lower expected loss" was bench-only.~~ **Fixed in bd-5lyoy**: ext4 writes now stage real `MergeProof::NonOverlappingExtents` with byte ranges.

### G-G: Operational Readiness Unproven

- xfstests: never run
- Writeback-cache 12-point crash matrix: artifact-JSON only, not executed
- Performance baselines: quarantined
- Soak/canary: smoke-only

### G-H: Swarm Drift and Tracker Pollution

2,995 beads, all closed, `br ready` empty, yet a P0 bug was live. Recent commits were dominated by evidence-machinery and cross-project pollution (`br-r37-c1-*` graph-library beads like "multidigraph edge view", "pickle parity").

All eight findings share one pattern: effort had flowed into *describing* readiness instead of *achieving* it.

---

## 2. The Fix: What the Bridge Epic Actually Did

The bridge plan created epic `bd-xuo95` with 40 children across 8 workstreams (A-H). Each workstream addressed a specific gap category.

### Workstream A: btrfs RW Durability (P0)

This workstream is the core fix for the headline problem. **All A-workstream items are now durable** (bd-jdo53).

**A0 Safety Interlock (bd-xuo95.1 → bd-jdo53).** *Retired (durable-by-default).* The EROFS interlock is no longer needed: mutations are durable by default. The `--btrfs-rw-ephemeral-ok` flag is now opt-in for genuinely ephemeral mounts (tree-log fast fsync only, non-durable across unmount). Shipped in 692cf933.

**A1-A3 CoW Serialization Pipeline.** *Implemented and wired.* `DiskWritebackContext::serialize_node` serializes `InMemoryCowBtrfsTree` nodes to disk with CRC32C checksums. `btrfs_full_transaction_commit` builds `WriteDependencyDag`, flushes nodes in reverse-topological order via `WritebackExecutor::execute`, issues fsync barrier, and atomically commits superblock with bumped generation. Shipped in:
- 5e1a1afa: `DiskWritebackContext` + 33 writeback tests
- 9cbc524a: ffs-core scaffold
- 692cf933: FUSE fsync wiring

**A4 Crash Consistency (bd-xuo95.5 → bd-jdo53).** *Enforced in production.* The write-dependency DAG, WB-I1/WB-I2 invariant oracles, and fsync barrier are now wired into `btrfs_full_transaction_commit`. Two invariants enforced:
- **WB-I1:** At every crash point, the set of durable nodes is prefix-closed under "references"
- **WB-I2:** A reader after crash observes generation `g` or `g+1`, never torn

**A5-A6 Remount/Differential Tests.** *Shipped.* `scripts/e2e/ffs_btrfs_rw_durable_remount_e2e.sh` mounts btrfs image, creates file, writes data, unmounts, remounts, verifies data persists. btrfs-progs differential (`btrfs check` on FrankenFS-written images) is implemented in `scripts/e2e/ffs_btrfs_progs_differential_e2e.sh` and `scripts/e2e/ffs_btrfs_fuse_crash_injection_e2e.sh`.

### Workstream B: Honest, Test-Derived Parity (P1)

**B1 Rows Cite Real Tests (bd-xuo95.10).**
Every `FEATURE_PARITY.md` capability row must name ≥1 concrete test ID. A row with no test is `unproven`, not `implemented`.

**B2 Execution-Gated Parity (bd-xuo95.11).**
`ParityReport` derives `implemented` from tests that **actually ran green** in this CI invocation. The tautology test was deleted.

**B3 Three-Column Truth (bd-xuo95.12).**
Split each row into `implemented` / `kernel-differentially-verified` / `rejection-only`. "Deterministic rejection of unsupported ops" is now its own visible column, excluded from any "100%" headline.

**B4 btrfs Row Granularity (bd-xuo95.13).**
btrfs parity rows split `parse-only` vs `read-verified` vs `RW-durable`.

**B5 Parity Honesty Tests (bd-xuo95.14).**
Unit + e2e tests proving the gate fails closed on a fabricated row, an ignored test, and a failing test.

**What parity verification actually proves now:**
- `ExecutionGatedParityReport` requires running tests, not just claiming them
- `ThreeColumnParityReport` separates implemented / kernel-verified / rejection-only
- `BtrfsParityGranularity` tracks `parse_only` vs `read_verified` vs `rw_durable`
- Rejection-only rows are explicitly excluded from headlines

**Remaining honest gaps:** The execution evidence map must be populated by CI. Manual row counting in `FEATURE_PARITY.md` is still the source. There is no automated "test X covers row Y" discovery. This is incremental improvement, not perfection: the tautology is broken, but evidence collection isn't fully automated.

### Workstream C: Release Gates That Execute (P1)

**C0 ExecutedEvidence Substrate (bd-xuo95.15).**
The shared `ExecutedEvidence` type, constructible *only* by running a process (no `Deserialize` path), carrying `{command, args, exit_code, stdout_sha256, stderr_sha256, duration_ms, ran_at, git_sha, host_class}`. This is the foundation both parity (B2) and release gates (C1/C2) build on.

**C1 Executable Lanes (bd-xuo95.15).**
The `fuse`, `repair_lab`, `crash_replay`, and `conformance` lanes now *run* their underlying command and attach `ExecutedEvidence`.

**C2 Evidence = Execution (bd-xuo95.16).**
Proof-bundle lane validation requires an `ExecutedEvidence` with `exit_code == 0`. A lane backed only by a checked-in artifact hash fails.

**C3 Honest Relabel (bd-xuo95.17).**
Lanes that genuinely cannot execute (permissioned xfstests on this host) are labelled `documentation-only` / `deferred` explicitly; they cannot contribute `pass`.

**C4 Gate Tests (bd-xuo95.18).**
Tests proving a lane fails closed when the command exits non-zero or is absent.

### Workstream D: Harness De-Bloat (P2)

**D1 Module Census (bd-xuo95.19).**
Classified every `ffs-harness/src/*.rs` module as `conformance` or `meta`, and recorded LOC. Result: 23 conformance modules (29,398 LOC, 22%) vs 58 meta modules (103,072 LOC, 78%).

**D2 Relocate Meta-Machinery (bd-xuo95.20).**
Moved purely self-referential modules (ambition-evidence matrix, readiness-action autopilot, campaign broker, schema-of-schema inventory) into `tools/ffs-ops/`, outside the `ffs-*` filesystem workspace members.

**D3 Growth Coupling (bd-xuo95.21).**
A CI check: a PR's `ffs-harness` net meta-LOC increase must be accompanied by an increase in executed-conformance-test count, else it is flagged for review.

### Workstream E: README Accuracy + De-Slop (P2)

**E1 Runtime-Path Fix (bd-xuo95.22).**
Corrected the false "`ffs-btrfs` not on the runtime path" claim.

**E3 Parity Wording (bd-xuo95.23).**
Stopped calling the table "100% parity"; it describes the test-derived measurement instead.

**E4 Count Fixes (bd-xuo95.24).**
Reconciled every quantitative claim with code: fuzz-target count, merge-proof-variant count ("2 mechanisms, 3 aliases, 2 no-ops").

**E5 De-Slop (bd-xuo95.25).**
Trimmed the 238 KB README claims to proven reality.

**E6 Reconcile "Verified" Claims (bd-xuo95.40).**
Each "Verified" label and headline number in the README now cites reproducible `ExecutedEvidence` or has been downgraded or retracted.

### Workstream F: MVCC Honesty (P2)

**F1 SSI Two-Edge Detection (bd-xuo95.26).**
Implemented true two-edge dangerous-structure detection (Cahill SSI): `T_in →rw→ T_pivot →rw→ T_out` with commit ordering. The previous single-edge detector is now just one half of the check.

**F2 Merge-Proof Taxonomy Honesty (bd-xuo95.27).**
Collapsed the public taxonomy to the 2 real mechanisms (AppendOnly and range overlay) and documented `Unsafe`/`DisjointBlocks` as the no-op pair.

### Workstream G: Operational Readiness, Actually Executed (P3)

**G2 Writeback-Cache Crash Matrix Executed (bd-xuo95.31).**
Executed the 12 crash scenarios as **in-memory CoW tree simulation** via `LabRuntime` DPOR. The matrix builds a `WriteDependencyDag` from `InMemoryCowBtrfsTree`, enumerates crash points, and runs WB-I1/WB-I2 invariant oracles. This proves the *invariant math* is correct against a deterministic model. **It is not real FUSE mount crash injection** (like xfstests/fstests). The artifact records simulation outcomes with `ExecutedEvidence`, not hand-authored expectations.

**G3 Perf Baselines Refreshed (bd-xuo95.32-33).**
Re-ran criterion + mounted benchmarks with dated numbers; dropped or substantiated the quarantined latency claims.

### Workstream H: Swarm Steering & Tracker Hygiene (P1)

**H2 Re-Point the Swarm (bd-xuo95.35).**
The bridge beads became the live `br ready` queue.

**H3 Standing Reality-Check Cadence (bd-xuo95.36).**
A recurring gate so the tracker cannot reach 100%-closed while a P0 bug is live.

---

## 3. The Verification Approach

### ExecutedEvidence: The Load-Bearing Type

The deepest fix for both G-B (self-certified parity) and G-C (non-executable gates) was a single shared type, `ExecutedEvidence`.

```rust
ExecutedEvidence {
    command: String,
    args: Vec<String>,
    exit_code: i32,
    stdout_sha256: String,
    stderr_sha256: String,
    duration_ms: u64,
    ran_at: DateTime<Utc>,
    git_sha: String,
    host_class: String,
}
```

It can only be *constructed* by actually running a process; there is no `serde` deserialization constructor. A hand-authored JSON file cannot forge one.

Both parity rows and release-gate lanes consume it. Parity becomes a *derived* quantity: `implemented = count(rows whose cited test produced fresh green ExecutedEvidence this CI run)`. A release-gate lane is `pass` only if it holds `ExecutedEvidence` with `exit_code == 0`.

### Crash-Consistency Matrix via DPOR (Simulation, Not Real Crashes)

The btrfs writeback crash matrix is not ad-hoc fault injection, but it is also **not real FUSE mount crash testing**. FrankenFS ships `LabRuntime` with virtual time and DPOR (Dynamic Partial Order Reduction).

**What the matrix actually does** (`crates/ffs-btrfs/src/crash_consistency.rs`):
1. Creates an `InMemoryCowBtrfsTree` with deterministic seed-varied shapes
2. Builds a `WriteDependencyDag` from the in-memory tree
3. Enumerates crash points via DPOR (pre/post flush, fsync barrier, superblock)
4. Runs WB-I1/WB-I2 invariant oracles against the DAG

**What it does NOT do:**
- No actual FUSE mount
- No real disk I/O
- No kernel-level crash simulation
- No process kill/recovery cycle

The 12 crash points (cp01-cp12) are driven through DPOR enumeration covering create, append, fsync boundaries, rename, and unlink sequences. Each crash point is reproducible from a seed. The matrix is exhaustive over the writeback linearization, proving the *invariant math* is correct.

The README claims a "12-point crash matrix" in its comparison table. That is technically true, but it could mislead readers into thinking there is real crash injection testing. Real FUSE mount crash testing (like xfstests/fstests) remains unexercised.

### Metamorphic Relation MR-WB

The differential remount oracle validates:

```
reparse(writeback(mutate(parse(img)))) ≡ model(mutate(parse(img)))
```

The re-parsed on-disk tree after unmount must equal the in-memory model. This is the test that would have caught G-A on day one.

---

## 4. Honest Current State

### What Is Genuinely Durable Now

**ext4 RW:** Fully durable. The read+write path is validated against the kernel's own `debugfs`/`dumpe2fs` (17/17 differential tests). Journal replay (JBD2, fast-commit), orphan recovery, and allocator mutations all persist correctly.

**btrfs READ:** Fully functional. Chunk mapping, tree walks, decompression (ZLIB/LZO/ZSTD), subvolume selection, and send-stream parsing all work correctly.

**btrfs RW:** Durable by default, end-to-end. The journey through this session is itself the story: the serializer + writeback-DAG + atomic-root-commit infrastructure shipped first as in-isolation green code (`DiskWritebackContext::serialize_node`, `WriteDependencyDag`, `WritebackExecutor`, `btrfs_full_transaction_commit`), with no mounted-FUSE harness to confirm the wiring actually worked. The first mounted-FUSE durability test (create fresh image → mount RW → write 5 files → unmount → remount) caught two real gaps in succession:

* `DiskWritebackContext::block_to_bytenr` was a placeholder `bytenr = block * nodesize` mapping that ignored the chunk tree, so the new superblock's `sb.root` pointed at an offset not covered by any chunk and the next mount failed with `invalid on-disk format: invalid field: logical_address (not covered by any chunk)`.
* `BtrfsSuperblock::to_bytes()` rebuilt a fresh 4 KiB buffer from only the fields the parser modeled, zeroing the embedded `dev_item`, `sys_chunk_array`, label, and backup-root-ring regions — which `btrfs check` rejected as `dev_item UUID does not match fsid`.

Both are now fixed: `BtrfsAllocState::alloc_metadata_for_tree` hands out logical addresses inside the metadata block group, the serializer rewrites internal-node child blockptrs through those allocated addresses via the new `BtrfsNodeSerializeParams::child_bytenrs`, the commit translates each logical address through `map_logical_to_physical` for the device write, and the superblock is patched in place (only `generation`, `root`, `root_level`, and the checksum are touched). The mounted-FUSE harness now reports `verdict: PASS, mutations_survived: 6, mutations_lost: 0` — all 5 files plus `sub/n.txt` survive unmount → remount with byte-exact content. `FEATURE_PARITY.md` rows 88-90 flip back to ✅ with the evidence captured under `docs/evidence/bd-1ving/`.

**The honest summary:** btrfs RW was a silent-data-loss facade; now it is empirically durable. `--btrfs-rw-ephemeral-ok` keeps its tree-log fast-fsync codepath as an explicit opt-in for callers that want ephemeral semantics. One downstream gap remains and is tracked separately: `btrfs check` against a FrankenFS-written image still flags EXTENT_TREE inconsistencies, because the commit allocates new metadata extents without (yet) inserting matching `EXTENT_ITEM` entries into the extent_tree or invalidating the old tree-block entries. The image stays mountable + readable; the failure mode is structural extent accounting, not data loss. See `docs/evidence/bd-1ving/btrfs_check_status.md` for the breakdown.

**Parity claims:** Now derived from tests that actually ran green. The 97/97 number persists but is honest: it counts rows with green `ExecutedEvidence`, not hand-authored assertions.

**Release gates:** `validate-proof-bundle --execute-configured-lanes` enforces `ExecutedEvidence`. Note: the `evaluate-release-gates` CLI path could still consume checked-in artifact hashes until a patch forces lane execution there too; this is a known gap being closed.

**Harness ratio:** Meta-machinery relocated to `tools/ffs-ops`. The `ffs-*` workspace filesystem LOC is no longer inflated by it.

### What Is Still Deferred

**bd-xuo95.39, btrfs tree-log fast-fsync (V1.x deferred).**
The btrfs tree-log write path makes a single-file `fsync` durable without a full transaction commit. The read/replay path already exists (`replay_tree_log`). The write path is explicitly tracked as V1.x future scope so the capability is NOT silently dropped. This is a performance optimization, not a correctness gap; btrfs `fsync` currently does a full transaction commit (correct, but slower than kernel btrfs).

**xfstests baseline.**
Real xfstests pass/fail evidence remains blocked on permissioned execution. The infrastructure exists; the evidence does not.

**FUSE merge proofs.**
~~The FUSE write path still stages `MergeProof::Unsafe`.~~ **DONE (bd-5lyoy).** The ext4 write path now stages `MergeProof::NonOverlappingExtents` with actual byte ranges for data writes, and `MergeProof::DisjointBlocks` for metadata/allocation writes. The adaptive merge policy can now make informed decisions based on real write patterns. The "9.5× lower expected loss" is now achievable in production, not just benchmarks.

**Real FUSE crash injection.**
~~The crash matrix tests in-memory simulation. Real kernel-level crash injection (like xfstests/fstests) is not exercised.~~ **DONE (bd-88kiu).** `scripts/e2e/ffs_btrfs_fuse_crash_injection_e2e.sh` now tests real FUSE mount crash injection: mounts btrfs image via FUSE, runs write workload, sends SIGKILL at configurable crash points, remounts in RO mode, and validates via `btrfs check`. Tests WB-I1/WB-I2 invariants on real I/O, not just DPOR simulation.

---

## 5. Lessons

1. **Evidence apparatus can outgrow the thing it measures.** 150K LOC of harness for a 280K LOC filesystem is a smell. The apparatus should be load-bearing, not decorative.

2. **Self-certification is seductive.** Parsing your own markdown table twice feels like validation. It isn't.

3. **"Experimental" is not a license for silent data loss.** Either fail loudly or persist correctly. There is no middle ground.

4. **Crash consistency requires executable oracles.** Prose invariants are necessary but not sufficient. WB-I1/WB-I2 are checkable at every DPOR-enumerated crash point.

5. **Swarm coordination needs grounding.** A tracker at 100% closed with a P0 bug live is a failure mode. Reality checks must be recurring, not one-shot.

6. **Documentation lag is the inverse problem.** Post-bridge, `FEATURE_PARITY.md` still marks some items as 🚧 "in progress" even though the beads closed (bd-xuo95.5 crash consistency, bd-xuo95.31 crash matrix). This is underclaiming: code ships before claims update. Better than the reverse, but still a gap.

---

## 6. Assessment

The bd-xuo95 reality-check-bridge work is solid engineering, not theater.

**What's good:**
- Honest disclosure: btrfs RW non-durability is clearly documented and fail-safe interlocked
- Parity verification improved: `ExecutionGatedParityReport` breaks the tautology
- Code quality high: `#![forbid(unsafe_code)]` everywhere, proper overflow handling, well-structured MVCC/SSI
- Real verification: DPOR enumeration plus WB-I1/WB-I2 oracles actually execute

**What needs attention:**
- Documentation staleness: `FEATURE_PARITY.md` may underclaim some completed work
- btrfs tree-log write path remains V1.x future scope (performance optimization)

**No overclaims found** in the post-bridge state:
- btrfs RW says "in-memory", not "durable"
- Parity requires execution evidence
- README wording is evidence-gated

**The core lesson:** this is how you fix overclaiming. Don't hide it, interlock it. The bd-xuo95 epic identified real gaps (the btrfs facade, the parity tautology), built infrastructure to close them, and made the limitations explicit and fail-safe. The code ships before the claims update, not the reverse.

---

## 7. Commit Trail

Key commits in the bd-xuo95 epic:

| Commit | Description |
|--------|-------------|
| `d12e326f` | Add reality-check bridge plan and gap-closure bead queue |
| `257bc666` | feat(ffs-btrfs): execute writeback-cache 12-point crash matrix (bd-xuo95.31) |
| `9d5cbbcb` | feat(ffs-harness): execution-gated parity replaces tautology test (bd-xuo95.11) |
| `697f3771` | feat(ffs-harness): three-column parity truth for B3 (bd-xuo95.12) |
| `baf9278c` | bd-xuo95.15 execute proof-bundle lanes from validator |
| `9937f98f` | bd-xuo95.26 implement SSI two-edge detection |
| `a8a13ca0` | bd-xuo95.27 clarify mvcc merge proof taxonomy |
| `982040d5` | chore(ffs-harness): add module census (bd-xuo95.19) |
| `5f8f04ca` | chore(ffs-harness): relocate meta ops to ffs-ops (bd-xuo95.20) |
| `d1f39120` | ci(ffs-harness): warn on unmatched meta loc growth (bd-xuo95.21) |
| `c7b8d0d8` | docs(readme): place ffs-btrfs on runtime path (bd-xuo95.22) |
| `1da9fb65` | docs(readme): de-slop public wording (bd-xuo95.25) |
| `4003df15` | docs(readme): E6 reconcile Verified claims with reproducible evidence (bd-xuo95.40) |
| `f915cd30` | chore(beads): close bd-xuo95.38 + reality-check-bridge epic closeout |

---

*Written 2026-05-21. This document describes the state of the codebase as of commit `f915cd30`. Revised with contributions from EmeraldCoast, SwiftLantern, WildOak, and DarkThrush.*
