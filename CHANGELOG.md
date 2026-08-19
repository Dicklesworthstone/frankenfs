# Changelog

All notable changes to FrankenFS are documented in this file, organized by capability area rather than chronological diff order. Development has been continuous since inception; **`v0.2.0` (2026-07-11) is the project's first tagged release**, cut to mark the completion of the solo performance-optimization campaign. Commit links point to the canonical GitHub repository.

> **Repository:** <https://github.com/Dicklesworthstone/frankenfs>
> **Period covered:** 2026-02-09 through 2026-08-19 (`main` HEAD [`f84e12d70`](https://github.com/Dicklesworthstone/frankenfs/commit/f84e12d702d36eae8adf8bd266f3b7f84b272003))
> **Total commits:** 3,448 (through the 2026-05-18 capability cutoff; the `v0.2.0` performance campaign covers 2026-05-18 → 2026-07-11; **1,634 further commits** sit on `main` after `v0.2.0` and are summarized under [Unreleased](#unreleased--post-v020-2026-07-11--2026-08-19))
> **Tracker:** [`.beads/issues.jsonl`](https://github.com/Dicklesworthstone/frankenfs/blob/main/.beads/issues.jsonl) (raw rows as of 2026-05-18: 2,859 closed, 45 open, 1 deferred; source-aware queue excludes 28 foreign-looking open rows)

> **What's new since the 2026-04-07 cutoff (2,765 additional commits):** the
> tracked V1 parity matrix is complete at 97/97, and most engineering attention
> has shifted from filling gaps to *gating public claims with structured
> evidence*. The dominant new themes are: a checked-in release-gate policy with
> proof-bundle lanes, the advisory readiness lab and permissioned campaign
> broker, hostile-image / adversarial threat-model containment, broad
> metamorphic-relation proptest coverage, an end-to-end schema inventory
> pinning every machine-readable report shape, an asupersync 0.2 → 0.3
> migration, and adaptive mount-runtime modes (`standard` / `managed` /
> `per-core`) with their own evidence manifests. The mounted write workload
> matrix, repair-writeback serializer, swarm responsiveness lanes, and soak /
> canary campaign reporter all landed in the same window.

---

## Version Timeline

| Version | Date | Kind | Headline |
|---|---|---|---|
| **[Unreleased](#unreleased--post-v020-2026-07-11--2026-08-19)** | 2026-07-11 → 2026-08-19 | commits on `main` after `v0.2.0` (no new tag / GitHub Release) | Mounted vs-kernel honesty campaign, btrfs tree-log kernel interop, FUSE directory-stat residue, occupancy-aware harness, and the 2026-08-19 janitor docs-reorg |
| **[v0.2.0](https://github.com/Dicklesworthstone/frankenfs/releases/tag/v0.2.0)** | 2026-07-11 | First tagged release (GitHub Release) | Performance-campaign consolidation: measured, byte-identical wins across checksum, metadata/directory, extent/read, allocator, compression, MVCC, and btrfs-COW subsystems, plus an honest negative-evidence ledger of every rejected lever |
| _(pre-tag)_ | 2026-02-09 → 2026-05-18 | Untagged continuous development | V1 parity matrix complete (97/97 tracked rows); release-gate policy, proof bundles, adaptive mount-runtime modes, hostile-image containment, metamorphic proptests, asupersync 0.2 → 0.3 (documented in the capability sections below) |

> `v0.2.0` remains the only tagged GitHub Release. Prior to that tag FrankenFS had no formal releases; the capability sections that follow reconstruct that untagged history by subsystem. The post-tag window is Unreleased.

---

## [Unreleased] — post-`v0.2.0` (2026-07-11 → 2026-08-19)

1,634 commits on [`main`](https://github.com/Dicklesworthstone/frankenfs/compare/v0.2.0...main) after the first tagged release. No new tag or GitHub Release exists in this window. The work is a measured vs-kernel campaign on mounted ext4/btrfs, a harness-honesty campaign that made those ratios admissible, and a btrfs tree-log interop slice the kernel can actually replay. Rejected levers stay in the negative-evidence ledger; several titled FUSE short-circuits were answered as near-nulls and left default-OFF.

### Mounted vs-kernel honesty (late July 2026)

The campaign's first defensible vs-incumbent number was that FrankenFS is **4.5× slower** than kernel ext4 on the mounted arm ([`e04111e1c`](https://github.com/Dicklesworthstone/frankenfs/commit/e04111e1c)). The harness grew the provenance that makes a ratio checkable: host-wide exclusivity, fixture quiescence, observed worker-thread attestation, CPU-governor recording, counterbalanced kernel A/A nulls, and a replaced null-CI straddle veto ([`2198a47de`](https://github.com/Dicklesworthstone/frankenfs/commit/2198a47de), [`6506e1fe6`](https://github.com/Dicklesworthstone/frankenfs/commit/6506e1fe6)). An admitted btrfs vs-incumbent ratio landed near **5.0× slower** and was replicated. Losing metadata-buffer and multi-reader FUSE candidates were reverted in the same week rather than survivorship-filtered.

### FUSE transport and directory-stat residue (2026-07-31 → 2026-08-19)

Opt-in Linux FUSE-over-io_uring (`FFS_FUSE_IO_URING`) ([`7473d535c`](https://github.com/Dicklesworthstone/frankenfs/commit/7473d535c)). A real `getattr_batch` resolves in inode order and returns in request order ([`8a806525c`](https://github.com/Dicklesworthstone/frankenfs/commit/8a806525c)). The readdir+stat residue was measured as a per-entry LOOKUP/GETATTR/GETXATTR trio (STATX with BTIME), not a getattr/`attr_valid` miss; several titled short-circuit levers were answered as <1% end-to-end or default-OFF. Occupancy padding is now an achieved-occupancy signal the harness can tune ([`f1bfe595d`](https://github.com/Dicklesworthstone/frankenfs/commit/f1bfe595d)).

### btrfs tree-log kernel interop (August 2026)

FrankenFS now emits the kernel's two-block tree-log shape, publishes N log nodes behind one barrier, and replays the kernel log-root-tree instead of refusing it ([`1ceca99e7`](https://github.com/Dicklesworthstone/frankenfs/commit/1ceca99e7)). A P0 checksum-map-twice bug was losing every ephemeral fsync on replay ([`6f477aec3`](https://github.com/Dicklesworthstone/frankenfs/commit/6f477aec3)). SYSTEM-chunk growth became kernel-mountable ([`aded6b9b3`](https://github.com/Dicklesworthstone/frankenfs/commit/aded6b9b3)).

### Janitor docs-reorg wave (2026-08-19)

Non-locked planning docs moved under [`docs/planning/`](https://github.com/Dicklesworthstone/frankenfs/tree/main/docs/planning). [`FEATURE_PARITY.md`](https://github.com/Dicklesworthstone/frankenfs/blob/main/FEATURE_PARITY.md) and the five root specs (`COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md`, `EXISTING_EXT4_BTRFS_STRUCTURE.md`, `PLAN_TO_PORT_FRANKENFS_TO_RUST.md`, `PLAN_TO_PORT_LEGACY_FS_TO_RUST.md`, `PROPOSED_ARCHITECTURE.md`) stay at the repository root because tests and the README table pin them.

- [`d21f58e2c`](https://github.com/Dicklesworthstone/frankenfs/commit/d21f58e2c1058622524452c067efec54d11862c4) — untrack skill-loop scratch.
- [`f84e12d70`](https://github.com/Dicklesworthstone/frankenfs/commit/f84e12d702d36eae8adf8bd266f3b7f84b272003) — relocate `EXISTING_LEGACY_FS_STRUCTURE.md`, `MODULARITY_RUNBOOK.md`, `PARITY-COVERAGE.md`, and `PROFILING-SUMMARY.md` into `docs/planning/`.

---

## v0.2.0 — Performance Campaign (2026-05-18 → 2026-07-11)

A multi-agent, negative-evidence-ledger-first optimization campaign. Every kept
lever is **measured** (honest same-worker A/B interleaved in one binary, gated on
**median** self-time vs a **paired null control** — the identical arm run twice —
with cv < 5%), **isomorphism-preserving** (behaviour proven byte-identical, and
btrfs images pass `btrfs-check` / ext4 images pass `e2fsck` before the win is
kept), and **profile-first** (the mechanism comes from a callgrind/perf profile
or the code, never a guess). One lever per commit. Rejected levers are not
deleted — they are recorded with their null-control result and a *retry
condition* in the negative-evidence ledger, so no one re-attempts a dead end.

The comparator throughout is the mounted **kernel** filesystem (ext4 / btrfs).
Ratios below are the measured medians from the campaign; where a candidate
*failed* honest scrutiny (e.g. a headline cold-read row that flipped sign under
a corrected harness), that too is recorded rather than shipped.

### Checksum / CRC — the deepest vein

Incremental and zero-run-aware CRC primitives replaced whole-block recomputation
across every checksum site.

- **Incremental `crc32c` primitive** — roll a delta into an existing CRC instead
  of re-CRC-ing the whole block: **11.6×** vs full recompute
  [`ff222d17`](https://github.com/Dicklesworthstone/frankenfs/commit/ff222d17), widened to **14×** with a table-driven `raw_crc32c`
  [`2372577b`](https://github.com/Dicklesworthstone/frankenfs/commit/2372577b) and **24.7×** with a branchless `gf2_matrix_times`
  [`17380f69`](https://github.com/Dicklesworthstone/frankenfs/commit/17380f69).
- **Incremental dir-block checksum** — **10.3×** vs full recompute
  [`56cb5f94`](https://github.com/Dicklesworthstone/frankenfs/commit/56cb5f94), wired into the CREATE/rename insert path (span-gated)
  at **9.25×** [`4976d6d7`](https://github.com/Dicklesworthstone/frankenfs/commit/4976d6d7).
- **Zero-run-aware CRCs** — algebraically skip the zero tail: superblock **1.12×**
  [`041f04f4`](https://github.com/Dicklesworthstone/frankenfs/commit/041f04f4) (completing the vein), plus zero-run-aware bitmap
  (2.54×), extent-node (3.52×) and dir-block (3.92×) variants.
- **Axis close** — the write-side inode checksum stamp was verified already
  no-copy (single-pass zero-in-place); crc32c uses the HW instruction and
  `csum_seed` is cached at open [`a5a97e12`](https://github.com/Dicklesworthstone/frankenfs/commit/a5a97e12).

### Metadata & directory operations — algorithmic complexity kills

The highest-value wins: several directory operations were quadratic and are now
linear or logarithmic.

- **Name-index closes the create existence-check `O(N²)`** — create went from
  **26× slower than kernel to kernel parity**
  [`1fcd0b62`](https://github.com/Dicklesworthstone/frankenfs/commit/1fcd0b62); hook extended to mkdir/mknod/symlink/link,
  `O(N²)→O(N)`, **75× → 1.35×** vs kernel [`96aa5c53`](https://github.com/Dicklesworthstone/frankenfs/commit/96aa5c53).
- **Delete htree fast-path** — removal `O(N²)→O(log N)`, delete gap **5.3× → 2.1×**
  [`85d46923`](https://github.com/Dicklesworthstone/frankenfs/commit/85d46923).
- **Coalesce contiguous extents on the file write-allocation path** —
  `O(N²)→O(N)`, **120× at N=40k** on fine-grained 4 KiB allocation
  [`2aa92946`](https://github.com/Dicklesworthstone/frankenfs/commit/2aa92946).
- **Rename preflights only the hash-target leaf**, not all dir blocks —
  `O(N²)→O(N)`, **5.57× at N=40k** [`51294142`](https://github.com/Dicklesworthstone/frankenfs/commit/51294142).
- **Shard the name-index** to fix a parallel-create rayon convoy — 4× *negative*
  scaling → 2×, kernel gap **16× → 8.3×** [`4cfc2dac`](https://github.com/Dicklesworthstone/frankenfs/commit/4cfc2dac).
- **htree leaf-search borrow** — lookup **2.5×**, helps every metadata op
  [`d52eb62e`](https://github.com/Dicklesworthstone/frankenfs/commit/d52eb62e); skeletal `AttrOnly` inode parse for getattr **1.11×**
  [`8314ca8c`](https://github.com/Dicklesworthstone/frankenfs/commit/8314ca8c); `MetadataOnly` parse for the name-index stamp **1.24×**
  [`bc47b311`](https://github.com/Dicklesworthstone/frankenfs/commit/bc47b311); `sort_unstable` for htree hash sorts **1.47×**
  [`a4ba9241`](https://github.com/Dicklesworthstone/frankenfs/commit/a4ba9241).

### SWAR / word-at-a-time primitives

Branchless byte-processing on hot string and hash paths.

- **Word-at-a-time hash for `extent_root_namespace`** — **7.14×**
  [`96c27663`](https://github.com/Dicklesworthstone/frankenfs/commit/96c27663).
- **SWAR one-pass path-component validation** (has-byte trick) — **3.41×**
  [`2a380996`](https://github.com/Dicklesworthstone/frankenfs/commit/2a380996); the has-zero family (name/path validate, first-NUL symlink) lands
  **3.1–4.0×**.
- **SWAR ASCII case-fold compare** for casefold directories — **1.64×**
  [`3dcf558f`](https://github.com/Dicklesworthstone/frankenfs/commit/3dcf558f); SWAR word-at-a-time name compare **1.80×**.
- **`str2hashbuf` on a stack `[u32;8]`** — ~34% faster htree hash, removes a
  per-hash heap alloc [`a6c4c505`](https://github.com/Dicklesworthstone/frankenfs/commit/a6c4c505).

### Extent resolution & read path

- **Binary-search the ext4 extent leaf + index** — `O(E)→O(log E)`, **up to 19×**
  [`2785e425`](https://github.com/Dicklesworthstone/frankenfs/commit/2785e425).
- **Sequential mapping hint** on the per-block read resolve — **2.0–2.5×**, no
  downside [`751251da`](https://github.com/Dicklesworthstone/frankenfs/commit/751251da), extended to the readdir plan loops
  [`8334e658`](https://github.com/Dicklesworthstone/frankenfs/commit/8334e658).
- **Fix `ExtentCache` shard distribution** (hash the namespace) — **4.6×**
  many-inode read-data [`0301f38a`](https://github.com/Dicklesworthstone/frankenfs/commit/0301f38a); extent-cache depth-1 borrow-in-place skips
  the per-block `Vec` take/store [`23986087`](https://github.com/Dicklesworthstone/frankenfs/commit/23986087).
- **Memoize journal-inode indirect resolution** in journal replay — fixes a
  **2024×** re-read at every mount [`fe00c75e`](https://github.com/Dicklesworthstone/frankenfs/commit/fe00c75e), plus a multi-entry indirect-block
  memo [`f7c9f328`](https://github.com/Dicklesworthstone/frankenfs/commit/f7c9f328).
- **btrfs read directly into the caller buffer** in `read_into` — **1.37× warm,
  RSS halved, beats kernel** [`54b0ae94`](https://github.com/Dicklesworthstone/frankenfs/commit/54b0ae94); RO decompressed-extent cache
  **1.55×** compressed random read [`90bf7cfa`](https://github.com/Dicklesworthstone/frankenfs/commit/90bf7cfa).

### Allocator

- **Binary range-overlap for the free-path reserved check** — **up to 3110×**
  [`af91cc18`](https://github.com/Dicklesworthstone/frankenfs/commit/af91cc18).
- **Cache the per-group reserved-block set** — mkdir **2.77×**, all
  block-allocation ops [`37cdf5f8`](https://github.com/Dicklesworthstone/frankenfs/commit/37cdf5f8); skip the per-alloc reserved-marking loop once
  the group is confirmed — mkdir **1.16×** [`c5df77f0`](https://github.com/Dicklesworthstone/frankenfs/commit/c5df77f0).
- **Byte-wise inode-bitmap padding fill** — create **1.14×** / parallel **1.18×**
  [`369f1493`](https://github.com/Dicklesworthstone/frankenfs/commit/369f1493); skip the per-alloc largest-free-run rescan on the single-block path
  (~1.15×, exact-on-demand) [`8319465d`](https://github.com/Dicklesworthstone/frankenfs/commit/8319465d).
- **Skip re-reading the unchanged bitmap** for the descriptor checksum —
  **15.8× fewer delete preads** [`b296dbdb`](https://github.com/Dicklesworthstone/frankenfs/commit/b296dbdb).

### Compression — codec-context reuse

Swapped the DEFLATE backend to the pure-safe-Rust `zlib-rs` (byte-identical
output, no C toolchain, compatible with `unsafe_code = "forbid"`) and reuse the
codec context across calls.

- **Thread-local zlib inflate context reuse** in `btrfs_decompress` — **1.43×**
  decode, avoids the 32 KiB inflate-window alloc per call
  [`32a86235`](https://github.com/Dicklesworthstone/frankenfs/commit/32a86235); shared with e2compr gzip inflate — **2.21× at 4 KiB**
  [`85f0ccea`](https://github.com/Dicklesworthstone/frankenfs/commit/85f0ccea); level-keyed deflate (write) context reuse — **1.44×**
  [`a1e666c0`](https://github.com/Dicklesworthstone/frankenfs/commit/a1e666c0).

### MVCC concurrency

- **Skip per-read snapshot register/release** for read-only reads — **5×**
  parallel random read [`9376f4d6`](https://github.com/Dicklesworthstone/frankenfs/commit/9376f4d6).
- **Drop the forced 4096-realign** on version storage — **1.82× commit, 1.35×
  throughput** [`eb229915`](https://github.com/Dicklesworthstone/frankenfs/commit/eb229915).
- **Size the sharded store to host parallelism** instead of a fixed 8 shards —
  parallel writes **1.17× @16w / 1.29× @32w** [`a2807896`](https://github.com/Dicklesworthstone/frankenfs/commit/a2807896).

### btrfs COW batching

- **COW `insert_many` in-place batching** — **1.68×** on the btrfs-create insert
  pattern [`56fdc677`](https://github.com/Dicklesworthstone/frankenfs/commit/56fdc677); coalesce the create/mkdir/delete/rename parent updates via
  `insert_many`/`remove_many`: create **1.43×** (gap 3.0× → 2.08×)
  [`b5e22c17`](https://github.com/Dicklesworthstone/frankenfs/commit/b5e22c17), mkdir **1.45×** [`d518312a`](https://github.com/Dicklesworthstone/frankenfs/commit/d518312a), delete **1.44×**
  [`aee47f35`](https://github.com/Dicklesworthstone/frankenfs/commit/aee47f35), rename **1.25×** [`f90648f5`](https://github.com/Dicklesworthstone/frankenfs/commit/f90648f5).
- **`Arc<[u8]>` for COW item data** — **1.47×** create [`2e4e848d`](https://github.com/Dicklesworthstone/frankenfs/commit/2e4e848d); **`FxHashMap`**
  node store — **1.20×** delete [`8b04930e`](https://github.com/Dicklesworthstone/frankenfs/commit/8b04930e); separator-carry-forward removal makes
  rename separator recompute `O(max_items)→O(1)`, **+1.13× @40k**
  [`c911e8a5`](https://github.com/Dicklesworthstone/frankenfs/commit/c911e8a5).
- **Fan-out gate the prefetch pool** — btrfs metadata walk **4.3×** (7× → 1.6× vs
  kernel) [`18fb0e88`](https://github.com/Dicklesworthstone/frankenfs/commit/18fb0e88); cold metadata is now **~3× faster than kernel** on a
  40k-file directory [`c27194d0`](https://github.com/Dicklesworthstone/frankenfs/commit/c27194d0).

### CLI / global allocator

- **jemalloc global allocator** — create **1.26–1.6× faster** (now faster than
  kernel single-thread), parallel **2.2×** [`14f443cb`](https://github.com/Dicklesworthstone/frankenfs/commit/14f443cb).
- **Parallelize `walk --read-data`** across files — many-small-files read **3.85×
  loss → 1.29× win** [`de194cb9`](https://github.com/Dicklesworthstone/frankenfs/commit/de194cb9); cap the rayon pool for metadata-only walk —
  **1.57×** (4.0× vs kernel `find + stat`) [`e9800e82`](https://github.com/Dicklesworthstone/frankenfs/commit/e9800e82).

### Honesty ledger — what was measured and *not* shipped

The campaign is as much about rejected levers as kept ones. Representative
findings recorded (not shipped) in the negative-evidence ledger:

- **Cold-read headline correction** — the previously-reported "1.7× faster than
  kernel" cold row **flipped sign under a corrected harness**: frankenfs is
  actually **1.42× slower**, and ext4-indirect / fragmented cold rows are slower
  too [`913dd5c6`](https://github.com/Dicklesworthstone/frankenfs/commit/913dd5c6), [`b873beac`](https://github.com/Dicklesworthstone/frankenfs/commit/b873beac). 41% of the best-config gap was traced to
  benchmark-harness overhead, not the filesystem [`ac08c8fd`](https://github.com/Dicklesworthstone/frankenfs/commit/ac08c8fd).
- **`Arc<InodeAttr>` whole-workspace change** — ~10% *regression* on both
  filesystems (a 130 B POD memcpy is cheaper than two atomic RMWs + a miss
  alloc); retry only if `InodeAttr` grows large.
- **Interpolation search on extent resolution** — 3.46–6.6× faster on synthetic
  uniform data but **2.4–2.9× slower** on realistic skewed extents; ext4's
  ≤340-entry leaves are L1-resident, so comparisons beat the per-probe divide.
  Rejected [`ae941d38`](https://github.com/Dicklesworthstone/frankenfs/commit/ae941d38).
- **The GDT-defer 2.3× lever** was measured real (per-op group-descriptor writes
  are ~55% of ext4 create) but **shelved unshipped** pending a focused flush-pass
  fix rather than landed blind [`8451bb5e`](https://github.com/Dicklesworthstone/frankenfs/commit/8451bb5e).

**Evidence sources for this section:** `docs/PERF_CAMPAIGN_FINAL.md` (the shipped
wins-by-axis and consolidated reject tables), `docs/PERF_CAMPAIGN_STATUS.md`
(live frontier statement), `docs/NEGATIVE_EVIDENCE.md` and
`docs/progress/perf-negative-results.md` (per-lever null-control ledger), the
`perf(` / `bench(` commit history on `main`, and the `.beads/issues.jsonl`
tracker rows (bd-4tw2n, bd-vpypn, bd-ddryj, bd-bhh0i, bd-cowbatch, bd-xmh5g,
bd-f8rd8, and siblings).

---

## Table of Contents

- [Readiness, Release Gates, and Proof Bundles](#readiness-release-gates-and-proof-bundles)
- [Hostile-Image and Adversarial Safety](#hostile-image-and-adversarial-safety)
- [Metamorphic Relations and Schema Conformance](#metamorphic-relations-and-schema-conformance)
- [Mount Runtime Modes and Adaptive Dispatcher](#mount-runtime-modes-and-adaptive-dispatcher)
- [On-Disk Parsing (ext4)](#on-disk-parsing-ext4)
- [On-Disk Parsing (btrfs)](#on-disk-parsing-btrfs)
- [FUSE Mount and VFS Layer](#fuse-mount-and-vfs-layer)
- [Block I/O and ARC Cache](#block-io-and-arc-cache)
- [MVCC Concurrency Engine](#mvcc-concurrency-engine)
- [Safe-Merge Conflict Resolution](#safe-merge-conflict-resolution)
- [Self-Healing Repair Pipeline](#self-healing-repair-pipeline)
- [Writeback-Cache Epoch Barriers](#writeback-cache-epoch-barriers)
- [Write Path (Allocation, Extents, Inodes, Directories, Xattrs)](#write-path)
- [Journal and WAL Recovery](#journal-and-wal-recovery)
- [CLI and Observability](#cli-and-observability)
- [TUI Dashboard](#tui-dashboard)
- [Conformance Harness and Testing](#conformance-harness-and-testing)
- [Fuzz Infrastructure](#fuzz-infrastructure)
- [Performance and Benchmarking](#performance-and-benchmarking)
- [Foundation Types and Error Handling](#foundation-types-and-error-handling)
- [Documentation and Architecture](#documentation-and-architecture)
- [Build, Dependencies, and Licensing](#build-dependencies-and-licensing)

---

## Readiness, Release Gates, and Proof Bundles

The single largest new workstream in this window. Tracked V1 parity reached
100% earlier in the year; the bridge to operationally-credible public claims
is now governed by a checked-in release-gate policy, a portable proof-bundle
artifact, and a structured advisory readiness lab.

- **Canonical release-gate policy v1** -- `tests/release-gates/release_gate_policy_v1.json` maps every public claim class (`mount.rw.ext4`, `mount.rw.btrfs`, `repair.rw.writeback`, `writeback_cache`, `swarm.responsiveness`, `security.hostile_image`, `performance.baseline`, `operational.soak_canary`, etc.) to required proof-bundle lanes, thresholds, kill switches, remediation beads, and explicit non-goals
  [`2104a1e`](https://github.com/Dicklesworthstone/frankenfs/commit/2104a1ef615a112954e6280bc7214a4283ce5c0f),
  [`9132c6c`](https://github.com/Dicklesworthstone/frankenfs/commit/9132c6c60093637d7db8838981ea2c366f7eec5e),
  [`068234d`](https://github.com/Dicklesworthstone/frankenfs/commit/068234d9d8187d4771a24b133aba221f95a90f0b)

- **Operator proof bundle** rooted at `artifacts/proof/bundle/manifest.json` with 14 required lanes (`conformance`, `xfstests`, `fuse`, `differential_oracle`, `repair_lab`, `crash_replay`, `performance`, `writeback_cache`, `scrub_repair_status`, `known_deferrals`, `release_gates`, `swarm_workload_harness`, `swarm_tail_latency`, `adaptive_runtime`); validated via `ffs-harness validate-proof-bundle` with bundle id, git SHA, toolchain, kernel, mount capability, raw logs, gate inputs, artifact hashes, redaction policy, and reproduction command
  [`fa66e92`](https://github.com/Dicklesworthstone/frankenfs/commit/fa66e923af47e5acff032dc3050d889fed77609f)

- **Advisory readiness lab** -- non-permissioned operator rehearsal surface that regenerates contracts, host simulation, RCH dry-run schedules, truth-graph summaries, xfstests handoff packets, NUMA/p99 replay reports, and readiness-dashboard rows without exporting permissioned ACK variables. Every artifact carries `product_evidence_claim=none` and a release-gate effect equivalent to `advisory_only_no_public_readiness_change`
  [`77a3289`](https://github.com/Dicklesworthstone/frankenfs/commit/77a32890b05d0dfcf1b00e2be6ae5db0c1d242c6),
  [`5beaaa6`](https://github.com/Dicklesworthstone/frankenfs/commit/5beaaa600b51ffc47cf5c82de0ae55d710914e22),
  [`5d85138`](https://github.com/Dicklesworthstone/frankenfs/commit/5d85138e1743dae318d6d004c25d13c549b1bfcf)

- **Permissioned campaign broker** -- packet/manifest/validator/ledger contract for xfstests and large-host swarm runs. Broker packets are operator handoff material and cannot be counted as `pass` evidence; ACK boundaries are exact strings (`XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices`, `FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host`)
  [`b7d18b4`](https://github.com/Dicklesworthstone/frankenfs/commit/b7d18b44e0e42d8a10d38468d92bbf4d3e59c757),
  [`aa433e5`](https://github.com/Dicklesworthstone/frankenfs/commit/aa433e5f17b858602027bf7d2da623d6e3437997)

- **Swarm responsiveness lanes** -- three proof-bundle lanes (`swarm_workload_harness`, `swarm_tail_latency`, `adaptive_runtime`) connecting the NUMA-aware workload harness, p99 attribution ledger, and adaptive runtime opt-in evidence to the release-gate policy. Strict `host_class` rules block `small_host_smoke` / `capability_downgraded_smoke` lanes from upgrading public claims
  [`0f39df4`](https://github.com/Dicklesworthstone/frankenfs/commit/0f39df4f5934e4b68af84ec9dcb7391d6af38425),
  [`6a5cf9d`](https://github.com/Dicklesworthstone/frankenfs/commit/6a5cf9d47fea1e0dfc42bcce7dd3b91c54036786),
  [`b1f3593`](https://github.com/Dicklesworthstone/frankenfs/commit/b1f35937dc310517727663c0e43f83e969811d97)

- **Soak / canary campaign reporter** -- `validate-soak-canary-campaigns` defines bounded smoke / nightly / stress / canary profiles, heartbeat logs, resource caps, flake follow-up rules, and proof-bundle / release-gate consumers
  [`fd5ab83`](https://github.com/Dicklesworthstone/frankenfs/commit/fd5ab831c4917ef3076ac9aa44d3872800c2ed6b),
  [`018fa31`](https://github.com/Dicklesworthstone/frankenfs/commit/018fa31fb5c353e2a55f4be5786ed606847b2aa4)

- **Source-aware tracker hygiene** -- `docs/tracker-hygiene.md` plus
  `./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh` define a queue-state check
  that classifies `claimable_ids`, `permission_gated_ids`, and
  `excluded_foreign_open_count` so the swarm tracker survives multi-project
  pollution without illegally claiming foreign rows
  [`7ec22d2`](https://github.com/Dicklesworthstone/frankenfs/commit/7ec22d2874e5f4d988dcc17e12e2fb041ae47089),
  [`c24fe01`](https://github.com/Dicklesworthstone/frankenfs/commit/c24fe01c0a4d50b69200fb8465901691c9e32ab5),
  [`4584fc4`](https://github.com/Dicklesworthstone/frankenfs/commit/4584fc44262988415632de419347a8b0dcd48a89)

- **Ambition evidence matrix** -- `ffs-harness validate-ambition-evidence-matrix` records ambition-row prerequisites, proof lanes, unit/E2E/log/artifact contracts, downstream proof-bundle and release-gate consumers, and the release claim each row may or may not strengthen
  [`a1352575`](https://github.com/Dicklesworthstone/frankenfs/commit/a135257548bfa2635e9f8e2539e24a9a0c7d3fb6)

- **Readiness action CLI** -- `ffs-harness` now exposes readiness-action dry-run logs, planning JSON, and validation JSON with insta snapshot coverage so dry-run output cannot drift unnoticed
  [`70faf60`](https://github.com/Dicklesworthstone/frankenfs/commit/70faf600bb361260b41846addbc67654e542151f),
  [`19ef13f`](https://github.com/Dicklesworthstone/frankenfs/commit/19ef13ff3ccfebaa0e945f002d122884ae224f12),
  [`eaded2b`](https://github.com/Dicklesworthstone/frankenfs/commit/eaded2bf2d9439113b1bbb6739e0fbe176a62c44)

- **Operator recovery drill** -- `docs/operator-recovery-drill.json` plus detection-only, dry-run, verified opt-in mutation, unsafe-refusal, rollback, verification, cleanup, and proof-bundle lane evidence under a single contract

---

## Hostile-Image and Adversarial Safety

A separate release-gated claim with its own threat model, fixtures, and
containment proofs.

- **Adversarial threat model** -- `security/adversarial_image_threat_model.json` defines how malformed images, hostile proof bundles, tampered repair ledgers, resource-exhaustion seeds, unsupported mount options, and unsafe operator-command combinations must be rejected, quarantined, capped, downgraded to detection-only, or preserved as evidence. Each containment scenario records resource class, limit value/unit, enforcement point, observed counters, cleanup policy, and confined artifact paths
  [`d2c446d`](https://github.com/Dicklesworthstone/frankenfs/commit/d2c446db069b20ac82a205643c8b1e864f91fa54),
  [`ab20351`](https://github.com/Dicklesworthstone/frankenfs/commit/ab20351146328a4f5e1847a965b2e847b6d02d83)

- **Hostile-image containment hardening** (bd-0qx9b) -- path traversal / symlink refusal, critical fail-closed handling, repair-ledger tamper refusal, docs-safe wording, and bounded hostile fixture classifications
  [`ab20351`](https://github.com/Dicklesworthstone/frankenfs/commit/ab20351146328a4f5e1847a965b2e847b6d02d83)

- **Adversarial on-disk corpus** -- 9 new ext4/btrfs surface MUST clauses; parser-level adversarial fixtures for `parse_dev_item`, `MmpBlock`, and adversarial ext4 / btrfs transaction regression coverage
  [`bcfd3cc`](https://github.com/Dicklesworthstone/frankenfs/commit/bcfd3ccab9870937aa67064eb5a47d0b2ba79a87),
  [`616175e`](https://github.com/Dicklesworthstone/frankenfs/commit/616175e565b6a020debca3f3370a20fdff873443),
  [`2d53508`](https://github.com/Dicklesworthstone/frankenfs/commit/2d535089d4fce61c4309c7d2695036c65eba0b91)

- **btrfs staged-allocation COW** with adversarial transaction regression suite -- exercises malformed allocator state across COW transactions and verifies durable rollback
  [`5f6c18b`](https://github.com/Dicklesworthstone/frankenfs/commit/5f6c18beb694ff4d3e01ea1d9b93649ccaf7188e)

- **Adversarial path redaction** in harness reports so hostile fixture paths cannot leak operator-machine-specific layout in CI logs
  [`4842fe6`](https://github.com/Dicklesworthstone/frankenfs/commit/4842fe6e1315b8686afeb2ee302b2e2a787de2c7)

---

## Metamorphic Relations and Schema Conformance

A systematic push to make every checksum, parser, and reporting surface
provably stable under input-shape perturbations and to lock every
machine-readable artifact's JSON shape to an inventory.

- **Metamorphic-relation proptests** across the parsing and checksum surface:
  - `crc32c_append` associativity (bd-oviw2)
  - `ext4_chksum` associativity (bd-8pbjm)
  - `dx_hash` zero-seed equivalence (bd-ldp92)
  - `ext4_casefold_key` idempotence (bd-8u2xy)
  - `ext4_gdt_crc16` associativity + empty-suffix MRs (bd-0djme)
  - `btrfs_send_crc32c` foundational laws (bd-gasht)
  - `btrfs_key_cmp` total-order laws (bd-f1k5j)
  - `Ext4GroupDesc::parse_from_bytes` determinism (bd-ewh2w)
  - `parse_from_image` determinism for both ext4 and btrfs (bd-vvkfy)
  - `verify_*_checksum` pair determinism (bd-begr3)
  - `batch_checksum` Blake3 variant (bd-2ihe1)
  - `btrfs_inode_ref` round-trip MRs into cargo test (bd-2nko1)
  - `touch_*` version-bump dispatch invariants (bd-wgvh5)
  - `bitmap` stamp/verify proptest MRs (bd-e5vp5)
  [`17451bb`](https://github.com/Dicklesworthstone/frankenfs/commit/17451bbc6d45501375e7c33588c5b91c2af2e3b1),
  [`7cbcdeb`](https://github.com/Dicklesworthstone/frankenfs/commit/7cbcdeb6e0c9f1f55ce444418811d8ed65d0dae8),
  [`fb8ed33`](https://github.com/Dicklesworthstone/frankenfs/commit/fb8ed33d4d917dba33272f92b4e2b8a84e957fdb),
  [`b103e28`](https://github.com/Dicklesworthstone/frankenfs/commit/b103e2834952f33a3286820c9c928ffb4e5f89b4),
  [`4e1d2ed`](https://github.com/Dicklesworthstone/frankenfs/commit/4e1d2ed7cb881e19cb13b0ae3ce5d902a273f3b2),
  [`caca750`](https://github.com/Dicklesworthstone/frankenfs/commit/caca750cedc37b89a8c6a7db5ea025d6d9ae6725)

- **Metamorphic seed catalog** -- enumerated catalog of metamorphic relations with snapshot pinning and fallible test coverage to prevent silent drift
  [`c3c9e54`](https://github.com/Dicklesworthstone/frankenfs/commit/c3c9e54009b92a9a45f21c0aea38bc2795a2fcdc),
  [`ef02a5b`](https://github.com/Dicklesworthstone/frankenfs/commit/ef02a5b29cdbab3c227f8e2bda05d4aad0aaa523)

- **Cross-oracle arbitration** -- when ext4/btrfs differential oracles disagree on observable filesystem behavior, an arbitration report classifies the disagreement (parser-class vs. host-class vs. permission-class) with a structural JSON contract
  [`4c0bd80`](https://github.com/Dicklesworthstone/frankenfs/commit/4c0bd80048dd837b0ed51b548e8308237b2b8ef2),
  [`8a7e5d0`](https://github.com/Dicklesworthstone/frankenfs/commit/8a7e5d05f0b3aecba1bfd9d58291ac2a33499653)

- **Schema inventory** -- every machine-readable report, manifest, and ledger
  in the project (writeback, swarm, repair, readiness, performance, fuzz
  dashboard, mounted lane, oracle recovery, hysteresis, reservation, agent
  mail) now has its JSON shape pinned in a checked-in inventory with
  structural validators and drift detectors
  [`ffa4219`](https://github.com/Dicklesworthstone/frankenfs/commit/ffa4219749f0421b2e7d972faf0c8c3271a855dd),
  [`b3c30b9`](https://github.com/Dicklesworthstone/frankenfs/commit/b3c30b93f1d348a39cc29081fa25555c7c6bae0c),
  [`a30882a`](https://github.com/Dicklesworthstone/frankenfs/commit/a30882a61ebbe3a5e6b04c4086d3bdb8890804ad)

- **Round-trip + insta snapshots** on every emitted report -- 167+ snapshot
  commits pin the markdown/JSON output of release-gate, writeback-cache audit,
  ordering oracle, crash-replay oracle, repair confidence, repair corpus,
  fuzz-smoke, fuzz dashboard, mounted lane decision, soak/canary campaign,
  swarm operator/cache/tail latency, readiness lab truth graph, ambition
  evidence matrix, and parity audit reports

- **Fallible-by-default test refactor** -- bd-rchk0 turned dozens of
  best-effort `assert!`-only paths into fallible `Result`-returning tests so
  evidence-gate failures surface as structured errors rather than silent
  passes or harness panics

---

## Mount Runtime Modes and Adaptive Dispatcher

The optional adaptive mount runtime, default-off, that the `swarm.responsiveness`
and `adaptive_runtime` release lanes gate.

- **Runtime-mode CLI contract** -- `--runtime-mode {standard|managed|per-core}` exposes three execution profiles. `standard` is the existing FUSE dispatcher; `managed` adds explicit unmount timeout, evidence-bearing teardown, and adaptive backpressure-gate control; `per-core` enables per-thread routing with idle stealing
  [`db52ad5`](https://github.com/Dicklesworthstone/frankenfs/commit/db52ad54b2c6bf151688daf0852bd431370fd183)

- **Adaptive runtime evidence manifest** (`docs/adaptive-runtime-evidence-manifest.json`) -- mount-runtime evidence contract validated by `ffs-harness validate-adaptive-runtime-manifest` and gated by the `adaptive_runtime` proof-bundle lane; default-off, requires `accepted_large_host` evidence with clean cleanup before any docs/release-gate upgrade
  [`99c11bf`](https://github.com/Dicklesworthstone/frankenfs/commit/99c11bf10077f98808ad0599176afcf1142eef17),
  [`417266f`](https://github.com/Dicklesworthstone/frankenfs/commit/417266f7811d93ba3d04a12cab0cc40838caab9a),
  [`1b191e7`](https://github.com/Dicklesworthstone/frankenfs/commit/1b191e76e881dc2410f0f4e8da70da0474567578)

- **Per-core dispatcher hardening** -- idle stealing guarded against thread starvation, per-core metrics arithmetic saturated to prevent overflow under heavy load (bd-pcmet), and stale managed-mode placeholder removed
  [`c786061`](https://github.com/Dicklesworthstone/frankenfs/commit/c78606181ae12d309a92df8decdab1b39ed211e3),
  [`ceafb76`](https://github.com/Dicklesworthstone/frankenfs/commit/ceafb76a2aa12bc37506c9fc02993fd3fb07f031),
  [`9809780`](https://github.com/Dicklesworthstone/frankenfs/commit/98097804fc1bd0e12e570f856457e9c0d9134415)

- **Managed backpressure gate** -- wired into `--runtime-mode managed` so that backpressure decisions can be observed and tuned without modifying the standard dispatcher's hot path (bd-jv6pj.2)
  [`db52ad5`](https://github.com/Dicklesworthstone/frankenfs/commit/db52ad54b2c6bf151688daf0852bd431370fd183)

- **NUMA-aware tail-latency harness** -- `ffs_swarm_workload_harness_e2e.sh`, `ffs_swarm_tail_latency_e2e.sh`, and `ffs_adaptive_runtime_runner_e2e.sh` define safe local smoke flows. The `p99_attribution_ledger` artifact is mandatory inside the `swarm_tail_latency` proof-bundle lane

- **Topology runtime advisor manifest** (`docs/topology-runtime-advisor-manifest.json`) -- host topology hints consumed by the adaptive runtime in managed and per-core modes

---

## On-Disk Parsing (ext4)

Pure, I/O-free parsing of ext4 on-disk structures in `ffs-ondisk`. All parsers take `&[u8]` and return typed structures.

- **Initial ext4 superblock and structure parsing** -- superblock (106 fields), group descriptors (32-bit and 64-bit), inodes, extent header/entries, feature flag decoding
  [`01bc389`](https://github.com/Dicklesworthstone/frankenfs/commit/01bc38985fb499db3598734e29ec9b7adcbc7253),
  [`3d334bf`](https://github.com/Dicklesworthstone/frankenfs/commit/3d334bfbe7a8012569582ab8292457c1f6d78412)

- **Group descriptor, inode, and directory traversal** -- expand parsing with directory ops, path resolution, extent mapping, file reads via `Ext4ImageReader`
  [`098b4c5`](https://github.com/Dicklesworthstone/frankenfs/commit/098b4c50777375a6b5478ebd4a8ac3e52a406ff4),
  [`f96eb7a`](https://github.com/Dicklesworthstone/frankenfs/commit/f96eb7ad7433e595ca5040a0a441d3c6df8a163a)

- **Feature flag decode helpers** with typed structs replacing raw `u32` constants; `Ext4InodeNumber` and `BtrfsObjectId` wrapper types
  [`5b284ac`](https://github.com/Dicklesworthstone/frankenfs/commit/5b284acdeb11cd8100f87956ca704b62cb3ba046),
  [`d959f65`](https://github.com/Dicklesworthstone/frankenfs/commit/d959f65c45926e8b3d306a10bea11aef36779b8e)

- **SystemTime helpers and inode edge-case tests**
  [`29627fa`](https://github.com/Dicklesworthstone/frankenfs/commit/29627fa159334a17fb079684b726f9101785193a)

- **Comprehensive superblock geometry validation**
  [`aaae453`](https://github.com/Dicklesworthstone/frankenfs/commit/aaae453d64052cee4f792a42cbcbc81d88b07376)

- **Validated inode location helpers** for computing group/block/offset from inode number
  [`5ebb344`](https://github.com/Dicklesworthstone/frankenfs/commit/5ebb3447f95957384eee8505f2ce61e922cd5e08)

- **Zero-allocation `DirBlockIter`** for ext4 directory parsing without heap allocation
  [`2aae5c7`](https://github.com/Dicklesworthstone/frankenfs/commit/2aae5c7d7a583c08abdda7204dbb74ad384d085a)

- **Metadata checksum fixes** -- correct dir + extent block checksum coverage areas
  [`2a1fda2`](https://github.com/Dicklesworthstone/frankenfs/commit/2a1fda2344794d085f0345513d8b106259c59c48)

- **CRC32C convention mismatch fix** in ext4 checksum verification
  [`004fbc0`](https://github.com/Dicklesworthstone/frankenfs/commit/004fbc0f471cd05c90f7f13cfa3556f5dcc7701d)

- **DX hash multi-chunk iteration fix**, TEA transform, and directory size corrections
  [`3958521`](https://github.com/Dicklesworthstone/frankenfs/commit/3958521a88a2bf36a4d6330af44f4bd86687728a)

- **Off-by-one fix** in ext4 inode extended field parsing
  [`93fb9ca`](https://github.com/Dicklesworthstone/frankenfs/commit/93fb9ca7ee0614272ed24417dea12939cdf3161a)

- **ext4 on-disk format enhancements** -- block cache traits, persistent allocator structures
  [`66b3acd`](https://github.com/Dicklesworthstone/frankenfs/commit/66b3acd138268b5aca32bcddcdd7d77e0c1afd52)

- **Block/inode bitmap checksum parsing and serialization** in group descriptors
  [`b7a5cb8`](https://github.com/Dicklesworthstone/frankenfs/commit/b7a5cb835ec5a3d3f93c434c7fd39a2d0ae7b25b)

- **Checksum stamping functions** with hardened integer casts and round-trip tests
  [`481d08f`](https://github.com/Dicklesworthstone/frankenfs/commit/481d08fc3fa286134cbb7409d4ad4c67191e84b1),
  [`dfb02ac`](https://github.com/Dicklesworthstone/frankenfs/commit/dfb02ac163e6647bffe7aecc0ad589c608b510d5)

- **Ext4 metadata surface expansion** -- superblock metadata, JBD2 superblock, flex BG, and MMP parsing landed alongside indirect-block addressing support for the ext4 read/write path
  [`c3b1f26`](https://github.com/Dicklesworthstone/frankenfs/commit/c3b1f260875e89861b3e7d54951c6ec03a296a83),
  [`ad2280e`](https://github.com/Dicklesworthstone/frankenfs/commit/ad2280e7c6dbdc771c199736ce83b9179b04ecb5),
  [`a19f7d6`](https://github.com/Dicklesworthstone/frankenfs/commit/a19f7d6b5976cdc8b396870b619ee7adf86f3d03)

- **Feature-compatibility and metadata-layout corrections** -- casefold lookup, relaxed incompat acceptance, external-journal UUID pairing, kernel-compatible bitmap CRC32C handling, and ext4 xattr field layout fixes all tightened ext4 compatibility
  [`9e8acdd`](https://github.com/Dicklesworthstone/frankenfs/commit/9e8acdd1cb518f55205acd85b6cd48f710e775b7),
  [`23c47de`](https://github.com/Dicklesworthstone/frankenfs/commit/23c47de559003906257ffa4e3bf211ac89d84966),
  [`20d65f4`](https://github.com/Dicklesworthstone/frankenfs/commit/20d65f4f35c42e05d2d17a6babe1ad9452678eb1),
  [`7f4d6eb`](https://github.com/Dicklesworthstone/frankenfs/commit/7f4d6ebac3f86aed106bcb80cdfc7fc37d00ee31),
  [`1b08f04`](https://github.com/Dicklesworthstone/frankenfs/commit/1b08f046476665bafca1cdfecaac449d6411259f)

- **Fixture exact-assertion gates** -- group descriptor (bd-mtt5k), inode (bd-gvcm4), dir entries (bd-zj2c8), deleted dir entries (bd-ntp1c), xattr entries (bd-d0oa9), checksum-tail dir entries (bd-qvxi1), invalid dir fixture errors (bd-y2vq4), and malformed dir-tail rejection (bd-gbr6m) are now structurally pinned in `ffs-harness`
  [`cae51b5`](https://github.com/Dicklesworthstone/frankenfs/commit/cae51b58514f9d1d4a90d77db0788bf59832b9b7),
  [`f6617e8`](https://github.com/Dicklesworthstone/frankenfs/commit/f6617e88f25e31776a0bc3efc0c5c53d2247bcec),
  [`8ffd006`](https://github.com/Dicklesworthstone/frankenfs/commit/8ffd006c1392f1ab1a777428636c6c6c08be7413),
  [`cf6df70`](https://github.com/Dicklesworthstone/frankenfs/commit/cf6df7054bef254f5af4483e2e104e9a21045ca0),
  [`f694513`](https://github.com/Dicklesworthstone/frankenfs/commit/f69451390d6298710869d595ba0d373e08c0cd35)

- **ext4 xattr layout pinning** -- xattr header layout (bd-lr8e4) and xattr entry offsets (bd-ziboa) are locked against on-disk drift
  [`57755655`](https://github.com/Dicklesworthstone/frankenfs/commit/57755655c51c98fa9f924c2097a6be5a6874aeae),
  [`4c7daece`](https://github.com/Dicklesworthstone/frankenfs/commit/4c7daece1d72c250248197268427fbdea81b9910)

---

## On-Disk Parsing (btrfs)

Pure parsing of btrfs on-disk structures, also in `ffs-ondisk` and the `ffs-btrfs` crate.

- **btrfs superblock parsing** with `sys_chunk_array` and validation
  [`e6fa78e`](https://github.com/Dicklesworthstone/frankenfs/commit/e6fa78eda92c2696d3ac9daf187e0f25e8344380)

- **Logical-to-physical mapping** via `sys_chunk_array` for single-device images
  [`6ed1bf0`](https://github.com/Dicklesworthstone/frankenfs/commit/6ed1bf0e47155890e8da3b0453f3dededabdaea8)

- **Internal node parsing + header validation** for btrfs B-tree traversal
  [`1ae63e0`](https://github.com/Dicklesworthstone/frankenfs/commit/1ae63e0a144461fef443284635ae1e6f94933cc1)

- **Read-only tree-walk** with I/O-agnostic callback, cycle detection, depth bounds, and visit deduplication
  [`35598fe`](https://github.com/Dicklesworthstone/frankenfs/commit/35598fee2d2be09bd33e367eceb65124aa75b4ac)

- **btrfs open/validate pipeline** with tree-walk integration in `ffs-core`
  [`7d2c475`](https://github.com/Dicklesworthstone/frankenfs/commit/7d2c475981651b5504e47ff036efd3689be79da3)

- **CRC32C checksum verification** for btrfs metadata
  [`c24a2b7`](https://github.com/Dicklesworthstone/frankenfs/commit/c24a2b75eea31c1b10b4ce43bb469fc94f761a5f)

- **Comprehensive btrfs structure parsing** -- leaf items, chunk items, root items, device items
  [`a3a9606`](https://github.com/Dicklesworthstone/frankenfs/commit/a3a960689f0c8a5a05e17aee436dcdd6482563d1)

- **Cycle and duplicate-node detection** in btrfs tree walker
  [`da090fe`](https://github.com/Dicklesworthstone/frankenfs/commit/da090feab3923042d051ef05a5a96ad2d9477bfd)

- **Subvolume enumeration and multi-device RAID stripe resolution**
  [`bc67946`](https://github.com/Dicklesworthstone/frankenfs/commit/bc67946e9b829f4d8f3d040115fdb9448911ce9f)

- **Snapshot navigation, subvolume CLI, and snapshot diff**
  [`0258ba2`](https://github.com/Dicklesworthstone/frankenfs/commit/0258ba2b07a76d3d55c3c97ae2a89f8de9dbfc45)

- **RAID5/6 parity rotation fix** for data stripe mapping
  [`18bc6b0`](https://github.com/Dicklesworthstone/frankenfs/commit/18bc6b01b219c611f0b35e117adc3e70e0c77092)

- **COW tree mutation API** with tracing diagnostics and snapshot registry
  [`45c401c`](https://github.com/Dicklesworthstone/frankenfs/commit/45c401c61771237fc08f5f3aed4bf294066a2774)

- **Transaction model with MVCC integration** and S3-FIFO cache eviction
  [`b3c6af2`](https://github.com/Dicklesworthstone/frankenfs/commit/b3c6af2802150f90ca5965297dc7442080aded94)

- **Delayed-ref queue** with bounded flush and parity bookkeeping
  [`f446e3f`](https://github.com/Dicklesworthstone/frankenfs/commit/f446e3fb1a3f16ce6da36097bc4c722976719c98)

- **Read-write mount support** with COW tree and extent allocator
  [`c9c7388`](https://github.com/Dicklesworthstone/frankenfs/commit/c9c7388a3b8333d764a0760d7042149984b16667)

- **Backup superblock mirror repair** from primary
  [`025c3ec`](https://github.com/Dicklesworthstone/frankenfs/commit/025c3ec385ddbd14a3269cbf74a4b1edaa2513fa)

- **btrfs statfs free space** -- report accurate free space from extent allocator
  [`cda44ce`](https://github.com/Dicklesworthstone/frankenfs/commit/cda44cee826f4dbb73bf9fcf42a59b0ec3b776b2)

- **Fallocate data preservation** during overlap and inline-to-regular extent transition
  [`b57e7aa`](https://github.com/Dicklesworthstone/frankenfs/commit/b57e7aaf010f3840490b0a6c85ad4cca9d14fb19)

- **Structured fallocate tracing** and comprehensive test coverage for btrfs
  [`9d3e88b`](https://github.com/Dicklesworthstone/frankenfs/commit/9d3e88b7d116134f2e8a8255cfa2d4475a53cff1),
  [`6fc1e5c`](https://github.com/Dicklesworthstone/frankenfs/commit/6fc1e5cfc78fbbc4cca2ff89eca039c00313f6ae)

- **btrfs metadata coverage expansion** -- subvolume object IDs/root dir IDs, chunk/device tree walking, `ram_bytes` on extent items, and multi-device RAID stripe resolution all became first-class in the parser + adapter stack
  [`ad2280e`](https://github.com/Dicklesworthstone/frankenfs/commit/ad2280e7c6dbdc771c199736ce83b9179b04ecb5),
  [`083f790`](https://github.com/Dicklesworthstone/frankenfs/commit/083f79043e4a64f743ddd0d2c9058e55d4bb4f18),
  [`3b3b5e8`](https://github.com/Dicklesworthstone/frankenfs/commit/3b3b5e8e8caa9955dd05869c39cf85c92c79d5fe),
  [`af1dfed`](https://github.com/Dicklesworthstone/frankenfs/commit/af1dfed592fc668c04b67b052658cd57310eb54b),
  [`207ee11`](https://github.com/Dicklesworthstone/frankenfs/commit/207ee11a1498b974e51cdce480258f907fb2a2f4)

- **btrfs fixture slot pinning** -- root tree (bd-1siwi), fs tree (bd-b3p2e), leaf (bd-08qba), sys_chunk fields (bd-j603q), devitem tail (bd-qiv6d), devitem provenance (bd-9x0kp) and tree leaf coverage (bd-fzs33) all now structurally assert fixture contents
  [`28b6b8e`](https://github.com/Dicklesworthstone/frankenfs/commit/28b6b8ef0c09ee7f68d6570e0d73bcd07fdd7b1a),
  [`26ea8ef`](https://github.com/Dicklesworthstone/frankenfs/commit/26ea8ef6ad369b0bc0694b591725a09b3a099b07),
  [`6e904f3`](https://github.com/Dicklesworthstone/frankenfs/commit/6e904f39587dc4ad0c08ac3dd91bf33d29774bbd),
  [`d0fb9a4`](https://github.com/Dicklesworthstone/frankenfs/commit/d0fb9a4d3722de69d01f3ddbf19768b16cf2e2c7),
  [`102b3a0`](https://github.com/Dicklesworthstone/frankenfs/commit/102b3a0285cf50d395609de4a8c10380e3c7e201),
  [`5f00305`](https://github.com/Dicklesworthstone/frankenfs/commit/5f00305b40946dc4e389d238500e6ef5da29ffe1)

- **btrfs chunk validator coverage** -- bootstrap root mappings asserted, chunk root mapping gaps covered, log root chunk coverage required, and any uncovered chunk fixture mapping is now rejected
  [`7124181`](https://github.com/Dicklesworthstone/frankenfs/commit/71241815ca18b8a36ccbc02031e4cbcecd6b2ee0),
  [`642992a`](https://github.com/Dicklesworthstone/frankenfs/commit/642992a8dee7d6bd685c0587d542d43dbf338dbe),
  [`ccbf02a`](https://github.com/Dicklesworthstone/frankenfs/commit/ccbf02a8dcee7fa8104398dfa1b9f1807070a4be),
  [`cf25c47`](https://github.com/Dicklesworthstone/frankenfs/commit/cf25c477c769586f5f43ba67e06eb0df7fa9995e)

- **btrfs send/receive parser hardening** -- magic, version, per-command CRC32C, required `END` terminator, 22 command types, attribute TLV encoding, missing-`END` rejection, and unknown-command fallback to `Unspec` preserving attributes. Differential validation against upstream `btrfs receive --dump` on a CRC-valid synthetic stream

---

## FUSE Mount and VFS Layer

The `ffs-fuse` adapter translates kernel FUSE protocol into `FsOps` calls on `ffs-core::OpenFs`. The `ffs-core` crate orchestrates format detection, validation, and all subsystem integration.

- **FsOps VFS trait** with `InodeAttr`, `DirEntry`, `FileType` -- the abstract interface all FUSE operations dispatch through
  [`535d019`](https://github.com/Dicklesworthstone/frankenfs/commit/535d0192b9b78951832bc2ac2c91adc80ba0e14a)

- **OpenFs API** with detect-parse-validate pipeline for both ext4 and btrfs
  [`d40f0fa`](https://github.com/Dicklesworthstone/frankenfs/commit/d40f0fa8bf8904bada753b47bb60c3b61513e000),
  [`0f368b7`](https://github.com/Dicklesworthstone/frankenfs/commit/0f368b7ce9ad7abd823b192d7eb575230106520d)

- **Device-based inode read pipeline**, extent mapping, readdir, name lookup, path resolution, file read, and symlink reading
  [`b1bfd2a`](https://github.com/Dicklesworthstone/frankenfs/commit/b1bfd2aca27f732ba2f76a0a74d846aceaad21e8),
  [`b3343f8`](https://github.com/Dicklesworthstone/frankenfs/commit/b3343f8c1af04a0f0b389aee4e0715e52e0e3b16),
  [`be49b64`](https://github.com/Dicklesworthstone/frankenfs/commit/be49b64365d390a0a4ef7c5d96eb502425095b95),
  [`f7a6e42`](https://github.com/Dicklesworthstone/frankenfs/commit/f7a6e42ac167770f7c77294ee985026236b44d84),
  [`0269d26`](https://github.com/Dicklesworthstone/frankenfs/commit/0269d26fedff201a69036b5ac5290b2af8d9bac2),
  [`8025164`](https://github.com/Dicklesworthstone/frankenfs/commit/8025164fcee105c7df3cdfdd53d8fa0e08284e3c)

- **Real FUSE adapter** via the `fuser` crate with read-only ops (lookup, getattr, read, readdir, readlink)
  [`f6b2ca8`](https://github.com/Dicklesworthstone/frankenfs/commit/f6b2ca8af0edcf672d58f2db5cfadbb4e354a45e),
  [`decc239`](https://github.com/Dicklesworthstone/frankenfs/commit/decc239e05cdd7fd2df37677d0eb2e3162ac4dc3)

- **Xattr VFS integration** -- `listxattr`/`getxattr` in FsOps and FUSE read-only xattr operations
  [`010dd43`](https://github.com/Dicklesworthstone/frankenfs/commit/010dd4393a72cbef1f45f130a7ab9a04c143280e),
  [`b61dc73`](https://github.com/Dicklesworthstone/frankenfs/commit/b61dc7311f2df34f55e95576636659217e9f3777)

- **Device numbers for block/char inodes**
  [`8074e16`](https://github.com/Dicklesworthstone/frankenfs/commit/8074e16dc3263719b24f1eacaadad56feb4b09ce)

- **Flush, fsync, fsyncdir FUSE handlers**
  [`892691e`](https://github.com/Dicklesworthstone/frankenfs/commit/892691e4d185db00cfa3ca7288cc7adbfee07cee)

- **FUSE write operations** -- create, mkdir, unlink, rmdir, rename, write, setattr, link, symlink
  [`d51a0c1`](https://github.com/Dicklesworthstone/frankenfs/commit/d51a0c1593f852b1938cbd677f7e651e8dc195c2),
  [`117b530`](https://github.com/Dicklesworthstone/frankenfs/commit/117b530ca52e97ba428e38c8b0d1887bad7d5df4)

- **Degradation FSM** with hysteresis and FUSE backpressure shedding; lock-free `AtomicU8` cache for FSM level reads
  [`b7704fc`](https://github.com/Dicklesworthstone/frankenfs/commit/b7704fc506944446ab1a6aec296a513cb1295845),
  [`a1996f0`](https://github.com/Dicklesworthstone/frankenfs/commit/a1996f06fcd9175a4d329c439493e1a3904f7c1a)

- **Thread-per-core dispatch routing** and FUSE metrics
  [`b2e24e7`](https://github.com/Dicklesworthstone/frankenfs/commit/b2e24e78c3faa9af1640d5b177155f71b9768497)

- **Backpressure throttle tier**, FUSE queue tuning, and mount timeout
  [`21c8652`](https://github.com/Dicklesworthstone/frankenfs/commit/21c8652c73774014d5c8d57cbbf49233cce7d0d0)

- **Backpressure shedding for fsync/fsyncdir** and preflight FCW extraction
  [`457613a`](https://github.com/Dicklesworthstone/frankenfs/commit/457613ab4ece4a00860392ad232c3685662b2a8f)

- **VFS link/symlink/fallocate/statfs** and readahead predictor
  [`9e58f4e`](https://github.com/Dicklesworthstone/frankenfs/commit/9e58f4eadf81ca11f7ba1564de0857001b02a4ed)

- **RequestScope plumbing** through all FsOps methods for MVCC read/write scoping
  [`58adb58`](https://github.com/Dicklesworthstone/frankenfs/commit/58adb580dc45d624a93e8b23ea6da1b79c23fe59)

- **Scope-free convenience methods** for `read_group_desc`, `read_inode`, `read_inode_attr`, `read_dir`, and `lookup_name`
  [`c6915f4`](https://github.com/Dicklesworthstone/frankenfs/commit/c6915f4a82cd2b623dc0094254859c3403d14bd9),
  [`efb7af1`](https://github.com/Dicklesworthstone/frankenfs/commit/efb7af18b2f7b11c5e8bbd687b4e53e6d3918d6a)

- **TransactionBlockAdapter** for MVCC-safe writes and directory entry handling
  [`cf39006`](https://github.com/Dicklesworthstone/frankenfs/commit/cf39006df0dfccf8c8e07cbe9aef7e698bd758b0)

- **Mount validation hardening** and stale readahead fix after writes
  [`8938b01`](https://github.com/Dicklesworthstone/frankenfs/commit/8938b0126555130a2206a1e6ff78525f4f50ee50)

- **Link/symlink/setattr API exposure** and ARC cache dirty tracking fix
  [`a16a009`](https://github.com/Dicklesworthstone/frankenfs/commit/a16a009f6c3ff9852b2b1ce53a4345babc73f0e9)

- **Ioctl and inspection-surface expansion** -- FIEMAP support, `EXT4_IOC_GETFLAGS/SETFLAGS`, btrfs FIEMAP, btrfs `DIR_ITEM` inspection, and stricter ioctl/path validation all landed in the same wave
  [`0f3bfa5`](https://github.com/Dicklesworthstone/frankenfs/commit/0f3bfa56e9cc2f11f866329afbdc8515419a7105),
  [`fafa0fa`](https://github.com/Dicklesworthstone/frankenfs/commit/fafa0fa31f76c7e8b714eb33b78b4994e974cdda),
  [`d546f57`](https://github.com/Dicklesworthstone/frankenfs/commit/d546f579cd3cd377649ac1a6a32ac53ef8b9b157),
  [`9bd4eb0`](https://github.com/Dicklesworthstone/frankenfs/commit/9bd4eb083a5951fc4a33800f25948e757165f2db),
  [`4bcc449`](https://github.com/Dicklesworthstone/frankenfs/commit/4bcc4496645d4ecc48bed1b7092c1686cb651c8f),
  [`284797e`](https://github.com/Dicklesworthstone/frankenfs/commit/284797ea0afea25d2d3396de33acee3406539ddf)

- **RequestScope and runtime hardening** -- ext4 mutators now run under active request scopes, scope-commit ordering was fixed after create, `fuser` ABI 7-31 was enabled, `forget` landed, and per-core/scope-failure metrics became more trustworthy
  [`16a309b`](https://github.com/Dicklesworthstone/frankenfs/commit/16a309bd520084bd7b2e00ce2f018fcd428030b4),
  [`f729ea8`](https://github.com/Dicklesworthstone/frankenfs/commit/f729ea8606dcdb4baa8fcad9ab860685d566de65),
  [`e9e89c0`](https://github.com/Dicklesworthstone/frankenfs/commit/e9e89c04bc2a4d9aea365c895f39b87da15d5d98),
  [`27a3207`](https://github.com/Dicklesworthstone/frankenfs/commit/27a3207e4c5959a95a3ca20affb154e6bbd59213),
  [`954ee2a`](https://github.com/Dicklesworthstone/frankenfs/commit/954ee2a654ef20c6ce5ec67835c6e88977ef7e32)

- **vendored fuser 7.40 upgrade** -- `vendor/fuser` is now pinned at ABI 7.40 (via `[patch.crates-io]`) so unrestricted ioctls reach the real FrankenFS userspace handlers. Used by FIEMAP, EXT4_IOC_* parity tests, and the new ioctl coverage below
  [`3aaebc8`](https://github.com/Dicklesworthstone/frankenfs/commit/3aaebc8a0a207124b315d1e732ee50939fd245aa)

- **New VFS ioctls** -- `FS_IOC_GETFSSYSFSPATH` (bd-04xv6), ext4 `getstate` (bd-xpg8e), expanded `Ext4FsOps` inode ioctl validation (bd-hx0dc). Btrfs IOCTL structs now encode/decode in native byte order to match kernel behavior
  [`fae0008`](https://github.com/Dicklesworthstone/frankenfs/commit/fae0008b2a886ed229a7d8022861f3e16aa727ba),
  [`9a2f1f5`](https://github.com/Dicklesworthstone/frankenfs/commit/9a2f1f5b17d9237cb1a4dfdec7e56501910adcad),
  [`bcc6a44`](https://github.com/Dicklesworthstone/frankenfs/commit/bcc6a4441ed54daf2bf7c3413da50ce0cd6fd167),
  [`a95fb71`](https://github.com/Dicklesworthstone/frankenfs/commit/a95fb7198fa456dc7f818f552dd7e0e18f16889e)

- **ioctl-dispatch fuzz expansion** -- 7 additional VFS ioctls fuzzed (bd-51a78), full ioctl seed corpus regenerated for all command types, ioctl trace drop counter saturated (bd-itmet)
  [`c7d5143`](https://github.com/Dicklesworthstone/frankenfs/commit/c7d5143d631a2540666d7bd2bd02ceb14c84f5ae),
  [`24da050`](https://github.com/Dicklesworthstone/frankenfs/commit/24da050fd52be3f4cadb8ec65487c9dab7e9c76d),
  [`cdc58c0`](https://github.com/Dicklesworthstone/frankenfs/commit/cdc58c00c1d7e68451533e3ba4a144900a43761d)

- **POSIX ACL surface (mounted-path)** -- `system.posix_acl_access` and `system.posix_acl_default` mounted-path list/get behavior covered in the FUSE E2E suite (bd-yf1el), plus missing-default `ENODATA` absence contract on regular files. POSIX ACL namespaces now differentially validated against `debugfs` via `crates/ffs-harness/tests/kernel_reference.rs`
  [`7d126c3`](https://github.com/Dicklesworthstone/frankenfs/commit/7d126c33912282e31caccfc3098ca152f4ec6998)

- **xattr CREATE/REPLACE error semantics** -- mounted-path `XATTR_CREATE` → `EEXIST` and `XATTR_REPLACE` → `ENODATA` failures verified; exact public `ENODATA` for missing `getxattr` / `removexattr` on `user.*`, empty `listxattr` length-0 probe, and exact-fit zero-length success on mounted files with no visible xattrs

---

## Block I/O and ARC Cache

The `ffs-block` crate provides the `BlockDevice` trait, Adaptive Replacement Cache (ARC), aligned buffers, and write-back coordination.

- **ARC eviction logic fix** and initial tests
  [`e52aa8b`](https://github.com/Dicklesworthstone/frankenfs/commit/e52aa8b60de1c30159edc085a5c43aa9e2215493)

- **CacheMetrics instrumentation surface** for observability
  [`8fead6b`](https://github.com/Dicklesworthstone/frankenfs/commit/8fead6b4364e34cc57cdaf8f42f00377e11f3a01)

- **Cache concurrency design** and TOCTOU race fix
  [`8b91122`](https://github.com/Dicklesworthstone/frankenfs/commit/8b91122f47dc7381ce92f938a548a3ebe16a5c76)

- **Criterion benchmarks** for ARC cache hot paths
  [`3fb2fc7`](https://github.com/Dicklesworthstone/frankenfs/commit/3fb2fc7268e66bfcfa10a98d46f1eef2880aa835)

- **Dirty block tracking and flush accounting** for write-back mode
  [`9ec9dab`](https://github.com/Dicklesworthstone/frankenfs/commit/9ec9dabce3d3c2986aff6d7f9370a973411a77fa)

- **MVCC-aware transactional dirty tracking** and flush lifecycle
  [`6d5d95e`](https://github.com/Dicklesworthstone/frankenfs/commit/6d5d95e4a011b26938ab2cb1c662b4b75a2e08c9)

- **ARC cache memory pressure hooks** for graceful degradation
  [`ff1663c`](https://github.com/Dicklesworthstone/frankenfs/commit/ff1663c40e95c4d0491f10652df8b4f09faf4d90)

- **Aligned I/O and vectored block ops** (`VectoredBlockDevice` trait) for O_DIRECT support
  [`9e58f4e`](https://github.com/Dicklesworthstone/frankenfs/commit/9e58f4eadf81ca11f7ba1564de0857001b02a4ed)

- **Pluggable IoEngine trait** for kernel-bypass I/O (io_uring future support)
  [`696ef28`](https://github.com/Dicklesworthstone/frankenfs/commit/696ef28004584a80dcc50307624208f499455dcd)

- **S3-FIFO cache panics replaced** with self-healing invariant recovery
  [`8967c05`](https://github.com/Dicklesworthstone/frankenfs/commit/8967c05195d8b9bc3027baab96f7e8f4beec64e3)

- **Dirty-block eviction panics replaced** with graceful skip-and-requeue
  [`d68552a`](https://github.com/Dicklesworthstone/frankenfs/commit/d68552a5608e47a38638a136392d4e036bc75082)

- **Dirty block eviction protection** during cache pressure
  [`1e759e9`](https://github.com/Dicklesworthstone/frankenfs/commit/1e759e9c1596c39244254543629c825d955d04c3)

- **Sequence-aware dirty tracking** and repair refactoring
  [`e3b1cc5`](https://github.com/Dicklesworthstone/frankenfs/commit/e3b1cc59d71f38c8052121a0161f9079a9ac6f54)

- **Don't restore dirty state** when repair notification fails after successful flush
  [`2fb7834`](https://github.com/Dicklesworthstone/frankenfs/commit/2fb78340ce693b75b4b54895ace3de9761b6ef33)

- **I/O metric semantics alignment** -- `IoEngine` submission counters now reflect real submission behavior rather than optimistic dispatch intent, improving block-layer observability
  [`3f67e30`](https://github.com/Dicklesworthstone/frankenfs/commit/3f67e302bc54338911d1383dee4c9a8709faae5e)

---

## MVCC Concurrency Engine

The `ffs-mvcc` crate provides block-level Multi-Version Concurrency Control with snapshot isolation, version chains, sharded stores, and WAL persistence.

- **MVCC-aware block device wrapper** with staged writes and snapshot isolation
  [`ddcb0ea`](https://github.com/Dicklesworthstone/frankenfs/commit/ddcb0ea2dc8be2cf324b37646e4dcc876290a095)

- **Deterministic MVCC concurrency invariant tests** using `LabRuntime`
  [`ee24769`](https://github.com/Dicklesworthstone/frankenfs/commit/ee247698148de9409eb032a9d3901fa5386c441e)

- **Watermark API + active snapshot tracking** for version GC
  [`9252739`](https://github.com/Dicklesworthstone/frankenfs/commit/9252739bce6ae7bbccde524c06ac93b1f51c6572)

- **Serializable Snapshot Isolation (SSI)** with rw-antidependency detection
  [`3211b35`](https://github.com/Dicklesworthstone/frankenfs/commit/3211b35321d1e3c93cc6cf09c6f3f0a2db4b3a5f),
  [`66e28b1`](https://github.com/Dicklesworthstone/frankenfs/commit/66e28b1cb2f6b26db631d3bb33ddf07b958b06f6)

- **WAL persistence layer** with crash recovery and replay
  [`c4a3764`](https://github.com/Dicklesworthstone/frankenfs/commit/c4a37647e277898a98d8945ababd13e433a50e4e)

- **Sharded concurrent MVCC store** (`ShardedMvccStore`) with sorted lock acquisition for deadlock prevention
  [`d9c2568`](https://github.com/Dicklesworthstone/frankenfs/commit/d9c25689cdba7c2ae2b2d4513e712dd4e7b72784)

- **MVCC store integration** into `OpenFs` with full transaction API
  [`f0dc595`](https://github.com/Dicklesworthstone/frankenfs/commit/f0dc595dd8c2b739e76fdfb7b7f78dd0f11def2a)

- **Version chain backpressure** with chain-cap enforcement
  [`d51a0c1`](https://github.com/Dicklesworthstone/frankenfs/commit/d51a0c1593f852b1938cbd677f7e651e8dc195c2),
  [`1a6f2ce`](https://github.com/Dicklesworthstone/frankenfs/commit/1a6f2cef817df9ae4b39742e1a59cea44a0effb0)

- **Zstd/Brotli transparent compression** for version chain entries
  [`ce6cb61`](https://github.com/Dicklesworthstone/frankenfs/commit/ce6cb6121d6afa1e4816ca736405770f497178c8)

- **RCU primitives** for lock-free metadata reads
  [`9de8036`](https://github.com/Dicklesworthstone/frankenfs/commit/9de80367844ef82b6345671c5a84c255cab65263)

- **Evidence ledger integration** and budget-aware GC
  [`2a9c863`](https://github.com/Dicklesworthstone/frankenfs/commit/2a9c8636ba15ad6f34d3459cbe51eaa88e00cc0d)

- **FCW commit split** into preflight+apply phases; RCU write-lock gap fix
  [`7a17036`](https://github.com/Dicklesworthstone/frankenfs/commit/7a1703654bcd5228f95f0142bae4d071fbcce767)

- **Snapshot backpressure semantics** restoration and clippy cleanup
  [`1a1e129`](https://github.com/Dicklesworthstone/frankenfs/commit/1a1e129637d10e0dabddf11aea3c43c5c86eb55f)

- **Epoch advancement consolidation** under single lock; field privacy and WAL rollback on write failure
  [`9132ceb`](https://github.com/Dicklesworthstone/frankenfs/commit/9132ceb27c29f775c80bd3e6d90fc8fad9c780df),
  [`9a34f35`](https://github.com/Dicklesworthstone/frankenfs/commit/9a34f355e030456bed4eb8df5306480d66c03117)

- **TOCTOU race fix** in `prune_safe` and RAID stripe arithmetic hardening
  [`020ac96`](https://github.com/Dicklesworthstone/frankenfs/commit/020ac96746847b5fb4059605a44a16b6d36f0d4b)

- **Contention metrics on chain-backpressure abort**
  [`f9386d7`](https://github.com/Dicklesworthstone/frankenfs/commit/f9386d79213435b62d90a8f04bcd283996ec6c63)

- **Zero-division guard** in `inode_index_in_group`
  [`40619b0`](https://github.com/Dicklesworthstone/frankenfs/commit/40619b0b21ba653076cedf07d0072a5ba6e888fc)

- **Bounds-check** on `resolve_data_with` index and block address overflow prevention
  [`d8e561a`](https://github.com/Dicklesworthstone/frankenfs/commit/d8e561a88d00bd128bc700588d94d2efb806b3d0)

- **`TxnAbortReason` re-export** as public for downstream crates
  [`8126e90`](https://github.com/Dicklesworthstone/frankenfs/commit/8126e906b76a90d1bd6718d4ba598008de3838d5)

- **MVCC durability tightening** -- sharding continued to expand, committed block versions now flush on `fsync`/destroy, snapshot capture was fixed, and `ext4_fallocate` no longer bypasses MVCC bookkeeping
  [`81ae68b`](https://github.com/Dicklesworthstone/frankenfs/commit/81ae68b602d72eb73c7b07492232bd7ecb8df24a),
  [`11c75dd`](https://github.com/Dicklesworthstone/frankenfs/commit/11c75dd55c25fb2fa3897f9f6809bc14f52f02a9),
  [`ff6edef`](https://github.com/Dicklesworthstone/frankenfs/commit/ff6edef314ae3c9e27853cd2c3bdcae075ab6454),
  [`27a3207`](https://github.com/Dicklesworthstone/frankenfs/commit/27a3207e4c5959a95a3ca20affb154e6bbd59213)

---

## Safe-Merge Conflict Resolution

Merge-proof system allowing non-conflicting concurrent writes to the same block, with adaptive policy selection.

- **Safe-merge taxonomy classifier** with pairwise commutativity tests
  [`c3c7c9c`](https://github.com/Dicklesworthstone/frankenfs/commit/c3c7c9c90943f84a38b653456594138fd542b162)

- **Merge-proof resolution** for non-conflicting concurrent writes (AppendOnly, IndependentKeys, NonOverlappingExtents, TimestampOnlyInode, DisjointBlocks)
  [`3ed57bc`](https://github.com/Dicklesworthstone/frankenfs/commit/3ed57bcd4268118caeb9b5a1b979886a42cf92c0)

- **100-writer append-only merge proof stress test** with structured progress
  [`b62f97d`](https://github.com/Dicklesworthstone/frankenfs/commit/b62f97df72c9ca3908fe785409de77c5c0ae7b76)

- **Adaptive conflict policy** with expected-loss selection between Strict FCW and SafeMerge
  [`3d3d5cc`](https://github.com/Dicklesworthstone/frankenfs/commit/3d3d5ccd29d0b32e12d65fd7e508f6c452bfa665)

- **Contention evidence types**, emit helpers, and CLI preset
  [`522f441`](https://github.com/Dicklesworthstone/frankenfs/commit/522f441d8887f0a1f11990e3a1d48f97a0041a06)

- **120-writer verification gate** stress test proving safe-merge under high contention (SafeMerge 9.5x lower expected loss than Strict, zero corruption)
  [`0a704cb`](https://github.com/Dicklesworthstone/frankenfs/commit/0a704cbadf0ba24ef8dba6e7e2a0efdc636511c8)

- **Policy-switch delta calculation fix** and collection of all merge variants
  [`a13818d`](https://github.com/Dicklesworthstone/frankenfs/commit/a13818dc44b187ce882143609f3148d6d36bc017)

- **`InodeMetadataMergeFootprint`** introduction and merge-classifier extraction
  [`1e415a3`](https://github.com/Dicklesworthstone/frankenfs/commit/1e415a360da3f147332db9fb23037301ff4ed186),
  [`e719cc4`](https://github.com/Dicklesworthstone/frankenfs/commit/e719cc47fdacc6660161ce715ebc2ddf8faeae40)

- **Merge preflight hardening** -- staged block-range validation now rejects malformed merge/write-set combinations before they can become visible
  [`4301dfa`](https://github.com/Dicklesworthstone/frankenfs/commit/4301dfac56f087663dafcac2f452267069421657)

---

## Self-Healing Repair Pipeline

RaptorQ fountain-coded repair with Bayesian overhead optimization, scrub
pipeline, adaptive refresh, and multi-host coordination in `ffs-repair`. In
this window, mounted automatic repair shipped behind an explicit ledger flag,
the read-write mounted repair writeback serializer landed, and the evidence
ledger settled at 23 event types (`EvidenceEventType`).

- **FrankenSQLite RaptorQ approach** extracted for filesystem repair design
  [`fdd193e`](https://github.com/Dicklesworthstone/frankenfs/commit/fdd193e5a2f379dc920d7339d8903e9548d37e39)

- **Scrub pipeline** for corruption detection
  [`a743f6a`](https://github.com/Dicklesworthstone/frankenfs/commit/a743f6a914224e2b436959351e5eca8ba30027aa)

- **Repair symbol format** and storage strategy
  [`1a8605b`](https://github.com/Dicklesworthstone/frankenfs/commit/1a8605b02f1cf97a778a63a3c8743b2e80aa83bd)

- **RaptorQ encode/decode workflow** (RFC 6330 fountain codes)
  [`ce955c3`](https://github.com/Dicklesworthstone/frankenfs/commit/ce955c3fc1976bc1f195ab4ee78881fc82021276)

- **`RepairPolicy` + `DurabilityAutopilot`** with Bayesian Beta posterior for overhead optimization
  [`f4c3073`](https://github.com/Dicklesworthstone/frankenfs/commit/f4c3073b0f9be7d12283c5a03342ecfd7f276a59)

- **Format-aware scrub validators** and error taxonomy refinement
  [`47d6e29`](https://github.com/Dicklesworthstone/frankenfs/commit/47d6e29cc89e32b5b8a7e8643d9bc20fada1b73d)

- **Background scrub daemon** with backpressure-aware scheduling
  [`65296a3`](https://github.com/Dicklesworthstone/frankenfs/commit/65296a3c5bf76e639f53285fd2fa4198d1b5b6c4),
  [`b0c9349`](https://github.com/Dicklesworthstone/frankenfs/commit/b0c9349dfe1eae491a72100de81ab42da872f3e7)

- **Adaptive symbol-refresh protocol** and Bayesian overhead autopilot
  [`62d688d`](https://github.com/Dicklesworthstone/frankenfs/commit/62d688d8023efd35de9d04e6d4654354a8dd1451)

- **Recovery and storage repair infrastructure**
  [`7a0d1fd`](https://github.com/Dicklesworthstone/frankenfs/commit/7a0d1fd5ff78cc578946448cd4f41d005bfefbc4),
  [`5bd3446`](https://github.com/Dicklesworthstone/frankenfs/commit/5bd344615fdc65ee1c6ff49579150053e1d99ad3)

- **Repair flush lifecycle** and budget-aware flush daemon
  [`fd195b8`](https://github.com/Dicklesworthstone/frankenfs/commit/fd195b852ed8161ce0650d6bc642cdd5e2966598)

- **Self-healing demo module** with adoption-wedge example
  [`e101bd9`](https://github.com/Dicklesworthstone/frankenfs/commit/e101bd96d6cb54836e438c740e1be53ab228fd49),
  [`00ea3f7`](https://github.com/Dicklesworthstone/frankenfs/commit/00ea3f750d401ed5ce4305d523ec5189d13cf3bb)

- **Local Reconstruction Codes (LRC)** for distributed repair
  [`6a64689`](https://github.com/Dicklesworthstone/frankenfs/commit/6a64689e477cb6ebd48fa73e3f5ce41c4b4b9037)

- **Proof of Retrievability (PoR)** for cryptographic durability audit
  [`020da2c`](https://github.com/Dicklesworthstone/frankenfs/commit/020da2cdd86205eee12033d4288f869647d80237)

- **Expected-loss model** for adaptive refresh trigger policies (age-only vs block-count vs hybrid)
  [`8a3c614`](https://github.com/Dicklesworthstone/frankenfs/commit/8a3c614f0374dc5d6b15794418ac2366122e3f47)

- **`RefreshLossModel` edge case hardening** for zero blocks, zero writes, degenerate thresholds
  [`46c0119`](https://github.com/Dicklesworthstone/frankenfs/commit/46c0119368d4bbc7e0e837c307775907c61412d1)

- **Hybrid refresh policy** combining age-timeout and block-count triggers
  [`6b383e6`](https://github.com/Dicklesworthstone/frankenfs/commit/6b383e63d26c9e3608895e84837b0422c6246d61)

- **Stale-window SLO instrumentation** with percentile-based breach detection (p95 83.3% reduction under heavy writes)
  [`f32ce08`](https://github.com/Dicklesworthstone/frankenfs/commit/f32ce0813c3b1fa81e5930f8e0ab93237dea875e)

- **Multi-host repair ownership protocol** with optimistic lease-based coordination
  [`d5fde69`](https://github.com/Dicklesworthstone/frankenfs/commit/d5fde691e643b9ace8dbf9435bbae1a28375257c)

- **Symbol exchange transport** and repair pipeline enhancement
  [`56a4b6d`](https://github.com/Dicklesworthstone/frankenfs/commit/56a4b6d788327e2733d78ec49371ec1b6552253a)

- **Adaptive symbol refresh** and xfstests conformance expansion
  [`14b1ec3`](https://github.com/Dicklesworthstone/frankenfs/commit/14b1ec33e2c3a42dcd8f508db12dbc7fc8b6a6df)

- **RaptorQ block-level recovery** wired into btrfs `fsck --repair` path
  [`ef72e83`](https://github.com/Dicklesworthstone/frankenfs/commit/ef72e83e1276ed7d272f130be0a250d1b48c36e0)

- **Evidence preset validation** and repair exchange refinement
  [`5965c04`](https://github.com/Dicklesworthstone/frankenfs/commit/5965c048336c83f7e9286051df3d2e091073a09d)

- **Repair robustness improvements** -- decode paths now fail explicitly instead of silently falling back, exchange completion shuts down TCP streams cleanly, and PoR challenge generation is cheaper for full-block cases
  [`5306287`](https://github.com/Dicklesworthstone/frankenfs/commit/5306287b9227dedb031665fe7648562dc9aacf3c),
  [`77229d4`](https://github.com/Dicklesworthstone/frankenfs/commit/77229d4fa4c65debf6a2c24946be0824ce531001),
  [`ffb921b`](https://github.com/Dicklesworthstone/frankenfs/commit/ffb921bf73a21d52f4b9a92a270a6cb2f860338e)

- **Mounted automatic repair** -- `ffs mount --background-repair --background-scrub-ledger <jsonl>` enables real block recovery + repair-symbol refresh after writable backing-image access is verified. Read-only mounts use direct backing-image authority; read-write mounts route recovered source blocks through the mounted MVCC request-scope serializer so repair writes and client writes share the same conflict-resolution boundary
  [`b75f47a`](https://github.com/Dicklesworthstone/frankenfs/commit/b75f47a3ef69c1e87bc974c9cc46c9cd02118417),
  [`fb50511`](https://github.com/Dicklesworthstone/frankenfs/commit/fb505115b47b700c8ec073fb49668ad4fd5f3914)

- **Repair writeback serialization contract** -- `docs/repair-writeback-serialization-contract.json` (57 KB) plus `docs/design-repair-writeback-serialization.md` formalize the state-machine, lease, MVCC epoch, fsync/fsyncdir, stale-symbol, cancellation, failure, route, stale-snapshot rejection, and writeback-cache-disabled proofs. Validated end-to-end by `./scripts/e2e/ffs_repair_writeback_route_e2e.sh`; the `repair.rw.writeback` release-gate claim depends on `repair_writeback_serialization_report.json` and `repair_writeback_route_artifact.json`
  [`e996265`](https://github.com/Dicklesworthstone/frankenfs/commit/e996265f1a2c4cf9648a45dca0a2f793d63e566d),
  [`36e6a98`](https://github.com/Dicklesworthstone/frankenfs/commit/36e6a98cfb941431a8e8e26a9f20c97eed55c583),
  [`65b75b0`](https://github.com/Dicklesworthstone/frankenfs/commit/65b75b0c5b8de968ea1247ee6a9bb787971c6270)

- **Repair confidence mutation safety** -- `docs/repair-confidence-mutation-safety.json` (31 KB) defines a matrix of safe / unsafe repair mutations and pairs each scenario with a confidence threshold, decoder-stat guard, and ledger contract. `bd-jv2vd` adds a repair confidence report snapshot
  [`c8ad3cf`](https://github.com/Dicklesworthstone/frankenfs/commit/c8ad3cf8be6d0fa16b5969911c1bcdc30fcf76d7)

- **Repair decision metamorphic tests** (`bd-rchk0.187`) -- the policy-mode decision (Eager / Lazy / Adaptive / Hybrid) now has metamorphic-relation coverage so refresh-policy switches under workload-shape perturbations cannot drift silently
  [`beda432`](https://github.com/Dicklesworthstone/frankenfs/commit/beda43203fa2776be46288b1b339e675c049d954)

- **Read-write background-repair gate schema** -- pinning the JSON of every report consumed by mounted repair lanes (background gate, mounted repair policy JSON, mounted repair boundary JSON, repair corpus report, repair confidence report)
  [`8e3cec7`](https://github.com/Dicklesworthstone/frankenfs/commit/8e3cec7eaa0ef2079d0bd326dc537a320963f3bc),
  [`4648ec3`](https://github.com/Dicklesworthstone/frankenfs/commit/4648ec32497491947de5440d6590185c3393e0a0),
  [`4adfe83`](https://github.com/Dicklesworthstone/frankenfs/commit/4adfe8364f599fb02af927572f8aacb6e980e8bb)

---

## Writeback-Cache Epoch Barriers

Per-inode epoch state machine (`staged >= visible >= durable`) for FUSE
writeback-cache enablement, with crash consistency proofs in `ffs-core`. In
this window the kernel `writeback_cache` option moved from "design only" to
"explicit-opt-in, evidence-gated, default-off" with a complete operator
contract.

- **Writeback-cache epoch barrier** with per-inode epoch tracking (staged/visible/durable counters)
  [`541e178`](https://github.com/Dicklesworthstone/frankenfs/commit/541e178fb0785220b70e6949ff479b7f9908d7e8)

- **Infallible `commit_epoch`** -- removed `EpochNotStaged` error
  [`5e11da6`](https://github.com/Dicklesworthstone/frankenfs/commit/5e11da667cc750d9089004ab969a8e89a3dc37ef)

- **12-scenario crash consistency matrix** for writeback epoch barrier
  [`e8bd18d`](https://github.com/Dicklesworthstone/frankenfs/commit/e8bd18d5ec7fe17670d72f0183b8216a264c358f)

- **Untracked inodes treated as visible** in epoch barrier; recovery hardening
  [`389e17a`](https://github.com/Dicklesworthstone/frankenfs/commit/389e17a832acc88a63e31c792cf6bb9953eefaae)

- **Writeback-cache benchmark workload types** and throughput comparison model
  [`72391c7`](https://github.com/Dicklesworthstone/frankenfs/commit/72391c70d50e5c68f40cff9c7fddc66ddc858cac)

- **Writeback-cache MVCC barrier schedule invariant checker** (6 formal invariants: I1-I6)
  [`f04d77c`](https://github.com/Dicklesworthstone/frankenfs/commit/f04d77cf6481c45f078702eecf86827abb53c305)

- **Barrier invariant types gated** behind `#[cfg(test)]`
  [`64e81db`](https://github.com/Dicklesworthstone/frankenfs/commit/64e81db1f4853a5480ab38d27f19a4edae174178)

- **Writeback-cache opt-in operator contract** -- the only supported kernel `writeback_cache` path is `--rw --writeback-cache` plus three accepted artifacts (`--writeback-cache-gate`, `--writeback-cache-ordering-oracle`, `--writeback-cache-crash-replay-oracle`) plus a disarmed `FFS_WRITEBACK_CACHE_KILL_SWITCH` and a matching host/lane manifest. Validated by `ffs-harness validate-writeback-cache-audit`, `validate-writeback-cache-ordering`, and `validate-writeback-cache-crash-replay`, plus `./scripts/e2e/ffs_writeback_cache_audit_e2e.sh`. `flush()` remains explicitly non-durable; `fsync` / `fsyncdir` are the only durability boundaries
  [`d008eb6`](https://github.com/Dicklesworthstone/frankenfs/commit/d008eb618149897859f93db2417f936a3648aa34),
  [`069ecba`](https://github.com/Dicklesworthstone/frankenfs/commit/069ecbab810ad6051ba266fd8e0463ba920b6396)

- **Writeback-cache crash/replay matrix oracle** -- 12-point crash matrix is now an artifact-level contract: all 12 crash point IDs, the mounted operation trace, raw FUSE options, survivor sets, flush/fsync/fsyncdir observations, cancellation and repeated-write classification, stdout/stderr paths, cleanup status, unsupported-combination rejections, and reproduction command are all required fields
  [`4cd6c03`](https://github.com/Dicklesworthstone/frankenfs/commit/4cd6c0374d5b03bcf6b7d4061fc94339833a0c4a)

- **Writeback ordering oracle** -- dirty-page / fsync ordering rules formalized with accept / reject scenarios (`writeback_cache_ordering_accepts_complete_oracle`, `..._rejects_missing_fsync`, `..._rejects_missing_fsyncdir`), pinned via insta snapshots
  [`54b8d07`](https://github.com/Dicklesworthstone/frankenfs/commit/54b8d07fa472ac6aa4ef512f6ea0c7dd324e916c),
  [`b760dbf`](https://github.com/Dicklesworthstone/frankenfs/commit/b760dbf86a780644249a28b0385f41d758f3561c)

- **Mounted-write reorder defense** -- `bd-tojwb` adds block-io writeback manifest rows so reorder regressions are caught at the manifest layer; `bd-17war` catalogues the writeback E2E scenario universe; `bd-slgzs` caps writeback drain polling so a stuck flush daemon cannot deadlock unmount
  [`bbfac4b`](https://github.com/Dicklesworthstone/frankenfs/commit/bbfac4b1270df287d03f36b1c69fc7b5870ea873),
  [`823dc47`](https://github.com/Dicklesworthstone/frankenfs/commit/823dc47de293b016fd52d1fcd1e6e970892043ac),
  [`6136c2d`](https://github.com/Dicklesworthstone/frankenfs/commit/6136c2d88e812cf02cdb6f03b86a2811d01bc542)

---

## Write Path

Block/inode allocation (`ffs-alloc`), extent B+tree (`ffs-btree`), extent mapping (`ffs-extent`), inode lifecycle (`ffs-inode`), directory operations (`ffs-dir`), and extended attributes (`ffs-xattr`).

- **ext4 extent B+tree operations** -- search, insert, split, merge
  [`092a48a`](https://github.com/Dicklesworthstone/frankenfs/commit/092a48aebdd7596170f5ebfc7467493489ef3f1c)

- **Block/inode allocation** -- mballoc-style bitmap allocator with buddy system, goal-directed placement, Orlov directory spreading
  [`5d99bd7`](https://github.com/Dicklesworthstone/frankenfs/commit/5d99bd72096335dded82b76fca8849e9edc70c57)

- **Extent write operations** -- insert, truncate, mark-written, punch-hole
  [`0e8a9d6`](https://github.com/Dicklesworthstone/frankenfs/commit/0e8a9d6690fb81cd91ca26dee994a8ddeec4b76b)

- **Inode lifecycle operations** -- create, read, write, delete with checksum validation
  [`20e4a7f`](https://github.com/Dicklesworthstone/frankenfs/commit/20e4a7f539fe543cb31bba1eb808ed2de49c5c32)

- **Directory write operations** -- add_entry, remove_entry, init_dir_block
  [`90baa90`](https://github.com/Dicklesworthstone/frankenfs/commit/90baa906db425777dee4d84aaeccbb7f10f3c48f)

- **Extended attribute write operations** with Create/Replace mode semantics
  [`3bde39c`](https://github.com/Dicklesworthstone/frankenfs/commit/3bde39ce0d5d4b68e9855f94a44f735f26eb3c7a)

- **Succinct rank/select bitmap** for O(1) free-space queries
  [`21de74b`](https://github.com/Dicklesworthstone/frankenfs/commit/21de74b375d81d49b3d9eab3812c8001431437d8)

- **Batch block allocator** and extent LRU cache
  [`a51c901`](https://github.com/Dicklesworthstone/frankenfs/commit/a51c9017fad2be285e00a381a7c51b9fd87691aa)

- **Punch-hole rewrite** with per-extent deletion and overflow tests
  [`240e061`](https://github.com/Dicklesworthstone/frankenfs/commit/240e061c20bd746d12de5e72477934491379b466)

- **Btree insert separator-key maintenance fix** with proptests
  [`47ef0f9`](https://github.com/Dicklesworthstone/frankenfs/commit/47ef0f99c028bfc1f6e41ac12b16e299acc16056)

- **Split write reordering** and deferred child frees for crash safety
  [`15769c7`](https://github.com/Dicklesworthstone/frankenfs/commit/15769c70107823dbdb314e9f75c49b19c107bb90)

- **Double-free detection** in inode bitmap allocator
  [`b6eb23c`](https://github.com/Dicklesworthstone/frankenfs/commit/b6eb23c297100f5f3eda34a8b2d0a248d0514a46)

- **Cross-group extent rejection** in `free_blocks`
  [`657ddc6`](https://github.com/Dicklesworthstone/frankenfs/commit/657ddc64879e331a3763f756626f09b600b6a35b)

- **Block allocator improvements** including empty bitmap panic elimination
  [`ecffd3d`](https://github.com/Dicklesworthstone/frankenfs/commit/ecffd3d1a8de57849e59a58224c751959984bdbf),
  [`49d0dbb`](https://github.com/Dicklesworthstone/frankenfs/commit/49d0dbbc4cec65009ec64709bbb4e418b4754987)

- **64-bit timestamp pipeline** for year-2106+ support
  [`53c697b`](https://github.com/Dicklesworthstone/frankenfs/commit/53c697b0d598062eb35968a2e20492c6ece3f734)

- **Checked/saturating arithmetic** for block numbers and counters
  [`4ef909f`](https://github.com/Dicklesworthstone/frankenfs/commit/4ef909fff1ac6d50460bd8166e1168cde3a1e365)

- **Saturating clamp helpers** replacing unsafe as-casts in `trim_extents`
  [`35610ff`](https://github.com/Dicklesworthstone/frankenfs/commit/35610ffd591b624640c8c8a8921fa7998c1808b0)

- **Missing FsGeometry fields** fix and `encode_extra_timestamp` nsec clamping
  [`549aaad`](https://github.com/Dicklesworthstone/frankenfs/commit/549aaad4736eb62e02f59292603cb0c6b2ddf2b9)

- **`huge_file` flag respect** in block accounting; COW for shared xattr blocks
  [`507f826`](https://github.com/Dicklesworthstone/frankenfs/commit/507f826fcf05e0846a0847296a5731ea7b0d73cc)

- **Directory nlink handling** correction, xattr block freeing on delete
  [`2791388`](https://github.com/Dicklesworthstone/frankenfs/commit/279138864e47004aa5988992f7b5dbab90a2d4ed)

- **ext4 directory metadata checksum support**
  [`875d735`](https://github.com/Dicklesworthstone/frankenfs/commit/875d73545214c82d8e465261ef91142f4133cf26)

- **ExtentCache namespace isolation tests**
  [`242c873`](https://github.com/Dicklesworthstone/frankenfs/commit/242c87378ea967fc6625877407d57b55584b16a6)

- **ext4 `e2compr` write support** -- the path moved from read-only decompression to bidirectional read/write, including single/double/triple indirect block pointers, cluster accounting, and compressed-indirect truncate coverage
  [`008da90`](https://github.com/Dicklesworthstone/frankenfs/commit/008da90153eb4778f420feac715e7585a0b548d9),
  [`ca8ed79`](https://github.com/Dicklesworthstone/frankenfs/commit/ca8ed795e755149f93a5dc691706dbcee7afd8a3),
  [`18cd3d7`](https://github.com/Dicklesworthstone/frankenfs/commit/18cd3d7218fc30a5436a4ee65895789735f13580),
  [`06a4288`](https://github.com/Dicklesworthstone/frankenfs/commit/06a428895242d385507fb8e3fd71a103900b00bd),
  [`a57561d`](https://github.com/Dicklesworthstone/frankenfs/commit/a57561dcb1a37bd1d6b2076510cd6d0eed57166a),
  [`220ea22`](https://github.com/Dicklesworthstone/frankenfs/commit/220ea22756df77e888787ccf1bc034817a788bdb)

- **btrfs fallocate and extent mutation expansion** -- punch-hole and zero-range support landed with overlapping-extent removal helpers, compressed-extent guard rails, and additional extent-management logic
  [`5731ae3`](https://github.com/Dicklesworthstone/frankenfs/commit/5731ae3910bcaa17a4e320558b5844e22a2763e8),
  [`bcf92b2`](https://github.com/Dicklesworthstone/frankenfs/commit/bcf92b2b2881c5d9921a561d31b199e392a4bd6b),
  [`ea9f019`](https://github.com/Dicklesworthstone/frankenfs/commit/ea9f019906fda8486b42af2fdc7b7afaee2b9448),
  [`10a90ff`](https://github.com/Dicklesworthstone/frankenfs/commit/10a90ff8645d2d3fbd66e66bf00ced12cb1fc398),
  [`f674445`](https://github.com/Dicklesworthstone/frankenfs/commit/f674445a43483ea5b24b5b86302f2601f7793a05)

- **Namespace and metadata correctness hardening** -- directory block allocation became transactional, POSIX rename semantics were enforced, inode `i_version` now bumps on mutation, xattr collision handling improved, and new/preflight dir blocks now initialize checksum tails correctly
  [`6b01343`](https://github.com/Dicklesworthstone/frankenfs/commit/6b01343d4a46c9903b050d06420e962b866fa341),
  [`75e1888`](https://github.com/Dicklesworthstone/frankenfs/commit/75e18886abc45b23cddeabd1a166da2ea1b94083),
  [`f3c69f2`](https://github.com/Dicklesworthstone/frankenfs/commit/f3c69f2277b2e020783afe1da2ce2d9211774dc7),
  [`24afc31`](https://github.com/Dicklesworthstone/frankenfs/commit/24afc3126b07f6fe0d99467a9db11c4d92855cde),
  [`872ce8d`](https://github.com/Dicklesworthstone/frankenfs/commit/872ce8dbfa7c9fad5b60af80f181dbc630808f6b),
  [`28ab2b4`](https://github.com/Dicklesworthstone/frankenfs/commit/28ab2b4b4dd98c93a9276a8a7ac724cbf644a368)

---

## Journal and WAL Recovery

JBD2 replay for ext4 compatibility and native MVCC WAL for crash recovery, in `ffs-journal` and `ffs-mvcc`.

- **JBD2 replay + native COW journal** implementation
  [`03925fb`](https://github.com/Dicklesworthstone/frankenfs/commit/03925fb7d9c3f63063921ad8cc0d481ae5350724)

- **Journal replay integration** into ext4 mount path
  [`db9d1d0`](https://github.com/Dicklesworthstone/frankenfs/commit/db9d1d0ef5fb838aa1e184e7dd8e87164b2a600e)

- **JBD2 revoke-across-transactions** semantics fix and `r_count` length limit enforcement
  [`4cf620a`](https://github.com/Dicklesworthstone/frankenfs/commit/4cf620a7422380d45cdb91df4e612ff0ec4c7636),
  [`d2e1be5`](https://github.com/Dicklesworthstone/frankenfs/commit/d2e1be5006d99b421c7222f520701cbe2dbae127)

- **Non-contiguous ext4 journal extents** support
  [`fdd192b`](https://github.com/Dicklesworthstone/frankenfs/commit/fdd192b4da525f6a41f67edd9975243f401db25b)

- **WAL replay engine extraction** and recovery pipeline hardening
  [`112ad62`](https://github.com/Dicklesworthstone/frankenfs/commit/112ad62393ee1645b5564f99b781d0ab0f56fc50)

- **Native-mode boundary resolution** and version-store format
  [`7fab707`](https://github.com/Dicklesworthstone/frankenfs/commit/7fab7079290c24f701eb682b5e06453599416d50)

- **WAL replay telemetry**, crash matrix, and verification runner
  [`d949529`](https://github.com/Dicklesworthstone/frankenfs/commit/d94952931e690f42ec17d28b3a819173a6ac7b56)

- **Journaled commit atomicity** fix; btrfs extent/fallocate correctness; ext4 unwritten extents
  [`b9772d0`](https://github.com/Dicklesworthstone/frankenfs/commit/b9772d080f059901b3944a4cad7fcdecfe6a6a25)

- **Superblock checksum write ordering** fix
  [`8400820`](https://github.com/Dicklesworthstone/frankenfs/commit/8400820e9317ee98b769dcb2bc920d20c31da623)

- **Recovery surface expansion** -- ext4 fast-commit, btrfs tree-log replay, mount-time fast-commit application, 64-bit JBD2 support, and external-journal pairing/replay helpers all landed in this window
  [`64098b5`](https://github.com/Dicklesworthstone/frankenfs/commit/64098b5ee0edae1d649a63329b51ce9311ccdcd9),
  [`6a4dd9c`](https://github.com/Dicklesworthstone/frankenfs/commit/6a4dd9cf0f5f2e2848a3c4e2c4b9e91dabc63eb8),
  [`a19f7d6`](https://github.com/Dicklesworthstone/frankenfs/commit/a19f7d6b5976cdc8b396870b619ee7adf86f3d03),
  [`23c47de`](https://github.com/Dicklesworthstone/frankenfs/commit/23c47de559003906257ffa4e3bf211ac89d84966),
  [`7a8ede4`](https://github.com/Dicklesworthstone/frankenfs/commit/7a8ede4fcb9e8f7550d518176417eca7eb1db700),
  [`81ae68b`](https://github.com/Dicklesworthstone/frankenfs/commit/81ae68b602d72eb73c7b07492232bd7ecb8df24a)

- **Journal and WAL hardening** -- malformed descriptors/revokes and duplicate sequence reuse are now rejected, duplicate/post-commit COW records are blocked, replay logic moved to event-ordered helpers, and WAL-writer logging/evidence paths were strengthened
  [`136231d`](https://github.com/Dicklesworthstone/frankenfs/commit/136231deadac66851cadc3935c124ed399165e5e),
  [`0441102`](https://github.com/Dicklesworthstone/frankenfs/commit/04411027c39c0afaa8b405276a3ab8751d2ffc91),
  [`c2faa7a`](https://github.com/Dicklesworthstone/frankenfs/commit/c2faa7a733b45372c6b6c4ae77247897950083b0),
  [`d20a990`](https://github.com/Dicklesworthstone/frankenfs/commit/d20a9900c000caa06b68636d4aeee233ce1ca4ee),
  [`b341e26`](https://github.com/Dicklesworthstone/frankenfs/commit/b341e2621063390991a9cdb1de61c591153e725c),
  [`b2aa26f`](https://github.com/Dicklesworthstone/frankenfs/commit/b2aa26f37a683c5fdd8aa030c8ea4fa3ca36f9a5),
  [`890ac99`](https://github.com/Dicklesworthstone/frankenfs/commit/890ac99be1ecb9c115034baa6a72d1a0850b6a45),
  [`cba534c`](https://github.com/Dicklesworthstone/frankenfs/commit/cba534c3f8cbc21e40b614d01b71501dd3bb3eca)

---

## CLI and Observability

The `ffs-cli` crate provides the command-line interface with 11 subcommands
(`inspect`, `mvcc-stats`, `info`, `dump`, `fsck`, `repair`, `mount`, `scrub`,
`parity`, `evidence`, `mkfs`). The `mount` subcommand has 22 flags
covering writeback-cache opt-in, background repair, adaptive runtime,
managed/per-core dispatcher, btrfs subvolume/snapshot selection, and ext4
external-journal pairing.

- **Clap-based structured CLI** replacing ad-hoc argument parsing
  [`f0aebe8`](https://github.com/Dicklesworthstone/frankenfs/commit/f0aebe8c11b0eb583893cf6378f64c30a6114ae6)

- **Mount subcommand** for read-only ext4 FUSE mount; later expanded to btrfs and experimental `--rw`
  [`de66b4b`](https://github.com/Dicklesworthstone/frankenfs/commit/de66b4b58c0c1a0c8dab3a2cfe6a971ce2f2770a),
  [`436c257`](https://github.com/Dicklesworthstone/frankenfs/commit/436c2576a38302cc7850978882feb5770aaf8f0d)

- **Scrub subcommand** for read-only integrity scanning
  [`3210ca5`](https://github.com/Dicklesworthstone/frankenfs/commit/3210ca536e7d963cef705df5c69802bab507c444)

- **Free-space subcommand** for ext4 analysis
  [`aa2ec8d`](https://github.com/Dicklesworthstone/frankenfs/commit/aa2ec8d233fd7e524867ae1ca855607db21d35f1)

- **Evidence ledger viewer** command with preset queries (replay-anomalies, repair-failures, pressure-transitions, contention) and summary aggregation
  [`7f5ed30`](https://github.com/Dicklesworthstone/frankenfs/commit/7f5ed3034397597998ea7672c273673a960715cb),
  [`77f6c56`](https://github.com/Dicklesworthstone/frankenfs/commit/77f6c56566e08690f4592537479958d8a562f354)

- **Evidence metrics presets** and expanded observability CLI
  [`907d7a5`](https://github.com/Dicklesworthstone/frankenfs/commit/907d7a5f1b479a29e2c18d5040f06596755a26b0)

- **`mvcc-stats` command** for version-chain statistics
  [`4b0c21d`](https://github.com/Dicklesworthstone/frankenfs/commit/4b0c21db419d360a393a03b2cf150477e1959a4d)

- **`fsck --force` semantics** with clean-state skip logic
  [`0e73ba8`](https://github.com/Dicklesworthstone/frankenfs/commit/0e73ba8b8d3413a3037127f702587316255deb78)

- **Major CLI expansion** -- dump superblock/inode/extents/dir, info with groups/mvcc/repair/journal, mkfs
  [`6290318`](https://github.com/Dicklesworthstone/frankenfs/commit/6290318e4d5fb7c8e60246ce88bd8637a0dada57),
  [`11202d4`](https://github.com/Dicklesworthstone/frankenfs/commit/11202d40f8d930f9d6c0e798f80a2c71c2cd0466)

- **Repair command expansion** and artifact manifest
  [`c47b7df`](https://github.com/Dicklesworthstone/frankenfs/commit/c47b7df5bd0d8f67f7e8b4186181bc3b9f4b49ed)

- **btrfs CLI integration** -- chunk-group reporting, btrfs inode dump, btrfs stale-only repair scoping, subvolume CLI
  [`a53de18`](https://github.com/Dicklesworthstone/frankenfs/commit/a53de18333d3bd3748a362716f3bb45f73fd07d5),
  [`162510f`](https://github.com/Dicklesworthstone/frankenfs/commit/162510fea6f376bc85d8207f5a1f33d22a89eab6),
  [`dbb5ed2`](https://github.com/Dicklesworthstone/frankenfs/commit/dbb5ed2410323d3af0f4718c18e6e22a76e6f512)

- **Runtime-mode CLI contract** with structured observability and E2E coverage
  [`9d4a46e`](https://github.com/Dicklesworthstone/frankenfs/commit/9d4a46e0677212a3337284163c1e408c1ac3d59b)

- **Seeked file-region I/O** replacing full-image reads in CLI
  [`47e0f11`](https://github.com/Dicklesworthstone/frankenfs/commit/47e0f11d593c4844be259451f3702254138eefac)

- **Operator runbooks** for replay failure triage, corruption recovery, and backpressure investigation
  [`b9caa45`](https://github.com/Dicklesworthstone/frankenfs/commit/b9caa45cadba75df5af3964be1475ce3777ecc80)

- **CLI inspection depth expansion** -- btrfs ZLIB/ZSTD/LZ4 decoding, DIR_INDEX-aware dumps, and dynamic superblock-derived constants improved the fidelity of `inspect`, `dump`, and `info`
  [`1b47dde`](https://github.com/Dicklesworthstone/frankenfs/commit/1b47dded7c0adc07c3871ea403161341b27c28a2),
  [`a7c0761`](https://github.com/Dicklesworthstone/frankenfs/commit/a7c076154219d07bd9b7b447839eed41b3c0a1e7),
  [`3f67e30`](https://github.com/Dicklesworthstone/frankenfs/commit/3f67e302bc54338911d1383dee4c9a8709faae5e),
  [`3231f01`](https://github.com/Dicklesworthstone/frankenfs/commit/3231f01b137fafdbf5223278facd477e09220b47)

- **Evidence and error-reporting hardening** -- evidence collection expanded, JSON escaping moved to `serde_json`, and scope-failure metrics made mount/runtime failures easier to diagnose
  [`5672f65`](https://github.com/Dicklesworthstone/frankenfs/commit/5672f656980bb75cfaa7d5ccc875eddbc2d5e509),
  [`890ac99`](https://github.com/Dicklesworthstone/frankenfs/commit/890ac99be1ecb9c115034baa6a72d1a0850b6a45),
  [`cba534c`](https://github.com/Dicklesworthstone/frankenfs/commit/cba534c3f8cbc21e40b614d01b71501dd3bb3eca),
  [`954ee2a`](https://github.com/Dicklesworthstone/frankenfs/commit/954ee2a654ef20c6ce5ec67835c6e88977ef7e32)

- **Mount subcommand surface expansion** -- the `mount` subcommand now exposes `--runtime-mode {standard|managed|per-core}`, `--writeback-cache` plus three accepted-artifact flags (`--writeback-cache-gate`, `--writeback-cache-ordering-oracle`, `--writeback-cache-crash-replay-oracle`), `--background-repair`, `--background-scrub`, `--no-background-scrub`, `--background-scrub-ledger`, `--background-scrub-interval-secs`, `--adaptive-runtime` plus its manifest/summary flags, `--managed-unmount-timeout-secs`, `--allow-other`, `--rw`, `--native`, `--subvol`, `--snapshot`, `--ext4-data-err-abort`, and `--ext4-nojournal-checksum`. The writeback-cache kill switch is the `FFS_WRITEBACK_CACHE_KILL_SWITCH` environment variable (not a flag). The external-journal pairing, `ext4_journal_replay_mode`, and `ext4_data_err_policy` are library-API controls on `OpenOptions` (not CLI flags as of this window)

- **`ffs-cli inspect --subvolumes --snapshots`** -- enumerates btrfs subvolumes and snapshots from the CLI for operator-path scoping verification before mount

- **Readiness action CLI** -- new entrypoint to drive readiness-lab dry-runs, planning JSON, and validation JSON with insta-pinned outputs

---

## TUI Dashboard

The `ffs-tui` crate provides a terminal-based live monitoring dashboard via `ftui`.

- **Minimal TUI dashboard** implementation
  [`1defb2d`](https://github.com/Dicklesworthstone/frankenfs/commit/1defb2d043bb44b5c7ff6bfe40b712e67c326558)

- **Expanded TUI rendering** capabilities and comprehensive test coverage
  [`2d72e2d`](https://github.com/Dicklesworthstone/frankenfs/commit/2d72e2d10367aee354c6b0cbf6ea1bf1938dbce8),
  [`0a019dc`](https://github.com/Dicklesworthstone/frankenfs/commit/0a019dcc70f4b4208276a9d9248d90c3fb263894)

---

## Conformance Harness and Testing

The `ffs-harness` crate provides sparse fixtures, golden-file conformance, parity tracking, E2E tests, and verification gates.

- **Fixture generation workflow** and `SparseFixture::from_bytes`
  [`c25115e`](https://github.com/Dicklesworthstone/frankenfs/commit/c25115ed8738735bff5c4c49394345fa883ad1d0)

- **Parity accounting invariant enforcement**
  [`032613f`](https://github.com/Dicklesworthstone/frankenfs/commit/032613fabd9ffc92caedf7e4b5629d7223f0b332)

- **ext4 fixtures** for group desc, inode, dir block, superblock
  [`de3bcef`](https://github.com/Dicklesworthstone/frankenfs/commit/de3bcef8b4731a48d80007dcdb5daa9e29414085),
  [`85f5fc6`](https://github.com/Dicklesworthstone/frankenfs/commit/85f5fc600f9edf92ec2dfcee4ed0b572742cf348)

- **btrfs fixtures** for sys_chunk mapping, leaf nodes, fs-tree, root-tree
  [`6a6d5de`](https://github.com/Dicklesworthstone/frankenfs/commit/6a6d5de85bab7445483b2e5298b7d280ce42b59c),
  [`882082b`](https://github.com/Dicklesworthstone/frankenfs/commit/882082b396d63d809bff1b1b47d456b0a902e95a)

- **Golden output verification** and isomorphism proof protocol
  [`a09518d`](https://github.com/Dicklesworthstone/frankenfs/commit/a09518dfd1877564f9e8d04255ba98b6203ff1ed)

- **Linux-kernel reference capture pipeline** and E2E conformance tests
  [`220c92a`](https://github.com/Dicklesworthstone/frankenfs/commit/220c92ae9993ca8de951ac16d9b506b1a7bf7e93)

- **End-to-end test infrastructure** and fixture generation
  [`4cdc823`](https://github.com/Dicklesworthstone/frankenfs/commit/4cdc823a4aef428199e89b48d0b2f8e584b09160)

- **xfstests harness** with result parsing and CI regression gate
  [`8417c93`](https://github.com/Dicklesworthstone/frankenfs/commit/8417c93a660eaaf1ff6a3736bcc3d235d5a967fc),
  [`a23e89b`](https://github.com/Dicklesworthstone/frankenfs/commit/a23e89b73c59db44ec8966eacc2d93b9b706da0b)

- **EMLINK limit test** for hard link rejection
  [`39d05e5`](https://github.com/Dicklesworthstone/frankenfs/commit/39d05e5780a3ffb50cafc71afcd4eedf3f10a2b5)

- **Deterministic SIGKILL recovery harness** replacing best-effort crash phase
  [`baeaca0`](https://github.com/Dicklesworthstone/frankenfs/commit/baeaca0dea4cefe3d55ae97f3163e88bbbea07de)

- **Massive edge-case test expansion** -- approximately 400+ new tests across all crates in a single push
  [`c256f40`](https://github.com/Dicklesworthstone/frankenfs/commit/c256f40873954e95b660b3205a6bf9ae0d9662ba),
  [`8023b64`](https://github.com/Dicklesworthstone/frankenfs/commit/8023b646a766be6b1b4045a502ed834c1860df84),
  [`0a3d02c`](https://github.com/Dicklesworthstone/frankenfs/commit/0a3d02cb49ab10f4174c1894e1050b1cf9fb0c8a),
  [`3742c29`](https://github.com/Dicklesworthstone/frankenfs/commit/3742c2964f20818816dfebb178a65aa5c4574123),
  [`9ae2809`](https://github.com/Dicklesworthstone/frankenfs/commit/9ae2809d296ae660c5c24c36cfc8f56071675f29),
  [`0a6425b`](https://github.com/Dicklesworthstone/frankenfs/commit/0a6425b2093491b514897b8ae08acb00e02b68d8),
  [`092e0ee`](https://github.com/Dicklesworthstone/frankenfs/commit/092e0eebcd877f84a661a15ec0a788608c11a647),
  [`c8197bb`](https://github.com/Dicklesworthstone/frankenfs/commit/c8197bb3b9e2fd5b3dfd5e483a2df0cca8e46480),
  [`ad9f258`](https://github.com/Dicklesworthstone/frankenfs/commit/ad9f2586d1bd34dd7bb0cb3fbb42a7b1cc5887ad),
  [`e58660b`](https://github.com/Dicklesworthstone/frankenfs/commit/e58660b0a1426c9396134f2476be13512c07aa84),
  [`d05069e`](https://github.com/Dicklesworthstone/frankenfs/commit/d05069ece5cc974522d27d936c95f6327e051842),
  [`d72ae01`](https://github.com/Dicklesworthstone/frankenfs/commit/d72ae01675dbbc7c2687f5b971c0ce6c686d788b)

- **Property-based tests (proptest)** -- ARC cache invariants, MVCC concurrency, ext4 checksums/parsing, RaptorQ codec, inode operations, types, xattr, extent, allocator, journal, directory
  [`f54f58f`](https://github.com/Dicklesworthstone/frankenfs/commit/f54f58f7bb5bc79689f3d9a220744f4b5ee83748),
  [`c104a48`](https://github.com/Dicklesworthstone/frankenfs/commit/c104a4875586f408631a037980357eff24b68aa7),
  [`869259f`](https://github.com/Dicklesworthstone/frankenfs/commit/869259f2fb2192372552b295b53fd7ce9fe3311c),
  [`09d0d70`](https://github.com/Dicklesworthstone/frankenfs/commit/09d0d704a3575ec06a1741030a4c1d7a4303762b),
  [`87b7f73`](https://github.com/Dicklesworthstone/frankenfs/commit/87b7f73b5aad0b3e490f8274ce80c05a31b4faf3),
  [`179beea`](https://github.com/Dicklesworthstone/frankenfs/commit/179beeaeeb340c54db40419f87c38b86a1069975),
  [`088584d`](https://github.com/Dicklesworthstone/frankenfs/commit/088584df72d3c5e0e9a80781332400285ba6146b),
  [`84b23c6`](https://github.com/Dicklesworthstone/frankenfs/commit/84b23c628a1932819243b0f34602406cad026109),
  [`5ec7a9e`](https://github.com/Dicklesworthstone/frankenfs/commit/5ec7a9e8941ed0d9b34f912e89190ffd08d2c3d0),
  [`09d8d62`](https://github.com/Dicklesworthstone/frankenfs/commit/09d8d6215e9ec60663fb8f9d39f9e10a4e47c22b)

- **Verification gate scripts** for MVCC replay, mount runtime modes, and V1.1 validation suite
  [`f102e14`](https://github.com/Dicklesworthstone/frankenfs/commit/f102e1403cc732498a2508ea1d9432f4fcd61c0d),
  [`ca275b6`](https://github.com/Dicklesworthstone/frankenfs/commit/ca275b62f64c255513f230441ed3c023c5691304),
  [`97501db`](https://github.com/Dicklesworthstone/frankenfs/commit/97501dbdf91730938f08051ba329477b0af8975b)

- **Cross-crate integration tests** for ffs-core
  [`a82cefe`](https://github.com/Dicklesworthstone/frankenfs/commit/a82cefe7b0ef4feff163483a6ac78744bc81f2ed)

- **Real-image FUSE regression coverage** -- FIEMAP moved to real ext images, ABI 7-31 was exercised under E2E, and truncate/fallocate/ioctl coverage expanded across ext4 and btrfs
  [`e9e89c0`](https://github.com/Dicklesworthstone/frankenfs/commit/e9e89c04bc2a4d9aea365c895f39b87da15d5d98),
  [`f273f30`](https://github.com/Dicklesworthstone/frankenfs/commit/f273f308d779b2768d678a45b947abb7d1337f8e),
  [`0f3bfa5`](https://github.com/Dicklesworthstone/frankenfs/commit/0f3bfa56e9cc2f11f866329afbdc8515419a7105),
  [`fafa0fa`](https://github.com/Dicklesworthstone/frankenfs/commit/fafa0fa31f76c7e8b714eb33b78b4994e974cdda),
  [`4fdf096`](https://github.com/Dicklesworthstone/frankenfs/commit/4fdf096d55ce94d4830f5ec5c2ff2184eaf1cd13)

- **`e2compr` and namespace hardening tests** -- adversarial decompression, new proptests, bulk create/lookup coverage, external-journal cases, and broader cross-crate integration suites landed with the write-path work
  [`17ca2ee`](https://github.com/Dicklesworthstone/frankenfs/commit/17ca2ee59dc9e51480557f3a9f3afe20d51112eb),
  [`60a85a7`](https://github.com/Dicklesworthstone/frankenfs/commit/60a85a72fffaf3e65331d6e6fcb04b8cb1ddf907),
  [`73dd17a`](https://github.com/Dicklesworthstone/frankenfs/commit/73dd17ab5f652504481e199a2ee0c02cf6dc6a98),
  [`9864864`](https://github.com/Dicklesworthstone/frankenfs/commit/9864864752179c5ce21ab6212b6fe23af892c594),
  [`5672f65`](https://github.com/Dicklesworthstone/frankenfs/commit/5672f656980bb75cfaa7d5ccc875eddbc2d5e509)

- **Canonical golden gate documentation** -- `verify_golden.sh` became the single documented entrypoint for golden/conformance verification, with the older script retained as a shim
  [`162aa59`](https://github.com/Dicklesworthstone/frankenfs/commit/162aa59058469cc7384f63e861d76f589d999024),
  [`bd91c3d`](https://github.com/Dicklesworthstone/frankenfs/commit/bd91c3d18e947e96730772f1fedaccb4505f59c7)

- **btrfs kernel-reference conformance expansion** -- dedicated kernel-reference harness coverage landed alongside refreshed sparse fixtures, goldens, capability-drift inputs, and checksum manifests
  [`207ee11`](https://github.com/Dicklesworthstone/frankenfs/commit/207ee11a1498b974e51cdce480258f907fb2a2f4),
  [`8ddd3de`](https://github.com/Dicklesworthstone/frankenfs/commit/8ddd3defd26fa6367d75c07467024d3dd276cf41)

- **Mounted write workload matrix** -- `./scripts/e2e/ffs_mounted_write_workload_matrix.sh` exercises every mounted-write scenario in the production matrix with canonicalized `SCENARIO_RESULT` outcomes, deduplicated e2e-marker fields, escaped JSON values, invalid-field rejection, empty-field counters, and shared-marker duplicate detection (bd-rchk0.337 ... bd-rchk0.346)
  [`316f361`](https://github.com/Dicklesworthstone/frankenfs/commit/316f3615583713432ffd6a550d40b43c57753f7a),
  [`02621d4`](https://github.com/Dicklesworthstone/frankenfs/commit/02621d465ba0e9c5a8d337d296545a4c249fed38),
  [`57bcf5e`](https://github.com/Dicklesworthstone/frankenfs/commit/57bcf5e1f2b1441c8e1b43ef6b3272e3703bc025),
  [`87d497d`](https://github.com/Dicklesworthstone/frankenfs/commit/87d497d8af27f1ee71148825053d78877f7ce17a)

- **RCH-routed cargo gates** -- compute-heavy harness paths (writeback-cache audit, repair writeback, repair writeback serialization, soak/canary, release gate, swarm tail latency, mounted-differential, performance manifest, adversarial threat model) now run through `rch exec -- cargo ...` so local resource contention from concurrent agents cannot mask harness failures
  [`65b75b0`](https://github.com/Dicklesworthstone/frankenfs/commit/65b75b0c5b8de968ea1247ee6a9bb787971c6270),
  [`66a8093`](https://github.com/Dicklesworthstone/frankenfs/commit/66a809356abfa781c2c6db4b81615409878d1f3b),
  [`82ebfb5`](https://github.com/Dicklesworthstone/frankenfs/commit/82ebfb525867e5434355e69339efaad2de86bbf6)

- **Beads compliance audit infrastructure** -- `beads_compliance_audit/` records two passes of dependency-aware bead completion verification (2026-05-10 → 2026-05-13). Pass 1 surfaced 2 PARTIALs and 1,557 cross-project beads polluting the universe; Pass 2 cut per-capita false positives by 75% and filed `bd-cvyt0` as P1 for cross-project pollution

---

## Fuzz Infrastructure

Fuzzing corpus, crash-to-regression promotion, and nightly fuzz dictionaries.

- **1281 fuzz corpus entries** for btrfs metadata, ext4 xattr, and VFS operations
  [`0ee5695`](https://github.com/Dicklesworthstone/frankenfs/commit/0ee5695ccea18561f40ff2e3220a47dbfcfe63a4)

- **Crash-to-regression-test promotion script**
  [`7225c09`](https://github.com/Dicklesworthstone/frankenfs/commit/7225c09731dcd7bcc24ed38664896b16ce077cea)

- **Fuzz infrastructure and serialization improvements** across crates
  [`527980e`](https://github.com/Dicklesworthstone/frankenfs/commit/527980e57f1d18453ef47555f64a365b29a9ec66)

- **Nightly fuzz dict flag placement fix**
  [`557f5fb`](https://github.com/Dicklesworthstone/frankenfs/commit/557f5fbf78a4f8bcfe42d0be30bb7ccc1b122905)

- **60 fuzz targets** -- the corpus now spans every parser, allocator, codec, oracle, manifest, and dispatcher in the workspace. Notable new targets in this window: `fuzz_authoritative_lane_manifest`, `fuzz_path_component_validation`, `fuzz_xattr_parsing`, `fuzz_btrfs_tree_items`, `fuzz_cli_btrfs_parsers`, `fuzz_ext4_extra_bit_pack`, `fuzz_repair_symbols`, `fuzz_ext4_image_reader`, `fuzz_inode_roundtrip`, `fuzz_alloc_succinct`, `fuzz_ext4_checksums`, `fuzz_ext4_extent_actual_len`, `fuzz_swarm_workload_harness`, `fuzz_btrfs_devitem_roundtrip`, `fuzz_ext4_metadata`, `fuzz_ext4_chksum`, `fuzz_ext4_xattr`, `fuzz_fuzz_smoke_manifest`, `fuzz_ioctl_dispatch`, `fuzz_por_authenticator`, `fuzz_jbd2_replay`, `fuzz_ext4_fast_commit`, `fuzz_btrfs_tree_log`

- **Fuzz smoke + dashboard gates** -- `bd-rchk0.300` tracks the fuzz smoke report schema; `bd-rchk0.313` tracks fuzz dashboard JSON schemas; fuzz target registration guarded so a deleted/renamed target trips the gate (`bd-0c2xy`); fuzz smoke manifest fuzzer sources hardened against external manipulation
  [`12801460`](https://github.com/Dicklesworthstone/frankenfs/commit/12801460246e70001e058e38330401ad52197b02),
  [`a741552a`](https://github.com/Dicklesworthstone/frankenfs/commit/a741552ae6925a2da1726f97ad986651aeee99e8),
  [`102edec`](https://github.com/Dicklesworthstone/frankenfs/commit/102edeccd292f7d642d1fab727654424b9f20683)

---

## Performance and Benchmarking

Criterion benchmarks, perf regression harness, baseline recording, and profiling infrastructure.

- **ondisk_parse benchmarks** and CLI baselines
  [`db56b56`](https://github.com/Dicklesworthstone/frankenfs/commit/db56b56c024dca15f31d5159eb1a23d310cee241)

- **ARC/S3-FIFO cache workload benchmarks** and Bw-Tree vs locked B-tree bench
  [`19ea92c`](https://github.com/Dicklesworthstone/frankenfs/commit/19ea92cbd77a08318241ad4da00ba1097c8e6efb)

- **Perf regression harness** with benchmark thresholds and CI workflow
  [`83cf153`](https://github.com/Dicklesworthstone/frankenfs/commit/83cf153f8f15da41ba093d1ba4a432a51c87ca9f),
  [`38921a6`](https://github.com/Dicklesworthstone/frankenfs/commit/38921a6b3368dca51eb91346a416603909670810)

- **Benchmark taxonomy**, log contracts, perf comparison, and E2E scenarios
  [`9bb2db6`](https://github.com/Dicklesworthstone/frankenfs/commit/9bb2db6f4f1c195f6def9a34dcf1e59e2f068b22)

- **Performance regression triage module** with runbook and E2E coverage
  [`4e8e37e`](https://github.com/Dicklesworthstone/frankenfs/commit/4e8e37e1a2663f9a044ee384d9cb0da01a07a970)

- **Extent resolve benchmarks**, metrics module, and profiling scripts
  [`137299f`](https://github.com/Dicklesworthstone/frankenfs/commit/137299f05e82a742405c040b14ed6b42f4bbf31d)

- **Benchmark governance** with comparison context and triage followup commands
  [`9bd8ced`](https://github.com/Dicklesworthstone/frankenfs/commit/9bd8cedc33e9c30e3b9428125bb06838309f3c0e)

- **Benchmark baseline refresh** and recording pipeline hardening
  [`4007dfa`](https://github.com/Dicklesworthstone/frankenfs/commit/4007dfa6416dfb649b96c2c1040c88ce36455c82)

- **Benchmark harness sanity fixes** -- benchmark RNG seeding was corrected and EBR benchmark artifacts were refreshed during recovery-path hardening
  [`096024e`](https://github.com/Dicklesworthstone/frankenfs/commit/096024ef42ce007c147f16bc4cc98d897fc2a041),
  [`90bbc5d`](https://github.com/Dicklesworthstone/frankenfs/commit/90bbc5d4330d1b146703e6fa7f5b40debce890ff)

- **20260406 baseline refresh** -- benchmark baselines, perf-regression inputs, benchmark-tooling scripts, and history artifacts were refreshed together in the latest committed benchmark pass
  [`8ddd3de`](https://github.com/Dicklesworthstone/frankenfs/commit/8ddd3defd26fa6367d75c07467024d3dd276cf41)

- **Performance manifest contracts** (`bd-rchk5.x` family) -- dated 2026-05-03 core and mounted throughput/latency artifacts, host/runtime metadata, delta closeout, no-reference decisions, and quarantined mounted-latency claims now flow through a single `validate-performance-manifest` contract. Quarantine and no-reference rows must be explicit; readiness wording cannot imply tuning is complete beyond the supported evidence tier
  [`88ebbf4`](https://github.com/Dicklesworthstone/frankenfs/commit/88ebbf4d0afd0f3d92c4e5c0427f9d18c81a1542),
  [`46288ea`](https://github.com/Dicklesworthstone/frankenfs/commit/46288ea00424811b84b64b7e711b4f58abdc7e72)

- **Benchmark taxonomy** (`bd-rchk0.326`) -- enumerated taxonomy with round-trip JSON validation for all 11 criterion benchmarks (`arc_cache`, `bwtree_vs_locked`, `bitmap_ops`, `batch_alloc`, `extent_resolve`, `mount_runtime`, `degraded_pressure`, `wal_throughput`, `scrub_codec`, `metadata_parse`, `ondisk_parse`)
  [`402f386`](https://github.com/Dicklesworthstone/frankenfs/commit/402f386c7bbe51036aa39e1bd02a9f63be6f25a2)

- **NUMA p99 attribution ledger** -- p99 attribution data structure (`p99_attribution_ledger` artifact role) attributes long-tail latency to thread, NUMA node, ioctl class, and FUSE operation. Required field of the `swarm_tail_latency` proof-bundle lane
  [`128adab`](https://github.com/Dicklesworthstone/frankenfs/commit/128adab986c69ff88361a0b603e873656211160f)

- **mvcc merge-proof success benchmark** (`bd-62jy8`) -- criterion harness for SafeMerge resolution rate under load
  [`b1f3593`](https://github.com/Dicklesworthstone/frankenfs/commit/b1f35937dc310517727663c0e43f83e969811d97)

---

## Foundation Types and Error Handling

`ffs-types` (newtypes, checked arithmetic) and `ffs-error` (currently 21-variant `FfsError` enum with errno mappings; began life as a 14-variant taxonomy and grew with directory + repair + mode-violation surfaces).

- **Canonical error taxonomy** with 14-variant `FfsError` and POSIX errno mappings
  [`74fce48`](https://github.com/Dicklesworthstone/frankenfs/commit/74fce48a2beb5d5267b71c95e52caa5d0fbbee4a)

- **Mount-validation error variants**
  [`0c24f84`](https://github.com/Dicklesworthstone/frankenfs/commit/0c24f84fb9466c3536cb08ce4f89a95222579d67)

- **Checked arithmetic and alignment helpers** in `ffs-types`
  [`6e91588`](https://github.com/Dicklesworthstone/frankenfs/commit/6e915881f7d7fd32c4f7012057c8cc08422be9fa)

- **Typed `BlockNumber`, `InodeNumber`, `TxnId`, `CommitSeq`** newtypes; `ByteOffset`/`DeviceId` wrappers
  [`f96eb7a`](https://github.com/Dicklesworthstone/frankenfs/commit/f96eb7ad7433e595ca5040a0a441d3c6df8a163a)

- **`InvalidMagic` typed error** replacing string-based `InvalidField` variant
  [`5a62422`](https://github.com/Dicklesworthstone/frankenfs/commit/5a62422df08d5d6b6dc2d95f3723a03f6733bfd8)

- **Lossy as-cast elimination** -- replaced with checked `try_from` conversions across core, alloc, and ondisk
  [`0181976`](https://github.com/Dicklesworthstone/frankenfs/commit/0181976cfc860238d4e737ed80e455e05e744113),
  [`73ce8c8`](https://github.com/Dicklesworthstone/frankenfs/commit/73ce8c88f1a26d7ccd22d4ba88f6d59d12b1f593)

- **Error taxonomy variant-class mismatch** fix for FFS-RPL-001
  [`9ed7fb2`](https://github.com/Dicklesworthstone/frankenfs/commit/9ed7fb2a85fd18c033a16fee4cfbf43ea071154f)

- **`SymbolEquationArityMismatch`** error handling and dependency graph update
  [`fb714f4`](https://github.com/Dicklesworthstone/frankenfs/commit/fb714f41da075d3dacc46f3595d481f36c1e5f11)

- **Broader checked-conversion and panic-removal sweep** -- more silent truncations, panicking integer casts, and ad hoc literals were replaced with fallible conversions and explicit error paths across `core`, `extent`, `alloc`, `types`, and `cli`
  [`efbebc3`](https://github.com/Dicklesworthstone/frankenfs/commit/efbebc37f96a75c76aafd85cf9b991a9a8cde85b),
  [`01c3439`](https://github.com/Dicklesworthstone/frankenfs/commit/01c34392867c8fb5528fd71ec92f29ad86c6e267),
  [`797b6de`](https://github.com/Dicklesworthstone/frankenfs/commit/797b6de5a5861bcb5e775850caeb7f31dc813896),
  [`5408144`](https://github.com/Dicklesworthstone/frankenfs/commit/54081449a1148c608bb839c7189d64b2daa99c0a),
  [`54b0857`](https://github.com/Dicklesworthstone/frankenfs/commit/54b0857f2d2cf32563d194959f35dc9ff40a1a38)

- **Type and error-surface expansion** -- additional filesystem kinds, directory/error variants, and xattr-adjacent APIs were added while pedantic cleanup reduced diagnostic noise
  [`edd50bd`](https://github.com/Dicklesworthstone/frankenfs/commit/edd50bd27446002e709f6d6acb62f9c340b009db),
  [`754907b`](https://github.com/Dicklesworthstone/frankenfs/commit/754907bf06308dffb732f0284f8b64b793a4d184)

---

## Documentation and Architecture

README, specification documents, architecture alignment, and design documents.

- **21-crate workspace architecture** reconciliation with spec, errata tracking, and Bayesian autopilot spec
  [`48858ce`](https://github.com/Dicklesworthstone/frankenfs/commit/48858ce3f02bd27844496d99e283763512343ed6)

- **Crate layering contract** alignment -- dependency graph matched to code
  [`f970460`](https://github.com/Dicklesworthstone/frankenfs/commit/f970460583b3bc0b270165dbcbb4f19a10f949be),
  [`3debcee`](https://github.com/Dicklesworthstone/frankenfs/commit/3debcee47cde14dfcb857fc7bce76240c8019ab9)

- **Canonical type definitions** with cross-links in spec
  [`1e06ab5`](https://github.com/Dicklesworthstone/frankenfs/commit/1e06ab56f36ee3c36e03b3bf0fb0c4fbf3fff1ff)

- **V1 filesystem scope section** and FAQ updates
  [`8ac730e`](https://github.com/Dicklesworthstone/frankenfs/commit/8ac730e70e45a54cd78c1bbbe929855b14c1f9c1)

- **Safe-merge taxonomy design** document with proof obligation sketches
  [`30d6fa3`](https://github.com/Dicklesworthstone/frankenfs/commit/30d6fa35d247dcc5120b8aec026e55270a9ac7d8)

- **Write-back cache + dirty tracking design** document
  [`29c17a9`](https://github.com/Dicklesworthstone/frankenfs/commit/29c17a97702d67e15c3fd454873c08e91c674ce9)

- **README rewrite** with MVCC merge proofs, adaptive policies, and benchmark model
  [`4a9b0d3`](https://github.com/Dicklesworthstone/frankenfs/commit/4a9b0d342e2ce4eb20a465396cd27263c4394a40)

- **README expansion** with writeback-cache design, repair pipeline, and evidence system
  [`2f8b5b1`](https://github.com/Dicklesworthstone/frankenfs/commit/2f8b5b1b06255c285dbcb805ee265e63a39e4931)

- **Comprehensive rustdoc** and property-based tests across core, extent, and MVCC crates
  [`1c6fe66`](https://github.com/Dicklesworthstone/frankenfs/commit/1c6fe66598cb5489c9b97001c63b11497f3ee247)

- **README and parity-document refresh** -- tracked V1 parity semantics, feature scope, test-count claims, and the canonical golden-verification workflow were all updated to match the implementation that landed after 2026-03-21
  [`3aff3af`](https://github.com/Dicklesworthstone/frankenfs/commit/3aff3af9b64c4f5ed19d82617b679e2057cd5454),
  [`5537150`](https://github.com/Dicklesworthstone/frankenfs/commit/55371504bd55dbbe0db29daf7423a876a5e3c579),
  [`dce710b`](https://github.com/Dicklesworthstone/frankenfs/commit/dce710be9609db5f59a709c1919fa2aaf6ef6385),
  [`7587971`](https://github.com/Dicklesworthstone/frankenfs/commit/7587971e3d29552da97c78c0997b46da9df08043),
  [`bd91c3d`](https://github.com/Dicklesworthstone/frankenfs/commit/bd91c3d18e947e96730772f1fedaccb4505f59c7)

- **Design doctrine documentation** -- `docs/design-writeback-cache-mvcc.md` (18 KB) formalizes the 6 invariants and 12-scenario crash matrix; `docs/design-repair-writeback-serialization.md` defines mounted repair serializer rules; `docs/mount-runtime-modes.md` (13 KB) documents the standard/managed/per-core operator contract; `docs/oq1-native-mode-boundary.md` and `docs/oq7-version-store-format.md` resolve open questions about native-mode boundary semantics and BlockVersion persistence

- **Tracker hygiene doctrine** -- `docs/tracker-hygiene.md` (17 KB, refreshed 2026-05-16) defines source-aware queue-state semantics, the per-claim-state vocabulary, and the safe-claimability signal used when raw `br ready` / `bv` outputs are polluted by cross-project rows

- **xfstests known-failures registry** -- `docs/xfstests-known-failures.md` (18 KB) records the allowlist with rationale; gates ensure these never silently flip without ACK

---

## Build, Dependencies, and Licensing

Workspace configuration, dependency management, CI, and license.

- **Initial commit** -- 21-crate Cargo workspace with `#![forbid(unsafe_code)]` at every crate root
  [`01bc389`](https://github.com/Dicklesworthstone/frankenfs/commit/01bc38985fb499db3598734e29ec9b7adcbc7253)

- **MIT + OpenAI/Anthropic rider license** adoption across workspace
  [`9cb3ba5`](https://github.com/Dicklesworthstone/frankenfs/commit/9cb3ba58f90cb867be567db80180282d229a1217)

- **asupersync/ftui bumped** to crates.io releases (0.2.0+)
  [`e98f3dc`](https://github.com/Dicklesworthstone/frankenfs/commit/e98f3dc9256ad7fc63a3b7e7668d75c3e3264aeb),
  [`cd7a9f8`](https://github.com/Dicklesworthstone/frankenfs/commit/cd7a9f8f77be5adb413e30b6b07606a8bd9d6c67)

- **asupersync 0.2 → 0.3 migration** -- the structured-concurrency runtime was bumped from 0.2.5 to 0.3.0 and then 0.3.1, with a checked-in [`docs/reports/UPGRADE_LOG.md`](docs/reports/UPGRADE_LOG.md) capturing migration notes. Btrfs CRC, clippy `too_many_lines`, and full-review suite blockers were unblocked in the same window. The `ftui` dependency was bumped 0.2.1 → 0.3.1 alongside
  [`53efe11`](https://github.com/Dicklesworthstone/frankenfs/commit/53efe118042144d975e44e33196b185830cc1b25),
  [`eacbc42`](https://github.com/Dicklesworthstone/frankenfs/commit/eacbc42f0af5c19670605933f8dfe4735ba5799f),
  [`947e53e`](https://github.com/Dicklesworthstone/frankenfs/commit/947e53e7e420b94897f697d4bc493d0d94ec4c71),
  [`5bb7e56`](https://github.com/Dicklesworthstone/frankenfs/commit/5bb7e56887b5f2aeed9e503f93972b127da454b9)

- **CI pipeline hardening** with `cargo fmt --check`, `cargo clippy -- -D warnings`, and full workspace test gate
  [`436c257`](https://github.com/Dicklesworthstone/frankenfs/commit/436c2576a38302cc7850978882feb5770aaf8f0d)

- **Rustfmt formatting** applied across all crates
  [`0603f71`](https://github.com/Dicklesworthstone/frankenfs/commit/0603f714e72b2856c843a1926dec5904906f7333)

- **Dead code cleanup** -- genuinely dead code removed from cli, core, and journal
  [`2a5f85b`](https://github.com/Dicklesworthstone/frankenfs/commit/2a5f85bf16b8efd240755ee0a1241911f5891e45)

- **Stale `#[allow(dead_code)]` removal** on actively-used items
  [`d5d118a`](https://github.com/Dicklesworthstone/frankenfs/commit/d5d118a310411e0007966cda1f36c67e8a1da3f6)

- **GitHub social preview image** (1280x640)
  [`042df32`](https://github.com/Dicklesworthstone/frankenfs/commit/042df327e04d8d505d187aa3684541d75541a0fe)

- **WebP illustration** added to README header
  [`a72cf4f`](https://github.com/Dicklesworthstone/frankenfs/commit/a72cf4f759db9773100dab0fd199749e8af7900d)

- **Verification entrypoint normalization** -- the legacy `verify-goldens.sh` path now shims to canonical `verify_golden.sh`, keeping CI and operator workflows on one supported script
  [`162aa59`](https://github.com/Dicklesworthstone/frankenfs/commit/162aa59058469cc7384f63e861d76f589d999024)

- **Cargo.lock refresh** for newly committed harness/conformance dependency changes
  [`07bd37a`](https://github.com/Dicklesworthstone/frankenfs/commit/07bd37a9423b7829e0fe42a8e7dbe91fc5664916)

- **Vendored fuser** -- `vendor/fuser` is pinned via `[patch.crates-io]` so ABI 7.40 + unrestricted ioctls are forwarded to FrankenFS handlers. This is the only mechanism by which FIEMAP / EXT4_IOC_* / BTRFS_IOC_* parity tests can exercise the real userspace handlers

- **Source-scope coverage gates** -- new gates ensure that fuzz orchestration (`bd-7pvw9`), fuzz targets (`bd-5u0sf`), and performance control (`7b32ee53`) are explicitly counted inside the source-scope coverage manifest so structural drift is caught at gate time

---

## Notes for Agents

- The historical `master` branch only exists for legacy URL compatibility; all work happens on `main` and the project tracker rejects `master`-referencing changes by convention.
- The single source of truth for tracked feature coverage is `FEATURE_PARITY.md`, parsed by `ParityReport::current()` in `ffs-harness`, and enforced by the `parity_report_matches_feature_parity_md` CI test.
- The single source of truth for release-gate behavior is `tests/release-gates/release_gate_policy_v1.json`.
- The evidence ledger event taxonomy is defined in `ffs-repair::evidence` and currently spans 30 `EvidenceEventType` variants. The five operator-facing CLI presets are `replay-anomalies`, `repair-failures`, `pressure-transitions`, and `contention` (plus the default tail view).
- Every machine-readable harness output is now snapshot-pinned with `insta`; if you change a report shape, run `cargo insta review` against `ffs-harness` before pushing.
- Cargo builds, tests, and clippy invocations should go through `rch exec -- cargo ...` when local resource contention from concurrent agent swarms could mask harness output. The hook is automatic for Claude Code; manual otherwise.
