# Ledger Resurrection Audit — frankenfs

**Campaign:** `perf-campaign-20260725`, Fleet-Wide Meta-Lever #1.
**Lane:** cc / STRUCTURAL (CreamBeaver). **Date:** 2026-07-25.
**Sources audited:** `docs/NEGATIVE_EVIDENCE.md` (2.1 MB) + `docs/progress/perf-negative-results.md` (387 KB).

A REJECT row is **VOID** when the measurement *could not have detected the lever* — as
opposed to detecting it and finding it absent. This audit separates those two cases.

---

## 1. Method

`docs/NEGATIVE_EVIDENCE.md` is heterogeneous: 538 markdown table rows on a fixed
8-column layout (`Date | Bead | Surface | Verdict | Ratio | Internal | Direct-kernel | Gates`)
plus 407 free-prose `###` subsections; `docs/progress/perf-negative-results.md` adds
86 `##` sections. All 1,031 entries were parsed, the **Verdict** column (or the prose
title) was classified, and only REJECT-verdict entries were audited. SURVEY rows
(`SURFACE / no code`, `N/A`, routing-only) are measurements, not rejected levers, and
are excluded.

Audit script: `scratchpad/audit_ledger.py` (regex screen over the parsed entries).
**The screen is a triage tool, not a verdict.** Every row in the curated queue in §3
was read in full and adjudicated by hand; the §5 table is the mechanical screen output.

### Verdict taxonomy

| Class | Meaning | Sound? |
|---|---|---|
| `VALID-PROFILE` | Rejected before any source edit, on a named profile frame with non-zero self-time and a computed Amdahl ceiling. | ✅ |
| `VALID-MECHANISM` | No A/A null recorded, but refuted on a *counted* mechanism — instructions/cycles/syscalls/allocations/faults unchanged. A null control cannot change "no work was removed". | ✅ |
| `VALID-AB` | A/B run with a recorded A/A null; the claimed effect sits inside that null. | ✅ |
| `VOID-CV` | An A/B ran, and the row was killed **only** by a `cv < 5%` gate — the gate campaign §2.3 proves is unreachable on this hardware. | ❌ |
| `VOID-ZEROSELF` | The target frame had ~0% self-time in the profile the bench actually exercised. | ❌ |
| `VOID-NONULL` | An A/B ran, was rejected on a near-1.0 wall ratio, and recorded **no** A/A null control and no counted mechanism. Cannot distinguish lever from harness. | ❌ |

---

## 2. Counts

| Metric | Count |
|---|---:|
| Ledger entries parsed | 1,031 |
| — KEEP verdict | 551 |
| — SURVEY / routing (not a lever rejection) | 181 |
| — UNKNOWN (unparsable verdict cell) | 23 |
| **REJECT verdict — audited** | **276** |
| VALID-AB | 34 |
| VALID-PROFILE | 12 |
| VALID-MECHANISM | 11 |
| **VOID-NONULL** | **214** |
| **VOID-CV** | **4** |
| **VOID-ZEROSELF** | **1** |
| **VOID total** | **219 / 276 = 79.3%** |
| Rows carrying a binary sha256 | 30 / 276 = 10.9% |

**Read this honestly.** A 79.3% void rate is *not* 219 buried wins. `VOID-NONULL`
overwhelmingly means "the row measured ~1.0× and never wrote down what ~1.0× means on
that bench" — most of those levers really are dead, and the class exists because the
row cannot *prove* it. The dominant sub-population is 2026-06-xx prose rows written
before this repo adopted null controls at all. The actionable yield is concentrated in
a small head, ranked in §3, and the single highest-value finding is not in the void
count at all — it is a lever that was **built, correctness-tested, and never measured
once** (§3, rank 1).

Two structural facts about this ledger, both worth fixing:

1. **89% of REJECT rows carry no binary sha256.** Concurrent agents share one worktree
   in `/data/projects/frankenfs`; several rows in the 2026-06 window were measured
   while peers were editing the same crates. Campaign §2.1 (self-reporting ELF sha) is
   already implemented in `crates/ffs-mvcc/benches/wal_throughput.rs`
   (`print_bench_evidence_metadata`, prints `bench_evidence,binary_sha256=…,worker=…`)
   — it just is not used by most benches.
2. **The `cv < 5%` gate is load-bearing in this repo's recent rows and it is wrong.**
   See rank 2 below: a **2.614×** effect against a **1.007×** A/A null was rejected
   because CV was 5.63% instead of 4.99%.

---

## 3. Ranked rehabilitation queue

Ranked by the campaign's rule — profile self-time of the target frame — with the tie
broken toward levers whose *design work is already done*.

### Rank 1 — ⭐ lock-free in-order `CommitPublicationGate` (`NEGATIVE_EVIDENCE.md:3491`)

**Class: VOID — no measurement was ever obtained.** The strongest form of void: the
lever was implemented, env-gated (`FFS_GATE_LOCKFREE`), and correctness-tested with a
16-thread shuffled-publish stress test, then shelved with **zero** timing rows because
`rch exec` kept landing on a fresh worker (5–8 min clean rebuild per arm) and the
`sharded_mvcc_disjoint_{8,16,32}writers` bench had CIs (`8w [5.03, 5.56, 6.25] ms`)
that swamped the expected effect. The row's own words: *"NOT landed on main (unmeasured
= cannot claim a gain); change shelved on `git stash`/branch `cc-gate-lockfree-fastpath`."*
That branch and stash no longer exist — the code is gone, the design is not.

Why this is rank 1:

- `CommitPublicationGate::publish` takes **one global `Mutex<PublicationState>` on every
  commit**, inserts into a `BTreeSet`, and `notify_all()`s. Fully disjoint-shard writers
  funnel through it.
- It is the frame this repo's own ledger names as the remaining global serializer:
  *"NEXT SERIALIZATION LEVERS (exposed by the 4/8-thread flatness): (a) the
  `CommitPublicationGate` commit ordering — inherently serializes the publish step …
  These are the remaining global bottlenecks on the parallel-create scaling surface."*
  (`perf-negative-results.md:2256`)
- It is *measured* to convoy: the `bd_bhh0i_contention` model put the publish lock at
  **p95 64.549 µs / p99 127.449 µs at 8 threads**, against a decomposed per-group alloc
  lock at p95 0.240 µs (`perf-negative-results.md:2447`).
- The later `CommitPublicationGate` REJECT (`NEGATIVE_EVIDENCE.md:85`, publication-prefix
  atomic-store batching, 0.999× — correctly rejected) states the residual explicitly:
  *"The gate already holds a `BTreeSet` removal loop whose ordered-tree work dominates
  these atomic accesses… Do not retry unless a profile attributes material self-time
  specifically to the per-entry atomic load/store rather than **the publication
  mutex/tree work**."* The atomic-shape family is closed. The mutex-and-tree family —
  which that row names as dominant — was never attacked in production.
- The measurement blocker is now removable: `wal_throughput` gained
  `print_actual_null_control` (31 interleaved A/A pairs, alternating order, median of
  per-round log-ratios, p90 spread, per-phase publication p99s, self-reported ELF sha).
  That is the campaign §2 contract, already in-tree, on the real production `commit`.

**Action: taken by this lane.** See §4.

### Rank 2 — same-transaction JBD2 descriptor/data write combining (`NEGATIVE_EVIDENCE.md:35`)

**Class: VOID-CV.** Candidate **8.511634 ms** vs scalar controls **22.409485 ms** and
**22.247282 ms** = **2.614×**, with an **A/A median spread of 1.007×**, 30 interleaved
samples, same worker `vmi1227854`, byte-readback equality asserted on all 65 × 4096
bytes. Rejected because CV was 5.634% / 5.652% / 10.266% — i.e. above 5%. Under the
campaign §2.3 median-CI gate a 2.614× effect against a 1.007× null is decidable by a
margin of roughly 200×. This is the textbook case the campaign describes.

Retry predicate (satisfied): re-decide on the median-CI gate rather than CV; then build
wrap-aware production grouping in `commit_transaction` and gate on journal replay +
crash-injection proof before keeping. **Owner: cod lane** (harness + frontier; this is
their re-run list). Flagged on the campaign thread.

### Rank 3 — `ExtentCache` eviction scan (`NEGATIVE_EVIDENCE.md:512`)

**Class: VOID-NONULL, but PARTLY SUPERSEDED — do not re-run as written.** The row
measured `tree --read-data` 450 ms → 93.8 ms = **4.8×** by raising the cache capacity so
the O(n) `min_by_key` eviction scan never fires, then correctly reverted (a larger cap
makes a >cap workload scan a bigger shard, ~23× worse at 100k inodes) and named the real
fix: O(1) exact-LRU or one-pass bypass. **Since then, bd-vpypn (2026-07-22, KEEP) landed
batch eviction** — `select_nth_unstable_by_key` selecting `max(1, capacity/8)` victims in
one scan, amortizing to O(len/batch) per insert, measured warm 8192-extent read 2.44× /
cold 1.80×. That captures most of the 4.8×. Residual: the batch scan still allocates and
scans a capacity-sized `Vec` per batch. Honest verdict: **the headline 4.8× is spent**;
what remains is a bounded O(1)-LRU cleanup, not a 4.8× resurrection.

### Rank 4 — Arc-share the hot ext4 inode (`NEGATIVE_EVIDENCE.md:838`)

**Class: VOID-NONULL.** `Ext4Inode::clone` at ~8% self-time at 64t; A/B was
`16834/18147/20918/17674` vs `20148/17377/17630/17011` "under box load ~20", base ahead
in 3 of 4 trials. Spread is ±20% with no null control — undecidable as recorded. The
row's *reasoning* is sound (self-time ≠ wall in an I/O-bound parallel section) and the
ceiling is ~8% of a 64t read path, so the expected value is low. Retry only if a quiet
pinned-worker A/A null on the read bench comes in below 1.02× **and** the read path is
shown CPU-bound rather than pread-bound at the tested thread count.

### Rank 5 — `bd-cowbatch` btrfs create insert batching (`NEGATIVE_EVIDENCE.md:1439`)

**Class: not void — an unlanded measured win blocked on a refactor.** `insert_many`
measured **13.25×** vs sequential and **7.60×** vs the existing batched primitive on
`btrfs_cow_write_mutation_256x4k`, proptest-hardened over 96 random cases. It is not
wired into `btrfs_create` because a correct batch must consume the DIR_INDEX seq without
inserting, detect and fall back on the rare DIR_ITEM hash collision, and keep the parent
INODE_ITEM timestamp update separate. Projected: btrfs create 3.0×-slower-than-kernel →
~2×. This is real, shovel-ready structural work in `ffs-core` — a peer-active file, so it
needs an Agent Mail reservation before anyone starts.

---

## 4. Resurrection yield

| Metric | Count |
|---|---:|
| Entries audited | 276 |
| Void | 219 |
| Re-run under the corrected harness | 1 (rank 1) |
| **Re-won** | **1 — 1.70× at 8 threads, decidable at a 2.14× log-margin** |
| Handed to the cod lane to re-run | 1 (rank 2) |
| Void but superseded — closed, not re-run | 1 (rank 3) |

**Resurrection yield: 1 of 1 re-run entries re-won.** The rank-1 row was void in the
strongest sense — not "rejected on a bad gate" but **never measured at all**. Its design
work was already paid for in June; all this turn added was a harness that could decide it.

### 4.1 Rank 1 re-run — profile attribution

Before touching source, the frame was re-attributed on the **real** commit path (not a
synthetic model). `bd-bhh0i`'s 2026-07-10 `cod_ffs` characterization ran the production
`ShardedMvccStore::commit` under `CommitLockProfile` at 1/2/4/8 threads:

| phase (p99, ns) | 1t | 2t | 4t | 8t |
|---|---:|---:|---:|---:|
| shard wait | 255 | 255 | 511 | 511 |
| shard hold | 32767 | 16383 | 8191 | 8191 |
| **publication mutex wait** | **127** | **2047** | **32767** | **131071** |
| publication hold | 255 | 1023 | 2047 | 2047 |
| ordered-prefix wait | 0 | 65535 | 131071 | 262143 |

The publication **mutex wait** grows **1,000× from 1t to 8t** and reaches **131 µs p99**,
against a shard wait of **511 ns** — a 256× ratio. The shard locks are not the problem;
the single gate mutex is. That is the frame the lever removes.

It also bounds the claim honestly. The gate has two costs and this lever only removes one:

- **Mutex wait** (131 µs p99 at 8t) — pure mechanism: queueing on one global lock to
  insert into a `BTreeSet` and `notify_all`. **Removed** by the ring + CAS prefix advance.
- **Ordered-prefix wait** (262 µs p99 at 8t) — semantic: a commit may not publish before
  its predecessors, because a snapshot must see a gap-free prefix. **Preserved exactly.**
  Any lever that removes this changes visibility semantics and is a different, much
  larger proof obligation.

So the ceiling for this lever is the mutex-wait term, not the whole publication cost.

### 4.2 Rank 1 re-run — method

The original code is gone (branch and stash both deleted), so it was rebuilt from the
row's description as `PublicationMode::{Mutex, WaitFree}` — a **per-store** setting, not
a process-global one, so **both arms run from one ELF** and codegen cannot differ between
them. Production selects via `FFS_MVCC_WAITFREE_PUBLISH`; unset means the untouched
mutex gate, so the default build is byte-identical to the pre-lever binary.

Harness: `crates/ffs-mvcc/benches/wal_throughput.rs` under `--features bench-instrumentation`,
which already implements the campaign §2 contract — self-reported ELF sha256 + worker,
31 interleaved pairs with alternating order, median of per-round log-ratios, p90 spread,
and per-phase publication p99s — against the real `ShardedMvccStore::commit`. Added:
`run_paired_arms` (so the same pairing driver produces both the A/A null and the A/B),
and `assert_publication_mode_isomorphism`, which runs **before any timing** and asserts
both modes produce an identical final watermark and an identical SHA-256 over every
block's resolved bytes at 1/2/4/8 writers.

**Prerequisite fixed first:** `--features bench-instrumentation` did not compile on HEAD
— `std::fmt::Write` and `std::io::Write` were both imported unaliased in
`wal_throughput.rs`, so every `write_all` call failed `E0599`. The repo's §2-contract
harness was unbuildable. Fixed (`use std::fmt::Write as FmtWrite`).

### 4.3 Rank 1 re-run — result: **RE-WON**

Full evidence in `docs/progress/perf-negative-results.md` (2026-07-25, turn 12). Binary
SHA-256 `516342ec9754db9fe37edcbf0944340e2875f6cb67dd867fa43d4338257fbcac`, worker
`vmi1227854`, 31 interleaved pairs per phase.

Behavior proven **before timing**: identical watermark and identical SHA-256 over every
resolved block at 1/2/4/8 writers, both modes.

Decision arm (unprofiled production commit path):

| threads | A/A null | A/A floor | A/B | verdict |
|--------:|---------:|----------:|----:|---|
| 1 | 1.0358 | 1.3970 | 0.9766 | inside null |
| 2 | 1.0076 | 1.2628 | 1.1525 | inside null |
| 4 | 1.0204 | 1.2666 | 1.3675 | outside floor, below the 2× margin — not claimed |
| 8 | 0.9839 | 1.2811 | **1.7004** | **decidable, 2.14× log-margin** |

Reproduced on two further independently built ELFs: **1.8841×** and **2.1066×** at
8 writers, each decidable against its own A/A floor (2.75× and 3.21× log-margins).
**Completed unprofiled 8-thread runs: 3/3 decidable, range 1.70–2.11×, median 1.88×.**
The conservative **1.70×** is the published claim, qualified as *on a quiet pinned
worker* — a fourth run whose thread sweep was truncated by a harness overrun read
only 1.30× on its profiled arm, and a contention-removal lever is by construction
load-sensitive: less contention on the box, less to remove.

Mechanism, not just wall time — publication **mutex** wait p99 collapses
32767 ns → **511 ns** at 8 threads (64×) while the **ordered-prefix** wait is identical
in both arms (524287 / 524287). Exactly the split predicted in §4.1: the mechanism cost
is removed, the semantic cost is untouched.

Default stays **OFF** until an end-to-end `create-bench` + `e2fsck` gate passes.

---

## 5. Per-row audit table

VOID rows first, ranked by target-frame self-time (campaign ranking rule), then the
sound rejections. `—` means the field is absent from the row, which for
"Null floor" and "Binary sha?" is itself the audit finding.

| # | Entry (file:line) | Ratio claimed | Null floor at the time | Self-time of target frame | Binary sha? | Verdict |
|---:|---|---:|---:|---:|:--:|---|
| 1 | `NEGATIVE_EVIDENCE.md:3739` — 2026-06-29 REFUTED (~0-gain): lookup_in_dir_block early-exit on match — measured neutral (CrimsonFox) | — | none recorded | 31.75% | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 2 | `NEGATIVE_EVIDENCE.md:512` — (profile + REVERTED neutral) | 4.8x | none recorded | 15% | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 3 | `NEGATIVE_EVIDENCE.md:21` — `bd-mounted-xattr-workload-gap-fr6iq` — list-64 direct wire retry / BronzeRabbit | — | recorded, unparsed | 8.96% | yes | **VOID-CV** — killed by the cv<5% gate, not by a measured regression |
| 4 | `NEGATIVE_EVIDENCE.md:838` — 2026-06-22 NEG-LEVER: Arc-share the hot ext4 inode (kill the per-read clone) — wall-NEUTRAL, REVERTED (CrimsonFox cc/opus) | — | none recorded | 8% | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 5 | `NEGATIVE_EVIDENCE.md:747` — 2026-06-22 scrub is ALLOCATION-bound, not validation-bound — parallelizing validation would NOT help (CrimsonFox cc/opus) | — | none recorded | 7.3% | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 6 | `NEGATIVE_EVIDENCE.md:22` — `bd-fsync-journal-latency-gap-ptp4x` / `bd-opb6l` / `bd-mounted-xattr-workload-gap-fr6iq` — consolidated measured-frontier refresh / BronzeRabbit | — | none recorded | 5% | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 7 | `progress/perf-negative-results.md:332` — btrfs runtime path swept for a byte-identical per-op lever — SATURATED (bd-kdmu4) - 2026-07-24 (turn 6, REJECT #2) | — | none recorded | 5% | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 8 | `progress/perf-negative-results.md:1170` — Mounted small-file create storm gap is FUSE-transport-bound, not a create-CPU lever - 2026-07-23 (NOT-A-LEVER / ledgered blocker; bd-kdmu4 small-file- | — | none recorded | 5% | no | **VOID-CV** — killed by the cv<5% gate, not by a measured regression |
| 9 | `progress/perf-negative-results.md:987` — Mounted metadata storm (stat-walk) is getattr-round-trip-bound + adaptive-readdirplus REJECT - 2026-07-23 (bd-kdmu4 small-file-storm sub-lane) | — | none recorded | 1.5% | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 10 | `progress/perf-negative-results.md:2634` — Seeded Do-Not-Retry Rows From Prior No-Gaps Work | — | none recorded | 0.1% | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 11 | `NEGATIVE_EVIDENCE.md:6445` — 2026-07-12 (cont.) — bd-vpypn RESOLVED by existing evidence: extent-walk is µs-scale even at E65536 (rejection holds at high extent counts) | — | none recorded | 0.05% | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 12 | `NEGATIVE_EVIDENCE.md:1439` — 2026-06-25 bd-cowbatch HARDENED (proptest) + FS-wiring blocker surfaced (CrimsonFox cc/opus) | 13.25x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 13 | `progress/perf-negative-results.md:3447` — 2026-07-10 — Cold-read: contention scales with FOLIO INSERTIONS, not reads, not threads (bd-ddryj, BlackThrush/cc_ffs) | 12.2x | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 14 | `NEGATIVE_EVIDENCE.md:3686` — 2026-06-29 MEASURED: parallel ext4 create gap quantified vs kernel — 5.5x (the #1 gap, bd-bhh0i) — CrimsonFox | 5.5x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 15 | `NEGATIVE_EVIDENCE.md:292` — bd-bhh0i / SilverPine | 3.24x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 16 | `NEGATIVE_EVIDENCE.md:35` — `bd-fsync-journal-latency-gap-ptp4x` — same-transaction JBD2 descriptor/data write combining / YellowPuma | 2.614x | 1.007x | — | no | **VOID-CV** — killed by the cv<5% gate, not by a measured regression |
| 17 | `NEGATIVE_EVIDENCE.md:1674` — 2026-06-25 MEASURED: ShardedMvccStore parallel commit = 2.11x vs single store at 8t — lever VALIDATED, but it still negative-scales (the publication g | 2.11x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 18 | `NEGATIVE_EVIDENCE.md:28` — `bd-opb6l` - shared-channel multiloop FUSE dispatch / YellowPuma | 1.96355x | recorded, unparsed | — | yes | **VOID-CV** — killed by the cv<5% gate, not by a measured regression |
| 19 | `progress/perf-negative-results.md:3571` — 2026-07-10 — Cold-read: the insertion-count-vs-throughput curve (bd-ddryj, BlackThrush/cc_ffs) | 1.49x | none recorded | 0% | yes | **VOID-ZEROSELF** — target frame ~0% self-time in the profile the bench ran |
| 20 | `NEGATIVE_EVIDENCE.md:525` — `bd-xmh5g` (mvcc decompress reuse probe) | 1.1x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 21 | `NEGATIVE_EVIDENCE.md:289` — bd-bhh0i / SilverPine | 1.09x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 22 | `NEGATIVE_EVIDENCE.md:191` — s3fast-tls-slab / BlackThrush | 1.083x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 23 | `NEGATIVE_EVIDENCE.md:71` — `bd-5koeh` — Btrfs internal-node array-reference field decode / Codex | 1.031x | 1.031x | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 24 | `NEGATIVE_EVIDENCE.md:273` — land-or-dig / SilverPine | 1.018x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 25 | `NEGATIVE_EVIDENCE.md:236` — profiling / BlackThrush | 1x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 26 | `NEGATIVE_EVIDENCE.md:251` — dig-deeper / BlackThrush | 1x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 27 | `NEGATIVE_EVIDENCE.md:276` — land-or-dig / SilverPine | 0.966x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 28 | `NEGATIVE_EVIDENCE.md:213` — ⭐MEASURED-NEGATIVE (REFUTES the "sole remaining lever") / BlackThrush | 0.9x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 29 | `NEGATIVE_EVIDENCE.md:3638` — 2026-06-29 MEASURED head-to-head (single-thread, +sync) + perf-lever exhaustion blocker — CrimsonFox | 0.84x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 30 | `NEGATIVE_EVIDENCE.md:315` — perf / SilverPine | 0.77x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 31 | `NEGATIVE_EVIDENCE.md:124` — `bd-b9dug` + `bd-bhh0i` — production-ISA rebench + parallel-create contention profile + jemalloc arena-tuning reject / BlackThrush (cc_ffs) | 0.58x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 32 | `NEGATIVE_EVIDENCE.md:4276` — 2026-06-29 REFUTED (measured, shelved): convoy commit-after-release via shared TransactionBlockAdapter — staging overhead + shared-bitmap conflict (Cr | 0.48x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 33 | `NEGATIVE_EVIDENCE.md:294` — land-or-dig / Codex | 0.269x | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 34 | `NEGATIVE_EVIDENCE.md:33` — `bd-mounted-xattr-workload-gap-fr6iq` — mounted read-only xattr get/list storm / YellowPuma | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 35 | `NEGATIVE_EVIDENCE.md:34` — `bd-opb6l` — mounted small-file create/delete storm / YellowPuma | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 36 | `NEGATIVE_EVIDENCE.md:70` — `bd-bhh0i` — sharded MVCC inline single-version chains / Codex | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 37 | `NEGATIVE_EVIDENCE.md:77` — `bd-kdmu4` — `ffs-block` single-iovec positioned-read dispatch / Codex | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 38 | `NEGATIVE_EVIDENCE.md:78` — `bd-fsync-journal-latency-gap-ptp4x` — group-commit in-place future extraction / Codex | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 39 | `NEGATIVE_EVIDENCE.md:87` — `bd-kdmu4` — ext4 complete-read hot-inode admission / Codex | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 40 | `NEGATIVE_EVIDENCE.md:125` — `bd-bhh0i` — parent-inode-write deferral: PROFILE-FIRST value measurement (env-gated skip of the per-create parent mtime/ctime `write_inode`) / BlackT | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 41 | `NEGATIVE_EVIDENCE.md:162` — ⚠️ **SELF-CORRECTION** of my own row below / `bd-ddryj` / BlackThrush (cc_ffs) | — | 1.41x | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 42 | `NEGATIVE_EVIDENCE.md:163` — `bd-kdmu4` DECISIVE EVIDENCE (owner decision surfaced) / `bd-ddryj` / BlackThrush (cc_ffs) | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 43 | `NEGATIVE_EVIDENCE.md:164` — `bd-ddryj` (granularity curve — the "reduce insertions" premise is REFUTED as a throughput lever) / BlackThrush (cc_ffs) | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 44 | `NEGATIVE_EVIDENCE.md:185` — datalayout-move-CORRECTED-adapter / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 45 | `NEGATIVE_EVIDENCE.md:186` — fuse-backpressure-decision-table / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 46 | `NEGATIVE_EVIDENCE.md:188` — succinct-structure-bold / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 47 | `NEGATIVE_EVIDENCE.md:192` — invariant-recompute-audit / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 48 | `NEGATIVE_EVIDENCE.md:195` — measure-then-revert / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 49 | `NEGATIVE_EVIDENCE.md:196` — reprofile-lookup-post-attronly / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 50 | `NEGATIVE_EVIDENCE.md:198` — fresh-profile+4-candidates / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 51 | `NEGATIVE_EVIDENCE.md:199` — swept-flagged-pattern / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 52 | `NEGATIVE_EVIDENCE.md:202` — pressed-flagged-candidate / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 53 | `NEGATIVE_EVIDENCE.md:222` — different-hot-path / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 54 | `NEGATIVE_EVIDENCE.md:290` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 55 | `NEGATIVE_EVIDENCE.md:295` — land-or-dig / SilverPine | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 56 | `NEGATIVE_EVIDENCE.md:317` — bd-8fbka-sib / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 57 | `NEGATIVE_EVIDENCE.md:318` — bd-bhh0i / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 58 | `NEGATIVE_EVIDENCE.md:319` — perf / SilverPine | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 59 | `NEGATIVE_EVIDENCE.md:321` — bd-bhh0i / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 60 | `NEGATIVE_EVIDENCE.md:322` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 61 | `NEGATIVE_EVIDENCE.md:326` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 62 | `NEGATIVE_EVIDENCE.md:337` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 63 | `NEGATIVE_EVIDENCE.md:344` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 64 | `NEGATIVE_EVIDENCE.md:352` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 65 | `NEGATIVE_EVIDENCE.md:354` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 66 | `NEGATIVE_EVIDENCE.md:361` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 67 | `NEGATIVE_EVIDENCE.md:367` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 68 | `NEGATIVE_EVIDENCE.md:370` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 69 | `NEGATIVE_EVIDENCE.md:384` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 70 | `NEGATIVE_EVIDENCE.md:387` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 71 | `NEGATIVE_EVIDENCE.md:388` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 72 | `NEGATIVE_EVIDENCE.md:393` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 73 | `NEGATIVE_EVIDENCE.md:400` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 74 | `NEGATIVE_EVIDENCE.md:415` — perf / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 75 | `NEGATIVE_EVIDENCE.md:421` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 76 | `NEGATIVE_EVIDENCE.md:424` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 77 | `NEGATIVE_EVIDENCE.md:425` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 78 | `NEGATIVE_EVIDENCE.md:426` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 79 | `NEGATIVE_EVIDENCE.md:427` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 80 | `NEGATIVE_EVIDENCE.md:428` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 81 | `NEGATIVE_EVIDENCE.md:429` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 82 | `NEGATIVE_EVIDENCE.md:430` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 83 | `NEGATIVE_EVIDENCE.md:431` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 84 | `NEGATIVE_EVIDENCE.md:432` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 85 | `NEGATIVE_EVIDENCE.md:434` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 86 | `NEGATIVE_EVIDENCE.md:435` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 87 | `NEGATIVE_EVIDENCE.md:436` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 88 | `NEGATIVE_EVIDENCE.md:437` — `(gap-dig)` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 89 | `NEGATIVE_EVIDENCE.md:439` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 90 | `NEGATIVE_EVIDENCE.md:442` — `bd-bhh0i` / IvoryBirch | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 91 | `NEGATIVE_EVIDENCE.md:448` — `bd-xmh5g` / BlackThrush | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 92 | `NEGATIVE_EVIDENCE.md:450` — `bd-xmh5g` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 93 | `NEGATIVE_EVIDENCE.md:461` — `bd-xmh5g.414` | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 94 | `NEGATIVE_EVIDENCE.md:464` — `bd-xmh5g` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 95 | `NEGATIVE_EVIDENCE.md:465` — `bd-xmh5g.414` | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 96 | `NEGATIVE_EVIDENCE.md:466` — `bd-xmh5g.409` | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 97 | `NEGATIVE_EVIDENCE.md:467` — `bd-29an3` (CrimsonFox cc/opus) | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 98 | `NEGATIVE_EVIDENCE.md:473` — (observation, CrimsonFox cc/opus — distinct from bd-eflng) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 99 | `NEGATIVE_EVIDENCE.md:474` — `bd-eflng` (CrimsonFox cc/opus) — **prototyped fix MEASURED INERT; root cause CORRECTED** | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 100 | `NEGATIVE_EVIDENCE.md:481` — (bd-eflng residual, CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 101 | `NEGATIVE_EVIDENCE.md:508` — (bug found, fix UNMEASURABLE → filed) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 102 | `NEGATIVE_EVIDENCE.md:522` — `bd-xmh5g.410` (default-impl sibling) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 103 | `NEGATIVE_EVIDENCE.md:540` — `bd-xmh5g` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 104 | `NEGATIVE_EVIDENCE.md:544` — `bd-xmh5g` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 105 | `NEGATIVE_EVIDENCE.md:545` — `bd-jgbam` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 106 | `NEGATIVE_EVIDENCE.md:552` — `bd-xmh5g.408` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 107 | `NEGATIVE_EVIDENCE.md:553` — `bd-xmh5g.407` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 108 | `NEGATIVE_EVIDENCE.md:554` — `bd-xmh5g` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 109 | `NEGATIVE_EVIDENCE.md:555` — `bd-2emlm` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 110 | `NEGATIVE_EVIDENCE.md:570` — `bd-xmh5g.409` (RESOLVED — not a real lever) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 111 | `NEGATIVE_EVIDENCE.md:580` — `bd-xmh5g.425` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 112 | `NEGATIVE_EVIDENCE.md:605` — 2026-06-21 ext4 indirect-read profile — same coordination floor, no lever (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 113 | `NEGATIVE_EVIDENCE.md:633` — 2026-06-22 ext4 sequential read at HEAD — dominates materialize 2.1x, loses to splice (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 114 | `NEGATIVE_EVIDENCE.md:682` — 2026-06-22 NEG-LEVER: serve single-job btrfs reads inline (skip rayon) — INERT, REVERTED (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 115 | `NEGATIVE_EVIDENCE.md:760` — 2026-06-22 NEG-LEVER: skip per-read mvcc_store RwLock (unused RO snapshot) — wall-NEUTRAL, REVERTED (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 116 | `NEGATIVE_EVIDENCE.md:778` — 2026-06-22 NEG-LEVER: throttle per-read Cx::checkpoint frequency — WORSE at the plateau, REVERTED (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 117 | `NEGATIVE_EVIDENCE.md:784` — 2026-06-22 NEG-LEVER + CONCLUSION: parallel read scaling ceiling is STRUCTURAL (copy/syscall tax), not removable contention (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 118 | `NEGATIVE_EVIDENCE.md:790` — 2026-06-22 NEG-LEVER: pre-size scrub read buffers (skip batch-1 staging) — neutral, REVERTED (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 119 | `NEGATIVE_EVIDENCE.md:794` — 2026-06-22 LOAD-INDEPENDENT confirm: random read issues kernel-identical preads (no amplification lever) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 120 | `NEGATIVE_EVIDENCE.md:808` — 2026-06-22 NEG-LEVER: per-thread buffer reuse in parallel rand-read (map_init) — neutral, REVERTED (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 121 | `NEGATIVE_EVIDENCE.md:852` — 2026-06-22 CONCLUSION: ext4/btrfs parallel random-read scaling ceiling CLOSED — residual is structural pread + harness rayon (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 122 | `NEGATIVE_EVIDENCE.md:856` — 2026-06-22 NEW GAP + NEG-LEVER: multi-file parallel read ~2.9x vs kernel; nested-rayon skip wall-NEUTRAL, REVERTED (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 123 | `NEGATIVE_EVIDENCE.md:874` — 2026-06-22 NEG-LEVER: full-block write builds buffer from slice (skip the wasted zero-init) — wall-NEUTRAL, REVERTED (CrimsonFox cc/opus) | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 124 | `NEGATIVE_EVIDENCE.md:878` — 2026-06-22 write lane at structural floor + prune_safe antipattern-sweep (defensive, unmeasured-in-CLI) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 125 | `NEGATIVE_EVIDENCE.md:884` — 2026-06-22 NO-GAP: large-directory lookup — frankenfs at parity-or-FASTER than kernel warm despite O(N) linear scan (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 126 | `NEGATIVE_EVIDENCE.md:888` — 2026-06-22 NO-GAP: full readdir of a large dir is O(N), NOT O(N²) — snapshot cache works (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 127 | `NEGATIVE_EVIDENCE.md:892` — 2026-06-22 GAP FOUND (load-blocked): readdir inode-table prefetch rayon coordination dominates htree-dir readdir (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 128 | `NEGATIVE_EVIDENCE.md:908` — 2026-06-22 NO-GAP: with-stat metadata walk (ls -l) — frankenfs FASTER than kernel readdir, even (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 129 | `NEGATIVE_EVIDENCE.md:928` — 2026-06-22 ROOT-CAUSE (load-blocked, correctness-critical): create O(N²) is the negative-lookup linear-scan fallback (bd-f8rd8) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 130 | `NEGATIVE_EVIDENCE.md:936` — 2026-06-22 create-bench now PERSISTS + create-path on-disk correctness validated by kernel mount (bd-c2bvq) (CrimsonFox cc/opus) | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 131 | `NEGATIVE_EVIDENCE.md:956` — 2026-06-22 MEASURED + root-caused: rename O(N^2) is the htree REBUILD-on-full-leaf, NOT the removal scan (bd-rename-rebuild) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 132 | `NEGATIVE_EVIDENCE.md:960` — 2026-06-22 bd-8ch29: htree incremental leaf split IMPLEMENTED + VALIDATED CORRECT but REVERTED (wall-neutral — rebuild was never the bottleneck) (Crim | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 133 | `NEGATIVE_EVIDENCE.md:980` — 2026-06-22 FINDING: read_block_vec uncached → 26x redundant preads of read-only htree index per metadata op (filed read-cache lever) (CrimsonFox cc/op | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 134 | `NEGATIVE_EVIDENCE.md:984` — 2026-06-22 bd-9e810 REFINED: the read-cache must be a POST-OVERLAY pread-cache (validation/hook-keying both inert) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 135 | `NEGATIVE_EVIDENCE.md:1032` — 2026-06-23 bd-bhh0i GDT-deferral identified as priority continuation candidate (measurement tooling-blocked) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 136 | `NEGATIVE_EVIDENCE.md:1048` — 2026-06-23 PRECISION + coverage-complete: write-bench is overlay-only (fast-path); durable write decomposes to characterized components (CrimsonFox cc | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 137 | `NEGATIVE_EVIDENCE.md:1052` — 2026-06-24 bd-bhh0i RESOLVED (measured, escaped the prior tooling block): GDT-write deferral is only 4-8% single-thread — REFUTED as a delete/rmdir le | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 138 | `NEGATIVE_EVIDENCE.md:1074` — 2026-06-24 BLOCKER + 5 contained micro-levers REFUTED by code evidence — single-thread metadata-write frontier is structurally exhausted (CrimsonFox c | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 139 | `NEGATIVE_EVIDENCE.md:1092` — 2026-06-24 bd-dedupcmp REFUTED (measured ~0-gain): per-commit MVCC dedup memcmp is NOT a metadata-write cost (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 140 | `NEGATIVE_EVIDENCE.md:1102` — 2026-06-24 bd-rdcache: writable-mode base-block cache — 47x pread reduction MEASURED but REVERTED (htree-incoherent; needs write-invalidation) (Crimso | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 141 | `NEGATIVE_EVIDENCE.md:1112` — 2026-06-24 bd-rdcache CLOSED: the 47x pread reduction was a STALE-SERVING ARTIFACT — coherent version is ~0-gain (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 142 | `NEGATIVE_EVIDENCE.md:1152` — 2026-06-24 bd-fbwrite REVERTED (~0-gain): full-block-write fast path is correct but wall-neutral (to_vec+commit dominate) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 143 | `NEGATIVE_EVIDENCE.md:1183` — 2026-06-24 bd-snaplock IMPLEMENTED + REVERTED (~0-gain): finer lock for snapshot register/release just moves the serialization point (corrects last tu | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 144 | `NEGATIVE_EVIDENCE.md:1274` — 2026-06-25 AUDIT (correctness, no fix needed): peer's `5f266067` ext4 base-device cache AVOIDS the bd-rdcache htree trap (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 145 | `NEGATIVE_EVIDENCE.md:1297` — 2026-06-25 Interleaved ext4 READ completes the scorecard: ~1.85x faster than kernel dd-materialize (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 146 | `NEGATIVE_EVIDENCE.md:1318` — 2026-06-25 REFUTED lever: no redundant copy on the ext4 4K-write version-install path (floor confirmed) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 147 | `NEGATIVE_EVIDENCE.md:1339` — 2026-06-25 REFUTED lever (root-cause-verified): 4K-write memmove is diffuse, NOT chain-trim — commit confirmed floor (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 148 | `NEGATIVE_EVIDENCE.md:1343` — 2026-06-25 NEW dimension: ext4 random 4K read ~1.5x slower than kernel — pread-bound + inherent per-read overhead (no lever above noise) (CrimsonFox c | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 149 | `NEGATIVE_EVIDENCE.md:1365` — 2026-06-25 REFUTED lever: sequential overlay write does NOT coalesce — same as random, per-block-commit-bound (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 150 | `NEGATIVE_EVIDENCE.md:1377` — 2026-06-25 REJECTED: one-descent btrfs COW update — duplicate `find` removal is below noise (IvoryBirch codex/gpt-5) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 151 | `NEGATIVE_EVIDENCE.md:1551` — 2026-06-26 REJECTED: staged internal-node reuse for btrfs COW insert batches did not improve the multi-leaf batch shape (IvoryBirch codex/gpt-5) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 152 | `NEGATIVE_EVIDENCE.md:1577` — 2026-06-26 REJECTED: MVCC FCW preflight/apply fused merge map did not improve request-scope commit (IvoryBirch codex/gpt-5) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 153 | `NEGATIVE_EVIDENCE.md:1613` — 2026-06-26 RATIO vs kernel: parallel random read is at KERNEL PARITY (~5M IOPS, both) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 154 | `NEGATIVE_EVIDENCE.md:1624` — 2026-06-26 CONSOLIDATED frankenfs-vs-kernel scorecard (campaign close: every measured dimension in one table) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 155 | `NEGATIVE_EVIDENCE.md:1641` — 2026-06-25 NEXT-EFFORT DESIGN + lane-split proposal: ext4 MVCC commit sharding (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 156 | `NEGATIVE_EVIDENCE.md:1709` — 2026-06-25 RE-PROFILE: the ext4 4K-write "floor" is NOT a floor — ~39% is optimizable MVCC commit machinery (peer's lane) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 157 | `NEGATIVE_EVIDENCE.md:1725` — 2026-06-25 REJECT (implemented+measured): bd-cc-ebrbatch — batching the per-commit EBR retire is INERT (0.994x); the real lever is the per-commit regi | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 158 | `NEGATIVE_EVIDENCE.md:1735` — 2026-06-25 REJECT (implemented+tested): bd-cc-ebrhandle — caching the LocalHandle BREAKS reclamation (collect/retire bag desync) (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 159 | `NEGATIVE_EVIDENCE.md:1791` — 2026-06-26 DIG (non-conflicting crates) + re-measurement + blocker (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 160 | `NEGATIVE_EVIDENCE.md:1802` — 2026-06-26 REJECT (new lever investigated): RO-gated direct small-read — blocked by the TOCTOU read contract (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 161 | `NEGATIVE_EVIDENCE.md:1844` — 2026-06-26 REJECT (measured ~0-gain, reverted): contains_visible on the cacheability-check sites (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 162 | `NEGATIVE_EVIDENCE.md:1870` — 2026-06-26 REVERT + CORRECTION: FFS_MVCC_STORE=single toggle — the WIRED single store backpressures on create-heavy; Sharded default is JUSTIFIED (Cri | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 163 | `NEGATIVE_EVIDENCE.md:1897` — 2026-06-26 REVERT + REFINE: prune-driver is INERT — the GC watermark is pinned, not just un-driven (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 164 | `NEGATIVE_EVIDENCE.md:1965` — 2026-06-26 STRUCTURAL BLOCKER (sharp + actionable): every shippable lever's integration is in ffs-core/lib.rs, the wiring owner's continuously-dirty f | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 165 | `NEGATIVE_EVIDENCE.md:2007` — 2026-06-26 DISCIPLINED read A/B (reliable): frankenfs read ≈ kernel dd parity on this box (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 166 | `NEGATIVE_EVIDENCE.md:2441` — 2026-06-26 RETRACT 41f0c43f: btrfs walk 2x is a SUBVOLUME-resolution bug (ext2_saved shows main-subvol files), NOT DIR_ITEM+DIR_INDEX (CrimsonFox cc/o | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 167 | `NEGATIVE_EVIDENCE.md:2478` — 2026-06-26 Rename residual (post-land next gap): profile blocked by toolchain (libpanic_abort.rlib missing); residual = per-op MVCC commit / collect_e | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 168 | `NEGATIVE_EVIDENCE.md:2513` — 2026-06-26 DELETE size-sweep (dig for removal lever): FLAT O(log N), no lever — confirms MVCC-commit-bound (peers') (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 169 | `NEGATIVE_EVIDENCE.md:2573` — 2026-06-27 REFUTE (bd-bhh0i follow-up): `BlockBuf` allocation has NO malloc-arena convoy — thread-local block-buffer pooling would be inert (CrimsonFo | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 170 | `NEGATIVE_EVIDENCE.md:2663` — 2026-06-27 DIG (ffs-core lookup + ffs-mvcc, now clean) — no clean lever; + independent conformance validation of integrated HEAD (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 171 | `NEGATIVE_EVIDENCE.md:2745` — 2026-06-27 REFINE: the install ~4.4µs is FIXED (not store-growth) + a concrete contributor — per-write `AlignedVec` realign-copy (CrimsonFox cc/opus) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 172 | `NEGATIVE_EVIDENCE.md:2934` — 2026-06-28 ❌REFUTED (measured per-crate): reserved-set `to_vec`→`Arc` borrow in `try_alloc_safe` — `+3.5%` SLOWER on `batch_alloc/single_20x1` | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 173 | `NEGATIVE_EVIDENCE.md:2977` — 2026-06-28 CONVERGENCE: full single-thread ext4 metadata-op N-curve sweep — after the rename preflight fix, ALL ops are flat/O(N); remaining gaps are  | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 174 | `NEGATIVE_EVIDENCE.md:3024` — 2026-06-28 ⚠️CORRECTION to the prior "sequential write O(N²)" entry: pure OVERWRITE of a mapped file is FLAT (~4-5 µs/op, kernel parity) — the O(N²) w | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 175 | `NEGATIVE_EVIDENCE.md:3036` — 2026-06-28 SCOPE the sequential-allocation O(N²): severity is governed by write GRANULARITY — fine-grained 4 KiB alloc is 45.5x slower than 64 KiB for | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 176 | `NEGATIVE_EVIDENCE.md:3127` — 2026-06-28 bd-bhh0i parallel-commit PROFILE (definitive): futex/synchronization-bound, NO userspace hotspot — confirms the gap is inherent ordered-pub | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 177 | `NEGATIVE_EVIDENCE.md:3491` — 2026-06-29 IMPLEMENTED + correctness-tested, MEASUREMENT-BLOCKED in-window: lock-free in-order CommitPublicationGate fast path (bd-bhh0i parallel-writ | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 178 | `NEGATIVE_EVIDENCE.md:3501` — 2026-06-29 MEASURED 1.83x single-thread create BUT REVERTED — intra-op write batching corrupts the ext4 alloc bitmap (bd-bhh0i) — CrimsonFox cc/opus | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 179 | `NEGATIVE_EVIDENCE.md:3528` — 2026-06-29 (cont.) bd-bhh0i intra-op batching — corruption PINPOINTED: group-1 GDT free_blocks_count never persists under deferred commit (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 180 | `NEGATIVE_EVIDENCE.md:3560` — 2026-06-29 REFUTED: lock-free CommitPublicationGate fast path busy-spins under contention (bd-bhh0i) — CrimsonFox | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 181 | `NEGATIVE_EVIDENCE.md:3662` — 2026-06-29 REFUTED (2nd form): lock-free publication-gate fast path — CAS-once-no-retry still regresses parallel writes (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 182 | `NEGATIVE_EVIDENCE.md:3724` — 2026-06-29 DIG (profile sweep): metadata-write hot paths now flat post-2-wins; remaining levers owner-lane/covered/inherent (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 183 | `NEGATIVE_EVIDENCE.md:3733` — 2026-06-29 DIG (profile): the 5.5x parallel-create convoy is BLOCKING-bound, not CPU-bound — unifies the gate refutations (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 184 | `NEGATIVE_EVIDENCE.md:3774` — 2026-06-29 SURFACED BLOCKER: parallel random-read 3.3x lever scoped (ShardedCache Mutex→RwLock) but unmeasurable — rand-read data-fixture gap (Crimson | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 185 | `NEGATIVE_EVIDENCE.md:3823` — 2026-06-29 REFUTED (measured REGRESSION, shelved): batch ext4_create's inode-alloc writes into one MVCC txn — 0.92x single / 0.96x parallel (CrimsonFo | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 186 | `NEGATIVE_EVIDENCE.md:3835` — 2026-06-29 DIG (convoy closure): the parallel-write 5.5x is fundamental in-order-publication blocking — gate already optimal, all per-op approaches me | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 187 | `NEGATIVE_EVIDENCE.md:3859` — 2026-06-29 DIG: btrfs-rename node-pool primitive REFUTED a priori — MVCC version-retention defers frees past the mutation burst (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 188 | `NEGATIVE_EVIDENCE.md:3878` — 2026-06-29 REFUTED (measured NEUTRAL, shelved): convert `ShardedCache` shards from `Mutex<BTreeMap>` to `RwLock<BTreeMap>` to relieve same-key paralle | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 189 | `NEGATIVE_EVIDENCE.md:3908` — 2026-06-29 NEGATIVE (parity, no lever): standalone ext4 lookup is already at/above kernel — metadata per-op frontier confirmed exhausted (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 190 | `NEGATIVE_EVIDENCE.md:3941` — 2026-06-29 REFUTED (measured NEUTRAL, shelved): `write_block_owned` to elide the staging copy in MVCC block writes (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 191 | `NEGATIVE_EVIDENCE.md:3981` — 2026-06-29 REFUTED (test-gated, reverted): eager-free retired btrfs CoW nodes in `commit_retired_nodes` — retained nodes ARE read for previous-version | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 192 | `NEGATIVE_EVIDENCE.md:3999` — 2026-06-29 DIG (convoy, pinpointed at the source + path clarified): the blocker is `CommitPublicationGate::publish` condvar wait, NOT a store-level lo | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 193 | `NEGATIVE_EVIDENCE.md:4052` — 2026-06-29 REFUTED (measured NEUTRAL, shelved): btrfs node hot/cold split — degradation is heap/alloc pressure, not live-map ops (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 194 | `NEGATIVE_EVIDENCE.md:4068` — 2026-06-29 DIG (btrfs degradation, serialize-retired FORECLOSED a priori): node item data is already Arc-shared (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 195 | `NEGATIVE_EVIDENCE.md:4082` — 2026-06-29 CORRECTION (measured): the parallel-write convoy is per-commit GLOBAL-LOCK acquisition, NOT the publish-wait condvar (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 196 | `NEGATIVE_EVIDENCE.md:4239` — 2026-06-29 ★CONVOY GAP QUANTIFIED vs kernel: parallel create 3.7x SLOWER at 16t (frankenfs negative-scales, kernel positive-scales) — the top remainin | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 197 | `NEGATIVE_EVIDENCE.md:4284` — 2026-06-29 Convoy spec FINALIZED (diagnostic): inodes ARE spread → per-group sharding viable, but a residual block-189 conflict remains (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 198 | `NEGATIVE_EVIDENCE.md:4292` — 2026-06-29 Convoy locality hypothesis REFUTED: block allocator is already group-local (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 199 | `NEGATIVE_EVIDENCE.md:4298` — 2026-06-29 Convoy PRIZE SIZED (upper-bound bench): ~9x achievable, would beat kernel (CrimsonFox) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 200 | `NEGATIVE_EVIDENCE.md:6258` — 2026-07-12 (cont.) — CORRECTION to c068e705 item-1 (it's a NON-lever) + journal/lookup/write-staging floor-verified | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 201 | `NEGATIVE_EVIDENCE.md:6397` — 2026-07-12 (cont.) — owner GREENLIT local cutover, but the gate is dcg-BLOCKED for the agent | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 202 | `NEGATIVE_EVIDENCE.md:6526` — 2026-07-12 (cont.) — bd-eflng CORRECT fix DESIGNED (lock-free single-entry hot-inode cache); blocked: OliveCliff holds exclusive lib.rs reservation | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 203 | `NEGATIVE_EVIDENCE.md:6637` — 2026-07-13 (BlackThrush) — writeback unread-telemetry vein CLOSED: the `AtomicRootCommit` crash-point sibling of 9bd37150 is TEST-ONLY (no production  | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 204 | `progress/perf-negative-results.md:117` — bd-bhh0i cutover residual @30k REFINED — read-your-writes-vs-prune TOCTOU (partial fix) + a suspected sub-threshold write clobber (bd-kdmu4) - 2026-07 | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 205 | `progress/perf-negative-results.md:374` — Mounted read-path zero-copy re-probe — FUSE transport floor CONFIRMED with 3 fresh negative findings (bd-kdmu4) - 2026-07-23 (turn 5, REJECT) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 206 | `progress/perf-negative-results.md:893` — bd-bhh0i parallel-create cutover RUN LOCALLY — baseline convoys, inode-table merge-base bug FIXED+validated, block-bitmap FCW is the next gap (bd-bhh0 | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 207 | `progress/perf-negative-results.md:953` — Dirty-fsync O(G) group-descriptor rewrite is disk-barrier-masked (flat with group count) → REJECT dirty-group tracking - 2026-07-23 (bd-fsync-journal- | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 208 | `progress/perf-negative-results.md:1670` — inode-parse base-area bounds-check hoist: NEUTRAL, the `len < 128` guard already elides - 2026-07-14 (REJECT, benched) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 209 | `progress/perf-negative-results.md:1815` — Extent-meta double-walk REJECTED (already fast-pathed) + sharded `from_superblock` vein closed - 2026-07-14 (REJECT / BOUND, no code) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 210 | `progress/perf-negative-results.md:2036` — Read/commit-path candidate bounds (3 non-levers) - 2026-07-13 (REJECT / BOUND) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 211 | `progress/perf-negative-results.md:2071` — `mvcc` cache-line-isolate the read-hot shard_mask - 2026-07-13 (REJECT) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 212 | `progress/perf-negative-results.md:2138` — `active_snapshots` atomic-refcount (de-serialize per-write register/release) - 2026-07-13 (REJECT) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 213 | `progress/perf-negative-results.md:2180` — `mvcc-commit` wait-free fetch_add for commit-seq / txn-id allocators - 2026-07-13 (REJECT) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 214 | `progress/perf-negative-results.md:2338` — `bd-bhh0i` synthetic-counter scope correction - 2026-07-10 | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 215 | `progress/perf-negative-results.md:2470` — BOLD-VERIFY measured verdict - 2026-06-25 | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 216 | `progress/perf-negative-results.md:4460` — 2026-07-10 — ISA verdict (plain), SWAR-widen correction, and the workload-class gap matrix (bd-b9dug, BlackThrush/cc_ffs) | — | none recorded | — | yes | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 217 | `progress/perf-negative-results.md:4597` — 2026-07-22 — FUSE-MOUNTED multi-file read gap ISOLATED for the first time + per-thread-read-fd lever REJECTED (bd-kdmu4 / bd-zvn7r(b), cc) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 218 | `progress/perf-negative-results.md:4724` — 2026-07-22 — three non-KEEPs close the cheap-dispatch vein: metadata offload REJECT, readahead null, request-count null (bd-kdmu4, cc) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 219 | `progress/perf-negative-results.md:4777` — 2026-07-22 — NEUTRAL-REJECT: daemon-side async next-window prefetch is redundant with kernel image-file readahead (bd-kdmu4, cc) | — | none recorded | — | no | **VOID-NONULL** — A/B rejection with no A/A null control recorded |
| 220 | `NEGATIVE_EVIDENCE.md:17` — `bd-fsync-journal-latency-gap-ptp4x` — tmpfs-backed 2-group vs 128-group dirty-fsync retry / BronzeRabbit | 2.0111x | 1.1x | 16.65% | no | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 221 | `NEGATIVE_EVIDENCE.md:18` — `bd-opb6l` — mounted zero-byte small-file create storm / BronzeRabbit | 4.599x | recorded, unparsed | 5.43% | no | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 222 | `NEGATIVE_EVIDENCE.md:19` — `bd-mounted-xattr-workload-gap-fr6iq` — list-128 direct-wire admission retry / BronzeRabbit | 4.274x | 0.8628x | 25.24% | no | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 223 | `NEGATIVE_EVIDENCE.md:20` — `bd-fsync-journal-latency-gap-ptp4x` / `bd-opb6l` — tmpfs-backed dirty-fsync scaling retry and mounted small-file continuation / BronzeRabbit | — | recorded, unparsed | 5% | yes | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 224 | `NEGATIVE_EVIDENCE.md:23` — `bd-mounted-xattr-workload-gap-fr6iq` — list-24 direct wire encoding / BronzeRabbit | — | recorded, unparsed | 4.96% | yes | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 225 | `NEGATIVE_EVIDENCE.md:24` — `bd-mounted-xattr-workload-gap-fr6iq` — read-only repeated-xattr result cache / BronzeRabbit | — | recorded, unparsed | 5% | no | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 226 | `NEGATIVE_EVIDENCE.md:25` — `bd-fsync-journal-latency-gap-ptp4x` — clean-fsync parsed-GDT cache invalidation / BronzeRabbit | 1.0002x | recorded, unparsed | 5% | yes | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 227 | `NEGATIVE_EVIDENCE.md:26` — `bd-opb6l` — disjoint delete-checksum snapshot / BronzeRabbit | 1.012x | recorded, unparsed | 5% | yes | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 228 | `NEGATIVE_EVIDENCE.md:32` — `bd-mounted-xattr-workload-gap-fr6iq` — root-mounted xattr transport attribution / YellowPuma | 1.005x | 1.005x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 229 | `NEGATIVE_EVIDENCE.md:36` — `bd-btrfs-sys-chunk-prealloc-7opvs` — Btrfs system-chunk result preallocation / BlackThrush | 1.0349x | 1.0349x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 230 | `NEGATIVE_EVIDENCE.md:39` — `bd-6ares` — live-name fixed-header view / BlackThrush | 1.3559x | recorded, unparsed | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 231 | `NEGATIVE_EVIDENCE.md:40` — `bd-raw-errno-kind-fallback-5gmt3` — raw OS errno / synthetic `ErrorKind` fallback split / BlackThrush | 1.035x | 1.035x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 232 | `NEGATIVE_EVIDENCE.md:43` — `bd-errno-hot-cold-split-qko8d` — `FfsError::to_errno` hot/cold split / BlackThrush | — | recorded, unparsed | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 233 | `NEGATIVE_EVIDENCE.md:45` — `bd-5koeh` — Btrfs leaf header-size conversion hoist / BlackThrush | 1.105x | 1.029x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 234 | `NEGATIVE_EVIDENCE.md:48` — `bd-bhh0i` — JBD2 data-checksum sequence-prefix hoist / Codex | 1.067x | 1.067x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 235 | `NEGATIVE_EVIDENCE.md:49` — `bd-5koeh` — Btrfs snapshot-diff dual-map fusion / Codex | 1.024x | 1.024x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 236 | `NEGATIVE_EVIDENCE.md:50` — `bd-kdmu4` — aligned block-buffer used-prefix zeroing / Codex | 1.204x | 1.204x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 237 | `NEGATIVE_EVIDENCE.md:52` — `bd-bhh0i` — MVCC snapshot stable-min watermark publication / Codex | 1.278x | 1.278x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 238 | `NEGATIVE_EVIDENCE.md:56` — `bd-fsync-journal-latency-gap-ptp4x` — sparse WAL empty-buffer drain guard / Codex | 1.509x | 1.509x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 239 | `NEGATIVE_EVIDENCE.md:58` — `bd-5koeh` — Btrfs snapshot output exact capacity / Codex | 1.093x | 1.093x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 240 | `NEGATIVE_EVIDENCE.md:60` — `bd-fsync-journal-latency-gap-ptp4x` — exact-capacity WAL buffer aggregation / Codex | 1.037x | 1.037x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 241 | `NEGATIVE_EVIDENCE.md:62` — `bd-fsync-journal-latency-gap-ptp4x` — group-commit payload-accounting scan fusion / Codex | 1.25x | 1.25x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 242 | `NEGATIVE_EVIDENCE.md:63` — `bd-5koeh` — Btrfs leaf header-size conversion hoist / Codex | 1.029x | 0.998x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 243 | `NEGATIVE_EVIDENCE.md:75` — `bd-bhh0i` — ext4 direct-indirect truncate leaf guard elision / Codex | — | recorded, unparsed | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 244 | `NEGATIVE_EVIDENCE.md:76` — `bd-5koeh` — Btrfs leaf fixed-width item-table iteration / Codex | — | recorded, unparsed | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 245 | `NEGATIVE_EVIDENCE.md:80` — `bd-fsync-journal-latency-gap-ptp4x` — group-commit epoch-prefix partition / Codex | — | recorded, unparsed | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 246 | `NEGATIVE_EVIDENCE.md:81` — `bd-5koeh` — WAL commit-record zero-fill elision / Codex | — | recorded, unparsed | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 247 | `NEGATIVE_EVIDENCE.md:82` — `bd-kdmu4` — `ffs-block` cache-hit payload-clone elision / Codex | — | none recorded | — | no | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 248 | `NEGATIVE_EVIDENCE.md:84` — `bd-bhh0i` — extent-index insert parent reparse elision / Codex | — | recorded, unparsed | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 249 | `NEGATIVE_EVIDENCE.md:85` — `bd-bhh0i` — MVCC publication-prefix atomic store batching / Codex | 1.019x | 0.999x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 250 | `NEGATIVE_EVIDENCE.md:88` — `bd-opb6l` — ext4 htree leaf-split projection vectors / Codex | 1.186x | 1.186x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 251 | `NEGATIVE_EVIDENCE.md:91` — `bd-fsync-journal-latency-gap-ptp4x` — ext4 duplicate device-sync elision | 1.205x | 1.205x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 252 | `NEGATIVE_EVIDENCE.md:106` — perf / Codex — Btrfs send parsed `INODE_REF` name handoff | 1.057x | 1.057x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 253 | `NEGATIVE_EVIDENCE.md:109` — perf / Codex — JBD2 committed-sequence redundant post-set sort | 1.067x | 1.067x | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 254 | `NEGATIVE_EVIDENCE.md:115` — `bd-mounted-xattr-workload-gap-fr6iq` — full ext4 xattr result-vector direct construction / Codex (`OliveCliff`) | 1.196x | recorded, unparsed | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 255 | `NEGATIVE_EVIDENCE.md:178` — `bd-8ch29` / `bd-wurxc` / Codex (`cod_ffs`) | — | none recorded | — | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 256 | `NEGATIVE_EVIDENCE.md:194` — delbench-profile / BlackThrush | — | recorded, unparsed | — | no | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 257 | `NEGATIVE_EVIDENCE.md:325` — perf / BlackThrush | — | none recorded | 12.89% | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 258 | `NEGATIVE_EVIDENCE.md:349` — perf / BlackThrush | — | none recorded | — | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 259 | `NEGATIVE_EVIDENCE.md:357` — perf / BlackThrush | — | none recorded | — | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 260 | `NEGATIVE_EVIDENCE.md:358` — perf / BlackThrush | — | none recorded | 7.6% | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 261 | `NEGATIVE_EVIDENCE.md:363` — perf / BlackThrush | — | none recorded | — | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 262 | `NEGATIVE_EVIDENCE.md:364` — perf / BlackThrush | — | none recorded | — | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 263 | `NEGATIVE_EVIDENCE.md:542` — `bd-defgb` | — | none recorded | — | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 264 | `NEGATIVE_EVIDENCE.md:6315` — 2026-07-12 (cont.) — fresh-profile path is RCH-INFRA-BLOCKED; the real gap is loom-gated bd-bhh0i | — | none recorded | — | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 265 | `progress/perf-negative-results.md:255` — Mounted frontier continuation: three fresh profile-first REJECTs and one 128-group fsck blocker - 2026-07-24 (BronzeRabbit) | — | 1.1x | 25.24% | yes | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 266 | `progress/perf-negative-results.md:544` — Fsync, small-file, and mounted-xattr measured frontier is transport/architecture-only - 2026-07-23 (BLOCKED; bd-fsync-journal-latency-gap-ptp4x / bd-o | — | recorded, unparsed | 5% | no | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 267 | `progress/perf-negative-results.md:608` — List-24 direct xattr wire encoding does not clear the mounted transport floor - 2026-07-23 (REJECT; bd-mounted-xattr-workload-gap-fr6iq) | — | recorded, unparsed | 10% | yes | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 268 | `progress/perf-negative-results.md:674` — Read-only repeated-xattr result cache cannot address the mounted transport gap - 2026-07-23 (REJECT; bd-mounted-xattr-workload-gap-fr6iq) | — | recorded, unparsed | 5% | yes | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 269 | `progress/perf-negative-results.md:726` — Clean-fsync parsed-GDT cache invalidation is below the transport floor - 2026-07-23 (REJECT; bd-fsync-journal-latency-gap-ptp4x) | 1.0002x | recorded, unparsed | 5% | yes | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 270 | `progress/perf-negative-results.md:771` — Delete checksum-snapshot split is below the measured frontier - 2026-07-23 (REJECT; bd-opb6l) | 1.012x | recorded, unparsed | 15.92% | yes | **VALID-PROFILE** — profile-first rejection with a named frame + Amdahl ceiling |
| 271 | `progress/perf-negative-results.md:1049` — splice() zero-copy FUSE read reply — IMPLEMENTED, byte-identical, PERF-NEUTRAL → REJECT (bd-kdmu4 zero-copy read-path sub-lane) - 2026-07-23 | — | recorded, unparsed | — | yes | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 272 | `progress/perf-negative-results.md:1114` — REOPEN + VALIDATED: splice() FUSE read replies are SAFE (not unsafe-blocked); warm large-read is 67% copy-tax - 2026-07-23 (bd-kdmu4 zero-copy read-pa | 1.4x | recorded, unparsed | — | yes | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 273 | `progress/perf-negative-results.md:1294` — Shared-channel multiloop FUSE dispatch - 2026-07-22 (REJECT; bd-opb6l) | — | recorded, unparsed | — | yes | **VALID-AB** — A/B with a recorded null; effect inside the null |
| 274 | `progress/perf-negative-results.md:2567` — Gauntlet Release-Readiness Scorecard | 3.2x | none recorded | — | no | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 275 | `progress/perf-negative-results.md:3338` — 2026-07-10 — Cold-read WHY: ranked frame table (bd-5koeh follow-up, BlackThrush/cc_ffs) | 1.44x | none recorded | 0.1% | yes | **VALID-MECHANISM** — no A/A null, but refuted on a counted mechanism (instructions/cycles/syscalls/allocs unchanged) that does not need one |
| 276 | `progress/perf-negative-results.md:4412` — 2026-07-10 — ISA finding + bd-bhh0i doc coverage (no collision) (bd-b9dug, BlackThrush/cc_ffs) | — | 1.21x | — | yes | **VALID-AB** — A/B with a recorded null; effect inside the null |
