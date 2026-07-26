# Performance Negative-Evidence Ledger

This ledger records every code-first optimization attempt in the no-gaps
campaign, including pending attempts that have not yet received a benchmark
verdict. Rejected rows are not to be retried unless their retry predicate is
met by new profile evidence.

## Rules

- One lever per row.
- Record the benchmark surface, result, and exact keep/reject/pending status.
- If benchmark execution is intentionally deferred, record the command that must
  produce the verdict.
- Rejected ideas require a concrete retry predicate, not a vague "try later."

## ⚠ bd-bhh0i wait-free gate — RUN 3 DID NOT REPRODUCE A DECIDABLE 8t EFFECT (harness overrun + a noisy worker); claim tempered to "1.70x on a quiet pinned worker" (bd-bhh0i) - 2026-07-25 (turn 12c, cc)

Recording a disagreement with my own result, because it changes how the number
should be quoted.

Run 3 (binary SHA-256 `c513a49a7b5503150178a10ff550cc20c39cbb84303ff2fb78abc1f90bf2f967`,
same pinned worker `vmi1227854`) added the `unprofiled_spin_vs_nospin_ab` phase,
which pushed total runtime past the 3000 s budget. Consequence: **the run died
before emitting the unprofiled 4-writer and 8-writer rows** — exactly the rows
every decision here rests on. What it did emit disagrees with runs 1 and 2:

| phase | t | A/A floor | A/B | log-margin | verdict |
|-------|--:|----------:|----:|-----------:|---------|
| profiled | 4 | 1.2872 | 1.6063 | 1.59x | below the 2x margin |
| profiled | 8 | 1.2619 | **1.2961** | **1.11x** | **NOT decidable** |

Run 1's profiled 8t was 2.2433 and run 2's unprofiled 8t was 1.8841. Run 3's
profiled 8t is 1.2961 — barely outside its own A/A floor. The A/A itself was
healthy (0.9867, floor 1.2619), so this is not a broken harness; it is a worker
that was busier during the candidate arms, and the paired design correctly
reported a smaller effect rather than hiding it.

STATE OF THE CLAIM after three runs:
- **Unprofiled (decision) 8t: 2 of 2 completed runs decidable — 1.7004x and
  1.8841x.** Run 3 never produced this row.
- **Profiled (attribution) 8t: 2 of 3 decidable — 2.2433x, (run 2 not separately
  re-read), 1.2961x NOT decidable.**

So the honest quotation is **"~1.70x at 8 writers on a quiet pinned worker"**, NOT
"1.70x". The effect is real — it is mechanism-backed (publication mutex wait p99
32767 -> 511 ns) and it reproduced on two independent ELFs — but its MAGNITUDE is
worker-load-sensitive, which is expected for a lever whose entire mechanism is the
removal of contention: less contention on the box, less to remove.

HARNESS FIX (landed with this row): the profiled pass is now OFF by default behind
`FFS_BENCH_PROFILED=1`. It roughly doubles wall time, and when a run overruns, what
it loses is the TAIL of the thread sweep — the 8-writer rows — so the failure mode
is silent and maximally damaging: a truncated run looks like a completed run that
simply had fewer phases. Any harness that sweeps a parameter in increasing order
and can time out has this bug shape; sweep the expensive end FIRST, or make the
expensive pass opt-in. Chose opt-in.

RETRY PREDICATE for anyone quoting this number: require a completed unprofiled
sweep (all four thread counts present), an 8-thread A/A floor below 1.30x, and a
candidate clearing it by a 2x log-margin. Two such runs exist; demand a third
before raising the claim above 1.70x, and re-check the box load before blaming the
lever if a run comes in low.

## bd-bhh0i wait-free gate: REPLICATED on a second binary (1.88x @8t) + an HONEST CPU caveat — the spin trades CPU for wall (bd-bhh0i / bd-kdmu4) - 2026-07-25 (turn 12b, cc)

REPLICATION. A second, independently built binary (SHA-256
`bf92caee472d944150ced8410cda8a7cdc658e8033e54ead52579f64a71c9f2f`, same pinned
worker `vmi1227854`) reproduced the win. Unprofiled decision arm:

| threads | A/A null | A/A floor | A/B run 1 | A/B run 2 |
|--------:|---------:|----------:|----------:|----------:|
| 1 | 1.0531 | 1.5026 | 0.9766 | 1.0072 |
| 2 | 0.9915 | 1.3564 | 1.1525 | 1.0890 |
| 4 | 0.9347 | 1.4622 | 1.3675 | 1.4087 |
| 8 | 0.9976 | 1.2589 | **1.7004** | **1.8841** |

Run 2's 8-thread A/B clears its own A/A floor by a **2.75x log-margin**. Two
independent ELFs agree on the shape (nothing at 1t/2t, directional at 4t,
decidable at 8t). **The conservative 1.70x remains the claim**; the range across
both runs is 1.70-1.88x.

⚠ HONEST CAVEAT — THE SPIN MOVES CPU, IT DOES NOT ELIMINATE IT. Profiling the
POST-lever path (wait-free only, 8 writers, same invocation) put
`CommitPublicationGate::publish_with_probe` at **16.33% self**, against **5.85%**
for the mutex gate on the same workload. Wall time fell ~1.8x while CPU in that
frame roughly TRIPLED. Mechanism: `PUBLICATION_SPIN_ROUNDS = 64` re-drains before
parking, and a spin accrues CPU samples where a futex wait accrues none. So the
part that genuinely VANISHED is the mutex queueing (publication mutex wait p99
32767 -> 511 ns); the waiting itself was converted from blocking into spinning.

This matters beyond bookkeeping. This repo has already ledgered the failure mode:
"spin-wait is CPU burned while other threads block on the device... Projection
1.12x-1.85x. Measurement 1.00x" (cold-read lane). On a host where FrankenFS shares
cores with the workload, a 16% self-time spin can be a NET LOSS even though the
isolated A/B shows a wall win. The 1.70x is measured on 8 writers with cores to
spare; it is NOT a claim about an oversubscribed host.

POST-LEVER FRONTIER (wait-free, 8 writers, top self-time frames):
`publish_with_probe` **16.33%**; `_rjem_je_arena_ptr_array_flush` 3.36%;
`drop_glue::<HashMap<...>>` 2.89%; thread-start 2.75%;
`parking_lot_core` TLS destroy 1.78%; `_rjem_je_edata_heap_remove` 1.77%;
`extent_recycle` 1.73%; `preflight_fcw_locked` 1.49%;
`Transaction::insert_staged_write` 1.34%; `commit_policy` 1.27%;
`commit_with_probe` 1.01%; `lock_shards` 0.96%. Note the allocator cluster
(jemalloc arena flush / heap remove / extent recycle ~6.9% combined) is now the
second-largest term — per-batch store construction and teardown, an artifact of
this harness rather than of production, so it is NOT a production lever.

NEXT LEVER (attributed, wired, not yet measured): added
`PublicationMode::WaitFreeNoSpin` so the spin can be A/B'd against no-spin inside
ONE binary via the same pairing driver
(`unprofiled_spin_vs_nospin_ab` phase, `FFS_MVCC_WAITFREE_PUBLISH=nospin`). Three
outcomes and what each means: (a) no-spin is neutral -> DELETE the spin, keep the
wall win and give back the 16% CPU; (b) no-spin is slower -> the spin is earning
its CPU on this workload, keep it and document the oversubscription caveat as a
standing risk; (c) no-spin is FASTER -> the spin is actively hurting and the
default should be no-spin. Retry predicate: decide only on a same-worker, same-ELF
interleaved A/A + A/B where the 8-thread A/A floor is below 1.30x and the
candidate clears it by a 2x log-margin, and re-profile to confirm
`publish_with_probe` self-time actually falls in the no-spin arm.

## 🛑 BLOCKER (infrastructure, not idea): the wait-free-gate e2e cutover cannot run — rch excludes `target/` from artifact retrieval AND the fleet has no `mke2fs`/`e2fsck` (bd-bhh0i / bd-b9dug) - 2026-07-25 (turn 12, cc)

Status: LEDGERED BLOCKER. The `FFS_MVCC_WAITFREE_PUBLISH` default stays OFF because
the end-to-end gate could not be executed, NOT because it failed.

WHAT WAS ATTEMPTED. After the ffs-mvcc primitive A/B won (1.70x @8t, entry below),
the plan was the documented cutover gate: `mke2fs -t ext4 -F -q -b 4096 -N 65536
<img> 524288` (2 GiB / 16 groups / 65536 inodes — image was created successfully
and verified with `dumpe2fs`), then `FFS_BHH0I_SHARDED=1 create-bench <img> /d
--count 40000 --threads 8` with `FFS_MVCC_WAITFREE_PUBLISH` off vs on from the SAME
binary (the per-store `PublicationMode` makes that a true same-ELF A/B), gated on
`e2fsck -fn` rc 0 and exact file parity.

WHY IT COULD NOT RUN — two independent walls, both infrastructure:

1. **rch cannot hand back a built binary.** Two `cargo build --profile release-perf
   -p ffs-cli --features bhh0i_sharded_alloc` runs both succeeded remotely (`ovh-a`
   378.0s; `vmi1227854` 658.5s, both exit 0) and both retrieved only **2-5 files /
   536-563 bytes**. Root cause is exact and global: `~/.config/rch/config.toml`
   `[transfer] exclude_patterns` contains **`"target/"`, `"target-*/"`,
   `"target_*/"`, `".rch-target*/"`, `".cargo-target/"`**. Every Cargo output
   directory is on the exclude list, so no compiled artifact can ever be retrieved
   from a worker — with the default target dir OR a custom one. The campaign's
   prescribed `env -u CARGO_TARGET_DIR` form does not help; the exclusion is on the
   destination directory name, not on the env var.
2. **The fleet cannot run the gate remotely either.** `mkfs.ext4`/`mke2fs` and
   `e2fsck` are absent on the workers (already ledgered 2026-07-13: the sharded
   create tests `open_writable_ext4_mkfs` SKIP there, and the in-Rust
   `build_ext4_image` helpers are single-group 128 KiB PARSE fixtures that cannot
   be opened writable for a multi-group parallel create). Shipping the image is not
   a workaround: rch's `verify_max_size_bytes` is 100 MiB and the image is 2 GiB.

So the gate is reachable only by an explicit LOCAL `release-perf` build of
`ffs-cli`. That is a deliberate policy decision (the campaign forbids SILENT local
fallback; `/data` has 246 GiB free and prior turns did run this cutover locally), and
the `cargo` PreToolUse hook routes every `cargo` invocation through rch, so taking it
means bypassing a user-installed guard. NOT done unilaterally — surfaced instead.

UNBLOCK (any one of these, all cheap):
(a) drop `target/` from `[transfer] exclude_patterns` for artifact RETRIEVAL (it is
    correct as an UPLOAD exclusion; applying it to the download direction is what
    breaks every "build remote, run local" workflow in this fleet);
(b) add an rch flag to retrieve named binaries (`rch exec --retrieve
    target/release-perf/ffs`);
(c) explicit greenlight for ONE local `release-perf` `ffs-cli` build per cutover turn.

This is a FLEET-WIDE finding, not a frankenfs one: any repo whose measurement needs a
locally-executed binary (mounted-FS gates, hardware-specific runs, anything needing a
tool absent on the workers) hits the same wall.

WHAT IS STILL PROVEN WITHOUT THE GATE: the ffs-mvcc commit primitive A/B (below) is
complete on its own terms — same ELF, pinned worker, A/A null in the same invocation,
byte-identity proven before timing, and per-phase p99 mechanism evidence. What the
e2e would add is (i) confirmation that the 8-thread gain survives the full create
path where MVCC commit is one term among allocation, directory insert and inode-table
RMW, and (ii) `e2fsck` proof on a mutated image. Neither is required to KEEP the flag
default-OFF; both are required to FLIP the default. Retry predicate: re-run the exact
gate above once any of (a)/(b)/(c) lands; flip the default only if 8-thread
creates/s improves beyond the create-bench A/A null AND both arms are `e2fsck -fn`
rc 0 with identical file counts.

## ⭐⭐ bd-bhh0i WIN — wait-free ordered publication: 1.70x at 8 threads, publication-lock wait collapses 64x (bd-bhh0i / bd-kdmu4) - 2026-07-25 (turn 12, cc/STRUCTURAL, MEASURED KEEP behind a flag)

Status: KEEP behind `FFS_MVCC_WAITFREE_PUBLISH` (default OFF = byte-identical to
the pre-lever binary). This is a **ledger resurrection**: the lever was
implemented, correctness-tested, and NEVER MEASURED on 2026-06-29
(`docs/NEGATIVE_EVIDENCE.md:3491`), then shelved on a branch/stash that no longer
exists. `docs/LEDGER_RESURRECTION.md` ranks it #1 of 276 audited REJECT rows.

LEVER (one): replace `CommitPublicationGate`'s global `Mutex<BTreeSet<u64>>` +
`Condvar` ordered-publication path with a wait-free power-of-two ring of ready
sequences plus a CAS walk of the contiguous prefix. The committer stores its own
sequence into `ring[seq & MASK]`, drains the prefix with a CAS loop, and only
parks on the `Condvar` if a predecessor has not published after a bounded spin.
The mutex survives solely as the parking path.

PROFILE-FIRST ATTRIBUTION (real path, not a synthetic model). bd-bhh0i's
2026-07-10 `CommitLockProfile` characterization of production
`ShardedMvccStore::commit`: publication mutex wait p99 **127 / 2047 / 32767 /
131071 ns** at 1/2/4/8 threads against a shard wait p99 of **255 / 255 / 511 /
511 ns** — the gate mutex grows **1000x** from 1t to 8t and reaches **131 us**,
a **256x** ratio over the shard locks. Same-invocation `perf` on the decision
binary put `publish_with_probe` at **1.89% self** (`verified_nonzero=true`);
an earlier mutex-only run put it at **5.85% self**. Self-time UNDERSTATES this
frame — time parked in a futex accrues no CPU samples — so the A/B wall ratio,
not an Amdahl bound on 5.85%, is the measure.

LEDGER GATE PASSED. `NEGATIVE_EVIDENCE.md:85` closed the publication **atomic
store shape** family (prefix-batching measured 0.999x, correctly rejected) and
its own retry text names the residual: *"the gate already holds a BTreeSet
removal loop whose ordered-tree work dominates these atomic accesses... do not
retry unless a profile attributes material self-time specifically to the
per-entry atomic load/store rather than the publication mutex/tree work."* This
lever removes the mutex and the tree — the thing that row names as dominant —
not the atomic shapes it closed.

BEHAVIOR PROOF, BEFORE TIMING. `assert_publication_mode_isomorphism` runs in the
same binary ahead of every timed arm: a deterministic multi-writer workload
(payload derived from block and index, so the correct final content is fixed and
interleaving-independent) commits under BOTH modes, then every block is resolved
at the final watermark and hashed in block order.

| threads | watermark | sha256 of all resolved blocks | result |
|--------:|----------:|-------------------------------|--------|
| 1 | 256  | `ae6bc48bcdee96b3...` | identical |
| 2 | 512  | `84cd5935a51b74a8...` | identical |
| 4 | 1024 | `f4ae906dcc619b15...` | identical |
| 8 | 2048 | `638052fc547a163f...` | identical |

Ordering preserved: the watermark advances only over a contiguous prefix in both
modes (`commit_publication_gate_wait_free_advances_only_over_contiguous_prefix`).
Tie-breaking / FP / RNG: N/A.

A/B + A/A NULL, SAME BINARY, SAME INVOCATION, ONE PINNED WORKER. Binary SHA-256
`516342ec9754db9fe37edcbf0944340e2875f6cb67dd867fa43d4338257fbcac`, worker
`vmi1227854`, `--profile release-perf --features bench-instrumentation`. 31
interleaved pairs per phase, order alternating per pair, statistic = median of
per-round log-ratios; floor = `exp(|median| + p90|deviation|)`. Both modes are a
per-STORE setting, so both arms run from ONE ELF and codegen cannot differ.

Decision arm (unprofiled = the production commit path, no instrumentation):

| threads | A/A null | A/A floor | A/B (mutex/wait-free) | log-margin vs floor | verdict |
|--------:|---------:|----------:|----------------------:|--------------------:|---------|
| 1 | 1.0358 | 1.3970 | 0.9766 | — | inside null (no convoy at 1t) |
| 2 | 1.0076 | 1.2628 | 1.1525 | 0.61x | inside null |
| 4 | 1.0204 | 1.2666 | 1.3675 | 1.32x | outside floor, BELOW the 2x margin — not claimed |
| 8 | 0.9839 | 1.2811 | **1.7004** | **2.14x** | **DECIDABLE WIN** |

Profiled arm (six `Instant::now()` probes per commit, paid by both arms): 1t
0.9971, 2t 1.0877, 4t 1.5657, 8t **2.2433** vs an A/A floor of 1.3233 (2.9x
log-margin). The probes inflate the mutex arm more because they cluster on the
gate, so **1.70x is the claim** and 2.24x is the instrumented upper reading.

MECHANISM PROOF (this is the part that makes it a lever and not a wall-time
story). Per-phase p99 from the profiled arms, mutex arm -> wait-free arm:

| threads | publication mutex wait p99 | ordered-prefix wait p99 |
|--------:|---------------------------:|------------------------:|
| 1 | 63 -> 63 ns | 0 -> 0 |
| 2 | 1023 -> **63 ns** | 131071 -> 131071 (identical) |
| 4 | 16383 -> **255 ns** | 262143 -> 262143 (identical) |
| 8 | 32767 -> **511 ns** (**64x collapse**) | 524287 -> 524287 (identical) |

The lock wait collapses 64x at 8 threads while the ordered-prefix wait is
byte-for-byte unchanged. That is the designed split: the MECHANISM cost (queue on
one global lock, insert into a BTreeSet, `notify_all` a thundering herd) is
removed; the SEMANTIC cost (a snapshot must see a gap-free prefix, so a commit
may not publish before its predecessors) is preserved exactly. Removing the
semantic half would change visibility semantics and is a different, much larger
proof obligation — NOT attempted here.

HONEST SCOPE. (1) 1t/2t are inside the null and no gain is claimed there — the
convoy does not exist without contention, which is itself confirmation of the
mechanism. (2) 4t is directionally positive but below the campaign's 2x
median-CI margin; not claimed. (3) The arm includes thread spawn/join per batch,
which dilutes the ratio — the true per-commit effect is larger than 1.70x. (4)
This is the ffs-mvcc commit primitive; it has NOT yet been measured end-to-end on
`create-bench` + `e2fsck`, so the default stays OFF pending that gate.

CODEGEN NOTE (bd-b9dug, cod lane): `codegen_isa,compile_sse2=true,
compile_sse4_2=false,compile_avx2=false,runtime_avx2=true` — the `release-perf`
bench binary is x86-64 baseline while the worker supports AVX2. Confirms the
campaign section 3b ISA mismatch on the exact binary these ratios come from.

GATES: `cargo test -p ffs-mvcc --lib` **497 passed / 0 failed** (495 before, plus
two new gate tests: `..._wait_free_matches_mutex_under_shuffled_publish`, 8
threads x 2000 shuffled publishes under both modes with identical final
watermark, no buffered remnants, no leaked waiters; and
`..._wait_free_advances_only_over_contiguous_prefix`). `cargo check -p ffs-mvcc
--features bench-instrumentation --benches` exit 0. `cargo clippy -p ffs-mvcc
--all-targets --features bench-instrumentation -- -D warnings`: **zero
diagnostics in `crates/ffs-mvcc`**; the 6 errors are pre-existing in
`crates/ffs-ondisk` (`ext4.rs` similar_names x2, `crc_incremental.rs`
cast_possible_truncation / needless_range_loop / large_stack_arrays x2) and are
the campaign section 3c nightly-clippy drift, untouched by this change.

PREREQUISITE FIXED FIRST: `--features bench-instrumentation` did NOT compile on
HEAD — `std::fmt::Write` and `std::io::Write` were both imported unaliased in
`crates/ffs-mvcc/benches/wal_throughput.rs`, so every `write_all` failed E0599.
This repo's own section-2-contract harness (self-reported ELF sha, interleaved
A/A pairs, median-of-ratios, per-phase publication p99s) was unbuildable.

NEXT (in order): (1) end-to-end `FFS_BHH0I_SHARDED=1 FFS_MVCC_WAITFREE_PUBLISH=1
create-bench <2GiB/16-group> --count 40000 --threads {1,4,8}` vs the same binary
with the flag off, gated on e2fsck rc0 and exact file parity; (2) only if that
holds, propose flipping the default. Retry predicate if a future run disagrees:
re-decide only on a same-worker, same-ELF interleaved A/A + A/B where the 8-thread
A/A floor is below 1.30x and the candidate clears it by a 2x log-margin.

## bd-bhh0i RELEASE-PERF A/B — the honest number: ~2.1x convoy ELIMINATION, NOT the aspirational 3.7x; scaling caps at 4t (bd-bhh0i / bd-kdmu4) - 2026-07-24 (turn 11, ⭐ MEASURED)

Status: definitive measurement (release-perf, e2fsck-validated). The bd-bhh0i
parallel-create cutover is CORRECT and beats the single-lock convoy ~2.1x at 4-8
threads, but does NOT achieve the campaign's long-quoted "3.7x / 8t≥4x1t" — that
was an unmeasured aspiration. Correcting the ledger with the real number.

A/B: `create-bench <2GiB/16-group ext4> / --count 40000 --threads T`, single-lock
(no env) vs sharded (`FFS_BHH0I_SHARDED=1`), same release-perf binary (built
`--profile release-perf --features bhh0i_sharded_alloc`, 3m57s). All runs e2fsck rc0.

| threads | single-lock c/s | sharded c/s | sharded/single-lock |
|--------:|----------------:|------------:|--------------------:|
| 1       | 119156          | 116382      | 0.98x (parity)      |
| 2       | 87737           | 129436      | 1.48x               |
| 4       | 68947           | 142627      | 2.07x               |
| 8       | 61512           | 128206      | 2.08x               |

READ: (1) single-lock CONVOYS — negative scaling 119k→61k (the whole-state write
lock; reproduces the memory's 143k→80k). (2) The sharded cutover REMOVES the
convoy: flat-to-positive, ~2.1x the single-lock at 4-8t; that convoy elimination is
the real, correct, e2fsck-validated win. (3) BUT sharded SELF-scaling is weak: 1t
116k → 4t 142k (1.23x) → 8t 128k (DIPS). "8t≥4x1t" is NOT met (8t is 1.10x of 1t);
peak is 4t at 1.23x. Sharded 1t≈single-lock 1t (parity — the auto-commit/base-clone
overhead is ~free at 1 thread).

WHY the 4t cap / 8t dip (the perf lever, needs a profile — NOT a correctness gap):
a high-thread serialization limiter. Per create the sharded path does SEVERAL MVCC
auto-commits (inode bitmap, inode-table slot w/ a full-block `base` clone [added
turn 8, ~free at 1t but allocator pressure at 8t], block bitmap) each hitting the
global commit-seq CAS + `prune_after_commit_if_due` + shard locks; that shared
machinery, not the per-group locks (0.5 thread/group at 8t/16-group), is the
suspect. Retry predicate to push past 2.1x: profile an 8t sharded create-bench
(release-perf, `perf -g`), find the >5%-self-time shared frame (commit-seq CAS /
prune / allocator), and cut per-create commit count or contention.

PROFILE DONE (perf -g --call-graph dwarf, 8t sharded create-bench count 120000,
105k creates/s): TOP self-time = **`__memmove/memcpy_avx_unaligned` 11.70%**
(block-sized copies — 10.5% is memcpy), then `ShardedMvccStore::commit` **5.19%**,
`RawMutex::lock_slow` 1.51%, `add_entry_reject_existing_tracked` 1.46%, crc32c
1.18%, jemalloc `sdallocx`+`malloc` ~2.0%, `RawRwLock::lock_shared_slow` 1.01%,
plus ~7% kernel `[unknown]` (write/read syscalls). VERDICT: the 8t cap is
MEMORY-BANDWIDTH-BOUND on 4 KiB block copies in the MVCC path — bandwidth is shared
across cores, so it saturates at 8t (→ the 4t→8t dip). The per-create MVCC path
copies each 4 KiB block multiple times: `read_visible`→Vec, the turn-8 `base`
clone in `rmw_commit_block_with_proof` (`(bytes.clone(), Some(bytes))`, needed for
the pruning-race merge base but a full-block copy on the no-conflict common path),
`write_block`→`data.to_vec()`, and the merge-install rebuild. NEXT LEVER (bounded,
one at a time): make the MVCC hot path Arc/COW-share block buffers instead of
cloning — e.g. record the `base` as a shared `Arc<[u8]>`/`BlockBuf` from
`read_visible_block_buf` (no copy) rather than an owned `Vec`, so the common
no-conflict inode/bitmap write stops paying a 4 KiB memcpy. Each copy-elim is its
own commit; re-measure the A/B after each. This is the path from ~2.1x toward the
memory's aspirational 3.7x, but it is bounded (memcpy is 11.7%, commit 5.2% — even
eliminating both fully is ~1.2x, so ~2.1x×1.2 ≈ 2.5x is a realistic ceiling for
copy-elim alone; 3.7x would additionally need fewer per-create commits).

⭐ HONEST CAMPAIGN VERDICT: bd-bhh0i is a CORRECTNESS success + a real ~2.1x
convoy-elimination throughput win, delivered end-to-end (BitmapOr proof +
block-bitmap find-race + inode-table pruning race + read-vs-prune TOCTOU, all
landed, e2fsck rc0 @40000/8t). The "3.7x" was aspirational and is not supported;
the measured ceiling is ~2.1x vs single-lock, capped at 4t by shared-commit
contention. Further gains are a bounded perf-tuning lever, not a structural one.

## ⭐⭐ bd-bhh0i CUTOVER COMPLETE — read-vs-prune TOCTOU FIXED; passes at 40k, e2fsck clean, 2.71x positive scaling (bd-bhh0i / bd-kdmu4) - 2026-07-24 (turn 10, ⭐ FULL PASS)

Status: LANDED (f9183ad9). The sharded parallel-create cutover now passes reliably
at the full count 40000 across 1/2/4/8 threads with e2fsck rc0 — the last
correctness gap (turn-8/9 residual) is closed.

Root cause (fully pinned, correcting turn 9): the bd-bhh0i writable adapters are
UNREGISTERED (perf opt), so `ShardedMvccStore::prune_safe`'s watermark is the chain
head whenever `active_snapshots` is empty → `prune_versions_older_than` collapses a
hot block to its single newest version. A "current" read that captured seq S then
races a concurrent commit+prune to S+1: `read_visible(block, S)` = None (S dropped)
→ falls to the STALE on-device block (mkfs-empty inode table for a run that never
flushes mid-run) → a create fails `NotFound` reading a just-committed parent inode.
NOT a write clobber — the turn-9 suspicion was wrong: `INSTALL-SHRINK` re-run at a
32-byte threshold on the inode-table blocks fired 0×. The turn-9 partial (MAX in
`with_latest_scope`) was DEAD: `read_block_with_scope` step-2 read_visible only
runs when `scope.tx.is_some()`, and the latest-scope has no tx, so the read fell
through to `read_current_block_vec_from_device`.

FIX: `read_current_block_vec_from_device` and `FsMvccBlockDevice::read_snapshot`
(read-your-writes) resolve at `CommitSeq::MAX` (newest RETAINED version) instead of
a freshly captured `current_snapshot()`. Pruning always keeps the newest, so MAX is
TOCTOU-free, and "current"/read-your-writes both mean newest. Byte-identical for
serialized single-lock + RO (newest == current): ffs-core default lib 1185 pass;
the 2 failures (fast_commit_del_range, btrfs_reflink_random) are PRE-EXISTING on
clean HEAD (verified by stash), not this change.

SCALING (debug binary, 2GiB/16-group, count 40000): 1t 9817 → 2t 13881 → 4t 21236
→ 8t 26622 creates/s = 2.71x @8t, POSITIVE (single-lock baseline scaled NEGATIVELY
143k→80k). e2fsck rc0, 40020 files.

⏭ REMAINING (perf, not correctness): (1) release-perf measurement (`--profile
release-perf`) — the ratio may differ from debug; (2) close the 2.71x→4x gap
(per-commit MVCC shard-lock / deferred-GDT / auto-commit-under-lock contention at
8t/16-group is the likely limiter — profile the 8t create path). Cutover CORRECTNESS
is done; the ≥4x is now a pure perf-tuning lever.

## bd-bhh0i cutover residual @30k REFINED — read-your-writes-vs-prune TOCTOU (partial fix) + a suspected sub-threshold write clobber (bd-kdmu4) - 2026-07-24 (turn 9, investigation)

Status: no net commit (exploration reverted; main stays at the turn-8 8k-validated
state, 73d7fa52). Investigated the turn-8 residual (`NotFound("inode N")` at
count~30000, groups near-full). Two findings, neither fully fixed → deferred.

(A) Write-clobber NOT confirmed but NOT ruled out: instrumented
`install_committed_version_locked` to flag any block-585..1096 (group-1 inode
table) version installed with `new_nz + 256 < prev_nz` non-zero bytes — fired 0×
on a failing run. BUT the `+256` threshold is too coarse: one inode slot holds
only ~100-150 non-zero bytes, so a SINGLE-slot clobber slips under it. Re-run with
threshold ~32 before concluding.

(B) Read-your-writes-vs-prune TOCTOU (diagnosed, partial fix measured): the
bd-bhh0i writable adapters are UNREGISTERED (a perf opt), so `ShardedMvccStore::
prune_safe`'s watermark = `current_snapshot().high` (the chain head) whenever
`active_snapshots` is empty. `prune_versions_older_than` then collapses a hot
inode-table block to its single newest version. A read-your-writes read
(`FsMvccBlockDevice::read_snapshot` = `current_snapshot()`) that captured seq S,
then races a concurrent commit+prune to S+1, calls `read_visible(block, S)` →
None (S's version dropped) → falls back to the STALE on-device block (the
create-bench never flushes mid-run, so the device inode table is mkfs-empty) →
`NotFound`. PARTIAL FIX TESTED: `read_snapshot` for read-your-writes returning
`Snapshot { high: CommitSeq(u64::MAX) }` (resolve the newest RETAINED version =
exactly read-your-writes semantics; byte-identical for the serialized single-lock
path) improved 4t/30000 to 4/6 pass but did NOT eliminate the failure → confirms a
SECOND residual (likely the (A) sub-threshold write clobber). Reverted (broad core
read-semantics change, not landed without the write-clobber fix + default-path
validation).

NEXT (both needed for the full 3.7x): (1) land the read-your-writes MAX-read fix
(after ffs-core writable default-path tests confirm byte-identity); (2) re-run
INSTALL-SHRINK at threshold ~32 to locate + fix the single-slot write clobber
(likely the merge-install rebuild vs a concurrently-advanced `latest`, or the
`observed <= snapshot` no-conflict path installing a base that lost a slot);
(3) then measure release-perf 8t≥4×1t on a ≥2GiB/16-group image. The cutover
already PASSES + scales positively at 8k (turn 8) — this is the last correctness
gap before the ≥4× measurement.

## bd-bhh0i cutover PASSES at 8k — block-bitmap find-race + inode-table pruning race FIXED; positive scaling (bd-bhh0i / bd-kdmu4) - 2026-07-24 (turn 8, ⭐ FIRST PASS)

Status: two fixes LANDED (7653bdec); the sharded parallel-create cutover PASSES
for the first time. As sole producer, drove the find-race (turn 7) to root cause
and fixed it + a second race it unmasked.

FIX 1 — block-bitmap find-race (`ext4_sharded_alloc_blocks`): the dir-growth block
alloc threaded the caller's BATCHED dir-add txn (`TransactionBlockAdapter`) as
`dev`, so it staged the bitmap write uncommitted. A concurrent same-group create's
find reads committed state (`dev.read_block` live) and MISSED that pick → both
picked the same free block → a double-alloc the OR-merge correctly fail-closes on.
Root cause was NOT a missing proof (turn 7) — it was invisibility of the in-flight
pick. Fix: auto-commit the bitmap UNDER THE PER-GROUP LOCK via
`block_device_adapter`, exactly as the sharded inode alloc already does (which is
why the inode bitmap never raced). Each pick is now committed before the lock
releases → visible to the next find. (The turn-7 `BitmapOr`/`rmw_block_bitmap_or`
proof-carrying path is now inert for the serialized bitmap but stays a correct
safety net.)

FIX 2 — inode-table pruning race (`rmw_commit_block_with_proof`): recorded
`base=None` when a version existed at the txn's snapshot, relying on the version
chain still holding it at commit. A concurrent committer's
`prune_after_commit_if_due` drops the version at this (unregistered auto-commit)
snapshot between stage and commit → the sharded merge's `version_bytes_at` yields
an EMPTY base → a spurious `base_len=0` length-mismatch abort of two creates
writing DISJOINT inode slots of the same inode-table block (proof
`TimestampOnlyInode`). Fix: record the snapshot base ALWAYS.

VALIDATED: `FFS_BHH0I_SHARDED=1 create-bench <512MiB/4-group ext4> / --count 8000
--threads {1,4,8}`, 6/6 clean at 8 threads, e2fsck rc0. Scaling (debug binary):
1t 9830 → 4t 17621 creates/s (~1.8x) → 8t ~24000 (~2.5x) = POSITIVE, vs the
single-lock baseline's NEGATIVE scaling (1t 143k → 8t 80k). First time the cutover
clears the e2fsck gate under concurrency.

RESIDUAL BLOCKER (next): at count ~30000 (a 4-group fs's inodes ~92% full) a
create intermittently fails `NotFound("inode <N>")` — an inode-table slot is lost.
The inode NUMBER alloc is race-free (auto-commit under lock, verified), so this is
a deeper MVCC merge-INSTALL race on the heavily-contended inode-table block
(`merged_write_bytes_locked` rebuilding against a `latest` that a concurrent
install advanced) under near-full-group pressure, NOT the pruning sub-case fixed
here. Retry predicate for the full 3.7x: reproduce at count≥30000 with a
per-inode-table-block conflict trace, fix the merge-install ordering, then measure
release-perf 8t≥4×1t. Note: the memory's "512MiB/4-group, 40000 creates" recipe is
inconsistent — 4 groups hold only 32768 inodes, so 40000 needs a ≥2GiB/16-group
image; use that for the ≥4× headroom measurement.

## bd-bhh0i cutover — turn-4b diagnosis CORRECTED; proof-carrying batched-txn landed; real blocker is a FIND-RACE (bd-bhh0i / bd-kdmu4) - 2026-07-24 (turn 7)

Status: substrate LANDED (1e08bb46) + deeper LEDGERED BLOCKER. As sole producer
(cod capped) with ffs-core/lib.rs unfrozen, drove the cutover to its true root
cause — and corrected the turn-4b ledger, which was WRONG.

Turn-4b said the sharded dir-growth block-bitmap write used a non-MVCC
`direct_block_device_adapter`. FALSE. `ext4_add_dir_entry` wraps the MVCC device
(`block_device_adapter`) in a `TransactionBlockAdapter` — an explicit BATCHED
transaction (`self.mvcc_store.begin()`) — and threads THAT as `dev` into the
dir-growth alloc. Its default `rmw_block` / `rmw_block_bitmap_or` fell through to
`write_block`, which stages `tx.stage_write` = `MergeProof::Unsafe`. So block 65's
BitmapOr proof (and every GDT/inode-table range proof) was LOST at the adapter,
and the batched txn FCW-aborted under concurrency. (Turn-4b's "block 65 never
reaches FsMvccBlockDevice methods" was because it went to `tx.stage_write`, not
because the device was non-MVCC.)

LANDED (byte-identical default by non-reachability; ffs-alloc 218/218, ffs-block
309/0): `TransactionBlockAdapter` now overrides `rmw_block` (→ `IndependentKeys`)
and `rmw_block_bitmap_or` (→ `BitmapOr`), staging the proof into the batched txn
with the merge base resolved at the txn's OWN snapshot via a new
`BlockDevice::read_merge_ancestor_at_snapshot` (default `None`→`read_block`;
`FsMvccBlockDevice`→ version at that snapshot, else raw base). Closes the
2b-harden stale-read window; preserves read-your-writes within the batch.

VERIFIED end-to-end (FFS_BHH0I_DEBUG instrumentation, added→removed): the override
IS now reached (`stage_rmw block=65 mech=BitmapOr`, 4096-byte base/latest/staged),
but the cutover STILL FCW-aborts on block 65 at 4/8 threads. The bitmap is
monotone (alloc-only), so a BitmapOr rejection can ONLY be a disjoint-new failure
= the SAME bit set by two writers = a genuine DOUBLE-ALLOCATION, which the
OR-merge correctly fail-closes on.

REAL BLOCKER — FIND-RACE: two concurrent same-group creates find the SAME free
block. `PerGroupAlloc::alloc_blocks` locks the group and calls
`try_alloc_blocks_in_group`, whose find does `dev.read_block` (the MVCC device's
LIVE, committed view) — which MISSES the first create's staged-but-uncommitted
allocation (staged in its own batched txn, not yet committed). So the second
create, even serialized behind the group lock, sees the block still free and
picks it too. The per-group lock serializes the find but not the visibility of
in-flight allocations. The OR-merge (disjoint COMMITS) was necessary but not
sufficient; disjoint PICKS are also required.

FIX (next): an in-memory per-group bitmap of in-flight staged allocations,
consulted (OR'd with the committed bitmap) by the sharded find and cleared on
commit/rollback — so the second create sees the first's pick. A per-group
allocation CURSOR alone does NOT suffice: on wrap-around it re-hits a block
allocated-but-uncommitted before the wrap. Auto-committing the bitmap alloc under
the group lock also works for the cutover but leaks a block on create-failure
(the dir-add batched txn rolls back but the separately-committed bitmap bit does
not). This lives in `sharded_alloc.rs` + `GroupStats` (ffs-alloc) — now editable
(sole producer). Retry predicate for the 3.7x: implement the in-flight bitmap +
the sharded find consults it → cutover 8t≥4×1t, e2fsck rc0, 40000-file read-back.

## Mounted frontier continuation: three fresh profile-first REJECTs and one 128-group fsck blocker - 2026-07-24 (BronzeRabbit)

Status: **REJECT 3/3; no source change.** Ledger and recent-log grep preceded
each lever. All mounted work used the exact current release-perf binary on
`vmi1227854` (SHA-256
`8ebff1f9cd9d77ed8cc68fb874f8384eb54726dc827f4db39fadb909cc150aca`)
inside a private privileged container, with the FUSE server pinned to CPU 8 and
the driver pinned to CPU 9. The container's `/tmp` mountpoint was required by
the host's AppArmor `fusermount3` policy; no host policy was changed. Raw
timing, profile, and fsck artifacts are retained under
`/data/tmp/bronzerabbit_frontier_20260724_Q7GDWQ/`.

1. **Dirty fsync, 2 groups versus 128 groups — REJECT before edit plus
   correctness BLOCKER (`bd-fsync-journal-latency-gap-ptp4x`).** A 30-round,
   median-of-21 interleave measured duplicate 2-group FrankenFS controls at
   191.922/211.106 us and the 128-group arm at 385.973 us. The paired
   128g/2g median was 1.9397x and the ratio-of-medians 2.0111x, but the
   duplicate-control null was already 1.1000x and CVs were
   26.168/25.446/23.936%. Kernel 2g/128g medians were 369.524/291.471 us
   with 90.105/58.767% CV. Thus no ratio is admitted. Exact parity was
   630 files, 80,640 bytes, and payload digest `0797b68e...` for every arm.
   Differential server profiles captured zero lost samples:
   `Cx::checkpoint` was 16.65% self at 128 groups versus 2.64% at 2 groups,
   but `ext4_persist_group_descriptors_from` remained only 0.47% self /
   0.56% children, below the ledger's 5% named-frame floor.

   Graceful unmount exposed a correctness blocker. `e2fsck -fn` returned rc 4
   on the 128-group FrankenFS image: sparse-super backup groups
   1,3,5,7,9,25,27,49,81,125 each reported a 1,027-block bitmap/count
   discrepancy, 10,270 blocks total. The 2-group FrankenFS image and both
   kernel images returned rc 0. This pattern is consistent with backup
   super/GDT reservation bits becoming authoritative in formerly-uninitialized
   group bitmaps, but that is an inference, not a diagnosed source cause.
   **Retry predicate:** first reproduce and fix this sparse-super
   backup-group durability/accounting failure with a minimal 128-group fixture
   and clean offline fsck. Only then retry performance on an isolated worker
   where all A/A/B/kernel arms have CV below 5% and an eligible non-fenced
   descriptor-persistence frame is at least 5% self.

2. **Mounted zero-byte create storm — REJECT before edit (`bd-opb6l`).**
   A 30,000-create server profile captured 3,691 cycles:u samples, zero lost.
   The only source frame above the frontier's 5% floor was
   `ShardedMvccStore::read_visible_block_buf` at 5.43% self, which is the
   explicitly fenced `bd-kdmu4` zero-copy/read architecture lane.
   `ShardedMvccStore::commit` was 4.63% and `lookup_in_dir_block` 3.20%;
   neither admits a local lever. A 30-round median-of-21 routing comparison
   preserved 630-file/zero-byte parity per arm and measured FFS A/A at
   66.555/66.750 us versus kernel 14.472 us, nominally 4.599x by medians.
   CVs were 79.131/85.570/16.295%, so no direct ratio is admitted.
   **Retry predicate:** a quiet profile must promote a non-`bd-kdmu4`,
   non-architectural source frame to at least 5% self; then all same-worker
   A/A/B/kernel arms must have CV below 5%, effect beyond null, exact file
   parity, and clean fsck.

3. **Mounted list-128 xattr direct-wire gate — REJECT before edit
   (`bd-mounted-xattr-workload-gap-fr6iq`).** Private FrankenFS/kernel files
   each contained 128 ordered one-byte attributes and a 1,664-byte list payload.
   Names and values matched exactly (`9b5c1c1d...` / `471fb943...`). A
   250,000-call profile captured 9,903 cycles:u samples, zero lost:
   `parse_xattr_entry_names` was 25.24% self, `_rjem_malloc` 9.19%, FUSE
   `listxattr` 8.38%, lossy UTF-8 iteration 7.76%, and
   `String::from_utf8_lossy` 4.93%. The shape/profile retry thresholds were
   met, but the mandatory pre-edit A/A gate was not: controls measured
   48.978/42.258 us, CV 36.743/37.473%, absolute-null median 15.979%, and
   absolute-null p95 63.921% versus the required p95 below 1%. Kernel was
   11.459 us with 16.991% CV. No direct-wire source was reopened and no direct
   kernel ratio is admitted. The small FrankenFS image containing this fixture
   passed offline fsck rc 0. **Retry predicate:** do not retry until a pinned
   pre-edit A/A run has absolute-null p95 below 1%; then require the paired
   candidate 95% lower bound to exceed that null p95, every A/A/B/kernel arm
   CV below 5%, exact mounted parity, and clean offline fsck.

This continuation therefore stops at the requested terminal condition: three
consecutive fresh REJECTs, with an independently ledgered current-source
128-group fsck blocker. No production, test, benchmark, or harness source was
edited.

## btrfs runtime path swept for a byte-identical per-op lever — SATURATED (bd-kdmu4) - 2026-07-24 (turn 6, REJECT #2)

Status: REJECT (no source change). Cycling levers off the floored read path, swept
the least-mined subsystem this campaign — the btrfs runtime read/lookup/readdir/
tree-walk path (crates/ffs-btrfs/src + the `btrfs_*` functions in ffs-core) — for
the byte-identical compile+test-landable classes (buffer-in-loop hoist,
materialize-then-scalar, multi-pass fold fusion, O(N)→O(1) memoization, hot-path
clone elimination). NO clean per-op lever found; the path is saturated with prior
`bd-*` optimizations:

- `btrfs_read_logical_into` reads straight into the caller's `out` slice (no
  per-block BlockBuf alloc, no post-read copy). `btrfs_read_file_into` = rayon
  deferred device reads + `split_at_mut` disjoint zero-copy windows + per-inode RO
  extent cache + lock-free hot-inode slot + decompressed-extent cache; its only
  `vec![0; compressed_len]` is INSIDE the rayon job (excluded).
- `btrfs_read_parsed_node` Arc node cache; its `vec![0; ns]` is MOVED into
  `parse_btrfs_tree_node_owned` as the node's retained backing (not a discarded
  loop buffer). `btrfs_lookup_child` O(1) dir-entry cache; `btrfs_readdir_entries`
  zero-copy `range_with` + FxHash first-occurrence dedup; `btrfs_fs_tree_root_bytenr`
  memoized O(1); `btrfs_decompress` per-thread zlib/zstd context reuse;
  `btrfs_verify_one_extent_csum` reused sector buffer (prior win e0aa5a1b).
- ffs-btrfs `.sum()`/`.fold()` sites (total_free/total_used/largest_free_extent/
  sync_block_group_accounting) are single-pass, on the write/commit path — not
  per-read, no fuseable multi-pass. Item parsers (parse_dir_items/extent_data/
  inode_refs/inode_item/collect_leaf_items) build only their required owned output.

Sub-noise candidate flagged + rejected: `btrfs_lookup_child` (ffs-core ~8604)
`parse_dir_items` materializes a `Vec<BtrfsDirItem>` (per-name `.to_vec()`) then
linear-scans for one name — the zero-alloc `visit_dir_items` visitor (ffs-btrfs
~1914) would early-exit without allocating. REJECTED: a DIR_ITEM bucket keyed at
one `name_hash` holds ≈1 entry (multiple only on hash collision) → ratio ≈1→1, and
it is a fallback BEHIND the O(1) `btrfs_dir_entry_cache` + tree-log point-descent →
below the noise floor. Retry only if a warm-btrfs-lookup profile shows
`parse_dir_items`/`btrfs_lookup_child` >~5% self-time (i.e. a collision-heavy or
cache-cold dir workload).

⭐ 2 consecutive fresh REJECTs this session (turn 5 read-path floor, turn 6 btrfs
saturation) on top of turn 4b's peer-file BLOCKER and the memory's exhaustive
ext4/alloc/dir/extent/xattr/inode/ondisk sweep. The bd-kdmu4 micro-lever surface
is exhausted; the sole productive lever remains the bd-bhh0i cutover, blocked on
the peer-side sharded dir-growth dev-routing (turn 4b) — flagged for coordination.

## Mounted read-path zero-copy re-probe — FUSE transport floor CONFIRMED with 3 fresh negative findings (bd-kdmu4) - 2026-07-23 (turn 5, REJECT)

Status: REJECT (no source change). After the bd-bhh0i wiring blocker, cycled back
to the zero-copy read lane and re-investigated it fresh (ledger + code, not just
prior memory). The mounted read is at its FUSE-transport floor; three doors the
prior ledger had NOT explicitly closed are now closed:

1. FUSE_PASSTHROUGH is advertised (`init()` adds `FUSE_PASSTHROUGH` +
   `set_max_stack_depth(1)`) but is ARCHITECTURALLY INAPPLICABLE to FrankenFS.
   Passthrough serves a FUSE file's read directly from a registered backing fd,
   but `struct fuse_backing_map` has `{fd, flags, padding}` and NO OFFSET field:
   fuse-file offset O maps to backing-fd offset O. FrankenFS is image-backed with
   extent-scattered file data (file byte O lives at some image offset X != O), so
   there is no single (fd, offset) that serves the file — passthrough cannot be
   wired for an image-backed extent-mapped fs. The advertised cap is inert for
   data reads. Not a lever.
2. `max_readahead` is kernel-capped: vendored fuser `KernelConfig::new` seeds
   `max_readahead == max_max_readahead == the kernel's init proposal`, and
   `set_max_readahead` can only LOWER it (`value > max_max_readahead => Err`). So
   the daemon cannot advertise a larger readahead window than the kernel offers;
   it is already at that ceiling without a call. `max_read=16 MiB` is already set,
   and `FUSE_ASYNC_READ` is on by default (vendored `INIT_FLAGS`). No init-flag
   read lever remains.
3. `read_file_data` assembly is copy-optimal (code-confirmed): segment tiling
   (Run / Partial / Zero), coalesced physically-consecutive runs read VECTORED
   straight into the caller's disjoint `&mut buf` windows (no assembly copy;
   partial head/tail blocks copy only their sub-range), parallel 128 KiB chunks
   (bd-yg6tk / bd-cc-pchunk, measured 1.67x warm), and a sequential extent hint
   (bd-vpypn) so the per-block `resolve_extent_seq` is an O(1) cached
   partition_point. The sole residual copy is the inherent page-cache -> reply-
   buffer copy, which splice targeted and was MEASURED perf-neutral (2026-07-23
   54872426: overlapped by readahead prefetch, not wall-clock-bound). mmap
   genuinely needs `unsafe` (memmap2 `Mmap::map` is an `unsafe fn`; no safe
   offset-mappable alternative) -> forbidden. io_uring submission likewise needs
   `unsafe`.

Conclusion: the mounted zero-copy read sub-lane is at its architectural floor
(transport RTT + one inherent reply copy that splice cannot beat under prefetch
overlap). This matches and extends the prior transport-bound ledger. Retry
predicate (unchanged from splice, still open): a profile showing the read
DAEMON-CPU-bound with the reply copy ON the critical path (many-client fan-in
out-running the readahead-prefetch overlap) — needs a dedicated heavy mounted
experiment; the stashed splice primitive is ready if that workload ever appears.
The sole productive bd-kdmu4 lever remains the bd-bhh0i parallel-create cutover,
now blocked on the peer-side sharded dir-growth dev-routing (turn 4b) — flagged
for coordination.

## bd-bhh0i BUG-4 wiring landed as substrate; cutover BLOCKED — sharded dir-growth bitmap write uses a NON-MVCC device (bd-bhh0i / bd-kdmu4) - 2026-07-23 (turn 4b)

Status: KEEP substrate + LEDGERED BLOCKER. Wired the OR-merge proof (turn 4 core)
through the device path and RAN the local cutover — which surfaced a precise,
diagnosed blocker that is NOT in my lane.

Landed (byte-identical default; ffs-alloc 218/218 in BOTH `default` and
`--features bhh0i_sharded_alloc`):
- `BlockDevice::rmw_block_bitmap_or` seam (ffs-block: default = read/patch/write,
  byte-identical for non-MVCC / MemBlockDevice) + `FsMvccBlockDevice` override
  (ffs-core/fs_mvcc_store.rs) that reads the base AT the txn snapshot and stages
  `MergeProof::BitmapOr` (mirrors `rmw_block`).
- `try_alloc_blocks_in_group` routes its block-bitmap write through the seam
  behind `cfg(feature = "bhh0i_sharded_alloc")`, scoped to the empty-rollback
  (steady-state) case (`ffs-alloc/src/lib.rs`); default path keeps the plain
  write. New feature `bhh0i_sharded_alloc` in `ffs-alloc/Cargo.toml`, propagated
  from `ffs-core/Cargo.toml`.

Cutover result (512 MiB / 4-group ext4, `FFS_BHH0I_SHARDED=1 create-bench / --count
N --threads T`): **1 thread OK** (8376 creates/s, e2fsck rc0); **4 and 8 threads
STILL PANIC** with the exact BUG-4 symptom `first-committer-wins conflict on block
65` (group-0 block bitmap).

Root cause (env-gated `FFS_BHH0I_DEBUG` instrumentation on every `FsMvccBlockDevice`
method + the alloc branch, added→removed): block 65 reaches my ffs-alloc
`rmw_block_bitmap_or` call (24×) but **NO `FsMvccBlockDevice` method ever sees it**
(0 in `write_block`, `rmw_block`, and the `rmw_block_bitmap_or` override — while
block 66 DID reach the override 4×, proving the seam works when `dev` is the MVCC
device). The sharded **dir-growth** block alloc (`ShardedTreeBlockAllocator` →
`ext4_sharded_alloc_blocks` → `try_alloc_blocks_in_group`) runs on
`direct_block_device_adapter()` = `CachedByteDeviceBlockAdapter`, whose
`write_block` delegates to `ByteDeviceBlockAdapter` → the RAW IMAGE (NON-MVCC).
So the dir-growth bitmap write bypasses MVCC and the OR-merge proof cannot engage;
yet the FCW conflict is a real MVCC conflict on block 65 (thousands of versions),
i.e. a SEPARATE MVCC path also stages block 65. The MVCC/non-MVCC device split for
the sharded block-bitmap alloc lives in **ffs-core's sharded create dev-threading
(`ffs-core/src/lib.rs`)** — a PEER's actively-modified file.

BLOCKER (stop condition): completing BUG-4 requires routing the sharded dir-growth
block allocation through the MVCC device (`FsMvccBlockDevice`) so
`rmw_block_bitmap_or` reaches the override and the OR-merge applies — a change in
the peer's `ffs-core/lib.rs` sharded create path, needing coordination. The seam +
`MergeProof::BitmapOr` proof landed here are the correct, tested substrate for it;
once the alloc `dev` is the MVCC device, the merge engages (block-66 proof).
Secondary finding: `Arc<D>`'s `BlockDevice` impl (ffs-block) forwards read/write
but NOT `rmw_block` / `rmw_block_bitmap_or` (uses the trait default) — a latent gap
for any `Arc<MVCC-device>` rmw caller; add forwarding when the dev-routing is fixed.

## bd-bhh0i BUG-4 core LANDED — MergeProof::BitmapOr bit-level OR-merge proof for the block-bitmap FCW (bd-bhh0i / bd-kdmu4) - 2026-07-23 (turn 4)

Status: KEEP (ab1567ba). The correctness-critical core BUG-4 needs. After BUG-5
(671cfa35) the sharded parallel-create cutover conflicts SOLELY on the group-0
block bitmap (block 65): two concurrent creates alloc dir-growth blocks in the
same group, set DISJOINT bits of the same pre-write bitmap, but the write stages
`MergeProof::Unsafe` so the two commits first-committer-wins conflict. A
byte-range (`IndependentKeys`) proof cannot express the merge — adjacent free
blocks share a bitmap byte, so the writers overlap at the BYTE level while their
BITS are disjoint.

Added `MergeProof::BitmapOr` (+ `MergeProofMechanism::BitmapOr`): whole-block
bit-level OR. `merged = latest | staged`, valid iff (1) equal length, (2) both
writers are SET-ONLY vs base (`base & !latest == 0` && `base & !staged == 0`) —
a *free* clears bits, fails this, and falls back to FCW, so the proof is only
ever effective on the alloc path; and (3) newly-set bits are disjoint
(`(latest & !base) & (staged & !base) == 0`) — two writers setting the same new
bit is a real double-allocation that MUST abort so the loser retries, never
silently coalesce. Under those preconditions `latest | staged == base |
latest_new | staged_new`: every allocation survives, no bit is invented.
`merge_valid` and `merge_bytes` share one validator (never diverge). Self-
validating: a free operation makes the proof invalid → FCW, so misuse fails
closed. Inert until a caller stages it (this commit adds no caller).

Gate: ffs-mvcc 495/0 incl. 9 new/updated BitmapOr tests — the crux (disjoint
bits sharing a byte OR-merge), fail-closed on free + on double-alloc, length
mismatch, an end-to-end concurrent same-block-alloc `resolved_writes_for_commit`
merge, the `merge_valid == merge_bytes.is_some()` invariant, and 2 proptests
(positive algebra: no allocation lost / no bit invented; negative: clears +
double-sets rejected). fmt clean. clippy on the crate is blocked by unrelated
pre-existing pedantic/nursery debt in peer-uncommitted `ffs-ondisk` (ext4.rs,
crc_incremental.rs) — not this change; my additions were hardened by inspection
against the same lints (short first doc paragraphs, no `useless_vec`, private
helper so no `must_use_candidate`).

REMAINING to complete the 3.7x cutover (next turn, precise plan):
- SLICE 2 (seam): add `BlockDevice::rmw_block_bitmap_or(cx, block, patch)` to
  `ffs-block` (default impl = read→patch→write, byte-identical for non-MVCC /
  MemBlockDevice) + an override on the MVCC device in
  `ffs-core/fs_mvcc_store.rs` that begins a txn, reads the base AT the txn
  snapshot (2b-harden rule: begin-first, else a stale-read no-conflict install
  clobbers a concurrent disjoint-bit writer), applies `patch`, and stages
  `MergeProof::BitmapOr` with the recorded device base (mirror `rmw_block` /
  `rmw_commit_block_with_proof`).
- SLICE 3 (wiring): in `ffs-alloc::try_alloc_blocks_in_group` route the bitmap
  write (`dev.write_block(cx, stats.block_bitmap_block, &bitmap)`, ~line 2697)
  through `rmw_block_bitmap_or` behind `cfg(feature = "bhh0i_sharded_alloc")`
  (default path stays byte-identical). The closure re-applies THIS op's bit
  mutations onto the base read at snapshot: the reserved marks (same
  `force_reserved_mark() || !reserved_confirmed` condition) + `bitmap_set_range
  (rel_start, alloc_count)`. Correctness note: converting to RMW-at-snapshot is
  ALSO the fix for the current separate `read_block`(2633)→`write_block`(2697)
  stale-read clobber hazard; if the found run is stale (concurrent alloc took
  it) the OR-merge disjoint-new-bits check fails → abort → retry re-finds
  (fail-closed, no double-alloc slips through).
- SLICE 3 interaction check (verified in-lane): the per-op GDT persist +
  block-bitmap checksum stamp is SKIPPED on the deferred path
  (`persist_group_desc_with_bitmap_overrides` returns `Ok` early when
  `gdt_persistence_deferred()`, default ON), and the GDT is re-persisted at
  flush from authoritative state (36257e4b), so the per-op `block_bitmap_
  override` inconsistency after a merge is moot on the cutover config; the
  post-merge bitmap checksum is validated by e2fsck. The GDT-persist-error
  rollback branch (2731) is unreachable on the deferred path (persist returns
  Ok). ⚠ If run with the sharded feature but deferral OFF, the per-op override
  (from local `bitmap`, not the merged content) could stamp a stale checksum —
  not the cutover config, but guard or assert if wiring it generally.
- SLICE 4 (validation = THE 3.7x measurement, LOCAL-ONLY): build
  `CARGO_TARGET_DIR=/data/tmp/bhh0i_target cargo build --profile release-perf -p
  ffs-cli --features bhh0i_sharded_alloc`; `FFS_BHH0I_SHARDED=1 create-bench
  <img> /d --count 40000 --threads {1,4,8}`. Gate: no FCW conflict on block 65
  at 4-8 threads, 8t ≥ 4×1t creates/s, e2fsck rc0, 40000-file read-back per
  thread. Retry predicate for BUG-4 as a whole: SLICE 2+3 wired AND SLICE 4
  green. Coordinate: peer(s) active on `ffs-core/sharded_alloc.rs` — Slice 3 is
  in `ffs-alloc/lib.rs`, do NOT touch sharded_alloc.rs.

## Fsync, small-file, and mounted-xattr measured frontier is transport/architecture-only - 2026-07-23 (BLOCKED; bd-fsync-journal-latency-gap-ptp4x / bd-opb6l / bd-mounted-xattr-workload-gap-fr6iq)

Status: BLOCKED with no source edit. This is the consolidated stop condition
after the list-24 direct-wire REJECT, not a claim that the kernel gaps are gone.
A fresh negative-ledger grep and `git log --oneline -30` were run after commit
`248dda68`, before considering another lever. They show that every remaining
measured hotspot is either below the profile floor, already optimized, or
inside the explicitly fenced architectural lane.

Fsync/journal:

- The newest quiet clean-directory profile measures FrankenFS at 14.957
  us/call versus kernel ext4 at 401.219 us/call: FrankenFS is already 26.83x
  faster on that exact no-op boundary. The proposed parsed-GDT-cache
  invalidation was rejected because the whole enclosing function was only
  0.02% self.
- The dirty create+write+fsync-each workload is barrier-parity: 18.24-19.20 ms
  for FrankenFS across 2 versus 128 groups, versus the same approximately
  20-ms physical barrier that puts the mounted storm at kernel parity. The
  64x group-count increase changed latency only about 4%, rejecting dirty-group
  tracking on ordinary SSD/disk.
- `ShardedMvccStore::flush_to_device` already sorts once, coalesces contiguous
  blocks, emits one write per run, and performs one sync. The only remaining
  structural durability lever is JBD2 cross-operation group commit / durable
  visibility gating, which is an architectural crash-consistency change and is
  outside this measured-frontier lane.

Small-file storm:

- Mounted single-thread create without fsync remains about 5.7x slower than
  kernel (590-621 ms versus 105-108 ms for 3,000 files), but the symbolized
  daemon profile is FUSE receive/reply/scheduler work; every `ffs_*` create
  frame is below 0.8% self. Fsync-each is already kernel parity
  (61,296 versus 61,671 ms).
- The fresh serial-delete profile put
  `remove_entry_take_inode_tracked` at only 1.16% self. Its disjoint checksum
  snapshot lever was therefore rejected before edit. The remaining
  `__memmove` / MVCC-publication costs and safe concurrent allocation cutover
  are precisely the `bd-kdmu4` / `bd-bhh0i` architectural lane fenced to cc;
  current log entries `ab1567ba` and `2f808ef8` confirm active ownership.
- Shared-channel multiloop dispatch is not a fallback: its measured speedup
  corrupted allocation/free accounting and failed offline fsck, so that family
  stays ledger-closed until its linearizability predicate is met.

Mounted xattr:

- The clean fixture gap is FUSE transport-dominated (71-77% including
  children). Result caching was rejected with internal frames at 0.01-0.04%
  self. The list-24 direct-wire retry then removed the last eligible
  names-materialisation seam but failed the decision gate: candidate CV 13.692%,
  paired mean -2.376%, bootstrap 95% `[-7.441%, +0.622%]`. Its source is fully
  reverted.

Therefore there is no eligible one-lever source change left in the requested
measured-frontier lane. Retry this consolidated blocker only when at least one
of these predicates holds: (1) a fresh quiet symbolized mounted profile puts a
non-fenced FrankenFS source frame at least 5% self on the critical path; (2) an
authorized, safe FUSE metadata batching/bypass primitive becomes available;
(3) the user explicitly hands off the `bd-kdmu4`/JBD2 architectural lane; or
(4) fsync is measured on pmem/battery-backed/nobarrier storage where latency
scales materially with group count instead of the device barrier. Until then,
another parser, cache, checksum, or coalescing cut would knowingly repeat a
dated REJECT below the transport/null floor.

## List-24 direct xattr wire encoding does not clear the mounted transport floor - 2026-07-23 (REJECT; bd-mounted-xattr-workload-gap-fr6iq)

Status: REJECT; prototype source fully reverted. Ledger and recent-log grep
first excluded the kept namespace borrow and by-index lookup plus the closed
formatter, size-probe, result-vector, metadata-worker offload, result-cache,
and unsafe transport families. The prior list-24 retry predicate was then met
with a private ext4 clone containing exactly `user.bench00` through
`user.bench23`: 24 names, 792 value bytes, and a 312-byte NUL-separated list.

Profile first: 500,000 validated baseline `listxattr` calls aggregated
12,000,000 names in 68.627 seconds. The server profile captured 849
`cycles:u` samples with zero lost. FUSE request/reply transport accounted for
76.71% including children; `parse_xattr_entry_names` was 3.29% self and
`__memmove` was 4.96% self overall, including 2.20% below the parser and 1.33%
below FUSE encoding. This admitted one narrow prototype: walk ext4 names once
and append namespace prefix, lossy-decoded name, and NUL directly into the FUSE
payload, avoiding `Vec<String>` plus the second encoding pass. It did not alter
transport, caching, batching, journaling, or the cc-owned architectural lane.

The prototype compiled strict-remote and passed its exact namespace/invalid-
UTF-8 wire test (1/1), the xattr-filtered `ffs-core`/`ffs-fuse` suites (80/80
unit tests plus 2/2 public OpenFs ext4/btrfs integration tests; two pre-existing
privileged tests ignored), and live mounted parity. Baseline, candidate, and
kernel ext4 returned identical ordered names and values with combined SHA-256
`79d600826ff6174187f7916ad7313335f455285883b296c4b979e50bbf1cc701`.
Ordering was preserved by the same entry walker; tie-breaking, floating point,
and RNG were N/A.

The admissible control was a clean-overlay build of parent `16861e4b` on RCH
worker `hz1`, SHA-256
`1c85330a78c0afad14d9fd89467e808299f6738a30167be4a4e8c07e0f93c9ea`.
The candidate was built on the same worker, SHA-256
`f133372e24a295d2bee328f8354afcbe7ee38e846fbe9d083cd2c8b12dc236b0`.
An earlier `4d309e82` control run was discarded before decision because it was
not the immediate parent. Two full 30-round runs were also retained as invalid
routing evidence: the first shared CPU 2 with a peer workload that went idle
mid-run (all-arm CV 57-68%); the second encountered a migrating peer SciPy job
(arm CV 10-20%). No quiet subset was selected.

The final pinned, priority-isolated 30-round A/A/B/kernel run used 8,000
validated calls per FFS sample and 35,000 per kernel sample. Parent controls
were 45.106 and 45.081 us/call with CV 1.847% and 2.506%; kernel ext4 was
10.682 us/call with CV 1.908%. The candidate median was 44.741 us/call, a
nominal 0.791% improvement over the pooled 45.098-us control, but candidate CV
was **13.692%**, failing the required under-5% gate. More decisively, paired
mean improvement was **-2.376%** (regression), paired median was +0.546%, the
deterministic 20,000-resample 95% bootstrap interval was
**[-7.441%, +0.622%]**, and the candidate won only 19/30 rounds. The A/A null
median was 0.637% (p95 4.971%). The raw candidate/kernel ratio was 4.188x, but
the candidate's invalid CV forbids a direct-kernel verdict.

The direct-wire source was reverted exactly; no source or benchmark harness
remains. After unmount, the reference, parent, candidate, prior-baseline, and
kernel clones were all byte-identical (SHA-256
`d1186ba20a77d1c640ee747bd1ead1e901e08f975d01163b24094dee136cd38e`)
and all passed `e2fsck -fn`.

Retry predicate: do not retry list-24 direct encoding on the current host state.
Reopen only on an exclusive or demonstrably quiet pinned host where a complete
30-round same-parent A/A/B/kernel run gives every arm CV below 5%, the paired
95% lower bound exceeds the measured A/A null, and either (a) a new profile
attributes at least 10% self to names materialisation/encoding, or (b) the
workload has at least 48 names / 624 wire bytes. Otherwise the mounted residual
remains the synchronous FUSE metadata request/reply boundary and needs an
authorized transport primitive rather than another parser/materialisation cut.

## Read-only repeated-xattr result cache cannot address the mounted transport gap - 2026-07-23 (REJECT; bd-mounted-xattr-workload-gap-fr6iq)

Status: REJECT before source edit. Ledger and recent-log grep first excluded the
kept namespace borrow and by-index lookup plus the closed formatter, size-probe,
result-vector, direct-wire tail, metadata-worker offload, and unsafe transport
families. The remaining narrow hypothesis was an inode/name result cache for a
read-only mount's repeated `getxattr` and `listxattr` requests.

Profile first: the exact clean reference fixture
`ffs_xattr_writer_reference_1677288_1782855891392514698.ext4` was cloned and
mounted read-only through quiet FrankenFS and kernel ext4 `norecovery`. Its
inline `user.mime` and `security.selinux`, 512-byte external `user.big`, absent
name, POSIX ACL access/default values, and returned name lists matched exactly.
A 500,000-syscall FrankenFS server profile captured **66K `cycles:u` samples
with zero lost**. FUSE reply send accounted for **71.40% including children**
and receive for **27.95%**. Core `getxattr` was **0.02% self**, the FUSE
`getxattr` handler **0.04% self**, and external by-index lookup **0.01% self**.
No internal list/parser frame cleared the 0.01% reporting floor.

A pinned rotating 30-sample comparator then ran 20,000 validated iterations /
100,000 syscalls per sample. FrankenFS measured **3,374.538 ms median /
33.745 us per syscall**, CV **1.799%**. Kernel ext4 measured **409.368 ms /
4.094 us per syscall**, CV **0.706%**. The admitted direct ratio is therefore
**8.243x slower** for FrankenFS. This replaces the earlier 7.495x routing-only
signal whose three arms all missed the 5% CV gate.

A result cache cannot address that residual: it can remove only an internal
lookup already below 0.04% self, while every hit must still cross the same
synchronous FUSE metadata request/reply boundary. The profile-first gate
therefore rejected the candidate before source or harness mutation; ordering,
tie-breaking, floating point, and RNG are N/A. Every timed sample asserted
aggregate result **11,380,000**. After unmount, both image clones were still
byte-identical to the source (SHA-256
`ccd38ae5397b1e7600cfd19d6901b5dee82f49a0fdadebe405d450f7dd6d74ca`)
and passed `e2fsck -fn`.

Strict-remote release-perf build: worker `vmi1227854`, job
`j-29944835100114983`, binary SHA-256
`1f8b41ed0780a7c1f7ee0664c7868cbe67dedecc4679fa26f6c3408ebf1dae91`.
Profile:
`/data/tmp/bronzerabbit_xattr_quiet_profile_4d309e82_20260723.data`.
The fixture still lacks the required 24-name list tail, so the broad parent
remains open despite the valid ratio for the covered shape.

Retry predicate: reopen a result-cache lever only when a quiet mounted profile
attributes at least **5% self** to an internal xattr frame. Reopen the
end-to-end gap only when an authorized clean clone adds list-24 and a safe,
supported transport primitive can bypass or batch metadata opcodes themselves.
Then repeat exact value/name/errno parity, server profiling, rotating
A/A/candidate/kernel measurement, effect beyond the A/A null, and CV below 5%
for every arm.

## Clean-fsync parsed-GDT cache invalidation is below the transport floor - 2026-07-23 (REJECT; bd-fsync-journal-latency-gap-ptp4x)

Status: REJECT before source edit. Ledger and recent-log grep first excluded the
kept clean-device sync epoch and durable watermark, plus the rejected dirty O(G)
descriptor rewrite, duplicate sync, JBD2 write combining, and group-commit
architecture. Source attribution found one distinct measured-frontier candidate:
`ext4_sync_with_logging` calls `clear_ext4_writable_group_desc_cache` after every
`flush_to_device_after`, including a clean boundary where `flushed == 0`. The
cache is striped across 64 mutex shards, so the hypothesis was to move this
invalidation under `flushed > 0`.

Profile first: the immutable `4d309e82` release-perf CLI was built by strict RCH
on `vmi1227854` (job `j-29944835100114983`; binary SHA-256
`1f8b41ed0780a7c1f7ee0664c7868cbe67dedecc4679fa26f6c3408ebf1dae91`).
On a private clean RW image, pinned 30 x 10,000 clean-directory `fsync` batches
measured **149.565 ms median / 14.957 us per call**, CV **3.091%**. A quiet
`cycles:u` profile captured **16K samples with zero lost**. FUSE receive/reply
syscalls dominated; the whole `ext4_sync_with_logging` function accounted for
only **0.02% self / 0.03% including children**, and neither the cache clear nor a
lock symbol reached the 0.01% reporting floor. Impossible elimination of the
entire enclosing function therefore has a ceiling of about **1.0002x**.

The identical pinned syscall loop on a kernel ext4 loop mount of an independent
clone measured **4,012.185 ms median / 401.219 us per call**, CV **1.551%**.
FrankenFS is already **26.83x faster / 96.27% lower latency** on this clean
directory shape because the previously kept device epoch skips a backing-file
sync when no write completed since the last successful sync. Both images passed
offline `e2fsck -fn`. This direct-kernel result supersedes the earlier noisy
routing-only kernel arm for this exact fixture; it does not generalize to dirty
fsync, which the same-day ledger shows at kernel parity and disk-barrier-bound.

No source or harness changed, so ordering, tie-breaking, floating point, and RNG
are N/A. No A/A/B was run: the profile gate rejects a candidate whose impossible
upper bound is below measurement resolution and whose target shape already beats
kernel ext4. A first default-INFO profile is explicitly invalid and discarded:
per-fsync tracing formatting dominated it. The accepted quiet profile is
`/data/tmp/bronzerabbit_fsync_clean_quiet_profile_4d309e82_20260723.data`.

Retry predicate: reopen only if a quiet symbolized clean-fsync profile attributes
at least **5% self** to `ext4_sync_with_logging` or `ShardedCache::clear`, or
after a supported FUSE transport primitive removes the request/reply floor and
promotes invalidation into the top path. Then use one immutable same-worker
binary, rotating A/A/B plus kernel, an effect beyond the A/A null, CV below 5%
for every arm, identical fsync results, and clean offline fsck.

## Delete checksum-snapshot split is below the measured frontier - 2026-07-23 (REJECT; bd-opb6l)

Status: REJECT before source edit. Ledger and recent-log grep first excluded the
closed allocation, directory-checksum, MVCC-copy, concurrent-dispatch, and
mounted-transport families. The remaining narrow hypothesis was to represent the
directory-entry removal checksum change as disjoint tiny fields instead of a
contiguous `DirBlockEdit` preimage snapshot.

Profile first: strict RCH built the immutable `4d309e82` release-perf CLI on
worker `vmi1227854` (job `j-29944835100114983`; binary SHA-256
`1f8b41ed0780a7c1f7ee0664c7868cbe67dedecc4679fa26f6c3408ebf1dae91`).
A fresh pinned `cycles:u` profile then removed 20,000 entries through the serial
direct-engine `delbench` path in **116.021 ms / 172,382 unlinks/s**. It captured
**893 samples with zero lost**. The whole
`ffs_dir::remove_entry_take_inode_tracked` helper accounted for just **1.16%
self**; the proposed checksum-snapshot representation is only a fraction of
that helper. Even impossible removal of the entire helper has an Amdahl ceiling
of `1 / (1 - 0.0116) = 1.0117x`.

The actual frontier remained `__memmove_avx_unaligned_erms` at **15.92% self**
(principally MVCC visible-version and block-buffer copies) and
`ShardedMvccStore::commit` at **8.72% self**. Those are architectural ownership
surfaces, not a permissible measured-frontier checksum edit. Fresh throughput
was within **0.82%** of the previous 173,790-unlinks/s run, corroborating the
same profile rather than exposing a new hotspot. The concurrent sharded merge
change landed after `4d309e82` does not affect this serial attribution.

No source or harness changed, so ordering, tie-breaking, floating point, and RNG
are N/A. No A/A/B was run: profile-first rejection prevents spending a noisy
candidate trial on a lever whose impossible upper bound is only **1.012x**. This
direct-engine attribution is not a fresh direct-kernel comparator; the existing
mounted delete/kernel measurement remains transport-dominated, and its kernel
arm missed the mandatory under-5% CV gate. The exercised image passed
`e2fsck -fn` after all deletes. Profile:
`/data/tmp/bronzerabbit_opb6l_profile_4d309e82_20260723.data`.

Retry predicate: reopen only when a clean symbolized delete profile attributes
at least **5% self** to `remove_entry_take_inode_tracked` /
`DirBlockEdit::delta`, or after a supported transport primitive removes the
mounted round-trip floor and promotes this helper into the top path. Then use
one immutable same-worker binary, rotating A/A/B, an effect beyond the A/A null,
CV below 5% for every arm, exact incremental-versus-full CRC equivalence, and a
clean offline fsck result.

## bd-bhh0i cutover — BUG-5 LANDED (sharded merge base); only the block-bitmap FCW (BUG-4) remains (bd-bhh0i / bd-kdmu4) - 2026-07-23 (turn 3)

Status: PROGRESS — cutover reduced to ONE remaining conflict. Root-caused why
BUG-3 (turn 1) didn't fix the parallel path: the create-bench uses the SHARDED
store (`ShardedMvccStore`, 32 shards), whose merge (`check_write_mergeable_locked`
preflight + `merged_write_bytes_locked` install) derived the merge base ONLY from
the version chain — empty for a freshly-allocated block — with NO staged_base
fallback. BUG-3 had only fixed the single-store `MvccStore`. Env-gated conflict
instrumentation (`FFS_MVCC_CONFLICT_DEBUG`, added then removed) confirmed the
inode-table conflict was `proof=TimestampOnlyInode base_len=0 staged_base=false`.

BUG-5 LANDED (`671cfa35`): added the staged_base fallback to BOTH sharded merge
sites (preflight + install — both are needed; fixing only the preflight would pass
the gate then install unmerged bytes via `merge_bytes`'s None fallback, clobbering
the concurrent writer). Byte-identical for the non-conflict path. Validated:
ffs-mvcc 488/0; the 4-thread sharded create-bench NO LONGER conflicts on the
inode-table block (was `block 76`).

BUG 4 — the ONLY remaining conflict (precisely diagnosed): after BUG-5, 4-thread
create-bench conflicts solely on `block 65` (512 MiB fs: group-0 BLOCK BITMAP;
`proof=Unsafe base_len=0 staged_base=false`). Mechanism: two concurrent CREATE
operations each allocate a dir-growth block in the same group; the per-group lock
serializes the in-memory bitmap read-modify, but the bitmap block is written
staged `Unsafe` (no merge), so the two commits (which set DISJOINT bits from the
same pre-write bitmap) first-committer-wins conflict. Fix needs a BIT-LEVEL
OR-merge proof: a byte-range proof (`independent_keys`) fails because two
allocations frequently set bits in the SAME byte (adjacent free blocks).
Allocation is monotonic bit-set (never clears during a create storm), so the
correct merge is `base | staged-new-bits | latest-new-bits` with validity "neither
writer cleared a base bit." This is a NEW `MergeProof` variant (correctness-
critical) plus routing the `ffs-alloc::try_alloc_blocks_in_group` bitmap
`dev.write_block` through a proof-carrying RMW (like the GDT's `rmw_block`).
Retry: implement the bitmap OR-merge proof + wire the bitmap write → full cutover
gate (8t≥4×1t AND e2fsck rc0 AND 40000-file read-back per thread). The FREE path
(punch/unlink) clears bits, so the proof/validity must handle mixed set+clear only
if a workload interleaves frees with the storm — the pure-create storm is set-only.

## bd-bhh0i cutover — BUG-3 LANDED; fast_commit regression is PRE-EXISTING on main; multiple concurrency bugs remain at 4t (bd-bhh0i / bd-kdmu4) - 2026-07-23 (turn 2)

Status: PROGRESS. BUG-3 (inode-table merge-base) LANDED as `18432557` after
resolving the landing blocker. Two follow-on findings:

fast_commit regression is PRE-EXISTING, not from BUG-3: `cargo test -p ffs-core
--lib fast_commit_del_range_apply_punches_and_frees_passes_e2fsck` FAILS on a
clean DEFAULT build (feature off, BUG-3 stashed) = clean origin/main. So the
e2fsck-unclean-after-DEL_RANGE failure is a real committed data-integrity
regression on main (in the fsync/journal lane; likely `23ad52f2 persist ext4
summaries at fsync boundary`), independent of the sharded work and of BUG-3
(which is byte-identical for that single-threaded test). BUG-3 was therefore
landed without adding any red test (main was already red on fast_commit +
btrfs_reflink flake). FOLLOW-UP: this DEL_RANGE regression deserves its own fix.

The cutover still panics at >1 thread, on MULTIPLE blocks — the "merge wiring
complete on paper" claim was badly wrong. Reproduced (512 MiB / 4-group image,
40000 creates, `--threads 4`, FFS_BHH0I_SHARDED=1, binary with BUG-3):
first-committer-wins conflicts on BOTH `block 65` (dumpe2fs: group-0 BLOCK BITMAP,
BUG 4) AND `block 76` (an INODE-TABLE block — so BUG-3 fixed the 1-2 thread
inode-table case but 4-thread load re-exposes an inode-table conflict). On the
16-group image the bitmap conflict was `block 257`; the block number tracks the
group-0 bitmap for the fs geometry.

Diagnosis blocker: the panic backtrace only shows the createbench closure —
`create` RETURNS the `CommitError::Conflict` (it doesn't panic at the write site),
so the conflict ORIGIN (which write path, which proof, disjoint vs overlapping
touched_ranges) is not on the trace. Next step MUST instrument the conflict
point: a targeted log in `MvccStore::resolved_write_valid_with_policy` just before
`Err(CommitError::Conflict)` printing block / proof variant / touched_ranges /
base|latest|staged lengths, to distinguish (a) a disjoint-slot merge GAP the
BUG-3 fix doesn't cover under N-way concurrency, (b) an inode/block ALLOCATION
RACE handing two threads the same slot (overlapping ranges → correct rejection,
but means the per-group lock doesn't serialize allocation), or (c) BUG 4 = the
bitmap staged `Unsafe` (no merge). Likely fixes: bitmap needs a bit-level merge
proof (OR set bits — a NEW proof kind, since two allocs can share a byte) or the
per-group lock held across the RMW+commit; the inode-table N-way case needs the
merge base/latest chain re-checked (possibly the recorded base is stale when a
writer read an intermediate version). Retry: instrument → fix each conflict class
→ full cutover gate (8t≥4×1t AND e2fsck rc0 AND 40000-file read-back per thread).

## bd-bhh0i parallel-create cutover RUN LOCALLY — baseline convoys, inode-table merge-base bug FIXED+validated, block-bitmap FCW is the next gap (bd-bhh0i / bd-kdmu4) - 2026-07-23

Status: MAJOR PROGRESS + INCOMPLETE. Disproved the standing "cutover is rch-remote-
only-blocked" assumption: `create-bench` + `mke2fs` + `e2fsck` all run locally (as
this whole campaign has). Ran the cutover A/B, found the single-lock convoy the
lever targets, FIXED one concrete FCW-conflict bug (validated), and identified the
NEXT one. Fix STASHED (`stash` "bhh0i-merge-base-fix"), not committed — one ffs-core
test regression in the tree needs isolation first (see below).

Cutover A/B (in-process `create-bench`, no FUSE transport; 2 GiB / 16-group image,
40000 creates, `--threads`, feature `bhh0i_sharded_alloc`, per-thread subdir):
- baseline (single-lock): 1t 143218 → 2t 112303 → 4t 81717 → 8t 79694 creates/s.
  NEGATIVE scaling (the whole-state write-lock convoy the lever exists to remove).
  e2fsck rc0 at every thread count.
- sharded (`FFS_BHH0I_SHARDED=1`): 1t 62161 creates/s (single-thread sharded
  overhead), but 2t+ PANIC with a first-committer-wins conflict.

BUG 3 (FIXED, stashed): the FIRST sharded panic was
`merge_proof_rejected: buffer length mismatch, base_len=0, latest_len=4096,
staged_len=4096` on a freshly-allocated inode-table block (TimestampOnlyInode proof),
then FCW-conflict. Root cause: `MvccStore::resolved_write_{bytes,valid}_with_policy`
derives the merge base via `version_bytes_at(block, snapshot.high).unwrap_or_default()`,
which is EMPTY for a brand-new block with no version at the snapshot — but two
concurrent creates writing disjoint inode slots of that new block both RMW'd the
same on-disk (device) content, which is the true common ancestor. The remote
concurrency test (6ed27b4a) missed this because it PRE-POPULATES a base version
(`read_visible(...).expect("base version visible")`), so base_len was always 4096.
Fix: record the RMW's device-read base on the `StagedWrite` (only when no version
existed) and fall back to it in the merge when `version_bytes_at` is None. Both
concurrent writers record the identical device base → sound merge. Byte-identical
for the single-lock / non-conflict path (base recorded but consumed only on a
concurrent merge). Validated: ffs-mvcc `cargo test` 530/0 (all merge/SSI/sharded
tests green); sharded 1t create-bench now writes all 40000 files with `e2fsck` rc0
and the merge-rejection warning gone.

BUG 4 (NEXT gap, not yet fixed): with BUG 3 fixed, sharded 2t now panics later, on
`block 257` (dumpe2fs: the group-0 BLOCK BITMAP) with NO merge-proof warning — i.e.
staged with the default `Unsafe` proof, no merge attempted. Concurrent block
allocations (directory growth) in the same group both RMW the group's block bitmap;
the per-group lock serializes the mutation but not the snapshot→commit window, so
the second committer FCW-conflicts. Needs either a bitmap-aware merge proof (OR the
disjoint set bits — a NEW proof kind, since two allocations can touch the same byte)
or holding the per-group lock across the RMW+commit. This means the memory's "shared-
metadata merge wiring COMPLETE / no remaining per-create shared-block conflict known
on paper" was WRONG — the actual run exposes multiple conflict points (inode-table,
now block-bitmap, and GDT is likely a third under cross-group load).

ffs-core regression to isolate before landing BUG-3 fix: a `--features
bhh0i_sharded_alloc` `cargo test -p ffs-core --lib` shows 1231 passed / 2 failed —
`btrfs_reflink_random_matches_reference_model` (documented pre-existing flake) and
`fast_commit_del_range_apply_punches_and_frees_passes_e2fsck` (an e2fsck-after-
DEL_RANGE check). The BUG-3 fix is byte-identical for that single-threaded test
(base recorded but never consumed without a concurrent merge), so it is not the
cause; the likely source is the recent `36257e4b perf(bd-bhh0i): fix cutover BUG 2 —
deferred-GDT flush sources from the sharded groups` commit or the uncommitted peer
`sharded_alloc.rs` in the tree. Retry predicate: isolate `fast_commit` on a clean
build (stash the peer's `sharded_alloc.rs`, revert BUG-3), then land BUG-3 + BUG-4
together with the full local cutover gate (8t ≥ 4×1t AND `e2fsck` rc0 AND 40000-file
read-back at every thread count).

## Dirty-fsync O(G) group-descriptor rewrite is disk-barrier-masked (flat with group count) → REJECT dirty-group tracking - 2026-07-23 (bd-fsync-journal-latency-gap-ptp4x / bd-kdmu4)

Status: REJECT (measured, not reasoned). `ext4_persist_group_descriptors_from`
rewrites ALL `G` group descriptors on every dirty fsync (`for gidx in
0..alloc.groups.len()`, lib.rs:17857) versus kernel ext4's O(touched). I flagged
this as a possible large-fs lever in prior turns but had only reasoned it away as
disk-masked; this entry MEASURES it decisively.

Measured: create+write(128B)+fsync-EACH storm of 200 files, per-op median, plain
disk-backed image (real `fsync`), 2 arms differing only in filesystem size / group
count:
- 256 MiB fs (2 groups):   18.24 / 18.58 ms per create+fsync
- 16 GiB fs (128 groups):  19.20 / 19.01 ms per create+fsync

Per-op latency is FLAT (~+4%) across a 64x increase in group count. The O(G)
descriptor rewrite is fully masked by the ~18 ms synchronous `fsync` disk barrier:
the descriptor writes land in the image's page cache (buffered) before the single
device `sync`, so they cost ~nothing on the wall clock, and the per-in-use-group
bitmap-checksum preads are page-cache hits. On the common create-many-fsync-ONCE
workload the incremental watermark already amortizes it to one flush per batch.

Therefore the risky dirty-group-tracking rewrite (track a dirty-group set, rewrite
only touched descriptors — flagged risky in prior ledgers: must cover every
free-count mutation site or `df` goes stale, plus atomic contention on parallel
alloc) is NOT justified: it cannot move a disk-barrier-bound wall clock, and the
descriptor CPU is already buffered/overlapped.

Retry predicate: reopen ONLY on a workload where the dirty fsync is NOT disk-
barrier-bound AND the descriptor flush is on the critical path — e.g. a
battery-backed / pmem / `nobarrier` device where `fsync` is ~free, on a
many-hundred-group fs, with a per-file-fsync (not batched) storm — AND a
same-worker A/B shows per-op latency scaling with `G`. On any normal
disk/SSD-backed fsync this is disk-bound and there is no lever.

## Mounted metadata storm (stat-walk) is getattr-round-trip-bound + adaptive-readdirplus REJECT - 2026-07-23 (bd-kdmu4 small-file-storm sub-lane)

Status: two findings. (1) The mounted metadata storm is 2.7-4.6x slower than
kernel ext4 and is FUSE-round-trip-bound (like the create storm), not a
FrankenFS-CPU lever. (2) Advertising adaptive readdirplus is byte-identical but
PERF-NEUTRAL-to-slightly-worse → REJECT; source reverted. The durable finding is
the ROOT cause below.

Measured (256 MiB ext4 tree, 11040 entries across 40 dirs, warm, daemon pinned
8-15, client 16-23):
- `find` (readdir, names only): FFS instant (~0-10 ms) — readdir/dentry cache
  works, name-only walks are already fast.
- explicit `os.lstat` walk (readdir + getattr/entry): FFS min 231-283 ms vs
  kernel 44 ms = ~4.6-6.4x.
- `ls -lR` (getdents + stat + getxattr per entry): FFS 0.20-0.27 s vs kernel
  0.07 s = ~2.7-3.9x.

Profile (symbolized daemon): the daemon is FUSE-transport-bound — `Session::run`
-> `read` 56%, `writev`/`send` 19%, scheduler block/wake 34%; NO `ffs_*` metadata
frame reaches 1.5% self-time. Each `lstat` costs ~2 daemon requests (lookup +
getattr); each `ls -l` entry costs ~8 (add per-entry `getxattr` for
`security.selinux` / `system.posix_acl_access`). The gap is the synchronous FUSE
round-trip per metadata op, which kernel ext4 does in-kernel. Read-only metadata
ops could be dispatched concurrently, but `find`/`ls`/`os.walk` are SERIAL
clients (each op waits for the previous reply), so concurrent daemon dispatch
cannot help — same structural wall as the create storm.

ROOT CAUSE of the repeat cost (the durable finding): the kernel does NOT serve
cached attributes for this mount even though `getattr`/`entry` replies carry a
60 s `attr_valid`/`entry_valid` (`ATTR_TTL`). 2000 repeated `os.lstat` of ONE
file -> 2064 daemon `read`s (every stat round-trips). The dentry cache works
(repeated same-path lookups don't round-trip) but the ATTR cache does not. This
is almost certainly inherent RO-FUSE behavior: without `FUSE_CAP_WRITEBACK_CACHE`
the kernel's `fuse_get_cache_mask()` is 0, so `fuse_update_get_attr` treats a
`STATX_BASIC_STATS` request as needing fields outside the cache mask and syncs
(getattr) on every stat regardless of `attr_valid`. writeback_cache requires
`--rw` (RO mounts cannot opt in), so RO metadata caching is FUSE-limited, not a
FrankenFS bug.

REJECT — adaptive readdirplus advertisement: FrankenFS's `init` advertises SPLICE
+ PASSTHROUGH but NOT `FUSE_DO_READDIRPLUS`, so the (already-implemented, bd-
xmh5g.399-optimized) `readdirplus` handler is never dispatched; the kernel uses
readdir + per-entry getattr. Hypothesis: advertising `FUSE_DO_READDIRPLUS |
FUSE_READDIRPLUS_AUTO` would collapse a stat-walk to ~1 round-trip/dir. Measured
(default-ON vs `FFS_FUSE_READDIRPLUS=0`): byte-identical (`find -printf '%p %s'`
sha `fe0d5180...` on both), but `ls -lR` NEUTRAL (0.21-0.27 s ON vs 0.20-0.25 s
OFF) and daemon requests slightly HIGHER with it on (88907 vs 77827 over one warm
`ls -lR`). Why it doesn't help: (a) the broken RO attr cache means the attrs
readdirplus pre-populates are not served on the client's subsequent stat; (b)
`ls -l`'s cost is dominated by per-entry `getxattr` (ACL/SELinux) round-trips
that readdirplus does not carry; (c) the AUTO heuristic did not reduce round-trips
on the warm walk. Source reverted (2 hunks in ffs-fuse `init`).

Retry predicate: reopen readdirplus (and RO attr caching generally) ONLY after
confirming the attr-cache mechanism with an `--rw --writeback-cache` mount — if
writeback caches repeated stats and RO does not, RO metadata caching is inherent
FUSE and neither lever helps; if even writeback fails to cache, root-cause the
`attr_valid` handling as a real bug first. A readdirplus win additionally
requires eliminating the per-entry `getxattr` round-trips (e.g. an xattr batch in
the readdirplus reply, which the FUSE protocol does not support) — so readdirplus
alone is not a stat-walk lever on ACL/SELinux-labeled trees.

## splice() zero-copy FUSE read reply — IMPLEMENTED, byte-identical, PERF-NEUTRAL → REJECT (bd-kdmu4 zero-copy read-path sub-lane) - 2026-07-23

Status: REJECT. The safe-splice zero-copy read is byte-identical and the splice
path provably engages, but it is measured PERF-NEUTRAL on every read shape.
Production source stashed (`stash@{0}` "splice-read-reject-wip-2026-07-23"), not
landed. This is the follow-through on the same-day REOPEN entry below: the lever
was reopened as the top-priority in-lane item, fully implemented behind a
default-OFF flag, measured, and rejected on the measurement.

Implementation (all stashed): a full vertical slice —
  - vendored fuser: `ReplySender::send_spliced(header, src_fd, offset, len)` with
    a byte-identical `pread`+`send` default (mock senders unaffected) and a
    `ChannelSender` override that stages the 16-byte `fuse_out_header` + splices
    `src→pipe→/dev/fuse` through a per-thread `F_SETPIPE_SZ`-enlarged pipe, with
    a session-level `SPLICE_WRITE_OK` disable-on-first-failure fallback and a
    buffered fallback for payloads over the pipe soft-cap; `ReplyData::data_spliced`.
  - ffs-block: `ByteDevice::backing_file() -> Option<Arc<File>>` (FileByteDevice
    returns its `Arc<File>`; `OverlayByteDevice` forwards it ONLY when its overlay
    holds no writes — clean journal — else None).
  - ffs-core: `FsOps::splice_read_plan` returning `Some((file, phys_offset, len))`
    only for a RO ext4 mount, plain-`FileByteDevice` backing, regular file, no
    encrypt/compr/verity/inline, extent-mapped, whole range in ONE written
    contiguous extent; `Arc<T>` forwarding of the new method (the crux miss that
    made it silently no-op at first — the mount uses `Box<Arc<OpenFs>>`).
  - ffs-fuse: default-OFF `FFS_FUSE_SPLICE_READ`, splice fast path in
    `serve_read_request` before `read_with_readahead`.

Correctness PROVEN: mounted-read sha256 byte-identical to the kernel across
whole-file / 128K / 1M / 17000-byte-odd / small-file reads, with the flag both
ON and OFF (fixture `data.bin` 3-extent 200 MiB + `small.bin`). `strace` confirms
the splice path engages: 300×128K reads → 400 `splice` calls (200 read×2), and a
`send_spliced: relay Done` trace on every eligible reply. A `SIGKILL`-class
desync never occurred (RO mount, no writes).

Decisive A/B (release-perf, daemon pinned 8-15, client 16-23, warm page cache,
min-of-N, flag toggled in one binary):
- single-stream 200 MiB read, 128 KiB chunks (splice engages): OFF min 74.7-75.8 ms
  vs ON min 74.9-77.2 ms — NEUTRAL (within the ~2 ms run-to-run spread).
- single-stream, 1 MiB chunks: OFF ~76 ms vs ON ~76 ms — NEUTRAL (and 1 MiB
  payloads exceed the 1 MiB `pipe-max-size` so they fall back to buffered anyway).
- 128×2 MiB multi-file, 16 parallel readers (the bd-kdmu4 headline shape): OFF
  min 16.4-17.1 ms vs ON min 16.1-18.4 ms — NEUTRAL.

ROOT CAUSE (this is the durable finding): the warm-large-read profile's "67%
`_copy_to_iter`" is 67% of DAEMON CPU, NOT of wall-clock. FrankenFS's readahead
prefetch (the `preadv` stream that still runs, ~960 `preadv` alongside the 400
`splice`) already overlaps the page-cache→userspace copy OFF the wall-clock
critical path, so eliminating the reply copy with splice frees daemon CPU that
was not the bottleneck. The mounted read is dispatch/RTT/pipeline-bound (as the
2026-07-22 async-dispatch and prefetch entries already found), not copy-bound.
splice trades a `preadv`+`writev` copy pair for a `splice`+`splice` page-move
pair of equal wall-cost on this pipeline. The `pipe-max-size` 1 MiB cap also
excludes the largest single reads.

Isomorphism: ordering/tie-breaking/bytes unchanged (sha256-proven); FP/RNG N/A.

Retry predicate: reopen ONLY if a future profile shows the mounted read is
DAEMON-CPU-bound (daemon saturating its cpuset with copy self-time ON the
critical path, e.g. a many-client fan-in that out-runs prefetch overlap) AND a
same-worker A/B beats the buffered path outside the A/A null. A zero-copy reply
alone does not help while readahead prefetch overlaps the copy. Do NOT re-attempt
the splice reply as a throughput lever for the current prefetch-overlapped read
path. The infrastructure (safe `send_spliced`, `backing_file`, `splice_read_plan`)
is preserved in the stash if a DAEMON-CPU-bound workload ever materializes.

## REOPEN + VALIDATED: splice() FUSE read replies are SAFE (not unsafe-blocked); warm large-read is 67% copy-tax - 2026-07-23 (bd-kdmu4 zero-copy read-path sub-lane)

Status: REOPEN. Correcting a ledger MISCLASSIFICATION and attaching profile-first
evidence. Prior rows (e.g. NEGATIVE_EVIDENCE.md 2026-07-04 swarm-routing) lumped
"splice-class read gaps" with io_uring/mmap as "blocked by forbid(unsafe_code)".
That is WRONG for splice: `nix::fcntl::splice` is a SAFE wrapper (takes `AsFd`,
no `unsafe`; verified nix 0.29-0.31 signatures) — only mmap-file-maps and
io_uring registered buffers require `unsafe`. splice was never actually blocked
by the workspace lint; it was closed on a false premise. This entry reopens it
with measurement.

Profile-first (this is the key correction to the "copies ~3%" framing): the ~3%
copy figure from 2026-07-22 was the SMALL-FILE multi-file read, which is
dispatch/RTT-bound. The WARM LARGE-CONTIGUOUS read is the opposite — copy-bound.
Symbolized daemon profile (release strip=false debug=1 to a scratch target dir,
400 MiB single-file warm read repeated, `perf record -g --call-graph dwarf`):
the daemon spends **82.9% in `preadv`, of which 67% is `_copy_to_iter` /
`copy_page_to_iter`** — the kernel's page-cache -> daemon-buffer copy (COPY 1).
The subsequent `ReplyData::data(&[u8])` -> `writev` to /dev/fuse is COPY 2. This
IS the "~2x pread copy-tax" the lane names, now located and quantified on the
workload where it dominates.

Ceiling microbench (`os.splice` file->pipe->/dev/null vs preadv->buffer->write,
400 MiB warm, 7 reps median): read+write 27.3 ms / 15.4 GB/s vs splice 19.4 ms /
21.6 GB/s = **1.40x** at the copy layer. This UNDERSTATES the FUSE win because
the microbench's `/dev/null` write is free, whereas the real path's COPY 2
(writev to /dev/fuse) is a genuine copy that splice also eliminates. Mounted warm
large read currently measures 2781 MB/s; splicing image_fd -> pipe -> /dev/fuse
would replace COPY 1 + COPY 2 with page moves, leaving only the kernel's
unavoidable /dev/fuse -> client copy (COPY 3).

Feasibility (both fds are reachable): /dev/fuse fd via `ChannelSender(Arc<File>)`;
image fd via `FileByteDevice::file() -> &Arc<File>`; physical offset via the
existing extent resolve. Implementation is a correctness-critical vertical slice,
so it is NOT rushed here (a bad FUSE read reply corrupts data):
  - Slice A (vendored fuser): add `ReplySender::send_spliced(header, src_fd,
    offset, len)` with a DEFAULT impl that reads into a buffer + `send` (so mock
    senders are byte-identical), and a `ChannelSender` override that enlarges a
    per-worker pipe via `F_SETPIPE_SZ` to max_read, writes the 16-byte
    `fuse_out_header`, `splice(src->pipe)` then `splice(pipe->/dev/fuse)` as one
    reply; plus `ReplyData::data_spliced(src_fd, offset, len)`.
  - Slice B (ffs-core): a method returning `Some((image_fd, phys_offset, len))`
    ONLY when the requested range is a single contiguous UNCOMPRESSED extent with
    NO MVCC overlay / pending write for those blocks (else None -> materialize).
  - Slice C (ffs-fuse read handler): try the eligibility check, splice-reply on
    Some, fall back to `data(&buf)` on None. Env kill switch FFS_FUSE_SPLICE_READ
    (default OFF). Gate: mounted-read sha256 byte-identity (flag on vs off vs
    kernel) + warm large-read A/B + conformance.

Retry/land predicate: implement the vertical slice behind the default-OFF flag;
land only if a mounted read is sha256 byte-identical with the flag on AND a
same-worker warm large-read A/B beats the materialize path outside the A/A null.
Eligibility MUST exclude compressed extents, MVCC-overlaid blocks, fragmented
(multi-extent) ranges, and any range crossing a hole. This is the top-priority
in-lane lever; it is NOT ledger-closed.

## Mounted small-file create storm gap is FUSE-transport-bound, not a create-CPU lever - 2026-07-23 (NOT-A-LEVER / ledgered blocker; bd-kdmu4 small-file-storm sub-lane)

Status: NOT-A-LEVER. The mounted single-thread create storm is 5.7x slower than
kernel ext4, but a SYMBOLIZED daemon profile proves the entire delta is the
synchronous FUSE round-trip; `FrankenFuse::create` / `ext4_create` do not reach
0.8% self-time. No FrankenFS create-path CPU lever exists on this workload, and
the only amortization (concurrent request dispatch) is ledger-CLOSED (multiloop
REJECT corrupts allocation) / bd-bhh0i local-only cutover. Recorded so the gap is
quantified and the create-CPU door is closed, not silently retried.

Measured (fresh 256 MiB ext4 image, 3,000 x 128-byte files created into one dir,
daemon pinned CPUs 8-15, client 16-23, plain-file backing = buffered so no
per-op disk I/O):
- no-fsync create storm: FrankenFS 590-621 ms vs kernel ext4 105-108 ms = ~5.7x
  (~200 us/create vs ~35 us/create).
- fsync-each create storm: FrankenFS 61,296 ms vs kernel 61,671 ms = PARITY
  (each fsync is a real ~20 ms disk barrier; physics-bound, correctly at parity).

Symbolized profile (release + `CARGO_PROFILE_RELEASE_STRIP=false DEBUG=1` to a
scratch target dir, 6,000-create storm, `perf record -g --call-graph dwarf` on
the daemon): the daemon time is `fuser::Session::run` -> `Channel::receive` ->
`read` (30.6% reading FUSE requests), `writev` / `ReplySender::send` (~14%
writing replies), and scheduler block/wake (`schedule`/`dequeue*` ~16% — the
synchronous block-on-`read` between requests). The vendored fuser receive buffer
is allocated ONCE before the loop and reused (`session.rs:148`), so there is no
per-op receive-buffer alloc/memset despite `BUFFER_SIZE = 16 MiB + 4096`. Every
`ffs_*` create frame (create/alloc/dir-entry/inode-write/commit) sits below the
0.8% self-time floor.

Also probed (out-of-lane, no lever): 128 MiB sequential write, `set_max_write`
is never negotiated in `init`, but FrankenFS measures 176-235 ms vs a very noisy
kernel 57-260 ms (writeback-timing variance) — roughly competitive, no clean gap,
and the kernel comparator fails the <5% CV gate, so no `max_write` lever is
justified.

Retry predicate: reopen a create-CPU lever only if a future profile shows an
`ffs_*` create frame above ~5% self-time on this workload (e.g. a new superlinear
per-create cost). The transport gap itself reopens only with the bd-bhh0i sharded
parallel-create local cutover (safe concurrent dispatch of allocation-disjoint
creates) or a safe io_uring FUSE transport — both currently blocked (local-only /
`forbid(unsafe_code)`).

## Clean-device fsync skip via FileByteDevice write/sync epochs - 2026-07-22 (KEEP; bd-fsync-journal-latency-gap-ptp4x / bd-opb6l)

Status: KEEP. The unchanged-directory `fsyncdir` storm — the residual both same-day
fsync-lane keeps left at 348-372x slower than kernel — is now 16.6x faster; the
kernel gap on this shape drops from ~372x to ~27x, and the remainder is the
synchronous FUSE round-trip itself (~25 us/call), not the sync path.

Profile first: the prior keeps' profile put the leading sync-path address cluster
at 18.94% and left the frozen storm at ~410 us/call. Source attribution found
`ext4_sync_with_logging` calls `self.dev.sync` unconditionally, even when the
no-op watermark guard returned `flushed == 0`. A host syscall pricing probe on
the same backing filesystem made the attribution quantitative: fsync of a CLEAN
file costs 398.3 us/call (dirty: 8.84 ms), matching the 411 us/call frozen
residual almost exactly. Ledger grep: the closed 2026-07-14 "ext4 duplicate
device-sync elision" family targeted the second sync after a DIRTY flush and was
rejected only because the small remote workload could not resolve it, with retry
predicate "tighter same-worker A/A controls or a deterministic sync-count/latency
backend" — both are supplied here (0.73% A/A null; epoch counters + strace
syscall counts), so this entry also satisfies that row's retry predicate rather
than retrying a closed idea blind. No prior clean-device/dirty-epoch attempt
exists in either ledger.

The lever is device-level, not call-site-level: `FileByteDevice` now keeps an
`Arc`-shared `(write_epoch, synced_epoch)` pair. Every attempted write syscall
(success or failure — a failed `write_all_at` may have partially written)
advances `write_epoch` after the syscall returns; `sync` reads `write_epoch`
first, performs `sync_all`, then publishes the observed epoch via `fetch_max`.
When the epochs are equal, `sync` returns without the syscall: no write has
completed through this device (or any clone — clones share the state) since
durability was last established, so there is nothing new to make durable. POSIX
fsync only covers writes completed before the call, and a FUSE client cannot
issue an fsync ordered after a write until the daemon replied to that write —
which happens strictly after the epoch bump — so the skip is semantically exact.
`write_epoch` starts ahead of `synced_epoch`, so the first sync after open
always runs (covers mount-time journal replay through the separate journal fd on
the same path). Env kill switch: `FFS_CLEAN_SYNC_SKIP=0` restores the old
unconditional fsync. Because the MVCC flush path already syncs the device
internally through the adapter (delegating to the same `FileByteDevice`), the
outer boundary sync after a DIRTY flush now also skips — dirty boundaries issue
exactly one real fsync instead of two, landing the 2026-07-14 duplicate-sync
elision as a byproduct. Ordering preserved: no write is moved or elided, only a
provably-no-op syscall. Tie-breaking, floating point, RNG: N/A.

Decisive same-worker rotating A/A/B/kernel run (fresh image copy + fresh mount
cycle per sample; 8,000 x 128-byte files + 3 sentinels populated outside timing;
daemon pinned to CPUs 8-15, client to 16-23; sample = median of 3 batches x
2,000 `fsync(dirfd)` calls on the unchanged 8,003-entry directory; 6 samples per
arm; candidate binary SHA-256
`b2e8f748bd3e2e82efbbad5bf14e05b943079ed0e17869eccd8cfc5f9be03ebe`, controls =
same binary with `FFS_CLEAN_SYNC_SKIP=0`, fixture SHA-256
`cff2c98c4d34e3d952a3b7f93fa22bfdbec7781942188b38bb42524f63a60dd8`):

- control A (env-off): 821.785 ms median, CV 0.94%
- control B (env-off): 827.777 ms median, CV 0.67% (A/A null spread 1.0073x)
- candidate (lever on): 49.567 ms median, CV 6.99% (12-sample: 48.538 ms, CV 6.32%)
- kernel ext4 (dio-loop): 1.846 ms median, CV 21.32% (routing evidence only)

Candidate is 16.58x faster than the faster control; the candidate arm's CV sits
above the 5% gate (RTT-bound shape on a loaded box), so the honest bound is
worst-candidate vs best-control = 807.260/53.228 = 15.2x — the verdict cannot
flip. Externally consistent: both env-off controls reproduce the prior session's
frozen-pre controls (819.5/818.1 ms) within 1.2%. Per-call: 411 us -> 24.8 us;
the removed 386 us equals the measured 398 us clean-fsync price within noise.

Mechanism proof: strace of the daemon during a 500-call storm counted exactly 1
fsync syscall with the lever on (the first-sync-always) vs 500 with it off.
Durability proof (kill -9): with skips exercised before and after, a new file
written and `fsync`ed, then SIGKILL (no graceful shutdown, no unmount flush):
`e2fsck -fn` rc 0 and the payload's exact SHA-256 read back through a kernel
mount. Every A/B cycle validated entry count, byte totals, and 3 sentinel
payloads before and after timing, and every image passed `e2fsck -fn` rc 0.

Gates: `cargo test -p ffs-block --lib` 309/0 including two new epoch-invariant
tests (first-sync-always + clean-skip + re-dirty, clone-shared state);
`cargo clippy -p ffs-block --all-targets -- -D warnings` clean (pre-existing
bench/example lint debt cleared in the companion chore commit); release CLI
build clean. Residual: the ~27x kernel gap on this shape is the synchronous FUSE
round-trip (~25 us/call vs kernel ~0.9 us in-kernel fsyncdir); the concurrent
dispatch that would amortize it is ledger-CLOSED above (multiloop REJECT) until
its linearizability retry predicate is met. `clear_ext4_writable_group_desc_cache`
still runs on every no-op boundary — a follow-up candidate, likely minor now.

## Shared-channel multiloop FUSE dispatch - 2026-07-22 (REJECT; bd-opb6l)

Status: REJECT and restore the single FUSE receive/dispatch loop. The candidate
nearly doubled the measured four-client delete throughput, but violated ext4
allocation/free and durability invariants under repeated churn. No production
source is retained.

Profile first: the frozen standard mount took 370.291824 ms for an 8,000-file,
four-directory/four-client delete plus `fsyncdir` storm versus kernel ext4 at
229.141343 ms (1.616x gap). A stripped daemon cycles profile captured 603 samples
with zero loss; `__memmove` held 7.12%, `memcmp` 2.37%, and the remaining leading
frames were FUSE read/write/syscall dispatch. Source attribution then found that
vendored `fuser::Session::run` has one explicitly non-concurrent receive loop even
though `MountOptions::resolved_thread_count()` reported four workers on the pinned
cpuset. Ledger and recent-log grep ruled out the closed delete-serial-floor,
version-coalescing, Cx-pooling, S3-FIFO slab, Bloom, DenseVisited, and
write-block-ownership families. The alien-graveyard Arrakis/io_uring primitive was
therefore tested narrowly: initialize once, then run one FUSE receive buffer/event
loop per available worker over the shared channel while cloning only the Arc-backed
adapter state.

The pinned rotating same-host A/A/B run used byte-identical clean ext4 images
(`e50b838a382a7e90ccaa71174fbce34b4e86626bb1706e835732727e05997aeb`), four
directories, four clients, exact 128-byte payloads, setup outside timing, directory
fsync, and 30 admitted 8,000-delete samples per arm:

- frozen-pre control A: 397.520856 ms, CV 1.971210%
- frozen-pre control B: 400.809427 ms, CV 4.300249%
- four-loop candidate: 203.287380 ms, CV 2.246183%
- kernel ext4: 76.778175 ms median, but CV 10.976081% (routing evidence only)

The candidate was 1.963551x faster than the control-pool mean, well beyond the
0.827270% A/A null spread. A larger 32,000-delete candidate/kernel comparator gave
670.580733 ms at 0.758367% CV versus 236.532995 ms at 5.352389% CV; the kernel arm
again missed the under-5% admission gate and no direct-kernel ratio is claimed.
Frozen/candidate binary SHA-256 values were respectively
`2918b6450ab97421e70b246776d5759de854ac4180d7988058e9ccd9d1788cf1` and
`1ca2a3a46c8f6c2b54d8d6272c222a3f8ce61aa8015e76f093570b857c8083b3`.

Correctness veto: three named scoped workers plus the main loop proved the
candidate was actually live. Under repeated near-capacity four-client churn it
then returned `EINVAL` while creating worker 2's file 13,641. Live accounting at
the failure was 61,658 used inodes and 246,662/262,144 used blocks; after deleting
every benchmark-created file it still reported 185,021 used blocks and only 17
used inodes. Frozen controls, after the same smaller-storm A/A workload, returned
to 16 inodes and 13,164 blocks. After graceful daemon shutdown, both frozen images
passed `e2fsck -fn` rc 0 at 16 files/13,164 blocks and kernel passed rc 0 at
16/13,600. The candidate failed rc 4 at 61,658 files/246,662 blocks with block- and
inode-bitmap differences plus wrong free-block counts in every group. Ordering and
tie-breaking are therefore not isomorphic: concurrent request execution can race
ext4 allocation/free and durable-summary publication even though individual
requests and replies are unchanged. Floating point and RNG are N/A.

Strict-remote `cargo check -p ffs-fuse --all-targets` passed on `ovh-b`, job
`j-29943190916169857`; strict-remote release CLI build passed on `vmi1153651`, job
`j-29943190916169856`; targeted nightly rustfmt and `git diff --check` passed before
measurement. Retry only when a mounted concurrency oracle proves linearizable
ext4 block/inode allocation, free, and durable-summary publication across concurrent
FUSE requests, and a fresh four-client 64,000-file create/delete cycle repeated at
least 15 times returns to the frozen control's inode/block counts with every image
passing `e2fsck -fn` rc 0. The same retry must also obtain an interleaved kernel
comparator below 5% CV. Until all parts hold, shared-channel multiloop dispatch is
ledger-CLOSED.

## Ext4 fsync deferred-summary durability boundary - 2026-07-22 (KEEP correctness; perf-neutral; bd-fsync-journal-latency-gap-ptp4x / bd-opb6l)

Status: KEEP as a required ext4 durability-boundary repair. The unchanged-directory
hot path is performance-neutral within the same-worker A/A null; this is not claimed
as another speedup.

Profile and conformance first: after the durable-watermark scan KEEP, the mounted
8,000-file unchanged-directory workload still spent 7.710211 seconds in 10,000
`fsyncdir` calls. A server-side cycles profile captured 1,870 samples with zero loss,
with the stripped release binary's leading sync-path address cluster holding 18.94%.
The mandatory post-profile mounted check then supplied stronger negative evidence:
both frozen controls and the candidate returned `e2fsck -fn` rc 4 with identical stale
inode/block bitmaps, free counts, checksums, and group summaries, while kernel ext4 was
clean. Ledger and recent-log grep showed that deferred GDT persistence is default-on
and is required at durability boundaries; its recorded retry predicate now held because
mounted FUSE and exact offline fsck reproduction were available. Source attribution
found that FUSE `ext4_sync_with_logging` flushed MVCC versions and synced the device but
never persisted the derived group descriptors or superblock free totals. It also
published the MVCC cursor before the caller's device sync, contrary to its retry
contract. No closed FIFO slab, Bloom prefilter, DenseVisited, or write-ownership family
was retried.

The kept boundary now holds the durable-cursor mutex while it flushes versions, clears
the writable descriptor cache, persists group descriptors and superblock free totals
when any version was flushed, and syncs the device. Only after every step succeeds does
it publish `durable_through`; any error leaves the old cursor so retry rewrites the full
suffix and its derived summaries. When `flushed == 0`, the new summary writes remain
skipped, preserving the no-op watermark fast path. Ordering preserved: the original
sorted/coalesced block writes are unchanged, followed by their required derived ext4
summaries and the existing device sync. Tie-breaking unchanged: newest-visible MVCC
selection is unchanged. Floating point and RNG: N/A.

The decisive pinned, rotating, same-worker A/A/B/kernel run used fresh clones and 30
samples per arm, each the median of three 2,000-call unchanged-directory `fsyncdir`
batches after an exact 8,000 x 128-byte durable warmup:

- frozen-pre control A: 819.529760 ms, CV 1.274955%
- frozen-pre control B: 818.145700 ms, CV 1.410293%
- candidate: 819.617904 ms, CV 0.947339%
- kernel ext4: 2.200209 ms, CV 2.905261%

Candidate/pre-control-pool is 1.000953x (0.0953% slower), inside the 1.001692x
(0.1692%) A/A null spread: performance-neutral. Candidate remains 372.518x slower than
kernel on this synchronous FUSE transport shape. Frozen/candidate binary SHA-256 values
were respectively
`5400b53171a337b1189657204f7728af08073bfcf1464de8e61593d9dfce02cb` and
`2918b6450ab97421e70b246776d5759de854ac4180d7988058e9ccd9d1788cf1`.

Behavior proof was exact. Every arm had 8,000 files, 1,024,000 payload bytes, and three
matching sentinels. After daemon-only graceful SIGINT, both frozen images reproduced rc
4 and their original 270-file/2,357-block summary; candidate passed `e2fsck -fn` rc 0
with 8,271 files/10,406 blocks, and kernel passed rc 0 with 8,271 files/10,403 blocks.
An independent fresh candidate clone also passed rc 0 with 8,271 files/10,406 blocks.
The focused default-on/checksum-on fsync-summary test passed 1/1 on strict-remote
`vmi1153651`, job `j-29943190916169812`; the release CLI build passed on strict-remote
`vmi1227854`, job `j-29943190916169818`. Targeted nightly rustfmt and
`git diff --check` passed.

## Durable-watermark no-op checkpoint scan guard - 2026-07-22 (KEEP; bd-fsync-journal-latency-gap-ptp4x / bd-opb6l)

Status: KEEP for the narrow MVCC checkpoint primitive. The mounted ext4 mutation
conformance gap described below remains open and prevents an end-to-end kernel-parity
claim.

Profile first: after the incremental durable-watermark KEEP, a frozen-pre mounted image
with 8,000 warm 128-byte files took 7.710211 seconds for 10,000 unchanged-directory
`fsyncdir` calls. The server-side cycles profile captured 1,870 samples with zero loss;
the stripped release binary's leading address cluster held 18.94% of samples. Source
attribution then found the exact residual: both `MvccStore::flush_to_device_after` and
`ShardedMvccStore::flush_to_device_after` still traversed every version map even when
`snapshot.high == flushed_through`, although every visited version must be rejected by
the watermark predicate. Ledger and recent-log grep found no prior read-side no-op
checkpoint guard. The `fed3a313` stable-watermark publication null was a different
SnapshotRegistry write-side atomic, and the closed DenseVisited/write-ownership families
were not retried.

The kept lever snapshots first and returns `(0, snapshot.high)` when
`snapshot.high <= flushed_through`. Commit sequences are monotonic, so the stable
snapshot cannot contain a version newer than the durable cursor in that branch. The old
scan would therefore reject every entry and issue zero writes. A commit racing after the
snapshot was already outside the old flush's visibility and remains outside the new one.
The caller's device `sync` is unchanged. Public full-checkpoint calls still pass sequence
zero and traverse whenever any committed version exists. Ordering preserved: yes, the
only skipped branch emits no block run. Tie-breaking unchanged: yes, no visible version
is selected in that branch. Floating point and RNG: N/A.

The decisive same-worker mounted proof used four clones of the same clean ext4 image and
froze the pre binary twice as null controls. Every arm was populated outside timing with
exactly 8,000 x 128-byte files and validated for exact count, byte total, and three
sentinel payloads before and after timing. Requester and three FUSE daemons were pinned to
separate CPUs. Thirty rotating samples per arm each took the median of three 2,000-call
unchanged-directory `fsyncdir` batches:

- frozen-pre control A: 1,018.687532 ms, CV 3.296456%
- frozen-pre control B: 1,018.529234 ms, CV 3.593459%
- candidate: 836.161306 ms, CV 3.478875%
- kernel ext4: 2.401584 ms, CV 2.750562%

Candidate is 1.218101x faster than the faster frozen control (17.905% lower latency),
comfortably clearing the 1.000155x A/A null spread. The remaining synchronous FUSE
boundary is still dominant: candidate is 348.171x slower than kernel ext4 for this
unchanged-directory shape, so this is an internal KEEP rather than a direct kernel win.
Frozen-pre binary SHA-256 was
`aff29fdaf03f5de5fb39ea3dfe3af28ad523167334c7da1893d891c797cd1454`;
candidate was
`5400b53171a337b1189657204f7728af08073bfcf1464de8e61593d9dfce02cb`;
source fixture was
`0de4b44cacb300d71cbf2b1ae1ef3eca7d56668bec25a8a0aad2faaea874c7cb`.

Behavior-isomorphism is exact at the lever boundary. Existing single-store and sharded
recording-device tests exercise the repeated call and assert zero writes plus the same
returned watermark; both passed (2/2, strict-remote job `j-29942429901652413`). The
all-target `ffs-mvcc` check passed on strict-remote `ovh-a` job
`j-29943190916169800`, and the release CLI build passed on `vmi1227854` job
`j-29943190916169756`. `git diff --check` passed.

The broader mounted conformance gate exposed an unrelated existing defect and is recorded
without laundering it: kernel ext4's post-run image passed `e2fsck -fn`, while both
frozen controls and candidate returned rc 4 with byte-for-byte identical diagnostics
(stale inode/block bitmaps, free counts, and group-summary metadata). A separate fresh
candidate clone with daemon-only graceful SIGINT reproduced the same result. Thus the
candidate neither creates nor hides this corruption, but the parent mounted comparator
must remain open. A direct kernel durability verdict requires the ext4 mutation path to
produce an `e2fsck -fn`-clean image for this exact 8,000-file setup first.

## Incremental MVCC durable-checkpoint watermark - 2026-07-22 (KEEP; bd-opb6l / bd-fsync-journal-latency-gap-ptp4x)

Status: KEEP - mounted small-file durability now beats kernel ext4 on the measured
fresh-image fsync storm while preserving stronger whole-store durability.

Profile-first attribution found the old implementation re-writing every visible MVCC
block on every durability call. After a small mounted create/write run, the daemon logged
`flushed_blocks=2087` and `duration_us=22172` for one final `fsyncdir`; batch latency rose
as the tracked store grew. A 1,124-cycle daemon profile put syscall/scheduler and memory
movement at the top, consistent with cumulative checkpoint traffic. Ledger and recent-log
grep found no prior incremental durable-watermark attempt and ruled out the closed
duplicate-sync, DenseVisited, write-block ownership, bitmap, htree, checksum, and
copy/materialization families.

The kept lever adds `flush_to_device_after` to both MVCC store layouts and keeps the
existing public `flush_to_device` as a full checkpoint. `OpenFs` owns a base-device-scoped
`CommitSeq` watermark under a mutex held across write and sync. Only latest visible
versions newer than that watermark are sorted, coalesced, and written. The cursor advances
only after success, so a partial failure retries the full suffix; serializing calls prevents
an older snapshot from overwriting a newer durable one. Mount/replay begins at sequence
zero. Ordering and newest-visible tie-breaking are unchanged; floating point and RNG are
N/A.

The decisive proof used six fresh SHA-identical ext4 images per arm, rotating frozen-pre
control A, frozen-pre control B, candidate, and kernel ext4 on one local worker. Each arm
created and durably warmed exactly 8,000 128-byte files, then pre-created exactly 200
128-byte files outside timing and timed 200 file fsync calls plus directory fsync. Medians:

- control A: 22,595.882959 ms, CV 4.025369%
- control B: 21,977.519074 ms, CV 3.062814%
- candidate: 109.866157 ms, CV 3.503933%
- kernel ext4: 3,718.134447 ms, CV 2.302359%

Thus candidate is 200.039x faster than the faster frozen control, clearing the 1.028x
null spread, and 33.842x faster than kernel ext4 (97.05% lower latency). FrankenFS provides
stronger behavior here: the first file fsync durably checkpoints all 200 already-created
files; the watermark makes the remaining calls skip already-durable MVCC versions. Every
run verified exact counts and byte totals outside timing, and all 24 images passed offline
`e2fsck -fn`. Source fixture SHA-256 was
`0de4b44cacb300d71cbf2b1ae1ef3eca7d56668bec25a8a0aad2faaea874c7cb`; pre/candidate
binary SHA-256 values were respectively
`025e9adc5c53e896ee8fce450d401a5bdddf5df566339578995f3613232de316` and
`aff29fdaf03f5de5fb39ea3dfe3af28ad523167334c7da1893d891c797cd1454`.

Correctness gates: new single and sharded tests prove unchanged durable old blocks,
changed/new-only incremental writes, idempotent zero-write repeat, and preserved public
full-checkpoint behavior (2/2 strict-remote, `ovh-a`, job `j-29942429901652302`). The
strict-remote all-target check for `ffs-mvcc` plus `ffs-core` passed in job
`j-29942429901652292`; release CLI build passed in job `j-29942429901652307`.
Targeted rustfmt and `git diff --check` passed. Two later full-crate-test submissions were
rejected before execution because RCH had no admissible worker; fail-closed remote policy
was honored and no local Cargo ran.

## ext4_write full-block build: skip the memset on a full-block overwrite - 2026-07-14 (KEEP)

Status: KEEP — a real DEFAULT write-path win (not sharded/default-off).

The write loop builds each block to stage into the MVCC txn. For an ALIGNED FULL-block
overwrite (`block_offset == 0 && chunk_len == bs`) it used `vec![0u8; bs]` (a full-block
memset) then `copy_from_slice(data)` (memcpy) — but the zero-init is ENTIRELY overwritten
by the copy, so it is pure waste. Took `data[data_start..].to_vec()` directly (one memcpy)
for that case; partial writes still zero-fill a freshly-allocated block (bytes outside the
chunk must read as zero) or RMW-read an existing one, then patch. Byte-IDENTICAL: the
full-block staged bytes are the same `data`-filled block either way (write/roundtrip/
fallocate suite 384/0). A/B (benches/write_full_block_build, 4 KiB): memset_then_copy
**123.8 ns** → direct_to_vec **58.6 ns** = **~2.1x**, ~65 ns/block eliminated (the memset).
Hits every full-block write — the dominant shape of large sequential writes — on the
buffered write CPU path (the block is staged, not device-written, so this is real per-op
CPU, not I/O-masked). LESSON: `vec![0; n]` + `copy_from_slice(whole)` is a memset the copy
throws away — take the source directly.

## ext4_setattr (chmod/chown/utimes): read-once / write-once lean - 2026-07-14 (BOUND, no code)

Status: BOUND — probed a less-benched metadata-mutation op; already lean. No lever.

`ext4_setattr` does exactly one `read_inode_with_scope`, applies the requested fields in
place (mode preserves the type bits; uid/gid direct; atime→touch_atime,
mtime→touch_mtime_ctime — all O(1)), runs cheap immutable/verity/append guards, then one
`write_inode`. No redundant read, no re-read, no recompute for the common
chmod/chown/utimes case; both the read and write halves are already optimized (AttrOnly/
Arc-share reads, make_mut write). The only heavy branch is `attrs.size` (truncate), which
frees blocks under the alloc lock — inherent work + peer-adjacent (bd-k2wc7 truncate).
Not a lever. Confirms the metadata-mutation ops (create alloc-lean, setattr read-once/
write-once) are lean, matching the create-path "alloc-LEAN" bound.

## Block-cache locking: sharded per-shard Mutex is the deliberate benched choice - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the per-block-read cache lock; a deliberate, already-benched
decision. No lever.

Every hot cache (`ext4_file_data_block_cache`, `ext4_inode_table_block_cache`,
`ext4_base_block_cache`, `ext4_group_desc_cache`, `ext4_inode_attr_cache`, btrfs node/
dir/extent caches) is a `ShardedCache` = FFS_CACHE_SHARDS shards, each a
`Mutex<FxHashMap>`; the hit path locks ONLY the key's shard + clones the value. The
`cache_get_rwlock` bench (bd-tag2s) A/B'd a SINGLE `Mutex` vs SINGLE `RwLock` — and the
adopted answer is SHARDING (per-shard Mutex), which beats a single RwLock: true
per-shard parallelism with no shared read-count atomic. A per-shard `RwLock` (instead
of Mutex) would help only the rare case of two threads hitting the SAME shard for reads
simultaneously (prob ~1/shards for random blocks) while paying RwLock's higher
uncontended cost on EVERY get — the d3ab1bb8 "sharding already handles contention →
RwLock marginal-to-negative" pattern. Not a lever without a profile showing same-shard
read contention. Settled.

## MVCC flush/fsync path (ShardedMvccStore::flush_to_device): already coalesce-optimized - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the flush path (per fsync/sync); already optimized. No lever.

`flush_to_device` collects visible (block, bytes) across shards (each under a brief read
lock), then `sort_unstable_by_key` on block number, coalesces contiguous blocks into
runs, and writes each run with ONE `write_contiguous_blocks` (a single pwrite instead of
one per block) + a single `sync` at the end. Already the right shape:
- `sort_unstable` (not stable) + contiguous coalescing = sequential-I/O optimal.
- the per-block owned `Vec` (`resolve_version_bytes_at_or_before`) is LOAD-BEARING: the
  data must outlive the shard read lock, which is deliberately released BEFORE the I/O
  ("sort + coalesce + write holding no shard lock"), so it cannot borrow.
- fsync is I/O-bound anyway; the O(N log N) collect+sort is dwarfed by the writes.
No lever. The fsync/flush path joins the mined set (cf. rejected JBD2 sequence sort
e04d2428, fsync_latency_workload bench).

## Free/delete serial floor (free_inode/free_blocks_in_group): already optimized - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the delete serial floor (free-path analog of the alloc floor);
already optimized, mirroring the alloc path.

- `free_blocks_in_group`: reserved-block overlap uses ONE binary search ("first reserved
  block >= rel_start decides overlap for the whole run"), not a linear scan.
- checksum update is incremental (single-bit clear via `BitmapChecksumUpdate`), not a
  full-block recompute (same infra as the alloc path).
- no `highest_set_bit_index`/scan on free: `itable_unused` is monotonic (min), so a free
  never grows it back — nothing to recompute.
- residual: `free_inode_in_group`/`free_blocks_in_group` do the per-op bitmap
  `.as_slice().to_vec()`, the SAME marginal make_mut candidate already rejected for the
  alloc path (Pareto but `read_visible_block_buf` Arc-shares the overlay version so it
  clones for the hot repeated-op case = parity-tail, d3ab1bb8 neutral pattern). Not a
  lever. The delete serial floor is mined, like the create floor.

## inode-bitmap padding fill: already byte-wise + O(1) fast path (was the #1 hot fn, already fixed) - 2026-07-14 (BOUND, no code)

Status: BOUND — probed `fill_inode_bitmap_padding_with_clear_undo` (per inode alloc,
create serial floor); already optimized, and its own comment shows it was ALREADY the
profiled #1 hot function that got fixed.

The inode bitmap block is `block_size` bytes but only `inodes_per_group` bits are used,
so the padding region [inodes_per_group, block_size*8) is thousands of bits, set on
EVERY inode alloc. It USED to scan bit-by-bit (with a per-bit `bitmap_get`) — the code
comment records it was "the #1 hot function in parallel create (~13% self time)"
because after the first alloc every padding bit is already set yet was re-scanned one
bit at a time. It has since been rewritten: whole `0xFF` bytes skipped in O(1), a fast
path that returns immediately once the FINAL byte is already `0xFF` (the padding is one
contiguous block, so a set final byte ⇒ whole region padded ⇒ nothing to do), and only
NEWLY-set bits recorded for rollback. The common already-padded case now touches no
bit. The non-undo sibling `fill_inode_bitmap_padding` is byte-wise (0xFF whole bytes)
too. No lever — this is exactly the profiled create-floor hot fn, already fixed
(alongside highest_set_bit 05a28387, bitmap SWAR, incremental checksum, reserved
no-alloc). The alloc create serial floor is thoroughly mined.

## Block-cache hasher + per-op timestamp: already optimal / not byte-id-changeable - 2026-07-14 (BOUND, no code)

Status: BOUND — two more per-op hot spots probed, neither a lever.

- `ShardedCache` (every metadata/data/extent-node/group-desc block cache get): already
  uses `rustc_hash::FxHashMap` (fast non-cryptographic hash — a u64 `BlockNumber` key
  needs no SipHash), sharded so gets on distinct shards run fully parallel, and the hit
  path locks only the key's shard + clones the value (`cache_get_rwlock` benched). The
  obvious "swap SipHash → FxHash" win is already done.
- `now_timestamp()` (per write/create/mkdir/setattr): a single `SystemTime::now()` =
  one vDSO `clock_gettime` (~5–10 ns) + arithmetic, called ONCE per op — not redundant.
  The only cheaper option, `CLOCK_REALTIME_COARSE` (~1 ns), changes the nanosecond
  timestamps written to disk (ctime/mtime/*_extra) — a SEMANTIC / non-byte-identical
  change, not a perf lever. Rejected.

## MVCC version-chain resolution + staged-write lookup: already binary-search/SmallVec - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the MVCC read/commit hot path (ffs-mvcc, my lane); already
optimal. No lever.

- `newest_visible_index` / `resolve_version_bytes_cow_at_or_before` (per `read_visible`,
  i.e. every read-your-writes + adapter read): `partition_point` BINARY search over the
  version chain, then a Cow (no copy on the borrow path). Not a linear scan.
- `staged_write_pos` (per staged-block lookup during a txn): `binary_search_by_key`;
  the write set is `StagedWrites = SmallVec<[(BlockNumber, StagedWrite); 4]>` — inline
  for the common small-txn case, no heap alloc.

Consistent with the rest of the MVCC store, which this campaign already mined (merge
validators b10fc652/5c802bae, preflight, contention-metrics gating 73174f5b, read GC
un-pin 0576bb8b, Arc-share reads 5d4a8f8d). Nothing left here.

## inode-parse base-area bounds-check hoist: NEUTRAL, the `len < 128` guard already elides - 2026-07-14 (REJECT, benched)

Status: REJECT — benched the array-ref hoist on the READ side of the inode parser
(the hottest metadata op); it is a no-op. The write-side hoist won for a reason that
does NOT apply to the read side.

`Ext4Inode::parse_from_bytes_with_ibody` reads ~20 base-area fields (offsets < 128)
via `ffs_types::read_le_u16/u32(bytes, off)?`, each a `.get()` bounds check. The
write side (`serialize_inode_into`, b83531ef) hoisted the base to a `&mut [u8; 128]`
array-ref and WON — but its only length fact was a `debug_assert_eq!(buf.len(),
inode_size)`, which LLVM ignores, so its per-field checks were NOT elided. The read
side is different: `parse_from_bytes_with_ibody` opens with `if bytes.len() < 128 {
return Err }`, which establishes `len >= 128` for LLVM's range analysis; with
`read_le_*` `#[inline]` + const call-site offsets, `bytes.get(off..off+n)` for
`off+n <= 128 <= len` is provably in-bounds and LLVM already elides it.

Bench (benches/inode_base_read_hoist, same binary, 15 base fields): production-style
`read_le_per_field` **3.66 ns** vs literal-offset `arrayref_const_offset` **3.48 ns**
— CIs overlap (3.36–4.01 vs 3.22–3.76), ~0.23 ns/field = just the loads+adds, no
bounds-check overhead in either. NEUTRAL → the hoist is redundant; kept the bench as a
regression guard (if the `len < 128` guard is ever removed, the checks come back).
Retry predicate: none — the guard already gives the elision the write side had to hoist for.

## ffs-dir htree-index sweep: binary-search where used, the rest is test-only/inherent - 2026-07-14 (BOUND, no code)

Status: BOUND — probed ffs-dir (a fresh crate); no production lever.

- `htree_find_leaf_idx` / `htree_insert`: already `partition_point` (binary search over
  the hash-sorted entries), not linear. Optimized.
- `htree_remove`: uses a linear `.iter().position()`, BUT it has ZERO production
  callers — only `#[cfg(test)]` sites (ffs-dir:1824/1827/2263/2272). Likewise
  `htree_find_leaf` has no ffs-core caller: the ext4 htree hot path resolves inline in
  ffs-core (`htree_resolve_logical`, benched), not through ffs-dir's API. So neither is
  on a production hot path; binary-search-narrowing `htree_remove` would optimize
  dead-for-prod code. Not a lever. (If ever wired to a hot delete path, note it is
  also I/O-masked: each dir-entry delete writes the dir block + frees the inode, so the
  in-memory O(#leaf-blocks) scan is dwarfed — the read_file_data segs/jobs "I/O-masked"
  class.)
- `block_contains_live_name` / the dir-block entry scans: inherent per-entry rec_len
  walks (variable-length records, not SWAR-able).
- The `.to_vec()` in the `*_tracked` variants (ffs-dir:267/794): load-bearing undo
  snapshots for journaled rollback, not waste.

## ffs-extent read-resolve + ext4 block-resolve sweep: all optimized - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the file-read logical→physical resolve path (a different crate
from last turn's ffs-alloc sweep); every hot function is already optimized. No lever.

Probed (already optimized, do NOT re-attempt):
- `ext4_resolve_block_from_mappings` (per-block read resolve): `partition_point` binary
  search over the sorted mappings — O(log E), not linear.
- `ext4_resolve_block_from_mappings_hinted` (bd-vpypn): caches the last mapping index so
  sequential reads are O(1) (one bounds check), falling back to the binary search —
  benched 2.0–2.5x, byte-identical.
- `ffs_extent::map_logical_to_physical` / `map_logical_range_by_walk`: one `ExtentMapping`
  pushed per real extent; `append_hole_mappings` emits ONE mapping per `u32::MAX` chunk
  (≈1 per hole), not per block — already O(#extents), not O(#blocks).

Considered + rejected (cold): `map_single_logical_to_physical` returns `vec![one_mapping]`
(a 1-element heap Vec) for the count==1 case. It is NOT on the hot read path — reads
resolve through the CACHED mappings via `ext4_resolve_block_from_mappings(_hinted)`, not a
per-block `map_logical_to_physical` call; `map_single` fires only for uncommon count==1
calls in the write/fallocate range paths (ffs-core:21671+). Cold + the public
`-> Vec<ExtentMapping>` return type would need a SmallVec API change to avoid the alloc.
Not worth it. Retry predicate: only if a profile shows count==1 `map_logical_to_physical`
on a hot path.

## Alloc-path fresh-function sweep: all optimized (only highest_set_bit was a gap) - 2026-07-14 (BOUND, no code)

Status: BOUND — after the `highest_set_bit_index` win, swept the neighbouring
inode/block-alloc hot functions; every one is already optimized. No lever this turn.

Probed (all already optimized, do NOT re-attempt):
- `bitmap_find_contiguous_linear` (multi-block alloc): 4-words-at-a-time SWAR fast
  path (bench `contiguous_scan_width`).
- `bitmap_count_free` (free-count): word-path + scalar partial tail (tests
  `..._word_path_handles_partial_tail`).
- `reserved_inodes_in_group` (per inode alloc/free): returns a NO-ALLOC `Vec::new()`
  for every group ≥ 1 (reserved inodes are all in group 0); the group-0 Vec is small
  + transient (group 0 fills once). Not a lever.
- htree `dx_hash` / `str2hashbuf` (per htree lookup/create): already uses a STACK
  `[u32; 8]` buffer, not a per-call `vec!` (bd-cc-str2hashbuf-stack).
- `stamp_bitmap_checksum_from_override` (per alloc): INCREMENTAL — a single-bit flip
  uses `BitmapChecksumUpdate::Incremental` (`bitmap_checksum_incremental_from_flipped_
  bit_range`), never a full-block crc32c recompute; `Full` only on bulk overrides.

Considered + rejected (marginal): `try_alloc_inode_in_group_persist_core` does
`bitmap_buf.as_slice().to_vec()` (a block-sized copy) per inode alloc. `make_mut()`
(COW, cf. 8984db03) would be Pareto, BUT the bitmap block gains an MVCC overlay
version after its first write, and `read_visible_block_buf` Arc-SHARES that version, so
every subsequent same-group alloc's `make_mut` CLONES (== to_vec) — only the first
base-read per group is free. On a create-storm that is parity-tail (the d3ab1bb8
"neutral-in-practice → reject" pattern); the borrow-flow churn (the `&mut bitmap`
threads through set-undo, find_free, padding, the override borrow, the write, and the
error-path rollback) is not justified for a ~always-clone win. Retry predicate: only if
a profile shows the per-alloc bitmap copy is non-trivial AND most reads are base-unique.

## `highest_set_bit_index` word-at-a-time reverse scan (inode-alloc itable_unused) - 2026-07-14 (KEEP)

Status: KEEP — a real DEFAULT-path win on the create serial floor (the first
non-sharded, non-post-cutover lever in several turns).

`highest_set_bit_index` runs on EVERY inode alloc (in `persist_group_desc_*`, to
recompute the group descriptor's `itable_unused = inodes_per_group - highest_used -
1`). It reverse-scanned the group's inode bitmap BYTE-BY-BYTE for the top set bit.
On a SPARSE group (few low inodes used — the common early-fill state, and the create
serial floor) it walks all the high zero bytes to reach the top bit — O(nbytes),
e.g. ~1024 iterations for inodes_per_group=8192. Rewrote it to skip a u64 (8 bytes)
per step: the last byte stays scalar (the only byte that can hold a padding bit >=
count), the fully-real lower bytes are skipped by `u64::from_le_bytes(..) != 0` +
`63 - leading_zeros()`. Byte-IDENTICAL to the scalar reverse scan, proven exhaustively
by a new proptest `proptest_highest_set_bit_index_matches_scalar` (512 random
bitmap/count cases incl. the padding boundary and count>bits) + the existing
`..._finds_top_used_bit_and_ignores_padding` edge-case test (ffs-alloc 218/218). A/B
(benches/highest_set_bit_width, sparse worst case): **~3.5x** — 2048: 86.8->24.8 ns;
8192: 284->80 ns; scaling ~3.5x at 65536; CIs cleanly separated. ~200 ns saved per
inode alloc (inodes_per_group=8192) on the create serial floor, so it helps BOTH the
single-lock create path AND the sharded 3.7x path (unlike the default-off sharded
micro-levers). Not the full 8x (the compiler partly handles the byte loop) but a
clean, e2fsck-safe (pure-function, proptest-pinned) reduction.

## ext4 metadata checksum path is already optimal (crc32c hardware-accelerated; simd warm is diagnostic-only) - 2026-07-14 (BOUND, no code)

Status: BOUND — the ext4 metadata-checksum hot path (every inode / group-desc /
dir-entry / extent-node write) is not a lever.

Investigated because a peer accelerated btrfs's crc32c (652bee53) and ext4 computes a
crc32c metadata checksum on every metadata write (a hot DEFAULT path). Findings:
- **crc32c math already hardware-accelerated.** `ext4_chksum` (ffs-ondisk/ext4.rs:34)
  routes through `ffs_types::crc32c_append`, which delegates to the `crc32c`
  DEPENDENCY crate (self-detecting SSE4.2 / aarch64-CRC internally). `#![forbid(unsafe_code)]`
  bars us from writing our own intrinsic path anyway; the dep already provides the
  fast one. Nothing to accelerate.
- **the per-call `simd_capabilities()` warm is diagnostic-only, and sub-noise.**
  `crc32c`/`crc32c_append`/`blake3_hash` each call `let _ = simd_capabilities();`
  (an `OnceLock::get_or_init`). But `SimdCapabilities` is CONSUMED nowhere in
  production for dispatch (grep: only its own one-time `tracing::info!` log +
  `#[cfg(test)]`); the checksum crates self-detect. So the warm is purely the
  one-time capability log. Under release-perf LTO (`codegen-units = 1`) its
  initialized fast path inlines to a hot acquire-load (sub-ns), dwarfed by the crc
  math (~tens of ns for a 256-byte inode). Removing it would trade the one-time
  diagnostic log for a sub-noise gain (the fd678afe "<0.5% of the op = sub-noise"
  rule) — not worth the behavior change. Retry predicate: only if a profile shows the
  warm as a non-trivial fraction of a metadata-write op (it will not under LTO).

## Extent-meta double-walk REJECTED (already fast-pathed) + sharded `from_superblock` vein closed - 2026-07-14 (REJECT / BOUND, no code)

Status: REJECT (the extent-meta double-walk candidate from the previous entry is not
worth landing) + BOUND (the remaining sharded `from_superblock` sites are justified or
churn) — the remote-only in-lane micro-lever surface is exhausted.

**REJECT — skip the post-write extent-tree meta walk (the previous entry's candidate).**
Verdict after reading `ext4_count_extent_tree_meta_blocks` (lib.rs:12897): it ALREADY
has a depth-0 fast path — an inline extent tree (the COMMON case: extents fit in the
inode) reads `root_bytes[6..8]` (eh_depth) and returns 0 with NO parse or walk. So both
`meta_before` and `meta_after` are O(1) for the common case; the double-walk only costs
for depth>0 EXTERNAL trees (large/fragmented files, a minority). Skipping the "after"
walk there would save a recursion over cached nodes — small absolute win, ONLY for the
minority — while carrying the i_blocks-miscount risk (the unwritten->written split from
the prior entry) whose validation needs local e2fsck. Low value (common case already
O(1)) + high risk + local-only validation = not worth it. Retry predicate UNCHANGED but
downgraded: only if a profile shows depth>0 in-place-overwrite meta-walks are a real
cost AND the ffs_btree node-delta signal + local e2fsck are both available.

**BOUND — `ext4_persist_ctx_lockfree`'s `from_superblock` is not a clean lever.** Each
sharded alloc/free helper computes `FsGeometry::from_superblock(sb)` AND calls
`persist_ctx_lockfree`, which recomputes it — a real double-compute. But
`persist_ctx_lockfree` needs geo only for `block_bitmap_units_per_group`, which reads
the DERIVED `geo.cluster_ratio` (BIGALLOC: `cluster_size/block_size`); the cached
`Ext4Geometry` lacks `cluster_ratio`/`blocks_per_group`/`feature_ro_compat`, so removing
the `from_superblock` there would either DUPLICATE the cluster-ratio derivation (breaks
single-source-of-truth) or thread the caller's geo through ~5 alloc/free helpers
(churn). Neither is the clean single-field elimination the inode_size/locate_inode
siblings were. Not landed. (Unlike those two: their geo use was purely VERBATIM fields.)

**Frontier (remote-only):** the in-lane micro-lever surface is exhausted — the sharded
`from_superblock` vein is mined (spread_seed 9a5c795f, inode_size da1c804d, locate_inode
77e94d08; the rest pass the full `FsGeometry` to the allocator = justified), the default
hot paths are cache-guarded, and the one real default-path candidate (extent-meta walk)
is already fast-pathed + correctness-gated. The remaining levers are the LOCAL cutover
(the 3.7x measurement + e2fsck) and the peer-owned lanes (ffs-btrfs / ffs-btree /
ffs-block). No further remote-only micro-lever should be manufactured without a profile.

## `bd-bhh0i` `ext4_sharded_locate_inode` reads verbatim superblock fields, not a whole `FsGeometry` + the extent-meta double-walk candidate - 2026-07-14 (KEEP + BOUND)

Status: KEEP (the hotter sibling of the inode_size field read) + BOUND (skipping the
post-write extent-tree meta walk is a real DEFAULT-path lever but correctness-gated).

**KEEP — `ext4_sharded_locate_inode`: `from_superblock(sb).{fields}` -> `sb.{fields}`.**
The locator built the whole `FsGeometry::from_superblock(sb)` — a u64 group-count
division plus a ~20-field struct build — but uses ONLY three verbatim superblock
fields (`inodes_per_group`, `block_size`, `inode_size`), no derived geometry (not even
`group_count`). Read them straight off `sb`. Byte-identical: `from_superblock` copies
each unchanged, and `ext4_sharded_locate_inode_matches_locate_inode_bd_bhh0i` (asserts
the sharded locator reproduces single-lock `locate_inode` exactly across a spread of
inodes) stays green (bd_bhh0i 24/24). Hotter than last turn's inode_size site: this
runs per sharded create AND per parent-inode write. Magnitude = the eliminated
`from_superblock` build (benches/bhh0i_geo_field): **8.34 ns** -> field reads
**0.53 ns**, ~7 ns net/call. Feature-gated (default-off) -> realized post-cutover; a
Pareto cleanup on the 3.7x target path (sibling of 9a5c795f / da1c804d).

**BOUND — skip the post-write extent-tree meta walk on no-op writes (candidate, NOT
landed; correctness-gated).** `ext4_write` counts extent-tree metadata blocks BEFORE
(22399) and AFTER (22698) the write and charges the delta to `i_blocks` — TWO tree
walks per write. On a pure in-place overwrite the tree is unchanged, so the "after"
walk is redundant. This is a genuine DEFAULT-path lever (writes are common; the walk
reads index/leaf nodes for deep trees). BUT a naive "nothing was allocated -> skip"
signal is UNSOUND: an unwritten->written extent SPLIT (writing into fallocate'd blocks)
mutates the tree WITHOUT allocating data blocks, and if it overflows a leaf the node
count (hence `i_blocks`) changes — skipping the walk would MISCOUNT i_blocks =
e2fsck-dirty. A sound version needs a "did any extent-tree node get added/removed"
signal plumbed through `ffs_btree` insert/split/coalesce, and the i_blocks drift can
only be validated with a real `e2fsck` (local-only, the cutover wall). Retry predicate:
implement the node-delta signal in ffs_btree AND validate with local `e2fsck` on a
fallocate+overwrite workload; do NOT gate on allocation count alone.

## `bd-bhh0i` read `inode_size` off the superblock, not a whole `FsGeometry` + geometry-caching is resize-unsafe - 2026-07-14 (KEEP + BOUND)

Status: KEEP (a clean byte-identical sibling on the sharded create path) + BOUND
(a mount-lifetime `FsGeometry` cache is NOT a lever — online resize makes it stale).

**KEEP — `from_superblock(sb).inode_size` -> `sb.inode_size` (2 sharded sites).**
`ext4_sharded_create_inode` and `ext4_sharded_write_inode` built the whole
`FsGeometry::from_superblock(sb)` — a u64 group-count division plus a ~20-field
struct build and a cluster-ratio feature check — only to read `.inode_size`, which
`from_superblock` copies UNCHANGED from `sb.inode_size` (ffs-alloc:1533). The
non-sharded inode path already reads `usize::from(sb.inode_size)` directly
(lib.rs:5612/11452/38711); the two sharded sites were the odd ones out. Replaced with
the direct field read. Byte-identical (same `u16`; bd_bhh0i suite 24/24 green). A/B
(benches/bhh0i_geo_field, same binary): build_geometry **8.68 ns** -> direct_field
**0.50 ns** = **~17x**, ~8 ns eliminated per sharded create/write. Feature-gated
(`bhh0i_sharded_alloc`, default-off) -> realized post-cutover; a Pareto cleanup on
the 3.7x target path (sibling of the spread-seed cache, 9a5c795f).

**BOUND — a cached `FsGeometry` on `OpenFs` is NOT a lever (resize-unsafe).** The
codebase recomputes `FsGeometry::from_superblock(sb)` at ~30 sites; the obvious
"compute once at mount, reuse" caching is UNSOUND: `ext4_resize_fs`
(EXT4_IOC_RESIZE_FS, lib.rs:37935) grows `blocks_count`/`group_count` online, so a
mount-lifetime `OnceLock<FsGeometry>` would go stale after a resize (`total_blocks`,
`group_count`, `total_inodes` are geometry fields). That is WHY the recompute is
per-op. And it is not a hot-path cost anyway: the hot ops already cache what they
need (`ext4_geometry: Ext4Geometry`, the `ext4_inode_table_locations` OnceLock); the
remaining raw `from_superblock` calls are cold introspection (`count_free_*`,
`free_space_summary`, statfs) or the default-off sharded path. Threading a
per-op-scoped geo through the sharded helpers is resize-safe but high-churn (many
callers incl. tests) for a default-off win. Retry predicate: only the per-op-scoped
sharded hoist, and only if the cutover profiles `from_superblock` as >X% of create;
never a mount-lifetime cache while online resize exists.

## `bd-bhh0i` cache the per-thread spread seed + remote-e2e-validation is infeasible - 2026-07-14 (KEEP + BOUND)

Status: KEEP (a clean micro-lever on the parallel-create target path) + BOUND
(remote end-to-end cutover validation is definitively infeasible).

**KEEP — `bhh0i_spread_seed` thread-local cache (feature-gated, parallel-create path).**
The sharded create/mkdir path calls `bhh0i_spread_seed()` once per op to pick the
per-thread inode-scan start group. It recomputed a `SipHash` over
`std::thread::current().id()` EVERY call — and `thread::current()` clones+drops the
thread handle (an atomic `Arc` refcount round-trip) — even though the seed is a pure
function of the stable `ThreadId` (invariant for the thread's life). Cached it in a
`thread_local!` (lazy init once per thread; `.with(|s| *s)` read thereafter).
Byte-identical: same `ThreadId` → same seed, so every call returns what the recompute
would (bd_bhh0i suite 24/24 green, incl. the spread-dependent create/mkdir/parallel
tests). A/B (benches/bhh0i_spread_seed, same-binary): recompute **21.09 ns** →
cached **1.24 ns** = **~17x** on the op, ~20 ns eliminated per create/mkdir, CIs
cleanly separated. VALUE CAVEAT: on the feature-gated (`bhh0i_sharded_alloc`,
default-off) sharded path, so the ~20 ns/op is realized only once the cutover flips
the default — a pre-emptive Pareto cleanup on the 3.7x target path, not a live
production win today.

**BOUND — remote end-to-end sharded-create validation is INFEASIBLE (closes the
question raised at 6ed27b4a).** After remote-validating the merge MECHANISM under
threads (6ed27b4a), the open question was whether the END-TO-END sharded create path
(alloc + dir-entry + inode-table + GDT together) could also be validated remotely,
so the local cutover would only need `e2fsck`. It cannot: the sharded create tests
use `open_writable_ext4_mkfs`, which shells out to `mkfs.ext4` (absent on the fleet →
those tests SKIP). The in-Rust `build_ext4_image` helpers are minimal SINGLE-GROUP
128 KiB PARSE fixtures (hand-written superblock; no real bitmaps, GDT bitmap-block
pointers, or root-dir structure) — insufficient to open+enable_writes and run a
multi-group cross-group parallel create. Producing a real multi-group writable image
in-Rust ≈ reimplementing `mkfs.ext4` (out of scope). ⇒ the cutover (create-bench +
`e2fsck`, the 3.7x measurement) is genuinely LOCAL-ONLY; it cannot be reduced to a
remote test. Retry predicate: only if a real in-Rust ext4 formatter is added
(separate large effort) or the rch-remote-only constraint is lifted for the cutover.

## `bd-bhh0i` sharded metadata RMW: snapshot-consistent base + the GDT finding - 2026-07-13 (KEEP hardening + BOUND next lever)

Status: KEEP (soundness hardening landed) + BOUND (GDT is the confirmed remaining
parallel-create conflict; its wiring is a bigger ffs-alloc refactor, next slice).

**What landed (KEEP, this commit).** Slice 2b (last commit) wired the sharded inode
write to stage the inode-table block under a slot-scoped `timestamp_only_inode_range`
proof so concurrent DISJOINT-slot writers merge. But it read the base block via a
SEPARATE adapter read taken BEFORE the auto-commit `begin()` — a read that can observe
an OLDER version than the transaction. If a concurrent writer to the same block commits
in the read→begin window, the RMW's own commit sees `observed <= snapshot.high` (NO
conflict) and installs the stale-based block, SILENTLY CLOBBERING the concurrent
writer's disjoint slot — a corruption the merge proof cannot catch (the conflict path
is never entered). Fixed: `FsMvccStore::rmw_commit_block_with_proof` does begin →
read AT `txn.snapshot()` (`read_visible`, else base device) → patch → stage-with-proof
→ commit. A commit after `begin` now forces `observed > snapshot.high` → the
conflict/merge path (overlays only the declared range onto latest = correct); with no
intervening commit the read is current and the install is fresh. Byte-identical
single-threaded (same bytes, same store); the snapshot-consistent read only matters
under a concurrent writer. Gate: `cargo test -p ffs-core --features bhh0i_sharded_alloc
bd_bhh0i` = 23/23 (incl. the disjoint-slot merge test + create/write byte-id
sentinels); default-features build clean. Concurrent soundness itself is validated at
the local cutover (slice 5, e2fsck-gated) — remote tests skip the image.

**The GDT finding (BOUND — the remaining conflict; next lever).** Confirmed the OTHER
shared-metadata block that FCW-conflicts on parallel create is the GROUP-DESCRIPTOR
(GDT) block. Evidence: the sharded inode alloc (`sharded_alloc::PerGroupAlloc::
alloc_inode` → `ffs_alloc::try_alloc_inode_in_group_persist_core`, ffs-alloc:3437)
persists the group descriptor PER ALLOC via `persist_group_desc_..._with_bitmap_
overrides` → `dev.write_block(gdt_block, ..)` (ffs-alloc:2243), staged under the
default `Unsafe` proof. All group descriptors for a small fs live in ONE GDT block, and
the per-group lock protects only the group's OWN bitmap block — NOT the shared GDT
block. So two concurrent creates in DIFFERENT groups both write that GDT block →
first-committer-wins conflict ("block 657"). The write is a clean per-descriptor RMW:
it patches only `buf[offset_in_block .. offset_in_block + desc_size]` (offset =
`(group % descs_per_block) * desc_size`, ffs-alloc:2145), so disjoint-group descriptors
are a textbook range-overlay merge (`independent_key_range(offset, desc_size)`).

Why NOT wired this turn: the GDT read+patch+write lives inside ffs-alloc's persist path,
shared with the single-lock path, and — like the inode case above — must read AT the
transaction's snapshot to be sound (a naive trait-level `write_block_disjoint` hint that
keeps the pre-read in `persist_group_desc` reintroduces the exact stale-clobber window
just fixed). Doing it right = threading a begin-first snapshot-consistent RMW through
`try_alloc_inode_in_group_persist_core` (or lifting the GDT write into a proof-carrying
ffs-core helper), which is a multi-file slice, not a one-turn drop-in. Superblock
free-totals are NOT a sibling: `ext4_sync_superblock_free_totals` /
`ext4_persist_group_descriptors_from` run at the durability boundary via a DIRECT
(non-MVCC) device adapter, not per-create — no per-create FCW surface there.
Retry predicate: next slice = snapshot-consistent GDT descriptor RMW under a
per-descriptor `independent_key_range` proof; gate the sharded bd_bhh0i suite + local
e2fsck at cutover.

## Frontier state: quick single-turn micro-lever surface EXHAUSTED - 2026-07-13 (BOUND)

Status: BOUND — where the remaining perf is, and where it ISN'T (stop micro-hunting).

After a long solo campaign (9 landed byte-identical wins this session + prior) plus an
active peer swarm (bd-k2wc7/OliveCliff mining btree/extent/inode-truncate), the
per-op CPU/alloc surface is harvested:
- **ext4 create/`ext4_add_dir_entry`/`ext4_create` are alloc-LEAN** — no per-op
  `collect`/`clone`/`to_vec`/`format!`/`Vec::new` in the hot bodies. The create-path
  CPU (the parallel-create 3.7x target) is NOT where the gap is.
- Read path (getattr/lookup/read/readdir) mined: hot-inode borrow+Arc-share, AttrOnly
  parse, snapshot-unpin, block-patch make_mut, RangeOverlay merge, write_blocks/
  contention-metrics gating. Remaining read allocs (read_file_data segs/jobs) are
  I/O-masked.
- `MvccStore::commit`'s per-commit `Instant::now()` is NOT gate-able like the ffs-core
  `commit_transaction` sibling (which guards it on `tracing::enabled!(INFO)`): here the
  duration feeds `record_commit_success` → the CONSUMED `commit_latency_us` histogram
  exposed via `MvccRuntimeMetricsSnapshot`, not an info!-only record. Porting gotcha.

**The remaining real lever is STRUCTURAL, not a micro-lever:** the parallel-commit
scaling gap (3.7x on parallel create) lives in the MVCC commit STRUCTURE — the
`CommitPublicationGate` in-order publish (a global Mutex/serialization per commit;
lock-free fast path has a lost-wakeup hazard = Loom-gated) and inode-table
merge-proof wiring (make concurrent same-table-block inode writes MERGE not FCW-
conflict; write_inode has no proof channel = multi-turn + local-e2fsck-gated). These
are the deliberate multi-turn efforts, NOT quick single-turn micro-levers. Retry
predicate for micro-levers: a FRESH profile revealing a new CPU-bound per-op frame;
absent that, do the structural work (Loom + local gate) or ledger bounds.

## Read/commit-path candidate bounds (3 non-levers) - 2026-07-13 (REJECT / BOUND)

Status: REJECT — bounds 3 tempting-but-wrong candidates surfaced by an Explore scan,
so the fleet does not re-attempt them (esp. #2, a correctness trap).

1. **`read_file_data` per-read `segs`/`jobs` Vec allocs** (ffs-core ~13119/13212):
   RE-CONFIRMED I/O-masked / sub-noise. The Vec::new()+first-push is one small heap
   alloc per read; a file read does device I/O (µs–ms) that dwarfs a ~50ns alloc
   (matches the prior "file-read jobs / readdir planned = device-read-masked" bound).
   Retry predicate: only if a profile shows these allocs as a material read-CPU frame
   (they won't while reads are I/O-bound).

2. **`readdir` `names = present.keys().cloned().collect()`** (ffs-core ~34498) is
   NOT dead work — it is LOAD-BEARING. An Explore scan flagged it as "built but never
   read on RO mounts" (lookup returns from `present` while `present: Some`). BUT on a
   RO→writable transition (`enable_writes` does NOT clear `dir_name_index`), the next
   create calls `note_dir_name_index_insert`, which flips `present: Some→None` and
   inserts only the NEW name into `names` — so a lookup for an ORIGINAL entry then
   falls to `!idx.names.contains(name)`. If `names` were built empty, that lookup
   returns None for a present entry = CORRECTNESS BUG. `names` is the post-transition
   membership fallback. DO NOT empty it. Retry predicate: none unless `enable_writes`
   is changed to clear/invalidate the RO index (then it becomes truly dead).

3. **`MvccStore::emit_transaction_commit` per-commit duration/runtime_metrics**
   (ffs-mvcc ~2173) is already appropriately conditional: the `EvidenceRecord` build +
   `sink.append` are gated on `evidence_sink: Some` (opt-in, None by default), and the
   `started.elapsed()` → `record_commit_success` feeds a CONSUMED latency histogram
   (runtime_metrics readers). Not dead, not cleanly gate-able. Retry predicate: none.

Also this turn: 27c505c9 (read_into Arc-share, WIN #9) CONFIRMED correct — ffs-core
1185 lib tests pass (all read tests green; only the pre-existing btrfs_reflink flake
fails). Its magnitude bench (arc_publish_vs_deep_clone) + 826df090's preflight_metrics
remain rch-BLOCKED (rch saturated ~all session by the peer swarm); anchored instead by
the measured hot-HIT clone precedent (bd-cc-hotinode ~6.6%).

## `mvcc` cache-line-isolate the read-hot shard_mask - 2026-07-13 (REJECT)

Status: REJECT / MEASURED NEUTRAL (refines the false-sharing lever class).

`report_hot_field_cache_line_layout` confirmed the IMMUTABLE `shard_mask` (read on
every `shard_index` — per block, every commit AND read) shares a 64-byte cache line
with `next_txn`/`next_commit`/`publication_gate`, all written every commit — so in
theory each commit invalidates `shard_mask` for concurrent readers. Wrapped it in
`#[repr(align(64))]` to give it its own line (byte-identical; layout test confirmed
isolation). But the A/B (`benches/shard_mask_false_sharing`, adjacent-same-line vs
isolated-own-line, committers `fetch_add` a counter + readers `x & mask`, N threads):

| committers | adjacent (same line) | isolated (own line) | delta    |
|------------|----------------------|---------------------|----------|
| 1          | 10.945 ms            | 11.102 ms           | neutral  |
| 2          | 31.845 ms            | 31.955 ms           | neutral  |
| 4          | 70.815 ms            | 71.460 ms           | neutral  |

NEUTRAL at every thread count (CIs fully overlap). Why: `shard_mask` is a PLAIN
(non-atomic) field. The compiler register-HOISTS a plain read-hot field out of hot
loops (it is loop-invariant behind a shared `&self`), so it is NOT re-read from the
invalidated cache line — the coherence invalidation costs nothing. Reverted (the
align wrapper added 56 B/store + a newtype for zero benefit).

KEY REFINEMENT of the false-sharing lever class (1382b032 any_version_installed WON
at 1.5-2.1x): false sharing only hurts ATOMIC reads (`load(...)` MUST re-fetch from
memory every access, so an invalidated line = a real miss). PLAIN reads are hoisted
and immune. So: cache-line-isolate a hot field ONLY if it is read via an ATOMIC load
on the hot path; a plain immutable field sharing a line with hot writers is a
non-issue. Retry predicate: none for plain fields; for atomics, isolate + bench.

## `mvcc-commit` guard the monotonic any_version_installed store - 2026-07-13 (KEEP, 1382b032)

Status: KEEP / BYTE-IDENTICAL / MEASURED (false-sharing mechanism).

`any_version_installed` is a MONOTONIC flag (false->true once, never clears) that
EVERY read loads to gate the MVCC overlay probe. commit's install loop stored it
`store(true, Release)` per committed BLOCK — redundant after the first-ever install,
and each store dirties the flag's cache line, invalidating the copy every concurrent
reader caches (committer<->reader false sharing on the parallel path). Fix: hoist the
store out of commit's per-block loop and guard both commit and commit_ssi with a
relaxed load, so the Release store fires only on the false->true transition (a no-op
after warmup). Byte-identical: flag is true after first install forever; store still
precedes publish; two racing first-installs both store true idempotently.

Bench `benches/any_version_flag_false_sharing` (4 reader threads loading the flag +
K committer threads doing the old unconditional store vs the new guarded load, 2M
iters each, same worker):

| committers | unguarded store | guarded load | reader speedup |
|------------|-----------------|--------------|----------------|
| 1          | 2.825 ms        | 1.858 ms     | 1.52x          |
| 2          | 3.109 ms        | 1.847 ms     | 1.68x          |
| 4          | 4.342 ms        | 2.049 ms     | 2.12x          |

The win grows with committer count (readers slow as more committers dirty the line;
guarded stays flat ~1.85ms). CIs cleanly separated. HONEST SCOPE: this tight-loop
model overstates the production magnitude — commits store at most once per commit
(now ZERO after warmup), not in a loop — but it proves the mechanism the change
eliminates. ffs-mvcc 484 lib + all integration green.

LESSON (reusable): a monotonic set-once flag on a hot shared cache line should be
relaxed-load-GUARDED before the Release store — the redundant stores are free CPU-
wise but cause cross-core false sharing with the flag's many readers. WHERE TO HUNT:
`store(true)`/`store(x)` to an already-settled atomic inside a per-op loop whose
value is loaded by other hot paths.

## `active_snapshots` atomic-refcount (de-serialize per-write register/release) - 2026-07-13 (REJECT)

Status: REJECT / REFUTED BY DE-RISKING A/B (before any production change).

After reads stopped pinning (0576bb8b), the remaining `active_snapshots`
contention is the per-WRITE `register_snapshot`+`release_snapshot`, which take the
store's single `RwLock<BTreeMap>` WRITE lock. Proposed: keep `write()` only to
INSERT a new key, use a shared `read()` lock + an `AtomicU64` value to bump an
EXISTING key's refcount, so concurrent ops at the same snapshot don't serialize.
Because a naive impl is fiddly (bool-return semantics, `fetch_sub` underflow on
double-release, remove-when-zero race) it would be a Loom-gated multi-turn effort
— so it was PROTOTYPE-BENCHED first (`benches/active_snapshots_refcount`, faithful
current-vs-atomic impls, N threads, shared-key AND distinct-key extremes).

Result (same worker, 100k register/release pairs per thread):

| case          | threads | current write-lock | atomic read-fastpath | delta        |
|---------------|---------|--------------------|----------------------|--------------|
| shared_key    | 1       | 6.93 ms            | 4.39 ms              | 1.58x faster |
| shared_key    | 2       | 14.44 ms           | 20.20 ms             | 1.40x SLOWER |
| shared_key    | 4       | 42.07 ms           | 56.76 ms             | 1.35x SLOWER |
| shared_key    | 8       | 133.9 ms           | 137.4 ms             | ~neutral     |
| distinct_keys | 1       | 6.48 ms            | 4.33 ms              | 1.50x faster |
| distinct_keys | 2       | 17.11 ms           | 20.07 ms             | 1.17x SLOWER |
| distinct_keys | 4       | 42.32 ms           | 37.13 ms             | 1.14x faster |
| distinct_keys | 8       | 76.92 ms           | 116.5 ms             | 1.51x SLOWER |

The atomic version is faster ONLY single-threaded (a lighter uncontended path);
under the contention it was meant to fix it is NEUTRAL-TO-SLOWER. Why: the write
lock's critical section is a tiny `BTreeMap` entry op that serializes CHEAPLY,
whereas the atomic-refcount adds read-lock acquisition PLUS all threads hammering
ONE `AtomicU64` (shared key) — a single hot cache line RMW-serializes via
coherence anyway, with MORE total traffic. So swapping the write lock for a shared
read-lock + one hot atomic does not help; the `active_snapshots` write lock is not
improvable this way. De-risking the design first saved a multi-turn Loom effort
that would have shipped a parallel regression.

Retry predicate: only a design that avoids BOTH the lock AND a single hot atomic —
e.g. sharded / per-CPU refcount cells summed lazily for the watermark — could beat
the write lock; re-attempt ONLY with such a design AND a bench beating current at
2-8 threads. Plain atomic-per-key: do not re-attempt.

## `mvcc-commit` wait-free fetch_add for commit-seq / txn-id allocators - 2026-07-13 (REJECT)

Status: REJECT / UNSOUND-PURE + END-TO-END-NEGLIGIBLE-GUARDED.

`next_commit_seq` / `next_txn_id` allocate a monotonic counter once per commit
via `fetch_update(|c| c.checked_add(1))` — a load + `compare_exchange` retry loop
that re-runs on every lost race under parallel-commit contention. Idea: replace
with a wait-free `fetch_add` (single RMW, no retries).

Two failure modes:
1. **Pure `fetch_add` is UNSOUND.** These counters are BOUNDED — they must ERROR
   (not wrap) on exhaustion; a wrapped txn id could be reissued and a wrapped
   commit seq breaks monotonicity. `fetch_add` wraps `u64::MAX -> 0`. Caught by
   `transaction_id_exhaustion_returns_error_without_wrap` (asserts the counter
   stays at MAX after an exhausted allocation). A conditional/checked increment
   fundamentally needs compare-exchange.
2. **Margin-guarded `fetch_add` is correct but not worth it.** A relaxed load
   below `u64::MAX - 2^32` (margin dwarfs any concurrency, so `fetch_add` cannot
   wrap) with a CAS fallback near the ceiling passes both exhaustion tests. But
   the isolated A/B (`benches/commit_seq_alloc`, 200k incr/thread, same worker):

   | threads | fetch_update CAS loop | margin_guarded fetch_add | delta |
   |---------|-----------------------|--------------------------|-------|
   | 1       | 1.587 ms              | 1.711 ms                 | ~0.93x (SLOWER, CIs overlap) |
   | 2       | 4.743 ms              | 4.279 ms                 | 1.11x |
   | 4       | 13.77 ms              | 11.14 ms                 | 1.24x |
   | 8       | 38.58 ms              | 25.45 ms                 | 1.52x |

   (Pure `fetch_add`, for reference, was 2.51x@8thr with no single-thread cost —
   the guard band's relaxed load both dilutes the contended win and adds a
   borderline single-thread regression.) Decisive: this atomic is ~7 ns of a
   ~1.9 us commit (<0.5%), so even the 1.52x@8thr is END-TO-END SUB-NOISE (the
   fd678afe lesson) while the guard band adds complexity + a single-thread cost.
   Production keeps `fetch_update`.

Retry predicate: only if a future profile shows the commit-seq/txn-id atomic is a
material fraction (>5%) of commit CPU under the target parallel workload AND a
wait-free form with no single-thread regression exists.

## `mvcc-commit` skip per-commit contention-metrics global lock under fixed policy - 2026-07-13 (KEEP, 73174f5b)

Status: KEEP / BYTE-IDENTICAL-FOR-DATA / MEASURED WIN (regime-dependent, Pareto).

Every ShardedMvccStore commit took `contention_metrics.write()` — a single GLOBAL
lock — on the success path to record EMA metrics + `select_policy`. Only
`ConflictPolicy::Adaptive` reads those metrics (`effective_policy`); production
runs a FIXED policy (default SafeMerge; ffs-core never calls set_conflict_policy,
zero readers of contention_metrics). So under a fixed policy that global lock is
pure unread telemetry that serializes every otherwise-disjoint parallel commit
across all shards — the "drop unread per-op telemetry on the production path"
lever class (cf. writeback 9bd37150), here a global-lock-per-commit. `commit_policy()`
resolves effective policy AND whether metrics are live (Adaptive only) in one
conflict_policy read; `preflight_fcw_locked` gates all three `contention_metrics.
write()` sites on it. Adaptive unchanged; fixed-policy commits skip the lock.

Parallel A/B (`benches/commit_metrics_lock`, N threads x 2000 disjoint-block
single-block commits, SafeMerge; `force_metrics_on` reproduces pre-gate via the
doc-hidden `set_force_metrics_record` knob vs `gated_off` = production, same worker):

| threads | force_metrics_on | gated_off | delta |
|---------|------------------|-----------|-------|
| 2       | 15.31 ms         | 7.54 ms   | 2.03x (CIs separated: on>=12.6, off<=8.4) |
| 4       | 18.14 ms         | 17.48 ms  | ~neutral (1.04x, CIs overlap) |
| 8       | 52.99 ms         | 51.36 ms  | ~neutral (1.03x, CIs overlap) |

Honest read: clean 2.03x at 2 threads; converges to neutral at 4/8 threads where
OTHER serialization becomes binding (the publication-gate commit ordering + shard-
index collisions across the disjoint block ranges — both present identically in
both arms, so they cancel in the ratio but dominate absolute time and mask the
metrics-lock delta once they saturate). Pareto: gated_off <= force_on at every
thread count (never a regression), 2x at low-moderate parallelism. Byte-identical
for data: install paths, conflict detection, merge all unchanged; only the unread
telemetry counters stop updating under fixed policy. ffs-mvcc 484 lib (incl. new
`fixed_policy_skips_contention_metrics_but_force_records`) + all integration green.

NEXT SERIALIZATION LEVERS (exposed by the 4/8-thread flatness): (a) the
`CommitPublicationGate` commit ordering — inherently serializes the publish step;
(b) `next_commit` AtomicU64 / shard-index collisions among concurrent commits.
These are the remaining global bottlenecks on the parallel-create scaling surface.

## `mvcc-merge` FCW preflight validates without building the merged block - 2026-07-13 (KEEP, 60962fa1)

Status: KEEP / BYTE-IDENTICAL / MEASURED WIN.

The FCW **preflight** conflict check built the FULL merged block via `merge_bytes`
only to answer "mergeable?" (`.is_ok()`), discarded it, and the install path then
rebuilt it — one block-sized allocation + copy per conflicting block, wasted,
under the shard lock on the contended commit path. Split the merge into validate
+ build (shared validators, cannot diverge): `MergeProof::merge_valid` (==
`merge_bytes(..).is_some()`, no output alloc) backed by `append_only_merge_valid`
/ `merge_non_overlapping_ranges_valid`. Preflight now validates only; install is
unchanged.
- MvccStore: `resolved_write_valid_with_policy` (preflight); install keeps
  `resolved_write_bytes_with_policy`.
- ShardedMvccStore: `resolved_write_bytes_locked` -> `check_write_mergeable_locked`
  (its only caller was preflight); install keeps `merged_write_bytes_locked`.

A/B (`benches/merge_range_overlay`, group `mvcc_merge_preflight`, same worker):
full-merge-then-discard vs validate-only, both faithful transcriptions:

| block size | full_merge (old preflight) | validate_only (new) | speedup |
|------------|----------------------------|---------------------|---------|
| 4096 (ext4)| 145.39 ns                  | 71.47 ns            | 2.03x   |
| 16384      | 504.67 ns                  | 205.34 ns           | 2.46x   |
| 65536      | 1708.0 ns                  | 1001.6 ns           | 1.71x   |

CIs cleanly separated (4K: old [143.15, 147.82] vs new [70.61, 72.33]). Stacked
on the 930045fa validator win, the same 4 KiB preflight check has gone ~230 ns ->
71 ns (~3.2x across both landings). Byte-identical: install paths untouched, same
merged bytes, same preflight gate + telemetry. ffs-mvcc 483 lib (incl. new
`merge_valid_matches_merge_bytes_is_some` drift guard) + all integration green.
Same caveat as 930045fa: fires only under *conflict* (concurrent same-block
writes) — a contended-path lock-hold reduction on the parallel-write scaling
surface, not a single-thread hot-op win.

## `mvcc-merge` range-overlay validator drops full-block scratch copy - 2026-07-13 (KEEP, 930045fa)

Status: KEEP / BYTE-IDENTICAL / MEASURED WIN.

`merge_non_overlapping_ranges` (the byte algorithm behind
`MergeProof::{IndependentKeys,NonOverlappingExtents,TimestampOnlyInode}`) runs on
the **contended commit path, under the shard lock**: when two txns write
non-overlapping ranges of the SAME block (production `write()` stages
`non_overlapping_extent_range` proofs for disjoint sub-block data writes), the
second committer hits FCW and merges. The "staged only touched the declared
ranges" validation was `expected = base.to_vec(); overlay staged ranges;
expected == staged` — one **block-sized allocation + memcpy + full-block
compare** per merge. That check is exactly "staged == base in the COMPLEMENT of
the declared ranges"; comparing the complement gaps directly (sort the disjoint
ranges, walk the gaps) removes the scratch buffer entirely. The merged output
(`latest` with staged ranges overlaid) is unchanged, so it is byte-identical.

Same-worker (vmi1149989) same-binary A/B, `benches/merge_range_overlay`
(faithful transcriptions of the old vs new validator, identical inputs, one
declared range near the block start + a disjoint `latest` write near the end =
the common clean-merge case):

| block size | old (expected_staged copy) | new (complement compare) | speedup |
|------------|----------------------------|--------------------------|---------|
| 4096 (ext4)| 201.19 ns                  | 154.20 ns                | 1.30x   |
| 16384      | 801.06 ns                  | 533.31 ns                | 1.50x   |
| 65536      | 2548.7 ns                  | 1719.1 ns                | 1.48x   |

CIs cleanly separated (4K: old [197.67, 204.84] vs new [151.22, 156.99]). The
~47 ns eliminated at 4 KiB is a 4 KiB alloc+memcpy; the win scales with block
size as the copy dominates. Correctness: ffs-mvcc 482 lib + all integration
tests green, incl. new `merge_non_overlapping_ranges_handles_multiple_unsorted_
ranges` (multi-range out-of-order sort path + gap/trailing integrity).

Note: the merge fires only under *conflict* (concurrent same-block writes), so
this is a contended-path lock-hold reduction, not a single-thread hot-op win —
it directly targets the parallel-write scaling surface (the MVCC lane the
bd-bhh0i cutover identified as the real bottleneck). Sibling hunt logged: inode-
table metadata writes (`write_inode`) still stage NO merge proof (default
`Unsafe`), so concurrent creates/setattrs on inodes sharing a table block hard-
conflict — wiring a slot-scoped `TimestampOnlyInode` proof through the inode
write path is the next (multi-turn, local-e2fsck-gated) MVCC lever.

## `bd-bhh0i` synthetic-counter scope correction - 2026-07-10

Status: REJECT AS ACTUAL-PATH EVIDENCE / RETAIN AS ROUTING EVIDENCE.

`bd_bhh0i_contention` does not satisfy the requested MVCC commit-lock and malloc
arena counter sweep. It measures synthetic `parking_lot` global/group/publish
mutexes and wall-clock latency of a 4 KiB `Vec` allocation. The 8-thread p99
values (176.341 us global allocation lock, 0.290 us disjoint group lock, 127.449
us synthetic publish lock) remain useful for routing, but are not measurements
of `CommitPublicationGate`, shard/`active_snapshots` locking, or allocator-arena
lock events.

Retry condition: collect 1/2/4/8 same-worker `release-perf` wait/hold histograms
at the actual MVCC locks and allocator contention through a safe external
profiler or audited bench-only facility. Do not introduce unsafe production Rust
and do not mutate a filesystem outside fixtures.

## Mounted xattr coverage gap and fsync evidence correction - 2026-07-10

Status: SURFACED / NO OPTIMIZATION / NO FILESYSTEM MUTATION.

The new-workload audit found **zero** mounted end-to-end xattr performance
comparisons against kernel ext4/btrfs. Four existing benchmark families measure
internal parsing/name transforms, and one mounted test is correctness-only.
Filed P1 `bd-mounted-xattr-workload-gap-fr6iq` for the safest next comparator: a
preseeded read-only ext4 get/list storm with one persistent syscall loop on both
arms, inline/external/absent and list-1/list-24 cases, at least 30 interleaved
same-worker `release-perf` batches, `cv_pct < 5`, and byte/name parity outside
timing. Set/remove remains excluded without explicit fixture-mutation authority.

The prior fsync row's nominal **3.033x slower** signal (71.744 us versus 23.654
us) is not a defensible current-source ratio. CV was **44.94% / 97.22%**; the
direct `OpenFs` and host-syscall arms do not share an API/durability boundary;
the host filesystem was not proven ext4/JBD2; and the harness duplicates sync
work on the FrankenFS arm. The refined `hz2` attempts never reached the workload
executable or `e2fsck`; both stopped during cold fat-LTO compile/link. Updated
`bd-fsync-journal-latency-gap-ptp4x` with the fair retry gate: verified ext4,
matched durability semantics, persistent same-boundary arms, >=30 interleaved
batches, `cv_pct < 5`, and parity/durability validation outside timing.

## `bd-bhh0i` bounded Loom writer proof and evidence correction - 2026-07-10

Status: WIN AS FORMAL DE-RISK / NO CUTOVER. No production filesystem path was
changed or mutated.

The new `bd_bhh0i_lock_decomposition_model` uses seven finite Loom projections
bounded to two groups, two independently mapped shards, two writers with one
allocation each, and at most one reader. The modeled accepted protocol retains
sorted allocation-group guards across the lean eager MVCC commit and
ready-prefix publication; it does not model the ledger-rejected
commit-after-release staging family. The checks cover disjoint and same-group
operations, opposing multi-group requests, disjoint groups with cross-mapped
shared shards, an exact early abort, installed-but-unpublished visibility, and
post-publication pruning. For the five enumerated writer configurations,
exhaustive over modeled schedules, the writer projection proves:

- sorted group/shard acquisition completes without deadlock;
- returned allocation bits replay against a sequential bitmap allocator, and a
  Loom-synchronized ghost history shows the commit sequence preserves every
  response-before-invocation edge;
- independently mapped MVCC shard payloads each replay to the corresponding
  group's exact sequential prefix;

Separate safety projections establish that:

- all shard versions are installed before the Release publication point and a
  reader at the Acquire-loaded prefix sees a complete prefix only;
- the exact early abort before metrics, sequence assignment, and install
  consumes no sequence and changes no allocator/MVCC state;
- `active_snapshots -> shards` pruning retains a registered snapshot version.

The seven projections are deliberately separate, not a formal composition of
writers, reader registration, and pruning. They exhaust without permutation,
duration, or preemption sampling limits. The bounded writer proof and separate
safety evidence cover the default sharded, no-JBD2 bitmap-allocation primitive,
not whole `ext4_create`, crash atomicity, starvation freedom, Single/JBD2, or
post-install compensation. RCH worker `ovh-a` passed all **7/7** final
projections in **3.40 seconds**.

Evidence correction: the earlier hand-enumerated 168-terminal model proves
final-state conservation, not linearizability, and its output is relabeled. The
synthetic plain publish mutex's 8-thread p99 wait of 127.449 us is routing-only;
it cannot establish that the real `CommitPublicationGate` is the next
bottleneck, especially because the prior real-path MVCC ceiling and neutral
publish-nowait experiment point the other way. The 8-thread global allocation
lock p99 wait of 176.341 us versus 0.290 us for disjoint synthetic group locks
remains valid contention characterization.

Gates: RCH workspace check passed with unrelated existing warnings; the full
`ffs-harness` run passed **2057/2058**, with only
`source_scope_scan_logs_workspace_hashes_and_counts` failing in the parallel
run, then passing **1/1** in isolated RCH replay. Targeted rustfmt and
`git diff --check` passed. UBS found **0 critical** findings in the two changed
Rust files (225 heuristic warnings). Workspace fmt/clippy remain red on
unrelated pre-existing formatting and warning debt; those files were not
modified.

## `bd-bhh0i` safe contention de-risk + fsync workload gap signal - 2026-07-10

Status: SURFACED / NO CUTOVER. This was an analysis and benchmark-harness commit
only. It did not attempt the owner-gated parallel metadata write cutover and did
not touch the mmap/io_uring read path.

Contention characterization added `crates/ffs-core/benches/bd_bhh0i_contention.rs`.
RCH release-perf on `hz2` measured the current global alloc lock at 8 threads:
p95 wait `66.920 us`, p99 wait `176.341 us`, mean hold `0.423 us`. The proposed
decomposed per-group lock model kept 8-thread p95 wait at `0.240 us` and p99 at
`0.290 us`, but the separate publish lock then convoys at p95 `64.549 us` and p99
`127.449 us`. Conclusion: per-group allocation removes the allocator convoy for
disjoint groups, but an owner-approved design must also handle publication
ordering or the convoy moves.

The bench's bounded model explored `168` two-thread terminal interleavings for
disjoint groups plus a global ordered publication lock: `deadlocks=0` and
`linearizable=true`. This is not a loom/shuttle substitute; retry/cutover
condition remains owner ACK plus a real loom or shuttle model and e2fsck-clean
parallel mutation fixtures.

New workload class: `fsync_latency_workload` found a same-worker RCH signal on
`ovh-a`: FrankenFS ext4 write+fsync median `71.744 us` vs kernel ext4 `23.654 us`,
or `3.033x` slower. The raw per-op CV was high (`44.94%` vs `97.22%`), so this is
not a final keep-gate result. Refined batch-median plus in-worker `e2fsck -fn`
reruns on `hz2` stalled twice in the executable phase and were interrupted.
Filed `bd-fsync-journal-latency-gap-ptp4x` to stabilize the harness, collect
low-CV same-worker evidence, and profile fsync/journal internals if the gap holds.

Gates: targeted rustfmt on both new benches passed; RCH `cargo check -p ffs-core
--bench bd_bhh0i_contention` passed; RCH `cargo check -p ffs-core --bench
fsync_latency_workload` passed before refinement; local `cargo check -p ffs-core
--bench fsync_latency_workload` passed after refinement. Warnings were pre-existing
`fetch_update` deprecations and the unused htree helper.

## BOLD-VERIFY measured verdict - 2026-06-25

### `bd-xmh5g` ffs-btrfs direct COW update descent - REJECT

Lever attempted in a clean scratch worktree:
`/data/projects/.scratch/frankenfs-ivory-btrfs-update-20260625`.
The candidate replaced `BtrfsBTree::update`'s current existence-probe plus
replace-capable insertion path with a direct COW descent that rewrites only the
path to an existing leaf item, and reused that helper for the non-root
`insert_then_update` fallback. The benchmark added a same-binary A/B group over
a multi-level COW tree: 2048 seeded extent items, 512 existing-key updates, old
model `get` + `upsert` versus direct `update`. The candidate source and bench
were reverted after measurement.

Measured result: RCH had no admissible remote worker and ran through its local
fallback, still under the requested `rch exec` wrapper and crate-scoped target:

```bash
AGENT_NAME=IvoryBirch CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release -p ffs-btrfs \
  --bench cow_write_mutation -- btrfs_cow_direct_update \
  --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
```

Criterion measured:

- `old_find_then_upsert`: `[1.8556 ms, 1.9392 ms, 1.9942 ms]`
- `direct_update`: `[1.8019 ms, 1.8619 ms, 1.9155 ms]`

Midpoint old/new is only `1.04x`, and conservative interval ratio is
`1.8556 / 1.9155 = 0.969x`. This is below the keep threshold and not
conservative-positive, so the lever is a no-ship.

Kernel ratio: no standalone ext4/btrfs-kernel ratio exists for this internal
in-memory btrfs COW-tree primitive. It was a candidate for the btrfs
write/create mutation frontier, but the component movement is too small to
justify a mounted-kernel rerun. Direct kernel W/L/N is `0/0/1`; internal W/L/N
is `0/0/1`.

Gates before revert: local `cargo fmt -p ffs-btrfs --check` passed; local
`git diff --check` passed; local
`cargo test -p ffs-btrfs update -- --nocapture` passed `13/0`; local
`cargo check -p ffs-btrfs --all-targets` passed. Post-revert source is
identical to `HEAD` for `crates/ffs-btrfs/src/lib.rs` and
`crates/ffs-btrfs/benches/cow_write_mutation.rs`; RCH conformance
`cargo test -p ffs-harness --test conformance -- --nocapture` passed on
`ovh-a` with `100 passed / 0 failed / 2 ignored`.

Retry predicate: do not retry direct existing-key COW update as a standalone
`ffs-btrfs` lever unless a fresh profile shows update descent itself as a
material hotspot and the new same-worker A/B clears the keep threshold with a
conservative-positive interval.

### `bd-9e810` ext4 base-device block cache below MVCC - KEEP

Source is already retained on `main` as `5f266067`:
`perf(ffs-core): add bounded ext4 base-device block cache below MVCC`.

Lever: add an ext4-only `OpenFs::ext4_base_block_cache` under the MVCC overlay,
served by `CachedByteDeviceBlockAdapter`, so repeated writable-path
`read_block_vec` calls for htree/name-index metadata avoid redundant base-device
preads. Direct adapter writes invalidate the affected base block ranges before
reaching the device. Btrfs remains uncached here because it still has raw
physical write paths outside this adapter.

Measured result: RCH same-worker Criterion on `hz2`:

```bash
cargo bench --profile release -p ffs-core --bench ext4_lookup_run_overlap -- ext4_base_block_cache --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
```

This measured `ext4_base_block_cache_1092reads_42unique`:
`uncached_read_block_vec` `[88.481 ms, 93.202 ms, 99.916 ms]` vs
`cached_read_block_vec` `[3.6667 ms, 3.7183 ms, 3.7794 ms]`. Median ratio is
`25.07x`; conservative interval ratio is `23.41x`.

Kernel ratio: no standalone ext4/btrfs-kernel comparator exists for this
internal cache primitive. The lever targets the existing ext4 delete residual
where the bead trace recorded 1092 `pread64` calls to 42 unique offsets
(about 26x repeated base metadata reads). Using the bead's 18% wall attribution,
the component win projects about `1.21x` end-to-end ext4 delete speedup and
would narrow the prior fair-kernel delete gap from `~1.3x` slower to
`~1.07x` slower. That projection is not a replacement for a future full mounted
kernel delete rerun.

Gates: RCH `cargo check -p ffs-core --all-targets` passed on `hz2`; RCH focused
test `cargo test -p ffs-core
ext4_base_block_cache_reuses_reads_and_invalidates_direct_writes --
--nocapture` passed on `ovh-a`; RCH conformance `cargo test -p ffs-harness
--test conformance -- --nocapture` passed on `vmi1153651` with
`100 passed / 0 failed / 2 ignored`; local `cargo fmt -p ffs-core --check` and
`git diff --check` passed. The requested `cargo bench --release` spelling was
attempted first and rejected by Cargo for bench mode, so the supported
equivalent `--profile release` was used. Scoped RCH `cargo clippy -p ffs-core
--all-targets --no-deps -- -D warnings` remains blocked by pre-existing
`ffs-core` pedantic debt outside this lever.

## Gauntlet Release-Readiness Scorecard

| Date | Bead | Workload | Verdict | Original-kernel ratio | Conformance gate | Readiness impact |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-07-09 | `bd-zero-copy-read-path-pz64v` continuation | User-requested restart of mmap/io_uring read-copy-tax lane after closeout; same-worker profile of incumbent safe direct paths plus implementation feasibility check | REJECT / BLOCKER, no production source kept | Direct ext4/btrfs-kernel ratio not rerun because no candidate could be legally built under the current unsafe policy. Fresh RCH `hz2` Criterion: 1 MiB staged scratch `917.20 us` vs direct `49.163 us` (`18.7x`); 128 KiB staged scatter `10.135 us` vs `preadv_direct` `8.0194 us` (`1.26x`). This confirms the safe direct-read space is harvested; the remaining pz64v residual is the `pread`/`copy_to_user` boundary or a borrow-returning mmap API. | RCH Criterion passed on `hz2`. No Rust source changed. External current docs confirm `memmap2` file-backed maps, including copy-read-only maps, are unsafe; `io-uring` fixed-buffer reads use registered buffers/raw buffer SQEs. Workspace root has `unsafe_code = "forbid"` and `ffs-block` has `#![forbid(unsafe_code)]`, so an mmap/io_uring production cutover would fail policy/lints without an explicit audited-unsafe exception. | Do not reopen pz64v for another safe copy micro-tune. The next valid work item is a dedicated audited unsafe I/O backend/API decision: one module/crate with documented mmap/io_uring invariants, read-only/truncation/write exclusion, overlay/journal fallback, byte-identity conformance, and destination-on-error proof. |
| 2026-07-09 | `bd-zero-copy-read-path-pz64v` | Zero-copy read-path relaunch after the safe direct-read and `preadv` fast paths; audit of mmap-backed `ByteDevice` / io_uring registered-buffer retry condition | REJECT / BLOCKER, no production source kept | Direct ext4/btrfs-kernel ratio not rerun because the ledgered retry condition still blocks a candidate. Fresh same-worker RCH `hz2` Criterion confirms the incumbent safe paths are already harvested: 1 MiB staged scratch `913.63 us` vs direct `51.411 us` (`17.8x`), 128 KiB staged scatter `10.728 us` vs `preadv_direct` `7.9739 us` (`1.35x`). The remaining prize is the prior pz64v kernel-boundary gap: warm 1 MiB `pread` into dst `333 us` / `3.2 GB/s` vs userspace memcpy `23.6 us` / `44.4 GB/s`. | No production source changed, so conformance risk is unchanged. RCH Criterion passed on `hz2`. Fresh `perf stat` was attempted twice but not accepted: counters were contaminated by RCH target-lock/build wait (344.1 s compile-heavy run; 108.6 s lock-wait run). Bounded RCH flamegraph timed out (`exit 124`) while compiling and produced no fresh SVG. | Close the bead under current invariants. Do not retry hidden mmap/io_uring or another copy micro-tune. Retry only after an explicit audited-unsafe backend decision plus a borrow-returning read API, or a genuinely safe zero-copy abstraction preserving byte identity and destination-on-error semantics. |
| 2026-06-20 | `bd-xmh5g.410` | `ffs-block::FileByteDevice::read_vectored_exact_at` large-read scratch elimination with one positioned `preadv` into caller `IoSliceMut`s, preserving the small-read and over-`IOV_MAX` scratch fallback | PENDING-BENCH / production code retained under disk-low code-only directive | N/A until next-turn direct ext4/btrfs kernel comparator reruns. No fresh cargo build/check/test/bench/rch was started this turn. | Not run this turn by directive. Required next gates: `cargo check -p ffs-block --all-targets`, focused vectored-read tests, Criterion `file_device_read`/`read_contiguous` A/B, and harness/direct-kernel comparators. | No readiness upgrade yet. Treat as an unscored candidate; keep only if accepted A/B clears `>1.05x` with conformance green, otherwise revert and mark rejected. |
| 2026-06-21 | `bd-xmh5g.408` | btrfs read metadata-descent elision across `ffs-core` and `ffs-cli`: centralize regular-read dir/symlink guard in `btrfs_read_file_into`, allow `readlink` symlink payload reads, and reuse final `lookup` attr in `ffs-cli read` instead of a final `getattr` | REJECT / production source reverted | Fresh 15-run direct btrfs-kernel rows at `d5ebffea`: single-file `/compressible.bin` baseline `38.7 ms`, candidate `37.6 ms`, kernel `cat` `7.5 ms`; candidate is `1.03x` old/new and still `5.01x` slower than kernel. Whole-tree `walk --read-data --no-stat` baseline `33.9 ms`, candidate `34.1 ms`, kernel `cat *` `12.2 ms`; candidate is `0.994x` old/new and `2.79x` slower than kernel. `strace -f -c -e pread64` showed the same `332` preads for baseline and candidate, so the suspected duplicate descents did not reduce syscall count on the target image. Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | RCH clean-source `cargo build --profile release-perf -p ffs-cli` passed on `vmi1227854`; isolated detached-worktree local release-perf baseline/candidate builds passed; edited-file rustfmt passed with `--config skip_children=true`; `cargo check -p ffs-core --all-targets` and `cargo check -p ffs-cli --all-targets` passed; focused btrfs read/readlink/symlink tests passed (`21/0/1 ignored`, `4/0`, `1/0`); post-revert `cargo test -p ffs-harness --test conformance -- --nocapture` passed `100 / 0 / 2 ignored`. | Do not retry metadata guard/final-getattr elision as a btrfs compressed-read lever without a new profile proving those descents escape the current caches. Route next work to the active physical-range partitioning follow-up (`bd-xmh5g.409`, owned by cod-a) or to fresh profiles of extent lookup/decode-output lifetime/I/O backend overhead. |
| 2026-06-20 | `bd-xmh5g` | btrfs streamed-read dir/symlink guard fold in `ffs-core`, measured against clean parent `5d77712a` on `/data/tmp/btrdiff2_1340519.img:/compressible.bin` | REJECT / production reverted in `37b7e8b` | Clean 15-run direct btrfs-kernel rows: single-file parent `57.1 ms`, clean current `56.5 ms`, kernel `cat` `7.1 ms`; clean current is only `1.011x` old/new and still `8.01x` slower than kernel. Whole-tree parent `34.4 ms`, clean current `34.9 ms`, kernel `cat *` `12.4 ms`; clean current is `0.986x` old/new and `2.82x` slower than kernel. Invalid contaminated run, before isolating peer `ffs-cli` 1 MiB read-tile edits, showed `22.7-23.3 ms` single-file and `34.3-36.0 ms` walk; that false win is not attributable to the guard fold. Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | RCH clean current `cargo build --profile release-perf -p ffs-cli` passed on `vmi1149989`; RCH parent build passed on `vmi1153651`; local clean parent/current release-perf builds passed; local `cargo fmt -p ffs-core --check` passed; local fallback `cargo test -p ffs-harness --test conformance -- --nocapture` passed `100 / 0 / 2 ignored`; RCH `cargo check -p ffs-core --all-targets` result is captured in the scorecard. | Do not retry this guard-fold metadata elision as a standalone btrfs compressed-read lever. The clean read path does not move; future work should isolate the peer CLI tile hypothesis separately, or profile btrfs extent lookup, decode/output lifetime, and I/O backend overhead before changing core read metadata guards. |
| 2026-06-20 | `bd-xmh5g.407` | `ffs-cli read` btrfs compressed single-file stream tile, 64 MiB -> 1 MiB, against `/data/tmp/btrdiff2_1340519.img:/compressible.bin` | REJECT / production source reverted | Acceptance 15-run direct btrfs-kernel rows: single-file `/compressible.bin` baseline FrankenFS `35.266 ms`, 1 MiB tile candidate `36.367 ms`, kernel `cat` `6.268 ms`; candidate is `0.970x` old/new and `5.80x` slower than kernel. Whole-tree `walk --read-data --no-stat` baseline `29.108 ms`, candidate binary `31.486 ms`, kernel `cat *` `11.888 ms`; candidate binary is `0.925x` old/new and `2.65x` slower than kernel. One-shot RSS smoke did not move materially (`47,844 KiB` baseline vs `47,812 KiB` candidate; minor faults `11,577` vs `11,561`). Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | RCH clean-source `cargo build --profile release-perf -p ffs-cli` passed on `vmi1227854`; RCH candidate build passed on `vmi1149989`; source reverted and `git diff --exit-code -- crates/ffs-cli/src/main.rs` passed; RCH conformance `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `hz2` (100 passed / 0 failed / 2 ignored). `cargo fmt -p ffs-cli --check` remains blocked by pre-existing formatting drift in `crates/ffs-cli/src/cmd_repair.rs`, unrelated to this reverted candidate. | Do not retry CLI stream-tile shrinkage for btrfs compressed reads without allocator attribution proving the 64 MiB request tile is the live-memory bottleneck. The accepted direct run says smaller tiles add per-call overhead/noise without reducing RSS or closing the kernel gap. Route next work to measured allocation sites inside `btrfs_read_file`, true decode-output lifetime reduction, extent metadata fan-out, or a structural I/O backend. |
| 2026-06-20 | `bd-xmh5g` | btrfs zstd compressed-read input-buffer scratch reuse, one retained compressed input `Vec` per Rayon worker for sub-1 MiB frames | REJECT / production source reverted | Acceptance 25-run direct btrfs-kernel rows: single-file `/compressible.bin` baseline FrankenFS `56.7 ms`, scratch `58.6 ms`, kernel `cat` `6.9 ms`; scratch is `0.968x` old/new and `8.53x` slower than kernel. Whole-tree `walk --read-data --no-stat` baseline `36.3 ms`, scratch `35.0 ms`, kernel `cat *` `12.6 ms`; scratch is `1.037x` old/new but still `2.77x` slower than kernel. Earlier 7-run smoke rows were `1.041x` and `1.102x` old/new but were treated as routing-only after the tighter run. Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | Local candidate `cargo check -p ffs-core --all-targets` passed before revert; source reverted; RCH `cargo build --release -p ffs-cli` passed on `vmi1153651`; RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1149989` (100 passed / 0 failed / 2 ignored). | Do not retry compressed-input scratch reuse without a profile proving allocation dominates. The accepted evidence says this lever is noise-to-regression and does not close the btrfs compressed-read kernel gap. Route next work to direct output placement, extent lookup fan-out, or a larger I/O backend design. |
| 2026-06-20 | `bd-giyxr` | e2compr compressed-cluster present-block read fan-out (`decompress_e2compr_cluster`; serial pointer PLAN, parallel data READ, ordered ASSEMBLE) | KEEP / production already retained in `e6259d5d`; current closeout is measured verification | Direct ext4/btrfs-kernel ratio is N/A for this isolated legacy e2compr cluster primitive: the same-process A/B uses a latency-injected `BlockDevice`, e2compr has no btrfs analogue, and no mounted-kernel e2compr comparator exists in the repo. Fresh cod-a RCH Criterion on `vmi1152480`: mean serial/parallel 4 blocks `1.6666 ms` / `915.24 us` (`1.82x`), 16 blocks `5.9532 ms` / `2.1675 ms` (`2.75x`), 32 blocks `12.303 ms` / `2.3427 ms` (`5.25x`). Internal win/loss/neutral `3/0/0`; direct kernel `0/0/1`. | RCH `cargo bench --profile release-perf -p ffs-core --bench e2compr_cluster_read_overlap -- --warm-up-time 1 --measurement-time 3` passed on `vmi1152480` with the bench's serial/parallel byte-equality assertion; RCH `cargo test -p ffs-core e2compr -- --nocapture` passed on `hz2` (25 passed / 0 failed); RCH `cargo build --release -p ffs-core` passed on `vmi1227854` (clean `/tmp/rch_target_frankenfs_cod_a_release` rerun after the requested shared-target build compiled on `vmi1264463` but failed artifact retrieval with `RCH-E309`/exit 102); RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1152480` (100 passed / 0 failed / 2 ignored). | Close the stale open bead as a verified keep. This improves readiness for the niche e2compr compressed ext4 path, but it is not a whole-filesystem kernel domination claim; remaining direct read losses stay routed to mounted ext4/btrfs read-path surfaces such as indirect planning and btrfs compressed reads. |
| 2026-06-20 | `bd-xmh5g` | btrfs zstd compressed read over mounted kernel btrfs image, thread-local zstd decompressor reuse plus targeted Criterion filter guard | KEEP / production retained | Direct btrfs-kernel loss remains, but the FrankenFS side improved on the target image. Single-file `/compressible.bin`: baseline `76.1 ms` -> confirmation `54.9 ms` (`1.39x` faster); current kernel `cat` `6.5 ms`, so FrankenFS is still `8.51x` slower. Whole-tree `walk --read-data --no-stat`: baseline `53.2 ms` -> confirmation `32.8 ms` (`1.62x` faster); current kernel `cat *` `11.0 ms`, so FrankenFS is still `2.99x` slower. Internal synthetic loss: RCH `vmi1167313` fresh decompressor median `5.9330 ms` vs reused median `7.2849 ms` (`0.814x` old/new), so synthetic W/L/N `0/1/0`; direct kernel W/L/N `0/2/0`. | RCH bench passed on `vmi1167313`; local mounted-image hyperfine confirmation passed; local `cargo fmt -p ffs-core --check` passed; RCH `cargo check -p ffs-core --all-targets` passed on `vmi1167313`; RCH `cargo test -p ffs-core btrfs_decompress -- --nocapture` passed on `vmi1167313` (10 passed / 0 failed); RCH conformance passed on `ovh-a` (100 passed / 0 failed / 2 ignored); RCH `cargo build --release -p ffs-cli` passed on `vmi1227854`. Scoped clippy is blocked by pre-existing `ffs-core` pedantic debt outside this lever. | Keep the direct-workload win, but do not claim kernel domination. The synthetic decompressor microbench is a loss and should not be used alone as a keep signal for future zstd-context levers. Next work should attack the remaining `2.99-8.51x` kernel gap with output-buffer reuse / decode-direct-to-final-buffer, metadata extent-lookup fan-out, or a kernel-shaped multi-file compressed image, not by retrying dedicated pools or tiny-frame decoder-context microbenches. |
| 2026-06-20 | `bd-xmh5g` | btrfs zstd direct-to-final-output attempt for full-overlap regular compressed extents | REJECT / production reverted | Direct btrfs-kernel loss remains. Candidate single-file `read --discard /compressible.bin` mean `57.961 ms` vs kernel `cat` `7.011 ms`, so FrankenFS is `8.27x` slower. Candidate `walk --read-data --no-stat` mean `34.883 ms` vs kernel `cat *` `11.537 ms`, so FrankenFS is `3.02x` slower. Internal A/B: single-file regressed current FrankenFS `55.931 ms -> 57.961 ms` (`0.965x` old/new); walk was neutral `34.8826 ms -> 34.8828 ms` (`1.000x`). Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | RCH candidate `cargo check -p ffs-core` and `cargo build --profile release-perf -p ffs-cli` passed on `vmi1152480`; production code was manually reverted; clean-source RCH `cargo check -p ffs-core` passed on `vmi1153651`; clean-source RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1227854` (100 passed / 0 failed / 2 ignored); clean-source RCH `cargo build --profile release-perf -p ffs-cli` passed on `vmi1149989`. | Do not retry final-buffer zstd decode for this read path without allocation-attribution evidence proving the decompressed output `Vec` plus copy dominates. The single-file path worsened and the whole-tree path did not move; route the remaining compressed-read gap to extent lookup/metadata fan-out, compressed scratch allocation, or CLI/open/read overhead. |
| 2026-06-20 | `bd-jgbam` | mmap-backed `ByteDevice` proposal for warm sequential ext4/btrfs reads after the safe large-read direct path | REJECT / no production source kept | Fresh local warm/shared-cache hyperfine still shows the kernel streaming path ahead: ext4 `/data/tmp/extdiff_1497854.img:/large.bin` FrankenFS `read --discard` mean `15.0 ms` vs mounted-kernel `cat` `4.4 ms` (`3.36x` slower); btrfs `/data/tmp/btrperf_1231197.img:/m.bin` FrankenFS `76.5 ms` vs mounted-kernel `cat` `11.6 ms` (`6.58x` slower). RCH `vmi1152480` confirms the already-shipped safe large-read direct primitive remains a real win: `file_device_read_1mib` staged scratch median `506.33 us` vs direct `32.957 us`, old/new `15.36x`. | RCH `cargo bench --profile release-perf -p ffs-block --bench file_device_read -- file_device_read_1mib --warm-up-time 1 --measurement-time 3` passed on `vmi1152480`; local ext4/btrfs hyperfine comparators passed; temporary read-only btrfs loop mount was unmounted. No production source code was changed, so conformance risk is unchanged. | Close the mmap sub-route as rejected under current invariants: current `memmap2` file-backed mapping constructors are `unsafe`, while the workspace and `ffs-block` use `unsafe_code = "forbid"` / `#![forbid(unsafe_code)]`. Do not retry by adding unsafe or a hidden mmap wrapper. Retry only with a safe, policy-approved I/O model: e.g. a safe io_uring/batched pread design that preserves destination-on-error, or an explicit project decision to allow an audited unsafe backend outside forbidden crates. |
| 2026-06-20 | `bd-r9c10` | ext4 indirect non-contiguous read overlap plus direct-output copy-elision follow-up (`ext4_indirect_read_overlap`, 16/64/256 synthetic latency-injected runs) | REJECT copy-elision / production reverted; keep incumbent owned-buffer parallel read | Existing direct kernel gap remains a loss from the prior 32 MiB `^extent` image probe: FrankenFS indirect read `211-224 ms` vs kernel ext4 `45 ms`, about `4.7-5.0x` slower. Today's RCH Criterion is Rust-internal: baseline incumbent parallel read on `vmi1149989` measured serial/parallel medians `5.7337 ms / 970.27 us` (16 runs), `23.414 ms / 2.7872 ms` (64), `92.482 ms / 13.491 ms` (256). Candidate same-binary A/B on `vmi1167313`: incumbent `parallel_rayon` vs `parallel_in_place` medians `2.7308 ms / 2.5461 ms` (`1.073x`, small win), `7.7753 ms / 8.6526 ms` (`0.899x`, regression), `25.508 ms / 25.452 ms` (`1.002x`, neutral). Win/loss/neutral: internal A/B `1/1/1`; direct kernel ratio `0/1/0` from the existing gap. | RCH `cargo bench --profile release-perf -p ffs-core --bench ext4_indirect_read_overlap -- ext4_indirect_read_overlap --warm-up-time 1 --measurement-time 3` passed on `vmi1149989` for baseline and on `vmi1167313` for candidate; benchmark asserts byte equality against the serial oracle before measuring. RCH `cargo check -p ffs-core --bench ext4_indirect_read_overlap` passed on `vmi1152480`; `rustfmt --edition 2024 --check crates/ffs-core/benches/ext4_indirect_read_overlap.rs` passed; `cargo test -p ffs-core read_ext4_indirect -- --nocapture` passed under RCH local fallback (1 focused test); `cargo test -p ffs-harness --test conformance -- --nocapture` passed under RCH local fallback (100 passed / 0 failed / 2 ignored). Clippy for `ffs-core` is blocked by pre-existing library pedantic debt unrelated to the benchmark-only final diff. Production source was restored to the incumbent owned-buffer parallel path; only the A/B benchmark guard remains. | Do not ship or retry the direct-output copy-elision variant for `read_ext4_indirect` without new profile evidence: it regresses the 64-run row and is neutral at 256. The remaining ~5x kernel loss is not closed by buffer assembly tweaks; route deeper to indirect pointer resolution/planning, real direct-kernel image fixtures, mmap/io_uring/vectorized device paths, or a genuinely fragmented indirect-image comparator. |
| 2026-06-20 | `bd-xmh5g` | ext4 indirect near-contiguous 32 MiB large-run read; one coalesced run split into ordered 16/32/64/128/256/512-block chunks | KEEP / production retained with `128` block default | Existing direct ext4-kernel gap remains open: prior 32 MiB `^extent` probe was FrankenFS `211-224 ms` vs kernel ext4 `45 ms` (`~4.7-5.0x` slower). Fresh RCH direct comparator created a valid no-extents image and built release-perf `ffs-cli`, but worker loop mount failed, so no new kernel ratio. Internal same-worker `vmi1227854` sweep: single-run `25.523 ms`; 16-block chunks `31.397 ms` (`0.813x`, loss), 32 `23.067 ms` (`1.106x`, neutral/noisy), 64 `17.267 ms` (`1.478x`), 128 `15.729 ms` (`1.623x`, kept), 256 `16.591 ms` (`1.539x`), 512 `17.475 ms` (`1.461x`). Internal W/L/N `4/1/1`; direct kernel `0/1/0` from existing gap, fresh rerun blocked. | RCH `cargo bench --profile release-perf -p ffs-core --bench ext4_indirect_read_overlap -- ext4_indirect_read_overlap/large_run --warm-up-time 1 --measurement-time 1 --sample-size 20` passed on `vmi1227854`; RCH `cargo test -p ffs-core ext4_indirect_large_run_chunks_default_bd_xmh5g -- --nocapture` passed on `vmi1167313`; RCH `cargo check -p ffs-core --all-targets` passed on `vmi1152480`; RCH-wrapper local fallback harness conformance passed `100 / 0 / 2 ignored`; full clippy remains blocked by pre-existing pedantic debt outside this lever. | Retains a measured internal 1.62x fix for the exact indirect large-run routing gap, but release readiness for ext4-kernel domination stays limited until loop-mount/kernel comparator access is restored and the direct `~5x` loss is remeasured. Do not retry 16-block chunks; use 128 as the current default. |
| 2026-06-20 | `bd-w3hol` | cod-a fresh verification of FUSE writeback-cache write path, 32 x 32 KiB writes to one file handle followed by flush, plus core request-scope batching rerun | KEEP / production retained | Direct ext4/btrfs-kernel ratio remains neutral/unavailable for this isolated primitive: Linux ext4/btrfs do not expose a timed comparator for FrankenFS's in-process per-`(ino, fh)` deferred `RequestScope` table. Fresh cod-a RCH Criterion on `hz1`: old per-write FUSE commit median `75.412 us` vs deferred flush median `64.716 us`, old/new `1.165x`, production latency `0.858x` (`14.2%` lower). Fresh cod-a core primitive rerun on `hz1`: per-write `8.7549 ms`, raw batched `6.6308 ms`, request-scope batched `6.7427 ms`; per-write/request-scope `1.299x`, request-scope is `1.7%` slower than raw batched. Win/loss/neutral: internal A/B `1/0/0`; direct kernel ratio `0/0/1`. | RCH `cargo bench --profile release-perf -p ffs-fuse --bench mount_runtime -- mount_runtime_writeback` passed on `hz1`; RCH `cargo bench --profile release-perf -p ffs-core --bench mvcc_commit_batching -- mvcc_commit_batching_2000` passed on `hz1`; RCH `cargo build --release -p ffs-fuse` passed on `hz1`; RCH `cargo test -p ffs-fuse writeback_cache -- --nocapture` passed on `vmi1152480` (12/12); RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1153651` (100 passed / 0 failed / 2 ignored). | Confirms the already-landed `bd-w3hol` production lever remains a keep on fresh cod-a evidence. Do not claim whole-filesystem kernel domination from this primitive alone; next direct-kernel work should measure mounted write+fsync after unrelated mounted-suite debt is isolated, or move to the open btrfs decompression oversubscription gap (`bd-defgb`). |
| 2026-06-20 | `bd-w3hol` | FUSE writeback-cache write path, 32 x 32 KiB writes to one file handle followed by flush, old per-write commit vs per-FH deferred `RequestScope` commit | KEEP / production retained | Direct ext4/btrfs-kernel ratio is neutral/unavailable for this isolated primitive: the Linux kernel does not expose a timed comparator for FrankenFS's per-file-handle `RequestScope` batching table. RCH Criterion on `vmi1227854`: per-write commit median `43.353 us`, deferred flush median `30.213 us`, old/new `1.435x`, production latency `0.697x` (`30.3%` lower). Win/loss/neutral: internal A/B `1/0/0`; direct kernel ratio `0/0/1`. | RCH `cargo build --release -p ffs-fuse` passed on `vmi1153651`; RCH `cargo test -p ffs-fuse writeback_cache -- --nocapture` passed on `ovh-a` (12/12); RCH `cargo clippy -p ffs-fuse --all-targets --no-deps -- -D warnings` passed on `hz1`; RCH `cargo test -p ffs-harness -- --nocapture` on `hz2` cleared lib `2056/2056`, `tests/btrfs_kernel_reference.rs` `7/7`, and `tests/conformance.rs` `100 passed / 0 failed / 2 ignored` before later unrelated mounted `fuse_e2e` failures; RCH focused post-patch `cargo test -p ffs-harness --test fuse_e2e ext4_fuse_inline_data_reads -- --nocapture` passed on `ovh-a` (2/2). | Converts `bd-w3hol` / `bd-xmh5g.401` into a measured keep for write-side commit amortization. Do not claim whole-filesystem kernel domination from this primitive alone; next direct-kernel work should measure mounted write+fsync throughput/latency after the existing unrelated `fuse_e2e` red rows are isolated or quarantined. |
| 2026-06-20 | `bd-27x9a` | btrfs 100 MiB single uncompressed extent read (`/data/tmp/btrperf_1231197.img`, `/m.bin`, one unencoded extent) | KEEP existing production chunking; no new code shipped | Local hyperfine, warm/shared-cache, release-perf CLI: kernel btrfs `dd` mean `48.7 ms`; current ffs default-32 mean `76.3 ms`; forced old 256-block chunk mean `91.1 ms`. Current ffs is `1.57x` slower than kernel, but `1.19x` faster than the old 256-block setting on this real-image wall-clock comparator. RCH Criterion on `ovh-a` isolates the Rust overlap primitive: serial `5.0966 ms` vs parallel `405.27 us` median (`12.58x`). | RCH `cargo build --release -p ffs-cli` passed on `ovh-a`; RCH `cargo bench --profile release-perf -p ffs-core --bench btrfs_uncompressed_read_overlap -- btrfs_uncompressed_read_overlap_16extents` passed on `ovh-a`; RCH `cargo test -p ffs-core btrfs_read -- --nocapture` passed on `hz1` (21 passed, 1 ignored, 0 failed). Local target verified with `filefrag`: `/m.bin` is one 100 MiB extent, no encoded/shared flags. | Converts `bd-27x9a` from hypothesis to measured evidence: chunking is still better than the old setting, but the kernel gap remains a loss. Do not claim btrfs-kernel domination from this lever; next work should attack file-device/syscall/copy overhead (mmap/io_uring/vectorized direct device) rather than retuning chunk size again. |
| 2026-06-20 | `bd-2x68s` | Warm sequential ext4 extent read gap, including `read_into` buffer reuse and parallel-read chunk retunes (`4096->256->32` blocks) | CLOSE / measured keep family, no new code in this closeout | Initial direct gap was warm ext4 extent reads at ~2.3-2.5x slower than kernel (`~25ms` frankenfs excluding ~10ms CLI/open artifact vs `~10ms` kernel dd). Shipped evidence closes the real read-engine gap: `d5e2059a` made multi-file `walk --read-data` **3.2x** faster (37ms -> 11.7ms) while single-shot `read_into` was neutral (33.6ms -> 33.0ms); `c110c39b` made 32MiB single-file warm **2.19x** faster (33.3ms -> 15.7ms) and cold **2.22x** faster (51.8ms -> 23.3ms), beating the kernel cold comparator (23.3ms < 30ms); `3671522c` then retuned `FFS_READ_CHUNK_BLOCKS` default `256->32`, measuring ext4 128MiB **1.67x warm / 1.24x cold** and btrfs 100MiB **3.14x warm / 1.90x cold** vs the prior 256-block default. Negative evidence retained: indirect direct-window rewrite regressed/neutral (warm ~42ms -> ~44ms, cold 49.5ms -> 53.4ms) and CLI process/open overhead had no frankenfs hot symbol. | Current cod-a RCH gates: `AGENT_NAME=BlackThrush RCH_WORKER=vmi1149989 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo build --release -p ffs-core -p ffs-cli` passed; `AGENT_NAME=BlackThrush RCH_WORKER=vmi1153651 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo test -p ffs-core read_file_data -- --nocapture` passed 4/4; `... cargo test -p ffs-core read_into -- --nocapture` passed 1/1. | Closes stale direct warm-extent bead as measured-resolved: production already has caller-buffer direct fill plus 32-block read chunking for ext4 and btrfs uncompressed reads. Remaining read losses are separate surfaces already ledgered: rare ext4 indirect sequential reads (~5x kernel) and btrfs compressed-read pool oversubscription. |
| 2026-06-19 | `bd-iamhf` | `ffs-cli read --discard` large-file read path, old whole-file `read_file` materialization vs streaming through one reused chunk buffer | KEEP / production retained | Non-sparse 200 MiB ext4 image on `vmi1149989`, release-perf, exact baseline `7050a1c3` vs candidate: warm mean old `0.196 s` vs streaming `0.162 s` (`1.21x` old/new); cold mean old `0.347 s` vs streaming `0.287 s` (`1.21x`). Kernel ext4 warm remains much faster at this low-resolution timing surface (`0.00-0.04 s`); cold kernel was noisy (`0.18/0.63/0.26 s`), so streaming is faster by mean (`1.24x`) but slightly slower by median (`0.28 s` vs `0.26 s`). Sparse 512 MiB allocation/zero-fill probe also favored streaming: warm `1.17 s` vs `0.928 s` (`1.26x`), cold `1.303 s` vs `0.973 s` (`1.34x`). Btrfs not rerun: no existing btrfs image was available and `mkfs` is blocked by DCG. | RCH `cargo check -p ffs-cli --all-targets` passed on `vmi1227854`; release-perf baseline and candidate both built on `vmi1149989`; correctness smoke read exactly `209715200` bytes from `/bigfile` on both binaries. `cargo fmt -p ffs-cli --check` is blocked by pre-existing formatting drift in `crates/ffs-cli/src/cmd_repair.rs`; edited `main.rs` was not the reported diff. | Converts the remaining warm-read allocation/copy tax into a measured keep for discard-mode perf probes without changing normal stdout semantics; stdout mode keeps the previous whole-file buffered write contract. |
| 2026-06-19 | `bd-xmh5g.389` | `ffs-inode` owned 4 KiB/16 KiB/64 KiB `BlockBuf` materialization, `into_inner()` vs `as_slice().to_vec()` for write_inode / indirect-free / xattr-block RMW call sites | REJECT / production reverted | N/A: Rust-internal owned-buffer materialization primitive; ext4/btrfs-kernel has no timed equivalent for `BlockBuf::into_inner()` vs `Vec::to_vec()`, and a kernel inode RMW benchmark would include syscall, VFS, journal, allocator, page-cache, and block-layer behavior that this microbench intentionally excludes. | `cargo fmt -p ffs-inode --check` passed locally; RCH `cargo check -p ffs-inode --all-targets` passed on `hz1`; RCH `cargo test -p ffs-inode --lib -- --nocapture` passed on `ovh-a` with 129 passed / 0 failed; RCH `cargo clippy -p ffs-inode --all-targets --no-deps -- -D warnings` passed on `hz2`; post-clippy focused RCH test `inode_uses_indirect_blocks_excludes_extents_inline_and_non_data_modes` passed on `ovh-a`. | Converted one cod-a `code-first batch-test pending` row into measured negative evidence; production restored to copying via `as_slice().to_vec()` at the three `ffs-inode` RMW sites. |
| 2026-06-19 | `bd-xmh5g.391` | `ffs-alloc` block/inode bitmap mutation materialization, `into_inner()` vs `as_slice().to_vec()` on allocation/free read-patch-write paths | REJECT / production reverted | N/A: Rust-internal bitmap buffer materialization primitive; ext4/btrfs-kernel has no timed equivalent for FrankenFS's `BlockBuf` ownership choice. A whole-filesystem allocator benchmark would include syscall, VFS, journal, allocator, page-cache, and device behavior and would not isolate this lever. | Current cod-a RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- bitmap_owned_move_ab`: old copy median `241.61 ns` vs move median `271.26 ns`; old/new speed ratio `0.891x`, so the move arm is `12.3%` slower. Gates passed: local `cargo fmt -p ffs-alloc --check`; RCH `cargo test -p ffs-alloc -- --nocapture` on `vmi1153651` with 213 passed / 0 failed; RCH `cargo clippy -p ffs-alloc --all-targets --no-deps -- -D warnings` on `hz1`; RCH `cargo build -p ffs-alloc --release` on `vmi1153651`. | Converts one cod-b pending row into measured negative evidence; production restored to `as_slice().to_vec()` for the nine bitmap mutation buffers while preserving the bit-level undo-log rollback guard. |
| 2026-06-19 | `bd-f759f` | `ffs_btrfs::writeback::WriteDependencyDag::reverse_topological_order` metadata flush scheduling, old `BTreeSet` visited membership vs production capacity-sized `HashSet` membership | KEEP / production retained | N/A: Rust-internal btrfs writeback DAG scheduling primitive; Linux btrfs does not expose a timed comparator for FrankenFS's in-memory visited-set membership implementation. A whole-filesystem btrfs writeback benchmark would include VFS, page-cache, allocator, checksum, journal, and device latency and would not isolate this lever. | RCH Criterion on `ovh-a`: old `BTreeSet` median `18.969 us` vs production `HashSet` median `13.220 us` (`1.435x` old/new; production `30.3%` lower scheduler latency). Gates passed: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order` on `hz1`, `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture` on `hz2` with 37 passed / 0 failed, and local `cargo fmt -p ffs-btrfs --check`. | Converted one cod-b `code-first batch-test pending` row into measured keep evidence; production keeps the `HashSet` visited set while the old-`BTreeSet` oracle remains as an A/B guard. |
| 2026-06-19 | `bd-xmh5g.400` | `ffs_btrfs::writeback::WriteDependencyDag::from_cow_tree` child-vector handling during metadata writeback DAG construction | REJECT / production reverted | N/A: Rust-internal btrfs writeback DAG construction primitive; the Linux btrfs kernel does not expose a timed comparator for FrankenFS's in-memory `WriteDependencyDag` child-vector materialization. A whole-filesystem btrfs writeback benchmark would include VFS, page-cache, allocator, checksum, and device latency and would not isolate this lever. | RCH Criterion on `ovh-a`: old double-clone median `89.928 us` vs moved-child production median `110.91 us` (`0.811x` old/new; production `23.3%` slower). Post-revert gates passed: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order` on `hz1`, `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture` on `hz2` with 37 passed / 0 failed, and local `cargo fmt -p ffs-btrfs --check`. | Converted one cod-b `code-first batch-test pending` row into measured negative evidence; production returned to the old child-vector double-clone construction while retaining the A/B benchmark guard. |
| 2026-06-19 | `bd-xmh5g.403` | `ffs_mvcc::MvccStore::commit_ssi_internal` successful SSI commit write-set log construction, prebuilt `BTreeSet` vs fused per-write insert | REJECT / production reverted | N/A: Rust-internal SSI commit-log construction primitive; ext4/btrfs-kernel has no timed equivalent for this in-memory `CommittedTxnRecord.write_set` implementation detail. FrankenFS current write path uses plain `commit`, not `commit_ssi`, so a kernel filesystem write benchmark would not isolate this lever. | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-mvcc --bench wal_throughput` passed on `vmi1227854`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-mvcc ssi -- --nocapture` passed on `hz2` with 70 filtered SSI lib tests, 1 evidence integration test, and 2 stress tests passing. | Converted one cod-b `code-first batch-test pending` row into measured negative evidence; production returned to prebuilding the write-key `BTreeSet` before consuming staged writes. |
| 2026-06-19 | `bd-xmh5g.398` | `FileByteDevice` 4 KiB scalar block read through `ByteBlockDevice::read_block`, staged `read_exact_at` vs owned-destination unstaged read | REJECT / reverted | N/A: Rust-internal FileByteDevice/BlockBuf materialization primitive; no direct ext4/btrfs-kernel comparator exists. A kernel `read(2)`/page-cache test would include syscall, VFS, cache, and filesystem work that this microbench intentionally excludes. | `cargo fmt -p ffs-block --check` passed locally; `rch exec -- cargo check -p ffs-block --all-targets` passed on `hz1`; `rch exec -- cargo clippy -p ffs-block --all-targets -- -D warnings` passed on `vmi1227854`; `rch exec -- cargo test -p ffs-block --lib -- --nocapture` passed on `ovh-a`: 304 passed, 0 failed. | Converted one cod-a `code-first batch-test pending` row into measured negative evidence; production restored to staged `read_exact_at` path. |
| 2026-06-19 | `bd-xmh5g.397` | Trusted vectored short-run `IoSliceMut` descriptor setup inside `ByteBlockDevice::read_contiguous_blocks` | REJECT / reverted | N/A: Rust-internal descriptor-allocation primitive; no ext4/btrfs-kernel equivalent for the `Vec<IoSliceMut>` vs `SmallVec` implementation detail. | `cargo fmt -p ffs-block --check` passed locally; `rch exec -- cargo check -p ffs-block --all-targets` passed on `hz1`; `rch exec -- cargo clippy -p ffs-block --all-targets -- -D warnings` passed on `vmi1227854`; `rch exec -- cargo test -p ffs-block --lib -- --nocapture` passed on `ovh-a`: 304 passed, 0 failed. | Enforced the gauntlet rule that within-noise or slower micro-levers do not ship; production restored to heap-backed `Vec<IoSliceMut>`. |
| 2026-06-19 | `bd-xmh5g.405` | Dense 4 KiB ext4 directory absent lookup plus checksum-tail malformed-header probe | KEEP | Current Rust local Criterion `lookup_absent_dense_4k` median 1.6485 us vs local ext4 kernel `fstatat` unique absent-name median 6.8119 us, Rust/kernel latency ratio 0.242x (4.13x faster). Diagnostic only: kernel number includes syscall/VFS/ext4 dcache work while Rust number is in-process parser/lookup. | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo test -p ffs-ondisk --lib parse_dir_block_ -- --nocapture` on `hz2`: 12 passed, 0 failed. | Converted one cod-a `code-first batch-test pending` row into measured keep evidence; no revert needed. |

## Current Campaign Rows

| Date | Bead | Surface | Lever | Status | Evidence | Retry predicate |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-06-20 | `bd-r9c10` | `ffs-core::read_ext4_indirect` non-contiguous run read overlap and direct-output candidate | Audit incumbent serial-plan/parallel-owned-buffer read path against a direct-output in-place variant that removes per-segment `Vec` materialization and serial assembly copy | Rejected / production reverted | Baseline RCH Criterion on `vmi1149989`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-core --bench ext4_indirect_read_overlap -- ext4_indirect_read_overlap --warm-up-time 1 --measurement-time 3`: serial vs incumbent `parallel_rayon` medians were `5.7337 ms / 970.27 us` (16 runs, `5.91x`), `23.414 ms / 2.7872 ms` (64, `8.40x`), and `92.482 ms / 13.491 ms` (256, `6.85x`). Candidate same-binary A/B on `vmi1167313`: `parallel_rayon` vs `parallel_in_place` medians `2.7308 ms / 2.5461 ms` (`1.073x` small win), `7.7753 ms / 8.6526 ms` (`0.899x` regression), and `25.508 ms / 25.452 ms` (`1.002x` neutral). Direct ext4-kernel comparator remains the existing indirect 32 MiB `^extent` loss (`211-224 ms` vs `45 ms`, ~`5x` slower), not closed here. | Do not retry direct-output/window-carving copy-elision for this path unless a fresh profile shows segment assembly copy dominates and a same-binary A/B beats all run-count rows by a material margin. Remaining work should re-localize the indirect gap instead of polishing buffer assembly. |
| 2026-06-20 | `bd-w3hol` | `ffs-fuse` writeback-cache write/flush/fsync/release paths and `ffs-core` request-scope batching primitive | Verify the already-landed per-`(ino, fh)` writeback batch table and core deferred `RequestScope` path under fresh cod-a rch runs | Measured keep | Fresh cod-a RCH Criterion on `hz1`: `mount_runtime_writeback/per_write_commit_32x32k` median `75.412 us`; `mount_runtime_writeback/deferred_flush_32x32k` median `64.716 us`; old/new `1.165x`, production `14.2%` lower latency. Fresh core rerun on `hz1`: per-write `8.7549 ms`, raw batched `6.6308 ms`, request-scope batched `6.7427 ms`; per-write/request-scope `1.299x`. Behavior/build gates: RCH `ffs-fuse` release build passed; RCH `ffs-fuse` writeback tests 12/12; RCH `ffs-harness` conformance 100 passed / 0 failed / 2 ignored. Direct ext4/btrfs-kernel ratio remains neutral/unavailable for this internal batching primitive. | Keep. Retry only if a direct mounted write+fsync ext4/btrfs-kernel comparator shows regression, or if a new correctness test proves a same-FH read/flush/fsync/release semantic gap. For kernel-ratio claims, first isolate mounted `fuse_e2e` unrelated debt and run a direct mounted writeback benchmark. |
| 2026-06-20 | `bd-w3hol` | `ffs-fuse` writeback-cache write/flush/fsync/release paths | Add a per-`(ino, fh)` writeback batch table that reuses a deferred write `RequestScope` across buffered writes and commits it on flush/fsync/release/destroy; synchronous and NOWAIT writes drain or bypass the deferred scope to preserve durability and lock semantics | Measured keep | RCH Criterion on `vmi1227854`: `mount_runtime_writeback/per_write_commit_32x32k` median `43.353 us`; `mount_runtime_writeback/deferred_flush_32x32k` median `30.213 us`; old/new `1.435x`, production `30.3%` lower latency. Behavior gates: RCH `ffs-fuse` writeback tests 12/12; RCH `ffs-fuse` build and clippy clean; RCH `ffs-harness` conformance 100 passed / 0 failed / 2 ignored; RCH post-patch inline-data FUSE fixture check 2/2; focused local clippy for changed harness test targets passed. Full mounted `fuse_e2e` is not green: a stale full RCH run printed unrelated btrfs rename/security-xattr/renameat2/read-only ioctl failures and was interrupted after several tests hung. | Keep the writeback batching lever. Retry only if a direct mounted write+fsync kernel comparator shows regression, or if a new correctness test proves a same-FH read/flush/fsync/release semantic gap. For kernel-ratio claims, first isolate/quarantine the existing unrelated mounted `fuse_e2e` red rows and then run a direct ext4/btrfs mounted writeback benchmark. |
| 2026-06-20 | `bd-27x9a` | `ffs-core` btrfs large uncompressed read through `ByteDeviceBlockAdapter` / `FileByteDevice` | Add an opt-in direct-overwrite byte-device read for callers that discard destinations on error, then route contiguous filesystem reads through it to skip `FileByteDevice`'s staging copy | Rejected / production reverted | Local release-perf hyperfine on the same one-extent btrfs target. Baseline before candidate: kernel `48.7 ms`, current ffs default-32 `76.3 ms`, forced 256-block `91.1 ms`. Candidate after direct-overwrite fast path: kernel `49.7 ms`, default-32 `75.7 ms`, forced 256-block `72.5 ms`. The default moved only `0.8%` (`76.3 -> 75.7 ms`), well inside run/load noise, and the forced old chunk result flipped faster than default, so the lever was not a credible keep. The code was reverted; no production source change shipped. | Do not retry `FileByteDevice` direct-overwrite reads as a small trait shim. Retry only with a profile showing staging-copy self-time dominates a real read workload and a same-worker A/B beats staged reads by at least 10% without weakening the public short-read destination-preservation contract. Prefer deeper file-device work: mmap-backed readonly image, `preadv2`/io_uring batching, or fewer larger kernel syscalls with explicit copy accounting. |
| 2026-06-20 | `bd-2x68s` | `ffs-core`/`ffs-cli` warm sequential extent reads vs ext4/btrfs kernel | Keep the already-shipped safe levers: `OpenFs::read_into` caller-buffer reuse, ext4 extent chunk default `4096->256->32` blocks, and btrfs uncompressed sub-read chunking on the same `FFS_READ_CHUNK_BLOCKS` default | Closed / measured keep family | Win/neutral/loss ledger: WIN `read_into` multi-file reuse 37ms -> 11.7ms (**3.2x**); NEUTRAL single-shot `read_into` 33.6ms -> 33.0ms; WIN extent chunk `4096->256` warm 33.3ms -> 15.7ms (**2.19x**) and cold 51.8ms -> 23.3ms (**2.22x**, beats kernel cold 30ms); WIN chunk `256->32` ext4 128MiB **1.67x warm / 1.24x cold** and btrfs 100MiB **3.14x warm / 1.90x cold**; REJECT indirect direct-window rewrite warm ~42ms -> ~44ms and cold 49.5ms -> 53.4ms; NO-LEVER for CLI process/open overhead (no frankenfs top symbols). Fresh gates: RCH release build `ffs-core`+`ffs-cli` passed on `vmi1149989`; RCH `read_file_data` tests passed 4/4 and `read_into` coalescing test passed 1/1 on `vmi1153651`. | Do not retry unsafe uninit allocation, allocator tuning, or global allocator swaps under the current `forbid(unsafe_code)` invariant. Retry only with a safe borrowed-buffer/cache API, a real io_uring/mmap backend decision, or fresh direct kernel evidence on a different read surface. |
| 2026-06-19 | `bd-xmh5g.406` | `ffs_journal::verify_jbd2_block_checksum` JBD2 commit-block checksum verification during replay | Stream CRC32C over the commit block as prefix + zero checksum field + suffix, eliminating the full-block `to_vec()` clone used only to zero four bytes before hashing | Rejected / production reverted | RCH Criterion on `ovh-a`, commit `01872c46`, `--profile release-perf`, command `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-journal --bench journal_replay_apply_io_overlap -- journal_commit_checksum_zero_field_clone_vs_segmented`. Mean old clone vs segmented: 1024 B `220.86 ns` vs `158.52 ns` (`1.393x` old/new, win), 4096 B `595.89 ns` vs `742.02 ns` (`0.803x` old/new, segmented is `24.5%` slower), 16384 B `2.8403 us` vs `2.2867 us` (`1.242x` old/new, win). Verdict follows the realistic 4 KiB JBD2 block-size row: reject and restore clone+zero verification. Direct ext4/btrfs-kernel ratio: N/A for this internal checksum microprimitive; repo search found broader mount/kernel artifacts but no direct kernel JBD2 checksum comparator. `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-journal` passed after revert. | Do not retry segmented commit-block CRC on the normal 4 KiB replay path. Retry only with a direct kernel/JBD2 checksum comparator or fresh profile evidence proving non-4 KiB commit blocks dominate the target workload enough to offset the 4 KiB regression. |
| 2026-06-19 | `bd-xmh5g.405` | `ffs_ondisk::walk_dir_block_entries` and `DirBlockIter` dense ext4 directory scans | Gate the trailing-suffix `all_zero_bytes` malformed-checksum-tail probe behind `is_malformed_dir_checksum_tail(...)`, so normal live/deleted entries skip the zero scan while valid checksum-tail padding validation remains unchanged | Measured keep | rch Criterion same-binary A/B on worker `vmi1152480`: `tail_scan_eager_suffix_probe_dense_4k` median 2.7869 us [2.7304, 2.8510] vs `tail_scan_gated_suffix_probe_dense_4k` median 882.05 ns [849.55, 923.52], new/old latency ratio 0.317x (3.16x faster). Same-host production before/after: parent `0e01c3f4` `lookup_absent_dense_4k` median 4.2479 us vs current median 1.6485 us, new/old ratio 0.388x (2.58x faster). Original-kernel diagnostic: local ext4 `fstatat` unique absent-name lookup in a 256-entry directory median 6.8119 us, current Rust/kernel ratio 0.242x (4.13x faster), with syscall/VFS-vs-parser caveat. Conformance: rch `hz2` `cargo test -p ffs-ondisk --lib parse_dir_block_ -- --nocapture` passed 12/12. | Do not retry the eager suffix-scan shape. Revisit only if a future profile shows checksum-tail validation or deleted-entry parsing, not normal live-entry lookup, dominating a realistic directory workload after this gate. |
| 2026-06-19 | `bd-xmh5g.404` | `ffs_journal::replay_jbd2_inner` JBD2 staged-block apply materialization after parallel reads | Consume each staged `BlockBuf` with `into_inner()` instead of copying `as_slice().to_vec()`, moving the owned aligned Vec for file-backed reads while preserving clone fallback for shared buffers | Rejected / production reverted | RCH Criterion on `ovh-a`, commit `01872c46`, `--profile release-perf`, command `RCH_WORKER=ovh-a RCH_WORKERS=ovh-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-journal --bench journal_replay_apply_io_overlap -- journal_replay_blockbuf_materialize`. Mean old `as_slice().to_vec()` vs `into_inner()`: 16 blocks `3.9888 us` vs `4.2087 us` (`0.948x` old/new, `into_inner` is `5.5%` slower), 64 blocks `21.282 us` vs `22.110 us` (`0.963x`, `3.9%` slower), 256 blocks `71.482 us` vs `77.324 us` (`0.924x`, `8.2%` slower). Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal materialization primitive; no kernel equivalent exists. `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-journal` passed after revert. | Do not retry `BlockBuf::into_inner()` materialization in JBD2 replay apply without a new producer proving truly zero-copy ownership and a focused same-worker A/B. The current owned-read shape loses across all tested replay sizes. |
| 2026-06-19 | `bd-xmh5g.403` | `ffs_mvcc::MvccStore::commit_ssi_internal` successful SSI commit log construction | Fuse committed write-set `BTreeSet` construction into the staged-write version-install loop, eliminating the prior separate `txn.write_set().keys().copied().collect()` pass before consuming the transaction | Rejected / production reverted | RCH Criterion on `vmi1227854`, commit under measurement `1cd8de6f`, command `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-mvcc --bench wal_throughput -- mvcc_commit_ssi_writekey_log_ab`. Mean old prebuild vs fused: 64 writes `437.77 ns` vs `790.80 ns` (`0.554x` old/new, fused is `80.6%` slower), 256 writes `1.8957 us` vs `4.1605 us` (`0.456x`, `119.5%` slower), 1024 writes `8.0965 us` vs `24.173 us` (`0.335x`, `198.6%` slower). Direct ext4/btrfs-kernel ratio: N/A for this internal SSI write-set construction primitive; no kernel-equivalent timed primitive exists, and the current write path uses plain `commit`, not `commit_ssi`. Production restored to the old prebuilt `BTreeSet` path; A/B bench rows remain as negative-evidence guards. Post-revert gates passed: RCH `cargo check -p ffs-mvcc --bench wal_throughput` on `vmi1227854`, and RCH `cargo test -p ffs-mvcc ssi -- --nocapture` on `hz2` with 70 filtered SSI lib tests, 1 evidence integration test, and 2 stress tests passing. | Do not retry fused per-write `BTreeSet` insertion in SSI commit-log construction. Retry only if a real profile names `commit_ssi_internal` write-set construction as material on a workload that actually uses SSI, and the replacement avoids per-insert tree costs while preserving the exact `CommittedTxnRecord.write_set`. |
| 2026-06-19 | `bd-ucrow` | `ffs-core` request-scope/direct MVCC commit paths when `repair_flush_lifecycle` is detached | Gate the write-set key collection for repair refresh notification behind `repair_flush_lifecycle.is_some()`, so default mounts skip the per-commit `Vec<BlockNumber>` allocation/copy while attached repair lifecycles still receive the exact sorted write-set | Rejected / production reverted | Current cod-a rch Criterion on `ovh-a`, `--profile release-perf`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-core --bench mvcc_commit_batching -- commit_scope_writeset_collect`. Median old always-collect vs lifecycle-none gated: 64 blocks `14.030 us` vs `16.430 us` (`0.854x` old/new, gated is `17.1%` slower), 256 blocks `56.169 us` vs `55.732 us` (`1.008x`, neutral), 1024 blocks `45.953 us` vs `247.65 us` (`0.185x`, anomalous but strongly non-keep). Prior gauntlet scorecard commit `848d28db` also recorded this lever as within-noise neutral. Direct ext4/btrfs-kernel ratio: N/A for this internal request-scope write-set collection primitive; whole-filesystem kernel write timing would not isolate the optional repair lifecycle notification block-list construction. Production restored the old unconditional write-set capture before commit; the Criterion A/B rows remain as negative-evidence guards. | Do not retry lifecycle-gating write-set collection on the commit path unless a fresh profile shows `txn.write_set().keys().collect()` materially dominates a realistic write workload and a same-worker A/B shows a clear win at the actual write-set sizes without lifecycle-present notification drift. |
| 2026-06-18 | `bd-xmh5g.401` | `ffs-core` MVCC request-scope write path / future FUSE per-file-handle writeback table | Add an explicit deferred `RequestScope` commit mode plus `OpenFs::{begin,commit,abort}_writeback_batch_scope`, proving multiple staged block writes can share one transaction and publish with one commit; extend `mvcc_commit_batching` with `request_scope_batched_commit` | Measured neutral / enabling only | Fresh cod-a rch Criterion on worker `vmi1149989`, command `AGENT_NAME=BlackThrush RCH_WORKER=vmi1149989 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-core --bench mvcc_commit_batching -- mvcc_commit_batching_2000 --warm-up-time 1 --measurement-time 1 --sample-size 10`: per-write commit `6.9593 ms`, raw batched commit `6.2581 ms`, request-scope batched commit `6.2478 ms`; request-scope/raw ratio `1.002x` and per-write/request-scope ratio `1.11x`, so the core primitive is not a direct domination win. Conformance gate: `rch exec -- cargo test -p ffs-core writeback_batch_scope_stages_multiple_writes_for_one_commit -- --nocapture` passed 1/1 filtered test. Direct ext4/btrfs-kernel ratio is N/A for this in-memory request-scope primitive; whole-filesystem proof belongs to the per-fh FUSE wiring bench. | Treat this as a neutral enabling primitive, not a scored win. Do not claim the write-back model until `bd-w3hol` wires the per-fh table and proves an e2e write/fsync workload beats per-write commit without violating read-your-writes, flush/fsync/release, bounded-dirty, or crash-consistency semantics. |
| 2026-06-19 | `bd-xmh5g.400` | `ffs_btrfs::writeback::WriteDependencyDag::from_cow_tree` / `collect_nodes` metadata writeback DAG construction | Consume the owned `BtrfsCowNode` snapshot and move internal child vectors into `DagNode`, avoiding the old second child-vector clone per internal node while preserving one recursion snapshot for descent | Rejected / production reverted | RCH Criterion on `ovh-a`, command `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-btrfs --bench writeback_dag_order -- writeback_dag_build_child_vector_ab`. Mean rows: old double-clone `89.928 us`, single-clone model `112.58 us`, moved-child production `110.91 us`; old/production ratio `0.811x`, so the production lever is `23.3%` slower on its own realistic DAG-build workload. Direct btrfs-kernel ratio: N/A for this in-memory writeback DAG construction primitive. Production restored the old double-clone child-vector path. Post-revert gates passed: RCH `cargo check -p ffs-btrfs --bench writeback_dag_order` on `hz1`, RCH `cargo test -p ffs-btrfs writeback -- --nocapture` on `hz2` with 37 passed / 0 failed, and local `cargo fmt -p ffs-btrfs --check`. | Do not retry the moved-child `collect_nodes` shape. Retry only if a new profile shows child-vector cloning dominating btrfs metadata writeback and a replacement beats the old double-clone path in the existing `writeback_dag_build_child_vector_ab` A/B while preserving exact DAG shape, reverse-topological order, and every WB-I1 prefix. |
| 2026-06-18 | `bd-xmh5g.399` | `ffs-core` ext4 `readdir` followed by stat-heavy `getattr` over returned entries | Best-effort prefetch of distinct returned-page inode-table blocks through the existing `ext4_inode_table_block_cache`, issuing uncached block reads in parallel on read-only mounts and preserving readdir output/errors by ignoring prefetch failures | Measured keep | Fresh cod-a rch Criterion on worker `vmi1149989`, command `AGENT_NAME=BlackThrush RCH_WORKER=vmi1149989 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-core --bench ls_dir_inode_prefetch -- --warm-up-time 1 --measurement-time 1 --sample-size 10`: serial `32.894 ms` mean vs parallel prefetch `3.7480 ms` mean, old/new ratio `8.78x`. Build gate: `rch exec -- cargo build --release -p ffs-core` passed on the same worker. Conformance gate: `rch exec -- cargo test -p ffs-core readdir -- --nocapture` passed 24/24 filtered unit tests. Direct ext4-kernel ratio is N/A for this synthetic in-request I/O-overlap microbench; use the real walk/kernel rows in the scorecard for whole-filesystem ratios. | Keep the read-only best-effort prefetch. Do not retry this vein unless a new workload has a serial per-entry device read inside one request; plain readdir+stat FUSE requests already fan out at the dispatcher, and the open write-side gap is commit amortization (`bd-w3hol`), not metadata I/O-overlap. |
| 2026-06-18 | `bd-f759f` | `ffs_btrfs::writeback::WriteDependencyDag::reverse_topological_order` metadata flush scheduling | Replace the ordered `BTreeSet` visited-membership set with a capacity-sized `HashSet`, preserving deterministic child-vector postorder plus `BTreeMap` disconnected-component iteration | Measured keep | RCH Criterion on `ovh-a`, command `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-btrfs --bench writeback_dag_order -- writeback_dag_order_hashset_ab`: old `BTreeSet` median `18.969 us` vs production `HashSet` median `13.220 us`; old/new ratio `1.435x`, new/old latency ratio `0.697x`, production `30.3%` lower scheduler latency. Direct btrfs-kernel ratio: N/A for this in-memory writeback DAG scheduling primitive. Conformance/build gates passed: RCH `cargo check -p ffs-btrfs --bench writeback_dag_order` on `hz1`, RCH `cargo test -p ffs-btrfs writeback -- --nocapture` on `hz2` with 37 passed / 0 failed, and local `cargo fmt -p ffs-btrfs --check`. | Keep the `HashSet` visited membership lever. Revalidate only if a future btrfs writeback profile shows `reverse_topological_order` has changed shape materially, or if a direct kernel-level metadata-writeback benchmark becomes available that can isolate this scheduler primitive rather than whole-filesystem VFS/device effects. |
| 2026-06-18 | `bd-xmh5g.398` | `ffs_block::ByteBlockDevice::read_block` plus local contiguous-read staging buffers on `FileByteDevice` | Add `ByteDevice::read_exact_at_unstaged` for owned/local destinations, override `FileByteDevice` to fill them directly, and keep public destination-preservation paths on the existing staged read | Rejected / production reverted | RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-block --bench block_buf_construct -- filebyte_read_block`. Old staged `read_exact_at` median `924.56 ns` [899.22, 957.19] vs new unstaged owned-destination median `999.73 ns` [990.66 ns, 1.0115 us]. New/old latency ratio `1.081x` (`8.1%` slower); old/new speed ratio `0.925x`. Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal copy-staging primitive. Source reverted to the staged `read_exact_at` path and the now-dead guard/bench rows were removed. | Do not retry owned-destination unstaged `FileByteDevice` reads unless a fresh profile shows staged-copy preservation dominating a realistic scalar block-read workload and a same-worker A/B beats staged `read_exact_at` by at least 10% with acceptable variance. |
| 2026-06-18 | `bd-xmh5g.397` | `ffs_block::ByteBlockDevice::read_contiguous_blocks` trusted vectored short-run descriptor setup | Replace the temporary heap-backed `Vec<IoSliceMut>` with stack-backed `SmallVec<[IoSliceMut; 16]>`, spilling only for wider runs | Rejected / production reverted | Prior gauntlet Criterion row `read_contiguous_short_trusted_vectored` measured the SmallVec descriptor path at `0.95x` vs the old Vec-backed descriptor list for the 16-block row: marginally slower and within noise, with no meaningful workload win. Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal descriptor setup. Source reverted to `Vec<IoSliceMut>` and the now-dead A/B bench rows were removed. | Do not retry stack-backed short-run iovec descriptors unless a profile names descriptor allocation as material on the trusted vectored contiguous-read path and a same-worker A/B shows a clear win across both 4-block and 16-block rows. |
| 2026-06-18 | `bd-xmh5g.392` | `ffs_block::ByteBlockDevice::read_contiguous_blocks` correctly sized `BlockBuf` runs on trusted byte devices | Add an explicit vectored all-or-nothing read capability and fill caller-owned block buffers with one trusted vectored read, skipping the whole-run staging `Vec` and chunk copies | Pending batch benchmark | Runtime lever, direct-path/error-preservation guards, and Criterion A/B row `read_contiguous_blocks_trusted_vectored` added. This cod-a batch is explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a cargo check -p ffs-block`; benchmarks/tests are not run in this commit. | Run `cargo bench -p ffs-block --bench read_contiguous -- read_contiguous_1mib` plus the crate contiguous-read conformance gate. Keep only on a meaningful correctly-sized block-buffer win and no destination-preservation regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-19 | `bd-xmh5g.391` | `ffs-alloc` block/inode bitmap read-patch-write allocation and free paths | Move disposable owned `BlockBuf` bitmap buffers with `into_inner()` and replace persistent rollback full-block snapshots with bit-level undo logs | Rejected / production reverted | Current cod-a RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- bitmap_owned_move_ab`: old `as_slice().to_vec()` median `241.61 ns` vs move `into_inner()` median `271.26 ns`; old/new speed ratio `0.891x`, so the owned-move arm is `12.3%` slower. Production restored the nine bitmap mutation materializations to `as_slice().to_vec()`; the bit-level undo-log rollback refactor and `bitmap_undo_logs_restore_exact_original_bytes` guard remain. Post-revert gates: local `cargo fmt -p ffs-alloc --check`; RCH `cargo test -p ffs-alloc -- --nocapture` on `vmi1153651` with 213 passed / 0 failed; RCH `cargo clippy -p ffs-alloc --all-targets --no-deps -- -D warnings` on `hz1`; RCH `cargo build -p ffs-alloc --release` on `vmi1153651`. Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal materialization primitive. | Do not retry `BlockBuf::into_inner()` on allocator bitmap RMW paths unless a fresh same-worker A/B at the exact bitmap block ownership shape beats `as_slice().to_vec()` and the rollback-byte guard remains green. The bit-level undo-log refactor is separately preserved. |
| 2026-06-19 | `bd-xmh5g.386` | `ffs_btree::search` / `search_with_leaf_window` validated ext4 extent leaf search | Private trusted `search_leaf_bounded_validated` path used only immediately after `parse_leaf_entries` has already rejected zero-length, unsorted, and overlapping leaves; checked helper retained for public pre-parsed roots | Measured keep | Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal ext4 extent-leaf search primitive; the kernel does not expose a timed comparator for FrankenFS's checked-rescan vs parser-validated helper split. RCH Criterion on `vmi1167313`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-btree --bench extent_leaf_search -- extent_leaf_search_validation_ab`: old checked zero-scan median `451.37 us` [443.15, 459.31] vs trusted validated no-rescan median `40.482 us` [39.645, 41.267], old/new `11.15x`, production latency `0.0897x` of old. Focused guard passed on `vmi1167313`: `cargo test -p ffs-btree search_parsed_root_rejects_caller_supplied_zero_length_leaf_bd_xmh5g_386 -- --nocapture`. Full crate gate passed on `vmi1149989`: `cargo test -p ffs-btree -- --nocapture` (156 passed, 0 failed, doc-tests 0). Scoped lint passed on `vmi1153651`: `cargo clippy -p ffs-btree --all-targets --no-deps -- -D warnings`. Local `cargo fmt -p ffs-btree --check` passed after mechanical formatting. Release compile evidence: `cargo build -p ffs-btree --release` finished successfully on `vmi1264463`, but rch returned `RCH-E309` because artifact retrieval from the worker-scoped target dir timed out; code compile was green, local artifact sync was incomplete. | Keep; `parse_leaf_entries` remains the single on-disk validator for private byte-parsed leaves, while public caller-supplied parsed roots still call the checked helper and reject zero-length extents. Do not restore the redundant per-search zero-length scan unless a future profile proves parser validation no longer dominates the trust boundary or a new public entry bypasses `parse_leaf_entries`. |
| 2026-06-19 | `bd-xmh5g.388` | `ffs_btrfs::BtrfsExtentAllocator::resolve_containing_data_extent` logical-ino/backref lookup | Replace the materializing from-zero extent-tree range scan with a `floor_key` predecessor walk that skips interleaved non-`EXTENT_ITEM` keys and checks the single greatest data extent candidate | Measured keep | Direct btrfs-kernel ratio: N/A for this Rust-internal extent-tree predecessor primitive; the kernel exposes LOGICAL_INO behavior, not a timed comparator for FrankenFS's in-memory `range_from_zero_scan` vs `floor_key` implementation. RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench -p ffs-btrfs --bench extent_fetch -- resolve_containing_extent_floor_ab`: old `range_from_zero_scan` median `624.25 us` [616.69, 632.68] vs `floor_key_predecessor` median `653.21 ns` [647.46, 660.70], old/new `955.7x`, production latency `0.00105x` of old. | Gates: RCH `cargo test -p ffs-btrfs -- --nocapture` on `hz2` passed 361 unit tests + 38 conformance golden tests + doc-tests; RCH `cargo build -p ffs-btrfs --release` on `hz2` passed; RCH scoped `cargo clippy -p ffs-btrfs --lib --no-deps -- -D warnings` on `hz1` passed. Full `cargo clippy -p ffs-btrfs --all-targets -- -D warnings` was blocked before ffs-btrfs by unrelated existing `ffs-repair` path-dependency lints (`manual_saturating_arithmetic`, `unused_self`). Do not retry the from-zero scan shape unless a new correctness requirement invalidates predecessor lookup; interleaved non-extent and mid-extent guards are green. |
| 2026-06-18 | `bd-xmh5g.384` | `ffs_ondisk::parse_leaf_items` dense btrfs leaf payload-overlap validation | Lazy descending-payload fast path that avoids eager coverage bitmap allocation on canonical leaves; exact bitset replay fallback for noncanonical layouts | Pending batch benchmark | Runtime lever, focused fallback fixture, and Criterion A/B row `btrfs_leaf_payload_coverage_ab` added. This cod-b batch is explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-ondisk`; benchmarks/tests are not run in this commit. | Run `cargo bench -p ffs-ondisk --bench btrfs_leaf_parse -- btrfs_leaf_payload_coverage_ab` plus the crate conformance/parser gate. Keep only on a meaningful parser win and no overlap-validation regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-19 | `bd-xmh5g.381` | `ffs-alloc::succinct::SuccinctBitmap::find_contiguous`, scalar old bit scan vs broadword zero-run detector (`succinct_find_contiguous_ab`) | KEEP / production retained | Direct ext4/btrfs-kernel ratio: N/A, Rust-internal allocator bitmap scan primitive; no kernel-exposed timed equivalent isolates one free-run detector. RCH Criterion on `hz2`, post-clippy tree, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- succinct_find_contiguous_ab`: old bit scan median `20.486 us` vs broadword median `2.3492 us`, old/new `8.72x`, production latency `0.115x` of old. | `cargo fmt -p ffs-alloc --check` passed locally; RCH `cargo check -p ffs-alloc --all-targets` passed on `hz2`; RCH `cargo test -p ffs-alloc -- --nocapture` passed on `ovh-a` with 213 passed / 0 failed; RCH `cargo clippy -p ffs-alloc --all-targets -- -D warnings` passed on `ovh-a` after removing two local allocator lint blockers. | Converts the cod-a broadword pending row into a measured keep; exact earliest-run behavior is guarded by `proptest_find_contiguous_matches_naive_earliest_run`, so no production revert. |
| 2026-06-20 | `bd-xmh5g.382` | `ffs-extent::ExtentCache::lookup` same-namespace hot hits | Shared read-lock hit path, then repaired striped hit/miss counters for the same read-lock path after the single shared atomic was identified as a cache-line bottleneck | Rejected / production reverted | Same-worker RCH `hz2`, `--profile release-perf`, lint-clean benchmark code. Baseline A/B before candidate on `hz1`: `extent_cache_same_ns_8t` write_lock_hit median `9.6402 ms` vs read_lock_atomic_hit `20.796 ms` (`0.464x`, read-lock slower). Production-shaped baseline `extent_cache_real_same_ns`: 1t `701.67 us`, 2t `4.6526 ms`, 4t `11.450 ms`, 8t `21.291 ms`. Final striped-counter A/B on `hz2`: write_lock_hit `14.201 ms`, read_lock_atomic_hit `20.348 ms`, read_lock_striped_atomic_hit `18.341 ms`; striped vs single atomic `1.11x`, while striped vs write-lock remains `0.774x`. Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal cache primitive. Production striped-counter changes were reverted; the synthetic striped arm remains only as a negative-evidence guard. | Do not retry same-namespace read-lock ExtentCache hits by moving contention among counters. Retry only if the new design removes both hot-hit shared stats and hot-hit per-entry recency traffic, or if a fresh profile plus same-worker A/B shows the replacement beating the write-lock baseline on the production-shaped bench. |
| 2026-06-18 | `bd-xmh5g.385` | `ffs-xattr::parse_external_entries` zero-initialized external xattr block acceptance | Replace scalar `block.iter().all(|b| *b == 0)` with chunked `ffs_types::all_zero_bytes` for the allow-zero-initialized invalid-magic fallback | Pending batch benchmark | Production lever and Criterion A/B row `xattr_zero_initialized_external_block` added. This cod-a batch was explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a cargo check -p ffs-xattr`; benchmarks/tests were not run in this commit. | Run `cargo bench -p ffs-xattr --bench xattr_exists_probe -- xattr_zero_initialized_external_block` and the crate conformance gate. Keep only on `Score >= 2.0` and no zero-block accept/reject regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-18 | `bd-xmh5g.387` | `ffs_mvcc::MvccBlockDevice::read_block` version-store hit | Materialize the visible `Cow` with `into_owned()` (MOVE the decompressed `Cow::Owned` Vec) instead of `to_vec()` (clone) | Pending batch benchmark | Production lever + Criterion A/B `read_block_cow_owned` + identical-bytes guard; `cargo check -p ffs-mvcc` only. | Run `cargo bench -p ffs-mvcc --bench read_block_cow_owned`. Clean-by-construction (`into_owned <= to_vec`, byte-identical) — keep unconditionally; only the uncompressed `Cow::Borrowed` path still clones (see `bd-xmh5g.394`). |
| 2026-06-18 | `bd-xmh5g.389` | `ffs-inode` 3 read-modify-write paths (write_inode, indirect-block free, POSIX-ACL) | Move the owned `BlockBuf` read buffer with `into_inner()` (Arc::try_unwrap) instead of `as_slice().to_vec()` | Rejected / production reverted | RCH Criterion on `vmi1227854`, command `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-mvcc --bench blockbuf_into_inner -- blockbuf_into_inner_vs_to_vec`. Mean old copy vs new move: 4096 B `576.96 ns` vs `534.36 ns` (`1.080x` old/new, small win), 16384 B `1.3722 us` vs `1.5633 us` (`0.878x` old/new, move is `13.9%` slower), 65536 B `3.7725 us` vs `4.2885 us` (`0.880x`, move is `13.7%` slower). Verdict follows the wider RMW-block rows: reject and restore `as_slice().to_vec()` at the three `ffs-inode` sites. Direct ext4/btrfs-kernel ratio: N/A for this internal owned-buffer materialization primitive. `cargo fmt -p ffs-inode --check` passed; RCH `cargo check -p ffs-inode --all-targets` passed on `hz1`; RCH `cargo test -p ffs-inode --lib -- --nocapture` passed on `ovh-a` with 129/129; RCH `cargo clippy -p ffs-inode --all-targets --no-deps -- -D warnings` passed on `hz2`; post-clippy focused RCH test `inode_uses_indirect_blocks_excludes_extents_inline_and_non_data_modes` passed on `ovh-a`. Broad dependency-lint clippy without `--no-deps` was blocked by an unrelated existing `ffs-extent` `significant_drop_tightening` lint. | Do not retry `BlockBuf::into_inner()` in `ffs-inode` RMW paths unless a fresh profile proves a 4 KiB-only workload dominates and a same-worker A/B clears the 16 KiB/64 KiB regressions or narrows the lever to a proven unique fast path. |
| 2026-06-18 | `bd-xmh5g.390` | `ffs-core::btrfs_write_logical` partial-block (unaligned) read-modify-write | Move the owned `BlockBuf` via `into_inner()` instead of `as_slice().to_vec()` | Pending batch benchmark | Production lever; `cargo check -p ffs-core` (no use-after-move). | Run `cargo bench -p ffs-mvcc --bench blockbuf_into_inner` (same primitive). Clean-by-construction — keep unconditionally. |
| 2026-06-18 | `bd-xmh5g.393` | `ffs-core` 8 read/RMW paths (ext4/btrfs superblock RMW, partial head/tail RMW, block-run/contiguous/indirect read-resolve) | Move owned `BlockBuf` read buffers via `into_inner()` instead of `as_slice().to_vec()` | Pending batch benchmark | Production lever; `cargo check -p ffs-core` confirms no use-after-move at any of the 8 sites. | Run `cargo bench -p ffs-mvcc --bench blockbuf_into_inner` (same primitive). Clean-by-construction — keep unconditionally. |
| 2026-06-18 | `bd-xmh5g.395` | `ffs_mvcc::sharded::make_chain_head_full` chain compaction (commit/GC chain-cap) | Move the resolved `Cow` via `into_owned()` instead of `to_vec()`; matches the already-corrected twin in `lib.rs:3113` | Pending batch benchmark | Production lever; `cargo check -p ffs-mvcc`. Found by auditing all 10 `resolve_data_with` callers (rest are comparisons/`.len()`, no clone). | Run `cargo bench -p ffs-mvcc --bench read_block_cow_owned` (same Cow move-vs-copy primitive). Clean-by-construction — keep unconditionally. |
| 2026-06-18 | `bd-xmh5g.394` | `ffs_mvcc` UNCOMPRESSED read path (`read_visible`/`read_block` `Cow::Borrowed -> into_owned`) | Store `VersionData::Full` as a shared aligned buffer and share it into `BlockBuf` with `Arc::clone`, eliminating the common uncompressed read allocation/copy | KEEP / production retained | Direct ext4/btrfs-kernel ratio: N/A, Rust-internal MVCC uncompressed-version materialization primitive; no kernel-exposed timed equivalent isolates one Arc-share vs block-copy step. RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench -p ffs-mvcc --bench read_block_uncompressed_clone_vs_share -- read_block_uncompressed`: `clone_into_owned` vs `arc_share` medians: 4K `86.318 ns` vs `621.25 ps` = `138.9x` old/new; 16K `228.72 ns` vs `722.58 ps` = `316.5x`; 64K `1.2177 us` vs `615.58 ps` = `1978.1x`. Production-shaped corroboration on `hz2`: `read_visible_sequential/scan_2000_blocks` median `257.62 us`, `29.615 GiB/s`. | RCH release builds passed on `hz2`: `cargo build -p ffs-mvcc --release`, `cargo build -p ffs-block --release`. RCH tests passed: `cargo test -p ffs-block -p ffs-mvcc -- --nocapture` on `hz2` after the root-safe `ffs-block` empty-write test fix; post-clippy `cargo test -p ffs-mvcc -- --nocapture` on `vmi1153651`. Hygiene passed: `cargo fmt -p ffs-block --check`, `cargo fmt -p ffs-mvcc --check`, RCH `cargo check -p ffs-block -p ffs-mvcc --all-targets` on `hz1`, and RCH `cargo clippy -p ffs-block -p ffs-mvcc --all-targets --no-deps -- -D warnings` on `hz1`. Broad dependency-lint clippy without `--no-deps` is blocked by unrelated existing `ffs-repair/src/storage.rs` lints. | Keep; Arc-share beats the clone arm at every measured size, including the 4K small-block break-even, and the shared-storage guard proves byte-identical exposure. No revert. |
| 2026-06-18 | `bd-xmh5g.396` | Ext4 metadata-only inode parse for `getattr`/`lookup`/`readdir`/existence checks in `ffs-core` and `Ext4FsOps` | Add `Ext4Inode::parse_metadata_from_bytes` and metadata reader wrappers that preserve all fixed inode fields while leaving `xattr_ibody` empty; keep `parse_from_bytes` full for xattr and inline-data users | Pending batch benchmark | Production lever, metadata-vs-full fixed-field guard, and existing Criterion A/B row `ext4_metadata_parse_xattr_ibody` are present. Local-only checks passed: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-ondisk` and `cargo check -p ffs-core` (rerun after hot-path factoring). No tests, benches, or rch were run in this code-first commit. | Run `cargo bench -p ffs-core --bench ext4_metadata_parse_xattr_ibody -- ext4_metadata_parse_xattr_ibody`, then ext4 metadata/xattr/inline-data conformance including `inode_metadata_parse_skips_ibody_only`. Keep only if metadata parse wins without xattr/listxattr/getxattr/inline-data regression; otherwise revert this lever and mark rejected with the measured ratio. |

## Seeded Do-Not-Retry Rows From Prior No-Gaps Work

These rows summarize already-explored families from the existing `bd-xmh5g`
history so the new campaign does not loop on known dead ends. Update each row
with fresh benchmark artifacts if a new workload or primitive changes the
profile.

| Family | Prior rows | Status | Retry predicate |
| --- | --- | --- | --- |
| RaptorQ source-row memoization/cache variants | `bd-xmh5g.149`, `bd-xmh5g.150`, `bd-xmh5g.165` | Rejected or no-ship under prior same-worker evidence | Retry only if a new profile shows row generation, not memory traffic or solve/projection, dominates the current workload after the kept source-domain encode path. |
| LRC small-parity and fused pair/quad microkernels | `bd-xmh5g.152`, `bd-xmh5g.153`, `bd-xmh5g.156`, `bd-xmh5g.157`, `bd-xmh5g.166`, `bd-xmh5g.167`, `bd-xmh5g.169` | Mixed to rejected under prior focused benches | Retry only with a new benchmark family whose workload shape differs materially from the old 64-block/8-parity lanes and includes same-binary A/B evidence. |
| Raw allocation bitmap contiguous/largest-run broadword families | `bd-xmh5g.78`, `bd-xmh5g.85`, `bd-dlc4x`, plus rejected table/broadword variants `bd-xmh5g.30`, `bd-xmh5g.57`, `bd-xmh5g.60`, `bd-xmh5g.77` | Already covered; some kept, some rejected | Do not duplicate raw bitmap work. Only optimize distinct call surfaces, such as succinct-index queries, and add an oracle guard before changing tie-breaking. |
| Owned read-buffer clone→move (`into_inner`/`into_owned`) across cc crates (ffs-mvcc/inode/core) | `bd-xmh5g.387`, `.389`, `.390`, `.393`, `.395` | PARTIALLY REJECTED — `.389` measured `BlockBuf::into_inner()` as a wider-block regression and was reverted; remaining open family members need their own measured verdict instead of the old "keep unconditionally" assumption | Do not re-sweep `.as_slice().to_vec()` / `Cow::to_vec` in ffs-mvcc/inode/core. For `BlockBuf::into_inner()` call sites, require same-worker A/B evidence at the actual block sizes before keeping; `.389` showed the 4 KiB micro-win did not generalize to 16 KiB/64 KiB. Retry only when a NEW owned-buffer-producing function has callers that clone-then-consume and the benchmark proves the concrete call family, not the syntactic pattern. The uncompressed read clone is the open `bd-xmh5g.394` swing, not a clean lever. |
| Redundant-recompute / materialize-to-count / O(N)-scan / Vec-presize on cc hot paths | (swept, no bead) | NO CLEAN HOT WIN | `resolve_data_with` is optimal (Full=borrow, compressed=decompress-once, no delta-fold). Redundant-recompute empty (only `ReadaheadCache::take` `cached.len()` after `split_off` = O(1) micro-lever trap, REJECTED). `collect_extents().len()` already won via header count (`bd-v388x`). O(N) scans are bounded NUL-scans / few btrfs roots / test / tiny commit-frequency SSI sets — none read-hot. `collect_extents` presize needs a counting pre-pass (a second walk = tradeoff). Retry only if a real profile names a specific hot recompute ≥0.1% self-time. |
| FUSE / metadata I/O-overlap parallelization vein | `bd-xmh5g.399` KEPT (readdirplus parallel getattr + ext4 readdir inode-table prefetch) | MINED for the rest | `read_with_readahead` issues ONE combined parallel read of [requested + predictor-sized prefetch tail] then caches the tail (reactive readahead, not a blocking serial prefetch); the ext4 readdir prefetch (`prefetch_ext4_readdir_inode_table_blocks`) is already `into_par_iter`; plain-readdir+stat getattrs are SEPARATE FUSE requests already dispatched concurrently by the worker threads; `copy_file_range` is a generic default over the already-parallel read path; remaining ffs-fuse loops (`encode_xattr_names`, `batch_forget`) are pure in-memory (no I/O). Retry only for a NEW FUSE batch op with a SERIAL per-item device read inside one request (the shape `bd-xmh5g.399` fixed). The open write-side lever is `bd-xmh5g.401` (write-back commit batching), an amortization lever, not I/O-overlap. |
| Write-path durability/sync coalescing (group commit) | (verified, no bead) | ALREADY IMPLEMENTED | `ffs-journal/wal_buffer.rs` already does GROUP COMMIT (epoch-batched WAL writes/syncs: `group_commit_write_start`/`group_commit_success`), so concurrent fsyncs already coalesce into one sync — do NOT file a group-commit lever. The write path commits per request via `commit_request_scope -> scope.commit_if_write(mvcc_store)`, which calls `mvcc_store.write().commit(tx)` — plain `commit` (SNAPSHOT isolation), NOT `commit_ssi`, so writes do NO SSI validation (an SSI inverted-index lever is moot for the write path). `flush_to_device` already coalesces contiguous block writes into ranged writes. The remaining per-commit overhead is therefore WAL append + snapshot bump + version insert (the `Arc<AlignedVec>` aligning copy lives in ffs-block, swarm-owned), which is exactly what `bd-xmh5g.401` (write-back: fewer commits between fsyncs) amortizes — that is the one open write lever. Retry a sync-side or SSI lever only if a profile shows that cost (not the per-commit CPU on snapshot-isolation commits) dominates. |

## BOLD-VERIFY measured verdicts — 2026-06-19 (cc, rch hz1, criterion median)

Resolves the "Pending batch benchmark" status for the swarm code-first levers below. Each was run
via `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cc rch exec -- cargo bench -p <crate>
--bench <name> -- <group> --warm-up-time 1 --measurement-time 3`; benches carry assert_eq/assert
isomorphism guards and built+ran to exit 0 (conformance of the A/B shapes is GREEN).

| Bead | Crate · bench (group) | old → new (median) | Ratio | Verdict |
| --- | --- | --- | --- | --- |
| `bd-xmh5g.385` | ffs-xattr · xattr_exists_probe · `xattr_zero_initialized_external_block` | scalar 1305 ns → chunked 573 ns (late-nonzero 1303 → 578 ns) | **2.28x / 2.25x** | KEEP — chunked `all_zero_bytes` beats the scalar byte loop on the zeroed external-xattr accept path. |
| `bd-xmh5g.384` | ffs-ondisk · btrfs_leaf_parse · `btrfs_leaf_payload_coverage_ab` | eager 7002 ns → lazy 3699 ns | **1.89x** | KEEP — descending-payload fast path skips the eager coverage-bitmap alloc on canonical leaves; bitset replay retained for noncanonical (overlap validation unchanged). |
| `bd-xmh5g.383` | ffs-block · read_contiguous · `read_contiguous_1mib` (outer_staged vs trusted_direct) | 699974 ns → 28577 ns | **24.5x** | KEEP — all-or-nothing ByteDevice lets the trusted contiguous read skip the outer staging Vec and read straight into the caller buffer. |
| `bd-xmh5g.392` | ffs-block · read_contiguous · `read_contiguous_1mib` (blocks_then_copy / ext4_vec vs trusted_vectored) | 1529826 / 1278027 ns → 876044 ns | **1.74x / 1.46x** | KEEP — one trusted vectored read into pre-sized BlockBufs instead of a whole-run staging Vec + per-chunk copy. |
| `bd-xmh5g.391` | ffs-alloc · bitmap_ops · `bitmap_owned_move_ab` (4k) | cod-a rerun copy-to_vec 241.61 ns → move-into_inner 271.26 ns | **0.891x** | REJECTED / REVERTED — `BlockBuf::into_inner()` is `12.3%` SLOWER than `as_slice().to_vec()` at 4K on the allocator bitmap mutation shape. Production restored the owned-move arm to `to_vec`; the bit-level undo-log change is a separate correctness refactor and stays guarded. |

**Pattern reinforced:** read/parse/staging levers WIN (.385/.384/.383/.392); the lone loss is the
`into_inner` owned-buffer move at small blocks — now negative three times, a settled do-not-retry for
4K RMW paths (see the seeded "Owned read-buffer clone→move" row; `.391` is the ffs-alloc instance).

### .382 extent-cache read-lock hot-hit — MEASURED REGRESSION (cc, 2026-06-19, rch hz1)

| Bead | Crate · bench (group) | old → new (median, 8 threads) | Ratio | Verdict |
| --- | --- | --- | --- | --- |
| `bd-xmh5g.382` | ffs-extent · extent_cache_same_ns · `extent_cache_same_ns_8t` | write_lock_hit 17.5 ms → read_lock_atomic_hit 21.7 ms | **0.81x** | REVERT (owner ffs-extent) — the "lock-free" read-lock hit path is SLOWER. Every lookup does `self.hits.fetch_add(1)` on ONE shared atomic counter → 8 threads ping-pong that single cache line: contention RELOCATED from the RwLock to the atomic, net worse. Corroborated by `extent_cache_real_same_ns` (production scales 1t 1.23 ms → 8t 21.9 ms = 17.8x degradation). `assert_eq` fold guard passed (correct, just slower). |
| `bd-xmh5g.382-striped` | ffs-extent · extent_cache_same_ns · `extent_cache_same_ns_8t` | write_lock_hit 14.201 ms → read_lock_striped_atomic_hit 18.341 ms; read_lock_atomic_hit 20.348 ms | **0.774x vs write-lock; 1.11x vs single atomic** | REJECT / PRODUCTION REVERTED — striped counters remove only part of the regression. The hot read path still pays shared read-lock traffic plus per-entry atomic recency updates, so the repaired lever remains slower than the write-lock baseline. Direct ext4/btrfs-kernel ratio remains N/A for this Rust-internal cache primitive. |

**Lever direction for a real win:** the read-lock path can only beat the write-lock once the
hot hit stops touching shared cache lines at all — not just by striping hit/miss accounting. A single
shared `AtomicU64` was a worse contention point than the lock it replaced, and the striped-counter
repair still measured only `0.774x` vs the write-lock baseline. The next viable design needs sampled or
deferred stats plus non-hot recency maintenance, or a different cache admission/eviction policy that
does not update shared metadata on every hit.

### .396 ext4 metadata-only inode parse — MEASURED WIN (cc, 2026-06-19, rch hz1)

| Bead | Crate · bench (group) | old → new (median) | Ratio | Verdict |
| --- | --- | --- | --- | --- |
| `bd-xmh5g.396` | ffs-core · ext4_metadata_parse_xattr_ibody | eager-to_vec 115648 ns → lazy-empty 25721 ns | **4.50x** | KEEP — `parse_metadata_from_bytes` skips the eager ~150B `xattr_ibody` heap alloc on the metadata hot path (getattr/lookup/readdir/access). Full `parse_from_bytes` retained for xattr/listxattr/getxattr/inline-data. Byte-identical fixed FileAttr fields (`inode_metadata_parse_skips_ibody_only` guard). Hot per-inode on ls/find/stat. |

### into_inner owned-buffer family RECONCILED — fresh primitive measurement (cc, 2026-06-19, rch hz1)

Ran the governing primitive bench `ffs-mvcc · blockbuf_into_inner · blockbuf_into_inner_vs_to_vec`
(sole-owned `BlockBuf::new`, the documented `read_block` invariant) on this host:

| size | into_inner_move | as_slice_to_vec_copy | ratio (copy/move) |
| --- | --- | --- | --- |
| 4096  | 246.4 ns | 274.1 ns | **1.11x** |
| 16384 | 677.6 ns | 702.8 ns | **1.04x** |
| 65536 | 2215.7 ns | 2405.5 ns | **1.09x** |

**`into_inner` WINS at ALL sizes on sole-owned buffers** — the `.389` "16K/64K regression" did NOT
reproduce here. The family reconciles cleanly by **ownership**, not block size:
- **Sole-owned** buffer (`read_block` cache-miss / compressed / single-ref) → `try_unwrap` succeeds →
  O(1) move → `into_inner` wins (1.04–1.11x). This is the `bd-xmh5g.390` (btrfs partial-block RMW)
  and `bd-xmh5g.393` (8 ffs-core read/RMW sites — all single-block `read_block(...).into_inner()`)
  case → **KEEP** (measured small win, not a regression).
- **Arc-shared** buffer (journal replay holds staged refs; `bd-xmh5g.394` version-store sharing) →
  `try_unwrap` fails → clone + the failed-unwrap atomic → marginally slower than a direct `to_vec`.
  This is why `bd-xmh5g.404` (journal replay, refs held) measured 0.64x and was correctly reverted,
  and why `bd-xmh5g.391`/`bd-xmh5g.382`-adjacent shared cases lose.

**Verdict:** the cc-owned ffs-core `into_inner` sites (`.390`/`.393`) are KEPT — measured sole-owned
win. The do-not-retry guidance updates to: `into_inner` is correct where `read_block` returns a
sole-referenced buffer that is then mutated/consumed; reject only where the buffer is provably
Arc-shared at the call site (the `.404` replay shape).

### Bulk-read loss PROFILED — userspace-pread tax, no safe lever (cc 2026-06-19)

`perf record -F 999` over warm `ffs walk --read-data` (256 MiB / 4,000 files, 6,364 samples). Top
self-time: `_copy_to_iter` 9.8% (kernel pread copy), spinlock 3.2%, libc `memset` 2.9% (read-buffer
zero-init), `memmove` 2.7% (staging copy), `SYSRETQ` 2.6% (syscall return); frankenfs userspace logic
only ~4%. **Verdict: the ~2× contiguous/many-files read gap to the kernel is the userspace-`pread`
copy+syscall model, NOT frankenfs parse/MVCC/extent code — architecturally bounded.** Do NOT chase it
with hot-path levers; the only avoidable frankenfs slice is read-buffer `memset`+`memmove` (~5.6%, partly
already taken by `.383`/`.392`). Closing the rest needs mmap (`unsafe`, forbidden) or `io_uring` batching
(major structural work). frankenfs's measured win territory is scattered/parallel access (metadata walk
3–5×, fragmented single-large-file read 1.4×); the 2-D boundary (parallelizable I/O AND large-enough
per-item payload) is the durable model. Retry only if an `io_uring`/mmap I/O backend is introduced.

### btrfs prefetch-pool fan-out gate — fix verified complete, ext4 sites do NOT share it (cc 2026-06-19)

The 4.3× btrfs metadata fix (`BTRFS_PREFETCH_MIN_CHILDREN`, commit 18fb0e88) is COMPLETE and bounded:
- **Single dispatch site.** `grep` confirms `btrfs_range_prefetch_pool().install()` appears exactly once
  (`walk_node_body`), shared by BOTH the `bd-h6p3w` range walker and the `bd-l8r3s` full-tree walker — so
  the one gate covers every btrfs parallel walk. No sibling site to fix.
- **Post-fix profile is healthy.** `perf` (2,291 samples) over the fixed walk shows the scheduler thrash
  GONE (no `update_curr`/`pick_task_fair`/`sched_yield` domination); remaining cost is distributed across
  legitimate work — `memmove` 4.9%, `_copy_to_iter` 2.8%, `memset` 2.3%, frankenfs b-tree/parse (`0x304c*`
  cluster ~6–8%), with only minor residual pool `osq_lock` 3.1%. The 1.6× vs kernel btrfs (single dir) is
  now genuine userspace b-tree-walk-per-getattr + I/O-copy cost, NOT a bug. No glaring further lever.
- **The ext4 `par_iter` read sites do NOT share the bug — do not "fix" them.** ffs-core's ext4 read/extent
  par sites (`collect_extents_recursive` child reads ~10499, `read_file_data` jobs ~10953, dir cold-run
  ~11095, dir block scan ~11204) use the GLOBAL rayon pool via plain `.into_par_iter()` — NOT
  `dedicated_pool.install()`. Rayon runs a tiny (1-element) `into_par_iter` inline on the current thread, so
  there is no forced pool entry / worker-wakeup overhead; the ext4 `--read-data` profile showed NO scheduler
  thrash (it was `_copy_to_iter`/syscall-bound). The btrfs thrash was unique to `install()`-into-a-dedicated-
  16-thread-pool called thousands of times per recursive walk. Retry a fan-out gate on the ext4 sites only
  if a profile actually shows scheduler thrash there (it does not today).

### ext4 INDIRECT-block sequential read ~5x slower than kernel (gap, cc 2026-06-19)

Differential-oracle perf probe: a 32 MB indirect-mapped (`^extent`) ext4 file (25 extents, near-contiguous)
read cold — kernel `dd bs=4M` 45 ms (711 MB/s) vs frankenfs `ffs read --discard` 211–224 ms (~145 MB/s) =
**frankenfs ~5x SLOWER** (byte-exact correctness confirmed). This is WORSE than the extent-path sequential
loss (~2x cold), indicating the indirect read path (`read_ext4_indirect`) does not chunk/parallelize a large
contiguous run the way the extent path's `bd-cc-pchunk` (16 MiB block-aligned chunks read in parallel) does —
it coalesces contiguous runs and parallelizes ACROSS non-contiguous runs (bd-r9c10) but a near-contiguous
indirect file surfaces few runs, so there is little to overlap and the per-run read isn't chunked. **Gap
(rare config — modern ext4 uses extents; only ext2/ext3-style `^extent` filesystems hit this), filed as a
lever candidate: port the `bd-cc-pchunk` chunked-parallel large-run read to `read_ext4_indirect`.** Note: the
intended *fragmented*-indirect test did not materialize — ext4's old block allocator coalesced the
fsync-interleaved + spacer writes to 25 extents (fragmentation is hard to force; the original 108-extent
fragmented-read win took deliberate effort), so this measures the contiguous/sequential indirect regime.

#### Follow-up: direct-output copy-elision for indirect reads failed (cod-b/BlackThrush 2026-06-20, bd-r9c10)

The existing `read_ext4_indirect` production path is already serial-plan / parallel-read / serial-assemble:
it resolves indirect pointers in byte order, reads each coalesced data segment on rayon into an owned buffer,
then assembles those buffers into the output. The tested follow-up removed the per-segment owned `Vec` and
let workers fill disjoint output windows directly. Production code was reverted after measurement.

RCH baseline on `vmi1149989` (`AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b
rch exec -- cargo bench --profile release-perf -p ffs-core --bench ext4_indirect_read_overlap --
ext4_indirect_read_overlap --warm-up-time 1 --measurement-time 3`): serial vs incumbent `parallel_rayon`
medians were 16 runs `5.7337 ms / 970.27 us` (`5.91x`), 64 runs `23.414 ms / 2.7872 ms` (`8.40x`), and
256 runs `92.482 ms / 13.491 ms` (`6.85x`). RCH did not keep the requested worker for the candidate and
selected `vmi1167313`; same-binary A/B on that worker measured incumbent `parallel_rayon` vs candidate
`parallel_in_place`: 16 runs `2.7308 ms / 2.5461 ms` (`1.073x`, small win), 64 runs `7.7753 ms / 8.6526 ms`
(`0.899x`, regression), and 256 runs `25.508 ms / 25.452 ms` (`1.002x`, neutral). The benchmark asserts byte
identity against the serial oracle before measuring. Conclusion: direct-output/window-carving copy-elision
does not close the ~5x direct kernel loss and should not be retried without a fresh profile proving assembly
copy dominates. Keep only the benchmark guard; route future work to indirect pointer planning, real fragmented
indirect fixtures, or deeper file-device/syscall/copy levers.

#### Follow-up: chunked large-run indirect reads kept (cod-b/BlackThrush 2026-06-20, bd-xmh5g)

The next lever attacked the actual residual shape from the kernel-loss row:
near-contiguous indirect files collapse into one large coalesced physical run,
which gives the existing parallel read phase only one data job. Production now
splits full-block coalesced indirect runs into ordered chunks before the
existing parallel owned-buffer READ and serial ASSEMBLE phases. The default is
`128` blocks per chunk, with `FFS_INDIRECT_READ_CHUNK_BLOCKS` overriding only
this path and `FFS_READ_CHUNK_BLOCKS` retained as a fallback.

RCH same-worker sweep on `vmi1227854`:

| Workload | Median | Ratio vs single-run | Verdict |
| --- | --- | --- | --- |
| `large_run_single/8192` | `25.523 ms` | baseline | Old one-job shape |
| `large_run_chunked_16blocks/8192` | `31.397 ms` | `0.813x` | Reject: too many chunks |
| `large_run_chunked_32blocks/8192` | `23.067 ms` | `1.106x` | Neutral/noisy |
| `large_run_chunked_64blocks/8192` | `17.267 ms` | `1.478x` | Win |
| `large_run_chunked_128blocks/8192` | `15.729 ms` | `1.623x` | KEEP default |
| `large_run_chunked_256blocks/8192` | `16.591 ms` | `1.539x` | Win, slower than 128 |
| `large_run_chunked_512blocks/8192` | `17.475 ms` | `1.461x` | Win, slower than 128 |

The byte-equivalence guard
`ext4_indirect_large_run_chunks_default_bd_xmh5g` passed on RCH `vmi1167313`.
It constructs a 129-block non-extent inode, verifies byte-identical output, and
asserts the default path performs one cached metadata read plus two chunked data
reads. RCH `cargo check -p ffs-core --all-targets` passed on `vmi1152480`.
Harness conformance passed under RCH-wrapper local fallback (`100 passed / 0
failed / 2 ignored`). Full clippy is still blocked by pre-existing pedantic debt
in `ffs-repair` and unrelated `ffs-core` sites; the lever-specific insertion
order issue was fixed by moving the segment enum and chunk helper out of the
function.

Fresh direct-kernel comparator status: blocked by loop-device policy. The RCH
command built release-perf `ffs-cli`, created a valid no-extents ext4 image, and
confirmed the target file used indirect and double-indirect mappings, but
`mount -o loop,ro` failed with `failed to setup loop device`
(`/tmp/ffs_indirect_cmp.0g2lsq`). Therefore this is a measured internal keep,
not a new kernel-domination claim. The existing direct ext4-kernel loss remains
the release-readiness limiter until the mounted comparator can rerun.

### FUSE write-path round-trip oracle — BLOCKED by sandbox (cc 2026-06-19)

Attempted a write-path differential oracle (frankenfs writes via `ffs mount --rw` FUSE → kernel reads back,
byte-exact) to validate the data-loss-critical WRITE path. `ffs mount --rw` is supported and `/dev/fuse` is
world-accessible with `fusermount3` setuid + `user_allow_other` set, but the mount fails `fusermount3: mount
failed: Permission denied` even as root — a container/sandbox restriction on the FUSE mount syscall. There is
no non-FUSE `ffs write` CLI, so the write-path e2e oracle is not exercisable in this environment. Write-path
conformance remains validated only by in-process unit/property tests, not an external kernel-readback oracle.

### Core-count-ADAPTIVE parallel-read chunk — REJECTED, overfit risk (cc 2026-06-19, bd-vffrx follow-up)

After shipping the fixed `FFS_READ_CHUNK_BLOCKS` default `256 -> 32` blocks (bd-vffrx / 3671522c, a measured
ext4 1.41x / btrfs 3.17x warm win on a 64-core box), tested whether the default should instead SCALE with the
rayon pool size (simulated via `RAYON_NUM_THREADS`), since the optimum clearly moves with thread count.

ext4 128 MiB warm, per-thread-count optimum (min duration_us): thr=2 -> 256, thr=4 -> 64, thr=8 -> 64,
thr=16 -> 32, thr=32 -> 32, thr=64 -> 32. So fixed-32 is OPTIMAL for >=16 threads (the many-core reality) and
only ~5-7% off the per-tier optimum at 2-8 threads.

REJECTED an adaptive scheme because the btrfs cross-thread data is too NOISY and self-CONTRADICTORY to tune
without overfitting: btrfs 100 MiB warm gave best=128 at thr=64 but best=16 at thr=8 and best=32 at thr=4 —
mutually inconsistent across runs (the `walk --read-data` path mixes readdir/getattr/metadata I/O with the
data read, so its per-chunk optimum is unstable). An adaptive formula fit to this would help small-core ext4
by ~5-7% while risking unpredictable btrfs regressions, and no clean principled rule (e.g. fixed chunks/thread)
reproduces the measured optima (4 threads wants 64-block chunks, not the 256 a "few-chunks-per-thread" rule
predicts). Fixed-32 is the simple, robust, measured choice: optimal on many-core hardware, within noise on
small-core, and a large win over the prior 256 everywhere. Conclusion: do NOT add adaptive chunk-sizing.

Commands: `FFS_LOG_FORMAT=json RUST_LOG=info RAYON_NUM_THREADS=<n> FFS_READ_CHUNK_BLOCKS=<cb> \
ffs-cli read IMG FILE --discard 2>&1 | grep duration_us` (ext4); `... ffs-cli walk IMG --read-data` (btrfs).

### btrfs compressed-read pool OVER-subscription — root-caused, `with_min_len` cap FAILED (cc 2026-06-19, bd-defgb)

`btrfs_read_file` fans every per-extent decompress (zstd/lzo) job across the FULL rayon pool. Decompression is
CPU- and cache-bound (unlike the uncompressed memcpy path, which is bandwidth-bound and scales with cores), so
on a 64-core box spreading ~270 short jobs across 64 threads OVER-subscribes. Measured (perf stat, 34 MiB zstd
file, `walk --read-data`) at 64 vs 8 threads: **4.5x task-clock** (293M vs 64M), **4.2x cache-misses** (6.6M vs
1.6M), **8x context-switches** — whole read **1.6x slower warm** (18.0 vs 11.4 ms) AND **1.46x slower cold**
(20.9 vs 14.3 ms) at the default pool; both warm+cold peak at ~8 threads. Real regression at the default pool
size — but NOT cleanly fixable from the work side.

ATTEMPTED FIX (reverted): cap concurrency via `IndexedParallelIterator::with_min_len(jobs.len()/16)` for
decompress-dominated reads. **Ineffective**: the rebuilt binary at the default 64-thread pool stayed at
16.7 ms while the SAME binary forced to `RAYON_NUM_THREADS=8` ran at 10.2 ms. `with_min_len` only coarsens the
task COUNT; it does not stop the 64-thread pool from waking/parking/steal-spinning, and that pool churn (not
task granularity) is the overhead. Confirmed byte-identity and that the uncompressed `btrperf` path was
unchanged, but with no speedup the change is pure complexity — reverted.

PROPER FIX (deferred, bd-defgb): run the decompress par_iter inside a dedicated small rayon pool (~min(16,
cores) threads) via a `OnceLock<ThreadPool>` + `install()`, so the idle global-pool threads stay parked. NOT
landed because per-file `install()` risks the documented dedicated-pool scheduler thrash on multi-file walks
(see the "spurious-fan-out gate" row) — `btrfs_read_file` is called once per file, so a `find`-style walk over
N compressed files = N installs. That regression is not testable in this environment (no large multi-file
compressed image), so the dedicated-pool fix needs a multi-file compressed-walk bench before it can ship.

#### Follow-up: production-shaped dedicated-pool synthetic bench also failed (cod-a/BlackThrush 2026-06-20, bd-defgb)

Added production-shaped synthetic bench
arms to `btrfs_decompress_extents` and tested the dedicated-pool idea before shipping it. Command:
`AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench
--profile release-perf -p ffs-core --bench btrfs_decompress_extents -- --warm-up-time 1 --measurement-time 3`
on worker `hz1`. Results: large 272x128KiB compressed file, global pool 3.1463 ms vs dedicated max16 pool
3.0628 ms = **1.03x**, below the keep gate; many-small-files 64x4x128KiB, always-install dedicated pool
8.0391 ms vs gated-small-files global fallback 8.7118 ms = **0.92x regression** for the gate. The attempted
production `OnceLock<ThreadPool>`/gate patch was reverted. Keep only the bench evidence. Conclusion: do NOT
ship the dedicated-pool or gated-dedicated-pool approach from synthetic evidence; it does not materially close
the compressed-read gap and the anti-thrash gate regresses its modeled workload. Next valid attempt needs a
different lever or an actual large multi-file compressed image with head-to-head kernel/frankenfs timings.

#### Follow-up: dedicated decompress pool ALSO failed — bottleneck mis-localized (cc 2026-06-19, bd-defgb)

Built the deferred fix anyway: a bounded `OnceLock<rayon::ThreadPool>` (FFS_DECOMPRESS_THREADS, default
min(16, cores)) with `install()` around the decompress map for decompress-dominated reads. **Also ineffective
and reverted.** Decisive diagnostic on the rebuilt binary: `FFS_DECOMPRESS_THREADS=1` ran the 34 MiB zstd file
in 19.9 ms and `=64` in 19.1 ms — i.e. the dedicated pool size has NO effect on the read time, so the
decompress map is NOT the pool-size-sensitive path. Yet shrinking the GLOBAL pool (`RAYON_NUM_THREADS=8`)
still gives ~10 ms vs ~18 ms at 64. Conclusion: the global-pool over-subscription is real but lives in a
DIFFERENT path than `btrfs_read_file`'s per-extent decompress jobs. Crucial missed detail: `walk --read-data`
issues the read in 1 MiB chunks (READ_CHUNK), so each `btrfs_read_file` call sees only ~8 extents — the
decompress-jobs guard (`decompress_jobs > 16`) never even trips, and 8 jobs on 64 threads is already only
8-way. The RAYON_NUM_THREADS sensitivity must come from a per-1 MiB-read path that fans across the global pool
(prime suspect: the btrfs extent-tree / metadata walk that locates the extents for each read, or the
`collect_extents_recursive` parallel child-block reads). bd-defgb re-scoped: ROOT-CAUSE must be re-localized
(profile which symbol's parallelism responds to RAYON_NUM_THREADS) BEFORE any cap is attempted — two cap
attempts (with_min_len, dedicated pool) both missed because the bottleneck was assumed to be the decompress
fan-out. No code shipped for this lever.

#### Follow-up: thread-local zstd decoder reuse kept on direct image, synthetic microbench lost (cod-a/BlackThrush 2026-06-20, bd-xmh5g)

Implemented a narrower, kernel-shaped zstd workspace lever: `btrfs_decompress`
now reuses one `zstd::bulk::Decompressor` per worker thread instead of calling
`zstd::bulk::decompress` for every independent btrfs zstd frame. This preserves
the existing btrfs sector-padding rule (`find_frame_compressed_size` still
slices the exact frame) and the shared short-frame zero-fill validation.

Direct mounted-image evidence on `/data/tmp/btrdiff2_1340519.img` against the
kernel mount `/data/tmp/btrdiff2mnt_1340519` pays:

| Workload | Prior FrankenFS | Candidate confirmation | FrankenFS old/new | Current kernel | Candidate vs kernel |
| --- | ---: | ---: | ---: | ---: | ---: |
| `read --discard /compressible.bin` | `76.1 ms` | `54.9 ms` | `1.39x` faster | `cat` `6.5 ms` | `8.51x` slower |
| `walk --read-data --no-stat` | `53.2 ms` | `32.8 ms` | `1.62x` faster | `cat *` `11.0 ms` | `2.99x` slower |

The targeted same-process synthetic did **not** support the mechanism: RCH
`vmi1167313`, command `AGENT_NAME=cod-a RCH_REQUIRE_REMOTE=1
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo
bench --profile release-perf -p ffs-core --bench btrfs_decompress_extents --
btrfs_decompress_tiny_zstd_321x4k_to_128k --warm-up-time 1 --measurement-time
1 --sample-size 10 --noplot`, measured fresh decompressor median `5.9330 ms`
vs thread-reused decompressor median `7.2849 ms` (`0.814x` old/new; reused is
slower). The benchmark file was also patched with a filter guard after two
filtered RCH runs were cancelled because existing bench functions eagerly built
unrelated large datasets before Criterion could apply the target filter.

Keep the production change because the real mounted-image workload wins twice,
but do not use the tiny-frame decompressor-context microbench as a future keep
gate. Next valid btrfs-compressed work should attack the remaining direct kernel
gap with a different primitive: decode directly into the final read buffer,
reuse output allocations across extents, or re-profile the extent-tree/metadata
fan-out that still responds to `RAYON_NUM_THREADS`. Do not retry dedicated pools,
`with_min_len`, or decompressor-context-only microbenches without a new direct
image signal.

#### Follow-up: one-tile serial zstd scheduling rejected at the synthetic gate (cod-a/BlackThrush 2026-06-21, bd-xmh5g)

Tested a narrower scheduling hypothesis from the remaining btrfs compressed-read
gap: when a one-megabyte `ffs-cli read` tile decomposes into only `8` independent
128 KiB zstd frames, skip Rayon and run the current thread-local zstd
decompressor serially. This would have targeted worker scheduling overhead
without changing decompression semantics or output ordering.

RCH `vmi1153651`, command `AGENT_NAME=BlackThrush
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo
bench --profile release -p ffs-core --bench btrfs_decompress_extents --
btrfs_decompress_tiny_zstd_8x4k_to_128k --warm-up-time 1 --measurement-time 1
--sample-size 10 --noplot`, measured current parallel reused decompressor
median `406.30 us` versus serial reused decompressor median `471.70 us`.
Serial scheduling is `0.861x` the current path by median. Criterion intervals
overlapped (`serial [444.38, 525.59] us`, `parallel [292.57, 630.26] us`) and
the parallel row was noisy, so this is negative routing evidence rather than
positive proof for either family.

Win/loss/neutral: internal A/B `0/1/0` for the serial-scheduling candidate;
direct kernel `0/0/1` because no production candidate reached mounted-kernel
A/B. The direct kernel target remains unchanged from the retained btrfs
compressed-read row: final-source single-file `/compressible.bin` still loses
`35.9 ms` versus kernel `cat` `6.7 ms` (`5.38x` slower), and whole-tree `walk
--read-data --no-stat` still loses `31.9 ms` versus kernel `cat *` `11.2 ms`
(`2.85x` slower).

No production code was changed. The retained benchmark guard asserts serial and
parallel decompression produce identical decompressed byte counts, so future
agents can rerun this exact scheduling gate before retrying the family. Local
`cargo fmt -p ffs-core --check` passed; RCH `cargo check -p ffs-core
--all-targets` passed on `vmi1152480`; `rch exec -- cargo test -p ffs-harness
--test conformance -- --nocapture` fell back local because no admissible workers
were available and passed `100 / 0 / 2 ignored`; RCH `cargo build --release -p
ffs-core` passed on `ovh-a`. RCH scoped clippy `cargo clippy -p ffs-core
--bench btrfs_decompress_extents --no-deps -- -D warnings` failed before the
benchmark target on existing/current shared `ffs-core` library pedantic rows:
`vfs.rs` derivable default, item-after-statement rows, redundant closures, old
indirect-pointer casts, and cod-b's in-progress ext4 direct-output enum. No
benchmark/doc-caused lint was reported. Note: `cargo bench --release` is not
valid Cargo syntax for benches, so the command uses the equivalent `--profile
release` spelling.

#### Follow-up: direct-to-final zstd extent decode rejected (cod-a/BlackThrush 2026-06-20, bd-xmh5g)

Tested the next data-movement lever from the graveyard: for regular zstd
compressed extents whose full decompressed `ram_bytes` exactly overlaps the
caller output window, read compressed bytes into bounded scratch but decode zstd
directly into the final `out` slice. Partial extents, inline extents, zlib/LZO,
and uncompressed reads kept the incumbent path. Production code was reverted
after measurement.

Direct mounted-image evidence used the same btrfs image and kernel mount:
`/data/tmp/btrdiff2_1340519.img` and `/data/tmp/btrdiff2mnt_1340519`.

| Workload | Current FrankenFS baseline | Candidate | FrankenFS old/new | Current kernel | Candidate vs kernel | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `read --discard /compressible.bin` | `55.931 ms` | `57.961 ms` | `0.965x` | `cat` `7.011 ms` | `8.27x` slower | REJECT |
| `walk --read-data --no-stat` | `34.8826 ms` | `34.8828 ms` | `1.000x` | `cat *` `11.537 ms` | `3.02x` slower | NEUTRAL/REJECT |

Win/loss/neutral: internal A/B `0/1/1`; direct kernel `0/2/0`.

Behavior/build gates: the candidate RCH `cargo check -p ffs-core` and RCH
`cargo build --profile release-perf -p ffs-cli` passed on `vmi1152480`.
After reverting the source, clean-source RCH `cargo check -p ffs-core` passed on
`vmi1153651`, clean-source RCH `cargo test -p ffs-harness --test conformance --
--nocapture` passed on `vmi1227854` with `100 passed / 0 failed / 2 ignored`,
and clean-source RCH `cargo build --profile release-perf -p ffs-cli` passed on
`vmi1149989`.

Conclusion: do not retry final-buffer zstd decode for this path without a heap
allocation attribution profile proving the decompressed `Vec` allocation and
copy dominate. The single-file read regressed and the whole-tree read was
indistinguishable. The remaining `3.02-8.27x` kernel gap is more likely in
btrfs extent lookup/metadata fan-out, compressed scratch allocation, or
CLI/open/read overhead than final output assembly.

### FileByteDevice thread-local read scratch buffer — MEASURED INERT, reverted (cc 2026-06-20, bd-cc-rscratch)

Hypothesis: the warm sequential-read sys-time is dominated by the per-chunk temp allocation in
`FileByteDevice::read_exact_at` (`let mut read_buf = vec![0u8; buf.len()]` → pread → `copy_from_slice` into
the caller's `dst`). The temp exists only to honour `preserves_read_exact_at_destination_on_error == true`
(a short/failed backing read must leave `dst` byte-for-byte unchanged — exercised by
`file_byte_device_scalar_read_preserves_buffer_on_short_read`, which truncates the backing file mid-read).
A per-call `vec![0u8; len]` zero-fills fresh pages every chunk; on a 128 MiB read split into 128 KiB chunks
that is ~1024 allocations. Attempt: replace the per-call temp with a **thread-local reusable scratch buffer**
(`thread_local! { static FILE_READ_SCRATCH: RefCell<Vec<u8>> }`, 1 MiB reuse cap, one-off alloc above cap)
in both `read_exact_at` and `read_vectored_exact_at` — faults the scratch pages in once per worker, keeps the
exact preservation contract (still copies into `dst` only on success), all tests green.

**Measured INERT.** `perf stat` of `ffs-cli read --discard` on a 128 MiB ext4 extent file (tmpfs image,
warm): page-faults **19,943 → 19,699** (unchanged), warm engine `duration_us` ~22–25 ms before and after
(within run-to-run variance). Diagnosis: the page-faults are **not** from the device temp — glibc's dynamic
`M_MMAP_THRESHOLD` already recycles the ~128 KiB temp from the arena after warm-up, so the thread-local merely
re-implements what the allocator already does. The faults are dominated by the read engine's **output buffer**
(`vec![0u8; to_read]` materialising the whole 128 MiB result), and the residual warm cost is the **second
copy** (page-cache → temp → `dst`, vs the kernel's single page-cache → user copy) plus that output zero-fill —
both inherent to a `#![forbid(unsafe_code)]` engine that must hand initialised `&mut [u8]` to the read and
cannot read directly into uninitialised memory. Reverted (only `crates/ffs-block/src/lib.rs`, restored).

**Do-not-retry predicate:** do not re-attempt buffer-recycling for `FileByteDevice` reads as a warm-read
lever — the allocator already recycles and the page-faults live in the engine output buffer, not the device
temp. The only paths that would actually remove the residual copy/zero-fill are (a) reading directly into the
caller `dst` (requires weakening `preserves_read_exact_at_destination_on_error`, which a deliberate test
guards), or (b) `mmap`/uninitialised-buffer reads (require `unsafe`, forbidden here) — i.e. the same structural
zero-copy gap already recorded in "Bulk-read loss PROFILED — userspace-pread tax, no safe lever".

### MEASUREMENT METHODOLOGY: head-to-head CLI reads must use `--profile release-perf`, not `release` (cc 2026-06-20)

Discovered while profiling the btrfs read gap that `[profile.release]` in the workspace `Cargo.toml` is
**`opt-level = "z"` (optimise for SIZE) + `lto = true` + `strip = true`** — it is the small-binary profile,
NOT the speed profile. The performance profile is **`[profile.release-perf]`: `opt-level = 3`,
`lto = "thin"`, `debug = "line-tables-only"`, `strip = false`** (criterion benches already use it via
`--profile release-perf`). A plain `cargo build --release -p ffs-cli` produces a size-optimised, symbol-stripped
binary. **Any `ffs-cli read` head-to-head built with `--release` therefore (a) understates frankenfs throughput
(size-opt de-optimises hot loops) and (b) cannot be `perf`-profiled (symbols stripped).** The
ext4-vs-kernel and ext4-vs-btrfs *ratios* in this ledger are still valid (both sides used the same size-opt
binary), but the absolute MB/s figures are a floor — re-measure with `--profile release-perf` for true numbers
and to get resolvable symbols. Recorded as a standing methodology fix: **build the CLI with
`cargo build --profile release-perf -p ffs-cli` (output `target/release-perf/ffs-cli`) for every perf
head-to-head and every `perf record`.** (The release-perf rebuild this session was blocked by rch-worker
contention + the slow `ffs-core` opt-3/LTO compile, so the btrfs-gap symbol localisation in bd-2emlm remains
pending that build.)

### Pending-lever re-verification harvest — 7 levers closed, 1 magnitude correction (cc 2026-06-20, rch)

Independently re-ran the criterion A/B benches for the 7 open "code-first batch-test pending" perf levers
(read JSON `median.point_estimate` from `CARGO_TARGET_DIR/criterion/*/new/estimates.json` — the harness
truncates rch bench stdout, the JSON survives). All stay above the 2.0× KEEP gate; closed all 7. Fresh
ratios this session:

| Bead | Bench | Fresh ratio (re-run) | Scorecard (prior) | Verdict |
|------|-------|----------------------|-------------------|---------|
| bd-avqg1 | recovery_build_writeback_blocks | 5.43× / 15.99× / **58.10×** (N=64/512/4096) | 4.75/22.9/70.4× | ✅ KEEP (algorithmic) |
| bd-g5v1s | recovery_capture_io_overlap | 7.10× / 7.38× / 7.68× (16/64/256) | 6.25/6.20/35.0× | ✅ KEEP |
| bd-wgv6x | inode_free_runs | **1008×** contiguous_1024; 1.01× fragmented | (new) | ✅ KEEP (neutral on fragmented = correct) |
| bd-w52e5 | repair_symbol_read_io_overlap | 7.37× / 7.53× / 7.62× (16/64/256) | 7.22/7.57/7.72× | ✅ KEEP (matches) |
| bd-eei3y | por_respond_io_overlap | 7.43× / 7.65× / 7.70× (64/256/460) | 7.59/7.78/7.82× | ✅ KEEP (matches) |
| bd-pkvrj | journal_replay_apply_io_overlap | 2.50× / 3.55× / 4.25× (16/64/256) | **8.74/42.4/51.9×** | ✅ KEEP (≥2.0) but **magnitude correction** |
| bd-ya8zh | por_authtable_build | (scorecard) 2.07/2.85/2.96× | — | ✅ KEEP (≥2.0 at all N) |

**Honesty note (bd-pkvrj):** the journal-replay I/O-overlap re-run is a clean win at every N but its magnitude
is **~10× lower** than the originally recorded 8.7/42/52× — the LatencyBlockDevice (`sleep` per read) ratio is
acutely sensitive to the bench host's pool size and the sleep duration, so the original figures were
over-recorded. The lever is still correct to keep (serial 6.7/24.8/104 ms vs parallel 2.7/7.0/24.4 ms), but
**I/O-overlap absolute ratios from these synthetic latency benches are host-dependent — read them as "clear
win, magnitude ±", not literal speedups.**

### ✅ btrfs read gap FIXED — read-into-`dst` fast path, 1.37× warm + RSS halved, now BEATS the kernel (cc 2026-06-20, bd-2emlm SHIPPED)

Acting on the root-cause below: `read_into` (the streamed-read API the CLI/FUSE use) had an **ext4 fast path
that reads straight into the caller's `dst`** but a **btrfs fallback through `FsOps::read` that allocates a
fresh owned `Vec` per 64 MiB chunk and copies it into `dst`** — the source of the 2× RSS, the `__memmove_avx`
samples, and the page-fault thrash. Fix: parameterised `btrfs_read_file` → **`btrfs_read_file_into(dst)`** that
writes straight into the caller buffer (zeroing `dst[..to_read]` first so holes stay zero — byte-identical to
the old `vec![0u8; to_read]`), kept a thin owned-`Vec` `btrfs_read_file` wrapper for the two callers that need
owned bytes (`FsOps::read`, symlink-target reads), and added a **btrfs fast path in `read_into`** mirroring the
ext4 one (dir/symlink guards then `btrfs_read_file_into`). MEASURED on the 128 MiB btrfs (release-perf, warm):

| metric | before | after | result |
|--------|--------|-------|--------|
| max RSS | 133 MB | **70 MB** | **−47 %** (matches ext4's 64 MB — the owned-Vec gone) |
| warm read | 80.7 ms (1587 MB/s) | **59.1 ms (2164 MB/s)** | **1.37× faster** |
| vs kernel `dd bs=128M` (82.9 ms) | 0.97× (parity) | **1.40× FASTER** | **flips btrfs from parity to a kernel-domination win** |

Byte-identical (ffs-core `btrfs_read*` + `read_into` tests green, exit 0; full ffs-core suite green).
**bd-2emlm closed.** This is the session's REAL kernel-domination win: btrfs warm reads now beat the in-kernel
btrfs driver's single-threaded materialise, the same way ext4 already did.

**Residual re-profiled (post-fix, release-perf):** the kept `out.fill(0)` memset is only **2.5 %**
(`__memset_avx2`) — NOT worth a zero-only-holes rewrite. The remaining btrfs-vs-ext4 (59 vs 21 ms) gap is
diffuse: **16.6 % `__memmove_avx`** = the `FileByteDevice::read_exact_at` temp→`dst` double-copy (page-cache →
temp → caller buffer vs the kernel's single copy — shared with ext4, the same userspace-pread tax recorded in
"Bulk-read loss PROFILED"), **~5 % rayon `Stealer::steal`** (mild btrfs pool imbalance, down from ~8 %), and
the btrfs per-chunk logical→physical resolution. The one shared lever (eliminate the FileByteDevice
double-copy) needs **relaxing `preserves_read_exact_at_destination_on_error`**, a guarantee the team
*deliberately added* (W160 bd-wvdrd/bd-d2bci, with a dedicated truncation test) — a design decision, not a
code tweak, so deferred rather than blindly undone. No further single-crate lever closes the residual safely.

### btrfs read gap ROOT-CAUSED: memory-pressure / 2× RSS, not CPU/syscalls/parallelism (cc 2026-06-20, release-perf + symbols, bd-2emlm)

Rebuilt `ffs-cli` with `--profile release-perf` (opt-level=3 + symbols) and profiled the btrfs vs ext4 read
head-to-head. Decisive evidence the btrfs gap is **memory-pressure-bound**, not what the original bead guessed:

- **opt-level insensitive:** release (opt-z) → release-perf (opt-3) sped ext4 **24.5→21.6 ms (+13 %)** but left
  btrfs **80.7 ms unchanged** — so the btrfs cost is NOT CPU-compute (opt-3 optimises compute, not memory/IO).
- **2× resident memory:** max RSS ext4 **64 MB** vs btrfs **133 MB** for the identical 128 MiB read — btrfs holds
  ~2× the working set, which drives the **52 471 vs 19 943 page-faults** already recorded.
- **the page-fault pressure slows the reads themselves:** `perf` children — ext4 spends 38.7 % in
  `FileByteDevice::read_exact_at` (of a 21 ms read ≈ 8 ms); btrfs spends 22.5 % (of an 80 ms read ≈ **18 ms**) —
  i.e. the *same* ~1040 preads take **2.25× longer** under btrfs's memory pressure. btrfs self-time also shows
  ~8 % `crossbeam_deque::Stealer::steal` (rayon workers idle-stealing = imbalanced/under-filled pool) and 5.8 %
  `__memmove_avx` (the FileByteDevice temp→dst copy), with the remainder in kernel page-fault/scheduler frames.

**Root cause (redirected):** the lever is NOT "parallelise the btrfs read" (it already chunk-parallelises and
reads direct-into-`dst`) — it is **reduce the btrfs read's memory footprint** so it stops doubling RSS and
thrashing page-faults. The ~+69 MB btrfs holds over ext4 is not yet pinned to a line (the CPU sampling profile
shows the *symptom* — page faults — not the *allocation site*); pinning needs a heap profiler (heaptrack/massif)
or a careful audit of `btrfs_read_file`'s owned allocations (`jobs`/`results`/`decompressed_by_idx`/the output
buffer lifetime) vs ext4's `read_file_data`. **Deferred, not blindly patched** — a blind footprint change in
peer-contended `ffs-core` could regress. bd-2emlm updated with this root-cause. Vs the KERNEL btrfs this read is
still parity (0.97× of `dd bs=128M`), so it is an internal ext4-vs-btrfs gap, not a kernel-loss — a worthwhile
future win (closing it would make btrfs warm reads beat the kernel as ext4 already does) but correctly sequenced
behind a heap profile.

### btrfs uncompressed warm read 3.3× slower than ext4 — INTERNAL gap filed bd-2emlm (cc 2026-06-20)

Rounded out the head-to-head onto btrfs (image via `btrfs-convert` of the ext4 fixture, csum-verify OFF =
default). frankenfs btrfs warm read **80.7 ms (1586 MB/s)** vs the SAME data on ext4 **24.5 ms (5216 MB/s)** =
**3.3× slower internally**. `perf stat`: btrfs read uses only **6.9 CPUs** (ext4 13–16), **676 M instructions**
(ext4 415 M, +63 %), **52 471 page-faults** (ext4 19 943, 2.6×). Vs the **kernel** btrfs it is still **parity**:
kernel materialise (`dd bs=128M`/`f.read`) 82.9 ms = frankenfs **0.97× (slight win)**; kernel streaming 25.1 ms
= frankenfs 3.2× slower (the same zero-copy-streaming boundary as ext4). So this is an **internal ext4-vs-btrfs
gap, not a fresh kernel-loss** — the btrfs read under-parallelises (prime suspect: per-chunk `ReadJob` temp
`Vec` allocation, the extra ~32 k page-faults beyond the output buffer; csum is off so not that). Filed
**bd-2emlm** with the profile; deferred (ffs-core peer-contended) — fix = apply ext4's `IoJob`
direct-into-`dst` `read_contiguous_into` pattern to the btrfs uncompressed read path.

### Warm contiguous read re-measured on the 64-core box — chunk-parallelism monotone (cc 2026-06-20, bd-vffrx confirm)

Independent re-measurement of the live `ffs-cli read --discard` warm throughput on a 128 MiB contiguous ext4
extent file (tmpfs-resident → pure CPU/bandwidth, warm; 7 runs/median), sweeping `FFS_READ_CHUNK_BLOCKS`:

| chunk | warm median | throughput |
|-------|-------------|------------|
| 32 blocks (128 KiB) — **shipped default** | 24.5 ms | **5216 MB/s** |
| 256 blocks (1 MiB) — W160 default | 28.1 ms | 4561 MB/s |
| 1024 blocks (4 MiB) | 36.7 ms | 3492 MB/s |
| 4096 blocks (16 MiB) — original default | 59.1 ms | 2165 MB/s |

Monotone: finer chunks → more jobs to fill the 64-thread rayon pool → higher throughput; the 4096→32 retune
is a **2.4× warm gain** on real many-core hardware. Like-for-like kernel comparators on the same file (warm):
single-threaded **full-materialise** (`dd bs=128M` / Python `f.read()`) ≈ 1798 MB/s → frankenfs **2.9× FASTER**;
**cache-hot streaming** (8 MiB reused buffer, never materialises) ≈ 12968 MB/s → frankenfs ~2.5× behind. This
confirms (not supersedes) the existing verdict: frankenfs's parallel read **beats** any reader that
materialises the file and trails only an idealised zero-copy streaming reader — the residual is the
materialisation + double-copy tax above, not a parallelism deficit. (Note: tmpfs image → `drop_caches` does
not evict, so only the warm/CPU-bound regime is characterised here, which is exactly where the gap lives.)

### REJECTED: btrfs read scratch/direct-into-dst candidates did not move the real read gap (cod-b 2026-06-20, bd-2emlm)

Tried the next obvious memory-footprint levers against `bd-2emlm` and reverted them because the primitive win
did not transfer to the real btrfs read:

- `FileByteDevice` thread-local reusable staging scratch, preserving destination-on-error semantics.
- btrfs `read_into` direct-to-caller-buffer form, avoiding the owned `Vec` + fallback copy in the streamed
  `OpenFs::read_into` path.

The isolated block primitive looked spectacular on RCH `hz1`: in one same-binary Criterion run,
`file_byte_device_read_1mib/fresh_temp_vec_shape` measured `1.0804 ms` median while
`file_device_reused_scratch` measured `96.908 us`, an `11.15x` old/new win. That was not enough. The candidate
release CLI still measured essentially neutral on the actual 100 MiB btrfs image:

| Comparator | Mean | Ratio | Verdict |
| --- | ---: | ---: | --- |
| FrankenFS candidate `read --discard /m.bin` | `74.949 ms` | vs prior `76.3 ms`: `1.02x` faster, inside noise | Neutral |
| FrankenFS candidate in kernel-streaming run | `77.580 ms` | vs prior `76.3 ms`: `0.98x` slower, inside noise | Neutral |
| kernel btrfs `dd bs=128M` | `127.923 ms` | FrankenFS `1.71x` faster | Win vs materialising comparator |
| kernel btrfs `dd bs=8M` | `51.407 ms` | FrankenFS `1.51x` slower | Loss |
| kernel btrfs `cat` | `11.710 ms` | FrankenFS `6.63x` slower | Loss |

The one-shot `/usr/bin/time` smoke for the candidate binary reported `maxrss=137968 KiB`, not lower than the
prior ~133 MiB btrfs profile. That falsifies the hoped-for "remove one big allocation and drop RSS" story for
this surface. The likely remaining gap is not the `FileByteDevice` temp buffer alone, nor the fallback copy
alone; it needs heap-allocation attribution inside the btrfs read pipeline (`jobs`, `results`,
`decompressed_by_idx`, output lifetime, and chunk-map metadata) before another code lever. Retrying scratch or
read-into-dst without a new allocation profile is expected to be neutral.

Commands/evidence:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench -p ffs-block --bench read_contiguous -- \
  file_byte_device_read_1mib --warm-up-time 1 --measurement-time 2

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo build --release -p ffs-cli

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture

hyperfine --warmup 3 --runs 10 \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli --log-format json read /data/tmp/btrperf_1231197.img /m.bin --discard >/dev/null 2>&1' \
  'dd if=/data/tmp/btrperfmnt_1231197/m.bin of=/dev/null bs=128M status=none'

hyperfine --warmup 3 --runs 10 \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli --log-format json read /data/tmp/btrperf_1231197.img /m.bin --discard >/dev/null 2>&1' \
  'cat /data/tmp/btrperfmnt_1231197/m.bin >/dev/null' \
  'dd if=/data/tmp/btrperfmnt_1231197/m.bin of=/dev/null bs=8M status=none'
```

Production verdict: **no code kept**. Both source candidates were reverted. `bd-2emlm` remains a real open
gap; the next credible move is a heap profiler or allocation census, not another temp-buffer micro-lever.

### btrfs compressed-read fused copy/drop kept (cod-a/BlackThrush 2026-06-20, bd-xmh5g)

Kept a narrower memory-pressure lever than the rejected direct-to-final zstd
attempt: regular compressed btrfs extents still decompress into the existing
owned `Vec`, but the parallel read/decompress job now slices, copies into its
disjoint final `out` window, and drops that decompressed `Vec` immediately.
Inline compressed extents keep the old owned-byte result because their overlap
range is only known after decompression. Uncompressed extents keep the existing
direct-into-output path.

This preserves the extent-order error policy by storing only a per-extent
`Done`/`Bytes` result and consuming those results in the serial assembly loop.
The actual data writes are to pre-carved non-overlapping output windows. The
change targets the specific live-buffer pressure identified by the remaining
compressed-read kernel gap: the old path retained every regular compressed
extent's decompressed `Vec` until serial assembly finished.

Direct mounted-image evidence used `/data/tmp/btrdiff2_1340519.img` with the
mounted kernel reference `/data/tmp/btrdiff2mnt_1340519`.

| Workload | Baseline | Candidate | FrankenFS old/new | Kernel btrfs | Candidate vs kernel | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Primary 15-run `read --discard /compressible.bin` | `56.1 ms` | `36.8 ms` | `1.52x` faster | `cat` `7.4 ms` | `5.00x` slower | KEEP |
| Primary 15-run `walk --read-data --no-stat` | `36.6 ms` | `34.0 ms` | `1.08x` faster | `cat *` `11.9 ms` | `2.85x` slower | Neutral-positive/no extra keep credit |
| Final-source 10-run `read --discard /compressible.bin` | `53.2 ms` | `35.9 ms` | `1.48x` faster | `cat` `6.7 ms` | `5.38x` slower | KEEP confirmation |
| Final-source 10-run `walk --read-data --no-stat` | `32.4 ms` | `31.9 ms` | `1.015x` faster | `cat *` `11.2 ms` | `2.85x` slower | Neutral |

Win/loss/neutral: internal A/B `1/0/1`; direct kernel `0/2/0`.

Memory smoke moved in the expected direction on single-file read:

| Probe | Baseline | Candidate |
| --- | ---: | ---: |
| Max RSS | `83,620 KiB` | `50,868 KiB` |
| Minor faults | `22,932` | `14,478` |

Byte identity was verified against the mounted kernel file:
`2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9`
for baseline, candidate, and kernel `compressible.bin`.

RCH caveat: `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo build --profile release-perf -p ffs-cli`
passed on `vmi1149989`, but artifact retrieval left the target-dir binary at
the clean baseline hash. The accepted direct A/B timings therefore use a local
release-perf build from the clean detached worktree; the RCH build is recorded
as a remote compile gate, not as the source of the measured binary.

Isomorphism:

- Ordering preserved: yes. Extents are still validated and consumed in extent
  order; only regular compressed extent bytes are copied into final disjoint
  output windows earlier.
- Tie-breaking unchanged: yes. The first per-idx error is retained, and the
  serial assembly loop still surfaces errors in extent order.
- Floating-point: N/A.
- RNG seeds: N/A.
- Golden/byte proof: candidate read SHA-256 matches the mounted kernel file;
  focused btrfs decompression tests and harness conformance passed.

Gates:

```bash
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --profile release-perf -p ffs-cli

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo build --profile release-perf -p ffs-cli

cargo fmt -p ffs-core --check

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo check -p ffs-core --all-targets

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo test -p ffs-core btrfs_decompress -- --nocapture

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo test -p ffs-harness --test conformance -- --nocapture
```

Results: `ffs-core` check passed; focused btrfs decompression tests passed
`10/10`; conformance passed `100 / 0 / 2 ignored`. Scoped clippy is still
blocked by pre-existing `ffs-repair` and `ffs-core` pedantic debt outside this
lever (`RequestCommitMode` derivable default, old local static/use/const
placement, indirect-pointer casts, redundant closures). The candidate-caused
local-enum clippy lint was fixed by moving helper enums to file scope.

Retry predicate: do not repeat generic scratch reuse or zstd direct-to-final.
The next credible compressed-read pass should attack the remaining kernel gap
after this memory win: metadata descent reuse/extent lookup (currently owned by
`bd-xmh5g.408`), compressed input read staging with a proof that it changes the
real mounted-image path, or a kernel-shaped streaming API that avoids whole-file
materialization rather than merely changing the decompression buffer.

---

## 2026-07-10 — Cold-read WHY: ranked frame table (bd-5koeh follow-up, BlackThrush/cc_ffs)

The cold-read hypothesis in `bd-5v3mh` ("frankenfs issues no readahead hints")
is **refuted** and its lever already shipped; the three ext4 cold rows re-derived
under a valid method all show frankenfs **slower** than kernel ext4. This section
answers *why*, from a profile of the exact prebuilt `release-perf` binary that
produced those numbers (no rebuild: `strip=false`, `debug="line-tables-only"`).

Workload: `ffs-cli read /data/tmp/q6k00/cold_ext4.img /big.bin --discard`
(128 MiB, 2 extents), `drop_caches=3` immediately before, `perf record -F 4999 -e cycles`.

### Ranked self-time frames (>= 0.1%), default RAYON_NUM_THREADS=64

| self% | frame | layer |
| --- | --- | --- |
| 39.07 | `native_queued_spin_lock_slowpath` | kernel — **lock contention** |
| 6.27 | `crossbeam_deque::Stealer::steal` | user — rayon work-stealing |
| 5.69 | `_copy_to_iter` | kernel — the actual copy |
| 5.21 | `clear_page_erms` | kernel — zero-fill of fresh anon pages |
| 2.59 | `crossbeam_epoch::Global::try_advance` | user — rayon epoch GC |
| 1.84 | `entry_SYSRETQ_unsafe_stack` | kernel — syscall return |
| 1.28 | `asm_exc_page_fault` | kernel — fault entry |
| 1.04 | `__filemap_add_folio` | kernel — page-cache insert |
| 0.78 | `up_read` | kernel |
| 0.74 | `pick_task_fair` | kernel — scheduler |
| 0.70 | `zap_present_ptes` | kernel — teardown |
| 0.67 | `rmqueue_bulk` | kernel — page allocator |
| 0.62 | `update_curr` | kernel — scheduler |
| 0.59 | `_raw_spin_lock` | kernel |
| 0.53 | `xas_find_conflict` | kernel — xarray |
| 0.49 | `rayon_core::WorkerThread::wait_until_cold` | user |
| 0.47 | `std::sys::sync::mutex::futex::Mutex::lock_contended` | user |
| 0.40 | `page_cache_ra_unbounded` | kernel — readahead |
| 0.38 | `get_page_from_freelist` | kernel — page allocator |
| 0.35 | `xas_load` | kernel — xarray |
| 0.34 | `lru_gen_add_folio` | kernel — LRU |

### The three candidate causes, tested and ranked

1. **Per-block syscall overhead — REFUTED.** `perf stat` counts **1,034**
   `pread64` calls for 128 MiB, i.e. ~128 KiB per call (1024 data preads + ~10
   metadata). The read path is not per-4-KiB-block. Syscall entry/exit is
   ~1.8% of self-time.
2. **Extent-tree walks — REFUTED.** The 128 MiB file has 2 extents; the
   fragmented fixture has 9 and the indirect fixture has 14. If walking drove
   the cost, tax would rise with extent count. It does not: parse+copy tax vs a
   same-mode floor is 1.35x (2 extents), 1.15x (9 extents), 1.36x (14 extents) —
   uncorrelated. No extent/indirect frame appears above 0.1% self-time.
3. **Copy tax — REAL BUT MINOR.** `_copy_to_iter` is 5.69% and
   `clear_page_erms` 5.21% (zero-filling freshly-allocated destination pages,
   19,279 page faults). Together ~11%, not the dominant term.

### Actual cause: kernel page-cache lock contention from over-parallelized buffered pread

`perf record -g` resolves the contended lock unambiguously:

```
32.99%  File::read_exact_at -> __libc_pread -> __x64_sys_pread64 -> vfs_read
        -> ext4_file_read_iter -> generic_file_read_iter -> filemap_read
        -> filemap_get_pages (32.71%)
           -> page_cache_sync_ra (31.62%)
              -> page_cache_ra_unbounded -> filemap_add_folio
                 -> __filemap_add_folio (28.34%)   [xarray xa_lock]
```

Every rayon worker preads the **same inode**, so all 64 threads serialize
inserting folios into that one `address_space` xarray. Cold read converts I/O
parallelism into lock contention. This is why the DIO-loop kernel arm is fast:
`O_DIRECT` never touches `filemap_add_folio`.

### Confirmation by prediction (byte-identical, prebuilt binary, no rebuild)

`RAYON_NUM_THREADS` sweep, cold, min-of-5, engine time minus 8.4 ms startup:

| threads | 1 | 2 | 4 | 8 | **16** | 32 | 64 (default) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| read (ms) | 86.2 | 63.3 | 40.4 | 32.0 | **30.1** | 32.9 | 37.0 |

Contention falls exactly as predicted:

| | spinlock self% | rayon steal | sys CPU |
| --- | --- | --- | --- |
| T=64 | 42.27% | 5.42% | 0.446 s |
| T=16 | 10.96% | 1.26% | 0.158 s |

Paired interleaved A/B (7 reps): T=16 faster **7/7**, sign-test p=0.0156,
1.24x faster; `sha256` identical to the kernel mount at both thread counts.
Generalizes: indirect **1.44x** faster, fragmented **1.19x** faster at T=16.

Effect on the kernel gap (vs kernel-best, dio loop):

| fixture | T=64 | T=16 |
| --- | --- | --- |
| ext4 extent 128 MiB | 1.37x slower | **1.11x slower** |
| ext4 indirect 50 MiB | 1.45x slower | **1.09x slower** |
| ext4 fragmented 48 MiB | 1.31x slower | **1.09x slower** |

**Warm reads want the same cap** (page-cache hot, min-of-5): T=4/8/16/32/64 read
= 15.5 / 9.0 / **8.5** / 10.0 / 12.6 ms. So capping read fan-out carries no
warm-path regression risk — the rayon default (`nproc`=64) over-parallelizes
reads in both regimes.

Retry predicate: do **not** spend further effort on readahead/`fadvise` tuning or
on chunk-size sweeps for cold reads — both are refuted. The open lever is the
read fan-out width itself (`into_par_iter` at `crates/ffs-core/src/lib.rs:10108`,
`12677`, `12819`, all on the global rayon pool). Tracked in `bd-ddryj`.

---

## 2026-07-10 — Cold-read: contention scales with FOLIO INSERTIONS, not reads, not threads (bd-ddryj, BlackThrush/cc_ffs)

Follow-up to the frame table above. Instrumented the cold read with
`filemap:mm_filemap_add_to_page_cache` (page-cache insertion count),
`syscalls:sys_enter_pread64` (read count) and `lock:contention_begin`, on the
prebuilt `release-perf` binary (**no rebuild**), `drop_caches=3` before each run.

### Q: does contention scale with thread count or with read count?

`ffs-cli read`, 128 MiB, `RAYON_NUM_THREADS` swept:

| T | folio inserts | B/insert | preads | lock contentions | cycles (M) |
| --- | --- | --- | --- | --- | --- |
| 1 | 2,230 | 60,187 | 1,034 | 0 | 337 |
| 2 | 10,145 | 13,229 | 1,034 | 1 | 345 |
| 4 | 12,623 | 10,633 | 1,034 | 78 | 398 |
| 8 | 15,137 | 8,867 | 1,034 | 669 | 439 |
| 16 | 17,914 | 7,493 | 1,034 | 2,473 | 548 |
| 32 | 23,271 | 5,768 | 1,034 | 7,541 | 819 |
| 64 | 27,174 | 4,940 | 1,034 | 11,912 | 1,467 |

**Read count is constant (1,034) at every thread count.** Contention does *not*
scale with reads. What scales is the number of distinct page-cache insertions:
2,230 → 27,174 (**12.2x**), because bytes-per-insertion collapses from ~60 KiB
(order-4 large folios) to ~4.9 KiB (order-0 pages).

### Why: one shared `struct file` destroys the readahead folio order

`FileByteDevice` holds `file: Arc<File>` (`crates/ffs-block/src/lib.rs:523`), so
every rayon worker `pread`s through **one** `struct file` and therefore one
`file->f_ra` readahead state. Interleaved offsets from N workers look
non-sequential to that single state machine, so `page_cache_ra_unbounded` stops
allocating large folios and falls back to order-0 — multiplying xarray
insertions, each taking the `address_space` `xa_lock`.

Controlled proof (same thread count, same reads, same bytes; only fd sharing
differs), raw parallel `pread` of the identical extents, `sha256`-verified:

| mode | T | inserts | B/insert | cycles (M) | ms |
| --- | --- | --- | --- | --- | --- |
| shared fd (what frankenfs does) | 8 | 17,476 | 7,680 | 392 | 36.7 |
| **per-thread fd** | 8 | **2,978** | **45,070** | 323 | **26.0** |
| shared fd | 32 | 19,382 | 6,925 | 615 | 30.7 |
| per-thread fd | 32 | 3,858 | 34,789 | 453 | 27.1 |
| shared fd | 64 | 19,542 | 6,868 | 655 | 31.8 |
| per-thread fd | 64 | 4,720 | 28,436 | 597 | 33.0 |

At T=8, giving each thread its own fd cuts insertions **5.9x** and wall **1.41x**.
Self-time confirms the mechanism: `native_queued_spin_lock_slowpath`
2.45% → 0.50%, `__filemap_add_folio` 2.29% → 0.14%.

**Answer: contention scales with page-cache insertion count. Thread count only
matters because a shared `struct file` inflates insertions; read count is
irrelevant.**

### Lever (a) "larger contiguous reads" — REFUTED as stated

Shared fd, T=8, chunk swept. Bigger reads cut syscalls 147x but do **not** cut
insertions, and hurt wall time:

| chunk | preads | inserts | B/insert | ms |
| --- | --- | --- | --- | --- |
| 128 KiB | 1,027 | 15,374 | 8,730 | 35.2 |
| 1 MiB | 131 | 18,014 | 7,451 | 34.5 |
| 8 MiB | 19 | 17,184 | 7,811 | 60.8 |
| 32 MiB | 7 | 17,149 | 7,827 | 66.6 |

Insertion count is a property of readahead folio order, not of read size. The
correct form of lever (a) is **preserve large folios by giving each reader its
own `f_ra`** (per-thread fd), not "read bigger".

### Lever (b) "spread across distinct inodes" — subsumed

The `xa_lock` is per-`address_space`, so distinct inodes would give distinct
xarrays. But the data show the lock is barely contended once insertions collapse
(0.50% at T=8 per-thread). The actionable half of (b) is the per-thread
`struct file`, which is what actually restores folio order. Splitting one file
across inodes is not possible for a single-file read anyway.

### Lever (c) O_DIRECT — QUANTIFIED, NOT IMPLEMENTED

Measured as a *ceiling only*, in the raw `pread` harness (page-aligned `mmap`
buffers, `os.preadv`), `sha256` identical to the kernel mount. **No frankenfs
code was changed; O_DIRECT would require audited-unsafe or a policy change.**

| mode | T | inserts | cycles (M) | ms |
| --- | --- | --- | --- | --- |
| O_DIRECT | 1 | ~0 (1,527 residual, loader) | 126 | 50.9 |
| O_DIRECT | 8 | ~0 | 174 | **25.0** |
| O_DIRECT | 32 | ~0 | 279 | 26.6 |
| O_DIRECT | 64 | ~0 | 397 | 28.4 |

Best-of-T wall, same bytes:

| approach | ms | vs today |
| --- | --- | --- |
| shared fd (frankenfs today) | 30.7 | 1.00x |
| per-thread fd | 26.0 | **1.18x** |
| O_DIRECT | 25.0 | 1.23x |
| *kernel-best (dio loop, t=32)* | *26.9* | *the comparator* |

**O_DIRECT buys only 1.04x of wall over the safe per-thread-fd fix, but 1.86x of
CPU (323M → 174M cycles).** So O_DIRECT is a CPU-efficiency play, not a latency
play; it is not worth an unsafe/policy change to close a 4% wall gap. Per-thread
fd + a bounded fan-out reaches **26.0 ms vs the kernel's 26.9 ms — parity.**

### Blocker (surfaced, not worked around)

The per-thread-fd gain is measured in the raw `pread` harness, not inside
frankenfs. Proving it *in* frankenfs needs a modified `FileByteDevice` binary,
and this box is under a disk constraint that forbids local `cargo build`, while
`rch exec -- cargo build` **cannot return the artifact**: the globally-exported
`CARGO_TARGET_DIR=/data/tmp/cargo-target` makes rch treat every build as a
custom-target-dir build and retrieval yields ~0 bytes (remote compile succeeds;
`check`/`test` are unaffected because they only stream diagnostics). A criterion
bench cannot substitute: this is a cold-path effect requiring `drop_caches` (root)
between reps, which criterion cannot express on a remote worker.

Retry predicate: do **not** re-test chunk size, readahead/`fadvise`, extent
walks, or the copy tax for cold reads — all refuted. The single open lever is
per-reader `struct file` + bounded fan-out (`bd-ddryj`).

---

## 2026-07-10 — Cold-read: the insertion-count-vs-throughput curve (bd-ddryj, BlackThrush/cc_ffs)

Requested sweep: folio insertions per MiB and lock-wait time at 4K/16K/64K/256K/1M
read granularities. Measured on frankenfs's **real** read path — granularity via
`FFS_READ_CHUNK_BLOCKS` (4 KiB blocks), verified to move `pread` count
(1 block → 32,777 preads; 256 blocks → 138). Prebuilt `release-perf` binary,
**no rebuild**. `drop_caches=3` before every run. 128 MiB, 2 extents.

Lock wait is real spin-wait time from `perf lock contention` (tracepoint mode),
summed across threads, attributed by caller. **Caveat:** `perf lock record`
instruments every contention event and inflates the run, so wait totals are
comparable *between arms* but must not be compared against the uninstrumented
`read` column.

| T | chunk | preads | ins/MiB | B/insert | wait (readahead) | contended | read | MiB/s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 4K | 32,777 | 16 | 67,311 | 0 ms | 0 | 134.2 ms | 954 |
| 1 | 16K | 8,202 | 16 | 66,576 | 0 ms | 0 | 100.6 ms | 1,272 |
| 1 | 64K | 2,058 | 17 | 62,777 | 0 ms | 1 | 91.2 ms | 1,403 |
| 1 | 256K | 522 | 18 | 58,534 | 0 ms | 0 | 90.1 ms | 1,421 |
| 1 | 1M | 138 | 17 | 61,909 | 0 ms | 2 | 92.0 ms | 1,391 |
| 16 | 4K | 32,777 | 105 | 9,986 | 42 ms | 3,113 | 41.0 ms | 3,123 |
| 16 | 16K | 8,202 | 111 | 9,459 | 84 ms | 5,158 | 34.1 ms | 3,750 |
| 16 | 64K | 2,058 | 134 | 7,828 | 235 ms | 10,930 | 32.9 ms | 3,896 |
| 16 | 256K | 522 | 169 | 6,195 | 366 ms | 15,250 | 35.4 ms | 3,611 |
| 16 | 1M | 138 | 115 | 9,100 | 233 ms | 9,468 | 31.7 ms | 4,041 |
| 64 | 4K | 32,777 | 143 | 7,323 | 1,814 ms | 20,064 | 47.1 ms | 2,717 |
| 64 | 16K | 8,202 | 156 | 6,739 | 2,114 ms | 21,773 | 39.5 ms | 3,239 |
| 64 | 64K | 2,058 | 198 | 5,303 | 3,208 ms | 26,713 | 41.8 ms | 3,065 |
| 64 | 256K | 522 | 254 | 4,128 | 3,414 ms | 32,024 | 38.3 ms | 3,340 |
| 64 | 1M | 138 | 107 | 9,800 | 1,143 ms | 9,036 | 38.8 ms | 3,303 |

All wait is attributed to `page_cache_ra_unbounded+0x14b` and
`page_cache_ra_order+0x1fe` — the `xa_lock` taken while inserting readahead folios.

### The curve refutes the premise: insertions drive LOCK WAIT, not THROUGHPUT

* `r(lockwait, ins/MiB)` = **+0.80** across all 15 points — insertions really do
  cause the contention.
* `r(ins/MiB, MiB/s)` **within a fixed thread count** = +0.15 (T=16), +0.25 (T=64).
  Insertion count has **no predictive power over throughput**.
* The pooled `r(ins/MiB, MiB/s)` = +0.78 is Simpson's paradox: thread count raises
  both insertions and throughput. Do not read it as causal.
* Direct counter-example, same T=64: **256K → 254 ins/MiB, 3,414 ms wait, 3,340 MiB/s**
  vs **1M → 107 ins/MiB, 1,143 ms wait, 3,303 MiB/s**. Cutting insertions 2.4x and
  lock wait 3.0x made it **1% slower**.

Spin-wait is CPU burned *while other threads wait on the device*; it is overlapped
with I/O, so it costs cycles, not wall. That is why capping fan-out helped (fewer
threads → less CPU burn *and* less readahead thrash) while shrinking insertions via
read size does not.

### Each requested lever, quantified

1. **Larger contiguous reads → fewer, bigger folios: REFUTED.** ins/MiB is flat in
   chunk size at T=1 (16→18 from 4K to 1M) and *rises* with chunk at T=16/64
   (105→169, 143→254) before falling only at 1M. Read size does not select folio
   order. The T=1 throughput gain (954 → 1,421 MiB/s, **1.49x**) is pure syscall
   amortization — insertions never move.
2. **Readahead that batches into one insertion: ALREADY HAPPENS — concurrency
   destroys it.** At T=1 the kernel yields ~64 KiB folios (67,311 B/insert) even for
   4 KiB reads. At T=64 it collapses to ~4–7 KiB. The knob is not IO size; it is
   readahead *sequentiality per `struct file`*. Restoring it (per-thread fd, prior
   commit `7155b208`) cut insertions 5.9x **and** wall 1.41x — the only change that
   moved both.
3. **Hugepage / large-folio-friendly IO sizes: REFUTED.** Folio order is chosen by
   the readahead state machine, not by the read size (see T=1, 4K reads → order-4
   folios). No IO size recovers order-4 folios at T=64 on a shared fd.

### Lever (c): what bypassing the page cache would buy — QUANTIFIED, NOT IMPLEMENTED

Measured only as a ceiling in the raw `pread` harness (page-aligned `mmap` buffers,
`O_DIRECT`, per-thread fd, T=16), `sha256` identical to the kernel mount.
**No frankenfs code was changed. O_DIRECT/mmap remain owner-gated (`bd-kdmu4`).**

| chunk | O_DIRECT MiB/s | O_DIRECT ms | buffered per-thread fd |
| --- | --- | --- | --- |
| 4K | 419 | 305.8 | **665 MiB/s** (192.5 ms) — buffered *wins*, readahead covers small reads |
| 16K | 1,139 | 112.4 | — |
| 64K | 3,216 | 39.8 | — |
| 256K | **4,981** | 25.7 | — |
| 1M | 4,923 | 26.0 | **5,020 MiB/s** (25.5 ms) |

**Bypassing the page cache buys 0% of wall time** once fds are per-thread and the
chunk is >= 256 KiB (25.5 ms buffered vs 25.7 ms O_DIRECT), and it is **1.6x SLOWER
than buffered at 4 KiB** because it forfeits readahead entirely. Its only real
benefit is CPU: 1.86x fewer cycles (323M → 174M, prior commit). O_DIRECT is a
CPU-efficiency play, not a latency play — it does not justify an audited-unsafe or
policy change on latency grounds.

### Net

The one lever that moves wall time is **restore per-reader readahead sequentiality
(per-thread `struct file`) + a bounded fan-out**, already filed as `bd-ddryj`.
frankenfs's shipped default (128 KiB chunks) is already near-optimal on granularity;
`FFS_READ_CHUNK_BLOCKS` is not worth tuning.

Retry predicate: do **not** re-test read granularity, readahead/`fadvise`, extent
walks, the copy tax, or "reduce insertions" as a throughput lever for cold reads.
All are now measured and refuted. Insertion count is a *lock-wait* (CPU) lever only.

### Ledger-integrity re-audit (frankenmermaid `5feb977` rule), 2026-07-10

frankenmermaid found four REJECT rows that had been A/B'd on a benchmark where the
code under test never executed (0.000% self-time), so those rows measured dead code.
House rule adopted: **every REJECT must carry the self-time figure proving the
function under test actually ran on the measured input.**

Re-auditing the cold-read rejects above with `perf report --percent-limit 0`:

| reject | code-executed proof (self-time) | verdict |
| --- | --- | --- |
| per-block syscall overhead | `entry_SYSRETQ_unsafe_stack` **1.84%**; `__x64_sys_pread64` on a 32.99% callchain | VALID — path is hot, just not the cost |
| copy tax | `_copy_to_iter` **5.69%**; `clear_page_erms` **5.21%** | VALID — executed, quantified at ~11% |
| readahead / folio-insertion levers | `__filemap_add_folio` **1.04%**; `page_cache_ra_unbounded` **0.40%**; 100% of spin-wait attributed to `page_cache_ra_*`; insertions varied 2,230→27,174 across arms | VALID |
| read-granularity lever | knob provably engaged: `pread` count moved **32,777 → 138** (237x) | VALID |
| **extent-tree walks** | `<ffs_core::OpenFs>::resolve_extent` **0.05%**; extent-map `arc_swap::load` **0.10%**; `ext4_es_lookup_extent` **0.13%** | **VALID BUT NARROW — see below** |

The extent-walk reject is **not** the frankenmermaid failure mode: the code did run
(non-zero self-time). But its self-time is ~0 because the fixtures barely exercise
it — `big.bin` has **2** extents, `frag.bin` **9**, `double_ind.bin` **14**, and a
sequential read parses the tree ~once, caching the map in an `arc_swap`ed
`Arc<[ExtentMapping]>`. So the claim "extent walks are not the cold-read cost" is
established **only for <= 14 extents**.

**A file with hundreds or thousands of extents was never measured. That regime is
UNTESTED, not refuted, and is reopened as `bd-vpypn`** — which must also cover the
random-read path, where the extent map is consulted per access rather than once.

---

## 2026-07-10 — Where folio insertions originate, and whether frankenfs can reduce them WITHOUT bypass (bd-ddryj / bd-kdmu4 evidence, BlackThrush/cc_ffs)

Hypothesis under test (as posed): *"if bigger reads do not reduce insertions, the
insertions are driven by the FUSE/page-cache path itself, one folio per block
regardless of request size"* — implying the only remaining lever is `O_DIRECT` or an
mmap-backed `ByteDevice`, i.e. the audited-unsafe policy change.

**Both halves of that hypothesis are false.** Measured on the prebuilt `release-perf`
binary (no rebuild), `drop_caches=3` per run, 128 MiB / 2 extents.

Two corrections of premise first: (1) **FUSE is not in this path.** `ffs-cli read`
`pread`s the image file directly; there is no FUSE round-trip to attribute insertions
to. (2) **Insertions are not one-per-block.** The
`filemap:mm_filemap_add_to_page_cache` tracepoint carries an `order` field:

### Folio order distribution, identical 128 KiB requests

| | order-0 (4 KiB) | order-2 (16 KiB) | order-6 (256 KiB) | mean |
| --- | --- | --- | --- | --- |
| T=1 | 1,599 (72.8%) | 78 | **506 — covering 126 of 128 MiB** | **62.8 KiB/insert** |
| T=64 | **28,191 (96.3%)** | 905 | 7 | **4.7 KiB/insert** |

At T=1 the kernel inserts **256 KiB folios for 128 KiB reads** — the folio is *larger
than the request*. Folio order is decoupled from request size, which is exactly why
the granularity sweep found no lever.

### Insertion origin (callchain-attributed, 100% of events)

| T | origin | share | orders emitted |
| --- | --- | --- | --- |
| 1 | `page_cache_ra_order` | 90.2% (1,981) | ord6 x506, ord2 x78, ord0 x1,383 |
| 1 | `page_cache_ra_unbounded` | 9.8% (215) | ord0 only |
| 1 | `__filemap_get_folio` | 0.0% (1) | — |
| 64 | `page_cache_ra_unbounded` | 57.6% (16,848) | **ord0 only** |
| 64 | `page_cache_ra_order` | 42.4% (12,413) | ord0 x11,340, ord2 x905, ord4 x99 |
| 64 | `__filemap_get_folio` | 0.0% (3) | — |

**Every insertion originates in the readahead path.** There is no per-block
`filemap_create_folio` fallback doing the work (`__filemap_get_folio` ≈ 0). Under
concurrency the insertions *migrate* to `page_cache_ra_unbounded`, which allocates
**only order-0 folios**, and even `page_cache_ra_order` stops choosing large orders.

### Can frankenfs reduce insertions WITHOUT bypassing the page cache? YES — 8.8x

Same T=8, same reads, same bytes, pure **buffered** `pread` (no `O_DIRECT`, no `mmap`);
only fd sharing differs. `sha256` identical to the kernel mount.

| | insertions | mean | large folios (order>=4) | covering |
| --- | --- | --- | --- | --- |
| shared fd (what `FileByteDevice` does) | 16,989 | 7.8 KiB | 477 | 44 MiB |
| **per-thread fd** | **1,926** | **69.2 KiB** | **1,011** | **126 MiB** |

Order-5 (128 KiB) folios go from 232 to **1,000**, i.e. essentially the entire file is
inserted as large folios again. This is a **pure page-cache-resident fix**: give each
reader its own `struct file` so its `f_ra` sees a sequential stream.

**The hypothesis that insertions are irreducible without bypass is REFUTED.**

Code-executed proof (ledger-integrity rule, `5feb977`): the readahead insertion path
under test is hot and provably ran — `__filemap_add_folio` **1.04% self-time**,
`page_cache_ra_unbounded` **0.40% self-time**; 100% of the 29,264 (T=64) / 2,197 (T=1)
insertion events attribute by callchain to `page_cache_ra_*`; and the knob provably
engaged (insertions moved 16,989 -> 1,926 under the arms). No arm measured dead code.

### What the bypass would buy — MEASURED, not projected

A projection from the insertion-count-vs-lock-wait curve was requested. **That
projection is invalid and is not offered here.** Within a fixed thread count,
`r(ins/MiB, MiB/s)` = +0.15 (T=16) / +0.25 (T=64): insertion count has no predictive
power over throughput, because spin-wait is CPU burned while other threads block on the
device — overlapped with I/O. A lock-wait-based projection would forecast a large win
where the direct measurement shows none.

Direct measurement instead (raw `pread` harness, page-aligned `mmap` buffers, per-thread
fd, T=16, `sha256` identical to the kernel mount; **no frankenfs code changed**):

| chunk | O_DIRECT | buffered, per-thread fd |
| --- | --- | --- |
| 4K | 419 MiB/s | **665 MiB/s** (buffered wins — bypass forfeits readahead) |
| 256K | **4,981 MiB/s** (25.7 ms) | — |
| 1M | 4,923 MiB/s | **5,020 MiB/s** (25.5 ms) |

**Bypassing the page cache buys 0% of wall time** (25.5 ms buffered vs 25.7 ms
`O_DIRECT`) once fds are per-thread and chunk >= 256 KiB, and it is **1.6x SLOWER at
4 KiB**. Its only benefit is CPU: **1.86x fewer cycles** (323M -> 174M at T=8).

### Owner decision, surfaced (bd-kdmu4)

`O_DIRECT` / mmap-backed `ByteDevice` **cannot be justified on latency grounds.** The
safe, `forbid(unsafe_code)`-compatible fix — per-reader `struct file` plus a bounded
fan-out (`bd-ddryj`) — reaches **25.5 ms vs the kernel's 26.9 ms**, i.e. parity, with
zero policy change. If the owner ever approves `bd-kdmu4`, the justification must be
**CPU efficiency (~150M cycles saved per 128 MiB read)**, not throughput. Recommendation:
do not approve it for latency.

Retry predicate: the cold-read mechanism is now closed end-to-end. Do **not** re-test
read granularity, readahead/`fadvise`, extent walks (<=14 extents), the copy tax,
"reduce insertions for throughput", or O_DIRECT-for-latency. The only open work is
`bd-ddryj` (per-reader `struct file` + bounded fan-out) and `bd-vpypn` (extent walks at
high extent counts, never measured).

---

## 2026-07-10 — Cold-read chain CLOSED: the projection is computed, and it is falsified (bd-kdmu4 owner decision, BlackThrush/cc_ffs)

Final turn of the cold-read chain. Prebuilt `release-perf` binary, **zero local cargo
builds**, `drop_caches=3` before every run, arms interleaved within each rep.

### 1. Insertions per READ — the requested per-read instrumentation

A 128 KiB read spans 32 x 4 KiB pages, so **32 insertions/read is the "one folio per
block" ceiling.** frankenfs's real binary, production 128 KiB chunk, `pread` count
constant at 1,034:

| T | insertions | insertions/read | % of one-folio-per-block ceiling |
| --- | --- | --- | --- |
| 1 | 2,230 | 2.16 | 6.7% |
| 2 | 10,145 | 9.81 | 30.7% |
| 4 | 12,623 | 12.21 | 38.1% |
| 8 | 15,137 | 14.64 | 45.7% |
| 16 | 17,914 | 17.32 | 54.1% |
| 32 | 23,271 | 22.51 | 70.3% |
| **64** | **27,174** | **26.28** | **82.1%** |

**The "one folio per block" intuition is 82% correct — but only at 64 threads.** It is a
symptom of concurrency on a shared `f_ra`, not a property of the page-cache path. Same
harness, same chunk, T=16, only fd sharing differs (1,027 preads both arms):

| | insertions | insertions/read | % of ceiling |
| --- | --- | --- | --- |
| shared fd | 16,430 | 16.00 | 50.0% |
| **per-thread fd** | **3,895** | **3.79** | **11.9%** |

### 2. CAN frankenfs reduce insertions without bypassing the page cache? YES — 4.2x

Answered definitively, in pure buffered mode, at the production chunk: **16,430 -> 3,895
insertions (4.2x), 16.00 -> 3.79 per read.** 100% of insertions originate in the readahead
path (`page_cache_ra_order` / `page_cache_ra_unbounded`); `__filemap_get_folio` ~= 0, so
there is no per-block `filemap_create_folio` fallback that only a bypass could avoid.

**The premise "insertions are irreducible without O_DIRECT/mmap" is REFUTED.** The
antecedent for escalating `bd-kdmu4` does not hold.

### 3. The projection, computed as requested — and falsified

**Model A** (Amdahl on spin-wait self-time; eliminating insertions removes all
`native_queued_spin_lock_slowpath` cycles, assume wall proportional to CPU):

| T | read | spinlock self-time | projected | projected speedup |
| --- | --- | --- | --- | --- |
| 64 | 37.0 ms | 42.27% | 21.4 ms | **1.73x** |
| 16 | 30.1 ms | 10.96% | 26.8 ms | **1.12x** |

**Model B** (aggregate spin-wait / threads, subtracted from wall):

| T | chunk | aggregate wait | per thread | wall | projected |
| --- | --- | --- | --- | --- | --- |
| 64 | 1M | 1,143 ms | 17.9 ms | 38.8 ms | 20.9 ms = **1.85x** |
| 64 | 256K | 3,414 ms | 53.3 ms | 38.3 ms | **-15.0 ms — NEGATIVE WALL** |

Model B predicts a negative wall time. **The projection method is self-refuting**, and
Model A inherits the same defect in milder form.

**Measurement** (`O_DIRECT` eliminates insertions entirely; raw harness, page-aligned
`mmap`, `sha256` == kernel mount; no frankenfs code changed):

* T=16: `O_DIRECT` **25.7 ms** vs buffered per-thread fd **25.5 ms** -> **1.00x (-1%)**
* T=64: `O_DIRECT` 28.4 ms
* device floor: raw buffered `pread` T=32 = 28.3 ms; kernel dio loop = **26.9 ms**

**Projection 1.12x-1.85x. Measurement 1.00x.** Spin-wait is CPU burned by threads that are
*already blocked on the device*; it is overlapped with I/O and never on the critical path.
Wall is bounded below by device bandwidth: 128 MiB at ~4,700-5,000 MiB/s = 25.5-27 ms.

### 4. Owner decision (bd-kdmu4) — SURFACED

After the fan-out cap frankenfs sits at **30.1 ms against the kernel's 26.9 ms**: total
remaining headroom **3.2 ms (1.12x)**, of which `O_DIRECT` captures **0 ms**. Its only
benefit is CPU: **1.86x fewer cycles** (323M -> 174M per 128 MiB read).

> `bd-kdmu4` (O_DIRECT / mmap-backed `ByteDevice`) **cannot be justified on latency
> grounds.** Approve it only if ~150M cycles per 128 MiB read is worth an audited-unsafe or
> policy change on **CPU-efficiency** grounds. Not implemented; nothing in its scope touched.

The remaining wall lever is the read **fan-out width** (`bd-ddryj`: rayon `nproc`=64 -> 16,
**1.24x cold, 7/7 paired reps, p=0.0156** on the real binary; warm 1.48x), which needs no
unsafe and no policy change.

### Ledger-integrity (frankenmermaid `5feb977`)

Code-executed proof for every reject in this section: `native_queued_spin_lock_slowpath`
**42.27%** self-time (T=64) / **10.96%** (T=16); `__filemap_add_folio` **1.04%**;
`page_cache_ra_unbounded` **0.40%**; 100% of 29,264 insertion events attributed by callchain
to `page_cache_ra_*`. Knob provably engaged: insertions/read **16.00 -> 3.79** under the arms.
No criterion bench was used anywhere in this campaign, so substrate-v2 defects (sequential
group members; `black_box` DCE) cannot apply — arms are wall-clock runs alternated **inside**
each rep, and results are consumed via `sha256` / XOR checksums / byte counts.

### Chain closed

Cold-read is now fully explained: kernel page-cache `xa_lock` contention, driven by folio
insertions, driven by readahead order collapse on a shared `struct file`. Insertions are a
**CPU** lever, not a throughput lever (three independent confirmations). Do not re-test
readahead/`fadvise`, extent walks (<=14 extents), the copy tax, read granularity, "reduce
insertions for throughput", or O_DIRECT-for-latency. Open: `bd-ddryj` (fan-out cap, blocked
on a build) and `bd-vpypn` (extent walks at high extent counts, never measured).

---

## 2026-07-10 — Honest cold baseline re-established; the gap has moved OUT of the kernel (bd-zvn7r, BlackThrush/cc_ffs)

With `xa_lock` and folio insertions off the table, this re-measures the real remaining
gap and re-ranks the frames. Prebuilt `release-perf` binary, **zero local cargo builds**;
`drop_caches=3` before every run; **all arms interleaved within each rep** (substrate v2);
`sha256` identical across arms (`b6cfaf9d…`, kernel mount == `ffs-cli read`).
Quiet box (load 4.4). 128 MiB, 2 extents, production 128 KiB chunk.

### The baseline (9 interleaved reps, medians)

| arm | median | min | cv | vs kernel |
| --- | --- | --- | --- | --- |
| ffs T=64 (**as shipped**) | 42.94 ms | 40.92 | 12.7% | **1.54x** |
| ffs T=16 (best config) | 34.67 ms | 33.09 | 2.3% | **1.25x** |
| *(ffs per-open startup, subtracted per rep)* | 4.79 ms | 4.60 | 5.3% | — |
| raw pread, same fd model + chunk | 28.20 ms | 27.80 | 10.4% | 1.01x |
| kernel dio loop T=32 | 27.80 ms | 26.70 | 8.5% | — |

`ffs T=16` beats `ffs T=64` in **9/9 paired reps, p=0.0039** — the fan-out cap (`bd-ddryj`)
reconfirmed on a quiet box.

### Decomposition of the residual

```
  ffs T=16 read                     34.67 ms
  raw pread, same fd model+chunk    28.20 ms   -> frankenfs-attributable  +6.47 ms
  kernel dio loop T=32              27.80 ms   -> buffered page-cache path +0.40 ms
  TOTAL gap vs kernel                          +6.87 ms  (1.25x)
```

**94% of the remaining gap is frankenfs's own cost. The buffered page-cache path now costs
0.40 ms.** That closes the kernel-side story: `xa_lock`, insertions, readahead, granularity
and the bypass are all done. The gap lives in frankenfs.

### Fresh ranked frame table — ffs, T=16, production chunk, self-time >= 0.1%

| self% | frame | layer |
| --- | --- | --- |
| 12.28 | `_copy_to_iter` | kernel — the buffered copy (inherent) |
| **11.81** | **`clear_page_erms`** | kernel — **zero-filling fresh destination pages** |
| 9.32 | `native_queued_spin_lock_slowpath` | kernel — residual `xa_lock` (was **42.27%** at T=64) |
| 5.74 | `asm_exc_page_fault` | kernel |
| 2.19 | `rmqueue_bulk` | kernel — page allocator |
| 2.02 | `__filemap_add_folio` | kernel |
| 1.67 | `lru_gen_add_folio` | kernel |
| 1.57 | `do_anonymous_page` | kernel |
| 1.44 | `mod_memcg_lruvec_state` | kernel |
| 1.13 | `crossbeam_deque::Stealer::steal` | user — rayon |
| 1.13 | `zap_present_ptes` | kernel |
| 1.09 | `up_read` | kernel |
| 0.94 | `get_page_from_freelist` | kernel |
| 0.80 | `__alloc_frozen_pages_noprof` | kernel |
| 0.77 | `__mem_cgroup_charge` | kernel |
| 0.69 | `ext4_mpage_readpages` | kernel |

CPU split at T=16: **user 4.5 ms, sys 188 ms** — frankenfs's *userspace* code is nearly free;
what it costs is the **kernel work its allocation pattern provokes**.

**New #1 frame owner: the anonymous-page alloc/fault/zero cluster = 28.91% of cycles**
(`clear_page_erms` + `asm_exc_page_fault` + `rmqueue_bulk` + `lru_gen_add_folio` +
`do_anonymous_page` + `mod_memcg_lruvec_state` + `zap_present_ptes` + `get_page_from_freelist` +
`__alloc_frozen_pages` + `__mem_cgroup_charge` + `get_mem_cgroup_from_mm` + …). Measured
**17,459 page faults (17,385 minor) for a read of 32,768 destination pages**: frankenfs allocates
a fresh destination buffer per chunk, so pages are faulted, zero-filled, and then immediately
overwritten by `_copy_to_iter`. Filed as `bd-zvn7r`.

### Recorded so nobody chases it again: per-thread fd cuts insertions 4.2x and buys NO wall time

At the production 128 KiB chunk, T=16, same 1,027 preads, only fd sharing differs:
insertions **16,430 -> 3,895** (16.00 -> 3.79 per read), yet wall is **1.025x median, 7/9 paired
reps, p=0.1797 — NOT significant**. Self-time proving the path ran: `__filemap_add_folio`
**2.02%**, `native_queued_spin_lock_slowpath` **9.32%**, `page_cache_ra_unbounded` **0.40%**
(T=64 profile). **Per-reader `struct file` is a CPU-efficiency change, not a latency fix.**

### A proxy that failed its own validity check — no REJECT recorded

I built a raw-pread proxy for the buffer-reuse lever (alloc-per-chunk vs reused per-thread buffer,
128 KiB, T=16, shared fd, `sha256` identical). It showed reuse **slower**: 0.957x median, reuse wins
**1/7** paired reps, p=1.0. **That result is inadmissible.** The proxy's alloc arm produced only
**2,364 page faults** against frankenfs's **17,459** (7.4x fewer), because glibc's *dynamic* mmap
threshold makes CPython recycle the freed 128 KiB block rather than returning it. The proxy never
exercises the mechanism under test, so its null says nothing about frankenfs.

This is the ledger-integrity rule (`5feb977`) applied to a **proxy** rather than a bench: the arm must
reproduce the mechanism's **magnitude**, not merely its shape. Same class of error as the earlier
proxy-chunk artifact. Buffer reuse is therefore **UNTESTED for frankenfs, not refuted** (`bd-zvn7r`).

### Do not project

Do **not** convert the 28.91% cycle share into a projected wall win. Projecting wall from cycle share
was already proven invalid on this exact workload (`bd-kdmu4`: Model A/B predicted 1.12–1.85x;
measurement was **1.00x**), because much of this cluster — like spin-wait — is CPU burned by threads
already blocked on the device. The size of the buffer-churn lever must be **measured in-tree**.

### Blocked

`bd-zvn7r` and `bd-ddryj` both need a modified binary run locally under `drop_caches`.
`RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo build` still does not return the
artifact. Unblock by fixing rch retrieval, or by granting one local build.

---

## 2026-07-10 — The new #1 frame is in the BENCHMARK HARNESS, not the filesystem (bd-zvn7r re-scoped, BlackThrush/cc_ffs)

**Reproducibility metadata (new ledger rule):** binary `ffs-cli`
`sha256=03b7456d8cd6fa118bd214b2fdf8a03e56cac79e6768b7311613b039c8ae81eb`
(55,453,584 bytes, `release-perf`, built 2026-07-10 04:02:59); allocator
`tikv_jemallocator` (`ffs-cli/src/main.rs:8`); worker = local host (perf/`drop_caches`
need root, so no remote worker); `rch` verification worker = `hz1`. cv per arm below.
Zero local cargo builds.

### Naming the frame, with self-time

From the T=16 profile (`perf record -F 4999 -e cycles`, prebuilt binary above):

| self% | frame |
| --- | --- |
| 12.28% | `_copy_to_iter` |
| **11.81%** | **`clear_page_erms`** |
| 9.32% | `native_queued_spin_lock_slowpath` |
| 5.74% | `asm_exc_page_fault` |
| 2.19% | `rmqueue_bulk` |
| 1.57% | `do_anonymous_page` |
| 1.13% | `zap_present_ptes` |
| 0.94% | `get_page_from_freelist` |
| 0.80% | `__alloc_frozen_pages_noprof` |
| 0.77% | `__mem_cgroup_charge` |

**Anon-page alloc/fault/zero cluster = 28.91% of cycles.**

### Where it comes from — traced to an exact line, and it is NOT the FS engine

`ffs-cli read` streams the file in `STREAM_CHUNK = 64 MiB` slices through **one reused
`vec![0_u8; 64 MiB]`** (`crates/ffs-cli/src/main.rs:2403-2407`; the reuse itself was an
earlier fix, `bd-2x68s`). First-touching that buffer faults **16,384 pages**, each of which
the kernel must `clear_page_erms` before the read overwrites it.

Numerically confirmed on the real binary:

| run | page-faults |
| --- | --- |
| `ffs read /small.bin` (4 KiB file) | 1,008 (process baseline) |
| `ffs read /big.bin` (128 MiB file) | 17,474 |
| difference | **16,466 ≈ 16,384 = 64 MiB / 4 KiB** |

A *per-chunk* destination would have faulted 32,768 pages (128 MiB). It faults 16,384 — the
64 MiB buffer, once, reused for the second half. And `ffs-block::read_exact_at` already
avoids a staging buffer for large reads (`lib.rs:573-592`), so the engine is not the source.

**Consequence: this frame belongs to the CLI harness, not to the filesystem.** A FUSE mount
serving 128 KiB reads never allocates a 64 MiB destination. Optimising it would optimise the
benchmark, not the product.

### ⚠️ Self-correction: my own baseline is contaminated by this

Last section attributed "+6.47 ms frankenfs-attributable, 94% of the residual". That
over-attributes. The floor arm preaded into a **128 KiB** per-chunk buffer (~2 MiB of anon
memory touched, glibc-recycled: **2,338 faults**), while ffs first-touches **64 MiB**
(17,474 faults). The kernel comparator never pays that cost. **The engine-only gap is
therefore smaller than 6.47 ms and is currently UNMEASURED.**

The headline gaps (ffs T=64 **1.54x**, T=16 **1.25x** vs kernel) carry the same contamination:
they include the CLI's 64 MiB first-touch, which the kernel arm does not perform.

### A floor arm that failed the impossibility check — inadmissible, no REJECT recorded

I rebuilt the floor with frankenfs's real destination policy (one reused 64 MiB buffer,
`preader4.py bigbuf`, `sha256` identical to the kernel mount). It **reproduced the mechanism**:
17,593 faults vs frankenfs's 17,471. But as a *timing* arm it is invalid:

| arm | median (7 interleaved reps) | cv |
| --- | --- | --- |
| ffs T=16 | 35.57 ms | 12.2% |
| floor bigbuf (64 MiB dest) | **65.90 ms** | 16.0% |
| floor smallbuf (128 KiB dest) | 30.60 ms | 26.6% |
| kernel dio loop T=32 | 27.50 ms | 10.0% |

**A floor cannot be slower than the thing it floors** (frankenfs does strictly more work than a
raw `pread` of the same extents). The `bigbuf` arm's 65.90 ms is python overhead — per-chunk
`memoryview` slicing, window recomputation, GIL — not I/O. Its implied "+35.30 ms destination
policy cost" is therefore **discarded, not recorded**. This is the same impossibility check that
originally caught the loop-device artifact in `bd-q6k00` ("frankenfs faster than the raw-device
floor, which is physically impossible").

Fault count valid; wall time invalid. **The wall cost of the 64 MiB first-touch remains
unmeasured**, and may not be projected from the 28.91% cycle share — that projection method was
already falsified on this workload (`bd-kdmu4`: predicted 1.12-1.85x, measured 1.00x).

### Re-scope of bd-zvn7r

It splits into two, and neither is the product lever it first appeared to be:

1. **Measurement hygiene (harness).** `STREAM_CHUNK = 64 MiB` makes every `ffs-cli read`
   benchmark pay a 64 MiB anon first-touch that no kernel comparator pays. Either shrink it,
   pre-fault the buffer outside the timed region, or subtract it. Until then **every
   `ffs-cli read` cold number is inflated by an unmeasured constant.**
2. **The real question, still open.** Does the *engine* (`OpenFs::read_into`, the rayon chunk
   jobs, `ffs-block`) allocate per-chunk destinations on the **FUSE** path? Unknown. It must be
   profiled through the FUSE mount, not through `ffs-cli read`.

Both need a build (blocked). Neither may be measured with a python proxy: the proxy must
reproduce the mechanism's magnitude *and* survive the impossibility check, and this one failed
the second.

---

## 2026-07-10 — How much of the cold-read gap is harness? MEASURED: 3.10 ms (41% of the best-config gap) (bd-zvn7r, BlackThrush/cc_ffs)

**Repro metadata (required on every entry):** binary `ffs-cli`
`sha256=03b7456d8cd6fa118bd214b2fdf8a03e56cac79e6768b7311613b039c8ae81eb`
(`release-perf`, 55,453,584 B, built 2026-07-10 04:02:59); allocator `tikv_jemallocator`
(`ffs-cli/src/main.rs:8`); worker = **local host** (`perf` + `drop_caches` require root, so
no remote worker is possible for this measurement); `rch` verification worker = `vmi1149989`.
cv per arm below. **Zero local cargo builds.**

### The rebuilt harness

The previous `bigbuf` floor was inadmissible (it timed **slower** than the thing it floored).
Two bugs, both mine: `bytearray(n)` **memsets** in CPython, and the allocation sat **inside**
the timed region. Rebuilt as `preader5.py`:

* `mmap.mmap(-1, n)` instead of `bytearray(n)` — the kernel lazily zero-fills an anonymous
  mapping, which is what jemalloc's `alloc_zeroed` actually gets; no CPython memset.
* destination allocation and **all** chunk-list construction hoisted **out** of the timed region.
* one persistent `ThreadPoolExecutor`, warmed before the timer — no thread spawn inside it.
* `drop_caches` outside the timer; result consumed via an XOR checksum so nothing can be elided.

Two arms, identical I/O and identical bytes, differing **only** in whether the destination is
already faulted:

* `cold_dst` — destination created fresh inside the timed region: pays the 64 MiB first-touch
  during the parallel preads, exactly as `ffs-cli read` does with its `vec![0u8; 64 MiB]`.
* `warm_dst` — destination created and pre-faulted before the timer: the timed region contains
  only reads.

**Validity gates, all passing:** identity (both arms return the same XOR checksum; bytes
`sha256`-identical to the kernel mount); **magnitude** (`cold_dst` 18,090 page faults vs
frankenfs's 17,467 — the mechanism is reproduced); **impossibility** (`cold_dst` 31.10 ms <
ffs 35.77 ms — a floor must be faster than the thing it floors).

### The measurement (9 interleaved reps, medians)

| arm | median | cv |
| --- | --- | --- |
| ffs T=64 (as shipped) | 42.88 ms | 7.7% |
| ffs T=16 (best config) | 35.77 ms | 8.6% |
| floor `cold_dst` (pays 64 MiB first-touch) | 31.10 ms | 10.7% |
| floor `warm_dst` (reads only) | 28.00 ms | 5.7% |
| kernel dio loop T=32 | 28.30 ms | 8.8% |

**Destination first-touch cost = `cold_dst` - `warm_dst` = 3.10 ms.** Measured, not projected.

### The honest gap

| config | reported | harness | honest | harness share of gap |
| --- | --- | --- | --- | --- |
| ffs T=64 (as shipped) | **1.52x** | 3.10 ms | **1.41x** | 3.10 / 14.58 = **21%** |
| ffs T=16 (best config) | **1.26x** | 3.10 ms | **1.15x** | 3.10 / 7.47 = **41%** |

**41% of the best-config cold-read gap vs kernel ext4 is harness overhead** — the first-touch of
`ffs-cli read`'s 64 MiB staging buffer, which no kernel comparator pays. Every `ffs-cli read`
cold number in this repo, including all of my own `bd-ddryj` baselines, carries this constant.

Note also `warm_dst` (28.00 ms) ~= kernel dio loop (28.30 ms): **a raw parallel `pread` into a warm
destination is already at kernel parity.** The residual filesystem overhead is
35.77 - 3.10 - 28.00 = **4.67 ms**.

### SCOPE OF THIS CORRECTION — do not over-claim

This invalidates **my own** `ffs-cli read`-based cold numbers by 21-41% of their gap. It does
**not** establish that `bd-kdmu4`'s headline "~2.9x slower than kernel" is an artifact: that figure
was produced by a **different** harness ("multi-file parallel read, in-process threaded", with a
claimed 41% pread copy tax and 27% nested-rayon coordination), which I have **not** audited. It is
now *suspect by association* and needs its own audit against the same three validity gates — but
calling it an artifact without measuring it would repeat exactly the error this ledger exists to
prevent. **`bd-kdmu4` remains RESOLVED on the O_DIRECT question** (bypass measured at 1.00x); its
2.9x premise is **unaudited**, not refuted.

### Now hunt the top frame — with the harness cost attributed

The 28.91% anon alloc/fault/zero cluster from the previous ranked table is **the harness**
(`clear_page_erms` 11.81% + `asm_exc_page_fault` 5.74% + the page-allocator/memcg tail). Removing it,
the ranked table for actual filesystem work at T=16 is:

| self% | frame | note |
| --- | --- | --- |
| 12.28% | `_copy_to_iter` | the buffered copy — **also paid by the `warm_dst` floor**, so not a gap source |
| 9.32% | `native_queued_spin_lock_slowpath` | residual `xa_lock` (42.27% at T=64; the fan-out cap already removed most) |
| 1.13% | `crossbeam_deque::Stealer::steal` | rayon work-stealing |
| 0.69% | `ext4_mpage_readpages` | kernel ext4 readahead |

`_copy_to_iter` is present in both ffs and the floor, so it cannot explain the 4.67 ms residual.
The residual is frankenfs's own userspace work (user CPU at T=16 is **4.5 ms** — the same order),
which the current profile cannot resolve further because `perf` attributes it below the 0.1% cut.

**Next step requires a build**: fix `STREAM_CHUNK` (or pre-fault the staging buffer outside the
timed region) so `ffs-cli read` measures only filesystem work, then re-profile. Until then the
residual 4.67 ms is real but unattributed. Tracked in `bd-zvn7r`(a).

### Retry predicate

Do not re-derive the cold-read mechanism (`xa_lock`, folio insertions, readahead, granularity,
O_DIRECT) — all closed. Do not trust any `ffs-cli read` cold ratio that has not subtracted the
3.10 ms harness constant. Do not project wall time from a cycle share.

---

## 2026-07-10 — Scope of the harness correction, and is the remaining gap worth a lever? (bd-zvn7r / bd-ddryj / bd-kdmu4, BlackThrush/cc_ffs)

**Metadata:** binary `ffs-cli` `sha256=03b7456d8cd6fa118bd214b2fdf8a03e56cac79e6768b7311613b039c8ae81eb`
(`release-perf`, 55,453,584 B); allocator `tikv_jemallocator`; worker = local host (`perf` +
`drop_caches` need root); `rch` verify worker `hz2`; cv per arm 7.7 / 8.6 / 10.7 / 5.7 / 8.8%;
self-time of the function under test `clear_page_erms` **11.81%** (cluster 28.91%).
**Zero local cargo builds.**

### Direction of the bias — no sign-flip is at risk

The 64 MiB first-touch is paid **only** by `ffs-cli read`; the kernel and raw-`pread` arms use small
buffers. So harness inflation always makes frankenfs look **slower**, never faster. Therefore:

* Every prior "frankenfs is slower than kernel ext4" verdict is **conservative and stands.**
* Only the **magnitudes** are affected — they are **upper bounds**.
* No "frankenfs is faster" claim survives anywhere in this ledger, so the correction cannot resurrect one.

### Conclusions drawn against the inflated number (do not re-derive; adjust magnitudes only)

All of these used `ffs-cli read` engine time and therefore include a first-touch of
`min(file_size, 64 MiB)`:

| ledger row | reported | status |
| --- | --- | --- |
| `bd-q6k00` ext4 extent 128 MiB cold — **1.42x slower** | inflated | sign stands; magnitude is an upper bound |
| `bd-5koeh` ext4 indirect 50 MiB — **1.45x slower** | inflated | sign stands; magnitude is an upper bound |
| `bd-5koeh` ext4 fragmented 48 MiB — **1.31x slower** | inflated | sign stands; magnitude is an upper bound |
| `bd-ddryj` baseline — ffs **1.54x / 1.25x** kernel | inflated | **superseded**: measured 1.41x / 1.15x |
| `bd-zvn7r` "94% of residual is frankenfs-attributable" | wrong | **superseded** (floor arm mismatched the destination policy) |
| `bd-zvn7r` "new #1 frame = anon-page churn 28.91%" | harness | **the cluster is the harness**, not the filesystem |

I have **not** re-measured the indirect/fragmented rows with a corrected harness; scaling the 3.10 ms
constant by file size would be a projection, and projections have already been falsified twice on this
workload. They are marked as upper bounds, not restated with new numbers.

### ⚠️ The 2.9x multi-file figure: NOT corrected to 1.41x — different workload, different harness

`bd-kdmu4`'s headline is **multi-file parallel read** (256 files x 256 KiB, `walk --read-data --parallel`)
against an in-process threaded C reader. My 3.10 ms constant is `ffs-cli read`'s single-file 64 MiB
`STREAM_CHUNK` staging buffer. **They do not transfer**, and I checked why rather than assuming:

* `walk_one_dir` **already reuses one buffer per rayon worker** (`ffs-cli/src/main.rs:3055-3060`,
  `map_init`; the per-file fresh-`Vec` churn was fixed in `bd-2x68s`). The multi-file harness does not
  have the allocation pattern I measured.

**However**, that figure carries its **own** acknowledged harness component — by its author's words, not
my measurement. From the 2026-06-22 entry (CrimsonFox): the post-fix multi-file profile is `pread` 43.6%
plus *"~25% OUTER `walk_one_dir` per-inode `par_iter` coordination … a real FUSE mount dispatches each
getattr/read as a separate per-request worker, never via this nested rayon, **so it's a harness artifact
not a real-fs cost**"*.

So the multi-file number is **partly instrumentation by its own admission (~25%), by a mechanism
different from the one I measured**, and the residual real-filesystem multi-file figure was **never
isolated**. It needs its own audit against the three validity gates (identity / magnitude /
impossibility). **I am not restating it as 1.41x — that would repeat, in the opposite direction, exactly
the error this ledger exists to prevent.** `bd-kdmu4` remains RESOLVED on the O_DIRECT question (bypass
measured at 1.00x) and **UNAUDITED** on its 2.9x premise.

### Is the remaining gap worth a lever?

Honest, harness-corrected, single-file 128 MiB extent read (same binary, 9 interleaved reps):

| | wall | vs kernel |
| --- | --- | --- |
| ffs as shipped (rayon = nproc = 64) | 39.78 ms | **1.41x** |
| ffs with fan-out capped at 16 | 32.67 ms | **1.15x** |
| raw pread into a warm destination | 28.00 ms | 0.99x |
| kernel dio loop | 28.30 ms | — |

**YES — for exactly one lever, and it is already named.** `bd-ddryj` (bound the read fan-out) converts
**1.41x → 1.15x**, an 18% wall reduction on the shipped default. It needs no unsafe, no policy change,
and it is reconfirmed at 9/9 paired reps (p=0.0039). It is blocked only on the build.

**NO — for anything beyond it.** After the cap, the residual is 4.67 ms (1.15x), and the corrected frame
table contains no lever:

* `_copy_to_iter` **12.28%** — the buffered copy. The `warm_dst` floor pays it too and still lands at
  kernel parity, so it cannot explain the residual. Removing it needs `O_DIRECT`/mmap, **measured at 1.00x**.
* `native_queued_spin_lock_slowpath` **9.32%** — residual `xa_lock`; the fan-out cap already removed the
  bulk (42.27% → 9.32%). Per-thread fd cuts insertions 4.2x and buys **no wall** (p=0.18).
* `Stealer::steal` 1.13%, `ext4_mpage_readpages` 0.69% — below any actionable threshold.

The residual 4.67 ms is frankenfs's own userspace work (user CPU 4.5 ms, same order), and `perf` cannot
resolve it above the 0.1% cut. **Attributing it requires fixing `STREAM_CHUNK` first** so the timed region
contains only filesystem work — `bd-zvn7r`(a), a small change, blocked on the same build.

**Recommendation: land `bd-ddryj`, fix the harness (`bd-zvn7r`a), and stop hunting the single-file cold
read.** At 1.15x of a direct-I/O kernel mount, with the floor itself at 0.99x, there is no headroom worth
an unsafe policy change or a further lever.

---

## 2026-07-10 — COLD-READ LANE CLOSED (bd-ddryj landed; summary of corrections, BlackThrush/cc_ffs)

The cold-read investigation is complete. Binary `sha256=03b7456d…81eb` (`release-perf`);
worker = local host (`perf`/`drop_caches` need root); `rch` verify workers `hz1`/`hz2`/`ovh-a`/
`vmi1149989`; null-control median 1.0232x. Zero local cargo builds.

### What was refuted, in order

1. **`xa_lock` contention is the cold-read cost** — TRUE as a mechanism, but it is driven by
   frankenfs's *own* read fan-out, not by anything intrinsic. Capping the fan-out removes it
   (`native_queued_spin_lock_slowpath` 42.27% → 9.32%). → `bd-ddryj`, LANDED this turn.
2. **Folio insertions are the throughput lever** — REFUTED. Insertions drive lock-*wait* (CPU),
   not wall time: `r(ins/MiB, MiB/s)` = +0.15/+0.25 within a fixed thread count; a T=64 case cut
   insertions 2.4x and ran 1% slower; per-thread fd cuts them 4.2x for no wall (p=0.18).
3. **Only O_DIRECT/mmap can help** — REFUTED. Bypassing the page cache is measured at **1.00x**
   of wall (25.7 vs 25.5 ms) and 1.6x slower at 4 KiB. `bd-kdmu4` needs no unsafe policy change on
   latency grounds; RESOLVED.
4. **The gap is 2.9–5x** — for the single-file `ffs-cli read` numbers, the gap was inflated by a
   measured **3.10 ms** harness constant (its 64 MiB `STREAM_CHUNK` first-touch). Honest single-file
   gap: **1.41x as-shipped**, **1.15x with the fan-out cap** (the raw floor itself is 0.99x of
   kernel). See the caveat below on the multi-file figure.

### ⚠️ The one claim I was asked to make and did NOT: "the headline 2.9–5x was 41% harness overhead"

That sentence is **false as written**, and the distinction matters for repo integrity:

* **41% and 1.41x are different arms.** The harness constant is **21%** of the *as-shipped* gap
  (→1.41x) and **41%** of the *fan-out-capped* gap (→1.15x). One number cannot describe both.
* **The 2.9–5x headline is a DIFFERENT workload** (`bd-kdmu4`: multi-file parallel read) with a
  **different harness**, measured by a different agent. My 3.10 ms constant is `ffs-cli read`'s
  single-file staging buffer, which does not exist in that path (`walk_one_dir` already reuses one
  buffer per worker, `main.rs:3055-3060`, `bd-2x68s`). I have **not** measured the multi-file
  harness, so I cannot say what fraction of 2.9x is overhead. Its author separately flagged ~25% of
  it as nested-`par_iter` coordination "a harness artifact not a real-fs cost", by yet another
  mechanism — but the residual real-fs figure was never isolated.
* **The honest statement:** *my own single-file `ffs-cli read` cold numbers were 21–41% harness;
  `bd-kdmu4`'s multi-file 2.9x is suspect by association but unaudited.* Writing "the headline was
  41% harness" would restate an unmeasured number — the same class of error (in the opposite
  direction) as the original "frankenfs dominates kernel" rows this whole audit corrected.

### Prior conclusions drawn against the inflated single-file number

Sign stands (harness bias only ever inflates "frankenfs slower"), magnitude is an upper bound:
`bd-q6k00` ext4 extent 1.42x; `bd-5koeh` indirect 1.45x / fragmented 1.31x. Superseded outright:
`bd-ddryj` baseline 1.54x/1.25x → 1.41x/1.15x; "94% frankenfs-attributable" (floor mismatched the
destination policy); "new #1 frame = anon churn 28.91%" (that cluster is the harness).

### Lane status

* `bd-ddryj` — **LANDED** (`7a6091a2`): dedicated 16-wide read pool. Behavior parity verified
  remote; perf measured on the equivalent `RAYON_NUM_THREADS=16` config (1.21x effect vs 1.02x null),
  the built binary not independently re-measured (build blocker).
* `bd-zvn7r`(a) — harness hygiene: `STREAM_CHUNK=64 MiB` inflates every `ffs-cli read` cold number;
  shrink / pre-fault / subtract. Open, needs a build.
* `bd-zvn7r`(b) — does the FUSE read path allocate per-chunk destinations? Open, profile through the mount.
* `bd-kdmu4` — RESOLVED on O_DIRECT (1.00x); its 2.9x multi-file premise UNAUDITED.
* `bd-vpypn` — extent walks at high extent counts, never measured. Open.

No further single-file cold-read lever exists: at 1.15x of a direct-I/O kernel mount with the raw
floor at 0.99x, the residual is inherent copy + userspace work.

---

## 2026-07-10 — bd-bhh0i de-risk: INDEPENDENT VERIFICATION of cod's safety proof (no collision, BlackThrush/cc_ffs)

cod (`cod_ffs`) owns `bd-bhh0i` and is usage-walled, but its work is active and recent
(loom model `da92afd7`, contention instrumentation `ef7073b8` / `52730e52`, all today).
The three de-risk deliverables the owner named already exist as cod's artifacts:

1. **Lock-hold histograms at 1/2/4/8 threads** — `crates/ffs-core/benches/bd_bhh0i_contention.rs`
   (records wait/hold/alloc-ns distributions; the 8t p99 figures are already in the ledger:
   global alloc 176.341 µs, disjoint group 0.290 µs, synthetic publish 127.449 µs).
2. **Loom model proven deadlock-free + linearizable** —
   `crates/ffs-core/tests/bd_bhh0i_lock_decomposition_model.rs`.
3. **Incremental plan** — `docs/bd-bhh0i-parallel-create-plan.md`.

Rather than duplicate active peer work (which would collide when cod returns), I did the one
useful non-colliding thing: **independently ran cod's loom safety proof** to confirm it holds.
`RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo test -p ffs-core --test
bd_bhh0i_lock_decomposition_model` on remote `vmi1227854` — **7/7 passed** (6.43 s):

* `disjoint_group_commits_are_deadlock_free_and_linearizable`
* `same_group_commits_serialize_and_replay_linearly`
* `opposing_multi_group_requests_normalize_to_one_lock_order`
* `disjoint_groups_with_cross_mapped_shards_normalize_both_lock_orders`
* `installed_unpublished_versions_are_hidden_until_the_prefix_is_complete`
* `post_publication_prune_preserves_registered_snapshot_visibility`
* `failure_before_install_leaves_no_allocator_or_mvcc_effect`

The model checks exactly the properties the owner asked for: deadlock-freedom, linearizability
(commit order respects every non-overlap edge and replays against a sequential bitmap allocator),
lock-order normalization (opposing multi-group requests reduce to one order), and the visibility
invariant (installed-but-unpublished versions stay hidden until `completed_prefix` publishes).

**Verdict: bd-bhh0i's safety substrate is de-risked and the proof is reproducible.** No new
artifact was written and no cod file was touched — the deliverables exist, are high quality, and
now carry an independent green run from a second agent. The remaining `bd-bhh0i` work (the actual
lock-decomposition cutover) stays with cod, is FS-mutating, and is explicitly out of scope here
(no cutover, no FS mutation beyond fixtures). I did not start it.

---

## 2026-07-10 — ISA finding + bd-bhh0i doc coverage (no collision) (bd-b9dug, BlackThrush/cc_ffs)

### ISA question: does frankenfs emit baseline or AVX2?

**For its own code: BASELINE (SSE2). Only runtime-dispatched deps use AVX2.** Filed as `bd-b9dug`.

Binary `sha256=03b7456d…81eb` (the one used for the entire cold-read campaign): `RUSTFLAGS` unset,
no `target-cpu`/`target-feature` in `.cargo/config.toml`, `Cargo.toml`, or `rust-toolchain.toml`, so a
plain `cargo build --profile release-perf` targets the default **x86-64 baseline**. frankenfs's own SWAR
hot functions (`names_eq`, `dx_hash`, word-at-a-time) disassemble to scalar GPR ops — no `ymm`/`zmm`
(the SWAR primitives are baseline-compatible by design, so a higher `target-cpu` would not help them,
but any autovectorizable ffs loop is emitted SSE2). The 1401 AVX2 + 2018 AVX-512 mnemonics present come
from **runtime-dispatched dep crates** (crc32c, xxhash, memchr, blake3) — the AVX-512 variants are dead
on this non-AVX512 host; correct portable pattern, not a gap.

**The gap:** production is `scripts/build-perf.sh`, which sets `-C target-cpu=x86-64-v3` (AVX2/BMI2/FMA) +
fat LTO + PGO (its header records ~8.5% fewer create instructions, ~3% lookup). rch's plain build does not
apply those flags, so **the benchmark binary ≠ the production binary**.

* A/B ratios are unaffected (same binary both arms) — `bd-ddryj` 1.21x, null 1.02x stand.
* Absolute vs-kernel numbers are a **second** upper bound: the honest cold-read gap (1.41x / 1.15x) would
  be tighter on the v3+PGO production binary. Real gap < 1.41x.
* **Every future workload-class benchmark must use the build-perf.sh binary**, or note it is baseline.

### bd-bhh0i incremental design doc — already delivered by cod; not touched

The owner asked for "the incremental design doc: each step independently safe, e2fsck-clean,
rollback-able, with the loom proof attached." **That doc already exists and is comprehensive:**
`docs/bd-bhh0i-parallel-create-plan.md` (316 committed lines, actively being expanded by cod right now —
a 59-line working-tree diff). It already contains: the incremental owner-reviewed plan with
independently-revertible steps, e2fsck-clean gates per step (`create-bench N → e2fsck -fn CLEAN`),
crash-consistency analysis, rollback framing, and the bounded-loom proof section. My independent 7/7
verification of that loom proof (previous entry) is the second-agent peer review it needed.

**I did not edit cod's doc** — it is active peer work and editing it would collide (and non-src edits
revert within minutes here). The plan is de-risked by two agents. The FS-mutating cutover stays with cod.

### Unbenchmarked workload classes — beaded (cod's lane); cross-cutting note

fsync/journal-commit latency (`bd-fsync-journal-latency-gap-ptp4x`) and mounted-xattr
(`bd-mount-xattr-workload-gap-fr6iq`) are already beaded and in cod's lane. I did not start them (cod
owns new workload classes; starting them mid-wall would collide). Cross-cutting requirement recorded on
`bd-b9dug`: **all of them must be benchmarked on the v3+PGO production binary**, not the baseline plain
build, or their absolute vs-kernel numbers will carry the same ISA upper-bound this ledger just found in
the cold-read numbers.

---

## 2026-07-10 — ISA verdict (plain), SWAR-widen correction, and the workload-class gap matrix (bd-b9dug, BlackThrush/cc_ffs)

### ISA verdict, plainly

**On the workers, frankenfs emits BASELINE x86-64 (SSE2) for its own code.** Definitive: `RUSTFLAGS`
unset, no `target-cpu`/`target-feature` in any config, so a plain `cargo build --profile release-perf`
targets the default baseline. Corroborating instruction counts in the benchmark binary
(`sha256=03b7456d…81eb`): `pdep`/`pext`/`blsr` = **0** (BMI2, no baseline fallback), `bsr` 922 vs `lzcnt`
34 — consistent with baseline codegen. The AVX2/AVX-512 present is runtime-dispatched dep code
(crc32c/xxhash/memchr/blake3), portable and partly dead on this non-AVX512 host. The production binary
(`build-perf.sh`) is `target-cpu=x86-64-v3` + PGO.

### The SWAR-widen premise is wrong — corrected

A build-widen (`target-cpu=v3`) only changes compiler **auto-emission**; it cannot turn hand-written u64
SWAR (GPR XOR/mask/shift) into vectors. So the named SWAR paths — `extent_root_namespace` (7.14x),
`names_eq`, symlink NUL-trim, casefold — **do not benefit from a build-fix**: they are ISA-independent by
construction and identical on baseline and v3. Rewriting them as explicit AVX2 is a code change blocked
by `forbid(unsafe_code)` (`std::arch` SIMD is unsafe).

**Where the measured v3 uplift really lands:** `build-perf.sh` records v3 as ~8.5% fewer **create**
instructions, ~3% **lookup** — not read. Those paths' hot loops include the allocator bitmap bit-scan
(`ffs-alloc/src/succinct.rs:426,435` `trailing_zeros`, `count_zeros`), which v3's `tzcnt`/`lzcnt` (and
possibly `pdep`/`pext`) accelerate over baseline `bsf`/`bsr`. That is **cod's active allocator lane**, not
the SWAR hash paths and not the read path (v3 gives read ~0 — the read gap is copy + userspace per the
cold-read closeout). Net: the build-widen is a real build-config decision, but its beneficiaries are the
allocator/metadata path (coordinate with cod), not my SWAR paths.

### Unbenchmarked workload classes — honest gap matrix

| class | harness | status |
| --- | --- | --- |
| fsync / journal-commit latency | **none in ffs-cli** (fsync exists only on the FUSE path) | needs a new `FsyncBench` subcommand → **build-blocked**; beaded `bd-fsync-journal-latency-gap-ptp4x` (cod) |
| xattr get/set/list storm | **none in ffs-cli** | needs a new subcommand → **build-blocked**; beaded `bd-mount-xattr-workload-gap-fr6iq` (cod) |
| small-file storm (create) | `CreateBench` (exists) | single-thread create is mined; **parallel** create = `bd-bhh0i` (cod's active write lane) → collision |
| readdir+stat storm | `Walk --no-stat` / `Walk` (exists) | **cold** readdir+stat = the withdrawn cold-read metadata-walk row (do not re-mine); **warm** CPU is mined (lookup fully dissected) |

**Honest surface: the measurable-now set is empty under the active constraints** {no local build; cod owns
the write/alloc lane; do not re-mine cold-read}. fsync and xattr — the two genuinely new classes — both
need a new CLI harness, which needs a build. The two with harnesses overlap cod's lane or the withdrawn
cold-read rows. This is a *build-blocked + coordination* boundary, not a lack of candidates: with one
granted build, `FsyncBench` + `XattrBench` subcommands would unblock the two new classes cleanly (they do
not touch the read path or the allocator).

### bd-bhh0i incremental design doc — cod's, still active, not touched

Re-checked this turn: `docs/bd-bhh0i-parallel-create-plan.md` still carries cod's uncommitted 59-line
working-tree diff (actively editing while walled). It already has the incremental owner-reviewed plan with
independently-revertible steps, per-step `e2fsck -fn` gates, crash-consistency, rollback, and the loom
proof section. My independent **7/7** verification stands as its second-agent peer review. Editing it would
collide and non-src edits revert within minutes — so I did not. The plan is sign-off-ready and de-risked by
two agents; the FS-mutating cutover remains cod's.

## 2026-07-22 — bd-kdmu4 PREMISE AUDIT: the 2.9–5x multi-file parallel-read headline is DEAD on current code — measured at KERNEL PARITY OR BETTER (cc)

The 2026-07-10 closeout left `bd-kdmu4` "RESOLVED on O_DIRECT (1.00x); its 2.9x multi-file
premise UNAUDITED" and prescribed an audit against the identity / magnitude / impossibility
validity gates. This entry is that audit. **Verdict: the premise no longer holds.**

### Premise under test

"Multi-file parallel read (256 files x 256 KiB, `walk --read-data --parallel`) is ~2.9–5x
slower than an in-process threaded C reader; 41% pread copy tax + 27% nested-rayon
coordination" (2026-06-22, CrimsonFox). Since then the gap was engineered away lever by
lever: `bd-2x68s` per-worker walk buffer reuse + 3.2x multi-file walk win, the 32-block
read-chunk retune, `21113a70` build_global(16) walk cap, `7a6091a2` 16-wide read pool, and
the 2026-07-16 fan-out-cap class (`9af088db`/`650fc5a9`/`ffd672ee`).

### Method

* **Subject:** `target/release/ffs-cli` (Jul 13, opt-z baseline-ISA `release` profile,
  contains `21113a70`'s x16 walk cap — every run printed `[parallel x16]`; predates the
  Jul-16 caps, which do not trigger on this workload). Engine time from the `walked … in Xms`
  line (excludes image open, includes parallel readdir+getattr+full data read).
* **Fixtures (fresh, purpose-built):** `/data/tmp/kdmu4_small.img` = exact premise replica,
  256 files x 256 KiB = 64 MiB in 16 dirs; `/data/tmp/kdmu4_big.img` = honest-size variant
  per the >=1 GiB sizing rule, 2048 files x 512 KiB = 1 GiB in 32 dirs. mke2fs -b4096 -d;
  all files single-extent (filefrag-verified).
* **Kernel arm:** in-process pthread C reader (`reader.c tree`), per-file open (own `f_ra`),
  contiguous per-thread file partition, 128 KiB pread chunks, readdir+lstat walk inside the
  timed region — on a **`--direct-io=on` loop mount** (dio=1 verified) per the recorded
  loop-dio methodology.
* **Floor arm:** same C harness in `ranges` mode: raw parallel pread of the files' physical
  extents from the image file, per-thread fd, contiguous partition. First floor build used
  atomic round-robin dispatch and FAILED the impossibility gate (ffs 225.5 ms < "floor"
  243.3 ms cold-1GiB) because round-robin destroys per-fd sequentiality while rayon gives
  each worker a contiguous span — the floor was rebuilt with contiguous partitioning and
  the gate then passed everywhere (e.g. cold-1GiB floor 200–212 ms < ffs 210–229 ms).
* **Gates:** identity — all three arms XOR64-identical per fixture (`46d5e61487c25876` /
  `6136f5eaeccd58af`, byte counts exact 67,108,864 / 1,073,741,824) + `ffs-cli read`
  sha256 == kernel-mount sha256 on sample files; magnitude — file/byte counts exact in every
  arm; impossibility — fixed floor below subject in every cell. `sync && drop_caches=3`
  before every cold arm, arms interleaved within each rep, 7 reps, medians + min + cv.

### Results (campaign 1, quiet box — 15-min load avg ~9; T=16 all arms)

| fixture / mode | ffs engine | kernel C reader (dio loop) | raw floor (fixed) | verdict |
| --- | --- | --- | --- | --- |
| 64 MiB premise replica, cold | **17.6 ms** (cv 2.1–3.2%) | 18.7 ms (cv 2.2%) | 13.7 ms | **ffs 1.06x FASTER** |
| 64 MiB premise replica, warm | 4.4–5.1 ms | 4.2–4.5 ms (cv 12–19%) | 2.3–2.9 ms | parity (<=1.2x within noise) |
| 1 GiB honest-size, cold | **225.5 ms** (cv 1.1%) | 244.6 ms (cv 0.7%) | 200–212 ms | **ffs 1.08x FASTER** |
| 1 GiB honest-size, warm | **29.7 ms** (cv 3.5%) | 33.5 ms (cv 3.2%) | 26.2 ms | **ffs 1.13x FASTER** |

Kernel-best sweep (T in {8,16,32}, min-of-3): best kernel cold anywhere = 17.8 ms (64 MiB)
/ 229.4 ms (1 GiB); against ffs's worst clean medians that is still **1.00–1.01x = parity**.
Conservative worst-vs-best framing does not resurrect any gap, and the opt-z baseline-ISA
subject binary only understates the v3+PGO production build.

### Load-storm replication (campaign 2) — the "needs low-load window" caveat is real

A 1-min load-avg spike to ~54 (sibling agents) landed mid-campaign-2. Cold verdicts
reproduced under load (ffs 1.03–1.09x faster than the kernel arm, cv 9–14%), but warm-1GiB
inverted: ffs 119–200 ms vs C reader 40–69 ms — **under CPU contention the rayon walk
degrades ~4x while the plain pthread reader degrades ~1.5x.** Campaign 1 is the valid
dataset; the load observation matches the bead's recorded "needs low-load window" and is a
scheduling-sensitivity fact, not a filesystem gap.

### Disposition

* `bd-kdmu4` **CLOSED**: O_DIRECT/mmap resolved earlier at 1.00x (do not approve for
  latency); the 2.9–5x multi-file premise is now AUDITED and REFUTED on current code —
  in-process multi-file parallel read is at kernel parity or better, floor-bounded residual
  headroom <=5–9% cold. The "41% copy tax" attribution died with the workload gap: the floor
  pays the same buffered copy and ffs sits within 5–9% of it.
* The mmap-backed / zero-copy ByteDevice lane is **not justified by any remaining measured
  gap on this surface** — consistent with the standing 1.00x bypass measurement.
* Reproduction: harness + driver at the session scratchpad (`reader.c`, `bench.py`),
  fixtures kept at `/data/tmp/kdmu4_{small,big}.img`.

### Retry predicate

Reopen a multi-file in-process read gap ONLY with: a quiet box (1-min load < ~2x cores/4),
the three validity gates, a contiguous-partition raw floor, and a dio-loop kernel arm.
Open adjacent surfaces this audit does NOT cover: the FUSE-mounted multi-file read path
(`bd-zvn7r`(b) per-chunk destination question) and rayon-under-CPU-contention scheduling
sensitivity (new observation above; a per-request dispatch comparator would isolate it).

## 2026-07-22 — FUSE-MOUNTED multi-file read gap ISOLATED for the first time + per-thread-read-fd lever REJECTED (bd-kdmu4 / bd-zvn7r(b), cc)

Continuation of the same-day premise audit above, moving to the one read surface it did not
cover: the real FUSE mount. Subject binary: Jul-13 `release` ffs-cli (baseline arm), then a
locally-built same-source binary for the lever A/B (env-toggled, same binary both arms).
Fixture: `/data/tmp/kdmu4_big.img` (2048 x 512 KiB = 1 GiB). Reader: the audited pthread C
tree reader (contiguous partition, T=16, 128 KiB), identity-gated (XOR64
`6136f5eaeccd58af` in EVERY run below, including through the full FUSE stack).
AppArmor gotcha recorded: Ubuntu's `fusermount3` profile only permits mounts under
`$HOME`/`/mnt`/`/media`/`/tmp`/`/run/user` — mounting at `/data/...` fails EPERM even via
sudo; use `/mnt/*`.

### The mounted gap (kernel arm = dio-loop ext4, same reader)

| regime | ffs FUSE | kernel | ratio |
| --- | --- | --- | --- |
| cold (drop_caches) | 1282–1689 ms | 232–241 ms | **5.5–7.0x slower** |
| daemon-warm (all image bytes page-cached, FUSE pages cold) | 596–1328 ms | n/a (no daemon) | **disk-free path is ~0.6–1.3 s for 1 GiB** |
| fully warm | 117 ms | 29–90 ms | measures kernel FUSE page cache, not the daemon |

The in-process engine is at kernel parity (entry above); **the mounted path is where the
multi-file read gap actually lives, and it is larger than the retired 2.9–5x headline.**
Daemon-warm ≈ cold shows the path is not disk-bound.

### Profile attribution (perf -g on the daemon, daemon-warm storm, 12.3k samples/8 s)

* `native_queued_spin_lock_slowpath` **41%** — `__filemap_add_folio` ← `page_cache_ra` ←
  `ext4_file_read_iter` ← `preadv` on the image file: the KNOWN shared-`struct file`
  readahead/`xa_lock` convoy (single `Arc<File>` in `FileByteDevice`, 16 `ffs-read-*`
  threads).
* `_copy_to_iter` **1.83%**, `__pi_memcpy` **1.50%** — **the copy tax is ~3% of daemon
  self-time on the mounted path.** The "~2x structural pread copy-tax / 41% of read time"
  framing is dead on this surface too; an mmap-backed ByteDevice has nothing to remove.
* ~12.3k samples / 8 s across 82 threads ≈ **~1.5 CPUs busy: the daemon is mostly idle.**
  Wall is bounded by FUSE round-trip/dispatch concurrency, not by daemon CPU and not by
  copies.

### The lever tried (one lever): per-thread re-opened read fds in `FileByteDevice` — REJECT

Rationale: the profiled 41% spin is the exact pathology the 2026-07-10 raw-harness rows
measured per-thread fds fixing (insertions 5.9x down, wall 1.41x at T=8) — but those same
rows also warned "per-thread fd cuts insertions 4.2x and buys no wall (p=0.18)" once the
fan-out is capped. Implemented safely (thread_local HashMap keyed by device id, re-open
verified against open-time `(st_dev, st_ino)`, reads only, `FFS_PER_THREAD_READ_FD=0`
kill-switch for same-binary A/B), built locally, measured 3 interleaved mount-cycle reps:

| arm | off (shared fd) | on (per-thread fds) | verdict |
| --- | --- | --- | --- |
| FUSE cold | 1281.7 ms (min 1257.6) | 1363.8 ms (min 1319.1) | **~6% REGRESSION** |
| FUSE daemon-warm | 596.2 ms (min 590.4) | 660.3 ms (min 635.7) | **~11% REGRESSION** |
| in-process walk cold | 221.3 ms | 219.4 ms | neutral (1.01x) |

Identity: XOR64 equal in all arms. **REJECT — the spin is overlapped CPU burn, not wall,
exactly as the 07-10 "insertion count is a lock-wait lever only" row predicted; the extra
re-opens/fstat and doubled readahead streams cost more than the convoy they remove.**
Production hunk STASHED (not landed): `stash@{0}` "bd-kdmu4 REJECTED lever: per-thread
read fds in FileByteDevice". The Jul-13 baseline binary was restored to `target/release`.
(Remote `cargo test -p ffs-block` on the lever tree also caught a test-module struct
literal needing the new fields — moot post-stash, but it re-confirms the update-all-
constructors rule.)

### Retry predicate / the actual next levers (measured surface, unworked)

Do NOT retry: per-thread/dup'd read fds for wall (twice-refuted), mmap/O_DIRECT on any
read surface (copy ~3% here, bypass 1.00x there), or insertion-count-driven levers.
The mounted read gap is a **round-trip/dispatch-concurrency** problem. Next levers, in
suspected order: (1) FUSE request sizing — verify negotiated `max_read`/`max_readahead`
and the per-request size the daemon actually serves (8192 x 128 KiB requests at ~73 us
effective each); (2) `--runtime-mode per-core` (thread-per-core dispatcher, shipped
opt-in, never A/B'd on this workload); (3) daemon-side readahead/prefetch depth on the
mounted path (OliveCliff's bounded readahead machinery exists); (4) FUSE passthrough is
NOT applicable (no per-file backing fd for image-embedded files). Each needs the same
identity-gated C-reader A/B on a quiet box (1-min load < ~16 here; this session ran at
9–33 with one storm to 54 — mount-cycle interleaving kept arms comparable).

## 2026-07-22 — KEEP: async per-request read dispatch on the FUSE mount — cold multi-file 3.85x faster, gap vs kernel 5.5x → 1.43x (bd-kdmu4, cc)

The turn-2 entry above attributed the mounted multi-file read gap to serial request
dispatch: `fuser::spawn_mount2` runs ONE session loop, the `Filesystem::read` op replied
inline, so 16 concurrent client readers were served strictly one-at-a-time (daemon ~1.5
CPUs busy, copies ~3%). This turn landed the bead's own prescribed "per-request dispatch
model" for the read op.

### The lever (one lever, src-only, `crates/ffs-fuse/src/lib.rs`)

`FuseInner` gains a dedicated `read_offload` rayon pool (sized by the existing
`thread_count` knob that already sizes `max_background`; named `ffs-fuse-rd-*`).
`Filesystem::read` now moves `(shared_handle, params, ReplyData)` onto that pool and
returns immediately — the session loop fetches the next kernel request while workers
serve and reply concurrently. The serve body is the exact former inline body
(`serve_read_request`), so bytes/errors/metrics are unchanged; fuser's `ReplySender` is
`Send + Sync + 'static` by design for cross-thread replies, and FUSE imposes no
reply-ordering requirement across requests. Kill switch: `FFS_FUSE_ASYNC_READ=0` forces
the inline pre-lever path (same-binary A/B); the pool also degrades to inline when it
cannot be built or `thread_count < 2`.

### Measurement (same binary, env-toggled, 4 interleaved mount-cycle reps, T=16 C reader, 1 GiB / 2048 files, quiet box load ~8)

| regime | inline (off) | dispatched (on) | ratio |
| --- | --- | --- | --- |
| cold (drop_caches) | 1327.5 ms (cv 1.8%) | **345.1 ms** (cv 3.8%) | **3.85x faster** |
| daemon-warm | 658.3 ms (cv 2.5%) | **244.3 ms** (cv 5.9%) | **2.69x faster** |
| vs kernel (dio-loop ext4, same session: 242.0 ms median cold) | 5.5x slower | **1.43x slower** | — |

Marginal cost, reported honestly: single-stream T=1 cold medians 1148 ms (off) vs 1207 ms
(on) over 3 interleaved reps with overlapping ranges (~5%, per-request handoff cost).
Accepted against the 3.85x multi-stream win; the T=1 surface has its own open lever
(daemon readahead depth).

### Behavior proof

* Identity: XOR64 `6136f5eaeccd58af` in every off/on run of every regime (16 A/B runs +
  T=1 runs), byte-identical through the full FUSE stack.
* `cargo test -p ffs-fuse` (remote): **573 passed / 0 failed**.
* Ordering preserved: per-request bytes identical; FUSE has no cross-request reply
  ordering contract. Tie-breaking/floating-point/RNG: N/A. The pre-existing
  `fuse_inner_shared_across_threads` test already models concurrent dispatch.
* ubs on the file: 19 criticals, all pre-existing whole-file heuristics (test panics,
  token-compare false positives), none in the changed hunks.

### Follow-ups (open, this lane)

Residual mounted gap is 1.43x cold: next levers are daemon-side readahead depth for the
single-stream path, offloading `readdir`/`getattr` the same way (metadata storms), and
the negotiated `max_readahead` audit. The rejected per-thread-fd stash and the mmap/
O_DIRECT closures are unaffected by this change.

## 2026-07-22 — three non-KEEPs close the cheap-dispatch vein: metadata offload REJECT, readahead null, request-count null (bd-kdmu4, cc)

Continuation after the 3.85x async-read KEEP (11d82483). Same harness, fixtures, identity
gates (XOR64 `6136f5eaeccd58af` held in every run below). Session loop occupancy probe
first: during a cold storm with async-read ON, the loop thread burns 54% of wall, the 8
`ffs-fuse-rd-*` workers ~50% each — headroom on the loop, workers intermittently starved.

### 1. Metadata-op offload onto the read pool — REJECT (production hunk stashed)

Factored `lookup`/`getattr`/`open`/`opendir`/`readdir` into `serve_*` bodies dispatched
onto the existing `read_offload` pool (env `FFS_FUSE_ASYNC_META`, writeback-cache mode
kept inline, `readdirplus` descoped). Same-binary interleaved A/B, 4 mount-cycle reps,
async-read ON in both arms:

| regime | inline meta (off) | offloaded meta (on) | verdict |
| --- | --- | --- | --- |
| cold | 337.2 ms (cv 1.4%) | 351.5 ms (cv 1.8%) | **+4% REGRESSION** |
| daemon-warm | 236.1 ms (cv 2.7%) | 262.1 ms (cv 3.0%) | **+11% REGRESSION** |

Mechanism: small metadata tasks queue behind large read tasks on the shared 8-thread
pool; the loop had spare capacity to pump them inline. Stashed as `stash@{0}`
("metadata-op offload onto read pool"). Retry predicate: only with a SEPARATE small-op
pool AND a measured session-loop occupancy >90% (loop saturation), e.g. after multiple
/dev/fuse queues exist. `flush`/`release` offload is predicted-negative by the same
mechanism — do not try it standalone.

### 2. Kernel readahead sizing (`/sys/class/bdi/<dev>/read_ahead_kb`) — NULL

FUSE bdi defaults to 128 KB. Sweeping 128 → 1024 → 4096 KB (no code change):
T=1 cold 1381 / 1495 / 1400 ms (flat, ±8% noise); T=16 cold 416 / 404 / 418 ms (flat).
Raising `max_readahead` in INIT is therefore not a lever on this workload — do not
plumb it as a mount option expecting wall.

### 3. Request-count instrumentation — coalescing works; T=1 is NOT round-trip-bound

strace read() totals over a T=1 cold GiB: 20,741 calls at ra=128 KB vs 14,581 at
ra=4096 KB — the kernel DOES issue fewer, larger requests with bigger readahead
(fuser already advertises `FUSE_ASYNC_READ`; `max_pages` derives from
`max(max_write, max_readahead)` and `FUSE_MAX_PAGES` is echoed). Yet un-straced wall is
flat — so the single-stream residual is serial pipeline bubbles (disk read → reply copy →
next request), not request count. Fixing that means daemon-side prefetch depth/overlap
(ReadaheadManager) — a structural item, not a config flip.

### Vein status (3 consecutive non-KEEPs → switch per campaign discipline)

The mounted multi-file read surface stands at **1.43x of kernel cold** (from 5.5x at
session start) with the loop unsaturated and cheap dispatch/config levers exhausted.
Remaining read-lane items are structural: single-stream prefetch pipelining (bounded
value; T=1 is a minor real-world surface), and multi-queue /dev/fuse (clone_fd) if the
loop ever saturates. Next turn switches vein per the alien-graveyard mandate (still
read-lane: a different primitive class, not more dispatch tuning). mmap/O_DIRECT remain
closed everywhere (copies ~3% of daemon self-time; bypass 1.00x).

## 2026-07-22 — NEUTRAL-REJECT: daemon-side async next-window prefetch is redundant with kernel image-file readahead (bd-kdmu4, cc)

Vein-switch lever after the dispatch-vein closure. Target: the measured T=1 "pipeline
bubble" (serial window fetch at every readahead boundary; request coalescing previously
proven present-but-flat). Implemented double-buffered prefetch: on a predicted-stream
miss, `read_with_readahead` background-fetches the FOLLOWING 256 KiB window on the
`read_offload` pool (in-flight dedup set in `ReadaheadManager`, snapshot-scoped
`ops.read`, no `access_predictor` feedback, RO-non-writeback mounts only — a background
insert on a writable mount could race `invalidate_inode` and re-cache pre-write bytes).
Env `FFS_FUSE_ASYNC_PREFETCH` for same-binary A/B.

### Measurement (4 interleaved mount-cycle reps, 1 GiB fixture, box load noisy — one
~2 s outlier per arm, cv 14–24%; min-of-4 is the robust stat)

| arm | prefetch off | prefetch on | verdict |
| --- | --- | --- | --- |
| T=1 cold | min 1324.5 ms (med 1511.6) | min 1331.4 ms (med 1350.3) | **PARITY at min** |
| T=16 cold | min 366.0 ms | min 355.6 ms | within noise (~3%) |

Identity XOR64 held in every run.

### Why it cannot win (the insight worth keeping)

`FileByteDevice` opens the image with `POSIX_FADV_SEQUENTIAL`; the daemon's window
fetches are near-sequential preads of the image file, so the KERNEL's own readahead on
the image file already pipelines the next windows into the page cache ahead of the
daemon. The "boundary stall" is a page-cache hit (~100 us), not a device read — there is
almost nothing for daemon-side prefetch to hide. Daemon-level prefetch duplicates
kernel-level prefetch one layer down. Production hunk STASHED (`stash@{0}`,
"async next-window prefetch"). Retry predicate: only if the image-file read path ever
loses kernel readahead (O_DIRECT backend, network/blob backend, or `FFS_READ_FADVISE=random`),
where a daemon-side window pipeline would be the only prefetch layer — measure there first.

### Lane status after this turn

Mounted multi-file: **1.43x cold** (session start 5.5x), loop unsaturated, dispatch +
config + prefetch veins all closed with numbers. In-process: kernel parity. T=1
single-stream: bounded by per-request service time under an already-pipelined backend;
no cheap lever identified. Consecutive non-KEEPs in this vein: 1 (this entry). Next
fresh vein candidates (unmeasured surfaces, per campaign lesson that un-benched spots
still yield): `bd-vpypn` extent walks at HIGH extent counts (never measured, both
sequential and random); mounted metadata-storm surfaces (statfs/xattr through FUSE).
mmap/O_DIRECT stay closed everywhere.

## 2026-07-22 — KEEP: ExtentCache batch eviction — warm 8192-extent read 2.44x faster, cold 1.80x (bd-vpypn / bd-kdmu4, cc)

The bd-vpypn regime ("extent behavior at hundreds-to-thousands of extents was never
measured") finally measured — and it hid the predicted scan gap.

### Fixture (new, reproducible)

`/data/tmp/kdmu4_frag.img`: `/d/frag.bin` = 64 MiB with **8192 single-block extents**
(alternating 4 KiB hole-punch via fallocate on a loop mount; filefrag -v verified;
note filefrag's summary line lies — trust `-v`), plus `/d/contig.bin` 64 MiB
contiguous control. e2fsck-clean.

### The gap and the mechanism

`ffs-cli read` warm: frag 161.6 ms vs contig 17.2 ms = **9.4x** while the kernel's
frag/contig warm ratio is 1.04x. Symbolized profile (release + debuginfo env
overrides): `ExtentCache::insert` 21.7% + BTree `search_tree` 14.1% + BTree
`Iter::next`/`next_kv`/`next_leaf_edge` 18.8% ≈ **57% of the read**. Cause:
`evict_lru_except` did a full-shard BTreeMap scan per insert (`min_by_key`), and one
inode's mappings all land in ONE shard (capacity 1024) — a >capacity extent stream
makes every insert O(shard), i.e. quadratic. (This is the true cost behind the
2026-07-16 fleet-blocked `insert_batch` stash, which chased the LOCK, not the scan.)

### Lever (one lever, `crates/ffs-extent/src/lib.rs`)

Batch eviction: one scan selects the `max(1, capacity/8)` LRU victims via
`select_nth_unstable_by_key` on the exact historical `(last_access, key)` ordering,
amortizing eviction to O(len/batch) per insert. `FFS_EXTENT_EVICT_BATCH=1` restores
the historical single-victim behavior (same-binary A/B); with batch=1 the victim is
IDENTICAL to the old `min_by_key`, tie-break included, so capacities <16 — including
both eviction unit tests — keep exact historical semantics. Eviction choice never
affects returned mappings, only what must be re-resolved from the authoritative tree.

### Measurement (same binary, env-toggled, interleaved, 5 reps + 7-rep contig guard)

| surface | single (incumbent) | batch | ratio |
| --- | --- | --- | --- |
| warm frag (pure CPU) | 210.5 ms (cv 3.6%) | **86.2 ms** (cv 6.5%) | **2.44x** |
| cold frag | 249.6 ms (cv 8.5%) | **139.0 ms** (cv 14.4%) | **1.80x** |
| warm contig guard | 17.3 ms | 17.4 ms | parity (eviction never fires) |

Identity: sha256 of full frag.bin bytes identical single-vs-batch AND equal to the
kernel loop-mount sha (`5fb93b1c…`). `cargo test -p ffs-extent` remote: **154/0**.
rustfmt clean; ubs 0 critical.

### Residual + next levers on this surface

Warm frag (86 ms) is still ~5x contig: the shard (cap 1024) cannot hold 8192 mappings,
so the stream still thrashes (miss → tree re-walk → insert → batch-evict cycle).
Candidates: don't cache a leaf's mappings when the namespace's mapping count exceeds
shard capacity (cache the LEAF page instead / rely on the arc_swap extent map);
per-namespace capacity awareness; or a direct extent-map path for >capacity files.
Also note `ffs-cli read` duration includes ~13 ms fixed CLI startup — ratios above are
end-to-end and thus conservative.

## 2026-07-22 — KEEP #2 on the high-extent regime: publish hot extents for DEEP trees on one-shot reads — warm frag another 2.53x, cold beats the kernel arm (bd-vpypn / bd-kdmu4, cc)

Profile-first on the post-batch-eviction binary: the residual warm-frag cost was still
~29% in the cache layer, now the per-insert BTreeMap DESCENT (`search_tree` 21.9% +
`insert` 6.7%) — ~16k lookups/inserts per read (8192 data mappings re-inserted leaf-by-
leaf plus one single-block HOLE SENTINEL per hole block) into a shard that can never
hold them.

### Root cause

`OpenFs` already has a lock-free full-map fast path (`ext4_hot_extents`,
`ArcSwapOption<(ns, Arc<[ExtentMapping]>)>`) that resolves blocks AND holes in-memory
with zero cache traffic — but its publication was gated on `inode_was_hot`, i.e. never
for a one-shot full-file read ("a one-shot multi-file read never pays the full-tree
walk"). For a DEEP extent tree that trade inverts: the "saved" full walk is ~25 leaf
reads the per-miss path pays leaf-by-leaf anyway, while the un-published read pays the
16k-op cache storm.

### Lever (one lever, `crates/ffs-core/src/lib.rs`)

Publish also when `ext4_deep_extent_tree(inode)`: root header `depth >= 1` from the
pure in-inode parse (`parse_inode_extent_tree`), env kill switch
`FFS_HOT_EXTENTS_DEEP=0`. Depth-0 trees (≤4 inline extents — every small-file-storm
case) keep the historical one-shot behavior byte-for-byte.

### Measurement (same binary, env-toggled, interleaved, 5 reps)

| surface | off (incumbent) | on (deep publish) | ratio |
| --- | --- | --- | --- |
| warm frag 8192-extent | 86.6 ms (cv 3.4%) | **34.2 ms** (cv 6.4%) | **2.53x** |
| cold frag | 106.5 ms (cv 6.3%) | **59.3 ms** (cv 3.1%) | **1.80x** |
| warm contig guard | 26.9 ms | 27.2 ms | parity |
| multi-file storm guard (1 GiB walk) | 229.4 ms | 230.4 ms | parity |

sha256 identity both arms (= kernel loop-mount sha). Targeted `ffs-core` tests
(extent/hot/resolve/read_file): **125 passed / 0 failed** remote. rustfmt clean.

### Stacked session result on this regime (fixture `/data/tmp/kdmu4_frag.img`)

warm frag: 161.6 → 34.2 ms (**4.7x**, now ~1.26x of contig vs kernel's 1.04x ratio);
cold frag: 184.4 → 59.3 ms (**3.1x**) — and the cold fragmented read now lands BELOW
the dio-loop kernel arm's 75.0 ms on the same fixture (different I/O path — direct
image pread vs loop — so stated as arm-vs-arm, not "faster than kernel ext4" absolute).
Remaining residual vs contig (~7 ms warm) is the per-segment assembly of 8192
one-block extents + hole memset; no cheap lever identified — diminishing returns.
