<div align="center">
  <img src="docs/assets/frankenfs_illustration.webp" alt="FrankenFS - Memory-safe ext4 + btrfs in Rust">
</div>

<p align="center">
  <br>
  <code>&nbsp;╔═╗┬─┐┌─┐┌┐┌┬┌─┌─┐┌┐┌╔═╗╔═╗&nbsp;</code><br>
  <code>&nbsp;╠╣ ├┬┘├─┤│││├┴┐├┤ │││╠╣ ╚═╗&nbsp;</code><br>
  <code>&nbsp;╚  ┴└─┴ ┴┘└┘┴ ┴└─┘┘└┘╚  ╚═╝&nbsp;</code><br>
  <br>
  <strong>Memory-safe ext4 + btrfs in Rust, from userspace</strong><br>
  <em>Block-level MVCC &middot; RaptorQ self-healing &middot; Adaptive conflict arbitration &middot; Zero unsafe code</em>
</p>

<p align="center">
  <a href="https://github.com/Dicklesworthstone/frankenfs/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT%2BOpenAI%2FAnthropic%20Rider-blue.svg" alt="MIT+Rider License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-nightly%202024-orange.svg" alt="Rust Nightly"></a>
  <img src="https://img.shields.io/badge/ParityReport-97%2F97%20feature%20rows-blue" alt="ParityReport: 97/97 feature rows">
  <img src="https://img.shields.io/badge/parity%20columns-implemented%20%7C%20kernel--verified%20%7C%20rejection--only-lightgrey" alt="Parity accounting columns">
  <img src="https://img.shields.io/badge/tests-source--derived-brightgreen" alt="Tests source-derived">
  <img src="https://img.shields.io/badge/fuzz%20targets-63-brightgreen" alt="63 fuzz targets">
  <img src="https://img.shields.io/badge/unsafe-forbidden-brightgreen.svg" alt="Unsafe Forbidden">
  <img src="https://img.shields.io/badge/runtime-asupersync%200.3-blueviolet.svg" alt="asupersync 0.3 runtime">
  <img src="https://img.shields.io/badge/status-experimental-yellow.svg" alt="Experimental">
</p>

---

## TL;DR

**The problem.** ext4 and btrfs are production kernel filesystems. That makes their behavior worth preserving, but it also makes experimentation with concurrency control, repair policy, and deterministic test harnesses difficult. ext4 serializes write commits through JBD2, while btrfs relies on kernel COW machinery and `scrub` plus redundancy for repair workflows.

**The approach.** FrankenFS extracts ext4 and btrfs behavior from ~205K lines of Linux kernel C (v6.19), re-implements that behavior in Rust with `#![forbid(unsafe_code)]`, and adds experimental layers for block-level MVCC, RaptorQ repair symbols, and explicit-opt-in FUSE writeback-cache barriers.

It runs as a normal Linux process via FUSE. The current `ParityReport::current()` printout is 97/97 rows in the tracked feature denominator, while the B-series accounting keeps implemented, kernel-verified, and rejection-only rows separate instead of treating the table as a blanket readiness score. Public readiness wording is gated by a checked-in release-gate policy with structured proof bundles, and the workspace ships **21 crates, a source-derived test inventory, 63 fuzz targets, 92 criterion benchmarks, 125 tracked end-to-end gate scripts, and 23 evidence-event types** under `#![forbid(unsafe_code)]`. The README count guard `readme_quantitative_claims_match_code` re-derives these inventory numbers from source so fast-moving test counts are not hand-pinned here.

| Pillar | What it does | Why it matters |
|---|---|---|
| **Block-level MVCC** | Version chains per block, snapshot isolation, 2 executable same-block merge mechanisms (`AppendOnly` and range overlay) exposed through `MergeProof` labels, the 3-outcome `MergeProofMechanism` enum (`NoSameBlockMerge`, `AppendOnly`, `RangeOverlay`), and three `ConflictPolicy` modes (`Strict` / `SafeMerge` / `Adaptive`) selected by an expected-loss decision model | Concurrent readers + writers without routing every commit through the ext4 JBD2 model. Safe-merge proofs let non-conflicting concurrent writes to the same block coexist when they validate through one of the two audited mechanisms. Under a 120-writer stress benchmark, SafeMerge runs 9.5× lower expected loss than Strict with no corruptions observed in that run. Note: the FUSE write path currently stages all writes with `MergeProof::Unsafe`; the 9.5× benefit is bench-demonstrated but not yet wired into production FUSE writes (tracked: bd-xuo95.28). |
| **RaptorQ self-healing** | Fountain-coded repair symbols (RFC 6330), Bayesian Beta-posterior durability autopilot, four refresh policies (`Eager` / `Lazy` / `Adaptive` / `Hybrid`), percentile-based stale-window SLO monitoring | Scrub detects corruption; `ffs repair` / `ffs fsck --repair` can recover offline when repair symbols are available. Mounted repair requires explicit `--background-repair --background-scrub-ledger <jsonl>` and records a durable evidence trail. Hybrid refresh has benchmark coverage for lower p95 stale-window age under write-heavy workloads; the exact percentage remains benchmark-artifact scoped. |
| **Writeback-cache safety net** | Per-inode `staged ≥ visible ≥ durable` epoch state machine, six formal invariants (I1–I6), 12-scenario crash/replay artifact gate, runtime kill switch | Kernel FUSE `writeback_cache` can reorder visibility in ways MVCC must account for. FrankenFS opts in *only* with `--rw --writeback-cache` plus three accepted-artifact gates, a matching host/lane manifest, and a disarmed kill switch. `flush` stays non-durable; `fsync` / `fsyncdir` are the durability boundaries operators reason about. |
| **Memory safety** | `#![forbid(unsafe_code)]` at every crate root, edition 2024 (nightly), workspace-level Clippy enforcement | Removes direct use of unsafe Rust from FrankenFS crates, including the common C filesystem hazards around buffer bounds, lifetime errors, and uninitialized reads. |
| **Structured concurrency** | [asupersync](https://github.com/Dicklesworthstone/asupersync) 0.3 instead of tokio: `Cx` capability contexts, regions, two-phase reserve/commit channels, deterministic `LabRuntime` with virtual time + DPOR | No orphan tasks. Cancellation is cooperative and budget-aware at every I/O boundary. Stress tests reproduce concurrency bugs deterministically across seeds. |
| **Userspace FUSE** | Vendored `fuser` 7.40 with unrestricted ioctls; runs as a normal process | Debug with `gdb`, profile with `perf`, replace the binary without a reboot. No kernel module loading. No reboot-on-crash. |

---

## Quick Example

```bash
# Clone and build
git clone https://github.com/Dicklesworthstone/frankenfs.git
cd frankenfs
cargo build --workspace

# Inspect an ext4 image (or a btrfs image; same command, format auto-detected)
cargo run -p ffs-cli -- inspect /path/to/fs.img --json

# Full filesystem info: superblock + groups + MVCC + journal sections
cargo run -p ffs-cli -- info /path/to/fs.img --groups --mvcc --journal --json

# Read-only mount (default, safe)
sudo cargo run -p ffs-cli -- mount /path/to/fs.img /mnt/ffs

# Read-write ext4 mount with mounted automatic repair + evidence ledger
sudo cargo run -p ffs-cli -- mount /path/to/fs.img /mnt/ffs \
    --rw --background-repair --background-scrub-ledger repair.jsonl

# btrfs read-write mount (durable by default via full transaction commit)
sudo cargo run -p ffs-cli -- mount /path/to/btrfs.img /mnt/ffs --rw

# Conformance + parity reports
cargo run -p ffs-harness -- check-fixtures
cargo run -p ffs-harness -- parity

# One-command self-healing demo (no FUSE, no sudo, runs against a temp raw image)
cargo run --bin ffs-demo -- self-healing

# The four gates that must pass before any merge
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

---

## Design Philosophy

### 1. Spec-first, not translation

FrankenFS does **not** translate C line-by-line. The porting doctrine:

1. Extract behavior from legacy kernel code into structured spec documents
2. Design idiomatic Rust architecture from the spec
3. Implement from the spec (not by copying C control flow)
4. Validate via conformance harness against real filesystem images
5. Track parity quantitatively in `FEATURE_PARITY.md`; the harness asserts the match in CI

This produces code that is Rust-native rather than "C with Rust syntax", and typically 3–5× more concise than the original kernel C while covering the same behavioral surface.

### 2. No ambient authority

Every I/O operation takes an `&asupersync::Cx` capability context. The `Cx` carries a poll budget, deadline, cancellation signal, and pressure feedback. No function can perform I/O, read the clock, or sleep without holding one. This enables cooperative cancellation, deadline propagation, and deterministic testing under a virtual-time lab runtime, with no global state and no hidden singletons.

### 3. Proof over heuristic

For high-risk subsystems, FrankenFS uses principled decision models rather than tuned constants:

- **MVCC conflict resolution.** An expected-loss decision rule selects between Strict FCW and SafeMerge based on EMA-tracked conflict / merge-success / abort rates.
- **Repair symbol overhead.** A Beta posterior over per-block corruption probability, minimizing `P(unrecoverable) · data_loss_cost + overhead · storage_cost`.
- **Repair refresh policy.** Expected-loss comparison of age-only vs block-count vs hybrid triggers, with workload-profile-aware decision boundaries.
- **Writeback-cache opt-in.** Expected-loss decision matrix scoring semantic-violation probability vs operational cost; default is off, opt-in is artifact-gated.

When a heuristic must be used, the spec documents why formal alternatives were not viable.

### 4. Layered isolation

Parser crates are pure (no I/O). MVCC knows nothing about files. FUSE knows nothing about on-disk formats. Repair operates on blocks, not inodes. Each concern lives in exactly one crate, and the workspace dependency graph is a strict DAG.

### 5. Evidence over claim

Public readiness assertions are tied to machine-readable artifacts:

- Tracked feature coverage lives in `FEATURE_PARITY.md` and is parsed by `ffs-harness::ParityReport::current()`; a CI test enforces the mapping.
- Release-gate behavior lives in `tests/release-gates/release_gate_policy_v1.json` and is validated by `ffs-harness validate-proof-bundle`.
- Public serialized `ffs-harness` report schemas (release-gate, writeback-cache audit, ordering oracle, crash-replay oracle, repair confidence, repair corpus, soak/canary, swarm tail latency, fuzz dashboard, mounted-lane decision, ...) are snapshot-pinned with `insta` against a checked-in schema inventory, and a drift detector catches silent shape changes. Crate-local human-output snapshots and exact-golden tests are tracked at their own test surfaces instead of being forced into that JSON schema inventory.
- Every checksum, parser, and reporting surface has metamorphic-relation proptests.

### 6. Zero unsafe, always

`#![forbid(unsafe_code)]` is set at every crate root and enforced as a workspace lint. There are no exceptions and no plans for exceptions. The performance cost is negligible: FUSE round-trip overhead (~10µs) dominates any bounds-check overhead (~1ns).

---

## Comparison with Alternatives

| | FrankenFS | Linux ext4 (kernel) | Linux btrfs (kernel) | ext4fuse | fuse-ext2 |
|---|---|---|---|---|---|
| **Language** | Rust | C | C | C | C |
| **Runs in** | Userspace (FUSE) | Kernel | Kernel | Userspace (FUSE) | Userspace (FUSE) |
| **Memory safety** | `forbid(unsafe_code)` | Manual | Manual | Manual | Manual |
| **ext4 support** | Read + experimental write | Full | n/a | Read-only | Read-write |
| **btrfs support** | Read + guarded experimental write | n/a | Full | n/a | n/a |
| **Both formats from one binary** | Yes | No | No | No | No |
| **Concurrent writes** | MVCC with adaptive policy | JBD2 (global lock) | COW B-tree | n/a | Single-writer |
| **Self-healing** | RaptorQ + Bayesian autopilot | None (run fsck) | Scrub + mirrors | None | None |
| **Conflict resolution** | Safe-merge proofs + expected-loss | n/a | n/a | n/a | n/a |
| **Crash-consistency model** | 12-point crash matrix + 6 invariants | Journal | COW + log tree | n/a | n/a |
| **Determinism for stress** | LabRuntime + DPOR | Thread scheduler | Thread scheduler | n/a | n/a |
| **Evidence trail** | 23-event JSONL ledger | dmesg | dmesg | n/a | n/a |
| **Debuggable** | Standard userspace tools | printk + crash dump | printk + crash dump | gdb | gdb |

### Where FrankenFS fits among Rust filesystem projects

| Project | Scope | Difference from FrankenFS |
|---|---|---|
| **Servo `rust-fuse`** (`fuser` upstream) | A FUSE protocol binding | Lower-level. FrankenFS *uses* a vendored `fuser` at ABI 7.40 as its FUSE transport. |
| **`bento`** | Rust-in-kernel filesystem framework | Kernel-level, requires kernel build; FrankenFS is userspace |
| **`gotenks`** | Pedagogical Rust ext-style filesystem | Custom on-disk format; FrankenFS preserves the real ext4/btrfs format and is mount-compatible |
| **`rfs`** / `rsfs` | Filesystem-on-flat-file projects | Custom formats; no on-disk compatibility |
| **`btrfs-rs`** | Read-only btrfs parser | Read-only; no FUSE, no MVCC, no repair |
| **`ext4-view`** | Read-only ext4 viewer | Read-only inspector; no FUSE, no write path |
| **`bdsh`** | Read-only ext4 shell | Read-only; CLI-only |

FrankenFS is focused on a specific intersection: real on-disk format compatibility for both ext4 *and* btrfs, MVCC experiments, fountain-code repair experiments, a structured-concurrency runtime, and zero unsafe code in FrankenFS crates.

### What FrankenFS is NOT

To avoid wasted reading, here is what this project is explicitly **not** trying to be:

- **Not a kernel filesystem.** It runs in userspace via FUSE. If you need kernel-only semantics or lower latency than FUSE can provide, use kernel ext4 / btrfs.
- **Not a drop-in replacement for `mount -t ext4`.** Mount the same images; observe semantically equivalent behavior; but the userspace path adds FUSE round-trip latency.
- **Not production-ready for irreplaceable data.** The tracked V1 feature denominator is complete according to `ParityReport::current()`, but the operational readiness lanes (xfstests, swarm.responsiveness, performance.baseline, soak/canary) are mid-evidence. Use this on data you can lose.
- **Not a loose parser experiment.** Parsers are fixture-pinned, kernel-differential-validated, and metamorphic-relation-proptested. The aim is fidelity to the documented V1 surface.
- **Not a multi-filesystem framework.** ext4 and btrfs are V1; XFS, ZFS, NTFS, etc. are out of scope. The structured-concurrency + repair-symbol architecture could generalize, but each format requires its own behavioral extraction effort and is not part of this roadmap.
- **Not a tokio project.** The entire tokio ecosystem is explicitly forbidden by the workspace lints; asupersync is the runtime.

---

## Architecture

FrankenFS is a 21-crate Cargo workspace with a strict DAG dependency graph.

```
Layer 1 (Foundation):  [ffs-types]  [ffs-error]
                              \      /
Layer 2 (On-disk):        [ffs-ondisk]                  [ffs-mvcc]
                           /    |    \                       |
Layer 3 (Storage):  [ffs-block]  [ffs-btree]  [ffs-xattr]----+
                     (+ ARC/S3-FIFO)  |
Layer 4 (Alloc):                [ffs-alloc]
                                    |
Layer 5 (Mid):  [ffs-journal]  [ffs-repair]  [ffs-extent]  [ffs-inode]
                 [ffs-btrfs]  (runtime btrfs tree/chunk/mutation adapter)
                                                              |
Layer 6 (Dir):                                            [ffs-dir]

Layer 7 (Core):                [ffs-core]  <-- orchestrates everything
                                /      \
Layer 8 (Interface):     [ffs-fuse]      [ffs]  (public facade)
                                       / | \
Layer 9 (Tooling):        [ffs-cli] [ffs-tui] [ffs-harness]

Legacy extraction reference (retained, not on the runtime path):
                        [ffs-ext4]
```

### Crate responsibilities

| Layer | Crates | What it does |
|-------|--------|--------------|
| **Foundation** | `ffs-types`, `ffs-error` | Newtypes (`BlockNumber`, `InodeNumber`, `TxnId`, `CommitSeq`, `ByteOffset`, `DeviceId`); 21-variant `FfsError` with errno mappings |
| **On-disk** | `ffs-ondisk` | Pure parsing of ext4 + btrfs superblocks, group descriptors, inodes, extents, B-tree headers. No I/O. |
| **Storage** | `ffs-block`, `ffs-journal`, `ffs-mvcc` | Block I/O with ARC / S3-FIFO cache; JBD2 replay + ext4 fast-commit + external-journal pairing; native MVCC with version chains, sharded store, snapshot isolation, two same-block merge mechanisms behind semantic proof labels, three conflict policies, Zstd/Brotli version compression, WAL persistence + recovery |
| **Tree / Alloc** | `ffs-btree`, `ffs-alloc`, `ffs-extent`, `ffs-btrfs` | B+tree search/insert/split/merge; mballoc-style buddy allocator with goal-directed placement and Orlov directory spreading; ext4 extent mapping; btrfs runtime tree walk, chunk/device mapping, tree-log replay, COW tree mutation helpers, and delayed-ref helpers consumed by `ffs-core` |
| **Namespace** | `ffs-inode`, `ffs-dir`, `ffs-xattr` | Inode lifecycle with CRC32C checksum, htree directories with case-folding, user/system/security/trusted xattr namespaces |
| **Interface** | `ffs-fuse`, `ffs-core`, `ffs` | FUSE protocol adapter (vendored `fuser` 7.40); `OpenFs` implementation of `FsOps` orchestrating format detection, mount, writeback epoch barrier, degradation FSM, backpressure gates; thin public facade |
| **Repair** | `ffs-repair` | RaptorQ symbol generation/recovery, background `ScrubDaemon`, Bayesian `DurabilityAutopilot`, four refresh policies, stale-window SLO with breach detection, optimistic lease-based multi-host coordination, 23-event evidence ledger, repair-writeback serializer for read-write mounted repair |
| **Tooling** | `ffs-cli`, `ffs-tui`, `ffs-harness` | 11-subcommand CLI; live TUI monitoring; conformance harness with sparse fixtures, golden-file validation, parity tracking, proof-bundle validation, performance manifests, schema inventory, metamorphic seed catalog, soak/canary campaign runner, release-gate validator |

### Layering rules

- **Parser crates are pure.** `ffs-ondisk` performs no I/O. It parses byte slices into typed structures, which makes it fuzz-friendly, snapshot-testable, and cross-platform.
- **MVCC is transport-agnostic.** `ffs-mvcc` knows nothing about FUSE, files, or directories.
- **FUSE delegates to `FsOps`.** `ffs-fuse` maps the FUSE protocol to `ffs-core::FsOps` (implemented by `OpenFs`) and contains no filesystem logic.
- **btrfs runtime logic flows through `ffs-btrfs`.** `ffs-core` depends on `ffs-btrfs` for tree-log replay, inode/extent/xattr item parsing, chunk/device mapping, and the in-memory COW tree used by guarded btrfs mutation paths.
- **Repair is orthogonal.** `ffs-repair` operates on blocks, not files. It doesn't know about inodes or directories.
- **Repair wiring is lifecycle-based.** `ffs-core` reaches repair via `ffs-mvcc` / block-flush integration rather than a direct `ffs-core → ffs-repair` dependency edge.
- **No dependency cycles.** The crate graph is a strict DAG, enforced by `cargo check`.
- **`Cx` everywhere.** Any operation that performs I/O or may block takes `&asupersync::Cx` as its first parameter.

---

## Data Flow

### Read path

```
userspace read(fd, buf, count)
  → kernel FUSE → fuser → ffs-fuse::read()
    → begin_request_scope(cx, op): MVCC snapshot + backpressure check
      → ffs-core FsOps (OpenFs): flavor dispatch (ext4 / btrfs)
        → extent/chunk mapping + block reads
          (ext4: ffs-extent/ffs-btree/ffs-block; btrfs: ffs-btrfs + ffs-block)
        → flavor-specific inode/file assembly in ffs-core
    → end_request_scope(cx, scope): release snapshot, update metrics
  → fuser → kernel → userspace
```

### Write path

```
userspace write(fd, buf, count)
  → kernel FUSE → fuser → ffs-fuse::write()
    → ffs-core FsOps (OpenFs): flavor dispatch, requires --rw
      → allocation + extent/tree updates (ffs-alloc, ffs-extent, ffs-btree)
      → block writes (ffs-block) staged into the current MVCC transaction
      → commit with adaptive conflict policy (merge-proof resolution if available)
      → journal/repair integration paths when enabled by the operation
    → ffs-core: return bytes written
  → fuser → kernel → userspace
```

### Corruption recovery

```
ffs-repair::ScrubDaemon [background, lifecycle-owned by mount]
  → ffs-block: read every block in the group
    → checksum verification (CRC32C for compat mode, BLAKE3 for native mode)
    → MISMATCH on block N
      → if mount has --background-repair + ledger:
          → ffs-repair: load RaptorQ repair symbols
          → asupersync RaptorQ decode
          → validate recovered block checksum
          → (RW mount) route writeback through MVCC repair-writeback serializer
          → ffs-block: write corrected block
          → ffs-repair: refresh repair symbols (hybrid age + block-count trigger)
          → emit { CorruptionDetected → RepairAttempted → RepairSucceeded } to ledger
      → else: emit CorruptionDetected only (detection-only mode)
```

---

## Sequence Diagrams

The data-flow boxes above show *which crate* handles each step. The diagrams below show *time order* and *failure surfaces*, which is what an operator usually wants to know when a request fails.

### Mount lifecycle (RO ext4, default `standard` runtime mode)

```
                                                         (time →)
Operator         ffs-cli           ffs-fuse              ffs-core         ffs-ondisk        ffs-block
   │                │                  │                     │                 │                 │
   │  mount IMG MNT │                  │                     │                 │                 │
   ├───────────────►│                  │                     │                 │                 │
   │                │ Cx::for_request() ◄─┐                  │                 │                 │
   │                │ OpenFs::open()                         │                 │                 │
   │                ├───────────────────────────────────────►│                 │                 │
   │                │                  │                     │ FileByteDevice::open │           │
   │                │                  │                     ├────────────────────────────────►  │
   │                │                  │                     │ probe superblock @1024 + @65536  │
   │                │                  │                     ├────────────────►│                 │
   │                │                  │                     │ parse + validate│                 │
   │                │                  │                     │◄────────────────┤                 │
   │                │                  │                     │ FsFlavor::Ext4(…) returned        │
   │                │ mount(Box::new(fs), MNT, &options)     │                 │                 │
   │                ├─────────────────►│                     │                 │                 │
   │                │                  │ fuser::Session::new │                 │                 │
   │                │                  │ install kernel notifier              │                 │
   │                │                  │ session.run()  ── enters request loop ──               │
   │                │                  │ ╔══════════════════════════════════╗  │                 │
   │                │                  │ ║   begin_request_scope             ║  │                │
   │                │                  │ ║     (snapshot + backpressure)    ║  │                │
   │                │                  │ ║   dispatch FsOps method          ║  │                │
   │                │                  │ ║   end_request_scope              ║  │                │
   │                │                  │ ╚══════════════════════════════════╝  │                │
   │                │                  │                     │                 │                 │
   │   fusermount3 -u MNT              │                     │                 │                 │
   ├───────────────────────────────────►                     │                 │                 │
   │                │                  │ session.run() returns                │                 │
   │                │◄─────────────────┤                     │                 │                 │
   │  exit 0        │                  │                     │                 │                 │
```

### Read path (FUSE → MVCC snapshot)

```
kernel                FUSE          ffs-fuse           OpenFs            MVCC store        block layer
  │                    │                │                  │                  │                 │
  │ read(fd, buf, n)   │                │                  │                  │                 │
  ├───────────────────►│                │                  │                  │                 │
  │                    │ FUSE_READ      │                  │                  │                 │
  │                    ├───────────────►│                  │                  │                 │
  │                    │                │ begin_request_scope ────► snapshot = current_seq      │
  │                    │                │                  │  ──────────────► RequestScope { snapshot } │
  │                    │                │ OpenFs::read(cx, ino, off, n)                          │
  │                    │                ├─────────────────►│                  │                 │
  │                    │                │                  │ resolve extent → physical block  N │
  │                    │                │                  │ MvccStore::read_visible(N, snapshot) │
  │                    │                │                  │ ────────────────►│                 │
  │                    │                │                  │   walk version chain N             │
  │                    │                │                  │   pick entry with commit_seq ≤ snapshot │
  │                    │                │                  │   return Cow<[u8]>                 │
  │                    │                │                  │ ◄────────────────┤                 │
  │                    │                │                  │ if not in version chain →          │
  │                    │                │                  │   BlockDevice::read_block(cx, N)──►│
  │                    │                │                  │                  │   ARC cache hit?│
  │                    │                │                  │ ◄──── bytes ─────┼─── if miss: ByteDevice::read_exact_at │
  │                    │                │ end_request_scope                   │                 │
  │                    │ reply.data(…)  │ release snapshot, update metrics    │                 │
  │ ◄──────────────────┤◄───────────────┤                                     │                 │
  │ bytes returned     │                │                                     │                 │
```

### Write path (FUSE → MVCC commit with conflict policy)

```
caller          ffs-fuse        OpenFs           Transaction        MvccStore         BlockDevice
  │                │                │                  │                  │                 │
  │ write(fd, …)   │                │                  │                  │                 │
  ├───────────────►│                │                  │                  │                 │
  │                │ FsOps::write   │                  │                  │                 │
  │                ├───────────────►│                  │                  │                 │
  │                │                │ store.begin() ──►│                  │                 │
  │                │                │                  │ snapshot = high  │                 │
  │                │                │                  │ stage write to block N (extent map ↓)│
  │                │                │  ext4-flavor encode + tree walk      │                 │
  │                │                │                  │ collect MergeProof if applicable    │
  │                │                │                  │   (AppendOnly / IndependentKeys / …) │
  │                │                │ store.commit(txn)│                  │                 │
  │                │                ├─────────────────►│ ────────────────►│                 │
  │                │                │                  │                  │ acquire shard locks (sorted) │
  │                │                │                  │                  │ CAS commit_seq += 1 │
  │                │                │                  │                  │ for each touched block:│
  │                │                │                  │                  │   if latest.commit_seq > snapshot: │
  │                │                │                  │                  │     try MergeProof.merge_bytes() │
  │                │                │                  │                  │     if fail → ConflictPolicy decision: │
  │                │                │                  │                  │       Strict → ABORT (FcwConflict)   │
  │                │                │                  │                  │       SafeMerge → also ABORT (no proof) │
  │                │                │                  │                  │       Adaptive → expected-loss vote   │
  │                │                │                  │                  │   else append BlockVersion │
  │                │                │                  │                  │ release shard locks │
  │                │                │                  │ ◄────────────────┤                 │
  │                │                │ if commit OK:    │                  │                 │
  │                │                │   WAL writer batches commit record  │                 │
  │                │                │   emit TransactionCommit            │                 │
  │                │                │ if abort:        │                  │                 │
  │                │                │   emit TxnAborted{reason}            │                 │
  │                │                │   return EAGAIN to caller (or auto-retry, configurable)│
```

### Background repair cycle (mounted, `--background-repair --background-scrub-ledger`)

```
                                                        (every interval_secs)
ScrubDaemon         BlockDevice        Checksum         RaptorQ decoder     EvidenceLedger
   │                    │                  │                  │                  │
   │  tick              │                  │                  │                  │
   ├──── for each block in next group ───► read_block(cx, N)  │                  │
   │                    │                  │ compute crc32c (or BLAKE3, native) │
   │                    │                  │◄─── computed_crc ──┤                │
   │                    │ stored_crc       │                  │                  │
   │                    │ if mismatch:     │                  │                  │
   │                    │   ─── CorruptionDetected → ledger ──────────────────► │
   │                    │   load repair symbols for group     │                  │
   │                    │   ────────────────────────────────► decode(K source + r repair)│
   │                    │                                     │ recovered bytes  │
   │                    │   ─── RepairAttempted → ledger ────────────────────►  │
   │                    │   verify recovered crc                                 │
   │                    │   if MVCC mount: pass through repair-writeback serializer │
   │                    │   else:           direct backing-image writeback        │
   │                    │   write_block(cx, N, recovered)                        │
   │                    │   ─── RepairSucceeded → ledger ─────────────────────► │
   │                    │   refresh repair symbols (hybrid age + block-count)    │
   │                    │   ─── SymbolRefresh → ledger ───────────────────────► │
   │ ─── ScrubCycleComplete → ledger ──────────────────────────────────────────► │
```

### Writeback-cache opt-in (release-gated path)

```
operator                ffs-cli            ffs-fuse           validators
   │                       │                  │                  │
   │ ffs mount --rw --writeback-cache         │                  │
   │   --writeback-cache-gate audit_gate.json │                  │
   │   --writeback-cache-ordering-oracle …    │                  │
   │   --writeback-cache-crash-replay-oracle …│                  │
   ├──────────────────────►│                  │                  │
   │                       │ check FFS_WRITEBACK_CACHE_KILL_SWITCH                  │
   │                       │   ─── if armed → REFUSE immediately                   │
   │                       │ load each artifact JSON              │                │
   │                       │ ──────────────────────────────────► │                │
   │                       │                                     │ validate_writeback_cache_audit │
   │                       │                                     │ validate_writeback_cache_ordering │
   │                       │                                     │ validate_writeback_cache_crash_replay │
   │                       │ ◄── per-artifact accept/reject ──── │                │
   │                       │ if any reject → ABORT mount         │                │
   │                       │ compare host_class / lane manifest  │                │
   │                       │ if mismatch → ABORT                 │                │
   │                       │ build MountOptions with WritebackCacheMode::Enabled  │
   │                       │ ─── ffs-fuse::mount(…) ─────────────►                │
   │                       │                  │ session starts with FUSE_INIT including writeback_cache flag │
   │                       │                  │ FUSE protocol now allows kernel-side writeback caching │
   │ session running       │                  │                  │                │
```

These diagrams are deliberately rough. The authoritative truth lives in the code; the diagrams are meant for orientation when reading the code or the evidence ledger.

---

## Mount Runtime Modes

`ffs-cli mount --runtime-mode {standard|managed|per-core}` selects between three execution profiles. The default is `standard`.

| Mode | When to use | What changes |
|---|---|---|
| **`standard`** | Default. Single-host workflows, development, inspection mounts | Existing FUSE dispatcher; no extra evidence required |
| **`managed`** | Production-like usage where you want graceful unmount, backpressure observability, and an evidence-bearing teardown | Adds `--managed-unmount-timeout-secs` and the managed backpressure gate; emits structured teardown evidence |
| **`per-core`** | High-fanout swarm workloads on machines with many cores | Thread-per-core dispatcher with idle-stealing guard; saturating per-core metrics; opt-in only |

**The optional adaptive runtime is default-off.** It governs the managed and per-core modes via `docs/adaptive-runtime-evidence-manifest.json` and is gated by the `adaptive_runtime` proof-bundle lane (see [Evidence and Release Gates](#evidence-release-gates-and-readiness)). Only `host_class = large_host` or `permissioned_large_host` with `release_claim = authoritative_large_host` can strengthen the `swarm.responsiveness` public claim. Local `small_host_smoke` and `capability_downgraded_smoke` lanes are downgrade evidence by construction.

Full details: [`docs/mount-runtime-modes.md`](docs/mount-runtime-modes.md).

---

## Deep Dive: MVCC Conflict Resolution

Traditional FUSE filesystems serialize all writes through a single lock. FrankenFS eliminates this bottleneck with block-level MVCC and a structured safe-merge system that lets non-conflicting concurrent writes to the same block coexist.

### Version chains and snapshot isolation

Every logical block maintains a version chain: an ordered sequence of `BlockVersion` entries, each tagged with a `CommitSeq` and a writer `TxnId`. Readers acquire a snapshot (`Snapshot { high: CommitSeq }`) and see only versions with `commit_seq <= snapshot.high`. Writers accumulate staged writes in a `Transaction` and attempt to commit atomically. Serializable Snapshot Isolation (SSI) detects two-edge rw-antidependency dangerous structures and aborts writers whose snapshots are no longer serializable.

### First-Committer-Wins with merge proofs

When a writer commits and discovers that a block it wrote has been modified since its snapshot, the default response is to abort (FCW). But many concurrent writes don't actually conflict at the byte level. Two writers might be appending to different regions of the same block, or updating disjoint metadata fields in the same inode block.

`MergeProof` is structured evidence that two writes can be combined without data loss. The public labels are not six separate byte algorithms: `AppendOnly` is one mechanism, `IndependentKeys` / `NonOverlappingExtents` / `TimestampOnlyInode` all route through the same range-overlay validator, and `DisjointBlocks` / `Unsafe` do not attempt same-block conflict resolution.

| Proof label | Use case | Executable mechanism |
|---|---|---|
| `AppendOnly { base_len }` | Log-structured appends, directory entry additions | Concatenate: keep the committed writer's prefix, append the new writer's tail |
| `IndependentKeys { touched_ranges }` | Disjoint metadata field updates | Overlay: copy each writer's byte ranges onto the committed base |
| `NonOverlappingExtents { touched_ranges }` | Extent-tree updates to different file regions | Same overlay strategy, scoped to extent blocks |
| `TimestampOnlyInode { touched_ranges }` | Concurrent `setattr` on different inode timestamp fields | Same overlay, validated for inode-specific byte layout |
| `DisjointBlocks` | Transactions touching completely different blocks | No same-block merge; this label documents why the FCW path should not have been reached |
| `Unsafe` | No proof available | No same-block merge; always aborts on conflict (FCW fallback) |

`MergeProof::merge_bytes()` takes `base` (the version at the writer's snapshot), `latest` (the currently committed version), and `staged` (the writer's proposed bytes). It validates that the proof's byte ranges are pairwise disjoint and that the committed writer didn't modify any of the same ranges, then produces the merged result.

### Adaptive conflict policy

Three policy modes are available:

```
ConflictPolicy::Strict      : pure FCW; any block-level conflict aborts later writer
ConflictPolicy::SafeMerge   : merge when a valid MergeProof exists; otherwise abort (default)
ConflictPolicy::Adaptive    : runtime decision per commit, using expected-loss model
```

The adaptive expected-loss model:

```
E[loss_strict]      = conflict_rate · abort_cost
E[loss_safe_merge]  = P(corruption) · severity + conflict_rate · (1 − merge_success_rate) · abort_cost
```

Three EMA-smoothed metrics drive the decision: `conflict_rate`, `merge_success_rate`, `abort_rate`. During a configurable warmup (default 50 commits) the system defaults to SafeMerge; afterwards the Adaptive policy selects whichever strategy has the lower expected loss. Under a 120-writer stress benchmark where test code explicitly stages merge proofs, SafeMerge achieves **9.5× lower expected loss than Strict with no corruptions observed in that run**. The FUSE write path does not yet derive real merge proofs (tracked: bd-xuo95.28), so production writes currently use `MergeProof::Unsafe` and do not benefit from safe-merge until this is wired in.

### Sharded store for high concurrency

For multi-threaded workloads, `ShardedMvccStore` partitions version chains across N shards (one `RwLock<MvccShard>` each). Writers to different block ranges proceed without contention. Multi-shard transactions acquire locks in sorted order to prevent deadlocks, and the commit sequence is a lock-free `AtomicU64`.

---

## Deep Dive: Self-Healing Durability

FrankenFS can detect corruption during scrub cycles and recover corrupted data from fountain-coded repair symbols.

### RaptorQ fountain codes (RFC 6330)

Each block group stores a configurable overhead of repair symbols alongside its source data blocks. RaptorQ is a *rateless* erasure code: given `K` source blocks, it generates as many repair symbols as needed, and any `K` of the combined source + repair symbols are sufficient to recover all `K` source blocks. FrankenFS can therefore recover from arbitrary corruption patterns as long as total losses don't exceed the repair overhead.

### Bayesian durability autopilot

The repair-symbol overhead isn't a fixed constant. `DurabilityAutopilot` maintains a Beta posterior over per-block corruption probability, updated from every scrub-cycle observation:

```
posterior  ~  Beta(α + corrupted, β + clean)

E[loss]    =  P(unrecoverable | overhead) · data_loss_cost  +  overhead · storage_cost
```

`P(unrecoverable | overhead)` is the Beta-Binomial tail probability that more than `overhead · source_blocks` blocks are simultaneously corrupted. The autopilot grid-searches `[min_overhead, max_overhead]` (default 3–10%) for the minimum, with a 2× multiplier for metadata-critical groups.

### Four refresh policies

Repair symbols become stale when source blocks are modified.

| Policy | Trigger | Best for |
|---|---|---|
| **Eager** | Refresh on every write to the group | Metadata groups (can't afford stale symbols) |
| **Lazy** | Age timeout (default 30s) or scrub cycle | Data groups under light writes |
| **Adaptive** | Switches Eager/Lazy based on the corruption posterior | Groups with variable risk |
| **Hybrid** | First of: age timeout OR block-count threshold | Write-heavy groups needing tight staleness bounds |

`RefreshLossModel` formally compares these policies via expected-loss calculations across workload profiles. Under heavy writes, the Hybrid policy reduces p95 stale-window age compared to age-only in the benchmark surface; use the dated benchmark artifacts for exact percentages. The block-count trigger caps staleness at ~500 writes regardless of how fast they arrive.

### Stale-window SLO monitoring

`StaleWindowSlo` evaluates a percentile-based SLO continuously (default: p95 groups must have staleness < 60s AND < 5000 writes). When breached, a structured `repair_stale_window_slo_breach` event is emitted with offending percentile values, group counts, and threshold details.

### Mounted automatic repair

```
ffs mount IMAGE MOUNT --background-repair --background-scrub-ledger repair.jsonl
ffs mount IMAGE MOUNT --rw --background-repair --background-scrub-ledger repair.jsonl
```

- Read-only mounts run **detection-only** scrub by default. `--no-background-scrub` disables it; `--background-scrub` keeps detection without enabling writes.
- Read-write mounts keep scrub disabled by default; `--background-scrub` opts into detection-only monitoring; `--background-repair` enables real block recovery + repair-symbol refresh.
- The mount lifecycle owns the `ScrubDaemon`: cancellation is wired to mount shutdown, and the worker is joined on unmount.
- Read-only repair uses the direct backing-image authority. Read-write repair routes recovered source blocks through the mounted MVCC request-scope serializer so repair writes and client writes share the same conflict-resolution boundary; stale repair snapshots fail closed before mutation. The serialization contract is formalized in `docs/repair-writeback-serialization-contract.json` (57 KB) and `docs/design-repair-writeback-serialization.md`.

### Hostile-image safety (separate claim)

`security.hostile_image` is its own release-gated claim. The adversarial threat model in `security/adversarial_image_threat_model.json` defines how malformed images, hostile proof bundles, tampered repair ledgers, resource-exhaustion seeds, unsupported mount options, and unsafe operator-command combinations must be rejected, quarantined, capped, downgraded to detection-only, or preserved as evidence. Each containment scenario records the resource class, limit value/unit, enforcement point, observed counters, cleanup policy, and confined artifact paths used by release gates.

---

## Deep Dive: Writeback-Cache Epoch Barriers

FUSE kernel writeback-cache mode improves throughput by batching and reordering daemon write requests. This creates a tension with MVCC snapshot isolation: if writes arrive out of order, a reader might see a newer write before an older one that the application issued first.

### Six reordering scenarios

| Scenario | Risk |
|---|---|
| Disjoint write batching | Request order becomes de facto MVCC order; swapped delivery breaks commit sequencing |
| Adjacent write merge | MVCC sees fewer mutation boundaries than the application issued |
| Delayed page writeback | Metadata ops commit against stale snapshots that exclude acknowledged data |
| Metadata overtakes data | Namespace durability overtakes data durability |
| Flush before writeback | V1 contract says flush is non-durable; must not advance visible state |
| Fsync with pending writeback | Fsync acknowledgment would overstate what is actually committed |

### Per-inode epoch state machine

FrankenFS tracks three monotonically advancing epoch counters per inode:

```
staged_epoch  ≥  visible_epoch  ≥  durable_epoch
```

- **Staged.** Dirty pages have arrived from the kernel.
- **Visible.** Committed to MVCC, admissible for snapshot readers.
- **Durable.** Synced to stable storage.

Writes are staged into the current global epoch. Only `fsync` / `fsyncdir` advance visibility and durability. `flush` remains a non-durable lifecycle hook. Cross-epoch reordering is forbidden by construction.

### Six formal invariants

| # | Invariant | Statement |
|---|---|---|
| I1 | Snapshot Visibility Boundary | Readers see only epochs that crossed the daemon visibility barrier |
| I2 | Alias Order Preservation | Writes to the same logical block preserve source order within an epoch |
| I3 | Metadata-After-Data Dependency | Metadata ops that depend on earlier data must not become visible first |
| I4 | Sync Boundary Completeness | `fsync` / `fsyncdir` acknowledges only fully delivered + committed + synced epochs |
| I5 | Flush Non-Durability | `flush` never advances visible or durable epoch |
| I6 | Cross-Epoch Order | Reordering may occur only within a single barrier epoch |

Each invariant has an executable checker; the design lives in [`docs/design-writeback-cache-mvcc.md`](docs/design-writeback-cache-mvcc.md).

### 12-scenario crash matrix

The crash matrix exercises every combination of crash timing against the epoch state machine: buffered write before commit, after commit before sync, after fsync, during epoch advance, partial sync across inodes, multi-round sequences, and so on. Recovery resets each inode to `staged = visible = durable = last_durable_epoch`, and the invariant `visible == durable` is verified after every recovery, proving no partial epochs leak.

### The supported opt-in

The kernel `writeback_cache` FUSE option is **default off**. The only supported enablement path is:

```bash
ffs mount --rw --writeback-cache \
    --writeback-cache-gate           artifacts/writeback-cache/audit_gate.json \
    --writeback-cache-ordering-oracle artifacts/writeback-cache/ordering_oracle.json \
    --writeback-cache-crash-replay-oracle artifacts/writeback-cache/crash_replay_oracle.json \
    IMAGE MOUNTPOINT
```

All three artifacts must be `--require-accept`-validated:

```bash
ffs-harness validate-writeback-cache-audit       --gate FILE   --scenario-id ID --require-accept
ffs-harness validate-writeback-cache-ordering    --oracle FILE --scenario-id ID --require-accept
ffs-harness validate-writeback-cache-crash-replay --oracle FILE --scenario-id ID --require-accept
./scripts/e2e/ffs_writeback_cache_audit_e2e.sh
```

The crash/replay oracle artifact records all 12 crash-point IDs, the mounted operation trace, raw FUSE options, survivor sets, flush/fsync/fsyncdir observations, cancellation and repeated-write classification, stdout/stderr paths, cleanup status, unsupported-combination rejections, and the reproduction command. A disarmed `FFS_WRITEBACK_CACHE_KILL_SWITCH` and a matching host/lane manifest are also required before `ffs-cli` forwards the option.

---

## Deep Dive: Block I/O and Caching

`ffs-block` provides a pluggable I/O abstraction with an adaptive cache and coordinated write-back.

### Two I/O traits

FrankenFS has two complementary I/O traits in `ffs-block`. The byte-addressed trait is what `OpenFs` uses directly for parser-driven reads at fixed offsets; the block-addressed trait is what the ARC cache and MVCC adapter wrap.

```rust
// Byte-addressed (pread/pwrite semantics), used by parsers and OpenFs
pub trait ByteDevice: Send + Sync {
    fn len_bytes(&self) -> u64;
    fn read_exact_at (&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()>;
    fn write_all_at  (&self, cx: &Cx, offset: ByteOffset, buf: &[u8])     -> Result<()>;
    fn flush(&self, cx: &Cx) -> Result<()>;
    // ...
}

// Block-addressed, wrapping a ByteDevice + optional cache + MVCC integration
pub trait BlockDevice: Send + Sync {
    fn read_block (&self, cx: &Cx, block: BlockNumber)              -> Result<BlockBuf>;
    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()>;
    fn block_size (&self) -> u32;
    fn block_count(&self) -> u64;
    fn sync(&self, cx: &Cx) -> Result<()>;
}
```

The canonical concrete `ByteDevice` is `FileByteDevice`, which `OpenFs::open` constructs from a path. Every call takes `&Cx`, enabling cooperative cancellation and budget tracking at the lowest I/O layer. A companion `VectoredBlockDevice` trait adds scatter/gather with a default scalar implementation.

### Aligned buffers

`AlignedVec` provides heap-allocated byte vectors with configurable alignment (default 4096 bytes), enabling `O_DIRECT` and avoiding memcpy penalties. `BlockBuf` wraps an `AlignedVec` and tracks logical-to-physical mapping metadata.

### ARC cache (with optional S3-FIFO)

`ArcCache<D>` wraps any `BlockDevice` with an Adaptive Replacement Cache (ARC), a self-tuning algorithm that balances recency and frequency via four LRU lists (T1, T2, B1, B2). The S3-FIFO variant is also available and is benchmarked side-by-side in `crates/ffs-block/benches/arc_cache.rs`. Two write policies:

| Policy | Behavior | Use case |
|---|---|---|
| **WriteThrough** | Every `write_block` immediately hits the device | Read-only mounts, simple correctness |
| **WriteBack** | Writes stay in cache until `sync`; dirty blocks cannot be evicted | Write-heavy workloads requiring batched I/O |

### Backpressure and flush coordination

Write-back mode uses a two-watermark backpressure model:

- **High watermark** (default 0.80 dirty ratio): aggressive flush of all dirty blocks.
- **Critical watermark** (default 0.95): block new writes until dirty ratio drops below high.

A background flush daemon writes dirty blocks in configurable batches with budget-aware throttling that reduces batch size when the `Cx` poll quota is low (avoiding starvation of other cooperative tasks).

`FlushPinToken` provides MVCC-aware coordination: the MVCC layer pins specific blocks during commit, preventing eviction or flush until the transaction is fully visible. This guarantees that a partially-committed transaction's blocks aren't flushed in an inconsistent order.

---

## Deep Dive: Format Detection and Dual-Personality Parsing

FrankenFS supports both ext4 and btrfs from a single binary. Format detection happens at mount time by probing the superblock at format-specific offsets.

### Superblock probing

```
ext4 :  offset 1024,  size 1024 bytes,  magic 0xEF53      at offset 0x38
btrfs:  offset 65536, size 4096 bytes,  magic "_BHRfS_M"  at offset 0x40
```

`OpenFs::open()` reads both regions, attempts parsing in each format, and returns a `FsFlavor::Ext4(superblock)` or `FsFlavor::Btrfs(superblock)`. If neither magic matches, `DetectionError::UnsupportedImage` is returned. The detected flavor drives every subsequent dispatch: extent mapping, inode parsing, directory traversal, journal recovery.

### Pure parsing (no I/O)

`ffs-ondisk` takes `&[u8]` and returns typed structures with zero I/O. This enables:

- **Fuzz-friendly parsing.** Byte slices can be generated by proptest or libfuzzer without needing real images.
- **Snapshot testing.** Parse results can be serialized to JSON for golden-file comparison.
- **Cross-platform unit testing.** Parsing tests do not require Linux with FUSE.

### ext4 structures parsed

Superblock (106 fields, including `s_mmp_*`, `s_backup_bgs`, quota inode metadata), group descriptors (32-bit and 64-bit variants, with bitmap-checksum fields), inodes (mode, timestamps with nanosecond precision and post-2038 range, extent header/entries, inline data flag, encryption context), extent tree (header + index + leaf entries, up to 4 levels deep), journal superblock (JBD2 header, transaction IDs, V2/V3 checksums), fast-commit stream (HEAD/TAIL/INODE/ADD_RANGE/DEL_RANGE/CREAT/LINK/UNLINK/PAD tags), feature flags (compat, incompat, RO-compat with named bitfields), Flex BG, and MMP. Adversarial fixtures cover malformed every above.

### btrfs structures parsed

Superblock (including `sys_chunk_array`, backup roots), B-tree headers (level, generation, owner), leaf items (key + offset + size), chunk items (stripe mapping for single + DUP + RAID 0/1/5/6/10), root items (root tree, extent tree, fs tree, checksum tree, device tree, log tree), device items (geometry validation with zero-capacity rejection), inode + xattr + extent-data items, send-stream commands (23 command variants, attribute TLV encoding, CRC32C per command).

---

## Deep Dive: Journal Recovery

Two journal recovery systems coexist: JBD2 replay for ext4 compatibility-mode images, and a native WAL for MVCC transactions.

### JBD2 replay (ext4 compatibility)

When mounting an ext4 image with `needs_recovery` set, FrankenFS replays committed transactions:

1. **Scan.** Read journal blocks starting from the journal superblock's `s_start`.
2. **Parse.** Identify descriptor blocks (target block lists), commit blocks (transaction seals), revoke blocks (cancellation records).
3. **Apply.** For each committed transaction, write journaled data to target locations.
4. **Revoke.** Skip any target blocks later revoked.
5. **Finalize.** Clear `needs_recovery` and reset journal sequence numbers.

Replay is idempotent. V2/V3 checksums (CRC32C with optional UUID-seed) are verified end-to-end. Non-contiguous ext4 journal extents are supported.

### Ext4 fast-commit replay

`replay_fast_commit()` parses fast-commit tag streams, buffers operations until the `TAIL` commit, and forces fallback when the stream is truncated. Committed FC operations are processed after JBD2 replay: `Create` / `Link` / `Unlink` / `AddRange` / `DelRange` are logged as observational evidence (JBD2 provides the authoritative block-level recovery); `InodeUpdate` triggers a verification read.

### External-journal pairing

Data filesystems referencing an external journal device support paired-open replay via the library-level `OpenOptions::external_journal_path` field, with UUID and block-size validation and fail-fast errors when required recovery cannot be performed safely. Standalone `JOURNAL_DEV` images are detected and reported with operator guidance. The current `ffs-cli mount` does not surface this as a flag; the harness opens it directly through the library API (see `crates/ffs-harness/tests/ext4_journal_recovery.rs`).

### MVCC WAL (native mode)

The native WAL in `ffs-mvcc`:

- **WAL segments.** Variable-length records with CRC32C integrity, storing committed transaction data (block writes, merge proofs, commit sequences).
- **WAL writer.** Background task batching pending records and flushing with configurable sync policy.
- **WAL replay.** On startup, rebuilds the in-memory MVCC store, skipping records already applied (idempotent replay with sequence-based deduplication). `TailPolicy::Conservative` truncates incomplete tails; `TailPolicy::Aggressive` recovers from partial trailing records when sealed by CRC.
- **Crash matrix.** Five crash points (before record visible, after record before checksum, after checksum before sync, after sync before publish, repeated crash replay) each verified to produce correct recovery.

### btrfs tree-log replay

`replay_tree_log()` walks the tree-log when `log_root != 0`, returns items for FS-tree merge, and is wired into the mount path. Fuzz coverage includes multilevel synthesized trees, absent log roots, and equivalent chunk mappings.

---

## Deep Dive: Structured Concurrency with asupersync

FrankenFS uses [`asupersync`](https://github.com/Dicklesworthstone/asupersync) 0.3 for all async and concurrent operations. The design requires properties tokio cannot provide.

### Why not tokio?

| Requirement | asupersync | tokio |
|---|---|---|
| Structured concurrency (no orphan tasks) | `create_root_region` + `create_task` | Manual `JoinSet` management |
| Cooperative cancellation via capability context | `&Cx` threaded through all calls | `CancellationToken` (opt-in, not universal) |
| Cancel-correct channels (no data loss on cancel) | Two-phase `reserve()` / `send()` | `send()` can lose data on cancel |
| Deterministic testing | `LabRuntime` with virtual time + DPOR | Non-deterministic executor |
| Budget-aware operations | `Cx::budget()` with poll quotas | No built-in budget mechanism |

The entire `tokio`/`hyper`/`reqwest`/`axum`/`async-std`/`smol` ecosystem is forbidden; the project's CI enforces this via dependency scanning.

### Capability context (`Cx`)

Every I/O operation takes `&Cx` as its first parameter. The `Cx` carries:

- **Budget.** Remaining poll quota and deadline; enables cooperative yielding.
- **Cancellation.** Checked at every `cx.checkpoint()`; propagates cancel through the call stack.
- **Deadline.** Operations automatically fail if the deadline expires.
- **Pressure.** System pressure feedback for backpressure-aware algorithms.

There is no way to fabricate a `Cx` without an explicit grant from the runtime.

### Deterministic lab runtime

`LabRuntime` provides a virtual-time executor where task scheduling is deterministic for a given seed, DPOR (Dynamic Partial Order Reduction) explores different interleavings, timeouts use virtual time (tests run instantly), and correctness oracles can assert invariants at every scheduling point. This is how the 120-writer merge-proof stress reproduces concurrency bugs deterministically across seeds.

---

## Deep Dive: Block Allocation

`ffs-alloc` manages free space with bitmap-based tracking and goal-directed placement, inspired by ext4's `mballoc` and reimplemented in safe Rust.

- **Bitmap operations.** `bitmap_find_free`, `bitmap_find_contiguous`, `bitmap_count_free` are O(n) in group size but operate on L1-cacheable data (a 32K-block group's bitmap fits in 4KB). The `succinct/` module adds a rank/select structure for O(1) free-space queries on hot paths.
- **Goal-directed placement.** Three-tier strategy: goal group/block first, then nearby groups within a distance of 8, then full scan. Locality keeps related extents physically contiguous.
- **Orlov directory spreading.** New directories bias toward groups with above-average free inodes and low existing directory density, spreading the namespace tree across the disk.
- **Reserved-block protection.** Metadata blocks (superblock copies, group descriptor tables, inode tables, bitmap blocks) can never be allocated to file data. A two-phase validation marks reserved regions in a temporary bitmap before confirming any allocation.
- **Batch allocator.** `batch_alloc` benchmarks confirm linear scaling under buddy-system allocation across grouped requests.
- **Btrfs fragmentation-aware free run.** `OpenFs::largest_contiguous_free_run` reports the largest gap from block-group / extent-tree analysis instead of the conservative total-free upper bound.

---

## Deep Dive: Extent Tree and Block Mapping

File data in ext4 (and FrankenFS's native mode) is mapped via an extent tree, a compact B+tree stored in the inode's `i_block` field with optional overflow blocks.

```
ExtentMapping {
    logical_start: u64,    // File-relative block offset
    physical_start: u64,   // Disk-absolute block offset
    count:          u16,   // Number of contiguous blocks (max 32768)
    unwritten:      bool,  // Preallocated but not yet written (reads as zeros)
}
```

| Level | Location | Max entries | Coverage at 4KB blocks |
|---|---|---|---|
| Root | Inode `i_block[0..14]` (60 bytes) | 4 extents | 128 MB |
| Depth 1 | External blocks | 340 per block | ~43 GB |
| Depth 2 | Two-level index | 340 × 340 | ~14.5 TB |
| Depth 3 | Three-level index | ~39 million | ~4.9 PB |

**Operations:**

- `map_logical_to_physical`: binary search at each tree level; returns a mapping or a hole.
- `allocate_extent`: request contiguous physical blocks from `ffs-alloc`, create an extent, insert into the tree with mid-point splitting.
- `truncate_extents`: remove all extents beyond a logical boundary, free physical blocks, collapse empty index nodes.
- `mark_written`: clear the unwritten flag on preallocated extents, splitting at range boundaries when needed (produces up to 3 replacement extents).
- `punch_hole`: remove block mappings within a range without changing file size.

Indirect-block addressing is also supported for ext4 images without the `EXTENTS` feature: `resolve_indirect_block()` handles direct + single/double/triple indirect pointers.

---

## Deep Dive: Directory Indexing

Directory entries in ext4 use a two-level scheme: an htree provides block-level indexing, while entries within each block are stored as a linked list.

```
+--------+---------+----------+-----------+------+
| inode  | rec_len | name_len | file_type | name |
| (4B)   | (2B)    | (1B)     | (1B)      | (var)|
+--------+---------+----------+-----------+------+
```

Entries are 4-byte aligned. Deleted entries have `inode = 0` and their `rec_len` is coalesced with the previous entry (space reclamation without compaction). `DirBlockIter` parses without heap allocation.

### Hash tree (htree)

For directories with more than ~200 entries:

1. **Hash computation.** Half-MD4 or TEA hash (configurable per filesystem) with a 4-word seed.
2. **Index lookup.** Binary search over `(hash, block)` pairs.
3. **Leaf scan.** Linear scan within the leaf block for the exact filename match (handles hash collisions).

The htree provides O(log n) lookup for large directories vs O(n) for linear scan.

### Case-folding

`lookup_in_dir_block_casefold()` performs Unicode-lowercase comparison for `CASEFOLD`-flagged directories. Case-folded lookup + readdir are covered both at the harness level and in the FUSE E2E suite.

### Encryption (nokey mode)

`ENCRYPT`-flagged inodes are accepted at mount; encrypted filenames are surfaced as raw bytes to `readdir` / `lookup`. `FS_IOC_GET_ENCRYPTION_POLICY` (legacy `_IOW`) and `FS_IOC_GET_ENCRYPTION_POLICY_EX` (`_IOWR`) ioctls return v1/v2 policy contexts; `ENODATA` is returned for unencrypted inodes. Full decryption requires key management not in V1.

---

## Deep Dive: Extended Attributes

Extended attributes (xattrs) provide per-file key-value metadata outside the standard POSIX inode fields. FrankenFS supports the full ext4 xattr model.

### Namespace routing

| Namespace | Prefix | Permission | Typical use |
|---|---|---|---|
| User | `user.*` | File owner or `CAP_FOWNER` | Application metadata |
| System | `system.*` | `CAP_SYS_ADMIN` | POSIX ACLs (`posix_acl_access`, `posix_acl_default`) |
| Security | `security.*` | `CAP_SYS_ADMIN` | SELinux labels, IMA |
| Trusted | `trusted.*` | `CAP_SYS_ADMIN` | Privileged daemon data |

POSIX ACL namespaces (`system.posix_acl_access` / `system.posix_acl_default`) are differentially validated against `debugfs`, and the FUSE E2E suite covers mounted-path list/get behavior plus the missing-default `ENODATA` contract on regular files.

### Hybrid storage

1. **Inline.** Stored directly in the inode after `extra_isize`, sharing the inode's block I/O. Limited by remaining inode space (~100–200 bytes for a 256-byte inode).
2. **External block.** Separate block pointed to by `inode.file_acl`. Used when inline space is exhausted or values are large (up to 64 KB per value).

The set operation tries inline first, then spills to external. The get operation checks both locations.

### Create/Replace semantics

`XATTR_CREATE` fails with `EEXIST` if the attribute already exists; `XATTR_REPLACE` fails with `ENODATA` if it does not. Empty `listxattr` returns length 0; exact-fit zero-length probes succeed; missing-default `ENODATA` is preserved across the FUSE boundary.

---

## Deep Dive: Inode Lifecycle

```
group  = (ino - 1) / inodes_per_group
index  = (ino - 1) % inodes_per_group
block  = inode_table_block[group] + (index * inode_size) / block_size
offset = (index * inode_size) % block_size
```

### Timestamps (nanosecond precision, post-2038 safe)

| Field | When updated | ext4 field |
|---|---|---|
| `atime` | File read | `i_atime` + `i_atime_extra` |
| `mtime` | File data write | `i_mtime` + `i_mtime_extra` |
| `ctime` | Metadata change | `i_ctime` + `i_ctime_extra` |
| `crtime` | File creation | `i_crtime` + `i_crtime_extra` |

The `_extra` fields provide sub-second precision and extended epoch range.

### Checksum verification

Each inode includes a CRC32C checksum (`i_checksum_lo` + `i_checksum_hi`) computed over the inode bytes with the filesystem UUID as salt. FrankenFS validates on read and recomputes on write, detecting single-bit corruption in the inode table.

### Operations

- `read_inode`: locate, read containing block, parse, validate checksum.
- `write_inode`: recompute checksum, read-modify-write the containing block.
- `create_inode`: allocate from group's inode bitmap, initialize fields, write to table.
- Delete: clear inode bitmap bit, zero timestamps, update group free counts, free xattr blocks.
- `i_version`: bumps on every metadata mutation.

---

## Deep Dive: Background Scrub Pipeline

`ffs-repair::pipeline` scans block integrity, emits evidence for detected corruption, and orchestrates recovery when run in repair-enabled mode. Mount-time background scrub uses the same pipeline in detection-only mode by default.

### Scrub cycle

1. **Block scan.** Read every block in the group; compute CRC32C (compat) or BLAKE3 (native).
2. **Mismatch detection.** Compare against stored checksum; any difference is flagged.
3. **Severity classification.** Single-bit flips vs multi-byte vs unreadable.
4. **Evidence logging.** Emit `CorruptionDetected` with `corruption_kind` (e.g., `"checksum_mismatch"`), `severity` (`"error"`, `"critical"`), `blocks_affected`, and a human-readable `detail`.

### Recovery orchestration

1. **Load repair symbols.** Read RaptorQ symbols from the repair tail region.
2. **Decode.** Feed available source blocks + repair symbols into the RaptorQ decoder.
3. **Validate.** Verify recovered block's checksum.
4. **Write back.** Replace corrupted block; on RW mounts, route through the MVCC repair-writeback serializer.
5. **Refresh symbols.** Re-encode with the corrected data (generation number advances).

### Multi-host coordination

V1.x write-side repair is single-host only:

- A coordination record `.<image>.ffs-repair-owner.json` stores owning host's UUID, hostname, and lease TTL.
- Hosts attempt to claim ownership before mutating image data or repair symbols.
- Expired leases can be taken over with deterministic tie-breaking (UUID comparison).
- Read-only scrub (detection only) does not require ownership.

Design details: [`docs/design-multi-host-repair.md`](docs/design-multi-host-repair.md).

---

## Deep Dive: FUSE Request Lifecycle

```
1. begin_request_scope(cx, op)  →  acquire MVCC snapshot, check backpressure
2. execute operation             →  dispatch to ext4/btrfs handler in ffs-core
3. end_request_scope(cx, scope)  →  release snapshot, update metrics
```

`RequestScope` captures the MVCC snapshot at request start so all reads within a single FUSE callback see a consistent point-in-time view of the filesystem, even when concurrent writers are committing new versions.

### Backpressure and graceful degradation

When the system is under pressure (high dirty-cache ratio, long GC pauses, or external memory pressure):

- **Read operations.** Always proceed (readers never block).
- **Write operations.** May be delayed when dirty ratio exceeds the high watermark.
- **Metadata operations.** May be shed when system pressure reaches critical levels.

`DegradationFsm` tracks pressure-level transitions (`Normal → Warning → Degraded → Critical → Emergency`) monotonically so degradation decisions don't oscillate.

### Mount tuning constants

```
ATTR_TTL                      = 60 seconds  (RO images are immutable from the kernel side)
FUSE_MAX_READ_BYTES           = 16 MB
MAX_COALESCED_READ_SIZE       = 256 KB
BACKPRESSURE_THROTTLE_DELAY   = 5 ms
```

The worker thread count maps to kernel FUSE queue tuning parameters (`max_background`, `congestion_threshold`).

---

## Deep Dive: btrfs Tree Walk and Chunk Mapping

btrfs uses copy-on-write B-trees addressed by logical block addresses that must be translated to physical disk offsets via a chunk mapping layer.

### Logical-to-physical translation

1. **Bootstrap.** The superblock embeds a `sys_chunk_array` containing enough chunk entries to locate the chunk tree itself.
2. **Chunk lookup.** Find the chunk entry whose `[key.offset, key.offset + length)` range contains the target logical address.
3. **Stripe calculation.** For single-device images, `physical = stripe.offset + (logical - chunk.key.offset)`.

For RAID profiles (single, DUP, RAID0, RAID1, RAID5, RAID6, RAID10), stripe calculation accounts for stripe width, sub-stripe interleaving, and mirror selection. `BtrfsDeviceSet` dispatches across multi-device sets with mirror fallback.

### Tree walk algorithm

`walk_tree` performs a depth-first traversal of any btrfs B-tree (root tree, extent tree, fs tree, checksum tree, device tree, log tree):

1. Read the node at the given logical address (translate via chunk map).
2. Parse the header: level, generation, number of items, owner.
3. If **leaf** (level 0): parse all items and collect them.
4. If **internal** (level > 0): recursively walk each child pointer in key order.
5. **Cycle detection.** Maintain an `active_path` set of logical addresses; reject if a cycle is found.
6. **Depth bound.** Reject trees deeper than 7 levels (btrfs maximum).
7. **Visit deduplication.** `visited_nodes` set prevents re-reading shared subtrees (COW sharing).

### Key types

| Key type | Object ID | Item type | What it represents |
|---|---|---|---|
| `INODE_ITEM` | inode number | 1 | Inode metadata |
| `DIR_ITEM` | parent inode | 84 | Directory entry |
| `EXTENT_DATA` | inode number | 108 | File extent (inline data or disk reference) |
| `ROOT_ITEM` | tree ID | 132 | Root of a subvolume or internal tree |
| `CHUNK_ITEM` | logical offset | 228 | Chunk-to-physical mapping |

### Compressed extents

`btrfs_decompress()` handles ZLIB (flate2), LZO (lzokay-native), and ZSTD inline + regular extents with exact `ram_bytes` validation and malformed-frame rejection. All three codecs are wired into the read path and validated by harness coverage including a cross-page read slice through the decompressed view.

### Subvolume / snapshot selection

`BTRFS_IOC_INO_LOOKUP` follows the requested `treeid` contract: `treeid=0` reports the mounted subvolume objectid; explicit tree IDs walk their matching `ROOT_ITEM` fs tree; root-object lookups return a NUL-terminated empty path. `--subvol NAME` and `--snapshot NAME` select named trees through the mount open path, including FUSE E2E coverage for root scoping and `NotFound` errors.

### Send/receive parsing

`parse_send_stream()` parses the btrfs send-stream format (magic, version, per-command CRC32C, required `END` terminator, 23 command variants, attribute TLV encoding). Differential validation runs against upstream `btrfs receive --dump` on a CRC-valid synthetic stream.

---

## Deep Dive: Version Chain Compression

MVCC version chains grow with every write to a block. Without compression, a hot block with thousands of versions would consume unbounded memory.

### Identical-version deduplication

When a new version's bytes match the previous version (common for metadata "touched but unchanged"), the chain stores an `Identical` marker with zero data:

```
Version chain:  [Full(4KB), Identical, Identical, Full(4KB), Identical]
Memory:           4096        0          0          4096        0      =   8192 bytes
Without dedup:    4096      4096       4096         4096      4096     =  20480 bytes
```

Resolution walks backward from the `Identical` marker to find the nearest `Full` or compressed version.

### Block-level compression

| Variant | Compression | Best for |
|---|---|---|
| `Full(Vec<u8>)` | None | Hot blocks accessed frequently |
| `Zstd(Vec<u8>)` | Zstd | Cold blocks in long chains |
| `Brotli(Vec<u8>)` | Brotli | Maximum compression ratio |
| `Identical` | None (walk backward) | Metadata blocks touched but unchanged |

`CompressionPolicy` configures the algorithm and the chain depth at which compression kicks in.

### Chain-length capping and GC

A configurable maximum chain length per block triggers epoch-based reclamation (`crossbeam-epoch`) once no active snapshot needs the oldest versions. A critical chain length (4× the cap) triggers `ChainBackpressure`: writers to that block are rejected until GC catches up, preventing unbounded memory growth under pathological write patterns.

---

## Deep Dive: Conformance Harness

`ffs-harness` is the testing infrastructure that validates FrankenFS against real filesystem images, tracks feature parity, and runs every release-gate proof.

### Sparse fixtures

Real ext4/btrfs images are impractical to check into git. FrankenFS uses **sparse JSON fixtures**: files containing only the non-zero byte regions:

```json
{"offset": 1024,  "data": "0xEF530001..."}
{"offset": 2048,  "data": "..."}
```

`load_sparse_fixture()` reconstructs a full-size byte buffer that `ffs-ondisk` parses identically to a real image. Fixtures stay under a few KB while covering the full parse surface, and every fixture is now structurally pinned with exact-assertion gates (group descriptors, inodes, dir entries, deleted entries, xattr entries, checksum-tail entries, btrfs sys-chunk fields, devitem provenance, leaf slots, tree leaves).

### Golden-file conformance

Parse results are serialized to JSON and compared against golden files. If the parse output changes, the test fails with a diff showing exactly which fields changed.

### Metamorphic relations

Every checksum, parser, and reporting surface has metamorphic-relation proptests:

- `crc32c_append` associativity
- `ext4_chksum` associativity
- `dx_hash` zero-seed equivalence
- `ext4_casefold_key` idempotence
- `ext4_gdt_crc16` associativity + empty-suffix
- `btrfs_send_crc32c` foundational laws
- `btrfs_key_cmp` total-order laws
- `Ext4GroupDesc::parse_from_bytes` determinism
- `parse_from_image` determinism (ext4 + btrfs)
- `verify_*_checksum` pair determinism
- `batch_checksum` Blake3 variant
- `btrfs_inode_ref` round-trip
- `touch_*` version-bump dispatch invariants
- `bitmap` stamp/verify

The full enumerated catalog is snapshot-pinned as a "metamorphic seed catalog" so coverage cannot silently drift.

### Schema inventory

Every machine-readable artifact (release-gate, writeback-cache audit/ordering/crash-replay, repair confidence, repair corpus, soak/canary campaign, swarm operator/cache/tail latency, readiness lab truth graph, ambition evidence matrix, fuzz dashboard, mounted lane decision, agent mail reservation, hysteresis, reservation snapshot, authoritative manifest, parity audit) has its JSON shape pinned in a checked-in inventory with structural validators and drift detectors. 226 tracked insta snapshot pins protect the markdown/JSON of every emitted report.

### Parity tracking

`FEATURE_PARITY.md` is both human-readable and machine-parseable. The harness reads it to generate `ParityReport::current()` for the tracked feature-denominator printout; `parity_report_matches_feature_parity_md` enforces that mapping in CI. The B-series parity accounting presents rows as implemented, kernel-verified, or rejection-only instead of treating the markdown domain sum as an authoritative readiness score. Every feature is implemented (with a test ID), explicitly excluded (with a documented reason), or tracked as in-progress. None can silently fall out of scope.

### Metrics framework

Three metric types, all lock-free atomic:

| Type | Operation | Use case |
|---|---|---|
| **Counter** | `increment(n)` | Total operations, bytes, errors |
| **Gauge** | `set(val)` / `adjust(delta)` | Current cache size, active snapshots, dirty blocks |
| **Histogram** | `observe(value)` | Latency distributions with fixed buckets |

`MetricsRegistry` supports enable/disable (zero overhead when disabled), rolling-window snapshots, and JSON export. `noop_handle` provides a zero-cost placeholder for optional metric paths.

---

## Deep Dive: The `Cx` Capability Context

Almost every Rust async ecosystem uses ambient authority somewhere: a global executor, an implicit current task, a built-in clock. `asupersync`, and therefore FrankenFS, eliminates ambient authority by passing an explicit `Cx` capability into every call that might block or time out.

**Important:** FrankenFS itself is **synchronous Rust**. The `Cx` is a capability handle, not a future-driven runtime. Functions take `&Cx` and return `Result<T, FfsError>` directly; the cooperative yield point is the explicit `cx.checkpoint()` call. The async runtime primitives (region scoping via `runtime.state.create_root_region` / `create_task`, two-phase `reserve()`/`send()` channels, `LabRuntime`) live in the upstream `asupersync` crate; FrankenFS uses them only at the outermost runtime boundary (mainly in the `ffs-fuse` session loop and in tests).

### What's inside a `Cx` (conceptual model)

The exact field layout lives in the `asupersync` crate and is private; what callers see is the *capability surface*:

| Capability | Methods | What it does |
|---|---|---|
| **Cancellation** | `cx.checkpoint()` | Returns `Err` if cancelled or the deadline expired; call regularly inside loops. |
| **Budget** | `cx.budget()` → `Budget { poll_quota, … }` | Tells the caller how many cooperative "poll units" remain before yielding is preferred. |
| **Deadline** | `cx.budget().is_past_deadline(cx.now())` | `checkpoint` returns `Err` once the budget's deadline is past. |
| **Clock** | `cx.now()` | Virtualizable time source: real wall-clock in production, virtual time under `LabRuntime`. |
| **Waker** | `cx.waker()` | The underlying task waker; rarely used by application code. |
| **Pressure** | `SystemPressure` observer | Backpressure feedback for adaptive batch sizing. |

The `Cx` is **borrowed, not owned**. A function signature `fn read_block(&self, cx: &Cx, …)` literally cannot store the `Cx` past its callsite, so no background work can outlive the region that produced the context.

### Why this matters for a filesystem

1. **No accidental I/O in pure functions.** `Ext4Superblock::parse_from_bytes(&[u8])` cannot perform I/O because there is no `&Cx` in its signature. The Rust type system prevents the bug.
2. **Cancellation is universal.** When the FUSE layer cancels a request (kernel interrupt), every nested call sees the cancel at its next `checkpoint()`.
3. **Deadlines compose.** A FUSE callback can install a 5-second deadline; a sub-operation can derive a tighter 1-second context; the lower limit wins.
4. **Determinism in tests.** Under `LabRuntime`, every `Cx` checkpoint is a DPOR scheduling point. The runtime can reorder operations across these points to explore alternative schedules, making concurrency bugs reproducible across seeds.
5. **Budget-aware GC and flush.** Background workers consult `cx.budget()` and shrink their batch size when the quota is low, avoiding starvation of foreground requests.

### Common patterns (sync, as used in FrankenFS)

```rust
use asupersync::{Cx, Budget};
use ffs_error::FfsError;

// Tight inner loop with cooperative checkpoints
fn flush_batch(cx: &Cx, blocks: &[BlockNumber]) -> Result<(), FfsError> {
    let target_batch = if cx.budget().poll_quota < 256 { 8 } else { 64 };
    for chunk in blocks.chunks(target_batch) {
        flush_chunk(cx, chunk)?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    }
    Ok(())
}

// Test contexts have explicit budgets and deadlines
#[cfg(test)]
fn cx_with_short_deadline() -> Cx {
    let deadline = asupersync::types::Time::now()
        + asupersync::types::Duration::from_secs(1);
    Cx::for_testing_with_budget(Budget::new().with_deadline(deadline))
}
```

The asupersync async primitives (region scoping via `create_root_region` + `create_task`, two-phase `sender.reserve(cx).await` then `.send(value)` for cancel-correct channels) exist in the runtime and are used by the async parts of `ffs-fuse` (the FUSE session loop) and `asupersync` itself, but FrankenFS application code is synchronous.

### How `Cx` interacts with FUSE

The FUSE adapter (`ffs-fuse`) is the *root* of every `Cx` chain on the mount path. The kernel issues a FUSE request; the adapter wraps it in a new `Cx` with:

- Budget seeded by the adapter's queue-tuning configuration.
- Deadline derived from FUSE timeout policy.
- Cancel hook installed for kernel interrupts.
- Pressure observer linked to the dirty-cache watermark.

Every downstream call (read, write, lookup, repair, GC, scrub) receives this `Cx` or a derived sub-context. When the kernel-side request is cancelled, every nested operation observes the cancel within one `checkpoint()`.

---

## Deep Dive: Architectural Design Rationale

Why this codebase looks the way it does. These are the load-bearing design decisions; everything else is a consequence.

### Decision 1: 21 small crates, not 3 big ones

The natural alternative would be `ffs-core` (everything), `ffs-fuse` (FUSE adapter), `ffs-cli` (CLI). We chose 21 small crates with a strict DAG instead. The reasons:

1. **Pure parser isolation.** Without `ffs-ondisk` as its own crate, accidental I/O in a parser path becomes possible. Crate boundaries are the only universally-enforced "no `Cx`, no I/O" boundary.
2. **Test parallelism.** `cargo test --workspace` can compile and run 21 test suites in parallel; the same code in three big crates would serialize.
3. **Targeted CI.** A PR that only touches `ffs-extent` doesn't need to recompile `ffs-fuse`.
4. **Public-API surface.** The `ffs` facade re-exports only what's stable. Internal crate APIs can change freely.
5. **Fuzz target boundaries.** Each fuzz target imports a specific crate's API, providing structural input-space scoping.

The cost is more `Cargo.toml` files and a slightly slower clean build. The benefit is enforceable layering and a much faster incremental build.

### Decision 2: No tokio

The full asupersync rationale is in `AGENTS.md`. The short version: structured concurrency, cancel-correct channels, and deterministic stress testing are not adequate in tokio for a system where a single dropped write is a correctness violation. The cost of forbidding tokio is that the surrounding crate ecosystem (hyper, reqwest, axum, …) is unavailable. For a filesystem with no network surface, this is acceptable.

### Decision 3: Sparse JSON fixtures, not real images

Committed real images would be hundreds of megabytes. Sparse JSON fixtures encode only non-zero regions:

```json
{"offset": 1024, "data": "0xEF530001..."}
```

This keeps fixtures under a few KB while covering the full parser surface, and lets fuzzers generate "minimally non-zero" images that exercise edge cases without the noise of random byte sequences. Every fixture is structurally exact-asserted by `ffs-harness::SparseFixture` plus a fixture-content schema gate.

### Decision 4: Evidence ledger as first-class output

Every decision FrankenFS makes (every scrub, every commit, every policy switch, every backpressure activation) emits a JSONL record. The alternative would be `dmesg`-style printouts ("we did X") that humans read once and discard.

Treating evidence as a first-class output buys us:
- Structured operator queries (`jq`, `awk`, log shipping pipelines).
- Release-gate enforcement (the policy file demands specific evidence shapes).
- Post-mortem reproducibility (every decision is timestamped and parameterized).
- Independent verification (a third party can read the ledger without trusting FrankenFS code).

This is why the schema inventory and 226 tracked insta snapshots exist: an evidence shape that drifts silently is a regression as serious as a parser bug.

### Decision 5: Bayesian / expected-loss decision models, not heuristics

Every "should I do X or Y?" decision in FrankenFS could be a tuned constant. We chose Bayesian posteriors and expected-loss models because:

- They explain themselves. The evidence ledger records the posterior, the loss values, and the chosen action. Operators can reconstruct *why* a decision was made.
- They generalize. A new workload doesn't require re-tuning a constant; the posterior updates online.
- They compose. Multiple decisions made by the same model (refresh policy, conflict policy, overhead) share a coherent risk framework.

The cost is more code per decision (one model per knob) and the cognitive overhead of reading Bayesian posterior updates instead of an `if rate > 0.8`. The benefit is auditable, principled behavior.

### Decision 6: `#![forbid(unsafe_code)]` everywhere

The bug class most likely to corrupt a filesystem in kernel C is the bug class Rust's safety model eliminates. We forbid unsafe entirely instead of restricting it to "audited" islands, because:

- An audited island is a moving target. The audit decays as code changes around it.
- The performance cost is negligible for a FUSE filesystem (FUSE round-trip is ~10 µs; bounds checks are ~1 ns).
- It's verifiable by the compiler, which is the cheapest possible audit.

The cost: we can't use SIMD intrinsics directly; we rely on third-party safe crates (e.g., BLAKE3's SIMD path is wrapped in safe Rust by the upstream `blake3` crate).

### Decision 7: Spec-first, not translation

Translating C line-by-line would be faster initially and slower forever. Extracting behavior into specifications produces:
- Documentation that survives the translation.
- A type system aligned with what the code does, not what C let us do.
- A regression-test surface (the spec doc) independent of the implementation.

The cost is a 94-KB spec document that has to stay current. The benefit is that `ffs-extent` is 300 lines of Rust where `fs/ext4/extents.c` is 3,000 lines of C, and the Rust version is more obviously correct.

### Decision 8: Vendor a `fuser` patch

The crates.io `fuser` 0.17 does not expose ABI 7.40 features (unrestricted ioctls, certain modern operations) needed for full FrankenFS parity. We ship the patch in `vendor/fuser` and apply it via `[patch.crates-io]`. This:

- Keeps the upstream crate name (`fuser`) intact in `Cargo.toml`.
- Lets us submit upstream PRs without forking the project's identity.
- Localizes the patch so the vendored copy can be diffed and audited.

### Decision 9: Beads (`br`) for task tracking, not GitHub Issues

The project uses `.beads/issues.jsonl` as the canonical task store. Reasons:

- Local-first: agents can claim, update, and close issues without a network round-trip.
- Dependency-aware: `br ready` shows actionable work (no blockers); GitHub Issues has no graph semantics.
- Git-versioned: every issue change is a diff in `issues.jsonl`, reviewable in PR diffs.
- Multi-project hygiene: cross-project pollution is detectable via the source-aware queue-state check.

### Decision 10: 125 E2E gate scripts

Each E2E script is a single scenario class: writeback-cache audit, repair writeback route, mounted differential oracle, etc. They could be a single mega-test. They are separate scripts because:

- Each script can fail closed independently with a specific reason.
- Permissioned vs non-permissioned lanes are explicit at the script level, not implicit in a test argument.
- Capability-skip is a script's own decision, not a global toggle.
- Artifact paths are scoped per script, so a failure leaves a small directory rather than a giant artifact dump.

---

## Observability and Evidence

FrankenFS maintains a machine-readable audit trail for every significant decision across all subsystems.

### Evidence ledger (23 event types)

The evidence ledger is an append-only JSONL file. Each line is a self-contained `EvidenceRecord` with a nanosecond timestamp, event type, block group, and event-specific payload.

| Category | Events | Count |
|---|---|---|
| **Corruption & repair** | `CorruptionDetected`, `RepairAttempted`, `RepairSucceeded`, `RepairFailed`, `ScrubCycleComplete` | 5 |
| **MVCC transactions** | `TransactionCommit`, `TxnAborted`, `SerializationConflict`, `VersionGc`, `SnapshotAdvanced` | 5 |
| **Merge resolution** | `MergeProofChecked`, `MergeApplied`, `MergeRejected`, `PolicySwitched`, `ContentionSample` | 5 |
| **Durability policy** | `PolicyDecision`, `SymbolRefresh`, `DurabilityPolicyChanged`, `RefreshPolicyChanged` | 4 |
| **Writeback & flush** | `FlushBatch`, `BackpressureActivated`, `DirtyBlockDiscarded`, `WalRecovery` | 4 |

Abort *reasons* (FCW conflict, SSI cycle, timeout, durability failure, user abort, etc.) are carried as a separate `TxnAbortReason` payload inside the `TxnAborted` event rather than as top-level event types.

### Query presets

The CLI provides eight operator presets for common queries (`--preset`):

```bash
ffs evidence <ledger> --preset replay-anomalies     # WAL recovery + aborts + SSI conflicts
ffs evidence <ledger> --preset repair-failures      # Corruption + repair outcomes + scrub cycles
ffs evidence <ledger> --preset pressure-transitions # Backpressure + flush + policy changes
ffs evidence <ledger> --preset contention           # Merge proofs + policy switches + contention samples
ffs evidence <ledger> --preset metrics              # Metrics-only view
ffs evidence <ledger> --preset cache                # Cache-layer events
ffs evidence <ledger> --preset mvcc                 # MVCC-only event subset
ffs evidence <ledger> --preset repair-live          # Live repair activity tail
```

### Contention metrics

Three EMA-smoothed rates are sampled to the evidence ledger every 100 commits:

- `conflict_rate`: how often commits hit a newer version.
- `merge_success_rate`: how often conflicts resolve by merge (vs abort).
- `abort_rate`: how often commits are aborted overall.

These metrics drive the `PolicySwitched` event when the adaptive policy changes its effective strategy.

### Sample evidence records

Every `EvidenceRecord` serializes to a single JSONL line. The fixed fields are `timestamp_ns`, `event_type` (snake_case), and `block_group`. Event-specific detail payloads are flattened onto top-level fields named after the event family (`corruption`, `repair`, `scrub_cycle`, `policy`, `symbol_refresh`, `wal_recovery`, `transaction_commit`, `txn_aborted`, `serialization_conflict`, `version_gc`, `snapshot_advanced`, `flush_batch`, `backpressure_activated`, `dirty_block_discarded`, `durability_policy_changed`, `refresh_policy_changed`, `merge_proof_checked`, `merge_applied`, `merge_rejected`, `policy_switched`, `contention_sample`). Any field absent for a given record is omitted via `serde(skip_serializing_if = "Option::is_none")`.

A small illustrative sample (formatting wrapped for readability; the file itself is one record per line):

```jsonl
{"timestamp_ns":1717023401123456000,"event_type":"corruption_detected","block_group":1247,
 "corruption":{"blocks_affected":1,"corruption_kind":"checksum_mismatch","severity":"error",
               "detail":"single-bit flip at block 981234"}}

{"timestamp_ns":1717023401129880000,"event_type":"repair_attempted","block_group":1247,
 "repair":{"generation":42,"corrupt_count":1,"symbols_used":256,"symbols_available":269,
           "decoder_stats":{"peeled":253,"inactivated":3,"gauss_ops":12,"pivots_selected":3},
           "verify_pass":false}}

{"timestamp_ns":1717023401141204000,"event_type":"repair_succeeded","block_group":1247,
 "repair":{"generation":42,"corrupt_count":1,"symbols_used":256,"symbols_available":269,
           "decoder_stats":{"peeled":253,"inactivated":3,"gauss_ops":12,"pivots_selected":3},
           "verify_pass":true}}

{"timestamp_ns":1717023420009122000,"event_type":"scrub_cycle_complete","block_group":1247,
 "scrub_cycle":{"blocks_scanned":32768,"blocks_corrupt":1,"blocks_io_error":0,"findings_count":1}}

{"timestamp_ns":1717023420301772000,"event_type":"policy_decision","block_group":1247,
 "policy":{"overhead_ratio":0.054,"expected_loss":1.2e-7,"corruption_posterior":1.7e-3,
           "posterior_alpha":1.0,"posterior_beta":100.0,"risk_bound":1.0e-6,
           "symbols_selected":3686,"metadata_group":false,
           "decision":"increase overhead from 0.05 to 0.054"}}

{"timestamp_ns":1717023421118554000,"event_type":"policy_switched","block_group":0,
 "policy_switched":{"from_policy":"safe_merge","to_policy":"strict",
                    "expected_loss_delta":2.4e-3,"trigger_reason":"contention_rate_change"}}

{"timestamp_ns":1717023421804119000,"event_type":"backpressure_activated","block_group":2048,
 "backpressure_activated":{"dirty_ratio":0.812,"threshold":0.80}}

{"timestamp_ns":1717023421999000000,"event_type":"txn_aborted","block_group":0,
 "txn_aborted":{"txn_id":482,"reason":"fcw_conflict","read_set_size":4,"write_set_size":2}}
```

The exact field set in each detail struct (`CorruptionDetail`, `RepairDetail`, `ScrubCycleDetail`, …) is defined in `crates/ffs-repair/src/evidence.rs` and locked by serde round trips plus an exact JSONL golden contract. The ledger is line-oriented and append-only, so `jq`, `awk`, or any log-shipping pipeline (Vector, Fluent Bit, Promtail) can consume it without changes. The CLI's `--preset` flags wrap common `jq` filters for operator use.

### Operator query examples

```bash
# Top 10 block groups by corruption-detect count
jq -r 'select(.event_type=="corruption_detected") | .block_group' repair.jsonl \
  | sort | uniq -c | sort -rn | head -10

# Distribution of repair symbol-consumption counts
jq -r 'select(.event_type=="repair_succeeded") | .repair.symbols_used' repair.jsonl \
  | sort -n | uniq -c

# Adaptive policy switch timeline (tab-separated)
jq -r 'select(.event_type=="policy_switched")
       | [.timestamp_ns, .policy_switched.from_policy, .policy_switched.to_policy, .policy_switched.expected_loss_delta]
       | @tsv' repair.jsonl

# All events in a specific block group
jq -r 'select(.block_group == 1247)' repair.jsonl

# All corruption-detected events whose detail string mentions a given block
jq -r 'select(.event_type=="corruption_detected" and (.corruption.detail|test("981234")))' repair.jsonl

# Abort reasons breakdown
jq -r 'select(.event_type=="txn_aborted") | .txn_aborted.reason' repair.jsonl \
  | sort | uniq -c | sort -rn
```

### Tracing layer

In addition to the structured ledger, FrankenFS uses the `tracing` crate for live diagnostics. Every operation creates a span carrying `Cx` deadline, budget, snapshot id, and operation id. Filter at any level:

```bash
RUST_LOG=ffs_core=debug,ffs_repair=trace,ffs_mvcc=info cargo run -p ffs-cli -- mount IMAGE MOUNT
```

The `tracing-subscriber` integration supports JSON output for machine-readable logs via the `--log-format json` CLI flag or the `FFS_LOG_FORMAT=json` environment variable (precedence: `--log-format` > `FFS_LOG_FORMAT` > `human`), useful when shipping to centralized observability stacks.

---

## Evidence, Release Gates, and Readiness

`ParityReport::current()` currently prints 97/97 rows in the tracked feature denominator. That is feature-matrix accounting, not a production-readiness claim; the B-series view keeps implemented rows, kernel-verified rows, and rejection-only rows in separate columns before README wording can strengthen. A checked-in release-gate policy and proof-bundle artifact define when a claim can move beyond experimental.

### Release-gate policy v1

`tests/release-gates/release_gate_policy_v1.json` maps every public claim class to the required proof-bundle lanes, thresholds, kill switches, remediation beads, and explicit non-goals. Examples:

| Public claim | Previous state | Target state | Required lanes |
|---|---|---|---|
| `mount.rw.ext4` / `mount.rw.btrfs` | `experimental` | `validated` | `fuse`, `conformance`, `release_gates` |
| `repair.rw.writeback` | `detection_only` | `mutating_repair` | `repair_lab`, `crash_replay`, `release_gates` |
| `writeback_cache` | `off_by_default` | `opt_in_supported` | `writeback_cache`, `crash_replay`, `release_gates` |
| `swarm.responsiveness` | `local_smoke_only` | `authoritative_large_host` | `swarm_workload_harness`, `swarm_tail_latency`, `adaptive_runtime` |
| `security.hostile_image` | `advisory_only` | `containment_proven` | `differential_oracle`, `repair_lab`, `release_gates` |
| `performance.baseline` | `quarantined_partial` | `current_evidence` | `performance`, `release_gates` |
| `operational.soak_canary` | `smoke_only` | `nightly_canary_proven` | `swarm_workload_harness`, `release_gates` |

Kill switches downgrade target state to `disabled` (on stale evidence) or `hidden` (on missing evidence). Thresholds ensure a lane is failed-closed when the proof-bundle lane count or error count crosses a boundary.

### Operator proof bundle

The proof-bundle artifact is rooted at `artifacts/proof/bundle/manifest.json`. Generate a local sample and validate the offline inspection path:

```bash
./scripts/e2e/ffs_proof_bundle_e2e.sh

rch exec -- cargo run -p ffs-harness -- validate-proof-bundle \
    --bundle             artifacts/proof/bundle/manifest.json \
    --current-git-sha    "$(git rev-parse HEAD)" \
    --max-age-days       14 \
    --out                artifacts/proof/bundle/report.json \
    --summary-out        artifacts/proof/bundle/summary.md
```

The 14 required lanes: `conformance`, `xfstests`, `fuse`, `differential_oracle`, `repair_lab`, `crash_replay`, `performance`, `writeback_cache`, `scrub_repair_status`, `known_deferrals`, `release_gates`, `swarm_workload_harness`, `swarm_tail_latency`, `adaptive_runtime`.

Each lane preserves bundle id, git SHA, toolchain, kernel, mount capability, raw logs, gate inputs, artifact hashes, redaction policy, and reproduction command. Lane outcomes: `pass` means evidence met the lane contract; `fail` means product or policy failure; `skip` means explicit capability/scope deferral; `error` means harness or evidence-production failure.

### Advisory readiness lab

The non-permissioned readiness lab regenerates advisory contracts, host simulation, RCH dry-run schedules, truth-graph summaries, xfstests handoff packets, NUMA/p99 replay reports, and readiness-dashboard rows without executing xfstests, mounted mutation campaigns, or large-host workloads. Every artifact carries `product_evidence_claim=none` and a release-gate effect equivalent to `advisory_only_no_public_readiness_change`.

```bash
AGENT_NAME="${AGENT_NAME:-operator}" ./scripts/e2e/ffs_readiness_lab_e2e.sh
```

### Permissioned campaign broker

Broker packets are operator handoff material for evidence campaigns that need explicit permission (xfstests, large-host swarm). They make the pending commands reproducible, but they are not executed evidence and **cannot** upgrade `xfstests.baseline` or `swarm.responsiveness` public wording. The ACK boundaries are exact strings:

```
XFSTESTS_REAL_RUN_ACK = xfstests-may-mutate-test-and-scratch-devices
FFS_SWARM_WORKLOAD_REAL_RUN_ACK = swarm-workload-may-use-permissioned-large-host
```

```bash
./scripts/e2e/ffs_permissioned_campaign_broker_e2e.sh
```

### Three writeback-cache artifacts

The only supported kernel `writeback_cache` path is gated by three accepted artifacts produced or checked by:

```bash
ffs-harness validate-writeback-cache-audit        --gate FILE   --scenario-id ID --require-accept
ffs-harness validate-writeback-cache-ordering     --oracle FILE --scenario-id ID --require-accept
ffs-harness validate-writeback-cache-crash-replay --oracle FILE --scenario-id ID --require-accept
./scripts/e2e/ffs_writeback_cache_audit_e2e.sh
```

Required scenario IDs include `writeback_cache_audit_fuser_options_default_off`, `writeback_cache_opt_in_fuser_options_enabled`, `writeback_cache_runtime_kill_switch_rejected`, `writeback_cache_ordering_accepts_complete_oracle`, `writeback_cache_ordering_rejects_missing_fsync`, `writeback_cache_ordering_rejects_missing_fsyncdir`, `writeback_cache_crash_replay_accepts_complete_matrix`, `writeback_cache_crash_replay_rejects_missing_crash_point`, `writeback_cache_crash_replay_rejects_survivor_mismatch`, `writeback_cache_crash_replay_rejects_flush_durability`, `writeback_cache_crash_replay_rejects_missing_fsyncdir`, and `writeback_cache_ext4_opt_in_flush_fsyncdir_reopen`.

### Proof-bundle structure (illustrative)

```json
{
  "bundle_id":          "bundle-2026-05-16-abc123",
  "generated_at":       "2026-05-16T12:34:56Z",
  "git_sha":            "0123abcd…",
  "toolchain":          "1.85.0-nightly (2026-04-10)",
  "kernel":             "6.17.0-14-generic",
  "host_class":         "small_host",
  "redaction_policy":   "v1",
  "reproduction_command": "rch exec -- cargo run -p ffs-harness -- validate-proof-bundle --bundle … --current-git-sha … --max-age-days 14",
  "lanes": [
    {
      "name":   "conformance",
      "status": "pass",
      "freshness_secs": 4321,
      "evidence": [
        { "role": "parity_report",        "path": "artifacts/parity/report.json",        "sha256": "…" },
        { "role": "kernel_reference",     "path": "artifacts/kernel_ref/ext4.json",      "sha256": "…" }
      ]
    },
    {
      "name":   "fuse",
      "status": "skip",
      "skip_reason":   "host_capability_skip",
      "failure_kind":  null,
      "remediation_hint": "install fuse3 and re-run with /dev/fuse accessible",
      "evidence": [
        { "role": "fuse_capability",      "path": "artifacts/fuse/fuse_capability.json", "sha256": "…" }
      ]
    },
    {
      "name":   "writeback_cache",
      "status": "pass",
      "evidence": [
        { "role": "audit_gate",           "path": "artifacts/writeback-cache/audit_gate.json",        "sha256": "…" },
        { "role": "ordering_oracle",      "path": "artifacts/writeback-cache/ordering_oracle.json",   "sha256": "…" },
        { "role": "crash_replay_oracle",  "path": "artifacts/writeback-cache/crash_replay_oracle.json","sha256": "…" }
      ]
    },
    {
      "name":   "swarm_tail_latency",
      "status": "fail",
      "failure_kind": "host_class_too_small",
      "remediation_hint": "rerun on host_class=permissioned_large_host",
      "evidence": [
        { "role": "p99_attribution_ledger", "path": "artifacts/swarm/p99.json",         "sha256": "…" }
      ]
    },
    { "name":"xfstests",          "status":"skip",  "skip_reason":"permissioned_run_required" },
    { "name":"adaptive_runtime",  "status":"skip",  "skip_reason":"manifest_missing" }
    // ... 8 more lanes (conformance, differential_oracle, repair_lab, crash_replay,
    //     performance, scrub_repair_status, known_deferrals, release_gates, swarm_workload_harness)
  ]
}
```

Each lane's `status` is one of `pass | fail | skip | error`; the release-gate policy maps the lane outcome plus the public-claim class to a final `state` per claim (`disabled | hidden | experimental | validated | …`).

### Allowed deferrals

- Local developer machines may skip mounted gates when `/dev/fuse`, `fusermount3`, kernel FUSE support, namespace permissions, or helper packages are missing. Permissioned CI / RCH lanes must fail closed when those deferrals are no longer acceptable.
- Crash-replay mounted write/reopen and repair-interruption lanes default to structured `skip` locally; `FFS_ENABLE_PERMISSIONED_CRASH_REPLAY=1` plus the explicit ACK and `FFS_PERMISSIONED_CRASH_REPLAY_RUNNER` are required for authoritative evidence.
- Full xfstests execution is a separate gate; curated mounted matrices may be used before the full xfstests environment is ready, but must not imply a current xfstests pass rate.
- Performance wording is bounded by the `bd-rchk5` closeout; correctness gates cannot silently upgrade throughput or latency claims beyond measured, comparable, and non-quarantined evidence.
- Soak / canary readiness is distinct from single-scenario E2E success.
- Hostile-image safety is explicitly delegated to the adversarial threat model and later containment / fuzz proofs.
- Kernel FUSE `writeback_cache` remains off by default and release-gated; the only enabled mount path is the explicit `--writeback-cache` request with all the gates above.
- These gates do not authorize production use of irreplaceable data. They define the evidence required before this README can reduce experimental caveats.

### Operational Readiness SLOs

Operational readiness SLOs are evaluated from the mounted evidence lane, especially `mounted_scenario_matrix.json`, before any README wording can move beyond experimental. The mounted lane must include `fuse_prod_fuse_lane_ext4_mount_unmount_probe` and `fuse_prod_btrfs_ro_mount_start`, and the release notes must tie those results back to `bd-rchk0.3.2`, `bd-rchk0.1.1`, `bd-rchk0.1.2`, `bd-rchk0.3.4`, `bd-rchk4.4`, and `bd-rchk5`.

The read-write repair gate remains blocked until `writeback_cache`, `repair.rw.writeback`, and the mounted repair matrix show that repair writeback can safely coexist with client writes. Missing, stale, or permission-gated evidence keeps the relevant public claim hidden or experimental.

---

## Algorithms and Mathematical Foundations

This section documents the non-trivial algorithms FrankenFS uses, why each was chosen, and which papers / RFCs underpin them. The goal is to make every consequential choice auditable.

### RaptorQ fountain codes (erasure coding theory)

**RFC 6330**. RaptorQ is a *systematic*, *rateless* erasure code. "Systematic" means the source symbols appear unmodified in the encoded stream; "rateless" means the encoder can emit unboundedly many repair symbols from a finite source.

Given `K` source symbols and `r` repair symbols, RaptorQ guarantees that any `K + ε` of the combined `K + r` symbols decode to all `K` source symbols, where `ε` is a small overhead (typically `< 2` symbols on average and `< 4` symbols at the 99% percentile, independent of `K`). This is the "ε-near-optimal" property that distinguishes RaptorQ from earlier Raptor codes and from MDS codes like Reed-Solomon (which have ε=0 but `O(K²)` decoding cost).

**Why fountain codes** for filesystem repair:

- **No redundancy explosion at scale.** A traditional `3+2` MDS code can lose 2 out of 5 blocks per group. FrankenFS can choose any overhead percentage (e.g., 5%) and tolerate that fraction of corruption *anywhere* in the group, with no fixed loss budget.
- **Streaming encode/decode.** RaptorQ's belief-propagation decoder runs in `O(K)` expected time, vs Reed-Solomon's `O(K²)`. For a 32K-block group at 4KB blocks (128 MB), this is the difference between sub-second and multi-minute decode.
- **Online repair-symbol top-up.** Adding repair capacity later requires emitting more symbols, not re-encoding the entire group.

**Encoding pipeline** (`ffs-repair::codec`):

```
source_blocks  ──►  intermediate_symbols  ──►  encoded_symbols
   (K)              (precompute, LU-like)        (K + r, on demand)
```

`asupersync` provides a pre-validated RaptorQ implementation that the FrankenFS repair pipeline drives directly; we do not re-implement the codec.

### Bayesian Beta-Binomial autopilot

The `DurabilityAutopilot` is a Bayesian agent that maintains a posterior over the per-block corruption probability `p`, then chooses the symbol overhead that minimizes expected loss.

**Conjugate model.** Block corruption is modeled as a Bernoulli process: each block is either corrupt or clean, independently. The conjugate prior for a Bernoulli rate is the Beta distribution:

```
prior     :  p ~ Beta(α₀, β₀)         # uninformative default α₀=β₀=1
posterior :  p ~ Beta(α₀ + c, β₀ + n − c)
```

where `n` is the number of blocks scanned in the latest cycle and `c` is the number of corrupt blocks. The posterior mean is `(α₀ + c) / (α₀ + β₀ + n)`, and that is the point estimate the autopilot uses (`DurabilityAutopilot::posterior_mean()`). The posterior mode `(α₀ + c − 1) / (α₀ + β₀ + n − 2)` for `α + c > 1` is the maximum-a-posteriori alternative; FrankenFS chooses the mean because it is well-defined for all `α, β > 0` and matches the integrated expected-loss calculation.

**Beta-Binomial tail.** The probability of seeing more than `k` corruptions in a future group of `m` blocks, integrating over the posterior, is the Beta-Binomial tail:

```
P(X > k | α, β, m) = ∑_{j=k+1}^{m} C(m, j) · B(α + j, β + m − j) / B(α, β)
```

where `B(·,·)` is the Beta function. The autopilot computes this for each candidate overhead level; at overhead `o` the relevant `k = ⌊o · K⌋`, and `P(X > k)` is the probability that decoding will fail.

**Loss function.**

```
E[loss(o)] = P(unrecoverable | o, posterior) · data_loss_cost  +  o · storage_cost
```

The autopilot evaluates this for `o ∈ [min_overhead, max_overhead]` on a fine candidate grid stepping by `CANDIDATE_STEP = 0.001` (about 70 candidates over the default 3–10% range) and picks the minimizer. Metadata-critical groups apply a 2× multiplier to `data_loss_cost`, biasing toward higher overhead.

**Convergence properties.** Because Beta is conjugate to Bernoulli, the posterior updates are O(1) per observation. The posterior concentrates at rate `1/√n` (standard for Beta-Binomial models), and the autopilot's overhead choice becomes monotone in observed corruption density once `n` exceeds the first-update threshold.

### Expected-loss decision rule (adaptive conflict policy)

The adaptive conflict policy is a single-step decision-theoretic agent:

```
choose argmin  E[loss_strict],     E[loss_safe_merge]
       a∈A
```

where the actions are `A = {Strict, SafeMerge}` and the loss model is:

```
E[loss_strict]      = conflict_rate · abort_cost
E[loss_safe_merge]  = P(corruption) · severity
                    + conflict_rate · (1 − merge_success_rate) · abort_cost
```

`abort_cost` and `severity` are tunable scalars; the three rate terms are EMA-tracked. Under a 120-writer stress, SafeMerge runs 9.5× lower expected loss than Strict because the second term is small (merge proofs hold for the disjoint-byte-range workload), while the first term in `E[loss_strict]` dominates (`abort_cost · conflict_rate ≈ 0.95 · 0.7 ≈ 0.665`).

### Exponentially-weighted moving average (EMA) contention tracking

For an observation `x_t` at step `t`:

```
ema_t = α · x_t + (1 − α) · ema_{t−1}
```

With `α = 0.1` (default), the EMA's effective memory is about `1/α = 10` samples. Three streams are tracked:

- `conflict_rate`: fraction of commits that hit a newer version
- `merge_success_rate`: fraction of conflicts resolved by merge (vs abort)
- `abort_rate`: fraction of commits aborted

EMAs are sampled to the evidence ledger every 100 commits as `ContentionSample` events, providing a slow-rolling view of policy effectiveness.

### Adaptive Replacement Cache (ARC)

`ArcCache<D>` implements the algorithm from Megiddo and Modha (FAST '03, "ARC: A Self-Tuning, Low Overhead Replacement Cache"). ARC maintains four lists:

| List | Contents | Purpose |
|---|---|---|
| **T1** | Recently inserted entries seen once | Captures recency-favoring workloads |
| **T2** | Entries seen at least twice | Captures frequency-favoring workloads |
| **B1** | Ghost entries (keys only) recently evicted from T1 | Tracks recency misses |
| **B2** | Ghost entries recently evicted from T2 | Tracks frequency misses |

The split between T1 and T2 (parameter `p`) is tuned online: a hit in B1 grows T1 at the expense of T2, a hit in B2 does the opposite. This auto-tunes the recency-vs-frequency trade-off based on observed miss patterns, with no manual configuration. Worst-case cost is `O(1)` per access.

For comparison, FrankenFS also includes an **S3-FIFO** implementation (Yang et al, SOSP '23, "FIFO Queues are All You Need for Cache Eviction"), which approximates ARC's hit rate with three simple FIFO queues. This is useful when ARC's hash-table overhead is undesirable on very large caches. The two are benchmarked head-to-head in `crates/ffs-block/benches/arc_cache.rs`.

### Dynamic Partial Order Reduction (DPOR)

DPOR (Flanagan and Godefroid, POPL '05; refined by Abdulla, Aronis, Jonsson, Sagonas, POPL '14) is the algorithm underlying `LabRuntime`'s schedule exploration. Naively exploring all interleavings of `n` concurrent operations is `O(n!)`. DPOR prunes the search by recognizing that two transitions that commute (don't access overlapping memory) need only be explored in one order.

In `LabRuntime` terms: the runtime tracks the *happens-before* edges induced by `Cx::checkpoint()` calls, channel send/recv pairs, and `Mutex::lock` orderings. When exploring a new schedule, DPOR backtracks only at points where reordering could observe a different value, which dramatically reduces the explored schedule space while remaining sound.

This is what makes the 120-writer SafeMerge stress test reproducible across seeds: every run with the same seed explores the same canonical schedule order, so concurrency bugs surface deterministically.

### CRC32C (Castagnoli polynomial)

ext4 and btrfs both use CRC32C (polynomial `0x1EDC6F41`) for metadata checksums, not the older Ethernet CRC32 (polynomial `0x04C11DB7`). CRC32C has better burst-error properties (it detects all bursts up to 32 bits and is a Hamming-distance-6 code at typical message sizes), and modern x86 CPUs implement it as a single instruction (`CRC32` from SSE 4.2, ~1 ns per 8 bytes).

FrankenFS uses the `crc32c` crate, which selects the hardware path at runtime and falls back to a portable table-driven implementation. UUID-seeded variants (V2/V3 JBD2) compute `crc32c(uuid_bytes || data)` to bind the checksum to the specific filesystem.

### BLAKE3 (native-mode integrity)

For native-mode blocks (FrankenFS's own COW metadata), the integrity hash is BLAKE3, not CRC32C. BLAKE3 is a Merkle-tree-based cryptographic hash designed by O'Connor, Aumasson, Neves, and Wilcox-O'Hearn (2020). Properties relevant to FrankenFS:

- **Cryptographic strength.** BLAKE3 is collision-resistant under the standard Merkle-Damgård assumptions; a flipped bit can't be hidden behind a matching CRC.
- **SIMD parallelism.** The tree structure parallelizes naturally to any number of cores via Rayon. On a 16-core box, BLAKE3 hashes ~10 GB/s.
- **Incremental verification.** Sub-trees can be verified independently, useful for the future block-level dedup work.

CRC32C is preserved for compat-mode (so an ext4 image written by FrankenFS still validates under kernel mount), and BLAKE3 layers underneath for FrankenFS-internal structures.

### CRC32C vs BLAKE3: when each is used

| Property | CRC32C | BLAKE3 |
|---|---|---|
| **Output width** | 32 bits | 256 bits |
| **Algorithm class** | Linear CRC | Cryptographic Merkle-tree hash |
| **Collision resistance** | None (linear) | 2¹²⁸ (cryptographic) |
| **Hardware path** | SSE 4.2 `CRC32` instruction (~1 ns / 8 B) | AVX2 / AVX-512 SIMD via Rayon (~5–10 GB/s) |
| **Detects single-bit flip** | Yes | Yes |
| **Detects deliberate forgery** | No (linear, forgeable) | Yes |
| **Suitable for ext4 metadata** | Yes (kernel-compatible) | No (wrong on-disk format) |
| **Suitable for FrankenFS-native COW** | Yes, but layered under BLAKE3 | Primary |
| **Used for journal block integrity** | Yes (JBD2 V2/V3) | n/a |
| **Used for repair-symbol generation identity** | n/a | Yes |
| **Used for inode checksums (ext4)** | Yes (with UUID-seed) | n/a (native blocks only) |
| **Used for sparse fixture digests** | n/a | Yes |
| **Used for proof-bundle artifact sha256 fields** | n/a | No; uses SHA-256 from the `sha2` crate for compatibility with standard tooling |

**Rule of thumb:** if the byte goes back into an ext4/btrfs image that another tool will read, the checksum is CRC32C. If the byte lives in FrankenFS's own native data structures, the integrity hash is BLAKE3. If the byte is an artifact in a proof bundle or evidence digest, the hash is SHA-256 (via the `sha2` crate) so external `sha256sum` tooling works.

### Half-MD4 and TEA (ext4 htree hashes)

ext4 directories use hash trees indexed by either Half-MD4 (the lower 32 bits of MD4, mixed with a 4-word seed) or TEA (Tiny Encryption Algorithm in hash mode). Both are non-cryptographic; they only need uniform distribution and 4-word collision separation. FrankenFS dispatches both through `dx_hash(hash_version, name, seed)` in `ffs-ondisk::ext4`, with kernel-bit-exact output verified by golden fixtures and proptest equivalence MRs (`bd-ldp92`).

### Crossbeam epoch-based reclamation (EBR)

`crossbeam-epoch` provides EBR for MVCC version GC. The problem: when a reader is holding a `Snapshot { high: CommitSeq }`, no version older than that snapshot can be freed even if it's been superseded. EBR solves this without per-version reference counting:

1. Each thread enters / leaves *epochs* (a monotone counter).
2. Retired versions are placed in a per-epoch garbage list.
3. Garbage from epoch `e` can be reclaimed once all threads have advanced past `e`.

EBR's amortized cost is `O(1)` per access, and it avoids the read-side memory barriers that reference counting requires. The cost is bounded memory overhead: retired versions linger for at most one epoch advance.

### Two-phase reserve/commit channels (asupersync)

A standard `mpsc` channel has a fundamental cancel-correctness problem: if `send(x)` is cancelled mid-call (e.g., by a deadline), the value `x` may have already been placed in the channel, but the caller no longer knows. With cancellation in the middle, you can't tell whether the send succeeded or not.

asupersync's two-phase channels split `send` into:

```
let slot = chan.reserve(cx, value).await?;   // reserves capacity, holds value
slot.commit().await?;                         // publishes; cancelling this is safe
```

`reserve` is cancel-safe by construction: if cancelled, the value is dropped and capacity returns. `commit` is the only non-cancellable region, but it's a single atomic publish and bounded. This eliminates an entire class of mid-flight data loss bugs.

### Succinct rank/select bitmaps

`ffs-alloc::succinct` provides `rank(i)` ("how many 1-bits in `bits[0..i]`?") and `select(j)` ("position of the j-th 1-bit?") in `O(1)` time and `o(n)` extra space, using Jacobson-style two-level indices (super-blocks + blocks). This collapses block-allocator hot paths (finding the next free block, counting free blocks in a range) from `O(n)` to `O(1)`.

The trade-off vs raw bitmaps is the cost of rebuilding the index when bits flip. For filesystem allocation, where bit flips are batched per transaction, the rebuild amortizes well.

### Serializable Snapshot Isolation (SSI)

Snapshot isolation alone (`snapshot_read`, `optimistic_commit`) prevents most anomalies but admits *write skew*: two transactions read overlapping data and write disjoint data, where the combined effect violates a constraint. SSI (Cahill, Röhm, Fekete, SIGMOD '08, "Serializable Isolation for Snapshot Databases") adds rw-antidependency tracking: whenever transaction `T1`'s write is dependent on `T2`'s prior read of the same item, an edge is recorded. If a cycle of rw-edges forms, one transaction is aborted.

FrankenFS tracks these edges lazily inside the commit path in `ffs-mvcc` and aborts the committing transaction only when it is the pivot of a two-edge dangerous structure: a committed concurrent transaction read a block the committer writes, and the committer read a block written by a committed concurrent transaction. A single stale-read edge remains serializable and does not abort by itself. SSI-related aborts surface as the `SerializationConflict` evidence event with reason `TxnAbortReason::SsiCycle` and conflict type `two_edge_rw_antidependency_cycle`.

---

## Performance Characteristics

FrankenFS publishes benchmarks under `crates/*/benches/` (criterion-based) and
dated baselines under `benchmarks/`. The historical numbers below were collected
on commodity Linux hardware.

### Historical performance evidence (`v0.2.0` campaign)

The `v0.2.0` release consolidates a solo, negative-evidence-ledger-first
optimization campaign. The table mixes internal same-ELF mechanism A/Bs with
mounted **kernel** comparisons; the cited ledger row is authoritative about which
kind of comparison each result represents. Kept filesystem mutations were proven
byte-identical before timing, with btrfs images checked by `btrfs check` and ext4
images checked by `e2fsck`.

| Subsystem | Lever | Result | Commit |
|---|---|---|---|
| Metadata / directory | Name-index closes the create existence-check `O(N²)` | Generic-ELF campaign: **26× internal reduction**. ⚠️ The "approximately kernel parity" half of this claim is **withdrawn — measured false**: against a live kernel ext4 arm we are **`2.753659x` slower** on the matching workload. See [Converted claims](#converted-claims-measured-against-a-live-incumbent) | [`1fcd0b62`](https://github.com/Dicklesworthstone/frankenfs/commit/1fcd0b62) |
| Write allocation | Coalesce contiguous extents, `O(N²)→O(N)` | **120× at N=40k** | [`2aa92946`](https://github.com/Dicklesworthstone/frankenfs/commit/2aa92946) |
| Allocator | Binary range-overlap reserved-check | **up to 3110×** | [`af91cc18`](https://github.com/Dicklesworthstone/frankenfs/commit/af91cc18) |
| Journal replay | Memoize indirect-block resolution | fixes **2024×** re-read/mount | [`fe00c75e`](https://github.com/Dicklesworthstone/frankenfs/commit/fe00c75e) |
| Checksum | Incremental `crc32c` (branchless `gf2_matrix_times`) | **24.7×** vs full recompute | [`17380f69`](https://github.com/Dicklesworthstone/frankenfs/commit/17380f69) |
| Extent resolution | Binary-search leaf + index, `O(E)→O(log E)` | **up to 19×** | [`2785e425`](https://github.com/Dicklesworthstone/frankenfs/commit/2785e425) |
| Allocator | Skip re-reading unchanged bitmap for descriptor csum | **15.8× fewer delete preads** | [`b296dbdb`](https://github.com/Dicklesworthstone/frankenfs/commit/b296dbdb) |
| Directory hash | Word-at-a-time `extent_root_namespace` hash (SWAR) | **7.14×** | [`96c27663`](https://github.com/Dicklesworthstone/frankenfs/commit/96c27663) |
| MVCC | Skip per-read snapshot register/release | **5×** parallel random read | [`9376f4d6`](https://github.com/Dicklesworthstone/frankenfs/commit/9376f4d6) |
| btrfs metadata | Fan-out gate the prefetch pool | Generic-ELF campaign: **4.3×** internally (7× → 1.6× vs kernel); shipped-binary kernel gap is not yet re-measured | [`18fb0e88`](https://github.com/Dicklesworthstone/frankenfs/commit/18fb0e88) |
| CLI | jemalloc global allocator | Generic-ELF source A/B: create **1.26–1.6×**; the old “faster than kernel” production wording is withdrawn pending a shipped-binary rerun | [`14f443cb`](https://github.com/Dicklesworthstone/frankenfs/commit/14f443cb) |
| btrfs read | Read directly into caller buffer | Generic-ELF source A/B: **1.37× warm, RSS halved**; the old “beats kernel” production wording is withdrawn pending a shipped-binary rerun | [`54b0ae94`](https://github.com/Dicklesworthstone/frankenfs/commit/54b0ae94) |

#### Converted claims (measured against a live incumbent)

Every row in the table above is an **internal** before/after: it compares FrankenFS to a
previous FrankenFS, and says nothing about whether you should run FrankenFS instead of
what you already run. Converting one means re-measuring it with kernel ext4 or kernel
btrfs executing **live in the same invocation**. Of the 678 kept claims in our ledgers,
**5 carry such a ratio** — see [`docs/INCUMBENT_RATIO_COVERAGE.md`](docs/INCUMBENT_RATIO_COVERAGE.md).

**Converted, 2026-07-31: the create existence-check parity claim is refuted.**

The first row's *"approximately kernel parity"* was the only claim in this table asserting
we had caught the incumbent, which makes it the most load-bearing one here. Its matching
workload is 2,000 serial `O_CREAT|O_EXCL` creates into one directory, an `fsync` of the
parent, 2,000 deletes, and a second `fsync` — `O_EXCL` is exactly the existence check the
name-index was built to make cheap, and one directory is exactly the growing-`N` shape.

| | |
| --- | --- |
| **FrankenFS ÷ kernel ext4** | **`2.753659x` `[2.707500, 2.782302]` slower** |
| Kernel A/A null | `0.996217x [0.985593, 1.007951]`, spread `1.014618x` |
| FUSE A/A null | `0.995167x [0.988305, 1.004712]`, spread `1.011833x` |
| Effect vs twice-widest-null margin | clears `1.029449x` |
| Threads requested → **observed** | 1 → **1** on all four arms, pinning attested |
| Replication | 3/3 on one driver ELF: `2.760102x`, `2.780381x`, `2.795147x` |

We are not at parity. We are about 2.75 times slower. The `26×` internal reduction is
real and stands; what it bought was a much faster FrankenFS, not a competitive one.

**What could not be measured, and why it is not being quietly dropped.** The stronger
version of this test — does the gap *grow* with directory size, which would mean residual
`O(N²)` — was attempted three times at N=8,000 and refused all three times. The kernel A/A
null spread came in at `1.031631`, `1.033187`, and `1.027150` against a `1.025` ceiling.
Quadrupling the crossover blocks (32 → 128) barely moved it, so this is a **systematic
asymmetry between the two physical kernel images at that N, not sampling noise** — the
storm mutates its image, and the four-round Latin square balances arm *roles*, not the
history each image accumulates across rounds. The three point estimates clustered at
`3.24x`–`3.40x`. **They are not claims and must not be quoted.** Whether the gap grows
with `N` is open.

**Build-identity correction (`bd-b9dug`, 2026-07-25).** Ordinary
`cargo bench --profile release-perf` compiles FrankenFS code for Rust's generic
x86-64 baseline, while the performance distribution produced by
`scripts/build-perf.sh` uses fat LTO, `target-cpu=x86-64-v3`, and a CLI workload
PGO profile. The campaign's previously published ratios therefore describe the
generic benchmark ELF unless a row explicitly proves another executing ELF; they
must not be presented as measurements of the binary shipped by that script.

Fresh whole-binary checks on pinned `hz2` now identify both codegen and the
executing ELF. The allocator ratio changed from generic
**12.445408×** (`444f2807…a1cb3`) to witnessed-v3 **13.631067×**
(`fc40f87b…41955`), a 9.53% increase. The production JBD2 writer ratio
changed in the other direction, from generic **2.630522×**
(`8695daa5…2f899`) to witnessed-v3 **2.605531×**
(`f91979ff…8f433`), a 0.95% decrease. Every run preserved exact output and
used an approximately 1.000× A/A null. Both v3 results remain decisive on
their median-ratio CIs.

An earlier claimed v3 allocator result (12.122× and an 11.6% absolute-time
reduction) is withdrawn: its distinct ELF still self-reported
`compile_avx2=false,compile_fma=false`. Local `RUSTFLAGS`, global Cargo
`build.rustflags`, and a target-table Cargo config each failed to reach the
top-level bench under RCH. A distinct ELF is therefore necessary but not
sufficient evidence. The admitted route explicitly allowlisted `RUSTFLAGS`
through RCH, and both remote rustc plus the executing binary reported
AVX2+FMA. These v3 benchmark ELFs did **not** contain the CLI PGO profile.

Accordingly:

- Kernel-comparator wins remain historical generic-ELF results, but their
  attribution to the shipped binary is withdrawn. No direction or correction
  factor transfers to an exact v3+PGO workload without a rerun.
- Kernel-comparator losses remain generic-ELF routing evidence. Until the exact
  v3+PGO workload is rerun, none may support a “structural” or “irreducible”
  frontier claim or be treated as an upper bound.
- Internal algorithmic ratios remain valid historical generic-ELF, same-build
  comparisons because both arms used one ELF. Fresh v3 reruns show that their
  magnitudes can move in either direction, so they are not absolute
  production-throughput claims.
- No universal correction factor is applied. ISA/PGO sensitivity is
  workload-specific; the two fresh ratios moved by -0.95% and +9.53%.

The complete correction and retry contract are in
[`docs/BD_B9DUG_ISA_CORRECTION.md`](docs/BD_B9DUG_ISA_CORRECTION.md).

**Current honesty methodology.** New claims are gated on the median-ratio 95% confidence
interval against a paired null control; coefficient of variation is reported
as provenance but is never the decision gate. The corrected owned benchmark
executables self-report their own SHA-256 as their first program line so the
executing ELF, rather than an adjacent build artifact, identifies each run.
Wins are not best-of-N; they are
isomorphism-preserving (behaviour proven byte-identical before keeping), and
every newly *rejected* lever is recorded—with its null-control result and a concrete
retry condition — in the negative-evidence ledger
(`docs/NEGATIVE_EVIDENCE.md`, `docs/PERF_CAMPAIGN_FINAL.md`) rather than quietly
dropped. Historical rows predate this contract: the current preflight finds 205
of 281 rejected rows (73.0%) measurement-void. The numerator has stayed at 205
while seven admissible decisions were added, so this methodology is a forward
gate rather than a blanket retroactive certification.
The contract is mechanically enforced in the staged index:

```bash
python3 scripts/perf_ledger_preflight.py --install-hook
python3 scripts/perf_ledger_preflight.py \
  --candidate "proposed mechanism" --surface "target function or benchmark"
```

The installed pre-commit hook exits 2 for a new or modified REJECT lacking
either a counted mechanism or a same-invocation A/A null control with a
bootstrap median CI. A KEEP requires both that median-CI evidence and a full
SHA-256 self-reported by the executing ELF; a hash computed next to the run is
deliberately not accepted. The hook also refuses a positive CV gate or
threshold, including `CV < 5%` deferred into a retry predicate. CV may be
reported only as non-decision provenance. Candidate preflight exits 2 when the
target surface matches prior negative evidence and prints that row's retry
predicate. When `--surface` includes a qualified function or module identifier,
at least one prior row must name that identifier family; generic terms such as a
container type cannot make an unrelated frontier look closed. `--audit`
reproduces the whole-ledger census; `--self-test` validates the policy
predicates without invoking Cargo.
When honest scrutiny contradicted an earlier claim,
it was corrected in the open: a previously-reported "1.7× faster than kernel"
cold-read row flipped
sign under a corrected generic-ELF harness (about 1.42× slower there); that
generic-ELF kernel gap is now also awaiting a shipped v3+PGO rerun. See the
[CHANGELOG](CHANGELOG.md#v020--performance-campaign-2026-05-18--2026-07-11) for
the full per-subsystem win list and the reject ledger.

### Verification-gate results

| Subsystem | Workload | Result |
|---|---|---|
| Safe-merge under contention | 120 concurrent writers, append-only proof | Bench-only: **9.5× lower expected loss** than Strict FCW; no corruptions observed in that stress suite |
| Adaptive refresh hybrid trigger | Write-heavy group, age vs hybrid | p95 stale-window reduction tracked in benchmark artifacts; no fixed README percentage |
| Writeback-cache crash recovery | 12-scenario crash matrix | Epoch monotonicity preserved in every scenario; `visible == durable` after recovery |
| WAL replay determinism | 5 crash points | Idempotent in all 5; sequence-based dedup verified |
| MVCC merge-proof success | `bd-62jy8` criterion suite | Merge-resolution latency and success rate tracked across policies |

### Microbenchmark surface (11 criterion targets)

| Crate | Benchmark | What it measures |
|---|---|---|
| `ffs-block` | `arc_cache` | ARC vs S3-FIFO hit-rate + throughput on canonical workloads |
| `ffs-btree` | `bwtree_vs_locked` | COW B-tree vs `RwLock`-guarded B-tree |
| `ffs-alloc` | `bitmap_ops` | `find_free` / `find_contiguous` / `count_free` |
| `ffs-alloc` | `batch_alloc` | Buddy-system batched allocation |
| `ffs-extent` | `extent_resolve` | Logical→physical mapping latency at depth 1–3 |
| `ffs-fuse` | `mount_runtime` | FUSE round-trip latency per op type |
| `ffs-fuse` | `degraded_pressure` | Backpressure gate decision latency under load |
| `ffs-mvcc` | `wal_throughput` | WAL writes/sec with group-commit batching |
| `ffs-repair` | `scrub_codec` | RaptorQ encode/decode throughput |
| `ffs-harness` | `metadata_parse` | ext4 superblock + group-descriptor parse cost |
| `ffs-harness` | `ondisk_parse` | btrfs tree-walk parse throughput |

### Reproducing benchmarks

```bash
# Run portable diagnostic benchmarks. These generic x86-64 ELFs are not the
# shipped v3+PGO binary and must not be published as production-equivalent.
cargo bench --workspace

# Run an x86-64-v3 benchmark through RCH. Publication still requires the
# executing binary to print compile_avx2=true and compile_fma=true.
RUSTFLAGS='-C target-cpu=x86-64-v3' \
RCH_ENV_ALLOWLIST=RUSTFLAGS RCH_REQUIRE_REMOTE=1 \
env -u CARGO_TARGET_DIR rch --no-self-healing exec -- \
cargo bench --profile release-perf -p ffs-alloc --bench inode_alloc_cursor

# Single crate (e.g., MVCC WAL)
cargo bench -p ffs-mvcc --bench wal_throughput

# Compare against a saved baseline
./scripts/benchmark.sh --compare benchmarks/baseline-2026-05-03.json

# Build the portable diagnostic profile, keeping debuginfo for flamegraphs.
cargo build --workspace --profile release-perf

# Flamegraph workflow
./scripts/flamegraph_generate.sh --target all --samples 4000 --duration 120
```

`scripts/build-perf.sh` documents the shipped CLI performance configuration
(fat LTO + x86-64-v3 + PGO). A production-equivalent publication run must apply
that complete configuration to the benchmark, self-report the executing ELF
hash, prove output parity, and run the same-invocation A/A plus median-CI gate.
The generic commands above deliberately do not satisfy that claim.

### Methodology

- **Warmup.** Every measurement is preceded by 3 warmup iterations (criterion default).
- **Sample size.** Criterion runs ≥100 samples per benchmark, with outlier detection.
- **Isolation.** Benchmarks pin to one logical core when available; `taskset` is honored.
- **Reproducibility.** Each benchmark records host class, kernel, toolchain, git SHA, and is published as a `performance.baseline` proof-bundle lane artifact.
- **Quarantine policy.** Mounted-latency benchmarks live under a separate quarantine when they involve `/dev/fuse` capability availability; readiness wording cannot upgrade beyond the supported evidence tier.

The `performance.baseline` claim is governed by `bd-rchk5.x` family beads and the `release_gate_policy_v1.json` policy.

---

## Real-World Scenarios

Concrete situations where FrankenFS is the right tool, with the rough command shape for each.

### Forensic disk-image inspection

A `.img` from a seized SSD or recovered drive. You want to enumerate the namespace, dump inode metadata, and walk the extent tree without ever mounting (so the image can't accidentally be written to).

```bash
ffs inspect evidence.img --json
ffs info evidence.img --groups --journal --json > metadata.json
ffs dump inode 12345 evidence.img --json
ffs dump extents 12345 evidence.img --json
ffs dump dir 2 evidence.img --json    # walk root directory
```

All operations are pure-parse, no `sudo`, no FUSE module load. The pure `ffs-ondisk` crate operates on `&[u8]`, so a Python or Rust forensics tool can link `ffs-ondisk` directly and skip the CLI entirely.

### Bit-rot recovery on an old archive

You have a years-old btrfs backup image; one block group has silent corruption that `btrfs check` reports but `btrfs scrub` cannot repair (insufficient mirrors). If the image was previously sealed by `ffs repair` with repair symbols, you can recover offline:

```bash
# Inspect-only scrub (writes JSON report to stdout)
ffs scrub backup.img --json
# Repair pass: full-scrub option triggers exhaustive group sweep
ffs repair backup.img --full-scrub --rebuild-symbols --max-threads 8 --json
# Offline fsck with optional repair attempts
ffs fsck backup.img --repair --force --json
```

The Bayesian autopilot will have selected a per-group overhead at sealing time based on observed bit-flip rates; the `RepairSucceeded` event in `scrub.jsonl` records exactly which symbols were consumed.

### High-concurrency log-append workload

An application that appends to many files concurrently (a message broker, a metrics ingestion pipeline). The traditional `ext4 + JBD2` global lock serializes all writers; FrankenFS's `MergeProof::AppendOnly` resolves disjoint-tail merges without abort.

```bash
ffs mount log.img /mnt/log --rw --runtime-mode managed \
    --managed-unmount-timeout-secs 60 \
    --background-scrub --background-scrub-ledger scrub.jsonl
```

Set `ConflictPolicy::Adaptive` in your library-mode embedder (CLI does not yet expose this flag); the policy switches to `SafeMerge` once contention warms up, and `MergeApplied` events dominate `MergeRejected` in the evidence ledger.

### Storage engine research

A database engineer wants to prototype a new B-tree algorithm against real ext4-format blocks without writing a kernel module. The `ffs-btree` and `ffs-extent` crates provide ext4-compatible structures with `Cx`-aware async APIs:

```rust
use asupersync::Cx;
use ffs::{OpenFs, MountConfig};

async fn experiment(cx: &Cx, image: &Path) -> anyhow::Result<()> {
    let fs = OpenFs::open(cx, image, MountConfig::default()).await?;
    // walk extents, capture metrics, ...
    Ok(())
}
```

Library consumers depend only on the `ffs` facade crate; the FUSE layer is optional.

### Container / read-only root with self-healing

A container image with a read-only root filesystem benefits from automatic bit-rot recovery (cosmic rays, flaky storage). Mount the image read-only with detection + repair enabled:

```bash
ffs mount rootfs.img /var/lib/containers/0/rootfs \
    --background-repair --background-scrub-ledger /var/log/ffs-scrub.jsonl \
    --background-scrub-interval-secs 30
```

Recovered blocks are written back to the backing image (which must be writable on the host side); the ledger gives ops a forensic trail for every recovery.

### Backup integrity verification

Periodic verification that backup images are still recoverable, without mounting. Use the scrub-only path with the evidence ledger:

```bash
# Per-image JSON scrub report (the CLI prints to stdout).
for img in /backups/2026-*.img; do
  ffs scrub "$img" --json > "$img.summary.json"
done
```

For a durable JSONL audit trail with `CorruptionDetected` records rather than only a summary, mount the image read-only with `--background-scrub --background-scrub-ledger <path>`. The ledger is the operator's alerting source.

### Cross-format conversion

Read an ext4 image with `ffs inspect --json`, emit a structured view, and feed it to a downstream system that writes btrfs. Because both formats use the same `OpenFs` API, the conversion script is shorter and parser-divergence is impossible: both sides go through `ffs-ondisk`.

---

## Extended Walkthroughs

Two end-to-end sessions, copy-pasteable, that exercise the most interesting code paths.

### Walkthrough A: Mount a btrfs image with a specific subvolume + automatic repair

Goal: take a btrfs image with multiple subvolumes, mount the `home` subvolume read-only with detection-only scrub plus durable evidence logging, then drive a corruption-recovery cycle.

```bash
# 1. Confirm the image is btrfs and inspect its subvolumes.
cargo run -p ffs-cli -- inspect /data/btrfs.img --subvolumes --snapshots --json \
    | jq '.btrfs.subvolumes[] | {id, name, generation}'

# Expected output (sample):
# { "id": 256, "name": "home",     "generation": 18 }
# { "id": 257, "name": "var-log",  "generation": 18 }
# { "id": 258, "name": "snap-2026-05-01", "generation": 19 }

# 2. Mount the home subvolume read-only with detection-only scrub + ledger.
sudo cargo run -p ffs-cli -- mount /data/btrfs.img /mnt/home \
    --subvol home \
    --background-scrub-interval-secs 30 \
    --background-scrub-ledger /var/log/ffs-home.scrub.jsonl &
MOUNT_PID=$!

# 3. Verify the mount sees the expected subvolume.
ls /mnt/home/ | head
findmnt /mnt/home -o SOURCE,FSTYPE,OPTIONS

# 4. Synthesize a corruption (do NOT do this on real data).
# Find the inode and physical block via dump:
cargo run -p ffs-cli -- dump inode 256 /data/btrfs.img --json

# 5. Watch the evidence ledger live; when scrub detects the corruption,
#    the CorruptionDetected event will appear:
tail -F /var/log/ffs-home.scrub.jsonl | jq '
  select(.event_type == "corruption_detected" or .event_type == "scrub_cycle_complete")'

# 6. To actually recover (requires --background-repair), unmount and remount with
#    explicit repair permission:
sudo umount /mnt/home
wait $MOUNT_PID 2>/dev/null

sudo cargo run -p ffs-cli -- mount /data/btrfs.img /mnt/home \
    --subvol home --rw \
    --background-repair \
    --background-scrub-ledger /var/log/ffs-home.scrub.jsonl

# 7. After a scrub cycle, look for the repair sequence:
jq -r '
  select(.event_type == "repair_attempted"
      or .event_type == "repair_succeeded"
      or .event_type == "repair_failed")
  | [.timestamp_ns, .event_type, .block_group, .repair.generation,
     .repair.corrupt_count, .repair.symbols_used, .repair.verify_pass] | @tsv' \
    /var/log/ffs-home.scrub.jsonl
```

What you've exercised:
- btrfs subvolume selection via `--subvol`
- The `ScrubDaemon` lifecycle owned by the mount process
- Evidence ledger as the operator's source of truth (no `dmesg` required)
- Mounted automatic repair through the MVCC repair-writeback serializer on a RW mount

### Walkthrough B: Forensic ext4 inspection without mounting (no FUSE, no sudo)

Goal: inspect an ext4 image without ever loading the FUSE module or requiring root. Useful for forensic chain-of-custody scenarios where the image must not be modifiable.

```bash
# 1. Format detect + top-level summary.
cargo run -p ffs-cli -- inspect /evidence/disk.img --json \
  | jq '{flavor, ext4_features: .ext4.feature_flags, blocks: .ext4.block_count}'

# 2. Show superblock + groups + journal status in one report.
cargo run -p ffs-cli -- info /evidence/disk.img --groups --journal --json \
  > /reports/disk.fs-info.json

# 3. Identify the root inode (always 2 for ext4) and walk its entries.
cargo run -p ffs-cli -- dump dir 2 /evidence/disk.img --json \
  | jq '.entries[] | {ino, file_type, name}'

# 4. For each top-level entry that looks interesting, dump the inode and its extents.
for INO in $(jq -r '.entries[] | select(.name|test("^(home|var|root|tmp)$")) | .ino' < /tmp/dir2.json); do
  cargo run -p ffs-cli -- dump inode  "$INO" /evidence/disk.img --json > "/reports/inode_${INO}.json"
  cargo run -p ffs-cli -- dump extents "$INO" /evidence/disk.img --json > "/reports/extents_${INO}.json"
done

# 5. Cross-validate against the kernel reference (e2fsprogs debugfs) if installed.
sudo debugfs -R "dump <2> /tmp/ref-root-dump" /evidence/disk.img
# Compare your dump_dir output against the debugfs reference (structural fields only).

# 6. Run a checksum scrub WITHOUT any write authority. The scrub subcommand
#    emits a JSON summary on stdout; the ledger-producing flow (with
#    CorruptionDetected JSONL records) is the read-only `ffs mount` path
#    with --background-scrub --background-scrub-ledger.
cargo run -p ffs-cli -- scrub /evidence/disk.img --json \
  > /reports/disk.scrub.summary.json

# 7. For a forensic chain-of-custody mount, capture the per-event JSONL ledger
#    via a read-only mount that is detection-only by default:
sudo cargo run -p ffs-cli -- mount /evidence/disk.img /mnt/evidence-ro \
    --background-scrub --background-scrub-ledger /reports/disk.scrub.jsonl &
MOUNT_PID=$!
# ... wait for some scrub cycles to run, then unmount ...

# 8. If you see any CorruptionDetected events, classify them by severity.
jq -r 'select(.event_type=="corruption_detected")
       | [.block_group, .corruption.blocks_affected,
          .corruption.corruption_kind, .corruption.severity] | @tsv' \
    /reports/disk.scrub.jsonl \
  | sort | uniq -c | sort -rn
```

What you've exercised:
- `ffs-ondisk` pure parsing (no I/O capability needed beyond reading the file).
- `OpenFs` open-without-mount workflow.
- `dump` subcommands for low-level metadata extraction.
- `scrub` in pure detection mode with a JSONL ledger.
- Cross-validation against `e2fsprogs debugfs` (the official ext4 kernel-reference tool).

Neither walkthrough requires production-readiness wording or release-gate ACK; both work today on any commodity Linux machine with Rust nightly.

---

## API Cookbook (Rust)

The `ffs` facade crate re-exports the public surface of `ffs-core` (`pub use ffs_core::*;`). The FrankenFS public API is **synchronous Rust**: functions take `&asupersync::Cx` for budget, deadline, and cancellation, but they return `Result<T, FfsError>` directly. No `async fn`, no `.await`. Internally, `Cx::checkpoint()` is the cooperative yield point and lets the surrounding runtime schedule other work.

### 1. Open an image and walk the root directory

```rust
use anyhow::Result;
use asupersync::Cx;
use ffs::{OpenFs, FfsError};
use ffs_types::InodeNumber;
use std::path::Path;

// ext4 root inode is always 2 by convention; btrfs root also resolves
// to inode 2 through the convenience layer. InodeNumber is a tuple
// newtype around u64; the field is pub so the tuple constructor works
// in const context.
const ROOT_INO: InodeNumber = InodeNumber(2);

fn list_root(image: &Path) -> Result<()> {
    let cx = Cx::for_request();
    let fs = OpenFs::open(&cx, image)?;

    // Convenience methods on OpenFs dispatch by flavor (ext4 + btrfs)
    // and open a fresh RequestScope::empty() internally.
    let root_attr = fs.getattr(&cx, ROOT_INO)?;
    println!("root: perm={:o}  size={}", root_attr.perm, root_attr.size);

    // readdir returns the format-agnostic DirEntry { ino, offset, kind, name }
    for entry in fs.readdir(&cx, ROOT_INO, 0)? {
        println!("{:>10}  {:?}  {}",
            entry.ino,
            entry.kind,
            String::from_utf8_lossy(&entry.name));
    }
    Ok(())
}
```

The convenience layer (`getattr`, `readdir`, `lookup`, `read`, etc.) flavor-dispatches inside `OpenFs`'s `FsOps` trait implementation, so the same code works on ext4 and btrfs images. The ext4-specific low-level layer (`read_inode` returning `Ext4Inode`, `read_dir(&Ext4Inode)` returning `Vec<Ext4DirEntry>`) is also available for callers that need on-disk-format detail; that surface is gated on `ext4_superblock()` and will return `FfsError::Format("not an ext4 filesystem")` on a btrfs image. For scoped operation inside a longer-lived MVCC request, use the `*_with_scope` variants (`read_inode_attr_with_scope`, `read_dir_with_scope`).

### 2. Read a specific file by path

```rust
use ffs::vfs::RequestScope;
use std::ffi::OsStr;
use ffs_types::InodeNumber;

// Format-agnostic version: walk path components via FsOps::lookup,
// which dispatches by flavor inside OpenFs. Works for both ext4 and btrfs.
fn cat_file(image: &Path, path: &str) -> Result<Vec<u8>> {
    let cx = Cx::for_request();
    let fs = OpenFs::open(&cx, image)?;

    let mut ino = InodeNumber(2);  // both flavors expose root as inode 2
    for component in path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()) {
        let attr = fs.lookup(&cx, ino, OsStr::new(component))?;
        ino = attr.ino;
    }

    let attr  = fs.getattr(&cx, ino)?;
    let bytes = fs.read(&cx, ino, 0, attr.size as u32)?;
    Ok(bytes)
}
```

`getattr`, `lookup`, and `read` all dispatch on `FsFlavor` inside `OpenFs`'s `FsOps` impl, so the same code works for ext4 and btrfs. If you have an ext4 image and want the on-disk inode struct back at the same time, `fs.resolve_path(&cx, &scope, path)` returns `(InodeNumber, Ext4Inode)` in one call. That method requires an ext4 superblock and returns `FfsError::Format("not an ext4 filesystem")` on a btrfs image.

### 3. Mount via the library API (blocking)

```rust
use ffs_fuse::{mount, MountOptions, WritebackCacheMode};

fn run_mount(image: &Path, mountpoint: &Path) -> Result<()> {
    let cx = Cx::for_request();
    let fs = OpenFs::open(&cx, image)?;

    let options = MountOptions {
        read_only:        true,
        allow_other:      false,
        auto_unmount:     true,
        writeback_cache:  WritebackCacheMode::Disabled,
        ioctl_trace_path: None,
        worker_threads:   0,    // 0 = auto: min(available_parallelism, 8)
    };

    // mount() blocks the calling thread until unmount.
    mount(Box::new(fs), mountpoint, &options)?;
    Ok(())
}
```

For a non-blocking variant, use `ffs_fuse::mount_background`, which returns a `BackgroundSession` whose `Drop` triggers unmount. For managed-mode mounts with the backpressure gate and graceful unmount timeout, wrap `MountOptions` in `ffs_fuse::MountConfig { options, backpressure, unmount_timeout }`.

### 4. Run an offline scrub-and-repair workflow

There is no `OpenFs::scrub` method; scrubbing is the job of `ffs-repair`. The simplest pattern is to drive it through the CLI:

```bash
# Inspection-only scrub: writes a JSON summary to stdout.
ffs scrub /path/to/image.img --json
# Repair pass (full-group sweep). The Repair subcommand drives the
# ScrubWithRecovery pipeline; for a durable JSONL ledger, use the
# read-only `ffs mount` with --background-scrub-ledger.
ffs repair /path/to/image.img --full-scrub --json
```

Programmatic usage means assembling a `ScrubWithRecovery<'a, W>` pipeline (with the source-block layout, the symbol store, the block device, the autopilot, and an `EvidenceLedger<W>` writer), then passing it plus a `ScrubDaemonConfig` to `ScrubDaemon::new(pipeline, config)`. The real fields on `ScrubDaemonConfig` cover scheduling and backpressure tuning (`interval: Duration`, `budget_poll_quota_threshold: u32`, `backpressure_headroom_threshold: f32`, etc.); the `repair_enabled` and `ledger` choices are made when constructing the `ScrubWithRecovery` pipeline itself. Read `crates/ffs-repair/src/pipeline.rs` for the canonical construction site, or copy the call graph from `crates/ffs-cli/src/cmd_repair.rs`.

### 5. Iterate the evidence ledger

```rust
use ffs::repair::{EvidenceRecord, EvidenceEventType};
use std::fs::File;
use std::io::{BufRead, BufReader};

fn count_corruptions(path: &Path) -> Result<usize> {
    let reader = BufReader::new(File::open(path)?);
    let mut count = 0;
    for line in reader.lines() {
        let rec: EvidenceRecord = serde_json::from_str(&line?)?;
        if rec.event_type == EvidenceEventType::CorruptionDetected {
            // detail lives at rec.corruption (Option<CorruptionDetail>)
            if let Some(c) = &rec.corruption {
                eprintln!("  group {} blocks_affected={} severity={} kind={} detail={}",
                          rec.block_group, c.blocks_affected, c.severity,
                          c.corruption_kind, c.detail);
            }
            count += 1;
        }
    }
    Ok(count)
}
```

Note: `EvidenceEventType` variants are `CamelCase` in Rust, and serde-rename to `snake_case` in JSON. The detail payload is **not** under a generic `.detail` field; it lives on the typed sibling (`rec.corruption`, `rec.repair`, `rec.scrub_cycle`, …).

### 6. `Cx` budget and deadline (synchronous capability)

```rust
use asupersync::{Cx, Budget};
use ffs::FfsError;

fn budgeted_work(cx: &Cx) -> Result<(), FfsError> {
    // Inspect the budget before launching a batch.
    let target_batch = if cx.budget().poll_quota < 256 { 8 } else { 64 };
    for chunk in (0..1024_u64).step_by(target_batch) {
        do_chunk(cx, chunk)?;
        // Cooperative yield + cancellation point.
        // Returns Err if cancelled or the deadline expired.
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    }
    Ok(())
}

#[cfg(test)]
fn with_test_deadline_cx() -> Cx {
    // Budget builder for tests: an explicitly-expired or short-deadline Cx,
    // matching the real pattern in crates/ffs-block/src/lib.rs.
    let expired_budget = Budget::new().with_deadline(asupersync::types::Time::ZERO);
    Cx::for_testing_with_budget(expired_budget)
}
```

The full asupersync runtime surface (region scoping via `runtime.state.create_root_region` + `create_task`, two-phase `sender.reserve(cx).await` then `.send(value)` channels, the `LabRuntime` with virtual time + DPOR) lives in the upstream crate. FrankenFS itself is synchronous code that *uses* `Cx` for cancellation and budget but does not spawn async tasks from filesystem code paths. Async primitives are only invoked at the runtime root (e.g., the `ffs-fuse` session loop and `LabRuntime`-based stress tests).

### 7. Direct on-disk parsing (no I/O)

```rust
use ffs::ondisk::ext4::Ext4Superblock;

fn parse_superblock(image_bytes: &[u8]) -> Result<Ext4Superblock> {
    // ext4 superblock lives at offset 1024 and is 1024 bytes wide.
    // `parse_from_bytes` also takes the group-descriptor size hint
    // (default 32 for classic ext4, 64 with the 64-bit feature).
    let desc_size: u16 = 32;
    Ext4Superblock::parse_from_bytes(&image_bytes[1024..2048], desc_size).map_err(Into::into)
}
```

`ffs-ondisk` is `no_std`-friendly in spirit (it takes `&[u8]`) and performs zero I/O, which makes it a good dependency for forensic tools, fuzz harnesses, and unit tests on non-Linux hosts.

---

## Profiling, Tracing, and Debugging

### Tracing levels and filtering

```bash
RUST_LOG=ffs_core=debug,ffs_repair=trace,ffs_mvcc=info \
  cargo run -p ffs-cli -- mount IMAGE MOUNT --rw

# JSON-formatted logs for centralized ingestion (either flag or env var works;
# --log-format wins over FFS_LOG_FORMAT, which wins over the default of 'human').
RUST_LOG=ffs_core=info \
  cargo run -p ffs-cli -- --log-format json mount IMAGE MOUNT --rw 2> ffs.log.json
```

Every async operation creates a `tracing` span carrying:
- `op`: the operation name (`read`, `write`, `lookup`, ...)
- `ino`: the inode number where applicable
- `snapshot`: the MVCC snapshot id
- `cx_budget_remaining`: poll-quota remaining when the span entered
- `cx_deadline_ms`: milliseconds until deadline (if set)

### Flamegraph workflow

```bash
# Generate the canonical set of flamegraphs (cli_inspect, fuse_read, baseline diff)
./scripts/flamegraph_generate.sh --target cli --samples 4000 --duration 60

# Smoke-test flamegraph generation
./scripts/flamegraph_smoke.sh

# Flamegraph for an end-to-end mount workload
sudo cargo flamegraph -p ffs-cli --profile release-perf -- mount IMAGE MOUNT --rw
```

Built with `--profile release-perf` (opt-level 3 + debuginfo), flamegraphs reliably attribute hot ops to functions. The default `--release` profile uses `opt-level = "z"` for binary size, which loses inlining detail.

### Attaching `gdb` to a mounted FUSE filesystem

```bash
# Find the ffs-cli process
ps -ef | grep ffs-cli

# Attach without unmounting (FUSE keeps running)
sudo gdb -p <pid>
(gdb) info threads
(gdb) thread apply all bt
```

Because FrankenFS runs in userspace, no kernel-debugger setup is needed; standard `gdb` works on the live mount process. The `tracing` spans surface in `gdb` thread names when `tokio_console` style instrumentation is enabled (off by default).

### Reproducing a stress-test failure deterministically

The real `LabRuntime` pattern is synchronous: build a runtime with a seed, create a root region with a `Budget`, run synchronous code that uses `Cx::checkpoint()` as the scheduling point, then drain the runtime.

```rust
// In a #[test] using LabRuntime (canonical shape from
// crates/ffs-mvcc/tests/mvcc_stress_suite.rs).
use asupersync::lab::{LabRuntime, LabConfig};
use asupersync::{Budget, yield_now};

#[test]
fn reproduce_safe_merge_120_writers() {
    let seed = 0xDEADBEEF_u64;
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(4_000_000));
    let region    = runtime.state.create_root_region(Budget::INFINITE);
    let store     = std::sync::Arc::new(ffs_mvcc::ShardedMvccStore::new(8));

    for writer_id in 0..120_u64 {
        let store = store.clone();
        runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                for op in 0..300_u64 {
                    yield_now().await;     // cooperative scheduling point
                    let mut txn = store.begin();
                    // ... stage writes, attach merge proofs, commit ...
                    let _ = store.commit(txn);
                }
            });
    }

    runtime.run_until_quiescent();
}
```

The same seed produces the same DPOR exploration order, the same task interleavings, and the same merge-proof commit sequence. A failure observed at seed `0xDEADBEEF` reproduces locally with `cargo test reproduce_safe_merge_120_writers`. The existing stress tests live under `crates/ffs-mvcc/tests/mvcc_stress_suite.rs`.

### Reading evidence post-mortem

```bash
# Last 50 events
ffs evidence repair.jsonl --tail 50 --json

# Specific block group
jq -r 'select(.block_group==1247)' repair.jsonl

# Adaptive policy decisions over time
jq -r 'select(.event_type=="policy_decision")
       | [.timestamp_ns, .policy.overhead_ratio, .policy.expected_loss] | @tsv' repair.jsonl \
   | column -t

# Filter for "Replay anomalies" preset
ffs evidence repair.jsonl --preset replay-anomalies
```

### Operator runtime console (`ffs mount --console`)

Managed and per-core mounts can emit an operator-facing runtime console
artifact on shutdown:

```bash
# Managed mount: write the console snapshot to the default artifact path.
ffs mount image.img /mnt/ffs --runtime-mode managed --console

# Per-core mount: write JSON and a Markdown summary to explicit paths.
ffs mount image.img /mnt/ffs --runtime-mode per-core --rw --console \
  --console-json artifacts/runtime-console/run.json \
  --console-summary artifacts/runtime-console/run.md
```

The console turns existing runtime signals (request counters, throttled/shed
counts, degradation level, per-core request/cache distribution, cleanup status)
into a bounded, redacted, schema-pinned `runtime_console_report` artifact. It is
**operational observability only**: every artifact carries
`product_evidence_claim=none` and never promotes `swarm.responsiveness` or
`adaptive_runtime` readiness. The standard runtime mode has no managed metrics
surface, so `--console` requires `--runtime-mode managed` or `per-core`.

Validate a console artifact (non-permissioned, non-mutating):

```bash
ffs-harness validate-runtime-console --report artifacts/runtime-console/run.json
```

See [docs/mount-runtime-modes.md](docs/mount-runtime-modes.md#runtime-console-artifact-contract)
for field meanings, forbidden interpretations, and failure triage.

---

## Cross-Validation Methodology

Every parser and operator path in FrankenFS is validated against an external reference where one exists.

### debugfs differential validation (ext4)

For ext4, the reference is `debugfs` from `e2fsprogs`:

```bash
# Build a deterministic two-extent reference file
mkfs.ext4 -t ext4 -E lazy_itable_init=0 -m 0 -U <uuid> /tmp/ref.img <size>
debugfs -R "dump <inode> /tmp/ref_dump" /tmp/ref.img

# FrankenFS reads the same image
cargo run -p ffs-cli -- dump inode <inode> /tmp/ref.img --json > /tmp/ffs_dump.json

# Compare structured outputs
cargo test -p ffs-harness kernel_reference
```

The harness in `crates/ffs-harness/tests/kernel_reference.rs` regenerates these references and asserts field-by-field equality. Coverage includes `collect_extents` against `debugfs blocks`, POSIX ACL xattrs (`system.posix_acl_access`, `system.posix_acl_default`), and inode metadata.

### btrfs receive --dump differential validation

For btrfs send/receive, the reference is upstream `btrfs receive --dump`:

```bash
# CRC-valid synthetic send stream
cargo test -p ffs-harness btrfs_kernel_reference -- --nocapture
```

`crates/ffs-harness/tests/btrfs_kernel_reference.rs` builds a synthetic send stream with a valid CRC32C, parses it with both `parse_send_stream()` and `btrfs receive --dump`, and asserts the normalized command sequences match.

### Differential oracles

Beyond external references, FrankenFS has internal differential oracles:

- **Ext4 vs btrfs.** Semantically equivalent operations (read, lookup, getattr) produce equivalent observable behavior on equivalent fixtures. Cross-oracle arbitration handles disagreement and classifies it (parser-class vs host-class vs permission-class).
- **`OpenFs` vs `BtrfsContext`.** Direct-context tests against FUSE-mounted equivalents.
- **`MvccStore` vs `ShardedMvccStore`.** Single-shard correctness must equal multi-shard correctness for the same transaction log.
- **`bitmap_largest_free_run` vs naive oracle** (`bd-qd7oi`): succinct rank/select results must match a brute-force counter.

### Conformance fixtures

Real images are large; FrankenFS uses **sparse JSON fixtures** containing only non-zero byte regions. Every fixture is now under structural exact-assertion gates: group descriptors, inode entries, dir entries (including deleted entries and checksum tails), xattr entries, sparse superblocks, btrfs leaf slots, sys_chunk fields, devitem fields, and tree-log node mappings. The full enumerated catalog is snapshot-pinned to prevent silent drift.

### Metamorphic relations

For functions where there is no direct external reference, FrankenFS uses metamorphic-relation proptests: input perturbations whose effect on output must follow a known rule.

```
crc32c_append associativity:
   crc32c(append(a, b))    ==    crc32c_combine(crc32c(a), crc32c(b), len(b))

parse_from_image determinism:
   parse(image)            ==    parse(image)   ∀ image

stripe translation covariance (btrfs):
   physical(logical + k)   ==    physical(logical) + k   when k fits one stripe

chunk-order permutation invariance:
   parse(perm(chunks))     ==    parse(chunks)   for any permutation perm
```

The full catalog is in `metamorphic_seed_catalog` (snapshot-pinned), and the proptest implementations live alongside the code under test.

---

## What's in the Box

A short tour of the repository layout, for anyone cloning the source and wondering what each top-level directory contains.

```
frankenfs/
├── Cargo.toml                  Workspace root (21 members, [patch.crates-io] for vendored fuser)
├── Cargo.lock
├── README.md                   This file
├── CHANGELOG.md                Capability-area changelog (3,448 commits, 2026-02-09 → 2026-05-18)
├── AGENTS.md                   Operating doctrine for AI coding agents working here
├── LICENSE                     MIT (with OpenAI/Anthropic rider)
├── rust-toolchain.toml         Pinned nightly channel for edition 2024
├──
├── crates/                     21 workspace members (see Architecture)
│   ├── ffs-types/              On-disk newtypes + ParseError
│   ├── ffs-error/              21-variant FfsError
│   ├── ffs-ondisk/             Pure parsers (ext4 + btrfs)
│   ├── ffs-block/              BlockDevice trait, ARC, S3-FIFO, AlignedVec
│   ├── ffs-journal/            JBD2 + fast-commit + external-journal
│   ├── ffs-mvcc/               Version chains, conflict policy, WAL, compression
│   ├── ffs-btree/              B+tree + COW Bw-tree experiments
│   ├── ffs-alloc/              Buddy allocator + succinct rank/select
│   ├── ffs-extent/             Logical→physical extent mapping
│   ├── ffs-xattr/              4-namespace extended attributes
│   ├── ffs-inode/              Inode lifecycle + checksums
│   ├── ffs-dir/                htree + linear directories
│   ├── ffs-fuse/               FUSE adapter + per-core dispatcher
│   ├── ffs-repair/             RaptorQ + autopilot + ScrubDaemon + evidence
│   ├── ffs-core/               OpenFs orchestrator + FsOps trait
│   ├── ffs/                    Public facade (re-export of ffs-core)
│   ├── ffs-cli/                11-subcommand binary
│   ├── ffs-tui/                Live monitoring dashboard (ftui)
│   ├── ffs-harness/            Conformance + benchmarks + proof-bundle validators
│   ├── ffs-ext4/               Legacy extraction reference (not on runtime path)
│   └── ffs-btrfs/              Runtime btrfs tree-walk, COW tree, chunk mapping, delayed refs
│
├── conformance/                Shared sparse parser/conformance fixtures
│   ├── fixtures/               JSON fixtures with non-zero byte regions
│   └── golden/                 Additional golden artifacts
│
├── tests/                      Shared test inputs
│   ├── fixtures/               Generated images + golden inspect outputs
│   ├── fuzz_corpus/            Shared fuzz seeds
│   ├── release-gates/          release_gate_policy_v1.json (canonical policy)
│   ├── crash-replay-artifact/  12-scenario crash matrix templates
│   ├── btrfs-multidevice-corpus/
│   ├── btrfs-send-receive-corpus/
│   ├── casefold-corpus/
│   ├── chaos-replay-lab/
│   └── …                       (40+ subdirectories, one per scenario class)
│
├── fuzz/
│   └── fuzz_targets/           63 libfuzzer targets
│
├── scripts/
│   ├── verify_golden.sh        Canonical CI verification gate
│   ├── benchmark.sh            Criterion runner with baseline comparison
│   ├── benchmark_record.sh     Historical baseline pinning
│   ├── flamegraph_generate.sh  Flamegraph workflow
│   ├── run_e2e.sh              E2E suite orchestrator
│   ├── update-goldens.sh       Regenerate golden outputs (use with care)
│   └── e2e/                    121 tracked E2E gate scripts (one per scenario)
│
├── benchmarks/                 Saved baseline JSON manifests
├── baselines/                  Historical baseline archive
├── profiles/                   Flamegraph SVGs + perf records
├── artifacts/                  Proof-bundle and per-run artifacts (gitignored beyond samples)
│
├── docs/                       Design docs, manifests, runbooks, reports
├── security/                   adversarial_image_threat_model.json
├── vendor/                     vendor/fuser pinned to ABI 7.40 via [patch.crates-io]
├── .beads/                     issues.jsonl (source-aware tracker state; counts move with each close)
├── beads_compliance_audit/     Cross-pass bead-completion audit artifacts
└── ci-artifacts/               CI run outputs
```

### Binaries built by `cargo build --workspace`

| Binary | Crate | What it does |
|---|---|---|
| `ffs-cli` | `ffs-cli` | The 11-subcommand operator tool |
| `ffs-tui` | `ffs-tui` | Live TUI dashboard |
| `ffs-demo` | `ffs-repair` (`src/bin/ffs-demo.rs`) | Self-healing adoption-wedge demo |
| `ffs-harness` | `ffs-harness` | Conformance + proof-bundle validation tool |

---

## Fuzz Target Inventory

All 63 libfuzzer targets are in `fuzz/fuzz_targets/`. Each one is driven by `cargo fuzz run <target>` (with `cargo-fuzz` installed) or via the smoke-gate script. Target-specific corpora live under `fuzz/corpus/<target>/`; shared regression seeds remain under `tests/fuzz_corpus/`. A categorized listing:

### On-disk parser fuzzers (ext4)

| Target | What it fuzzes |
|---|---|
| `fuzz_detect_filesystem` | Magic-number probing at both ext4 (`0xEF53`@`0x38`) and btrfs (`_BHRfS_M`@`0x10040`) superblock offsets |
| `fuzz_ext4_metadata` | Superblock + group-descriptor decode (32-bit and 64-bit variants) |
| `fuzz_ext4_chksum` | CRC32C compute + verify against random buffers |
| `fuzz_ext4_checksums` | Group-descriptor / inode / extent-block checksums |
| `fuzz_ext4_stamp_verify_roundtrip` | Stamp-then-verify property on every metadata block type |
| `fuzz_ext4_group_desc_roundtrip` | `Ext4GroupDesc::parse_from_bytes` ↔ `to_bytes` round-trip |
| `fuzz_ext4_dir_extent` | Directory-block parsing + extent-tree traversal |
| `fuzz_ext4_extent_actual_len` | Extent length decoding (unwritten flag handling) |
| `fuzz_ext4_extra_bit_pack` | The packed `_extra` timestamp / extended-field encoding |
| `fuzz_ext4_xattr` | Inline + external xattr blocks across all 4 namespaces |
| `fuzz_ext4_htree_mmp` | Hash-tree (htree) directories plus MMP block decoding |
| `fuzz_ext4_casefold` | Case-folded directory lookup (Unicode normalization) |
| `fuzz_ext4_image_reader` | Whole-image read API at random offsets and sizes |
| `fuzz_ext4_fast_commit` | Fast-commit replay parser (HEAD / TAIL / ADD_RANGE / DEL_RANGE / CREAT / LINK / UNLINK / PAD) |
| `fuzz_verify_ext4_integrity` | End-to-end mount-time validation pipeline |

### On-disk parser fuzzers (btrfs)

| Target | What it fuzzes |
|---|---|
| `fuzz_btrfs_metadata` | Superblock + B-tree header decoding |
| `fuzz_btrfs_verify_superblock_checksum` | Superblock CRC32C validation |
| `fuzz_btrfs_tree_items` | Declared btrfs item-type constants in B-tree leaves (20 currently) |
| `fuzz_btrfs_tree_log` | Tree-log replay (`replay_tree_log` over synthesized log trees) |
| `fuzz_btrfs_chunk_mapping` | `sys_chunk_array` + chunk-tree resolution |
| `fuzz_btrfs_raid_profile` | Single / DUP / RAID0/1/5/6/10 stripe selection |
| `fuzz_btrfs_devitem` | DEV_ITEM parsing including geometry validation |
| `fuzz_btrfs_devitem_roundtrip` | Round-trip property |
| `fuzz_btrfs_inode_ref_payload` | INODE_REF payload structure |
| `fuzz_btrfs_parse_inode_refs` | Multi-ref enumeration |
| `fuzz_btrfs_send_stream` | Send-stream parsing with CRC32C-per-command + END terminator |
| `fuzz_cli_btrfs_parsers` | CLI-side btrfs parser entrypoints |

### Storage layer

| Target | What it fuzzes |
|---|---|
| `fuzz_block_aligned_vec` | `AlignedVec` allocation + boundary-handling at every alignment |
| `fuzz_block_mem_io_engine` | In-memory I/O engine simulator |
| `fuzz_btree_bw_tree` | COW B-tree (Bw-Tree) splits / merges under adversarial sequences |
| `fuzz_extent_tree` | Logical→physical mapping invariants |
| `fuzz_extent_cache_concurrent` | Extent cache under concurrent access |

### Allocation & namespace

| Target | What it fuzzes |
|---|---|
| `fuzz_alloc_bitmap` | Block/inode bitmap operations (find_free, find_contiguous, set_bit) |
| `fuzz_alloc_succinct` | Succinct rank/select bitmap correctness vs naive oracle |
| `fuzz_dir_operations` | add_entry / remove_entry / linear-scan / htree paths |
| `fuzz_inode_roundtrip` | Inode encode-decode round-trip across all flag combinations |
| `fuzz_xattr_parsing` | All 4 namespaces + inline + external block storage |
| `fuzz_file_handle` | NFS-style `name_to_handle_at` file-handle round-trip |
| `fuzz_path_component_validation` | Path component validation (length, NUL bytes, dot segments) |
| `fuzz_path_encoding_mount` | Mount-time path encoding edge cases |

### MVCC + journal

| Target | What it fuzzes |
|---|---|
| `fuzz_mvcc_operations` | Version-chain operations under adversarial commit sequences |
| `fuzz_mvcc_compression_resolve` | Zstd/Brotli-compressed version resolution + walking |
| `fuzz_wal_replay` | WAL crash-recovery replay with `TailPolicy::Conservative` and `Aggressive` |
| `fuzz_jbd2_replay` | JBD2 journal replay engine |
| `fuzz_openfs_mvcc_wal_recovery` | End-to-end mount-time WAL recovery |
| `fuzz_openfs_journal_replay` | End-to-end mount-time JBD2 replay |
| `fuzz_native_cow_recovery` | Native MVCC COW crash recovery |
| `fuzz_openfs_recovery` | Whole-`OpenFs` recovery pipeline |

### Repair pipeline

| Target | What it fuzzes |
|---|---|
| `fuzz_repair_symbols` | RaptorQ repair-symbol generation + parsing |
| `fuzz_repair_codec_roundtrip` | Encode-then-decode round-trip property |
| `fuzz_repair_evidence_ledger` | Evidence-ledger JSONL parsing under malformed input |
| `fuzz_por_authenticator` | Proof-of-Retrievability challenge-response correctness |
| `fuzz_lrc_repair` | Local Reconstruction Code fallback |

### FUSE surface

| Target | What it fuzzes |
|---|---|
| `fuzz_ioctl_dispatch` | All FUSE ioctl entry points (FIEMAP, EXT4_IOC_*, FS_IOC_*, BTRFS_IOC_*) |
| `fuzz_fuse_splice_mount` | FUSE splice/sendfile mount-side handling |

### Evidence, manifests, and dashboards

| Target | What it fuzzes |
|---|---|
| `fuzz_fuzz_dashboard` | Fuzz-dashboard JSON shape |
| `fuzz_fuzz_smoke_manifest` | Fuzz smoke manifest validators (drift detection, source paths) |
| `fuzz_verification_runner` | E2E `SCENARIO_RESULT` parser and script-conformance classifier |
| `fuzz_rch_capacity_preflight` | RCH capacity preflight report validator and fail-closed probe diagnostics |
| `fuzz_authoritative_lane_manifest` | Proof-bundle authoritative-lane manifest parser |
| `fuzz_perf_baseline` | Performance manifest validator |
| `fuzz_swarm_workload_harness` | Swarm workload harness manifest |

The full catalog is structurally pinned by a checked-in inventory snapshot, and `bd-0c2xy` guards target registration so a deleted or renamed target fails the fuzz-dashboard gate.

---

## Roadmap Beyond V1

The V1 surface (the tracked 97-row parity matrix) is implemented and tested. The bridge to "operationally validated" is governed by the release-gate policy. The following items are explicitly out of V1 and are likely V1.x or V2 candidates.

| Area | What's next | Why deferred |
|---|---|---|
| **Multi-host concurrent repair** | Coordinated write-side repair across hosts using a richer consensus primitive than optimistic leases | Single-host repair is sufficient for V1; multi-host needs a formal Byzantine-safe protocol design |
| **Encryption with key management** | Full fscrypt v2 read/write with key derivation, key revocation, and per-file IV scheduling | V1 only handles nokey mode (encrypted filenames as raw bytes); key plumbing is its own deliverable |
| **io_uring backend** | An `IoEngine` impl using `io_uring` for higher throughput on the block layer | Pluggable `IoEngine` trait already exists; the implementation requires a host-capability matrix |
| **macFUSE / WinFSP ports** | Mount surfaces for macOS (macFUSE) and Windows (WinFSP) | FUSE protocol surface is identical; vendored `fuser` would need parallel patches |
| **Snapshot-based replication** | Stream MVCC snapshots between hosts to replicate filesystem state | Builds on the existing `Snapshot` + WAL infrastructure; needs network transport |
| **Block-level dedup** | BLAKE3-keyed dedup table, COW reference counting | The native-mode BLAKE3 path already produces strong block identifiers |
| **Compressed MVCC pages** | Per-page Zstd/Brotli compression *of MVCC metadata*, separate from version data | Version-data compression is done; metadata compression needs spec work |
| **First-class CLI for adaptive conflict policy** | `--mvcc-policy {strict,safe-merge,adaptive}` on `ffs mount` | Currently library-only; CLI surface awaits broader operator experience |
| **NUMA-aware allocator: authoritative large-host evidence** | Per-NUMA-node block group preference *proven* to improve `swarm.responsiveness` on a permissioned 64+ core / 256GB+ host | The opt-in allocator hook, contract, runtime topology propagation, and the advisory `numa_allocation_placement_report` evidence lane are implemented; authoritative large-host proof remains gated on the permissioned campaign `bd-rchk0.53.8` |

These items are surfaced via the proof-bundle release-gate policy (`tests/release-gates/release_gate_policy_v1.json`) under explicit `non-goals` and `deferred` lists, so docs and release wording cannot accidentally claim coverage they don't have.

---

## Glossary

| Term | Definition |
|---|---|
| **ABI 7.40** | The FUSE protocol version supported by the vendored `fuser` 7.40 patch; required for unrestricted ioctls. |
| **Adaptive policy** | A `ConflictPolicy` mode that selects between `Strict` and `SafeMerge` per commit using EMA contention metrics and an expected-loss decision rule. |
| **ARC (Adaptive Replacement Cache)** | The Megiddo-Modha cache eviction algorithm with four lists (T1/T2/B1/B2) that auto-tunes the recency-vs-frequency split. |
| **`asupersync`** | The structured-concurrency runtime used in place of tokio (cancel-correct channels, `Cx` capability, `LabRuntime` with virtual time + DPOR). |
| **Beta-Binomial** | The distribution governing the number of corrupted blocks given a Beta-prior on corruption probability. Used by `DurabilityAutopilot` to compute `P(unrecoverable)`. |
| **BLAKE3** | The cryptographic Merkle-tree hash used for FrankenFS-native integrity checks; complements CRC32C used in compat mode. |
| **Block group** | The unit of ext4 / btrfs space allocation; FrankenFS tracks repair symbols, autopilot posteriors, and refresh policies per group. |
| **bd-rchk0.*** | The current parity-reality-check tracker prefix in `.beads/issues.jsonl`. |
| **`Cx` (capability context)** | An `asupersync` value carrying poll budget, deadline, cancellation, and pressure feedback; required by every I/O operation. |
| **CRC32C (Castagnoli)** | The CRC polynomial `0x1EDC6F41` used by ext4 and btrfs for metadata checksums; faster and stronger than the older Ethernet CRC32. |
| **DPOR (Dynamic Partial Order Reduction)** | The algorithm `LabRuntime` uses to deterministically explore concurrent schedules, pruning by commutativity. |
| **EBR (Epoch-Based Reclamation)** | The memory-reclamation strategy from `crossbeam-epoch` used to free retired MVCC versions safely. |
| **EMA (Exponentially-Weighted Moving Average)** | `ema_t = α·x_t + (1−α)·ema_{t−1}`; used to smooth contention metrics. |
| **e2compr** | ext4's experimental compression scheme using `EXT4_COMPRBLK_FL` and 16-byte cluster headers; supported R/W for gzip/LZO/none. |
| **Evidence ledger** | The append-only JSONL audit trail emitted by `ffs-repair`; 23 event types. |
| **FCW (First-Committer-Wins)** | The default MVCC conflict resolution rule: when two transactions touch the same block, the later committer aborts unless a merge proof applies. |
| **FFS / `ffs-*`** | Crate prefix used across the workspace; the user-facing binary is `ffs-cli`. |
| **`FsOps`** | The trait every filesystem operation flows through; implemented by `OpenFs`. |
| **`FUSE` (Filesystem in Userspace)** | The Linux kernel interface that lets a userspace process expose a filesystem; FrankenFS uses the vendored `fuser` crate. |
| **htree** | ext4's hash-tree directory index; uses Half-MD4 or TEA hashes with a 4-word seed. |
| **JBD2 (Journaled Block Device 2)** | ext4's journal layer; FrankenFS implements both JBD2 replay and the newer fast-commit format. |
| **`LabRuntime`** | The virtual-time + DPOR runtime used for deterministic stress tests in `asupersync`. |
| **Managed mode** | `--runtime-mode managed`: the mount runtime profile with graceful unmount, evidence-bearing teardown, and adaptive backpressure-gate control. |
| **Merge proof** | Structured evidence (`MergeProof::*` variants) that two concurrent writes to the same block can be combined without data loss. |
| **MVCC (Multi-Version Concurrency Control)** | The concurrency model FrankenFS uses to allow concurrent readers/writers; block-level, snapshot-isolated. |
| **`OpenFs`** | The single `FsOps` implementation that handles both ext4 and btrfs flavors. |
| **Per-core mode** | `--runtime-mode per-core`: managed mode plus a thread-per-core dispatcher with idle stealing. |
| **PoR (Proof of Retrievability)** | A cryptographic challenge-response protocol for durability auditing in `ffs-repair::por`. |
| **Proof bundle** | The portable readiness artifact rooted at `artifacts/proof/bundle/manifest.json`; the 14-lane gating surface for public claims. |
| **RaptorQ** | The fountain code from RFC 6330 used for self-healing repair symbols. |
| **`rch`** | Remote Compilation Helper; offloads heavy `cargo` invocations to a remote build fleet, avoiding local resource contention. |
| **Readiness lab** | The non-permissioned advisory generator that regenerates readiness artifacts without executing destructive evidence campaigns. |
| **Refresh policy** | The trigger model for regenerating stale repair symbols: `Eager`, `Lazy`, `Adaptive`, or `Hybrid`. |
| **`RequestScope`** | The per-FUSE-callback object that holds an MVCC snapshot and backpressure decisions. |
| **S3-FIFO** | A modern cache eviction algorithm (Yang et al, SOSP '23) using three FIFO queues; available alongside ARC in `ffs-block`. |
| **Safe-merge** | Shorthand for the `MergeProof`-backed path that resolves non-conflicting concurrent writes without aborting. |
| **Snapshot isolation (SI)** | The MVCC reading model: every reader observes a consistent point-in-time view, immune to in-flight writers. |
| **Sparse fixture** | A JSON file containing only the non-zero byte regions of a filesystem image; used to keep conformance fixtures small. |
| **SSI (Serializable Snapshot Isolation)** | An extension to SI that detects rw-antidependency cycles and aborts to preserve serializability. |
| **Stale-window SLO** | The percentile-based freshness guarantee on repair symbols; default p95 < 60s AND < 5000 writes. |
| **Standard mode** | `--runtime-mode standard` (default): the simplest FUSE dispatcher; no extra evidence required. |
| **Transaction abort reason** | A `TxnAbortReason` payload carried by the `TxnAborted` event; values include `FcwConflict`, `SsiCycle`, `Timeout`, `DurabilityFailure`, `UserAbort`. |
| **TxnId / CommitSeq** | Newtypes for transaction identifier and commit sequence number in `ffs-types`. |
| **WAL (Write-Ahead Log)** | The native MVCC log for crash recovery; segments are CRC32C-protected with batched group commit. |
| **Writeback-cache** | The optional kernel FUSE feature that batches writes; default-off in FrankenFS, opt-in only via an artifact-gated path. |

---

## Security Model

Three hard constraints, not best-effort guidelines.

### Zero unsafe code

`#![forbid(unsafe_code)]` is set at every crate root and enforced as a workspace-level Clippy lint. No buffer overflows (bounds-checked indexing). No use-after-free (ownership system). No uninitialized memory reads. No data races (`Send`/`Sync` enforced at compile time). The performance cost is negligible: FUSE protocol overhead (~10µs per round-trip) dominates any bounds-check overhead (~1ns per access).

### No ambient authority

Every I/O operation requires an explicit `&Cx` capability. Code that doesn't have a `Cx` reference cannot perform I/O, read the clock, or sleep. This prevents hidden side effects in "pure" code paths, resource leaks from forgotten cancel handlers, and accidental I/O in unit tests (test contexts have explicit budgets).

### Mount-time validation

On mount, FrankenFS validates the image against a strict compatibility contract:

- Required feature flags must be present (`FILETYPE` for ext4).
- All known incompat feature flags are accepted (`COMPRESSION`, `JOURNAL_DEV`, `ENCRYPT`, `CASEFOLD`, `INLINE_DATA`, etc.).
- Unknown incompat bits cause rejection.
- Geometry parameters must be within supported ranges.
- Superblock checksum must validate (ext4 CRC32C; btrfs CRC32C).
- ext4 MMP state is conservatively rejected (`fsck`-active, active-writer, or unsafe/unknown states reject deterministically).

Images that fail validation are rejected with a specific `FfsError` variant. FrankenFS will not "best-effort" parse a potentially incompatible image.

### Hostile-image containment (separate claim)

Path traversal / symlink refusal, critical fail-closed handling, resource caps with observed counters, bounded hostile fixture classifications, repair-ledger tamper refusal, adversarial path redaction in operator-facing reports, and docs-safe wording. Validated by `ffs-harness validate-adversarial-threat-model` plus security E2E smoke gates.

### Threat model and trust boundaries

The release-gate policy treats `security.hostile_image` as a distinct, separately-validated claim from "FrankenFS is generally safe to run." The authoritative threat model lives in [`security/adversarial_image_threat_model.json`](security/adversarial_image_threat_model.json) (47 KB); the high-level summary:

| Adversary capability | Mitigation in FrankenFS |
|---|---|
| Hands FrankenFS a maliciously crafted ext4/btrfs image (wrong fields, impossible geometry, oversized arrays) | Parser-level validation; structural rejection at `ffs-ondisk::*::parse_*`. Adversarial fixtures pin behavior for 9 specific surfaces (`MmpBlock`, `parse_dev_item`, `parse_inode_item`, etc.). |
| Embeds path-traversal or symlink-loop payloads in directory entries | Path resolution refuses absolute symlinks and bounded-depth loops; `resolve_path` rejects non-`/`-prefixed paths and validates each component. |
| Crafts a hostile repair-symbol blob (forged generation, wrong checksum) | Repair ledger tamper refusal; `RepairAttempted` records expected/actual checksums; mismatches surface as `RepairFailed` with diagnostic detail rather than silent corruption. |
| Submits an image that triggers unbounded memory growth (huge field counts, deeply nested trees) | Resource caps with observed counters per containment scenario; tree depth bounded to 7 levels (btrfs maximum) with cycle and visit-deduplication. |
| Submits an image that triggers infinite-loop parsing | `cx.checkpoint()` plus bounded iteration; the `LabRuntime` `max_steps` parameter caps stress-test work. |
| Tries to leak operator host paths via report output | Adversarial path redaction in harness reports (`bd-rchk0` adversarial path redaction hardening). |
| Submits an image that would mutate test/scratch devices outside the sandbox | Mount-time geometry / device-id validation; xfstests permissioned-lane ACK boundary is required for any device-mutating run. |
| Tries to escape containment by exploiting unsafe FFI / `unsafe` blocks | None possible. `#![forbid(unsafe_code)]` is set at every crate root and enforced as a workspace lint. There is no `unsafe` block to exploit. |
| Tries to escalate via setuid binaries inside the image | FrankenFS is mounted as a normal user process via FUSE; setuid semantics in the image surface only when the host kernel re-evaluates them on the mounted view, which is the host's policy choice, not FrankenFS's. |
| Tries to wedge the mount with one slow / hostile request | `BackpressureGate` + per-request deadline + `cx.checkpoint()` interleaving prevent single-request starvation. |

**Trust boundaries:**
- **Code → image bytes:** untrusted. Every parser is fuzz-validated and the on-disk format is rejected on any deviation.
- **Code → host filesystem:** FrankenFS only reads/writes the image path, the optional external-journal path, and any explicitly-passed evidence-ledger / artifact paths. No ambient host-filesystem authority.
- **Code → kernel FUSE protocol:** the vendored `fuser` 7.40 is in scope; kernel-side bugs in FUSE itself are out of scope (use a current kernel).
- **Code → proof-bundle artifacts:** untrusted at parse time (validators reject malformed / forged artifacts before granting "evidence accepted" status).
- **Operator → release gates:** the release-gate policy file is the authoritative claim mapping; bypassing it via undocumented ACK strings is not supported.

Hostile-image containment is *bounded*; there are known capabilities a sufficiently determined attacker has, such as occupying disk or exhausting an evidence-ledger writer's space. The threat model enumerates these explicitly under `non_goals`. The release-gate policy will not promote `security.hostile_image` until every "bounded" entry has a corresponding cap with observed-counter evidence.

---

## Failure Mode Taxonomy

Filesystems fail in many ways; here is a structured map of what FrankenFS does when each class of failure happens.

| Failure class | Trigger | What FrankenFS does | Operator-visible signal |
|---|---|---|---|
| **Single bit-flip in data block** | Cosmic ray / flaky storage | Scrub detects on next pass; if `--background-repair` enabled, RaptorQ decoder reconstructs and writes back | `CorruptionDetected` → `RepairSucceeded` in ledger |
| **Multi-byte corruption in data block** | Hardware fault | Same as above, classified `severity: "critical"` (vs `"error"` for single-bit) | Elevated severity field on the `CorruptionDetected` record |
| **Block group fully corrupt beyond repair overhead** | Mass corruption exceeding RaptorQ tolerance | Decode fails; `RepairFailed` event recorded; affected block returns EIO on read | `RepairFailed` plus `EIO` on read |
| **Single bit-flip in inode** | As above on an inode block | CRC32C mismatch on inode read → `FfsError::Corruption { block }`; auto-repair if enabled | Inode op returns `EIO` |
| **Journal needs recovery on mount** | Unclean shutdown of ext4 image | JBD2 replay on mount; fast-commit replay if applicable | `WalRecovery` event; mount succeeds |
| **External journal missing / mismatched UUID** | Library caller passed wrong `OpenOptions::external_journal_path` | Fail-fast on open with `FfsError::Format` | Open aborts with diagnostic |
| **Unknown incompat feature bit** | Image declares feature this build doesn't accept | `FfsError::IncompatibleFeature` | Mount aborts with feature name |
| **MMP active-writer state** | Image is currently mounted elsewhere | `FfsError::UnsupportedFeature` (conservative reject) | Mount aborts |
| **MVCC commit conflict (FCW)** | Concurrent writer beat us | Under `Strict`: abort with `EAGAIN`; under `SafeMerge`: attempt merge; under `Adaptive`: expected-loss vote | `TxnAborted { reason: fcw_conflict }`; caller sees `EAGAIN` |
| **SSI rw-antidependency cycle** | Concurrent transactions form a serializable cycle | Abort one transaction with `EAGAIN` | `SerializationConflict` event |
| **Version chain critical overflow** | Hot block accumulates too many versions | Reject new writers with `CommitError::ChainBackpressure` until GC catches up | `TxnAborted { reason: timeout, detail: "ChainBackpressure …" }`; caller sees `EAGAIN` |
| **Cx deadline exceeded** | Operator-set deadline expired | All in-flight calls return `FfsError::Cancelled` at next `checkpoint()` | `Timeout` (via abort detail); caller sees `EINTR` |
| **`Cx` budget exhausted** | Cooperative yield needed | Background workers shrink batch size; foreground requests proceed | `BackpressureActivated` event |
| **Dirty cache critical watermark** | Writeback can't keep up | New writes block until dirty ratio drops below high watermark | `BackpressureActivated`; caller sees write latency spike |
| **Disk full** | Backing image cannot accept writes | `FfsError::NoSpace` → `ENOSPC` to caller | Write returns ENOSPC |
| **WAL write failure mid-commit** | Backing image I/O error | Commit aborts; WAL writer logs error; no partial commit visible | `TxnAborted { reason: durability_failure }` |
| **Kill -9 of the mount process** | Sudden process death | Kernel sees daemon disappear; mount becomes "transport endpoint not connected"; image is consistent (writes that completed `fsync` persist) | Caller must `fusermount3 -u` and remount |
| **OOM kill of the mount process** | Memory pressure on host | Same as kill -9 | Same |
| **Backing image truncated externally** | Operator did something they shouldn't | Subsequent block reads beyond `block_count` return `EIO`; mount may fail to unmount cleanly | `EIO` on affected reads; ledger records `CorruptionDetected` with `severity: "critical"` |
| **Backing image deleted while mounted** | Same as above | Open file descriptor keeps the inode alive on Unix; behavior is "the mount continues until process exit" | None until unmount |
| **Hostile image (resource exhaustion)** | Malicious fixture | Resource caps enforced; quarantine record in ledger | Threat-model scenario classification |
| **Writeback-cache opt-in with stale gate artifact** | `--writeback-cache-gate` JSON is stale | Validator refuses; mount aborts | Specific scenario id mismatch error |
| **Adaptive runtime evidence missing on managed mount** | Operator forgot the manifest | Mount falls back to non-adaptive managed mode with explicit log warning | Log: "adaptive_runtime_enabled=false" |
| **Tracker pollution (foreign-project beads)** | Workspace-wide tooling artifact | `bv`/`br` queries return foreign rows; source-aware queue-state check classifies and excludes them | `excluded_foreign_open_count` in tracker hygiene report |

The recovery posture is consistent across these: **fail closed, emit structured evidence, never silently corrupt**. The evidence ledger is the operator's tool for distinguishing "FrankenFS rejected this safely" from "FrankenFS recovered transparently."

---

## The `FfsError` Error Variant Reference

The 21 variants of `FfsError` are the unified failure surface for every public API. Each one maps to a specific POSIX errno used by FUSE replies, and the variant carries enough structured context for diagnosis.

| Variant | errno | When it fires | Common cause |
|---|---|---|---|
| `Io(std::io::Error)` | `EIO` | OS-level I/O failure | Disk error, file descriptor problem, network filesystem hiccup |
| `Corruption { block, detail }` | `EIO` | Live metadata read produced invalid data at a known block | Checksum mismatch, truncated on-disk structure, out-of-range field |
| `Format(String)` | `EINVAL` | Wrong filesystem type or unsupported format version | Bad superblock magic, image isn't ext4/btrfs |
| `Parse(String)` | `EINVAL` | Higher-level surface lift of `ParseError` from `ffs-types` | Structure didn't decode; carrier for finer-grained parse errors |
| `UnsupportedFeature(String)` | `EOPNOTSUPP` | Image declares a feature this build doesn't yet support | `lzv1` / `bzip2` / `lzrw3a` codec request, MMP unsafe state, unknown mount option |
| `IncompatibleFeature(String)` | `EINVAL` | Image's compat bits cannot be satisfied | Missing required `FILETYPE` for ext4, or unknown incompat bit set |
| `UnsupportedBlockSize(String)` | `EINVAL` | Block size outside 1 KB / 2 KB / 4 KB | Format is valid but build doesn't accept this block size |
| `InvalidGeometry(String)` | `EINVAL` | Mount-time geometry parameter out of range | Zero `blocks_per_group`, impossible `bytes_used > total_bytes`, zero-capacity device |
| `MvccConflict { tx, block }` | `EAGAIN` | Block-level FCW conflict at commit time | Concurrent writer modified the block since the snapshot; retry the transaction |
| `Cancelled` | `EINTR` | `Cx::checkpoint()` saw cancellation or deadline expiry | FUSE-side interrupt, operator-set deadline, kernel-issued cancel |
| `NoSpace` | `ENOSPC` | No free blocks or inodes available | Disk full; allocator exhausted in target groups |
| `NotFound(String)` | `ENOENT` | File / directory / object lookup failed | Path doesn't exist, missing inode, missing block-group descriptor |
| `PermissionDenied` | `EACCES` | Insufficient permissions for the requested operation | Mode bits / owner / capabilities denied the op |
| `ReadOnly` | `EROFS` | Write attempted on a read-only mount | Mount was opened without `--rw`, or RO fallback after fault |
| `NotDirectory` | `ENOTDIR` | A path component is not a directory | `cd` / `lookup` traversed through a file |
| `IsDirectory` | `EISDIR` | File operation attempted on a directory | `read` or `truncate` on a directory inode |
| `NotEmpty` | `ENOTEMPTY` | `rmdir` on a non-empty directory | Directory still contains entries |
| `NameTooLong` | `ENAMETOOLONG` | Filename exceeds the filesystem's name length limit | Component name > 255 bytes for ext4 |
| `Exists` | `EEXIST` | Target already exists (create / mkdir / exclusive open) | Used by `XATTR_CREATE`, `O_EXCL` creates |
| `RepairFailed(String)` | `EIO` | RaptorQ repair or self-healing workflow could not recover data | Corruption exceeds repair-symbol overhead; or repair-symbol fixture itself is damaged |
| `ModeViolation(String)` | `EPERM` | Native-mode-only op attempted in compat mode | Trying to write repair symbols or BLAKE3 checksums on a compat-mode mount |

### Error conversion strategy

Internal crate-specific errors (e.g., `ParseError` from `ffs-types`, `FuseError` from `ffs-fuse`, `CommitError` from `ffs-mvcc`) are converted to `FfsError` at crate boundaries via `From` implementations. The unified type means every public surface is `Result<T, FfsError>`. Internal code can use more precise error types where they help; the conversion to `FfsError` happens once, at the crate boundary.

`thiserror`-derived `Display` messages embed the failing block number, the diagnostic string, or the responsible transaction ID where applicable. The CLI formats these as both plain text and JSON (`--json` flag), and the FUSE adapter maps them to the corresponding errno + optional `EINTR` retry hint.

---

## Lifetime of a Block

A single 4 KB block can pass through every storage subsystem during its lifetime. This walkthrough shows the typical journey.

```
                                                              evidence
   stage           commit            visible            durable        emitted
     │               │                  │                  │              │
     │               │                  │                  │              ▼
 ┌───┴────┐    ┌─────┴────┐      ┌──────┴─────┐    ┌───────┴────┐   ┌────────────────┐
 │ alloc  │───►│  staged  │─────►│  version   │───►│ written to │──►│ ledger entry:  │
 │  via   │    │  in txn  │      │  chain     │    │  backing   │   │ TransactionCom │
 │  buddy │    │ (staged) │      │  (visible) │    │  image     │   │ +SymbolRefresh │
 │ alloc  │    └──────────┘      └────────────┘    └────────────┘   └────────────────┘
 └────────┘                            │                                  │
                                       │           later, on scrub:       │
                                       │           checksum mismatch?     │
                                       ▼                                  ▼
                                ┌──────────────┐                   ┌──────────────┐
                                │ identical →  │                   │ corruption   │
                                │ dedup marker │                   │ detected →   │
                                └──────────────┘                   │ repair       │
                                       │                            │ attempted   │
                                later (GC):                         └──────────────┘
                                       ▼
                                ┌──────────────┐
                                │ all snapshots│
                                │ moved past   │
                                │ this version │
                                │ → epoch GC   │
                                │ reclaims it  │
                                └──────────────┘
```

Step-by-step:

1. **Allocation.** `ffs-alloc::allocate_blocks(cx, hint)` consults the goal-directed placement heuristic (goal group → nearby groups → full scan) and returns one or more contiguous block numbers, marking them allocated in the in-memory bitmap. Free-space accounting in the group descriptor is updated.

2. **Staging.** A `Transaction` accumulates `stage_write(block_number, bytes)` calls. The transaction holds a snapshot `Snapshot { high: CommitSeq }` from `store.begin()` and remembers every block it has touched.

3. **Commit.** `store.commit(txn)` acquires shard locks in sorted block order, increments the global `CommitSeq` atomically, and for each touched block:
   - If the latest committed version's `commit_seq <= snapshot.high`, append a new `BlockVersion` to the chain.
   - Otherwise the writer hit a conflict. Under `Strict` policy, abort with `FcwConflict`. Under `SafeMerge`, try `MergeProof::merge_bytes(base, latest, staged)`. Under `Adaptive`, use the expected-loss decision to pick between these two paths.

4. **Visibility.** Once `commit` returns success, the new version's `commit_seq` is in the chain. Readers whose snapshot has `high ≥ commit_seq` will observe it.

5. **WAL writeback.** The native MVCC WAL writer batches commits and writes them to the WAL file with CRC32C-protected segments. Group-commit batching amortizes the `fsync`.

6. **Backing-image flush.** The MVCC layer pins the block via `FlushPinToken` so the ARC cache cannot flush it before the transaction is fully visible. After visibility, the dirty page is unpinned and the flush daemon writes it (according to the configured watermarks).

7. **Compression.** New versions written under a `CompressionPolicy { algo: CompressionAlgo::Zstd { level } }` (the default) land as `Zstd(Vec<u8>)` rather than `Full(Vec<u8>)`. Identical-version deduplication collapses unchanged "touched" entries to a one-byte marker.

8. **Repair-symbol refresh.** The block's group has a `RefreshPolicy`; on the relevant trigger (Eager / Lazy timeout / Adaptive risk threshold / Hybrid age-or-count), the group's RaptorQ repair symbols are regenerated. A `SymbolRefresh` event is logged.

9. **Garbage collection.** Once no active snapshot still requires the oldest version in the chain (tracked by the `SnapshotRegistry`'s `oldest_registered_at` watermark), the epoch-based reclamation in `crossbeam-epoch` retires the bytes. A `VersionGc` event is logged with the reclamation count.

10. **Scrub cycle.** Independently, the `ScrubDaemon` reads the block (cache-first), computes the on-disk checksum (CRC32C in compat, BLAKE3 in native), and compares with the stored checksum. On mismatch, the recovery pipeline runs as described in the diagram.

The whole lifecycle is auditable. Every step that mutates global state emits a structured `EvidenceRecord`: `TransactionCommit`, `VersionGc`, `SymbolRefresh`, `CorruptionDetected`, `RepairSucceeded`, etc.

---

## Lifetime of a Transaction

The dual to "lifetime of a block": every state a transaction passes through, and what an aborted transaction looks like.

```
   begin          stage           commit          publish        retire
     │              │                │               │              │
     ▼              ▼                ▼               ▼              ▼
 ┌───────┐    ┌──────────┐    ┌────────────┐   ┌──────────┐   ┌──────────┐
 │ txn = │    │ stage_   │    │  CAS       │   │ versions │   │ snapshot │
 │ store │──► │ write(N, │──► │  CommitSeq │──►│ visible  │──►│ released,│
 │ .begin│    │  bytes)  │    │  per shard │   │ to new   │   │ chain GC │
 │ ()    │    └──────────┘    └────────────┘   │ readers  │   │ may run  │
 └───────┘                          │           └──────────┘   └──────────┘
   │                                │
   │                                │ on conflict:
   │                                │   try MergeProof
   │                                │   or abort
   │                                ▼
   │                          ┌──────────────────┐
   │                          │ TxnAborted event │
   │                          │  reason: fcw_…   │
   │                          │  /ssi_cycle/…    │
   │                          └──────────────────┘
   │
   │  (in-flight, no published versions)
   │  if dropped before commit: clean cancel,
   │  no evidence record needed, equivalent
   │  to never-having-existed.
```

| State | Owned by | Visible to readers? | Recoverable on crash? |
|---|---|---|---|
| **Begun** | Caller's `Transaction` value | No (staged-only) | No (transaction state is in-memory) |
| **Staged** | Caller's `Transaction` value | No | No |
| **Committing (mid-CAS)** | MVCC store, briefly | No | If WAL written → yes; else no |
| **Committed (published)** | MVCC store | Yes, to snapshots with `high ≥ commit_seq` | Yes (WAL has the segment) |
| **Aborted** | n/a (released) | No (versions never published) | n/a |
| **Retired (GC)** | EBR garbage list | No (snapshots have moved past) | n/a |

Crash recovery for a committing transaction depends on which side of the WAL `fsync` the crash falls on. Either the WAL segment is durable (replay republishes the versions) or it isn't (the transaction is treated as never-having-existed). There is no in-between visible state.

---

## E2E Test Categories

The 121 tracked E2E gate scripts in `scripts/e2e/` are organized by capability area. Selected highlights, grouped by category:

### Conformance and baseline
- `ffs_baseline_validation_e2e.sh`: initial conformance gate
- `ffs_verification_gate_e2e.sh`: top-level verification suite
- `ffs_verification_runner_e2e.sh`: long-form verification runner
- `ffs_health_consistency_e2e.sh`: cross-subsystem health consistency
- `ffs_smoke.sh`: minimal smoke gate

### MVCC and conflict resolution
- `ffs_mvcc_lifecycle_e2e.sh`: full transaction lifecycle
- `ffs_mvcc_replay_gate_e2e.sh`: WAL replay invariants
- `ffs_mounted_differential_oracle_e2e.sh`: mounted differential oracle
- `ffs_cross_oracle_arbitration_e2e.sh`: disagreement classification
- `ffs_invariant_oracle_e2e.sh`: invariant oracle consumer
- `ffs_wal_replay_e2e.sh` / `ffs_wal_writer_e2e.sh` / `ffs_wal_group_commit_gate_e2e.sh`

### Repair and self-healing
- `ffs_repair_confidence_lab_e2e.sh`: repair-confidence harness
- `ffs_repair_writeback_serialization_e2e.sh`: MVCC repair-writeback serializer
- `ffs_repair_writeback_route_e2e.sh`: RW mount repair routing
- `ffs_repair_5pct_e2e.sh`: 5% overhead canonical scenario
- `ffs_scrub_repair_scheduler_e2e.sh`: scrub + repair scheduling
- `ffs_repair_recovery_smoke.sh`: end-to-end recovery smoke
- `ffs_repair_exchange_loopback_e2e.sh`: multi-host symbol exchange
- `ffs_repair_corpus_e2e.sh`: synthesized repair corpus
- `ffs_self_healing_demo.sh`: self-healing adoption demo

### Crash and recovery
- `ffs_crash_matrix_e2e.sh`: the 12-point crash matrix
- `ffs_crash_replay_refinement_e2e.sh`: replay-refinement gate
- `ffs_mounted_recovery_matrix_e2e.sh`: mounted recovery scenarios
- `ffs_crash_promotion_e2e.sh`: crash-finding promotion path
- `ffs_chaos_replay_lab_e2e.sh`: chaos replay lab
- `ffs_fault_injection_corpus_e2e.sh`: fault-injection corpus

### Writeback-cache
- `ffs_writeback_cache_audit_e2e.sh`: the canonical audit gate (89 KB); covers default-off, opt-in, kill-switch, ordering-oracle, and crash-replay-oracle scenarios in one script
- `ffs_writeback_e2e.sh`: smaller writeback smoke

### Ext4 / btrfs format-specific
- `ffs_ext4_ro_roundtrip.sh`: ext4 read-only roundtrip
- `ffs_ext4_rw_smoke.sh`: ext4 read-write smoke
- `ffs_btrfs_ro_smoke.sh`: btrfs read-only smoke
- `ffs_btrfs_rw_smoke.sh`: btrfs read-write smoke (33 KB)
- `ffs_btrfs_rw_hardening_gate_e2e.sh`: RW hardening gate
- `ffs_btrfs_capability_drift_e2e.sh`: capability-drift detection
- `ffs_btrfs_write_churn_e2e.sh`: write-churn workload
- `ffs_btrfs_multidevice_corpus_e2e.sh`: multi-device RAID corpus
- `ffs_btrfs_send_receive_corpus_e2e.sh`: send-stream corpus
- `ffs_casefold_corpus_e2e.sh`: casefold corpus

### Performance and scalability
- `ffs_swarm_workload_harness_e2e.sh`: NUMA-aware workload harness (33 KB)
- `ffs_swarm_tail_latency_e2e.sh`: p99 attribution
- `ffs_swarm_cache_controller_e2e.sh`: swarm cache controller
- `ffs_swarm_operator_report_e2e.sh`: swarm operator report
- `ffs_performance_manifest_e2e.sh`: manifest schema + freshness (28 KB)
- `ffs_performance_delta_closeout_e2e.sh`: perf delta closeout
- `ffs_permissioned_campaign_broker_e2e.sh`: broker dry-run safety (60 KB)
- `ffs_adaptive_runtime_runner_e2e.sh`: adaptive runtime runner
- `ffs_adaptive_runtime_manifest_e2e.sh`: adaptive runtime evidence manifest
- `ffs_topology_runtime_advisor_e2e.sh`: topology runtime advisor
- `ffs_benchmark_taxonomy_e2e.sh` / `ffs_benchmark_governance_e2e.sh` / `ffs_benchmark_expansion_e2e.sh`
- `ffs_perf_comparison_e2e.sh`: cross-baseline perf comparison

### Fuzzing
- `ffs_fuzz_targets_e2e.sh`: target registration drift
- `ffs_fuzzing_gate_e2e.sh`: fuzz dashboard schema
- `ffs_fuzz_smoke_e2e.sh`: smoke gate with fixed seeds
- `ffs_fuzz_dashboard_e2e.sh`: fuzz dashboard JSON
- `ffs_metamorphic_workload_seed_catalog_e2e.sh`: metamorphic seed catalog

### xfstests integration
- `ffs_xfstests_e2e.sh`: main runner (gated by ACK)
- `ffs_xfstests_preflight_e2e.sh`: precondition validation (43 KB)
- `ffs_xfstests_regression_gate.sh`: regression guard

### Readiness and gates
- `ffs_readiness_lab_e2e.sh`: non-permissioned advisory lab
- `ffs_readiness_lab_contracts_e2e.sh`: lab contract validation
- `ffs_readiness_dashboard_e2e.sh`: dashboard renderer
- `ffs_readiness_action_autopilot_e2e.sh`: readiness-action autopilot
- `ffs_release_gate_e2e.sh`: release-gate validator (34 KB)
- `ffs_proof_bundle_e2e.sh`: proof-bundle E2E generator (34 KB)
- `ffs_proof_overhead_budget_e2e.sh`: proof-overhead budget
- `ffs_ambition_evidence_matrix_e2e.sh`: ambition row gate
- `ffs_tracker_source_hygiene_e2e.sh`: source-aware tracker queue state (50 KB)
- `ffs_operational_readiness_report_e2e.sh`: operational readiness report
- `ffs_inventory_closeout_gate_e2e.sh`: inventory closeout
- `ffs_report_schema_inventory_e2e.sh`: report-schema inventory

### Security and hostile-image
- `ffs_adversarial_threat_model_e2e.sh`: threat-model gate (17 KB)

### Operational
- `ffs_operator_recovery_drill_e2e.sh`: runbook scenarios
- `ffs_operator_tooling_gate_e2e.sh`: operator-tooling gate
- `ffs_soak_canary_campaign_e2e.sh`: campaign profile validation
- `ffs_mounted_write_workload_matrix.sh`: production mounted-write matrix (39 KB)
- `ffs_mounted_write_error_classes_e2e.sh`: mounted-write error classes
- `ffs_mounted_checkpoint_survivor_e2e.sh`: mounted checkpoint survivor
- `ffs_mounted_repair_mutation_boundary_e2e.sh`: mounted-repair mutation boundary
- `ffs_runbooks_e2e.sh` / `ffs_tabletop_drill_e2e.sh`
- `ffs_log_contract_e2e.sh`: structured-log contract
- `ffs_error_taxonomy_e2e.sh`: error-taxonomy coverage

Every script writes a `junit.xml` + `run.log` + per-scenario manifest to `artifacts/e2e/<timestamp>_<script>/`, and is consumed by `validate-proof-bundle` when wired into a proof-bundle lane.

---

## The `vendor/fuser` Patch

FrankenFS pins a vendored copy of the `fuser` crate via `[patch.crates-io]`:

```toml
[patch.crates-io]
fuser = { path = "vendor/fuser" }
```

The patch is at ABI 7.40 and is the only mechanism by which FUSE protocol features added after the upstream crate's last release are available to FrankenFS. Specifically, the patch:

- **Forwards unrestricted ioctls** to FrankenFS userspace handlers. Upstream `fuser` filters ioctls based on a built-in allow-list; for FrankenFS parity tests against `FIEMAP`, `EXT4_IOC_GETFLAGS`, `EXT4_IOC_SETFLAGS`, `EXT4_IOC_GETSTATE`, `FS_IOC_GET_ENCRYPTION_POLICY`, `FS_IOC_GET_ENCRYPTION_POLICY_EX`, `FS_IOC_GETFSUUID`, `FS_IOC_GETFSSYSFSPATH`, `BTRFS_IOC_INO_LOOKUP`, `BTRFS_IOC_DEV_INFO`, `BTRFS_IOC_GET_SUBVOL_INFO`, `FIBMAP`, `FITRIM`, etc., we need full forwarding.
- **Exposes `splice`/`sendfile` plumbing** that newer kernels rely on for zero-copy reads.
- **Adds the FUSE 7.40 `STATX` reply path** so `getattr` can return high-precision timestamps and the post-2038 epoch range that FrankenFS already supports internally.
- **Plumbs the `inotify` event delivery** path required for some mount-time integration tests.
- **Quiets dead-code warnings** in the vendored copy where upstream's `#[allow(dead_code)]` had decayed (bd-aw9l8).

The vendored copy is included in `cargo vet`'s supply-chain audit, can be diffed against upstream cleanly, and is the explicit subject of a beads ticket (`bd-x4l3t`) tracking its lifecycle and eventual upstream PRs.

---

## RAID Profile Support Matrix

Btrfs supports a number of RAID profiles. FrankenFS V1 tests these explicitly via the `ffs-btrfs::map_logical_to_stripes` dispatcher:

| Profile | Read | Write | Stripe-fallback | Mirror dispatch | Status |
|---|---|---|---|---|---|
| `Single` | ✅ | ✅ (experimental) | n/a | n/a | Supported |
| `DUP` | ✅ | ✅ (experimental) | n/a | ✅ (primary + mirror) | Supported |
| `RAID0` | ✅ | ✅ (experimental) | ✅ | n/a | Supported |
| `RAID1` | ✅ | ✅ (experimental) | n/a | ✅ (mirror fallback) | Supported |
| `RAID10` | ✅ | ✅ (experimental) | ✅ | ✅ (mirror-stripe) | Supported |
| `RAID5` | ✅ | ✅ (experimental) | ✅ (parity rotation) | n/a | Supported |
| `RAID6` | ✅ | ✅ (experimental) | ✅ (double parity) | n/a | Supported |
| `RAID1C3` | ❌ | ❌ | n/a | n/a | V1.x deferred |
| `RAID1C4` | ❌ | ❌ | n/a | n/a | V1.x deferred |

The parity rotation logic for RAID5/RAID6 received an explicit fix (`18bc6b0`) to align with btrfs's left-symmetric layout. Stripe-translation properties are differentially validated via metamorphic relations:

- **Stripe-translation covariance:** `physical(logical + k) == physical(logical) + k` when `k` fits within one stripe.
- **Chunk-order permutation invariance:** `parse(perm(chunks)) == parse(chunks)` for any permutation `perm` of the chunk list.
- **Single-vs-DUP primary mapping equivalence:** the primary mirror in DUP must return the same physical mapping as the equivalent Single chunk.

Mirror dispatch in RAID1 / DUP / RAID10 also exercises a **fallback path**: if the primary mirror returns a corrupt block (per checksum), the next mirror is tried. This is part of `BtrfsDeviceSet::read_logical` and is tested directly in harness coverage.

---

## POSIX Semantics: Quirks We Preserve

A few POSIX corners are worth calling out explicitly because they often surprise people writing portable filesystem code.

| Behavior | What FrankenFS does | Why |
|---|---|---|
| **Directory `nlink`** | Counts as: `2 + (number of subdirectories)`. The `2` is for `.` (self-loop) and the parent's entry pointing to this directory. | This is the standard POSIX convention; kernel ext4 enforces it. |
| **`atime` updates** | Default to lazy / on-explicit-stat. Read paths do not necessarily bump `atime` on every read. | Performance + alignment with `relatime`/`noatime` kernel mount defaults. |
| **`mtime` precision** | Nanosecond precision via `i_mtime_extra`. | Matches kernel ext4 with the `extra_isize` feature. |
| **Post-2038 timestamps** | Fully supported via the 2-bit epoch extension in `_extra` fields. | Avoids the year-2038 overflow. |
| **Hard-link count limit** | `EMLINK` returned at the format-specific maximum (`65000` for ext4 with the `dir_nlink` feature). | Tested in `ffs-harness::tests::emlink`. |
| **`unlink` of an open file** | Inode `nlink` decrements; the inode and its blocks are reclaimed only after the last open handle closes (the standard Unix orphan-on-unlink rule). On crash, mount-time orphan recovery (`maybe_recover_ext4_orphans`) walks the orphan chain. | Standard Unix semantics; kernel ext4 stores the orphan in `s_last_orphan`. |
| **`rename` overwrite atomicity** | A successful `rename(src, dst)` atomically replaces any existing `dst` with a single MVCC commit. | POSIX-required atomicity. |
| **Directory entry coalescing** | Deleted entries (`inode = 0`) have their `rec_len` merged into the previous entry; the directory block does not compact on every delete. | Matches kernel ext4 behavior; full compaction happens on directory restructure. |
| **`fsync` of a directory** | `fsyncdir` is a separate FUSE op and is durable; data writes to files in that directory must be `fsync`'d separately. | Standard POSIX semantics; `fsync` of a dir doesn't promise file durability. |
| **`flush` (close)** | Non-durable; equivalent to "the file descriptor is going away." Does NOT promise on-disk visibility. | This is the V1.x contract; `fsync` / `fsyncdir` are the durability boundaries. |
| **Case-folding** | Per-directory (`EXT4_CASEFOLD_FL`), Unicode-normalized comparison. A case-folded directory accepts mixed-case lookups; uncovered directories do not. | Matches kernel ext4 `CASEFOLD` feature. |
| **Encrypted filenames (nokey mode)** | Returned as raw bytes from `readdir`. No decryption attempted; this is the standard "image opened without the key" behavior. | Full decryption requires key management not in V1. |

---

## Installation

### From source (only method during early development)

```bash
# rust-toolchain.toml pins the nightly channel; Cargo handles the rest.
git clone https://github.com/Dicklesworthstone/frankenfs.git
cd frankenfs
cargo build --workspace
```

### Requirements

- **Rust nightly** (edition 2024, minimum 1.85).
- **Linux** (FUSE target).
- **FUSE headers**: `sudo apt install libfuse-dev` (Debian/Ubuntu) or `sudo dnf install fuse-devel` (Fedora).
- **fusermount3** for mount/unmount probes (`sudo apt install fuse3` / `sudo dnf install fuse3`).

### Optional convenience

```bash
# Symlink the built binary onto PATH
ln -s "$PWD/target/release/ffs-cli" ~/.local/bin/ffs

# Build with the perf-tuned profile (max speed, retains debuginfo for flamegraphs)
cargo build --workspace --profile release-perf
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Dicklesworthstone/frankenfs.git
cd frankenfs

# 2. Build
cargo build --workspace

# 3. Run the full test suite
cargo test --workspace

# 4. Inspect a filesystem image
cargo run -p ffs-cli -- inspect /path/to/fs.img --json

# 5. Run the conformance parity report
cargo run -p ffs-harness -- parity

# 6. Mount read-only
sudo cargo run -p ffs-cli -- mount /path/to/fs.img /mnt/ffs

# 7. Unmount
sudo fusermount3 -u /mnt/ffs
```

---

## Commands

### `ffs-cli`

```bash
# Inspect ext4 or btrfs image metadata
cargo run -p ffs-cli -- inspect <image-path> --json
cargo run -p ffs-cli -- inspect <image-path> --subvolumes --snapshots  # btrfs

# MVCC version-chain statistics
cargo run -p ffs-cli -- mvcc-stats <image-path> --json

# Filesystem info (superblock + optional sections)
cargo run -p ffs-cli -- info <image-path> --groups --mvcc --repair --journal --json

# Low-level metadata dumps
cargo run -p ffs-cli -- dump superblock <image-path> --json --hex
cargo run -p ffs-cli -- dump inode 2 <image-path> --json
cargo run -p ffs-cli -- dump extents 12 <image-path> --json
cargo run -p ffs-cli -- dump dir 2 <image-path> --json

# Mount (default read-only, FUSE)
cargo run -p ffs-cli -- mount <image-path> <mountpoint>

# Mount with experimental read-write (durable by default for both ext4 and btrfs)
cargo run -p ffs-cli -- mount <image-path> <mountpoint> --rw

# Mount with mounted automatic repair + evidence ledger
cargo run -p ffs-cli -- mount <image-path> <mountpoint> \
    --background-repair --background-scrub-ledger repair.jsonl
cargo run -p ffs-cli -- mount <image-path> <mountpoint> --rw \
    --background-repair --background-scrub-ledger repair.jsonl

# Mount with managed runtime + adaptive runtime evidence
cargo run -p ffs-cli -- mount <image-path> <mountpoint> --rw \
    --runtime-mode managed --managed-unmount-timeout-secs 30 \
    --adaptive-runtime \
    --adaptive-runtime-manifest docs/adaptive-runtime-evidence-manifest.json \
    --adaptive-runtime-summary-json summary.json \
    --adaptive-runtime-summary-md   summary.md

# Mount with btrfs subvolume / snapshot selection
cargo run -p ffs-cli -- mount <image-path> <mountpoint> --subvol home
cargo run -p ffs-cli -- mount <image-path> <mountpoint> --snapshot 2026-05-01

# Mount with explicit kernel writeback-cache (fully evidence-gated)
cargo run -p ffs-cli -- mount <image-path> <mountpoint> --rw --writeback-cache \
    --writeback-cache-gate            artifacts/writeback-cache/audit_gate.json \
    --writeback-cache-ordering-oracle artifacts/writeback-cache/ordering_oracle.json \
    --writeback-cache-crash-replay-oracle artifacts/writeback-cache/crash_replay_oracle.json

# Read-only scrub (JSON summary on stdout)
cargo run -p ffs-cli -- scrub <image-path> --json

# Offline filesystem checks + optional repair
cargo run -p ffs-cli -- fsck <image-path> --repair --json --force

# Manual repair workflow
cargo run -p ffs-cli -- repair <image-path> --json
cargo run -p ffs-cli -- repair <image-path> --rebuild-symbols --max-threads 8 --json

# Current feature-parity report
cargo run -p ffs-cli -- parity --json

# Evidence ledger inspection (with operator presets)
cargo run -p ffs-cli -- evidence <ledger>.jsonl --json --tail 50
cargo run -p ffs-cli -- evidence <ledger>.jsonl --preset contention
cargo run -p ffs-cli -- evidence <ledger>.jsonl --preset repair-failures
cargo run -p ffs-cli -- evidence <ledger>.jsonl --preset replay-anomalies
cargo run -p ffs-cli -- evidence <ledger>.jsonl --preset pressure-transitions

# Create a new ext4 image (wraps mkfs.ext4 + FrankenFS validation)
cargo run -p ffs-cli -- mkfs <output> --size-mb 64 --block-size 4096 --label demo --json
```

### `ffs-harness`

```bash
# Validate conformance fixtures against golden data
cargo run -p ffs-harness -- check-fixtures

# Generate feature-parity report
cargo run -p ffs-harness -- parity

# Validate an operator proof bundle
cargo run -p ffs-harness -- validate-proof-bundle \
    --bundle artifacts/proof/bundle/manifest.json \
    --current-git-sha "$(git rev-parse HEAD)" \
    --max-age-days 14 \
    --out artifacts/proof/bundle/report.json \
    --summary-out artifacts/proof/bundle/summary.md

# Run benchmarks
cargo bench -p ffs-harness
```

### Canonical CI gate

```bash
# These four commands must pass before any merge
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

`./scripts/verify_golden.sh` is the checked-in single entrypoint for artifact integrity + harness conformance. Cargo-heavy steps route through `rch exec -- ...` when local resource contention from concurrent agent swarms could mask harness output.

---

## Tuning and Configuration

All knobs are struct fields. There are no hidden environment variables, except the ones explicitly listed under [Evidence and Release Gates](#evidence-release-gates-and-readiness).

### MVCC

| Parameter | Default | Effect |
|---|---|---|
| `ConflictPolicy` | `SafeMerge` | `Strict` for max safety, `Adaptive` for auto-tuning |
| `AdaptivePolicyConfig.ema_alpha` | 0.1 | Higher = more responsive to contention changes |
| `AdaptivePolicyConfig.warmup_commits` | 50 | Commits before adaptive policy activates |
| `CompressionPolicy.max_chain_length` | `Some(64)` | Version-chain cap; `None` disables the cap |
| `CompressionPolicy.dedup_identical` | true | Identical-version deduplication |
| `GcBackpressureConfig.min_poll_quota` | 256 | Budget threshold for GC batch throttling |

### Block cache

| Parameter | Default | Effect |
|---|---|---|
| `ArcWritePolicy` | `WriteThrough` | `WriteBack` for batched I/O (requires flush daemon) |
| `DIRTY_HIGH_WATERMARK` | 0.80 | Dirty ratio triggering aggressive flush |
| `DIRTY_CRITICAL_WATERMARK` | 0.95 | Dirty ratio blocking new writes |
| `FlushDaemonConfig.batch_size` | configurable | Dirty blocks per flush cycle |
| `FlushDaemonConfig.interval` | configurable | Sleep between flush cycles |

### Repair

| Parameter | Default | Effect |
|---|---|---|
| `DurabilityAutopilot.min_overhead` | 0.03 | Minimum repair-symbol overhead (3%) |
| `DurabilityAutopilot.max_overhead` | 0.10 | Maximum overhead (10%) |
| `DurabilityAutopilot.metadata_multiplier` | 2.0 | Extra overhead for metadata groups |
| `RefreshPolicy` | `Lazy { 30s }` | `Eager` for metadata, `Hybrid` for write-heavy |
| `StaleWindowSlo.max_age_ms` | 60,000 | SLO breach threshold (age) |
| `StaleWindowSlo.max_writes` | 5,000 | SLO breach threshold (writes) |
| `StaleWindowSlo.percentile` | 0.95 | SLO percentile |

### FUSE / mount

| Parameter | Default | Effect |
|---|---|---|
| `MountOptions.read_only` | `true` | Safe default; `--rw` for experimental writes |
| `MountOptions.worker_threads` | 0 (auto) | `min(available_parallelism, 8)` |
| `MountOptions.allow_other` | `false` | Multi-user FUSE access |
| `--runtime-mode` | `standard` | `managed` or `per-core` for richer evidence |
| Kernel `writeback_cache` | off | Opt-in only via three accepted artifacts + matching host manifest |

---

## How Spec-First Porting Works in Practice

The porting doctrine is a concrete workflow with traceable artifacts at every step.

### Step 1: Behavioral extraction

Legacy C code (e.g., `fs/ext4/extents.c`) is read for its *behavioral contract*, not its implementation. The output is `EXISTING_EXT4_BTRFS_STRUCTURE.md` (94 KB) capturing what each function does, what invariants it maintains, what error conditions it handles, and what on-disk format constraints it enforces.

### Step 2: Architecture design

The behavioral spec maps to a Rust crate/module structure (`PROPOSED_ARCHITECTURE.md`, 24 KB). Decisions: which behaviors become traits vs concrete types, where crate boundaries go (parser vs I/O vs policy), what the dependency DAG looks like, and what the testing strategy is for each component.

### Step 3: Idiomatic implementation

Code is written from the spec, not by translating C control flow. No `goto → loop` patterns (Rust's `?` and `match` replace C's error-handling gotos). No manual memory management (`Vec` / `Box` / `Arc` replace `kmalloc`/`kfree`). No global state (`&Cx` replaces the kernel's ambient `current` task). Enum-based dispatch replaces function-pointer tables.

### Step 4: Conformance validation

`ffs-harness` validates the implementation against real filesystem images using golden-file comparison and exact-assertion sparse fixtures. Feature parity is tracked quantitatively in `FEATURE_PARITY.md`; every feature is implemented (with a test), explicitly excluded (with a reason), or marked in-progress.

### The result

The ext4 extent-tree implementation handles the full 4-level tree structure in ~300 lines of Rust vs ~3,000 lines of kernel C, because Rust's type system, iterators, and error handling eliminate the boilerplate that dominates kernel code.

---

## Project Status

**FrankenFS is in experimental operational state.** `ParityReport::current()` prints 97/97 rows for [`FEATURE_PARITY.md`](FEATURE_PARITY.md)'s tracked feature denominator, meaning every current denominator item has an implemented and tested contract. The B-series accounting still separates implemented, kernel-verified, and rejection-only rows before any wording is allowed to strengthen into broader readiness claims. Three subsystem evidence lanes are tracked separately:

| Subsystem | Status | Key metric |
|---|---|---|
| **Safe-Merge Conflict Arbitration** | Bench-verified | 120-writer stress, SafeMerge 9.5× lower expected loss than Strict |
| **Adaptive Repair Symbol Refresh** | Bench-scoped | Hybrid policy lowers p95 stale-window age under heavy writes; exact percentage remains tied to benchmark artifacts |
| **FUSE Writeback-Cache Barriers** | Gate-verified | 12-point crash/replay matrix, epoch monotonicity preserved |

### Feature parity accounting

| Domain | `ParityReport::current()` rows |
|---|---|
| ext4 metadata parsing | 27/27 implemented |
| btrfs metadata parsing | 27/27 implemented |
| MVCC / COW core | 14/14 implemented |
| FUSE surface | 19/19 implemented |
| self-healing durability | 10/10 implemented |
| **Overall tracked denominator** | **97/97 implemented** |

These are the machine-parsed feature-denominator numbers printed by `ffs-harness parity`, not an authoritative readiness or kernel-verification headline. The B-series classifier keeps `implemented`, `kernel-verified`, and `rejection-only` rows distinct; deterministic rejection rows prove their rejection contract but do not strengthen a general verification claim.

Rows in the btrfs experimental RW contract can still be `partially supported` or `unsupported` without reducing tracked parity when the expected V1 behavior is a deterministic partial-success or explicit rejection path that is implemented and tested.

### What works today

- **ext4.** Superblock, inode, extent header/entry, group descriptor, feature flag decoding, mount-time journal recovery (JBD2 + fast-commit + external-journal pairing), FUSE mount (RO default, experimental RW), `e2compr` read+write for gzip/LZO/none, casefold, encryption nokey mode, inline data, indirect block addressing, fallocate (KEEP_SIZE / PUNCH_HOLE / ZERO_RANGE / COLLAPSE_RANGE / INSERT_RANGE), POSIX ACL xattrs, MMP conservative rejection.
- **btrfs.** Superblock, B-tree header, leaf item metadata, geometry validation, RAID stripe mapping (single/DUP/RAID0/1/5/6/10), FUSE mount (RO default; experimental RW with durable writeback via `btrfs_full_transaction_commit`), transparent ZLIB/LZO/ZSTD decompression, named subvolume/snapshot selection, tree-log replay, send/receive stream parsing, btrfs fallocate (KEEP_SIZE / PUNCH_HOLE / ZERO_RANGE / COLLAPSE_RANGE / INSERT_RANGE), backup superblock mirror repair, fragmentation-aware free-run reporting.
- **MVCC.** Snapshot visibility, commit sequencing, FCW conflict detection, two same-block merge mechanisms behind semantic `MergeProof` labels, three conflict policies with adaptive expected-loss selection, EMA contention tracking, sharded concurrent store, Zstd/Brotli version compression, WAL persistence + crash recovery, SSI two-edge rw-antidependency detection.
- **Self-healing.** Bayesian durability autopilot, RaptorQ symbol generation/recovery, four refresh policies (Eager/Lazy/Adaptive/Hybrid), stale-window SLO with percentile-based breach detection, multi-host repair-ownership coordination, expected-loss policy comparison, mounted automatic repair contract (read-only + read-write via MVCC repair-writeback serializer).
- **Writeback-cache.** Epoch-based commit barriers with per-inode staged/visible/durable tracking, deferred visibility for MVCC isolation, dirty-page ordering oracle, 12-point crash/replay matrix artifact gate, runtime guard, and host/lane manifest checks. Kernel option default-off; explicit opt-in is evidence-gated.
- **Observability.** Evidence ledger with 23 event types and 8 operator presets (`replay-anomalies`, `repair-failures`, `pressure-transitions`, `contention`, `metrics`, `cache`, `mvcc`, `repair-live`), contention metrics, policy-switch detection, structured logging across all subsystems, JSONL audit trail.
- **CLI.** `inspect`, `mvcc-stats`, `info`, `dump`, `fsck`, `repair`, `mount` (22 flags), `scrub`, `parity`, `evidence`, `mkfs`.
- **Testing.** Source-derived `#[test]` / `proptest!` inventory across 21 crates, 63 fuzz targets, 92 criterion benchmarks, 125 tracked end-to-end gate scripts, metamorphic-relation proptests across the checksum/parser surface, and 226 tracked insta snapshots covering every emitted report shape.

### What's next

Items outside the tracked 97-row parity denominator, the operational bridge backlog:

| Bead | Area | Current target |
|---|---|---|
| `bd-rchk1` | Docs/status reconciliation | Keep canonical docs explicit that tracked parity is complete while operational readiness work remains |
| `bd-rchk2` | btrfs delayed refs | Complete: scoped V1 model with retry-safe failed-flush and overflow coverage |
| `bd-rchk3` | xfstests | 2026-05-21 xfstests lane wired to ExecutedEvidence via `evidence_backed_lane::execute_xfstests_lane()`; properly skips when prerequisites missing (fsstress, TEST_DIR, SCRATCH_MNT); real execution requires environment setup + `XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices` |
| `bd-rchk4` | Mounted FUSE CI | Use the permissioned lane in `scripts/e2e/README.md` to run critical mounted ext4/btrfs paths with structured capability and cleanup artifacts |
| `bd-rchk5` | Performance | Complete: dated 2026-05-03 core and mounted throughput/latency artifacts, host/runtime metadata, delta closeout, quarantined mounted latency claims recorded |
| `bd-rchk6` | Mounted self-healing | Complete: automatic mounted repair implemented for `--background-repair --background-scrub-ledger`; RW repair routes through MVCC repair-writeback serializer with stale-snapshot rejection |
| `bd-rchk7` | Fuzz / conformance | Complete: remaining open-ended corpus notes tied to completed fixtures, closed child beads, or the fixed-seed fuzz-smoke gate |

See [`FEATURE_PARITY.md`](FEATURE_PARITY.md) for the full capability matrix and [`PLAN_TO_PORT_FRANKENFS_TO_RUST.md`](PLAN_TO_PORT_FRANKENFS_TO_RUST.md) for the 9-phase roadmap.

---

## V1 Filesystem Scope

**ext4.** Single-device images with block sizes 1K/2K/4K. Requires `FILETYPE`; `EXTENTS` is optional (indirect-block addressing is supported). FUSE mount defaults to read-only; `--rw` is available but experimental. All known incompat feature flags are accepted at mount time. `COMPRESSION` covers ext4 e2compr read/write for the implemented gzip/LZO/"none" method-table paths; rare legacy codecs (`lzv1`, `bzip2`, `lzrw3a`) reject deterministically with `EOPNOTSUPP`. `JOURNAL_DEV` images are detected; data filesystems referencing an external journal support paired-open replay through `OpenOptions::external_journal_path` (library API) with UUID/block-size validation. `ENCRYPT` shows filenames as raw bytes (nokey mode). `CASEFOLD` provides case-insensitive directory lookup. `INLINE_DATA` reads from inode block area + `system.data` xattr. MMP unsafe states are rejected with `EOPNOTSUPP`.

**btrfs.** Single- and multi-device images with single / DUP / RAID 0/1/5/6/10 support. Metadata parsing + validation (superblock, leaf items, sys_chunk_array, chunk tree walking, device tree walking). FUSE mount/runtime contract fully tracked; the operator-facing mount path is experimental and defaults to read-only. `--rw` enables durable btrfs metadata mutation via `btrfs_full_transaction_commit()`. The `--btrfs-rw-ephemeral-ok` flag now controls commit strategy (ephemeral tree-log vs full durable commit), not permission. Transparent ZLIB/LZO/ZSTD decompression, named subvolume/snapshot selection (`--subvol`, `--snapshot`), tree-log replay, and send/receive stream parsing all implemented.

### btrfs RW contract

Btrfs RW is **durable by default** as of bd-jdo53. The commit sequence allocates real logical addresses from chunk-covered metadata block groups, rewrites internal child blockptrs, translates logical→physical via `map_logical_to_physical` for each device write, updates the FS_TREE ROOT_ITEM, commits EXTENT_TREE and ROOT_TREE, and patches the on-disk superblock in place. Coverage in `scripts/e2e/ffs_btrfs_rw_durable_remount_e2e.sh` proves 6/6 mutations survive unmount/remount with byte-exact content.

| Operation class | Status | Contract |
|---|---|---|
| Core mutations (`create`, `mkdir`, `mknod`, `unlink`, `rmdir`, `rename`, `write`, `setattr`, `link`, `symlink`, xattrs) | Durable experimental | Deterministic success/error under `ffs-core` + FUSE tests; mutations are durable via full transaction commit on fsync/unmount |
| `fallocate(mode=0, FALLOC_FL_KEEP_SIZE)` | Durable | Preallocation paths supported and validated |
| `fallocate(PUNCH_HOLE\|KEEP_SIZE)` | Durable | Zero-fills the requested range while preserving file size and unaffected bytes |
| `fallocate(ZERO_RANGE [\|KEEP_SIZE])` | Durable | Zero-fills; `KEEP_SIZE` preserves EOF; non-`KEEP_SIZE` can extend file size |
| `fallocate(COLLAPSE_RANGE)` | Durable | Removes aligned range, shifts tail left, shrinks file size, preserves shifted prealloc extents as FIEMAP `UNWRITTEN` |
| `fallocate(INSERT_RANGE)` | Durable | Inserts aligned hole, shifts tail right, grows file size, preserves shifted prealloc extents as FIEMAP `UNWRITTEN` |
| `fallocate(unknown/extra mode bits)` | Unsupported | Returns `EOPNOTSUPP` with no partial mutation before rejection |
| Unsupported-path observability | Required | Structured logs include `operation_id`, `scenario_id`, `outcome`, and `error_class` |

Full normative scope: [`COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md`](COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Permission denied` on mount | Missing `fusermount3` or user not in `fuse` group | `sudo apt install fuse3` (Debian/Ubuntu); add user to `fuse` group; or run with `sudo` |
| `Transport endpoint is not connected` | Mount process died without cleanup | `fusermount3 -u <mountpoint>`; remount |
| `UnsupportedImage` on inspect | Neither ext4 nor btrfs magic at expected offsets | Verify image is a real ext4/btrfs filesystem with `file <img>` |
| `IncompatibleFeature` on mount | Image declares an incompat flag this build doesn't accept | Check `FEATURE_PARITY.md`; file an issue with the flag name |
| `MvccConflict` (errno `EAGAIN`) under write | Concurrent writer modified the block since your snapshot | Retry with a fresh snapshot; switch to `ConflictPolicy::Adaptive` |
| Background scrub finds corruption but doesn't repair | Read-only mount or `--background-repair` not set | Add `--background-repair --background-scrub-ledger <jsonl>` to the mount command |
| `--writeback-cache` is rejected | Missing one of: `--rw`, gate artifact, ordering oracle, crash-replay oracle, disarmed kill switch, matching host manifest | Run `./scripts/e2e/ffs_writeback_cache_audit_e2e.sh` to regenerate artifacts |
| Tests hang under heavy parallel agent activity | Local cargo resource contention | Route through `rch exec -- cargo ...`; the project assumes this for harness-heavy paths |
| `br ready` shows foreign-looking rows | Cross-project tracker pollution | See [`docs/tracker-hygiene.md`](docs/tracker-hygiene.md) and use the source-aware queue-state check |

---

## Limitations

- **Linux only.** FUSE is the sole mount target. No macOS or Windows support planned.
- **Nightly Rust required.** Edition 2024 features require the nightly toolchain.
- **Runtime is experimental.** Tracked feature-denominator completion means the V1 matrix is implemented and tested; it does not mean operational hardening, performance tuning, kernel verification, or future-scope features are finished. Mount / write paths should be treated as experimental in operational environments.
- **btrfs read-write is experimental but durable.** `--rw` enables full durable metadata writeback via `btrfs_full_transaction_commit()`. The `--btrfs-rw-ephemeral-ok` flag now controls commit strategy (ephemeral tree-log-only vs full durable commit), not permission.
- **Kernel FUSE writeback-cache mode is default-off and release-gated in V1.x.** The `--writeback-cache` opt-in requires `--rw`, an accepted audit gate, an accepted ordering oracle, fresh runtime-guard evidence, an accepted crash/replay oracle, a matching host/lane manifest, and a disarmed `FFS_WRITEBACK_CACHE_KILL_SWITCH`. `flush` is non-durable; `fsync` / `fsyncdir` are the explicit durability boundaries.
- **Swarm responsiveness claims require permissioned large-host evidence.** Local swarm workload and tail-latency smoke lanes are downgrade artifacts; only fresh `authoritative_large_host` proof-bundle lanes strengthen `swarm.responsiveness`.
- **Default CLI mount path does not enable optional backpressure / per-core scheduling hooks.** `ffs-cli mount` defaults to the `standard` runtime mode without wiring `BackpressureGate` controls.
- **Mount background scrub is detection-only by default**, with explicit automatic repair available via `--background-repair --background-scrub-ledger <jsonl>`. Read-write repair uses the mounted MVCC request-scope authority so recovered blocks share the same serializer as client writes.
- **External dependencies.** Workspace dependencies currently use crates.io releases (`asupersync = 0.3.1`, `ftui = 0.3.1`); local path overrides can be supplied with Cargo `[patch]` during sibling-repo development. `vendor/fuser` is pinned via `[patch.crates-io]` to expose ABI 7.40 and unrestricted ioctls.
- **Legacy reference corpus is not included.** The Linux kernel ext4/btrfs source used for behavioral extraction (~205K lines) is gitignored due to size. Extracted contracts are in [`EXISTING_EXT4_BTRFS_STRUCTURE.md`](EXISTING_EXT4_BTRFS_STRUCTURE.md). For the original source, see `git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git` at tag v6.19.
- **Multi-host repair is single-host only in V1.x.** Lease-based ownership coordination exists; concurrent write-side repair across hosts is V1.x-deferred.
- **Hostile-image safety is a separate claim.** Containment is implemented and threat-modeled, but `security.hostile_image` is release-gated and requires its own proof-bundle lanes before docs may improve wording.

---

## FAQ

**Q: Why reimplement ext4 and btrfs instead of just using them?**
A: Kernel filesystems can't be extended with MVCC or self-healing from userspace. FrankenFS is a research vehicle for exploring what ext4/btrfs could look like with modern concurrency control and erasure coding, while remaining mount-compatible with existing images.

**Q: Can I mount real ext4/btrfs data with this today?**
A: `ffs mount` supports both ext4 and btrfs images under the tracked V1 feature contract, but the runtime is operationally experimental. Default behavior is read-only. Both ext4 and btrfs `--rw` paths are experimental but durable - writes survive unmount and remount. Do not rely on it for production data.

**Q: What does "spec-first" mean?**
A: Instead of translating C to Rust line by line, we first extract the *behavioral contract* of each kernel subsystem into specification documents (~600 KB of structured Markdown across the canonical spec, the behavioral-extraction document, the architecture document, the porting plan, and the parity matrix). Then we implement from the spec in idiomatic Rust. This avoids carrying over C-isms and allows architectural improvements.

**Q: Why MVCC instead of the existing journal?**
A: ext4's JBD2 journal serializes commits through a single path. Block-level MVCC with version chains lets FrankenFS test concurrent-writer behavior under snapshot isolation. The adaptive conflict policy selects between strict first-committer-wins and safe-merge resolution based on observed contention, using the expected-loss model described above.

**Q: What are fountain codes / RaptorQ?**
A: RaptorQ (RFC 6330) is a fountain code, an erasure coding scheme that generates repair symbols from source data. Given enough symbols, FrankenFS can recover lost or corrupted source blocks. It stores a configurable overhead of repair symbols per block group (default 5%). The Bayesian autopilot adjusts overhead based on observed corruption rates.

**Q: Why `forbid(unsafe_code)` everywhere?**
A: Filesystem bugs in C frequently involve buffer overflows, use-after-free, and uninitialized memory. Forbidding unsafe Rust removes direct use of unsafe operations from FrankenFS crates. The performance cost is negligible for this FUSE design because the FUSE protocol dominates the relevant overhead.

**Q: What is the "adaptive conflict policy"?**
A: When two transactions write the same block, FrankenFS can either abort the later writer (Strict FCW) or merge the writes using a proof that they do not conflict (SafeMerge). The Adaptive policy uses an expected-loss decision model tracking conflict rate, merge success rate, and abort rate via EMAs, then selects the lower expected-cost strategy. Under a 120-writer stress test, SafeMerge achieves 9.5× lower expected loss than Strict.

**Q: How does self-healing refresh work?**
A: Repair symbols become stale when source blocks are modified. FrankenFS supports four refresh triggers: Eager (every write), Lazy (age timeout or scrub cycle), Adaptive (switches based on the corruption posterior), and Hybrid (first of age timeout OR block-count threshold). `RefreshLossModel` compares all four using expected-loss calculations across workload profiles, and `StaleWindowSlo` monitors percentile staleness with configurable breach detection.

**Q: Why not tokio?**
A: We need structured concurrency without orphan tasks, cooperative cancellation via a capability context threaded through every call, two-phase reserve/commit channels that don't lose data on cancel, deterministic testing under virtual time with DPOR, and a per-operation poll budget. asupersync provides all of these; tokio provides none of them.

**Q: What does `--background-repair` actually do?**
A: It turns mounted scrub from detection-only into recovery-enabled. The `ScrubDaemon` runs as part of the mount lifecycle; on a corruption detect, it loads RaptorQ repair symbols, decodes the original data, validates the result, and writes the corrected block back. On read-only mounts this uses direct backing-image authority; on read-write mounts it routes through the MVCC repair-writeback serializer so repair writes share the serialization boundary with client writes. Every step emits structured evidence to the JSONL ledger.

**Q: What if I just want to look inside an image without mounting it?**
A: `ffs inspect`, `ffs info`, and `ffs dump` operate without FUSE; they read the image directly via seeked I/O. No `sudo` required, no FUSE headers needed, no kernel module loading.

**Q: How is this different from the kernel ext4 + btrfs?**
A: Same on-disk format for the tracked V1 features, with different internals: MVCC experiments beside journal semantics, RaptorQ repair-symbol experiments beside existing scrub/fsck workflows, expected-loss decision models, structured concurrency, zero unsafe code in FrankenFS crates, and userspace FUSE instead of kernel modules.

---

## Documentation

| Document | Size | What it covers |
|---|---|---|
| [`COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md`](COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md) | 344 KB | Canonical specification, all subsystems |
| [`EXISTING_EXT4_BTRFS_STRUCTURE.md`](EXISTING_EXT4_BTRFS_STRUCTURE.md) | 94 KB | Behavioral extraction from Linux kernel ext4/btrfs source |
| [`PLAN_TO_PORT_FRANKENFS_TO_RUST.md`](PLAN_TO_PORT_FRANKENFS_TO_RUST.md) | 79 KB | 9-phase porting roadmap with scope and acceptance criteria |
| [`PROPOSED_ARCHITECTURE.md`](PROPOSED_ARCHITECTURE.md) | 24 KB | 21-crate architecture, trait hierarchy, data flow |
| [`FEATURE_PARITY.md`](FEATURE_PARITY.md) | 72 KB | Quantitative implementation coverage |
| [`CHANGELOG.md`](CHANGELOG.md) | n/a | Project history organized by capability area |
| [`AGENTS.md`](AGENTS.md) | 43 KB | Guidelines for AI coding agents working in this codebase |

### Design documents

| Document | What it covers |
|---|---|
| [`design-writeback-cache-mvcc.md`](docs/design-writeback-cache-mvcc.md) | FUSE writeback-cache reordering model, 6 formal invariants, epoch fence state machine, 12-scenario crash matrix |
| [`design-repair-writeback-serialization.md`](docs/design-repair-writeback-serialization.md) | Read-write mounted repair writeback serialization contract, stale-snapshot rejection invariants, evidence fields |
| [`design-safe-merge-taxonomy.md`](docs/design-safe-merge-taxonomy.md) | Safe-merge proof obligations for concurrent block writes |
| [`design-adaptive-refresh.md`](docs/design-adaptive-refresh.md) | Expected-loss model for age-only vs block-count vs hybrid refresh triggers |
| [`design-multi-host-repair.md`](docs/design-multi-host-repair.md) | Optimistic lease-based repair ownership for shared storage |
| [`mount-runtime-modes.md`](docs/mount-runtime-modes.md) | `standard` / `managed` / `per-core` operator contract |
| [`oq1-native-mode-boundary.md`](docs/oq1-native-mode-boundary.md) | Kernel FUSE boundary semantics for native-mode operations |
| [`oq7-version-store-format.md`](docs/oq7-version-store-format.md) | `BlockVersion` on-disk persistence format |
| [`tracker-hygiene.md`](docs/tracker-hygiene.md) | Source-aware queue-state semantics and claimability rules |
| [`xfstests-known-failures.md`](docs/xfstests-known-failures.md) | xfstests allowlist with rationale |

---

## References and Inspirations

### RFCs and standards

- **RFC 6330**: *RaptorQ Forward Error Correction Scheme for Object Delivery* (Watson, Stockhammer, Luby, IETF, August 2011). The fountain code at the heart of FrankenFS self-healing.
- **POSIX.1-2017**: *IEEE Std 1003.1-2017*. The semantic baseline for filesystem operations exposed via FUSE.
- **FUSE protocol**: Linux kernel `include/uapi/linux/fuse.h`; ABI 7.40 specifically, exposed through the vendored `fuser` crate.

### Papers underpinning the design

- Megiddo and Modha, *ARC: A Self-Tuning, Low Overhead Replacement Cache*, USENIX FAST 2003. The adaptive cache algorithm behind `ArcCache<D>` in `ffs-block`.
- Yang et al, *FIFO Queues are All You Need for Cache Eviction*, ACM SOSP 2023. The S3-FIFO alternative.
- Cahill, Röhm, Fekete, *Serializable Isolation for Snapshot Databases*, ACM SIGMOD 2008. The SSI two-edge rw-antidependency detection used in `ffs-mvcc`'s commit path.
- Flanagan and Godefroid, *Dynamic Partial-Order Reduction for Model Checking Software*, ACM POPL 2005. The DPOR algorithm used by `LabRuntime`.
- Abdulla, Aronis, Jonsson, Sagonas, *Optimal Dynamic Partial Order Reduction*, ACM POPL 2014. The optimal variant.
- Bernstein, Hadzilacos, Goodman, *Concurrency Control and Recovery in Database Systems*, 1987. Foundational MVCC theory.
- Reed, *Naming and Synchronization in a Decentralized Computer System*, MIT, 1978. The original snapshot-isolation paper.
- Mattern, *Virtual Time and Global States of Distributed Systems*, Parallel and Distributed Algorithms, 1989. The conceptual basis for virtual-time schedule exploration.
- O'Connor, Aumasson, Neves, Wilcox-O'Hearn, *BLAKE3: One Function, Fast Everywhere*, 2020. The cryptographic hash used in native mode.
- Castagnoli, Bräuer, Herrmann, *Optimization of Cyclic Redundancy-Check Codes with 24 and 32 Parity Bits*, IEEE Trans. Comm. 1993. Origin of the CRC32C polynomial.

### Linux kernel sources

The behavioral spec extracted in `EXISTING_EXT4_BTRFS_STRUCTURE.md` (94 KB) is rooted in the Linux v6.19 kernel sources:

```
fs/ext4/super.c             ext4 superblock and mount behavior
fs/ext4/inode.c             ext4 inode lifecycle
fs/ext4/extents.c           ext4 extent tree
fs/ext4/balloc.c            ext4 block allocation
fs/ext4/mballoc.c           multi-block allocator
fs/ext4/namei.c             path resolution, htree
fs/ext4/dir.c               directory entries
fs/ext4/xattr.c             extended attributes
fs/ext4/orphan.c            orphan recovery
fs/ext4/fast_commit.c       fast-commit replay
fs/ext4/crypto.c            encryption (nokey mode)
fs/ext4/inline.c            inline data
fs/jbd2/recovery.c          JBD2 journal recovery
fs/btrfs/super.c            btrfs superblock and mount
fs/btrfs/disk-io.c          on-disk I/O
fs/btrfs/ctree.c            btrfs B-tree
fs/btrfs/extent-tree.c      extent allocation
fs/btrfs/transaction.c      transactions
fs/btrfs/tree-log.c         tree-log replay
fs/btrfs/scrub.c            scrub
fs/btrfs/send.c             send/receive
fs/btrfs/volumes.c          chunks, devices, RAID
fs/btrfs/delayed-ref.c      delayed refs
fs/btrfs/compression.c      compressed extents
fs/btrfs/ioctl.c            ioctl surface
```

For the original source: `git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git` at tag `v6.19`.

### Sibling projects

- **[asupersync](https://github.com/Dicklesworthstone/asupersync)**: the structured-concurrency runtime, capability context, RaptorQ pipeline, and deterministic lab runtime.
- **[ftui (frankentui)](https://github.com/Dicklesworthstone/frankentui)**: the terminal-UI framework used by `ffs-tui`.
- **[FrankenSQLite](https://github.com/Dicklesworthstone/frankensqlite)**: the original spec-first port that this project's doctrine descends from. The repair-symbol design and self-healing approach were extracted from FrankenSQLite's storage layer.
- **[beads_rust](https://github.com/Dicklesworthstone/beads_rust)** (`br`): the local-first issue tracker used by the project (`.beads/issues.jsonl`).

### Tooling and Rust ecosystem

- `crossbeam-epoch` for EBR (Niko Matsakis, Aaron Turon, and the crossbeam team).
- `proptest` for property-based testing.
- `criterion` for statistically rigorous benchmarking.
- `insta` for snapshot testing.
- `serde` / `serde_json` for the evidence-ledger and proof-bundle serialization.
- `tracing` and `tracing-subscriber` for structured diagnostics.
- `thiserror` for the `FfsError` derive.
- `clap` for the CLI argument parsing.

---

## Acknowledgments

FrankenFS exists because of decades of accumulated kernel-filesystem work in C. The behavioral contracts extracted into `EXISTING_EXT4_BTRFS_STRUCTURE.md` are the distilled product of:

- The ext4 maintainers (Ted Ts'o, Andreas Dilger, Jan Kara, and many others), who built ext4 over 18+ years.
- The btrfs team (Chris Mason, Josef Bacik, David Sterba, and the Facebook / SUSE / Oracle btrfs developers).
- The JBD2 layer maintainers who kept ext4's journaling honest.
- The `e2fsprogs` and `btrfs-progs` userspace tool authors, whose code is the reference for many corner cases.

This project does not, and cannot, replace the kernel implementations. It is a research vehicle for asking what these filesystems would look like with modern concurrency control, structured concurrency, fountain-code self-healing, and a memory-safe implementation language. Every external behavior FrankenFS supports is required to match the kernel reference on a CRC-valid image; every deviation is either explicitly out-of-scope or filed as a parity gap in `FEATURE_PARITY.md`.

---

## About Contributions

Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

[MIT License (with OpenAI/Anthropic Rider)](LICENSE)
