# AGENTS.md — FrankenFS (ffs)

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE 0.5 - SUITE-WIDE RULES LIVE IN /data/projects/AGENTS.md

The suite-wide rules in **`/data/projects/AGENTS.md`** bind you here too. Read it. Two sections
are load-bearing for perf work and are NOT duplicated below, so they cannot drift out of sync:

- **`## Named Reward-Hacking Patterns (ALL FORBIDDEN)`** — 12 named patterns, several already
  observed in this suite: gate self-weakening (and the exact price of a legitimate gate fix),
  proof-class inflation, golden regeneration reflex, commit-stream pumping, tautological tests,
  easy-lever cherry-picking, close-pump abuse, scope-splitting, spec-editing as progress,
  conformance metastasis, dependency smuggling, bench-path hardcoding.
- **`### Work-Graph Discipline`** — JSONL is truth and `beads.db` is disposable, `br sync
  --import-only` after every pull, single-writer on graph structure, closure on cited evidence
  with blocker beads gated on their named probe, `br dep cycles` stays empty.

The three that most often decide whether a number here is real: a **self-speedup is
MAINTENANCE, not a win** — a win needs the incumbent live in the SAME invocation; **never
weaken a gate to land a change**, and if a gate is genuinely defective, meet the evidence
standard and publish the win/lose split of what the fix admits; and **reporting a loss is a
success** — one line, revert, next lever, no retraction narrative.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main:master`

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required — see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability and reproducibility
- **Configuration:** Cargo.toml workspace with `workspace = true` pattern
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]` at crate roots + workspace lint)

### Async Runtime: asupersync (MANDATORY — NO TOKIO)

**This project uses [asupersync](/dp/asupersync) exclusively for all async/concurrent operations. Tokio and the entire tokio ecosystem are FORBIDDEN.**

- **Structured concurrency**: `Cx`, `Scope`, `region()` — no orphan tasks
- **Cancel-correct channels**: Two-phase `reserve()/send()` — no data loss on cancellation
- **Sync primitives**: `asupersync::sync::Mutex`, `RwLock`, `OnceCell`, `Pool` — cancel-aware
- **Deterministic testing**: `LabRuntime` with virtual time, DPOR, oracles
- **No ambient authority.** Cancellation/deadline-sensitive operations should take `&asupersync::Cx`

**Forbidden crates**: `tokio`, `hyper`, `reqwest`, `axum`, `tower` (tokio adapter), `async-std`, `smol`, or any crate that transitively depends on tokio.

**Pattern**: All async functions take `&Cx` as first parameter. The `Cx` flows down from the consumer's runtime — FrankenFS does NOT create its own runtime.

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `asupersync` | Structured async runtime (channels, sync, regions, `Cx`, deterministic lab runtime, RaptorQ pipeline) |
| `ftui` (frankentui) | Terminal UX for CLI diagnostics and tooling |
| `bitflags` | On-disk flag field modeling |
| `blake3` | Fast cryptographic hashing for block integrity |
| `crc32c` | CRC32C checksums (ext4/btrfs on-disk format) |
| `xxhash-rust` | XXH3 non-cryptographic hashing for hot paths |
| `memchr` | Hot path byte scanning |
| `smallvec` | Hot path stack-allocated vectors |
| `fuser` | FUSE userspace filesystem interface |
| `serde` + `serde_json` | Fixtures, conformance vectors, metadata reports |
| `thiserror` | Ergonomic error type derivation |
| `tracing` | Structured logging and diagnostics |
| `criterion` | Performance benchmarks |
| `proptest` | Property-based testing |
| `tempfile` | Temporary file/directory creation for tests |
| `insta` | Snapshot testing |

### Release Profile

The release build optimizes for size (this is a filesystem, size matters for embedded/mount contexts):

```toml
[profile.release]
opt-level = "z"       # Size-optimized
lto = true            # Link-time optimization
codegen-units = 1     # Single codegen unit for better optimization
panic = "abort"       # No unwinding overhead
strip = true          # Remove debug symbols

[profile.release-perf]
inherits = "release"
opt-level = 3         # Max speed for benchmark profiling
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings (workspace-wide)
cargo check --workspace --all-targets

# Check for clippy lints (pedantic + nursery are enabled)
cargo clippy --workspace --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

For perf/conformance work, also run:

```bash
cargo test -p ffs-harness -- --nocapture
cargo bench -p ffs-harness
```

If a gate fails, fix root causes instead of suppressing diagnostics.

---

## Testing

### Testing Policy

Every component crate includes inline `#[cfg(test)]` unit tests alongside the implementation. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

Cross-component integration tests primarily live in crate-local `crates/*/tests/` suites. Shared sparse parser/conformance fixtures live under `conformance/fixtures/`, while the workspace `tests/` directory provides shared golden outputs, images, and fuzz corpus consumed by those suites.

### Unit Tests

```bash
# Run all tests across the workspace
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run tests for a specific crate
cargo test -p ffs-types
cargo test -p ffs-error
cargo test -p ffs-ondisk
cargo test -p ffs-block
cargo test -p ffs-journal
cargo test -p ffs-mvcc
cargo test -p ffs-btree
cargo test -p ffs-alloc
cargo test -p ffs-inode
cargo test -p ffs-dir
cargo test -p ffs-extent
cargo test -p ffs-xattr
cargo test -p ffs-fuse
cargo test -p ffs-repair
cargo test -p ffs-core
cargo test -p ffs-harness

# Run tests with all features enabled
cargo test --workspace --all-features
```

### Test Categories

| Crate | Focus Areas |
|-------|-------------|
| `ffs-types` | On-disk type definitions, flag fields, size constants |
| `ffs-error` | Error type derivation, error propagation contracts |
| `ffs-ondisk` | Superblock parsing, on-disk structure round-trip, endianness |
| `ffs-block` | Block I/O, block cache, read/write correctness |
| `ffs-journal` | Journal replay, transaction commit/abort, recovery |
| `ffs-mvcc` | MVCC snapshot isolation, COW semantics, conflict detection |
| `ffs-btree` | B-tree insert/delete/lookup, rebalancing, iteration |
| `ffs-alloc` | Block/inode allocation, free space tracking, bitmap ops |
| `ffs-inode` | Inode lifecycle, metadata read/write, permission checks |
| `ffs-dir` | Directory entry management, lookup, hash-tree directories |
| `ffs-extent` | Extent tree operations, allocation, splitting, merging |
| `ffs-xattr` | Extended attribute get/set/list/remove |
| `ffs-fuse` | FUSE mount surface integration |
| `ffs-repair` | Self-healing durability, fountain-code repair workflows |
| `ffs-core` | High-level filesystem orchestration |
| `ffs-harness` | Conformance harness, fixture-driven golden tests, benchmarks |
| `ffs-ext4` | Legacy ext4 format extraction reference |
| `ffs-btrfs` | Btrfs structures/tree/mutation logic used by `ffs-core`, plus legacy extraction reference coverage |
| `conformance/` (workspace) | Shared sparse parser/conformance fixtures consumed by harness + integration suites |
| `tests/` (workspace) | Shared golden outputs, generated images, and fuzz corpus consumed by integration suites |
| `crates/*/benches/` | Crate-local performance benchmarks with regression detection |

### Test Fixtures

`conformance/fixtures/` provides the sparse parser/conformance fixtures used by `ffs-harness` and integration suites, while `tests/fixtures/` stores generated images plus golden JSON outputs for ext4/btrfs inspection behavior.

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## FrankenFS — This Project

**This is the project you're working on.** FrankenFS (ffs) is a memory-safe, clean-room Rust reimplementation of ext4 and btrfs with a higher-level architecture that combines mount-compatible behavior, MVCC + copy-on-write internals, and self-healing durability via fountain-code-based repair workflows.

### What It Does

Provides a unified filesystem that can mount ext4/btrfs images in Linux userspace (FUSE), with MVCC/COW transaction semantics for concurrent writers and fountain-code-based self-healing repair for durability.

### Architecture

```
Image/VFS I/O
  -> Format adapters (ext4 + btrfs parsers/encoders)
  -> MVCC/COW transaction engine
  -> Self-healing durability layer (repair symbols + decode proofs)
  -> FUSE mount surface (Linux userspace)
  -> CLI + harness + conformance + perf gates
```

### Workspace Structure

```
frankenfs/
├── Cargo.toml                     # Workspace root
├── crates/
│   ├── ffs-types/                 # On-disk type definitions, constants, flag fields
│   ├── ffs-error/                 # Unified error types (thiserror-derived)
│   ├── ffs-ondisk/                # Superblock, group descriptor, on-disk structure parsing
│   ├── ffs-block/                 # Block I/O layer, block cache
│   ├── ffs-journal/               # Journal/transaction commit, replay, recovery
│   ├── ffs-mvcc/                  # MVCC snapshot isolation, COW engine
│   ├── ffs-btree/                 # Extent-tree/B-tree operations (ext4-focused, plus Bw-tree experiments)
│   ├── ffs-alloc/                 # Block/inode allocation, free space management
│   ├── ffs-inode/                 # Inode lifecycle and metadata
│   ├── ffs-dir/                   # Directory entry management
│   ├── ffs-extent/                # Extent tree operations
│   ├── ffs-xattr/                 # Extended attributes
│   ├── ffs-fuse/                  # FUSE mount surface
│   ├── ffs-repair/                # Self-healing repair (fountain codes)
│   ├── ffs-core/                  # High-level orchestration
│   ├── ffs/                       # Facade crate (thin re-export of `ffs-core` public API)
│   ├── ffs-cli/                   # CLI binary
│   ├── ffs-tui/                   # TUI diagnostics (frankentui)
│   ├── ffs-harness/               # Conformance harness + benchmarks
│   ├── ffs-ext4/                  # Legacy ext4 extraction reference
│   └── ffs-btrfs/                 # Btrfs tree/mutation layer + legacy extraction reference
├── conformance/                   # Shared sparse parser/conformance fixtures
│   ├── fixtures/                  # Sparse JSON fixtures used by ffs-harness
│   └── golden/                    # Additional conformance artifacts
├── tests/                         # Shared goldens, images, and fuzz corpus
│   ├── fixtures/                  # Generated images + golden inspect outputs
│   └── fuzz_corpus/               # Shared fuzz seeds
├── crates/*/benches/              # Crate-local performance benchmarks
└── (legacy_ext4_and_btrfs_code/)  # Original C source (gitignored; see kernel.org v6.19)
```

### Key Files by Crate

| Crate | Key Domain | Purpose |
|-------|------------|---------|
| `ffs-types` | Primitives | On-disk type definitions, size constants, flag field bitflags |
| `ffs-error` | Errors | Unified `FfsError` enum across all crates (thiserror-derived) |
| `ffs-ondisk` | Parsing | Superblock, group descriptors, on-disk structure serialization/deserialization |
| `ffs-block` | Storage | Block device I/O abstraction, block cache, read/write paths |
| `ffs-journal` | Durability | Journal transaction commit/abort, log replay, crash recovery |
| `ffs-mvcc` | Concurrency | MVCC snapshot isolation, copy-on-write engine, conflict detection |
| `ffs-btree` | Indexing | Extent-tree/B-tree insert/delete/lookup/iterate, node splitting/merging |
| `ffs-alloc` | Allocation | Block and inode allocators, free space bitmaps, group management |
| `ffs-inode` | Metadata | Inode create/read/update/delete, permission and timestamp management |
| `ffs-dir` | Directories | Directory entry CRUD, hash-tree directories, name lookup |
| `ffs-extent` | Mapping | Extent tree operations, block mapping, extent splitting/merging |
| `ffs-xattr` | Attributes | Extended attribute get/set/list/remove |
| `ffs-fuse` | Mount | FUSE userspace mount surface, VFS dispatch |
| `ffs-repair` | Healing | Fountain-code-based self-healing, repair symbol generation, decode proofs |
| `ffs-core` | Orchestration | High-level filesystem operations, format adapter coordination |
| `ffs-harness` | Testing | Conformance harness, fixture-driven golden tests, benchmark suite |

### Core Types Quick Reference

| Type | Purpose |
|------|---------|
| `Cx` | asupersync capability context — passed to all async operations |
| `FfsError` | Unified error enum across all crates (thiserror-derived) |
| `Superblock` | On-disk superblock structure (ext4/btrfs format-aware) |
| `BlockDevice` | Block I/O abstraction trait |
| `Transaction` | Journal transaction handle |
| `Snapshot` | MVCC snapshot for consistent reads |
| `BTree` / `BTreeNode` | B-tree index structures |
| `Inode` | In-memory inode representation |
| `DirEntry` | Directory entry structure |
| `Extent` | Block mapping extent |
| `RepairSymbol` | Fountain code repair symbol for self-healing |

### Key Design Decisions

- **No line-by-line translation from C.** Extract behavior, then re-implement idiomatically in Rust
- **No compatibility shims for bad designs.** If legacy behavior is flawed but externally observable, preserve the observable contract while fixing internals
- **No ambient authority.** Cancellation/deadline-sensitive operations take `&asupersync::Cx`
- **Deterministic testability.** Concurrency-sensitive logic must be testable under asupersync lab runtime
- **Proof-first for risky logic.** Include invariants, explicit error budgets, and evidence for conflict-resolution policies
- **Spec-first porting doctrine:** Extract behavior into spec docs first, then implement from the spec — conformance harness is the arbiter, not vibes
- **FUSE boundary isolation.** FUSE-specific logic stays in dedicated crate boundaries; format adapters stay independent of transport/mount frontends
- **Compatibility mode preserves on-disk interpretation** of ext4/btrfs images where declared supported
- **Native mode innovations** (MVCC/COW/self-heal) preserve correctness and explicit conversion semantics
- **Alien-artifact quality bar** for high-risk subsystems: Bayesian evidence updates, expected-loss decision rules, anytime-valid monitoring, deterministic audit logs
- **asupersync exclusively** — NO tokio/reqwest/hyper. All async via `Cx` + structured concurrency
- **LabRuntime for deterministic tests** — virtual time, DPOR schedule exploration, correctness oracles
- **Cancel-correct lifecycle** — background workers use asupersync regions, channels use two-phase reserve/commit

---

## Required Spec Documents

These files are mandatory and must stay current:

1. `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` (canonical source of truth)
2. `PLAN_TO_PORT_FRANKENFS_TO_RUST.md` (scope, exclusions, sequencing)
3. `EXISTING_EXT4_BTRFS_STRUCTURE.md` (behavior extraction from legacy code)
4. `PROPOSED_ARCHITECTURE.md` (Rust crate/module architecture)
5. `FEATURE_PARITY.md` (measured parity status and gaps)

Legacy bootstrap documents (retained only for history; do not treat as canonical):
- `PLAN_TO_PORT_LEGACY_FS_TO_RUST.md`
- `docs/planning/EXISTING_LEGACY_FS_STRUCTURE.md`

Reference artifact copied from FrankenSQLite:
- `COMPREHENSIVE_SPEC_FOR_FRANKENSQLITE_V1.md`

Use that document as a strategy template, not as a direct filesystem specification.

---

## Porting Doctrine (Spec-First, Conformance-First)

Follow this sequence:

1. **Extract behavior from legacy ext4/btrfs code** into `EXISTING_EXT4_BTRFS_STRUCTURE.md`
2. **Design Rust architecture** in `PROPOSED_ARCHITECTURE.md`
3. **Implement from spec** (not by copying C flow)
4. **Validate via conformance harness**
5. **Track parity numerically** in `FEATURE_PARITY.md`

### Explicit Exclusions (for now)

Anything excluded must be listed explicitly in:
- `PLAN_TO_PORT_FRANKENFS_TO_RUST.md`
- `FEATURE_PARITY.md`

Hidden exclusions are not allowed.

### Legacy Source Navigation

Primary legacy kernel modules (Linux v6.19 from `git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`):

| Kernel Path | Domain |
|-------------|--------|
| `fs/ext4/super.c` | ext4 superblock and mount behavior |
| `fs/ext4/inode.c` | ext4 inode lifecycle |
| `fs/ext4/extents.c` | ext4 extent tree operations |
| `fs/btrfs/super.c` | btrfs superblock and mount behavior |
| `fs/btrfs/ctree.c` | btrfs tree ops |
| `fs/btrfs/extent-tree.c` | extent allocation/reference logic |
| `fs/btrfs/transaction.c` | transaction semantics |

> **Note:** The kernel source corpus is gitignored due to size (~205K lines). Extracted behavioral contracts are in [EXISTING_EXT4_BTRFS_STRUCTURE.md](EXISTING_EXT4_BTRFS_STRUCTURE.md).

---

## Conformance and Benchmarking Requirements

FrankenFS must include:

1. **Fixture-based conformance tests** (goldens for ext4/btrfs metadata behavior)
2. **Legacy behavior mapping** (feature-to-source traceability)
3. **Benchmark suite** with baselines and regression detection
4. **Feature parity report** with explicit percentages and blocked items

### Benchmark Loop (mandatory)

- Baseline first (`hyperfine`)
- Profile hotspots
- Apply one optimization lever at a time
- Prove behavioral equivalence after each change
- Re-measure and record deltas

---

## Playbooks

### Session Start Ritual (Cass-Proven)

1. Read `AGENTS.md` and `README.md` fully.
2. Get oriented: run `git status --porcelain`, `bv --robot-next`, `br ready --json`.
   If raw `br`/`bv` output hangs, includes foreign-looking rows, or promotes
   permissioned work without the required ACK, consult
   [docs/tracker-hygiene.md](docs/tracker-hygiene.md) and run the source-aware
   queue-state check before claiming anything:
   ```bash
   TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
   ```
   Use the local script for live tracker triage because it reads the current
   workspace JSONL directly. Route cargo-based validator runs through `rch`
   when you need the Rust harness gate, but do not trust a remote worker's stale
   tracker snapshot as the local claimability source.
   Treat `source_aware_queue_state.verdict`, `claimable_ids`,
   `permission_gated_ids`, and `excluded_foreign_open_count` as the safe
   claimability signal under tracker pollution. Do not delete, rewrite, close,
   or rename foreign-looking rows merely because they appear in raw triage.
3. Claim exactly one bead and announce it to other agents (Agent Mail thread = bead ID).
4. Make the smallest correct change set that advances parity, specs, or conformance.
5. Run gates (fmt/check/clippy/test) before claiming "done".

### Cass Archaeology (Context Recovery)

Rules:
- Do not pipe large cass outputs to `head`/`tail` (broken pipe panics). Redirect to a file, then inspect the file.

Copy-paste workflow:

```bash
# Health + refresh (always first)
cass status --json && cass index --json

# Terrain scan: who did what, when?
cass search "*" --workspace /data/projects/frankenfs --aggregate agent,date --limit 1 --json

# Find the exact prior discussion/prompt
cass search "KEYWORD" --workspace /data/projects/frankenfs --json --fields minimal --limit 50

# Follow a hit
cass view /path/from/source_path.jsonl -n LINE -C 20
cass expand /path/from/source_path.jsonl --line LINE --context 3
cass context /path/from/source_path.jsonl --json
```

### Alien-Artifact Mode (Principled, Auditable Decisions)

Use when logic is high-risk (MVCC conflict rules, repair policy, consistency, corruption decisions).

Elicitation prompt (copy-paste):

```
Now, TRULY think even harder. Surely there is some math invented in the
last 60 years that would be relevant and helpful here? Super hard, esoteric
math that would be ultra accretive and give a ton of alpha for the specific
problems we're trying to solve here, as efficiently as possible?

REALLY RUMINATE ON THIS!!! DIG DEEP!!

STUFF THAT EVEN TERRY TAO WOULD HAVE TO CONCENTRATE SUPER HARD ON!
```

Required outputs for "alien artifact" quality work:
- Explicit invariants (what MUST remain true).
- Evidence ledger (what evidence drove what decision).
- Loss matrix / expected-loss rule for any threshold-like decision.

### Extreme Optimization Loop (One Lever, Behavior-Proven)

Rules:
- Profile first.
- One optimization lever per commit.
- Prove behavior unchanged (goldens or invariants) for every change.

```bash
# Baseline
hyperfine --warmup 3 --runs 10 'COMMAND'

# Verify unchanged behavior (example pattern)
sha256sum golden_outputs/* > golden_checksums.txt
sha256sum -c golden_checksums.txt
```

Isomorphism proof template (required for perf work):
- Ordering preserved: yes/no + why
- Tie-breaking unchanged: yes/no + why
- Floating-point identical: identical/N/A
- RNG seeds unchanged: unchanged/N/A
- Goldens verified: `sha256sum -c golden_checksums.txt` (or equivalent)

### Porting-To-Rust Essence Extraction (Spec-First)

Rules:
- Never translate C line-by-line.
- Extract behavior into spec docs first, then implement from the spec.
- Conformance harness is the arbiter, not vibes.

Minimal checklist:
1. Extract behavior into `EXISTING_EXT4_BTRFS_STRUCTURE.md` (what, not how).
2. Update `PROPOSED_ARCHITECTURE.md` (crate/module boundaries, trait contracts).
3. Implement idiomatically in Rust.
4. Add/extend fixtures + harness tests.
5. Update `FEATURE_PARITY.md` in the same change set.

### Output Expectations

- Be direct, technical, and explicit
- Quantify parity and performance claims
- Prefer table-driven status reporting
- Clearly separate: implemented, partially implemented, not implemented

No hand-wavy "done" claims without tests, metrics, and parity evidence.

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```
   If this is stale, hangs, or includes foreign project rows, use the
   source-aware tracker hygiene report before claiming work:
   ```bash
   TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
   ```
   For the Rust validator path, use `rch exec -- cargo run -p ffs-harness --`
   rather than local cargo, and compare its tracker snapshot to the local JSONL
   before relying on it for claims.
   Claim only IDs listed in `source_aware_queue_state.claimable_ids`.
   Permission-gated IDs require the exact ACKs listed in the report, and
   foreign-looking IDs require owner handoff rather than local mutation.

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point when the tracker is source-clean.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

If `bv` recommendations include foreign-looking rows or permissioned rows that
cannot be executed in the current environment, treat `bv` as graph context only
and switch to the source-aware queue-state workflow in
[docs/tracker-hygiene.md](docs/tracker-hygiene.md). Raw graph rank is not a
claim signal when `source_aware_queue_state.verdict` says there is no safe
local claimable work.

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
  Category (N errors)
    file.rs:42:5 - Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | fix -> how to fix | Exit 0/1 -> pass/fail

### Fix Workflow

1. Read finding -> category + fix suggestion
2. Navigate `file:line:col` -> view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` -> exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of 8 remote Contabo VPS workers instead of building locally. This prevents compilation storms from overwhelming csd when many agents run simultaneously.

**RCH is installed at `~/.local/bin/rch` and is hooked into Claude Code's PreToolUse automatically.** Most of the time you don't need to do anything if you are Claude Code — builds are intercepted and offloaded transparently.

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, but you can (and should) still manually offload compute-intensive compilation commands using `rch exec -- <command>`. This avoids local resource contention when multiple agents are building simultaneously.

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** -> `ast-grep`
- Need raw speed or **hunting text** -> `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Rust Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Rust -p 'fn $NAME($$$ARGS) -> $RET { $$$BODY }'

# Find all unwrap() calls
ast-grep run -l Rust -p '$EXPR.unwrap()'

# Quick textual hunt
rg -n 'println!' -t rust

# Combine speed + precision
rg -l -t rust 'unwrap\(' | xargs ast-grep run -l Rust -p '$X.unwrap()' --json
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How does the MVCC engine work?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is the repair workflow implemented?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `BlockDevice::read`" | `ripgrep` | Targeted literal search |
| "Find files with `println!`" | `ripgrep` | Simple pattern |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/dp/frankenfs",
  query: "How does the MVCC snapshot isolation work?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name -> use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" -> wastes time with manual reads
- **Don't** use `ripgrep` for codemods -> risks collateral edits

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress -> closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `br sync --flush-only` to export to JSONL
5. **Hand off** - Provide context for next session


---

## cass — Cross-Agent Session Search

`cass` indexes prior agent conversations (Claude Code, Codex, Cursor, Gemini, ChatGPT, etc.) so we can reuse solved problems.

**Rules:** Never run bare `cass` (TUI). Always use `--robot` or `--json`.

### Examples

```bash
cass health
cass search "async runtime" --robot --limit 5
cass view /path/to/session.jsonl -n 42 --json
cass expand /path/to/session.jsonl -n 42 -C 3 --json
cass capabilities --json
cass robot-docs guide
```

### Tips

- Use `--fields minimal` for lean output
- Filter by agent with `--agent`
- Use `--days N` to limit to recent history

stdout is data-only, stderr is diagnostics; exit code 0 means success.

Treat cass as a way to avoid re-solving problems other agents already handled.

---

Note for Codex/GPT-5.2:

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/cli/commands/upgrade.rs, src/storage/sqlite.rs, tests/conformance.rs, tests/storage_deps.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
2. Triage beads_rust-orko (clippy/cargo warnings) and beads_rust-ydqr (rustfmt failures).
3. If you want a full suite run later, fix conformance/clippy blockers and re-run cargo test --all.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.
