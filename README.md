<p align="center">
  <br>
  <code>&nbsp;╔═╗┬─┐┌─┐┌┐┌┬┌─┌─┐┌┐┌╔═╗╔═╗&nbsp;</code><br>
  <code>&nbsp;╠╣ ├┬┘├─┤│││├┴┐├┤ │││╠╣ ╚═╗&nbsp;</code><br>
  <code>&nbsp;╚  ┴└─┴ ┴┘└┘┴ ┴└─┘┘└┘╚  ╚═╝&nbsp;</code><br>
  <br>
  <strong>Memory-safe ext4 + btrfs in Rust, from userspace</strong><br>
  <em>Block-level MVCC &middot; RaptorQ self-healing &middot; Zero unsafe code</em>
</p>

<p align="center">
  <a href="https://github.com/Dicklesworthstone/frankenfs/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-nightly%202024-orange.svg" alt="Rust Nightly"></a>
  <img src="https://img.shields.io/badge/unsafe-forbidden-brightgreen.svg" alt="Unsafe Forbidden">
  <img src="https://img.shields.io/badge/status-early%20development-yellow.svg" alt="Early Development">
</p>

---

## TL;DR

**The problem:** Linux filesystems are trapped in kernel space. ext4 is 30 years old with a global journal lock (JBD2) that serializes all writes. btrfs has better internals but remains kernel-only, hard to test, and impossible to extend from userspace. Both lack automatic corruption recovery — you run `fsck` after the fact and hope.

**The solution:** FrankenFS extracts the *behavior* of ext4 and btrfs from ~205K lines of Linux kernel C (v6.19) and re-implements it idiomatically in Rust as a FUSE filesystem. It reads real ext4/btrfs disk images today (with experimental read-only ext4 mount) and is evolving toward safe write-path support, while adding two structural innovations that the kernel implementations can't:

| What | How | Why it matters |
|------|-----|----------------|
| **Block-level MVCC** | Version chains per block, snapshot isolation, first-committer-wins conflict detection | Concurrent readers + writers without the JBD2 global lock. Multi-writer throughput scales with core count. |
| **RaptorQ self-healing** | Fountain-coded repair symbols (RFC 6330) stored alongside each block group | Corruption detected by checksums triggers automatic recovery. No separate fsck pass. No downtime. |
| **Memory safety** | `#![forbid(unsafe_code)]` at every crate root, Rust 2024 edition | Eliminates the buffer overflows and use-after-free bugs that plague kernel C filesystem code. |
| **Userspace FUSE** | Runs as a normal process via FUSE | Debug with standard tools. No kernel module loading. No reboot-on-crash. |

---

## Quick Example

```bash
# Clone and build
git clone https://github.com/Dicklesworthstone/frankenfs.git
cd frankenfs
cargo build --workspace

# Inspect an ext4 image
cargo run -p ffs-cli -- inspect /path/to/ext4.img --json

# Inspect a btrfs image
cargo run -p ffs-cli -- inspect /path/to/btrfs.img --json

# Run conformance checks against real filesystem images
cargo run -p ffs-harness -- check-fixtures
cargo run -p ffs-harness -- parity

# Full CI gate
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

---

## Design Philosophy

### 1. Spec-first, not translation

FrankenFS does **not** translate C line-by-line. The porting doctrine is:

1. Extract behavior from legacy kernel code into structured spec documents
2. Design idiomatic Rust architecture from the spec
3. Implement from the spec (not by copying C control flow)
4. Validate via conformance harness against real filesystem images

This produces code that is Rust-native rather than "C with Rust syntax."

### 2. No ambient authority

Every I/O operation takes an `&asupersync::Cx` capability context. This enables cooperative cancellation, deadline propagation, and deterministic testing under a lab runtime. No global state, no hidden singletons.

### 3. Proof over heuristic

For high-risk subsystems (MVCC conflict resolution, self-healing redundancy policy, corruption recovery), FrankenFS uses principled models:

- Bayesian evidence updates for corruption/failure rate estimation
- Expected-loss decision rules for repair symbol overhead
- First-committer-wins with serializable snapshot isolation for conflict detection

If a heuristic must be used, the spec documents why formal alternatives were not viable.

### 4. Layered isolation

Parser crates are pure (no I/O). MVCC knows nothing about files. FUSE knows nothing about on-disk formats. Repair operates on blocks, not inodes. Each concern lives in exactly one crate.

### 5. Zero unsafe, always

`#![forbid(unsafe_code)]` is set at every crate root and enforced as a workspace lint. There are no exceptions and no plans for exceptions.

---

## Comparison with Alternatives

| | FrankenFS | Linux ext4 (kernel) | Linux btrfs (kernel) | ext4fuse | fuse-ext2 |
|---|---|---|---|---|---|
| **Language** | Rust | C | C | C | C |
| **Runs in** | Userspace (FUSE) | Kernel | Kernel | Userspace (FUSE) | Userspace (FUSE) |
| **Memory safety** | `forbid(unsafe_code)` | Manual | Manual | Manual | Manual |
| **ext4 support** | Read (write planned) | Full | N/A | Read-only | Read-write |
| **btrfs support** | Read (write planned) | N/A | Full | N/A | N/A |
| **Both formats** | Yes | No | No | No | No |
| **Concurrent writes** | MVCC (no global lock) | JBD2 (global lock) | COW B-tree | N/A | Single-writer |
| **Self-healing** | RaptorQ fountain codes | None (run fsck) | Scrub + mirrors | None | None |
| **Debuggable** | Standard userspace tools | printk + crash dump | printk + crash dump | gdb | gdb |

---

## Architecture

FrankenFS is a 21-crate Cargo workspace (19 core crates + 2 legacy/reference wrappers) with a strict DAG dependency graph:

```
                    ┌──────────┐  ┌──────────┐
                    │ ffs-types│  │ ffs-error │
                    └────┬─────┘  └─────┬─────┘
                         └──────┬───────┘
                                │
                         ┌──────▼──────┐
                         │  ffs-ondisk  │       ┌──────────┐
                         └──────┬──────┘       │ ffs-mvcc  │
                                │              │           │
              ┌─────────────────┼──────────┐   │           │
              │                 │          │   │           │
       ┌──────▼──────┐  ┌──────▼──────┐  ┌▼───┴──────────┐
       │  ffs-block   │  │  ffs-btree  │  │   ffs-xattr   │
       │  (+ ARC)     │  └──────┬──────┘  └───────────────┘
       └──┬───┬───┬───┘        │
          │   │   │      ┌─────▼─────┐
          │   │   │      │ ffs-alloc  │
          │   │   │      └─────┬─────┘
          │   │   │            │
   ┌──────▼┐  │  ┌▼──────┐  ┌─▼────────┐  ┌──────────────┐
   │ffs-   │  │  │ffs-   │  │ffs-extent│  │  ffs-inode   │
   │journal│  │  │repair │  └──────────┘  └──────┬───────┘
   └───────┘  │  └───────┘                       │
              │                           ┌──────▼──────┐
              │                           │   ffs-dir   │
              │                           └─────────────┘
              │
       ┌──────▼──────┐
       │   ffs-core   │  (orchestrates everything)
       └──┬───────┬───┘
          │       │
   ┌──────▼────┐  │  ┌────────────┐
   │  ffs-fuse  │  │  │    ffs     │  (public facade)
   └────────────┘  │  └──┬───┬────┘
                   │     │   │
           ┌───────┘     │   └────────┐
           │             │            │
    ┌──────▼──┐  ┌──────▼─────┐ ┌───▼────────┐
    │ ffs-cli  │  │  ffs-tui   │ │ ffs-harness │
    └─────────┘  └────────────┘ └────────────┘
```

### Crate Responsibilities

| Layer | Crates | What it does |
|-------|--------|-------------|
| **Foundation** | `ffs-types`, `ffs-error` | Newtypes (`BlockNumber`, `InodeNumber`, `TxnId`), 14-variant error enum, errno mappings |
| **On-disk** | `ffs-ondisk` | Pure parsing of ext4 + btrfs superblocks, group descriptors, inodes, extents, B-tree headers. No I/O. |
| **Storage** | `ffs-block`, `ffs-journal`, `ffs-mvcc` | Block I/O with ARC (Adaptive Replacement Cache), JBD2-compatible journal replay, COW journal, MVCC version chains with snapshot isolation |
| **Tree / Alloc** | `ffs-btree`, `ffs-alloc`, `ffs-extent` | B+tree search/insert/split/merge, mballoc-style multi-block allocator (buddy system), extent mapping (logical-to-physical) |
| **Namespace** | `ffs-inode`, `ffs-dir`, `ffs-xattr` | Inode lifecycle, directory ops (linear scan + htree), extended attributes (user/system/security/trusted) |
| **Interface** | `ffs-fuse`, `ffs-core`, `ffs` | FUSE protocol adapter, engine integration (format detection, mount orchestration, Bayesian durability autopilot), public API facade |
| **Repair** | `ffs-repair` | RaptorQ symbol generation/recovery per block group, background scrub |
| **Tooling** | `ffs-cli`, `ffs-tui`, `ffs-harness` | CLI (`inspect`, planned: `mount`/`fsck`/`repair`), live TUI monitoring, conformance test harness + benchmarks |

### Layering Rules

- **Parser crates are pure.** `ffs-ondisk` performs no I/O — it parses byte slices into typed structures.
- **MVCC is transport-agnostic.** `ffs-mvcc` knows nothing about FUSE, files, or directories.
- **FUSE delegates to ffs-core.** `ffs-fuse` maps FUSE protocol to `ffs-core::FrankenFsEngine` — it contains no filesystem logic.
- **Repair is orthogonal.** `ffs-repair` operates on blocks, not files. It doesn't know about inodes or directories.
- **No dependency cycles.** The crate graph is a strict DAG.
- **`Cx` everywhere.** Any operation that performs I/O or may block takes `&asupersync::Cx` as its first parameter.

---

## Data Flow

### Read Path

```
userspace read(fd, buf, count)
  → kernel FUSE → fuser → ffs-fuse::read()
    → ffs-core: begin read transaction
      → ffs-mvcc: get snapshot, read versioned blocks
        → ffs-extent: resolve logical offset → physical blocks
          → ffs-btree: walk extent B+tree
        → ffs-block: read blocks through ARC cache
          → BlockDevice::read_block()
    → ffs-core: assemble response, end transaction
  → fuser → kernel → userspace
```

### Write Path

```
userspace write(fd, buf, count)
  → kernel FUSE → fuser → ffs-fuse::write()
    → ffs-core: begin write transaction
      → ffs-mvcc: create new block versions (COW)
        → ffs-extent: allocate physical blocks
          → ffs-alloc: mballoc allocation
          → ffs-btree: update extent tree
        → ffs-block: write through cache
      → ffs-journal: record transaction
      → ffs-repair: refresh repair symbols
      → ffs-mvcc: commit (SSI validation)
    → ffs-core: return bytes written
  → fuser → kernel → userspace
```

### Corruption Recovery

```
ffs-repair::scrub() [background]
  → ffs-block: read all blocks in group
    → checksum verification (crc32c or BLAKE3)
    → MISMATCH on block N
      → ffs-repair: load repair symbols
        → asupersync RaptorQ decode
        → recovered block data
      → ffs-block: write corrected block
      → ffs-repair: refresh symbols
      → report: { block: N, status: recovered }
```

---

## Installation

### From Source (only method during early development)

```bash
# Requires Rust nightly (managed automatically via rust-toolchain.toml)
git clone https://github.com/Dicklesworthstone/frankenfs.git
cd frankenfs
cargo build --workspace
```

The `rust-toolchain.toml` pins the nightly channel. Cargo handles the rest.

### Requirements

- **Rust nightly** (edition 2024, minimum version 1.85)
- **Linux** (FUSE target — `libfuse-dev` or `fuse3` for mount support)
- **FUSE headers**: `sudo apt install libfuse-dev` (Debian/Ubuntu) or `sudo dnf install fuse-devel` (Fedora)

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Dicklesworthstone/frankenfs.git
cd frankenfs

# 2. Build
cargo build --workspace

# 3. Run tests
cargo test --workspace

# 4. Inspect a filesystem image
cargo run -p ffs-cli -- inspect /path/to/ext4.img --json

# 5. Run conformance parity report
cargo run -p ffs-harness -- parity
```

---

## Commands

### `ffs-cli`

```bash
# Inspect ext4 or btrfs image metadata (JSON output)
cargo run -p ffs-cli -- inspect <image-path> --json

# Mount an ext4 image via FUSE (read-only)
cargo run -p ffs-cli -- mount <image-path> <mountpoint>

# Run a read-only scrub over image blocks
cargo run -p ffs-cli -- scrub <image-path> --json

# Show current feature parity report
cargo run -p ffs-cli -- parity --json

# Planned (not yet implemented):
# ffs fsck <image>
# ffs info <image>
# ffs repair <image>
```

### `ffs-harness`

```bash
# Validate conformance fixtures against golden data
cargo run -p ffs-harness -- check-fixtures

# Generate feature parity report
cargo run -p ffs-harness -- parity

# Run benchmarks
cargo bench -p ffs-harness

# Record reproducible hyperfine baseline artifacts
scripts/benchmark_record.sh --compare
```

### Development Gates

```bash
# These four commands must pass before any merge
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

---

## Key Dependencies

| Crate | Role |
|-------|------|
| [`asupersync`](https://github.com/Dicklesworthstone/asupersync) | Async runtime, `Cx` capability contexts, deterministic lab runtime, RaptorQ codec |
| [`ftui`](https://github.com/Dicklesworthstone/frankentui) | Terminal UI framework for `ffs-tui` |
| `crc32c` | ext4-compatible checksums |
| `blake3` | Native-mode integrity checksums |
| `parking_lot` | Fast synchronization primitives |
| `bitflags` | Filesystem flags and mode bits |
| `thiserror` | Error type derivation |
| `criterion` | Benchmark harness |
| `proptest` | Property-based testing for tree invariants |

---

## Project Status

FrankenFS is in **early development**. The workspace compiles, on-disk parsing and MVCC scaffolding work, and supports experimental read-only ext4 mounting via FUSE. btrfs mounting and write-path support are still in progress.

### Feature Parity

| Domain | Coverage |
|--------|----------|
| ext4 metadata parsing | 47.4% (9/19) |
| btrfs metadata parsing | 35.0% (7/20) |
| MVCC/COW core | 28.6% (4/14) |
| FUSE surface | 50.0% (6/12) |
| self-healing durability policy | 30.0% (3/10) |
| **Overall** | **38.7% (29/75)** |

### What Works Today

- ext4 superblock, inode, extent header/entry, group descriptor, and feature flag decoding
- btrfs superblock, B-tree header, leaf item metadata decoding, and geometry validation
- MVCC snapshot visibility, commit sequencing, first-committer-wins conflict detection
- Bayesian durability policy model and RaptorQ config mapping
- CLI `inspect`, `mount` (ext4 read-only), `scrub`, and `parity` commands
- Conformance fixture harness and Criterion benchmark scaffolding

### What's Next

- ext4 journal replay and allocator mutation paths
- btrfs transaction/delayed-ref/scrub parity
- Broaden FUSE coverage beyond the current ext4 read-only surface and add btrfs read-only mount
- Block I/O with ARC cache integration
- RaptorQ corruption recovery pipeline

See [FEATURE_PARITY.md](FEATURE_PARITY.md) for the full capability matrix and [PLAN_TO_PORT_FRANKENFS_TO_RUST.md](PLAN_TO_PORT_FRANKENFS_TO_RUST.md) for the 9-phase roadmap.

---

## V1 Filesystem Scope

**ext4:** Single-device images with block sizes 1K/2K/4K. Requires `FILETYPE` + `EXTENTS` feature flags. Read-only FUSE mount. Features explicitly excluded: `COMPRESSION`, `ENCRYPT`, `CASEFOLD`, `INLINE_DATA`, `JOURNAL_DEV`. Images with excluded flags are rejected at mount time.

**btrfs:** Single-device images only. Metadata parsing + validation (superblock, leaf items, sys_chunk_array). Read-only mount is phased (not yet implemented). Multi-device, RAID profiles, transparent compression, and send/receive are out of scope for V1.

See [COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md](COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md) for the full normative scope.

## Limitations

- **Read-only mount only.** `ffs mount` supports read-only ext4 via FUSE. Write support and btrfs mount are not yet implemented.
- **Linux only.** FUSE is the sole mount target. No macOS or Windows support planned.
- **Nightly Rust required.** Edition 2024 features require the nightly toolchain.
- **No write path.** Current parsing is read-only. Write-path MVCC and journaling are in progress.
- **External dependencies.** Requires `asupersync` and `ftui` as sibling project checkouts (not yet published to crates.io).
- **Legacy reference corpus is checked in.** The Linux kernel ext4/btrfs source used for behavioral extraction is available under `legacy_ext4_and_btrfs_code/linux-fs/`. The extracted behavior is fully captured in [EXISTING_EXT4_BTRFS_STRUCTURE.md](EXISTING_EXT4_BTRFS_STRUCTURE.md).

---

## FAQ

**Q: Why reimplement ext4 and btrfs instead of just using them?**
A: Kernel filesystems can't be extended with MVCC or self-healing from userspace. FrankenFS is a research vehicle for exploring what ext4/btrfs could look like with modern concurrency control and erasure coding, while remaining mount-compatible with existing images.

**Q: Can I mount my real ext4 partition with this today?**
A: `ffs mount` supports read-only ext4 mounting via FUSE for images with supported feature flags. This is experimental — do not rely on it for production data. btrfs mount is not yet supported.

**Q: What does "spec-first" mean?**
A: Instead of translating C to Rust line by line, we first extract the *behavioral contract* of each kernel subsystem into specification documents (~400KB of structured Markdown). Then we implement from the spec in idiomatic Rust. This avoids carrying over C-isms and allows architectural improvements.

**Q: Why MVCC instead of the existing journal?**
A: ext4's JBD2 journal uses a global lock that serializes all writes through a single thread. Block-level MVCC with version chains allows concurrent writers with snapshot isolation. The tradeoff is higher memory overhead (version chain storage) for significantly better multi-writer throughput.

**Q: What are fountain codes / RaptorQ?**
A: RaptorQ (RFC 6330) is a fountain code — an erasure coding scheme that generates repair symbols from source data. Given enough symbols, you can recover any lost/corrupted source blocks. FrankenFS stores a configurable overhead of repair symbols per block group (default 5%), enabling automatic corruption recovery without redundant copies.

**Q: Why `forbid(unsafe_code)` everywhere?**
A: Filesystem bugs in C frequently involve buffer overflows, use-after-free, and uninitialized memory. By forbidding unsafe Rust entirely, we eliminate these categories of bugs at compile time. The performance cost is negligible for a FUSE filesystem (the FUSE protocol is already the bottleneck).

---

## Documentation

| Document | Size | What it covers |
|----------|------|----------------|
| [COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md](COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md) | 242KB | Canonical specification — 24 sections covering every subsystem |
| [EXISTING_EXT4_BTRFS_STRUCTURE.md](EXISTING_EXT4_BTRFS_STRUCTURE.md) | 95KB | Behavioral extraction from Linux kernel ext4/btrfs source |
| [PLAN_TO_PORT_FRANKENFS_TO_RUST.md](PLAN_TO_PORT_FRANKENFS_TO_RUST.md) | 69KB | 9-phase porting roadmap with scope and acceptance criteria |
| [PROPOSED_ARCHITECTURE.md](PROPOSED_ARCHITECTURE.md) | 18KB | 21-crate architecture (19 core + 2 legacy/reference), trait hierarchy, data flow |
| [FEATURE_PARITY.md](FEATURE_PARITY.md) | 3KB | Quantitative implementation coverage tracking |
| [AGENTS.md](AGENTS.md) | 10KB | Guidelines for AI coding agents working in this codebase |

---

## Legacy Source Corpus

FrankenFS was designed by extracting behavior from Linux kernel v6.19 filesystem source (~205K lines of C):

- **ext4** — superblock, inode, extent tree, journal (JBD2), block allocation (mballoc)
- **btrfs** — B-tree, transaction, delayed refs, scrub, extent allocation

The legacy kernel source corpus is present in this repository under `legacy_ext4_and_btrfs_code/linux-fs/`. All extracted behavioral contracts are captured in [EXISTING_EXT4_BTRFS_STRUCTURE.md](EXISTING_EXT4_BTRFS_STRUCTURE.md) (95KB).

---

## About Contributions

Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

[MIT](LICENSE)
