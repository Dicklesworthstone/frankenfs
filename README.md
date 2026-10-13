<div align="center">
  <img src="docs/assets/frankenfs_illustration.webp" alt="FrankenFS — Rust userspace filesystems: ext4, btrfs, FAT16, FAT32, NTFS and ZFS">
</div>

<h1 align="center">FrankenFS</h1>

<p align="center">
  <strong>Rust userspace filesystems: ext4 and btrfs, expanding to FAT16, FAT32, NTFS and ZFS</strong><br>
  <em>Block-level MVCC · RaptorQ repair · Explicit durability boundaries · Unsafe forbidden in first-party crates</em>
</p>

<p align="center">
  <a href="LICENSE">License</a> ·
  <a href="README_EXT4_BTRFS.md">Detailed ext4/btrfs guide</a> ·
  <a href="COMPREHENSIVE_PLAN_FOR_NTFS_FAT16_FAT32_AND_ZFS.md">Multi-format plan</a> ·
  <a href="FEATURE_PARITY.md">Feature and evidence accounting</a>
</p>

## What it is

FrankenFS reimplements native filesystem behavior in Rust and runs in userspace
through FUSE and offline-image tools. Its established development base is ext4
and btrfs, with experimental block-level multi-version concurrency control
(MVCC), RaptorQ repair symbols and explicit writeback/durability gates.

The expansion now includes **FAT16, FAT32, NTFS and ZFS companion tools**. These
are real native-image paths, not just format-signature recognizers, but their
capabilities differ substantially. A read profile is not a native writer, a
parser is not a mounted filesystem, and source code is not executed proof.

**All profiles remain experimental. Keep original images untouched and use
separate copies for mutation experiments.** The first-party unsafe-code ban
does not cover every dependency or the vendored FUSE transport, and it does not
prevent logical filesystem corruption.

The previous long-form README is retained, byte-for-byte, as the
[detailed ext4/btrfs guide](README_EXT4_BTRFS.md). It preserves architecture,
operational examples, benchmark qualifications, recovery/writeback discussion,
and historical evidence. The format matrix below is the front-page overview
of the broader project; per-format profiles define the actual admission rules.

## Current format surface

| Format | Entry point | Implemented surface | Important boundary |
|---|---|---|---|
| **ext4** | Main `ffs-cli` / `OpenFs` path | Native reads, experimental mounted writes, journal integration, MVCC and repair work | Writeback, recovery and release readiness remain evidence-gated; see the detailed guide and current parity ledger. |
| **btrfs** | Main `ffs-cli` / `OpenFs` path | Native reads and guarded experimental writes, transaction-commit and repair work | Native feature/topology admission and durability evidence still matter; not blanket kernel parity. |
| **FAT16** | `ffs-fat` | Native reads/catalog/extraction, read-only FUSE, allocation checking, fresh-image formatting/population, ordered offline replacement and create-only files | New files use portable ASCII 8.3 names. Existing subdirectories can grow; the fixed root cannot. No writable mount or crash replay. |
| **FAT32** | `ffs-fat` | The FAT16 companion surface plus FAT32 root chains, selected-FAT handling and free-space hints | Create-only updates can grow full roots/subdirectories with ordered native allocation. No atomic namespace transaction or writable mount. |
| **NTFS** | `ffs-ntfs` | Read-only native namespace and file/stream access, sparse and admitted compressed/transformed data, metadata inspection and FUSE | The exact NTFS read profile controls admission. Native `$LogFile` recovery and general NTFS mutation are not implemented by these reads. |
| **ZFS** | `ffs-zfs` | Native dataset/snapshot discovery and reads, admitted compression/checksums, selected mirror/RAIDZ and read-only mount profiles | Explicit offline pool/configuration selection is not native pool import. No native allocation/TXG writer or ZIL recovery claim. |

The new formats currently live in companion binaries. They are **not yet a
unified six-format `OpenFs` backend**, and the ext4/btrfs MVCC/RaptorQ integration
must not be inferred to apply automatically to their native writes.

The historical `97/97` parity figure describes rows in the original feature
table. It is not a six-format completeness percentage, a passing test count,
or a release-readiness score.

## FAT: create a file in an existing image

The newest mutation increment closes a practical gap between fresh-image
population and replacement: an offline image can now receive a **new file**,
including when a cluster-backed parent needs another directory cluster.

```sh
# Preflight only: no image mutation. The parent directory must already exist.
ffs-fat replace volume.img /NEW.BIN \
  --source payload.bin --create --offline-image --dry-run

# Explicit create-only publication. An existing name or alias is an error.
ffs-fat replace volume.img /NEW.BIN \
  --source payload.bin --create --offline-image

# Read back and check allocation through the native FAT reader.
ffs-fat cat volume.img /NEW.BIN > readback.bin
ffs-fat check volume.img
```

Without `--create`, `replace` retains its existing-file-only behavior. Source
files must remain immutable; the image must not be mounted or modified by
another program. Advisory locks do not enforce that against unrelated writers.
`--offset`, `--length` and `--oem-code-page` retain explicit volume/name selection.

Creation checks visible names and native aliases, preserves existing entries,
initializes disjoint payload allocation, and synchronizes a successor directory
terminator before an old end marker becomes live. Directory growth zeroes and
synchronizes the new cluster, then its FAT end-of-chain, before linking the old
tail. Final native-reader SHA-256 and complete allocation checks precede clean
state publication. FAT32 inactive-copy and reserved-high-bit rules are retained.

This is **ordered offline mutation, not an atomic transaction**. Interruption
may leave a dirty image requiring native checking/recovery on another copy.
The creation profile does not yet admit new long names, mixed-case 8.3
components, new directories, unlink/rename or writable mounts. See the
[creation and directory-growth contract](docs/FAT_CREATE_PROFILE.md).

### Evidence for this increment

Nine regressions have been authored for creation and directory growth, including
both dialects, 512/4096-byte sectors, alias collisions, existing-byte preservation,
stale plans, capacity, nonzero free space, and modeled write/flush failures with
lost or retained pending data and torn prefixes. **They have not been executed
in the implementation session.** Rust tools and network access were unavailable;
compilation, formatting, Clippy, runtime and native-interchange qualification
are not claimed. A concurrent source review also reported formatting differences
in the initial increment. Those checks must be completed before relying on it.

## Build and explore

Use the checked-in Rust toolchain and the platform/dependency instructions in the
[detailed guide](README_EXT4_BTRFS.md) and [AGENTS.md](AGENTS.md).

```sh
cargo build -p ffs-cli --bins

# Existing ext4/btrfs entry point.
cargo run -p ffs-cli -- inspect /path/to/fs.img --json

# Native FAT image tools; reads do not require a FUSE mount.
cargo run -p ffs-cli --bin ffs-fat -- inspect /path/to/fat.img
cargo run -p ffs-cli --bin ffs-fat -- ls /path/to/fat.img /

# Discover exact companion arguments before selecting a volume or ZFS pool.
cargo run -p ffs-cli --bin ffs-ntfs -- --help
cargo run -p ffs-cli --bin ffs-zfs -- --help
```

Read-only mount and native-image examples, supported feature masks, ownership
projection and rejection rules are in the corresponding profiles:

| Profile | Documentation |
|---|---|
| FAT reads, names, mounts, checking and fresh-image creation | [FAT profile](docs/FAT_READ_PROFILE.md) |
| Existing-image FAT creation and directory growth | [Create-only profile](docs/FAT_CREATE_PROFILE.md) |
| NTFS native reads and read-only mounts | [NTFS profile](docs/NTFS_READ_PROFILE.md) |
| ZFS datasets, snapshots, topology and read-only mounts | [ZFS profile](docs/ZFS_READ_PROFILE.md) |
| ext4/btrfs architecture, operation and evidence | [Detailed guide](README_EXT4_BTRFS.md), [current parity ledger](FEATURE_PARITY.md) |

## Architecture and remaining priorities

Native parsing belongs in `ffs-ondisk`; image and block I/O, transaction control,
filesystem operations, FUSE adaptation, repair and evidence have distinct
boundaries. The project uses `asupersync::Cx` for explicit budget/cancellation
propagation. Full context propagation and worker scoping remain work, not a
blanket property of every existing path.

The multi-format plan deliberately separates native compatibility from
FrankenFS-specific improvements. The remaining high-impact work includes FAT
long-name/directory creation and broader namespace operations; NTFS native
recovery plus allocator/MFT/index mutation; ZFS native allocation/TXG/ZIL and
pool lifecycle; shared backend integration; and executable native-interchange,
crash/reopen and mounted-operation evidence for each admitted profile.

The [comprehensive plan](COMPREHENSIVE_PLAN_FOR_NTFS_FAT16_FAT32_AND_ZFS.md),
[implementation workpackages](docs/NTFS_FAT_ZFS_IMPLEMENTATION_WORKPACKAGES.md),
and `.beads/` track these separately. Implemented symbols, authored tests,
executed tests and native interoperability are different evidence levels.

For contributors, use the repository's prescribed remote execution workflow
when available. The focused FAT checks are:

```sh
rch exec -- cargo test -p ffs-cli --bin ffs-fat replacement
rch exec -- cargo check -p ffs-cli --bin ffs-fat
rch exec -- cargo clippy -p ffs-cli --bin ffs-fat --all-targets -- -D warnings
cargo fmt --check
```

Passing those is necessary, not sufficient for filesystem readiness. Existing
native-format compatibility, fault-injection, mounted and release gates remain
in force; none are waived by adding a format or a new command.

## License

See [LICENSE](LICENSE) for the project's MIT + OpenAI/Anthropic Rider terms.
