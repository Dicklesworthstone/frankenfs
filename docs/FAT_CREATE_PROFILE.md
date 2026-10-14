# Experimental create-only updates to existing FAT16/FAT32 images

The ordered offline writer has an explicit create-only mode. Unlike ordinary
replacement, it refuses an existing destination, including collisions with a
long name or native short alias. This advances the comprehensive plan's FAT
namespace-mutation milestone; it does not complete the native-write profile.

```sh
# The image must be offline; the source must remain immutable.
ffs-fat replace volume.img '/Release notes 🦀.txt' --source payload.bin --create --offline-image --dry-run
ffs-fat replace volume.img '/Release notes 🦀.txt' --source payload.bin --create --offline-image
ffs-fat cat volume.img '/Release notes 🦀.txt' > readback.bin
ffs-fat check volume.img
```

`--create` is opt-in. Without it, `replace` still requires an existing file and
never creates one. Both modes retain explicit `--offset`, `--length` and OEM
selection, regular-file-only inputs, retained handles, advisory locking,
source/image identity checks, complete allocation checking and SHA-256 readback.
Advisory locks do not exclude kernel mounts or unrelated writers.

## Native short and long names

Creation supports portable ASCII 8.3 names and lossless UTF-16 long names,
including mixed case, spaces and non-ASCII characters supplied as UTF-8. A
component must fit both 255 UTF-8 bytes (the current host presentation limit)
and 255 UTF-16 units. Control characters, native forbidden separators and
punctuation, trailing dots/spaces, U+FFFF and reserved DOS device names are
refused before mutation. Unpaired-surrogate names cannot be supplied through
this UTF-8 command interface.

Exact short names retain the native base/extension case bits. Other names use
one to twenty native LFN records and a collision-checked ASCII short alias.
The records retain all UTF-16 units, native reverse ordinals, checksum binding,
terminators and padding. Names exactly divisible by thirteen units do not
consume an extra record. Generated numeric aliases reserve existing raw short
names, displayed names and aliases under both the selected OEM comparison and
a conservative Unicode case key. This is not Windows-version-exact Unicode
collation or byte-identical Windows alias generation. Existing names are never
renamed to accommodate a new alias. Final readback requires the exact requested
spelling, prepared short alias and native case flags, not just matching payload.

## Slot reservation and directory growth

The entire LFN/short-entry set is reserved in logical directory order, across
sector boundaries and fragmented cluster chains. Deleted slots can be reused,
but scattered holes are not counted as a contiguous record set. Live entries
are not moved. The existing 65,536-slot budget includes any added allocation.

FAT16's fixed root cannot grow. A FAT32 root or FAT16/FAT32 subdirectory can add
up to two clusters when needed for the complete name set. That covers twenty
LFN records plus the short entry even with 512-byte clusters and a full parent.
Directory allocation is separate from payload allocation. Every new directory
cluster is zeroed and synchronized; all new FAT links are synchronized before
the old parent tail points to them. Stale slots, tails or reserved allocation
are refused during pre-publication validation.

When an end marker is consumed, its successor after the complete name set is
cleared and synchronized first. The short-entry position and later LFN slots
are then prepared as deleted records while preserving both the first slot and
the actual old end marker until the hidden suffix is durable. That marker can
be inside the reserved run when earlier deleted slots are reused. LFN records
are written from the short-entry end back toward the first slot and synchronized.
Only then is the actual file's short entry published. Hidden stale short records
cannot adopt the new long name, and bytes after the prior end cannot become
newly visible files.

## Native directory creation

`ffs-fat mkdir IMAGE /PATH --offline-image` creates one empty native directory
under an existing parent. It uses the same long-name/short-alias collision policy
and parent-slot reservation as file creation. The new directory receives its own
disjoint cluster, which is initialized and synchronized with native `.` and
`..` entries before the allocation entry and parent namespace entry are
published. FAT16 and FAT32 root children use native parent cluster zero;
nested children point at their actual parent cluster. This follows the
[Microsoft FAT specification, §6.5](https://www.scs.stanford.edu/~zyedidia/docs/_other/fat.pdf)
and the existing strict native checker.

The parent may grow through the same bounded FAT-chain protocol used by long file
names. A dry-run performs admission, name, slot and allocation planning without
writing. Success requires native path resolution, empty-directory enumeration,
raw dot-entry readback, exact free-space accounting and a complete checker pass.

```sh
ffs-fat mkdir volume.img '/Release Assets' --offline-image --dry-run
ffs-fat mkdir volume.img '/Release Assets' --offline-image
ffs-fat ls volume.img '/Release Assets'
ffs-fat check volume.img
```

This is still ordered offline mutation rather than an atomic mkdir transaction.
A failed write or flush can leave the image dirty and requiring native recovery.

## Publication and failure contract

New payload clusters are disjoint from existing allocation and initialized,
including zeroed final-cluster slack, before their FAT links are published.
The native dirty state remains set until the directory entry, reader readback,
exact free-space hints and complete checker result are synchronized. FAT32
selected-copy and reserved-high-bit rules are unchanged. Empty files require
no payload clusters, though their parent may need directory allocation.
Native timestamps use the existing writer's UTC projection.

This operation is **not atomic** and has no replay/rollback protocol. Write,
flush, cancellation or verification failures retain the image and report the
phase; native checking/recovery on a separate copy may be required. Do not use
unqualified experimental writes on the sole copy of valuable data.

JSON identifies `operation: create_new_file`,
`name_profile: portable_utf16_lfn_ascii_alias`, `new_directory_clusters`,
allocation/digest information and `created_new_file: false` for a dry-run.
Completed updates add native-reader payload verification and
`durability: all_data_metadata_and_clean_state_synced`.

## Evidence and remaining work

The nine earlier creation/growth regressions remain. Eight additional authored
controls cover native LFN record encoding, name limits, mixed-case/Unicode and
maximum-length readback, generated alias collisions, two-cluster growth,
fragmented free slots, stale reserved slots, and modeled write/flush cuts across
a sector/cluster-spanning name. The interior-marker regression separately checks
that consuming the old end requires durable, harmless hidden slots, even if a
flush fails. Formerly unsupported valid name cases now have positive native-
publication controls; invalid names and collisions still have zero-write tests.

All 133 FAT Rust tests, including all 17 creation/growth/name controls and three
mkdir controls, passed in RCH job `j-30063538684821517`: zero failures, ignored
or filtered tests. The mkdir controls cover root/nested dot entries in both
dialects and sector sizes, full FAT32 parent growth, and collision/fixed-root/
cancellation refusals without writes. The old FAT32 producer failed the
unchanged native checker's root-parent invariant in `j-30063538684821514`;
the corrected producer passed the complete suite with exact root-parent zero
and nested-parent identity checks.

These are executed synthetic native-image and storage-model unit controls;
Windows and hardware power-cut qualification remain pending. The same source
passed RCH workspace/all-target check `j-30063538684821519`, strict Clippy
`j-30063538684821516` and formatting on base `eeef44fe3` plus overlay
`c58623d3232fa8c06bc8bdb3ca6de7d6da6b23952d887639b50a2e3280f36a81`.
Earlier gate failures were fixed without removing any verification condition or
test case. The unchanged required checks include:

```sh
rch exec -- cargo test -p ffs-cli --bin ffs-fat replacement
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

The public `ffs-fat` built by RCH `j-30063538684821518` has SHA-256
`65b85607187b6c9c3a6747991e76b77bcdb41d6676af5218316d8821a18534f4`,
independently matched between worker and retrieved artifact. It executed
root/nested mkdir on fresh 64 MiB FAT16 and FAT32 images produced by dosfstools.
Independent raw boot-geometry/dot-entry reads, empty-child resolution, exact
directory/free-space accounting and `fsck.fat -n` before/after all passed.
Dry-run and case-insensitive collision refusal preserved full image hashes.
This is real offline CLI/dosfstools interchange evidence for those profiles;
it does not qualify writable mounts, interruption recovery, Windows or hardware
power cuts.

Recursive parent creation, unlink/rename, writable mounts, crash replay and MVCC/RaptorQ
integration remain unfinished. NTFS/ZFS native recovery and write milestones
are not changed by this FAT increment. Read-only FAT behavior and the existing
replacement protocol remain described in [the FAT profile](FAT_READ_PROFILE.md).
