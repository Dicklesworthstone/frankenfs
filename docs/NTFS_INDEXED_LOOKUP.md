# Opt-in NTFS index-directed path lookup

The shared `ffs-ntfs` library exposes `NtfsVolume::resolve_indexed(cx, path)`
and `resolve_indexed_no_follow(cx, path)`. They descend only through native
`$I30` branches whose folded-key interval can contain the requested component,
rather than enumerating and opening every sibling FILE record.

`resolve` and `resolve_no_follow` remain the default full-enumeration paths.
`list_directory` still validates the whole admitted directory and every target.
This is an additional search contract, not a relaxation of those operations or
an assertion that unvisited metadata is intact.

The CLI exposes the same explicit choice with `--indexed-lookup` on `read`,
`readlink` and `ls`. For `ls`, this changes only locating the requested directory;
its contents still pass complete enumeration. `readlink` retains the final link
itself. The flag is not accepted by mount, checkers or record-number commands,
and existing volume bounds, offline acknowledgement and stream selectors remain.

`NtfsFs::new_indexed(cx, volume, uid, gid)` explicitly selects native index search
for inode-relative `FsOps::lookup`. `NtfsFs::new` keeps its existing strict root
enumeration. Both constructors retain journal, root and UpCase admission. Indexed
construction checks the root index and child descriptors without reading the
child blocks. Selected and negative lookups do not populate the complete-directory
cache; `readdir` still enumerates and validates all targets before publishing one
snapshot. Native inode generations, hard-link identity, relative symlinks,
directory ancestry and lossless host-name projection remain required.

```sh
ffs-ntfs read volume.img /large-directory/report.bin --offline-image --indexed-lookup
ffs-ntfs read volume.img /large-directory/report.bin --offline-image \
  --indexed-lookup --stream-utf16 006e,006f,0074,0065 --start 513 --bytes 1025
ffs-ntfs ls volume.img /large-directory --offline-image --indexed-lookup
ffs-ntfs readlink volume.img /large-directory/link --offline-image --indexed-lookup
```

## Native interpretation

The search uses the complete validated volume `$UpCase` table, never host Unicode
case folding. All equal-folded separator intervals are explored, including both
adjacent children. An exact native spelling wins over case-insensitive candidates;
without an exact match, POSIX-namespace names do not match case-insensitively.
Distinct matching record references are ambiguous, not an arbitrary first hit.
When matching keys share one reference, every selected parent/sequence/namespace/
UTF-16 name identity must exist in its FILE catalog, independent of key order.
The catalog's FILE_NAME attributes are scanned once for all those identities.
An early exact match does not suppress later errors in its relevant search range.

Every loaded index node is parsed by the existing FILE_NAME/INDX machinery and
checked for folded-key ordering, inherited search bounds and parent identities.
All child descriptors in each loaded node must have valid initialized ranges,
bitmap allocation and non-aliased identities before descent. Visited children
retain update-sequence, VCN, cycle and depth checks. The selected target passes
the same sequence, complete attribute catalog, FILE_NAME and reparse metadata
validation as full enumeration. No alternate graph or unverified fallback is used.

Path depth, relative-symlink expansion, root confinement, final-link inspection,
trailing-slash semantics and WOF/provider admission share the existing resolver.
No host pathname is derived from image metadata. The new path is read-only and
has no backing write or sync calls.

## Coverage and work bounds

Directed lookup relies on the native tree's routing semantics. It does not read
unselected descendant contents or sibling FILE records, nor prove global index
reachability or bitmap completeness. Damage confined there may be detected by
strict enumeration but not by this opt-in search. It is not a consistency checker,
repair operation, recovery mode, or permission to mutate an NTFS volume.

The existing 16,384-block and 32-level index limits remain. At most 65,536 loaded
keys are examined per component; equal-folded ranges can legitimately span many
nodes. Native node/stream/catalog size limits remain independent. No asymptotic
or measured speedup is claimed. Cancellation and a failure anywhere in the
selected search range fail the whole resolution.

## Evidence

Seven new constructed-image Rust tests cover resident and external indexes,
short aliases, Unicode, exact/insensitive/POSIX names, equal separators, selected
target sequence/parent/fixup failures, local ordering and inherited-bound damage,
bitmap/alias refusal, no unrelated sibling reads, misses, symlinks, cancellation
and malformed UpCase. Three additional CLI controls cover explicit selection,
unchanged defaults, volume bounds, raw UTF-16 streams, ranges, offline admission,
and rejection of mutation/unrelated-command options. Test storage panics on writes
and sync. Existing directory, path, recovery and CLI tests are retained unchanged.

Two additional reader regressions require a missing same-reference identity to
fail in either index order and a complete alias pair to remain readable. Seven
FsOps regressions cover constructor admission, inode-relative names, aliases,
hard links, read-only operations, full enumeration/cookies, unrelated damaged
siblings, selected I/O failures, cancellation and native-name projection. These
are constructed-image unit tests, not native-producer or mounted evidence.

The original implementation environment's gate attempts exited 127. The current
combined source at `990539073` plus explicit overlays subsequently passed strict
remote RCH execution: all 360 NTFS and 24 NTFS CLI tests, including the nine reader,
seven FsOps and three CLI controls above. The immutable old-code control passed
the valid alias case and failed the missing-alias case; repaired source passes
both orders. Full workspace checking, strict Clippy and formatting also passed.

The current Linux CLI passed 27 native indexed positive calls, three typed
negative calls and 25 byte comparisons on retained plain/bounded and compressed
images. A separate exclusively created 64MiB native image with 256 files has
13 allocated/reachable index nodes, 12 leaves and two levels of child traversal,
independently decoded from native tool streams. Strict/indexed endpoints and
middle keys passed 12 full/ranged comparisons and two listings; six missing-gap
queries returned typed NotFound with empty stdout. Read-phase hashes stayed
unchanged. No timing comparison or performance win is inferred.

Four strict default `NtfsFs` read-only kernel FUSE mounts also passed 24 mounted
byte comparisons and eight EROFS/ENOENT refusals, normal unmounts and unchanged
hashes. An independent rerun passed the same inputs and test design; count that
coverage once. These mounted results do not exercise `new_indexed`. The public
facade mount path and indexed FsOps mounting remain outside this qualification.
Source/hash checks and interval models alone remain static evidence. Full
harness and benchmark acceptance are tracked separately from this bounded path.
The repository's unchanged gate commands are:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ntfs indexed
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ntfs namespace
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-ntfs indexed
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings
RCH_REQUIRE_REMOTE=1 rch exec --job -- cargo fmt --check
```

Native collation references: Linux v6.12 `fs/ntfs3/upcase.c` and `index.c`, and
NTFS-3G 2022.10.3 `libntfs-3g/dir.c`. Traversal code is independently written and
reuses FrankenFS's existing checked parsers and metadata admission.
