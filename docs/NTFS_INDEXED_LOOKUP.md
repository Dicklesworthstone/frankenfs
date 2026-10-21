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

These tests were authored but could not be executed in the implementation
environment: Cargo, rustc, rustfmt and RCH are absent; gate attempts exited 127.
Source/hash checks and an independent interval-search model are not Rust execution,
native NTFS interoperability, kernel FUSE evidence or performance measurements.
Run the repository's unchanged gates before relying on the new path:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ntfs indexed
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ntfs namespace
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-ntfs indexed
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Native collation references: Linux v6.12 `fs/ntfs3/upcase.c` and `index.c`, and
NTFS-3G 2022.10.3 `libntfs-3g/dir.c`. Traversal code is independently written and
reuses FrankenFS's existing checked parsers and metadata admission.
