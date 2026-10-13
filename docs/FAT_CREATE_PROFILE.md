# Experimental create-only updates to existing FAT16/FAT32 images

The ordered offline writer has an explicit create-only mode. Unlike ordinary
replacement, it refuses an existing destination, including collisions with a
long name or native short alias. This is an implementation increment toward the
comprehensive plan's FAT namespace-mutation milestone, not completion of it.

```sh
# The image must be offline; the source must remain immutable.
ffs-fat replace volume.img /NEW.BIN --source payload.bin --create --offline-image --dry-run
ffs-fat replace volume.img /NEW.BIN --source payload.bin --create --offline-image
ffs-fat cat volume.img /NEW.BIN > readback.bin
ffs-fat check volume.img
```

`--create` is opt-in. Without it, `replace` still requires an existing file and
never creates one. Both modes retain explicit `--offset`, `--length` and OEM
selection, regular-file-only inputs, retained handles, advisory locking,
source/image identity checks, complete allocation checking and SHA-256 readback.
Advisory locks do not exclude kernel mounts or unrelated writers.

The creation profile admits portable ASCII 8.3 destination names in an existing
parent directory. Each base/extension component may be entirely upper- or
lowercase; native case bits preserve its spelling. Mixed-case components, new
long names, spaces, non-ASCII names and reserved DOS device names are refused.
Existing parent paths may use the reader's admitted long-name/OEM policy.
No existing entry is renamed or overwritten.

FAT16's fixed root and FAT32/subdirectory cluster chains are searched within the
existing 65,536-slot budget. Deleted slots preserve live successors. When an end
marker becomes a file, the next logical slot is cleared and synchronized first,
even across a physical boundary; stale bytes after the old end cannot become
newly visible directory entries. Orphan long-name suffixes cannot adopt the new
short entry.

## Bounded directory growth

A full FAT32 root or FAT16/FAT32 subdirectory can grow by one cluster if both
the free-allocation and directory-slot budgets admit it. The new cluster is
reserved separately from the payload, fully zeroed and synchronized. Its native
end-of-chain entry is then synchronized in every selected FAT before the old
directory tail can point to it. The existing directory chain is never rebuilt,
and old entries are not moved. A stale prepared tail or allocation refuses the
operation before dirty publication.

The new file entry is published only after those directory-storage barriers.
The final allocation checker accounts for the extra directory cluster as well
as file data. A full FAT16 fixed root cannot grow and is refused before writes.
This does not create new directories or implement general namespace transactions.

## Publication and failure contract

New payload clusters are disjoint from existing allocation and initialized,
including zeroed final-cluster slack, before their FAT links are published.
The native dirty state remains set until the directory entry, reader readback,
exact free-space hints and complete checker result are synchronized. FAT32
selected-copy and reserved-high-bit rules are unchanged. Empty files require
no payload clusters, though a full cluster-backed parent needs a directory
cluster. Native creation/access/modification dates use the existing writer's
UTC projection.

This operation is **not atomic** and has no replay/rollback protocol. Write,
flush, cancellation or verification failures retain the image and report the
phase; native checking/recovery on a separate copy may be required. Do not use
unqualified experimental writes on the sole copy of valuable data.

JSON identifies `operation: create_new_file`, `name_profile: portable_ascii_8_3`,
`new_directory_clusters`, allocation/digest information, and
`created_new_file: false` for a dry-run. Completed updates add native-reader
payload verification and `durability: all_data_metadata_and_clean_state_synced`.

## Evidence and remaining work

Nine authored regressions cover both dialects, 512/4096-byte sectors, active FAT,
empty/nonempty contents, retained bytes, deleted/end slots, stale successors,
long-name/alias collisions, invalid names, capacity, cancellation, CLI admission,
full root/subdirectory growth, nonzero free-space initialization, stale tails,
and every modeled write/flush failure with retained/lost pending data and torn
prefixes. They are synthetic native-image/storage-model controls, not Windows
or dosfstools interchange or hardware power-cut evidence.

At publication, this session could not execute Rust compilation, rustfmt,
Clippy or these tests: Rust tools were absent and the execution environment's
network was unavailable. No passing runtime or native-interchange result is
claimed. The existing replacement writer likewise retains its separate evidence
limits in [the FAT profile](FAT_READ_PROFILE.md).

```sh
rch exec -- cargo test -p ffs-cli --bin ffs-fat replacement
```

Long-name creation, directory creation, unlink/rename, writable mounts,
crash replay and MVCC/RaptorQ integration remain unfinished. The NTFS and ZFS
native recovery/write milestones are not changed by this FAT increment.
