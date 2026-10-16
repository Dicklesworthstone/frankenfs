# Explicit FAT32 boot-sector recovery

`ffs-fat recover --repair-boot-from BYTE_OFFSET` restores the first logical
boot sector from one explicitly selected native copy. The selection is relative
to the selected FAT volume, **not the host image**. It is never guessed from a
cosmetic type label or from a hard-coded sector size.

```sh
# A backup at sector 6 on a 512-byte-sector volume is at byte 3072.
# Run on an independently preserved working copy, exclusively offline.
ffs-fat recover working-copy.img --offline-image --repair-boot-from 3072 --dry-run
ffs-fat recover working-copy.img --offline-image --repair-boot-from 3072

# Source zero selects primary -> its BPB-declared backup instead.
ffs-fat recover working-copy.img --offline-image --repair-boot-from 0 --dry-run
```

A backup at sector 6 on a 4096-byte-sector volume is at byte **24576**.
`--offset` and `--length` still select a bounded volume within a larger image;
neither partition tables nor neighboring volumes are repaired or rewritten.
The source's checked BPB must identify the exact requested backup position.
FAT16, FAT12, exFAT, missing backups, and guessed backup locations are refused.

## Selection, not automatic authority

The selected sector supplies the geometry for a private, read-only diagnostic
projection of the primary and backup boot copies. No normal reader or mounted
filesystem receives this projected device. The complete existing allocation
and namespace checker must validate the selected interpretation. Every selected
FAT retains its actual reserved entries, recorded I/O errors, bad-cluster
markers, and allocation links; the projection conceals none of them.

A second parseable boot copy with different geometry, hidden-sector location,
media descriptor, or volume serial is an ambiguity, not permission to move a
filesystem. Such disagreements are refused, as are another filesystem's NTFS
or exFAT identifier, surface-test/unknown boot-state flags, conflicting mirrors,
broken live chains, cross-links, malformed names, invalid FSInfo signatures,
and incomplete or truncated structural evidence. Valid stale FSInfo hints and
proven lost allocation may be reported, but are not changed by this operation.

Even a structurally valid source is not proof of intended historical contents.
The operator must retain an independent image copy and select the boot source
from independent evidence. The operation restores one complete logical sector,
including its bootstrap bytes. It does not restore additional bootstrap sectors,
make the image bootable, repair FSInfo, choose allocation-table authority, restore
filenames, reclaim clusters, or verify file-payload integrity.

## Publication and failure behavior

Preflight records both complete boot sectors, selected FAT headers, bounded
allocation-table and primary-FSInfo fingerprints, and complete retained directory
mapping/record evidence. It repeats structural validation after capturing the
allocation evidence and revalidates before mutation. Table fingerprints normalize
only the FAT32 clean-shutdown bit; I/O-error state and reserved high nibbles are
not normalized.

The write order is selected FAT dirty markers and sync/readback, retained source
boot dirty marker and sync/readback, then the restored destination sector and
sync/readback. Final verification reads the actual repaired image without the
projection and checks both boot sectors, dirty markers, unchanged allocation
and FSInfo, retained namespace, and structural counts. Inactive FAT32 tables are
not written. The data-entry bits of every FAT, file bytes, and directory records
are never modified.

**A changed image always remains dirty.** The report has
`clean_state_published: false` and `requires_recovery: true`. This prevents a
stale clean backup from erasing evidence of an interrupted operation. Use a
separate `ffs-fat check` and explicit ordinary `ffs-fat recover` decision after
reviewing the restored image. Lost clusters still require separate salvage or
explicit discard authorization. Boot restoration cannot be combined with
`--repair-mirrors-from`, `--reclaim-lost`, `--discard-orphan-lfn`, or `--salvage-to`.
Sidecars, devices, symlink image targets, and non-offline use are refused.

Matching boot sectors (ignoring only their dirty bit) are no-write/no-sync
no-ops. Dry-run performs the full preflight on a read-only, shared-locked regular
image and does not write or sync the backing. Advisory locks do not exclude
kernel mounts or unrelated writers; exclusive offline ownership remains required.

An error/cancellation stops further writes without rollback or cleanup. A torn
sector or failed sync may leave the image partly restored. Native dirty markers
and the surviving source remain the recovery boundary, not a crash-atomic
transaction. The source is changed only in its native dirty bit.

## Bounds and validation status

The existing checker bounds apply, including at most 8,388,608 data clusters.
Boot recovery additionally admits at most 128 MiB of selected FAT-table bytes
for preservation evidence. Hashing buffers are at most 64 KiB and native boot
sectors at most 4096 bytes; no file payload is buffered or hashed.

Regression sources cover both restoration directions, ordinary-reader refusal,
explicit cleanup afterward, stale evidence, source/geometry/identity refusal,
active-FAT/high-bit and partition preservation, 4096-byte logical sectors,
lost-allocation retention, cancellation, dropped writes, post-readback corruption,
and write/sync cuts. Their presence is not an executed Rust/native-OS result.
Compilation, Cargo tests, Clippy, formatting, mounted FUSE, dosfstools, and
Windows interchange were unavailable in the authoring environment and are not
claimed to have passed. No checker/admission gate was relaxed.
