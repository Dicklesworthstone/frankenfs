# Offline FAT resize into a new image

`ffs-fat resize` grows a FAT16/FAT32 volume, or shrinks it into a **new standalone
image**. By default the removed tail must be completely free; `--relocate` can
move live tail clusters into free retained slots. The source stays strictly read-only, including
on errors and cancellation. Keep the source offline and immutable throughout;
advisory locks do not exclude kernel mounts or unrelated writers.

```sh
ffs-fat resize original.img --output larger.img --size-mib 128 --offline-image --dry-run
ffs-fat resize original.img --output larger.img --size-mib 128 --offline-image
ffs-fat check larger.img
```

The target size must remain valid for the original FAT dialect and cluster size.
FAT tables and the fixed-root/data regions can move physically. Without
`--relocate`, native cluster numbers are retained. In both modes chain order,
preallocation, names (including raw UTF-16), short aliases,
DOS attributes, timestamps, volume label and serial are retained. The standalone
output has a zero hidden-sector offset. Existing free-cluster contents and new
free space are zeroed, not copied as recoverable deleted-file data. Bad-cluster
markers are preserved without reading their payload. No bootability is promised.

A complete native ownership check precedes output creation. Default shrink refuses
any live, preallocated or bad cluster beyond the proposed limit. Relocation is
explicit and still refuses a bad tail or insufficient free retained capacity.
Dialect conversion, cluster-size changes,
in-place resizing, raw-device writes and partition-table changes are not supported.
Selected source `--offset` and `--length` bounds are honored; surrounding partitions
are not included in the output. The existing checker limit of 8,388,608 clusters
applies to both source and target.

## Shrinking an allocated tail

```sh
ffs-fat resize original.img --output smaller.img --size-mib 64 --offline-image --relocate --dry-run
ffs-fat resize original.img --output smaller.img --size-mib 64 --offline-image --relocate
```

Only live clusters above the target limit move; retained live and bad clusters
keep their numbers. Destinations are checked free slots below the limit, in
ascending order. Reachable preallocation moves too, even for zero-length files.
This is tail compaction for resizing, not a whole-volume defragmenter.

The private relocation view rewrites selected FAT successors, native first-cluster
fields, directory `.`/`..` records, and both FAT32 root boot pointers as needed.
It traverses native entries without converting names into host paths, changing
short aliases, or allocating temporary directory slots. FAT16 EA-index fields,
FAT32 directory reserved bits, and the reserved high nibble of each destination
FAT slot are preserved. Inactive FAT copies are never promoted or rewritten.

Before creating output, both the relocated source-size view and the final resized
view must pass complete ownership/accounting checks. The existing output
readback/checker/publication protocol is unchanged. Reports include
`relocation_requested`, `relocated_clusters`, and `cluster_numbers_preserved`.
Native cluster identities and physical entry-slot selectors for moved directories
change in the output; selectors from the original image must not be reused there.

Planning uses an additional temporary allocation-state byte per source cluster
and a bounded sorted map of three 32-bit words per moved cluster. Directory
patches are bounded by the existing 131,072-object/256-depth profile. Payloads
are streamed, not materialized. No native interoperability or runtime qualification
is inferred merely from these checks or the authored regression tests.

## Verification and publication

All backing transfers are at most 64 KiB. A bounded one-byte-per-source-cluster
map records live/free/bad state. Both candidate namespace checks and a full-image
SHA-256 readback precede primary boot publication. The source, retained output
file and output parent identities are checked before publication. The output is
create-new mode 0600: an existing file, hard link, symlink or device is never
replaced. Keep the output parent directory stable too.

`--dry-run` performs geometry, tail-allocation and planned native namespace checks
but creates no output and does not synchronize or write the source. It is not a
payload-readability test or a guarantee that the host has enough output space.
Execution reads and verifies the complete output length, including zero space;
this is deliberately not a constant-time sparse-image resize.

The primary boot sector is withheld until verification succeeds. Errors retain
partial output for inspection; no cleanup or rollback is performed. An error in
final publication, readback or parent-directory synchronization may leave an
already complete image, and is still reported as an error. The source is never
modified. The SHA-256 proves copy/readback agreement, not pre-existing file-content
integrity or authenticity.

Sidecars are refused rather than repaired, reused at a different geometry, or
silently detached. The output needs separately created and verified protection.
Native filesystem-tool and mounted interoperability qualification remains required;
constructed-image tests do not establish that qualification.
