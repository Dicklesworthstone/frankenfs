# Offline FAT resize into a new image

`ffs-fat resize` grows a FAT16/FAT32 volume, or shrinks a completely free tail,
into a **new standalone image**. The source stays strictly read-only, including
on errors and cancellation. Keep the source offline and immutable throughout;
advisory locks do not exclude kernel mounts or unrelated writers.

```sh
ffs-fat resize original.img --output larger.img --size-mib 128 --offline-image --dry-run
ffs-fat resize original.img --output larger.img --size-mib 128 --offline-image
ffs-fat check larger.img
```

The target size must remain valid for the original FAT dialect and cluster size.
FAT tables and the fixed-root/data regions can move physically; native cluster
numbers, chain order, preallocation, names (including raw UTF-16), short aliases,
DOS attributes, timestamps, volume label and serial are retained. The standalone
output has a zero hidden-sector offset. Existing free-cluster contents and new
free space are zeroed, not copied as recoverable deleted-file data. Bad-cluster
markers are preserved without reading their payload. No bootability is promised.

A complete native ownership check precedes output creation. Shrink refuses any
live, preallocated or bad cluster beyond the proposed limit. It does not compact
or relocate individual cluster IDs. Dialect conversion, cluster-size changes,
in-place resizing, raw-device writes and partition-table changes are not supported.
Selected source `--offset` and `--length` bounds are honored; surrounding partitions
are not included in the output. The existing checker limit of 8,388,608 clusters
applies to both source and target.

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
