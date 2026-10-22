# Expand a full FAT16 root without rebuilding files

`ffs-fat resize --root-entries SLOTS` expands the fixed FAT16 root directory in a
**new standalone output image**. This addresses a full root even when ordinary
file allocation still has free clusters. SLOTS counts 32-byte native records,
not filenames: long names and volume labels also consume records.

```sh
# Inspect the complete plan without creating output.
ffs-fat resize original.img --output expanded.img --size-mib 64 \
  --root-entries 4096 --offline-image --dry-run

# The source remains unchanged; the output must not already exist.
ffs-fat resize original.img --output expanded.img --size-mib 64 \
  --root-entries 4096 --offline-image
```

The requested count must fit the native 16-bit field, cover whole logical
sectors, and be at least the source's count. For 512-byte sectors, counts are
multiples of 16, up to 65,520; for 4096-byte sectors, multiples of 128, up to
65,408. An equal count preserves the existing capacity. Root shrinking is refused.
FAT32 is explicitly refused for this option: its root already uses a cluster
chain. Omitting the option leaves the existing FAT16/FAT32 resize behavior intact.

At the same output size, a larger root reduces the data region. An allocated
tail is still a refusal unless `--relocate` is supplied, in which case the
existing relocation engine moves live tail clusters into verified retained free
space. Bad tail clusters, insufficient capacity, dialect changes, dirty state,
ambiguous ownership and other unsupported source damage remain refusals before
output creation. Increasing output size can avoid the need for relocation.

## Native preservation and publication

A private read-only view inserts zeroed root storage before the data area and
adjusts the BPB root-entry/total-sector fields. The view temporarily grows by
exactly the added metadata space, preserving every original cluster number and
allocation word. The original source and the expanded candidate both undergo
complete ownership checking. This view cannot write or synchronize its source.

The existing relocation and resize engines then map that view to the requested
output geometry. Original root records, including long-name sequences and short
aliases, remain in their original order; no host-name export/reimport is used.
File payload, subdirectory dot pointers and preallocation retain their native
meaning. Added slots are actual zeros, not bytes borrowed from the old data area.
Only explicitly requested tail relocation changes cluster IDs. Reports identify
original/output root capacity and the real original volume length, not the
private intermediate view's larger length. Selected-volume bounds still apply;
neighboring partitions and source suffix bytes are not copied into the result.

Publication retains the create-new output, full-image SHA-256 readback, complete
candidate checker and withheld-primary-boot protocol. Failures retain the partial
output; no automatic deletion or rollback is attempted. Final publication errors
can leave a complete image and are still reported as errors. This is not an
in-place root resize, a partition editor, sidecar migration, or a claim that a
copied boot program will boot successfully.

Constructed-image Rust regressions cover 512/4096-byte sectors, full roots,
long names, nested directories, exact region-crossing reads, preallocation,
combined relocation, no-write refusals, source failures, cancellation and output
publication faults. Authoring these tests is not execution evidence. Compile,
execute the Rust tests and qualify native filesystem-tool interchange before
using the feature on anything other than disposable test images.
