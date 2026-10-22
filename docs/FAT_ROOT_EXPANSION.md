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
publication faults. All nine root-expansion Rust regressions passed on
2026-10-22 (`tests-d452-fat-root-expansion-0207.log`). That constructed-image
result is separate from native interchange qualification.

The permanent `scripts/verify_fat_read.py` root-growth case also passed against
a native-produced 64 MiB FAT16 image with 512-byte sectors: 532 captured commands,
530 successful commands and two expected refusals. Native mcopy filled the
512-slot root, then confirmed the full-root error. FrankenFS expanded it to
1,024 slots; original records and three payloads survived, added slots were zero,
and native mcopy and FrankenFS each created files that the other reader verified.
Native `fsck.fat -n` passed. Plain and bounded expansion produced identical
selected images; source hashes and surrounding sentinel bytes stayed unchanged.
The old CLI failed the same case specifically because it lacked `--root-entries`.

This native result uses base `8dae5e14b` plus explicit Rust overlays, fingerprint
`d1224d035dd49a9089e6981720f81374c280fef275d98b6493ecc9926ee121be`, Linux CLI
SHA-256 `12af1605e9a1e2f9fbd4f22971a9c87a1820401bbc3d1c72b03670c786641b8b`,
and runner SHA-256
`7cb88675ffe717009b22bc096b03d8862c30b2d02f3875bc25a63cd6b2d763af`.
The retained log is `native-fat-root-workload-8dae-positive-0327.log` under
`~/Library/Logs/frankenfs-verification/`; native evidence is retained on CSD in
`/data/ssd/tmp/ffs-native-verification-7CWV8iQw/fat-root-8dae-native-a_dxn2cp`.
Only this component of the runner was executed in that invocation. Native
4096-byte-sector relocation, mounted operation, bootability, field use and later
streaming changes remain outside this evidence.

A separate operation-output probe reopened this exact expanded image through
the previously qualified public `ffs` consumer (SHA-256 `e862954f...e4ef48`)
and a strict read-only `FatFs` FUSE mount using the CLI above. It verified all
514 root listing names including dot entries, all five original/new payloads
and sizes, public write refusal, mounted full/range bytes and EROFS, then clean
unmount and native fsck. The expanded image's SHA-256 stayed unchanged. Log:
`native-fat-operation-output-consumers-0358.log`; retained CSD evidence:
`/tmp/fat-operation-consumers-68fgd5vi/result.json`. The two executable source
cuts remain distinct; this is read-only consumption of the actual growth output,
not a facade-mounted, writable, boot or field qualification.
