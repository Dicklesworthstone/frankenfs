# ZIL reads through the admitted native storage set

The native ZIL inspector and existing memory-only copied-write/EOF-truncation
recovery path now retain the same complete storage owner as ordinary MOS/ZPL
reads: a single leaf, complete mirror, striped standalone top-level leaves, or
one complete ordinary RAIDZ1/2/3 group. The existing topology/feature admission
still decides which images constitute a pool. This does not admit missing
members, SLOG devices, nested groups, dRAID, or expanded RAIDZ.

`ffs-zfs zil-inspect` and `ffs-zfs zil-read` retain the existing `--member`
options and aliases. `--offset` and `--length` still select the same span on
each image. More than seven additional images and sidecar healing are refused
before opening storage. No on-disk log claim, replay-sequence update, TXG
publication, physical repair, write or flush is introduced.

Log blocks use their native ZILOG/ZILOG2 embedded checksum and chain identity,
not the ordinary DMU block-pointer checksum. Mirror replicas are tried without
changing that identity. RAIDZ uses the shared native mapping and reconstruction
algorithms, but verifies every assembled candidate with the log verifier. A
bad P equation may be excluded while Q/R reconstruct the data. Parity is read
only after the original data fails; this is not an all-copy/parity scrub.

Before data I/O, every declared DVA and member extent must satisfy sector,
allocation-size, vdev, partition and end-label bounds. Actual allocation
intervals, including skip sectors, are retained per supplied member across
the complete log chain. Distinct vdevs may reuse a numeric offset; overlapping
allocations on one member are refused.

`physical_work_bytes` counts admitted read bytes for every declared replica and
parity column, including copies that a successful earlier read makes unnecessary.
The existing 64 MiB cap remains. `reconstruction_work_bytes` separately charges
all native padded column bytes for each RAIDZ assembly attempt, with a 256 MiB
per-scan cap. These are cumulative work bounds, not whole-process memory limits.

Cancellation and exhausted budgets terminate immediately. If no verified copy
can be reconstructed, any physical I/O failure remains an error. Only fully
readable but checksum-invalid copies may form an unverified tail. Claimed log
boundaries still fail closed; extracting an unclaimed verified prefix still
requires explicit `--allow-unverified-tail` authorization. Such a tail can be
unwritten or damaged, so a prefix is not certification of complete recovery.

Pending namespace records, indirect writes, range-free records, native durable
replay and writable mounts remain outside the existing file-data recovery
profile. This change expands storage topology, not replay operation semantics.

## Validation

Twelve new Rust regression functions cover topology transport and CLI admission,
including mixed checksum variants/byte orders, 512-byte through 64-KiB native
sectors, parity corruption, I/O erasures, cancellation, allocation aliases,
budget exhaustion, and the public Objects-to-ZPL recovered-read path. These are
constructed fixtures, not native OpenZFS import or interoperability evidence.

Rust/Cargo/RCH are unavailable in the authoring environment. Compilation,
Rust execution, rustfmt, Clippy and native OpenZFS comparisons remain unverified.
Independent Python finite models and patch-application/whitespace checks do not
substitute for those gates.
