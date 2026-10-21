# Read-only ZFS dataset block scrub

`ffs-zfs scrub` verifies the allocated DMU block graph of one selected filesystem
head or named snapshot. It is a bounded native-checksum scrub, not a full-pool
scrub, namespace checker, repair engine, or resilver operation.

```sh
rch exec -- cargo build -p ffs-cli --bin ffs-zfs

# Explicit committed candidate; use actual values from inspect.
ffs-zfs scrub leaf.img --offline-image --pool-guid 123 --label 0 --slot 2 --dataset data

# Automatic candidate selection uses the existing read-only selection policy.
ffs-zfs scrub leaf.img --offline-image --auto-import --dataset data --snapshot before

# Native topology and partition selections are shared with ordinary reads.
ffs-zfs scrub first.img --member second.img --offline-image --auto-import \
  --offset 1048576 --length 134217728 --dataset data \
  --max-pointers 16777216 --max-bytes 1099511627776 --max-objects 1048576
```

A successful exit requires `clean: true`. Detected corruption, unsupported
structures, missing descendants, and work-budget exhaustion produce JSON with
`clean: false` followed by a nonzero exit. Admission failure or cancellation
returns an error, never a successful partial scrub report. Output failure also
fails the command. Pool TXG, selected-view TXG, root birth and dataset GUID bind
the report to the selected committed view. Pending ZIL intent is not replayed.

The scanner starts with a fresh object-set cache and walks the meta-dnode,
all allocated dnode slots, indirect blocks and ordinary payload blocks, plus
admitted SA spill pointers. Large-dnode interior slots are not independent
objects. Private xattr/ACL objects are covered even when they have no ordinary
ZPL path. Bonus bytes are protected by their containing dnode-block checksum.
The scrub does not parse every bonus payload or validate namespace/ACL semantics.

The walker skips native hole subtrees without iterating their logical block
range or allocating zeroes. Arithmetic uses u128 for tree coordinates, including
legal capacities above u64::MAX; object IDs remain within the native 48-bit
namespace. Allocated pointers beyond dn_maxblkid are errors, not silently omitted.
Every reached pointer retains the existing type, level, logical-size, feature,
checksum/decompression, vdev-boundary and parent/snapshot birth checks.

Independent branches continue after an error. An unreadable indirect block or
malformed dnode records unknown descendants rather than treating the branch as
an empty success. Diagnostic storage is capped at 128 entries of at most 512
Unicode characters each; counters retain the total and number omitted.

Defaults are 16,777,216 pointer visits, 1 TiB cumulative decoded bytes attempted,
and 1,048,576 allocated dnodes. The CLI accepts explicit nonzero budgets, with a
2^32 ceiling for pointer/object counts. These are work limits, not process-memory,
physical-I/O, native-format or unique-block limits. Hole pointers consume pointer
budget; failed and repeated decoded-block attempts consume decoded-byte budget.
Existing bounded native gang/reconstruction limits remain additional per-read
limits. `verified_blocks` and `verified_bytes` count decoded references, not unique
physical sectors. Sparse-hole logical sizes are deliberately not accumulated.

All raw images remain read-only. The scanner uses the existing native good-copy
and reconstruction path, which can succeed from one replica; it does not verify
every unused mirror copy or every RAIDZ parity sector. `repaired_blocks` is zero
and `all_replicas_checked` is false. Sidecar input is refused before opening the
image because on-read sidecar healing must not be disguised as read-only native
verification. Images must remain immutable for the entire command.

Not covered: other datasets/snapshots, pool free-space and space-map consistency,
ZIL replay, all physical copies/parity, namespace or ACL semantic correctness,
healing, resilver, or native writes. A clean report is evidence only for the
explicit `selected_dataset_dmu_blocks` scope, never a claim of whole-pool health.

## Validation status

The implementation adds constructed-graph Rust tests and CLI parser/refusal tests.
They cover ordinary/private blocks, large dnodes, spills, both byte orders,
sparse geometry, corrupt data/metadata, cancellation, cold-cache behavior,
historical birth bounds and finite work limits. Test devices panic on writes or
flushes. No Rust compiler, Cargo or RCH executable is available in the authoring
environment; Rust tests, compilation, formatting and native OpenZFS comparisons
have not been executed here. No existing test assertion or gate was relaxed.

Required validation includes:

Engine tests have moved into the `ffs-zfs` library, with separate CLI tests;
these current verification commands do not imply a new execution result.

```sh
rch exec -- cargo test -p ffs-zfs --lib -- scrub
rch exec -- cargo test -p ffs-cli --bin ffs-zfs
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
