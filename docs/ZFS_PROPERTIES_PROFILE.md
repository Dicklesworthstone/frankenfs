# Read-only native DSL property queries

`ffs-zfs properties` resolves explicitly named properties through the selected,
checksum-verified MOS and DSL ancestry. It does not mount a dataset, change
properties, enforce ACLs, change the reader's read-only status, or infer host
paths from stored strings.

```sh
ffs-zfs properties pool.img --offline-image --auto-import \
  --dataset data readonly compression copies recordsize example.org:owner

ffs-zfs properties pool.img --offline-image --auto-import \
  --dataset data --snapshot before exec example.org:owner

ffs-zfs properties first.img --member second.img --offline-image \
  --pool-guid 123 --label 0 --slot 2 --offset 1048576 --length 134217728 \
  --dataset vm/disk readonly compression volthreading
```

Spaces or commas separate requested property names. There is no implicit `all`.
Dataset names are pool-relative; the empty name selects the pool root. Snapshot
selection is exact stored-name selection. Dataset and snapshot bytes are retained
without lossy UTF-8 substitution. Native/user property names use the supported
ASCII grammar and must be shorter than 256 bytes. Leading hyphens are refused.

## Value and source semantics

The implementation follows OpenZFS `zfs-2.3.0` `dsl_prop_get_dd` and
`dsl_prop_get_ds`. A local value wins over a received value; an explicit
`$inherit` marker suppresses the received value, not a local value. Inheritable
properties search the validated `dd_parent_obj` chain, never the clone origin.
Noninheritable properties do not use ancestor values. Recognized `$iuv` index
values precede local values on DSL directories; unknown index values fall back
to the ordinary native lookup. Snapshot-local storage does not use `$iuv`.
A noninheritable snapshot property does not suppress a received value merely
because an inheritance marker exists.

Snapshot property state belongs to the **selected MOS transaction**, not
necessarily the transaction that created the snapshot's immutable data. A
snapshot-local property can be changed after snapshot creation. Output therefore
includes both `pool_txg` and `snapshot_creation_txg`; neither changes the selected
snapshot data root. The existing exact-name lineage validator remains in use.

Each row distinguishes `local`, `received`, `inherited`, `default`, and `unset`.
For an inherited value, `stored_source` records whether the supplying ancestor
stored it locally or as a received value. `setpoint_components_bytes` records
that ancestor's exact pool-relative name; an empty array denotes the pool root,
whereas null denotes no stored source. `setpoint_snapshot_bytes` identifies a
snapshot-local source. `received` retains the target's received value even when
it is overridden or explicitly suppressed.

Native numeric values are returned as decimal strings with `type: uint64` to
avoid JSON consumer precision loss. Index values remain native numbers, not
host-interpreted enum strings or assertions that a codec/write mode is supported.
Strings retain their exact bytes and also provide `text` when valid UTF-8. The
native terminating NUL is validated and omitted from the returned value; empty
strings are distinct from unset properties. Invalid widths, unterminated strings,
interior NULs and oversized values fail instead of being coerced.

## Declared subset and limits

User-defined colon names are inheritable strings with no default. The native
subset is: `atime`, `relatime`, `overlay`, `devices`, `exec`, `setuid`, `readonly`,
`zoned`, `vscan`, `nbmand`, `canmount`, `snapdir`, `snapdev`, `logbias`, `sync`,
`copies`, `checksum`, `compression`, `recordsize`, `volthreading`, `sharenfs`,
`sharesmb`, `context`, `fscontext`, `defcontext`, and `rootcontext`. Applicability,
inheritance and defaults come from the pinned property registry. Not every
property applies to every filesystem, volume or snapshot.

Computed properties, quotas/accounting fields, mountpoint expansion, platform-
dependent defaults, encryption/key state and other unimplemented schemas fail
explicitly. This command is not a complete replacement for native `zfs get`.
Existing `zvol-info` remains the capacity/volume-geometry interface. A stored
`readonly=off`, `canmount=on`, or compression index never grants write, mount,
replay, or unsupported decoder capability.

Queries are limited to 1–128 unique names, at most 65 DSL directory ancestors,
8 KiB per encoded string including its terminator, and an aggregate 32 MiB
catalog-payload / 65,536-entry retention budget. Each underlying DMU/ZAP read also
retains its existing work, geometry, checksum, feature and birth checks. The
aggregate payload budget is not a complete process-memory or physical-I/O cap.
Catalogs are loaded lazily and reused only within the batch; a resolved local
value does not read an unneeded parent property catalog. The complete DSL
inventory and ancestor identity checks still occur.

Malformed, missing or aliased required property catalogs, corrupt reachable
metadata, unsupported requests, and cancellation return an error without a
successful partial property report. Standard-output failure also fails the
command, although the host stream may already contain a prefix. No image or
sidecar is written or flushed. Sidecar input is refused before opening images
on this command path; other existing commands are unchanged.

## Validation status

Nine engine regression functions and three CLI/serialization regression functions
were authored. Engine fixtures cover both byte orders, a checked MOS with parent,
head and snapshot objects, received/local/inherited precedence, IUV behavior,
noninheritable properties, post-snapshot property changes, malformed metadata,
checksum failures, cancellation and lazy ancestor I/O. They are constructed
fixtures, not OpenZFS-generated pool evidence. Existing CLI test bodies are
unchanged.

The independent Python walk/ranked-candidate model executed 144,240 comparisons
without mismatches. Exact original-file hashes, uploaded engine hashes and
whitespace checks also passed. These checks do not execute the Rust code. Cargo,
rustc, rustfmt and RCH are unavailable in the authoring environment; compilation,
the Rust tests, Clippy, native OpenZFS comparisons and FUSE execution remain
unverified. Required full-workspace validation includes:

Engine tests have moved into the `ffs-zfs` library, with separate CLI tests;
these current verification commands do not imply a new execution result.

```sh
rch exec -- cargo test -p ffs-zfs --lib -- properties
rch exec -- cargo test -p ffs-cli --bin ffs-zfs
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
