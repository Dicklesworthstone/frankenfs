# Read-only NTFS MFT record ownership checking

`ffs-ntfs check-allocation --verify-record-ownership` adds a separately bounded
base/extension ownership pass to physical cluster accounting. The two results
are separate: allocated clusters can balance even when an extension FILE record
is missing from its base file's attribute catalog.

```sh
ffs-ntfs check-allocation volume.img --offline-image --verify-record-ownership
ffs-ntfs check-allocation disk.img --offline-image --offset 1048576 \
  --length 67108864 --verify-record-ownership --max-records 1048576 \
  --max-metadata-bytes 1073741824
```

The library exposes `NtfsVolume::check_record_ownership(cx, RecordOwnershipLimits)`
through the same engine. The report types are exported from `reader::allocation`.
There is no serialization dependency in the library and no native write API.

## Native ownership boundary

The pass reads the native `$MFT::$BITMAP` and visits every allocated initialized
FILE record. Base records use the existing bidirectional `$ATTRIBUTE_LIST`
validator: each listed reference must match a record sequence, native attribute
ID, type, UTF-16 name and initial VCN; every loaded attribute must appear in the
catalog. Each extension's base reference must identify that same base generation.
The implementation does not replace the native catalog parser or stream mapping.

Catalog references to bitmap-free or uninitialized records are rejected before
reading those FILE bytes. Only a fully validated base catalog publishes ownership
into the pass's bounded bitset. Once all allocated records and base catalogs are
successfully examined, every allocated extension must have such an owner. An
unlisted extension is reported as a defect, not a record that may safely be freed.

The MFT's own bitmap is obtained through its already admitted native stream;
bootstrap cannot use an unread bitmap to validate itself. Its catalog is checked
again with bitmap authority during the scan, and record zero must be allocated.
Free FILE headers are not scanned: this does not prove bitmap completeness for
records absent from every catalog. Unknown journal, namespace or writer state
is not bypassed by a successful report.

## Bounds and failure behavior

`--max-records` bounds logical MFT slots before checker I/O. The independent
`--max-metadata-bytes` budget defaults to one GiB and admits up to one TiB. It
charges each FILE read, including repeated extension reads, every attribute-list
value, and the bitmap bytes before the corresponding work. Resident list/bitmap
values count too, so the counter is a conservative metadata work measure, not
unique physical I/O. Library open/bootstrap is outside this checker's budget.
The pre-existing per-list and per-catalog parser limits remain in force.

The pass retains three slot bitsets, at most six MiB at the hard 16,777,216-slot
limit, plus one bounded native catalog at a time and 128 diagnostic records.
Detailed errors are capped at 512 characters; omitted diagnostics are counted.
Ordinary file payload, compression providers and image-derived host paths are
never opened. It performs no backing writes or synchronization calls.

A record/catalog I/O or parse error leaves coverage incomplete and suppresses
`extensions_without_owner` to null. Work exhaustion also cannot return a
consistent result. Bitmap-authority failures fail the call, rather than returning
a partial success. Cancellation is terminal. Sources must remain offline and
immutable; sidecars and recovery overlays are refused before the CLI opens them.

The CLI emits a separate `record_ownership` object and
`requested_checks_consistent`. Either failed or incomplete requested check causes
a nonzero exit after JSON output. `allocation_consistent` retains its original
physical-run meaning. `reclaimable_records` and `reclaimable_clusters` stay null.
Without the flag, the ownership pass does not run and its report is null.

## Evidence and remaining obligations

Eight new library controls reuse the existing fragmented-MFT fixture. They cover
512/4096-byte clusters, valid extensions, unlisted owners despite consistent
physical accounting, free-target pre-I/O refusal, stale sequence/base/attribute
identity, incomplete-scan suppression, cancellation, exact work boundaries,
nonresident lists, overlay refusal and invalid bitmap authority. Three CLI/report
controls cover explicit selection, independent bounds, pre-open refusal and
nonzero outcomes. Existing assertions and catalog rules are unchanged.

These Rust tests are authored, not executed in this environment. Cargo/RCH are
absent; compiler, runtime, Clippy and rustfmt qualification remain outstanding.
Source/hash/patch or independent model checks do not replace those gates or
Windows/NTFS3/NTFS-3G native interoperability. This is not full chkdsk, logical
stream assembly, directory/link reachability, journal recovery, repair or writable
admission. No bead or full-format completion is awarded by this increment.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ntfs record_ownership
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-ntfs record_ownership
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ntfs allocation
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Native contract reference: Microsoft Learn, NTFS v3 Master File Table and
ATTRIBUTE_LIST_ENTRY developer notes. The runtime implementation is independent
and shares FrankenFS's existing catalog validation rather than native driver code.
