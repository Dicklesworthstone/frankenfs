# Read-only NTFS physical allocation check

`ffs-ntfs check-allocation` cross-checks physical run claims from allocated MFT
records against the volume's native `$Bitmap`. It uses the shared `ffs-ntfs`
library, not a shell-out to an external checker. This is a bounded maintenance
primitive toward the NTFS-07 plan, **not a complete NTFS checker, repair command,
writer admission, or proof that Windows will consider the filesystem clean**.

```sh
ffs-ntfs check-allocation volume.img --offline-image

# Explicitly selected partition; no partition discovery or host-device writes.
ffs-ntfs check-allocation disk.img --offline-image \
  --offset 1048576 --length 67108864 \
  --max-records 1048576 --max-clusters 33554432 --max-runs 1048576
```

The source must remain offline and immutable. The existing reader retains a
shared advisory lock, bounded image view, NTFS 3.1 bootstrap and record-zero
mirror checks; a shared lock does not exclude unrelated writers. The command
refuses sidecars and `--recover-logfile` before opening either file. The library
also refuses dirty volume flags and published recovery overlays. It does not
inspect `$LogFile` or establish hibernation safety: clean flags alone are not
native recovery validation. No read invokes repair, writes or synchronization.

## Accounting

`$MFT::$BITMAP` identifies allocated FILE records. Each allocated initialized
record is read through the existing MFT map, including fragmentation, and has
its update-sequence protection, record identity and live sequence checked.
Each record's direct nonresident attributes contribute their physical runs.
Extension records are scanned once by their own allocated bit; the scan does
not recursively flatten ATTRIBUTE_LIST and then count those same runs again.

All nonresident attribute types participate, not just unnamed DATA. Named and
extension-backed streams, metadata allocation, reachable preallocation and
sparse/compressed/EFS physical mappings are retained. Sparse holes have no
physical owner. Counting encrypted or compressed storage does not decrypt,
decompress or validate its contents. Resident values already occupy their FILE
record and do not acquire a second allocation claim. Nonresident ATTRIBUTE_LIST
storage is counted, but its semantic reference graph is not validated here.

Sorted intervals and a volume sweep detect:

- overlapping physical claims, with two record/attribute-instance witnesses;
- referenced clusters whose native volume bitmap says free;
- allocated clusters for which the completed scan observed no physical claim.

Counts use the union of physical spans, not a sum that double-counts overlaps.
No traversal-order heuristic chooses a rightful owner. Unexplained allocations
are **not proven reclaimable orphans**; the JSON always leaves
`reclaimable_clusters` null. No bitmap or FILE record is changed.

## Incomplete coverage is not a clean result

An unreadable/torn FILE record, invalid mapping, unsupported storage flags or
exhausted run budget leaves `complete: false`. Already observed conflicts can
still be reported, but `allocated_without_reference` becomes null: unseen
references must not be mistaken for absent ones. An allocated record beyond
initialized MFT data is reported without reading its uninitialized bytes.

A failure in either authority bitmap aborts the command rather than treating
unknown bits as free. Cancellation is terminal and returns no successful
partial report. Issue details retain record/attribute/cluster context, with at
most 128 entries and a separate omitted count. Counts continue after that
presentation bound; it does not silently stop checking.

The CLI prints JSON and returns failure for discrepancies, unsupported state or
incomplete coverage. Success means only `allocation_consistent: true` within
`scope: allocated_mft_record_physical_runs`. It deliberately does not emit a
whole-filesystem `clean: true` claim. Output errors also fail the command.
Numeric scan/allocation counters are grouped under `counts`; coverage, issues
and the nullable unreferenced-allocation result remain explicit top-level fields.

## Bounds and exclusions

Defaults are 1,048,576 logical MFT slots, 33,554,432 volume clusters and 1,048,576
mapping runs. Explicit maximums are 16,777,216 slots, 268,435,456 clusters and
1,048,576 runs. Excess geometry is reported before bitmap materialization,
not checked as an arbitrary prefix. Bitmap reads use at most 64 KiB per call.
The two bitsets need at most 34 MiB together at the hard ceilings; retained run
claims and the existing bounded bootstrap/catalog machinery are additional.
The interval sweep avoids work proportional to every cluster of every
potentially overlapping run. Record reads remain bounded by native record size
and the explicit slot count; these limits are not a latency promise.

Unallocated FILE headers are not scanned; a live FILE with a clear MFT bitmap
bit is outside this pass. Directory indexes, namespace reachability, hard-link
counts, complete logical stream/ATTRIBUTE_LIST relationships, payload validity,
security/secondary indexes, full MFT mirror coverage, journal/recovery state
and Windows checking remain separate obligations. A valid checksum/USA or an
allocation-consistent report does not establish any of those properties.

The library API is `NtfsVolume::check_allocations(cx, AllocationLimits)` with
public report/issue types under `ffs_ntfs::reader::allocation`; it adds no
serialization dependency to the native library.

## Namespace and directory-index verification

Add `--verify-namespace` to reconcile allocated base FILE records with their
native `$I30` directory indexes. This complements physical allocation and the
separate `--verify-record-ownership` check: a volume can account for every cluster
while a file's name is absent from its parent directory.

```sh
ffs-ntfs check-allocation volume.img --offline-image --verify-namespace
ffs-ntfs check-allocation disk.img --offline-image \
  --offset 1048576 --length 67108864 \
  --verify-record-ownership --verify-namespace \
  --max-records 1048576 --max-namespace-entries 1048576 \
  --max-metadata-bytes 1073741824
```

The pass assembles each base record's validated attribute catalog, including
extension records, and retains native record sequences and exact UTF-16 name
identities. It walks each directory's resident root and allocated INDX children,
checks update-sequence protection, child geometry and allocation, and verifies
the order using the volume's own `$UpCase` table. An allocated but unreachable
index block is a discrepancy. Ordinary file contents and reparse targets are
not followed. Reparse directories and unsupported transformed or sparse index
storage leave the namespace check incomplete.

After complete inspection, it compares both directions: every indexed name must
identify an allocated, sequence-matching base FILE with that name in its catalog,
and every non-root FILE_NAME must have its corresponding parent index entry.
The parent must itself be an allocated, sequence-matching directory. Root
reachability is derived from verified links, with reserved unnamed system slots
kept separate from ordinary user records. Duplicate names and invalid directory
hierarchies are reported without selecting an owner or changing the image.

Each completely parsed base catalog also checks the native FILE header's link
count. Every FILE_NAME attribute counts, including separate DOS aliases and names
held in validated extension records. A combined Win32/DOS name counts once.
Disagreements produce a `link_count_mismatch` issue naming the base record and
both counts; the source remains unchanged. An unreadable extension, malformed
name or exhausted budget prevents this comparison for that base record, while a
previously established mismatch remains reportable if another record later fails.
This is native attribute accounting, distinct from the mounted POSIX `nlink`,
which excludes separate DOS aliases. The distinction follows the independent
[Linux v6.19 NTFS3 inode reader](https://github.com/torvalds/linux/blob/v6.19/fs/ntfs3/inode.c).

The library API is `NtfsVolume::check_namespace(cx, NamespaceLimits)`. Its types
are exported from `ffs_ntfs::reader::allocation`. The defaults are 1,048,576 MFT
slots, 1,048,576 combined FILE_NAME/index identities and one GiB of metadata work.
The entry ceiling is 16,777,216. FILE, ATTRIBUTE_LIST, bitmap, index and UpCase
bytes are charged before their reads, including repeated metadata and resident
values. This is a work budget rather than a unique-byte or resident-memory
measurement; the retained identity graph also consumes memory. Reader bootstrap
occurs before the checker and retains its own bounds.

`--max-metadata-bytes` applies independently to each requested structural check.
Selecting both ownership and namespace checking grants each that amount; it is
not a combined cap, and it does not change the physical allocation scan's bounds.
`--max-namespace-entries` requires `--verify-namespace`. All selected checks retain
the original offline, immutable-source and no-recovery-overlay requirements.

JSON includes a separate `namespace` object and `requested_checks_consistent`.
`allocation_consistent` keeps its original physical-run meaning. An unreadable
record/index, unsupported metadata or exhausted budget prevents namespace
success. Incomplete coverage leaves `missing_index_entries` and
`unreachable_records` null, not zero. Cancellation fails the call. A failure in
the MFT bitmap or UpCase authority also fails the call. Diagnostics retain
bounded issue details and omitted counts; `reclaimable_records` remains null.

This verifies the selected native namespace structure. It does not validate
DOS-to-Win32 alias pairing, unallocated FILE headers,
security descriptors, non-I30 secondary indexes, payloads or the journal. Full
NTFS checking, formatting, resize and native mutation remain open under
`bd-h7cme` and the related writer work.

## Complete MFT mirror comparison

`--verify-mft-mirror` compares the complete initialized unnamed DATA stream of
`$MFTMirr` with the corresponding primary MFT records. Opening the reader
already checks bootstrap record zero; this pass also detects disagreements in
the mirror's `$MFTMirr`, `$LogFile` and `$Volume` records and any larger declared
mirror prefix. It does not choose which copy is authoritative or repair either
copy. An image whose record-zero bootstrap is already unreadable or inconsistent
remains refused by the normal reader.

```sh
ffs-ntfs check-allocation volume.img --offline-image --verify-mft-mirror
ffs-ntfs check-allocation volume.img --offline-image \
  --verify-mft-mirror --verify-record-ownership --verify-namespace \
  --max-records 1048576 --max-metadata-bytes 1073741824
```

The pass validates the native record-1 catalog, MFT allocation bits for the four
bootstrap records, initialized record boundaries, plain nonsparse mirror
storage and agreement with the boot-sector mirror location. Mirror extents
cannot overlap themselves or any primary MFT extent: equality between two views
of the same physical allocation would not establish a separate recovery copy.
Each record is parsed with update-sequence and attribute bounds checks before
its used metadata is compared. Unused record slack and the validated USA array
do not affect logical equality; restored sector trailers within used metadata
still participate in the comparison.

The JSON `mft_mirror` result separates `required_prefix_matches` for records 0–3
from `extended_record_differences`. This matters because NTFS-3G documents that
Windows versions since 2017 can leave later mirror records different on
large-cluster volumes ([native comparator source](https://github.com/tuxera/ntfs-3g/blob/edge/ntfsprogs/ntfsfix.c)).
Such a difference is reported without calling it proof of corruption. The full
comparison still returns a failing status when the declared copies differ;
`consistent: true` means all inspected used metadata agrees. No result supplies
a `repair_source`, a native recovery decision, or general filesystem cleanliness.

`--max-records` retains its whole-MFT slot bound. `--max-metadata-bytes` applies
independently to this pass, charging FILE/catalog/bitmap work and both copies
before each pair is read. A limit, unreadable record or unsupported storage
leaves `complete: false`; a required-prefix comparison that could not finish is
null. Already established differences remain visible. Cancellation returns an
error, not a partial successful report. The same original-image, offline,
no-sidecar and no-recovery-overlay requirements apply, and the pass never writes
or synchronizes the backing device.

Nine library controls and three CLI controls are authored for this increment.
They cover 512-byte and 4 KiB cluster fixtures, four- and eight-record mirrors,
used-data versus slack/USA distinctions, required and extended differences,
torn/stale records, boot mapping and self-aliasing, invalid initialized ranges,
MFT bitmap disagreement, pre-I/O work limits, I/O errors, cancellation and
unchanged backing bytes. These constructed records are not native Windows
qualification; executed results are recorded separately when available.

## Evidence and remaining qualification

Ten library regressions and four CLI/report controls are authored. They cover
an independent per-cluster accounting oracle, bounded evidence, constructed
fragmented MFT records and matching native bitmaps at 512/4096-byte clusters,
extension-backed and sparse allocation, cross-links, free references, unknown
allocation, torn/I/O-failed records, uninitialized MFT tails, cancellation,
work bounds, unchanged bytes/no payload reads and pre-open source-policy refusal.
Test devices panic on writes and flushes. They are constructed native-byte tests,
not images generated or checked by Windows.

The namespace increment adds thirteen parameterized library tests and three CLI
controls. They cover resident and multilevel indexes, extension-backed names,
hard links and DOS aliases, stale/free references, missing reverse entries,
conflicting names, directory cycles, invalid root identities, malformed indexes,
cancellation and pre-I/O global budgets. Read-recording fixtures exclude ordinary
payload access and verify that incomplete scans retain unknown absence counts.

Runtime qualification is still pending. In the current environment, the pinned
nightly toolchain is available and the changed NTFS/CLI Rust files pass rustfmt.
Focused all-target checks and a single-job retry were terminated by SIGKILL
while compiling the `asupersync` dependency under memory pressure; they did not
reach the new checker or execute its tests. No full-workspace, native checker or
Windows pass is claimed. The earlier independent Python allocation model's
4,900 layouts and 19,600 comparisons did not execute this Rust implementation.

Required validation remains:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-ntfs allocation
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-ntfs allocation
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Native format references: Microsoft's
[Master File Table notes](https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table)
and [VOLUME_BITMAP_BUFFER](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-volume_bitmap_buffer).
The existing pure NTFS FILE/mapping-pair parsers supply the checked grammar;
this increment does not replace or weaken them. The complete native maintenance
and write goals remain in the comprehensive plan and workpackages.
