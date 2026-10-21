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

## Evidence and remaining qualification

Ten library regressions and four CLI/report controls are authored. They cover
an independent per-cluster accounting oracle, bounded evidence, constructed
fragmented MFT records and matching native bitmaps at 512/4096-byte clusters,
extension-backed and sparse allocation, cross-links, free references, unknown
allocation, torn/I/O-failed records, uninitialized MFT tails, cancellation,
work bounds, unchanged bytes/no payload reads and pre-open source-policy refusal.
Test devices panic on writes and flushes. They are constructed native-byte tests,
not images generated or checked by Windows.

These Rust tests have **not been executed in this implementation environment**.
RCH, Cargo, rustc and rustfmt are unavailable; attempted test/check/lint/format
commands could not start (exit 127). Exact baseline and uploaded blob comparisons
and Git whitespace checks passed. An independent Python accounting model passed
4,900 layouts and 19,600 comparisons; it did not execute this Rust implementation.
No native NTFS3/NTFS-3G/Windows, full-workspace or runtime pass is claimed.

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
