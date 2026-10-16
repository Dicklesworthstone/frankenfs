# Explicit FAT16/FAT32 mirror reconciliation

`ffs-fat recover` can reconcile two mirrored FATs using a copy explicitly
selected by the operator. This is useful after an interrupted native metadata
update, but **structural validity cannot determine which conflicting copy
contains the intended file contents**. Keep an untouched original image and
choose a copy from independent evidence; the tool does not choose for you.

```sh
# Source copy numbers are zero-based. Preflight performs no writes or syncs.
ffs-fat recover working-copy.img --offline-image --repair-mirrors-from 0 --dry-run

# Explicitly authorize reconciliation against the selected interpretation.
ffs-fat recover working-copy.img --offline-image --repair-mirrors-from 0
```

The operation accepts only an offline regular image with two mirrored FATs.
The image is exclusively advisory-locked for mutation and read-only/shared-locked
for dry-run. Locks do not exclude kernel mounts or unrelated writers. Existing
volume offset/length and OEM-name options are honored. Sidecars, devices,
symlink targets, invalid copy numbers, single-FAT volumes and non-mirrored FAT32
volumes are refused. An inactive FAT is never promoted to recovery authority.

## Preflight and preservation

Every copy's native reserved entries, recorded I/O errors and boot-state flags
are checked before any alternative interpretation is constructed. A private
read-only diagnostic overlay supplies the selected copy's data-entry values
to both FATs; the existing complete allocation/namespace checker must validate
that interpretation. It cannot escape into the ordinary reader or mount path.
Cross-links, broken live chains, malformed names, incomplete/truncated evidence,
invalid FSInfo signatures and unknown damage are refused. A selected copy is
never replaced by another copy merely because its check fails.

Only entries for addressable data clusters are reconciled. FAT32 high nibbles,
reserved entries, table padding, native directory records and file payloads
are not copied from the selected table. Normal dirty/clean markers and primary
FSInfo hints have their separate verified update protocol. A native bad-cluster
marker in another copy cannot be cleared by selecting a copy without it.
Selected bad-cluster markers may be propagated, never allocated to live files.

Preflight retains the selected data entries plus per-sector SHA-256 evidence,
not two full replacement tables. Storage is bounded by the existing
8,388,608-cluster limit; sector evidence and namespace traversal are bounded too.
Before mutation, input sectors and the selected view's complete retained
namespace are revalidated. A changed chosen table is not silently restored from
a stale preflight snapshot.

## Publication and completion

The native dirty state is synchronized first. Changed FAT sectors use
expected-value, sector-preserving writes and immediate exact readback. After
synchronization, all covered source/target sectors and retained namespace
evidence are verified again. Primary FSInfo is rebuilt from the selected view,
then the actual image must reproduce its allocation and namespace accounting.

If the chosen interpretation has no lost allocation, final clean state is
synchronized and checked. Otherwise **no lost clusters are reclaimed and the
image remains dirty**. The result has `native_recovery_required: true`; an
operator can then choose a separate `--salvage-to` or `--reclaim-lost` operation.
Mirror selection cannot be combined with those options or `--discard-orphan-lfn`
in the same invocation. Matching tables are a no-write/no-sync no-op; that does
not clear unrelated dirty state or stale hints.

`different_entries` counts differing native entries; `planned_fat_sector_writes`
counts their FAT-sector publications, excluding dirty/clean and FSInfo writes.
`selected_view` is the preflight interpretation, not a claim about original
file contents. Success explicitly reports `file_contents_verified: false` and
`file_payloads_written: false`.

This is ordered, non-atomic structural repair, not transaction replay or
payload restoration. A failure returns its phase, retains the image, and makes
no rollback or automatic cleanup writes. An interrupted attempt may still leave
disagreeing FATs and require another explicit recovery decision.

## Validation boundary

The implementation includes masked-byte projection tests and native-image
regressions for both dialects, source choice, dry-run, error/bad-marker refusal,
stale evidence, source changes during preflight, selected-volume bounds,
high-nibble/padding preservation, dirty lost allocation and storage faults.
Rust compilation and these Rust tests have not executed in the authoring
environment because Cargo is absent. Independent Python projection/fault models
are supplementary evidence, not Rust, FUSE or native-OS qualification.

```sh
cargo test -p ffs-cli --bin ffs-fat mirrors
```
