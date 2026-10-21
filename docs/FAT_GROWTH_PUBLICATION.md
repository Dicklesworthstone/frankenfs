# Native FAT growth allocation publication

Ordinary positioned writes, truncate-growth, allocation/KEEP_SIZE, ZERO_RANGE,
and copy_file_range share the FAT range-update engine. New data and allocation
are staged under the caller's exclusive operation gate. Existing clusters and
preallocation remain in place; only missing capacity is allocated.

Synchronizing newly written FAT links is not sufficient evidence that the
prepared chain exists. A dropped or misdirected acknowledged write can leave a
missing or wrong successor even when data initialization succeeded. Checking
only after publishing a larger EOF detects that condition too late.

The engine now reads the prepared allocation through a fresh FAT reader at two
publication boundaries. After synchronizing the new detached run, it verifies
both that run and every retained old link, including the old end-of-chain,
BEFORE attaching the old tail. After attachment it verifies the complete prepared
chain BEFORE publishing the file's head, size or metadata. The selected FAT copies
must agree; inactive copies do not become authorities and reserved high bits do
not become successor bits. No pre-mutation FAT cache can certify these readbacks.

Growth into existing preallocation also rechecks its retained links after the
data barrier and before a larger EOF is published, even when no clusters were
added. KEEP_SIZE receives the attachment checks despite leaving logical EOF
unchanged. An unallocated empty file must verify its new chain before acquiring
a first-cluster reference. No extra synchronization or rollback writes are added;
all existing initialized-data, final-chain and full-volume consistency checks
remain in place. The extra reads have not been performance-qualified.

A failed verification stops before subsequent namespace publication. It does
not undo live bytes already overwritten or detach allocations that may already
have been linked. Dirty-state admission and mounted failure quarantine remain
required. This is not crash atomicity, proof against dishonest flushes, arbitrary
media corruption immunity, or a persistent transaction-replay protocol.

Constructed-image regressions cover the six shared caller paths, per-copy dropped
FAT writes, empty-file first allocation, retained-link corruption, preallocated
growth, read failures/cancellation and mounted cache quarantine. They are authored
tests, not evidence of executed Rust, kernel FUSE or native-tool interoperability.
