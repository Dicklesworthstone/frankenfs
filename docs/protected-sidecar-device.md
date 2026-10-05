# Mutable images with external repair coverage

`ffs_repair::sidecar::live::SidecarImageDevice` is a fixed-size `ByteDevice`
implementation for a regular filesystem image and an existing FFSRQSC2 sidecar.
It is a proposed implementation, not enabled by the existing mount CLI. It does
not reserve or overwrite filesystem allocator space.

## Durability contract

`open` exclusively locks both inodes for the device lifetime. It requires the
image to match the saved whole-image digest, validates each group source table
against the image, and rejects damaged parity. It remembers one digest per
source table so an internally valid table transplanted from another generation
cannot authorize read repair. Startup differences are never implicitly rolled
back: use the existing offline restore-to-new-image operation when explicit
snapshot restoration is intended.

Before the first new source write, the device writes an invalid/pending archive
header and synchronizes that file. `write_all_at` is write-through, not a durable
coverage acknowledgement. It verifies complete affected blocks before preserving
partial-write bytes, and tracks digests of the intended new blocks.

A write replacing every real byte of a block does not read or repair the discarded
contents. It can explicitly replace an unrecoverable block, even in a dirty epoch,
without using stale parity. Replacing the complete short final block preserves its
virtual zero padding and does not extend the image. Mixed writes still verify all
partially preserved blocks before the first caller-data write or new epoch fence.
This is replacement with the caller's new bytes, not reconstruction of lost data.

`sync` first synchronizes the source, then verifies its bytes against the intended
write epoch. It constructs a replacement sidecar, re-encoding changed groups or
groups with damaged parity and copying only validated unchanged records. It
rechecks the whole image, reads back the staged header, source tables and parity,
locks the new archive inode before publication, atomically replaces the archive,
and synchronizes its parent directory. Only then is the epoch clean.

When dirty-sync verification encounters checksum corruption or an explicit media
read failure in an unaffected group, it uses the same whole-group generation guard
as read repair. Every intended digest in that group must still match its admitted
protection point. Recovery is attempted once, followed by a fresh load and complete
verification against the intended bytes; a changed peer cannot be rolled back.
Healthy modified groups are verified directly and receive new parity, without
trying to decode their old generation. No preparatory read or scrub is required.

Repairs completed before a later group fails may remain in the source image, but
they do not publish any pending writes. Failed refresh retains the pending header
and intended digests for an explicit retry. Cancellation and non-media I/O errors
do not trigger recovery. A clean `sync` remains a durability barrier, not a scrub.

An interrupted or failed epoch remains unavailable for automatic recovery. The
ordinary sidecar reader rejects its pending header; it cannot revive old parity
as fresh coverage after process restart. There is no automatic reconciliation of
an unfinished epoch. Do not restore the old magic/checksum by hand. Keep the image
and archive as evidence and establish a known-good source independently before
creating new protection.

## Verified reads and repair

At a clean boundary, a checksum failure or media read error can trigger real
RaptorQ reconstruction. Every recovered block must match its source digest, every
target is compared with its captured before-image, and all outputs are checked
before the first repair write. Success requires source sync and readback.

Complete source-group corruption, including a one-block partial tail, can use
parity-only reconstruction when the surviving equations have sufficient rank.
This retains the admitted-generation table anchors and per-block verification;
it does not relax the ordinary on-image codec's intact-source requirement.

`scrub` checks source and protection together at a clean boundary. After all
source groups verify, damaged parity or header bytes are replaced through the
same verified, locked, atomic archive publication path. Intact source data can
regenerate even a completely damaged parity set. The return value remains the
number of recovered source blocks, not regenerated symbols. Corrupt source-digest
metadata or unrecoverable source data is an error, not permission to create new
protection from unknown bytes.

Dirty-epoch reads still verify intended bytes. Recovery remains available for a
group only when every intended source digest in that group matches the admitted
protection point. A changed digest anywhere in the group forbids using its old
parity, including for an unchanged block; writes in other groups do not. Partial
writes can likewise recover preserved bytes in an unaffected group before
recording their new intended digests. Repair never clears the pending header or
publishes outstanding writes: only a successful explicit `sync` does that.
Insufficient redundancy, changed tables, corruption in a changed repair group,
permission failures and cancellation are errors. Failed reads preserve the
caller's destination. Partial write failures poison the handle rather than
silently acknowledging uncertain state.

## Boundaries and cost

All source writes and repair operations must go through the same device.
Advisory locks cannot exclude a kernel mount or an unrelated writer. The archive
parent must be under the caller's exclusive namespace control. The image cannot
be resized. Checksums detect accidental damage, not malicious authentication.

Dirty sync scans the entire image and archive; only changed groups are normally
re-encoded. A scrub that rebuilds protection also performs this complete refresh.
Memory includes per-group table anchors and per-changed-block hashes, plus bounded
group buffers. No low-latency fsync claim is made. Truncated images and startup
mismatches still require explicit offline recovery rather than live resizing or
implicit rollback.

The adapter is accepted by the existing `OpenFs::from_device` interface, but
mount-CLI wiring, default/native repair, filesystem-level replay, background
workers, multi-device recovery and mounted crash certification are not included.

## Validation required

The regression suite includes three real subprocess exit boundaries (after the
pending fence, after a source write, and after successful sync), acknowledged-byte
restoration, repeated refresh epochs, metadata transplantation, read repair,
insufficient redundancy, cancellation and inode-lock lifetime. Added regressions
cover complete group corruption, parity/header replenishment, full-block and
short-tail replacement, and refusal to preserve corrupt partial-write bytes.
Dirty-sync regressions cover cross-group and short-tail recovery, changed-target
and changed-peer refusal, exhausted parity, explicit retry, cancellation,
rewriting a group to its admitted generation, truncation, cached-table substitution,
and a later-group failure after successful earlier recovery. The sync-recovery
extension still requires execution of these Rust tests with the pinned toolchain.
Process exit is not a hardware power-loss simulation.

For the 2026-10-04 changes, Rust/Cargo and RCH were unavailable in the implementation
container. Added Rust tests and source review are not evidence of a passing build
or mounted filesystem run. Use the pinned toolchain and inspect CI results before
treating the implementation as validated:

```sh
cargo fmt -p ffs-repair
cargo test -p ffs-repair --locked
cargo clippy -p ffs-repair --locked --all-targets -- -D warnings
cargo fmt -p ffs-repair --check
```
