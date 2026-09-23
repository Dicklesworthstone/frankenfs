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

`sync` first synchronizes the source, then verifies its bytes against the intended
write epoch. It constructs a replacement sidecar, re-encoding changed groups or
groups with damaged parity and copying only validated unchanged records. It
rechecks the whole image, reads back the staged header, source tables and parity,
locks the new archive inode before publication, atomically replaces the archive,
and synchronizes its parent directory. Only then is the epoch clean.

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

Dirty-epoch reads still verify intended bytes but never use preceding parity.
Insufficient redundancy, changed tables, unknown corruption during refresh,
permission failures and cancellation are errors. Failed reads preserve the
caller's destination. Partial write failures poison the handle rather than
silently acknowledging uncertain state.

## Boundaries and cost

All source writes and repair operations must go through the same device.
Advisory locks cannot exclude a kernel mount or an unrelated writer. The archive
parent must be under the caller's exclusive namespace control. The image cannot
be resized. Checksums detect accidental damage, not malicious authentication.

Dirty sync scans the entire image and archive; only changed groups are normally
re-encoded. Memory includes per-group table anchors and per-changed-block hashes,
plus bounded group buffers. No low-latency fsync claim is made. Complete source
group loss is left to offline restore, which has its own independently checked
whole-image publication path.

The adapter is accepted by the existing `OpenFs::from_device` interface, but
mount-CLI wiring, default/native repair, filesystem-level replay, background
workers, multi-device recovery and mounted crash certification are not included.

## Validation required

The new Rust implementation and its 15 regression tests have not been compiled,
formatted with rustfmt, or executed in the preparation environment. Tests include
three real subprocess exit boundaries (after the pending fence, after a source
write, and after successful sync), acknowledged-byte restoration, repeated
refresh epochs, metadata transplantation, read repair, insufficient redundancy,
cancellation and inode-lock lifetime. Process exit is not a hardware power-loss
simulation.

Run on the repository's pinned toolchain before treating the change as validated:

```sh
cargo fmt -p ffs-repair
cargo test -p ffs-repair --locked
cargo clippy -p ffs-repair --locked --all-targets -- -D warnings
cargo fmt -p ffs-repair --check
```
