# Offline image protection and recovery

`ffs-image-repair` protects an offline image with an external RaptorQ sidecar.
It stores checksums and parity outside the image: no ext4 or btrfs block is
assumed free, reserved implicitly, or overwritten with repair metadata. It
protects every image byte, including superblocks, allocation metadata, and the
last partial block. The implementation streams bounded source groups instead
of loading the whole image.

## Commands

```sh
cargo build -p ffs-repair --bin ffs-image-repair

# Unmount the image and stop all writers before taking the protection point.
target/debug/ffs-image-repair protect disk.img disk.ffs-rq --offline

# Read-only comparison with that saved generation.
target/debug/ffs-image-repair verify disk.img disk.ffs-rq

# Restore the saved generation to a NEW file; never alter the damaged source.
target/debug/ffs-image-repair restore disk.img disk.ffs-rq recovered.img --offline
```

Successful commands emit JSON. Exit status 0 means success, 2 means verification
found source differences or invalid parity (and also denotes CLI argument
errors), 4 means an operational or recovery failure, and 130 means cancellation.
Protection and restoration refuse to replace an existing destination, including
a hard link to the input. The completed output is synced before publication and
the containing directory is synced afterwards. A publication-stage sync failure
can leave a visible file with uncertain durability; inspect that path rather
than retrying with overwrite semantics.

## Protection point, not transparent live repair

The sidecar describes one exact image generation. Legitimate filesystem writes
after capture are also reported as differences. Restoration deliberately writes
a separate file so recovery cannot silently roll back newer source data. Check
the restored image using the appropriate filesystem checker before using it.
Keep the sidecar on independent storage to avoid losing image and parity to the
same device failure. A sidecar is redundancy, not a full backup.

The source must be offline. An advisory lock on the actual image inode excludes
cooperating operations even through hard-link aliases and is held for the whole
operation. It cannot stop a kernel mount or an unrelated writer that ignores
locks. Capture rereads the image before publication and refuses detected
changes; that check does not turn a live, externally modified image into a
consistent snapshot. Ctrl-C propagates through the explicit capability context
at I/O and group boundaries; an in-progress codec calculation completes before
the next checkpoint.

Defaults are 4096-byte blocks, 256 source blocks per group, and 16 repair
symbols per group. `protect` accepts `--block-size`, `--group-blocks`, and
`--repair-symbols`. Source buffers are capped at 4 MiB per group; codec working
memory adds bounded overhead. These groups are protection units, not filesystem
allocation groups. Damage concentrated in one group can exceed its redundancy
even when total image damage is small. The current decoder requires at least
one intact source block in each damaged group and may reject a rank-deficient
set. The final partial group has the same repair-symbol budget but fewer source
blocks, possibly only one; losing that entire group is not recoverable through
the current decoder.

## Integrity and publication

The archive header, group geometry and source digest tables are checksummed.
Every repair symbol has its own checksum and encoding-symbol ID; corrupt or
duplicate symbols are excluded independently. Recovery uses the existing
FrankenFS RaptorQ decoder with the exact captured, validated source buffers.
Every recovered block must match its saved BLAKE3 digest. The entire staged
output is reread and must match the saved whole-image digest before publication.
An unrecoverable later group never exposes a partial final image.

Checksums detect accidental corruption, not maliciously forged archives. This
format does not authenticate a sidecar supplied by an adversary. It is a new,
explicit offline path; it does not enable default mounted self-healing, change
`ffs-cli repair`'s on-image storage layout, certify native allocator reservations,
or provide multi-device image-set recovery. Those remain separate work under
`bd-11a8t` and `bd-hk5w3`.
