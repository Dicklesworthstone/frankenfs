# Native FAT range insertion

The FAT `FsOps::fallocate` implementation accepts `FALLOC_FL_INSERT_RANGE` for
regular files. It inserts `length` zero bytes at `offset`, shifts the original
suffix to higher logical offsets, and grows EOF by `length`. Offset and length
must be cluster-aligned, length must be nonzero, and offset must be strictly
inside the old EOF. Length may exceed the old file size. The new file size must
fit FAT's `2^32 - 1` byte field. Invalid alignment/offsets return `EINVAL`;
size overflow returns `EFBIG`. No flag combinations are accepted. Existing
allocation, KEEP_SIZE, ZERO_RANGE, and COLLAPSE_RANGE behavior is unchanged.

Unlike extent-based sparse files, FAT represents the inserted zero range with
real allocated clusters. Allocation/block counts increase accordingly; there
is no sparse-hole, reflink, or space-saving claim. This is distinct from adding
native on-disk support for sparse files. It requires exactly `length / cluster_size`
free clusters, not another copy of the existing file. Insufficient capacity is
refused before any backing write or synchronization, including dirty markers.

The implementation splices an initialized new run into the native chain. It
does not read or copy existing file payload, shift its physical cluster IDs, or
reclaim any original allocation. Reachable preallocation shifts with the suffix,
including the old partial-EOF cluster and its slack. It is not consumed as gap
capacity or exposed beyond the new EOF. Fragmentation, prefix insertion and
insertion into the final partial cluster use the same native protocol.

Names, short aliases, creation/access timestamps, DOS hidden/system flags,
FAT16 EA fields, FAT32 reserved bits and selected-copy policy are preserved.
Modification time and the archive bit are updated. Mounted operation locking
covers both native mutation and refresh of chain, size, block count and free-space
caches. Inode/handle identity is retained, including mount-retained unlinked files.

## Publication and failure contract

A complete clean namespace/ownership check and all capacity reservations precede
writes. Dirty state is synchronized and verified first. The new clusters are
fully zeroed, synchronized and read back before publishing their detached FAT
chain. The detached chain and unchanged old chain are verified with fresh FAT
readers. No existing payload is overwritten, even by an interrupted insertion.

Logical EOF is then published as zero with the old head and verified. Only then
is the inserted tail connected to the old suffix. That chain and the old chain
are checked before updating the predecessor or directory head. The full inserted
chain, directory record and zero range must verify before publishing the larger
EOF. Separating EOF/head publication prevents a prefix-torn head update from
exposing unrelated allocation through the old size. Publishing zero to the final
size also avoids an intermediate larger value from a torn little-endian carry.
Whole-sector directory readback preserves/checks neighboring records. A final
ownership/accounting check includes retained preallocation before clean state.

This is **not crash-atomic**. An interruption may leave the file logically empty,
partly shifted, or with a shorter visible prefix, plus detached allocation or
conflicting FAT copies requiring explicit recovery. Original bytes remaining on
disk do not imply automatic recovery of the old name/length/chain. No rollback,
cleanup writes, or stronger hardware guarantee is claimed. Mounted failures after
an I/O attempt quarantine further cached access. Full-volume checks and multiple
synchronization barriers remain; no measured performance speedup is claimed.

The constructed-image and direct-FsOps tests cover fragmentation, capacity,
preallocation, sector widths, selected FATs, high cluster IDs, dropped/torn I/O,
cancellation, held/unlinked handles and competing insertions. Authored tests are
not execution evidence. Rust compilation, test execution, kernel FUSE and native
filesystem-tool interchange must be qualified separately.
