# Native FAT range collapse

The FAT `FsOps::fallocate` path supports `FALLOC_FL_COLLAPSE_RANGE` for regular
files. It removes `[offset, offset + length)`, shifts subsequent logical data
toward the beginning, and reduces EOF by `length`. Both values must be multiples
of the volume's cluster size. Length must be nonzero and the removed range must
end strictly before EOF; use truncation for tail removal. Invalid ranges return
`EINVAL`. Mode combinations and other unsupported allocation modes remain
refusals, never successful no-ops or sparse-file emulation.

The implementation retains the existing prefix and suffix cluster identities,
rewires their native chain, and releases only the removed clusters. It performs
no file-payload reads or writes and requires no spare data clusters. Fragmented
files and full volumes use the same path. Reachable allocation beyond EOF is
retained and shifted with the suffix, not accidentally released as spare space.

File size, allocated block count, free-space cache and cluster-chain cache are
refreshed through the existing mounted operation guard before success. Existing
inode/handle identity is unchanged. Native hidden/system attributes, names,
aliases, creation/access times, FAT16 EA fields and FAT32 reserved bits are
preserved; modification time and the archive bit are updated. Only the selected
FAT copies are modified.

## Durability boundary

This operation is **not crash-atomic**. It requires the same exclusive offline
or mounted writer ownership as other native mutations. Complete clean ownership
and boot-state checks precede writes. Dirty markers are synchronized and verified
before metadata changes.

EOF is temporarily published as zero with the old head, then verified before
changing chain links. This prevents an old EOF from exposing preallocation after
a splice, including the prefix-removal case where head and size occupy different
bytes of one directory entry. Zeroing EOF also avoids an arbitrary shorter
little-endian size briefly increasing during a prefix-torn size write. The
retained chain is verified before restoring its final length. Detached clusters
are reclaimed only after the final record and complete retained chain pass
readback. Allocation, namespace and preallocation accounting are checked again
before clean-state publication.

A failed or interrupted operation may leave an empty or shorter file, detached
allocation, conflicting FAT copies, or damaged metadata requiring recovery. The
mount refuses further use after uncertain mutation or cache publication. There
is no rollback, transactional guarantee, arbitrary-media-corruption immunity or
claim that prior logical EOF can always be recovered. Removed payload is not
securely erased. Full-volume checking and ordered synchronization remain costs
of this experimental native writer; no measured speedup is claimed.

Constructed-image and direct-FsOps regressions cover full-volume operation,
fragmentation, preallocation, active FAT policy, cancellation, dropped/torn I/O,
cache refresh and concurrent requests. These do not substitute for executed
Rust tests, a kernel FUSE mount, or native filesystem interoperability checks.
