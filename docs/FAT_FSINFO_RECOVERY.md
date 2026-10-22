# Explicit FAT32 FSInfo reconstruction

`ffs-fat repair-fsinfo` reconstructs the declared primary FSInfo signatures and
allocation hints when complete native ownership evidence is available. It fills
an operational gap in ordinary recovery: `recover` intentionally refuses an
invalid FSInfo signature rather than assuming authority to rewrite that sector.

```sh
ffs-fat repair-fsinfo recovery-copy.img --offline-image --dry-run
ffs-fat repair-fsinfo recovery-copy.img --offline-image
ffs-fat check recovery-copy.img
# Examine the findings before separately authorizing ordinary recovery.
ffs-fat recover recovery-copy.img --offline-image
```

The reusable entry point is `ffs_fat::reader::recovery::repair_fsinfo`. The CLI
requires explicit offline ownership, regular-file/no-follow and identity checks,
and advisory locking. Dry-run holds only read authority and performs no writes
or synchronization. Sidecars are refused: diagnosis cannot trigger read-repair.
These checks do not make an unrelated kernel or image writer safe.

## Authority and preservation

This operation is FAT32-only. The BPB must already declare a nonzero FSInfo
sector inside its reserved region, distinct from the backup boot sector. No
missing pointer, new sector, partition table, or boot record is invented.
Complete allocation and namespace checks must reject ambiguous ownership,
conflicting selected FAT copies, hard errors, truncated evidence, and unrelated
structural damage. Proven lost allocation may remain but is never reclaimed.

The free count comes from actual FAT entries, not either copy's old hint. The
next-free value identifies the first verified free cluster, or `0xffffffff` when
none is available. Bad clusters, live allocation and reachable preallocation are
not counted as free. FAT32 reserved high bits are not successor bits.

Only five four-byte fields change in each repaired FSInfo sector: its three
signatures, free count, and next-free hint. All other bytes, including the rest
of a 4096-byte logical sector, are retained. A conventional backup at
`backup_boot_sector + fs_info_sector` is updated only when it lies inside the
reserved region and already has all three FSInfo signatures. An unknown sector
at that location is fingerprinted and preserved, not reconstructed from a guess.
The report states which backup policy applied and includes before/after sector
hashes and the previous hints. Those hashes are not file-content checksums.

## Publication and failure

The plan captures selected allocation words, complete allocated directory
storage and physical directory mappings, and boot/reserved state. Only clean
bits are normalized. It rechecks complete ownership and captured evidence before
writes and again after verified dirty-state publication. Counts alone cannot
hide a changed native name, chain mapping, or orphan successor.

Each changed hint sector is synchronized and read back in full. Final evidence
must match the retained namespace/allocation, the exact proposed sectors and all
native dirty markers. A repeated request with already-correct hints issues no
write or synchronization. File payload and allocation links are never rewritten.

A changed image remains dirty. Ordinary `recover` is a separate explicit step;
it may still refuse remaining findings or require separate lost-allocation
consent. This operation does not salvage data, clear errors, replay transactions,
roll back, or make native FAT crash-atomic. An interruption can leave partly
repaired metadata. Failed writes, syncs, readbacks and cancellation stop without
cleanup writes. Retain a separate copy and use disposable test images until
compilation and independent native-tool qualification have been completed.

Eleven authored Rust regressions cover 512/4096-byte sectors, selected active
FATs, exact byte preservation, full/bad-cluster volumes, invalid authority,
same-summary evidence changes, late namespace damage, no-op behavior, faults at
write/sync boundaries, and a public CLI-to-ordinary-recovery round trip. They
were not compiled or executed in the authoring environment; source checks and
an independent Python model are not Rust, kernel-FUSE, or native-tool evidence.
