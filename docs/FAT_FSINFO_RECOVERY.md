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
cleanup writes. Retain a separate copy; the executed qualification below covers
disposable offline images and does not establish crash or field reliability.

Eleven Rust regressions cover 512/4096-byte sectors, selected active
FATs, exact byte preservation, full/bad-cluster volumes, invalid authority,
same-summary evidence changes, late namespace damage, no-op behavior, faults at
write/sync boundaries, and a public CLI-to-ordinary-recovery round trip. They
all passed on 2026-10-22: 11 passed, zero failed or ignored, 484 other tests
filtered (`tests-8dae-fsinfo-vmi114-0311.log`, RCH `30074357740995216`). The
authoring environment's earlier source checks and Python model remain separate
from this executed Rust evidence.

The permanent `scripts/verify_fat_read.py` FSInfo component then passed 20
captured commands on a private bounded copy of a native-produced 128 MiB FAT32
image with 512-byte sectors: 17 successful commands and three expected nonzero
statuses. It damaged primary signatures and both copies' hints, required explicit
offline authority, proved ordinary recovery refused the invalid signatures,
and checked dry-run preservation. Repair reconstructed 253,962 free clusters
and next-free cluster 4,118 from native allocation, changed only the five
permitted words per hint sector plus four dirty markers, and remained dirty.
A repeated repair preserved every byte. Separately invoked ordinary recovery
restored clean state with no reclamation. Native mcopy verified all three file
payloads before and after recovery, FrankenFS verified them after recovery, and
native `fsck.fat -n` passed on the recovered image. Independently calculated
whole-file hashes proved preservation of every other byte and both neighboring
sentinel regions; all original source, tool, binary and workload hashes stayed
unchanged.

This result uses `8dae5e14b` plus explicit Rust overlays, fingerprint
`d1224d035dd49a9089e6981720f81374c280fef275d98b6493ecc9926ee121be`, Linux CLI
SHA-256 `12af1605e9a1e2f9fbd4f22971a9c87a1820401bbc3d1c72b03670c786641b8b`,
and runner SHA-256
`320d1c1318b6470462698e5e51f19c11f38203cd75185848781335d5a38f5d55`.
Log: `native-fat-fsinfo-8dae-fixed-0339.log` under
`~/Library/Logs/frankenfs-verification/`. Native evidence is retained on CSD in
`/data/ssd/tmp/ffs-native-verification-7CWV8iQw/fat-fsinfo-8dae-native-_qg201_z`.
The first probe incorrectly expected exit zero from the intentionally dirty
checker; its six-command failure is retained in `native-fat-fsinfo-8dae-0342.log`.
The correction requires the CLI's documented exit one and unchanged complete
ownership/four-marker assertions. Only this component ran in this invocation;
the full runner, native 4096-byte-sector operation, kernel-FUSE, crash atomicity,
later streaming changes and field use remain outside this evidence.

A separate operation-output probe also opened the recovered clean image through
the previously qualified public `ffs` consumer (SHA-256 `e862954f...e4ef48`)
and a strict read-only `FatFs` FUSE mount using the CLI above. Its three payloads,
sizes and five root listing names including dot entries matched; public and
mounted writes were refused, mounted full/range reads passed, native fsck passed,
and the mount exited zero and unmounted. The recovered image hash stayed
`6d0c54f9b158a65f5ffa3028b80c1fc9c9c13d3020cce8973e368accc0f9fe33`.
Log: `native-fat-operation-output-consumers-0358.log`; CSD evidence:
`/tmp/fat-operation-consumers-68fgd5vi/result.json`. This separately qualifies
read-only consumption of the actual recovered output with two distinct executable
source cuts; it does not establish facade-mounted routing, writable recovery,
crash atomicity or field use.

Final workspace/all-target check, strict Clippy (`-D warnings`) and full
`cargo fmt --check` passed on `8dae5e14b` plus eight overlays, fingerprint
`7262c1db4f99fdb1f5a8887af02a35b2fa3ea2f290900216853e3d81952f81c5`
(RCH `30074357740995264`, `30074357740995256`, `30074357740995259`). The
production corrections are equivalent boolean/chunk-iterator spellings; the
test corrections preserve the literal value and all assertions while releasing
a fixture mutex before host-file writes. These receipts are distinct from the
earlier native executable's source cut and do not qualify later streaming code.
All eleven tests also reran successfully with the final production corrections
on overlay `a02d60b9` (RCH `30074357740995253`, zero failures or ignores,
20.64 seconds). That runtime predates only the two test-only literal/fixture-guard
edits; the final compiler/Clippy gates above compile those edits.
