# Native ZFS allocation-map inspection

`ffs-zfs allocation` reconstructs committed metaslab allocation for the selected
MOS. It does not allocate, free, repair, import, replay, or change mounted statfs.

```bash
ffs-zfs allocation leaf.img --offline-image --auto-import
ffs-zfs allocation first.img --offline-image --pool-guid 123 --label 0 --slot 2 \
  --member second.img --max-metaslabs 65536 --max-records 16777216 \
  --max-metadata-bytes 536870912 --max-ranges 65536
```

The existing explicit pool/member/partition ownership rules remain in force.
There is no dataset or snapshot argument: pool allocation is shared by all
retained datasets, snapshots and other native owners at the selected MOS TXG.
Sidecars are refused before image open; successful inspection issues no writes
or syncs. An image must remain offline and immutable for the entire operation.

## What is reconstructed

The reader follows MOS object 1's `config` reference to its typed packed nvlist,
then checks its pool/vdev identities and geometry against the admitted label
configuration. Ordinary leaves, complete mirrors, RAIDZ1/2/3, and admitted
striped top-level leaves reuse the existing checked physical block pipeline.
Advanced allocation classes, removed/indirect vdevs, expanded RAIDZ, dRAID and
nonallocating vdev state are not silently interpreted as ordinary allocation.

The native metaslab count is `asize >> metaslab_shift`. Bytes in a partial tail
are reported separately, not counted as a complete free metaslab. Each typed
metaslab-array entry identifies a unique space-map object; zero means a native
never-initialized map. The complete object mapping is checked before following
space-map streams. Sparse array cells are zero; a hole in a nonempty space-map
stream is an error, not an allocation record synthesized from zeroes.

Each stream is read through checksum-verified DMU blocks in that block's byte
order, stopping at `smp_length`, not dnode allocation capacity. One-word and
feature-admitted two-word records are supported; two-word records cannot cross a
block boundary. Native debug padding is distinct from the valid zero-valued
one-unit allocation record. Historical allocation/free operations build a
coalesced interval tree, rejecting overlapping allocations, invalid frees,
arithmetic overflow, foreign log-map vdev IDs and inconsistent allocation
counters. Legacy and histogram-extended headers are supported. Histograms are
retained by the parser but are not treated as allocation authority.

Active `com.delphix:log_spacemap` and `com.delphix:zpool_checkpoint` are refused:
unflushed log maps and checkpoint retention need additional accounting before
base metaslab maps can describe the complete selected state. They are not
ignored or bypassed with a force option.

## Report and bounds

Reports contain per-metaslab and per-vdev allocation/free totals, interval
counts, largest individual free ranges, stream lengths and unmapped tails.
Byte amounts are **top-level DVA/asize bytes**, including RAIDZ parity and
allocation padding, not usable file payload capacity. All uint64 JSON values
are decimal strings. A complete report is constructed before stdout output;
a transport failure may still leave a partial JSON document.

Default limits are 65,536 metaslabs, 16,777,216 records, 512 MiB conservative
metadata work and 65,536 intervals per metaslab. Work includes repeated cached
tree traversals and mirror-label revalidation. The caller's MOS cache is not
modified. Cancellation or any late failure discards private reconstruction;
no partial free-space totals are returned as success.

These work limits apply after the existing candidate and MOS feature admission,
which retains its own bounds. They measure decoded metadata work, not physical
device traffic across redundant-copy retries or decompression CPU instructions.

This is not namespace ownership/leak detection, all-replica scrubbing, quota or
reservation accounting, pool slop calculation, allocator admission, or native
TXG/write support. In particular, reported unallocated bytes are not a promise
that an arbitrary user write can consume that amount.

The format contract is pinned to OpenZFS `zfs-2.3.0` `space_map.h`, `space_map.c`,
`spa.c`, `vdev.c`, `vdev_label.c` and `metaslab.c`. Rust regression fixtures are
constructed graphs, not pools created by OpenZFS. Native interchange and Rust
execution must be verified independently; adding this command grants no parity
completion credit.
