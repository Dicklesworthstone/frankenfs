# Bounded-memory native FAT file reads

`FatVolume::open_file_reader(cx, entry)` constructs a reusable `FileReader`
for an immutable FAT16/FAT32 file. `ffs-fat cat`, exact-slot `extract`, and the
public `stream_file` helper use this reader. It addresses FAT-02's bounded
chain-cursor and sparse-anchor work without changing native file semantics.
Here "sparse anchors" means a small in-memory index, NOT sparse files on FAT.

Construction validates the COMPLETE allocation chain before any payload read,
including reachable preallocation beyond logical EOF. It shares the existing
chain walker with materialized mutation maps: invalid/free/bad/reserved links,
mirror disagreement, cycles, short coverage, I/O errors, cancellation and the
8,388,608-cluster work limit are not bypassed. It does not replace the global
ownership checker or certify absence of cross-links between different files.

Instead of retaining all cluster IDs, the reader records every 256th cluster
and the total allocation count. The admitted maximum requires 32,768 stored
anchor values (128 KiB of u32 values), rather than 32 MiB of cluster values.
Anchor capacity grows fallibly with a capped reservation request; allocator
metadata and potential allocator over-allocation are not included in those
value-byte counts. `index_storage_bytes()` exposes actual retained Vec capacity.
The two selected-FAT windows are separately bounded to 64 KiB each. Payload
buffers are independently limited by the existing 16 MiB read-request bound;
CLI streaming requests at most 1 MiB at a time.

Random positioning follows at most 255 links from an anchor. Sequential calls
reuse a cursor and FAT windows instead of restarting at the file head. Adjacent
physical clusters still coalesce into transfers of at most 64 KiB, with no data
read beyond the request or logical EOF. Empty and preallocated zero-length files
remain empty; slack/preallocation is counted but never emitted. A late error
fails the entire individual read rather than returning an earlier partial buffer.
The CLI may already have emitted preceding successful chunks, and reports that
later failure instead of claiming atomic stdout output.

## Lifetime and scope

The source and metadata MUST remain unchanged for the complete reader lifetime,
including between calls. The returned object borrows its originating volume and
cannot be rebound to a different device. A Rust shared borrow or advisory lock
is NOT a snapshot and does not make external writers safe. Drop the reader
before native mutation. No backing write, synchronization, dirty-state change,
repair or metadata rewrite is issued by this reader.

Existing `file_chain`/`read` APIs, mutation plans, and the mounted mutable-chain
cache retain their full-map representation. This increment does not give mutable
mounts an immutable index, increase the native file-size limit, or remove the
full validation cost at open. Re-reading FAT links trades bounded retained memory
for metadata I/O on random seeks. No measured latency/speedup or native/mounted
qualification is claimed.

The constructed-image regressions exercise both dialects, 512/4096-byte sectors,
fragmented/random/reverse reads, the maximum 32-bit native file length without
materializing a 4 GiB host image, preallocation, corrupt tails, work bounds,
active FATs/reserved bits, partial device errors, cancellation, bounded physical
runs and the public streaming/exact-selector paths. They must be compiled and
executed; authoring them and running a separate model are not Rust execution or
independent native-tool interchange evidence.
