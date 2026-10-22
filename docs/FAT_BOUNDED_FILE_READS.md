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
for metadata I/O on random seeks. No measured latency/speedup or mounted
qualification is claimed for this reader.

The constructed-image regressions exercise both dialects, 512/4096-byte sectors,
fragmented/random/reverse reads, the maximum 32-bit native file length without
materializing a 4 GiB host image, preallocation, corrupt tails, work bounds,
active FATs/reserved bits, partial device errors, cancellation, bounded physical
runs and the public streaming/exact-selector paths. They must be compiled and
executed; authoring them and running a separate model are not Rust execution or
independent native-tool interchange evidence.

## Executed native CLI slice — 2026-10-22

The permanent `Run.streaming_reads` component in `scripts/verify_fat_read.py`
passed on retained native FAT16/FAT32 images and the previously verified expanded
FAT16/recovered FAT32 outputs. Four images, fourteen file instances, both `cat`
and native-slot `extract`, and plain/8192-byte-offset selections produced 56
exact payload comparisons. Sixteen catalog checks preserve native slot ancestry
and volume-relative offsets. Sixteen unknown/wrong-parent selector refusals and
eight private cyclic-tail refusals returned one with empty stdout. The latter
change only the last allocation word in each mirror and preserve reserved bits.
Fourteen native `mcopy` reference reads and eight `fsck.fat -n` checks passed.
All 118 captured commands matched their exact expected status (94 zero, 24 one);
all 15 source/payload/tool/executable hashes stayed unchanged.

RCH build `30074357740995285` returned zero with terminal acknowledgment on
`ea0bc8afd444dae2960713ad2d6c6b1cc49b12be` plus nine overlays, fingerprint
`ed09c13eb2eeab4f156d97c26adb92f6f0845e91c4c0a1505ec55d506a77c8f6`.
The Linux CLI SHA-256 is
`a45f6380c4ce1faefa66082c9586ccf0de9a8eb6c21afc9a02d70e92f7aa1e9a`;
the workload is
`b0645eed2faba3a9782ea64aa1ba22b3763c905ed24f60b7351a05816dd3d840`.
Retained evidence: CSD
`/data/ssd/tmp/ffs-native-verification-7CWV8iQw/fat-stream-ea-native-n3rmvqrt/result.json`,
local log `native-fat-stream-ea-a45f-0445.log` in the verification log directory.
This is CLI execution on retained native-produced images. Native fragmentation,
4096-byte sectors, 4 GiB files, mounted immutable-reader use, crash behavior and
field use remain outside this slice.

The full FAT/facade run on that same `ed09c13e` cut passed 548 tests, with zero
failures and one existing ignored native-tool interchange test (RCH
`30074357740995283`). This includes all ten streaming regressions. Subsequent
test-only lint corrections preserve all ten tests, 55 assertions and six fault
labels: equivalent empty-value comparisons, numeric separators and a redundant
match arm. Production source is unchanged. On final overlay
`7d13873c18805f020d68515fbba8121b96a1213d06c2ac4e756dddd2c17a6ad1`,
the ten streaming regressions reran successfully (`30074357740995310`, zero
failed/ignored, 495 filtered, 39.20 seconds). Workspace/all-target check
(`30074357740995301`), strict Clippy with `-D warnings`
(`30074357740995296`) and full formatting (`30074357740995295`) also returned
zero with terminal acknowledgment. The earlier Clippy failure is retained;
no assertion, fault case or lint was suppressed. The native CLI receipt remains
bound to its earlier executable cut, and the full 548-test suite is not silently
relabelled as a complete runtime rerun after those test-only edits.

Whole-change UBS still returns one: 27 critical reports comprising 23 public
hash comparisons and four test-only no-write/no-sync panic tripwires. Those
checks remain intact pending independent disposition. Compiler/runtime passes
do not grant publication, closure, crash or field qualification.
