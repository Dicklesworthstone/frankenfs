# Read-only ZFS physical-copy and parity audit

`ffs-zfs scrub --verify-redundancy` extends the existing selected-dataset DMU
walk with fresh physical-copy verification. Normal `scrub` retains its existing
readability contract: a valid recovered copy is enough. The new mode asks a
different question: are the copies and parity of the walked blocks intact?

```sh
# Identity values below are placeholders. Supply the actual images/candidate.
ffs-zfs scrub first.img --member second.img --offline-image \
  --pool-guid 123 --label 0 --slot 2 --dataset data \
  --verify-redundancy --max-copy-bytes 1073741824

# The same audit can remain anchored to a historical snapshot.
ffs-zfs scrub first.img --member second.img --offline-image \
  --pool-guid 123 --label 0 --slot 2 --dataset data --snapshot before \
  --verify-redundancy
```

## What is verified

After the ordinary native reader admits the complete pointer and topology, the
audit rereads every ordinary DVA on every supplied leaf/mirror replica. Striped
DVAs retain their native top-level member routing. Each replica passes the
original physical checksum and transform decoder independently; neither a warm
cache nor another good replica substitutes for this check.

For RAIDZ1/2/3, every active native column is read, including parity that an
ordinary healthy data read does not need. Actual data columns are assembled
without erasure substitution and verified against their original block pointer.
Only then are native P/Q/R equations checked bytewise. Unequal column lengths
contribute zero beyond their payload; skip-only allocations are not data terms.
The implementation follows the mathematical description in OpenZFS zfs-2.3.0
`module/zfs/vdev_raidz.c`, using GF(256) polynomial 0x11D, with independently
written code. No native source implementation was copied.

A mismatch does **not** identify a guilty disk: unchecksummed sector padding can
also disagree with parity. If actual data is unreadable or fails verification,
parity is reported as unverified, not falsely convicted using bad data and not
certified from a separately reconstructed logical read.

The normal verified reader still supplies traversal bytes, so readable metadata
can continue the walk while the audit records a damaged secondary copy. The
audit never replaces traversal data or inserts unverified bytes into caches.
Its coverage includes ordinary indirect blocks, dnode tables, data and admitted
SA spills reachable from this selected meta-dnode.

## Gang headers and fragmented blocks

Gang pointers now use the same complete native graph admission as ordinary
reads before their physical-copy audit starts. Every nested header and ordinary
fragment is included; this is not a second gang parser. Existing depth, node,
overlap, physical-byte, aggregate-allocation and topology checks remain in force.
The admitted header graph is retained rather than rediscovered through each
replica. No fragment-copy audit starts until the complete graph is admitted.

Header copies are read as 512-byte native headers, not as the leader's PSIZE
and not as the aggregate DVA ASIZE. Each uses the original DVA-zero and physical
birth verifier, even when it is read from a later DVA. Each independently valid
header must describe exactly the admitted child pointers; a divergent but
self-checksummed header is an error and its alternative graph is never followed.
Fragment copies retain their own physical checksums. Leader decompression and
the complete leader checksum still belong to the ordinary verified read path.

RAIDZ header stripes use the native header map and embedded checksum before
checking their P/Q/R equations. Actual corrupt or missing data is not replaced
with reconstructed bytes for the parity audit. Recovered readability therefore
does not certify the damaged header, fragment or parity column. Leaf/mirror and
striped routes retain their admitted member mapping and per-DVA header sizes.

The whole gang audit reserves a conservative work allowance before even its
extra manifest reads: eight times aggregate native allocation for leaf/mirror
or stripe paths, and 256 times for RAIDZ. Mirror multiplicity and every declared
DVA are included. The larger RAIDZ allowance covers padded-header recovery and
all-copy parity work. These are deliberately conservative byte-work charges,
not measured I/O, elapsed time, or a claim that all charged work was performed.
Small explicit budgets can refuse a readable gang tree before any extra audit
read. Native limits still cap each tree at 256 MiB aggregate allocation,
65,536 nodes and 32 header levels.

Per-logical-pointer diagnostics are capped at 128 retained defects plus an
explicit unsupported-coverage marker. On saturation, the remaining gang nodes
are not audited and the result cannot be clean. Cancellation remains terminal,
including cancellation after the diagnostic ledger fills.

## Bounds, missing members, and results

`--max-copy-bytes` is a separate conservative work cap over audit reads, assembly,
decode and parity arithmetic. It defaults to one TiB and requires
`--verify-redundancy` when explicitly supplied. Existing pointer, decoded-byte
and object budgets remain independent. The full audit cost of a pointer is
reserved before its first audit I/O; exhaustion stops with a non-clean report.
Ordinary traversal/bootstrap reads are covered by their existing contracts, not
this extra audit-work counter.

The report includes `redundancy_requested`, `copy_work_bytes`, `copies_examined`,
`raidz_columns_examined`, `parity_columns_checked`, `parity_columns_unverified`
and `missing_native_members`. These are pointer-reference counts, not deduplicated
whole-device coverage. Defects retain object/block/level context and bounded
copy/column diagnostics in the existing issue ledger. Cancellation is terminal:
there is no successful partial report and no retry of cancellation as damage.

An explicitly absent mirror or RAIDZ member prevents a clean redundancy result,
even if the selected data is readable. No absent device is fabricated, read,
repaired or written. A non-clean report makes the CLI fail after printing JSON.
`selected_dmu_redundancy_verified` is true only for a completed clean audit in
this mode. The legacy pool-wide `all_replicas_checked` remains false.

## Boundaries

This is not a pool-wide native scrub or a repair/resilver operation. Labels,
uberblock rings, enclosing object-set roots, other datasets/snapshots, ZIL,
space maps and references embedded in bonus data are not covered by this walk.
Gang headers and fragments reachable from a walked pointer are covered by the
bounded protocol above. Native allocation/namespace/ACL consistency is still a
separate obligation; this increment adds no pool writer or repair authority.

The images must remain immutable/offline. No member write, sync, healing or
atime update occurs. Sidecars remain refused before image open; this mode also
refuses a ZIL replay overlay rather than auditing a different view silently.

## Evidence

Eleven authored Rust tests cover secondary mirror corruption in metadata/data/SA,
a bad second DVA, fresh I/O despite warm caches, independent audit budget,
cancellation in an otherwise unused replica, P/Q/R parity-only damage, recovered
but corrupt actual data, unequal columns, high-bit GF arithmetic, CLI selection,
and pre-I/O sidecar/replay refusal. Missing-mirror and missing-RAIDZ controls
also exercise native label admission with direct constructed Objects views:
readability can succeed while the redundancy result remains non-clean, without
any read from an absent member. These are not full uberblock-import tests.
Synthetic storage panics on writes/flushes.
Existing readability tests and their assertions are retained.

Seven additional authored gang controls exercise native DMU reads and scrub,
both byte orders, 512/4096/65536-byte sectors, secondary header/fragment damage,
nested trees, extra header DVAs, valid-but-divergent header refusal, complete
pre-I/O work reservation, cancellation, manifest failure, bounded diagnostics,
and actual-data/parity corruption on RAIDZ1/2/3. Their backing devices panic on
write and sync. These tests have NOT run in this implementation environment;
no Rust, mounted, native OpenZFS or power-failure qualification is inferred.

These Rust tests have not been executed in this implementation environment.
RCH and Cargo validation attempts exited 127 because the tools are absent.
Exact baseline-blob checks and Git whitespace checks are source evidence only.
An independent Python polynomial/Horner comparison is mathematical model
validation, not Rust execution, OpenZFS-produced image interchange or kernel
FUSE evidence. Run the unchanged repository gates before relying on this mode:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-zfs redundancy
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-zfs scrub
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-zfs gang
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
