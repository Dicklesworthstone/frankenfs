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
Gang-block readability continues through the existing reader, but all-copy
verification of gang headers and fragments is not yet implemented. Encountering
a gang pointer records unsupported coverage and cannot produce a clean enhanced
report. Native allocation/namespace/ACL consistency is a separate obligation.

The images must remain immutable/offline. No member write, sync, healing or
atime update occurs. Sidecars remain refused before image open; this mode also
refuses a ZIL replay overlay rather than auditing a different view silently.

## Evidence

Nine authored Rust tests cover secondary mirror corruption in metadata/data/SA,
a bad second DVA, fresh I/O despite warm caches, independent audit budget,
cancellation in an otherwise unused replica, P/Q/R parity-only damage, recovered
but corrupt actual data, unequal columns, high-bit GF arithmetic, CLI selection,
and pre-I/O sidecar/replay refusal. Synthetic storage panics on writes/flushes.
Existing readability tests and their assertions are retained.

These Rust tests have not been executed in this implementation environment.
RCH and Cargo validation attempts exited 127 because the tools are absent.
Exact baseline-blob checks and Git whitespace checks are source evidence only.
An independent Python polynomial/Horner comparison is mathematical model
validation, not Rust execution, OpenZFS-produced image interchange or kernel
FUSE evidence. Run the unchanged repository gates before relying on this mode:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-zfs redundancy
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-cli --bin ffs-zfs scrub
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
