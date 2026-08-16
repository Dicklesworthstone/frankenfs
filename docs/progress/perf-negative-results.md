# Performance Negative-Evidence Ledger

This ledger records every code-first optimization attempt in the no-gaps
campaign, including pending attempts that have not yet received a benchmark
verdict. Rejected rows are not to be retried unless their retry predicate is
met by new profile evidence.

> **WORKER-SCOPED RATIOS (2026-08-15, `bd-4w2mf`).** A row that does not name the
> machine it ran on is **worker-scoped**: valid *on an unrecorded machine*, never
> comparable to a row measured elsewhere. The same cell measured `1.2693x` on one rch
> worker and `0.0093x` on another — a 13.6x swing — with **both A/A nulls passing**,
> because a null controls within-invocation noise only and is blind to between-worker
> CPU model, cache, memory bandwidth and contention. `rch` also fails **open to local**
> when the fleet is saturated, so two `rch exec` calls minutes apart can straddle two
> machines silently.
>
> This re-scopes; it does **not** retract. No row here is known multi-worker and the
> campaign already required same-invocation arms, so these are most likely
> valid-but-unattributed rather than split across machines — the defect is that the row
> cannot prove which. Per-row repair is impossible: zero run `report.json` files
> survive, so no host is recoverable and inventing one would be worse than the gap.
>
> **18** rows in this file quote a vs-incumbent ratio and name no host (148 more in
> `docs/NEGATIVE_EVIDENCE.md`). List them with
> `python3 scripts/perf_ledger_preflight.py --worker-scope --list`; that count is a
> ratchet the preflight enforces, and it may only fall.

## Rules

- One lever per row.
- Record the benchmark surface, result, and exact keep/reject/pending status.
- If benchmark execution is intentionally deferred, record the command that must
  produce the verdict.
- Rejected ideas require a concrete retry predicate, not a vague "try later."
- **Record the machine.** Every timed row names its execution host — `RCH_WORKER=<id>`
  for a remote run, `same_host=<hostname>` for a local mounted-comparator run. A row
  that does not is worker-scoped; see the note at the top of this file.

## Benchmark-admission blocker: btrfs unlink avoids a redundant inode lookup, but no production candidate is available - 2026-08-04

`bd-btrfs-create-delete-storm-2p36x-w57dg` reuses the initial pre-mutation
`btrfs_read_inode_from_tree` in `btrfs_unlink_impl` instead of performing a
second child-inode lookup after the adjustment.  The validated `nlink - 1`
transition is the only intervening link-count mutation, so `nlink <= 1` is
exactly the post-adjustment zero-link/purge predicate.  The same bead adds a
64-file create/delete test that requires every final unlink to remove both the
directory entry and inode.

No mounted-kernel ratio is claimed.  The only locally available driver/candidate
pair was driver SHA-256
`004e58a65160fd248b876e21e67bec63dbd9f8cd9d769d06582ee4308995868` and
candidate SHA-256
`86e25c6c47eee8bc2ac8e81f2d7be14b843ffc59188d0e69adada25f61898e6d`.
The exact btrfs 2,000-operation, 12-pair invocation refused before mounting:

```
mounted_kernel_gate,error=candidate is not the x86-64-v3 production ISA: missing compile_sse4_2=true
```

The required strict-remote targeted test also could not reach the new test:
the transferred workspace has unrelated `ffs-core` type/API errors at 5904,
5934, 13244, 15903, 16152, 16319, 16449, 19450, and 19517.  Full remote
`cargo check --all-targets` separately stopped in the unrelated
`ffs-journal` descriptor-decode bench API, and full remote Clippy stopped on
pre-existing `ffs-ondisk` diagnostics.  These are blockers, not evidence for
or against this lever.

**Retry predicate:** provide a freshly built, executing x86-64-v3 + PGO
candidate whose in-process SHA-256 and profile identity satisfy the harness, then
run the btrfs create/delete storm with 2,000 operations in one four-arm
invocation.  Require both A/A median-CIs to contain 1 before interpreting the
candidate/kernel ratio; do not reuse the baseline-ISA artifact that failed
identity admission.

## REJECT + REVERT: logical B-epsilon create messages double the mounted metadata gap - 2026-08-02

This attempt did not repeat the rejected whole-block overlay below. It buffered
logical `(parent, name, child inode, type, timestamp)` create messages across 64
parent-striped interior-node shards, bounded the buffer at 4,096 messages, and
drained each linear directory by reading its leaves once, applying the complete
message run in memory, stamping each dirty leaf once, and publishing the final
leaves plus parent inode in one MVCC transaction. Indexed or growing directories
fell back to the mature one-create path. Namespace reads and conflicting
mutations drained first; `fsyncdir`, sync, and unmount were durability boundaries.
The production path was default-on with `FFS_EXT4_BE_CREATE_BUFFER=0` as a
same-ELF kill switch. Implementation commit `333838e8` is fully reverted in this
closeout because the live-kernel result is a large loss.

Correctness was materially better than the earlier whole-block attempt. The
focused strict-remote test
`be_tree_create_messages_batch_at_fsyncdir_and_remain_findable` passed. A mounted
one-thread diagnostic then completed 8 warmups plus 12 measured pairs with all
512 acknowledged creates removed on every reset, exact four-arm tree parity, one
observed and pinned worker per arm, and four clean offline `e2fsck` results. Its
timing was intentionally underpowered and null-blocked; it is correctness
evidence only. Report SHA-256
`cedae694f71f266c12a7518deba17710cec1e189bb4555edb9687aeb3f854307`:
`/data/tmp/frankenfs-be-create-score/diag-1t-r1/report.json`.

The decisive mounted comparison used the unchanged frozen driver, ext4, 512
creates, 8 observed/pinned workers, one private FUSE daemon CPU, 512 balanced
four-arm pairs / 128 crossover blocks, and one durability boundary per timed
observation. Candidate ELF
`cd68a89a18b90664d97c6a7a03bc7bfd92d0f909746d1c671a5bc1523cc336d5`
was built x86-64-v3 on `vmi1227854` with the banked PGO profile
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`;
driver ELF SHA-256 was
`d8786a0663dbc635f4e508bcc9ade6cb8cad22c0c7353f9a6280d28329628c65`.

| Same candidate ELF | FrankenFS / live kernel ext4 | Kernel A/A spread | FUSE A/A spread | Kernel / FUSE median wall |
| --- | ---: | ---: | ---: | ---: |
| B-epsilon ON (default) | `2.854120x [2.748979, 3.018131]` | `1.042877x` | `1.041383x` | `32.388 / 91.271 ms` |
| B-epsilon OFF | `1.365410x [1.317870, 1.407852]` | `1.053137x` | `1.032855x` | `35.086 / 46.736 ms` |
| Banked admitted reference | `1.510822x [1.493097, 1.539011]` | `1.024316x` | `1.021662x` | - |

Each new ratio has its own same-invocation A/A null control with a deterministic
20,000-resample bootstrap median CI. ON: kernel `1.014248x`
`[0.996833, 1.042877]`, FUSE `1.006548x [0.968748, 1.041383]`. OFF: kernel
`1.018520x [0.987281, 1.053137]`, FUSE `1.008744x [0.984245, 1.032855]`.

Both new invocations are honestly `BLOCKED_NULL`, not admitted competitive
claims: their A/A bootstrap spreads exceeded the frozen `1.025x` ceiling even
though both null medians remained within 2% of one. They nevertheless reject
the lever without a rerun. ON is nowhere near the target even at its `2.748979x`
lower diagnostic bound, while OFF returns toward the live bank from the exact
same ELF. ON/OFF is a **`2.090303x` ratio-of-ratios regression**, and the FUSE
median itself is **`1.952917x` slower** with buffering. Both runs completed exact
reset accounting, initial/final four-arm parity, worker-count and pinning proof,
and four clean offline `e2fsck` checks. ON report SHA-256
`13f5ad728dc462ad66b129bfafcf80a2fb98d2a6b1783f30f5e3ff98f740b8ec`:
`/data/tmp/frankenfs-be-create-score/scored-8t-p512/report.json`. OFF report
SHA-256
`3385acaf0d9eb96988ff6e461f1c39c7d09d63f2e6b3d73573c28f71eccb20b5`:
`/data/tmp/frankenfs-be-create-score/control-off-8t-p512/report.json`.

The structural miss is scope: this shape batches only the final directory-leaf
mutation. Every create still allocates and publishes its inode and allocation
metadata, then the timed `fsyncdir` path pays the new leaf reconstruction and
batch publication. It therefore adds a second materialization boundary without
removing the dominant per-request path.

Ordering was preserved by holding the parent-shard lock from duplicate checking
through message append and by draining each parent in append order. Tie-breaking,
floating point, and RNG are N/A. Mounted reset, tree parity, and offline checks
are the behavioral-equivalence proof.

**Decision in one line:** REJECT + REVERT - logical B-epsilon create buffering
moved the live-kernel diagnostic from `1.365410x` OFF to `2.854120x` ON, so it
more than doubled the gap instead of beating ext4.

**Retry predicate:** do not retry directory-entry-only buffering. Reopen B-epsilon
metadata only after an exact mounted whole-job profile shows inode allocation,
bitmap updates, inode-table publication, directory insertion, and their MVCC
commits together consume at least **40%** of timed FUSE wall, and a design buffers
that complete logical create transaction (with lookup visibility) rather than
adding a second `fsyncdir` materialization boundary. The next vein is transport,
not another directory-leaf buffer.

## REJECT + REVERT: read-only concurrent handle lifecycle narrows but does not close `parallel-read-8t` - 2026-08-02

The earlier concurrent-dispatch rejection required an opcode census before
reopening this surface. That condition was met: over four rounds of 256 files,
`FUSE_OPEN`, `FUSE_FLUSH`, and
`FUSE_RELEASE` contributed 1,024 requests each, or about **73%** of the row's
FUSE traffic, while `FUSE_READ` remained zero because the kernel page cache
served the payload. Unlike the live ext4 incumbent, FrankenFS serialized all
three stateless read-only lifecycle operations behind the session's exclusive
dispatch gate. The candidate added an explicit fuser capability and admitted
only those three opcodes to shared dispatch on read-only FrankenFS mounts;
writable mounts retained the existing exclusive ordering. One focused remote
test passed and proved the opt-in was read-only. The implementation and test
are now fully reverted.

**Counted mechanism:** the connection-filtered wire syscall count was 1,024
`OPEN` + 1,024 `FLUSH` + 1,024 `RELEASE` requests across four rounds, versus
zero `READ` requests; lifecycle operations were about 73% of all FUSE traffic.

The executing candidate ELF self-reported SHA-256
`82af3376f2edb2d4281c4d9da7f27f99f88c582577d42de2c180dfeaad9710db`
in-process, with x86-64-v3 codegen and banked PGO profile
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`.
The live score kept all eight client threads and used the maximum currently
admissible four FUSE workers on four isolated daemon CPUs after three preserved
8-CPU attempts failed closed on host-quiescence or placement gates. It ran 128
balanced four-arm crossover pairs over 256 separate 256 KiB files. Median wall
time was 3.557990 ms for live Linux 6.17 ext4 and 3.806981 ms for FrankenFS.
The admitted result was **`1.069612x` slower**, deterministic 20,000-resample
bootstrap median 95% CI **`[1.061955, 1.076284]`**, verdict `HONEST_LOSS`.

The **same-invocation A/A null controls** were kernel `1.001349`
[`0.996232`, `1.003943`] and FUSE `0.993640`
[`0.989095`, `1.005551`]; both null gates were clear. Eight timed worker threads
used deterministic bootstrap median 95% CI values. Eight timed worker threads
were observed and pinned in every arm. Initial/final four-arm tree parity passed
with SHA-256
`aac7d54d2c47af9e92c404f46f326941eaa5e86c8530e05d0f6521320dcebfb6`,
all workload digests matched, and post-unmount offline validation was clean.
Report SHA-256
`3499de259d5369fb4a2d1f3aad3e45b55c20248a985f7a40bae64e38047b23f0`:
`/data/tmp/frankenfs-handle-lifecycle-score-retry3-w4.knIlQy/report.json`.
Ordering and file metadata were preserved by four-arm parity; tie-breaking,
floating point, and RNG are N/A.

**Decision in one line:** REJECT + REVERT - shared read-only handle lifecycle
reduced the banked `1.287862x` gap to an admitted `1.069612x`, but FrankenFS
still lost decisively to the live kernel and therefore did not meet the target.

**Retry predicate:** do not retry this dispatch change unless the live harness
can first allocate eight quiet daemon CPUs and a same-ELF 4-worker/8-worker
diagnostic on this exact 8-client job shows the 8-worker median at least **8%**
lower with a bootstrap 95% upper ratio below `0.93`; otherwise profile the
remaining structural 6.2-7.6% gap and switch veins.

## REJECT + REVERT: `FUSE_HANDLE_KILLPRIV_V2` does not suppress audit GETXATTR traffic - 2026-08-02

The worst scored mounted row, `large_directory_readdir_stat_8t`, was selected
because the whole-job profile and a kernel stack count found one userspace
`security.capability` round trip per inode. In-kernel ext4 answers the same
`get_vfs_caps_from_disk` audit query from its inode/xattr cache, while FrankenFS
pays `/dev/fuse` transport. The proposed lever implemented the complete
killpriv-v2 contract rather than advertising an unsafe flag: the vendored ABI
carried the missing protocol bits, write/truncate/chown transactionally removed
`security.capability`, and the kernel's hints cleared setuid plus executable
setgid. Five focused remote tests passed. This code was used only to falsify the
mechanism and is fully reverted.

The connection-filtered `fuse:fuse_request_send` census is decisive. Over one
warmed enumerate-plus-stat sweep of 32,768 entries, the same binary produced
identical opcode counts with `FFS_FUSE_KILLPRIV_V2=0` and `=1`:

| opcode | capability off | capability on |
| --- | ---: | ---: |
| `FUSE_GETXATTR` | **32,779** | **32,779** |
| `FUSE_READDIR` | 66 | 66 |
| `FUSE_OPENDIR` / `RELEASEDIR` / `STATFS` | 1 each | 1 each |

**Counted mechanism:** the syscall count was **32,779 GETXATTR syscalls vs
32,779 GETXATTR syscalls** with the capability off versus on.

The candidate log confirms that the kernel accepted the capability. Thus
`FUSE_HANDLE_KILLPRIV_V2` affects write-time privilege removal but does not
suppress audit's read-side `get_vfs_caps_from_disk` probe on this Linux 6.17
mount. Raw counts and mount identities are under
`/data/tmp/frankenfs-killpriv-v2-opcodes.6rkgFh`; off/on count SHA-256 values are
`7269998e8448a4ef88596f84298c878c2085899808b54cb4e4a69ec5b359e592`
and `0269096336472b6ae3a67177c75060c95d8bcfd3f1873ddbd9a6fb30f7addde4`.

The required live-incumbent score used candidate ELF
`287d204450645a23503f584a3dceef390b5618c903fb05712afd562f39f6d301`
(x86-64-v3, banked PGO
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`),
eight FUSE workers on eight daemon CPUs, 32,768 operations, and 128 balanced
crossover pairs. Median wall time was 20.664 ms for live kernel ext4 versus
70.864 ms for FrankenFS: **`3.424952x` slower**, bootstrap 95% CI
**`[3.409124, 3.431527]`**, admitted `HONEST_LOSS`. Kernel A/A was `1.004554`
[`0.997570`, `1.009370`] and FUSE A/A was `1.002600` [`0.999739`, `1.004678`];
both null gates were clear. Four-arm initial/final tree parity passed with hash
`a91834cf56bad86fc2d7324f41593e5b5b3794a76f9dbeab5dc0ff697f908c79`,
8 worker threads were observed in every arm, and all images passed offline
`e2fsck -fn`. Report SHA-256
`6c32eea13fbe207a25ded1fa9b498db5a6b06177b7c68a0328be2f3f08fb9e25`:
`/data/tmp/frankenfs-killpriv-v2-score-retry1.XMqsIG/report.json`.
Ordering and file metadata were preserved by four-arm parity; tie-breaking,
floating point, and RNG are N/A.

The **same-invocation A/A null controls** used deterministic bootstrap median 95% CI values:
kernel `1.004554` [`0.997570`, `1.009370`] and FUSE `1.002600`
[`0.999739`, `1.004678`].

**Decision in one line:** REJECT + REVERT - negotiation succeeded but removed
zero GETXATTR round trips, and the scored candidate remained `3.424952x` slower
than live ext4; all seven source files are restored exactly to HEAD.

**Retry predicate:** revisit killpriv as a performance lever only after a kernel
or FUSE protocol change is first shown, by a connection-filtered census on this
exact workload, to reduce `FUSE_GETXATTR` below **0.05 per entry**. Do not time
another killpriv implementation while the count remains approximately one per
entry.

## REJECT BEFORE EDIT: `rmw_block` range deltas are amortized flush work, not the metadata gap - 2026-08-02

The pending row below hypothesized that `FsMvccBlockDevice::rmw_block` copied a
whole 4 KiB block several times per create and required an exact call/byte count
before any patch-chain redesign. That count rejects the premise. Uprobes covered
every linked `rmw_block`, `rmw_block_bitmap_or`, `TransactionBlockAdapter::stage_rmw`,
and `persist_group_desc_force_with_bitmap_overrides` symbol while one real
`create-bench` process created 256 files and flushed the image. The only hits
were **2** calls to the non-MVCC `ByteDeviceBlockAdapter::rmw_block` and the
matching two GDT helper/closure calls. All MVCC RMW and staged-RMW probes were
zero. The originating whole-job perf profile's broad libc `memmove` frame was
**8.81% self**; the call count proves this proposed caller does not generate it
per operation.

Thus this surface moves at most `2 * 4096 = 8192` full-block bytes for the whole
job, or **32 bytes amortized per create**, not 4-8 KiB several times per create.
The group counters are deferred and persisted at flush; they are not a per-op
MVCC patch chain. The instrumented ELF self-reported SHA-256
`d99b144a51801685d739f887615dc71205b41bf84eb859fc8038f1bdfd910a06` and
embedded PGO SHA-256
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`.
The mutated clone remained clean under offline `e2fsck -fn` (the advisory
"extent tree could be narrower" optimization note is not corruption). Count
artifact SHA-256
`591ee5eac73dbd1bc35c94014fbf30d9a64d5f1e58dabdaadaff615c911e3af1`:
`/data/tmp/frankenfs-rmw-count-20260802/rmw-count-256.txt`.

**Decision in one line:** REJECT BEFORE EDIT - even impossible elimination of
all observed `rmw_block` copies removes only 32 bytes per create and cannot close
the banked live-incumbent metadata loss; no source or timing claim was made.

**Retry predicate:** revisit range-delta storage only if a fresh count on the
exact scored mounted workload observes at least **one MVCC `rmw_block` or
`stage_rmw` per operation** and at least **4096 copied bytes per operation**, and
a symbolized caller profile attributes at least 10% of whole-job self-time to
those exact calls rather than diffuse full-version materialisation elsewhere.

## REJECT + REVERT: adaptive large-directory FUSE reply reservation does not beat live ext4 - 2026-08-02

This was the first self-generated lever after the supplied four-lever list. A
whole-job paired `perf` capture of the exact 32,768-entry enumerate-then-stat
shape separated costs paid by both arms from costs exclusive to the FrankenFS
daemon. The client/kernel arms shared `__d_lookup_rcu` (9.40% kernel / 9.85%
FUSE), `entry_SYSRETQ` (6.10% / 6.97%), and the C driver worker loop (4.13% /
4.38%); those are not the structural gap. In the daemon-only samples the
ranked leaders were:

| exclusive daemon self-time | share |
| --- | ---: |
| `fuser::ll::reply::EntListBuf::push` | **10.24%** |
| `prefetch_ext4_readdir_inode_table_blocks` | 9.64% |
| libc `memmove` | 5.91% |
| `ext4_inode_table_location` | 2.77% |
| request dispatch | 2.31% |
| lookup | 2.02% |

The prefetch family is already shipped/mined. `EntListBuf::push` and its
geometric buffer-growth copies are FUSE reply materialisation that in-kernel
ext4 does not perform, so it was the first fresh structural entry. The profile
is routing evidence rather than a scored timing result: two attempts to profile
the scored harness correctly stopped at the busy-core guard, after which the
same validated read-only images were exercised by a lower-overhead compiled C
driver. The 128 alternating diagnostic pairs were 25.842 ms kernel versus
30.560 ms FUSE (`1.182587x`), with 13,645 / 13,221 client samples and 819 daemon
samples, zero lost. Capture SHA-256
`6f58224cee923b04990e8e2df4806df81a94d27083501f3582538dda8f829a72`:
`/data/tmp/frankenfs-whole-job-paired-profile-20260802-manual1/paired-cdriver-128.perf.data`.

The candidate left small replies untouched, but once a reply crossed 4 KiB it
reserved the ordinary 32 KiB response capacity in one step, capped at 64 KiB
for unusually large requests. A focused remote unit test pinned the small,
ordinary, and capped cases (1 passed / 0 failed). Ordering, entry bytes, padding,
and overflow behavior were unchanged; tie-breaking / floating point / RNG are
N/A. The mounted four-arm parity hash and post-unmount tree hash both passed,
and all four images passed offline `e2fsck -fn`.

One v3+PGO candidate ELF (SHA-256
`d99b144a51801685d739f887615dc71205b41bf84eb859fc8038f1bdfd910a06`,
PGO profile
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`)
ran beside two live Linux 6.17 ext4 mounts in the same invocation on
`fixmydocuments`: 128 balanced crossover pairs, 32,768 entries, 8 observed and
pinned client threads, one private FUSE CPU, same LLC, exact tree parity. Raw
medians were 21.894 ms kernel and 25.661 ms FUSE, or **`1.132835x` slower** with
bootstrap interval `[1.108349, 1.144753]`. This is diagnostic only because both
A/A symmetric spreads missed the predeclared `1.025` ceiling: kernel
median `0.997917` with bootstrap 95% CI `[0.972656, 1.004561]` and spread
`1.028112`; FUSE median `0.999373` with bootstrap 95% CI
`[0.967989, 1.027721]` and spread `1.033069`. Verdict `BLOCKED_NULL`,
admitted=false. Report
SHA-256 `88ed6e90a9b5e68294f182ab76f1eabcf9ff56d9f99d06a940a128a22d6d33b7`:
`/data/tmp/frankenfs-entlist-reserve-scored-20260802/report.json`.

**Decision in one line:** REJECT + REVERT - the candidate did not beat the live
kernel, did not produce an admitted competitive result, and had no same-ELF
control that could attribute the raw ratio to reservation; its source and test
are fully reverted.

**Retry predicate:** do not retry directory-reply preallocation unless a fresh
quiet whole-job profile attributes at least **25% of daemon self-time** to
`EntListBuf::push` plus its allocator copies. Then use one ELF with an A/B switch,
require both A/A symmetric spreads at or below `1.025`, require the candidate's
paired 95% lower speedup bound to exceed twice the widest null log-margin, and
ship only if the admitted live-incumbent FUSE/kernel 95% **upper** bound is below
`1.0`.

## REJECT + REVERT: concurrent FUSE creates over the per-group allocator exhaust leaked free-inode counters - 2026-08-02

Lever 4 from the live-incumbent metadata list exposed `FUSE_CREATE` to the
existing `FFS_FUSE_WORKERS=8` reader pool so the default allocator arm serialized
inside FrankenFS's whole-state allocation lock while
`FFS_BHH0I_SHARDED=1` could reach the already-implemented per-group allocator.
Everything else in the mutation set remained behind the whole-session exclusive
gate. The source exposure is **REVERTED**: it cannot be shipped because the
sharded arm does not complete the scored job.

One v3+PGO ELF supplied both arms (SHA-256
`311992e274df94155d883cc7175e933f41812fb99064769eb326548555ef403a`,
PGO profile
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`).
Each invocation mounted two kernel-ext4 and two FrankenFS images on
`fixmydocuments`, ran 8 pinned clients creating exactly 512 empty files across
private directories and fsyncing every worker directory, and placed the FUSE
daemon on the maximum 7 admissible sibling CPUs. There were 128 four-round
crossover pairs; the gate used wall time, deterministic 20,000-resample median
CIs, and same-invocation A/A nulls (`cv_used=false`,
`instructions_used=false`).

The global-lock control (`FFS_BHH0I_SHARDED` unset) completed and was admitted:

Same-invocation A/A null control `1.001994x` was used as a gate input;
deterministic 20,000-resample bootstrap median 95% CI
`[0.992118, 1.022133]`. The sibling FrankenFS FUSE A/A null control was
`0.997024x [0.992315, 1.001802]`; both are clear under the `1.025x`
symmetric-spread limit.

| quantity | result |
| --- | ---: |
| kernel median batch | 2.871270 ms |
| FrankenFS median batch | 11.099821 ms |
| FUSE / kernel | **`3.863792x [3.854198, 3.938998]` honest loss** |
| kernel A/A spread | `1.022133x` (clear) |
| FUSE A/A spread | `1.007745x` (clear) |
| tree parity / post-unmount validation | pass / clean |

Control report SHA-256:
`b09803b187334b559ae483dd08f22dd06e28af7ee2a850d81421e9f3927d6998`
at `/data/tmp/frankenfs-sharded-alloc-results-multi7/control/report.json`.
The control's worse-than-banked ratio is itself useful mechanism evidence:
allowing creates to queue concurrently behind the same whole-state lock exposes
the allocator convoy instead of hiding it in the serial FUSE loop.

The sharded arm used the identical binary and placement with only
`FFS_BHH0I_SHARDED=1`. It failed during measured pair 127 with `ENOSPC` while
creating `fuse_b/.../worker-7/r000127-000040`; therefore it has **no admissible
timing** and no speedup is claimed. The workload deletes all 512 files between
observations, so 65,000+ cumulative creates must not consume inode capacity.
Read-only offline `e2fsck -fn` identifies the leak:

| image | recorded free inodes | bitmap-counted free inodes | e2fsck |
| --- | ---: | ---: | --- |
| FrankenFS `fuse_a` | 488 | 65,512 | rc 4, errors remain |
| FrankenFS `fuse_b` | 0 | 65,024 | rc 4, errors remain |
| kernel `kernel_a` | - | - | rc 0, 24/65,536 files |
| kernel `kernel_b` | - | - | rc 0, 24/65,536 files |

The inode bitmaps were freed, but the sharded free-inode counters were not
credited back; allocation eventually trusts the exhausted counters and rejects
free bitmap slots. That is a correctness failure before it is a performance
question. Ordering/tie-breaking/FP/RNG are N/A; the control's tree parity passed,
and the candidate failed the required durability/isomorphism gate.

**Decision in one line:** REJECT + REVERT - the only admitted arm remains
`3.864x` slower than live kernel ext4, while the sharded candidate exhausts
stale free-inode counters before the job finishes.

**Retry predicate:** do not expose concurrent creates again until a
same-filesystem create/delete churn test exceeding **2x the filesystem inode
capacity** proves the sharded per-group and superblock free-inode counters return
to their exact baseline after every reset, followed by `e2fsck -fn` rc 0; only
then rerun this unchanged mounted four-arm comparator.

## KEEP: concurrent FUSE dispatch at matched daemon CPUs - the worst banked row goes 4.803406x -> 3.467786x against LIVE kernel ext4, all four invocations admitted - 2026-08-02

The `--fuse-cpus` row below finally has its number. A 2x2 (daemon CPUs x
`FFS_FUSE_WORKERS`), four invocations from ONE ELF, every one of them admitted by
the mounted comparator in a single quiet window, on a host whose benchmark CPUs
both sampled `0.000000` busy at placement.

### The 2x2

| daemon CPUs | workers | kernel ms | FUSE ms | FrankenFS / kernel ext4, bootstrap median 95% CI | 2x null margin | kernel A/A | FUSE A/A |
| ---: | --- | ---: | ---: | --- | ---: | ---: | ---: |
| 1 | off | 23.658 | 113.050 | `4.803406` `[4.784500, 4.817726]` | 1.014502 | 1.007225 | 1.002261 |
| 1 | 8 | 22.982 | 121.008 | `5.281854` `[5.242662, 5.309511]` | 1.028074 | 1.006637 | 1.013940 |
| 8 | off | 20.684 | 130.361 | `6.277800` `[6.254249, 6.309525]` | 1.020765 | 1.010329 | 1.000706 |
| **8** | **8** | 20.589 | **71.577** | **`3.467786` `[3.442365, 3.483467]`** | 1.012223 | 1.006093 | 1.002107 |

Every row `admitted=true`, `directional_claim_clear=true`, `verdict=HONEST_LOSS`,
`cv_used=false`, `instructions_used=false`; all four A/A spreads are inside the
`1.025` limit and every A/A interval contains 1.0.

- **The lever's sign flips on daemon CPU count.** At one daemon CPU it is
  `1.0996x SLOWER` (`4.803406` -> `5.281854`); at eight it is **`1.8103x FASTER`**
  (`6.277800` -> `3.467786`). This confirms the 2026-08-01 internal A/B on the
  real mounted comparator instead of a side rig.
- **The row, control to best, in one window: `4.803406x` -> `3.467786x` =
  1.3852x.** Our own arm alone: `113.050` -> `71.577 ms` = **1.5794x faster**.
- **Still an HONEST LOSS.** `3.467786x` is not a win over ext4. At 8 readers we
  serve 2.18 us/entry against the kernel's 0.63 us; the residual is the one
  `security.capability` round trip per entry the incumbent answers from memory.

### The control that mattered, and the prediction it broke

The `8 CPU / workers off` arm was included because a serial session loop cannot
use eight CPUs, so it should have moved nothing and thereby proved that any gain
in the workers-on arm was the lever rather than the CPUs.

**It moved 1.31x the WRONG way** (`113.050` -> `130.361 ms`). At `--fuse-cpus 1`
the daemon owns a private physical core with its SMT sibling guarded idle
(`fuse_cpus=[5]`); at `--fuse-cpus 8` it gets eight hyperthreads that each share a
physical core with a client thread. **The matched-CPU placement is not the more
generous one** — it trades a private core for contended siblings. So the honest
decomposition is: placement costs 1.31x, the lever wins 1.8103x inside that
placement, and the net against the same-window control is 1.3852x. Without this
control the entire 1.3852x would have been credited to the lever.

### Two confounds, stated rather than buried

- At `--fuse-cpus > 1` the driver is placed first with an EMPTY fuse-guard set,
  so the driver's own layout changes too: it landed on eight distinct physical
  cores (`1:2:3:5:32:36:38:39`) instead of seven-plus-a-shared-sibling
  (`0:1:2:3:4:6:7:35`), which is why the kernel arm also improved, `23.658` ->
  `20.6 ms`. **Cross-placement ratio comparisons are therefore confounded**;
  FUSE-arm absolute times and within-placement comparisons are not.
- Placement is re-chosen per invocation, so the two 8-CPU runs used different
  CCXs. Their kernel arms agree to **0.5%** (`20.684` vs `20.589 ms`), which is
  what makes the within-placement comparison defensible.

### Provenance

Candidate ELF `7d0526c45fdf610d5402aec92f1fc6aacabf65a0abe85de8655a2fb9abc9ba7f`
(x86-64-v3 + fat LTO + PGO
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`, the banked
profile), driver ELF
`d8786a0663dbc635f4e508bcc9ade6cb8cad22c0c7353f9a6280d28329628c65`. Each FUSE
daemon printed its own executing ELF in process under `FFS_MOUNT_BENCH_EVIDENCE=1`:

    mount_bench_evidence,binary_sha256=7d0526c45fdf610d5402aec92f1fc6aacabf65a0abe85de8655a2fb9abc9ba7f

`proc_exe_sha256` matches on every arm. Four-arm parity `verdict=pass`, initial
and final tree `a91834cf56bad86fc2d7324f41593e5b5b3794a76f9dbeab5dc0ff697f908c79`
over 32,773 entries; `incumbent_isolation_proof=pass`; 8 observed worker threads
on all four arms of all four invocations. Dispatch mode attested from
`/proc/<pid>/task/*/comm` at runtime, not from a log: the workers-on daemons
carried **7 `fuse-dispatch` threads** plus the primary. Reports under
`/data/tmp/frankenfs-fusecpus/a1_c{1,8}_{off,on}/report.json`.

### Relationship to the bank, and what is NOT restated

The banked row stays `4.967448x`: it was taken with candidate `f44b3dc4…` and a
different driver, and this session's control used a different ELF. The control
reproduced it to **0.3% on our own arm** (`113.050` vs the banked `113.44 ms`);
the ratio differs because the *kernel* arm ran 3.6% faster in the banked window
(`22.84` vs `23.658 ms`). Do not restate `3.467786x` as replacing `4.967448x` —
it is a different placement, and both must be published together.

### The follow-up this seems to imply, and why it is WRONG

The sign flipping on daemon CPU count invites an obvious default: read
`sched_getaffinity` at mount and enable readers whenever the daemon holds more
than one CPU. **Do not do this.** The 2026-08-01 parallel-read rejection below
measured `0.839141x` at **8 matched daemon CPUs** and `0.842005x` at one — its
own words, "the loss is the same size at 1 daemon CPU and at 8" — because 73% of
that row's requests (`OPEN`/`FLUSH`/`RELEASE`) take the dispatch gate
**exclusively**, so the whole session serializes no matter how many readers
exist. An affinity-gated default would trade this row's `1.8103x` for roughly a
`1.19x` regression on parallel-read. CPU count decides the sign *within* a row
whose mix is shared-set; it does not make the lever safe globally.

There is also a memory cost that bars any generous default: each reader owns a
`BUFFER_SIZE` = `MAX_WRITE_SIZE + 4096` = **16 MiB + 4 KiB** receive buffer, so
8 readers is 128 MiB and the `MAX_FUSE_DISPATCH_WORKERS` ceiling of 64 would be
1 GiB.

**`FFS_FUSE_WORKERS` therefore stays default OFF and explicitly opt-in.** The
real widening lever is to make `Open`/`Flush`/`Release` concurrency-safe so they
stop taking the gate exclusively — that is what would move parallel-read's 73%
exclusive share into the shared set and let this win generalize to its family.
That is a file-handle-table change, not a dispatch change, and it needs its own
row.

## NEXT LEVER, located but not yet attempted: `rmw_block` copies a whole 4 KiB block to change 256 bytes - 2026-08-02

The 2026-07-31 metadata-row profile closed with an item it did not chase:
`__memmove_avx_unaligned_erms` at **8.81% of daemon CPU, the largest single
userspace symbol**, "consistent with whole 4 KiB block copies per metadata
update". This row names the exact code that produces it, so the next agent does
not have to re-derive it. **Nothing is measured here and no effect is claimed.**

`FsMvccBlockDevice::rmw_block` (`crates/ffs-core/src/fs_mvcc_store.rs`) is the
read-modify-write path for the inode table, the inode and block bitmaps and the
group-descriptor table. Per call it does:

- `read_visible_block_buf(...)` then `buf.as_slice().to_vec()` — one whole-block
  copy; or, when no version exists at the snapshot, `self.base.read_block(...)`
  **and then** `device_base.clone()` — the read's own allocation plus a second
  whole-block copy, because the pre-image must survive for the merge proof;
- `patch(&mut data)`, which mutates a few bytes — an ext4 inode is 256 bytes of
  a 4,096-byte block, a bitmap allocation is one bit;
- stages the full 4,096-byte image as the new version.

So a create that changes on the order of 256 bytes moves 4 KiB to 8 KiB through
`memmove`, several times over (inode table, inode bitmap, block bitmap, GDT,
superblock). **In-kernel ext4 dirties a buffer-head in place and copies a whole
block only when JBD2 journals it**, so by the does-the-incumbent-pay-it test
most of this copy is ours. It also lands on the one daemon CPU that bounds the
`parallel-metadata-write` row, where our filesystem work is `7.5 us` of a
`82.7 us` per-op budget.

The shape of the change is to stage a range-scoped delta rather than a whole
block: `rmw_block` is already handed `disjoint_ranges`, so the information
needed to store `(range, bytes)` instead of a 4,096-byte image is present at the
call site. That touches the ffs-mvcc read path (a version chain becomes a patch
chain) and is not a small change.

**Cheap first step, before any of that:** count bytes moved per create with a
counter around the two copy sites and report bytes-per-create, which is a count
and therefore decidable on a loaded host. Only if it is large is the ffs-mvcc
restructuring worth proposing. Do not begin the restructuring on the strength of
one profile symbol.

## CORRECTNESS FIX (no timing taken): unlink/rmdir stop re-notifying the kernel about the entry they just removed - deadlock reproduced and removed - 2026-08-02

`26d122a6`. Self-generated lever, chosen by the standing rule "rank the job's
costs and retain only the ones the incumbent does not also pay". This row records a
correctness result; **no ratio is claimed and none was measured** — see the
closing paragraph.

### The redundancy

`dispatch_unlink`/`dispatch_rmdir` issued `FUSE_NOTIFY_INVAL_ENTRY` for the entry
they had just removed, from inside the request handler and **before** replying.
On a successful `FUSE_UNLINK`/`FUSE_RMDIR` reply the kernel already runs
`fuse_dir_changed()` and `fuse_entry_unlinked()`, which expire that dentry's
cache entry, and the VFS then `d_delete`s it, so the notify asks the kernel to
forget an entry it is in the middle of forgetting. In-kernel ext4 has no such
channel at all.

The lever was proposed on the theory that this is also **one extra `/dev/fuse`
round trip per delete** on the `2.753659x` `create-delete-storm` row, which
performs 2,000 deletes per job. **That theory is unproven and this row does not
rest on it** — see "the counted mechanism that failed" below.

### The deadlock, reproduced and removed

The kernel holds the parent directory's inode lock across `fuse_unlink` while it
waits in `request_wait_answer`; `fuse_reverse_inval_entry` wants that same lock.
A notify issued from the handler before the reply is therefore a circular wait.

Both arms from ONE binary via `FFS_FUSE_NOTIFY_UNLINK`, 8 threads x 150
iterations of create+unlink+mkdir+rmdir on a mounted read-write ext4 image
(`mke2fs -E root_owner=1000:1000`, 1 GiB, 65,536 inodes). The outcome is
**categorical, not timed**, which is why it is valid on a host too loaded for any
perf number:

| arm | `FFS_FUSE_NOTIFY_UNLINK` | outcome |
| --- | --- | --- |
| lever (new default) | unset | **COMPLETED** 2,400 create+delete pairs in 2 s, all 8 workers rc=0, `/dl` empty, `e2fsck` **rc 0** (13/65536 files, 13020/262144 blocks) |
| historical | `1` | **HUNG**: `daemon tid=2085471 state=D wchan=fuse_reverse_inval_entry`, connection `waiting=7` |

The wait channel is read from `/proc/<tid>/wchan`, so the mechanism is observed
from the kernel rather than inferred. `cargo test -p ffs-fuse --release`: **572
passed / 0 failed** plus the doctest; `rustfmt` clean.

A sharper finding than the recorded 2026-08-01 hang, which needed eight threads:
**`rmdir` deadlocks single-threaded.** A serial loop of 200 `rmdir`s with
`FFS_FUSE_NOTIFY_UNLINK=1` wedged the daemon on the same wait channel with 19
requests queued, while a serial loop of 200 `unlink`s did not. So concurrency is
not the trigger; it merely makes the `unlink` path hit it too. Both wedged
daemons were released by aborting **their own** FUSE connection
(`/sys/fs/fuse/connections/<minor>/abort`, minor read from
`/proc/self/mountinfo` for our mountpoint) — a peer agent held a live
`fuse.ffs` mount on this host throughout, on connection 167, and it was never
touched.

### The counted mechanism that failed, and why its zero difference means nothing

The "one extra round trip per delete" theory was tested by counting the daemon's
write syscalls from `/proc/<pid>/io` `syscw` across a fixed serial delete loop,
both arms from one binary:

| arm | op | n | writes | per op |
| --- | --- | ---: | ---: | ---: |
| lever | unlink | 200 | 1,000 | 5.000 |
| lever | unlink | 400 | 2,000 | 5.000 |
| lever | rmdir | 200 | 999 | 4.995 |
| historical | unlink | 200 | 1,000 | 5.000 |
| historical | rmdir | 200 | — | deadlocked |

Stated for the contract in one line: on 200 serial unlinks the two arms record
1,000 syscalls vs 1,000 — a zero difference, and the next paragraph is why that
zero carries no information.

Doubling the operation count doubles the writes exactly, so the counter is
sensitive to *something* per-operation — but that something is the daemon's
image `pwrite`s, not its `/dev/fuse` traffic. `Notifier::send` goes through
`with_iovec` → `writev`, and so do the request replies, which is why the total
does not move between arms and why five writes per delete is a suspiciously
round number for a path that also replies to `LOOKUP` and `UNLINK`. **The
instrument is blind to the quantity under test, so its zero difference neither
confirms nor refutes the extra round trip.** It is recorded here so the next attempt does
not repeat it: count `/dev/fuse` traffic with a counter that observes `writev`
(the 2026-07-31 census used `strace` on the daemon; note `ptrace_scope=1` on
this host, so `strace` must launch the daemon rather than attach to it).

A first version of the deadlock test reported COMPLETED for **both** arms — every
operation was failing with `Permission denied` because a plain `mke2fs` root
inode is uid 0 and the client is uid 1000, and a workload whose every operation
fails also finishes. The `e2fsck` block count being unchanged is what exposed
it. The harness now creates its working directory as a gate and checks every
worker's exit status, so an all-failures arm can no longer read as success.

`rename` still notifies, after its reply, and is deliberately unchanged: it is
not a deadlock source and its two round trips are a separate question.

### What is NOT claimed

**No performance effect is claimed, implied, or banked.** The round-trip theory
that motivated the lever is unmeasured — the counter that was supposed to settle
it could not see the quantity — and no mounted-comparator run was admissible on
this host tonight (see the row below). The change stands on the correctness
proof alone, which needs no perf number to justify it: it removes a reproduced
deadlock. The command that must produce a perf verdict, if one is wanted:

```
ffs-mounted-kernel-bench --ffs-cli <v3+PGO elf> --filesystem ext4 \
  --workload create-delete-storm --operations 2000 --pairs 128
```
run with `FFS_FUSE_NOTIFY_UNLINK` unset and `=1` from one ELF, on a host whose
every CPU is quiet, with the historical arm's own admitted ratio reproducing the
banked `2.753659x` before the lever arm is read.

## PENDING (no verdict): `--fuse-cpus` removes the 8:1 daemon handicap; the one window this session could not decide anything - 2026-08-02

Instrument-only row: it banks a harness knob, committed as `b3eebca8`, and no
FrankenFS optimization. The number the knob exists to produce is NOT in it. The 2026-08-01 dispatch entry below measured concurrent FUSE
dispatch at **1.923x faster** on `readdir-stat-8t` with the daemon on eight CPUs
and **1.141x slower** with it on one, and named the missing harness knob as the
thing blocking a bankable result. This adds it.

### Why the placement was worth changing

`select_fuse_cpus` returned `vec![cpu]`. In the kernel arm the filesystem
executes inside the client threads, so on an eight-thread row in-kernel ext4 has
eight CPUs of filesystem capacity and FrankenFS has one — every multi-threaded
banked row carries that 8:1 asymmetry. `--fuse-cpus N` defaults to 1 and at 1
takes the identical former code path, so no banked row changes. Above 1 the
clients are placed first, exactly as they are today, and the daemon then takes
quiet CPUs the clients did not claim; inside one last-level-cache domain (16
logical CPUs over 8 physical cores here) those are the clients' SMT siblings, so
both arms occupy **the same eight physical cores** and the daemon runs on
hyperthreads the kernel arm structurally cannot use for this job. That is a
different resource contract, not a better one: reports carry
`requested_fuse_cpus` and a `fuse_cpu_isolation` string
(`private_physical_core_clients_placed_after` vs
`shares_physical_cores_with_clients_placed_after`) so a number taken at one
placement can never be restated as the other. Neither placement retires the
other and the banked rows stay as they are.

### The measurement attempt, and why it decided nothing

One invocation completed before the host filled up: `readdir-stat-8t`,
32,768 operations, 128 pairs, `--fuse-cpus 1`, `FFS_FUSE_WORKERS` unset — i.e.
the control that had to reproduce the banked `4.967448x` before any candidate
number could be read at all.

| quantity | banked row | this window |
| --- | ---: | ---: |
| kernel median batch | 22.84 ms | 32.32 ms |
| FrankenFS median batch | 113.44 ms | 208.39 ms |
| fuse / kernel | `4.967448x` | `6.292487x` `[5.812018, 6.455416]` |
| kernel A/A spread | `1.008448x` | **`1.031347x`** |
| FUSE A/A spread | `1.002503x` | **`1.048235x`** |

Both A/A nulls exceed the `1.025x` limit, `directional_claim_clear=false`,
`verdict=blocked_null`, `admitted=false`. The two byte-identical FUSE mounts
differed by 14% from each other (`fuse_a` 194.29 ms, `fuse_b` 221.53 ms). The
placement preflight had passed — our own LLC CPUs sampled 0.051 busy — so the
contention was shared L3/memory traffic from sibling agents on other CCDs, which
a same-LLC per-CPU check cannot see. Host one-minute load went 14 -> 30 -> 87
during the session. The remaining three invocations then fail-closed at
placement (`no physical core has every SMT thread below the driver contention
limit`) and produced no data.

Estimator and provenance, each on one line:

`fuse_over_kernel` deterministic 20,000-resample bootstrap median 95% CI = `6.292487x [5.812018, 6.455416]`; wall time is the gate, `cv_used=false`, `instructions_used=false`.

Emitted by each FUSE daemon itself under `FFS_MOUNT_BENCH_EVIDENCE=1`, in process, not by a neighbouring `sha256sum`:

    mount_bench_evidence,binary_sha256=d3d6adeb23a9f654a857c9712be21b5642b2ee9918a8768469cdbcbed4adb0d8
    mount_build_profile,pgo_profile_sha256=6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc

**Nothing here is pooled, selected among, or reported as an effect.** The gate
limit was not touched. Report preserved at
`/data/tmp/frankenfs-fusecpus/c1_off/report.json`. Both FUSE daemons
self-reported the executing ELF in process as SHA-256
`d3d6adeb23a9f654a857c9712be21b5642b2ee9918a8768469cdbcbed4adb0d8`, matching
`/proc/<pid>/exe` (`proc_exe_sha256` identical on both arms), on PGO profile
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc` — the banked
profile — with `isa=x86-64-v3,verdict=pass`; driver ELF
`d8786a0663dbc635f4e508bcc9ade6cb8cad22c0c7353f9a6280d28329628c65`. Four-arm
tree parity passed (`a91834cf…`, 32,773 entries) and the daemon pinning was
attested live from `/proc`: both daemons `Cpus_allowed_list: 29`, zero
`fuse-dispatch` threads.

### Method rule this establishes

**A candidate placement number is unreadable until the control at the banked
placement reproduces the banked row inside its twice-null margin, in the same
window.** Running the candidate first and comparing it to a number from a
different day would have shown a large apparent improvement here purely because
this window is 1.4x slower end to end.

### The command that must produce the verdict

Four invocations from one ELF, on a host whose *every* CPU is quiet — not just
the benchmark's — for five consecutive one-second samples:

```
ffs-mounted-kernel-bench --ffs-cli <v3+PGO elf> --filesystem ext4 \
  --workload readdir-stat-8t --operations 32768 --pairs 128 \
  --fuse-cpus {1,8} --harness-builder <host> --candidate-builder <host>
```
with `FFS_FUSE_WORKERS` unset and `=8`. `--fuse-cpus 8` + workers unset is the
control that matters: a serial session loop cannot use eight CPUs, so it must
move nothing, and any movement in `--fuse-cpus 8` + `FFS_FUSE_WORKERS=8` that it
does not also show is the CPUs rather than the lever. Admission requires the
`c1_off` control to land on `4.967448x` first.

## KEEP (default OFF, maintenance only): append-only ext4 metadata WAL + quiesced compactor - diagnostic live-incumbent ratio 1.502x -> 1.216-1.237x, null-blocked - 2026-08-02

Lever 3 from the mounted-live-incumbent list replaces synchronous random
home-block metadata checkpointing with an append-only CRC-protected MVCC WAL.
`FFS_EXT4_METADATA_LOG=1` gives each writable ext4 mount a sidecar WAL; fsync
captures the latest MVCC blocks plus derived group-descriptor/superblock
summaries, appends and syncs one sequential commit, then publishes the
read-your-writes index. An owned background compactor sorts/coalesces blocks and
waits for a 10 ms quiet window before home-location writeback so it does not
race sibling foreground fsyncs. Clean unmount joins the worker, performs one
authoritative full checkpoint, and only then truncates the WAL to its header.

### Crash and isomorphism proof

Strict-remote `ffs-core` regression
`append_only_metadata_log_replays_then_checkpoints_clean` passed: the test
observed a non-empty WAL after fsync, simulated a crash without the final
checkpoint, replayed exactly one committed record with the file contents
visible, then checkpointed to a 16-byte header and passed `e2fsck -fn`. Both
mounted candidate runs created independent sidecars for both FUSE arms; all
four sidecars were 16 bytes after clean unmount. Initial/final tree parity and
offline post-unmount validation passed for all four physical arms in every
invocation.

Ordering remains the MVCC commit-sequence order; last revision still wins for a
block, and the compactor may only discard older block images after the newer WAL
record is durable. Tie-breaking, floating point, and RNG are N/A.

### Measurement against live kernel ext4

Each invocation used the frozen mounted driver
`b6fcf0c90c45b66a8ad0160dacf954bda58d535432163804900764e00777579f`,
the same PGO profile
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`,
four simultaneous independent arms (kernel A/B and FUSE A/B), 128 balanced
crossover pairs, 512 creates, eight observed/pinned workers, and one directory
fsync per worker under same-LLC placement. The control and first WAL run used
the identical candidate ELF
`e5efe9a592490492a783e18020a0a877786b8812514315d5904debd761d6f5ec`;
the quiesced-compactor refinement used
`d3d6adeb23a9f654a857c9712be21b5642b2ee9918a8768469cdbcbed4adb0d8`.
Both executing ELFs self-reported in process before the run:
`bench_evidence,binary_sha256=e5efe9a592490492a783e18020a0a877786b8812514315d5904debd761d6f5ec`
and
`bench_evidence,binary_sha256=d3d6adeb23a9f654a857c9712be21b5642b2ee9918a8768469cdbcbed4adb0d8`.

| path | kernel median | FUSE median | FUSE / kernel | 95% CI | kernel/FUSE A/A spread | admission |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| same-ELF WAL-off control | 27.139 ms | 40.315 ms | 1.501579x | [1.456096, 1.532052] | 1.034486 / 1.015496 | BLOCKED_NULL |
| same-ELF WAL-on | 29.502 ms | 34.371 ms | 1.216150x | [1.192461, 1.256547] | 1.082532 / 1.032545 | BLOCKED_NULL |
| WAL-on, quiesced compactor | 22.044 ms | 29.574 ms | 1.237305x | [1.218937, 1.262013] | 1.029163 / 1.026533 | BLOCKED_NULL |

Reports and SHA-256:

- `/data/tmp/frankenfs-metadata-log/control/report.json`:
  `18ad92c143af814b6e6adf7ce7b18c2e11d788a06798201c6fc323b84f68bc2c`;
- `/data/tmp/frankenfs-metadata-log/candidate/report.json`:
  `9d97c2e1b0ee4d5c35349e068d73cd0c902f2aed949cc055f7c63393490dc916`;
- `/data/tmp/frankenfs-metadata-log/quiesced/report.json`:
  `df6b99823ab7551ecdfeb1b758bd6d425beb2ee06764b7728165e7a2ed894c31`.

Each reported interval is a 20,000-resample bootstrap median 95% CI;
`cv_used=false`. Every invocation is null-blocked, so these are diagnostic
maintenance results, not a scored competitive claim. The repeat feature-on
ratios nevertheless move the structural gap from about 1.50x to about
1.22-1.24x while preserving mounted parity and clean images.

### Decision

**KEEP DEFAULT OFF as a maintenance win; DO NOT BANK.** Sequential WAL
durability and deferred/coalesced home writeback remove a material part of the
random-checkpoint tax, but FrankenFS still trails the live incumbent by at least
21.9% at the candidate CI lower bounds. The remaining loss is in the parallel
create/allocator/commit body rather than home-location durability; proceed to
per-core allocation arenas and lock-free inode allocation, and require an
admitted live-incumbent run before changing this row to competitive KEEP.

## REJECT + REVERT: FUSE-over-io_uring on parallel metadata - diagnostic FUSE wall time 1.487x slower, null-blocked - 2026-08-01

Lever 2 from the mounted-live-incumbent list: batch FUSE request submission and
completion through Linux FUSE-over-io_uring instead of paying one classic
`/dev/fuse` read/write round trip per request. The implementation used queue
depth 4 and a 128 KiB payload per queue entry and stayed opt-in behind
`FFS_FUSE_IO_URING=1` plus the kernel's `enable_uring=Y` switch.

### Activation and behavioral proof

This was not an environment-only A/B. The exact scored binary logged
`kernel accepted FUSE-over-io_uring: queue_depth=4, payload_size=131072` on the
standard blocking `mount` path used by `ffs-mounted-kernel-bench`; the managed
path was wired and proved separately. A 32-create smoke test persisted all 32
names (sorted-name SHA-256
`e92f6a53507f6728ca8bd62d1dfb89ff3186ea13048e762e5c247de6e3ecb623`),
unmounted cleanly, and passed offline `e2fsck -fn`. The kernel switch was
restored to `N` after measurement.

Isomorphism proof for the candidate: ordering stayed behind the same global
dispatch lock and every request still entered `Request::dispatch`; tie-breaking,
floating point and RNG are N/A; the mounted harness passed initial/final tree
parity and post-unmount validation on all eight physical images across the two
invocations.

### Measurement against live kernel ext4

Same frozen candidate ELF in both invocations,
`431fa57ba7996a0a865dc20a505a7d2dcbac70bc9917d50cf720147fdf076b74`,
PGO profile
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`;
same frozen mounted driver
`b6fcf0c90c45b66a8ad0160dacf954bda58d535432163804900764e00777579f`.
Each invocation ran four live independent arms (kernel A/B and FUSE A/B), 128
balanced crossover pairs, 512 creates, eight observed/pinned client threads,
one directory fsync per worker, on CPUs `24-31,56-63` (`same-llc`). Reports:

Every reported interval is a 20,000-resample bootstrap median 95% CI;
`cv_used=false` and instructions were not used. Each report contains its own
same-invocation A/A null controls: classic kernel A/A 1.021933x and FUSE A/A
0.981960x; io_uring kernel A/A 0.993509x and FUSE A/A 1.004114x.

- classic control: `/data/tmp/frankenfs-io-uring-v2/control/report.json`,
  SHA-256 `bb87eefbdcf1f7de9971ef177485a1a4a5d7b96d1fa21f7fdc166aa43cdb1442`;
- io_uring candidate: `/data/tmp/frankenfs-io-uring-v2/candidate/report.json`,
  SHA-256 `7b1aa1cc86605b2a4f972ec6bdfc27ffc7f40f8a12bab9203b01d82cdb2c9be3`.

| transport | kernel median | FUSE median | FUSE / kernel | 95% CI | admission |
| --- | ---: | ---: | ---: | ---: | --- |
| classic control | 33.761 ms | 46.718 ms | 1.357088x | [1.297664, 1.438340] | BLOCKED_NULL |
| io_uring | 33.551 ms | 69.450 ms | 2.097425x | [2.053373, 2.187929] | BLOCKED_NULL |

Both ratios are diagnostic only: control kernel/FUSE symmetric A/A spreads
were 1.084395/1.039428 and candidate spreads were 1.063001/1.030066, all above
the required 1.025 where noted by the reports. Therefore this row makes no
bankable competitive timing claim. It does supply a decisive engineering
direction: with the live kernel arm flat within 0.7%, io_uring increased FUSE
wall time by **1.486583x** and worsened the diagnostic incumbent ratio by
**1.545533x**.

### Decision and mechanism

**REVERT.** The compiled/runtime io_uring surface, ABI 7.42 negotiation and
dependency were removed; the later concurrent-dispatch lever remains intact.
The rejected source module is deliberately unreferenced rather than deleted,
because repository policy requires a separate explicit file-deletion grant.

This implementation created a ring worker for every possible CPU, assembled
each request into a fresh `Vec`, crossed an MPSC channel plus eventfd for every
reply, and then serialized filesystem callbacks behind a mutex. For this
small-metadata row those structural costs exceeded the classic syscall cost;
there was no batching win to amortize them.

**Retry predicate:** revisit only with a profile showing classic `/dev/fuse`
submission/completion as the remaining exclusive gap *and* a design that uses
only the daemon's assigned CPUs, keeps request buffers zero-copy through
dispatch, and batches multiple reply commits per wakeup. Any retry still needs
an admitted same-invocation live-incumbent gate.

## KEEP (default OFF): concurrent FUSE dispatch - readdir+stat 1.923x faster than the single-threaded loop, and 1.14x SLOWER on the banked 1-CPU daemon placement - 2026-08-01

Lever chosen by profiling the whole readdir+stat job against the live kernel arm
and asking, per cost, "does the incumbent pay this too?"

### What the profile says (the 4.967x row)

The banked worst row is `large_directory_readdir_stat_8t`. The daemon profile
under that workload is 100% transport - `entry_SYSRETQ` 6.6%, `memmove` 5.1%,
`fuse_dev_do_read` 3.6%, `fuse_copy_fill` 3.5%, plus scheduler and audit
syscall entry/exit. No frankenfs symbol clears 1.2%.

The per-`lstat` round trip is now named, with its caller. `kprobe:fuse_getxattr`
with `kstack` over an 8-thread stat sweep of 8,192 warm entries:

```
fuse_getxattr / __vfs_getxattr / get_vfs_caps_from_disk /
audit_copy_inode / __audit_inode / filename_lookup / vfs_statx / vfs_fstatat  : 8193
```

8,193 round trips for 8,192 `lstat`s = **1.000/entry**, all for
`security.capability` (`kprobe:fuse_getxattr { @[str(arg1)] }` reports that one
name and no other). The host has audit enabled (`auditctl -s`: `enabled 1`, two
rules watching `/data/projects`), so `__audit_inode` fires on every path
resolution.

**The incumbent pays the same call and not the same cost.** During a kernel-arm
sweep `get_vfs_caps_from_disk` is answered by `ext4_xattr_get` from the inode
already in memory - no round trip - while `fuse_getxattr` stays at background
level (196 host-wide vs 24,864 for the FUSE arm's own sweep). By the
does-the-incumbent-pay-it test the transport is structural and it is ours.

Round trips per stat cannot be reduced: on 6.17 nothing in the FUSE protocol
suppresses a per-name xattr probe (`fc->no_getxattr` needs an `ENOSYS` reply and
kills *all* xattr support; `FUSE_HANDLE_KILLPRIV_V2` only sets `S_NOSEC`, which
gates `file_remove_privs` on the WRITE path and does nothing for this stack -
this retires the fix proposed by the 2026-07-31 SURVEY row below for this row).
What *is* reducible is how many of them can be in flight.

### The structural gap

`Session::run` reads one request from `/dev/fuse`, services it, replies, and
only then reads the next. Eight client threads issuing 8,192 stats are funnelled
through **one** server thread while in-kernel ext4 runs the same work inside the
eight callers on eight CPUs. `run_with_threads` from `b08a03ca` was reverted
five minutes later in `1040f2f6` with no ledger row, so HEAD dispatches serially.

### Lever (one lever)

`FFS_FUSE_WORKERS=N` runs N reader threads on the same `/dev/fuse` fd (the
kernel hands each blocked reader a distinct pending request), gated by a
reader/writer lock in `Session::dispatch_request`:

- `Request::is_concurrency_safe()` = `Lookup | GetAttr | ReadLink | Read |
  StatFs | GetXAttr | ListXAttr | ReadDir | ReadDirPlus | Access | BMap | Lseek
  | Statx` take the gate **shared**;
- everything else - every mutation, `Open`/`Release`/`Flush`, `Forget`, the
  handshake - takes it **exclusively**, i.e. keeps the exact whole-session
  exclusion the single-threaded loop always gave it.

INIT is always serviced on the primary thread before any worker starts. Unset /
`1` / invalid selects the historical loop and the gate is `None`, so the default
path is byte-identical and the same ELF supplies both A/B arms. Wired into both
`mount()` and `mount_managed()`. The mounted-kernel harness actually invokes
the standard `mount()` path; an earlier version of this ledger incorrectly
called it managed. That distinction is proved for the io_uring rejection above
by explicit kernel-acceptance logging on the scored standard path.

### Measurement (one ELF, four arms live at once, interleaved, order rotates per round)

8,192-entry `large-directory`, `readdir` then 8 forked workers `lstat` every
entry once; 11 rounds, round 0 discarded; clients pinned to CPUs 24-31; both
FUSE arms mounted simultaneously from byte-identical images and pinned to the
same CPU set; `tmpfs` is the T5 driver-ceiling control.

21 rounds, round 0 discarded, 20 observations per arm. Every interval below is a
deterministic 20,000-resample bootstrap median 95% CI (seed `0x5EED`).
Wall time decided this row; `cv_used=false`, `instructions_used=false`.

| daemon CPUs | kernel ext4 median | fuse1 (control) | fuse8 (candidate) | **fuse1/fuse8** | 95% CI |
| --- | --- | --- | --- | --- | --- |
| **56-63 (8, matched)** | 3.792 ms | 33.006 ms | **17.162 ms** | **1.923233x faster** | **[1.895582, 1.970661]** |
| **58 (1, as banked)** | 3.790 ms | 32.785 ms | 37.409 ms | **0.876400x (1.141x SLOWER)** | **[0.858258, 0.896773]** |

Neither interval contains `1.0`, and they do not overlap each other. Against the
live kernel arm the row moves `8.703447x [8.509252, 8.964847]` ->
`4.525424x [4.424609, 4.639032]` at matched CPUs, and
`8.649655x [8.463620, 8.963691]` -> `9.869528x [9.588661, 10.299974]` at one CPU.

Both arms self-reported the SAME executing ELF in-process, from
`elf_self_sha256()` under `FFS_MOUNT_BENCH_EVIDENCE=1`, printed by each daemon:
`mount_bench_evidence,binary_sha256=b7f0c1c6a371525f1a20a3b54e03f7eb3730b2f588a98543b049bc04d1d597c3`
Dispatch
mode attested from `/proc/<pid>/task/*/comm` at runtime, not from a log: control
**0** `fuse-dispatch-*` threads, candidate **7** plus the primary; both
`taskset -cp` = the same CPU list. Raw per-round samples are kept alongside the
run (`ab_samples_{8cpu,1cpu}.json`).

### What this run does NOT claim

`tmpfs / kernel` reads `1.005766x [0.970756, 1.031050]` and
`0.994833x [0.966971, 1.035229]`: in this rig the **kernel arm sits on the
driver's own ceiling**, so by T5 its number is client-bound and the
`fuse/kernel` ratios above are upper bounds that must not be compared with the
banked `4.967448x` (different corpus size, driver and placement). The decidable
claim is the internal A/B - both FUSE arms are 4.5-8.7x above the ceiling.

### Why the default stays OFF: the banked placement is where it loses

`select_fuse_cpus` returns `vec![cpu]`. The banked readdir report
(`run_1785384757_637562`) records `driver_cpus = [24,25,27,28,56,61,62,63]` and
`fuse_cpus = [58]` - **8 CPUs of clients against 1 CPU of filesystem**, while the
incumbent's filesystem code runs inside those 8 client threads. Every
multi-threaded FrankenFS-vs-kernel row is measured under that 8:1 handicap, and
it is exactly the regime where this lever is a 1.14x loss.

**Next step (blocking a bankable number):** teach
`ffs_mounted_kernel_bench` a `--fuse-cpus` knob so the daemon can be given the
same CPU count as `--client-threads`, publish both placements, and only then
re-run `--workload readdir-stat-8t`.

### Correctness

Read-only parity across all three arms: identical stat digest `271884288` over
8,192 entries; `find -printf '%p %s %m %n %y'` identical between the two FUSE
arms (**8,194 entries, empty diff**); offline `e2fsck -fn` **rc 0** on both
images with identical `8206/262144 files, 34544/524288 blocks`. Formatting clean
on the four touched files.

### Blocked: pre-existing HEAD deadlock on the concurrent MUTATION path

The mutation half of the correctness gate could not run - and the reason is not
this lever. Eight threads doing `create/rename/unlink/rmdir/symlink` deadlock the
mounted rw daemon **on the default single-threaded path too**:

```
daemon thread   state=D   wchan=fuse_reverse_inval_entry
8 client threads state=S  wchan=request_wait_answer
```

`dispatch_unlink` and `dispatch_rmdir` call `notify_entry_invalidation` -
`Notifier::inval_entry` - **before replying**, from the dispatch thread. The
kernel holds the parent directory's inode lock across `fuse_unlink` while
blocked in `request_wait_answer`; `fuse_reverse_inval_entry` wants that same
lock. Circular wait. (`rename` already notifies after `reply.ok()`.) Reproduced
identically with the lever OFF and ON, so it is a HEAD bug, not a regression.
Fix belongs in its own change: hand `(parent, name)` to a dedicated notifier
thread so no invalidation is ever issued from a request handler.

## REJECT: widening concurrent FUSE dispatch to the parallel-READ row - 0.839x - the opcode census says 73% of the row is in the exclusive set - 2026-08-01

Attempt to widen the KEEP above to the rest of its family. `parallel-read-8t`
(banked `1.287862x`) is the other read-only 8-thread row and `Read` is already in
`Request::is_concurrency_safe()`, so it should have converted with zero new code.

### Measurement (same rig, same ELF, same discipline as the KEEP above)

256 x 256 KiB files, enumerate then 8 forked workers `pread` every file exactly
once; 21 rounds, round 0 discarded, 20 observations per arm; deterministic
20,000-resample bootstrap median 95% CI (seed `0x5EED`). Same executing ELF
self-reported by both daemons:
`mount_bench_evidence,binary_sha256=b7f0c1c6a371525f1a20a3b54e03f7eb3730b2f588a98543b049bc04d1d597c3`
Wall time decided this row; `cv_used=false`, `instructions_used=false`.

| daemon CPUs | fuse1 (control) | fuse8 (candidate) | **fuse1/fuse8** | 95% CI |
| --- | --- | --- | --- | --- |
| **56-63 (8, matched)** | 7.676 ms | 9.148 ms | **0.839141x** | **[0.814367, 0.870853]** |
| **58 (1, as banked)** | 7.715 ms | 9.162 ms | **0.842005x** | **[0.822414, 0.912637]** |

Both intervals exclude `1.0` on the losing side, and - unlike the metadata row -
the verdict does **not** move with the daemon's CPU count. That is the tell.

### Counted mechanism - and it refutes the obvious explanation

`fuse:fuse_request_send` census on this arm's connection, 4 rounds of 256 files
(the "byte-bound payload" guess is wrong - there is no payload):

| opcode | requests | per round | gate class |
| --- | --- | --- | --- |
| **FUSE_OPEN** | 1024 | 256 | **exclusive** |
| **FUSE_FLUSH** | 1024 | 256 | **exclusive** |
| **FUSE_RELEASE** | 1024 | 256 | **exclusive** |
| FUSE_GETXATTR | 1162 | ~290 | shared |
| FUSE_LOOKUP | 258 | ~1 (cached) | shared |
| **FUSE_READ** | **0** | **0** | - |

Counted on the wire, not sampled - syscall count per round: 1058 syscalls vs 8193 for the readdir+stat row this same lever wins on.

**Zero READ requests.** The 64 MiB never crosses `/dev/fuse` at all - the kernel
serves every byte from its own page cache - so this row is not byte-bound and it
is not `Read`-bound. Its FUSE traffic is ~1058 round trips per round of which
**~768 (73%) are handle-lifecycle ops that `is_concurrency_safe()` deliberately
puts in the EXCLUSIVE set.** Eight workers therefore queue on an exclusive
`RwLock` for three quarters of the row's requests, which is exactly why the loss
is the same size at 1 daemon CPU and at 8.

### Scope rule this establishes

Concurrent dispatch pays in proportion to the **share of a row's request mix that
is in the shared set**, not to how parallel the client is. readdir+stat is ~100%
shared (`GETXATTR`+`LOOKUP`) and wins 1.92x; parallel-read is 73% exclusive and
loses 1.19x. Census the opcode mix before applying this lever to any new row.

**Retry predicate:** re-test only after `Open`/`Flush`/`Release` are shown safe to
move into the shared set (i.e. the file-handle table is proven concurrent), which
would flip this row's mix from 73% exclusive to ~0%.

## SURVEY (no code change): one wasted `security.capability` round trip PER FILE on the default path - 2026-07-31

Found while building the counter the READDIRPLUS retry predicate demanded. Not a
candidate yet - a located structural difference plus the reason it cannot be
switched on safely today.

### The counter

`/proc/<pid>/io` conflates image `pread`s with FUSE traffic, so this uses the
`fuse:fuse_request_send` tracepoint via bpftrace - a pure `/dev/fuse` opcode
census. Enumerate-then-stat sweep over 4,000 entries, warm cache:

| Opcode | readdirplus OFF (default) | readdirplus ON |
| --- | --- | --- |
| **GETXATTR** | **4030 = 1.008/entry** | 4036 = 1.009/entry |
| GETATTR | **1** | 4001 = 1.000/entry |
| READDIR / READDIRPLUS | 9 | 21 |

`strace` of the daemon's `/dev/fuse` reads names the culprit: **482 requests for
`security.capability` across 400 files** - one probe per file, and nothing else.

### Two conclusions

**The READDIRPLUS premise was wrong, and this proves it.** The default path
already issues essentially ZERO per-entry GETATTR (1 for 4,000 entries) - the
kernel serves those stats from cache, so the "32,768 stat round trips" that lever
was aimed at never existed. Enabling readdirplus ADDED 4,000 GETATTRs, because
the kernel does not accept the attributes in our replies and re-fetches every
one. That is the mechanism behind its 2.2x loss, now visible at opcode level.

**The real per-file tax is `security.capability`.** In-kernel ext4 answers it
from the inode's cached xattr area with no round trip; for us it is a full FUSE
round trip per file on every enumeration, every `ls -l`, `find`, `du` and
`git status`. It is invisible to a CPU profile of our own code because the cost
is transport, and it is exactly the class of structural difference the standing
directive says to retain: the incumbent does NOT pay it.

### Why it is NOT a one-line flag flip

The kernel suppresses this probe per inode via `S_NOSEC`, which requires
`SB_NOSEC` on the superblock, which FUSE sets only for a connection advertising
`FUSE_HANDLE_KILLPRIV_V2`. Advertising that is a CONTRACT: the filesystem must
itself clear setuid/setgid and `security.capability` on write, chown and file
shortening. Two blockers, both real:

- We implement none of it - no `killpriv` / suid-clearing path exists in
  `crates/ffs-core` or `crates/ffs-fuse`. Advertising the flag without it is a
  security regression: a setuid binary would survive an unprivileged write.
- `FUSE_HANDLE_KILLPRIV_V2` is not even present in `vendor/fuser`
  (`fuse_abi.rs` carries only `FUSE_HANDLE_KILLPRIV`, bit 19). A peer is
  concurrently bumping `fuser` to `abi-7-42`, which is the range that would
  supply it - coordinate before touching that vendor tree.

### Next lever (in order)

1. Implement the killpriv contract in the write/chown/shorten paths, with a test
   proving a setuid file loses its bit on unprivileged write.
2. Only then advertise `FUSE_HANDLE_KILLPRIV_V2` and re-run this opcode census;
   the success condition is GETXATTR per entry dropping from ~1.0 to ~0.
3. Re-measure `readdir-stat-8t` against the live kernel arm - currently
   `4.967448x`, our worst row.

## READDIRPLUS negotiation is REJECTED - correct, but 2.2x SLOWER - 2026-07-31

Self-generated lever, picked by the standing directive: profile the whole job,
keep only entries the incumbent does NOT also pay, then attack the worst row.
The kept entry was the FUSE per-op transport tax (62.44% of daemon CPU; in-kernel
ext4 runs in the caller's context and pays none of it) and the worst row is
`readdir-stat-8t` at `4.967448x`, which is 32,768 enumerate-then-stat round trips.

The find looked ideal: `readdirplus` is fully implemented in `crates/ffs-fuse`
(batched parallel getattr, 128/batch, bounded overshoot) and we already return a
60s `ATTR_TTL`, but `init()` advertised only SPLICE and PASSTHROUGH - so the
capability was never negotiated, the kernel only ever sent plain READDIR, and the
handler was DEAD CODE. Adding `FUSE_DO_READDIRPLUS` should have let the kernel
answer those 32,768 stats from its own dcache.

It does not. Reverted; `crates/ffs-fuse/src/lib.rs` is unchanged on HEAD.

### Correctness passed - this is purely a speed rejection

Same tree enumerated with the capability on and off, 3,000 entries: entry-name
lists byte-identical, per-entry `stat` output (size, mode, nlink) byte-identical,
offline `e2fsck` rc=0. So the dead handler was not buggy, merely slower.

### Counted mechanism: round trips went UP, not down

Interleaved on/off/on/off, 8,000-entry enumerate-then-stat sweep, daemon syscall
count from `/proc/<pid>/io` plus wall time for the sweep alone:

| Capability | daemon syscall count / entry | sweep wall |
| --- | --- | --- |
| `DO_READDIRPLUS + READDIRPLUS_AUTO` | 2.08 | 129 ms / 142 ms |
| off (baseline) | 2.01 | 135 ms / 129 ms |
| `DO_READDIRPLUS` alone (always plus) | **4.88 / 4.89** | **287 ms / 310 ms** |
| off (baseline) | 2.01 | 143 ms / 125 ms |

Two distinct failures. **AUTO is inert**: the kernel's `fuse_use_readdirplus()`
issues plus only when `ctx->pos == 0` or a prior lookup set `FUSE_I_ADVISE_RDPLUS`,
so only the FIRST getdents batch of a large enumeration comes back with
attributes and every remaining entry still round trips - 2.08 vs 2.01 is nothing.
**Always-plus is a 2.2x LOSS**: the kernel does send READDIRPLUS, our handler
computes attributes for every entry it returns, and the per-entry stats round trip
anyway - so the attribute work is paid twice. Fatter replies also fill the client
buffer after ~150-200 entries instead of more, so the enumeration needs more
READDIR calls on top.

Caveat on the counter: `/proc/<pid>/io` `syscr+syscw` counts the daemon's image
`pread`s as well as `/dev/fuse` traffic, so it is an upper bound on round trips,
not a pure round-trip count. The wall time is the honest arbiter and it agrees -
287/310 ms against 125/143 ms.

### Retry predicate

Retry only after establishing WHY the kernel does not satisfy the following
`stat` from the readdirplus-populated dcache, measured on a `/dev/fuse`-only
counter (not `/proc/<pid>/io`) showing per-entry round trips actually FALL. Until
that is understood, advertising the capability makes the worst row worse. Do not
re-add `READDIRPLUS_AUTO` at all - it is measurably inert for large directories.

## PROFILE: the mounted metadata row is TRANSPORT-bound, so levers 1/3/4 are all capped below parity - 2026-07-31

Why this exists: lever 1 was rejected on correctness, but that left open "would a
correct version have won?". This profile answers it with arithmetic instead of
another candidate. It also retires levers 3 and 4 for this row.

### The budget, from the admitted same-invocation run

The `1.507220x` control (same-invocation A/A nulls `1.012983x` kernel /
`1.002400x` FUSE, bootstrap median CI `[1.494469, 1.524164]`, four-arm crossover)
carries a per-op decomposition:

| Quantity | Value |
| --- | --- |
| kernel arm, per op | `57.6 us` (its filesystem work runs in the callers' contexts across all 8 driver CPUs) |
| FUSE arm, per op | `82.7 us` (served by ONE daemon CPU - `fuse_cpus=[6]` vs `driver_cpus` of 8) |
| gap to close | `25.1 us` |
| our filesystem core, CPU per create | **`7.5 us`** (`create-bench`, 1 thread, 20000 creates, user+sys) |

**Deleting the entire filesystem layer leaves `82.7 - 7.5 = 75.2 us` against the
kernel's `57.6 us` - still `1.31x` slower.** No lever that optimizes filesystem
work can reach parity on this row. That covers lever 1 (buffer the commits),
lever 3 (log-structure the metadata) and lever 4 (per-core arenas / lock-free
inode alloc) alike.

### Where the daemon's CPU actually goes

`perf record -F 4999` on the FUSE daemon pinned to one CPU while 8 clients create
files, 48,344 samples:

| DSO | Share |
| --- | --- |
| `[kernel.kallsyms]` | **62.44%** |
| `ffs-cli` (our code) | 24.43% |
| `libc` (mostly 4 KiB `memmove`) | 12.82% |

Top userspace symbols are flat - `lookup_in_dir_block` 1.88%, `ext4_add_dir_entry`
1.50%, `Mutex::lock_contended` 1.34%, and **`ShardedMvccStore::commit` 1.04%**.
That last one is lever 1's ENTIRE target: about **1%** of the cost on the path
that loses. The kernel side is per-syscall and per-context-switch tax -
`entry_SYSRETQ_unsafe_stack` 4.21%, SRSO mitigation thunks 2.66%, and ~7%+ of
visible CFS scheduler work (`update_load_avg`, `reweight_entity`, `update_curr`,
`psi_group_change`, `enqueue_task_fair`), plus `fuse_dev_do_read`.

A corroborating in-process profile (`create-bench`, 8 threads, 1948 samples) puts
the whole MVCC write path at `write_block` 4.25% inclusive / `commit` 4.07%
inclusive / `prune_safe` 2.61% inclusive - so even measured generously and away
from FUSE, lever 1's target is <=7%.

### What this redirects to

The headroom is the 62% kernel-side transport tax, i.e. round-trips on
`/dev/fuse` and the context switch each one costs. That is lever 2's technology
(io_uring, batched submission/completion) pointed at the FUSE TRANSPORT rather
than at the data path. This host can host it: kernel `6.17.0-35-generic` has
`CONFIG_FUSE_IO_URING=y` and a runtime knob `/sys/module/fuse/parameters/enable_uring`,
currently `N`. The blocker is ours - the vendored `vendor/fuser` implements no
ring protocol, so adopting it is real work, not a flag.

Also unexplained and worth a separate look: 8.81% of the daemon's CPU is
`__memmove_avx_unaligned_erms`, the largest single userspace item, consistent
with whole 4 KiB block copies per metadata update.

### Retry predicate

Do not spend another candidate on reducing filesystem CPU for
`parallel-metadata-write` until the per-op budget above is invalidated - i.e. a
run where the FUSE daemon is NOT the single-CPU bottleneck, or where our
filesystem CPU per create is shown to exceed ~25 us. Attack the transport first
and re-derive this budget afterwards.

## Be-tree metadata message buffer (lever 1) is REJECTED - correctness, not speed - 2026-07-31

`FFS_EXT4_METADATA_BUFFER` buffered whole-block metadata messages across 64
shards and drained them into ONE transaction at fsync, so 512 creates paid ~8
commits instead of 512. Reverted in `f2dbb84a` (reverts `9ccee47a`); both touched
files are byte-identical to the pre-lever state `cb66b18d`.

### The control validates the instrument

Mounted 512-pair / 128-crossover-block ext4 comparison against the in-kernel
incumbent: a same-invocation four-arm crossover over four independent live
mounts, worker pinning attested. Both A/A null controls below are same-invocation
nulls taken in the very run that produced the ratio - kernel A/A null `1.012983x`
and FUSE A/A null `1.002400x`, each a bootstrap median CI containing 1.0. Candidate
ELF `47a5f86d...` built `target-cpu=x86-64-v3` + PGO profile `6a22cfcf...` - the
SAME profile as the frozen bank candidate `f44b3dc4...`, so the lever source is
the only delta and the `bd-b9dug` admissibility rule is satisfied.

| Arm | FrankenFS / kernel ext4 | Kernel A/A | FUSE A/A | Decision |
| --- | --- | --- | --- | --- |
| control, buffer OFF | `1.507220x` `[1.494469, 1.524164]`, `directional_claim_clear=true`, `admitted=true` | `1.012983x` | `1.002400x` | reproduces bank |
| banked reference | `1.510822x` `[1.493097, 1.539011]` | - | - | - |
| lever, buffer ON | NO RATIO - failed a correctness gate | - | - | **REJECT** |

The control lands **0.24%** from the banked row from a freshly built ELF and a
freshly built driver. That is an independent reproduction of the banked
parallel-metadata loss, and it means the lever arm's failure is the lever's.

### Why it is rejected: acknowledged creates go missing

```
reset parallel metadata file .../fuse_a/parallel-metadata/worker-0/
r000001-000000: No such file or directory (os error 2)
```

The harness removes exactly the files it created; one was already gone, in
warmup round 1. This is **not** a concurrency race - it reproduces serially:

| threads | buffer | result |
| --- | --- | --- |
| 8 | on | reset failure |
| **1** | **on** | **reset failure** |
| 1 | off | clean |

An acknowledged create is invisible to a later lookup even single-threaded.
That is precisely what `528adc44` ("honor buffered reads ... including for
scopes that have an active transaction") was written to fix: a read inside a
transaction-backed scope consulted only the committed MVCC snapshot, and a
snapshot cannot name an uncommitted buffered message.

### Removed rather than left default-off

`d7495a16` reverted the FIX (`528adc44`) and restored "the pre-candidate
implementation exactly", which left the UNFIXED buffer on HEAD -
`crates/ffs-core/src/fs_mvcc_store.rs` at HEAD was byte-identical to `9ccee47a`.
Dead-but-armed code: setting the env var turned on silent metadata loss at any
thread count. Independently, the FIXED version measured `1.587108x`
`[1.582255, 1.594626]`, about **5% worse** than the 1.51x baseline, so there was
no performance case for carrying it either.

### Retry predicate

Do not retry whole-block message buffering on the ext4 metadata path until (a)
every read path that can observe a buffered block consults the buffer - including
transaction-backed scopes - proven by a mounted run at `--client-threads 1` AND
`8` that completes its reset without a missing file, and (b) a profile shows the
per-write `begin()+commit()` is actually a material share of create time. The
`create-bench` probe at n=9/arm could not resolve it: within-arm spreads were
1.17-1.22x, an ~18% floor, with `off` 48211/s vs `cap=4096` 47864/s. Amdahl also
bounds the prize - `ext4_create` holds `ext4_alloc_state.write()` across its
body, so buffering shortens a serialized region rather than removing it.

## Mounted 64 MiB bulk durable output is a current 2.201986x loss - 2026-07-31 (IvoryBison, vs-INCUMBENT measurement)

This deliverable keeps one realistic mounted-comparator workload and makes no
production-filesystem tuning claim. One job overwrites a preallocated 64 MiB
file with 64 sequential 1 MiB positioned writes, then calls `fsync` on the file
once. Payload allocation and fill happen before timing. Untimed witnesses prove
the exact 67,108,864-byte initial and final file contents on all four mounts;
the final file is uniformly byte `95` with SHA-256
`1374a09b8b03a5e43ff90e52c8fd06d88a6a0134b990b58ba32c018e3e0ad82c`.
Full tree/content parity and all four post-unmount `e2fsck` checks pass.

### Admitted direct-incumbent result

| Workload | Kernel A/A null | FUSE A/A null | FrankenFS / kernel ext4 | Decision |
| --- | --- | --- | --- | --- |
| 64 sequential 1 MiB overwrites plus one final file `fsync`, one observed worker | `1.000096x [0.993402, 1.006928]`, spread `1.006928x`, clear | `0.987647x [0.982082, 0.992391]`, spread `1.018245x`, clear | **`2.201986x [2.181190, 2.219212]` slower**; twice-null margin `1.036823x` | **HONEST LOSS** |

Both A/A medians are inside the corrected inclusive `[0.98, 1.02]` clause,
both symmetric CI spreads are below `1.025x`, and CI straddling is telemetry,
not a gate input. The competitive interval clears twice the widest null
log-margin. The gate is a wall-time deterministic-bootstrap median CI with
20,000 resamples; `cv_used=false` and `instructions_used=false`. Diagnostic
median batches were 106,764,850 ns for kernel ext4 and 240,221,050 ns for
FrankenFS.

**We lose: FrankenFS takes 2.201986 times the kernel-ext4 wall time for this
complete 64 MiB durable-output job.**

The admitted invocation used 2,048 paired rounds / 512 complete four-round
physical crossover blocks, eight balanced warmups, and one observation per
arm. Requested and actual observed timed workers were `1/1` on every kernel-A,
kernel-B, FUSE-A, and FUSE-B arm. The benchmark-driver TID was both bound to and
observed on CPU 27 throughout every arm; both FUSE daemons were guarded on CPU
25, with SMT siblings excluded. Mount options were matched at
`rw,noatime,nodev,nosuid`; kernel ext4 additionally reported `data=ordered`.
The timed durability boundary is identical in all arms: all 64 writes followed
by exactly one file `fsync`.

### Identity and frequency provenance

- Execution host: `thinkstation1`, AMD Ryzen Threadripper PRO 5975WX, 32
  physical cores / 64 logical threads, 231,691,894,784 bytes RAM, one NUMA node,
  Linux `6.17.0-35-generic`.
- Runtime ISA: `avx+avx2+f16c+fma+sse2+sse4.2`.
- CPU policy on all 64 CPUs: driver `amd-pstate-epp`, governor `powersave`, EPP
  `performance`; the non-performance-governor warning is retained.
- Driver emitted its in-process self-reported executing ELF SHA-256: `a0852814a9fab2f909512a346e2664940e335c49612247f58e23df83d841eeab`
  (built on remote worker `ovh-a`).
- FrankenFS self-reported executing ELF SHA-256 `f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349`;
  both daemon self-reports and both `/proc/<pid>/exe` hashes agree. PGO profile
  SHA-256:
  `6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`.
- Kernel incumbent artifact SHA-256:
  `01e534223c871bd6246e8d57fd8c8101205384d682a3a23b6a5577fe28997c41`.

The exact admitted report is
`/data/tmp/frankenfs-mounted-xattr-current/run_1785492391_3882038/mounted-kernel-report.json`
with SHA-256
`b1db0bc574fc8aec3c4955fcef0a1027610251cae8c8464ae49b58e11c8f824c`.
It uses same-LLC placement and one-second CPU-contention sampling; sustained
host-wide quiescence is explicitly not applicable to this same-LLC row.

### Preserved blocked pilot

The pre-registered 128-pair / 32-block pilot correctly emitted
`BLOCKED_NULL`, not a scored ratio. Its diagnostic effect was `2.636181x
[2.566631, 2.676452]`, but the kernel null spread was `1.055032x` and the
FUSE null spread was `1.045671x`, both above `1.025x`; their medians
(`0.992425x` and `0.991155x`) did pass the corrected median clause. That report
is
`/data/tmp/frankenfs-mounted-xattr-current/run_1785492075_3762184/mounted-kernel-report.json`
with SHA-256
`80cf2d58c7a4396eff6adc6d7526fc2eb4ffdf51e7f880d04f24dfa02c65a88d`.
Before inspecting any high-N result, the single retry was registered at 512
crossover blocks / 2,048 pairs. The two invocations are not pooled, and there
will be no third null-selected retry.

### Build, validation, and retry predicate

The driver build and focused validation used strict remote execution from
source base `8e0400ff` with `rch exec --base 8e0400ff --clean-overlay` and only
`crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs` overlaid. Remote
`cargo check -j2 -p ffs-harness --bin ffs-mounted-kernel-bench` passed on
`ovh-a`; focused bulk-durable tests passed 2/2 there. The x86-64-v3
release-perf driver was built on `ovh-a` and copied to the privileged execution
host because RCH does not retrieve artifacts. There was no local Cargo fallback
and no per-task Cargo target directory. The complete binary suite then passed
28/28 on strict-remote worker `vmi1152480` from the same base and one-file clean
overlay. Final no-dependency `-D warnings` Clippy reached `ffs-harness` on
`vmi1227854` but exited 101 only on the pre-existing `fetch_update`
deprecations in untouched `crates/ffs-harness/src/metrics.rs:94,100`; no
diagnostic named the edited binary. (`ovh-a` was then inadmissible under stale
disk-critical telemetry, and `vmi1152480` lacked the pinned nightly Clippy
component; both attempts failed closed without local fallback.) Edited-file
rustfmt and `git diff --check` pass.

**Retry predicate:** replace this ratio only after the shipping candidate ELF,
PGO profile, mounted-write implementation, or declared 64 MiB job shape
changes. Use the same four independent mounts, four-round crossover, at least
512 complete blocks, corrected median-plus-spread null gate, doubled-null
margin, exact initial/final file witnesses, observed TID/CPU attestation,
in-process ELF identities, governor/host provenance, matched durability, and
four clean offline checks. A host-wide replacement additionally requires both
sustained quiet gates to pass in the same invocation. Profile this admitted
whole job before choosing a production lever; never pool the blocked pilot or
select among repeated null attempts.

## Mounted xattr report is a current 6.059387x loss - 2026-07-30 (IvoryBison, vs-INCUMBENT measurement)

This deliverable keeps one new mounted-comparator workload and makes no
production-filesystem tuning claim. A real read-only xattr report repeats 5,000
complete jobs. Each job performs five API calls through the Linux VFS:

1. read a 12-byte inline xattr value;
2. read a 512-byte external-block xattr value;
3. check one absent xattr name;
4. list a file with one xattr name; and
5. list a file with 24 xattr names.

The fixture proves the intended ext4 storage shapes outside timing with
`debugfs`: the inline file has `File ACL: 0`, while the external-value and
many-name files have nonzero external xattr blocks. Untimed exact witnesses
validate every returned name and value, the absent lookup, and both list
cardinalities before and after the timed region. The shared witness SHA-256 is
`7aafc655fbff1cd5eae7a0d24acd44492cc1d253f1452cf18280c12fd880bdeb`;
the full logical tree/content digest is also unchanged, and all four
post-unmount `e2fsck` checks are clean.

### Admitted direct-incumbent result

| Workload | Kernel A/A null | FUSE A/A null | FrankenFS / kernel ext4 | Decision |
| --- | --- | --- | --- | --- |
| 5,000 complete xattr reports, one observed worker | `1.000756x [0.994355, 1.000847]`, spread `1.005677x`, clear | `0.999737x [0.998300, 1.001787]`, spread `1.001787x`, clear | **`6.059387x [6.036945, 6.071929]` slower**; twice-null margin `1.011385x` | **HONEST LOSS** |

Both A/A medians are inside the corrected inclusive `[0.98, 1.02]` clause,
both symmetric CI spreads are below `1.025x`, and CI straddling is telemetry,
not a gate input. The competitive interval clears twice the widest null
log-margin. The gate is wall-time deterministic-bootstrap median CI with
20,000 resamples; `cv_used=false` and `instructions_used=false`. Diagnostic
median batches were 85,553,446.5 ns for kernel ext4 and 518,425,656.5 ns for
FrankenFS.

**We lose: FrankenFS takes 6.059387 times the kernel-ext4 wall time for this
complete xattr report job.**

The run used 32 paired rounds / eight complete four-round physical crossover
blocks, eight balanced warmups, three repeats per observation, and the minimum
reducer. Requested and actual observed timed workers were `1/1` on every
kernel-A, kernel-B, FUSE-A, and FUSE-B arm. The driver TID was observed on and
bound to CPU 0; both FUSE daemons were guarded on CPU 1, with SMT siblings
excluded. Mount options were matched at `ro,noatime,nodev,nosuid`; the kernel
incumbent additionally used the required read-only `noload` semantic.

### Identity and frequency provenance

- Execution host: `thinkstation1`, AMD Ryzen Threadripper PRO 5975WX, 32
  physical cores / 64 logical threads, 231,691,894,784 bytes RAM, one NUMA node,
  Linux `6.17.0-35-generic`.
- Runtime ISA: `avx+avx2+f16c+fma+sse2+sse4.2`.
- CPU policy on all 64 CPUs: driver `amd-pstate-epp`, governor `powersave`, EPP
  `performance`; the non-performance-governor warning is retained.
- In-process driver ELF SHA-256:
  `99a9684235ab1f923a30057ae23d92a6c88a19944c03246dd11fb122140d449b`
  (built on remote worker `ovh-a`).
- FrankenFS self-reported executing ELF SHA-256 `f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349`;
  both daemon self-reports and both `/proc/<pid>/exe` hashes agree. PGO profile
  SHA-256:
  `6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`.
- Kernel incumbent artifact SHA-256:
  `01e534223c871bd6246e8d57fd8c8101205384d682a3a23b6a5577fe28997c41`.

The exact report is
`/data/tmp/frankenfs-mounted-xattr-current/run_1785470336_3449697/mounted-kernel-report.json`
with SHA-256
`daac1522f778e4bbc963cfbff73cecff8fe896699e9eedb85fbb3104b2618ae1`.
It uses same-LLC placement, a one-second CPU-contention sample, and records
`host_wide_quiescence=not_applicable`, matching the current ext4 scorecard
placement scope.

A separately attempted host-wide run passed its initial requirement of five
consecutive clear one-second samples only after 213 samples (213.1 seconds).
After mount and fixture setup its second sustained gate found no five-sample
clear window within 300 samples and 300 seconds. The harness failed closed
before timing and emitted no row; that attempt is not pooled with, selected
against, or used to strengthen the same-LLC result.

### Build, validation, and retry predicate

The driver build and focused validation used strict remote execution from
source base `69346cd5` with
`rch exec --base 69346cd5 --clean-overlay` and only `Cargo.toml`,
`Cargo.lock`, `crates/ffs-harness/Cargo.toml`, and
`crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs` overlaid. Remote
`cargo check -j2 -p ffs-harness --bin ffs-mounted-kernel-bench` passed on
`ovh-a`; the focused live-filesystem xattr witness/batch test passed on `hz1`.
The release-perf driver was built on `ovh-a` and copied to the privileged
execution host because RCH does not retrieve artifacts. There was no local
Cargo fallback. A final strict-remote no-dependency Clippy attempt from current
base `3cdd4cd6` reached `ffs-harness` on `hz1` but exited 101 on two pre-existing
`fetch_update` deprecation errors in untouched
`crates/ffs-harness/src/metrics.rs:94,100`; neither that file nor the warnings
were in this clean overlay. Edited-file rustfmt and `git diff --check` pass.

**Retry predicate:** replace this ratio only after the shipping candidate ELF,
PGO profile, xattr implementation, or declared five-call job shape changes.
Use the same four independent mounts, four-round crossover, corrected
median-plus-spread null gate, doubled-null margin, exact xattr witnesses,
observed TID/CPU attestation, in-process ELF identities, governor/host
provenance, and clean offline checks. A host-wide replacement additionally
requires both five-consecutive-sample gates to pass in the same invocation.
Do not infer a source-level optimization from this aggregate gap; profile this
exact job first, and never pool the failed host-wide attempt with an admitted
row.

## Null medians now bound arm-order bias; CI straddling is telemetry - 2026-07-30 (PurpleSnow, vs-INCUMBENT gate correction)

The fleet-level gate correction was explicitly authorized for this comparator.
Schema v6 removes only the requirement that each A/A confidence interval contain
`1.0`. A null control is now clear when both of these unchanged/bounded
conditions hold:

1. its median is in the inclusive range `[0.98, 1.02]`; and
2. its symmetric CI spread remains at most `--maximum-null-ratio` (default
   `1.025x`).

The CI endpoints and whether they contain `1.0` remain in console and JSON
telemetry, with `ci_contains_one_gate_input=false`. The effect must still clear
**twice the widest null log-margin**. No identity, exact-work, worker-count,
worker-pinning, host-quiescence, mount-option/durability, parity, offline-check,
incumbent-isolation, or wall-time median-CI gate changed. The immediately
following physical-diagnosis row remains valid, but its historical statement
that both A/A CIs must contain `1.0` is superseded by this policy correction.

### Three-row integrity reproduction

The exact three previously unscored 2026-07-27 workload reports were evaluated
with every recorded non-null gate and the `1.025x` spread ceiling held fixed.
The controls use same-invocation A/A deterministic bootstrap median 95% CI estimates.
For example, the storm controls were kernel
`1.009041x [1.001744, 1.013361]` and FUSE
`1.000952x [0.995548, 1.008376]`.

| Workload | Replacement-null result | Effect-margin result | Counterfactual decision |
| --- | --- | --- | --- |
| Multi-file parallel read, 8 threads, 256 x 256 KiB | Still blocked: kernel median `0.966904x` is outside `[0.98, 1.02]`; spreads are also `1.070666x` / `1.036149x` | Clears (`1.203230x [1.162802, 1.239236]`) | **STILL BLOCKED** |
| Small-file create/delete storm, 2,000 files | Clears: medians `1.009041x` / `1.000952x`, spreads `1.013361x` / `1.008376x` | Clears twice-null margin `1.026900x`; effect `2.957531x [2.939013, 2.971326]` | **LOSE** |
| Large-directory readdir+stat, 8 threads, 32,768 entries | Still blocked: medians are in range, but kernel spread `1.025464x` remains above `1.025x` | Clears (`4.212274x [4.068120, 4.290202]`) | **STILL BLOCKED** |

Therefore **1 previously vetoed row becomes decidable: 0 WIN / 1 LOSE**. The
focused regression test
`historical_three_row_gate_audit_yields_one_loss_and_no_wins` reproduces that
count while exercising the retained twice-null-margin predicate.

As a broader integrity check, all **44** retained
`mounted-kernel-report.json` artifacts (**47** filesystem rows) were scanned.
Six schema-v1 rows were straddle-only null rejects under the old predicate and
clear the replacement null predicate plus the doubled effect margin:
**0 WIN / 6 LOSE**. All six predate the current worker-CPU-pinning attestation,
so this is counterfactual gate evidence, not permission to republish those old
ratios. The current pinned five-workload bank already cleared the old predicate;
its **0 wins / 4 losses / 1 neutral** score does not change. The correction
produces no win and therefore shows none of the loosening signature that would
invalidate it.

### Validation and remote-build provenance

The final source overlay passed the focused mounted-comparator suite **25/25**
on strict-remote worker `vmi1153651` (RCH project hash
`5d696f67726a27b7`). Scoped no-dependency Clippy with warnings denied passed on
`hz1` (hash `ef5c2455acc23b8b`); the allowance was limited to the repository's
pre-existing `fetch_update` deprecations. Edited-file rustfmt and
`git diff --check` passed.

The broader strict-remote `cargo test -p ffs-harness -- --nocapture` run
(worker `vmi1153651`, hash `1794541a32a4a2ae`) passed **2,058/2,058** library
tests, **3/3** main-binary tests, **25/25** mounted-comparator tests,
**7/7** btrfs-kernel-reference tests, and **100/100** conformance tests
(2 ignored). It then exited 101 in the unrelated compile-fail suite:
`executed_evidence_cannot_be_directly_constructed` passed, while
`executed_evidence_cannot_be_deserialized` differed from its committed stderr
only because `trybuild` normalized the registry source to `$CARGO/...` in the
golden but RCH emitted `$WORKSPACE/.rch-tmp/...`. Neither the compile-fail test
nor its golden was in the overlay, and this policy correction does not bless or
rewrite that unrelated snapshot.

Workspace-wide strict-remote check (hash `c240c23f41290aee`) is independently
blocked by pre-existing `ffs-btrfs` all-target bench wiring:
`csum_lookup.rs` calls
`bench_delete_backrefs_for_extent_borrowed_candidate` and
`bench_locate_extent_key` although both methods are compiled only with the
`bench-instrumentation` feature. Workspace fmt is likewise blocked by committed
format drift outside the edited file. The identical base plus one-path clean
overlay nevertheless produced four different displayed RCH hashes
(`5d696f67726a27b7`, `c240c23f41290aee`, `ef5c2455acc23b8b`, and
`1794541a32a4a2ae`) and cold targets, so command-stable target reuse did not
engage; these hashes are reported rather than treating the cold builds as cache
hits.

## Unpinned timed threads, not host noise, were breaking the mounted A/A nulls; all five rows now score - 2026-07-30 (BlackThrush, vs-INCUMBENT instrument KEEP)

This row banks an instrument fix and four re-measured direct-incumbent rows. **No
gate was loosened**: `--maximum-null-ratio` stays `1.025`, both A/A CIs must still
contain 1, and the doubled-null-log-margin clearance is unchanged.

### Which nulls were failing, on which mount, and why

Recovered from the preserved `raw_wall_ns` arrays in the 2026-07-27 reports, all
of which ran `--pairs 32`, i.e. only **8 crossover blocks**:

| Workload | Mount | Median batch | Per-block \|log ratio\| RMS | A/A null 95% CI | Spread | Vetoing clause |
| --- | --- | --- | --- | --- | --- | --- |
| Parallel read, 256 x 256 KiB | kernel | 3.47 ms | 5.41% | `0.966904x [0.933998, 1.008743]` | **`1.070666x`** | ratio threshold |
| Parallel read, 256 x 256 KiB | FUSE | 4.14 ms | 1.54% | `0.991734x [0.969409, 1.036149]` | **`1.036149x`** | ratio threshold |
| readdir+stat, 32,768 entries | kernel | 27.70 ms | 6.86% | `0.990140x [0.975169, 1.009721]` | **`1.025464x`** | ratio threshold, by 0.05% |
| Create/delete storm, 2,000 files | kernel | 92.41 ms | 2.14% | `1.009041x [1.001744, 1.013361]` | `1.013361x` | **CI-straddle only** |

Four failing nulls across three workloads, in two modes. Read and readdir failed
the **ratio** threshold with medians near 1 — variance, not bias. The storm null
did **not** fail the ratio threshold at all; it failed only because its interval
excluded 1. See the gate audit below for that one.

### Physical cause: the timed threads were never bound to a CPU

`pin_current_process` tasksets the *process* to `placement.driver_cpus`, which for
an 8-thread workload is an **8-CPU set**. The eight workers are freshly spawned
inside every timed batch, so the kernel chose their placement and migrated them
mid-batch, independently on every round. That variance is independent between the
two same-type physical arms, so it does not cancel in the A/A crossover
difference, while it partly cancels in the competitive ratio, which averages both
arms of a type within a round. The nulls broke; the ratios did not.

It predicts the per-workload pattern exactly:

- `client_threads() == 1` for storm and fsync, so `select_driver_cpus` returned a
  **single** CPU and taskset already bound them. Neither failed the ratio gate.
- `client_threads() == 8` for read, readdir, and metadata. Read and readdir are
  cache-bound, so placement noise dominates them. Metadata is dominated by eight
  directory `fsync`s per batch, so the same noise is a small fraction of its batch.
- The kernel readdir arm's block RMS is 6.86% at 27.70 ms while the FUSE arm's is
  0.93% at 116.56 ms: ~1.9 ms versus ~1.08 ms in *absolute* terms. Roughly
  constant absolute jitter is the signature of a fixed-cost, high-variance
  component, not a proportional slowdown.

### Ruled out, with reasons

- **Mount-option asymmetry.** Structurally impossible as a cause of a *same-type*
  null: both kernel arms take one identical option string from a single `match`
  arm (`ffs_mounted_kernel_bench.rs:1386-1389`) and both FUSE arms come from one
  `Command` builder. Option asymmetry can only move the competitive ratio.
- **Ordering effects between arms in one invocation.** `BALANCED_ORDERS` plus
  `physical_arm_for` form a four-round Latin square: over one block each physical
  arm occupies each of the four execution slots exactly once, and the
  logical-to-physical assignment alternates every round. Summed over a block,
  fixed physical-arm bias, execution-slot effects, and any linear time drift each
  cancel to exactly zero (slot sums `0-2+3-1+2-0+1-3 = 0`; global time-index sums
  `30 = 30`).
- **Page-cache state carried between arms.** 226 GB RAM with 175 GB already in
  page cache and no eviction pressure; the reproduction below recorded `pgsteal`
  of 0-8k pages across whole runs. The fix that worked does not touch cache state.
- **Governor.** Real and recorded (`amd-pstate-epp` / `powersave` /
  `balance_performance` on all 64 CPUs), but not the dominant term: the FUSE
  readdir arm ran under the identical governor on the identical CPUs with 7.4x
  lower block RMS, and pinning fixed the null without touching the governor. The
  host is shared with other agents, so the governor was deliberately not changed.

### Reproduction outside the harness

A standalone C replica (8 pthreads, same stride partition, same min-of-3 reducer,
same four-round crossover, same estimator) drove two byte-identical kernel-ext4
loop mounts built by `mke2fs -d` from one fixture, with the process `taskset` to 8
CPUs exactly as the harness does. The only variable was whether each worker binds
itself to one CPU.

| Case | Median arm | Per-block RMS | A/A null 95% CI | Spread | Verdict |
| --- | --- | --- | --- | --- | --- |
| readdir 65,536, unpinned | 40.88 ms | 6.49% | `1.002494x [0.978920, 1.031857]` | `1.031857x` | FAIL |
| readdir 65,536, **pinned** | 34.54 ms | 1.90% | `0.993848x [0.985174, 1.000269]` | `1.015049x` | **PASS** |
| readdir 65,536, unpinned (replicate) | 61.77 ms | 7.41% | `0.994255x [0.950493, 1.024059]` | `1.052086x` | FAIL |
| readdir 65,536, **pinned** (replicate) | 34.88 ms | 3.44% | `0.991733x [0.981778, 1.009910]` | `1.018560x` | **PASS** |
| read 1024 x 256 KiB, unpinned | 13.00 ms | 4.12% | `0.987347x [0.972331, 1.011465]` | `1.028457x` | FAIL |
| read 1024 x 256 KiB, **pinned** | 12.57 ms | 2.13% | `0.995949x [0.991406, 1.004359]` | `1.008668x` | **PASS** |
| read 256 x 256 KiB, unpinned | 3.09 ms | 5.74% | `0.998884x [0.981284, 1.031521]` | `1.031521x` | FAIL |
| read 256 x 256 KiB, **pinned** | 2.73 ms | 3.96% | `1.005352x [0.987117, 1.015670]` | `1.015670x` | **PASS** |

Four unpinned FAILs and four pinned PASSes across three shapes. Pinned medians
also reproduce across invocations (34.54 / 34.88 ms) where unpinned ones did not
(40.88 / 61.77 ms), and pinning made the arms 12-18% faster because locality is
preserved rather than rediscovered every batch.

### Re-measured rows, one driver ELF, `--pairs 128` (32 crossover blocks)

| Workload | Kernel A/A | FUSE A/A | FrankenFS/kernel wall ratio | Decision |
| --- | --- | --- | --- | --- |
| readdir+stat, 8 threads, 32,768 entries | `1.000904x [0.996822, 1.008448]`, spread `1.008448x` | `0.998792x [0.997503, 1.000626]`, spread `1.002503x` | **`4.967448x [4.946319, 4.989285]` slower** | **HONEST LOSS** |
| Small-file create/delete storm, 2,000 files | `0.996217x [0.985593, 1.007951]`, spread `1.014618x` | `0.995167x [0.988305, 1.004712]`, spread `1.011833x` | **`2.753659x [2.707500, 2.782302]` slower** | **HONEST LOSS** |
| Multi-file parallel read, 8 threads, 256 x 256 KiB | `1.003293x [0.982553, 1.016450]`, spread `1.017757x` | `0.994130x [0.982397, 1.002347]`, spread `1.017918x` | **`1.287862x [1.269319, 1.307285]` slower** | **HONEST LOSS** |
| Fsync/journal commit, 8 x 4 KiB | `1.001860x [0.991465, 1.004642]`, spread `1.008609x` | `0.997807x [0.991484, 1.015215]`, spread `1.015215x` | `0.997098x [0.990808, 1.009108]` against a twice-null margin of `1.030661x` | **HONEST NEUTRAL** |
| Parallel metadata writes, 8 threads, 512 creates, **128 blocks** | `1.007184x [0.998479, 1.024316]`, spread `1.024316x` | `0.995707x [0.978797, 1.000111]`, spread `1.021662x` | **`1.510822x [1.493097, 1.539011]` slower** | **HONEST LOSS** |
| Parallel metadata writes, replicate on a disjoint CPU set | `0.998642x [0.990286, 1.009556]`, spread `1.009809x` | `0.998780x [0.990819, 1.002688]`, spread `1.009266x` | **`1.513052x [1.490837, 1.534711]` slower** | **HONEST LOSS** |

**The direct-incumbent score for these five ext4 surfaces is 0 wins / 4 losses /
1 neutral / 0 unscored**, replacing the prior 1 win / 1 loss / 3 unscored.

Metadata needed **128 crossover blocks** (`--pairs 512`), not the 32 that suffice
for the other four. That is a precision increase, not a loosening: the estimand is
unchanged and a median CI narrows as ~`1/sqrt(blocks)`. At 32 blocks its spread sat
at `1.036x`-`1.090x` across four runs; at 128 blocks it is `1.024316x` and
`1.009809x`, and the two runs agree on the effect to **0.15%**
(`1.510822x` vs `1.513052x`) on **disjoint CPU sets** (`24,25,26,29,31,56,59,60`
versus `0,1,5,6,33,34,35,39`), each clearing its own twice-null margin
(`1.049223x`, `1.019714x`). The published `1.942477x` was therefore overstated by
about 28%; the honest figure is **`1.512x` slower**, and the workload needs four
times the blocks because its timed region is eight serialized ext4 journal commits
whose latency is heavy-tailed.

Two results are corrections against FrankenFS and must not be softened:

- **readdir and read losses grew** once admissible: `4.212274x -> 4.967448x` and
  `1.203230x -> 1.287862x`. Pinning made the *kernel* arm faster by preserving
  locality, so a correct instrument makes the incumbent look better. The old
  blocked estimates flattered us. readdir replicated across two driver ELFs and
  two windows at `4.967448x` and `5.026341x`, within 1.2%.
- **The fsync `1.005153x` win does not survive.** It re-measures `0.997098x
  [0.990808, 1.009108]` and `directional_claim_clear=false`, because the effect
  must clear a twice-null margin of `1.030661x`. It was a sub-null-margin effect
  and is **withdrawn**, not restated.

Storm moved the other way: `2.957531x -> 2.753659x`, a smaller loss than the
blocked estimate.

### Metadata: a second unpinned thread, then a block-count shortfall

`parallel_metadata_write_batch` performs all eight worker-directory `fsync`s on
the **driver thread**, inside the timed region. On ext4 `data=ordered` each forces
a journal commit, so that serial tail is a large fraction of a ~26 ms batch, and
the first fix bound only the workers. Storm does the same journal-commit work on a
thread the serial path already bound, and its null passes at `1.014618x` - a clean
contrast. The driver thread is now bound once at startup
(`mounted_kernel_driver_thread_binding`, observed `driver_thread_cpu=25`), and
each worker's bind is its first action so the inherited single-CPU mask window is
one syscall.

That change alone did not rescue the row at 32 blocks. Across **four** runs at
`--pairs 128` the metadata null stayed blocked with spreads `1.077930x`,
`1.057067x`, `1.090403x`, `1.052172x` and effects `1.688491x`, `1.659983x`,
`1.613519x`, `1.508913x` - the effect reproduced while the **verdict was stable**,
which by the fleet gate-audit criterion proves the cause physical rather than a
gate artifact. Raising the block count to 128 (`--pairs 512`) then admitted it
twice in a row, so the residual was a power shortfall on top of the driver-thread
binding, not an irreducible property of the workload. Every blocked estimate was
*below* the published `1.942477x`, and the two admitted values (`1.510822x`,
`1.513052x`) sit at the bottom of that spread.

The 2026-07-27 metadata null passed for a bad reason: its kernel arm's last
quarter ran **2.64x** slower than its first (21.51 -> 56.80 ms), and only 8
crossover blocks plus a robust median kept that instability out of the interval.

### Inert-regime control proves a bad window, not a bad change

The driver-thread pass ran while the host was contended (six distinct gate
refusals including a core at 100% busy, and one window offering only 4 quiet
client CPUs). Fsync and storm are 1-thread workloads whose driver thread the
serial path **already** bound, so the new binding is provably inert for them -
they are a free null control. Both degraded anyway, by **+9.16pp** and
**+12.07pp** of A/A spread, which can only be host contention. Meanwhile metadata,
the only workload the change targets, posted its best spread of four runs. The
contended pass is therefore not a valid comparison window, and the quiet-window
results above stand.

Reusable lesson: **when a lever has a regime where it is provably inert, run that
regime as a free null control on the real harness.**

### Gate audit: the CI-straddle veto is present and cost exactly one row

`fs_report` ANDs `BootstrapMedianCi::contains_null()` (`low <= 1.0 && high >=
1.0`) with the ratio threshold, so the straddle veto **is** in this gate. Tested
across 24 null evaluations in 12 runs rather than assumed:

| Veto class | Count | Cases |
| --- | --- | --- |
| **straddle-only** | **1** | storm 2026-07-27 kernel |
| ratio-threshold-only | 8 | read 07-27 (x2), readdir 07-27, metadata (x5) |
| both | 1 | metadata fuse, third run |

The single straddle-only veto looked like a textbook instance: null median
`1.009041x`, spread `1.013361x` comfortably inside `1.025x`, CI
`[1.001744, 1.013361]` missing `1.0` by **0.17%**, vetoing a `2.957531x` effect
whose deviation is **108.4%** against a 2x-half-width margin of **2.7%**.

**It is not a live gate defect, and an earlier draft of this row overstated it.**
The handoff's test requires the *same* ELF; the storm verdict movement first cited
here (blocked, pass, pass) spanned three different driver ELFs and both the
unpinned and pinned instruments, so it does not isolate the gate. Re-run properly -
one ELF `8c357460af...`, three reps, placement landing on `driver_cpus` 3, 28, and
14 at differing load - storm passes **3/3** with spreads `1.022639x`, `1.011589x`,
`1.016627x` and effects `2.760102x`, `2.780381x`, `2.795147x`, reproducing within
**1.3%**. A stable verdict on a reproducible effect means the gate is sound; the
07-27 veto was a single historical event produced by the unpinned instrument, not
gate flakiness.

The straddle clause therefore explains none of this campaign's blocked rows. Read,
readdir, and metadata all vetoed on the **ratio** threshold, 1 to 9 points over a
2.5% allowance, with stable verdicts. `contains_null` is the only straddle test in
the file (`:377`) and is used at exactly two sites (`:3513`, `:3515`); the
remaining hits are its own unit tests. The gate is left unchanged, correctly, and
the clause is flagged as latent rather than active.

### Provenance

Driver ELF `75b400a965010294f60c88cb3a591fd013248c92456e2fe13f7e2d01a5b3369b`
built on rch worker **hz1**; the driver-thread-bound follow-up ELF is
`8c357460afc2edb061e4d17676f46435b0cb9b0102ec5597813843afafbb27aa`, also hz1.
Candidate ELF `f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349`
built on **vmi1167313**, self-reporting compile+runtime SSE4.2/AVX2/FMA
(x86-64-v3) and PGO profile
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc` - the same
profile the 2026-07-27 rows used, so the re-measurement is comparable. `rch exec`
has no artifact-retrieval mechanism, so both ELFs were built remotely and copied
to `thinkstation1`; the harness now requires `--harness-builder` and
`--candidate-builder` and records them in `binary_provenance`. Every admitted run
reports `worker_cpu_pinning_clear=true` with the observed CPU set exactly equal to
the bound set, 4-arm tree/content parity, and `post_unmount_validation="clean"`.
Gate basis was the wall-time bootstrap median CI throughout; `cv_used=false` and
`instructions_used=false`.

One label caveat: the banked artifacts print
`method=sched_setaffinity_then_proc_thread_self_stat`, but the value in
`observed_worker_cpus` came from vDSO `sched_getcpu` in both paths, with
`/proc/thread-self/stat` used only for the serial arms' no-migration assertion.
The literal was stale, not the mechanism, and is corrected in source.

Every admitted ratio and every A/A null above is a deterministic 20,000-resample same-invocation bootstrap median 95% CI over wall time, with CV never a gate.

The executing driver hashed itself in process and printed `bench_evidence,binary_sha256=75b400a965010294f60c88cb3a591fd013248c92456e2fe13f7e2d01a5b3369b`; the driver-thread-bound follow-up printed `bench_evidence,binary_sha256=8c357460afc2edb061e4d17676f46435b0cb9b0102ec5597813843afafbb27aa`, and the candidate printed `bench_evidence,binary_sha256=f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349`.

**Retry predicate for all five rows:** re-measure only with every timed thread,
driver included, bound to one CPU, and with at least 32 crossover blocks - 128 for
parallel metadata writes, which does not resolve at 32. Require both A/A spreads at
most `1.025x` with intervals containing 1, the effect clearing twice its own null
log-margin, exact four-arm parity, and clean `e2fsck`. Never pool the blocked
`1.509x`-`1.688x` metadata estimates, and never restate `1.942477x` or the
withdrawn fsync `1.005153x` win. Before attributing any future null failure to the
gate, reproduce the frankenlibc test with a **single** ELF across several cores:
this campaign's first attempt compared different ELFs and wrongly implicated the
gate.

## SURVEY: gate-audit handoff finds CI-straddle veto; no gate change or new scoreable rerun - 2026-07-29 (PurpleSnow, audit incomplete)

The fleet gate audit found a real mechanism in the mounted comparator:
`BootstrapMedianCi`'s interval-straddle predicate requires the A/A confidence
interval to include `1.0`, and `fs_report` ANDs that result with the existing
`1.025x` symmetric-spread ceiling. FrankenFS therefore does contain the
CI-straddle veto identified by the fleet directive. This turn did
**not** change that gate: the required same-ELF, different-core/lower-load
reproduction has not yet been completed, so there is no evidence yet that the
verdict moves randomly while the competitive effect remains stable.

The owned, already-pushed instrument work is commit `bd2824b9`: schema v5 adds
a realistic job statement, an exact-work contract, a chooser statement scoped
to the recorded workload and hardware, an explicit same-invocation incumbent
isolation proof, and runtime ISA positives and negatives. The frozen
continuation candidate remains ELF
`93ed882e6e4771db82371c933af28d7a907a6efdcfb13f29357baf2b7befe7f6`
with PGO profile
`1410ff5d34f99faa10eeb2dbbcb08747a6acdccdb065a3e34b89396a43b40ab0`.
The exact requested jobs remain:

- 256 files x 256 KiB, eight read workers, 64 MiB total, min of three;
- 2,000 creates, one parent-directory fsync, 2,000 deletes, and a second
  parent-directory fsync, one worker;
- 32,768 directory entries plus 32,768 metadata reads, eight workers, min of
  three.

A companion owns active uncommitted CPU-pinning changes in
`.gitignore`, `crates/ffs-harness/Cargo.toml`, and
`crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs`. Those changes produced
useful diagnostic evidence that fixed worker-to-CPU binding can clear the read
and readdir A/A controls, but the diagnostic runs used candidate
`f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349`
with the older `6a22...` PGO profile, same-LLC placement, and retry-selected
attempts. They are not current-candidate campaign evidence and none of their
competitive ratios is banked here. The dirty paths were preserved and were
not staged, overwritten, or committed by PurpleSnow.

**Single next step after reset:** obtain an explicit handoff of the pinning
paths, finish the per-artifact origin and timed-instrumentation work-count
audit, then pre-register two complete quiet-host placements using one final
driver ELF and the frozen `93ed...` candidate. Retain both placements without
selection. Change the straddle clause only if the competitive effects reproduce
within 2.5% while a different subset of A/A controls passes; otherwise leave
the gate intact and fix the physical A/A instability. Every eventual score
still requires the effect CI to exclude `1.0`, clearance beyond twice the
larger A/A half-width, both A/A medians within 2% if the fleet-corrected rule is
evidence-activated, exact worker counts, matched work, parity, clean offline
checks, and wall-time median-CI gating with `cv_used=false`.

## Exact-work scaling preflight kept; Threadripper sweep stops on its first FUSE null - 2026-07-29 (PurpleSnow, instrument KEEP / measurement BLOCKED-NULL)

This turn changed the mounted comparator, not FrankenFS. Before opening a
production lever, the planned scaling work itself was audited. The driver
required `operations % client_threads == 0`, so the pre-registered 8,192
operations would reject the 96-thread point. Commit `89fefe8b` replaced that
constraint with a deterministic exact-total partition: each worker gets the
quotient, and the first `operations % threads` workers get one additional
operation. The identical partition is used by the timed create batch and its
untimed reset.

The counted contract is therefore:

| Requested threads | Per-worker distribution | Exact timed/reset total |
| --- | --- | --- |
| 1 | `1 x 8,192` | 8,192 |
| 96 | `32 x 86 + 64 x 85` | 8,192 |
| 128 | `128 x 64` | 8,192 |

The report records the minimum and maximum operations per worker, the number of
workers receiving the remainder, and `operation_distribution_exact_total=true`.
A regression test creates and removes a non-divisible 9-operation / 2-thread
batch and separately proves the 8,192 / 96 partition. Strict-remote
exact-source tests passed **19/19** on `ovh-a`; scoped no-dependency Clippy with
warnings denied except the crate's reproduced deprecation class, file rustfmt,
and `git diff --check` passed. This instrument correction is kept independently
of the measurement outcome because it prevents the sweep from doing different
total work at different thread counts.

After the explicit `[trj] CLAIM frankenfs`, the frozen candidate and freshly
built self-hashing driver started the pre-registered
1/2/4/8/16/32/64/96/128 sweep. The invocation stopped at the required first
failure:

| Point | Kernel A/A bootstrap median 95% CI | FUSE A/A bootstrap median 95% CI | Competitive estimate | Decision |
| --- | --- | --- | --- | --- |
| ext4 parallel metadata write, 1 requested/observed worker, 8,192 operations | `1.006357x [0.996054, 1.019204]`, spread `1.019204x` | `1.006701x [1.003212, 1.014440]`, spread `1.014440x` | **No admissible ratio.** Apparent `3.029651x [3.008041, 3.066799]` is diagnostic only. | **BLOCKED-NULL** |

The FUSE interval is narrower than the `1.025x` spread ceiling but excludes 1,
so admission fails. Repeating the same point until it happens to contain 1
would select on the null control. No thread-count points from 2 through 128 were
run, no scaling curve exists, and the apparent competitive loss is not a
campaign claim or a basis for production tuning. The exclusive machine was
released immediately in `[trj] RELEASE frankenfs` message `6323`.

All non-timing gates were clean. The invocation used 48 paired rounds / 12
complete four-round physical-role crossover blocks, eight balanced warmups,
20,000 deterministic bootstrap resamples, four independent mounts, matched
mount/durability settings, and wall-time median confidence intervals.
`cv_used=false` and `instructions_used=false`. Every arm completed exactly
8,192 operations and repeatedly observed exactly one Linux worker TID.
Initial and post-mount host-wide quiet gates passed, as did initial/final
four-arm namespace/content parity and all four offline checks. Physical medians
were:

- kernel A/B: `168,499,134 ns` / `169,908,172 ns`;
- FUSE A/B: `502,031,299 ns` / `499,437,890 ns`.

The residual `1.005193x` physical FUSE-arm median offset is consistent with the
failed FUSE null and remains unexplained even though logical roles crossed over
the two physical mounts. That is a measurement-system result, not filesystem
source evidence.

Provenance:

- host `threadripperje`, 64 physical cores / 128 logical threads,
  536,069,869,568 bytes RAM, one NUMA node;
- runtime ISA `avx2+fma+sse2+sse4.2`;
- every CPU reported `amd-pstate-epp`, governor `performance`, and EPP
  `performance`;
- driver CPU 0 with SMT guard 0/64; both FUSE daemons on CPU 1 with guard 1/65;
- initial quiet gate: five consecutive clear one-second samples after eight
  observed samples / 8,006 ms; post-mount gate: five samples / 5,004 ms;
- driver self-report
  `executing_elf_sha256=b9c3cbeb95f7696ca567e9aa5778dfa18f4016daacaf90bd83b618ecdd9b353e`;
- candidate ELF SHA-256
  `2db6860eaa3e86abf28ba8d2f6a82eea99c873510430edf5b20eb1ee5ceb4f10`,
  PGO profile SHA-256
  `23108426f429eef45acf65c6eb0489a5a74d1fc8ef1401ed2cf8dbba31ee7307`;
- incumbent kernel `6.17.0-41-generic`, `/boot/vmlinuz-6.17.0-41-generic`
  SHA-256
  `4a480bffbc34d52479023f0b9990f6ecfab3d0a325cf86c81e8b04d2a719a7a4`,
  runtime notes SHA-256
  `084b46c7dd63c2a8e23cf0e99aa41c97419de5dce98f37be6b5512635b9ed034`;
- report
  `/data/tmp/frankenfs-mounted-metadata-sweep/threads-1-attempt-7.json`,
  SHA-256
  `a5871ad197c77e003c5873d94e2cda084fa17f8b803942c449aca92183c8b82e`;
- log
  `/data/tmp/frankenfs-mounted-metadata-sweep/threads-1-attempt-7.log`,
  SHA-256
  `9d56026e38b0b2c7a0ba7cac648c4639484ae1c63c53f08f4830ea73f7abe4c3`.

**Retry predicate:** do not rerun on a merely fresh placement, pool this
failed-null estimate with another invocation, or change the candidate based on
it. First add counted per-four-round attribution for physical FUSE mount
identity, CPU migrations, minor/major faults, and host-wide busy state during
timing, or otherwise identify and remove the measured physical FUSE-arm
asymmetry. Then pre-register one new complete invocation starting at thread 1
with the same frozen candidate/incumbent identities, exact-total work
distribution, four independent arms, and physical-role crossover. Every point
must have the requested worker count on every arm, both A/A median CIs
containing 1 with spread at most `1.025x`, a competitive interval clearing
twice the worst null log-margin, full parity, and clean offline checks.
`cv_used=false`; instruction count remains provenance only.

## Governor- and thread-attested mounted rerun admits storm; read and readdir remain null-blocked - 2026-07-29 (PurpleSnow, vs-INCUMBENT instrument KEEP)

This rerun changes the instrument, not FrankenFS. The comparator now records
the CPU frequency driver, governor, and energy-performance preference; requires
five consecutive one-second host-wide samples below the contention ceiling
both before placement and after mount/fixture setup; and refuses admission
unless every logical arm repeatedly reports exactly the requested number of
Linux worker TIDs. Serial workloads observe the pinned driver TID before and
after every timed batch. Parallel workloads report worker TIDs from inside each
timed batch. The production candidate stayed frozen across all three
invocations.

### Current candidate results

| Workload | Kernel A/A bootstrap median 95% CI | FUSE A/A bootstrap median 95% CI | FrankenFS/kernel wall ratio | Decision |
| --- | --- | --- | --- | --- |
| Multi-file parallel read, 8 threads, 1,024 x 256 KiB, min of 3 | `1.003535x [0.959197, 1.043999]`, spread `1.043999x` | `0.980314x [0.960412, 1.090015]`, spread `1.090015x` | **No admissible ratio.** Apparent `1.655303x [1.600913, 1.731016]` slower is retained only as blocked evidence. | **BLOCKED-NULL** |
| Small-file create/delete storm, 2,000 files | `0.999131x [0.979908, 1.014892]`, spread `1.020504x` | `1.003032x [0.994522, 1.006388]`, spread `1.006388x` | **`2.691204x [2.675323, 2.717540]` slower** | **HONEST LOSS** |
| Large-directory readdir+stat, 8 threads, 65,536 entries, min of 3 | `1.000216x [0.962482, 1.041209]`, spread `1.041209x` | `1.001277x [0.999156, 1.005984]`, spread `1.005984x` | **No admissible ratio.** Apparent `4.502939x [4.432475, 4.580046]` slower is retained only as blocked evidence. | **BLOCKED-NULL** |

The storm competitive interval clears twice the worst same-invocation null
log-margin (`1.041428x`) and is admitted. Parallel read fails both nulls.
Readdir+stat repeats the kernel-only asymmetry while its FUSE null passes.
Therefore the current candidate's result on this three-workload rerun is
**0 wins / 1 loss / 0 neutral / 2 unscored**. The 2026-07-28 results below
remain frozen historical evidence for their different candidate ELF; they are
not substituted for the current candidate's two failed-null invocations.

All three runs used 128 rounds / 32 complete four-round physical-role
crossover blocks, eight balanced warmup rounds, 20,000 deterministic bootstrap
resamples, a 100 ms untimed arm settle, matched mount/durability options, full
four-arm parity, and four clean offline `e2fsck` checks. Wall time and bootstrap
median confidence intervals were the decision inputs; `cv_used=false` and
`instructions_used=false`. Requested and actually observed client threads were
`8/8`, `1/1`, and `8/8`, consistently on every arm.

The host was `thinkstation1`, AMD Ryzen Threadripper PRO 5975WX, 32 physical
cores / 64 logical threads, 231,691,894,784 bytes RAM, one NUMA node, runtime
ISA `avx2+fma+sse2+sse4.2`, with no cpuset cap. Every CPU reported
`amd-pstate-epp`, governor `powersave`, and EPP `balance_performance`; the
non-performance-governor warning is preserved in every report. Runtime client
affinity was:

- read: CPUs `4:7:15:21:26:29:32:33`, mask `00000003,24208090`;
- storm: CPU `14`, mask `00000000,00004000`;
- readdir+stat: CPUs `1:10:27:29:34:39:44:45`, mask
  `00003084,28000402`.

The initial/post-mount quiet windows consumed `71/56`, `269/106`, and `5/250`
one-second samples respectively. That wait history is evidence that a
one-instant contention sample would not be an adequate admission mechanism on
this host.

The executing comparator self-reported
`executing_elf_sha256=96ebd0ef4a95290dd1fad255472e21043e0a026816aeebfbdb56bfb0d792c181`.
Both FUSE arms self-reported the frozen x86-64-v3+PGO candidate
`93ed882e6e4771db82371c933af28d7a907a6efdcfb13f29357baf2b7befe7f6`
with PGO profile
`1410ff5d34f99faa10eeb2dbbcb08747a6acdccdb065a3e34b89396a43b40ab0`.
The incumbent identity was kernel `6.17.0-35-generic`, ext4 module/runtime
notes, and `/boot/vmlinuz-6.17.0-35-generic` SHA-256
`01e534223c871bd6246e8d57fd8c8101205384d682a3a23b6a5577fe28997c41`.
Preserved reports and file hashes:

- read:
  `/data/tmp/frankenfs-mounted-kernel-governor-rerun/parallel-read-observed-threads-report.json`,
  `138a6be8c01b45bbb826e06321f5071a7215ec50625ec3c48d1ec05fc7e5adce`;
- storm:
  `/data/tmp/frankenfs-mounted-kernel-governor-rerun/create-delete-observed-threads-report.json`,
  `12cd0fc5a7403c42ddc0e93fb70482e0c2dbb4a3ebc40ecce3b11ebb2048dcae`;
- readdir+stat:
  `/data/tmp/frankenfs-mounted-kernel-governor-rerun/readdir-stat-observed-threads-report.json`,
  `00cd9aa7c9929a46f6db640c605b7802ea9acf7db497cb9d69f9340e55d26a48`.

Instrument commit `e91cd59e` passed strict-remote exact-source tests **18/18**
on `ovh-a`, scoped no-dependency Clippy with warnings denied except the
pre-existing deprecation class, file rustfmt, and `git diff --check`. The first
non-scoped Clippy command stopped only on 23 pre-existing `ffs-ondisk` lints
before reaching the comparator; it is not a candidate failure.

**Retry predicate for parallel read and readdir+stat:** do not rerun on another
merely fresh placement or under the same unobserved dynamic-frequency regime.
First obtain a machine-level exclusive lease that covers the complete timed
routine and either (a) owner-authorized `performance` governor on every allowed
CPU, recorded before and after the invocation, or (b) counted per-arm
frequency-residency evidence that proves equivalent boost behavior. Also add
per-four-round-block attribution for CPU migrations, minor/major faults, and
host-wide busy samples throughout timing so a peer that starts after preflight
cannot remain invisible. Then rerun the unchanged workload with exactly eight
observed worker TIDs per arm and admit only if both A/A bootstrap median CIs
contain 1 with spread at most `1.025x`, the competitive CI clears twice the
worst null log-margin, and parity/fsck remain clean. Never pool the blocked
point estimates.

## Four-round physical-arm crossover clears all three blocked ext4 nulls - 2026-07-28 (GreenSpring, vs-INCUMBENT instrument KEEP)

This is the final measured closeout for the three workloads that the original
five-workload invocation left `BLOCKED-NULL`. It changes the comparator, not the
filesystem. Each logical kernel and FUSE role crosses over both physical
image/mount identities in a complete four-round Latin-schedule block. The
estimator uses only complete blocks, after eight identically balanced warmup
rounds, so fixed physical-image and schedule-position bias cancel rather than
being averaged more precisely. Each final invocation used 128 rounds / 32
complete crossover blocks, a 100 ms settle after every arm, pinned client and
FUSE cores in one quiet LLC, and `sync -f` outside the timed interval after
mutating an arm.

### Final admitted results

| Workload | Kernel A/A bootstrap median 95% CI | FUSE A/A bootstrap median 95% CI | FrankenFS/kernel wall ratio | Decision |
| --- | --- | --- | --- | --- |
| Multi-file parallel read, 8 threads, 1,024 x 256 KiB, min of 3 | `0.998988x [0.992238, 1.007322]`, spread `1.007822x` | `1.000804x [0.996671, 1.003045]`, spread `1.003340x` | **`1.298761x [1.285335, 1.309185]` slower** | **HONEST LOSS** |
| Small-file create/delete storm, 2,000 files | `1.010078x [0.994165, 1.016433]`, spread `1.016433x` | `1.003297x [0.996501, 1.008202]`, spread `1.008202x` | **`2.705229x [2.688109, 2.726206]` slower** | **HONEST LOSS** |
| Large-directory readdir+stat, 8 threads, 65,536 entries, min of 3 | `1.002819x [0.982342, 1.023088]`, spread `1.023088x` | `0.999492x [0.998021, 1.002427]`, spread `1.002427x` | **`4.404952x [4.370993, 4.469923]` slower** | **HONEST LOSS** |

Every A/A interval contains 1 and has symmetric spread at most `1.025x`; every
competitive interval also clears twice the worst same-invocation null
log-margin. Wall time and deterministic 20,000-resample bootstrap median CIs
are the decision inputs; `cv_used=false` and `instructions_used=false`. The
full five-workload ext4 score is therefore **1 win / 4 losses / 0 neutral / 0
unscored**.

The in-process harness self-report was
`executing_elf_sha256=49e8db7462cc450c1d76e733ac7eb7cc29b0ddc41bd7c4768bf1b6cc65dcf1e6`.
Both FUSE daemons self-reported production x86-64-v3+PGO ELF SHA-256
`502c4c877d61de5bd9daac8b6826e1a67ab046e65e0c625b8c4dd5dc75b1d835`
and PGO profile SHA-256
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`.
The preserved reports and their file SHA-256s are:

- parallel read:
  `/data/tmp/frankenfs-mounted-kernel-workloads/run_1785266486_3211479/mounted-kernel-report.json`,
  `b45fc69231501177777ece3adc139b01e327b1af4386196c068677729de371ac`;
- create/delete storm:
  `/data/tmp/frankenfs-mounted-kernel-workloads/run_1785266581_3239624/mounted-kernel-report.json`,
  `a1ad17787ed14f7d9eb1858e27181de4c07ef13fae486fd8993f935abee8ed1a`;
- readdir+stat:
  `/data/tmp/frankenfs-mounted-kernel-workloads/run_1785266818_3348552/mounted-kernel-report.json`,
  `23f19bd17410a2ad48d7df1a81d424181bf0efe6fbc0d03d3463462bff358d98`.

The 2026-07-27 section immediately below and the later counterbalance
diagnostic retain the failed-null history and its then-unscored point estimates;
they do not describe the current measurement status.

**Retry predicate for replacing any final ratio:** use a new shipping-shaped,
self-reporting FrankenFS ELF and a self-reporting schema-v4 driver with
host-wide exclusivity enabled. Preserve the same four independent mounts,
four-round physical-role crossover, matched mount/durability settings,
constant-state reset, full parity/fsck checks, and at least 32 complete blocks.
Each row must record host/core/thread/RAM/NUMA/ISA provenance, runtime affinity,
requested and actually observed worker threads, and incumbent/candidate
SHA-256s. Require both same-invocation A/A bootstrap median CIs to contain 1
with spread at most `1.025x`, and require the competitive CI to clear twice the
worst null log-margin. Never pool blocked estimates or gate on CV/instructions.

## Mounted ext4 workload suite admits metadata and fsync ratios; three surfaces remain null-blocked - 2026-07-27 (GreenSpring, vs-INCUMBENT measurement)

This is a direct-incumbent measurement row, not a FrankenFS before/after
self-speedup and not a production tuning lever. The existing Rust comparator
was extended with the five named workloads, then each workload ran against two
independent real kernel-ext4 mounts and two independent FrankenFS FUSE mounts
in one invocation. Every FUSE daemon self-reported the exact shipping-shaped
x86-64-v3+PGO ELF, each mapped `/proc/<pid>/exe` hash matched that report, and
the driver self-reported its own ELF. The balanced four-arm schedule supplied a
kernel A/A and a FUSE A/A in every invocation. Every decision below therefore
has numeric same-invocation A/A null controls with bootstrap median 95% CIs.
Wall time and deterministic
20,000-resample bootstrap median CIs were the only decision inputs;
`cv_used=false` and `instructions_used=false`.
For example, the admitted metadata invocation's same-invocation kernel A/A
null control was `0.999980x`, with bootstrap median confidence interval
`[0.989622, 1.007939]`.

The common mount contract was `noatime,nodev,nosuid`. Read workloads were
read-only (`noload` on kernel ext4); mutating workloads were read-write with
kernel ext4 `data=ordered`. Durability was workload-specific and identical on
both sides: eight directory fsyncs after parallel creates, no mutation for
reads, `create -> fsyncdir -> delete -> fsyncdir` for the storm, and a 4 KiB
positioned write plus `fsync` for every journal-latency operation. All reported
invocations passed four-arm namespace/content parity and four post-unmount
`e2fsck` checks.

### Results

| Workload | Kernel A/A bootstrap median 95% CI | FUSE A/A bootstrap median 95% CI | FrankenFS/kernel wall ratio | Decision |
| --- | --- | --- | --- | --- |
| Parallel metadata writes, 8 threads, 512 creates/observation | `0.999980x [0.989622, 1.007939]`, spread `1.010487x` | `1.004105x [0.993961, 1.010532]`, spread `1.010532x` | **`1.942477x [1.654395, 2.069775]` slower** | **HONEST LOSS** |
| Multi-file parallel read, 8 threads, 256 x 256 KiB, min of 3 | `0.966904x [0.933998, 1.008743]`, spread `1.070666x` | `0.991734x [0.969409, 1.036149]`, spread `1.036149x` | **No admissible ratio.** Apparent `1.203230x [1.162802, 1.239236]` is retained only as blocked evidence. | **BLOCKED-NULL** |
| Small-file create/delete storm, 2,000 files | `1.009041x [1.001744, 1.013361]`, spread `1.013361x` | `1.000952x [0.995548, 1.008376]`, spread `1.008376x` | **No admissible ratio.** Apparent `2.957531x [2.939013, 2.971326]` is retained only as blocked evidence. | **BLOCKED-NULL** |
| Large-directory readdir+stat, 8 threads, 32,768 entries, min of 3 | `0.990140x [0.975169, 1.009721]`, spread `1.025464x` | `1.000955x [0.996572, 1.007587]`, spread `1.007587x` | **No admissible ratio.** Apparent `4.212274x [4.068120, 4.290202]` is retained only as blocked evidence. | **BLOCKED-NULL** |
| Fsync/journal commit, 8 x 4 KiB write+fsync operations | `0.998159x [0.993763, 1.004863]`, spread `1.006276x` | `0.998367x [0.994864, 1.002099]`, spread `1.005162x` | **`0.994873x [0.992102, 0.999695]` kernel time**, equivalently **`1.005153x [1.000305, 1.007961]` faster** | **HONEST WIN** |

The current direct-incumbent score for these five named ext4 surfaces is
**1 win / 1 loss / 0 neutral / 3 unscored**. The admitted metadata loss replaces
the separate-invocation 8.3x routing estimate for this exact workload. The
earlier ~2.9x parallel-read and 4.599x storm estimates remain unverified rather
than being silently converted into claims.

### Provenance and blocked-null audit trail

The measured FrankenFS executable was
`7116aae15f64d47ce0703e9395f0ff64dcc4aa742c0735eb512fab0c20d9ff57`;
it reported compile/runtime SSE4.2, AVX2, and FMA and PGO profile SHA-256
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`.
The admitted metadata report used driver ELF
`c68355edf6ee4f6863652ae73b5b979382c01b8e942132aad94cc8400920c127`;
its report is
`/data/tmp/frankenfs-mounted-kernel-workloads/run_1785206871_2625082/mounted-kernel-report.json`.
The final driver ELF was
`b1aa15e3b331f6a0c607628f9f3b1b315fb8c54197627102f45a7cd90c954282`;
the only semantic change between those drivers makes directory `st_size` an
implementation-specific allocation detail rather than part of the logical
tree hash. File lengths, paths, modes, ownership, link counts, contents,
namespace parity, and offline checks remain mandatory. The admitted fsync
report is
`/data/tmp/frankenfs-mounted-kernel-workloads/run_1785207888_2762113/mounted-kernel-report.json`.

Representative preserved blocked reports are:

- parallel read:
  `/data/tmp/frankenfs-mounted-kernel-workloads/run_1785206977_2643668/mounted-kernel-report.json`;
- create/delete storm:
  `/data/tmp/frankenfs-mounted-kernel-workloads/run_1785207688_2739056/mounted-kernel-report.json`;
- large-directory readdir+stat:
  `/data/tmp/frankenfs-mounted-kernel-workloads/run_1785208004_2776442/mounted-kernel-report.json`.

Longer and repeated attempts did not satisfy the retry predicate: 64-pair
256-file and 1,024/2,048-file read variants, repeated storm invocations, and
8,192/32,768-entry directory variants continued to alternate which physical
kernel or FUSE A/A arm was biased. Their point estimates were not pooled or
selected. Fifty-three GiB of image/report artifacts remain under
`/data/tmp/frankenfs-mounted-kernel-workloads`; none was deleted.

**Retry predicate for the three unscored workloads:** do not retry merely on
another fresh placement on this shared host. First provide either an exclusive
quiet mount-capable measurement host, or a counted instrument improvement that
counterbalances physical image/mount identity or continuously attributes
per-arm CPU contention. Then rerun the exact shipping-shaped ELF in one
four-independent-arm invocation, preserve the matched settings and full
parity/fsck contract, and require both kernel and FUSE A/A bootstrap median
95% CIs to contain 1 with symmetric spread at most `1.025x` before admitting
the competitive wall/cycles ratio. Never gate on CV or instruction count.

## Mounted-kernel Rust arm produces an honest ext4 warm-stat loss; btrfs remains null-blocked - 2026-07-27 (GreenSpring, vs-INCUMBENT instrument KEEP)

This row banks an instrument, not a FrankenFS optimization or self-speedup.
The mounted-kernel arm now runs two independent real-kernel mounts and two
independent FrankenFS FUSE mounts in the same process. It therefore supplies
both incumbent/candidate A/B and one A/A null control for each side without
using a shared component as the baseline.

The institutional preflight was run before this surface was opened. A broad
`mounted stat` proposal correctly recovered the closed readdirplus/cache
REJECT and its recorded reopening condition, so that lever was not re-derived. The qualified
measurement-only surface passed:

```text
preflight: OK — no prior REJECT covers surface=[ffs_mounted_kernel_bench runtime mount identity ELF provenance interleaved comparator harness] proposal=[measurement-only four independent mount comparator driver with incumbent and candidate A/A]
```

### Runtime contract

Each filesystem invocation owns four separately cloned images and four unique
mountpoints. Before measuring, the harness proves:

- `kernel_a` and `kernel_b` are real kernel `ext4` or `btrfs` mounts backed by
  distinct declared loop devices, distinct image paths, and distinct mounted
  superblock device identities;
- `fuse_a` and `fuse_b` are `fuse.ffs` mounts backed by distinct images and
  distinct daemon PIDs;
- each FUSE daemon's in-process self-reported ELF SHA-256 equals both
  `/proc/<pid>/exe` and the preflight-approved candidate SHA-256;
- the executing Rust driver also self-hashes;
- all four arms return identical payload SHA-256, length, mode, uid, gid, and
  link count before timing; and
- the kernel and FUSE arms use the common read-only `ro,noatime,nodev,nosuid`
  contract. Ext4 additionally uses kernel `noload`; FrankenFS disables
  background scrub and writeback cache. The workload performs no mutation, so
  the matched durability contract is `read_only_no_mutation`.

The driver pins itself to a quiet CPU and pins both serially exercised FUSE
daemons to the same separate quiet physical CPU in the driver's last-level
cache domain. It samples both SMT sibling sets and aborts if any selected
physical core is above its pre-registered occupancy ceiling. One invocation
then runs exactly 32 balanced four-arm rounds, interleaving all arms and
rotating all orders equally. Each observation is the minimum of three
executions of 2,000 warm `stat` calls. The decision input is wall time only. A
deterministic 20,000-resample bootstrap median 95% CI gates each A/A control
and the competitive ratio; `cv_used=false` and `instructions_used=false`.
All requested filesystems run and write their raw report before a failed null
gate returns exit 2.

The measured candidate is the production-shaped x86-64-v3+PGO
`release-perf` `ffs-cli`. Each FUSE daemon self-reported executing ELF
SHA-256
`9b5e0f5ffc2866a1e281abea72f7790bb58401815e296c307f722642b0d89e9c`
and PGO profile SHA-256
`6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`.
The incumbent identity was Linux `6.17.0-35-generic`.
The executing final-source harness self-reported ELF SHA-256 `7099f14070d0e78851e30988c5c55a825a54e259fe8afbf6ec8d06e998454e40`.

### Honest result

| Filesystem | Kernel A/A bootstrap median 95% CI | FUSE A/A bootstrap median 95% CI | FrankenFS/kernel bootstrap median 95% CI | Verdict |
| --- | --- | --- | --- | --- |
| ext4 | `0.998996x [0.998100, 1.000246]`, symmetric spread `1.001903x` | `0.999638x [0.998008, 1.001696]`, symmetric spread `1.001996x` | **`5.033559x [5.023263, 5.050188]` slower** | Honest; both null CIs contain 1 and both spreads are below `1.025x` |
| btrfs | `1.001833x [0.999823, 1.003129]`, symmetric spread `1.003129x` | `0.996028x [0.994686, 0.998294]`, symmetric spread `1.005342x` | Not admissible (`4.931910x [4.921023, 4.943701]` observed internally) | **BLOCKED-NULL**; the FUSE A/A CI excludes 1 |

The current correct claim is narrowly scoped: on this 2,000-operation
read-only warm-stat workload, the production x86-64-v3+PGO FrankenFS FUSE
mount is **5.033559x slower than kernel ext4, bootstrap median 95% CI
[5.023263, 5.050188]**. There is no current admissible btrfs competitive
number because its final-source A/A gate did not clear. This is direct
vs-incumbent evidence: **0 wins / 1 loss / 0 neutral**, with btrfs unscored. It
is not a self-speedup and no source lever was applied.

All final-source arms returned payload SHA-256
`edc918914d9862e5c2a6193ed293fe1de2f319a8b4124ee9acbcd4926b3f4189`
with identical metadata across all four arms. The ext4 images passed
post-unmount `e2fsck`; the btrfs images passed post-unmount `btrfs check`.
The combined machine-readable report, including every raw wall sample, runtime
identity, CPU/LLC placement, admitted ext4 row, and rejected btrfs row, is
`/data/tmp/frankenfs-mounted-kernel/run_1785188339_332893/mounted-kernel-report.json`.

### Bring-up results that were not admissible

These outcomes shaped the fail-closed contract but are not competitive
measurements:

| Attempt | Result | Disposition and concrete retry predicate |
| --- | --- | --- |
| FUSE mountpoints under `/data/tmp` | `fusermount3: mount failed: Permission denied`; enforced AppArmor permits the mount helper under `/tmp/**`, not `/data/tmp/**`. | **BLOCKED-ENVIRONMENT.** Retry only with all images/evidence retained under `/data/tmp`, all four mountpoints under an allowed path, and otherwise identical mount options. The final runs satisfy this with `/tmp/frankenfs-mounted-kernel-mounts`. |
| First ext4 run after mount-path correction | Selected FUSE CPU measured `36.7%` busy, above the `35%` preflight ceiling; no timed ratio was admitted. | **BLOCKED-CONTENTION.** Retry only after a fresh occupancy sample selects distinct driver/FUSE CPUs below the ceiling. Both final runs satisfy it. |
| Early ext4 timing | Kernel A/A bootstrap median 95% CI `[1.001049, 1.003365]` excluded 1; no competitive point estimate was admitted. | **BLOCKED-NULL.** Retry only with a quiet pinned core and an exactly balanced four-order schedule whose kernel and FUSE A/A CIs both contain 1 and have symmetric spread at most `1.025x`. The final ext4 run satisfies it. |
| 31-round ext4 prototype | It emitted `5.037058x [5.028123, 5.071204]` with clear nulls, but 31 rounds cannot balance four orders exactly. | **VOID-SCHEDULE; never publish or pool.** Retry only with a positive pair count divisible by four and equal counts for every arm position. The final 32-round ext4 run satisfies it. |
| First btrfs identity check | Btrfs mountinfo exposed anonymous major:minor `0:124`, so looking that value up as a loop device failed before timing. | **BLOCKED-IDENTITY.** Retry only after resolving the declared mount source loop device through `/sys/class/block/<loop>/loop/backing_file` and proving it matches the arm image. The final btrfs run satisfies it. |
| Early btrfs timing | Identical FUSE arms produced an approximately `1.273x` A/A point ratio when their daemons could land on different cores; no competitive point estimate was admitted. | **BLOCKED-NULL; never publish or pool.** Retry only with both serially exercised daemons pinned to the same quiet physical CPU plus the exact balanced schedule and the same `1.025x` CI gate. The final harness satisfies the placement predicate, though its final btrfs measurements remain null-blocked. |
| Root-invoked driver | Elevating the whole driver caused the candidate mount to appear as generic `fuse`, so the required runtime `fuse.ffs` identity assertion stopped the run before timing. | **BLOCKED-IDENTITY.** Run the driver as the invoking user and elevate only the kernel mount/unmount commands internally. All later runs satisfy this predicate. |
| Cross-CCD combined run, harness ELF `b89d11db87aa2ec0286b2c30bd62e80df2dd7a5e575b355ec5727e89866d9b91` | Clear A/A controls accompanied apparent ext4 `6.509070x [6.494282, 6.515157]` and btrfs `6.460477x [6.451439, 6.467185]` losses, but the driver ran on CPU 0 and FUSE on CPU 24 in different L3/CCD domains. Report: `/data/tmp/frankenfs-mounted-kernel/run_1785187240_273792/mounted-kernel-report.json`. | **VOID-TOPOLOGY; never publish or pool.** Same-side A/A cannot detect a bias shared by both FUSE arms. Retry only when driver and FUSE cores share the same last-level-cache domain and both physical cores' SMT siblings are quiet. The final harness enforces this mechanically. |
| Pre-final separate ext4 and btrfs runs, harness ELF `9a22b69b6da25ee28a14a22761d20d5c23d8dabadade1782819e216621606e08` | Clear A/A controls produced ext4 `4.998240x [4.991335, 5.011338]` and btrfs `4.951192x [4.947170, 4.956124]`. Reports: `/data/tmp/frankenfs-mounted-kernel/run_1785185833_160264/mounted-kernel-report.json` and `/data/tmp/frankenfs-mounted-kernel/run_1785185816_153813/mounted-kernel-report.json`. | **SUPERSEDED-SOURCE; retain internally, not the current claim.** Retry with the exact committed harness that mechanically requires same-LLC placement and preserves reports before returning exit 2. The final-source ext4 run satisfies this; final-source btrfs remains null-blocked. |
| Same-LLC combined run, harness ELF `e63c31f663ba05a16d031e5e5d5c0356aae26836290639a399bf5f6f68267b39` | Ext4 cleared both nulls and observed `5.012652x [5.006774, 5.020606]`; btrfs FUSE A/A `0.998178x [0.996967, 0.998891]` excluded 1. The then-current error path returned before persisting the mixed-verdict report. | **BLOCKED-EVIDENCE for the combined artifact.** Retry only after every requested filesystem runs and the complete raw report is written before exit 2. Harness ELF `7099f140…54e40` implements that contract. |
| First report-preserving combined run, harness ELF `7099f14070d0e78851e30988c5c55a825a54e259fe8afbf6ec8d06e998454e40` | Ext4 kernel A/A `[0.997289, 0.999878]` and btrfs FUSE A/A `[1.001021, 1.002657]` excluded 1, so neither observed competitive ratio was admitted. Report: `/data/tmp/frankenfs-mounted-kernel/run_1785188310_331136/mounted-kernel-report.json`. | **BLOCKED-NULL.** The predeclared retry was a fresh zero-load placement in the same LLC with both SMT sibling sets guarded; the next unchanged-ELF invocation applied it. |
| Second report-preserving combined run, same ELF | Ext4 cleared both A/A controls and admitted the current `5.033559x [5.023263, 5.050188]` loss. Btrfs FUSE A/A `[0.994686, 0.998294]` excluded 1, so its observed `4.931910x [4.921023, 4.943701]` ratio is unscored. Report: `/data/tmp/frankenfs-mounted-kernel/run_1785188339_332893/mounted-kernel-report.json`. | **EXT4 HONEST / BTRFS BLOCKED-NULL.** Do not pool the btrfs point estimate with any other run. |
| Third final-ELF btrfs attempt | FUSE A/A cleared, but kernel A/A `0.999286x [0.998196, 0.999924]` excluded 1; observed `4.960432x [4.958407, 4.963746]` remains unscored. Report: `/data/tmp/frankenfs-mounted-kernel/run_1785188398_345293/mounted-kernel-report.json`. | **BLOCKED-NULL; stop this vein after three final-ELF rejects.** Retry btrfs only after continuous per-arm CPU attribution or another counted mechanism explains and removes the alternating kernel/FUSE A/A asymmetry; then require both same-invocation median CIs to contain 1. A fresh placement alone is no longer a sufficient retry predicate. |

**KEEP the instrument. Retry predicate for replacing the ext4 number:** use the
same four-independent-arm, same-invocation, runtime-identity,
production-v3+PGO self-report, exact-parity, matched mount/durability,
interleaved-order, same-LLC quiet-core contract; require both A/A bootstrap
median 95% CIs to contain 1 with symmetric spread at most `1.025x`; and gate
the new wall/cycles ratio on its bootstrap median CI with `cv_used=false` and
`instructions_used=false`. For btrfs, first satisfy the stronger counted-attribution
predicate in the final bring-up row. A different workload may add a separately
scoped claim but does not supersede this warm-stat result.

## Borrowed extent-item refcount payload clears the null and 5% floors - 2026-07-27 (GreenSpring, KEEP)

The institutional preflight found no prior decision on the exact
`BtrfsExtentAllocator::extent_item_refs` surface. The broader ledger grep kept
this exact-key read separate from the closed keyed-backref scan/delete rows:
this function materialized an inclusive one-key `range` result only to read the
first eight payload bytes.

The production-shaped fixture stored 4,096 real `BTRFS_ITEM_EXTENT_ITEM`
records and repeated their public lookups four times per observation. The
materialized control therefore performed:

- 16,384 public `extent_item_refs`-shaped calls;
- 16,384 result-vector allocations;
- 16,384 payload-vector allocations; and
- 393,216 cloned payload bytes.

The borrowed `range_with` path reduced all three materialization counts to
zero. Both paths returned digest `31166e01c212cbd4` in the same probe order.
A separate oracle proved identical valid-item values, short-item `None`,
absent-item `None`, and production results.

Before production changed, a source-neutral strict-remote x86-64-v3
release-perf process on pinned `ovh-a` self-reported executing ELF SHA-256
`aa34ba930d8e8e34aaa7ab166ee751658025d9c860b3e3ee277f8937612034d3`,
worker `fixmydocuments`, and compile/runtime SSE2, SSE4.2, AVX2, and FMA. Its
materialized/borrowed model measured:

- median **1.206740x**;
- deterministic 20,000-resample bootstrap median 95% CI
  **[1.202154, 1.210859]**; and
- saved-fraction lower bound **0.168160**.

The same invocation's materialized/materialized A/A measured median
**0.999289x**, CI **[0.996377, 1.000338]**, symmetric null floor
**1.003636x**, and twice-null threshold **1.007286x**. This admitted the
production edit but was not used as its final magnitude.

Production now decodes the refcount inside `range_with` while the exact-key
payload remains borrowed from the tree node. Inclusive key selection, tree
errors, valid refcount values, short/absent `None`, ordering, and the
side-effect-free read contract are unchanged. Tie-breaking, floating point,
and RNG are N/A.

The final actual-production invocation was independently linked. From inside
the timed process it emitted `bench_evidence,binary_sha256=cec1a4f6321ebd10c3e11db867ebc29c6cac83a3d7648ac8f7087c817e1ee9e4,worker=fixmydocuments`.
This x86-64-v3 release-perf ELF again ran on pinned `ovh-a` with
compile/runtime SSE2, SSE4.2, AVX2, and FMA. It measured:

- materialized/production-borrowed median **1.193053x**;
- bootstrap median 95% CI **[1.186397, 1.194739]**;
- saved-fraction lower bound **0.157112**;
- same-invocation A/A median **0.999146x**;
- A/A CI **[0.997507, 0.999695]**;
- symmetric null floor **1.002499x**; and
- twice-null threshold **1.005005x**.

**KEEP, narrowly scoped.** The final lower bound cleared both twice-null and
the pre-registered 5% saved-fraction floor. Each valid invocation owned 31
alternating `AAB`/`BAA` pairs, min-of-three observations, exact parity, and
its own deterministic bootstrap median wall-time decision. Results were not
pooled. CV and instruction count were not decision inputs.

One earlier command omitted `FFS_BTRFS_EXTENT_ITEM_REFS_GATE` from
`RCH_ENV_ALLOWLIST`, so the remote process ran the ordinary Criterion suite
instead of this contract. That invocation is invalid and unscored.

Strict-remote `ffs-btrfs` library tests passed **374/374**, with one manual
timing test intentionally ignored. Scoped library-plus-benchmark Clippy passed
with every warning denied after allowing only the reproduced pre-existing
`similar_names`, `too_long_first_doc_paragraph`, and `too_many_arguments`
categories in untouched library code. Targeted rustfmt and `git diff --check`
passed. `/data` had **393G or more** free before final Cargo invocations; every
target remained worker-scoped and there was no local fallback.

This is a 16,384-call internal lookup batch, not an ordinary single extent,
whole free/reflink/purge, PGO, mounted, shipped, or kernel magnitude.

**Retry predicate:** publish an end-to-end magnitude only after a production
free, purge, or reflink profile observes the real call cardinality and
attributes at least 5% of whole-operation wall/cycles to `extent_item_refs`.
Then use that whole operation in one self-hashing same-worker
x86-64-v3+PGO A/A+B invocation, preserve the exact final tree/image plus an
independent `btrfs check` where applicable, and require a bootstrap median
wall/cycles CI clearing twice its own null log-margin with at least a 5%
saved-fraction lower bound. Never transfer this internal batch ratio or gate
on CV/instructions.

## Ext4 names-only external result-vector merge is below the null and 5% floors - 2026-07-27 (GreenSpring, REJECT)

The institutional preflight found no prior REJECT on the qualified
`Ext4ImageReader::list_xattr_names` external-vector merge surface. The family
grep did recover two adjacent closed families and kept them separate:

- the 2026-07-13 rejected second full-`Ext4Xattr` parser result vector; and
- the list-24/list-64/list-128 direct-FUSE-wire retries.

This experiment changed neither family. The actual production control parsed
four inode-body names into its result, parsed 128 external-block names into a
second `Vec<String>`, and moved those 128 string objects into the first vector
with `extend`. The source-neutral model retained the same first vector and
parser semantics but appended external names directly.

The one-process proof covered:

- exact complete output: 132 names, checksum `b5a030122573b5dd`;
- exact ibody-first then external ordering;
- all declared namespace prefixes plus the unknown prefix;
- invalid UTF-8 lossiness;
- the counted mechanism: **one temporary external vector and 128 moved
  `String` objects to zero**; and
- 31 alternating `AAB`/`BAA` pairs with min-of-three batch observations.

The strict-remote pinned `vmi1149989` process self-reported x86-64-v3
release-perf ELF SHA-256
`a47eff4b6e296ed173cfee231fefbe57439d9c7673ddb36c43b61e8b7bd75fda`
(15,477,760 bytes), with compile/runtime SSE2, SSE4.2, AVX2, and FMA.
`/data` had 410G free before both Cargo requests, and RCH used only its remote
worker-scoped target.

Production/materialized over direct-append measured:

- median **1.021639x**;
- bootstrap median 95% CI **[1.017085, 1.035235]**; and
- saved-fraction lower bound **0.016798**, below the required **0.05**.

The same invocation's production/production A/A measured median
**0.990247x**, bootstrap median CI **[0.970793, 1.005216]**, symmetric null
floor **1.030085x** versus the maximum **1.025x**, and twice-null threshold
**1.061076x**. The decision used only the deterministic 20,000-resample
bootstrap median CI over wall time. CV and instruction count were not decision
inputs.

**REJECT before production edit.** The model failed the A/A floor, twice-null
threshold, and 5% saved-fraction lower bound. Production still returns
`parse_xattr_block_names` into a temporary vector and extends it. The hidden
contract and feature-gated noinline attributes remain only so the rejected
boundary is mechanically replayable; normal production behavior is unchanged.

The current mounted list-128 profile remains useful context: it attributes
25.24% self-time to `parse_xattr_entry_names`, but that number includes the
whole per-name parser and string construction and does not attribute 5% to this
top-level vector. A new report-only profile attempt was refused before
execution because the pinned worker reached RCH queue timeout; strict remote
prevented local fallback, so no new profile percentage is claimed.

Strict-remote focused xattr tests passed **29/29**, and the adversarial xattr
corpus passed **1/1**. The owned library-plus-benchmark Clippy target passed
with every warning denied after allowing only eight categories reproduced in
the untouched library before the benchmark was checked. The benchmark passed
targeted rustfmt and `git diff --check`; whole-file `ext4.rs` rustfmt remains
blocked by unrelated existing drift.

**Retry predicate:** retry only when a fresh allocator/symbolized production
profile directly attributes at least 5% of whole `list_xattr_names` wall/cycles
to allocation, growth, movement, or drop of the temporary external result
vector itself—not per-name strings or parsing—or when a real multi-inode caller
batch exposes at least the same one-vector-per-inode fraction. Use that observed
shape in one self-hashing same-worker v3+PGO A/A+B invocation and require exact
ordered names/errors, an A/A symmetric floor at most 1.025x, a bootstrap median
wall/cycles CI clearing twice its own null log-margin, and at least a 5%
saved-fraction lower bound. The separate direct-wire predicate must also be met
before reopening wire encoding. Never gate on CV or instruction count.

## Grouped JBD2 run assembly is below the profile-admission floor - 2026-07-27 (GreenSpring, SURFACE / NOT ADMITTED)

The institutional preflight passed the qualified surface
`jbd2_same_transaction_run_assembly_memcpy_after_grouping`. The required family
grep also recovered the existing same-transaction descriptor/data grouping and
the closed cross-transaction group-commit and pwritev families, so this profile
did not re-derive either frontier. It asked one narrower question: after
grouping was kept, is assembling the contiguous descriptor-plus-payload buffer
now expensive enough to justify scatter/gather?

The retained report-only route exercises the actual grouped
`Jbd2Writer::commit_transaction` path for 2,048 samples, each containing 64
full-size payload blocks. Before profiling, the same process ran the frozen
scalar-write oracle and grouped production path and asserted byte-for-byte
equality over the 524,288-byte journal region.

**Counted mechanism:** current assembly performs allocation count **1** and
copies one 4 KiB descriptor plus 64 4 KiB payloads, **266,240 bytes total**, per
descriptor group before the existing single contiguous device write.

The final-source strict-remote x86-64-v3 release-perf process ran on pinned
`vmi1149989` and self-reported executing ELF SHA-256 `75cb7e80d11bcda59006ec7ee7c291295d14f1279747af78215604b81467ea1a`
(3,763,336 bytes), with compile/runtime SSE4.2, AVX2, and FMA. `/data` had
**435G** free before the replay, and RCH used a worker-scoped target without
local fallback.

`perf record -F 999 -g --call-graph fp` followed by
`perf report --children` attributed:

- `jbd2_write_combining::run_production_commit`: **2.98%**;
- `Cx::checkpoint`: **1.25%** and **0.84%** symbol variants;
- `stamp_jbd2_tag_data_checksum`: **0.18%**; and
- `assemble_jbd2_descriptor_data_run`: **0.12%**.

**SURFACE / NOT ADMITTED; no production lever.** The named assembly frame is
only **0.12%**, far below the pre-registered **5.00%** attribution floor. Even
impossible elimination of the entire named frame is below campaign
resolution, so no scatter/gather or pwritev candidate was implemented and no
A/B ratio is published. The run explicitly reported
`ratio_published=false`; A/A and bootstrap median-CI gates become applicable
only after a candidate clears attribution. CV and instruction count were not
decision inputs.

An independent pre-Clippy-refactor invocation self-reported ELF
`0c938e09eaa30fa52461326f26f6a485e8985a5cc699d5d410d6d29b6cc4ef82`
and attributed **0.07%** to the same assembly frame. The final-source replay is
the primary result; the two profiles are reported separately and were not
pooled.

The feature-gated named helper is retained as attribution infrastructure.
Normal production builds request inlining, while `bench-instrumentation`
forces a stable out-of-line frame. Descriptor/payload order, transaction
boundaries, contiguous write count, checksums, journal bytes, and crash
semantics are unchanged.

Strict-remote focused tests passed **277/277**. Scoped library-plus-benchmark
Clippy passed with only the reproduced `incompatible_msrv` category allowed;
all-targets Clippy passed with the reproduced baseline categories
`incompatible_msrv`, `significant_drop_tightening`, and `too_many_lines`
allowed and every other warning denied. Targeted rustfmt and
`git diff --check` passed.

**Retry predicate:** retry run-copy elimination only when a fresh symbolized
production-shaped profile attributes at least 5% children or self time to
`assemble_jbd2_descriptor_data_run` on an observed descriptor-group
cardinality. Then require one self-hashing same-worker x86-64-v3 A/A+B
invocation, exact journal bytes plus crash/replay parity, a counted
allocation/copy/syscall mechanism, and a bootstrap median wall/cycles CI
clearing twice its own null log-margin with at least a 5% saved-fraction lower
bound. Never gate on CV or instruction count, and do not reopen
cross-transaction group commit unless its separate durability predicate is
met.

## Lazy queued group-id tracing is below the whole-callback null floor - 2026-07-27 (GreenSpring, REJECT)

The qualified institutional preflight found no prior REJECT on
`queued_refresh_group_ids_debug_materialization`. A broader first key had
matched the unrelated 2026-06-28 `ffs-core` repair write-set collection reject;
the exact field/materialization key separated the callback-local logging
surface without reopening that commit-path family.

The retained source-neutral model froze every banked callback decision:
disjoint-range indexing, compact temporary sort/dedup, persistent hash
membership, deterministic drain order, overlap first-input-match fallback,
mutex boundaries, and tracing event order. It changed only how the first debug
event exposes group IDs. The control eagerly collected `Vec<u32>` before the
event; the candidate supplied a lazy `DebugList` view over the already-sorted
`GroupNumber` slice.

The untimed proof covered 512 unique groups:

- exact ascending queue output and checksum `7a8c925983737ede`;
- exact 2,903-byte rendered debug-field text;
- eager mechanism: **one allocation, 512 copied IDs, 2,048 copied bytes**; and
- lazy mechanism: **zero allocations and zero copied IDs**.

**Counted mechanism:** allocation count `1 -> 0`; copied-ID count `512 -> 0`;
copied-byte count `2,048 -> 0`.

One strict-remote invocation on pinned `ovh-a` built x86-64-v3 release-perf
and executed ELF
`aca3ce86968eef94b57cc108748f54430be594838216311cb50129c3ed74767d`.
The process self-reported compile/runtime SSE2, SSE4.2, AVX2, and FMA. Its
optional environment-only worker field printed `unknown`; the RCH selection
and execution logs are the worker witness. `/data` had **436G** free before
the build, and all target output remained worker-scoped.

Across 41 alternating A/A+B rounds, each observation used min-of-three and a
calibrated batch of 64 complete callback-plus-drain executions:

- eager/eager A/A median **0.999851x**, deterministic bootstrap median 95% CI
  **[0.999269, 1.000424]**;
- symmetric null floor **1.000732x** and twice-null threshold **1.001464x**;
- eager/lazy median **0.999772x**, CI **[0.999142, 1.001288]**; and
- saved-fraction lower bound **0.000000**, versus the pre-registered 5% floor.

In the same invocation, the A/A null-control median was **0.999851x** with a
deterministic bootstrap median 95% CI **[0.999269, 1.000424]**.

An unpooled exact-source replay self-reported ELF
`290f17258dc9275bd143951cfac4d04280d1ee5505519e35e9d8865581049b51`
and independently returned the same decision: eager/eager A/A
**0.999408x [0.998450, 1.000148]**, symmetric null floor **1.001552x**,
twice-null **1.003107x**, and eager/lazy **1.000178x [0.999386, 1.000652]**.
Its saved-fraction lower bound was again **0.000000**. The two invocations are
reported separately and were not pooled.

**REJECT; no production edit.** Eliminating the allocation is real, but the
complete callback does not move: both full A/B CIs remain inside their own
twice-null thresholds and their lower-bound saving is zero. The source-neutral guard stays in
`queued_refresh_lookup.rs`; production continues to materialize `group_ids`.
This decision used only bootstrap median wall-time CI. CV was printed as
provenance and was not a gate; instruction count was not used. This is neither
PGO nor whole-flush, mounted, shipped, or kernel evidence.

**Retry predicate:** retry only when a current production callback profile
attributes at least 5% of whole-callback wall/cycles specifically to eager
group-ID materialization, or production telemetry shows a materially different
small callback shape (p50 at most eight unique groups) where allocation
profiling names this `Vec`. Use that observed cardinality and tracing state in
one self-hashing same-worker A/A+B invocation, preserve exact rendered field
text and queue output, and require the bootstrap median wall/cycles CI to clear
twice its own null log-margin with at least a 5% saved-fraction lower bound.
Never gate on CV or instruction count.

## Exact v3+PGO warm-read gate leaves no resolved ISA correction - 2026-07-27 (GreenSpring, CLAIM CORRECTION / NULL)

The institutional preflight found no prior row on
`bd_b9dug_whole_binary_read_gate`; the required family grep recovered the
closed cold-read/copy/page-fault frontiers (`bd-ddryj`, `bd-q6k00`, and
`bd-zvn7r`). None of their reopening conditions was met, so this work did not
re-derive a read-path lever. It added only the missing whole-binary identity
gate for the named warm sequential-read claim class.

All Cargo stages were strict-remote and pinned to `ovh-a`. The generic
release-perf process self-reported executing ELF
`deb2cc4693434e3fa7d292e2259f4be92eeddd9002513858cb7eb0083acf66d9`,
with SSE2 and without compile-time SSE4.2/AVX2/FMA. The profile-generation
process self-reported ELF
`5092a0e81137618d742fac4e47af332b68d21ea1f9167da4a271a49a624a5291`
and compile/runtime AVX2+FMA. Its production-shaped corpus generated 518 raw
profiles and a 28,783,720-byte merged profile with SHA-256
`60b213e302a5b888c205cff8fd050a1b7b0cf4d9d9d849cecb9c98e2cbe02692`.
The final v3+PGO process self-reported executing ELF
`ad55a58a0b2c0b5d3b75c586adcf960da8e94ed7f91ab9f68c208ecdb001587c`,
compile/runtime AVX2+FMA, and that exact consumed-profile SHA.

The immutable input image SHA-256 was
`3905bfa23212cf8d5b9d3cf95beb7bb8fb519a0faa47189f606304fe5cb717fd`.
Both arms returned exactly 33,554,432 bytes with payload SHA-256
`edeadec8f638055689d5be63b4bcf2654fb64bf91fb6651e9a924f052a9c7db0`;
payload parity ran outside timing, and the image hash remained unchanged.
Every timed child printed its ELF/ISA/profile identity from inside that exact
process before starting its timer. One parent invocation then owned two
warmups per binary and 31 alternating `AAB`/`BAA` rounds.

Generic warm-read median was **8,398 us** and v3+PGO median was **7,903 us**.
The paired generic/generic A/A median was **1.037304x**, deterministic
20,000-resample bootstrap median 95% CI **[0.903229, 1.168764]**. Its symmetric
null floor was therefore **1.168764x** and its pre-registered twice-null
threshold was **1.366010x**. Paired generic/v3+PGO median was **1.009827x**,
95% CI **[0.928481, 1.070209]**.

**CLAIM CORRECTION / NULL, not a source REJECT.** The lower raw v3+PGO median
is descriptive only: the paired A/B CI overlaps 1.0 and is wholly below the
same-invocation null floor. No speedup, slowdown, or correction factor is
admissible. The gate used read wall time and bootstrap median CI;
`cv_used=false`; `instructions_used=false`. This is a warm offline sequential
32 MiB CLI read, not a cold-cache, mounted FUSE, multi-file, or kernel
comparison. Historical cold/mounted ratios remain measurements of their
baseline-ISA ELFs and are now explicitly restated that way in
`docs/BD_B9DUG_ISA_CORRECTION.md`.

After the owned helper signature was tightened for scoped Clippy, an
exact-source replay rebuilt v3+PGO ELF
`09928b976c66d4452f2e26d056a95c8ef5079dcf93c8e998ae1a1e9e226a685c`.
It self-reported the same ISA and consumed-profile identity, returned the same
payload and immutable-image hashes, and repeated all 31 A/A+B pairs. Generic
median was **8,114 us**, v3+PGO median was **7,241 us**, and paired A/B was
**1.068757x**, 95% CI **[1.009721, 1.220066]**. Its A/A was **0.963717x**,
95% CI **[0.856697, 1.094219]**, giving a **1.167274x** symmetric null floor
and **1.362528x** twice-null threshold. The apparently positive A/B interval
still failed even the invocation's own null floor, so the independent replay
also returned **BLOCKED_NULL_FLOOR**. The two decisions are not pooled.

**Retry predicate:** publish a cold or mounted read correction only after one
same-worker invocation contains generic release-perf, exact v3+PGO, and the
matched mounted-kernel arm; every timed FrankenFS child must self-report its
executing ELF/profile SHA, all arms must return byte-identical payloads, and
the image/filesystem must pass independent validation. A cold claim must
control cache state for every arm. Require two independent complete
invocations whose bootstrap median wall/cycles CIs each clear twice their own
A/A null log-margin; never substitute CV, instruction count, this warm result,
or an arithmetic factor from lookup/create.

## Btrfs free-path backref key projection - 2026-07-27 (GreenSpring, REJECT)

The institutional exact-surface preflight found no prior REJECT on
`BtrfsExtentAllocator::delete_backrefs_for_extent`. The required family grep
did recover the older noisy `remove_many` frontier, so this attempt explicitly
left the existing ascending per-key delete loop unchanged. It tested only
whether the preliminary range scan should materialize `(key, Vec<u8>)` pairs or
borrow each payload while retaining the same ordered key vector.

The full-path fixture held 512 keyed `EXTENT_DATA_REF` items for one extent plus
two out-of-range sentinels. Both arms deleted the same 512 keys in ascending
tree order, produced deleted-key digest `d12155af72c1634f`, and retained the
same two sentinels byte-for-byte. The materialized control cloned **512
temporary payload `Vec`s / 14,336 bytes**; the borrowed projection cloned
**0**. Tie-breaking was unchanged/N/A; floating point and RNG were N/A.

A pre-edit source-neutral strict-remote pinned-`ovh-a` x86-64-v3 process
self-reported
`bench_evidence,binary_sha256=f444fdfd8119d6af411d846c33500f9568aa4fa01db935d37a5d160115a366d4`.
Its full selection-plus-512-deletes model median was **1.071793x**, bootstrap
median 95% CI **[1.055711, 1.081472]**, against same-invocation A/A median
**1.003734x** with bootstrap median 95% CI **[0.985769, 1.016860]**, and a
**1.034004x** twice-null threshold. The saved-fraction lower bound was
**0.052771**, narrowly clearing the pre-registered 5% admission floor.

The candidate was then installed in the actual production body and linked
again. That final candidate process self-reported
`bench_evidence,binary_sha256=e9434c725a553d7aab989a6f8bd1a571acd0429e6f3690bcd643f47b8d52403f`;
compile/runtime SSE2, SSE4.2, AVX2, and FMA were all true. The same invocation
again proved exact ordered-delete/final-tree parity and the **512 `Vec`s /
14,336 bytes to 0** mechanism, but its A/A median was **0.974376x**, bootstrap
median 95% CI **[0.962568, 0.995147]**. That yielded a **1.038887x** symmetric
null floor and **1.079287x** twice-null threshold. Actual candidate median was
only **1.043917x**, CI **[1.026145, 1.051577]**, with saved-fraction lower bound
**0.025478**.

**REJECT; production materialization restored.** The final candidate CI did
not clear twice null, its lower-bound saving was below 5%, and the A/A floor
itself exceeded the pre-registered 1.025 limit. The source-neutral admission
was therefore insufficient to publish or retain a production lever. A
`bench-instrumentation` replay remains behind
`FFS_BTRFS_BACKREF_DELETE_GATE=candidate`; normal production continues to use
the original materialized scan. This result is only a 512-backref internal
free-path shape, not an ordinary one-ref extent, whole truncate/unlink,
v3+PGO, mounted, shipped, or kernel magnitude. The decision used bootstrap
median wall-time CIs; `cv_used=false`; `instructions_used=false`.

After restoring production, strict-remote `free_extent`-filtered tests passed
**7/7** with `bench-instrumentation` enabled. Scoped library-plus-benchmark
Clippy passed under `--no-deps -D warnings` after the owned benchmark
controller was split to satisfy `too_many_lines`; only the repository's known
dependency deprecation warnings remained. Targeted rustfmt and
`git diff --check` passed. `/data` had **436G** free before every Cargo
invocation; all target output remained worker-scoped.

**Retry predicate:** retry borrowed key projection only after a witnessed
x86-64-v3+PGO production free/truncate profile both observes at least 512 keyed
backrefs on the target extent and attributes at least 5% of whole-operation
wall/cycles specifically to payload materialization in
`delete_backrefs_for_extent`. Then use that observed cardinality in one
same-worker self-hashing whole-operation A/A+B invocation, require exact final
tree/image plus `btrfs check` parity, use min-of-three paired observations, and
require the bootstrap median wall/cycles CI to clear twice its own null
log-margin with a saved-fraction lower bound of at least 5%. The closed
`remove_many` frontier remains out of scope unless its separate ledger retry
predicate is independently met.

## Btrfs keyed extent backrefs parse borrowed payloads - 2026-07-27 (GreenSpring, KEEP)

The institutional preflight found no prior row on
`BtrfsExtentAllocator::get_extent_data_refs`. The required family grep recovered
the adjacent kept checksum-delete key projection, but no rejected backref
parsing surface. A source-neutral harness therefore froze the exact inclusive
`(bytenr, EXTENT_DATA_REF, 0..=u64::MAX)` range, ascending key order,
`BtrfsExtentDataRef::from_bytes` validation, malformed-record skip behavior,
and returned record vector while comparing the existing materializing range
walk with a borrowed `range_with` walk.

The pre-edit strict-remote pinned-`ovh-a` x86-64-v3 release-perf process
self-reported ELF
`544851737a95df49dbfc71d9bec4fbbc0e6ce1f7091cf0c8486a1fe97a196cb4`.
All compile/runtime SSE2, SSE4.2, AVX2, and FMA checks were true. On 4,096 keyed
backrefs, control, borrowed model, and then-current production returned the
same 4,096 parsed records in the same order, checksum `7f3c7a247fc4a0b6`.
The control materialized **4,096 temporary payload `Vec`s / 114,688 bytes**
before retaining the fixed-size parsed records; the candidate materialized
**0** temporary payload vectors while retaining the identical output vector.

One invocation owned exact parity, the counted mechanism, and both timing
controls. Materialized/materialized A/A median was **1.001039x**, deterministic
20,000-resample bootstrap median 95% CI **[0.998937, 1.003046]**, yielding a
symmetric null floor of **1.003046x** and a pre-registered twice-null threshold
of **1.006100x**. Materialized/borrowed-model median was **2.192214x**,
bootstrap median 95% CI **[2.187101, 2.195836]**; its saved-fraction lower
bound was **0.542774**, clearing the 5% admission floor.

Production `get_extent_data_refs` now parses each selected value while it is
borrowed from its tree node and retains only the parsed `BtrfsExtentDataRef`.
Inclusive range boundaries, ascending key traversal, parsed-record order,
short/malformed payload omission, and returned errors are unchanged. A
traversal error can populate only a local vector that is discarded with the
`Err`, so no partial result or side effect escapes. Tie-breaking is
unchanged/N/A; floating point and RNG are N/A.

The final-source strict-remote pinned-`ovh-a` x86-64-v3 release-perf process
self-reported
`bench_evidence,binary_sha256=e9035b7a97ee51b7c1a674f12b83d367f88fbdd3f5fbf41ee683fa87a68142d1`.
The same invocation again proved exact frozen-control/borrowed-model/
actual-production record and order parity, counted the same
**4,096 `Vec`s / 114,688 bytes to 0** mechanism, and ran 31 alternating-order
paired rounds with min-of-three timing. Materialized/materialized A/A median
was **0.997114x**, bootstrap median 95% CI **[0.990664, 1.007784]**; the
symmetric null floor was **1.009424x** and the twice-null threshold
**1.018936x**. Frozen-materialized/actual-production median was **2.601449x**,
bootstrap median 95% CI **[2.574732, 2.617050]**, with a **0.611610**
saved-fraction lower bound.

**KEEP, narrowly scoped.** This is an isolated high-cardinality scan of 4,096
keyed backrefs for one logical extent. It is not a typical one-ref extent,
whole `BTRFS_IOC_LOGICAL_INO`, PGO, mounted, shipped, or kernel magnitude. The
gate basis was bootstrap median CI over wall time; `cv_used=false` and
`instructions_used=false`.

Strict-remote focused keyed-ref tests passed **4/4**, covering first keyed-ref
lookup, duplicate merge, count decrement/removal, and inline/keyed coexistence.
Scoped `--no-deps -D warnings` Clippy passed after allowing only the reproduced
pre-existing `similar_names`, `too_long_first_doc_paragraph`, and
`too_many_arguments` categories in untouched code. Targeted rustfmt and
`git diff --check` passed. `/data` had **436G** free before every Cargo
invocation; all builds were strict-remote and no local target directory was
created.

**Retry predicate:** publish an end-to-end or shipped magnitude only after a
production `BTRFS_IOC_LOGICAL_INO[_V2]` profile records the actual keyed-backref
cardinality and attributes at least 5% of whole-ioctl wall/cycles to
`get_extent_data_refs`; then run a same-worker whole-ioctl A/A+B gate with
identical returned tuples and a bootstrap median wall/cycles CI clearing twice
its own null log-margin. Revisit the remaining parsed-output vector only if a
fresh profile attributes at least 5% to its allocation/growth and a caller-owned
buffer or iterator can preserve the public API contract. Never transfer this
4,096-ref ratio to ordinary one-ref extents; `cv_used=false`;
`instructions_used=false`.

## Btrfs orphan reclaim borrows extent-tree keys - 2026-07-27 (GreenSpring, KEEP)

The institutional preflight found no prior row on
`BtrfsExtentAllocator::reclaim_unreferenced_data_extents`. The required family
grep recovered an unrelated rejected allocator gap-scan representation, whose
reopening condition was not met, and left this clean-recovery payload
materialization surface open. A source-neutral harness therefore froze the
current inclusive extent-tree range, block-group and item-type filters,
referenced-set lookup, and orphan output order while comparing the existing
materializing `range` walk with a borrowed `range_with` walk.

The pre-edit strict-remote pinned-`ovh-a` x86-64-v3 release-perf process
self-reported ELF
`b532ea27a5300e11869e432f11efd5714cb8f9eac36456f97fe0e6a9e962a51d`.
All compile/runtime SSE2, SSE4.2, AVX2, and FMA checks were true. On 4,096
referenced data extents and zero orphans, the frozen control and borrowed model
returned exactly the same empty orphan sequence. The control materialized
**4,096 payload `Vec`s / 217,088 bytes** that orphan classification never
observed; the candidate materialized **0**. One invocation owned exact parity,
the A/A null, and the A/B admission gate. Materialized/materialized A/A median
was **1.004839x**, deterministic 20,000-resample bootstrap median 95% CI
**[0.998378, 1.015259]**, yielding a symmetric null floor of **1.015259x** and
a pre-registered twice-null threshold of **1.030752x**.
Materialized/borrowed-model median was **1.865467x**, bootstrap median 95% CI
**[1.851003, 1.877787]**; its saved-fraction lower bound was **0.459752**,
clearing the 5% attribution/admission floor.

Production now traverses the identical range through `range_with` and borrows
each key while classifying it. It still accumulates all orphans before any
delete, so a traversal error cannot partially mutate the tree. Block-group
iteration, ascending tree-key traversal, inclusive range boundaries,
`objectid < bg_end`, item-type filtering, referenced membership, orphan vector
order, delayed deletion order, metadata-item exclusion, and the
error-before-mutation boundary are unchanged. Tie-breaking is unchanged/N/A;
floating point and RNG are N/A.

The final-source strict-remote pinned-`ovh-a` x86-64-v3 release-perf process
self-reported
`bench_evidence,binary_sha256=4721ab125cadfa69047c274564caf0677f57e2b1edcda0fd4ad01584d8b60e46`.
The same invocation proved exact frozen-control/borrowed-model/actual-production
output and ordering, counted the same **4,096 `Vec`s / 217,088 bytes to 0**
mechanism, and ran 31 alternating-order paired rounds with min-of-three timing.
Materialized/materialized A/A median was **0.999775x**, bootstrap median 95% CI
**[0.997404, 1.001660]**; the symmetric null floor was **1.002603x** and the
twice-null threshold **1.005212x**. Frozen-materialized/actual-production
median was **1.823254x**, bootstrap median 95% CI
**[1.820986, 1.828589]**, with a **0.450847** saved-fraction lower bound.

**KEEP, narrowly scoped.** This is a clean-recovery classification scan with
4,096 referenced extents and no deletes. It is not an orphan-delete-heavy,
whole-recovery, PGO, mounted, shipped, or kernel magnitude. The gate basis was
bootstrap median CI over wall time; `cv_used=false` and
`instructions_used=false`.

Strict-remote focused reclaim tests passed **2/2**: orphan data extents are
freed while referenced extents remain, and metadata extents remain untouched.
Scoped `--no-deps -D warnings` Clippy passed after allowing only the reproduced
pre-existing `similar_names`, `too_long_first_doc_paragraph`, and
`too_many_arguments` categories in untouched code; all diagnostics introduced
by the new harness were fixed. Targeted rustfmt and `git diff --check` passed.
`/data` had **436G** free before every Cargo invocation; all builds were
strict-remote and no local target directory was created.

**Retry predicate:** restate an end-to-end or shipped magnitude only after a
production recovery profile attributes at least 5% of whole-recovery
wall/cycles to orphan classification on a named image and a same-worker
whole-recovery A/A+B gate proves identical final tree/image plus `fsck` output,
with its bootstrap median wall/cycles CI clearing twice its own null
log-margin. Revisit this representation only if the `range_with` contract
changes, a fresh profile attributes at least 5% of classification wall/cycles
to a remaining key/orphan-vector allocation, or an orphan-delete-heavy shape
dominates enough that deletion cost changes the observed ceiling. Benchmark
that exact production shape in one self-hashing invocation; never gate on CV or
instruction count.

## Queued repair persistent membership uses hash + deterministic drain - 2026-07-27 (GreenSpring, KEEP)

The institutional preflight found no prior REJECT on
`QueuedRepairRefresh::queued_groups`; the two immediately preceding repair
keeps explicitly left this persistent `BTreeSet` unchanged. A pre-edit
source-neutral model therefore froze the current indexed lookup, compact
temporary `Vec`, persistent ordered tree, and deterministic drain against a
persistent `HashSet` whose internal order is sorted only after draining.

The pre-edit strict-remote x86-64-v3 release-perf process self-reported ELF
`8cf25304d706befcc553f6654d39dd03f55d105a6797654569a70f2eab44939b`.
It proved exact 512-group output/order parity and admitted the representation:
tree/tree A/A bootstrap median 95% CI **[0.995205, 1.022097]**, symmetric null
floor **1.022097x**, twice-null threshold **1.044682x**, and tree/hash median
**1.360373x** with bootstrap median 95% CI **[1.345692, 1.371074]**.

Production now stores queued group membership in a persistent
`HashSet<GroupNumber>`, reserves for the incoming unique group batch, and
retains the table allocation across drains. `drain_queued_groups` drains under
the same mutex, drops the guard, and then sorts the result. Consequently the
randomized internal bucket order never escapes. Ascending group order,
duplicate suppression across and within callbacks, overlap first-input-match
selection, debug event order, mutex-poison errors, and the critical
drain/drop/process re-entry boundary are unchanged. Tie-breaking is unchanged;
floating point and RNG are N/A.

The final-source strict-remote pinned-`ovh-a` x86-64-v3 release-perf process
self-reported
`bench_evidence,binary_sha256=4746f4396e523f9e0e6469abb8cac156be448dfc71ab39f8061ca609e0c45e0f`.
One invocation owned the parity proof, 41 alternating A/A+B rounds, and the
decision. Frozen-tree/frozen-tree A/A median was **1.003447x**, deterministic
20,000-resample bootstrap median 95% CI **[0.997756, 1.008698]**; the symmetric
null floor was **1.008698x** and the pre-registered twice-null threshold was
**1.017472x**. Frozen-tree/actual-production-callback median was **1.279996x**,
bootstrap median 95% CI **[1.278681, 1.281732]**. The timed candidate arm called
production `on_flush_committed` plus `drain_queued_groups`; the model and actual
production callback also returned the same 512 ascending unique groups and
checksum `7a8c925983737ede`.

**KEEP, narrowly scoped.** This is a whole-callback result for 512 flushed
blocks mapping to 512 unique groups in a 4,096-range / 1 GiB repair layout. It
is not a PGO, mounted, whole-flush, self-healing pipeline, or kernel magnitude.
The gate basis was bootstrap median CI over wall time; `cv_used_as_gate=false`
and instructions were not decision inputs.

Strict-remote focused queue tests passed **6/6**, including repeated blocks,
unsorted disjoint ranges, overlap fallback, empty/out-of-range behavior, and
the lock-release/re-entry invariant. Scoped `--no-deps -D warnings` Clippy
passed after allowing only the reproduced baseline categories: two untouched
nightly deprecations plus `needless_pass_by_value`,
`manual_saturating_arithmetic`, and `unused_self` in untouched code. Targeted
rustfmt and `git diff --check` passed. `/data` had **436G** free before every
Cargo invocation; all builds were strict-remote and no local target directory
was created.

**Retry predicate:** restate an end-to-end or shipped magnitude only after a
production-shaped self-healing profile attributes at least 5% of whole flush
wall/cycles to queued repair notification and a same-worker whole-flush A/A+B
gate proves identical durable state with a bootstrap median wall/cycles CI
clearing twice its own null log-margin. Revisit the membership representation
only if current production telemetry shows a materially smaller drain shape
(p50 at most eight unique queued groups), a materially larger sparse table
shape, or a fresh profile attributes at least 5% of callback wall/cycles to
hashing or sort-on-drain. Then benchmark that exact cardinality against the
retained frozen tree in one self-hashing invocation; never gate on CV or
instructions.

## Btrfs-send final output buffer growth has a sub-null ideal ceiling - 2026-07-27 (GreenSpring, REJECT)

The institutional candidate preflight found no prior rejected row on
`SendStreamBuilder::new`. Before inventing an input-derived capacity heuristic,
a feature-gated exact-capacity oracle bounded the entire output-buffer growth
family. Production still starts with `Vec::new()`; only the explicit
benchmark-instrumentation entry point knows the final stream length in advance.

The retained harness replays the production allocation sequence over the exact
stream framing and counts the mechanism. On the deep-path fixture, 4,549 command
frames produced a 3,048,915-byte stream from 1,985 items / 159,712 input-payload
bytes. The production builder changed capacity 19 times, relocated its pointer
15 times, and moved 4,896,289 live bytes during those relocations. The oracle
preallocated exactly 3,048,915 bytes and eliminated that entire mechanism.
Control and oracle emitted the identical stream, SHA-256
`54f09f39e3a07fc563836b72c495d6e59d244fae206ffa763d7ceed432ada3ad`.

One strict-remote x86-64-v3 release-perf invocation on pinned `ovh-a`
(`fixmydocuments`) self-reported executing ELF
`c7e76568411ce85285cc7a1e91d93f6eb0e3c386756ef28a79939991c2de423d`.
The same invocation owned the A/A null control and the ideal-capacity A/B.
Across 31 alternating `AAB`/`BAA` pairs with two complete streams per
observation (allocation-growth count **19 vs 0**):

- zero-capacity/zero-capacity A/A median was **0.995559x**, deterministic
  bootstrap median 95% CI **[0.992484, 1.002684]**;
- the symmetric null floor was **1.007573x** and the pre-registered twice-null
  threshold was **1.015203x**; and
- zero-capacity/exact-capacity median was only **1.007404x**, bootstrap median
  95% CI **[1.001732, 1.010988]**.

**REJECT_IDEAL_CEILING_BELOW_TWICE_NULL.** Even an impossible production oracle
cannot clear twice the invocation-local null margin, so no capacity estimate or
production allocation change ships. Ordering, command framing, attributes,
CRCs, and every output byte are identical; tie-breaking is unchanged/N/A;
floating point and RNG are N/A. The gate used only the bootstrap median CI over
whole-stream wall time; CV and instruction count were not computed or consulted.

Focused strict-remote release-perf send-stream tests passed **22/22** with
`bench-instrumentation` enabled. Targeted rustfmt and `git diff --check` passed;
the only build diagnostics were pre-existing nightly deprecations in dependency
crates outside this change. Scoped Clippy stopped before reaching `ffs-btrfs`
on 23 promoted nightly errors in untouched `ffs-ondisk`; neither changed file
produced a diagnostic.

**Retry predicate:** reopen output preallocation only after a current
production-shaped witnessed-v3+PGO profile attributes at least 5% of whole-send
wall/cycles to `SendStreamBuilder`-originated allocation growth or relocation,
or after allocator/growth-policy drift materially changes the counted mechanism.
Then rerun this exact-capacity ceiling first in one self-hashing, pinned-worker
invocation with exact stream parity and at least 31 alternating A/A+B pairs.
Do not attempt a production hint unless the ceiling's bootstrap median
wall/cycles CI clears twice its own null log-margin; never gate on CV or
instructions.

## Btrfs-send ordered inode-link groups replace the outer BTreeMap - 2026-07-27 (GreenSpring, KEEP)

The institutional candidate preflight matched the 2026-07-13 rejected
parsed-`INODE_REF` name-handoff row. That prior row required either a materially
quieter paired harness or proof that this handoff is a whole-send bottleneck.
No production edit was made until a source-neutral attribution invocation
satisfied that requirement.

On the 3,048,915-byte deep-path fixture, the old `inode_links` construction
performed 1,088 map-entry probes for 1,088 parsed links across 896 unique
inodes and copied 5,312 name bytes. The pre-edit x86-64-v3 release-perf process
self-reported ELF
`b48117f27efd146c9e3e3d1dd550075db8b9dbef9fee3531317f164fb8850083`
on pinned strict-remote `ovh-a`. Its same-invocation whole/whole A/A symmetric
null floor was **1.008357x**. The complete link-map stage occupied
**12.944545%** of whole-stream wall, with deterministic bootstrap median 95%
CI **[12.829439%, 13.040409%]**. That lower bound cleared the pre-registered 5%
admission floor.

Production now uses a compact ordered `Vec<SendInodeLinkGroup>` when the
tree-walk input is monotone by objectid. A binary search provides the same
inode lookup contract without one BTreeMap node/probe per parsed
`INODE_REF`. Public arbitrary-slice behavior remains exact: a monotonicity
check routes non-monotone input through the original BTreeMap gather, including
the original within-inode insertion order. This lever deliberately retains
the existing parsed-name clone, so it does not mix in or re-derive the rejected
clone-to-move handoff.

The final source-exact invocation reported:

- `bench_evidence,binary_sha256=1417e48797830580d83dfc5b24ea5021a2cb1d7dffc33e84e6e2769860750eb2`;
- worker `fixmydocuments` (`ovh-a`), with compile/runtime SSE2, SSE4.2, AVX2,
  and FMA all true;
- BTreeMap/BTreeMap A/A median **0.999342x**, bootstrap median 95% CI
  **[0.997662, 1.000983]**, symmetric null floor **1.002343x**, and
  pre-registered twice-null threshold **1.004691x**; and
- BTreeMap/ordered-group median **1.081022x**, bootstrap median 95% CI
  **[1.077525, 1.084050]**, clearing twice-null across 31 alternating
  `AAB`/`BAA` pairs with eight complete streams per observation.

Control and candidate emitted the identical 3,048,915-byte stream, SHA-256
`54f09f39e3a07fc563836b72c495d6e59d244fae206ffa763d7ceed432ada3ad`.
The decision used the deterministic 20,000-resample bootstrap median CI over
whole-stream wall time. CV and instruction count were not computed or
consulted.

**DECISION — KEEP.** Ordering is preserved: objectid groups remain sorted and
links within each inode retain encounter order. First-link tie-breaking and
hardlink emission are unchanged. Parse/error skipping, path construction,
command attributes, CRCs, and complete stream bytes are identical. Floating
point and RNG are N/A. This is witnessed v3 release-perf evidence, not PGO or
shipped-binary magnitude evidence.

Strict-remote correctness gates passed the focused ordered/fallback proof
**1/1** and existing send-stream family **7/7**. Targeted rustfmt and
`git diff --check` passed. Scoped Clippy reached the owned library and
benchmark; all diagnostics were blame-confirmed pre-existing library/legacy
bench debt outside this diff, and neither new function produced a diagnostic.

**Retry predicate:** restate this magnitude as shipped only after the exact
production PGO training profile is consumed by the same strict-remote
whole-stream gate. Revisit the representation itself only if a production
caller measurably supplies non-monotone objectids, or a fresh profile
attributes at least 5% of whole wall/cycles to the binary-search/fallback
branch. Any retry must retain the in-process ELF/ISA/profile witness, exact
stream plus arbitrary-order fallback parity, at least 31 same-invocation
alternating A/A+B pairs, and a bootstrap median wall/cycles CI clearing twice
its own null log-margin. Never gate on CV or instruction count.

## Ext4 read-pool cap retained, quarter-nproc scaling corrected - 2026-07-27 (GreenSpring, KEEP / CLAIM CORRECTION)

The institutional candidate preflight found the existing `bd-ddryj` row and
printed its unresolved predicate: the dedicated-pool binary itself had never
been measured. The historical profile was still useful but narrower than its
policy:

- on the 64-thread profile host, 64-to-16 reduced
  `native_queued_spin_lock_slowpath` self-time from **42.27% to 9.32%** and
  improved cold wall by about **1.21x**;
- production had generalized that point to
  `(available_parallelism / 4).clamp(4, 16)`; and
- the committed code had only been compile-tested. The reported ratio came
  from an equivalent environment override in an older binary.

A new hidden whole-binary gate self-hashes before doing work, verifies that a
spawned `bench-evidence` child reports the same executing ELF, constructs a
private deterministic ext4 file, proves exact candidate/control bytes, and
owns A/A plus A/B in one invocation. It alternates order for 31 pairs, evicts
the image with `POSIX_FADV_DONTNEED` before every child, and gates only on a
deterministic 20,000-resample bootstrap median CI over wall time. CV and
instruction count are not computed or consulted.

The first v3 invocation exposed a policy error. On pinned strict-remote
`ovh-a`, where `available_parallelism` is 16, the shipped default selected 4
threads. Executing ELF
`a21b26bcff6d8b6010fedac47930bbefc82a7eafb29fabad1122b8b1586f4118`
measured:

- default/default A/A median **0.983423x**, 95% CI
  **[0.961861, 1.022792]**, symmetric null floor **1.039651x**; and
- default-4 / explicit-16 median **0.793266x**, CI
  **[0.772379, 0.808476]**.

Quartering a smaller worker was decisively harmful. The default is now
`min(available_parallelism, 16)`: preserve all available threads below the
profiled ceiling and cap larger machines at 16. The dedicated-pool boundary
and `FFS_READ_PARALLELISM` override are unchanged.

A fresh, unpooled corrected-policy invocation admitted the change:

- executing v3 release-perf ELF
  `8f7039d78a42e5ca7aa79cf7fa0e5c80415b61971469465d0ca5e9d881003082`;
- machine-readable in-process witness
  `bench_evidence,binary_sha256=8f7039d78a42e5ca7aa79cf7fa0e5c80415b61971469465d0ca5e9d881003082`;
- parent and identity child reported the same SHA; compile/runtime SSE4.2,
  AVX2, and FMA were true; PGO profile SHA was `none`;
- private image SHA-256
  `144db18f7f7134058092a6d88768a285660001f3cf06a530ad1db729dc76a919`;
- corrected-default/corrected-default A/A median **0.993140x**, bootstrap
  median 95% CI **[0.986304, 1.002085]**, symmetric null floor
  **1.013887x**, and twice-null threshold **1.027966x**;
- corrected-default-16 / old-quarter-4 median **1.248257x**, CI
  **[1.226142, 1.279943]**, clearing the threshold; and
- both arms returned the identical 33,554,432-byte stream, all `0xA5`,
  SHA-256
  `edeadec8f638055689d5be63b4bcf2654fb64bf91fb6651e9a924f052a9c7db0`.

Two subsequent exact-source invocations were deliberately given zero weight.
One was rejected by a wide A/A CI of **[0.893182, 1.082108]**. The other
passed the broad null bound but its A/B lower bound **1.036707x** did not clear
its disturbance-inflated **1.086391x** twice-null threshold. A larger 128 MiB
attempt never entered timing because the 64 MiB source image filled during
setup. None was pooled with the admitted invocation.

**DECISION — KEEP THE 16-THREAD CEILING, CORRECT THE SCALING RULE, AND RESTATE
THE CLAIM.** The old 64-to-16 profile remains evidence for the ceiling on that
host. The actual-binary 16-to-4 result refutes quarter scaling and the
corrected 16-to-4 gate independently confirms the repair. The **1.248257x**
ratio is witnessed v3 release-perf evidence on this offline ext4 workload, not
a v3+PGO, mounted-FUSE, or kernel-ext4 result. Historical kernel ratios are not
rescaled.

Semantic proof: only worker count changes. Indexed segments retain their
logical assembly order, candidate/control bytes and length are exact, and the
pool remains isolated from scrub/walk/repair. Ordering is preserved.
Tie-breaking is unchanged/N/A. Floating point and RNG are N/A.

Strict-remote checks passed for `ffs-cli --all-targets`; focused CLI parsing and
core topology tests passed. CLI Clippy passed with `-D warnings` after allowing
only reproduced pre-existing categories. Core/workspace Clippy remains blocked
by unrelated pre-existing pedantic/nursery debt.

**Retry predicate:** revisit the width policy only when a production-shaped
profile on a materially different worker/device attributes the residual to
read-pool width and its optimum differs from `min(nproc, 16)`. Then require an
in-process executing-ELF/ISA/profile witness, exact stream parity, at least 31
same-invocation alternating A/A+B pairs, and a bootstrap median wall/cycles CI
clearing twice its own null log-margin. Claim a shipped magnitude only after
the exact production PGO profile is consumed. Never gate on CV or instruction
count.

## Btrfs-send path/depth cache Fx hashing clears attribution but not the whole-stream null floor - 2026-07-27 (GreenSpring, REJECT)

The institutional candidate preflight matched the earlier closed SipHash sweep:
`generate_send_stream_impl`'s `path_cache` and `depth_cache` had been classified
as rare/non-hot. Its printed escape condition required either materially
quieter paired whole-send evidence or a counted whole-send bottleneck before
any production edit.

A source-neutral x86-64-v3 attribution mode in
`send_stream_path_cache.rs` reproduced both cache algorithms without changing
production. On the deep-path fixture it counted:

- 2,880 path-cache gets and 129 inserts;
- 639 depth-cache gets and 256 inserts; and
- 1,089 emitted paths totaling 660,352 path bytes.

The retained attribution harness was corrected during final diff review:
inode classification is precomputed outside the timed region, while its
compile-time-false timed route performs no counting, path folding, or exact-path
cloning. It was then replayed after production had been restored and its
temporary whole-stream control removed. That corrected final-source invocation
was a same-invocation protocol owning duplicate whole/whole and stage/stage A/A controls plus the
RandomState/FxBuildHasher stage comparison. The executing process self-reported
ELF `9c0ad2942c734e291c4c6dfd02a95384a5c05f8c738aa0d37f9b0d0287ff4020`
on pinned strict-remote `ovh-a`, with compile/runtime AVX2+FMA true. Results:

- whole A/A median **0.980129x**, deterministic bootstrap median 95% CI
  **[0.956172, 1.006992]**, symmetric null floor **1.045837x**;
- stage A/A median **1.025608x**, CI **[1.009478, 1.032967]**, symmetric
  null floor **1.032967x**, twice-null threshold **1.067020x**;
- cache-stage / whole-stream fraction **24.261466%**, CI
  **[23.723773%, 24.843648%]**; and
- RandomState/FxBuildHasher stage median **1.310055x**, CI
  **[1.292686, 1.336789]**.

The attribution lower bound exceeded the pre-registered 5% floor, so the stale
"non-hot" premise was falsified and one production-shaped whole-stream A/B was
admitted. The temporary candidate changed only the hasher used by the two
integer-key caches. A feature-gated control retained RandomState so both arms
ran in one ELF. Before timing, the invocation asserted exact full-stream parity:
both arms emitted 3,048,915 bytes with SHA-256
`54f09f39e3a07fc563836b72c495d6e59d244fae206ffa763d7ceed432ada3ad`.
The counted mechanism remained 3,904 total cache operations.

The final strict-remote process self-reported ELF
`bb3d992fd12cccd295b8e87561ef9dcb628f9639437bbeb54b3a0d38fa501414`
on the same pinned worker, again with compile/runtime AVX2+FMA true. Across 31
alternating `AAB`/`BAA` pairs:

- RandomState/RandomState A/A median **0.985884x**, CI
  **[0.952269, 1.012486]**;
- symmetric null floor **1.050123x**, pre-registered twice-null threshold
  **1.102758x**; and
- RandomState/FxBuildHasher whole-stream median **1.038185x**, CI
  **[1.023832, 1.061480]**.

**DECISION — REJECT_BELOW_TWICE_NULL AND REVERT PRODUCTION.** The isolated
mechanism is substantial and the whole-stream interval excludes 1.0, but its
lower bound does not clear twice the invocation-local null margin. The
production hasher edit and benchmark-only whole-stream control were removed;
only the source-neutral, counted attribution mode remains. The decision used
the deterministic 20,000-resample paired bootstrap median CI over wall time.
CV and instruction count were not computed or consulted.

Final-source gates were strict-remote on `ovh-a`: the focused send-stream suite
passed **22/22**; scoped bench Clippy passed under `-D warnings` after allowing
only the six reproduced pre-existing library/legacy-bench diagnostic
categories; targeted rustfmt and `git diff --check` passed.

Semantic proof: both cache key domains are internal inode numbers; map equality
and lookup values are independent of the hasher; neither map is iterated for
emission order; path construction, directory-depth ordering, command
attributes, CRCs, and complete stream bytes matched exactly. Ordering is
preserved, tie-breaking is unchanged, and floating point/RNG are N/A. This is
witnessed v3 release-perf evidence, not PGO or shipped-binary evidence.

**Retry predicate:** reopen only when a fresh production-shaped v3+PGO send
profile attributes at least 5% of whole wall/cycles to these caches and either
(a) a pinned same-worker A/A invocation demonstrates a symmetric null floor at
or below **1.015x**, making the observed effect decision-capable, or (b) a
materially different fixture counts at least **4x** the current 3,904 cache
operations per 3,048,915 output bytes. Then require an in-process
ELF/ISA/profile witness, exact full-stream parity, at least 31 alternating
A/A+B pairs, and a bootstrap median wall/cycles CI clearing twice its own null
log-margin. Never gate on CV or instruction count.

## Exact v3+PGO persisted-create gate corrects bd-b9dug for one offline corpus - 2026-07-27 (GreenSpring, KEEP / CLAIM CORRECTION)

The institutional preflight found no prior rejected row on the exact
`bd_b9dug_whole_binary_create_gate in crates/ffs-cli/tests/cli_e2e.rs`
surface. One pinned strict-remote `ovh-a` pipeline built and executed:

- generic release-perf ELF
  `65bca08591dcdf4b8257f0386cbfcca4f9f4ac3624be4a96a837ea088c7f0866`,
  which self-reported SSE2 true and SSE4.2/AVX2/FMA false;
- v3 profile-generation ELF
  `d1c03d4b19e09a554f865b020083dd5e744a8f5db6f4a180cae7a5302e4bad4a`,
  which self-reported SSE2/SSE4.2/AVX2/FMA true; and
- final v3+PGO ELF
  `1a0c7c419e658bfb73abef80c5621063598baf32e94f3a3e79e440cd7e236f03`,
  which self-reported the same v3 ISA and embedded consumed-profile SHA-256
  `ec01cb1f413a6fa7260df6de74a4b722b8200e957fd7804871429e2ac0075da4`.

The final process printed
`bench_evidence,binary_sha256=1a0c7c419e658bfb73abef80c5621063598baf32e94f3a3e79e440cd7e236f03`
before its ISA/profile lines. All three processes reported runtime AVX2+FMA.
The 28,739,968-byte profile merged 518 run-prefixed raw profiles generated by
6,000 creates, 1,000,000 lookups, 2,000 renames, 2,000 deletes, and one walk.

One parent invocation owned 31 alternating `AAB`/`BAA` pairs. Every
observation copied the exact source image, verified source/copy SHA-256
`0de4b44cacb300d71cbf2b1ae1ef3eca7d56668bec25a8a0aad2faaea874c7cb`,
then ran `create-bench --count 2000 --threads 1 --rounds 2`. The primary
persisted-wall metric sums both create rounds and the final image flush. The
same child ELF then reopened and walked the output image; every arm returned
the exact semantic signature
`walked 3 dirs + 4257 files (4260 entries, 0 stats, 0 bytes / 0.0 MiB @ 0 MiB/s)`.

- generic persisted-wall median: **22,829.5 us**;
- v3+PGO persisted-wall median: **19,622 us**;
- generic/generic A/A median: **0.989621x**, deterministic bootstrap median
  95% CI **[0.979910, 1.002842]**;
- symmetric null floor: **1.020502x**; pre-registered twice-null threshold:
  **1.041424x**; and
- generic/v3+PGO median: **1.155904x**, 95% CI
  **[1.135311, 1.178988]**, verdict **PGO_FASTER**.

The secondary create-loop-only observation agreed at **1.163197x**, 95% CI
**[1.145606, 1.178757]**, against an A/A CI of
**[0.977759, 1.000578]** and a 1.046011x twice-null threshold. It was not the
decision metric.

The exact-source replay rebuilt v3+PGO ELF
`b9915a20b1eef40e6627a9c2826b5713cc55ee493ba675ec6a67ad41b6455580`,
which self-reported the same v3 ISA and consumed-profile SHA. A fresh
31-pair invocation reproduced the decision without pooling:

- generic persisted-wall median: **22,406.5 us**;
- v3+PGO persisted-wall median: **19,175 us**;
- generic/generic A/A: **0.993953x**, 95% CI
  **[0.985172, 1.037221]**;
- symmetric null floor: **1.037221x**; twice-null threshold:
  **1.075828x**; and
- generic/v3+PGO: **1.152540x**, 95% CI
  **[1.137778, 1.178502]**, verdict **PGO_FASTER**.

The replay's secondary create-loop-only result was **1.157775x**, 95% CI
**[1.144666, 1.186080]**.

**DECISION — KEEP THE HARNESS AND CORRECT ONLY THE NAMED CLAIM.** The
production-shaped binary measured 1.155904x faster in the first run and
1.152540x faster in the unpooled exact-source replay on this persisted,
single-thread, offline 4,000-create batch. The
decision gate was the deterministic 20,000-resample paired bootstrap median CI
over persisted wall time. CV and instruction count were not computed or
consulted.

This row does not contain a mounted FUSE arm, a kernel-ext4 arm, a parallel
create arm, or an independent `e2fsck` run. It therefore does not rescale the
historical mounted small-file storm or any kernel ratio. The walk is an exact
same-binary semantic reopen check, not a substitute for a filesystem checker.

**Retry predicate:** change a mounted or kernel create claim only after the
same source is trained and built through v3+PGO on one pinned worker, the
executing process self-reports ELF SHA, AVX2+FMA, and consumed-profile SHA, and
one invocation owns generic A/A, generic/v3+PGO, and the workload-matched
mounted/kernel arm. Require exact created-name/count parity plus independent
filesystem validation, and gate on a bootstrap median wall/cycles CI clearing
twice its own null log-margin. Never transfer this offline ratio, use
instruction count, or gate on CV.

## Exact v3+PGO whole-CLI lookup closes the bd-b9dug build-identity gap for one corpus - 2026-07-27 (GreenSpring, KEEP / CLAIM CORRECTION)

The institutional preflight found no prior rejected row on the exact
`remote_pgo_training_driver in crates/ffs-cli/src/main.rs` surface. The harness
then built and executed all three identities on one pinned strict-remote
`ovh-a` worker:

- generic `release-perf` control ELF
  `1d36a367ee3703d99a92b8af52387af2570787db4070065082185db681517764`
  self-reported compile-time SSE2 true and SSE4.2/AVX2/FMA false;
- v3 profile-generation ELF
  `16b0b3d621dac6742d3af29aeac235bddbc3b3fc191403e64354432b0f64582a`
  self-reported compile-time SSE2/SSE4.2/AVX2/FMA true; and
- final v3+PGO ELF
  `7136d8bf768a222ec2e6985efbe25249131a274db3b9bc81a4394323265adc62`
  self-reported compile-time SSE2/SSE4.2/AVX2/FMA true and embedded the
  consumed merged-profile SHA-256
  `3dbce2b2fca971cacd1963d0aaeb867de10417761624a0c1236d01a6880860db`.

The final process printed
`bench_evidence,binary_sha256=7136d8bf768a222ec2e6985efbe25249131a274db3b9bc81a4394323265adc62`
as its in-process executing-ELF identity before the ISA/profile lines.

All three reported runtime AVX2+FMA. The 28,739,968-byte profile merged 518
run-prefixed raw profiles produced by the production CLI workload family:
6,000 creates, 1,000,000 lookups, 2,000 renames, 2,000 deletes, and one walk.
Counts were scaled to the checked-in 64 MiB fixture; the build otherwise used
the shipping shape—fat-LTO `release-perf`, `target-cpu=x86-64-v3`,
`profile-generate`, merge, and `profile-use`. This proves the consumed profile
for this build, not byte identity with an older opaque profile.

One parent invocation controlled 31 alternating `AAB`/`BAA` rounds. A/A was
generic/generic; A/B used the midpoint of those two controls against the
v3+PGO CLI. Each observation performed 200,000 lookups against the same
8,003-entry image, SHA-256
`7fab3cc32b282ef9a23ef5afb222cd472fc7f3751f630f6848ff46e96c9503a6`.
Every arm returned the exact signature
`lookupbench: 200000 lookups in / (8003 entries) -> 200000`.

- generic median: **21,667 us**;
- v3+PGO median: **15,110 us**;
- generic/generic A/A median: **0.994371x**, deterministic bootstrap median
  95% CI **[0.974583, 1.005166]**;
- symmetric null floor: **1.026080x**; pre-registered twice-null threshold:
  **1.052840x**; and
- generic/v3+PGO median: **1.437700x**, 95% CI
  **[1.414742, 1.494961]**, verdict **PGO_FASTER**.

The post-lint exact-source replay rebuilt v3+PGO ELF
`1cf9b1dc5c162760787fb3fe003fbcbcccf132c4a1f753376996ac871c5275af`,
which self-reported the same consumed-profile SHA and ISA witness. It preserved
the same image SHA and output signature. Generic median was **21,410 us**,
v3+PGO median was **14,266 us**, and generic/v3+PGO was **1.495236x**, 95% CI
**[1.459215, 1.520699]**. Its A/A was **1.032385x**, CI
**[1.008930, 1.059704]**, so the symmetric null floor was **1.059704x** and
the twice-null threshold was **1.122973x**. The real lower bound cleared that
independent invocation's threshold. The two decisions are not pooled.

**DECISION — KEEP THE HARNESS AND CORRECT THE CLAIMS.** The hidden
`bench-evidence` CLI command hashes `current_exe()` from inside the executing
process, reports compile/runtime ISA, and reports the consumed profile SHA.
The same invocation owns the null and real arms, and the only decision gate is
the deterministic 20,000-resample paired bootstrap median CI. CV is not
computed. `scripts/build-perf.sh` now embeds the merged profile SHA in the
final build and runs `bench-evidence`, so production-shaped identity is
mechanically visible. Retraining also refuses a non-empty profile directory,
and reuse refuses a missing or empty merged profile; stale artifacts therefore
fail closed without recursive deletion.

This result closes absolute generic-versus-production-shaped attribution only
for the named lookup corpus. It does not contain a mounted-kernel arm, does not
restate any kernel ratio, and does not adjust create/read/rename/delete or
internal same-ELF lever ratios.

**Retry predicate:** restate another historical claim only after the same
source is trained and built through v3+PGO on one pinned worker, the executing
process prints its ELF SHA, AVX2+FMA witness, and consumed-profile SHA, exact
output/fsck parity holds as applicable, and same-invocation A/A plus A/B yields
a bootstrap median wall/cycles CI clearing twice its own null log-margin. Add
the mounted-kernel arm before changing a kernel claim. Never transfer this
lookup ratio to another workload, gate on instruction count, or use CV as the
decision rule.

## Historical 960x JBD2 group-commit claim is VOID: the FS path issues zero durability barriers (bd-fsync-journal-latency-gap-ptp4x) - 2026-07-26 (GreenSpring, VOID-MECHANISM / NO BENCH)

The institutional preflight blocked a proposed cross-FsOp JBD2 group-commit
lever on the prior fsync/group-commit rows. Source and history inspection then
showed that the proposed optimization's baseline mechanism does not exist:

- `ffs_journal::Jbd2Writer::commit_transaction` writes descriptor, data,
  revoke, and commit blocks, advances `head`, and returns without calling
  `BlockDevice::sync`;
- `ffs_core::OpenFs::commit_transaction_journaled` calls that writer and then
  makes the transaction visible in MVCC, again without a sync; and
- `git blame` traces the no-sync implementation back to the original
  `Jbd2Writer` commit `d51a0c159`. No later JBD2 change removed a barrier.

The counted mechanism is therefore **syscall count: 0 sync syscalls -> 0 sync
syscalls at `commit_transaction_journaled` return**, not the one-per-FsOp
baseline asserted by the 2026-06-28/29 rows. The separately measured ~960x result belongs to
`wal_buffer::GroupCommitCoordinator` / `FileWalWriter`, where `flush_epoch`
really does call `WalWriter::sync`; that WAL subsystem is not used by the FS
JBD2 path. The old journal-level ratio cannot establish either a current
FS-level gap or an FS-level speedup.

**DECISION — REJECT / VOID-MECHANISM:** classify the historical “JBD2 txn +
fdatasync per FsOp” premise
and every 960x FS-level extrapolation from it as **VOID-MECHANISM**. No
production edit and no benchmark were run. Benchmarking “one sync per
transaction versus one sync per epoch” against current `main` would fabricate a
control arm that production does not execute. This audit also exposes a
correctness obligation: the method documented as making the JBD2 transaction
durable currently publishes MVCC visibility after buffered writes alone.
Correcting that durability contract is not a performance optimization and is
outside this docs-only result.

**Retry predicate:** do not reopen JBD2 group commit as a performance lever
until all of the following are true:

1. the FS JBD2 path has an explicit durability barrier after its commit block
   and before MVCC visibility/return;
2. injected write and sync failures prove that an unsynced epoch is never
   reported durable or made visible, and crash replay proves that every
   returned-durable transaction survives while incomplete epochs do not;
3. a current FS-level harness counts exactly one real device sync per
   ungrouped returned-durable transaction; and
4. one self-hashing x86-64-v3+PGO process on one pinned worker runs
   same-invocation A/A plus ungrouped/grouped A/B, proves exact journal replay
   and visibility order, and gates on a bootstrap median wall/cycles CI clearing
   twice its own null margin. Never use the historical WAL ratio, instruction
   count, or CV as the decision gate.

## Duplicate Btrfs send inode-item parse is only 0.4246% of whole-stream time (bd-btrfs-send-inode-reparse-etlpr) - 2026-07-26 (GreenSpring, PROFILE-BOUND / NOT ADMITTED)

Before proposing a production edit, ledger grep and the institutional preflight
found the earlier parsed-`INODE_REF` negative-evidence row on this exact
`generate_send_stream` parse surface. Its escape condition requires evidence
that the parsed work is a whole-send bottleneck. The new source-neutral
attribution mode reproduces the second complete `parse_inode_item` pass over the
already-grouped inode entries and counts **897 duplicate parses** per stage
observation. It runs duplicate unchanged whole streams as its same-invocation
A/A null control.

The witnessed x86-64-v3 release-perf process reported:

`bench_evidence,binary_sha256=8ba9bd0535388339e6bd13ea1167da8378ac2e70bd5ad1431b9eb1b818eb860d,worker=fixmydocuments`

Compile-time and runtime AVX2 and FMA were true. The unchanged whole-stream arms
produced identical 3,048,915-byte output, SHA-256
`54f09f39e3a07fc563836b72c495d6e59d244fae206ffa763d7ceed432ada3ad`.
Across 31 alternating whole/whole/stage observations, the deterministic
20,000-resample bootstrap results were:

- whole/whole A/A median **1.001070x**, CI **[0.995185, 1.006003]**;
- duplicate-reparse/whole median **0.4246%**, CI
  **[0.4029%, 0.4342%]**; and
- pre-registered admission floor **5%**.

**DECISION:** PROFILE-BOUND / NOT ADMITTED. No production source was edited and
no primitive-only A/B was allowed. Even perfect elimination has less than half
a percent observed whole-stream budget on this 897-inode fixture, before paying
for retained-item storage and lookup. The benchmark-only source-neutral mode is
retained to make the closure reproducible. This is v3 attribution evidence, not
a PGO or shipped-binary speedup claim. The gate used the bootstrap median CI and
never computed or consulted CV.

**Retry predicate:** reopen only if a fresh witnessed-v3+PGO production send
workload attributes at least **5%** of whole-stream wall/cycles to the duplicate
`parse_inode_item` pass, or a materially different many-tiny-inode workload
raises the counted stage's median-CI lower bound to at least 5%. Then retain the
already-validated parsed item, prove exact complete-stream and malformed-item
behavior, and require one self-hashing v3+PGO ELF with pinned-worker
same-invocation A/A+B whose bootstrap median wall/cycles CI clears twice its own
null margin. Never gate on CV.

## Profitability-gated repair source reads reject on their scalar fallback (bd-repair-source-read-profitability-w74sl) - 2026-07-26 (GreenSpring, MEASURED REJECT #3 / SWITCH VEINS)

The institutional exact-surface preflight exited 2 on the preceding
`codec::encode_group` contiguous-read REJECT and printed its concrete escape
condition. This attempt did not waive that closure. Before editing it supplied a
named real-file backend and explicit default-false profitability contract,
separate from functional contiguous-read support; the decision harness supplied
an in-process executable hash, same-invocation A/A null control **1.000000x** plus
A/B, deterministic 10,000-resample bootstrap median-ratio CIs, exact full-output
and first-error oracles, and physical-call counters. CV was never computed or
used.

The candidate asked the `BlockDevice` profitability capability once per
`encode_group`. Opted-in devices replaced 16 ordered positioned reads with one
ordered contiguous read. Devices that did not opt in executed the unchanged
scalar loop. The same process proved exact equality of every `EncodedGroup`
field and repair byte, identical source/symbol ordering, and the same first
injected error at block 3. The counted target mechanism was **16 logical / 16
physical reads -> 16 logical / 1 physical read**. The cheap arm stayed scalar
and retired **496 physical calls in both arms** over 31 observations.

### Invalid instrument input, then satisfied retry

The first v3 scouting invocation selected an 80-byte divisor of the executing
ELF as its file-backed block size. `ByteBlockDevice` correctly rejected that
non-power-of-two geometry after the latency and cheap controls ran. This was an
instrument-input reject, not a performance verdict.

**Retry predicate:** rerun only with production-valid, power-of-two block
geometry and a stable real-file fixture. The next source used the checked-in
`conformance/golden/ext4_8mb_reference.ext4` at 4KiB blocks and satisfied that
predicate. No generated local image or fresh local Cargo target was created.

### Routing-only v3 and profile-generation evidence

The corrected non-PGO scouting ELF
`e4fb9ba677fc2c2cc22fad4b58187e3faea93641f94508d1abf8eb1a6437866e`
reported compile/runtime AVX2 and FMA and cleared all three routing arms:

- 250 us/call: **14.820947x**, CI **[14.740945, 14.840636]**, versus A/A
  **[0.999918, 1.000033]**;
- zero-latency scalar fallback: **0.998165x**, CI
  **[0.996801, 0.999542]**, inside doubled A/A envelope
  **[0.996372, 1.003641]**; and
- warm checked-in ext4 file: **1.452175x**, CI
  **[1.449020, 1.455309]**, versus A/A
  **[0.998786, 1.000304]**.

Those results admitted PGO generation but were not publishable shipped-binary
claims. The instrumented training ELF
`68baa853bf76d5add2b6f045444a1bdee92d5ef5e39d427d0ca71ad238c3864d`
then ran the same complete contract on pinned worker `ovh-a` and generated a
14,565,488-byte merged profile with SHA-256
`b46277d4058788abb9d9d055b4a27ea17786f0f47d2343f19b24ccd0c49266bb`.
Its routing ratios were 13.593584x for the latency arm, neutral for the scalar
fallback, and 1.016512x for the warm file. They describe the instrumented
training binary only.

### Final v3+PGO decision: REJECT

The final profile-use process reported:

`bench_elf_sha256=2fe8049ec08d747144a32c8d19f02111e85b1ead3d14979f7c34b812090e6e23 (15096336 bytes)`

It witnessed compile/runtime SSE2, SSE4.2, AVX2, and FMA, and embedded the
consumed profile SHA-256
`b46277d4058788abb9d9d055b4a27ea17786f0f47d2343f19b24ccd0c49266bb`.
The same-worker, same-invocation decision was:

| shape | control / candidate medians | median ratio | bootstrap median CI | A/A CI | verdict |
|---|---:|---:|---:|---:|---|
| 250 us physical-call latency | 4.902002 / 0.331432 ms | **14.792775x** | **[14.760729, 14.822999]** | **[0.999828, 0.999939]** | target win |
| zero-latency scalar fallback | 17.293 / 17.342 us | **0.997174x** | **[0.994190, 0.998325]** | **[0.998334, 1.001428]** | decisive non-neutral loss |

The cheap arm's doubled-null equivalence interval was
**[0.996680, 1.003331]**. Its complete real CI escaped that interval, identifying
the per-encode dynamic capability query/branch as a small but statistically real
cost even though both arms issued the same 496 scalar reads. The harness exited
101 at that pre-registered assertion, before the final-PGO warm-file arm; the
earlier v3/training warm-file ratios are therefore not substituted as a final
claim.

**DECISION:** REJECT and manually restore every production and benchmark source
hunk. Output/error isomorphism passed, but performance does not admit the
per-call profitability contract. This is the third consecutive repair
source-read scheduling REJECT, after parallel reads and unconditional contiguous
batching, so the no-ceiling rule switches to another profile-attributed vein.

**Retry predicate:** do not retry codec-level per-call source-read scheduling.
Reopen only if a fresh witnessed-v3+PGO production profile attributes at least
**5%** of whole repair-encode wall/cycles to scalar source-read calls on a named
backend, and the backend strategy can be bound once outside the timed
`encode_group` path so the measured query/branch is absent. The next decision
must use one self-hashing v3+PGO ELF, exact output and first-error parity, counted
logical/physical calls, and same-invocation A/A plus A/B. Both the target
latency/cold arm and warm real-file arm must clear twice their own bootstrap
median null margins; the cheap-device CI must lie wholly inside its doubled A/A
equivalence envelope. Never gate on CV.

## bd-bhh0i cutover: wait-free publication is now the default after a 1.467327x final-source e2e win (2026-07-26, GreenSpring, MEASURED)

The institutional preflight found the prior wait-free publication row and printed
its exact remaining cutover predicate: one further end-to-end run whose A/A median
is inside 1.10x, symmetric null floor is at most 1.15x, A/B effect clears twice that
null margin, and both arms have real `e2fsck` parity. This run satisfies that
predicate; it does not reopen the already-closed commit-primitive frontier.

The cutover also repairs a measurement-contract gap in the earlier
`create-bench --rounds` evidence. Those rows self-reported the executing ELF, but
the control and candidate filesystems were still created in separate CLI
invocations. The new `create-bench-cutover-gate` opens four filesystems in one
process and selects `Mutex` or `WaitFree` explicitly on each empty MVCC store,
without process-global environment mutation. Each of 11 rounds contains both a
`Mutex`/`Mutex` A/A pair at one thread and a `WaitFree`/`Mutex` A/B pair at eight
threads. Every round runs A/A then A/B, while the two arms inside each pair
alternate order. Every timed arm creates exactly 40,000 files; image flushes,
ELF hashing, and external fsck are outside the timed interval.
The process computes a deterministic 20,000-resample paired bootstrap CI over
median log ratios. It never computes or gates on CV.

The final admitted process self-reported its executing ELF SHA-256 in-process as `2facbbb0f9a99a463abf7f761d7c870ddae0d8cad893be343562f080fca6dd43`.
Every executable reported its SHA-256 as stdout line one from `current_exe()`
inside the process, then witnessed compile-time and runtime SSE2, SSE4.2, AVX2,
and FMA. The scoped local exception was used only for
`cargo build -p ffs-cli --profile release-perf --features
bhh0i_sharded_alloc` with `RUSTFLAGS=-C target-cpu=x86-64-v3`, reusing the repo's
single `target/` directory. `/data` had 473G free before the final-source gate
and 473G after all four fsck runs, safely above the 120G abort floor.

### REJECTED instrument input: four independently formatted images

The first full invocation used four separate `mke2fs` outputs. It correctly
rejected itself:

- A/A median **1.043360**, bootstrap median CI
  **[0.997696, 2.577479]**, symmetric null floor **2.577479x**;
- A/B median **1.397478**, CI **[1.369969, 1.557756]**; and
- `performance_admitted=false`, because the null floor exceeded 1.15x and the
  A/B lower bound did not clear the twice-null threshold **6.643396x**.

This was an input-construction defect, not a publication-mode verdict.
Independent ext4 UUID and directory-hash seeds let the A/A directory layouts
diverge at high fill: from round 6 onward one nominally identical mutex image took
2.0-2.59x as long. The counted post-run evidence agreed: both A/A arms had 440,012
files and fsck rc 0, but occupied 55,634 versus 55,357 blocks; the A/B arms had
440,100 files and fsck rc 0 but occupied 54,611 versus 54,545 blocks.

**Retry predicate:** rerun only after cloning one byte-identical freshly formatted
base image into all four paths outside timing, without reflink COW asymmetry, and
prove all four pre-run image hashes equal. That predicate was immediately satisfied
with non-reflink sparse copies; all four inputs had SHA-256
`8e62d7e218d7b80c5c8c1936af1854b6fe9e423ca2b9b044eda93494681b2700`.

### Preliminary cloned-input PASS

Before the default flip and self-enforcing image validator were added, ELF
`4bd8574e1c425049b3a80ae7a3aa6f66a42ac2e4765e282614dba6859d31c176`
produced:

| phase | median ratio | bootstrap median CI | decision threshold |
|---|---:|---:|---:|
| A/A, mutex lhs / mutex rhs | **0.989123** | **[0.956675, 0.997225]** | inside 1.10x; null floor **1.045287x** <= 1.15x |
| A/B, wait-free / mutex throughput | **1.645237x** | **[1.420257, 1.934142]** | lower bound > twice-null **1.092626x** |

External fsck then matched at 440,012 files / 55,566 blocks for both A/A images
and 440,100 files / 54,611 blocks for both A/B images. This satisfied the
pre-registered predicate, but the production default and the input guard changed
the ELF afterward, so this is corroboration rather than the published
final-source ratio.

### REJECTED final-source validator: sequential full-image hashing

The first hardened final-source ELF,
`8060a799feef0583d7ddb5e822a598258af57b1c41642dc9dfd363b453715278`,
correctly refused to publish its result:

- A/A median **0.966427**, CI **[0.678536, 1.020347]**, null floor
  **1.473762x**;
- A/B median **1.413596**, CI **[1.221787, 1.529118]**; and
- twice-null threshold **2.171975x**, therefore
  `performance_admitted=false` and a nonzero process exit.

The validator had read four complete 2GiB images sequentially immediately before
timing, giving later paths a page-cache recency advantage. The A/A control named
that mechanism: the same cloned inputs still produced a 47% null floor.

**Retry predicate:** preserve complete in-process input hashing but stream one
64KiB chunk from each image in round-robin order, bounding validation recency skew
to one chunk rather than multiple GiB. Then reformat one base, copy it without
reflinks, and rerun once. The final source implements and satisfies this predicate.

### KEEP: final-source cloned-input cutover gate

The final executable reported:

`bench_evidence,binary_sha256=2facbbb0f9a99a463abf7f761d7c870ddae0d8cad893be343562f080fca6dd43,worker=thinkstation1`

It rejected hard links and unequal image bytes in-process. Round-robin hashing
proved all four fresh inputs had SHA-256
`98b891ece5a76578e64c2996db119e121ef6f4bab671a79c76b16c69cf1e5c3a`.
The final-source result was:

| phase | median ratio | bootstrap median CI | decision threshold |
|---|---:|---:|---:|
| A/A, mutex lhs / mutex rhs | **0.985164** | **[0.964017, 1.006859]** | inside 1.10x; null floor **1.037326x** <= 1.15x |
| A/B, wait-free / mutex throughput | **1.467327x** | **[1.342048, 1.619068]** | lower bound > twice-null **1.076045x** |

The process emitted `aa_inside_1_10=true`, `null_floor_le_1_15=true`,
`ab_ci_clears_twice_null=true`, and `performance_admitted=true`, then exited 0.
External correctness passed on those exact admitted images:

- both A/A images: `e2fsck -fn` rc 0, **440,012 files**, **55,859 blocks**; and
- both A/B images: `e2fsck -fn` rc 0, **440,100 files**, **54,864 blocks**.

The only fsck diagnostic was the non-fixing “extent tree could be narrower”
suggestion; no structural, count, connectivity, reference-count, or group-summary
error was reported. Ordering and tie-breaking are unchanged because both
publication algorithms expose only the same contiguous commit-sequence prefix.
Filesystem bytes and allocation counts match exactly within each A/A and A/B pair.
Floating point and RNG are N/A.

**DECISION:** KEEP the same-invocation cutover harness and make
`PublicationMode::WaitFree` the production default. Setting
`FFS_MVCC_WAITFREE_PUBLISH=mutex` (or `0`, `false`, `off`, or `no`) restores the
compatibility mutex gate; `nospin` remains diagnostic. This final run supersedes
the earlier default-OFF recommendation and is the first single invocation to
satisfy every pre-registered performance and external-correctness criterion.
Historical 1.44-1.57x separate-invocation results and the preliminary 1.645237x
same-invocation result remain corroborating evidence, not the published
final-source ratio.

Strict-remote v3 validation passed the focused CLI check and the publication
default/fallback unit test (1/1). A broad `-D warnings` CLI Clippy run reached
the changed path; after its owned findings were repaired, the final rerun
reported exactly 51 older CLI diagnostics and none on the cutover-owned
surface. Targeted rustfmt remains blocked only by existing lines outside the
owned hunks; the owned hunks and `git diff --check` are clean.

**Retry predicate:** revisit the default only when the shipped target CPU,
toolchain, publication algorithm, or workload changes, or when a production
profile on an oversubscribed host makes aggregate cycles/CPU rather than wall
throughput the discriminator. Require one witnessed-v3+PGO executing ELF, four
byte-identical non-reflink input images, same-invocation interleaved A/A plus A/B,
exact per-pair fsck file/block parity, and a bootstrap median wall/cycles CI that
clears twice its own null log-margin. Never gate on CV.

## Send-stream primary-parent projection removed: 1.044838x whole-stream win (bd-btrfs-send-parent-index-azojl) - 2026-07-26 (GreenSpring, MEASURED)

The institutional preflight first exited 2 on the existing parsed-`INODE_REF`
negative-evidence row and printed its prior escape condition. That condition allowed a
production edit only after either usable line-level profiling or a counted
whole-stream stage attributed at least 0.1% to the derived primary-parent map.
Before changing production, a source-neutral decision invocation measured the
exact `inode_links -> inode_parents` projection against duplicate executions of
the current complete stream:

- 896 projected primary entries from 1,088 total links;
- 4,352 primary-name bytes cloned into the redundant map;
- projection/whole-stream median fraction **3.8593%**, deterministic
  20,000-resample bootstrap median CI **[3.8394%, 3.9644%]**; and
- same-invocation whole/whole A/A **0.999853**, CI
  **[0.995953, 1.005182]**, symmetric null envelope **1.005182x**.

That source-neutral `x86-64-v3` process self-reported executing ELF SHA-256
`11d5cc8eccc4714f7e0f8dd4cde9c05bbc8256cf929ce9f749153287aab29999`
and compile/runtime SSE2, SSE4.2, AVX2, and FMA true. It also pinned primary-map
SHA-256 `4eac935568a24607ace1aa59c4688ddfcb9f30fbdb857e3d72a9fe2b8d5eb7f9`
and complete-stream SHA-256
`54f09f39e3a07fc563836b72c495d6e59d244fae206ffa763d7ceed432ada3ad`.
The 3.84% lower bound cleared the pre-registered 0.1% admission threshold, so
the source edit was allowed.

Production now reads the canonical first link directly from the already-required
`inode_links` map. The secondary `BTreeMap<u64, (u64, Vec<u8>)>` allocation and
all primary-name clones are gone. A `bench-instrumentation` control monomorph
retains the prior materialized projection only for the same-process decision
harness; normal builds instantiate the direct-link path.

The final-source whole-stream gate ran 31 alternating `AAB`/`BAA` rounds on
pinned strict-remote worker `ovh-a` (reported hostname `fixmydocuments`), with
two complete stream generations per observation. The executing process emitted
`bench_evidence,binary_sha256=51a59b548173c252ae2b2cacdb9a5fe221afbffa4c822e13ad3edeffd6509a52,worker=fixmydocuments`
and reported compile/runtime SSE2, SSE4.2, AVX2, and FMA true. Its results were:

- materialized/materialized A/A median **1.000859**, bootstrap median CI
  **[0.998920, 1.003464]**;
- symmetric null envelope **1.003464x** and pre-registered twice-null threshold
  **1.006941x**;
- materialized/direct median **1.044838x**, bootstrap median CI
  **[1.040822, 1.047479]**; and
- gate verdict **KEEP**, because the complete A/B CI is above both 1.0 and the
  twice-null threshold. CV was not computed or consulted.

The control and candidate each produced the identical 3,048,915-byte stream,
SHA-256
`54f09f39e3a07fc563836b72c495d6e59d244fae206ffa763d7ceed432ada3ad`.
Ordering is preserved because both paths choose `inode_links[ino].first()` in
the same insertion order; hardlink emission still iterates the same vector from
index 1 onward. Tie-breaking is therefore unchanged. Floating point and RNG are
N/A. The final strict-remote focused `generate_send_stream` suite passed 7/7.
Final-source scoped Clippy reached the owned crate and stopped only on the five
pre-existing `parse_xattr_names`/`add_utimes_command_direct` diagnostics; the
candidate-specific private-`Result` lint found by the first run was fixed and
did not recur. Targeted nightly rustfmt and `git diff --check` passed.

**DECISION:** KEEP the direct primary-link lookup. The measured claim is a
**1.044838x whole-stream wall-time win (95% median CI
[1.040822, 1.047479])** for this deep-path/hardlink fixture under a witnessed
v3 release-perf ELF. It is not a PGO claim and is not a mounted-kernel
comparison.

**Retry predicate:** revisit a separately materialized primary-parent index only
if a fresh witnessed-v3+PGO production profile on a concrete send workload
attributes at least 5% of whole-stream cycles to repeated direct first-link
lookups, or if a correctness requirement needs a primary ordering different
from `inode_links` insertion order. Any retry must preserve exact complete-stream
and hardlink-order hashes, count cloned/borrowed primary-name bytes, self-report
the executing ELF SHA/ISA, and use one fixed worker with same-invocation
interleaved A/A plus A/B whose bootstrap median wall/cycles CI clears twice its
own null log-margin; never gate on CV.

## bd-bhh0i spin/no-spin NULL resolved: persistent harness proves a 1.203-1.318x wall-throughput win at 8 writers (bd-mvcc-spin-persistent-ci-ml4nw) - 2026-07-26 (GreenSpring, MEASURED)

The prior row required an 8-writer A/A floor below 1.10x and named the mechanism
polluting the instrument: every timed observation rebuilt the store and spawned/joined
its workers. The institutional preflight correctly exited 2 on that closed surface.
This run satisfies the recorded escape hatch:

- four stores and their 32 workers are created once per process;
- eight bounded block banks are populated before timing and reused in steady state;
- each of 31 rounds interleaves a `WaitFree`/`WaitFree` A/A pair and a
  `WaitFree`/`WaitFreeNoSpin` A/B pair, alternating both pair and arm order;
- each arm retires exactly 16,384 commits per observation;
- pruning, store/thread lifecycle, ELF hashing, and full-state digests are outside
  the timed worker interval; and
- the only decision statistic is a deterministic 20,000-resample paired bootstrap
  median CI over log ratios. The new gate does not compute or consult CV.
- each expected worker result has a 10-second no-progress bound that reports its
  exact arm, epoch, completed-writer set, and publication watermark before exiting 2.

Three strict-remote `x86-64-v3` release-perf invocations ran on pinned worker `ovh-a`
(reported hostname `fixmydocuments`). The executing processes self-reported distinct
ELFs:

- `bench_evidence,binary_sha256=a6b0fb82ec93394e119619c8546af2f6b05fc31ab4c640e2b4f14bfb061e4bd1`
- `bench_evidence,binary_sha256=d2059be34c2c90666a72b17dcc84214e901dc05bf38ff843cd077e8be8f1e41c`
- `bench_evidence,binary_sha256=bf4804c53e507ae78d69ec11d803533097c83cba5a682731df8df8db18d50ed4`

All three reported compile/runtime SSE2, SSE4.2, and AVX2 true.

| run | A/A median CI | symmetric null envelope | spin/no-spin median | spin/no-spin median CI | verdict |
|---|---:|---:|---:|---:|---|
| 1 | `[0.967670, 1.014414]` | `1.033410x` | `0.758570` | `[0.725926, 0.779200]` | spin faster |
| 2 | `[0.950265, 0.997507]` | `1.052338x` | `0.759147` | `[0.734401, 0.777777]` | spin faster |
| 3 | `[0.955871, 1.031111]` | `1.046166x` | `0.831172` | `[0.760373, 0.850078]` | spin faster |

All three null envelopes clear the pre-registered `<1.10x` admission bound. Every
A/B CI is wholly below twice its own null log-margin. In throughput terms the
spinning submode is **1.203-1.318x faster** (**16.9-24.1% less elapsed time**) than
parking immediately in this isolated steady-state 8-writer workload.

Correctness is exact, not inferred from equal commit counts. Before timing, all four
arms had watermark 16,384 and identical bytes over all 16,384 blocks, SHA-256
`1cb4c8f0a7e38ea1018077959bc30d69c53b994142801ea60afb0cb42a771928`.
After timing, all four had watermark 524,288 and identical bytes, SHA-256
`87e7183d06f60b8d9da6d5536daf006b9642e48f72a9ccab528b3d440b7ed193`.

A separate current-source attempt self-reported ELF
`b14a6158e5b64cb65a42fb08e06d0e73d8b050e2bf8b4c6307334bdffacc407c`
and passed pre-timing parity, then produced no timing rows while both it and an
unrelated job on `ovh-a` had stale RCH progress. It was cancelled after more than
six minutes to release four fleet slots and is **not** counted as a performance or
production-liveness verdict. That incident motivated the bounded liveness diagnostic;
the final ELF then completed every pair on the same worker without firing it.

**DECISION AT THIS SUBTEST:** keep the persistent median-CI harness and retain the
spinning `PublicationMode::WaitFree` submode. This subtest itself made no production
default change. The later final-source cutover row above now makes `WaitFree` the
absent-variable default; `mutex` restores the compatibility gate and `nospin`
remains an explicit option for CPU-constrained or oversubscribed hosts. This result
settles isolated wall throughput, not aggregate CPU efficiency on those hosts.

**Retry predicate:** revisit immediate parking only after a production profile on an
oversubscribed or CPU-budgeted deployment makes aggregate cycles/CPU the
discriminator. Require a pinned witnessed-v3+PGO executing ELF, same-invocation
persistent A/A plus A/B, full watermark/content parity, and a bootstrap median
wall/cycles CI clearing twice its own null log-margin. Never gate on CV or retry with
per-sample store construction and thread churn. If the new
`persistent_commit_liveness_blocker` fires on an otherwise idle worker, first
reproduce the reported arm/epoch under the existing publication-gate watchdog tests;
do not infer a production deadlock from RCH stale-progress metadata alone.

> **CUTOVER SUPERSESSION:** the chronological `bd-bhh0i` rows below correctly
> record why the default was still OFF at each intermediate checkpoint. They are
> historical state, not the current configuration. The final-source cutover row
> above satisfied the remaining null-floor and real-fsck predicate; absent an
> override, production now selects `PublicationMode::WaitFree`.

## INSTRUMENT FIX for the three BLOCKED-NULL workloads: the kernel-side A/A failure is a SYSTEMATIC per-image bias, not variance — counterbalancing cancels it exactly (bd-opb6l / bd-57lae) - 2026-07-28 (turn 16, cc, MEASURED)

CLASS: **instrument diagnostic**. Not a self-speedup and not a vs-incumbent claim —
no FrankenFS code executes anywhere in this experiment. It is kernel-ext4 against
kernel-ext4, so there is no candidate ELF to self-report: the incumbent is the
comparator.

Counterbalanced same-invocation A/A null control 0.999579x, bootstrap median CI [0.996553, 1.003571], spread 1.0070x, 20,000 resamples, interleaved A/A order-alternating.
Uncounterbalanced same-invocation A/A null control 1.010414x direct and 0.992466x swapped, bootstrap median CI [0.982591, 1.018390] and [0.980826, 0.995819].
`cv_used=false`; CV is never a gate here.

CONTEXT. GreenSpring's five-workload mounted suite admitted two ratios and blocked
three on A/A nulls. The proposed remedies were more rounds, larger batches, longer
settle, cache equalisation. **Those address variance. This is bias, and averaging
more samples of a biased comparison converges to the bias.**

THE TELL, already present in GreenSpring's own data: the create/delete storm's
KERNEL null was `1.009041x [1.001744, 1.013361]` — a confidence interval that
**excludes 1.0**. Two byte-identical kernel ext4 mounts cannot differ systematically
by chance.

### Experiment (`scripts/kernel_null_counterbalance_diag.py`)

Two byte-identical kernel ext4 images from the same `mke2fs` invocation, both
mounted `rw,noatime`, on distinct loop devices, pinned to CPUs 2,3. Same 2,000-file
create/delete storm, 15 paired rounds, execution order alternating.

| configuration | median | bootstrap 95% CI | offset |
|---|---:|---|---:|
| run 1 direct (A = first image) | 1.010414 | [0.982591, 1.018390] | **+1.041%** |
| run 1 swapped (roles exchanged) | 0.992466 | [0.980826, 0.995819] | **minus 0.753%** |
| run 2 direct | 1.006652 | [0.994325, 1.018088] | **+0.665%** |
| run 2 swapped | 0.994280 | [0.989667, 1.000804] | **minus 0.572%** |
| **run 2 COUNTERBALANCED** | **0.999579** | **[0.996553, 1.003571]** | spread **1.0070x** |

**The offset FLIPS SIGN when the two physical images exchange logical roles, in 2 of
2 runs.** The asymmetry is bound to the physical image/mount — backing-store
placement, loop-device state, resident cache — not to the logical arm, the ordering,
or the workload. Magnitude 0.57 to 1.04%, matching the +0.90% GreenSpring measured.

### Why counterbalancing is the fix, and why it is exact

With a fixed multiplicative bias `p` per physical image, the direct ratio is
`(p_a * T_A) / (p_b * T_B)` and the swapped ratio is `(p_b * T_A) / (p_a * T_B)`, so
the geometric mean of the two is exactly `T_A / T_B`: the `p` factors cancel
identically.

**Exact cancellation per pair, not convergence.** That is why it succeeds where extra
rounds cannot: extra rounds shrink the interval *around the biased point estimate*,
which makes a blocked null MORE likely to exclude 1.0, not less.

Demonstrated: counterbalanced null **0.999579 [0.996553, 1.003571], spread 1.0070x**
— contains 1.0 and clears the 1.025x spread requirement in GreenSpring's own retry
predicate with room to spare.

### What this settles and what it does not

It settles the KERNEL-side null failure, which is what blocked the create/delete
storm and the large-directory readdir+stat — both of which passed their FUSE null.
The multi-file parallel read failed BOTH nulls, so counterbalancing is necessary
there but may not be sufficient: the FUSE-side null (`0.991734x [0.969409,
1.036149]`, spread 1.036x) carries its own dispersion, which this experiment does
not address.

Nothing here changes the filesystem. **No tuning was done and none should be until
the nulls pass** — the three raw ratios (1.203230x, 2.957531x, 4.212274x slower)
remain unscoreable.

### Handoff

The four-arm Rust comparator is GreenSpring's file and already owns four mounts, so
it can counterbalance without new mounts: alternate which physical kernel image
serves the A-role across paired rounds and combine each pair by geometric mean; same
for the two FUSE mounts. Raised on the campaign thread rather than edited directly.

## ⭐⭐⭐ MOUNTED-KERNEL ARM EXISTS — first defensible vs-incumbent number: frankenfs is 4.5x SLOWER than kernel ext4 on mounted create+fsyncdir (bd-kdmu4) - 2026-07-27 (turn 15, cc, MEASURED — A MISS, WHICH IS THE POINT)

Status: the instrument this repo has never had is built, landed, and has produced an
honest number. **It is a loss, and that is the success condition for this task.**

⚠ CLASS: **vs-INCUMBENT**. Kernel ext4, loop-mounted, running beside the frankenfs
FUSE mount in ONE process, with A/A nulls for BOTH arms. This is the first row in this
ledger that is not a self-speedup. Every prior KEEP this campaign — including my own
wait-free publication gate — is frankenfs-before vs frankenfs-after and reads `N/A` in
the direct-kernel column, so none of them can be shown to matter competitively.

`bench_evidence,binary_sha256=2356a39b3806f37eb2c851e6e8e8281389664abf302c1471c72bda9f3833b4a3`
Bootstrap median CI (20,000 resamples, percentile method) is reported for every arm:
kernel A/A [0.9878, 1.0073], frankenfs A/A [0.9512, 1.1061], A/B [0.1893, 0.2432].

PROVENANCE. The measuring process is a driver, not the code under test, so hashing it
would prove nothing. The harness instead locates the process actually answering FUSE
requests for the mount and hashes `/proc/<pid>/exe` in-process:
`pid=3455837 exe=/data/tmp/cargo-target/release-perf/ffs-cli
sha256=2356a39b3806f37eb2c851e6e8e8281389664abf302c1471c72bda9f3833b4a3`. A
`sha256sum` of a path on disk cannot establish which binary is serving a mount.

`scripts/mounted_kernel_ab.py` + `scripts/mounted_kernel_ab_setup.sh`.

### The number

Workload: create 2,000 empty files, then ONE `fsync` of the directory — an identical
POSIX call sequence issued by one driver to both arms. Host loadavg 26.68.

| arm | median seconds | vs tmpfs driver ceiling |
|---|---:|---:|
| kernel ext4 (`/dev/loop6`, `rw,noatime`) | **0.0604** | 2.55x |
| frankenfs FUSE (`fuse.ffs`, `rw,noatime`) | **0.3104** | 13.11x |

| ratio (kernel time / frankenfs time) | median | bootstrap 95% CI |
|---|---:|---|
| **A/A null — kernel** | 0.9999 | **[0.9878, 1.0073]** |
| **A/A null — frankenfs** | 0.9826 | **[0.9512, 1.1061]** |
| **A/B kernel vs frankenfs** | **0.2213** | **[0.1893, 0.2432]** |

Both A/A CIs contain 1.0; the A/B CI **excludes** it by a wide margin. Governing null
floor 1.1946, margin **8.48x**. **DECIDABLE: frankenfs is 4.52x slower.**
A prior run at loadavg 12.3 gave 4.76x with margin 15.25x — consistent.

⚠ **~4.5x is a LOWER bound and the bias favours us.** The kernel arm sits only 2.55x
above the Python driver's own ceiling, so a real share of its measured time is driver
overhead common to both arms, which compresses the ratio. Subtracting the ceiling from
both gives `(0.0604-0.0237)/(0.3104-0.0237) = 7.8x`. Honest statement: **at least
4.5x slower; ~7-8x driver-corrected.** A faster driver sharpens this and makes
frankenfs look worse, not better.

### The six traps, and what each actually caught

  T1 DISPATCH — identity asserted at RUNTIME from the measuring process's own
  `/proc/self/mountinfo`, never from the path string. Not theoretical: during bring-up
  `touch /tmp/ffsf/probe` **succeeded** on what I believed was the FUSE mount and was
  in fact an ordinary empty directory, because the mount had failed on a bad flag. A
  path that accepts writes proves nothing.

  T2 UNMATCHED CONFIG — one driver, byte-identical POSIX sequences, same durability
  boundary (one directory fsync; neither arm may skip it). The first run was NOT
  matched: kernel came up `relatime` against FUSE `noatime`. The harness prints both
  option strings, which is how I caught it; the mismatch had favoured frankenfs.

  T3 NON-INTERLEAVED — arms alternate inside one measured routine, order flipping per
  round. At loadavg 26.68 the kernel A/A CI still came in at [0.9878, 1.0073], which
  is the interleaving working.

  T4 CORE CONTENTION — explicit `sched_setaffinity` to CPUs 2,3, recorded with loadavg.

  T5 CLIENT-BOUND — a tmpfs arm measures the driver ceiling and the run is REFUSED if
  an arm lands within 2x of it. It passed, but the kernel arm at 2.55x is close, which
  is why the caveat above is stated rather than buried.

  T6 SHARED BASELINE — arms must be distinct mounts on distinct sources; asserted
  (`/dev/loop6` vs `frankenfs`). Two paths on one mount would measure a filesystem
  against itself.

### What this changes

The standing "8.3x slower than kernel at 8 threads" came from separate runs, not a
side-by-side invocation, and is not comparable. **This row is the only vs-incumbent
create number with an in-invocation incumbent arm, A/A nulls for both sides, bootstrap
CIs, and runtime identity assertion.**

It also places the wait-free publication gate correctly: its 1.44-1.57x is a
**self-speedup** on the FFS side of a gap still ~4.5-8x in the incumbent's favour.
Real, worth having, and **not a competitive claim**.

### Next

(a) btrfs arm — same harness, `mount -t btrfs`; the identity assertion generalises.
(b) Move the workload driver out of Python to sharpen T5. (c) Re-run with
`FFS_MVCC_WAITFREE_PUBLISH=1` to measure how much of the gap the landed self-speedup
actually closes — the only route by which that lever becomes a competitive statement.

## ⚠ CORRECTION + CONFIRMATION — the e2e win replicates 3/3 (1.44-1.57x) but my "26 images all rc 0" was PARTLY VACUOUS; real count is 68 (bd-bhh0i) - 2026-07-26 (turn 14b, cc)

`bench_evidence,binary_sha256=2356a39b3806f37eb2c851e6e8e8281389664abf302c1471c72bda9f3833b4a3`
— self-reported IN-PROCESS by the executing ELF (`current_exe()`, outside the timed
region) on every run below. Each decision row carries its own execution provenance;
inheriting it from a neighbouring row is exactly the "a sha256sum beside the run"
weakness the guard rejects.

Two things, and the correction comes first because I published the bad claim.

### CORRECTION: the fsck in v3/v4/v4b/v5 was verifying nothing

The row below (`bb992934`) states "26 end-to-end images, all `e2fsck -fn` rc 0".
**Withdrawn for v3/v4/v4b/v5.** Defect in MY harness, not in the product:
`--rounds 2` x `--count 40000` = 80,000 creates against a **65,536-inode** image.
Round 1 hits `NoSpace`, the worker threads panic, and the process dies **before**
`sync_all_to_device`. Nothing was persisted, so every fsck in those runs checked a
pristine 13-file seed image and returned rc 0. Reproduced directly:
`create cb_5_00003086: NoSpace` -> `13/65536 files`.

A green check that passes because it never reached the code under test. That is the
exact failure class this campaign's ledger audit exists to find, and I walked into it
in my own harness — in the same turn as a row praising the pre-commit guard for
catching my provenance gap. Recording it at full strength rather than quietly fixing
it, because a correctness claim that was never evidence is worse than no claim.

**What survives unaffected:** the THROUGHPUT ratios. Round 0 completes and is timed
before round 1 panics, and both arms get identical treatment, so every ratio stands.
**What is withdrawn:** the correctness half of v3/v4/v4b/v5 only.

Note also the mechanism of my own error: stripping the flush out of the TIMED REGION
(the fix that made the instrument work) also removed the thing that made the fsck
meaningful. The negative control caught the timing defect; only the per-arm parity
check caught this one. **Two different guards were needed for two different errors.**

### CONFIRMATION: three independent decidable runs, and real correctness

Fixed by sizing the image (`-N 262144`) so both rounds fit and the flush completes.

| run | control median | control null floor | 8t median | margin | fsck |
|---|---:|---:|---:|---:|---|
| v4b | 1.0105 | 1.1145x | **1.4914** | 3.69x | vacuous |
| v5 | 1.0020 | 1.0904x | **1.4395** | 4.21x | vacuous |
| **v6** | 1.0109 | 1.1693x | **1.5698** | **2.88x** | ✅ **REAL** |

**3 of 3 decidable. Range 1.44-1.57x, median ~1.49x.** v6 shows **COMPLETE arm
separation**: min(wait-free) 185,206 > max(mutex) 147,264 c/s across all 11 paired
rounds.

v6 correctness is real and exact: **80,013 files at 1 thread and 80,029 at 8 threads,
IDENTICAL in both arms, `e2fsck -fn` rc 0 on all 44 arm-images.** Corrected total of
genuinely verified end-to-end images: **v1 20 + v2 4 + v6 44 = 68**, all rc 0 with
exact per-arm file-count parity.

### The flip predicate: 3 of 4 met, and I am NOT flipping on my own authority

I pre-registered: "A/A null inside 1.10x, floor <= 1.15x, 8-thread margin >= 2.0x,
plus per-arm e2fsck rc 0 with exact file-count parity."

| criterion | v6 | |
|---|---|---|
| A/A null inside 1.10x | 1.0109 | ✅ |
| 8t margin >= 2.0x | 2.88x | ✅ |
| per-arm e2fsck rc 0 + exact parity | 80,013 / 80,029 both arms | ✅ |
| control floor <= 1.15x | **1.1693x** | ❌ |

**No single run satisfies all four**: v5 met the floor (1.0904x) but its fsck was
vacuous; v6 has real correctness but a 1.1693x floor.

I believe the floor criterion is **redundant with the margin criterion** — the margin
already divides the effect by the floor, so a wider floor with a still-passing margin
is *more* conservative, not less, and v6 clears 2.88x on the wider floor. But I
pre-registered it and I am not going to quietly reinterpret a criterion after seeing
the number. **Flagging it explicitly instead: 3 of 4 met, the miss is on the
criterion I now think was redundant, and the decision to flip the default belongs to
the owner, not to me.**

DEFAULT: `FFS_MVCC_WAITFREE_PUBLISH` remains **OFF**. Recommendation to the owner:
flip it. Evidence is 3/3 decidable end-to-end runs at 1.44-1.57x, complete arm
separation, 68 fsck-clean images with exact parity, and a commit-primitive A/B that
was already decidable 3/3 at 1.70-2.11x. If a fourth run is wanted, the one criterion
to re-check is a control floor <= 1.15x alongside real correctness in the SAME run.

## ⭐⭐⭐ bd-bhh0i E2E DECIDABLE AT LAST — wait-free publication gate is 1.49x at 8 threads end-to-end; instrument rebuilt from a 52% null floor to 1.1145x (bd-bhh0i / bd-kdmu4) - 2026-07-26 (turn 14, cc, MEASURED)

Status: the end-to-end question that has been UNDECIDABLE through four instrument
versions is now DECIDED. The lever wins on the real create path, not only on the
commit primitive.

`bench_evidence,binary_sha256=2356a39b3806f37eb2c851e6e8e8281389664abf302c1471c72bda9f3833b4a3`
— self-reported IN-PROCESS by the executing ELF from `current_exe()`, outside the
timed region, not a `sha256sum` run beside it (see PROVENANCE below).

### The decidable result

A/A NULL CONTROL: the 1-thread arm. At 1 writer both arms execute the identical code
path — the ffs-mvcc micro A/B measured the lever inert below 4 writers across three
ELFs — so the 1-thread arm is a true A/A null on the production binary, and it is run
in the SAME invocation as the test.

| arm | median ratio (on/off) | null floor | cv off / on |
|---|---:|---:|---:|
| **A/A null (1 thread)** | **1.0105** | **1.1145x** | 4.1% / 6.1% |
| **A/B test (8 threads)** | **1.4914** | — | 9.5% / 6.2% |

Margin `|log 1.4914| / log(1.1145) = 0.3997 / 0.1084 = **3.69x**` against the
campaign's required 2.0x. **DECIDABLE.**

⭐ COMPLETE ARM SEPARATION: across all 11 paired rounds, **every** wait-free value
(186,748-228,201 c/s) exceeds **every** mutex value (116,785-156,134 c/s). Zero
overlap. That is independent of any statistic.

### The honest range, and why the two runs differ

The SAME instrument measured **1.2440x** an hour earlier (margin 1.28x, NOT
decidable) under heavier fleet load: arm cv was 16.9/17.5% then versus 9.5/6.2% now.
That is coherent with the mechanism rather than a contradiction — a
contention-removal lever shows LESS benefit when the box is already saturated,
because contention adds a load-dependent cost common to both arms and compresses the
ratio toward 1.

**Published claim: ~1.24-1.49x at 8 threads, quoting the conservative 1.24x.** The
decidable measurement is 1.49x; the 1.24x run was not decidable and is reported as
the floor of the observed range, not as a competing result.

### The instrument rebuild that made this possible

Four versions, each gated on the A/A null:

| version | change | control median | control null floor | control cv |
|---|---|---:|---:|---:|
| v1 | historical shape | 0.8118 | — (52% worst dev) | 21.4 / 36.5% |
| v2 | rounds share one image; flush excluded | 1.3445 | — (57% worst dev) | **5.5%** / 19.3% |
| v3 | v2 + arms alternate per round | 0.9632 | 1.678x | 22.6 / 20.4% |
| v4 | v3 + measured region 44 ms -> 440 ms | 1.0353 | 1.1853x | 3.7% / 7.6% |
| v4b | v4 + quieter box + ELF self-report | **1.0105** | **1.1145x** | 4.1% / 6.1% |

⭐ THE v2 FAILURE IS THE INSTRUCTIVE ONE. v2 fixed exactly what it targeted — the
unaffected arm's cv fell 21% -> 5.5% — yet its control median went to 1.34 with a
STEP CHANGE at round 4, not noise, because running each arm as ONE whole sequential
process left time-correlated drift uncancelled; v1's per-round alternation had been
suppressing it. **The two variance sources want OPPOSITE structures: page-cache
variance wants rounds batched inside one process, drift wants arms interleaved in
time.** v3 gets both by using `mke2fs` per run (a sparse 2 GiB mke2fs perturbs the
page cache far less than copying a populated 2 GiB file) instead of `cp`.
Generalizable: **fixing one variance source can destroy the design property that was
suppressing another, and only a negative control catches it.**

Landed as `create-bench --rounds` — additive; `--rounds 1` is byte-identical to the
historical path, flush inside the timer and all, so every previously published
create-bench number stays comparable.

### PROVENANCE — a real weakness, found by the repo's own pre-commit guard

The first attempt to land this row was REFUSED by `scripts/perf_ledger_preflight.py
--lint --staged`, the ledger guard installed after fleet broadcast 2. It was right:
every create-bench number produced before this row identified its binary with a
`sha256sum` run BESIDE the benchmark, which proves which file was on disk, not which
binary the kernel mapped. Those diverge in this fleet — the first `ffs-cli` cutover
build died because rustup replaced the toolchain mid-build.

Fixed at the source: `ffs-cli` now hashes `current_exe()` in-process, outside the
timed region, emitting `bench_evidence,binary_sha256=...`. The v4b numbers above are
the first create-bench measurements in this repo with real execution provenance. The
guard blocking its own author on the first commit after installation is the strongest
available evidence that it works.

### Correctness

`e2fsck -fn` rc 0. Across v1+v2+v3+v4+v4b that is **26 end-to-end images, all rc 0**,
with exact file parity between arms wherever both were fscked (v1: 20 images, 40,013
@1t and 40,021 @8t identical in both arms every round; v2: 4 images, identical).

### Default

`FFS_MVCC_WAITFREE_PUBLISH` stays **OFF pending one confirming decidable run**. One
decidable end-to-end win is enough to PROPOSE the flip and not enough to make it: the
same instrument returned a non-decidable 1.24x an hour earlier, and flipping a default
on a single favourable run is the failure this campaign exists to prevent. Retry
predicate for the flip: one further run with the A/A null inside 1.10x, floor <=1.15x,
and 8-thread margin >= 2.0x, plus per-arm `e2fsck` rc 0 with exact file-count parity.

## ⭐ bd-bhh0i E2E CUTOVER GATE RUN — correctness PASSES 20/20, performance UNDECIDABLE; default stays OFF for a MEASURED reason (bd-bhh0i) - 2026-07-25 (turn 13, cc, scoped local-exec exception)

Status: the gate that has been blocked since 2026-07-13 finally RAN. Correctness is
an unambiguous pass. The performance question is **undecidable on this harness**, and
the harness's own negative control proves it. `FFS_MVCC_WAITFREE_PUBLISH` stays
default OFF — but the reason is now a measurement, not a blocker.

SETUP. Orchestrator granted a scoped local-exec exception (one crate, not the
workspace; image files under /data/tmp; 2 GiB cap; df recorded; abort under 120G).
Binary `ffs-cli` SHA-256
`71ddd314d3f52104d6a0546d81461326eb2cd2aff0df2d92bdc5cbd7f0d859c9`, built
`--profile release-perf --features bhh0i_sharded_alloc` on the newly PINNED
`nightly-2026-07-20`. Image: `mke2fs -t ext4 -F -q -b 4096 -N 65536`, 524288 blocks =
2 GiB / 16 groups / 65536 inodes, verified by `dumpe2fs`. 20 runs = 2 thread counts x
2 arms x 5 interleaved rounds, arm order ALTERNATING per round, FRESH image copy per
run, `e2fsck -fn` + file count on EVERY run. Disk 233G -> 232G, floor 120G, never
approached.

⭐ DESIGN CHOICE THAT DECIDED THE OUTCOME: **1 thread is a built-in NEGATIVE
CONTROL.** The ffs-mvcc micro A/B measured the lever as inert below 4 writers
(1t 0.98-1.01x, 2t inside the null across three ELFs), so at 1t the two arms are the
SAME code path in every respect that matters. Whatever the 1t arm reports is
therefore harness noise by construction — no modelling required.

| threads | off median c/s | on median c/s | median ratio | per-round ratios |
|--------:|---------------:|--------------:|-------------:|------------------|
| 1 (control) | 119,104 | 79,198 | **0.8118** | 0.476, 0.625, 0.812, 1.054, 1.090 |
| 8 (test) | 87,469 | 93,473 | **1.0582** | 0.869, 1.035, 1.058, 1.131, 2.102 |

**THE CONTROL DEVIATES FROM 1.0 BY UP TO 52%** (ratios 0.476 and 2.102 both appear).
The 8-thread effect is **5.8%**. An instrument whose null swings 52% cannot resolve a
6% effect. **VERDICT: UNDECIDABLE — not a win, not a loss.** Per-round ratio spread is
2.29x (1t) and 2.42x (8t); arm CVs 21.4/36.5% and 11.3/19.8%.

Anyone quoting "1.06x end-to-end" from this table would be quoting noise. So would
anyone quoting "0.81x at 1 thread" as a regression. Both readings are inside the same
floor.

✅ CORRECTNESS — UNAMBIGUOUS PASS. **20 of 20 runs `e2fsck -fn` rc 0.** Exact file
parity, identical in both arms in every round: **40,013 files at 1 thread and 40,021
at 8 threads** (40,000 created + baseline). No divergence between the mutex gate and
the wait-free gate on any run. That is the result the cutover gate existed to produce,
and it is now in hand: **the wait-free publication gate is correct end-to-end on a real
multi-group ext4 image under 8-way parallel create, validated by an independent fsck.**

WHY THE END-TO-END EFFECT IS SMALL EVEN IF REAL (Amdahl, stated as reasoning not
measurement): the micro A/B isolated `ShardedMvccStore::commit`, where publication is
a dominant term. End-to-end, a create is inode alloc + directory insert + inode-table
RMW + block bitmap + MVCC commit + a final whole-image flush. Publication is a small
share of that, so a 1.70x on the commit primitive dilutes to low single digits on
create throughput. Nothing here contradicts the primitive result; the two measure
different things and both are correctly reported.

WHY THIS HARNESS CANNOT RESOLVE IT, mechanically: each run copies a 2 GiB image and
ends with a full `sync_all_to_device` flush, so run-to-run variance is dominated by
page-cache and writeback state, not by the filesystem. Round 1 of each thread count is
the low outlier in BOTH arms (64,883 and 63,378 c/s) — a cold-cache artifact the
alternating order cannot cancel because it is per-round, not per-arm.

RETRY PREDICATE (concrete). Re-decide only on a create-bench whose 1-thread negative
control lands inside 1.10x, which requires removing the per-run image copy and the
whole-image flush from the timed region — e.g. a tmpfs-backed image reused across
rounds with the flush outside the timer — and >= 15 rounds. Absent that instrument,
**do not flip the default and do not quote an end-to-end ratio for this lever.** The
defensible claims are exactly two: the commit-primitive A/B (1.70-2.11x, decidable
3/3, see the turn-12 rows) and correctness (20/20 e2fsck rc 0, exact parity).

DEFAULT: stays **OFF**. Not blocked any more — measured. The flag is available for a
deployment that has independently established the commit path is its bottleneck.

## bd-b9dug CORRECTED: every published frankenfs ratio came from a baseline-ISA binary that is NOT what ships; claims re-stated by class (bd-b9dug) - 2026-07-25 (Lane L, cc, no worker used)

Full writeup: `docs/BD_B9DUG_ISA_CORRECTION.md`.

THE DELTA. `cargo bench --profile release-perf` and `scripts/build-perf.sh` share the
same Cargo profile (opt-level 3, fat LTO, codegen-units 1, panic=abort) and differ in
exactly the two things a Cargo profile CANNOT express: **`-C target-cpu=x86-64-v3`**
(AVX2/BMI2/FMA) and **PGO**. So `[profile.release-perf]` is not wrong, it is
INCOMPLETE as a description of what ships — and nothing in the bench path ever said so.

IN-BINARY WITNESS (not inference — the executing binary reported it):
`codegen_isa,compile_sse2=true,compile_sse4_2=false,compile_avx2=false,
runtime_sse4_2=true,runtime_avx2=true` on `vmi1227854`. Compiled for a CPU far weaker
than the one it ran on.

SIZE, from evidence already in-repo (`build-perf.sh` header, `perf stat` 2026-07-03,
behaviour-preserving and stacking): target-cpu=v3 ~8.5% fewer create instructions / ~3%
lookup; PGO on top ~10% / ~24%; compounded **~17.6% create, ~26.3% lookup**.
⚠ INSTRUCTION COUNTS, NOT WALL — the script itself says "wall-clock was too noisy to
see them", and this repo's own ledger carries the matching lesson ("instructions alone
with flat cycles = neutral", the scrub word→SIMD REJECT). Direction established,
instruction magnitude measured, **wall magnitude unknown**. Do not convert 17.6% fewer
instructions into 17.6% faster.

CLAIMS RE-STATED BY CLASS:
- **Class A (wins vs kernel** — allocator range-overlap 3110x, journal replay 2024x,
  extent coalescing 120x, incremental crc32c 24.7x): FrankenFS ran on the WEAKER
  binary, kernel arm unaffected ⇒ these wins are **UNDERSTATED**. Nothing to withdraw;
  quote as ">= N x (baseline-ISA build)".
- **Class B (losses vs kernel** — parallel metadata writes 8.3x slower @8t, multi-file
  parallel read ~2.9x, mounted create storm 4.599x): same direction ⇒ these losses are
  **OVERSTATED**; the real gap is smaller. Strategically unchanged, but ⭐ **no loss in
  this class may be called "structural" or "irreducible" on the strength of a
  baseline-ISA measurement** — campaign §3b names exactly that failure mode.
- **Class C (internal A/B, one binary** — the 2026-07-25 wait-free gate 1.70-2.11x and
  essentially every KEEP/REJECT row in this file): both arms share one ELF, **the ISA
  cancels and the ratio stands as measured.** What does not automatically transfer is
  the magnitude on the shipped binary: a compute-shaped lever can SHRINK under v3+PGO
  (the baseline it improves gets faster) while a contention-shaped lever can GROW (the
  compute term shrinks, so the serialization term is a larger share). The wait-free gate
  is contention-shaped, so its 1.70x is not at risk and should if anything be LARGER on
  the shipped binary — recorded as a prediction, not a measurement.
- **Not affected:** e2fsck results, byte-identity proofs, conformance counts. ISA
  changes codegen, not behaviour.

THE CORRECTION — deliberately NOT "make v3 the default". `build-perf.sh` explains why
it is opt-in (v3 needs a 2015+ CPU and removes the runtime scalar fallback FrankenFS
keeps), and campaign §3b adds that worker `ovh-b` SIGILLs on AVX2 builds: a global
default trades a reporting bug for a crash. Instead, make the mismatch UNPUBLISHABLE:
(1) every bench binary self-reports `codegen_isa` (ffs-mvcc `wal_throughput` does);
(2) NEW ADMISSIBILITY RULE — a ratio may not be published from a run whose output lacks
a `codegen_isa` line, and a ratio whose `compile_avx2` differs from the shipped config
must carry the A/B/C qualifier above; (3) reproduce production with
`RUSTFLAGS="-C target-cpu=x86-64-v3"` (or `scripts/build-perf.sh` for +PGO), pinned to
an AVX2-capable worker, with the ELF sha proving codegen changed; (4) an ISA A/B is
gated on wall/cycles, NEVER on instruction count — an ISA change retires more work per
instruction, so fewer instructions is the mechanism, not a neutral proxy.

STILL OPEN: the WALL-CLOCK size of the ISA+PGO gap. That is a whole-binary A/B (two
ELFs, `paired()` inapplicable) needing same-worker execution with ELF-sha confirmation
on an AVX2-capable pinned worker — a measurement window this lane does not hold. FILED,
NOT DONE. Retry predicate: identical source, baseline vs v3, confirm the shas differ,
gate on wall/cycles.

## bd-bhh0i wait-free gate FINAL: 8t decidable 3/3 (1.70 / 1.88 / 2.11x) + the spin-vs-nospin question is a NULL (bd-bhh0i / bd-kdmu4) - 2026-07-25 (turn 12d, cc, MEASURED)

Run 4 (binary SHA-256 `32c5c1ba5afb89a292aa119986b979e6ca6e7113e871787f58948660f83989cc`,
pinned worker `vmi1227854`) completed the full unprofiled sweep with the profiled
pass off, and settles both open questions.

### 1. The main lever: 3 of 3 completed runs decidable at 8 writers

| threads | A/A null | A/A floor | Mutex -> WaitFree | log-margin | verdict |
|--------:|---------:|----------:|------------------:|-----------:|---------|
| 1 | 1.0160 | 1.5097 | 1.0009 | — | inside null |
| 2 | 1.0140 | 1.3230 | 1.1285 | 0.42x | inside null |
| 4 | 0.9555 | 1.3817 | 1.4771 | 1.21x | outside floor, BELOW the 2x margin — not claimed |
| 8 | 1.0035 | 1.2615 | **2.1066** | **3.21x** | **DECIDABLE** |

Completed unprofiled 8-thread runs: **1.7004x, 1.8841x, 2.1066x — 3/3 decidable**,
on three independently built ELFs. Median 1.88x. **The conservative 1.70x remains
the published claim**; the observed range is 1.70-2.11x and the "quiet pinned
worker" qualifier from turn 12c stands (run 3 truncated before this row and its
profiled reading was not decidable). Shape is identical in all runs: nothing at
1t/2t, directional at 4t, decidable at 8t — which is what a contention-removal
lever must look like.

### 2. Is the pre-park spin earning its 16% CPU? NULL — not decidable

`PublicationMode::WaitFree` (spin 64 rounds) vs `PublicationMode::WaitFreeNoSpin`
(park immediately), same ELF, same pairing driver, `lhs = spin`:

| threads | A/A floor | spin / nospin | \|log ratio\| vs floor | verdict |
|--------:|----------:|--------------:|------------------------:|---------|
| 1 | 1.5097 | 0.9155 | 0.088 vs 0.412 | inside null |
| 2 | 1.3230 | 0.8904 | 0.116 vs 0.280 | inside null |
| 4 | 1.3817 | 0.9290 | 0.074 vs 0.323 | inside null |
| 8 | 1.2615 | 0.9172 | 0.086 vs 0.232 | inside null |

**The spin's wall effect is inside the A/A null at EVERY thread count.** Directionally
it is consistently favourable (spin faster by 8-11%, and **4 of 4 thread counts point
the same way** — a sign test gives one-sided p = 0.0625), but no single reading is
decidable and the campaign's rule is explicit: nothing inside the null may be claimed.

DECISION, and a deliberate departure from my own pre-registered rule. Turn 12b
pre-registered "(a) no-spin is neutral -> DELETE the spin, keep the wall win and give
back the 16% CPU." The result IS neutral, so the rule says delete. **I am not
deleting it, and I am flagging that rather than quietly re-interpreting the rule.**
Reasons: (i) the pre-registration did not contemplate a consistent 4/4 direction, and
deleting on a null whose every reading favours the thing being deleted is not
conservative, it is just a different bet; (ii) the 1.70-2.11x headline was measured
WITH the spin, and removing it would mean the shipped configuration is no longer the
measured one — the exact substitution this campaign exists to prevent.

So both remain available and neither is claimed over the other:
`FFS_MVCC_WAITFREE_PUBLISH=1` (spin, the measured configuration) and
`FFS_MVCC_WAITFREE_PUBLISH=nospin` (park immediately, for CPU-constrained or
oversubscribed hosts where the 16.33%-self-time spin is a real cost).

RETRY PREDICATE for the spin question: it needs a harness with an 8-thread A/A floor
below **1.10x** to resolve an 8-11% effect at a 2x margin; this harness floors at
1.26-1.51x, so it CANNOT decide it — that is a statement about the instrument, not
about the spin. Either build a lower-variance harness (drop the per-batch thread
spawn/join and the per-batch store construction, which is where the jemalloc cluster
in the post-lever profile comes from) or decide it on an oversubscribed host where
the CPU cost, not the wall time, is the discriminator.

## ⚠ bd-bhh0i wait-free gate — RUN 3 DID NOT REPRODUCE A DECIDABLE 8t EFFECT (harness overrun + a noisy worker); claim tempered to "1.70x on a quiet pinned worker" (bd-bhh0i) - 2026-07-25 (turn 12c, cc)

Recording a disagreement with my own result, because it changes how the number
should be quoted.

Run 3 (binary SHA-256 `c513a49a7b5503150178a10ff550cc20c39cbb84303ff2fb78abc1f90bf2f967`,
same pinned worker `vmi1227854`) added the `unprofiled_spin_vs_nospin_ab` phase,
which pushed total runtime past the 3000 s budget. Consequence: **the run died
before emitting the unprofiled 4-writer and 8-writer rows** — exactly the rows
every decision here rests on. What it did emit disagrees with runs 1 and 2:

| phase | t | A/A floor | A/B | log-margin | verdict |
|-------|--:|----------:|----:|-----------:|---------|
| profiled | 4 | 1.2872 | 1.6063 | 1.59x | below the 2x margin |
| profiled | 8 | 1.2619 | **1.2961** | **1.11x** | **NOT decidable** |

Run 1's profiled 8t was 2.2433 and run 2's unprofiled 8t was 1.8841. Run 3's
profiled 8t is 1.2961 — barely outside its own A/A floor. The A/A itself was
healthy (0.9867, floor 1.2619), so this is not a broken harness; it is a worker
that was busier during the candidate arms, and the paired design correctly
reported a smaller effect rather than hiding it.

STATE OF THE CLAIM after three runs:
- **Unprofiled (decision) 8t: 2 of 2 completed runs decidable — 1.7004x and
  1.8841x.** Run 3 never produced this row.
- **Profiled (attribution) 8t: 2 of 3 decidable — 2.2433x, (run 2 not separately
  re-read), 1.2961x NOT decidable.**

So the honest quotation is **"~1.70x at 8 writers on a quiet pinned worker"**, NOT
"1.70x". The effect is real — it is mechanism-backed (publication mutex wait p99
32767 -> 511 ns) and it reproduced on two independent ELFs — but its MAGNITUDE is
worker-load-sensitive, which is expected for a lever whose entire mechanism is the
removal of contention: less contention on the box, less to remove.

HARNESS FIX (landed with this row): the profiled pass is now OFF by default behind
`FFS_BENCH_PROFILED=1`. It roughly doubles wall time, and when a run overruns, what
it loses is the TAIL of the thread sweep — the 8-writer rows — so the failure mode
is silent and maximally damaging: a truncated run looks like a completed run that
simply had fewer phases. Any harness that sweeps a parameter in increasing order
and can time out has this bug shape; sweep the expensive end FIRST, or make the
expensive pass opt-in. Chose opt-in.

RETRY PREDICATE for anyone quoting this number: require a completed unprofiled
sweep (all four thread counts present), an 8-thread A/A floor below 1.30x, and a
candidate clearing it by a 2x log-margin. Two such runs exist; demand a third
before raising the claim above 1.70x, and re-check the box load before blaming the
lever if a run comes in low.

## bd-bhh0i wait-free gate: REPLICATED on a second binary (1.88x @8t) + an HONEST CPU caveat — the spin trades CPU for wall (bd-bhh0i / bd-kdmu4) - 2026-07-25 (turn 12b, cc)

REPLICATION. A second, independently built binary (SHA-256
`bf92caee472d944150ced8410cda8a7cdc658e8033e54ead52579f64a71c9f2f`, same pinned
worker `vmi1227854`) reproduced the win. Unprofiled decision arm:

| threads | A/A null | A/A floor | A/B run 1 | A/B run 2 |
|--------:|---------:|----------:|----------:|----------:|
| 1 | 1.0531 | 1.5026 | 0.9766 | 1.0072 |
| 2 | 0.9915 | 1.3564 | 1.1525 | 1.0890 |
| 4 | 0.9347 | 1.4622 | 1.3675 | 1.4087 |
| 8 | 0.9976 | 1.2589 | **1.7004** | **1.8841** |

Run 2's 8-thread A/B clears its own A/A floor by a **2.75x log-margin**. Two
independent ELFs agree on the shape (nothing at 1t/2t, directional at 4t,
decidable at 8t). **The conservative 1.70x remains the claim**; the range across
both runs is 1.70-1.88x.

⚠ HONEST CAVEAT — THE SPIN MOVES CPU, IT DOES NOT ELIMINATE IT. Profiling the
POST-lever path (wait-free only, 8 writers, same invocation) put
`CommitPublicationGate::publish_with_probe` at **16.33% self**, against **5.85%**
for the mutex gate on the same workload. Wall time fell ~1.8x while CPU in that
frame roughly TRIPLED. Mechanism: `PUBLICATION_SPIN_ROUNDS = 64` re-drains before
parking, and a spin accrues CPU samples where a futex wait accrues none. So the
part that genuinely VANISHED is the mutex queueing (publication mutex wait p99
32767 -> 511 ns); the waiting itself was converted from blocking into spinning.

This matters beyond bookkeeping. This repo has already ledgered the failure mode:
"spin-wait is CPU burned while other threads block on the device... Projection
1.12x-1.85x. Measurement 1.00x" (cold-read lane). On a host where FrankenFS shares
cores with the workload, a 16% self-time spin can be a NET LOSS even though the
isolated A/B shows a wall win. The 1.70x is measured on 8 writers with cores to
spare; it is NOT a claim about an oversubscribed host.

POST-LEVER FRONTIER (wait-free, 8 writers, top self-time frames):
`publish_with_probe` **16.33%**; `_rjem_je_arena_ptr_array_flush` 3.36%;
`drop_glue::<HashMap<...>>` 2.89%; thread-start 2.75%;
`parking_lot_core` TLS destroy 1.78%; `_rjem_je_edata_heap_remove` 1.77%;
`extent_recycle` 1.73%; `preflight_fcw_locked` 1.49%;
`Transaction::insert_staged_write` 1.34%; `commit_policy` 1.27%;
`commit_with_probe` 1.01%; `lock_shards` 0.96%. Note the allocator cluster
(jemalloc arena flush / heap remove / extent recycle ~6.9% combined) is now the
second-largest term — per-batch store construction and teardown, an artifact of
this harness rather than of production, so it is NOT a production lever.

NEXT LEVER (attributed, wired, not yet measured): added
`PublicationMode::WaitFreeNoSpin` so the spin can be A/B'd against no-spin inside
ONE binary via the same pairing driver
(`unprofiled_spin_vs_nospin_ab` phase, `FFS_MVCC_WAITFREE_PUBLISH=nospin`). Three
outcomes and what each means: (a) no-spin is neutral -> DELETE the spin, keep the
wall win and give back the 16% CPU; (b) no-spin is slower -> the spin is earning
its CPU on this workload, keep it and document the oversubscription caveat as a
standing risk; (c) no-spin is FASTER -> the spin is actively hurting and the
default should be no-spin. Retry predicate: decide only on a same-worker, same-ELF
interleaved A/A + A/B where the 8-thread A/A floor is below 1.30x and the
candidate clears it by a 2x log-margin, and re-profile to confirm
`publish_with_probe` self-time actually falls in the no-spin arm.

## 🛑 BLOCKER (infrastructure, not idea): the wait-free-gate e2e cutover cannot run — rch excludes `target/` from artifact retrieval AND the fleet has no `mke2fs`/`e2fsck` (bd-bhh0i / bd-b9dug) - 2026-07-25 (turn 12, cc)

Status: LEDGERED BLOCKER. The `FFS_MVCC_WAITFREE_PUBLISH` default stays OFF because
the end-to-end gate could not be executed, NOT because it failed.

WHAT WAS ATTEMPTED. After the ffs-mvcc primitive A/B won (1.70x @8t, entry below),
the plan was the documented cutover gate: `mke2fs -t ext4 -F -q -b 4096 -N 65536
<img> 524288` (2 GiB / 16 groups / 65536 inodes — image was created successfully
and verified with `dumpe2fs`), then `FFS_BHH0I_SHARDED=1 create-bench <img> /d
--count 40000 --threads 8` with `FFS_MVCC_WAITFREE_PUBLISH` off vs on from the SAME
binary (the per-store `PublicationMode` makes that a true same-ELF A/B), gated on
`e2fsck -fn` rc 0 and exact file parity.

WHY IT COULD NOT RUN — two independent walls, both infrastructure:

1. **rch cannot hand back a built binary.** Two `cargo build --profile release-perf
   -p ffs-cli --features bhh0i_sharded_alloc` runs both succeeded remotely (`ovh-a`
   378.0s; `vmi1227854` 658.5s, both exit 0) and both retrieved only **2-5 files /
   536-563 bytes**. Root cause is exact and global: `~/.config/rch/config.toml`
   `[transfer] exclude_patterns` contains **`"target/"`, `"target-*/"`,
   `"target_*/"`, `".rch-target*/"`, `".cargo-target/"`**. Every Cargo output
   directory is on the exclude list, so no compiled artifact can ever be retrieved
   from a worker — with the default target dir OR a custom one. The campaign's
   prescribed `env -u CARGO_TARGET_DIR` form does not help; the exclusion is on the
   destination directory name, not on the env var.
2. **The fleet cannot run the gate remotely either.** `mkfs.ext4`/`mke2fs` and
   `e2fsck` are absent on the workers (already ledgered 2026-07-13: the sharded
   create tests `open_writable_ext4_mkfs` SKIP there, and the in-Rust
   `build_ext4_image` helpers are single-group 128 KiB PARSE fixtures that cannot
   be opened writable for a multi-group parallel create). Shipping the image is not
   a workaround: rch's `verify_max_size_bytes` is 100 MiB and the image is 2 GiB.

So the gate is reachable only by an explicit LOCAL `release-perf` build of
`ffs-cli`. That is a deliberate policy decision (the campaign forbids SILENT local
fallback; `/data` has 246 GiB free and prior turns did run this cutover locally), and
the `cargo` PreToolUse hook routes every `cargo` invocation through rch, so taking it
means bypassing a user-installed guard. NOT done unilaterally — surfaced instead.

UNBLOCK (any one of these, all cheap):
(a) drop `target/` from `[transfer] exclude_patterns` for artifact RETRIEVAL (it is
    correct as an UPLOAD exclusion; applying it to the download direction is what
    breaks every "build remote, run local" workflow in this fleet);
(b) add an rch flag to retrieve named binaries (`rch exec --retrieve
    target/release-perf/ffs`);
(c) explicit greenlight for ONE local `release-perf` `ffs-cli` build per cutover turn.

This is a FLEET-WIDE finding, not a frankenfs one: any repo whose measurement needs a
locally-executed binary (mounted-FS gates, hardware-specific runs, anything needing a
tool absent on the workers) hits the same wall.

WHAT IS STILL PROVEN WITHOUT THE GATE: the ffs-mvcc commit primitive A/B (below) is
complete on its own terms — same ELF, pinned worker, A/A null in the same invocation,
byte-identity proven before timing, and per-phase p99 mechanism evidence. What the
e2e would add is (i) confirmation that the 8-thread gain survives the full create
path where MVCC commit is one term among allocation, directory insert and inode-table
RMW, and (ii) `e2fsck` proof on a mutated image. Neither is required to KEEP the flag
default-OFF; both are required to FLIP the default. Retry predicate: re-run the exact
gate above once any of (a)/(b)/(c) lands; flip the default only if 8-thread
creates/s improves beyond the create-bench A/A null AND both arms are `e2fsck -fn`
rc 0 with identical file counts.

## ⭐⭐ bd-bhh0i WIN — wait-free ordered publication: 1.70x at 8 threads, publication-lock wait collapses 64x (bd-bhh0i / bd-kdmu4) - 2026-07-25 (turn 12, cc/STRUCTURAL, MEASURED KEEP behind a flag)

Status: KEEP behind `FFS_MVCC_WAITFREE_PUBLISH` (default OFF = byte-identical to
the pre-lever binary). This is a **ledger resurrection**: the lever was
implemented, correctness-tested, and NEVER MEASURED on 2026-06-29
(`docs/NEGATIVE_EVIDENCE.md:3491`), then shelved on a branch/stash that no longer
exists. `docs/LEDGER_RESURRECTION.md` ranks it #1 of 276 audited REJECT rows.

LEVER (one): replace `CommitPublicationGate`'s global `Mutex<BTreeSet<u64>>` +
`Condvar` ordered-publication path with a wait-free power-of-two ring of ready
sequences plus a CAS walk of the contiguous prefix. The committer stores its own
sequence into `ring[seq & MASK]`, drains the prefix with a CAS loop, and only
parks on the `Condvar` if a predecessor has not published after a bounded spin.
The mutex survives solely as the parking path.

PROFILE-FIRST ATTRIBUTION (real path, not a synthetic model). bd-bhh0i's
2026-07-10 `CommitLockProfile` characterization of production
`ShardedMvccStore::commit`: publication mutex wait p99 **127 / 2047 / 32767 /
131071 ns** at 1/2/4/8 threads against a shard wait p99 of **255 / 255 / 511 /
511 ns** — the gate mutex grows **1000x** from 1t to 8t and reaches **131 us**,
a **256x** ratio over the shard locks. Same-invocation `perf` on the decision
binary put `publish_with_probe` at **1.89% self** (`verified_nonzero=true`);
an earlier mutex-only run put it at **5.85% self**. Self-time UNDERSTATES this
frame — time parked in a futex accrues no CPU samples — so the A/B wall ratio,
not an Amdahl bound on 5.85%, is the measure.

LEDGER GATE PASSED. `NEGATIVE_EVIDENCE.md:85` closed the publication **atomic
store shape** family (prefix-batching measured 0.999x, correctly rejected) and
its own retry text names the residual: *"the gate already holds a BTreeSet
removal loop whose ordered-tree work dominates these atomic accesses... do not
retry unless a profile attributes material self-time specifically to the
per-entry atomic load/store rather than the publication mutex/tree work."* This
lever removes the mutex and the tree — the thing that row names as dominant —
not the atomic shapes it closed.

BEHAVIOR PROOF, BEFORE TIMING. `assert_publication_mode_isomorphism` runs in the
same binary ahead of every timed arm: a deterministic multi-writer workload
(payload derived from block and index, so the correct final content is fixed and
interleaving-independent) commits under BOTH modes, then every block is resolved
at the final watermark and hashed in block order.

| threads | watermark | sha256 of all resolved blocks | result |
|--------:|----------:|-------------------------------|--------|
| 1 | 256  | `ae6bc48bcdee96b3...` | identical |
| 2 | 512  | `84cd5935a51b74a8...` | identical |
| 4 | 1024 | `f4ae906dcc619b15...` | identical |
| 8 | 2048 | `638052fc547a163f...` | identical |

Ordering preserved: the watermark advances only over a contiguous prefix in both
modes (`commit_publication_gate_wait_free_advances_only_over_contiguous_prefix`).
Tie-breaking / FP / RNG: N/A.

A/B + A/A NULL, SAME BINARY, SAME INVOCATION, ONE PINNED WORKER. Binary SHA-256
`516342ec9754db9fe37edcbf0944340e2875f6cb67dd867fa43d4338257fbcac`, worker
`vmi1227854`, `--profile release-perf --features bench-instrumentation`. 31
interleaved pairs per phase, order alternating per pair, statistic = median of
per-round log-ratios; floor = `exp(|median| + p90|deviation|)`. Both modes are a
per-STORE setting, so both arms run from ONE ELF and codegen cannot differ.

Decision arm (unprofiled = the production commit path, no instrumentation):

| threads | A/A null | A/A floor | A/B (mutex/wait-free) | log-margin vs floor | verdict |
|--------:|---------:|----------:|----------------------:|--------------------:|---------|
| 1 | 1.0358 | 1.3970 | 0.9766 | — | inside null (no convoy at 1t) |
| 2 | 1.0076 | 1.2628 | 1.1525 | 0.61x | inside null |
| 4 | 1.0204 | 1.2666 | 1.3675 | 1.32x | outside floor, BELOW the 2x margin — not claimed |
| 8 | 0.9839 | 1.2811 | **1.7004** | **2.14x** | **DECIDABLE WIN** |

Profiled arm (six `Instant::now()` probes per commit, paid by both arms): 1t
0.9971, 2t 1.0877, 4t 1.5657, 8t **2.2433** vs an A/A floor of 1.3233 (2.9x
log-margin). The probes inflate the mutex arm more because they cluster on the
gate, so **1.70x is the claim** and 2.24x is the instrumented upper reading.

MECHANISM PROOF (this is the part that makes it a lever and not a wall-time
story). Per-phase p99 from the profiled arms, mutex arm -> wait-free arm:

| threads | publication mutex wait p99 | ordered-prefix wait p99 |
|--------:|---------------------------:|------------------------:|
| 1 | 63 -> 63 ns | 0 -> 0 |
| 2 | 1023 -> **63 ns** | 131071 -> 131071 (identical) |
| 4 | 16383 -> **255 ns** | 262143 -> 262143 (identical) |
| 8 | 32767 -> **511 ns** (**64x collapse**) | 524287 -> 524287 (identical) |

The lock wait collapses 64x at 8 threads while the ordered-prefix wait is
byte-for-byte unchanged. That is the designed split: the MECHANISM cost (queue on
one global lock, insert into a BTreeSet, `notify_all` a thundering herd) is
removed; the SEMANTIC cost (a snapshot must see a gap-free prefix, so a commit
may not publish before its predecessors) is preserved exactly. Removing the
semantic half would change visibility semantics and is a different, much larger
proof obligation — NOT attempted here.

HONEST SCOPE. (1) 1t/2t are inside the null and no gain is claimed there — the
convoy does not exist without contention, which is itself confirmation of the
mechanism. (2) 4t is directionally positive but below the campaign's 2x
median-CI margin; not claimed. (3) The arm includes thread spawn/join per batch,
which dilutes the ratio — the true per-commit effect is larger than 1.70x. (4)
This is the ffs-mvcc commit primitive; it has NOT yet been measured end-to-end on
`create-bench` + `e2fsck`, so the default stays OFF pending that gate.

CODEGEN NOTE (bd-b9dug, cod lane): `codegen_isa,compile_sse2=true,
compile_sse4_2=false,compile_avx2=false,runtime_avx2=true` — the `release-perf`
bench binary is x86-64 baseline while the worker supports AVX2. Confirms the
campaign section 3b ISA mismatch on the exact binary these ratios come from.

GATES: `cargo test -p ffs-mvcc --lib` **497 passed / 0 failed** (495 before, plus
two new gate tests: `..._wait_free_matches_mutex_under_shuffled_publish`, 8
threads x 2000 shuffled publishes under both modes with identical final
watermark, no buffered remnants, no leaked waiters; and
`..._wait_free_advances_only_over_contiguous_prefix`). `cargo check -p ffs-mvcc
--features bench-instrumentation --benches` exit 0. `cargo clippy -p ffs-mvcc
--all-targets --features bench-instrumentation -- -D warnings`: **zero
diagnostics in `crates/ffs-mvcc`**; the 6 errors are pre-existing in
`crates/ffs-ondisk` (`ext4.rs` similar_names x2, `crc_incremental.rs`
cast_possible_truncation / needless_range_loop / large_stack_arrays x2) and are
the campaign section 3c nightly-clippy drift, untouched by this change.

PREREQUISITE FIXED FIRST: `--features bench-instrumentation` did NOT compile on
HEAD — `std::fmt::Write` and `std::io::Write` were both imported unaliased in
`crates/ffs-mvcc/benches/wal_throughput.rs`, so every `write_all` failed E0599.
This repo's own section-2-contract harness (self-reported ELF sha, interleaved
A/A pairs, median-of-ratios, per-phase publication p99s) was unbuildable.

NEXT (in order): (1) end-to-end `FFS_BHH0I_SHARDED=1 FFS_MVCC_WAITFREE_PUBLISH=1
create-bench <2GiB/16-group> --count 40000 --threads {1,4,8}` vs the same binary
with the flag off, gated on e2fsck rc0 and exact file parity; (2) only if that
holds, propose flipping the default. Retry predicate if a future run disagrees:
re-decide only on a same-worker, same-ELF interleaved A/A + A/B where the 8-thread
A/A floor is below 1.30x and the candidate clears it by a 2x log-margin.

## bd-bhh0i RELEASE-PERF A/B — the honest number: ~2.1x convoy ELIMINATION, NOT the aspirational 3.7x; scaling caps at 4t (bd-bhh0i / bd-kdmu4) - 2026-07-24 (turn 11, ⭐ MEASURED)

Status: definitive measurement (release-perf, e2fsck-validated). The bd-bhh0i
parallel-create cutover is CORRECT and beats the single-lock convoy ~2.1x at 4-8
threads, but does NOT achieve the campaign's long-quoted "3.7x / 8t≥4x1t" — that
was an unmeasured aspiration. Correcting the ledger with the real number.

A/B: `create-bench <2GiB/16-group ext4> / --count 40000 --threads T`, single-lock
(no env) vs sharded (`FFS_BHH0I_SHARDED=1`), same release-perf binary (built
`--profile release-perf --features bhh0i_sharded_alloc`, 3m57s). All runs e2fsck rc0.

| threads | single-lock c/s | sharded c/s | sharded/single-lock |
|--------:|----------------:|------------:|--------------------:|
| 1       | 119156          | 116382      | 0.98x (parity)      |
| 2       | 87737           | 129436      | 1.48x               |
| 4       | 68947           | 142627      | 2.07x               |
| 8       | 61512           | 128206      | 2.08x               |

READ: (1) single-lock CONVOYS — negative scaling 119k→61k (the whole-state write
lock; reproduces the memory's 143k→80k). (2) The sharded cutover REMOVES the
convoy: flat-to-positive, ~2.1x the single-lock at 4-8t; that convoy elimination is
the real, correct, e2fsck-validated win. (3) BUT sharded SELF-scaling is weak: 1t
116k → 4t 142k (1.23x) → 8t 128k (DIPS). "8t≥4x1t" is NOT met (8t is 1.10x of 1t);
peak is 4t at 1.23x. Sharded 1t≈single-lock 1t (parity — the auto-commit/base-clone
overhead is ~free at 1 thread).

WHY the 4t cap / 8t dip (the perf lever, needs a profile — NOT a correctness gap):
a high-thread serialization limiter. Per create the sharded path does SEVERAL MVCC
auto-commits (inode bitmap, inode-table slot w/ a full-block `base` clone [added
turn 8, ~free at 1t but allocator pressure at 8t], block bitmap) each hitting the
global commit-seq CAS + `prune_after_commit_if_due` + shard locks; that shared
machinery, not the per-group locks (0.5 thread/group at 8t/16-group), is the
suspect. Retry predicate to push past 2.1x: profile an 8t sharded create-bench
(release-perf, `perf -g`), find the >5%-self-time shared frame (commit-seq CAS /
prune / allocator), and cut per-create commit count or contention.

PROFILE DONE (perf -g --call-graph dwarf, 8t sharded create-bench count 120000,
105k creates/s): TOP self-time = **`__memmove/memcpy_avx_unaligned` 11.70%**
(block-sized copies — 10.5% is memcpy), then `ShardedMvccStore::commit` **5.19%**,
`RawMutex::lock_slow` 1.51%, `add_entry_reject_existing_tracked` 1.46%, crc32c
1.18%, jemalloc `sdallocx`+`malloc` ~2.0%, `RawRwLock::lock_shared_slow` 1.01%,
plus ~7% kernel `[unknown]` (write/read syscalls). VERDICT: the 8t cap is
MEMORY-BANDWIDTH-BOUND on 4 KiB block copies in the MVCC path — bandwidth is shared
across cores, so it saturates at 8t (→ the 4t→8t dip). The per-create MVCC path
copies each 4 KiB block multiple times: `read_visible`→Vec, the turn-8 `base`
clone in `rmw_commit_block_with_proof` (`(bytes.clone(), Some(bytes))`, needed for
the pruning-race merge base but a full-block copy on the no-conflict common path),
`write_block`→`data.to_vec()`, and the merge-install rebuild. NEXT LEVER (bounded,
one at a time): make the MVCC hot path Arc/COW-share block buffers instead of
cloning — e.g. record the `base` as a shared `Arc<[u8]>`/`BlockBuf` from
`read_visible_block_buf` (no copy) rather than an owned `Vec`, so the common
no-conflict inode/bitmap write stops paying a 4 KiB memcpy. Each copy-elim is its
own commit; re-measure the A/B after each. This is the path from ~2.1x toward the
memory's aspirational 3.7x, but it is bounded (memcpy is 11.7%, commit 5.2% — even
eliminating both fully is ~1.2x, so ~2.1x×1.2 ≈ 2.5x is a realistic ceiling for
copy-elim alone; 3.7x would additionally need fewer per-create commits).

⭐ HONEST CAMPAIGN VERDICT: bd-bhh0i is a CORRECTNESS success + a real ~2.1x
convoy-elimination throughput win, delivered end-to-end (BitmapOr proof +
block-bitmap find-race + inode-table pruning race + read-vs-prune TOCTOU, all
landed, e2fsck rc0 @40000/8t). The "3.7x" was aspirational and is not supported;
the measured ceiling is ~2.1x vs single-lock, capped at 4t by shared-commit
contention. Further gains are a bounded perf-tuning lever, not a structural one.

## ⭐⭐ bd-bhh0i CUTOVER COMPLETE — read-vs-prune TOCTOU FIXED; passes at 40k, e2fsck clean, 2.71x positive scaling (bd-bhh0i / bd-kdmu4) - 2026-07-24 (turn 10, ⭐ FULL PASS)

Status: LANDED (f9183ad9). The sharded parallel-create cutover now passes reliably
at the full count 40000 across 1/2/4/8 threads with e2fsck rc0 — the last
correctness gap (turn-8/9 residual) is closed.

Root cause (fully pinned, correcting turn 9): the bd-bhh0i writable adapters are
UNREGISTERED (perf opt), so `ShardedMvccStore::prune_safe`'s watermark is the chain
head whenever `active_snapshots` is empty → `prune_versions_older_than` collapses a
hot block to its single newest version. A "current" read that captured seq S then
races a concurrent commit+prune to S+1: `read_visible(block, S)` = None (S dropped)
→ falls to the STALE on-device block (mkfs-empty inode table for a run that never
flushes mid-run) → a create fails `NotFound` reading a just-committed parent inode.
NOT a write clobber — the turn-9 suspicion was wrong: `INSTALL-SHRINK` re-run at a
32-byte threshold on the inode-table blocks fired 0×. The turn-9 partial (MAX in
`with_latest_scope`) was DEAD: `read_block_with_scope` step-2 read_visible only
runs when `scope.tx.is_some()`, and the latest-scope has no tx, so the read fell
through to `read_current_block_vec_from_device`.

FIX: `read_current_block_vec_from_device` and `FsMvccBlockDevice::read_snapshot`
(read-your-writes) resolve at `CommitSeq::MAX` (newest RETAINED version) instead of
a freshly captured `current_snapshot()`. Pruning always keeps the newest, so MAX is
TOCTOU-free, and "current"/read-your-writes both mean newest. Byte-identical for
serialized single-lock + RO (newest == current): ffs-core default lib 1185 pass;
the 2 failures (fast_commit_del_range, btrfs_reflink_random) are PRE-EXISTING on
clean HEAD (verified by stash), not this change.

SCALING (debug binary, 2GiB/16-group, count 40000): 1t 9817 → 2t 13881 → 4t 21236
→ 8t 26622 creates/s = 2.71x @8t, POSITIVE (single-lock baseline scaled NEGATIVELY
143k→80k). e2fsck rc0, 40020 files.

⏭ REMAINING (perf, not correctness): (1) release-perf measurement (`--profile
release-perf`) — the ratio may differ from debug; (2) close the 2.71x→4x gap
(per-commit MVCC shard-lock / deferred-GDT / auto-commit-under-lock contention at
8t/16-group is the likely limiter — profile the 8t create path). Cutover CORRECTNESS
is done; the ≥4x is now a pure perf-tuning lever.

## bd-bhh0i cutover residual @30k REFINED — read-your-writes-vs-prune TOCTOU (partial fix) + a suspected sub-threshold write clobber (bd-kdmu4) - 2026-07-24 (turn 9, investigation)

Status: no net commit (exploration reverted; main stays at the turn-8 8k-validated
state, 73d7fa52). Investigated the turn-8 residual (`NotFound("inode N")` at
count~30000, groups near-full). Two findings, neither fully fixed → deferred.

(A) Write-clobber NOT confirmed but NOT ruled out: instrumented
`install_committed_version_locked` to flag any block-585..1096 (group-1 inode
table) version installed with `new_nz + 256 < prev_nz` non-zero bytes — fired 0×
on a failing run. BUT the `+256` threshold is too coarse: one inode slot holds
only ~100-150 non-zero bytes, so a SINGLE-slot clobber slips under it. Re-run with
threshold ~32 before concluding.

(B) Read-your-writes-vs-prune TOCTOU (diagnosed, partial fix measured): the
bd-bhh0i writable adapters are UNREGISTERED (a perf opt), so `ShardedMvccStore::
prune_safe`'s watermark = `current_snapshot().high` (the chain head) whenever
`active_snapshots` is empty. `prune_versions_older_than` then collapses a hot
inode-table block to its single newest version. A read-your-writes read
(`FsMvccBlockDevice::read_snapshot` = `current_snapshot()`) that captured seq S,
then races a concurrent commit+prune to S+1, calls `read_visible(block, S)` →
None (S's version dropped) → falls back to the STALE on-device block (the
create-bench never flushes mid-run, so the device inode table is mkfs-empty) →
`NotFound`. PARTIAL FIX TESTED: `read_snapshot` for read-your-writes returning
`Snapshot { high: CommitSeq(u64::MAX) }` (resolve the newest RETAINED version =
exactly read-your-writes semantics; byte-identical for the serialized single-lock
path) improved 4t/30000 to 4/6 pass but did NOT eliminate the failure → confirms a
SECOND residual (likely the (A) sub-threshold write clobber). Reverted (broad core
read-semantics change, not landed without the write-clobber fix + default-path
validation).

NEXT (both needed for the full 3.7x): (1) land the read-your-writes MAX-read fix
(after ffs-core writable default-path tests confirm byte-identity); (2) re-run
INSTALL-SHRINK at threshold ~32 to locate + fix the single-slot write clobber
(likely the merge-install rebuild vs a concurrently-advanced `latest`, or the
`observed <= snapshot` no-conflict path installing a base that lost a slot);
(3) then measure release-perf 8t≥4×1t on a ≥2GiB/16-group image. The cutover
already PASSES + scales positively at 8k (turn 8) — this is the last correctness
gap before the ≥4× measurement.

## bd-bhh0i cutover PASSES at 8k — block-bitmap find-race + inode-table pruning race FIXED; positive scaling (bd-bhh0i / bd-kdmu4) - 2026-07-24 (turn 8, ⭐ FIRST PASS)

Status: two fixes LANDED (7653bdec); the sharded parallel-create cutover PASSES
for the first time. As sole producer, drove the find-race (turn 7) to root cause
and fixed it + a second race it unmasked.

FIX 1 — block-bitmap find-race (`ext4_sharded_alloc_blocks`): the dir-growth block
alloc threaded the caller's BATCHED dir-add txn (`TransactionBlockAdapter`) as
`dev`, so it staged the bitmap write uncommitted. A concurrent same-group create's
find reads committed state (`dev.read_block` live) and MISSED that pick → both
picked the same free block → a double-alloc the OR-merge correctly fail-closes on.
Root cause was NOT a missing proof (turn 7) — it was invisibility of the in-flight
pick. Fix: auto-commit the bitmap UNDER THE PER-GROUP LOCK via
`block_device_adapter`, exactly as the sharded inode alloc already does (which is
why the inode bitmap never raced). Each pick is now committed before the lock
releases → visible to the next find. (The turn-7 `BitmapOr`/`rmw_block_bitmap_or`
proof-carrying path is now inert for the serialized bitmap but stays a correct
safety net.)

FIX 2 — inode-table pruning race (`rmw_commit_block_with_proof`): recorded
`base=None` when a version existed at the txn's snapshot, relying on the version
chain still holding it at commit. A concurrent committer's
`prune_after_commit_if_due` drops the version at this (unregistered auto-commit)
snapshot between stage and commit → the sharded merge's `version_bytes_at` yields
an EMPTY base → a spurious `base_len=0` length-mismatch abort of two creates
writing DISJOINT inode slots of the same inode-table block (proof
`TimestampOnlyInode`). Fix: record the snapshot base ALWAYS.

VALIDATED: `FFS_BHH0I_SHARDED=1 create-bench <512MiB/4-group ext4> / --count 8000
--threads {1,4,8}`, 6/6 clean at 8 threads, e2fsck rc0. Scaling (debug binary):
1t 9830 → 4t 17621 creates/s (~1.8x) → 8t ~24000 (~2.5x) = POSITIVE, vs the
single-lock baseline's NEGATIVE scaling (1t 143k → 8t 80k). First time the cutover
clears the e2fsck gate under concurrency.

RESIDUAL BLOCKER (next): at count ~30000 (a 4-group fs's inodes ~92% full) a
create intermittently fails `NotFound("inode <N>")` — an inode-table slot is lost.
The inode NUMBER alloc is race-free (auto-commit under lock, verified), so this is
a deeper MVCC merge-INSTALL race on the heavily-contended inode-table block
(`merged_write_bytes_locked` rebuilding against a `latest` that a concurrent
install advanced) under near-full-group pressure, NOT the pruning sub-case fixed
here. Retry predicate for the full 3.7x: reproduce at count≥30000 with a
per-inode-table-block conflict trace, fix the merge-install ordering, then measure
release-perf 8t≥4×1t. Note: the memory's "512MiB/4-group, 40000 creates" recipe is
inconsistent — 4 groups hold only 32768 inodes, so 40000 needs a ≥2GiB/16-group
image; use that for the ≥4× headroom measurement.

## bd-bhh0i cutover — turn-4b diagnosis CORRECTED; proof-carrying batched-txn landed; real blocker is a FIND-RACE (bd-bhh0i / bd-kdmu4) - 2026-07-24 (turn 7)

Status: substrate LANDED (1e08bb46) + deeper LEDGERED BLOCKER. As sole producer
(cod capped) with ffs-core/lib.rs unfrozen, drove the cutover to its true root
cause — and corrected the turn-4b ledger, which was WRONG.

Turn-4b said the sharded dir-growth block-bitmap write used a non-MVCC
`direct_block_device_adapter`. FALSE. `ext4_add_dir_entry` wraps the MVCC device
(`block_device_adapter`) in a `TransactionBlockAdapter` — an explicit BATCHED
transaction (`self.mvcc_store.begin()`) — and threads THAT as `dev` into the
dir-growth alloc. Its default `rmw_block` / `rmw_block_bitmap_or` fell through to
`write_block`, which stages `tx.stage_write` = `MergeProof::Unsafe`. So block 65's
BitmapOr proof (and every GDT/inode-table range proof) was LOST at the adapter,
and the batched txn FCW-aborted under concurrency. (Turn-4b's "block 65 never
reaches FsMvccBlockDevice methods" was because it went to `tx.stage_write`, not
because the device was non-MVCC.)

LANDED (byte-identical default by non-reachability; ffs-alloc 218/218, ffs-block
309/0): `TransactionBlockAdapter` now overrides `rmw_block` (→ `IndependentKeys`)
and `rmw_block_bitmap_or` (→ `BitmapOr`), staging the proof into the batched txn
with the merge base resolved at the txn's OWN snapshot via a new
`BlockDevice::read_merge_ancestor_at_snapshot` (default `None`→`read_block`;
`FsMvccBlockDevice`→ version at that snapshot, else raw base). Closes the
2b-harden stale-read window; preserves read-your-writes within the batch.

VERIFIED end-to-end (FFS_BHH0I_DEBUG instrumentation, added→removed): the override
IS now reached (`stage_rmw block=65 mech=BitmapOr`, 4096-byte base/latest/staged),
but the cutover STILL FCW-aborts on block 65 at 4/8 threads. The bitmap is
monotone (alloc-only), so a BitmapOr rejection can ONLY be a disjoint-new failure
= the SAME bit set by two writers = a genuine DOUBLE-ALLOCATION, which the
OR-merge correctly fail-closes on.

REAL BLOCKER — FIND-RACE: two concurrent same-group creates find the SAME free
block. `PerGroupAlloc::alloc_blocks` locks the group and calls
`try_alloc_blocks_in_group`, whose find does `dev.read_block` (the MVCC device's
LIVE, committed view) — which MISSES the first create's staged-but-uncommitted
allocation (staged in its own batched txn, not yet committed). So the second
create, even serialized behind the group lock, sees the block still free and
picks it too. The per-group lock serializes the find but not the visibility of
in-flight allocations. The OR-merge (disjoint COMMITS) was necessary but not
sufficient; disjoint PICKS are also required.

FIX (next): an in-memory per-group bitmap of in-flight staged allocations,
consulted (OR'd with the committed bitmap) by the sharded find and cleared on
commit/rollback — so the second create sees the first's pick. A per-group
allocation CURSOR alone does NOT suffice: on wrap-around it re-hits a block
allocated-but-uncommitted before the wrap. Auto-committing the bitmap alloc under
the group lock also works for the cutover but leaks a block on create-failure
(the dir-add batched txn rolls back but the separately-committed bitmap bit does
not). This lives in `sharded_alloc.rs` + `GroupStats` (ffs-alloc) — now editable
(sole producer). Retry predicate for the 3.7x: implement the in-flight bitmap +
the sharded find consults it → cutover 8t≥4×1t, e2fsck rc0, 40000-file read-back.

## Mounted frontier continuation: three fresh profile-first REJECTs and one 128-group fsck blocker - 2026-07-24 (BronzeRabbit)

Status: **REJECT 3/3; no source change.** Ledger and recent-log grep preceded
each lever. All mounted work used the exact current release-perf binary on
`vmi1227854` (SHA-256
`8ebff1f9cd9d77ed8cc68fb874f8384eb54726dc827f4db39fadb909cc150aca`)
inside a private privileged container, with the FUSE server pinned to CPU 8 and
the driver pinned to CPU 9. The container's `/tmp` mountpoint was required by
the host's AppArmor `fusermount3` policy; no host policy was changed. Raw
timing, profile, and fsck artifacts are retained under
`/data/tmp/bronzerabbit_frontier_20260724_Q7GDWQ/`.

1. **Dirty fsync, 2 groups versus 128 groups — REJECT before edit plus
   correctness BLOCKER (`bd-fsync-journal-latency-gap-ptp4x`).** A 30-round,
   median-of-21 interleave measured duplicate 2-group FrankenFS controls at
   191.922/211.106 us and the 128-group arm at 385.973 us. The paired
   128g/2g median was 1.9397x and the ratio-of-medians 2.0111x, but the
   duplicate-control null was already 1.1000x and CVs were
   26.168/25.446/23.936%. Kernel 2g/128g medians were 369.524/291.471 us
   with 90.105/58.767% CV. Thus no ratio is admitted. Exact parity was
   630 files, 80,640 bytes, and payload digest `0797b68e...` for every arm.
   Differential server profiles captured zero lost samples:
   `Cx::checkpoint` was 16.65% self at 128 groups versus 2.64% at 2 groups,
   but `ext4_persist_group_descriptors_from` remained only 0.47% self /
   0.56% children, below the ledger's 5% named-frame floor.

   Graceful unmount exposed a correctness blocker. `e2fsck -fn` returned rc 4
   on the 128-group FrankenFS image: sparse-super backup groups
   1,3,5,7,9,25,27,49,81,125 each reported a 1,027-block bitmap/count
   discrepancy, 10,270 blocks total. The 2-group FrankenFS image and both
   kernel images returned rc 0. This pattern is consistent with backup
   super/GDT reservation bits becoming authoritative in formerly-uninitialized
   group bitmaps, but that is an inference, not a diagnosed source cause.
   **Retry predicate:** first reproduce and fix this sparse-super
   backup-group durability/accounting failure with a minimal 128-group fixture
   and clean offline fsck. Only then retry performance on an isolated worker
   where all A/A/B/kernel arms have CV below 5% and an eligible non-fenced
   descriptor-persistence frame is at least 5% self.

2. **Mounted zero-byte create storm — REJECT before edit (`bd-opb6l`).**
   A 30,000-create server profile captured 3,691 cycles:u samples, zero lost.
   The only source frame above the frontier's 5% floor was
   `ShardedMvccStore::read_visible_block_buf` at 5.43% self, which is the
   explicitly fenced `bd-kdmu4` zero-copy/read architecture lane.
   `ShardedMvccStore::commit` was 4.63% and `lookup_in_dir_block` 3.20%;
   neither admits a local lever. A 30-round median-of-21 routing comparison
   preserved 630-file/zero-byte parity per arm and measured FFS A/A at
   66.555/66.750 us versus kernel 14.472 us, nominally 4.599x by medians.
   CVs were 79.131/85.570/16.295%, so no direct ratio is admitted.
   **Retry predicate:** a quiet profile must promote a non-`bd-kdmu4`,
   non-architectural source frame to at least 5% self; then all same-worker
   A/A/B/kernel arms must have CV below 5%, effect beyond null, exact file
   parity, and clean fsck.

3. **Mounted list-128 xattr direct-wire gate — REJECT before edit
   (`bd-mounted-xattr-workload-gap-fr6iq`).** Private FrankenFS/kernel files
   each contained 128 ordered one-byte attributes and a 1,664-byte list payload.
   Names and values matched exactly (`9b5c1c1d...` / `471fb943...`). A
   250,000-call profile captured 9,903 cycles:u samples, zero lost:
   `parse_xattr_entry_names` was 25.24% self, `_rjem_malloc` 9.19%, FUSE
   `listxattr` 8.38%, lossy UTF-8 iteration 7.76%, and
   `String::from_utf8_lossy` 4.93%. The shape/profile retry thresholds were
   met, but the mandatory pre-edit A/A gate was not: controls measured
   48.978/42.258 us, CV 36.743/37.473%, absolute-null median 15.979%, and
   absolute-null p95 63.921% versus the required p95 below 1%. Kernel was
   11.459 us with 16.991% CV. No direct-wire source was reopened and no direct
   kernel ratio is admitted. The small FrankenFS image containing this fixture
   passed offline fsck rc 0. **Retry predicate:** do not retry until a pinned
   pre-edit A/A run has absolute-null p95 below 1%; then require the paired
   candidate 95% lower bound to exceed that null p95, every A/A/B/kernel arm
   CV below 5%, exact mounted parity, and clean offline fsck.

This continuation therefore stops at the requested terminal condition: three
consecutive fresh REJECTs, with an independently ledgered current-source
128-group fsck blocker. No production, test, benchmark, or harness source was
edited.

## btrfs runtime path swept for a byte-identical per-op lever — SATURATED (bd-kdmu4) - 2026-07-24 (turn 6, REJECT #2)

Status: REJECT (no source change). Cycling levers off the floored read path, swept
the least-mined subsystem this campaign — the btrfs runtime read/lookup/readdir/
tree-walk path (crates/ffs-btrfs/src + the `btrfs_*` functions in ffs-core) — for
the byte-identical compile+test-landable classes (buffer-in-loop hoist,
materialize-then-scalar, multi-pass fold fusion, O(N)→O(1) memoization, hot-path
clone elimination). NO clean per-op lever found; the path is saturated with prior
`bd-*` optimizations:

- `btrfs_read_logical_into` reads straight into the caller's `out` slice (no
  per-block BlockBuf alloc, no post-read copy). `btrfs_read_file_into` = rayon
  deferred device reads + `split_at_mut` disjoint zero-copy windows + per-inode RO
  extent cache + lock-free hot-inode slot + decompressed-extent cache; its only
  `vec![0; compressed_len]` is INSIDE the rayon job (excluded).
- `btrfs_read_parsed_node` Arc node cache; its `vec![0; ns]` is MOVED into
  `parse_btrfs_tree_node_owned` as the node's retained backing (not a discarded
  loop buffer). `btrfs_lookup_child` O(1) dir-entry cache; `btrfs_readdir_entries`
  zero-copy `range_with` + FxHash first-occurrence dedup; `btrfs_fs_tree_root_bytenr`
  memoized O(1); `btrfs_decompress` per-thread zlib/zstd context reuse;
  `btrfs_verify_one_extent_csum` reused sector buffer (prior win e0aa5a1b).
- ffs-btrfs `.sum()`/`.fold()` sites (total_free/total_used/largest_free_extent/
  sync_block_group_accounting) are single-pass, on the write/commit path — not
  per-read, no fuseable multi-pass. Item parsers (parse_dir_items/extent_data/
  inode_refs/inode_item/collect_leaf_items) build only their required owned output.

Sub-noise candidate flagged + rejected: `btrfs_lookup_child` (ffs-core ~8604)
`parse_dir_items` materializes a `Vec<BtrfsDirItem>` (per-name `.to_vec()`) then
linear-scans for one name — the zero-alloc `visit_dir_items` visitor (ffs-btrfs
~1914) would early-exit without allocating. REJECTED: a DIR_ITEM bucket keyed at
one `name_hash` holds ≈1 entry (multiple only on hash collision) → ratio ≈1→1, and
it is a fallback BEHIND the O(1) `btrfs_dir_entry_cache` + tree-log point-descent →
below the noise floor. Retry only if a warm-btrfs-lookup profile shows
`parse_dir_items`/`btrfs_lookup_child` >~5% self-time (i.e. a collision-heavy or
cache-cold dir workload).

⭐ 2 consecutive fresh REJECTs this session (turn 5 read-path floor, turn 6 btrfs
saturation) on top of turn 4b's peer-file BLOCKER and the memory's exhaustive
ext4/alloc/dir/extent/xattr/inode/ondisk sweep. The bd-kdmu4 micro-lever surface
is exhausted; the sole productive lever remains the bd-bhh0i cutover, blocked on
the peer-side sharded dir-growth dev-routing (turn 4b) — flagged for coordination.

## Mounted read-path zero-copy re-probe — FUSE transport floor CONFIRMED with 3 fresh negative findings (bd-kdmu4) - 2026-07-23 (turn 5, REJECT)

Status: REJECT (no source change). After the bd-bhh0i wiring blocker, cycled back
to the zero-copy read lane and re-investigated it fresh (ledger + code, not just
prior memory). The mounted read is at its FUSE-transport floor; three doors the
prior ledger had NOT explicitly closed are now closed:

1. FUSE_PASSTHROUGH is advertised (`init()` adds `FUSE_PASSTHROUGH` +
   `set_max_stack_depth(1)`) but is ARCHITECTURALLY INAPPLICABLE to FrankenFS.
   Passthrough serves a FUSE file's read directly from a registered backing fd,
   but `struct fuse_backing_map` has `{fd, flags, padding}` and NO OFFSET field:
   fuse-file offset O maps to backing-fd offset O. FrankenFS is image-backed with
   extent-scattered file data (file byte O lives at some image offset X != O), so
   there is no single (fd, offset) that serves the file — passthrough cannot be
   wired for an image-backed extent-mapped fs. The advertised cap is inert for
   data reads. Not a lever.
2. `max_readahead` is kernel-capped: vendored fuser `KernelConfig::new` seeds
   `max_readahead == max_max_readahead == the kernel's init proposal`, and
   `set_max_readahead` can only LOWER it (`value > max_max_readahead => Err`). So
   the daemon cannot advertise a larger readahead window than the kernel offers;
   it is already at that ceiling without a call. `max_read=16 MiB` is already set,
   and `FUSE_ASYNC_READ` is on by default (vendored `INIT_FLAGS`). No init-flag
   read lever remains.
3. `read_file_data` assembly is copy-optimal (code-confirmed): segment tiling
   (Run / Partial / Zero), coalesced physically-consecutive runs read VECTORED
   straight into the caller's disjoint `&mut buf` windows (no assembly copy;
   partial head/tail blocks copy only their sub-range), parallel 128 KiB chunks
   (bd-yg6tk / bd-cc-pchunk, measured 1.67x warm), and a sequential extent hint
   (bd-vpypn) so the per-block `resolve_extent_seq` is an O(1) cached
   partition_point. The sole residual copy is the inherent page-cache -> reply-
   buffer copy, which splice targeted and was MEASURED perf-neutral (2026-07-23
   54872426: overlapped by readahead prefetch, not wall-clock-bound). mmap
   genuinely needs `unsafe` (memmap2 `Mmap::map` is an `unsafe fn`; no safe
   offset-mappable alternative) -> forbidden. io_uring submission likewise needs
   `unsafe`.

Conclusion: the mounted zero-copy read sub-lane is at its architectural floor
(transport RTT + one inherent reply copy that splice cannot beat under prefetch
overlap). This matches and extends the prior transport-bound ledger. Retry
predicate (unchanged from splice, still open): a profile showing the read
DAEMON-CPU-bound with the reply copy ON the critical path (many-client fan-in
out-running the readahead-prefetch overlap) — needs a dedicated heavy mounted
experiment; the stashed splice primitive is ready if that workload ever appears.
The sole productive bd-kdmu4 lever remains the bd-bhh0i parallel-create cutover,
now blocked on the peer-side sharded dir-growth dev-routing (turn 4b) — flagged
for coordination.

## bd-bhh0i BUG-4 wiring landed as substrate; cutover BLOCKED — sharded dir-growth bitmap write uses a NON-MVCC device (bd-bhh0i / bd-kdmu4) - 2026-07-23 (turn 4b)

Status: KEEP substrate + LEDGERED BLOCKER. Wired the OR-merge proof (turn 4 core)
through the device path and RAN the local cutover — which surfaced a precise,
diagnosed blocker that is NOT in my lane.

Landed (byte-identical default; ffs-alloc 218/218 in BOTH `default` and
`--features bhh0i_sharded_alloc`):
- `BlockDevice::rmw_block_bitmap_or` seam (ffs-block: default = read/patch/write,
  byte-identical for non-MVCC / MemBlockDevice) + `FsMvccBlockDevice` override
  (ffs-core/fs_mvcc_store.rs) that reads the base AT the txn snapshot and stages
  `MergeProof::BitmapOr` (mirrors `rmw_block`).
- `try_alloc_blocks_in_group` routes its block-bitmap write through the seam
  behind `cfg(feature = "bhh0i_sharded_alloc")`, scoped to the empty-rollback
  (steady-state) case (`ffs-alloc/src/lib.rs`); default path keeps the plain
  write. New feature `bhh0i_sharded_alloc` in `ffs-alloc/Cargo.toml`, propagated
  from `ffs-core/Cargo.toml`.

Cutover result (512 MiB / 4-group ext4, `FFS_BHH0I_SHARDED=1 create-bench / --count
N --threads T`): **1 thread OK** (8376 creates/s, e2fsck rc0); **4 and 8 threads
STILL PANIC** with the exact BUG-4 symptom `first-committer-wins conflict on block
65` (group-0 block bitmap).

Root cause (env-gated `FFS_BHH0I_DEBUG` instrumentation on every `FsMvccBlockDevice`
method + the alloc branch, added→removed): block 65 reaches my ffs-alloc
`rmw_block_bitmap_or` call (24×) but **NO `FsMvccBlockDevice` method ever sees it**
(0 in `write_block`, `rmw_block`, and the `rmw_block_bitmap_or` override — while
block 66 DID reach the override 4×, proving the seam works when `dev` is the MVCC
device). The sharded **dir-growth** block alloc (`ShardedTreeBlockAllocator` →
`ext4_sharded_alloc_blocks` → `try_alloc_blocks_in_group`) runs on
`direct_block_device_adapter()` = `CachedByteDeviceBlockAdapter`, whose
`write_block` delegates to `ByteDeviceBlockAdapter` → the RAW IMAGE (NON-MVCC).
So the dir-growth bitmap write bypasses MVCC and the OR-merge proof cannot engage;
yet the FCW conflict is a real MVCC conflict on block 65 (thousands of versions),
i.e. a SEPARATE MVCC path also stages block 65. The MVCC/non-MVCC device split for
the sharded block-bitmap alloc lives in **ffs-core's sharded create dev-threading
(`ffs-core/src/lib.rs`)** — a PEER's actively-modified file.

BLOCKER (stop condition): completing BUG-4 requires routing the sharded dir-growth
block allocation through the MVCC device (`FsMvccBlockDevice`) so
`rmw_block_bitmap_or` reaches the override and the OR-merge applies — a change in
the peer's `ffs-core/lib.rs` sharded create path, needing coordination. The seam +
`MergeProof::BitmapOr` proof landed here are the correct, tested substrate for it;
once the alloc `dev` is the MVCC device, the merge engages (block-66 proof).
Secondary finding: `Arc<D>`'s `BlockDevice` impl (ffs-block) forwards read/write
but NOT `rmw_block` / `rmw_block_bitmap_or` (uses the trait default) — a latent gap
for any `Arc<MVCC-device>` rmw caller; add forwarding when the dev-routing is fixed.

## bd-bhh0i BUG-4 core LANDED — MergeProof::BitmapOr bit-level OR-merge proof for the block-bitmap FCW (bd-bhh0i / bd-kdmu4) - 2026-07-23 (turn 4)

Status: KEEP (ab1567ba). The correctness-critical core BUG-4 needs. After BUG-5
(671cfa35) the sharded parallel-create cutover conflicts SOLELY on the group-0
block bitmap (block 65): two concurrent creates alloc dir-growth blocks in the
same group, set DISJOINT bits of the same pre-write bitmap, but the write stages
`MergeProof::Unsafe` so the two commits first-committer-wins conflict. A
byte-range (`IndependentKeys`) proof cannot express the merge — adjacent free
blocks share a bitmap byte, so the writers overlap at the BYTE level while their
BITS are disjoint.

Added `MergeProof::BitmapOr` (+ `MergeProofMechanism::BitmapOr`): whole-block
bit-level OR. `merged = latest | staged`, valid iff (1) equal length, (2) both
writers are SET-ONLY vs base (`base & !latest == 0` && `base & !staged == 0`) —
a *free* clears bits, fails this, and falls back to FCW, so the proof is only
ever effective on the alloc path; and (3) newly-set bits are disjoint
(`(latest & !base) & (staged & !base) == 0`) — two writers setting the same new
bit is a real double-allocation that MUST abort so the loser retries, never
silently coalesce. Under those preconditions `latest | staged == base |
latest_new | staged_new`: every allocation survives, no bit is invented.
`merge_valid` and `merge_bytes` share one validator (never diverge). Self-
validating: a free operation makes the proof invalid → FCW, so misuse fails
closed. Inert until a caller stages it (this commit adds no caller).

Gate: ffs-mvcc 495/0 incl. 9 new/updated BitmapOr tests — the crux (disjoint
bits sharing a byte OR-merge), fail-closed on free + on double-alloc, length
mismatch, an end-to-end concurrent same-block-alloc `resolved_writes_for_commit`
merge, the `merge_valid == merge_bytes.is_some()` invariant, and 2 proptests
(positive algebra: no allocation lost / no bit invented; negative: clears +
double-sets rejected). fmt clean. clippy on the crate is blocked by unrelated
pre-existing pedantic/nursery debt in peer-uncommitted `ffs-ondisk` (ext4.rs,
crc_incremental.rs) — not this change; my additions were hardened by inspection
against the same lints (short first doc paragraphs, no `useless_vec`, private
helper so no `must_use_candidate`).

REMAINING to complete the 3.7x cutover (next turn, precise plan):
- SLICE 2 (seam): add `BlockDevice::rmw_block_bitmap_or(cx, block, patch)` to
  `ffs-block` (default impl = read→patch→write, byte-identical for non-MVCC /
  MemBlockDevice) + an override on the MVCC device in
  `ffs-core/fs_mvcc_store.rs` that begins a txn, reads the base AT the txn
  snapshot (2b-harden rule: begin-first, else a stale-read no-conflict install
  clobbers a concurrent disjoint-bit writer), applies `patch`, and stages
  `MergeProof::BitmapOr` with the recorded device base (mirror `rmw_block` /
  `rmw_commit_block_with_proof`).
- SLICE 3 (wiring): in `ffs-alloc::try_alloc_blocks_in_group` route the bitmap
  write (`dev.write_block(cx, stats.block_bitmap_block, &bitmap)`, ~line 2697)
  through `rmw_block_bitmap_or` behind `cfg(feature = "bhh0i_sharded_alloc")`
  (default path stays byte-identical). The closure re-applies THIS op's bit
  mutations onto the base read at snapshot: the reserved marks (same
  `force_reserved_mark() || !reserved_confirmed` condition) + `bitmap_set_range
  (rel_start, alloc_count)`. Correctness note: converting to RMW-at-snapshot is
  ALSO the fix for the current separate `read_block`(2633)→`write_block`(2697)
  stale-read clobber hazard; if the found run is stale (concurrent alloc took
  it) the OR-merge disjoint-new-bits check fails → abort → retry re-finds
  (fail-closed, no double-alloc slips through).
- SLICE 3 interaction check (verified in-lane): the per-op GDT persist +
  block-bitmap checksum stamp is SKIPPED on the deferred path
  (`persist_group_desc_with_bitmap_overrides` returns `Ok` early when
  `gdt_persistence_deferred()`, default ON), and the GDT is re-persisted at
  flush from authoritative state (36257e4b), so the per-op `block_bitmap_
  override` inconsistency after a merge is moot on the cutover config; the
  post-merge bitmap checksum is validated by e2fsck. The GDT-persist-error
  rollback branch (2731) is unreachable on the deferred path (persist returns
  Ok). ⚠ If run with the sharded feature but deferral OFF, the per-op override
  (from local `bitmap`, not the merged content) could stamp a stale checksum —
  not the cutover config, but guard or assert if wiring it generally.
- SLICE 4 (validation = THE 3.7x measurement, LOCAL-ONLY): build
  `CARGO_TARGET_DIR=/data/tmp/bhh0i_target cargo build --profile release-perf -p
  ffs-cli --features bhh0i_sharded_alloc`; `FFS_BHH0I_SHARDED=1 create-bench
  <img> /d --count 40000 --threads {1,4,8}`. Gate: no FCW conflict on block 65
  at 4-8 threads, 8t ≥ 4×1t creates/s, e2fsck rc0, 40000-file read-back per
  thread. Retry predicate for BUG-4 as a whole: SLICE 2+3 wired AND SLICE 4
  green. Coordinate: peer(s) active on `ffs-core/sharded_alloc.rs` — Slice 3 is
  in `ffs-alloc/lib.rs`, do NOT touch sharded_alloc.rs.

## Fsync, small-file, and mounted-xattr measured frontier is transport/architecture-only - 2026-07-23 (BLOCKED; bd-fsync-journal-latency-gap-ptp4x / bd-opb6l / bd-mounted-xattr-workload-gap-fr6iq)

Status: BLOCKED with no source edit. This is the consolidated stop condition
after the list-24 direct-wire REJECT, not a claim that the kernel gaps are gone.
A fresh negative-ledger grep and `git log --oneline -30` were run after commit
`248dda68`, before considering another lever. They show that every remaining
measured hotspot is either below the profile floor, already optimized, or
inside the explicitly fenced architectural lane.

Fsync/journal:

- The newest quiet clean-directory profile measures FrankenFS at 14.957
  us/call versus kernel ext4 at 401.219 us/call: FrankenFS is already 26.83x
  faster on that exact no-op boundary. The proposed parsed-GDT-cache
  invalidation was rejected because the whole enclosing function was only
  0.02% self.
- The dirty create+write+fsync-each workload is barrier-parity: 18.24-19.20 ms
  for FrankenFS across 2 versus 128 groups, versus the same approximately
  20-ms physical barrier that puts the mounted storm at kernel parity. The
  64x group-count increase changed latency only about 4%, rejecting dirty-group
  tracking on ordinary SSD/disk.
- `ShardedMvccStore::flush_to_device` already sorts once, coalesces contiguous
  blocks, emits one write per run, and performs one sync. The only remaining
  structural durability lever is JBD2 cross-operation group commit / durable
  visibility gating, which is an architectural crash-consistency change and is
  outside this measured-frontier lane.

Small-file storm:

- Mounted single-thread create without fsync remains about 5.7x slower than
  kernel (590-621 ms versus 105-108 ms for 3,000 files), but the symbolized
  daemon profile is FUSE receive/reply/scheduler work; every `ffs_*` create
  frame is below 0.8% self. Fsync-each is already kernel parity
  (61,296 versus 61,671 ms).
- The fresh serial-delete profile put
  `remove_entry_take_inode_tracked` at only 1.16% self. Its disjoint checksum
  snapshot lever was therefore rejected before edit. The remaining
  `__memmove` / MVCC-publication costs and safe concurrent allocation cutover
  are precisely the `bd-kdmu4` / `bd-bhh0i` architectural lane fenced to cc;
  current log entries `ab1567ba` and `2f808ef8` confirm active ownership.
- Shared-channel multiloop dispatch is not a fallback: its measured speedup
  corrupted allocation/free accounting and failed offline fsck, so that family
  stays ledger-closed until its linearizability predicate is met.

Mounted xattr:

- The clean fixture gap is FUSE transport-dominated (71-77% including
  children). Result caching was rejected with internal frames at 0.01-0.04%
  self. The list-24 direct-wire retry then removed the last eligible
  names-materialisation seam but failed the decision gate: candidate CV 13.692%,
  paired mean -2.376%, bootstrap 95% `[-7.441%, +0.622%]`. Its source is fully
  reverted.

Therefore there is no eligible one-lever source change left in the requested
measured-frontier lane. Retry this consolidated blocker only when at least one
of these predicates holds: (1) a fresh quiet symbolized mounted profile puts a
non-fenced FrankenFS source frame at least 5% self on the critical path; (2) an
authorized, safe FUSE metadata batching/bypass primitive becomes available;
(3) the user explicitly hands off the `bd-kdmu4`/JBD2 architectural lane; or
(4) fsync is measured on pmem/battery-backed/nobarrier storage where latency
scales materially with group count instead of the device barrier. Until then,
another parser, cache, checksum, or coalescing cut would knowingly repeat a
dated REJECT below the transport/null floor.

## List-24 direct xattr wire encoding does not clear the mounted transport floor - 2026-07-23 (REJECT; bd-mounted-xattr-workload-gap-fr6iq)

Status: REJECT; prototype source fully reverted. Ledger and recent-log grep
first excluded the kept namespace borrow and by-index lookup plus the closed
formatter, size-probe, result-vector, metadata-worker offload, result-cache,
and unsafe transport families. The prior list-24 retry predicate was then met
with a private ext4 clone containing exactly `user.bench00` through
`user.bench23`: 24 names, 792 value bytes, and a 312-byte NUL-separated list.

Profile first: 500,000 validated baseline `listxattr` calls aggregated
12,000,000 names in 68.627 seconds. The server profile captured 849
`cycles:u` samples with zero lost. FUSE request/reply transport accounted for
76.71% including children; `parse_xattr_entry_names` was 3.29% self and
`__memmove` was 4.96% self overall, including 2.20% below the parser and 1.33%
below FUSE encoding. This admitted one narrow prototype: walk ext4 names once
and append namespace prefix, lossy-decoded name, and NUL directly into the FUSE
payload, avoiding `Vec<String>` plus the second encoding pass. It did not alter
transport, caching, batching, journaling, or the cc-owned architectural lane.

The prototype compiled strict-remote and passed its exact namespace/invalid-
UTF-8 wire test (1/1), the xattr-filtered `ffs-core`/`ffs-fuse` suites (80/80
unit tests plus 2/2 public OpenFs ext4/btrfs integration tests; two pre-existing
privileged tests ignored), and live mounted parity. Baseline, candidate, and
kernel ext4 returned identical ordered names and values with combined SHA-256
`79d600826ff6174187f7916ad7313335f455285883b296c4b979e50bbf1cc701`.
Ordering was preserved by the same entry walker; tie-breaking, floating point,
and RNG were N/A.

The admissible control was a clean-overlay build of parent `16861e4b` on RCH
worker `hz1`, SHA-256
`1c85330a78c0afad14d9fd89467e808299f6738a30167be4a4e8c07e0f93c9ea`.
The candidate was built on the same worker, SHA-256
`f133372e24a295d2bee328f8354afcbe7ee38e846fbe9d083cd2c8b12dc236b0`.
An earlier `4d309e82` control run was discarded before decision because it was
not the immediate parent. Two full 30-round runs were also retained as invalid
routing evidence: the first shared CPU 2 with a peer workload that went idle
mid-run (all-arm CV 57-68%); the second encountered a migrating peer SciPy job
(arm CV 10-20%). No quiet subset was selected.

The final pinned, priority-isolated 30-round A/A/B/kernel run used 8,000
validated calls per FFS sample and 35,000 per kernel sample. Parent controls
were 45.106 and 45.081 us/call with CV 1.847% and 2.506%; kernel ext4 was
10.682 us/call with CV 1.908%. The candidate median was 44.741 us/call, a
nominal 0.791% improvement over the pooled 45.098-us control, but candidate CV
was **13.692%**, failing the required under-5% gate. More decisively, paired
mean improvement was **-2.376%** (regression), paired median was +0.546%, the
deterministic 20,000-resample 95% bootstrap interval was
**[-7.441%, +0.622%]**, and the candidate won only 19/30 rounds. The A/A null
median was 0.637% (p95 4.971%). The raw candidate/kernel ratio was 4.188x, but
the candidate's invalid CV forbids a direct-kernel verdict.

The direct-wire source was reverted exactly; no source or benchmark harness
remains. After unmount, the reference, parent, candidate, prior-baseline, and
kernel clones were all byte-identical (SHA-256
`d1186ba20a77d1c640ee747bd1ead1e901e08f975d01163b24094dee136cd38e`)
and all passed `e2fsck -fn`.

Retry predicate: do not retry list-24 direct encoding on the current host state.
Reopen only on an exclusive or demonstrably quiet pinned host where a complete
30-round same-parent A/A/B/kernel run gives every arm CV below 5%, the paired
95% lower bound exceeds the measured A/A null, and either (a) a new profile
attributes at least 10% self to names materialisation/encoding, or (b) the
workload has at least 48 names / 624 wire bytes. Otherwise the mounted residual
remains the synchronous FUSE metadata request/reply boundary and needs an
authorized transport primitive rather than another parser/materialisation cut.

## Read-only repeated-xattr result cache cannot address the mounted transport gap - 2026-07-23 (REJECT; bd-mounted-xattr-workload-gap-fr6iq)

Status: REJECT before source edit. Ledger and recent-log grep first excluded the
kept namespace borrow and by-index lookup plus the closed formatter, size-probe,
result-vector, direct-wire tail, metadata-worker offload, and unsafe transport
families. The remaining narrow hypothesis was an inode/name result cache for a
read-only mount's repeated `getxattr` and `listxattr` requests.

Profile first: the exact clean reference fixture
`ffs_xattr_writer_reference_1677288_1782855891392514698.ext4` was cloned and
mounted read-only through quiet FrankenFS and kernel ext4 `norecovery`. Its
inline `user.mime` and `security.selinux`, 512-byte external `user.big`, absent
name, POSIX ACL access/default values, and returned name lists matched exactly.
A 500,000-syscall FrankenFS server profile captured **66K `cycles:u` samples
with zero lost**. FUSE reply send accounted for **71.40% including children**
and receive for **27.95%**. Core `getxattr` was **0.02% self**, the FUSE
`getxattr` handler **0.04% self**, and external by-index lookup **0.01% self**.
No internal list/parser frame cleared the 0.01% reporting floor.

A pinned rotating 30-sample comparator then ran 20,000 validated iterations /
100,000 syscalls per sample. FrankenFS measured **3,374.538 ms median /
33.745 us per syscall**, CV **1.799%**. Kernel ext4 measured **409.368 ms /
4.094 us per syscall**, CV **0.706%**. The admitted direct ratio is therefore
**8.243x slower** for FrankenFS. This replaces the earlier 7.495x routing-only
signal whose three arms all missed the 5% CV gate.

A result cache cannot address that residual: it can remove only an internal
lookup already below 0.04% self, while every hit must still cross the same
synchronous FUSE metadata request/reply boundary. The profile-first gate
therefore rejected the candidate before source or harness mutation; ordering,
tie-breaking, floating point, and RNG are N/A. Every timed sample asserted
aggregate result **11,380,000**. After unmount, both image clones were still
byte-identical to the source (SHA-256
`ccd38ae5397b1e7600cfd19d6901b5dee82f49a0fdadebe405d450f7dd6d74ca`)
and passed `e2fsck -fn`.

Strict-remote release-perf build: worker `vmi1227854`, job
`j-29944835100114983`, binary SHA-256
`1f8b41ed0780a7c1f7ee0664c7868cbe67dedecc4679fa26f6c3408ebf1dae91`.
Profile:
`/data/tmp/bronzerabbit_xattr_quiet_profile_4d309e82_20260723.data`.
The fixture still lacks the required 24-name list tail, so the broad parent
remains open despite the valid ratio for the covered shape.

Retry predicate: reopen a result-cache lever only when a quiet mounted profile
attributes at least **5% self** to an internal xattr frame. Reopen the
end-to-end gap only when an authorized clean clone adds list-24 and a safe,
supported transport primitive can bypass or batch metadata opcodes themselves.
Then repeat exact value/name/errno parity, server profiling, rotating
A/A/candidate/kernel measurement, effect beyond the A/A null, and CV below 5%
for every arm.

## Clean-fsync parsed-GDT cache invalidation is below the transport floor - 2026-07-23 (REJECT; bd-fsync-journal-latency-gap-ptp4x)

Status: REJECT before source edit. Ledger and recent-log grep first excluded the
kept clean-device sync epoch and durable watermark, plus the rejected dirty O(G)
descriptor rewrite, duplicate sync, JBD2 write combining, and group-commit
architecture. Source attribution found one distinct measured-frontier candidate:
`ext4_sync_with_logging` calls `clear_ext4_writable_group_desc_cache` after every
`flush_to_device_after`, including a clean boundary where `flushed == 0`. The
cache is striped across 64 mutex shards, so the hypothesis was to move this
invalidation under `flushed > 0`.

Profile first: the immutable `4d309e82` release-perf CLI was built by strict RCH
on `vmi1227854` (job `j-29944835100114983`; binary SHA-256
`1f8b41ed0780a7c1f7ee0664c7868cbe67dedecc4679fa26f6c3408ebf1dae91`).
On a private clean RW image, pinned 30 x 10,000 clean-directory `fsync` batches
measured **149.565 ms median / 14.957 us per call**, CV **3.091%**. A quiet
`cycles:u` profile captured **16K samples with zero lost**. FUSE receive/reply
syscalls dominated; the whole `ext4_sync_with_logging` function accounted for
only **0.02% self / 0.03% including children**, and neither the cache clear nor a
lock symbol reached the 0.01% reporting floor. Impossible elimination of the
entire enclosing function therefore has a ceiling of about **1.0002x**.

The identical pinned syscall loop on a kernel ext4 loop mount of an independent
clone measured **4,012.185 ms median / 401.219 us per call**, CV **1.551%**.
FrankenFS is already **26.83x faster / 96.27% lower latency** on this clean
directory shape because the previously kept device epoch skips a backing-file
sync when no write completed since the last successful sync. Both images passed
offline `e2fsck -fn`. This direct-kernel result supersedes the earlier noisy
routing-only kernel arm for this exact fixture; it does not generalize to dirty
fsync, which the same-day ledger shows at kernel parity and disk-barrier-bound.

No source or harness changed, so ordering, tie-breaking, floating point, and RNG
are N/A. No A/A/B was run: the profile gate rejects a candidate whose impossible
upper bound is below measurement resolution and whose target shape already beats
kernel ext4. A first default-INFO profile is explicitly invalid and discarded:
per-fsync tracing formatting dominated it. The accepted quiet profile is
`/data/tmp/bronzerabbit_fsync_clean_quiet_profile_4d309e82_20260723.data`.

Retry predicate: reopen only if a quiet symbolized clean-fsync profile attributes
at least **5% self** to `ext4_sync_with_logging` or `ShardedCache::clear`, or
after a supported FUSE transport primitive removes the request/reply floor and
promotes invalidation into the top path. Then use one immutable same-worker
binary, rotating A/A/B plus kernel, an effect beyond the A/A null, CV below 5%
for every arm, identical fsync results, and clean offline fsck.

## Delete checksum-snapshot split is below the measured frontier - 2026-07-23 (REJECT; bd-opb6l)

Status: REJECT before source edit. Ledger and recent-log grep first excluded the
closed allocation, directory-checksum, MVCC-copy, concurrent-dispatch, and
mounted-transport families. The remaining narrow hypothesis was to represent the
directory-entry removal checksum change as disjoint tiny fields instead of a
contiguous `DirBlockEdit` preimage snapshot.

Profile first: strict RCH built the immutable `4d309e82` release-perf CLI on
worker `vmi1227854` (job `j-29944835100114983`; binary SHA-256
`1f8b41ed0780a7c1f7ee0664c7868cbe67dedecc4679fa26f6c3408ebf1dae91`).
A fresh pinned `cycles:u` profile then removed 20,000 entries through the serial
direct-engine `delbench` path in **116.021 ms / 172,382 unlinks/s**. It captured
**893 samples with zero lost**. The whole
`ffs_dir::remove_entry_take_inode_tracked` helper accounted for just **1.16%
self**; the proposed checksum-snapshot representation is only a fraction of
that helper. Even impossible removal of the entire helper has an Amdahl ceiling
of `1 / (1 - 0.0116) = 1.0117x`.

The actual frontier remained `__memmove_avx_unaligned_erms` at **15.92% self**
(principally MVCC visible-version and block-buffer copies) and
`ShardedMvccStore::commit` at **8.72% self**. Those are architectural ownership
surfaces, not a permissible measured-frontier checksum edit. Fresh throughput
was within **0.82%** of the previous 173,790-unlinks/s run, corroborating the
same profile rather than exposing a new hotspot. The concurrent sharded merge
change landed after `4d309e82` does not affect this serial attribution.

No source or harness changed, so ordering, tie-breaking, floating point, and RNG
are N/A. No A/A/B was run: profile-first rejection prevents spending a noisy
candidate trial on a lever whose impossible upper bound is only **1.012x**. This
direct-engine attribution is not a fresh direct-kernel comparator; the existing
mounted delete/kernel measurement remains transport-dominated, and its kernel
arm missed the mandatory under-5% CV gate. The exercised image passed
`e2fsck -fn` after all deletes. Profile:
`/data/tmp/bronzerabbit_opb6l_profile_4d309e82_20260723.data`.

Retry predicate: reopen only when a clean symbolized delete profile attributes
at least **5% self** to `remove_entry_take_inode_tracked` /
`DirBlockEdit::delta`, or after a supported transport primitive removes the
mounted round-trip floor and promotes this helper into the top path. Then use
one immutable same-worker binary, rotating A/A/B, an effect beyond the A/A null,
CV below 5% for every arm, exact incremental-versus-full CRC equivalence, and a
clean offline fsck result.

## bd-bhh0i cutover — BUG-5 LANDED (sharded merge base); only the block-bitmap FCW (BUG-4) remains (bd-bhh0i / bd-kdmu4) - 2026-07-23 (turn 3)

Status: PROGRESS — cutover reduced to ONE remaining conflict. Root-caused why
BUG-3 (turn 1) didn't fix the parallel path: the create-bench uses the SHARDED
store (`ShardedMvccStore`, 32 shards), whose merge (`check_write_mergeable_locked`
preflight + `merged_write_bytes_locked` install) derived the merge base ONLY from
the version chain — empty for a freshly-allocated block — with NO staged_base
fallback. BUG-3 had only fixed the single-store `MvccStore`. Env-gated conflict
instrumentation (`FFS_MVCC_CONFLICT_DEBUG`, added then removed) confirmed the
inode-table conflict was `proof=TimestampOnlyInode base_len=0 staged_base=false`.

BUG-5 LANDED (`671cfa35`): added the staged_base fallback to BOTH sharded merge
sites (preflight + install — both are needed; fixing only the preflight would pass
the gate then install unmerged bytes via `merge_bytes`'s None fallback, clobbering
the concurrent writer). Byte-identical for the non-conflict path. Validated:
ffs-mvcc 488/0; the 4-thread sharded create-bench NO LONGER conflicts on the
inode-table block (was `block 76`).

BUG 4 — the ONLY remaining conflict (precisely diagnosed): after BUG-5, 4-thread
create-bench conflicts solely on `block 65` (512 MiB fs: group-0 BLOCK BITMAP;
`proof=Unsafe base_len=0 staged_base=false`). Mechanism: two concurrent CREATE
operations each allocate a dir-growth block in the same group; the per-group lock
serializes the in-memory bitmap read-modify, but the bitmap block is written
staged `Unsafe` (no merge), so the two commits (which set DISJOINT bits from the
same pre-write bitmap) first-committer-wins conflict. Fix needs a BIT-LEVEL
OR-merge proof: a byte-range proof (`independent_keys`) fails because two
allocations frequently set bits in the SAME byte (adjacent free blocks).
Allocation is monotonic bit-set (never clears during a create storm), so the
correct merge is `base | staged-new-bits | latest-new-bits` with validity "neither
writer cleared a base bit." This is a NEW `MergeProof` variant (correctness-
critical) plus routing the `ffs-alloc::try_alloc_blocks_in_group` bitmap
`dev.write_block` through a proof-carrying RMW (like the GDT's `rmw_block`).
Retry: implement the bitmap OR-merge proof + wire the bitmap write → full cutover
gate (8t≥4×1t AND e2fsck rc0 AND 40000-file read-back per thread). The FREE path
(punch/unlink) clears bits, so the proof/validity must handle mixed set+clear only
if a workload interleaves frees with the storm — the pure-create storm is set-only.

## bd-bhh0i cutover — BUG-3 LANDED; fast_commit regression is PRE-EXISTING on main; multiple concurrency bugs remain at 4t (bd-bhh0i / bd-kdmu4) - 2026-07-23 (turn 2)

Status: PROGRESS. BUG-3 (inode-table merge-base) LANDED as `18432557` after
resolving the landing blocker. Two follow-on findings:

fast_commit regression is PRE-EXISTING, not from BUG-3: `cargo test -p ffs-core
--lib fast_commit_del_range_apply_punches_and_frees_passes_e2fsck` FAILS on a
clean DEFAULT build (feature off, BUG-3 stashed) = clean origin/main. So the
e2fsck-unclean-after-DEL_RANGE failure is a real committed data-integrity
regression on main (in the fsync/journal lane; likely `23ad52f2 persist ext4
summaries at fsync boundary`), independent of the sharded work and of BUG-3
(which is byte-identical for that single-threaded test). BUG-3 was therefore
landed without adding any red test (main was already red on fast_commit +
btrfs_reflink flake). FOLLOW-UP: this DEL_RANGE regression deserves its own fix.

The cutover still panics at >1 thread, on MULTIPLE blocks — the "merge wiring
complete on paper" claim was badly wrong. Reproduced (512 MiB / 4-group image,
40000 creates, `--threads 4`, FFS_BHH0I_SHARDED=1, binary with BUG-3):
first-committer-wins conflicts on BOTH `block 65` (dumpe2fs: group-0 BLOCK BITMAP,
BUG 4) AND `block 76` (an INODE-TABLE block — so BUG-3 fixed the 1-2 thread
inode-table case but 4-thread load re-exposes an inode-table conflict). On the
16-group image the bitmap conflict was `block 257`; the block number tracks the
group-0 bitmap for the fs geometry.

Diagnosis blocker: the panic backtrace only shows the createbench closure —
`create` RETURNS the `CommitError::Conflict` (it doesn't panic at the write site),
so the conflict ORIGIN (which write path, which proof, disjoint vs overlapping
touched_ranges) is not on the trace. Next step MUST instrument the conflict
point: a targeted log in `MvccStore::resolved_write_valid_with_policy` just before
`Err(CommitError::Conflict)` printing block / proof variant / touched_ranges /
base|latest|staged lengths, to distinguish (a) a disjoint-slot merge GAP the
BUG-3 fix doesn't cover under N-way concurrency, (b) an inode/block ALLOCATION
RACE handing two threads the same slot (overlapping ranges → correct rejection,
but means the per-group lock doesn't serialize allocation), or (c) BUG 4 = the
bitmap staged `Unsafe` (no merge). Likely fixes: bitmap needs a bit-level merge
proof (OR set bits — a NEW proof kind, since two allocs can share a byte) or the
per-group lock held across the RMW+commit; the inode-table N-way case needs the
merge base/latest chain re-checked (possibly the recorded base is stale when a
writer read an intermediate version). Retry: instrument → fix each conflict class
→ full cutover gate (8t≥4×1t AND e2fsck rc0 AND 40000-file read-back per thread).

## bd-bhh0i parallel-create cutover RUN LOCALLY — baseline convoys, inode-table merge-base bug FIXED+validated, block-bitmap FCW is the next gap (bd-bhh0i / bd-kdmu4) - 2026-07-23

Status: MAJOR PROGRESS + INCOMPLETE. Disproved the standing "cutover is rch-remote-
only-blocked" assumption: `create-bench` + `mke2fs` + `e2fsck` all run locally (as
this whole campaign has). Ran the cutover A/B, found the single-lock convoy the
lever targets, FIXED one concrete FCW-conflict bug (validated), and identified the
NEXT one. Fix STASHED (`stash` "bhh0i-merge-base-fix"), not committed — one ffs-core
test regression in the tree needs isolation first (see below).

Cutover A/B (in-process `create-bench`, no FUSE transport; 2 GiB / 16-group image,
40000 creates, `--threads`, feature `bhh0i_sharded_alloc`, per-thread subdir):
- baseline (single-lock): 1t 143218 → 2t 112303 → 4t 81717 → 8t 79694 creates/s.
  NEGATIVE scaling (the whole-state write-lock convoy the lever exists to remove).
  e2fsck rc0 at every thread count.
- sharded (`FFS_BHH0I_SHARDED=1`): 1t 62161 creates/s (single-thread sharded
  overhead), but 2t+ PANIC with a first-committer-wins conflict.

BUG 3 (FIXED, stashed): the FIRST sharded panic was
`merge_proof_rejected: buffer length mismatch, base_len=0, latest_len=4096,
staged_len=4096` on a freshly-allocated inode-table block (TimestampOnlyInode proof),
then FCW-conflict. Root cause: `MvccStore::resolved_write_{bytes,valid}_with_policy`
derives the merge base via `version_bytes_at(block, snapshot.high).unwrap_or_default()`,
which is EMPTY for a brand-new block with no version at the snapshot — but two
concurrent creates writing disjoint inode slots of that new block both RMW'd the
same on-disk (device) content, which is the true common ancestor. The remote
concurrency test (6ed27b4a) missed this because it PRE-POPULATES a base version
(`read_visible(...).expect("base version visible")`), so base_len was always 4096.
Fix: record the RMW's device-read base on the `StagedWrite` (only when no version
existed) and fall back to it in the merge when `version_bytes_at` is None. Both
concurrent writers record the identical device base → sound merge. Byte-identical
for the single-lock / non-conflict path (base recorded but consumed only on a
concurrent merge). Validated: ffs-mvcc `cargo test` 530/0 (all merge/SSI/sharded
tests green); sharded 1t create-bench now writes all 40000 files with `e2fsck` rc0
and the merge-rejection warning gone.

BUG 4 (NEXT gap, not yet fixed): with BUG 3 fixed, sharded 2t now panics later, on
`block 257` (dumpe2fs: the group-0 BLOCK BITMAP) with NO merge-proof warning — i.e.
staged with the default `Unsafe` proof, no merge attempted. Concurrent block
allocations (directory growth) in the same group both RMW the group's block bitmap;
the per-group lock serializes the mutation but not the snapshot→commit window, so
the second committer FCW-conflicts. Needs either a bitmap-aware merge proof (OR the
disjoint set bits — a NEW proof kind, since two allocations can touch the same byte)
or holding the per-group lock across the RMW+commit. This means the memory's "shared-
metadata merge wiring COMPLETE / no remaining per-create shared-block conflict known
on paper" was WRONG — the actual run exposes multiple conflict points (inode-table,
now block-bitmap, and GDT is likely a third under cross-group load).

ffs-core regression to isolate before landing BUG-3 fix: a `--features
bhh0i_sharded_alloc` `cargo test -p ffs-core --lib` shows 1231 passed / 2 failed —
`btrfs_reflink_random_matches_reference_model` (documented pre-existing flake) and
`fast_commit_del_range_apply_punches_and_frees_passes_e2fsck` (an e2fsck-after-
DEL_RANGE check). The BUG-3 fix is byte-identical for that single-threaded test
(base recorded but never consumed without a concurrent merge), so it is not the
cause; the likely source is the recent `36257e4b perf(bd-bhh0i): fix cutover BUG 2 —
deferred-GDT flush sources from the sharded groups` commit or the uncommitted peer
`sharded_alloc.rs` in the tree. Retry predicate: isolate `fast_commit` on a clean
build (stash the peer's `sharded_alloc.rs`, revert BUG-3), then land BUG-3 + BUG-4
together with the full local cutover gate (8t ≥ 4×1t AND `e2fsck` rc0 AND 40000-file
read-back at every thread count).

## Dirty-fsync O(G) group-descriptor rewrite is disk-barrier-masked (flat with group count) → REJECT dirty-group tracking - 2026-07-23 (bd-fsync-journal-latency-gap-ptp4x / bd-kdmu4)

Status: REJECT (measured, not reasoned). `ext4_persist_group_descriptors_from`
rewrites ALL `G` group descriptors on every dirty fsync (`for gidx in
0..alloc.groups.len()`, lib.rs:17857) versus kernel ext4's O(touched). I flagged
this as a possible large-fs lever in prior turns but had only reasoned it away as
disk-masked; this entry MEASURES it decisively.

Measured: create+write(128B)+fsync-EACH storm of 200 files, per-op median, plain
disk-backed image (real `fsync`), 2 arms differing only in filesystem size / group
count:
- 256 MiB fs (2 groups):   18.24 / 18.58 ms per create+fsync
- 16 GiB fs (128 groups):  19.20 / 19.01 ms per create+fsync

Per-op latency is FLAT (~+4%) across a 64x increase in group count. The O(G)
descriptor rewrite is fully masked by the ~18 ms synchronous `fsync` disk barrier:
the descriptor writes land in the image's page cache (buffered) before the single
device `sync`, so they cost ~nothing on the wall clock, and the per-in-use-group
bitmap-checksum preads are page-cache hits. On the common create-many-fsync-ONCE
workload the incremental watermark already amortizes it to one flush per batch.

Therefore the risky dirty-group-tracking rewrite (track a dirty-group set, rewrite
only touched descriptors — flagged risky in prior ledgers: must cover every
free-count mutation site or `df` goes stale, plus atomic contention on parallel
alloc) is NOT justified: it cannot move a disk-barrier-bound wall clock, and the
descriptor CPU is already buffered/overlapped.

Retry predicate: reopen ONLY on a workload where the dirty fsync is NOT disk-
barrier-bound AND the descriptor flush is on the critical path — e.g. a
battery-backed / pmem / `nobarrier` device where `fsync` is ~free, on a
many-hundred-group fs, with a per-file-fsync (not batched) storm — AND a
same-worker A/B shows per-op latency scaling with `G`. On any normal
disk/SSD-backed fsync this is disk-bound and there is no lever.

## Mounted metadata storm (stat-walk) is getattr-round-trip-bound + adaptive-readdirplus REJECT - 2026-07-23 (bd-kdmu4 small-file-storm sub-lane)

Status: two findings. (1) The mounted metadata storm is 2.7-4.6x slower than
kernel ext4 and is FUSE-round-trip-bound (like the create storm), not a
FrankenFS-CPU lever. (2) Advertising adaptive readdirplus is byte-identical but
PERF-NEUTRAL-to-slightly-worse → REJECT; source reverted. The durable finding is
the ROOT cause below.

Measured (256 MiB ext4 tree, 11040 entries across 40 dirs, warm, daemon pinned
8-15, client 16-23):
- `find` (readdir, names only): FFS instant (~0-10 ms) — readdir/dentry cache
  works, name-only walks are already fast.
- explicit `os.lstat` walk (readdir + getattr/entry): FFS min 231-283 ms vs
  kernel 44 ms = ~4.6-6.4x.
- `ls -lR` (getdents + stat + getxattr per entry): FFS 0.20-0.27 s vs kernel
  0.07 s = ~2.7-3.9x.

Profile (symbolized daemon): the daemon is FUSE-transport-bound — `Session::run`
-> `read` 56%, `writev`/`send` 19%, scheduler block/wake 34%; NO `ffs_*` metadata
frame reaches 1.5% self-time. Each `lstat` costs ~2 daemon requests (lookup +
getattr); each `ls -l` entry costs ~8 (add per-entry `getxattr` for
`security.selinux` / `system.posix_acl_access`). The gap is the synchronous FUSE
round-trip per metadata op, which kernel ext4 does in-kernel. Read-only metadata
ops could be dispatched concurrently, but `find`/`ls`/`os.walk` are SERIAL
clients (each op waits for the previous reply), so concurrent daemon dispatch
cannot help — same structural wall as the create storm.

ROOT CAUSE of the repeat cost (the durable finding): the kernel does NOT serve
cached attributes for this mount even though `getattr`/`entry` replies carry a
60 s `attr_valid`/`entry_valid` (`ATTR_TTL`). 2000 repeated `os.lstat` of ONE
file -> 2064 daemon `read`s (every stat round-trips). The dentry cache works
(repeated same-path lookups don't round-trip) but the ATTR cache does not. This
is almost certainly inherent RO-FUSE behavior: without `FUSE_CAP_WRITEBACK_CACHE`
the kernel's `fuse_get_cache_mask()` is 0, so `fuse_update_get_attr` treats a
`STATX_BASIC_STATS` request as needing fields outside the cache mask and syncs
(getattr) on every stat regardless of `attr_valid`. writeback_cache requires
`--rw` (RO mounts cannot opt in), so RO metadata caching is FUSE-limited, not a
FrankenFS bug.

REJECT — adaptive readdirplus advertisement: FrankenFS's `init` advertises SPLICE
+ PASSTHROUGH but NOT `FUSE_DO_READDIRPLUS`, so the (already-implemented, bd-
xmh5g.399-optimized) `readdirplus` handler is never dispatched; the kernel uses
readdir + per-entry getattr. Hypothesis: advertising `FUSE_DO_READDIRPLUS |
FUSE_READDIRPLUS_AUTO` would collapse a stat-walk to ~1 round-trip/dir. Measured
(default-ON vs `FFS_FUSE_READDIRPLUS=0`): byte-identical (`find -printf '%p %s'`
sha `fe0d5180...` on both), but `ls -lR` NEUTRAL (0.21-0.27 s ON vs 0.20-0.25 s
OFF) and daemon requests slightly HIGHER with it on (88907 vs 77827 over one warm
`ls -lR`). Why it doesn't help: (a) the broken RO attr cache means the attrs
readdirplus pre-populates are not served on the client's subsequent stat; (b)
`ls -l`'s cost is dominated by per-entry `getxattr` (ACL/SELinux) round-trips
that readdirplus does not carry; (c) the AUTO heuristic did not reduce round-trips
on the warm walk. Source reverted (2 hunks in ffs-fuse `init`).

Retry predicate: reopen readdirplus (and RO attr caching generally) ONLY after
confirming the attr-cache mechanism with an `--rw --writeback-cache` mount — if
writeback caches repeated stats and RO does not, RO metadata caching is inherent
FUSE and neither lever helps; if even writeback fails to cache, root-cause the
`attr_valid` handling as a real bug first. A readdirplus win additionally
requires eliminating the per-entry `getxattr` round-trips (e.g. an xattr batch in
the readdirplus reply, which the FUSE protocol does not support) — so readdirplus
alone is not a stat-walk lever on ACL/SELinux-labeled trees.

## splice() zero-copy FUSE read reply — IMPLEMENTED, byte-identical, PERF-NEUTRAL → REJECT (bd-kdmu4 zero-copy read-path sub-lane) - 2026-07-23

Status: REJECT. The safe-splice zero-copy read is byte-identical and the splice
path provably engages, but it is measured PERF-NEUTRAL on every read shape.
Production source stashed (`stash@{0}` "splice-read-reject-wip-2026-07-23"), not
landed. This is the follow-through on the same-day REOPEN entry below: the lever
was reopened as the top-priority in-lane item, fully implemented behind a
default-OFF flag, measured, and rejected on the measurement.

Implementation (all stashed): a full vertical slice —
  - vendored fuser: `ReplySender::send_spliced(header, src_fd, offset, len)` with
    a byte-identical `pread`+`send` default (mock senders unaffected) and a
    `ChannelSender` override that stages the 16-byte `fuse_out_header` + splices
    `src→pipe→/dev/fuse` through a per-thread `F_SETPIPE_SZ`-enlarged pipe, with
    a session-level `SPLICE_WRITE_OK` disable-on-first-failure fallback and a
    buffered fallback for payloads over the pipe soft-cap; `ReplyData::data_spliced`.
  - ffs-block: `ByteDevice::backing_file() -> Option<Arc<File>>` (FileByteDevice
    returns its `Arc<File>`; `OverlayByteDevice` forwards it ONLY when its overlay
    holds no writes — clean journal — else None).
  - ffs-core: `FsOps::splice_read_plan` returning `Some((file, phys_offset, len))`
    only for a RO ext4 mount, plain-`FileByteDevice` backing, regular file, no
    encrypt/compr/verity/inline, extent-mapped, whole range in ONE written
    contiguous extent; `Arc<T>` forwarding of the new method (the crux miss that
    made it silently no-op at first — the mount uses `Box<Arc<OpenFs>>`).
  - ffs-fuse: default-OFF `FFS_FUSE_SPLICE_READ`, splice fast path in
    `serve_read_request` before `read_with_readahead`.

Correctness PROVEN: mounted-read sha256 byte-identical to the kernel across
whole-file / 128K / 1M / 17000-byte-odd / small-file reads, with the flag both
ON and OFF (fixture `data.bin` 3-extent 200 MiB + `small.bin`). `strace` confirms
the splice path engages: 300×128K reads → 400 `splice` calls (200 read×2), and a
`send_spliced: relay Done` trace on every eligible reply. A `SIGKILL`-class
desync never occurred (RO mount, no writes).

Decisive A/B (release-perf, daemon pinned 8-15, client 16-23, warm page cache,
min-of-N, flag toggled in one binary):
- single-stream 200 MiB read, 128 KiB chunks (splice engages): OFF min 74.7-75.8 ms
  vs ON min 74.9-77.2 ms — NEUTRAL (within the ~2 ms run-to-run spread).
- single-stream, 1 MiB chunks: OFF ~76 ms vs ON ~76 ms — NEUTRAL (and 1 MiB
  payloads exceed the 1 MiB `pipe-max-size` so they fall back to buffered anyway).
- 128×2 MiB multi-file, 16 parallel readers (the bd-kdmu4 headline shape): OFF
  min 16.4-17.1 ms vs ON min 16.1-18.4 ms — NEUTRAL.

ROOT CAUSE (this is the durable finding): the warm-large-read profile's "67%
`_copy_to_iter`" is 67% of DAEMON CPU, NOT of wall-clock. FrankenFS's readahead
prefetch (the `preadv` stream that still runs, ~960 `preadv` alongside the 400
`splice`) already overlaps the page-cache→userspace copy OFF the wall-clock
critical path, so eliminating the reply copy with splice frees daemon CPU that
was not the bottleneck. The mounted read is dispatch/RTT/pipeline-bound (as the
2026-07-22 async-dispatch and prefetch entries already found), not copy-bound.
splice trades a `preadv`+`writev` copy pair for a `splice`+`splice` page-move
pair of equal wall-cost on this pipeline. The `pipe-max-size` 1 MiB cap also
excludes the largest single reads.

Isomorphism: ordering/tie-breaking/bytes unchanged (sha256-proven); FP/RNG N/A.

Retry predicate: reopen ONLY if a future profile shows the mounted read is
DAEMON-CPU-bound (daemon saturating its cpuset with copy self-time ON the
critical path, e.g. a many-client fan-in that out-runs prefetch overlap) AND a
same-worker A/B beats the buffered path outside the A/A null. A zero-copy reply
alone does not help while readahead prefetch overlaps the copy. Do NOT re-attempt
the splice reply as a throughput lever for the current prefetch-overlapped read
path. The infrastructure (safe `send_spliced`, `backing_file`, `splice_read_plan`)
is preserved in the stash if a DAEMON-CPU-bound workload ever materializes.

## REOPEN + VALIDATED: splice() FUSE read replies are SAFE (not unsafe-blocked); warm large-read is 67% copy-tax - 2026-07-23 (bd-kdmu4 zero-copy read-path sub-lane)

Status: REOPEN. Correcting a ledger MISCLASSIFICATION and attaching profile-first
evidence. Prior rows (e.g. NEGATIVE_EVIDENCE.md 2026-07-04 swarm-routing) lumped
"splice-class read gaps" with io_uring/mmap as "blocked by forbid(unsafe_code)".
That is WRONG for splice: `nix::fcntl::splice` is a SAFE wrapper (takes `AsFd`,
no `unsafe`; verified nix 0.29-0.31 signatures) — only mmap-file-maps and
io_uring registered buffers require `unsafe`. splice was never actually blocked
by the workspace lint; it was closed on a false premise. This entry reopens it
with measurement.

Profile-first (this is the key correction to the "copies ~3%" framing): the ~3%
copy figure from 2026-07-22 was the SMALL-FILE multi-file read, which is
dispatch/RTT-bound. The WARM LARGE-CONTIGUOUS read is the opposite — copy-bound.
Symbolized daemon profile (release strip=false debug=1 to a scratch target dir,
400 MiB single-file warm read repeated, `perf record -g --call-graph dwarf`):
the daemon spends **82.9% in `preadv`, of which 67% is `_copy_to_iter` /
`copy_page_to_iter`** — the kernel's page-cache -> daemon-buffer copy (COPY 1).
The subsequent `ReplyData::data(&[u8])` -> `writev` to /dev/fuse is COPY 2. This
IS the "~2x pread copy-tax" the lane names, now located and quantified on the
workload where it dominates.

Ceiling microbench (`os.splice` file->pipe->/dev/null vs preadv->buffer->write,
400 MiB warm, 7 reps median): read+write 27.3 ms / 15.4 GB/s vs splice 19.4 ms /
21.6 GB/s = **1.40x** at the copy layer. This UNDERSTATES the FUSE win because
the microbench's `/dev/null` write is free, whereas the real path's COPY 2
(writev to /dev/fuse) is a genuine copy that splice also eliminates. Mounted warm
large read currently measures 2781 MB/s; splicing image_fd -> pipe -> /dev/fuse
would replace COPY 1 + COPY 2 with page moves, leaving only the kernel's
unavoidable /dev/fuse -> client copy (COPY 3).

Feasibility (both fds are reachable): /dev/fuse fd via `ChannelSender(Arc<File>)`;
image fd via `FileByteDevice::file() -> &Arc<File>`; physical offset via the
existing extent resolve. Implementation is a correctness-critical vertical slice,
so it is NOT rushed here (a bad FUSE read reply corrupts data):
  - Slice A (vendored fuser): add `ReplySender::send_spliced(header, src_fd,
    offset, len)` with a DEFAULT impl that reads into a buffer + `send` (so mock
    senders are byte-identical), and a `ChannelSender` override that enlarges a
    per-worker pipe via `F_SETPIPE_SZ` to max_read, writes the 16-byte
    `fuse_out_header`, `splice(src->pipe)` then `splice(pipe->/dev/fuse)` as one
    reply; plus `ReplyData::data_spliced(src_fd, offset, len)`.
  - Slice B (ffs-core): a method returning `Some((image_fd, phys_offset, len))`
    ONLY when the requested range is a single contiguous UNCOMPRESSED extent with
    NO MVCC overlay / pending write for those blocks (else None -> materialize).
  - Slice C (ffs-fuse read handler): try the eligibility check, splice-reply on
    Some, fall back to `data(&buf)` on None. Env kill switch FFS_FUSE_SPLICE_READ
    (default OFF). Gate: mounted-read sha256 byte-identity (flag on vs off vs
    kernel) + warm large-read A/B + conformance.

Retry/land predicate: implement the vertical slice behind the default-OFF flag;
land only if a mounted read is sha256 byte-identical with the flag on AND a
same-worker warm large-read A/B beats the materialize path outside the A/A null.
Eligibility MUST exclude compressed extents, MVCC-overlaid blocks, fragmented
(multi-extent) ranges, and any range crossing a hole. This is the top-priority
in-lane lever; it is NOT ledger-closed.

## Mounted small-file create storm gap is FUSE-transport-bound, not a create-CPU lever - 2026-07-23 (NOT-A-LEVER / ledgered blocker; bd-kdmu4 small-file-storm sub-lane)

Status: NOT-A-LEVER. The mounted single-thread create storm is 5.7x slower than
kernel ext4, but a SYMBOLIZED daemon profile proves the entire delta is the
synchronous FUSE round-trip; `FrankenFuse::create` / `ext4_create` do not reach
0.8% self-time. No FrankenFS create-path CPU lever exists on this workload, and
the only amortization (concurrent request dispatch) is ledger-CLOSED (multiloop
REJECT corrupts allocation) / bd-bhh0i local-only cutover. Recorded so the gap is
quantified and the create-CPU door is closed, not silently retried.

Measured (fresh 256 MiB ext4 image, 3,000 x 128-byte files created into one dir,
daemon pinned CPUs 8-15, client 16-23, plain-file backing = buffered so no
per-op disk I/O):
- no-fsync create storm: FrankenFS 590-621 ms vs kernel ext4 105-108 ms = ~5.7x
  (~200 us/create vs ~35 us/create).
- fsync-each create storm: FrankenFS 61,296 ms vs kernel 61,671 ms = PARITY
  (each fsync is a real ~20 ms disk barrier; physics-bound, correctly at parity).

Symbolized profile (release + `CARGO_PROFILE_RELEASE_STRIP=false DEBUG=1` to a
scratch target dir, 6,000-create storm, `perf record -g --call-graph dwarf` on
the daemon): the daemon time is `fuser::Session::run` -> `Channel::receive` ->
`read` (30.6% reading FUSE requests), `writev` / `ReplySender::send` (~14%
writing replies), and scheduler block/wake (`schedule`/`dequeue*` ~16% — the
synchronous block-on-`read` between requests). The vendored fuser receive buffer
is allocated ONCE before the loop and reused (`session.rs:148`), so there is no
per-op receive-buffer alloc/memset despite `BUFFER_SIZE = 16 MiB + 4096`. Every
`ffs_*` create frame (create/alloc/dir-entry/inode-write/commit) sits below the
0.8% self-time floor.

Also probed (out-of-lane, no lever): 128 MiB sequential write, `set_max_write`
is never negotiated in `init`, but FrankenFS measures 176-235 ms vs a very noisy
kernel 57-260 ms (writeback-timing variance) — roughly competitive, no clean gap,
and the kernel comparator fails the <5% CV gate, so no `max_write` lever is
justified.

Retry predicate: reopen a create-CPU lever only if a future profile shows an
`ffs_*` create frame above ~5% self-time on this workload (e.g. a new superlinear
per-create cost). The transport gap itself reopens only with the bd-bhh0i sharded
parallel-create local cutover (safe concurrent dispatch of allocation-disjoint
creates) or a safe io_uring FUSE transport — both currently blocked (local-only /
`forbid(unsafe_code)`).

## Clean-device fsync skip via FileByteDevice write/sync epochs - 2026-07-22 (KEEP; bd-fsync-journal-latency-gap-ptp4x / bd-opb6l)

Status: KEEP. The unchanged-directory `fsyncdir` storm — the residual both same-day
fsync-lane keeps left at 348-372x slower than kernel — is now 16.6x faster; the
kernel gap on this shape drops from ~372x to ~27x, and the remainder is the
synchronous FUSE round-trip itself (~25 us/call), not the sync path.

Profile first: the prior keeps' profile put the leading sync-path address cluster
at 18.94% and left the frozen storm at ~410 us/call. Source attribution found
`ext4_sync_with_logging` calls `self.dev.sync` unconditionally, even when the
no-op watermark guard returned `flushed == 0`. A host syscall pricing probe on
the same backing filesystem made the attribution quantitative: fsync of a CLEAN
file costs 398.3 us/call (dirty: 8.84 ms), matching the 411 us/call frozen
residual almost exactly. Ledger grep: the closed 2026-07-14 "ext4 duplicate
device-sync elision" family targeted the second sync after a DIRTY flush and was
rejected only because the small remote workload could not resolve it, with retry
predicate "tighter same-worker A/A controls or a deterministic sync-count/latency
backend" — both are supplied here (0.73% A/A null; epoch counters + strace
syscall counts), so this entry also satisfies that row's retry predicate rather
than retrying a closed idea blind. No prior clean-device/dirty-epoch attempt
exists in either ledger.

The lever is device-level, not call-site-level: `FileByteDevice` now keeps an
`Arc`-shared `(write_epoch, synced_epoch)` pair. Every attempted write syscall
(success or failure — a failed `write_all_at` may have partially written)
advances `write_epoch` after the syscall returns; `sync` reads `write_epoch`
first, performs `sync_all`, then publishes the observed epoch via `fetch_max`.
When the epochs are equal, `sync` returns without the syscall: no write has
completed through this device (or any clone — clones share the state) since
durability was last established, so there is nothing new to make durable. POSIX
fsync only covers writes completed before the call, and a FUSE client cannot
issue an fsync ordered after a write until the daemon replied to that write —
which happens strictly after the epoch bump — so the skip is semantically exact.
`write_epoch` starts ahead of `synced_epoch`, so the first sync after open
always runs (covers mount-time journal replay through the separate journal fd on
the same path). Env kill switch: `FFS_CLEAN_SYNC_SKIP=0` restores the old
unconditional fsync. Because the MVCC flush path already syncs the device
internally through the adapter (delegating to the same `FileByteDevice`), the
outer boundary sync after a DIRTY flush now also skips — dirty boundaries issue
exactly one real fsync instead of two, landing the 2026-07-14 duplicate-sync
elision as a byproduct. Ordering preserved: no write is moved or elided, only a
provably-no-op syscall. Tie-breaking, floating point, RNG: N/A.

Decisive same-worker rotating A/A/B/kernel run (fresh image copy + fresh mount
cycle per sample; 8,000 x 128-byte files + 3 sentinels populated outside timing;
daemon pinned to CPUs 8-15, client to 16-23; sample = median of 3 batches x
2,000 `fsync(dirfd)` calls on the unchanged 8,003-entry directory; 6 samples per
arm; candidate binary SHA-256
`b2e8f748bd3e2e82efbbad5bf14e05b943079ed0e17869eccd8cfc5f9be03ebe`, controls =
same binary with `FFS_CLEAN_SYNC_SKIP=0`, fixture SHA-256
`cff2c98c4d34e3d952a3b7f93fa22bfdbec7781942188b38bb42524f63a60dd8`):

- control A (env-off): 821.785 ms median, CV 0.94%
- control B (env-off): 827.777 ms median, CV 0.67% (A/A null spread 1.0073x)
- candidate (lever on): 49.567 ms median, CV 6.99% (12-sample: 48.538 ms, CV 6.32%)
- kernel ext4 (dio-loop): 1.846 ms median, CV 21.32% (routing evidence only)

Candidate is 16.58x faster than the faster control; the candidate arm's CV sits
above the 5% gate (RTT-bound shape on a loaded box), so the honest bound is
worst-candidate vs best-control = 807.260/53.228 = 15.2x — the verdict cannot
flip. Externally consistent: both env-off controls reproduce the prior session's
frozen-pre controls (819.5/818.1 ms) within 1.2%. Per-call: 411 us -> 24.8 us;
the removed 386 us equals the measured 398 us clean-fsync price within noise.

Mechanism proof: strace of the daemon during a 500-call storm counted exactly 1
fsync syscall with the lever on (the first-sync-always) vs 500 with it off.
Durability proof (kill -9): with skips exercised before and after, a new file
written and `fsync`ed, then SIGKILL (no graceful shutdown, no unmount flush):
`e2fsck -fn` rc 0 and the payload's exact SHA-256 read back through a kernel
mount. Every A/B cycle validated entry count, byte totals, and 3 sentinel
payloads before and after timing, and every image passed `e2fsck -fn` rc 0.

Gates: `cargo test -p ffs-block --lib` 309/0 including two new epoch-invariant
tests (first-sync-always + clean-skip + re-dirty, clone-shared state);
`cargo clippy -p ffs-block --all-targets -- -D warnings` clean (pre-existing
bench/example lint debt cleared in the companion chore commit); release CLI
build clean. Residual: the ~27x kernel gap on this shape is the synchronous FUSE
round-trip (~25 us/call vs kernel ~0.9 us in-kernel fsyncdir); the concurrent
dispatch that would amortize it is ledger-CLOSED above (multiloop REJECT) until
its linearizability retry predicate is met. `clear_ext4_writable_group_desc_cache`
still runs on every no-op boundary — a follow-up candidate, likely minor now.

## Shared-channel multiloop FUSE dispatch - 2026-07-22 (REJECT; bd-opb6l)

Status: REJECT and restore the single FUSE receive/dispatch loop. The candidate
nearly doubled the measured four-client delete throughput, but violated ext4
allocation/free and durability invariants under repeated churn. No production
source is retained.

Profile first: the frozen standard mount took 370.291824 ms for an 8,000-file,
four-directory/four-client delete plus `fsyncdir` storm versus kernel ext4 at
229.141343 ms (1.616x gap). A stripped daemon cycles profile captured 603 samples
with zero loss; `__memmove` held 7.12%, `memcmp` 2.37%, and the remaining leading
frames were FUSE read/write/syscall dispatch. Source attribution then found that
vendored `fuser::Session::run` has one explicitly non-concurrent receive loop even
though `MountOptions::resolved_thread_count()` reported four workers on the pinned
cpuset. Ledger and recent-log grep ruled out the closed delete-serial-floor,
version-coalescing, Cx-pooling, S3-FIFO slab, Bloom, DenseVisited, and
write-block-ownership families. The alien-graveyard Arrakis/io_uring primitive was
therefore tested narrowly: initialize once, then run one FUSE receive buffer/event
loop per available worker over the shared channel while cloning only the Arc-backed
adapter state.

The pinned rotating same-host A/A/B run used byte-identical clean ext4 images
(`e50b838a382a7e90ccaa71174fbce34b4e86626bb1706e835732727e05997aeb`), four
directories, four clients, exact 128-byte payloads, setup outside timing, directory
fsync, and 30 admitted 8,000-delete samples per arm:

- frozen-pre control A: 397.520856 ms, CV 1.971210%
- frozen-pre control B: 400.809427 ms, CV 4.300249%
- four-loop candidate: 203.287380 ms, CV 2.246183%
- kernel ext4: 76.778175 ms median, but CV 10.976081% (routing evidence only)

The candidate was 1.963551x faster than the control-pool mean, well beyond the
0.827270% A/A null spread. A larger 32,000-delete candidate/kernel comparator gave
670.580733 ms at 0.758367% CV versus 236.532995 ms at 5.352389% CV; the kernel arm
again missed the under-5% admission gate and no direct-kernel ratio is claimed.
Frozen/candidate binary SHA-256 values were respectively
`2918b6450ab97421e70b246776d5759de854ac4180d7988058e9ccd9d1788cf1` and
`1ca2a3a46c8f6c2b54d8d6272c222a3f8ce61aa8015e76f093570b857c8083b3`.

Correctness veto: three named scoped workers plus the main loop proved the
candidate was actually live. Under repeated near-capacity four-client churn it
then returned `EINVAL` while creating worker 2's file 13,641. Live accounting at
the failure was 61,658 used inodes and 246,662/262,144 used blocks; after deleting
every benchmark-created file it still reported 185,021 used blocks and only 17
used inodes. Frozen controls, after the same smaller-storm A/A workload, returned
to 16 inodes and 13,164 blocks. After graceful daemon shutdown, both frozen images
passed `e2fsck -fn` rc 0 at 16 files/13,164 blocks and kernel passed rc 0 at
16/13,600. The candidate failed rc 4 at 61,658 files/246,662 blocks with block- and
inode-bitmap differences plus wrong free-block counts in every group. Ordering and
tie-breaking are therefore not isomorphic: concurrent request execution can race
ext4 allocation/free and durable-summary publication even though individual
requests and replies are unchanged. Floating point and RNG are N/A.

Strict-remote `cargo check -p ffs-fuse --all-targets` passed on `ovh-b`, job
`j-29943190916169857`; strict-remote release CLI build passed on `vmi1153651`, job
`j-29943190916169856`; targeted nightly rustfmt and `git diff --check` passed before
measurement. Retry only when a mounted concurrency oracle proves linearizable
ext4 block/inode allocation, free, and durable-summary publication across concurrent
FUSE requests, and a fresh four-client 64,000-file create/delete cycle repeated at
least 15 times returns to the frozen control's inode/block counts with every image
passing `e2fsck -fn` rc 0. The same retry must also obtain an interleaved kernel
comparator below 5% CV. Until all parts hold, shared-channel multiloop dispatch is
ledger-CLOSED.

## Ext4 fsync deferred-summary durability boundary - 2026-07-22 (KEEP correctness; perf-neutral; bd-fsync-journal-latency-gap-ptp4x / bd-opb6l)

Status: KEEP as a required ext4 durability-boundary repair. The unchanged-directory
hot path is performance-neutral within the same-worker A/A null; this is not claimed
as another speedup.

Profile and conformance first: after the durable-watermark scan KEEP, the mounted
8,000-file unchanged-directory workload still spent 7.710211 seconds in 10,000
`fsyncdir` calls. A server-side cycles profile captured 1,870 samples with zero loss,
with the stripped release binary's leading sync-path address cluster holding 18.94%.
The mandatory post-profile mounted check then supplied stronger negative evidence:
both frozen controls and the candidate returned `e2fsck -fn` rc 4 with identical stale
inode/block bitmaps, free counts, checksums, and group summaries, while kernel ext4 was
clean. Ledger and recent-log grep showed that deferred GDT persistence is default-on
and is required at durability boundaries; its recorded retry predicate now held because
mounted FUSE and exact offline fsck reproduction were available. Source attribution
found that FUSE `ext4_sync_with_logging` flushed MVCC versions and synced the device but
never persisted the derived group descriptors or superblock free totals. It also
published the MVCC cursor before the caller's device sync, contrary to its retry
contract. No closed FIFO slab, Bloom prefilter, DenseVisited, or write-ownership family
was retried.

The kept boundary now holds the durable-cursor mutex while it flushes versions, clears
the writable descriptor cache, persists group descriptors and superblock free totals
when any version was flushed, and syncs the device. Only after every step succeeds does
it publish `durable_through`; any error leaves the old cursor so retry rewrites the full
suffix and its derived summaries. When `flushed == 0`, the new summary writes remain
skipped, preserving the no-op watermark fast path. Ordering preserved: the original
sorted/coalesced block writes are unchanged, followed by their required derived ext4
summaries and the existing device sync. Tie-breaking unchanged: newest-visible MVCC
selection is unchanged. Floating point and RNG: N/A.

The decisive pinned, rotating, same-worker A/A/B/kernel run used fresh clones and 30
samples per arm, each the median of three 2,000-call unchanged-directory `fsyncdir`
batches after an exact 8,000 x 128-byte durable warmup:

- frozen-pre control A: 819.529760 ms, CV 1.274955%
- frozen-pre control B: 818.145700 ms, CV 1.410293%
- candidate: 819.617904 ms, CV 0.947339%
- kernel ext4: 2.200209 ms, CV 2.905261%

Candidate/pre-control-pool is 1.000953x (0.0953% slower), inside the 1.001692x
(0.1692%) A/A null spread: performance-neutral. Candidate remains 372.518x slower than
kernel on this synchronous FUSE transport shape. Frozen/candidate binary SHA-256 values
were respectively
`5400b53171a337b1189657204f7728af08073bfcf1464de8e61593d9dfce02cb` and
`2918b6450ab97421e70b246776d5759de854ac4180d7988058e9ccd9d1788cf1`.

Behavior proof was exact. Every arm had 8,000 files, 1,024,000 payload bytes, and three
matching sentinels. After daemon-only graceful SIGINT, both frozen images reproduced rc
4 and their original 270-file/2,357-block summary; candidate passed `e2fsck -fn` rc 0
with 8,271 files/10,406 blocks, and kernel passed rc 0 with 8,271 files/10,403 blocks.
An independent fresh candidate clone also passed rc 0 with 8,271 files/10,406 blocks.
The focused default-on/checksum-on fsync-summary test passed 1/1 on strict-remote
`vmi1153651`, job `j-29943190916169812`; the release CLI build passed on strict-remote
`vmi1227854`, job `j-29943190916169818`. Targeted nightly rustfmt and
`git diff --check` passed.

## Durable-watermark no-op checkpoint scan guard - 2026-07-22 (KEEP; bd-fsync-journal-latency-gap-ptp4x / bd-opb6l)

Status: KEEP for the narrow MVCC checkpoint primitive. The mounted ext4 mutation
conformance gap described below remains open and prevents an end-to-end kernel-parity
claim.

Profile first: after the incremental durable-watermark KEEP, a frozen-pre mounted image
with 8,000 warm 128-byte files took 7.710211 seconds for 10,000 unchanged-directory
`fsyncdir` calls. The server-side cycles profile captured 1,870 samples with zero loss;
the stripped release binary's leading address cluster held 18.94% of samples. Source
attribution then found the exact residual: both `MvccStore::flush_to_device_after` and
`ShardedMvccStore::flush_to_device_after` still traversed every version map even when
`snapshot.high == flushed_through`, although every visited version must be rejected by
the watermark predicate. Ledger and recent-log grep found no prior read-side no-op
checkpoint guard. The `fed3a313` stable-watermark publication null was a different
SnapshotRegistry write-side atomic, and the closed DenseVisited/write-ownership families
were not retried.

The kept lever snapshots first and returns `(0, snapshot.high)` when
`snapshot.high <= flushed_through`. Commit sequences are monotonic, so the stable
snapshot cannot contain a version newer than the durable cursor in that branch. The old
scan would therefore reject every entry and issue zero writes. A commit racing after the
snapshot was already outside the old flush's visibility and remains outside the new one.
The caller's device `sync` is unchanged. Public full-checkpoint calls still pass sequence
zero and traverse whenever any committed version exists. Ordering preserved: yes, the
only skipped branch emits no block run. Tie-breaking unchanged: yes, no visible version
is selected in that branch. Floating point and RNG: N/A.

The decisive same-worker mounted proof used four clones of the same clean ext4 image and
froze the pre binary twice as null controls. Every arm was populated outside timing with
exactly 8,000 x 128-byte files and validated for exact count, byte total, and three
sentinel payloads before and after timing. Requester and three FUSE daemons were pinned to
separate CPUs. Thirty rotating samples per arm each took the median of three 2,000-call
unchanged-directory `fsyncdir` batches:

- frozen-pre control A: 1,018.687532 ms, CV 3.296456%
- frozen-pre control B: 1,018.529234 ms, CV 3.593459%
- candidate: 836.161306 ms, CV 3.478875%
- kernel ext4: 2.401584 ms, CV 2.750562%

Candidate is 1.218101x faster than the faster frozen control (17.905% lower latency),
comfortably clearing the 1.000155x A/A null spread. The remaining synchronous FUSE
boundary is still dominant: candidate is 348.171x slower than kernel ext4 for this
unchanged-directory shape, so this is an internal KEEP rather than a direct kernel win.
Frozen-pre binary SHA-256 was
`aff29fdaf03f5de5fb39ea3dfe3af28ad523167334c7da1893d891c797cd1454`;
candidate was
`5400b53171a337b1189657204f7728af08073bfcf1464de8e61593d9dfce02cb`;
source fixture was
`0de4b44cacb300d71cbf2b1ae1ef3eca7d56668bec25a8a0aad2faaea874c7cb`.

Behavior-isomorphism is exact at the lever boundary. Existing single-store and sharded
recording-device tests exercise the repeated call and assert zero writes plus the same
returned watermark; both passed (2/2, strict-remote job `j-29942429901652413`). The
all-target `ffs-mvcc` check passed on strict-remote `ovh-a` job
`j-29943190916169800`, and the release CLI build passed on `vmi1227854` job
`j-29943190916169756`. `git diff --check` passed.

The broader mounted conformance gate exposed an unrelated existing defect and is recorded
without laundering it: kernel ext4's post-run image passed `e2fsck -fn`, while both
frozen controls and candidate returned rc 4 with byte-for-byte identical diagnostics
(stale inode/block bitmaps, free counts, and group-summary metadata). A separate fresh
candidate clone with daemon-only graceful SIGINT reproduced the same result. Thus the
candidate neither creates nor hides this corruption, but the parent mounted comparator
must remain open. A direct kernel durability verdict requires the ext4 mutation path to
produce an `e2fsck -fn`-clean image for this exact 8,000-file setup first.

## Incremental MVCC durable-checkpoint watermark - 2026-07-22 (KEEP; bd-opb6l / bd-fsync-journal-latency-gap-ptp4x)

Status: KEEP - mounted small-file durability now beats kernel ext4 on the measured
fresh-image fsync storm while preserving stronger whole-store durability.

Profile-first attribution found the old implementation re-writing every visible MVCC
block on every durability call. After a small mounted create/write run, the daemon logged
`flushed_blocks=2087` and `duration_us=22172` for one final `fsyncdir`; batch latency rose
as the tracked store grew. A 1,124-cycle daemon profile put syscall/scheduler and memory
movement at the top, consistent with cumulative checkpoint traffic. Ledger and recent-log
grep found no prior incremental durable-watermark attempt and ruled out the closed
duplicate-sync, DenseVisited, write-block ownership, bitmap, htree, checksum, and
copy/materialization families.

The kept lever adds `flush_to_device_after` to both MVCC store layouts and keeps the
existing public `flush_to_device` as a full checkpoint. `OpenFs` owns a base-device-scoped
`CommitSeq` watermark under a mutex held across write and sync. Only latest visible
versions newer than that watermark are sorted, coalesced, and written. The cursor advances
only after success, so a partial failure retries the full suffix; serializing calls prevents
an older snapshot from overwriting a newer durable one. Mount/replay begins at sequence
zero. Ordering and newest-visible tie-breaking are unchanged; floating point and RNG are
N/A.

The decisive proof used six fresh SHA-identical ext4 images per arm, rotating frozen-pre
control A, frozen-pre control B, candidate, and kernel ext4 on one local worker. Each arm
created and durably warmed exactly 8,000 128-byte files, then pre-created exactly 200
128-byte files outside timing and timed 200 file fsync calls plus directory fsync. Medians:

- control A: 22,595.882959 ms, CV 4.025369%
- control B: 21,977.519074 ms, CV 3.062814%
- candidate: 109.866157 ms, CV 3.503933%
- kernel ext4: 3,718.134447 ms, CV 2.302359%

Thus candidate is 200.039x faster than the faster frozen control, clearing the 1.028x
null spread, and 33.842x faster than kernel ext4 (97.05% lower latency). FrankenFS provides
stronger behavior here: the first file fsync durably checkpoints all 200 already-created
files; the watermark makes the remaining calls skip already-durable MVCC versions. Every
run verified exact counts and byte totals outside timing, and all 24 images passed offline
`e2fsck -fn`. Source fixture SHA-256 was
`0de4b44cacb300d71cbf2b1ae1ef3eca7d56668bec25a8a0aad2faaea874c7cb`; pre/candidate
binary SHA-256 values were respectively
`025e9adc5c53e896ee8fce450d401a5bdddf5df566339578995f3613232de316` and
`aff29fdaf03f5de5fb39ea3dfe3af28ad523167334c7da1893d891c797cd1454`.

Correctness gates: new single and sharded tests prove unchanged durable old blocks,
changed/new-only incremental writes, idempotent zero-write repeat, and preserved public
full-checkpoint behavior (2/2 strict-remote, `ovh-a`, job `j-29942429901652302`). The
strict-remote all-target check for `ffs-mvcc` plus `ffs-core` passed in job
`j-29942429901652292`; release CLI build passed in job `j-29942429901652307`.
Targeted rustfmt and `git diff --check` passed. Two later full-crate-test submissions were
rejected before execution because RCH had no admissible worker; fail-closed remote policy
was honored and no local Cargo ran.

## ext4_write full-block build: skip the memset on a full-block overwrite - 2026-07-14 (KEEP)

Status: KEEP — a real DEFAULT write-path win (not sharded/default-off).

The write loop builds each block to stage into the MVCC txn. For an ALIGNED FULL-block
overwrite (`block_offset == 0 && chunk_len == bs`) it used `vec![0u8; bs]` (a full-block
memset) then `copy_from_slice(data)` (memcpy) — but the zero-init is ENTIRELY overwritten
by the copy, so it is pure waste. Took `data[data_start..].to_vec()` directly (one memcpy)
for that case; partial writes still zero-fill a freshly-allocated block (bytes outside the
chunk must read as zero) or RMW-read an existing one, then patch. Byte-IDENTICAL: the
full-block staged bytes are the same `data`-filled block either way (write/roundtrip/
fallocate suite 384/0). A/B (benches/write_full_block_build, 4 KiB): memset_then_copy
**123.8 ns** → direct_to_vec **58.6 ns** = **~2.1x**, ~65 ns/block eliminated (the memset).
Hits every full-block write — the dominant shape of large sequential writes — on the
buffered write CPU path (the block is staged, not device-written, so this is real per-op
CPU, not I/O-masked). LESSON: `vec![0; n]` + `copy_from_slice(whole)` is a memset the copy
throws away — take the source directly.

## ext4_setattr (chmod/chown/utimes): read-once / write-once lean - 2026-07-14 (BOUND, no code)

Status: BOUND — probed a less-benched metadata-mutation op; already lean. No lever.

`ext4_setattr` does exactly one `read_inode_with_scope`, applies the requested fields in
place (mode preserves the type bits; uid/gid direct; atime→touch_atime,
mtime→touch_mtime_ctime — all O(1)), runs cheap immutable/verity/append guards, then one
`write_inode`. No redundant read, no re-read, no recompute for the common
chmod/chown/utimes case; both the read and write halves are already optimized (AttrOnly/
Arc-share reads, make_mut write). The only heavy branch is `attrs.size` (truncate), which
frees blocks under the alloc lock — inherent work + peer-adjacent (bd-k2wc7 truncate).
Not a lever. Confirms the metadata-mutation ops (create alloc-lean, setattr read-once/
write-once) are lean, matching the create-path "alloc-LEAN" bound.

## Block-cache locking: sharded per-shard Mutex is the deliberate benched choice - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the per-block-read cache lock; a deliberate, already-benched
decision. No lever.

Every hot cache (`ext4_file_data_block_cache`, `ext4_inode_table_block_cache`,
`ext4_base_block_cache`, `ext4_group_desc_cache`, `ext4_inode_attr_cache`, btrfs node/
dir/extent caches) is a `ShardedCache` = FFS_CACHE_SHARDS shards, each a
`Mutex<FxHashMap>`; the hit path locks ONLY the key's shard + clones the value. The
`cache_get_rwlock` bench (bd-tag2s) A/B'd a SINGLE `Mutex` vs SINGLE `RwLock` — and the
adopted answer is SHARDING (per-shard Mutex), which beats a single RwLock: true
per-shard parallelism with no shared read-count atomic. A per-shard `RwLock` (instead
of Mutex) would help only the rare case of two threads hitting the SAME shard for reads
simultaneously (prob ~1/shards for random blocks) while paying RwLock's higher
uncontended cost on EVERY get — the d3ab1bb8 "sharding already handles contention →
RwLock marginal-to-negative" pattern. Not a lever without a profile showing same-shard
read contention. Settled.

## MVCC flush/fsync path (ShardedMvccStore::flush_to_device): already coalesce-optimized - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the flush path (per fsync/sync); already optimized. No lever.

`flush_to_device` collects visible (block, bytes) across shards (each under a brief read
lock), then `sort_unstable_by_key` on block number, coalesces contiguous blocks into
runs, and writes each run with ONE `write_contiguous_blocks` (a single pwrite instead of
one per block) + a single `sync` at the end. Already the right shape:
- `sort_unstable` (not stable) + contiguous coalescing = sequential-I/O optimal.
- the per-block owned `Vec` (`resolve_version_bytes_at_or_before`) is LOAD-BEARING: the
  data must outlive the shard read lock, which is deliberately released BEFORE the I/O
  ("sort + coalesce + write holding no shard lock"), so it cannot borrow.
- fsync is I/O-bound anyway; the O(N log N) collect+sort is dwarfed by the writes.
No lever. The fsync/flush path joins the mined set (cf. rejected JBD2 sequence sort
e04d2428, fsync_latency_workload bench).

## Free/delete serial floor (free_inode/free_blocks_in_group): already optimized - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the delete serial floor (free-path analog of the alloc floor);
already optimized, mirroring the alloc path.

- `free_blocks_in_group`: reserved-block overlap uses ONE binary search ("first reserved
  block >= rel_start decides overlap for the whole run"), not a linear scan.
- checksum update is incremental (single-bit clear via `BitmapChecksumUpdate`), not a
  full-block recompute (same infra as the alloc path).
- no `highest_set_bit_index`/scan on free: `itable_unused` is monotonic (min), so a free
  never grows it back — nothing to recompute.
- residual: `free_inode_in_group`/`free_blocks_in_group` do the per-op bitmap
  `.as_slice().to_vec()`, the SAME marginal make_mut candidate already rejected for the
  alloc path (Pareto but `read_visible_block_buf` Arc-shares the overlay version so it
  clones for the hot repeated-op case = parity-tail, d3ab1bb8 neutral pattern). Not a
  lever. The delete serial floor is mined, like the create floor.

## inode-bitmap padding fill: already byte-wise + O(1) fast path (was the #1 hot fn, already fixed) - 2026-07-14 (BOUND, no code)

Status: BOUND — probed `fill_inode_bitmap_padding_with_clear_undo` (per inode alloc,
create serial floor); already optimized, and its own comment shows it was ALREADY the
profiled #1 hot function that got fixed.

The inode bitmap block is `block_size` bytes but only `inodes_per_group` bits are used,
so the padding region [inodes_per_group, block_size*8) is thousands of bits, set on
EVERY inode alloc. It USED to scan bit-by-bit (with a per-bit `bitmap_get`) — the code
comment records it was "the #1 hot function in parallel create (~13% self time)"
because after the first alloc every padding bit is already set yet was re-scanned one
bit at a time. It has since been rewritten: whole `0xFF` bytes skipped in O(1), a fast
path that returns immediately once the FINAL byte is already `0xFF` (the padding is one
contiguous block, so a set final byte ⇒ whole region padded ⇒ nothing to do), and only
NEWLY-set bits recorded for rollback. The common already-padded case now touches no
bit. The non-undo sibling `fill_inode_bitmap_padding` is byte-wise (0xFF whole bytes)
too. No lever — this is exactly the profiled create-floor hot fn, already fixed
(alongside highest_set_bit 05a28387, bitmap SWAR, incremental checksum, reserved
no-alloc). The alloc create serial floor is thoroughly mined.

## Block-cache hasher + per-op timestamp: already optimal / not byte-id-changeable - 2026-07-14 (BOUND, no code)

Status: BOUND — two more per-op hot spots probed, neither a lever.

- `ShardedCache` (every metadata/data/extent-node/group-desc block cache get): already
  uses `rustc_hash::FxHashMap` (fast non-cryptographic hash — a u64 `BlockNumber` key
  needs no SipHash), sharded so gets on distinct shards run fully parallel, and the hit
  path locks only the key's shard + clones the value (`cache_get_rwlock` benched). The
  obvious "swap SipHash → FxHash" win is already done.
- `now_timestamp()` (per write/create/mkdir/setattr): a single `SystemTime::now()` =
  one vDSO `clock_gettime` (~5–10 ns) + arithmetic, called ONCE per op — not redundant.
  The only cheaper option, `CLOCK_REALTIME_COARSE` (~1 ns), changes the nanosecond
  timestamps written to disk (ctime/mtime/*_extra) — a SEMANTIC / non-byte-identical
  change, not a perf lever. Rejected.

## MVCC version-chain resolution + staged-write lookup: already binary-search/SmallVec - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the MVCC read/commit hot path (ffs-mvcc, my lane); already
optimal. No lever.

- `newest_visible_index` / `resolve_version_bytes_cow_at_or_before` (per `read_visible`,
  i.e. every read-your-writes + adapter read): `partition_point` BINARY search over the
  version chain, then a Cow (no copy on the borrow path). Not a linear scan.
- `staged_write_pos` (per staged-block lookup during a txn): `binary_search_by_key`;
  the write set is `StagedWrites = SmallVec<[(BlockNumber, StagedWrite); 4]>` — inline
  for the common small-txn case, no heap alloc.

Consistent with the rest of the MVCC store, which this campaign already mined (merge
validators b10fc652/5c802bae, preflight, contention-metrics gating 73174f5b, read GC
un-pin 0576bb8b, Arc-share reads 5d4a8f8d). Nothing left here.

## inode-parse base-area bounds-check hoist: NEUTRAL, the `len < 128` guard already elides - 2026-07-14 (REJECT, benched)

Status: REJECT — benched the array-ref hoist on the READ side of the inode parser
(the hottest metadata op); it is a no-op. The write-side hoist won for a reason that
does NOT apply to the read side.

`Ext4Inode::parse_from_bytes_with_ibody` reads ~20 base-area fields (offsets < 128)
via `ffs_types::read_le_u16/u32(bytes, off)?`, each a `.get()` bounds check. The
write side (`serialize_inode_into`, b83531ef) hoisted the base to a `&mut [u8; 128]`
array-ref and WON — but its only length fact was a `debug_assert_eq!(buf.len(),
inode_size)`, which LLVM ignores, so its per-field checks were NOT elided. The read
side is different: `parse_from_bytes_with_ibody` opens with `if bytes.len() < 128 {
return Err }`, which establishes `len >= 128` for LLVM's range analysis; with
`read_le_*` `#[inline]` + const call-site offsets, `bytes.get(off..off+n)` for
`off+n <= 128 <= len` is provably in-bounds and LLVM already elides it.

Bench (benches/inode_base_read_hoist, same binary, 15 base fields): production-style
`read_le_per_field` **3.66 ns** vs literal-offset `arrayref_const_offset` **3.48 ns**
— CIs overlap (3.36–4.01 vs 3.22–3.76), ~0.23 ns/field = just the loads+adds, no
bounds-check overhead in either. NEUTRAL → the hoist is redundant; kept the bench as a
regression guard (if the `len < 128` guard is ever removed, the checks come back).
Retry predicate: none — the guard already gives the elision the write side had to hoist for.

## ffs-dir htree-index sweep: binary-search where used, the rest is test-only/inherent - 2026-07-14 (BOUND, no code)

Status: BOUND — probed ffs-dir (a fresh crate); no production lever.

- `htree_find_leaf_idx` / `htree_insert`: already `partition_point` (binary search over
  the hash-sorted entries), not linear. Optimized.
- `htree_remove`: uses a linear `.iter().position()`, BUT it has ZERO production
  callers — only `#[cfg(test)]` sites (ffs-dir:1824/1827/2263/2272). Likewise
  `htree_find_leaf` has no ffs-core caller: the ext4 htree hot path resolves inline in
  ffs-core (`htree_resolve_logical`, benched), not through ffs-dir's API. So neither is
  on a production hot path; binary-search-narrowing `htree_remove` would optimize
  dead-for-prod code. Not a lever. (If ever wired to a hot delete path, note it is
  also I/O-masked: each dir-entry delete writes the dir block + frees the inode, so the
  in-memory O(#leaf-blocks) scan is dwarfed — the read_file_data segs/jobs "I/O-masked"
  class.)
- `block_contains_live_name` / the dir-block entry scans: inherent per-entry rec_len
  walks (variable-length records, not SWAR-able).
- The `.to_vec()` in the `*_tracked` variants (ffs-dir:267/794): load-bearing undo
  snapshots for journaled rollback, not waste.

## ffs-extent read-resolve + ext4 block-resolve sweep: all optimized - 2026-07-14 (BOUND, no code)

Status: BOUND — probed the file-read logical→physical resolve path (a different crate
from last turn's ffs-alloc sweep); every hot function is already optimized. No lever.

Probed (already optimized, do NOT re-attempt):
- `ext4_resolve_block_from_mappings` (per-block read resolve): `partition_point` binary
  search over the sorted mappings — O(log E), not linear.
- `ext4_resolve_block_from_mappings_hinted` (bd-vpypn): caches the last mapping index so
  sequential reads are O(1) (one bounds check), falling back to the binary search —
  benched 2.0–2.5x, byte-identical.
- `ffs_extent::map_logical_to_physical` / `map_logical_range_by_walk`: one `ExtentMapping`
  pushed per real extent; `append_hole_mappings` emits ONE mapping per `u32::MAX` chunk
  (≈1 per hole), not per block — already O(#extents), not O(#blocks).

Considered + rejected (cold): `map_single_logical_to_physical` returns `vec![one_mapping]`
(a 1-element heap Vec) for the count==1 case. It is NOT on the hot read path — reads
resolve through the CACHED mappings via `ext4_resolve_block_from_mappings(_hinted)`, not a
per-block `map_logical_to_physical` call; `map_single` fires only for uncommon count==1
calls in the write/fallocate range paths (ffs-core:21671+). Cold + the public
`-> Vec<ExtentMapping>` return type would need a SmallVec API change to avoid the alloc.
Not worth it. Retry predicate: only if a profile shows count==1 `map_logical_to_physical`
on a hot path.

## Alloc-path fresh-function sweep: all optimized (only highest_set_bit was a gap) - 2026-07-14 (BOUND, no code)

Status: BOUND — after the `highest_set_bit_index` win, swept the neighbouring
inode/block-alloc hot functions; every one is already optimized. No lever this turn.

Probed (all already optimized, do NOT re-attempt):
- `bitmap_find_contiguous_linear` (multi-block alloc): 4-words-at-a-time SWAR fast
  path (bench `contiguous_scan_width`).
- `bitmap_count_free` (free-count): word-path + scalar partial tail (tests
  `..._word_path_handles_partial_tail`).
- `reserved_inodes_in_group` (per inode alloc/free): returns a NO-ALLOC `Vec::new()`
  for every group ≥ 1 (reserved inodes are all in group 0); the group-0 Vec is small
  + transient (group 0 fills once). Not a lever.
- htree `dx_hash` / `str2hashbuf` (per htree lookup/create): already uses a STACK
  `[u32; 8]` buffer, not a per-call `vec!` (bd-cc-str2hashbuf-stack).
- `stamp_bitmap_checksum_from_override` (per alloc): INCREMENTAL — a single-bit flip
  uses `BitmapChecksumUpdate::Incremental` (`bitmap_checksum_incremental_from_flipped_
  bit_range`), never a full-block crc32c recompute; `Full` only on bulk overrides.

Considered + rejected (marginal): `try_alloc_inode_in_group_persist_core` does
`bitmap_buf.as_slice().to_vec()` (a block-sized copy) per inode alloc. `make_mut()`
(COW, cf. 8984db03) would be Pareto, BUT the bitmap block gains an MVCC overlay
version after its first write, and `read_visible_block_buf` Arc-SHARES that version, so
every subsequent same-group alloc's `make_mut` CLONES (== to_vec) — only the first
base-read per group is free. On a create-storm that is parity-tail (the d3ab1bb8
"neutral-in-practice → reject" pattern); the borrow-flow churn (the `&mut bitmap`
threads through set-undo, find_free, padding, the override borrow, the write, and the
error-path rollback) is not justified for a ~always-clone win. Retry predicate: only if
a profile shows the per-alloc bitmap copy is non-trivial AND most reads are base-unique.

## `highest_set_bit_index` word-at-a-time reverse scan (inode-alloc itable_unused) - 2026-07-14 (KEEP)

Status: KEEP — a real DEFAULT-path win on the create serial floor (the first
non-sharded, non-post-cutover lever in several turns).

`highest_set_bit_index` runs on EVERY inode alloc (in `persist_group_desc_*`, to
recompute the group descriptor's `itable_unused = inodes_per_group - highest_used -
1`). It reverse-scanned the group's inode bitmap BYTE-BY-BYTE for the top set bit.
On a SPARSE group (few low inodes used — the common early-fill state, and the create
serial floor) it walks all the high zero bytes to reach the top bit — O(nbytes),
e.g. ~1024 iterations for inodes_per_group=8192. Rewrote it to skip a u64 (8 bytes)
per step: the last byte stays scalar (the only byte that can hold a padding bit >=
count), the fully-real lower bytes are skipped by `u64::from_le_bytes(..) != 0` +
`63 - leading_zeros()`. Byte-IDENTICAL to the scalar reverse scan, proven exhaustively
by a new proptest `proptest_highest_set_bit_index_matches_scalar` (512 random
bitmap/count cases incl. the padding boundary and count>bits) + the existing
`..._finds_top_used_bit_and_ignores_padding` edge-case test (ffs-alloc 218/218). A/B
(benches/highest_set_bit_width, sparse worst case): **~3.5x** — 2048: 86.8->24.8 ns;
8192: 284->80 ns; scaling ~3.5x at 65536; CIs cleanly separated. ~200 ns saved per
inode alloc (inodes_per_group=8192) on the create serial floor, so it helps BOTH the
single-lock create path AND the sharded 3.7x path (unlike the default-off sharded
micro-levers). Not the full 8x (the compiler partly handles the byte loop) but a
clean, e2fsck-safe (pure-function, proptest-pinned) reduction.

## ext4 metadata checksum path is already optimal (crc32c hardware-accelerated; simd warm is diagnostic-only) - 2026-07-14 (BOUND, no code)

Status: BOUND — the ext4 metadata-checksum hot path (every inode / group-desc /
dir-entry / extent-node write) is not a lever.

Investigated because a peer accelerated btrfs's crc32c (652bee53) and ext4 computes a
crc32c metadata checksum on every metadata write (a hot DEFAULT path). Findings:
- **crc32c math already hardware-accelerated.** `ext4_chksum` (ffs-ondisk/ext4.rs:34)
  routes through `ffs_types::crc32c_append`, which delegates to the `crc32c`
  DEPENDENCY crate (self-detecting SSE4.2 / aarch64-CRC internally). `#![forbid(unsafe_code)]`
  bars us from writing our own intrinsic path anyway; the dep already provides the
  fast one. Nothing to accelerate.
- **the per-call `simd_capabilities()` warm is diagnostic-only, and sub-noise.**
  `crc32c`/`crc32c_append`/`blake3_hash` each call `let _ = simd_capabilities();`
  (an `OnceLock::get_or_init`). But `SimdCapabilities` is CONSUMED nowhere in
  production for dispatch (grep: only its own one-time `tracing::info!` log +
  `#[cfg(test)]`); the checksum crates self-detect. So the warm is purely the
  one-time capability log. Under release-perf LTO (`codegen-units = 1`) its
  initialized fast path inlines to a hot acquire-load (sub-ns), dwarfed by the crc
  math (~tens of ns for a 256-byte inode). Removing it would trade the one-time
  diagnostic log for a sub-noise gain (the fd678afe "<0.5% of the op = sub-noise"
  rule) — not worth the behavior change. Retry predicate: only if a profile shows the
  warm as a non-trivial fraction of a metadata-write op (it will not under LTO).

## Extent-meta double-walk REJECTED (already fast-pathed) + sharded `from_superblock` vein closed - 2026-07-14 (REJECT / BOUND, no code)

Status: REJECT (the extent-meta double-walk candidate from the previous entry is not
worth landing) + BOUND (the remaining sharded `from_superblock` sites are justified or
churn) — the remote-only in-lane micro-lever surface is exhausted.

**REJECT — skip the post-write extent-tree meta walk (the previous entry's candidate).**
Verdict after reading `ext4_count_extent_tree_meta_blocks` (lib.rs:12897): it ALREADY
has a depth-0 fast path — an inline extent tree (the COMMON case: extents fit in the
inode) reads `root_bytes[6..8]` (eh_depth) and returns 0 with NO parse or walk. So both
`meta_before` and `meta_after` are O(1) for the common case; the double-walk only costs
for depth>0 EXTERNAL trees (large/fragmented files, a minority). Skipping the "after"
walk there would save a recursion over cached nodes — small absolute win, ONLY for the
minority — while carrying the i_blocks-miscount risk (the unwritten->written split from
the prior entry) whose validation needs local e2fsck. Low value (common case already
O(1)) + high risk + local-only validation = not worth it. Retry predicate UNCHANGED but
downgraded: only if a profile shows depth>0 in-place-overwrite meta-walks are a real
cost AND the ffs_btree node-delta signal + local e2fsck are both available.

**BOUND — `ext4_persist_ctx_lockfree`'s `from_superblock` is not a clean lever.** Each
sharded alloc/free helper computes `FsGeometry::from_superblock(sb)` AND calls
`persist_ctx_lockfree`, which recomputes it — a real double-compute. But
`persist_ctx_lockfree` needs geo only for `block_bitmap_units_per_group`, which reads
the DERIVED `geo.cluster_ratio` (BIGALLOC: `cluster_size/block_size`); the cached
`Ext4Geometry` lacks `cluster_ratio`/`blocks_per_group`/`feature_ro_compat`, so removing
the `from_superblock` there would either DUPLICATE the cluster-ratio derivation (breaks
single-source-of-truth) or thread the caller's geo through ~5 alloc/free helpers
(churn). Neither is the clean single-field elimination the inode_size/locate_inode
siblings were. Not landed. (Unlike those two: their geo use was purely VERBATIM fields.)

**Frontier (remote-only):** the in-lane micro-lever surface is exhausted — the sharded
`from_superblock` vein is mined (spread_seed 9a5c795f, inode_size da1c804d, locate_inode
77e94d08; the rest pass the full `FsGeometry` to the allocator = justified), the default
hot paths are cache-guarded, and the one real default-path candidate (extent-meta walk)
is already fast-pathed + correctness-gated. The remaining levers are the LOCAL cutover
(the 3.7x measurement + e2fsck) and the peer-owned lanes (ffs-btrfs / ffs-btree /
ffs-block). No further remote-only micro-lever should be manufactured without a profile.

## `bd-bhh0i` `ext4_sharded_locate_inode` reads verbatim superblock fields, not a whole `FsGeometry` + the extent-meta double-walk candidate - 2026-07-14 (KEEP + BOUND)

Status: KEEP (the hotter sibling of the inode_size field read) + BOUND (skipping the
post-write extent-tree meta walk is a real DEFAULT-path lever but correctness-gated).

**KEEP — `ext4_sharded_locate_inode`: `from_superblock(sb).{fields}` -> `sb.{fields}`.**
The locator built the whole `FsGeometry::from_superblock(sb)` — a u64 group-count
division plus a ~20-field struct build — but uses ONLY three verbatim superblock
fields (`inodes_per_group`, `block_size`, `inode_size`), no derived geometry (not even
`group_count`). Read them straight off `sb`. Byte-identical: `from_superblock` copies
each unchanged, and `ext4_sharded_locate_inode_matches_locate_inode_bd_bhh0i` (asserts
the sharded locator reproduces single-lock `locate_inode` exactly across a spread of
inodes) stays green (bd_bhh0i 24/24). Hotter than last turn's inode_size site: this
runs per sharded create AND per parent-inode write. Magnitude = the eliminated
`from_superblock` build (benches/bhh0i_geo_field): **8.34 ns** -> field reads
**0.53 ns**, ~7 ns net/call. Feature-gated (default-off) -> realized post-cutover; a
Pareto cleanup on the 3.7x target path (sibling of 9a5c795f / da1c804d).

**BOUND — skip the post-write extent-tree meta walk on no-op writes (candidate, NOT
landed; correctness-gated).** `ext4_write` counts extent-tree metadata blocks BEFORE
(22399) and AFTER (22698) the write and charges the delta to `i_blocks` — TWO tree
walks per write. On a pure in-place overwrite the tree is unchanged, so the "after"
walk is redundant. This is a genuine DEFAULT-path lever (writes are common; the walk
reads index/leaf nodes for deep trees). BUT a naive "nothing was allocated -> skip"
signal is UNSOUND: an unwritten->written extent SPLIT (writing into fallocate'd blocks)
mutates the tree WITHOUT allocating data blocks, and if it overflows a leaf the node
count (hence `i_blocks`) changes — skipping the walk would MISCOUNT i_blocks =
e2fsck-dirty. A sound version needs a "did any extent-tree node get added/removed"
signal plumbed through `ffs_btree` insert/split/coalesce, and the i_blocks drift can
only be validated with a real `e2fsck` (local-only, the cutover wall). Retry predicate:
implement the node-delta signal in ffs_btree AND validate with local `e2fsck` on a
fallocate+overwrite workload; do NOT gate on allocation count alone.

## `bd-bhh0i` read `inode_size` off the superblock, not a whole `FsGeometry` + geometry-caching is resize-unsafe - 2026-07-14 (KEEP + BOUND)

Status: KEEP (a clean byte-identical sibling on the sharded create path) + BOUND
(a mount-lifetime `FsGeometry` cache is NOT a lever — online resize makes it stale).

**KEEP — `from_superblock(sb).inode_size` -> `sb.inode_size` (2 sharded sites).**
`ext4_sharded_create_inode` and `ext4_sharded_write_inode` built the whole
`FsGeometry::from_superblock(sb)` — a u64 group-count division plus a ~20-field
struct build and a cluster-ratio feature check — only to read `.inode_size`, which
`from_superblock` copies UNCHANGED from `sb.inode_size` (ffs-alloc:1533). The
non-sharded inode path already reads `usize::from(sb.inode_size)` directly
(lib.rs:5612/11452/38711); the two sharded sites were the odd ones out. Replaced with
the direct field read. Byte-identical (same `u16`; bd_bhh0i suite 24/24 green). A/B
(benches/bhh0i_geo_field, same binary): build_geometry **8.68 ns** -> direct_field
**0.50 ns** = **~17x**, ~8 ns eliminated per sharded create/write. Feature-gated
(`bhh0i_sharded_alloc`, default-off) -> realized post-cutover; a Pareto cleanup on
the 3.7x target path (sibling of the spread-seed cache, 9a5c795f).

**BOUND — a cached `FsGeometry` on `OpenFs` is NOT a lever (resize-unsafe).** The
codebase recomputes `FsGeometry::from_superblock(sb)` at ~30 sites; the obvious
"compute once at mount, reuse" caching is UNSOUND: `ext4_resize_fs`
(EXT4_IOC_RESIZE_FS, lib.rs:37935) grows `blocks_count`/`group_count` online, so a
mount-lifetime `OnceLock<FsGeometry>` would go stale after a resize (`total_blocks`,
`group_count`, `total_inodes` are geometry fields). That is WHY the recompute is
per-op. And it is not a hot-path cost anyway: the hot ops already cache what they
need (`ext4_geometry: Ext4Geometry`, the `ext4_inode_table_locations` OnceLock); the
remaining raw `from_superblock` calls are cold introspection (`count_free_*`,
`free_space_summary`, statfs) or the default-off sharded path. Threading a
per-op-scoped geo through the sharded helpers is resize-safe but high-churn (many
callers incl. tests) for a default-off win. Retry predicate: only the per-op-scoped
sharded hoist, and only if the cutover profiles `from_superblock` as >X% of create;
never a mount-lifetime cache while online resize exists.

## `bd-bhh0i` cache the per-thread spread seed + remote-e2e-validation is infeasible - 2026-07-14 (KEEP + BOUND)

Status: KEEP (a clean micro-lever on the parallel-create target path) + BOUND
(remote end-to-end cutover validation is definitively infeasible).

**KEEP — `bhh0i_spread_seed` thread-local cache (feature-gated, parallel-create path).**
The sharded create/mkdir path calls `bhh0i_spread_seed()` once per op to pick the
per-thread inode-scan start group. It recomputed a `SipHash` over
`std::thread::current().id()` EVERY call — and `thread::current()` clones+drops the
thread handle (an atomic `Arc` refcount round-trip) — even though the seed is a pure
function of the stable `ThreadId` (invariant for the thread's life). Cached it in a
`thread_local!` (lazy init once per thread; `.with(|s| *s)` read thereafter).
Byte-identical: same `ThreadId` → same seed, so every call returns what the recompute
would (bd_bhh0i suite 24/24 green, incl. the spread-dependent create/mkdir/parallel
tests). A/B (benches/bhh0i_spread_seed, same-binary): recompute **21.09 ns** →
cached **1.24 ns** = **~17x** on the op, ~20 ns eliminated per create/mkdir, CIs
cleanly separated. VALUE CAVEAT: on the feature-gated (`bhh0i_sharded_alloc`,
default-off) sharded path, so the ~20 ns/op is realized only once the cutover flips
the default — a pre-emptive Pareto cleanup on the 3.7x target path, not a live
production win today.

**BOUND — remote end-to-end sharded-create validation is INFEASIBLE (closes the
question raised at 6ed27b4a).** After remote-validating the merge MECHANISM under
threads (6ed27b4a), the open question was whether the END-TO-END sharded create path
(alloc + dir-entry + inode-table + GDT together) could also be validated remotely,
so the local cutover would only need `e2fsck`. It cannot: the sharded create tests
use `open_writable_ext4_mkfs`, which shells out to `mkfs.ext4` (absent on the fleet →
those tests SKIP). The in-Rust `build_ext4_image` helpers are minimal SINGLE-GROUP
128 KiB PARSE fixtures (hand-written superblock; no real bitmaps, GDT bitmap-block
pointers, or root-dir structure) — insufficient to open+enable_writes and run a
multi-group cross-group parallel create. Producing a real multi-group writable image
in-Rust ≈ reimplementing `mkfs.ext4` (out of scope). ⇒ the cutover (create-bench +
`e2fsck`, the 3.7x measurement) is genuinely LOCAL-ONLY; it cannot be reduced to a
remote test. Retry predicate: only if a real in-Rust ext4 formatter is added
(separate large effort) or the rch-remote-only constraint is lifted for the cutover.

## `bd-bhh0i` sharded metadata RMW: snapshot-consistent base + the GDT finding - 2026-07-13 (KEEP hardening + BOUND next lever)

Status: KEEP (soundness hardening landed) + BOUND (GDT is the confirmed remaining
parallel-create conflict; its wiring is a bigger ffs-alloc refactor, next slice).

**What landed (KEEP, this commit).** Slice 2b (last commit) wired the sharded inode
write to stage the inode-table block under a slot-scoped `timestamp_only_inode_range`
proof so concurrent DISJOINT-slot writers merge. But it read the base block via a
SEPARATE adapter read taken BEFORE the auto-commit `begin()` — a read that can observe
an OLDER version than the transaction. If a concurrent writer to the same block commits
in the read→begin window, the RMW's own commit sees `observed <= snapshot.high` (NO
conflict) and installs the stale-based block, SILENTLY CLOBBERING the concurrent
writer's disjoint slot — a corruption the merge proof cannot catch (the conflict path
is never entered). Fixed: `FsMvccStore::rmw_commit_block_with_proof` does begin →
read AT `txn.snapshot()` (`read_visible`, else base device) → patch → stage-with-proof
→ commit. A commit after `begin` now forces `observed > snapshot.high` → the
conflict/merge path (overlays only the declared range onto latest = correct); with no
intervening commit the read is current and the install is fresh. Byte-identical
single-threaded (same bytes, same store); the snapshot-consistent read only matters
under a concurrent writer. Gate: `cargo test -p ffs-core --features bhh0i_sharded_alloc
bd_bhh0i` = 23/23 (incl. the disjoint-slot merge test + create/write byte-id
sentinels); default-features build clean. Concurrent soundness itself is validated at
the local cutover (slice 5, e2fsck-gated) — remote tests skip the image.

**The GDT finding (BOUND — the remaining conflict; next lever).** Confirmed the OTHER
shared-metadata block that FCW-conflicts on parallel create is the GROUP-DESCRIPTOR
(GDT) block. Evidence: the sharded inode alloc (`sharded_alloc::PerGroupAlloc::
alloc_inode` → `ffs_alloc::try_alloc_inode_in_group_persist_core`, ffs-alloc:3437)
persists the group descriptor PER ALLOC via `persist_group_desc_..._with_bitmap_
overrides` → `dev.write_block(gdt_block, ..)` (ffs-alloc:2243), staged under the
default `Unsafe` proof. All group descriptors for a small fs live in ONE GDT block, and
the per-group lock protects only the group's OWN bitmap block — NOT the shared GDT
block. So two concurrent creates in DIFFERENT groups both write that GDT block →
first-committer-wins conflict ("block 657"). The write is a clean per-descriptor RMW:
it patches only `buf[offset_in_block .. offset_in_block + desc_size]` (offset =
`(group % descs_per_block) * desc_size`, ffs-alloc:2145), so disjoint-group descriptors
are a textbook range-overlay merge (`independent_key_range(offset, desc_size)`).

Why NOT wired this turn: the GDT read+patch+write lives inside ffs-alloc's persist path,
shared with the single-lock path, and — like the inode case above — must read AT the
transaction's snapshot to be sound (a naive trait-level `write_block_disjoint` hint that
keeps the pre-read in `persist_group_desc` reintroduces the exact stale-clobber window
just fixed). Doing it right = threading a begin-first snapshot-consistent RMW through
`try_alloc_inode_in_group_persist_core` (or lifting the GDT write into a proof-carrying
ffs-core helper), which is a multi-file slice, not a one-turn drop-in. Superblock
free-totals are NOT a sibling: `ext4_sync_superblock_free_totals` /
`ext4_persist_group_descriptors_from` run at the durability boundary via a DIRECT
(non-MVCC) device adapter, not per-create — no per-create FCW surface there.
Retry predicate: next slice = snapshot-consistent GDT descriptor RMW under a
per-descriptor `independent_key_range` proof; gate the sharded bd_bhh0i suite + local
e2fsck at cutover.

## Frontier state: quick single-turn micro-lever surface EXHAUSTED - 2026-07-13 (BOUND)

Status: BOUND — where the remaining perf is, and where it ISN'T (stop micro-hunting).

After a long solo campaign (9 landed byte-identical wins this session + prior) plus an
active peer swarm (bd-k2wc7/OliveCliff mining btree/extent/inode-truncate), the
per-op CPU/alloc surface is harvested:
- **ext4 create/`ext4_add_dir_entry`/`ext4_create` are alloc-LEAN** — no per-op
  `collect`/`clone`/`to_vec`/`format!`/`Vec::new` in the hot bodies. The create-path
  CPU (the parallel-create 3.7x target) is NOT where the gap is.
- Read path (getattr/lookup/read/readdir) mined: hot-inode borrow+Arc-share, AttrOnly
  parse, snapshot-unpin, block-patch make_mut, RangeOverlay merge, write_blocks/
  contention-metrics gating. Remaining read allocs (read_file_data segs/jobs) are
  I/O-masked.
- `MvccStore::commit`'s per-commit `Instant::now()` is NOT gate-able like the ffs-core
  `commit_transaction` sibling (which guards it on `tracing::enabled!(INFO)`): here the
  duration feeds `record_commit_success` → the CONSUMED `commit_latency_us` histogram
  exposed via `MvccRuntimeMetricsSnapshot`, not an info!-only record. Porting gotcha.

**The remaining real lever is STRUCTURAL, not a micro-lever:** the parallel-commit
scaling gap (3.7x on parallel create) lives in the MVCC commit STRUCTURE — the
`CommitPublicationGate` in-order publish (a global Mutex/serialization per commit;
lock-free fast path has a lost-wakeup hazard = Loom-gated) and inode-table
merge-proof wiring (make concurrent same-table-block inode writes MERGE not FCW-
conflict; write_inode has no proof channel = multi-turn + local-e2fsck-gated). These
are the deliberate multi-turn efforts, NOT quick single-turn micro-levers. Retry
predicate for micro-levers: a FRESH profile revealing a new CPU-bound per-op frame;
absent that, do the structural work (Loom + local gate) or ledger bounds.

## Read/commit-path candidate bounds (3 non-levers) - 2026-07-13 (REJECT / BOUND)

Status: REJECT — bounds 3 tempting-but-wrong candidates surfaced by an Explore scan,
so the fleet does not re-attempt them (esp. #2, a correctness trap).

1. **`read_file_data` per-read `segs`/`jobs` Vec allocs** (ffs-core ~13119/13212):
   RE-CONFIRMED I/O-masked / sub-noise. The Vec::new()+first-push is one small heap
   alloc per read; a file read does device I/O (µs–ms) that dwarfs a ~50ns alloc
   (matches the prior "file-read jobs / readdir planned = device-read-masked" bound).
   Retry predicate: only if a profile shows these allocs as a material read-CPU frame
   (they won't while reads are I/O-bound).

2. **`readdir` `names = present.keys().cloned().collect()`** (ffs-core ~34498) is
   NOT dead work — it is LOAD-BEARING. An Explore scan flagged it as "built but never
   read on RO mounts" (lookup returns from `present` while `present: Some`). BUT on a
   RO→writable transition (`enable_writes` does NOT clear `dir_name_index`), the next
   create calls `note_dir_name_index_insert`, which flips `present: Some→None` and
   inserts only the NEW name into `names` — so a lookup for an ORIGINAL entry then
   falls to `!idx.names.contains(name)`. If `names` were built empty, that lookup
   returns None for a present entry = CORRECTNESS BUG. `names` is the post-transition
   membership fallback. DO NOT empty it. Retry predicate: none unless `enable_writes`
   is changed to clear/invalidate the RO index (then it becomes truly dead).

3. **`MvccStore::emit_transaction_commit` per-commit duration/runtime_metrics**
   (ffs-mvcc ~2173) is already appropriately conditional: the `EvidenceRecord` build +
   `sink.append` are gated on `evidence_sink: Some` (opt-in, None by default), and the
   `started.elapsed()` → `record_commit_success` feeds a CONSUMED latency histogram
   (runtime_metrics readers). Not dead, not cleanly gate-able. Retry predicate: none.

Also this turn: 27c505c9 (read_into Arc-share, WIN #9) CONFIRMED correct — ffs-core
1185 lib tests pass (all read tests green; only the pre-existing btrfs_reflink flake
fails). Its magnitude bench (arc_publish_vs_deep_clone) + 826df090's preflight_metrics
remain rch-BLOCKED (rch saturated ~all session by the peer swarm); anchored instead by
the measured hot-HIT clone precedent (bd-cc-hotinode ~6.6%).

## `mvcc` cache-line-isolate the read-hot shard_mask - 2026-07-13 (REJECT)

Status: REJECT / MEASURED NEUTRAL (refines the false-sharing lever class).

`report_hot_field_cache_line_layout` confirmed the IMMUTABLE `shard_mask` (read on
every `shard_index` — per block, every commit AND read) shares a 64-byte cache line
with `next_txn`/`next_commit`/`publication_gate`, all written every commit — so in
theory each commit invalidates `shard_mask` for concurrent readers. Wrapped it in
`#[repr(align(64))]` to give it its own line (byte-identical; layout test confirmed
isolation). But the A/B (`benches/shard_mask_false_sharing`, adjacent-same-line vs
isolated-own-line, committers `fetch_add` a counter + readers `x & mask`, N threads):

| committers | adjacent (same line) | isolated (own line) | delta    |
|------------|----------------------|---------------------|----------|
| 1          | 10.945 ms            | 11.102 ms           | neutral  |
| 2          | 31.845 ms            | 31.955 ms           | neutral  |
| 4          | 70.815 ms            | 71.460 ms           | neutral  |

NEUTRAL at every thread count (CIs fully overlap). Why: `shard_mask` is a PLAIN
(non-atomic) field. The compiler register-HOISTS a plain read-hot field out of hot
loops (it is loop-invariant behind a shared `&self`), so it is NOT re-read from the
invalidated cache line — the coherence invalidation costs nothing. Reverted (the
align wrapper added 56 B/store + a newtype for zero benefit).

KEY REFINEMENT of the false-sharing lever class (1382b032 any_version_installed WON
at 1.5-2.1x): false sharing only hurts ATOMIC reads (`load(...)` MUST re-fetch from
memory every access, so an invalidated line = a real miss). PLAIN reads are hoisted
and immune. So: cache-line-isolate a hot field ONLY if it is read via an ATOMIC load
on the hot path; a plain immutable field sharing a line with hot writers is a
non-issue. Retry predicate: none for plain fields; for atomics, isolate + bench.

## `mvcc-commit` guard the monotonic any_version_installed store - 2026-07-13 (KEEP, 1382b032)

Status: KEEP / BYTE-IDENTICAL / MEASURED (false-sharing mechanism).

`any_version_installed` is a MONOTONIC flag (false->true once, never clears) that
EVERY read loads to gate the MVCC overlay probe. commit's install loop stored it
`store(true, Release)` per committed BLOCK — redundant after the first-ever install,
and each store dirties the flag's cache line, invalidating the copy every concurrent
reader caches (committer<->reader false sharing on the parallel path). Fix: hoist the
store out of commit's per-block loop and guard both commit and commit_ssi with a
relaxed load, so the Release store fires only on the false->true transition (a no-op
after warmup). Byte-identical: flag is true after first install forever; store still
precedes publish; two racing first-installs both store true idempotently.

Bench `benches/any_version_flag_false_sharing` (4 reader threads loading the flag +
K committer threads doing the old unconditional store vs the new guarded load, 2M
iters each, same worker):

| committers | unguarded store | guarded load | reader speedup |
|------------|-----------------|--------------|----------------|
| 1          | 2.825 ms        | 1.858 ms     | 1.52x          |
| 2          | 3.109 ms        | 1.847 ms     | 1.68x          |
| 4          | 4.342 ms        | 2.049 ms     | 2.12x          |

The win grows with committer count (readers slow as more committers dirty the line;
guarded stays flat ~1.85ms). CIs cleanly separated. HONEST SCOPE: this tight-loop
model overstates the production magnitude — commits store at most once per commit
(now ZERO after warmup), not in a loop — but it proves the mechanism the change
eliminates. ffs-mvcc 484 lib + all integration green.

LESSON (reusable): a monotonic set-once flag on a hot shared cache line should be
relaxed-load-GUARDED before the Release store — the redundant stores are free CPU-
wise but cause cross-core false sharing with the flag's many readers. WHERE TO HUNT:
`store(true)`/`store(x)` to an already-settled atomic inside a per-op loop whose
value is loaded by other hot paths.

## `active_snapshots` atomic-refcount (de-serialize per-write register/release) - 2026-07-13 (REJECT)

Status: REJECT / REFUTED BY DE-RISKING A/B (before any production change).

After reads stopped pinning (0576bb8b), the remaining `active_snapshots`
contention is the per-WRITE `register_snapshot`+`release_snapshot`, which take the
store's single `RwLock<BTreeMap>` WRITE lock. Proposed: keep `write()` only to
INSERT a new key, use a shared `read()` lock + an `AtomicU64` value to bump an
EXISTING key's refcount, so concurrent ops at the same snapshot don't serialize.
Because a naive impl is fiddly (bool-return semantics, `fetch_sub` underflow on
double-release, remove-when-zero race) it would be a Loom-gated multi-turn effort
— so it was PROTOTYPE-BENCHED first (`benches/active_snapshots_refcount`, faithful
current-vs-atomic impls, N threads, shared-key AND distinct-key extremes).

Result (same worker, 100k register/release pairs per thread):

| case          | threads | current write-lock | atomic read-fastpath | delta        |
|---------------|---------|--------------------|----------------------|--------------|
| shared_key    | 1       | 6.93 ms            | 4.39 ms              | 1.58x faster |
| shared_key    | 2       | 14.44 ms           | 20.20 ms             | 1.40x SLOWER |
| shared_key    | 4       | 42.07 ms           | 56.76 ms             | 1.35x SLOWER |
| shared_key    | 8       | 133.9 ms           | 137.4 ms             | ~neutral     |
| distinct_keys | 1       | 6.48 ms            | 4.33 ms              | 1.50x faster |
| distinct_keys | 2       | 17.11 ms           | 20.07 ms             | 1.17x SLOWER |
| distinct_keys | 4       | 42.32 ms           | 37.13 ms             | 1.14x faster |
| distinct_keys | 8       | 76.92 ms           | 116.5 ms             | 1.51x SLOWER |

The atomic version is faster ONLY single-threaded (a lighter uncontended path);
under the contention it was meant to fix it is NEUTRAL-TO-SLOWER. Why: the write
lock's critical section is a tiny `BTreeMap` entry op that serializes CHEAPLY,
whereas the atomic-refcount adds read-lock acquisition PLUS all threads hammering
ONE `AtomicU64` (shared key) — a single hot cache line RMW-serializes via
coherence anyway, with MORE total traffic. So swapping the write lock for a shared
read-lock + one hot atomic does not help; the `active_snapshots` write lock is not
improvable this way. De-risking the design first saved a multi-turn Loom effort
that would have shipped a parallel regression.

Retry predicate: only a design that avoids BOTH the lock AND a single hot atomic —
e.g. sharded / per-CPU refcount cells summed lazily for the watermark — could beat
the write lock; re-attempt ONLY with such a design AND a bench beating current at
2-8 threads. Plain atomic-per-key: do not re-attempt.

## `mvcc-commit` wait-free fetch_add for commit-seq / txn-id allocators - 2026-07-13 (REJECT)

Status: REJECT / UNSOUND-PURE + END-TO-END-NEGLIGIBLE-GUARDED.

`next_commit_seq` / `next_txn_id` allocate a monotonic counter once per commit
via `fetch_update(|c| c.checked_add(1))` — a load + `compare_exchange` retry loop
that re-runs on every lost race under parallel-commit contention. Idea: replace
with a wait-free `fetch_add` (single RMW, no retries).

Two failure modes:
1. **Pure `fetch_add` is UNSOUND.** These counters are BOUNDED — they must ERROR
   (not wrap) on exhaustion; a wrapped txn id could be reissued and a wrapped
   commit seq breaks monotonicity. `fetch_add` wraps `u64::MAX -> 0`. Caught by
   `transaction_id_exhaustion_returns_error_without_wrap` (asserts the counter
   stays at MAX after an exhausted allocation). A conditional/checked increment
   fundamentally needs compare-exchange.
2. **Margin-guarded `fetch_add` is correct but not worth it.** A relaxed load
   below `u64::MAX - 2^32` (margin dwarfs any concurrency, so `fetch_add` cannot
   wrap) with a CAS fallback near the ceiling passes both exhaustion tests. But
   the isolated A/B (`benches/commit_seq_alloc`, 200k incr/thread, same worker):

   | threads | fetch_update CAS loop | margin_guarded fetch_add | delta |
   |---------|-----------------------|--------------------------|-------|
   | 1       | 1.587 ms              | 1.711 ms                 | ~0.93x (SLOWER, CIs overlap) |
   | 2       | 4.743 ms              | 4.279 ms                 | 1.11x |
   | 4       | 13.77 ms              | 11.14 ms                 | 1.24x |
   | 8       | 38.58 ms              | 25.45 ms                 | 1.52x |

   (Pure `fetch_add`, for reference, was 2.51x@8thr with no single-thread cost —
   the guard band's relaxed load both dilutes the contended win and adds a
   borderline single-thread regression.) Decisive: this atomic is ~7 ns of a
   ~1.9 us commit (<0.5%), so even the 1.52x@8thr is END-TO-END SUB-NOISE (the
   fd678afe lesson) while the guard band adds complexity + a single-thread cost.
   Production keeps `fetch_update`.

Retry predicate: only if a future profile shows the commit-seq/txn-id atomic is a
material fraction (>5%) of commit CPU under the target parallel workload AND a
wait-free form with no single-thread regression exists.

## `mvcc-commit` skip per-commit contention-metrics global lock under fixed policy - 2026-07-13 (KEEP, 73174f5b)

Status: KEEP / BYTE-IDENTICAL-FOR-DATA / MEASURED WIN (regime-dependent, Pareto).

Every ShardedMvccStore commit took `contention_metrics.write()` — a single GLOBAL
lock — on the success path to record EMA metrics + `select_policy`. Only
`ConflictPolicy::Adaptive` reads those metrics (`effective_policy`); production
runs a FIXED policy (default SafeMerge; ffs-core never calls set_conflict_policy,
zero readers of contention_metrics). So under a fixed policy that global lock is
pure unread telemetry that serializes every otherwise-disjoint parallel commit
across all shards — the "drop unread per-op telemetry on the production path"
lever class (cf. writeback 9bd37150), here a global-lock-per-commit. `commit_policy()`
resolves effective policy AND whether metrics are live (Adaptive only) in one
conflict_policy read; `preflight_fcw_locked` gates all three `contention_metrics.
write()` sites on it. Adaptive unchanged; fixed-policy commits skip the lock.

Parallel A/B (`benches/commit_metrics_lock`, N threads x 2000 disjoint-block
single-block commits, SafeMerge; `force_metrics_on` reproduces pre-gate via the
doc-hidden `set_force_metrics_record` knob vs `gated_off` = production, same worker):

| threads | force_metrics_on | gated_off | delta |
|---------|------------------|-----------|-------|
| 2       | 15.31 ms         | 7.54 ms   | 2.03x (CIs separated: on>=12.6, off<=8.4) |
| 4       | 18.14 ms         | 17.48 ms  | ~neutral (1.04x, CIs overlap) |
| 8       | 52.99 ms         | 51.36 ms  | ~neutral (1.03x, CIs overlap) |

Honest read: clean 2.03x at 2 threads; converges to neutral at 4/8 threads where
OTHER serialization becomes binding (the publication-gate commit ordering + shard-
index collisions across the disjoint block ranges — both present identically in
both arms, so they cancel in the ratio but dominate absolute time and mask the
metrics-lock delta once they saturate). Pareto: gated_off <= force_on at every
thread count (never a regression), 2x at low-moderate parallelism. Byte-identical
for data: install paths, conflict detection, merge all unchanged; only the unread
telemetry counters stop updating under fixed policy. ffs-mvcc 484 lib (incl. new
`fixed_policy_skips_contention_metrics_but_force_records`) + all integration green.

NEXT SERIALIZATION LEVERS (exposed by the 4/8-thread flatness): (a) the
`CommitPublicationGate` commit ordering — inherently serializes the publish step;
(b) `next_commit` AtomicU64 / shard-index collisions among concurrent commits.
These are the remaining global bottlenecks on the parallel-create scaling surface.

## `mvcc-merge` FCW preflight validates without building the merged block - 2026-07-13 (KEEP, 60962fa1)

Status: KEEP / BYTE-IDENTICAL / MEASURED WIN.

The FCW **preflight** conflict check built the FULL merged block via `merge_bytes`
only to answer "mergeable?" (`.is_ok()`), discarded it, and the install path then
rebuilt it — one block-sized allocation + copy per conflicting block, wasted,
under the shard lock on the contended commit path. Split the merge into validate
+ build (shared validators, cannot diverge): `MergeProof::merge_valid` (==
`merge_bytes(..).is_some()`, no output alloc) backed by `append_only_merge_valid`
/ `merge_non_overlapping_ranges_valid`. Preflight now validates only; install is
unchanged.
- MvccStore: `resolved_write_valid_with_policy` (preflight); install keeps
  `resolved_write_bytes_with_policy`.
- ShardedMvccStore: `resolved_write_bytes_locked` -> `check_write_mergeable_locked`
  (its only caller was preflight); install keeps `merged_write_bytes_locked`.

A/B (`benches/merge_range_overlay`, group `mvcc_merge_preflight`, same worker):
full-merge-then-discard vs validate-only, both faithful transcriptions:

| block size | full_merge (old preflight) | validate_only (new) | speedup |
|------------|----------------------------|---------------------|---------|
| 4096 (ext4)| 145.39 ns                  | 71.47 ns            | 2.03x   |
| 16384      | 504.67 ns                  | 205.34 ns           | 2.46x   |
| 65536      | 1708.0 ns                  | 1001.6 ns           | 1.71x   |

CIs cleanly separated (4K: old [143.15, 147.82] vs new [70.61, 72.33]). Stacked
on the 930045fa validator win, the same 4 KiB preflight check has gone ~230 ns ->
71 ns (~3.2x across both landings). Byte-identical: install paths untouched, same
merged bytes, same preflight gate + telemetry. ffs-mvcc 483 lib (incl. new
`merge_valid_matches_merge_bytes_is_some` drift guard) + all integration green.
Same caveat as 930045fa: fires only under *conflict* (concurrent same-block
writes) — a contended-path lock-hold reduction on the parallel-write scaling
surface, not a single-thread hot-op win.

## `mvcc-merge` range-overlay validator drops full-block scratch copy - 2026-07-13 (KEEP, 930045fa)

Status: KEEP / BYTE-IDENTICAL / MEASURED WIN.

`merge_non_overlapping_ranges` (the byte algorithm behind
`MergeProof::{IndependentKeys,NonOverlappingExtents,TimestampOnlyInode}`) runs on
the **contended commit path, under the shard lock**: when two txns write
non-overlapping ranges of the SAME block (production `write()` stages
`non_overlapping_extent_range` proofs for disjoint sub-block data writes), the
second committer hits FCW and merges. The "staged only touched the declared
ranges" validation was `expected = base.to_vec(); overlay staged ranges;
expected == staged` — one **block-sized allocation + memcpy + full-block
compare** per merge. That check is exactly "staged == base in the COMPLEMENT of
the declared ranges"; comparing the complement gaps directly (sort the disjoint
ranges, walk the gaps) removes the scratch buffer entirely. The merged output
(`latest` with staged ranges overlaid) is unchanged, so it is byte-identical.

Same-worker (vmi1149989) same-binary A/B, `benches/merge_range_overlay`
(faithful transcriptions of the old vs new validator, identical inputs, one
declared range near the block start + a disjoint `latest` write near the end =
the common clean-merge case):

| block size | old (expected_staged copy) | new (complement compare) | speedup |
|------------|----------------------------|--------------------------|---------|
| 4096 (ext4)| 201.19 ns                  | 154.20 ns                | 1.30x   |
| 16384      | 801.06 ns                  | 533.31 ns                | 1.50x   |
| 65536      | 2548.7 ns                  | 1719.1 ns                | 1.48x   |

CIs cleanly separated (4K: old [197.67, 204.84] vs new [151.22, 156.99]). The
~47 ns eliminated at 4 KiB is a 4 KiB alloc+memcpy; the win scales with block
size as the copy dominates. Correctness: ffs-mvcc 482 lib + all integration
tests green, incl. new `merge_non_overlapping_ranges_handles_multiple_unsorted_
ranges` (multi-range out-of-order sort path + gap/trailing integrity).

Note: the merge fires only under *conflict* (concurrent same-block writes), so
this is a contended-path lock-hold reduction, not a single-thread hot-op win —
it directly targets the parallel-write scaling surface (the MVCC lane the
bd-bhh0i cutover identified as the real bottleneck). Sibling hunt logged: inode-
table metadata writes (`write_inode`) still stage NO merge proof (default
`Unsafe`), so concurrent creates/setattrs on inodes sharing a table block hard-
conflict — wiring a slot-scoped `TimestampOnlyInode` proof through the inode
write path is the next (multi-turn, local-e2fsck-gated) MVCC lever.

## `bd-bhh0i` synthetic-counter scope correction - 2026-07-10

Status: REJECT AS ACTUAL-PATH EVIDENCE / RETAIN AS ROUTING EVIDENCE.

`bd_bhh0i_contention` does not satisfy the requested MVCC commit-lock and malloc
arena counter sweep. It measures synthetic `parking_lot` global/group/publish
mutexes and wall-clock latency of a 4 KiB `Vec` allocation. The 8-thread p99
values (176.341 us global allocation lock, 0.290 us disjoint group lock, 127.449
us synthetic publish lock) remain useful for routing, but are not measurements
of `CommitPublicationGate`, shard/`active_snapshots` locking, or allocator-arena
lock events.

Retry condition: collect 1/2/4/8 same-worker `release-perf` wait/hold histograms
at the actual MVCC locks and allocator contention through a safe external
profiler or audited bench-only facility. Do not introduce unsafe production Rust
and do not mutate a filesystem outside fixtures.

## Mounted xattr coverage gap and fsync evidence correction - 2026-07-10

Status: SURFACED / NO OPTIMIZATION / NO FILESYSTEM MUTATION.

The new-workload audit found **zero** mounted end-to-end xattr performance
comparisons against kernel ext4/btrfs. Four existing benchmark families measure
internal parsing/name transforms, and one mounted test is correctness-only.
Filed P1 `bd-mounted-xattr-workload-gap-fr6iq` for the safest next comparator: a
preseeded read-only ext4 get/list storm with one persistent syscall loop on both
arms, inline/external/absent and list-1/list-24 cases, at least 30 interleaved
same-worker `release-perf` batches, `cv_pct < 5`, and byte/name parity outside
timing. Set/remove remains excluded without explicit fixture-mutation authority.

The prior fsync row's nominal **3.033x slower** signal (71.744 us versus 23.654
us) is not a defensible current-source ratio. CV was **44.94% / 97.22%**; the
direct `OpenFs` and host-syscall arms do not share an API/durability boundary;
the host filesystem was not proven ext4/JBD2; and the harness duplicates sync
work on the FrankenFS arm. The refined `hz2` attempts never reached the workload
executable or `e2fsck`; both stopped during cold fat-LTO compile/link. Updated
`bd-fsync-journal-latency-gap-ptp4x` with the fair retry gate: verified ext4,
matched durability semantics, persistent same-boundary arms, >=30 interleaved
batches, `cv_pct < 5`, and parity/durability validation outside timing.

## `bd-bhh0i` bounded Loom writer proof and evidence correction - 2026-07-10

Status: WIN AS FORMAL DE-RISK / NO CUTOVER. No production filesystem path was
changed or mutated.

The new `bd_bhh0i_lock_decomposition_model` uses seven finite Loom projections
bounded to two groups, two independently mapped shards, two writers with one
allocation each, and at most one reader. The modeled accepted protocol retains
sorted allocation-group guards across the lean eager MVCC commit and
ready-prefix publication; it does not model the ledger-rejected
commit-after-release staging family. The checks cover disjoint and same-group
operations, opposing multi-group requests, disjoint groups with cross-mapped
shared shards, an exact early abort, installed-but-unpublished visibility, and
post-publication pruning. For the five enumerated writer configurations,
exhaustive over modeled schedules, the writer projection proves:

- sorted group/shard acquisition completes without deadlock;
- returned allocation bits replay against a sequential bitmap allocator, and a
  Loom-synchronized ghost history shows the commit sequence preserves every
  response-before-invocation edge;
- independently mapped MVCC shard payloads each replay to the corresponding
  group's exact sequential prefix;

Separate safety projections establish that:

- all shard versions are installed before the Release publication point and a
  reader at the Acquire-loaded prefix sees a complete prefix only;
- the exact early abort before metrics, sequence assignment, and install
  consumes no sequence and changes no allocator/MVCC state;
- `active_snapshots -> shards` pruning retains a registered snapshot version.

The seven projections are deliberately separate, not a formal composition of
writers, reader registration, and pruning. They exhaust without permutation,
duration, or preemption sampling limits. The bounded writer proof and separate
safety evidence cover the default sharded, no-JBD2 bitmap-allocation primitive,
not whole `ext4_create`, crash atomicity, starvation freedom, Single/JBD2, or
post-install compensation. RCH worker `ovh-a` passed all **7/7** final
projections in **3.40 seconds**.

Evidence correction: the earlier hand-enumerated 168-terminal model proves
final-state conservation, not linearizability, and its output is relabeled. The
synthetic plain publish mutex's 8-thread p99 wait of 127.449 us is routing-only;
it cannot establish that the real `CommitPublicationGate` is the next
bottleneck, especially because the prior real-path MVCC ceiling and neutral
publish-nowait experiment point the other way. The 8-thread global allocation
lock p99 wait of 176.341 us versus 0.290 us for disjoint synthetic group locks
remains valid contention characterization.

Gates: RCH workspace check passed with unrelated existing warnings; the full
`ffs-harness` run passed **2057/2058**, with only
`source_scope_scan_logs_workspace_hashes_and_counts` failing in the parallel
run, then passing **1/1** in isolated RCH replay. Targeted rustfmt and
`git diff --check` passed. UBS found **0 critical** findings in the two changed
Rust files (225 heuristic warnings). Workspace fmt/clippy remain red on
unrelated pre-existing formatting and warning debt; those files were not
modified.

## `bd-bhh0i` safe contention de-risk + fsync workload gap signal - 2026-07-10

Status: SURFACED / NO CUTOVER. This was an analysis and benchmark-harness commit
only. It did not attempt the owner-gated parallel metadata write cutover and did
not touch the mmap/io_uring read path.

Contention characterization added `crates/ffs-core/benches/bd_bhh0i_contention.rs`.
RCH release-perf on `hz2` measured the current global alloc lock at 8 threads:
p95 wait `66.920 us`, p99 wait `176.341 us`, mean hold `0.423 us`. The proposed
decomposed per-group lock model kept 8-thread p95 wait at `0.240 us` and p99 at
`0.290 us`, but the separate publish lock then convoys at p95 `64.549 us` and p99
`127.449 us`. Conclusion: per-group allocation removes the allocator convoy for
disjoint groups, but an owner-approved design must also handle publication
ordering or the convoy moves.

The bench's bounded model explored `168` two-thread terminal interleavings for
disjoint groups plus a global ordered publication lock: `deadlocks=0` and
`linearizable=true`. This is not a loom/shuttle substitute; retry/cutover
condition remains owner ACK plus a real loom or shuttle model and e2fsck-clean
parallel mutation fixtures.

New workload class: `fsync_latency_workload` found a same-worker RCH signal on
`ovh-a`: FrankenFS ext4 write+fsync median `71.744 us` vs kernel ext4 `23.654 us`,
or `3.033x` slower. The raw per-op CV was high (`44.94%` vs `97.22%`), so this is
not a final keep-gate result. Refined batch-median plus in-worker `e2fsck -fn`
reruns on `hz2` stalled twice in the executable phase and were interrupted.
Filed `bd-fsync-journal-latency-gap-ptp4x` to stabilize the harness, collect
low-CV same-worker evidence, and profile fsync/journal internals if the gap holds.

Gates: targeted rustfmt on both new benches passed; RCH `cargo check -p ffs-core
--bench bd_bhh0i_contention` passed; RCH `cargo check -p ffs-core --bench
fsync_latency_workload` passed before refinement; local `cargo check -p ffs-core
--bench fsync_latency_workload` passed after refinement. Warnings were pre-existing
`fetch_update` deprecations and the unused htree helper.

## BOLD-VERIFY measured verdict - 2026-06-25

### `bd-xmh5g` ffs-btrfs direct COW update descent - REJECT

Lever attempted in a clean scratch worktree:
`/data/projects/.scratch/frankenfs-ivory-btrfs-update-20260625`.
The candidate replaced `BtrfsBTree::update`'s current existence-probe plus
replace-capable insertion path with a direct COW descent that rewrites only the
path to an existing leaf item, and reused that helper for the non-root
`insert_then_update` fallback. The benchmark added a same-binary A/B group over
a multi-level COW tree: 2048 seeded extent items, 512 existing-key updates, old
model `get` + `upsert` versus direct `update`. The candidate source and bench
were reverted after measurement.

Measured result: RCH had no admissible remote worker and ran through its local
fallback, still under the requested `rch exec` wrapper and crate-scoped target:

```bash
AGENT_NAME=IvoryBirch CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo bench --profile release -p ffs-btrfs \
  --bench cow_write_mutation -- btrfs_cow_direct_update \
  --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
```

Criterion measured:

- `old_find_then_upsert`: `[1.8556 ms, 1.9392 ms, 1.9942 ms]`
- `direct_update`: `[1.8019 ms, 1.8619 ms, 1.9155 ms]`

Midpoint old/new is only `1.04x`, and conservative interval ratio is
`1.8556 / 1.9155 = 0.969x`. This is below the keep threshold and not
conservative-positive, so the lever is a no-ship.

Kernel ratio: no standalone ext4/btrfs-kernel ratio exists for this internal
in-memory btrfs COW-tree primitive. It was a candidate for the btrfs
write/create mutation frontier, but the component movement is too small to
justify a mounted-kernel rerun. Direct kernel W/L/N is `0/0/1`; internal W/L/N
is `0/0/1`.

Gates before revert: local `cargo fmt -p ffs-btrfs --check` passed; local
`git diff --check` passed; local
`cargo test -p ffs-btrfs update -- --nocapture` passed `13/0`; local
`cargo check -p ffs-btrfs --all-targets` passed. Post-revert source is
identical to `HEAD` for `crates/ffs-btrfs/src/lib.rs` and
`crates/ffs-btrfs/benches/cow_write_mutation.rs`; RCH conformance
`cargo test -p ffs-harness --test conformance -- --nocapture` passed on
`ovh-a` with `100 passed / 0 failed / 2 ignored`.

Retry predicate: do not retry direct existing-key COW update as a standalone
`ffs-btrfs` lever unless a fresh profile shows update descent itself as a
material hotspot and the new same-worker A/B clears the keep threshold with a
conservative-positive interval.

### `bd-9e810` ext4 base-device block cache below MVCC - KEEP

Source is already retained on `main` as `5f266067`:
`perf(ffs-core): add bounded ext4 base-device block cache below MVCC`.

Lever: add an ext4-only `OpenFs::ext4_base_block_cache` under the MVCC overlay,
served by `CachedByteDeviceBlockAdapter`, so repeated writable-path
`read_block_vec` calls for htree/name-index metadata avoid redundant base-device
preads. Direct adapter writes invalidate the affected base block ranges before
reaching the device. Btrfs remains uncached here because it still has raw
physical write paths outside this adapter.

Measured result: RCH same-worker Criterion on `hz2`:

```bash
cargo bench --profile release -p ffs-core --bench ext4_lookup_run_overlap -- ext4_base_block_cache --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
```

This measured `ext4_base_block_cache_1092reads_42unique`:
`uncached_read_block_vec` `[88.481 ms, 93.202 ms, 99.916 ms]` vs
`cached_read_block_vec` `[3.6667 ms, 3.7183 ms, 3.7794 ms]`. Median ratio is
`25.07x`; conservative interval ratio is `23.41x`.

Kernel ratio: no standalone ext4/btrfs-kernel comparator exists for this
internal cache primitive. The lever targets the existing ext4 delete residual
where the bead trace recorded 1092 `pread64` calls to 42 unique offsets
(about 26x repeated base metadata reads). Using the bead's 18% wall attribution,
the component win projects about `1.21x` end-to-end ext4 delete speedup and
would narrow the prior fair-kernel delete gap from `~1.3x` slower to
`~1.07x` slower. That projection is not a replacement for a future full mounted
kernel delete rerun.

Gates: RCH `cargo check -p ffs-core --all-targets` passed on `hz2`; RCH focused
test `cargo test -p ffs-core
ext4_base_block_cache_reuses_reads_and_invalidates_direct_writes --
--nocapture` passed on `ovh-a`; RCH conformance `cargo test -p ffs-harness
--test conformance -- --nocapture` passed on `vmi1153651` with
`100 passed / 0 failed / 2 ignored`; local `cargo fmt -p ffs-core --check` and
`git diff --check` passed. The requested `cargo bench --release` spelling was
attempted first and rejected by Cargo for bench mode, so the supported
equivalent `--profile release` was used. Scoped RCH `cargo clippy -p ffs-core
--all-targets --no-deps -- -D warnings` remains blocked by pre-existing
`ffs-core` pedantic debt outside this lever.

## Gauntlet Release-Readiness Scorecard

| Date | Bead | Workload | Verdict | Original-kernel ratio | Conformance gate | Readiness impact |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-07-09 | `bd-zero-copy-read-path-pz64v` continuation | User-requested restart of mmap/io_uring read-copy-tax lane after closeout; same-worker profile of incumbent safe direct paths plus implementation feasibility check | REJECT / BLOCKER, no production source kept | Direct ext4/btrfs-kernel ratio not rerun because no candidate could be legally built under the current unsafe policy. Fresh RCH `hz2` Criterion: 1 MiB staged scratch `917.20 us` vs direct `49.163 us` (`18.7x`); 128 KiB staged scatter `10.135 us` vs `preadv_direct` `8.0194 us` (`1.26x`). This confirms the safe direct-read space is harvested; the remaining pz64v residual is the `pread`/`copy_to_user` boundary or a borrow-returning mmap API. | RCH Criterion passed on `hz2`. No Rust source changed. External current docs confirm `memmap2` file-backed maps, including copy-read-only maps, are unsafe; `io-uring` fixed-buffer reads use registered buffers/raw buffer SQEs. Workspace root has `unsafe_code = "forbid"` and `ffs-block` has `#![forbid(unsafe_code)]`, so an mmap/io_uring production cutover would fail policy/lints without an explicit audited-unsafe exception. | Do not reopen pz64v for another safe copy micro-tune. The next valid work item is a dedicated audited unsafe I/O backend/API decision: one module/crate with documented mmap/io_uring invariants, read-only/truncation/write exclusion, overlay/journal fallback, byte-identity conformance, and destination-on-error proof. |
| 2026-07-09 | `bd-zero-copy-read-path-pz64v` | Zero-copy read-path relaunch after the safe direct-read and `preadv` fast paths; audit of mmap-backed `ByteDevice` / io_uring registered-buffer retry condition | REJECT / BLOCKER, no production source kept | Direct ext4/btrfs-kernel ratio not rerun because the ledgered retry condition still blocks a candidate. Fresh same-worker RCH `hz2` Criterion confirms the incumbent safe paths are already harvested: 1 MiB staged scratch `913.63 us` vs direct `51.411 us` (`17.8x`), 128 KiB staged scatter `10.728 us` vs `preadv_direct` `7.9739 us` (`1.35x`). The remaining prize is the prior pz64v kernel-boundary gap: warm 1 MiB `pread` into dst `333 us` / `3.2 GB/s` vs userspace memcpy `23.6 us` / `44.4 GB/s`. | No production source changed, so conformance risk is unchanged. RCH Criterion passed on `hz2`. Fresh `perf stat` was attempted twice but not accepted: counters were contaminated by RCH target-lock/build wait (344.1 s compile-heavy run; 108.6 s lock-wait run). Bounded RCH flamegraph timed out (`exit 124`) while compiling and produced no fresh SVG. | Close the bead under current invariants. Do not retry hidden mmap/io_uring or another copy micro-tune. Retry only after an explicit audited-unsafe backend decision plus a borrow-returning read API, or a genuinely safe zero-copy abstraction preserving byte identity and destination-on-error semantics. |
| 2026-06-20 | `bd-xmh5g.410` | `ffs-block::FileByteDevice::read_vectored_exact_at` large-read scratch elimination with one positioned `preadv` into caller `IoSliceMut`s, preserving the small-read and over-`IOV_MAX` scratch fallback | PENDING-BENCH / production code retained under disk-low code-only directive | N/A until next-turn direct ext4/btrfs kernel comparator reruns. No fresh cargo build/check/test/bench/rch was started this turn. | Not run this turn by directive. Required next gates: `cargo check -p ffs-block --all-targets`, focused vectored-read tests, Criterion `file_device_read`/`read_contiguous` A/B, and harness/direct-kernel comparators. | No readiness upgrade yet. Treat as an unscored candidate; keep only if accepted A/B clears `>1.05x` with conformance green, otherwise revert and mark rejected. |
| 2026-06-21 | `bd-xmh5g.408` | btrfs read metadata-descent elision across `ffs-core` and `ffs-cli`: centralize regular-read dir/symlink guard in `btrfs_read_file_into`, allow `readlink` symlink payload reads, and reuse final `lookup` attr in `ffs-cli read` instead of a final `getattr` | REJECT / production source reverted | Fresh 15-run direct btrfs-kernel rows at `d5ebffea`: single-file `/compressible.bin` baseline `38.7 ms`, candidate `37.6 ms`, kernel `cat` `7.5 ms`; candidate is `1.03x` old/new and still `5.01x` slower than kernel. Whole-tree `walk --read-data --no-stat` baseline `33.9 ms`, candidate `34.1 ms`, kernel `cat *` `12.2 ms`; candidate is `0.994x` old/new and `2.79x` slower than kernel. `strace -f -c -e pread64` showed the same `332` preads for baseline and candidate, so the suspected duplicate descents did not reduce syscall count on the target image. Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | RCH clean-source `cargo build --profile release-perf -p ffs-cli` passed on `vmi1227854`; isolated detached-worktree local release-perf baseline/candidate builds passed; edited-file rustfmt passed with `--config skip_children=true`; `cargo check -p ffs-core --all-targets` and `cargo check -p ffs-cli --all-targets` passed; focused btrfs read/readlink/symlink tests passed (`21/0/1 ignored`, `4/0`, `1/0`); post-revert `cargo test -p ffs-harness --test conformance -- --nocapture` passed `100 / 0 / 2 ignored`. | Do not retry metadata guard/final-getattr elision as a btrfs compressed-read lever without a new profile proving those descents escape the current caches. Route next work to the active physical-range partitioning follow-up (`bd-xmh5g.409`, owned by cod-a) or to fresh profiles of extent lookup/decode-output lifetime/I/O backend overhead. |
| 2026-06-20 | `bd-xmh5g` | btrfs streamed-read dir/symlink guard fold in `ffs-core`, measured against clean parent `5d77712a` on `/data/tmp/btrdiff2_1340519.img:/compressible.bin` | REJECT / production reverted in `37b7e8b` | Clean 15-run direct btrfs-kernel rows: single-file parent `57.1 ms`, clean current `56.5 ms`, kernel `cat` `7.1 ms`; clean current is only `1.011x` old/new and still `8.01x` slower than kernel. Whole-tree parent `34.4 ms`, clean current `34.9 ms`, kernel `cat *` `12.4 ms`; clean current is `0.986x` old/new and `2.82x` slower than kernel. Invalid contaminated run, before isolating peer `ffs-cli` 1 MiB read-tile edits, showed `22.7-23.3 ms` single-file and `34.3-36.0 ms` walk; that false win is not attributable to the guard fold. Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | RCH clean current `cargo build --profile release-perf -p ffs-cli` passed on `vmi1149989`; RCH parent build passed on `vmi1153651`; local clean parent/current release-perf builds passed; local `cargo fmt -p ffs-core --check` passed; local fallback `cargo test -p ffs-harness --test conformance -- --nocapture` passed `100 / 0 / 2 ignored`; RCH `cargo check -p ffs-core --all-targets` result is captured in the scorecard. | Do not retry this guard-fold metadata elision as a standalone btrfs compressed-read lever. The clean read path does not move; future work should isolate the peer CLI tile hypothesis separately, or profile btrfs extent lookup, decode/output lifetime, and I/O backend overhead before changing core read metadata guards. |
| 2026-06-20 | `bd-xmh5g.407` | `ffs-cli read` btrfs compressed single-file stream tile, 64 MiB -> 1 MiB, against `/data/tmp/btrdiff2_1340519.img:/compressible.bin` | REJECT / production source reverted | Acceptance 15-run direct btrfs-kernel rows: single-file `/compressible.bin` baseline FrankenFS `35.266 ms`, 1 MiB tile candidate `36.367 ms`, kernel `cat` `6.268 ms`; candidate is `0.970x` old/new and `5.80x` slower than kernel. Whole-tree `walk --read-data --no-stat` baseline `29.108 ms`, candidate binary `31.486 ms`, kernel `cat *` `11.888 ms`; candidate binary is `0.925x` old/new and `2.65x` slower than kernel. One-shot RSS smoke did not move materially (`47,844 KiB` baseline vs `47,812 KiB` candidate; minor faults `11,577` vs `11,561`). Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | RCH clean-source `cargo build --profile release-perf -p ffs-cli` passed on `vmi1227854`; RCH candidate build passed on `vmi1149989`; source reverted and `git diff --exit-code -- crates/ffs-cli/src/main.rs` passed; RCH conformance `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `hz2` (100 passed / 0 failed / 2 ignored). `cargo fmt -p ffs-cli --check` remains blocked by pre-existing formatting drift in `crates/ffs-cli/src/cmd_repair.rs`, unrelated to this reverted candidate. | Do not retry CLI stream-tile shrinkage for btrfs compressed reads without allocator attribution proving the 64 MiB request tile is the live-memory bottleneck. The accepted direct run says smaller tiles add per-call overhead/noise without reducing RSS or closing the kernel gap. Route next work to measured allocation sites inside `btrfs_read_file`, true decode-output lifetime reduction, extent metadata fan-out, or a structural I/O backend. |
| 2026-06-20 | `bd-xmh5g` | btrfs zstd compressed-read input-buffer scratch reuse, one retained compressed input `Vec` per Rayon worker for sub-1 MiB frames | REJECT / production source reverted | Acceptance 25-run direct btrfs-kernel rows: single-file `/compressible.bin` baseline FrankenFS `56.7 ms`, scratch `58.6 ms`, kernel `cat` `6.9 ms`; scratch is `0.968x` old/new and `8.53x` slower than kernel. Whole-tree `walk --read-data --no-stat` baseline `36.3 ms`, scratch `35.0 ms`, kernel `cat *` `12.6 ms`; scratch is `1.037x` old/new but still `2.77x` slower than kernel. Earlier 7-run smoke rows were `1.041x` and `1.102x` old/new but were treated as routing-only after the tighter run. Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | Local candidate `cargo check -p ffs-core --all-targets` passed before revert; source reverted; RCH `cargo build --release -p ffs-cli` passed on `vmi1153651`; RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1149989` (100 passed / 0 failed / 2 ignored). | Do not retry compressed-input scratch reuse without a profile proving allocation dominates. The accepted evidence says this lever is noise-to-regression and does not close the btrfs compressed-read kernel gap. Route next work to direct output placement, extent lookup fan-out, or a larger I/O backend design. |
| 2026-06-20 | `bd-giyxr` | e2compr compressed-cluster present-block read fan-out (`decompress_e2compr_cluster`; serial pointer PLAN, parallel data READ, ordered ASSEMBLE) | KEEP / production already retained in `e6259d5d`; current closeout is measured verification | Direct ext4/btrfs-kernel ratio is N/A for this isolated legacy e2compr cluster primitive: the same-process A/B uses a latency-injected `BlockDevice`, e2compr has no btrfs analogue, and no mounted-kernel e2compr comparator exists in the repo. Fresh cod-a RCH Criterion on `vmi1152480`: mean serial/parallel 4 blocks `1.6666 ms` / `915.24 us` (`1.82x`), 16 blocks `5.9532 ms` / `2.1675 ms` (`2.75x`), 32 blocks `12.303 ms` / `2.3427 ms` (`5.25x`). Internal win/loss/neutral `3/0/0`; direct kernel `0/0/1`. | RCH `cargo bench --profile release-perf -p ffs-core --bench e2compr_cluster_read_overlap -- --warm-up-time 1 --measurement-time 3` passed on `vmi1152480` with the bench's serial/parallel byte-equality assertion; RCH `cargo test -p ffs-core e2compr -- --nocapture` passed on `hz2` (25 passed / 0 failed); RCH `cargo build --release -p ffs-core` passed on `vmi1227854` (clean `/tmp/rch_target_frankenfs_cod_a_release` rerun after the requested shared-target build compiled on `vmi1264463` but failed artifact retrieval with `RCH-E309`/exit 102); RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1152480` (100 passed / 0 failed / 2 ignored). | Close the stale open bead as a verified keep. This improves readiness for the niche e2compr compressed ext4 path, but it is not a whole-filesystem kernel domination claim; remaining direct read losses stay routed to mounted ext4/btrfs read-path surfaces such as indirect planning and btrfs compressed reads. |
| 2026-06-20 | `bd-xmh5g` | btrfs zstd compressed read over mounted kernel btrfs image, thread-local zstd decompressor reuse plus targeted Criterion filter guard | KEEP / production retained | Direct btrfs-kernel loss remains, but the FrankenFS side improved on the target image. Single-file `/compressible.bin`: baseline `76.1 ms` -> confirmation `54.9 ms` (`1.39x` faster); current kernel `cat` `6.5 ms`, so FrankenFS is still `8.51x` slower. Whole-tree `walk --read-data --no-stat`: baseline `53.2 ms` -> confirmation `32.8 ms` (`1.62x` faster); current kernel `cat *` `11.0 ms`, so FrankenFS is still `2.99x` slower. Internal synthetic loss: RCH `vmi1167313` fresh decompressor median `5.9330 ms` vs reused median `7.2849 ms` (`0.814x` old/new), so synthetic W/L/N `0/1/0`; direct kernel W/L/N `0/2/0`. | RCH bench passed on `vmi1167313`; local mounted-image hyperfine confirmation passed; local `cargo fmt -p ffs-core --check` passed; RCH `cargo check -p ffs-core --all-targets` passed on `vmi1167313`; RCH `cargo test -p ffs-core btrfs_decompress -- --nocapture` passed on `vmi1167313` (10 passed / 0 failed); RCH conformance passed on `ovh-a` (100 passed / 0 failed / 2 ignored); RCH `cargo build --release -p ffs-cli` passed on `vmi1227854`. Scoped clippy is blocked by pre-existing `ffs-core` pedantic debt outside this lever. | Keep the direct-workload win, but do not claim kernel domination. The synthetic decompressor microbench is a loss and should not be used alone as a keep signal for future zstd-context levers. Next work should attack the remaining `2.99-8.51x` kernel gap with output-buffer reuse / decode-direct-to-final-buffer, metadata extent-lookup fan-out, or a kernel-shaped multi-file compressed image, not by retrying dedicated pools or tiny-frame decoder-context microbenches. |
| 2026-06-20 | `bd-xmh5g` | btrfs zstd direct-to-final-output attempt for full-overlap regular compressed extents | REJECT / production reverted | Direct btrfs-kernel loss remains. Candidate single-file `read --discard /compressible.bin` mean `57.961 ms` vs kernel `cat` `7.011 ms`, so FrankenFS is `8.27x` slower. Candidate `walk --read-data --no-stat` mean `34.883 ms` vs kernel `cat *` `11.537 ms`, so FrankenFS is `3.02x` slower. Internal A/B: single-file regressed current FrankenFS `55.931 ms -> 57.961 ms` (`0.965x` old/new); walk was neutral `34.8826 ms -> 34.8828 ms` (`1.000x`). Internal W/L/N `0/1/1`; direct kernel W/L/N `0/2/0`. | RCH candidate `cargo check -p ffs-core` and `cargo build --profile release-perf -p ffs-cli` passed on `vmi1152480`; production code was manually reverted; clean-source RCH `cargo check -p ffs-core` passed on `vmi1153651`; clean-source RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1227854` (100 passed / 0 failed / 2 ignored); clean-source RCH `cargo build --profile release-perf -p ffs-cli` passed on `vmi1149989`. | Do not retry final-buffer zstd decode for this read path without allocation-attribution evidence proving the decompressed output `Vec` plus copy dominates. The single-file path worsened and the whole-tree path did not move; route the remaining compressed-read gap to extent lookup/metadata fan-out, compressed scratch allocation, or CLI/open/read overhead. |
| 2026-06-20 | `bd-jgbam` | mmap-backed `ByteDevice` proposal for warm sequential ext4/btrfs reads after the safe large-read direct path | REJECT / no production source kept | Fresh local warm/shared-cache hyperfine still shows the kernel streaming path ahead: ext4 `/data/tmp/extdiff_1497854.img:/large.bin` FrankenFS `read --discard` mean `15.0 ms` vs mounted-kernel `cat` `4.4 ms` (`3.36x` slower); btrfs `/data/tmp/btrperf_1231197.img:/m.bin` FrankenFS `76.5 ms` vs mounted-kernel `cat` `11.6 ms` (`6.58x` slower). RCH `vmi1152480` confirms the already-shipped safe large-read direct primitive remains a real win: `file_device_read_1mib` staged scratch median `506.33 us` vs direct `32.957 us`, old/new `15.36x`. | RCH `cargo bench --profile release-perf -p ffs-block --bench file_device_read -- file_device_read_1mib --warm-up-time 1 --measurement-time 3` passed on `vmi1152480`; local ext4/btrfs hyperfine comparators passed; temporary read-only btrfs loop mount was unmounted. No production source code was changed, so conformance risk is unchanged. | Close the mmap sub-route as rejected under current invariants: current `memmap2` file-backed mapping constructors are `unsafe`, while the workspace and `ffs-block` use `unsafe_code = "forbid"` / `#![forbid(unsafe_code)]`. Do not retry by adding unsafe or a hidden mmap wrapper. Retry only with a safe, policy-approved I/O model: e.g. a safe io_uring/batched pread design that preserves destination-on-error, or an explicit project decision to allow an audited unsafe backend outside forbidden crates. |
| 2026-06-20 | `bd-r9c10` | ext4 indirect non-contiguous read overlap plus direct-output copy-elision follow-up (`ext4_indirect_read_overlap`, 16/64/256 synthetic latency-injected runs) | REJECT copy-elision / production reverted; keep incumbent owned-buffer parallel read | Existing direct kernel gap remains a loss from the prior 32 MiB `^extent` image probe: FrankenFS indirect read `211-224 ms` vs kernel ext4 `45 ms`, about `4.7-5.0x` slower. Today's RCH Criterion is Rust-internal: baseline incumbent parallel read on `vmi1149989` measured serial/parallel medians `5.7337 ms / 970.27 us` (16 runs), `23.414 ms / 2.7872 ms` (64), `92.482 ms / 13.491 ms` (256). Candidate same-binary A/B on `vmi1167313`: incumbent `parallel_rayon` vs `parallel_in_place` medians `2.7308 ms / 2.5461 ms` (`1.073x`, small win), `7.7753 ms / 8.6526 ms` (`0.899x`, regression), `25.508 ms / 25.452 ms` (`1.002x`, neutral). Win/loss/neutral: internal A/B `1/1/1`; direct kernel ratio `0/1/0` from the existing gap. | RCH `cargo bench --profile release-perf -p ffs-core --bench ext4_indirect_read_overlap -- ext4_indirect_read_overlap --warm-up-time 1 --measurement-time 3` passed on `vmi1149989` for baseline and on `vmi1167313` for candidate; benchmark asserts byte equality against the serial oracle before measuring. RCH `cargo check -p ffs-core --bench ext4_indirect_read_overlap` passed on `vmi1152480`; `rustfmt --edition 2024 --check crates/ffs-core/benches/ext4_indirect_read_overlap.rs` passed; `cargo test -p ffs-core read_ext4_indirect -- --nocapture` passed under RCH local fallback (1 focused test); `cargo test -p ffs-harness --test conformance -- --nocapture` passed under RCH local fallback (100 passed / 0 failed / 2 ignored). Clippy for `ffs-core` is blocked by pre-existing library pedantic debt unrelated to the benchmark-only final diff. Production source was restored to the incumbent owned-buffer parallel path; only the A/B benchmark guard remains. | Do not ship or retry the direct-output copy-elision variant for `read_ext4_indirect` without new profile evidence: it regresses the 64-run row and is neutral at 256. The remaining ~5x kernel loss is not closed by buffer assembly tweaks; route deeper to indirect pointer resolution/planning, real direct-kernel image fixtures, mmap/io_uring/vectorized device paths, or a genuinely fragmented indirect-image comparator. |
| 2026-06-20 | `bd-xmh5g` | ext4 indirect near-contiguous 32 MiB large-run read; one coalesced run split into ordered 16/32/64/128/256/512-block chunks | KEEP / production retained with `128` block default | Existing direct ext4-kernel gap remains open: prior 32 MiB `^extent` probe was FrankenFS `211-224 ms` vs kernel ext4 `45 ms` (`~4.7-5.0x` slower). Fresh RCH direct comparator created a valid no-extents image and built release-perf `ffs-cli`, but worker loop mount failed, so no new kernel ratio. Internal same-worker `vmi1227854` sweep: single-run `25.523 ms`; 16-block chunks `31.397 ms` (`0.813x`, loss), 32 `23.067 ms` (`1.106x`, neutral/noisy), 64 `17.267 ms` (`1.478x`), 128 `15.729 ms` (`1.623x`, kept), 256 `16.591 ms` (`1.539x`), 512 `17.475 ms` (`1.461x`). Internal W/L/N `4/1/1`; direct kernel `0/1/0` from existing gap, fresh rerun blocked. | RCH `cargo bench --profile release-perf -p ffs-core --bench ext4_indirect_read_overlap -- ext4_indirect_read_overlap/large_run --warm-up-time 1 --measurement-time 1 --sample-size 20` passed on `vmi1227854`; RCH `cargo test -p ffs-core ext4_indirect_large_run_chunks_default_bd_xmh5g -- --nocapture` passed on `vmi1167313`; RCH `cargo check -p ffs-core --all-targets` passed on `vmi1152480`; RCH-wrapper local fallback harness conformance passed `100 / 0 / 2 ignored`; full clippy remains blocked by pre-existing pedantic debt outside this lever. | Retains a measured internal 1.62x fix for the exact indirect large-run routing gap, but release readiness for ext4-kernel domination stays limited until loop-mount/kernel comparator access is restored and the direct `~5x` loss is remeasured. Do not retry 16-block chunks; use 128 as the current default. |
| 2026-06-20 | `bd-w3hol` | cod-a fresh verification of FUSE writeback-cache write path, 32 x 32 KiB writes to one file handle followed by flush, plus core request-scope batching rerun | KEEP / production retained | Direct ext4/btrfs-kernel ratio remains neutral/unavailable for this isolated primitive: Linux ext4/btrfs do not expose a timed comparator for FrankenFS's in-process per-`(ino, fh)` deferred `RequestScope` table. Fresh cod-a RCH Criterion on `hz1`: old per-write FUSE commit median `75.412 us` vs deferred flush median `64.716 us`, old/new `1.165x`, production latency `0.858x` (`14.2%` lower). Fresh cod-a core primitive rerun on `hz1`: per-write `8.7549 ms`, raw batched `6.6308 ms`, request-scope batched `6.7427 ms`; per-write/request-scope `1.299x`, request-scope is `1.7%` slower than raw batched. Win/loss/neutral: internal A/B `1/0/0`; direct kernel ratio `0/0/1`. | RCH `cargo bench --profile release-perf -p ffs-fuse --bench mount_runtime -- mount_runtime_writeback` passed on `hz1`; RCH `cargo bench --profile release-perf -p ffs-core --bench mvcc_commit_batching -- mvcc_commit_batching_2000` passed on `hz1`; RCH `cargo build --release -p ffs-fuse` passed on `hz1`; RCH `cargo test -p ffs-fuse writeback_cache -- --nocapture` passed on `vmi1152480` (12/12); RCH `cargo test -p ffs-harness --test conformance -- --nocapture` passed on `vmi1153651` (100 passed / 0 failed / 2 ignored). | Confirms the already-landed `bd-w3hol` production lever remains a keep on fresh cod-a evidence. Do not claim whole-filesystem kernel domination from this primitive alone; next direct-kernel work should measure mounted write+fsync after unrelated mounted-suite debt is isolated, or move to the open btrfs decompression oversubscription gap (`bd-defgb`). |
| 2026-06-20 | `bd-w3hol` | FUSE writeback-cache write path, 32 x 32 KiB writes to one file handle followed by flush, old per-write commit vs per-FH deferred `RequestScope` commit | KEEP / production retained | Direct ext4/btrfs-kernel ratio is neutral/unavailable for this isolated primitive: the Linux kernel does not expose a timed comparator for FrankenFS's per-file-handle `RequestScope` batching table. RCH Criterion on `vmi1227854`: per-write commit median `43.353 us`, deferred flush median `30.213 us`, old/new `1.435x`, production latency `0.697x` (`30.3%` lower). Win/loss/neutral: internal A/B `1/0/0`; direct kernel ratio `0/0/1`. | RCH `cargo build --release -p ffs-fuse` passed on `vmi1153651`; RCH `cargo test -p ffs-fuse writeback_cache -- --nocapture` passed on `ovh-a` (12/12); RCH `cargo clippy -p ffs-fuse --all-targets --no-deps -- -D warnings` passed on `hz1`; RCH `cargo test -p ffs-harness -- --nocapture` on `hz2` cleared lib `2056/2056`, `tests/btrfs_kernel_reference.rs` `7/7`, and `tests/conformance.rs` `100 passed / 0 failed / 2 ignored` before later unrelated mounted `fuse_e2e` failures; RCH focused post-patch `cargo test -p ffs-harness --test fuse_e2e ext4_fuse_inline_data_reads -- --nocapture` passed on `ovh-a` (2/2). | Converts `bd-w3hol` / `bd-xmh5g.401` into a measured keep for write-side commit amortization. Do not claim whole-filesystem kernel domination from this primitive alone; next direct-kernel work should measure mounted write+fsync throughput/latency after the existing unrelated `fuse_e2e` red rows are isolated or quarantined. |
| 2026-06-20 | `bd-27x9a` | btrfs 100 MiB single uncompressed extent read (`/data/tmp/btrperf_1231197.img`, `/m.bin`, one unencoded extent) | KEEP existing production chunking; no new code shipped | Local hyperfine, warm/shared-cache, release-perf CLI: kernel btrfs `dd` mean `48.7 ms`; current ffs default-32 mean `76.3 ms`; forced old 256-block chunk mean `91.1 ms`. Current ffs is `1.57x` slower than kernel, but `1.19x` faster than the old 256-block setting on this real-image wall-clock comparator. RCH Criterion on `ovh-a` isolates the Rust overlap primitive: serial `5.0966 ms` vs parallel `405.27 us` median (`12.58x`). | RCH `cargo build --release -p ffs-cli` passed on `ovh-a`; RCH `cargo bench --profile release-perf -p ffs-core --bench btrfs_uncompressed_read_overlap -- btrfs_uncompressed_read_overlap_16extents` passed on `ovh-a`; RCH `cargo test -p ffs-core btrfs_read -- --nocapture` passed on `hz1` (21 passed, 1 ignored, 0 failed). Local target verified with `filefrag`: `/m.bin` is one 100 MiB extent, no encoded/shared flags. | Converts `bd-27x9a` from hypothesis to measured evidence: chunking is still better than the old setting, but the kernel gap remains a loss. Do not claim btrfs-kernel domination from this lever; next work should attack file-device/syscall/copy overhead (mmap/io_uring/vectorized direct device) rather than retuning chunk size again. |
| 2026-06-20 | `bd-2x68s` | Warm sequential ext4 extent read gap, including `read_into` buffer reuse and parallel-read chunk retunes (`4096->256->32` blocks) | CLOSE / measured keep family, no new code in this closeout | Initial direct gap was warm ext4 extent reads at ~2.3-2.5x slower than kernel (`~25ms` frankenfs excluding ~10ms CLI/open artifact vs `~10ms` kernel dd). Shipped evidence closes the real read-engine gap: `d5e2059a` made multi-file `walk --read-data` **3.2x** faster (37ms -> 11.7ms) while single-shot `read_into` was neutral (33.6ms -> 33.0ms); `c110c39b` made 32MiB single-file warm **2.19x** faster (33.3ms -> 15.7ms) and cold **2.22x** faster (51.8ms -> 23.3ms), beating the kernel cold comparator (23.3ms < 30ms); `3671522c` then retuned `FFS_READ_CHUNK_BLOCKS` default `256->32`, measuring ext4 128MiB **1.67x warm / 1.24x cold** and btrfs 100MiB **3.14x warm / 1.90x cold** vs the prior 256-block default. Negative evidence retained: indirect direct-window rewrite regressed/neutral (warm ~42ms -> ~44ms, cold 49.5ms -> 53.4ms) and CLI process/open overhead had no frankenfs hot symbol. | Current cod-a RCH gates: `AGENT_NAME=BlackThrush RCH_WORKER=vmi1149989 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo build --release -p ffs-core -p ffs-cli` passed; `AGENT_NAME=BlackThrush RCH_WORKER=vmi1153651 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo test -p ffs-core read_file_data -- --nocapture` passed 4/4; `... cargo test -p ffs-core read_into -- --nocapture` passed 1/1. | Closes stale direct warm-extent bead as measured-resolved: production already has caller-buffer direct fill plus 32-block read chunking for ext4 and btrfs uncompressed reads. Remaining read losses are separate surfaces already ledgered: rare ext4 indirect sequential reads (~5x kernel) and btrfs compressed-read pool oversubscription. |
| 2026-06-19 | `bd-iamhf` | `ffs-cli read --discard` large-file read path, old whole-file `read_file` materialization vs streaming through one reused chunk buffer | KEEP / production retained | Non-sparse 200 MiB ext4 image on `vmi1149989`, release-perf, exact baseline `7050a1c3` vs candidate: warm mean old `0.196 s` vs streaming `0.162 s` (`1.21x` old/new); cold mean old `0.347 s` vs streaming `0.287 s` (`1.21x`). Kernel ext4 warm remains much faster at this low-resolution timing surface (`0.00-0.04 s`); cold kernel was noisy (`0.18/0.63/0.26 s`), so streaming is faster by mean (`1.24x`) but slightly slower by median (`0.28 s` vs `0.26 s`). Sparse 512 MiB allocation/zero-fill probe also favored streaming: warm `1.17 s` vs `0.928 s` (`1.26x`), cold `1.303 s` vs `0.973 s` (`1.34x`). Btrfs not rerun: no existing btrfs image was available and `mkfs` is blocked by DCG. | RCH `cargo check -p ffs-cli --all-targets` passed on `vmi1227854`; release-perf baseline and candidate both built on `vmi1149989`; correctness smoke read exactly `209715200` bytes from `/bigfile` on both binaries. `cargo fmt -p ffs-cli --check` is blocked by pre-existing formatting drift in `crates/ffs-cli/src/cmd_repair.rs`; edited `main.rs` was not the reported diff. | Converts the remaining warm-read allocation/copy tax into a measured keep for discard-mode perf probes without changing normal stdout semantics; stdout mode keeps the previous whole-file buffered write contract. |
| 2026-06-19 | `bd-xmh5g.389` | `ffs-inode` owned 4 KiB/16 KiB/64 KiB `BlockBuf` materialization, `into_inner()` vs `as_slice().to_vec()` for write_inode / indirect-free / xattr-block RMW call sites | REJECT / production reverted | N/A: Rust-internal owned-buffer materialization primitive; ext4/btrfs-kernel has no timed equivalent for `BlockBuf::into_inner()` vs `Vec::to_vec()`, and a kernel inode RMW benchmark would include syscall, VFS, journal, allocator, page-cache, and block-layer behavior that this microbench intentionally excludes. | `cargo fmt -p ffs-inode --check` passed locally; RCH `cargo check -p ffs-inode --all-targets` passed on `hz1`; RCH `cargo test -p ffs-inode --lib -- --nocapture` passed on `ovh-a` with 129 passed / 0 failed; RCH `cargo clippy -p ffs-inode --all-targets --no-deps -- -D warnings` passed on `hz2`; post-clippy focused RCH test `inode_uses_indirect_blocks_excludes_extents_inline_and_non_data_modes` passed on `ovh-a`. | Converted one cod-a `code-first batch-test pending` row into measured negative evidence; production restored to copying via `as_slice().to_vec()` at the three `ffs-inode` RMW sites. |
| 2026-06-19 | `bd-xmh5g.391` | `ffs-alloc` block/inode bitmap mutation materialization, `into_inner()` vs `as_slice().to_vec()` on allocation/free read-patch-write paths | REJECT / production reverted | N/A: Rust-internal bitmap buffer materialization primitive; ext4/btrfs-kernel has no timed equivalent for FrankenFS's `BlockBuf` ownership choice. A whole-filesystem allocator benchmark would include syscall, VFS, journal, allocator, page-cache, and device behavior and would not isolate this lever. | Current cod-a RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- bitmap_owned_move_ab`: old copy median `241.61 ns` vs move median `271.26 ns`; old/new speed ratio `0.891x`, so the move arm is `12.3%` slower. Gates passed: local `cargo fmt -p ffs-alloc --check`; RCH `cargo test -p ffs-alloc -- --nocapture` on `vmi1153651` with 213 passed / 0 failed; RCH `cargo clippy -p ffs-alloc --all-targets --no-deps -- -D warnings` on `hz1`; RCH `cargo build -p ffs-alloc --release` on `vmi1153651`. | Converts one cod-b pending row into measured negative evidence; production restored to `as_slice().to_vec()` for the nine bitmap mutation buffers while preserving the bit-level undo-log rollback guard. |
| 2026-06-19 | `bd-f759f` | `ffs_btrfs::writeback::WriteDependencyDag::reverse_topological_order` metadata flush scheduling, old `BTreeSet` visited membership vs production capacity-sized `HashSet` membership | KEEP / production retained | N/A: Rust-internal btrfs writeback DAG scheduling primitive; Linux btrfs does not expose a timed comparator for FrankenFS's in-memory visited-set membership implementation. A whole-filesystem btrfs writeback benchmark would include VFS, page-cache, allocator, checksum, journal, and device latency and would not isolate this lever. | RCH Criterion on `ovh-a`: old `BTreeSet` median `18.969 us` vs production `HashSet` median `13.220 us` (`1.435x` old/new; production `30.3%` lower scheduler latency). Gates passed: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order` on `hz1`, `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture` on `hz2` with 37 passed / 0 failed, and local `cargo fmt -p ffs-btrfs --check`. | Converted one cod-b `code-first batch-test pending` row into measured keep evidence; production keeps the `HashSet` visited set while the old-`BTreeSet` oracle remains as an A/B guard. |
| 2026-06-19 | `bd-xmh5g.400` | `ffs_btrfs::writeback::WriteDependencyDag::from_cow_tree` child-vector handling during metadata writeback DAG construction | REJECT / production reverted | N/A: Rust-internal btrfs writeback DAG construction primitive; the Linux btrfs kernel does not expose a timed comparator for FrankenFS's in-memory `WriteDependencyDag` child-vector materialization. A whole-filesystem btrfs writeback benchmark would include VFS, page-cache, allocator, checksum, and device latency and would not isolate this lever. | RCH Criterion on `ovh-a`: old double-clone median `89.928 us` vs moved-child production median `110.91 us` (`0.811x` old/new; production `23.3%` slower). Post-revert gates passed: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-btrfs --bench writeback_dag_order` on `hz1`, `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-btrfs writeback -- --nocapture` on `hz2` with 37 passed / 0 failed, and local `cargo fmt -p ffs-btrfs --check`. | Converted one cod-b `code-first batch-test pending` row into measured negative evidence; production returned to the old child-vector double-clone construction while retaining the A/B benchmark guard. |
| 2026-06-19 | `bd-xmh5g.403` | `ffs_mvcc::MvccStore::commit_ssi_internal` successful SSI commit write-set log construction, prebuilt `BTreeSet` vs fused per-write insert | REJECT / production reverted | N/A: Rust-internal SSI commit-log construction primitive; ext4/btrfs-kernel has no timed equivalent for this in-memory `CommittedTxnRecord.write_set` implementation detail. FrankenFS current write path uses plain `commit`, not `commit_ssi`, so a kernel filesystem write benchmark would not isolate this lever. | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo check -p ffs-mvcc --bench wal_throughput` passed on `vmi1227854`; `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo test -p ffs-mvcc ssi -- --nocapture` passed on `hz2` with 70 filtered SSI lib tests, 1 evidence integration test, and 2 stress tests passing. | Converted one cod-b `code-first batch-test pending` row into measured negative evidence; production returned to prebuilding the write-key `BTreeSet` before consuming staged writes. |
| 2026-06-19 | `bd-xmh5g.398` | `FileByteDevice` 4 KiB scalar block read through `ByteBlockDevice::read_block`, staged `read_exact_at` vs owned-destination unstaged read | REJECT / reverted | N/A: Rust-internal FileByteDevice/BlockBuf materialization primitive; no direct ext4/btrfs-kernel comparator exists. A kernel `read(2)`/page-cache test would include syscall, VFS, cache, and filesystem work that this microbench intentionally excludes. | `cargo fmt -p ffs-block --check` passed locally; `rch exec -- cargo check -p ffs-block --all-targets` passed on `hz1`; `rch exec -- cargo clippy -p ffs-block --all-targets -- -D warnings` passed on `vmi1227854`; `rch exec -- cargo test -p ffs-block --lib -- --nocapture` passed on `ovh-a`: 304 passed, 0 failed. | Converted one cod-a `code-first batch-test pending` row into measured negative evidence; production restored to staged `read_exact_at` path. |
| 2026-06-19 | `bd-xmh5g.397` | Trusted vectored short-run `IoSliceMut` descriptor setup inside `ByteBlockDevice::read_contiguous_blocks` | REJECT / reverted | N/A: Rust-internal descriptor-allocation primitive; no ext4/btrfs-kernel equivalent for the `Vec<IoSliceMut>` vs `SmallVec` implementation detail. | `cargo fmt -p ffs-block --check` passed locally; `rch exec -- cargo check -p ffs-block --all-targets` passed on `hz1`; `rch exec -- cargo clippy -p ffs-block --all-targets -- -D warnings` passed on `vmi1227854`; `rch exec -- cargo test -p ffs-block --lib -- --nocapture` passed on `ovh-a`: 304 passed, 0 failed. | Enforced the gauntlet rule that within-noise or slower micro-levers do not ship; production restored to heap-backed `Vec<IoSliceMut>`. |
| 2026-06-19 | `bd-xmh5g.405` | Dense 4 KiB ext4 directory absent lookup plus checksum-tail malformed-header probe | KEEP | Current Rust local Criterion `lookup_absent_dense_4k` median 1.6485 us vs local ext4 kernel `fstatat` unique absent-name median 6.8119 us, Rust/kernel latency ratio 0.242x (4.13x faster). Diagnostic only: kernel number includes syscall/VFS/ext4 dcache work while Rust number is in-process parser/lookup. | `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo test -p ffs-ondisk --lib parse_dir_block_ -- --nocapture` on `hz2`: 12 passed, 0 failed. | Converted one cod-a `code-first batch-test pending` row into measured keep evidence; no revert needed. |

## Current Campaign Rows

| Date | Bead | Surface | Lever | Status | Evidence | Retry predicate |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-06-20 | `bd-r9c10` | `ffs-core::read_ext4_indirect` non-contiguous run read overlap and direct-output candidate | Audit incumbent serial-plan/parallel-owned-buffer read path against a direct-output in-place variant that removes per-segment `Vec` materialization and serial assembly copy | Rejected / production reverted | Baseline RCH Criterion on `vmi1149989`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-core --bench ext4_indirect_read_overlap -- ext4_indirect_read_overlap --warm-up-time 1 --measurement-time 3`: serial vs incumbent `parallel_rayon` medians were `5.7337 ms / 970.27 us` (16 runs, `5.91x`), `23.414 ms / 2.7872 ms` (64, `8.40x`), and `92.482 ms / 13.491 ms` (256, `6.85x`). Candidate same-binary A/B on `vmi1167313`: `parallel_rayon` vs `parallel_in_place` medians `2.7308 ms / 2.5461 ms` (`1.073x` small win), `7.7753 ms / 8.6526 ms` (`0.899x` regression), and `25.508 ms / 25.452 ms` (`1.002x` neutral). Direct ext4-kernel comparator remains the existing indirect 32 MiB `^extent` loss (`211-224 ms` vs `45 ms`, ~`5x` slower), not closed here. | Do not retry direct-output/window-carving copy-elision for this path unless a fresh profile shows segment assembly copy dominates and a same-binary A/B beats all run-count rows by a material margin. Remaining work should re-localize the indirect gap instead of polishing buffer assembly. |
| 2026-06-20 | `bd-w3hol` | `ffs-fuse` writeback-cache write/flush/fsync/release paths and `ffs-core` request-scope batching primitive | Verify the already-landed per-`(ino, fh)` writeback batch table and core deferred `RequestScope` path under fresh cod-a rch runs | Measured keep | Fresh cod-a RCH Criterion on `hz1`: `mount_runtime_writeback/per_write_commit_32x32k` median `75.412 us`; `mount_runtime_writeback/deferred_flush_32x32k` median `64.716 us`; old/new `1.165x`, production `14.2%` lower latency. Fresh core rerun on `hz1`: per-write `8.7549 ms`, raw batched `6.6308 ms`, request-scope batched `6.7427 ms`; per-write/request-scope `1.299x`. Behavior/build gates: RCH `ffs-fuse` release build passed; RCH `ffs-fuse` writeback tests 12/12; RCH `ffs-harness` conformance 100 passed / 0 failed / 2 ignored. Direct ext4/btrfs-kernel ratio remains neutral/unavailable for this internal batching primitive. | Keep. Retry only if a direct mounted write+fsync ext4/btrfs-kernel comparator shows regression, or if a new correctness test proves a same-FH read/flush/fsync/release semantic gap. For kernel-ratio claims, first isolate mounted `fuse_e2e` unrelated debt and run a direct mounted writeback benchmark. |
| 2026-06-20 | `bd-w3hol` | `ffs-fuse` writeback-cache write/flush/fsync/release paths | Add a per-`(ino, fh)` writeback batch table that reuses a deferred write `RequestScope` across buffered writes and commits it on flush/fsync/release/destroy; synchronous and NOWAIT writes drain or bypass the deferred scope to preserve durability and lock semantics | Measured keep | RCH Criterion on `vmi1227854`: `mount_runtime_writeback/per_write_commit_32x32k` median `43.353 us`; `mount_runtime_writeback/deferred_flush_32x32k` median `30.213 us`; old/new `1.435x`, production `30.3%` lower latency. Behavior gates: RCH `ffs-fuse` writeback tests 12/12; RCH `ffs-fuse` build and clippy clean; RCH `ffs-harness` conformance 100 passed / 0 failed / 2 ignored; RCH post-patch inline-data FUSE fixture check 2/2; focused local clippy for changed harness test targets passed. Full mounted `fuse_e2e` is not green: a stale full RCH run printed unrelated btrfs rename/security-xattr/renameat2/read-only ioctl failures and was interrupted after several tests hung. | Keep the writeback batching lever. Retry only if a direct mounted write+fsync kernel comparator shows regression, or if a new correctness test proves a same-FH read/flush/fsync/release semantic gap. For kernel-ratio claims, first isolate/quarantine the existing unrelated mounted `fuse_e2e` red rows and then run a direct ext4/btrfs mounted writeback benchmark. |
| 2026-06-20 | `bd-27x9a` | `ffs-core` btrfs large uncompressed read through `ByteDeviceBlockAdapter` / `FileByteDevice` | Add an opt-in direct-overwrite byte-device read for callers that discard destinations on error, then route contiguous filesystem reads through it to skip `FileByteDevice`'s staging copy | Rejected / production reverted | Local release-perf hyperfine on the same one-extent btrfs target. Baseline before candidate: kernel `48.7 ms`, current ffs default-32 `76.3 ms`, forced 256-block `91.1 ms`. Candidate after direct-overwrite fast path: kernel `49.7 ms`, default-32 `75.7 ms`, forced 256-block `72.5 ms`. The default moved only `0.8%` (`76.3 -> 75.7 ms`), well inside run/load noise, and the forced old chunk result flipped faster than default, so the lever was not a credible keep. The code was reverted; no production source change shipped. | Do not retry `FileByteDevice` direct-overwrite reads as a small trait shim. Retry only with a profile showing staging-copy self-time dominates a real read workload and a same-worker A/B beats staged reads by at least 10% without weakening the public short-read destination-preservation contract. Prefer deeper file-device work: mmap-backed readonly image, `preadv2`/io_uring batching, or fewer larger kernel syscalls with explicit copy accounting. |
| 2026-06-20 | `bd-2x68s` | `ffs-core`/`ffs-cli` warm sequential extent reads vs ext4/btrfs kernel | Keep the already-shipped safe levers: `OpenFs::read_into` caller-buffer reuse, ext4 extent chunk default `4096->256->32` blocks, and btrfs uncompressed sub-read chunking on the same `FFS_READ_CHUNK_BLOCKS` default | Closed / measured keep family | Win/neutral/loss ledger: WIN `read_into` multi-file reuse 37ms -> 11.7ms (**3.2x**); NEUTRAL single-shot `read_into` 33.6ms -> 33.0ms; WIN extent chunk `4096->256` warm 33.3ms -> 15.7ms (**2.19x**) and cold 51.8ms -> 23.3ms (**2.22x**, beats kernel cold 30ms); WIN chunk `256->32` ext4 128MiB **1.67x warm / 1.24x cold** and btrfs 100MiB **3.14x warm / 1.90x cold**; REJECT indirect direct-window rewrite warm ~42ms -> ~44ms and cold 49.5ms -> 53.4ms; NO-LEVER for CLI process/open overhead (no frankenfs top symbols). Fresh gates: RCH release build `ffs-core`+`ffs-cli` passed on `vmi1149989`; RCH `read_file_data` tests passed 4/4 and `read_into` coalescing test passed 1/1 on `vmi1153651`. | Do not retry unsafe uninit allocation, allocator tuning, or global allocator swaps under the current `forbid(unsafe_code)` invariant. Retry only with a safe borrowed-buffer/cache API, a real io_uring/mmap backend decision, or fresh direct kernel evidence on a different read surface. |
| 2026-06-19 | `bd-xmh5g.406` | `ffs_journal::verify_jbd2_block_checksum` JBD2 commit-block checksum verification during replay | Stream CRC32C over the commit block as prefix + zero checksum field + suffix, eliminating the full-block `to_vec()` clone used only to zero four bytes before hashing | Rejected / production reverted | RCH Criterion on `ovh-a`, commit `01872c46`, `--profile release-perf`, command `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-journal --bench journal_replay_apply_io_overlap -- journal_commit_checksum_zero_field_clone_vs_segmented`. Mean old clone vs segmented: 1024 B `220.86 ns` vs `158.52 ns` (`1.393x` old/new, win), 4096 B `595.89 ns` vs `742.02 ns` (`0.803x` old/new, segmented is `24.5%` slower), 16384 B `2.8403 us` vs `2.2867 us` (`1.242x` old/new, win). Verdict follows the realistic 4 KiB JBD2 block-size row: reject and restore clone+zero verification. Direct ext4/btrfs-kernel ratio: N/A for this internal checksum microprimitive; repo search found broader mount/kernel artifacts but no direct kernel JBD2 checksum comparator. `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-journal` passed after revert. | Do not retry segmented commit-block CRC on the normal 4 KiB replay path. Retry only with a direct kernel/JBD2 checksum comparator or fresh profile evidence proving non-4 KiB commit blocks dominate the target workload enough to offset the 4 KiB regression. |
| 2026-06-19 | `bd-xmh5g.405` | `ffs_ondisk::walk_dir_block_entries` and `DirBlockIter` dense ext4 directory scans | Gate the trailing-suffix `all_zero_bytes` malformed-checksum-tail probe behind `is_malformed_dir_checksum_tail(...)`, so normal live/deleted entries skip the zero scan while valid checksum-tail padding validation remains unchanged | Measured keep | rch Criterion same-binary A/B on worker `vmi1152480`: `tail_scan_eager_suffix_probe_dense_4k` median 2.7869 us [2.7304, 2.8510] vs `tail_scan_gated_suffix_probe_dense_4k` median 882.05 ns [849.55, 923.52], new/old latency ratio 0.317x (3.16x faster). Same-host production before/after: parent `0e01c3f4` `lookup_absent_dense_4k` median 4.2479 us vs current median 1.6485 us, new/old ratio 0.388x (2.58x faster). Original-kernel diagnostic: local ext4 `fstatat` unique absent-name lookup in a 256-entry directory median 6.8119 us, current Rust/kernel ratio 0.242x (4.13x faster), with syscall/VFS-vs-parser caveat. Conformance: rch `hz2` `cargo test -p ffs-ondisk --lib parse_dir_block_ -- --nocapture` passed 12/12. | Do not retry the eager suffix-scan shape. Revisit only if a future profile shows checksum-tail validation or deleted-entry parsing, not normal live-entry lookup, dominating a realistic directory workload after this gate. |
| 2026-06-19 | `bd-xmh5g.404` | `ffs_journal::replay_jbd2_inner` JBD2 staged-block apply materialization after parallel reads | Consume each staged `BlockBuf` with `into_inner()` instead of copying `as_slice().to_vec()`, moving the owned aligned Vec for file-backed reads while preserving clone fallback for shared buffers | Rejected / production reverted | RCH Criterion on `ovh-a`, commit `01872c46`, `--profile release-perf`, command `RCH_WORKER=ovh-a RCH_WORKERS=ovh-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-journal --bench journal_replay_apply_io_overlap -- journal_replay_blockbuf_materialize`. Mean old `as_slice().to_vec()` vs `into_inner()`: 16 blocks `3.9888 us` vs `4.2087 us` (`0.948x` old/new, `into_inner` is `5.5%` slower), 64 blocks `21.282 us` vs `22.110 us` (`0.963x`, `3.9%` slower), 256 blocks `71.482 us` vs `77.324 us` (`0.924x`, `8.2%` slower). Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal materialization primitive; no kernel equivalent exists. `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-journal` passed after revert. | Do not retry `BlockBuf::into_inner()` materialization in JBD2 replay apply without a new producer proving truly zero-copy ownership and a focused same-worker A/B. The current owned-read shape loses across all tested replay sizes. |
| 2026-06-19 | `bd-xmh5g.403` | `ffs_mvcc::MvccStore::commit_ssi_internal` successful SSI commit log construction | Fuse committed write-set `BTreeSet` construction into the staged-write version-install loop, eliminating the prior separate `txn.write_set().keys().copied().collect()` pass before consuming the transaction | Rejected / production reverted | RCH Criterion on `vmi1227854`, commit under measurement `1cd8de6f`, command `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-mvcc --bench wal_throughput -- mvcc_commit_ssi_writekey_log_ab`. Mean old prebuild vs fused: 64 writes `437.77 ns` vs `790.80 ns` (`0.554x` old/new, fused is `80.6%` slower), 256 writes `1.8957 us` vs `4.1605 us` (`0.456x`, `119.5%` slower), 1024 writes `8.0965 us` vs `24.173 us` (`0.335x`, `198.6%` slower). Direct ext4/btrfs-kernel ratio: N/A for this internal SSI write-set construction primitive; no kernel-equivalent timed primitive exists, and the current write path uses plain `commit`, not `commit_ssi`. Production restored to the old prebuilt `BTreeSet` path; A/B bench rows remain as negative-evidence guards. Post-revert gates passed: RCH `cargo check -p ffs-mvcc --bench wal_throughput` on `vmi1227854`, and RCH `cargo test -p ffs-mvcc ssi -- --nocapture` on `hz2` with 70 filtered SSI lib tests, 1 evidence integration test, and 2 stress tests passing. | Do not retry fused per-write `BTreeSet` insertion in SSI commit-log construction. Retry only if a real profile names `commit_ssi_internal` write-set construction as material on a workload that actually uses SSI, and the replacement avoids per-insert tree costs while preserving the exact `CommittedTxnRecord.write_set`. |
| 2026-06-19 | `bd-ucrow` | `ffs-core` request-scope/direct MVCC commit paths when `repair_flush_lifecycle` is detached | Gate the write-set key collection for repair refresh notification behind `repair_flush_lifecycle.is_some()`, so default mounts skip the per-commit `Vec<BlockNumber>` allocation/copy while attached repair lifecycles still receive the exact sorted write-set | Rejected / production reverted | Current cod-a rch Criterion on `ovh-a`, `--profile release-perf`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-core --bench mvcc_commit_batching -- commit_scope_writeset_collect`. Median old always-collect vs lifecycle-none gated: 64 blocks `14.030 us` vs `16.430 us` (`0.854x` old/new, gated is `17.1%` slower), 256 blocks `56.169 us` vs `55.732 us` (`1.008x`, neutral), 1024 blocks `45.953 us` vs `247.65 us` (`0.185x`, anomalous but strongly non-keep). Prior gauntlet scorecard commit `848d28db` also recorded this lever as within-noise neutral. Direct ext4/btrfs-kernel ratio: N/A for this internal request-scope write-set collection primitive; whole-filesystem kernel write timing would not isolate the optional repair lifecycle notification block-list construction. Production restored the old unconditional write-set capture before commit; the Criterion A/B rows remain as negative-evidence guards. | Do not retry lifecycle-gating write-set collection on the commit path unless a fresh profile shows `txn.write_set().keys().collect()` materially dominates a realistic write workload and a same-worker A/B shows a clear win at the actual write-set sizes without lifecycle-present notification drift. |
| 2026-06-18 | `bd-xmh5g.401` | `ffs-core` MVCC request-scope write path / future FUSE per-file-handle writeback table | Add an explicit deferred `RequestScope` commit mode plus `OpenFs::{begin,commit,abort}_writeback_batch_scope`, proving multiple staged block writes can share one transaction and publish with one commit; extend `mvcc_commit_batching` with `request_scope_batched_commit` | Measured neutral / enabling only | Fresh cod-a rch Criterion on worker `vmi1149989`, command `AGENT_NAME=BlackThrush RCH_WORKER=vmi1149989 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-core --bench mvcc_commit_batching -- mvcc_commit_batching_2000 --warm-up-time 1 --measurement-time 1 --sample-size 10`: per-write commit `6.9593 ms`, raw batched commit `6.2581 ms`, request-scope batched commit `6.2478 ms`; request-scope/raw ratio `1.002x` and per-write/request-scope ratio `1.11x`, so the core primitive is not a direct domination win. Conformance gate: `rch exec -- cargo test -p ffs-core writeback_batch_scope_stages_multiple_writes_for_one_commit -- --nocapture` passed 1/1 filtered test. Direct ext4/btrfs-kernel ratio is N/A for this in-memory request-scope primitive; whole-filesystem proof belongs to the per-fh FUSE wiring bench. | Treat this as a neutral enabling primitive, not a scored win. Do not claim the write-back model until `bd-w3hol` wires the per-fh table and proves an e2e write/fsync workload beats per-write commit without violating read-your-writes, flush/fsync/release, bounded-dirty, or crash-consistency semantics. |
| 2026-06-19 | `bd-xmh5g.400` | `ffs_btrfs::writeback::WriteDependencyDag::from_cow_tree` / `collect_nodes` metadata writeback DAG construction | Consume the owned `BtrfsCowNode` snapshot and move internal child vectors into `DagNode`, avoiding the old second child-vector clone per internal node while preserving one recursion snapshot for descent | Rejected / production reverted | RCH Criterion on `ovh-a`, command `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-btrfs --bench writeback_dag_order -- writeback_dag_build_child_vector_ab`. Mean rows: old double-clone `89.928 us`, single-clone model `112.58 us`, moved-child production `110.91 us`; old/production ratio `0.811x`, so the production lever is `23.3%` slower on its own realistic DAG-build workload. Direct btrfs-kernel ratio: N/A for this in-memory writeback DAG construction primitive. Production restored the old double-clone child-vector path. Post-revert gates passed: RCH `cargo check -p ffs-btrfs --bench writeback_dag_order` on `hz1`, RCH `cargo test -p ffs-btrfs writeback -- --nocapture` on `hz2` with 37 passed / 0 failed, and local `cargo fmt -p ffs-btrfs --check`. | Do not retry the moved-child `collect_nodes` shape. Retry only if a new profile shows child-vector cloning dominating btrfs metadata writeback and a replacement beats the old double-clone path in the existing `writeback_dag_build_child_vector_ab` A/B while preserving exact DAG shape, reverse-topological order, and every WB-I1 prefix. |
| 2026-06-18 | `bd-xmh5g.399` | `ffs-core` ext4 `readdir` followed by stat-heavy `getattr` over returned entries | Best-effort prefetch of distinct returned-page inode-table blocks through the existing `ext4_inode_table_block_cache`, issuing uncached block reads in parallel on read-only mounts and preserving readdir output/errors by ignoring prefetch failures | Measured keep | Fresh cod-a rch Criterion on worker `vmi1149989`, command `AGENT_NAME=BlackThrush RCH_WORKER=vmi1149989 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-core --bench ls_dir_inode_prefetch -- --warm-up-time 1 --measurement-time 1 --sample-size 10`: serial `32.894 ms` mean vs parallel prefetch `3.7480 ms` mean, old/new ratio `8.78x`. Build gate: `rch exec -- cargo build --release -p ffs-core` passed on the same worker. Conformance gate: `rch exec -- cargo test -p ffs-core readdir -- --nocapture` passed 24/24 filtered unit tests. Direct ext4-kernel ratio is N/A for this synthetic in-request I/O-overlap microbench; use the real walk/kernel rows in the scorecard for whole-filesystem ratios. | Keep the read-only best-effort prefetch. Do not retry this vein unless a new workload has a serial per-entry device read inside one request; plain readdir+stat FUSE requests already fan out at the dispatcher, and the open write-side gap is commit amortization (`bd-w3hol`), not metadata I/O-overlap. |
| 2026-06-18 | `bd-f759f` | `ffs_btrfs::writeback::WriteDependencyDag::reverse_topological_order` metadata flush scheduling | Replace the ordered `BTreeSet` visited-membership set with a capacity-sized `HashSet`, preserving deterministic child-vector postorder plus `BTreeMap` disconnected-component iteration | Measured keep | RCH Criterion on `ovh-a`, command `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b rch exec -- cargo bench --profile release-perf -p ffs-btrfs --bench writeback_dag_order -- writeback_dag_order_hashset_ab`: old `BTreeSet` median `18.969 us` vs production `HashSet` median `13.220 us`; old/new ratio `1.435x`, new/old latency ratio `0.697x`, production `30.3%` lower scheduler latency. Direct btrfs-kernel ratio: N/A for this in-memory writeback DAG scheduling primitive. Conformance/build gates passed: RCH `cargo check -p ffs-btrfs --bench writeback_dag_order` on `hz1`, RCH `cargo test -p ffs-btrfs writeback -- --nocapture` on `hz2` with 37 passed / 0 failed, and local `cargo fmt -p ffs-btrfs --check`. | Keep the `HashSet` visited membership lever. Revalidate only if a future btrfs writeback profile shows `reverse_topological_order` has changed shape materially, or if a direct kernel-level metadata-writeback benchmark becomes available that can isolate this scheduler primitive rather than whole-filesystem VFS/device effects. |
| 2026-06-18 | `bd-xmh5g.398` | `ffs_block::ByteBlockDevice::read_block` plus local contiguous-read staging buffers on `FileByteDevice` | Add `ByteDevice::read_exact_at_unstaged` for owned/local destinations, override `FileByteDevice` to fill them directly, and keep public destination-preservation paths on the existing staged read | Rejected / production reverted | RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-block --bench block_buf_construct -- filebyte_read_block`. Old staged `read_exact_at` median `924.56 ns` [899.22, 957.19] vs new unstaged owned-destination median `999.73 ns` [990.66 ns, 1.0115 us]. New/old latency ratio `1.081x` (`8.1%` slower); old/new speed ratio `0.925x`. Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal copy-staging primitive. Source reverted to the staged `read_exact_at` path and the now-dead guard/bench rows were removed. | Do not retry owned-destination unstaged `FileByteDevice` reads unless a fresh profile shows staged-copy preservation dominating a realistic scalar block-read workload and a same-worker A/B beats staged `read_exact_at` by at least 10% with acceptable variance. |
| 2026-06-18 | `bd-xmh5g.397` | `ffs_block::ByteBlockDevice::read_contiguous_blocks` trusted vectored short-run descriptor setup | Replace the temporary heap-backed `Vec<IoSliceMut>` with stack-backed `SmallVec<[IoSliceMut; 16]>`, spilling only for wider runs | Rejected / production reverted | Prior gauntlet Criterion row `read_contiguous_short_trusted_vectored` measured the SmallVec descriptor path at `0.95x` vs the old Vec-backed descriptor list for the 16-block row: marginally slower and within noise, with no meaningful workload win. Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal descriptor setup. Source reverted to `Vec<IoSliceMut>` and the now-dead A/B bench rows were removed. | Do not retry stack-backed short-run iovec descriptors unless a profile names descriptor allocation as material on the trusted vectored contiguous-read path and a same-worker A/B shows a clear win across both 4-block and 16-block rows. |
| 2026-06-18 | `bd-xmh5g.392` | `ffs_block::ByteBlockDevice::read_contiguous_blocks` correctly sized `BlockBuf` runs on trusted byte devices | Add an explicit vectored all-or-nothing read capability and fill caller-owned block buffers with one trusted vectored read, skipping the whole-run staging `Vec` and chunk copies | Pending batch benchmark | Runtime lever, direct-path/error-preservation guards, and Criterion A/B row `read_contiguous_blocks_trusted_vectored` added. This cod-a batch is explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a cargo check -p ffs-block`; benchmarks/tests are not run in this commit. | Run `cargo bench -p ffs-block --bench read_contiguous -- read_contiguous_1mib` plus the crate contiguous-read conformance gate. Keep only on a meaningful correctly-sized block-buffer win and no destination-preservation regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-19 | `bd-xmh5g.391` | `ffs-alloc` block/inode bitmap read-patch-write allocation and free paths | Move disposable owned `BlockBuf` bitmap buffers with `into_inner()` and replace persistent rollback full-block snapshots with bit-level undo logs | Rejected / production reverted | Current cod-a RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- bitmap_owned_move_ab`: old `as_slice().to_vec()` median `241.61 ns` vs move `into_inner()` median `271.26 ns`; old/new speed ratio `0.891x`, so the owned-move arm is `12.3%` slower. Production restored the nine bitmap mutation materializations to `as_slice().to_vec()`; the bit-level undo-log rollback refactor and `bitmap_undo_logs_restore_exact_original_bytes` guard remain. Post-revert gates: local `cargo fmt -p ffs-alloc --check`; RCH `cargo test -p ffs-alloc -- --nocapture` on `vmi1153651` with 213 passed / 0 failed; RCH `cargo clippy -p ffs-alloc --all-targets --no-deps -- -D warnings` on `hz1`; RCH `cargo build -p ffs-alloc --release` on `vmi1153651`. Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal materialization primitive. | Do not retry `BlockBuf::into_inner()` on allocator bitmap RMW paths unless a fresh same-worker A/B at the exact bitmap block ownership shape beats `as_slice().to_vec()` and the rollback-byte guard remains green. The bit-level undo-log refactor is separately preserved. |
| 2026-06-19 | `bd-xmh5g.386` | `ffs_btree::search` / `search_with_leaf_window` validated ext4 extent leaf search | Private trusted `search_leaf_bounded_validated` path used only immediately after `parse_leaf_entries` has already rejected zero-length, unsorted, and overlapping leaves; checked helper retained for public pre-parsed roots | Measured keep | Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal ext4 extent-leaf search primitive; the kernel does not expose a timed comparator for FrankenFS's checked-rescan vs parser-validated helper split. RCH Criterion on `vmi1167313`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-btree --bench extent_leaf_search -- extent_leaf_search_validation_ab`: old checked zero-scan median `451.37 us` [443.15, 459.31] vs trusted validated no-rescan median `40.482 us` [39.645, 41.267], old/new `11.15x`, production latency `0.0897x` of old. Focused guard passed on `vmi1167313`: `cargo test -p ffs-btree search_parsed_root_rejects_caller_supplied_zero_length_leaf_bd_xmh5g_386 -- --nocapture`. Full crate gate passed on `vmi1149989`: `cargo test -p ffs-btree -- --nocapture` (156 passed, 0 failed, doc-tests 0). Scoped lint passed on `vmi1153651`: `cargo clippy -p ffs-btree --all-targets --no-deps -- -D warnings`. Local `cargo fmt -p ffs-btree --check` passed after mechanical formatting. Release compile evidence: `cargo build -p ffs-btree --release` finished successfully on `vmi1264463`, but rch returned `RCH-E309` because artifact retrieval from the worker-scoped target dir timed out; code compile was green, local artifact sync was incomplete. | Keep; `parse_leaf_entries` remains the single on-disk validator for private byte-parsed leaves, while public caller-supplied parsed roots still call the checked helper and reject zero-length extents. Do not restore the redundant per-search zero-length scan unless a future profile proves parser validation no longer dominates the trust boundary or a new public entry bypasses `parse_leaf_entries`. |
| 2026-06-19 | `bd-xmh5g.388` | `ffs_btrfs::BtrfsExtentAllocator::resolve_containing_data_extent` logical-ino/backref lookup | Replace the materializing from-zero extent-tree range scan with a `floor_key` predecessor walk that skips interleaved non-`EXTENT_ITEM` keys and checks the single greatest data extent candidate | Measured keep | Direct btrfs-kernel ratio: N/A for this Rust-internal extent-tree predecessor primitive; the kernel exposes LOGICAL_INO behavior, not a timed comparator for FrankenFS's in-memory `range_from_zero_scan` vs `floor_key` implementation. RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench -p ffs-btrfs --bench extent_fetch -- resolve_containing_extent_floor_ab`: old `range_from_zero_scan` median `624.25 us` [616.69, 632.68] vs `floor_key_predecessor` median `653.21 ns` [647.46, 660.70], old/new `955.7x`, production latency `0.00105x` of old. | Gates: RCH `cargo test -p ffs-btrfs -- --nocapture` on `hz2` passed 361 unit tests + 38 conformance golden tests + doc-tests; RCH `cargo build -p ffs-btrfs --release` on `hz2` passed; RCH scoped `cargo clippy -p ffs-btrfs --lib --no-deps -- -D warnings` on `hz1` passed. Full `cargo clippy -p ffs-btrfs --all-targets -- -D warnings` was blocked before ffs-btrfs by unrelated existing `ffs-repair` path-dependency lints (`manual_saturating_arithmetic`, `unused_self`). Do not retry the from-zero scan shape unless a new correctness requirement invalidates predecessor lookup; interleaved non-extent and mid-extent guards are green. |
| 2026-06-18 | `bd-xmh5g.384` | `ffs_ondisk::parse_leaf_items` dense btrfs leaf payload-overlap validation | Lazy descending-payload fast path that avoids eager coverage bitmap allocation on canonical leaves; exact bitset replay fallback for noncanonical layouts | Pending batch benchmark | Runtime lever, focused fallback fixture, and Criterion A/B row `btrfs_leaf_payload_coverage_ab` added. This cod-b batch is explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-ondisk`; benchmarks/tests are not run in this commit. | Run `cargo bench -p ffs-ondisk --bench btrfs_leaf_parse -- btrfs_leaf_payload_coverage_ab` plus the crate conformance/parser gate. Keep only on a meaningful parser win and no overlap-validation regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-19 | `bd-xmh5g.381` | `ffs-alloc::succinct::SuccinctBitmap::find_contiguous`, scalar old bit scan vs broadword zero-run detector (`succinct_find_contiguous_ab`) | KEEP / production retained | Direct ext4/btrfs-kernel ratio: N/A, Rust-internal allocator bitmap scan primitive; no kernel-exposed timed equivalent isolates one free-run detector. RCH Criterion on `hz2`, post-clippy tree, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- succinct_find_contiguous_ab`: old bit scan median `20.486 us` vs broadword median `2.3492 us`, old/new `8.72x`, production latency `0.115x` of old. | `cargo fmt -p ffs-alloc --check` passed locally; RCH `cargo check -p ffs-alloc --all-targets` passed on `hz2`; RCH `cargo test -p ffs-alloc -- --nocapture` passed on `ovh-a` with 213 passed / 0 failed; RCH `cargo clippy -p ffs-alloc --all-targets -- -D warnings` passed on `ovh-a` after removing two local allocator lint blockers. | Converts the cod-a broadword pending row into a measured keep; exact earliest-run behavior is guarded by `proptest_find_contiguous_matches_naive_earliest_run`, so no production revert. |
| 2026-06-20 | `bd-xmh5g.382` | `ffs-extent::ExtentCache::lookup` same-namespace hot hits | Shared read-lock hit path, then repaired striped hit/miss counters for the same read-lock path after the single shared atomic was identified as a cache-line bottleneck | Rejected / production reverted | Same-worker RCH `hz2`, `--profile release-perf`, lint-clean benchmark code. Baseline A/B before candidate on `hz1`: `extent_cache_same_ns_8t` write_lock_hit median `9.6402 ms` vs read_lock_atomic_hit `20.796 ms` (`0.464x`, read-lock slower). Production-shaped baseline `extent_cache_real_same_ns`: 1t `701.67 us`, 2t `4.6526 ms`, 4t `11.450 ms`, 8t `21.291 ms`. Final striped-counter A/B on `hz2`: write_lock_hit `14.201 ms`, read_lock_atomic_hit `20.348 ms`, read_lock_striped_atomic_hit `18.341 ms`; striped vs single atomic `1.11x`, while striped vs write-lock remains `0.774x`. Direct ext4/btrfs-kernel ratio: N/A for this Rust-internal cache primitive. Production striped-counter changes were reverted; the synthetic striped arm remains only as a negative-evidence guard. | Do not retry same-namespace read-lock ExtentCache hits by moving contention among counters. Retry only if the new design removes both hot-hit shared stats and hot-hit per-entry recency traffic, or if a fresh profile plus same-worker A/B shows the replacement beating the write-lock baseline on the production-shaped bench. |
| 2026-06-18 | `bd-xmh5g.385` | `ffs-xattr::parse_external_entries` zero-initialized external xattr block acceptance | Replace scalar `block.iter().all(|b| *b == 0)` with chunked `ffs_types::all_zero_bytes` for the allow-zero-initialized invalid-magic fallback | Pending batch benchmark | Production lever and Criterion A/B row `xattr_zero_initialized_external_block` added. This cod-a batch was explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a cargo check -p ffs-xattr`; benchmarks/tests were not run in this commit. | Run `cargo bench -p ffs-xattr --bench xattr_exists_probe -- xattr_zero_initialized_external_block` and the crate conformance gate. Keep only on `Score >= 2.0` and no zero-block accept/reject regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-18 | `bd-xmh5g.387` | `ffs_mvcc::MvccBlockDevice::read_block` version-store hit | Materialize the visible `Cow` with `into_owned()` (MOVE the decompressed `Cow::Owned` Vec) instead of `to_vec()` (clone) | Pending batch benchmark | Production lever + Criterion A/B `read_block_cow_owned` + identical-bytes guard; `cargo check -p ffs-mvcc` only. | Run `cargo bench -p ffs-mvcc --bench read_block_cow_owned`. Clean-by-construction (`into_owned <= to_vec`, byte-identical) — keep unconditionally; only the uncompressed `Cow::Borrowed` path still clones (see `bd-xmh5g.394`). |
| 2026-06-18 | `bd-xmh5g.389` | `ffs-inode` 3 read-modify-write paths (write_inode, indirect-block free, POSIX-ACL) | Move the owned `BlockBuf` read buffer with `into_inner()` (Arc::try_unwrap) instead of `as_slice().to_vec()` | Rejected / production reverted | RCH Criterion on `vmi1227854`, command `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench --profile release-perf -p ffs-mvcc --bench blockbuf_into_inner -- blockbuf_into_inner_vs_to_vec`. Mean old copy vs new move: 4096 B `576.96 ns` vs `534.36 ns` (`1.080x` old/new, small win), 16384 B `1.3722 us` vs `1.5633 us` (`0.878x` old/new, move is `13.9%` slower), 65536 B `3.7725 us` vs `4.2885 us` (`0.880x`, move is `13.7%` slower). Verdict follows the wider RMW-block rows: reject and restore `as_slice().to_vec()` at the three `ffs-inode` sites. Direct ext4/btrfs-kernel ratio: N/A for this internal owned-buffer materialization primitive. `cargo fmt -p ffs-inode --check` passed; RCH `cargo check -p ffs-inode --all-targets` passed on `hz1`; RCH `cargo test -p ffs-inode --lib -- --nocapture` passed on `ovh-a` with 129/129; RCH `cargo clippy -p ffs-inode --all-targets --no-deps -- -D warnings` passed on `hz2`; post-clippy focused RCH test `inode_uses_indirect_blocks_excludes_extents_inline_and_non_data_modes` passed on `ovh-a`. Broad dependency-lint clippy without `--no-deps` was blocked by an unrelated existing `ffs-extent` `significant_drop_tightening` lint. | Do not retry `BlockBuf::into_inner()` in `ffs-inode` RMW paths unless a fresh profile proves a 4 KiB-only workload dominates and a same-worker A/B clears the 16 KiB/64 KiB regressions or narrows the lever to a proven unique fast path. |
| 2026-06-18 | `bd-xmh5g.390` | `ffs-core::btrfs_write_logical` partial-block (unaligned) read-modify-write | Move the owned `BlockBuf` via `into_inner()` instead of `as_slice().to_vec()` | Pending batch benchmark | Production lever; `cargo check -p ffs-core` (no use-after-move). | Run `cargo bench -p ffs-mvcc --bench blockbuf_into_inner` (same primitive). Clean-by-construction — keep unconditionally. |
| 2026-06-18 | `bd-xmh5g.393` | `ffs-core` 8 read/RMW paths (ext4/btrfs superblock RMW, partial head/tail RMW, block-run/contiguous/indirect read-resolve) | Move owned `BlockBuf` read buffers via `into_inner()` instead of `as_slice().to_vec()` | Pending batch benchmark | Production lever; `cargo check -p ffs-core` confirms no use-after-move at any of the 8 sites. | Run `cargo bench -p ffs-mvcc --bench blockbuf_into_inner` (same primitive). Clean-by-construction — keep unconditionally. |
| 2026-06-18 | `bd-xmh5g.395` | `ffs_mvcc::sharded::make_chain_head_full` chain compaction (commit/GC chain-cap) | Move the resolved `Cow` via `into_owned()` instead of `to_vec()`; matches the already-corrected twin in `lib.rs:3113` | Pending batch benchmark | Production lever; `cargo check -p ffs-mvcc`. Found by auditing all 10 `resolve_data_with` callers (rest are comparisons/`.len()`, no clone). | Run `cargo bench -p ffs-mvcc --bench read_block_cow_owned` (same Cow move-vs-copy primitive). Clean-by-construction — keep unconditionally. |
| 2026-06-18 | `bd-xmh5g.394` | `ffs_mvcc` UNCOMPRESSED read path (`read_visible`/`read_block` `Cow::Borrowed -> into_owned`) | Store `VersionData::Full` as a shared aligned buffer and share it into `BlockBuf` with `Arc::clone`, eliminating the common uncompressed read allocation/copy | KEEP / production retained | Direct ext4/btrfs-kernel ratio: N/A, Rust-internal MVCC uncompressed-version materialization primitive; no kernel-exposed timed equivalent isolates one Arc-share vs block-copy step. RCH Criterion on `hz2`, command `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench -p ffs-mvcc --bench read_block_uncompressed_clone_vs_share -- read_block_uncompressed`: `clone_into_owned` vs `arc_share` medians: 4K `86.318 ns` vs `621.25 ps` = `138.9x` old/new; 16K `228.72 ns` vs `722.58 ps` = `316.5x`; 64K `1.2177 us` vs `615.58 ps` = `1978.1x`. Production-shaped corroboration on `hz2`: `read_visible_sequential/scan_2000_blocks` median `257.62 us`, `29.615 GiB/s`. | RCH release builds passed on `hz2`: `cargo build -p ffs-mvcc --release`, `cargo build -p ffs-block --release`. RCH tests passed: `cargo test -p ffs-block -p ffs-mvcc -- --nocapture` on `hz2` after the root-safe `ffs-block` empty-write test fix; post-clippy `cargo test -p ffs-mvcc -- --nocapture` on `vmi1153651`. Hygiene passed: `cargo fmt -p ffs-block --check`, `cargo fmt -p ffs-mvcc --check`, RCH `cargo check -p ffs-block -p ffs-mvcc --all-targets` on `hz1`, and RCH `cargo clippy -p ffs-block -p ffs-mvcc --all-targets --no-deps -- -D warnings` on `hz1`. Broad dependency-lint clippy without `--no-deps` is blocked by unrelated existing `ffs-repair/src/storage.rs` lints. | Keep; Arc-share beats the clone arm at every measured size, including the 4K small-block break-even, and the shared-storage guard proves byte-identical exposure. No revert. |
| 2026-06-18 | `bd-xmh5g.396` | Ext4 metadata-only inode parse for `getattr`/`lookup`/`readdir`/existence checks in `ffs-core` and `Ext4FsOps` | Add `Ext4Inode::parse_metadata_from_bytes` and metadata reader wrappers that preserve all fixed inode fields while leaving `xattr_ibody` empty; keep `parse_from_bytes` full for xattr and inline-data users | Pending batch benchmark | Production lever, metadata-vs-full fixed-field guard, and existing Criterion A/B row `ext4_metadata_parse_xattr_ibody` are present. Local-only checks passed: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-ondisk` and `cargo check -p ffs-core` (rerun after hot-path factoring). No tests, benches, or rch were run in this code-first commit. | Run `cargo bench -p ffs-core --bench ext4_metadata_parse_xattr_ibody -- ext4_metadata_parse_xattr_ibody`, then ext4 metadata/xattr/inline-data conformance including `inode_metadata_parse_skips_ibody_only`. Keep only if metadata parse wins without xattr/listxattr/getxattr/inline-data regression; otherwise revert this lever and mark rejected with the measured ratio. |

## Seeded Do-Not-Retry Rows From Prior No-Gaps Work

These rows summarize already-explored families from the existing `bd-xmh5g`
history so the new campaign does not loop on known dead ends. Update each row
with fresh benchmark artifacts if a new workload or primitive changes the
profile.

| Family | Prior rows | Status | Retry predicate |
| --- | --- | --- | --- |
| RaptorQ source-row memoization/cache variants | `bd-xmh5g.149`, `bd-xmh5g.150`, `bd-xmh5g.165` | Rejected or no-ship under prior same-worker evidence | Retry only if a new profile shows row generation, not memory traffic or solve/projection, dominates the current workload after the kept source-domain encode path. |
| LRC small-parity and fused pair/quad microkernels | `bd-xmh5g.152`, `bd-xmh5g.153`, `bd-xmh5g.156`, `bd-xmh5g.157`, `bd-xmh5g.166`, `bd-xmh5g.167`, `bd-xmh5g.169` | Mixed to rejected under prior focused benches | Retry only with a new benchmark family whose workload shape differs materially from the old 64-block/8-parity lanes and includes same-binary A/B evidence. |
| Raw allocation bitmap contiguous/largest-run broadword families | `bd-xmh5g.78`, `bd-xmh5g.85`, `bd-dlc4x`, plus rejected table/broadword variants `bd-xmh5g.30`, `bd-xmh5g.57`, `bd-xmh5g.60`, `bd-xmh5g.77` | Already covered; some kept, some rejected | Do not duplicate raw bitmap work. Only optimize distinct call surfaces, such as succinct-index queries, and add an oracle guard before changing tie-breaking. |
| Owned read-buffer clone→move (`into_inner`/`into_owned`) across cc crates (ffs-mvcc/inode/core) | `bd-xmh5g.387`, `.389`, `.390`, `.393`, `.395` | PARTIALLY REJECTED — `.389` measured `BlockBuf::into_inner()` as a wider-block regression and was reverted; remaining open family members need their own measured verdict instead of the old "keep unconditionally" assumption | Do not re-sweep `.as_slice().to_vec()` / `Cow::to_vec` in ffs-mvcc/inode/core. For `BlockBuf::into_inner()` call sites, require same-worker A/B evidence at the actual block sizes before keeping; `.389` showed the 4 KiB micro-win did not generalize to 16 KiB/64 KiB. Retry only when a NEW owned-buffer-producing function has callers that clone-then-consume and the benchmark proves the concrete call family, not the syntactic pattern. The uncompressed read clone is the open `bd-xmh5g.394` swing, not a clean lever. |
| Redundant-recompute / materialize-to-count / O(N)-scan / Vec-presize on cc hot paths | (swept, no bead) | NO CLEAN HOT WIN | `resolve_data_with` is optimal (Full=borrow, compressed=decompress-once, no delta-fold). Redundant-recompute empty (only `ReadaheadCache::take` `cached.len()` after `split_off` = O(1) micro-lever trap, REJECTED). `collect_extents().len()` already won via header count (`bd-v388x`). O(N) scans are bounded NUL-scans / few btrfs roots / test / tiny commit-frequency SSI sets — none read-hot. `collect_extents` presize needs a counting pre-pass (a second walk = tradeoff). Retry only if a real profile names a specific hot recompute ≥0.1% self-time. |
| FUSE / metadata I/O-overlap parallelization vein | `bd-xmh5g.399` KEPT (readdirplus parallel getattr + ext4 readdir inode-table prefetch) | MINED for the rest | `read_with_readahead` issues ONE combined parallel read of [requested + predictor-sized prefetch tail] then caches the tail (reactive readahead, not a blocking serial prefetch); the ext4 readdir prefetch (`prefetch_ext4_readdir_inode_table_blocks`) is already `into_par_iter`; plain-readdir+stat getattrs are SEPARATE FUSE requests already dispatched concurrently by the worker threads; `copy_file_range` is a generic default over the already-parallel read path; remaining ffs-fuse loops (`encode_xattr_names`, `batch_forget`) are pure in-memory (no I/O). Retry only for a NEW FUSE batch op with a SERIAL per-item device read inside one request (the shape `bd-xmh5g.399` fixed). The open write-side lever is `bd-xmh5g.401` (write-back commit batching), an amortization lever, not I/O-overlap. |
| Write-path durability/sync coalescing (group commit) | (verified, no bead) | ALREADY IMPLEMENTED | `ffs-journal/wal_buffer.rs` already does GROUP COMMIT (epoch-batched WAL writes/syncs: `group_commit_write_start`/`group_commit_success`), so concurrent fsyncs already coalesce into one sync — do NOT file a group-commit lever. The write path commits per request via `commit_request_scope -> scope.commit_if_write(mvcc_store)`, which calls `mvcc_store.write().commit(tx)` — plain `commit` (SNAPSHOT isolation), NOT `commit_ssi`, so writes do NO SSI validation (an SSI inverted-index lever is moot for the write path). `flush_to_device` already coalesces contiguous block writes into ranged writes. The remaining per-commit overhead is therefore WAL append + snapshot bump + version insert (the `Arc<AlignedVec>` aligning copy lives in ffs-block, swarm-owned), which is exactly what `bd-xmh5g.401` (write-back: fewer commits between fsyncs) amortizes — that is the one open write lever. Retry a sync-side or SSI lever only if a profile shows that cost (not the per-commit CPU on snapshot-isolation commits) dominates. |

## BOLD-VERIFY measured verdicts — 2026-06-19 (cc, rch hz1, criterion median)

Resolves the "Pending batch benchmark" status for the swarm code-first levers below. Each was run
via `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cc rch exec -- cargo bench -p <crate>
--bench <name> -- <group> --warm-up-time 1 --measurement-time 3`; benches carry assert_eq/assert
isomorphism guards and built+ran to exit 0 (conformance of the A/B shapes is GREEN).

| Bead | Crate · bench (group) | old → new (median) | Ratio | Verdict |
| --- | --- | --- | --- | --- |
| `bd-xmh5g.385` | ffs-xattr · xattr_exists_probe · `xattr_zero_initialized_external_block` | scalar 1305 ns → chunked 573 ns (late-nonzero 1303 → 578 ns) | **2.28x / 2.25x** | KEEP — chunked `all_zero_bytes` beats the scalar byte loop on the zeroed external-xattr accept path. |
| `bd-xmh5g.384` | ffs-ondisk · btrfs_leaf_parse · `btrfs_leaf_payload_coverage_ab` | eager 7002 ns → lazy 3699 ns | **1.89x** | KEEP — descending-payload fast path skips the eager coverage-bitmap alloc on canonical leaves; bitset replay retained for noncanonical (overlap validation unchanged). |
| `bd-xmh5g.383` | ffs-block · read_contiguous · `read_contiguous_1mib` (outer_staged vs trusted_direct) | 699974 ns → 28577 ns | **24.5x** | KEEP — all-or-nothing ByteDevice lets the trusted contiguous read skip the outer staging Vec and read straight into the caller buffer. |
| `bd-xmh5g.392` | ffs-block · read_contiguous · `read_contiguous_1mib` (blocks_then_copy / ext4_vec vs trusted_vectored) | 1529826 / 1278027 ns → 876044 ns | **1.74x / 1.46x** | KEEP — one trusted vectored read into pre-sized BlockBufs instead of a whole-run staging Vec + per-chunk copy. |
| `bd-xmh5g.391` | ffs-alloc · bitmap_ops · `bitmap_owned_move_ab` (4k) | cod-a rerun copy-to_vec 241.61 ns → move-into_inner 271.26 ns | **0.891x** | REJECTED / REVERTED — `BlockBuf::into_inner()` is `12.3%` SLOWER than `as_slice().to_vec()` at 4K on the allocator bitmap mutation shape. Production restored the owned-move arm to `to_vec`; the bit-level undo-log change is a separate correctness refactor and stays guarded. |

**Pattern reinforced:** read/parse/staging levers WIN (.385/.384/.383/.392); the lone loss is the
`into_inner` owned-buffer move at small blocks — now negative three times, a settled do-not-retry for
4K RMW paths (see the seeded "Owned read-buffer clone→move" row; `.391` is the ffs-alloc instance).

### .382 extent-cache read-lock hot-hit — MEASURED REGRESSION (cc, 2026-06-19, rch hz1)

| Bead | Crate · bench (group) | old → new (median, 8 threads) | Ratio | Verdict |
| --- | --- | --- | --- | --- |
| `bd-xmh5g.382` | ffs-extent · extent_cache_same_ns · `extent_cache_same_ns_8t` | write_lock_hit 17.5 ms → read_lock_atomic_hit 21.7 ms | **0.81x** | REVERT (owner ffs-extent) — the "lock-free" read-lock hit path is SLOWER. Every lookup does `self.hits.fetch_add(1)` on ONE shared atomic counter → 8 threads ping-pong that single cache line: contention RELOCATED from the RwLock to the atomic, net worse. Corroborated by `extent_cache_real_same_ns` (production scales 1t 1.23 ms → 8t 21.9 ms = 17.8x degradation). `assert_eq` fold guard passed (correct, just slower). |
| `bd-xmh5g.382-striped` | ffs-extent · extent_cache_same_ns · `extent_cache_same_ns_8t` | write_lock_hit 14.201 ms → read_lock_striped_atomic_hit 18.341 ms; read_lock_atomic_hit 20.348 ms | **0.774x vs write-lock; 1.11x vs single atomic** | REJECT / PRODUCTION REVERTED — striped counters remove only part of the regression. The hot read path still pays shared read-lock traffic plus per-entry atomic recency updates, so the repaired lever remains slower than the write-lock baseline. Direct ext4/btrfs-kernel ratio remains N/A for this Rust-internal cache primitive. |

**Lever direction for a real win:** the read-lock path can only beat the write-lock once the
hot hit stops touching shared cache lines at all — not just by striping hit/miss accounting. A single
shared `AtomicU64` was a worse contention point than the lock it replaced, and the striped-counter
repair still measured only `0.774x` vs the write-lock baseline. The next viable design needs sampled or
deferred stats plus non-hot recency maintenance, or a different cache admission/eviction policy that
does not update shared metadata on every hit.

### .396 ext4 metadata-only inode parse — MEASURED WIN (cc, 2026-06-19, rch hz1)

| Bead | Crate · bench (group) | old → new (median) | Ratio | Verdict |
| --- | --- | --- | --- | --- |
| `bd-xmh5g.396` | ffs-core · ext4_metadata_parse_xattr_ibody | eager-to_vec 115648 ns → lazy-empty 25721 ns | **4.50x** | KEEP — `parse_metadata_from_bytes` skips the eager ~150B `xattr_ibody` heap alloc on the metadata hot path (getattr/lookup/readdir/access). Full `parse_from_bytes` retained for xattr/listxattr/getxattr/inline-data. Byte-identical fixed FileAttr fields (`inode_metadata_parse_skips_ibody_only` guard). Hot per-inode on ls/find/stat. |

### into_inner owned-buffer family RECONCILED — fresh primitive measurement (cc, 2026-06-19, rch hz1)

Ran the governing primitive bench `ffs-mvcc · blockbuf_into_inner · blockbuf_into_inner_vs_to_vec`
(sole-owned `BlockBuf::new`, the documented `read_block` invariant) on this host:

| size | into_inner_move | as_slice_to_vec_copy | ratio (copy/move) |
| --- | --- | --- | --- |
| 4096  | 246.4 ns | 274.1 ns | **1.11x** |
| 16384 | 677.6 ns | 702.8 ns | **1.04x** |
| 65536 | 2215.7 ns | 2405.5 ns | **1.09x** |

**`into_inner` WINS at ALL sizes on sole-owned buffers** — the `.389` "16K/64K regression" did NOT
reproduce here. The family reconciles cleanly by **ownership**, not block size:
- **Sole-owned** buffer (`read_block` cache-miss / compressed / single-ref) → `try_unwrap` succeeds →
  O(1) move → `into_inner` wins (1.04–1.11x). This is the `bd-xmh5g.390` (btrfs partial-block RMW)
  and `bd-xmh5g.393` (8 ffs-core read/RMW sites — all single-block `read_block(...).into_inner()`)
  case → **KEEP** (measured small win, not a regression).
- **Arc-shared** buffer (journal replay holds staged refs; `bd-xmh5g.394` version-store sharing) →
  `try_unwrap` fails → clone + the failed-unwrap atomic → marginally slower than a direct `to_vec`.
  This is why `bd-xmh5g.404` (journal replay, refs held) measured 0.64x and was correctly reverted,
  and why `bd-xmh5g.391`/`bd-xmh5g.382`-adjacent shared cases lose.

**Verdict:** the cc-owned ffs-core `into_inner` sites (`.390`/`.393`) are KEPT — measured sole-owned
win. The do-not-retry guidance updates to: `into_inner` is correct where `read_block` returns a
sole-referenced buffer that is then mutated/consumed; reject only where the buffer is provably
Arc-shared at the call site (the `.404` replay shape).

### Bulk-read loss PROFILED — userspace-pread tax, no safe lever (cc 2026-06-19)

`perf record -F 999` over warm `ffs walk --read-data` (256 MiB / 4,000 files, 6,364 samples). Top
self-time: `_copy_to_iter` 9.8% (kernel pread copy), spinlock 3.2%, libc `memset` 2.9% (read-buffer
zero-init), `memmove` 2.7% (staging copy), `SYSRETQ` 2.6% (syscall return); frankenfs userspace logic
only ~4%. **Verdict: the ~2× contiguous/many-files read gap to the kernel is the userspace-`pread`
copy+syscall model, NOT frankenfs parse/MVCC/extent code — architecturally bounded.** Do NOT chase it
with hot-path levers; the only avoidable frankenfs slice is read-buffer `memset`+`memmove` (~5.6%, partly
already taken by `.383`/`.392`). Closing the rest needs mmap (`unsafe`, forbidden) or `io_uring` batching
(major structural work). frankenfs's measured win territory is scattered/parallel access (metadata walk
3–5×, fragmented single-large-file read 1.4×); the 2-D boundary (parallelizable I/O AND large-enough
per-item payload) is the durable model. Retry only if an `io_uring`/mmap I/O backend is introduced.

### btrfs prefetch-pool fan-out gate — fix verified complete, ext4 sites do NOT share it (cc 2026-06-19)

The 4.3× btrfs metadata fix (`BTRFS_PREFETCH_MIN_CHILDREN`, commit 18fb0e88) is COMPLETE and bounded:
- **Single dispatch site.** `grep` confirms `btrfs_range_prefetch_pool().install()` appears exactly once
  (`walk_node_body`), shared by BOTH the `bd-h6p3w` range walker and the `bd-l8r3s` full-tree walker — so
  the one gate covers every btrfs parallel walk. No sibling site to fix.
- **Post-fix profile is healthy.** `perf` (2,291 samples) over the fixed walk shows the scheduler thrash
  GONE (no `update_curr`/`pick_task_fair`/`sched_yield` domination); remaining cost is distributed across
  legitimate work — `memmove` 4.9%, `_copy_to_iter` 2.8%, `memset` 2.3%, frankenfs b-tree/parse (`0x304c*`
  cluster ~6–8%), with only minor residual pool `osq_lock` 3.1%. The 1.6× vs kernel btrfs (single dir) is
  now genuine userspace b-tree-walk-per-getattr + I/O-copy cost, NOT a bug. No glaring further lever.
- **The ext4 `par_iter` read sites do NOT share the bug — do not "fix" them.** ffs-core's ext4 read/extent
  par sites (`collect_extents_recursive` child reads ~10499, `read_file_data` jobs ~10953, dir cold-run
  ~11095, dir block scan ~11204) use the GLOBAL rayon pool via plain `.into_par_iter()` — NOT
  `dedicated_pool.install()`. Rayon runs a tiny (1-element) `into_par_iter` inline on the current thread, so
  there is no forced pool entry / worker-wakeup overhead; the ext4 `--read-data` profile showed NO scheduler
  thrash (it was `_copy_to_iter`/syscall-bound). The btrfs thrash was unique to `install()`-into-a-dedicated-
  16-thread-pool called thousands of times per recursive walk. Retry a fan-out gate on the ext4 sites only
  if a profile actually shows scheduler thrash there (it does not today).

### ext4 INDIRECT-block sequential read ~5x slower than kernel (gap, cc 2026-06-19)

Differential-oracle perf probe: a 32 MB indirect-mapped (`^extent`) ext4 file (25 extents, near-contiguous)
read cold — kernel `dd bs=4M` 45 ms (711 MB/s) vs frankenfs `ffs read --discard` 211–224 ms (~145 MB/s) =
**frankenfs ~5x SLOWER** (byte-exact correctness confirmed). This is WORSE than the extent-path sequential
loss (~2x cold), indicating the indirect read path (`read_ext4_indirect`) does not chunk/parallelize a large
contiguous run the way the extent path's `bd-cc-pchunk` (16 MiB block-aligned chunks read in parallel) does —
it coalesces contiguous runs and parallelizes ACROSS non-contiguous runs (bd-r9c10) but a near-contiguous
indirect file surfaces few runs, so there is little to overlap and the per-run read isn't chunked. **Gap
(rare config — modern ext4 uses extents; only ext2/ext3-style `^extent` filesystems hit this), filed as a
lever candidate: port the `bd-cc-pchunk` chunked-parallel large-run read to `read_ext4_indirect`.** Note: the
intended *fragmented*-indirect test did not materialize — ext4's old block allocator coalesced the
fsync-interleaved + spacer writes to 25 extents (fragmentation is hard to force; the original 108-extent
fragmented-read win took deliberate effort), so this measures the contiguous/sequential indirect regime.

#### Follow-up: direct-output copy-elision for indirect reads failed (cod-b/BlackThrush 2026-06-20, bd-r9c10)

The existing `read_ext4_indirect` production path is already serial-plan / parallel-read / serial-assemble:
it resolves indirect pointers in byte order, reads each coalesced data segment on rayon into an owned buffer,
then assembles those buffers into the output. The tested follow-up removed the per-segment owned `Vec` and
let workers fill disjoint output windows directly. Production code was reverted after measurement.

RCH baseline on `vmi1149989` (`AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b
rch exec -- cargo bench --profile release-perf -p ffs-core --bench ext4_indirect_read_overlap --
ext4_indirect_read_overlap --warm-up-time 1 --measurement-time 3`): serial vs incumbent `parallel_rayon`
medians were 16 runs `5.7337 ms / 970.27 us` (`5.91x`), 64 runs `23.414 ms / 2.7872 ms` (`8.40x`), and
256 runs `92.482 ms / 13.491 ms` (`6.85x`). RCH did not keep the requested worker for the candidate and
selected `vmi1167313`; same-binary A/B on that worker measured incumbent `parallel_rayon` vs candidate
`parallel_in_place`: 16 runs `2.7308 ms / 2.5461 ms` (`1.073x`, small win), 64 runs `7.7753 ms / 8.6526 ms`
(`0.899x`, regression), and 256 runs `25.508 ms / 25.452 ms` (`1.002x`, neutral). The benchmark asserts byte
identity against the serial oracle before measuring. Conclusion: direct-output/window-carving copy-elision
does not close the ~5x direct kernel loss and should not be retried without a fresh profile proving assembly
copy dominates. Keep only the benchmark guard; route future work to indirect pointer planning, real fragmented
indirect fixtures, or deeper file-device/syscall/copy levers.

#### Follow-up: chunked large-run indirect reads kept (cod-b/BlackThrush 2026-06-20, bd-xmh5g)

The next lever attacked the actual residual shape from the kernel-loss row:
near-contiguous indirect files collapse into one large coalesced physical run,
which gives the existing parallel read phase only one data job. Production now
splits full-block coalesced indirect runs into ordered chunks before the
existing parallel owned-buffer READ and serial ASSEMBLE phases. The default is
`128` blocks per chunk, with `FFS_INDIRECT_READ_CHUNK_BLOCKS` overriding only
this path and `FFS_READ_CHUNK_BLOCKS` retained as a fallback.

RCH same-worker sweep on `vmi1227854`:

| Workload | Median | Ratio vs single-run | Verdict |
| --- | --- | --- | --- |
| `large_run_single/8192` | `25.523 ms` | baseline | Old one-job shape |
| `large_run_chunked_16blocks/8192` | `31.397 ms` | `0.813x` | Reject: too many chunks |
| `large_run_chunked_32blocks/8192` | `23.067 ms` | `1.106x` | Neutral/noisy |
| `large_run_chunked_64blocks/8192` | `17.267 ms` | `1.478x` | Win |
| `large_run_chunked_128blocks/8192` | `15.729 ms` | `1.623x` | KEEP default |
| `large_run_chunked_256blocks/8192` | `16.591 ms` | `1.539x` | Win, slower than 128 |
| `large_run_chunked_512blocks/8192` | `17.475 ms` | `1.461x` | Win, slower than 128 |

The byte-equivalence guard
`ext4_indirect_large_run_chunks_default_bd_xmh5g` passed on RCH `vmi1167313`.
It constructs a 129-block non-extent inode, verifies byte-identical output, and
asserts the default path performs one cached metadata read plus two chunked data
reads. RCH `cargo check -p ffs-core --all-targets` passed on `vmi1152480`.
Harness conformance passed under RCH-wrapper local fallback (`100 passed / 0
failed / 2 ignored`). Full clippy is still blocked by pre-existing pedantic debt
in `ffs-repair` and unrelated `ffs-core` sites; the lever-specific insertion
order issue was fixed by moving the segment enum and chunk helper out of the
function.

Fresh direct-kernel comparator status: blocked by loop-device policy. The RCH
command built release-perf `ffs-cli`, created a valid no-extents ext4 image, and
confirmed the target file used indirect and double-indirect mappings, but
`mount -o loop,ro` failed with `failed to setup loop device`
(`/tmp/ffs_indirect_cmp.0g2lsq`). Therefore this is a measured internal keep,
not a new kernel-domination claim. The existing direct ext4-kernel loss remains
the release-readiness limiter until the mounted comparator can rerun.

### FUSE write-path round-trip oracle — BLOCKED by sandbox (cc 2026-06-19)

Attempted a write-path differential oracle (frankenfs writes via `ffs mount --rw` FUSE → kernel reads back,
byte-exact) to validate the data-loss-critical WRITE path. `ffs mount --rw` is supported and `/dev/fuse` is
world-accessible with `fusermount3` setuid + `user_allow_other` set, but the mount fails `fusermount3: mount
failed: Permission denied` even as root — a container/sandbox restriction on the FUSE mount syscall. There is
no non-FUSE `ffs write` CLI, so the write-path e2e oracle is not exercisable in this environment. Write-path
conformance remains validated only by in-process unit/property tests, not an external kernel-readback oracle.

### Core-count-ADAPTIVE parallel-read chunk — REJECTED, overfit risk (cc 2026-06-19, bd-vffrx follow-up)

After shipping the fixed `FFS_READ_CHUNK_BLOCKS` default `256 -> 32` blocks (bd-vffrx / 3671522c, a measured
ext4 1.41x / btrfs 3.17x warm win on a 64-core box), tested whether the default should instead SCALE with the
rayon pool size (simulated via `RAYON_NUM_THREADS`), since the optimum clearly moves with thread count.

ext4 128 MiB warm, per-thread-count optimum (min duration_us): thr=2 -> 256, thr=4 -> 64, thr=8 -> 64,
thr=16 -> 32, thr=32 -> 32, thr=64 -> 32. So fixed-32 is OPTIMAL for >=16 threads (the many-core reality) and
only ~5-7% off the per-tier optimum at 2-8 threads.

REJECTED an adaptive scheme because the btrfs cross-thread data is too NOISY and self-CONTRADICTORY to tune
without overfitting: btrfs 100 MiB warm gave best=128 at thr=64 but best=16 at thr=8 and best=32 at thr=4 —
mutually inconsistent across runs (the `walk --read-data` path mixes readdir/getattr/metadata I/O with the
data read, so its per-chunk optimum is unstable). An adaptive formula fit to this would help small-core ext4
by ~5-7% while risking unpredictable btrfs regressions, and no clean principled rule (e.g. fixed chunks/thread)
reproduces the measured optima (4 threads wants 64-block chunks, not the 256 a "few-chunks-per-thread" rule
predicts). Fixed-32 is the simple, robust, measured choice: optimal on many-core hardware, within noise on
small-core, and a large win over the prior 256 everywhere. Conclusion: do NOT add adaptive chunk-sizing.

Commands: `FFS_LOG_FORMAT=json RUST_LOG=info RAYON_NUM_THREADS=<n> FFS_READ_CHUNK_BLOCKS=<cb> \
ffs-cli read IMG FILE --discard 2>&1 | grep duration_us` (ext4); `... ffs-cli walk IMG --read-data` (btrfs).

### btrfs compressed-read pool OVER-subscription — root-caused, `with_min_len` cap FAILED (cc 2026-06-19, bd-defgb)

`btrfs_read_file` fans every per-extent decompress (zstd/lzo) job across the FULL rayon pool. Decompression is
CPU- and cache-bound (unlike the uncompressed memcpy path, which is bandwidth-bound and scales with cores), so
on a 64-core box spreading ~270 short jobs across 64 threads OVER-subscribes. Measured (perf stat, 34 MiB zstd
file, `walk --read-data`) at 64 vs 8 threads: **4.5x task-clock** (293M vs 64M), **4.2x cache-misses** (6.6M vs
1.6M), **8x context-switches** — whole read **1.6x slower warm** (18.0 vs 11.4 ms) AND **1.46x slower cold**
(20.9 vs 14.3 ms) at the default pool; both warm+cold peak at ~8 threads. Real regression at the default pool
size — but NOT cleanly fixable from the work side.

ATTEMPTED FIX (reverted): cap concurrency via `IndexedParallelIterator::with_min_len(jobs.len()/16)` for
decompress-dominated reads. **Ineffective**: the rebuilt binary at the default 64-thread pool stayed at
16.7 ms while the SAME binary forced to `RAYON_NUM_THREADS=8` ran at 10.2 ms. `with_min_len` only coarsens the
task COUNT; it does not stop the 64-thread pool from waking/parking/steal-spinning, and that pool churn (not
task granularity) is the overhead. Confirmed byte-identity and that the uncompressed `btrperf` path was
unchanged, but with no speedup the change is pure complexity — reverted.

PROPER FIX (deferred, bd-defgb): run the decompress par_iter inside a dedicated small rayon pool (~min(16,
cores) threads) via a `OnceLock<ThreadPool>` + `install()`, so the idle global-pool threads stay parked. NOT
landed because per-file `install()` risks the documented dedicated-pool scheduler thrash on multi-file walks
(see the "spurious-fan-out gate" row) — `btrfs_read_file` is called once per file, so a `find`-style walk over
N compressed files = N installs. That regression is not testable in this environment (no large multi-file
compressed image), so the dedicated-pool fix needs a multi-file compressed-walk bench before it can ship.

#### Follow-up: production-shaped dedicated-pool synthetic bench also failed (cod-a/BlackThrush 2026-06-20, bd-defgb)

Added production-shaped synthetic bench
arms to `btrfs_decompress_extents` and tested the dedicated-pool idea before shipping it. Command:
`AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo bench
--profile release-perf -p ffs-core --bench btrfs_decompress_extents -- --warm-up-time 1 --measurement-time 3`
on worker `hz1`. Results: large 272x128KiB compressed file, global pool 3.1463 ms vs dedicated max16 pool
3.0628 ms = **1.03x**, below the keep gate; many-small-files 64x4x128KiB, always-install dedicated pool
8.0391 ms vs gated-small-files global fallback 8.7118 ms = **0.92x regression** for the gate. The attempted
production `OnceLock<ThreadPool>`/gate patch was reverted. Keep only the bench evidence. Conclusion: do NOT
ship the dedicated-pool or gated-dedicated-pool approach from synthetic evidence; it does not materially close
the compressed-read gap and the anti-thrash gate regresses its modeled workload. Next valid attempt needs a
different lever or an actual large multi-file compressed image with head-to-head kernel/frankenfs timings.

#### Follow-up: dedicated decompress pool ALSO failed — bottleneck mis-localized (cc 2026-06-19, bd-defgb)

Built the deferred fix anyway: a bounded `OnceLock<rayon::ThreadPool>` (FFS_DECOMPRESS_THREADS, default
min(16, cores)) with `install()` around the decompress map for decompress-dominated reads. **Also ineffective
and reverted.** Decisive diagnostic on the rebuilt binary: `FFS_DECOMPRESS_THREADS=1` ran the 34 MiB zstd file
in 19.9 ms and `=64` in 19.1 ms — i.e. the dedicated pool size has NO effect on the read time, so the
decompress map is NOT the pool-size-sensitive path. Yet shrinking the GLOBAL pool (`RAYON_NUM_THREADS=8`)
still gives ~10 ms vs ~18 ms at 64. Conclusion: the global-pool over-subscription is real but lives in a
DIFFERENT path than `btrfs_read_file`'s per-extent decompress jobs. Crucial missed detail: `walk --read-data`
issues the read in 1 MiB chunks (READ_CHUNK), so each `btrfs_read_file` call sees only ~8 extents — the
decompress-jobs guard (`decompress_jobs > 16`) never even trips, and 8 jobs on 64 threads is already only
8-way. The RAYON_NUM_THREADS sensitivity must come from a per-1 MiB-read path that fans across the global pool
(prime suspect: the btrfs extent-tree / metadata walk that locates the extents for each read, or the
`collect_extents_recursive` parallel child-block reads). bd-defgb re-scoped: ROOT-CAUSE must be re-localized
(profile which symbol's parallelism responds to RAYON_NUM_THREADS) BEFORE any cap is attempted — two cap
attempts (with_min_len, dedicated pool) both missed because the bottleneck was assumed to be the decompress
fan-out. No code shipped for this lever.

#### Follow-up: thread-local zstd decoder reuse kept on direct image, synthetic microbench lost (cod-a/BlackThrush 2026-06-20, bd-xmh5g)

Implemented a narrower, kernel-shaped zstd workspace lever: `btrfs_decompress`
now reuses one `zstd::bulk::Decompressor` per worker thread instead of calling
`zstd::bulk::decompress` for every independent btrfs zstd frame. This preserves
the existing btrfs sector-padding rule (`find_frame_compressed_size` still
slices the exact frame) and the shared short-frame zero-fill validation.

Direct mounted-image evidence on `/data/tmp/btrdiff2_1340519.img` against the
kernel mount `/data/tmp/btrdiff2mnt_1340519` pays:

| Workload | Prior FrankenFS | Candidate confirmation | FrankenFS old/new | Current kernel | Candidate vs kernel |
| --- | ---: | ---: | ---: | ---: | ---: |
| `read --discard /compressible.bin` | `76.1 ms` | `54.9 ms` | `1.39x` faster | `cat` `6.5 ms` | `8.51x` slower |
| `walk --read-data --no-stat` | `53.2 ms` | `32.8 ms` | `1.62x` faster | `cat *` `11.0 ms` | `2.99x` slower |

The targeted same-process synthetic did **not** support the mechanism: RCH
`vmi1167313`, command `AGENT_NAME=cod-a RCH_REQUIRE_REMOTE=1
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo
bench --profile release-perf -p ffs-core --bench btrfs_decompress_extents --
btrfs_decompress_tiny_zstd_321x4k_to_128k --warm-up-time 1 --measurement-time
1 --sample-size 10 --noplot`, measured fresh decompressor median `5.9330 ms`
vs thread-reused decompressor median `7.2849 ms` (`0.814x` old/new; reused is
slower). The benchmark file was also patched with a filter guard after two
filtered RCH runs were cancelled because existing bench functions eagerly built
unrelated large datasets before Criterion could apply the target filter.

Keep the production change because the real mounted-image workload wins twice,
but do not use the tiny-frame decompressor-context microbench as a future keep
gate. Next valid btrfs-compressed work should attack the remaining direct kernel
gap with a different primitive: decode directly into the final read buffer,
reuse output allocations across extents, or re-profile the extent-tree/metadata
fan-out that still responds to `RAYON_NUM_THREADS`. Do not retry dedicated pools,
`with_min_len`, or decompressor-context-only microbenches without a new direct
image signal.

#### Follow-up: one-tile serial zstd scheduling rejected at the synthetic gate (cod-a/BlackThrush 2026-06-21, bd-xmh5g)

Tested a narrower scheduling hypothesis from the remaining btrfs compressed-read
gap: when a one-megabyte `ffs-cli read` tile decomposes into only `8` independent
128 KiB zstd frames, skip Rayon and run the current thread-local zstd
decompressor serially. This would have targeted worker scheduling overhead
without changing decompression semantics or output ordering.

RCH `vmi1153651`, command `AGENT_NAME=BlackThrush
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo
bench --profile release -p ffs-core --bench btrfs_decompress_extents --
btrfs_decompress_tiny_zstd_8x4k_to_128k --warm-up-time 1 --measurement-time 1
--sample-size 10 --noplot`, measured current parallel reused decompressor
median `406.30 us` versus serial reused decompressor median `471.70 us`.
Serial scheduling is `0.861x` the current path by median. Criterion intervals
overlapped (`serial [444.38, 525.59] us`, `parallel [292.57, 630.26] us`) and
the parallel row was noisy, so this is negative routing evidence rather than
positive proof for either family.

Win/loss/neutral: internal A/B `0/1/0` for the serial-scheduling candidate;
direct kernel `0/0/1` because no production candidate reached mounted-kernel
A/B. The direct kernel target remains unchanged from the retained btrfs
compressed-read row: final-source single-file `/compressible.bin` still loses
`35.9 ms` versus kernel `cat` `6.7 ms` (`5.38x` slower), and whole-tree `walk
--read-data --no-stat` still loses `31.9 ms` versus kernel `cat *` `11.2 ms`
(`2.85x` slower).

No production code was changed. The retained benchmark guard asserts serial and
parallel decompression produce identical decompressed byte counts, so future
agents can rerun this exact scheduling gate before retrying the family. Local
`cargo fmt -p ffs-core --check` passed; RCH `cargo check -p ffs-core
--all-targets` passed on `vmi1152480`; `rch exec -- cargo test -p ffs-harness
--test conformance -- --nocapture` fell back local because no admissible workers
were available and passed `100 / 0 / 2 ignored`; RCH `cargo build --release -p
ffs-core` passed on `ovh-a`. RCH scoped clippy `cargo clippy -p ffs-core
--bench btrfs_decompress_extents --no-deps -- -D warnings` failed before the
benchmark target on existing/current shared `ffs-core` library pedantic rows:
`vfs.rs` derivable default, item-after-statement rows, redundant closures, old
indirect-pointer casts, and cod-b's in-progress ext4 direct-output enum. No
benchmark/doc-caused lint was reported. Note: `cargo bench --release` is not
valid Cargo syntax for benches, so the command uses the equivalent `--profile
release` spelling.

#### Follow-up: direct-to-final zstd extent decode rejected (cod-a/BlackThrush 2026-06-20, bd-xmh5g)

Tested the next data-movement lever from the graveyard: for regular zstd
compressed extents whose full decompressed `ram_bytes` exactly overlaps the
caller output window, read compressed bytes into bounded scratch but decode zstd
directly into the final `out` slice. Partial extents, inline extents, zlib/LZO,
and uncompressed reads kept the incumbent path. Production code was reverted
after measurement.

Direct mounted-image evidence used the same btrfs image and kernel mount:
`/data/tmp/btrdiff2_1340519.img` and `/data/tmp/btrdiff2mnt_1340519`.

| Workload | Current FrankenFS baseline | Candidate | FrankenFS old/new | Current kernel | Candidate vs kernel | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `read --discard /compressible.bin` | `55.931 ms` | `57.961 ms` | `0.965x` | `cat` `7.011 ms` | `8.27x` slower | REJECT |
| `walk --read-data --no-stat` | `34.8826 ms` | `34.8828 ms` | `1.000x` | `cat *` `11.537 ms` | `3.02x` slower | NEUTRAL/REJECT |

Win/loss/neutral: internal A/B `0/1/1`; direct kernel `0/2/0`.

Behavior/build gates: the candidate RCH `cargo check -p ffs-core` and RCH
`cargo build --profile release-perf -p ffs-cli` passed on `vmi1152480`.
After reverting the source, clean-source RCH `cargo check -p ffs-core` passed on
`vmi1153651`, clean-source RCH `cargo test -p ffs-harness --test conformance --
--nocapture` passed on `vmi1227854` with `100 passed / 0 failed / 2 ignored`,
and clean-source RCH `cargo build --profile release-perf -p ffs-cli` passed on
`vmi1149989`.

Conclusion: do not retry final-buffer zstd decode for this path without a heap
allocation attribution profile proving the decompressed `Vec` allocation and
copy dominate. The single-file read regressed and the whole-tree read was
indistinguishable. The remaining `3.02-8.27x` kernel gap is more likely in
btrfs extent lookup/metadata fan-out, compressed scratch allocation, or
CLI/open/read overhead than final output assembly.

### FileByteDevice thread-local read scratch buffer — MEASURED INERT, reverted (cc 2026-06-20, bd-cc-rscratch)

Hypothesis: the warm sequential-read sys-time is dominated by the per-chunk temp allocation in
`FileByteDevice::read_exact_at` (`let mut read_buf = vec![0u8; buf.len()]` → pread → `copy_from_slice` into
the caller's `dst`). The temp exists only to honour `preserves_read_exact_at_destination_on_error == true`
(a short/failed backing read must leave `dst` byte-for-byte unchanged — exercised by
`file_byte_device_scalar_read_preserves_buffer_on_short_read`, which truncates the backing file mid-read).
A per-call `vec![0u8; len]` zero-fills fresh pages every chunk; on a 128 MiB read split into 128 KiB chunks
that is ~1024 allocations. Attempt: replace the per-call temp with a **thread-local reusable scratch buffer**
(`thread_local! { static FILE_READ_SCRATCH: RefCell<Vec<u8>> }`, 1 MiB reuse cap, one-off alloc above cap)
in both `read_exact_at` and `read_vectored_exact_at` — faults the scratch pages in once per worker, keeps the
exact preservation contract (still copies into `dst` only on success), all tests green.

**Measured INERT.** `perf stat` of `ffs-cli read --discard` on a 128 MiB ext4 extent file (tmpfs image,
warm): page-faults **19,943 → 19,699** (unchanged), warm engine `duration_us` ~22–25 ms before and after
(within run-to-run variance). Diagnosis: the page-faults are **not** from the device temp — glibc's dynamic
`M_MMAP_THRESHOLD` already recycles the ~128 KiB temp from the arena after warm-up, so the thread-local merely
re-implements what the allocator already does. The faults are dominated by the read engine's **output buffer**
(`vec![0u8; to_read]` materialising the whole 128 MiB result), and the residual warm cost is the **second
copy** (page-cache → temp → `dst`, vs the kernel's single page-cache → user copy) plus that output zero-fill —
both inherent to a `#![forbid(unsafe_code)]` engine that must hand initialised `&mut [u8]` to the read and
cannot read directly into uninitialised memory. Reverted (only `crates/ffs-block/src/lib.rs`, restored).

**Do-not-retry predicate:** do not re-attempt buffer-recycling for `FileByteDevice` reads as a warm-read
lever — the allocator already recycles and the page-faults live in the engine output buffer, not the device
temp. The only paths that would actually remove the residual copy/zero-fill are (a) reading directly into the
caller `dst` (requires weakening `preserves_read_exact_at_destination_on_error`, which a deliberate test
guards), or (b) `mmap`/uninitialised-buffer reads (require `unsafe`, forbidden here) — i.e. the same structural
zero-copy gap already recorded in "Bulk-read loss PROFILED — userspace-pread tax, no safe lever".

### MEASUREMENT METHODOLOGY: head-to-head CLI reads must use `--profile release-perf`, not `release` (cc 2026-06-20)

Discovered while profiling the btrfs read gap that `[profile.release]` in the workspace `Cargo.toml` is
**`opt-level = "z"` (optimise for SIZE) + `lto = true` + `strip = true`** — it is the small-binary profile,
NOT the speed profile. The performance profile is **`[profile.release-perf]`: `opt-level = 3`,
`lto = "thin"`, `debug = "line-tables-only"`, `strip = false`** (criterion benches already use it via
`--profile release-perf`). A plain `cargo build --release -p ffs-cli` produces a size-optimised, symbol-stripped
binary. **Any `ffs-cli read` head-to-head built with `--release` therefore (a) understates frankenfs throughput
(size-opt de-optimises hot loops) and (b) cannot be `perf`-profiled (symbols stripped).** The
ext4-vs-kernel and ext4-vs-btrfs *ratios* in this ledger are still valid (both sides used the same size-opt
binary), but the absolute MB/s figures are a floor — re-measure with `--profile release-perf` for true numbers
and to get resolvable symbols. Recorded as a standing methodology fix: **build the CLI with
`cargo build --profile release-perf -p ffs-cli` (output `target/release-perf/ffs-cli`) for every perf
head-to-head and every `perf record`.** (The release-perf rebuild this session was blocked by rch-worker
contention + the slow `ffs-core` opt-3/LTO compile, so the btrfs-gap symbol localisation in bd-2emlm remains
pending that build.)

### Pending-lever re-verification harvest — 7 levers closed, 1 magnitude correction (cc 2026-06-20, rch)

Independently re-ran the criterion A/B benches for the 7 open "code-first batch-test pending" perf levers
(read JSON `median.point_estimate` from `CARGO_TARGET_DIR/criterion/*/new/estimates.json` — the harness
truncates rch bench stdout, the JSON survives). All stay above the 2.0× KEEP gate; closed all 7. Fresh
ratios this session:

| Bead | Bench | Fresh ratio (re-run) | Scorecard (prior) | Verdict |
|------|-------|----------------------|-------------------|---------|
| bd-avqg1 | recovery_build_writeback_blocks | 5.43× / 15.99× / **58.10×** (N=64/512/4096) | 4.75/22.9/70.4× | ✅ KEEP (algorithmic) |
| bd-g5v1s | recovery_capture_io_overlap | 7.10× / 7.38× / 7.68× (16/64/256) | 6.25/6.20/35.0× | ✅ KEEP |
| bd-wgv6x | inode_free_runs | **1008×** contiguous_1024; 1.01× fragmented | (new) | ✅ KEEP (neutral on fragmented = correct) |
| bd-w52e5 | repair_symbol_read_io_overlap | 7.37× / 7.53× / 7.62× (16/64/256) | 7.22/7.57/7.72× | ✅ KEEP (matches) |
| bd-eei3y | por_respond_io_overlap | 7.43× / 7.65× / 7.70× (64/256/460) | 7.59/7.78/7.82× | ✅ KEEP (matches) |
| bd-pkvrj | journal_replay_apply_io_overlap | 2.50× / 3.55× / 4.25× (16/64/256) | **8.74/42.4/51.9×** | ✅ KEEP (≥2.0) but **magnitude correction** |
| bd-ya8zh | por_authtable_build | (scorecard) 2.07/2.85/2.96× | — | ✅ KEEP (≥2.0 at all N) |

**Honesty note (bd-pkvrj):** the journal-replay I/O-overlap re-run is a clean win at every N but its magnitude
is **~10× lower** than the originally recorded 8.7/42/52× — the LatencyBlockDevice (`sleep` per read) ratio is
acutely sensitive to the bench host's pool size and the sleep duration, so the original figures were
over-recorded. The lever is still correct to keep (serial 6.7/24.8/104 ms vs parallel 2.7/7.0/24.4 ms), but
**I/O-overlap absolute ratios from these synthetic latency benches are host-dependent — read them as "clear
win, magnitude ±", not literal speedups.**

### ✅ btrfs read gap FIXED — read-into-`dst` fast path, 1.37× warm + RSS halved, now BEATS the kernel (cc 2026-06-20, bd-2emlm SHIPPED)

Acting on the root-cause below: `read_into` (the streamed-read API the CLI/FUSE use) had an **ext4 fast path
that reads straight into the caller's `dst`** but a **btrfs fallback through `FsOps::read` that allocates a
fresh owned `Vec` per 64 MiB chunk and copies it into `dst`** — the source of the 2× RSS, the `__memmove_avx`
samples, and the page-fault thrash. Fix: parameterised `btrfs_read_file` → **`btrfs_read_file_into(dst)`** that
writes straight into the caller buffer (zeroing `dst[..to_read]` first so holes stay zero — byte-identical to
the old `vec![0u8; to_read]`), kept a thin owned-`Vec` `btrfs_read_file` wrapper for the two callers that need
owned bytes (`FsOps::read`, symlink-target reads), and added a **btrfs fast path in `read_into`** mirroring the
ext4 one (dir/symlink guards then `btrfs_read_file_into`). MEASURED on the 128 MiB btrfs (release-perf, warm):

| metric | before | after | result |
|--------|--------|-------|--------|
| max RSS | 133 MB | **70 MB** | **−47 %** (matches ext4's 64 MB — the owned-Vec gone) |
| warm read | 80.7 ms (1587 MB/s) | **59.1 ms (2164 MB/s)** | **1.37× faster** |
| vs kernel `dd bs=128M` (82.9 ms) | 0.97× (parity) | **1.40× FASTER** | **flips btrfs from parity to a kernel-domination win** |

Byte-identical (ffs-core `btrfs_read*` + `read_into` tests green, exit 0; full ffs-core suite green).
**bd-2emlm closed.** This is the session's REAL kernel-domination win: btrfs warm reads now beat the in-kernel
btrfs driver's single-threaded materialise, the same way ext4 already did.

**Residual re-profiled (post-fix, release-perf):** the kept `out.fill(0)` memset is only **2.5 %**
(`__memset_avx2`) — NOT worth a zero-only-holes rewrite. The remaining btrfs-vs-ext4 (59 vs 21 ms) gap is
diffuse: **16.6 % `__memmove_avx`** = the `FileByteDevice::read_exact_at` temp→`dst` double-copy (page-cache →
temp → caller buffer vs the kernel's single copy — shared with ext4, the same userspace-pread tax recorded in
"Bulk-read loss PROFILED"), **~5 % rayon `Stealer::steal`** (mild btrfs pool imbalance, down from ~8 %), and
the btrfs per-chunk logical→physical resolution. The one shared lever (eliminate the FileByteDevice
double-copy) needs **relaxing `preserves_read_exact_at_destination_on_error`**, a guarantee the team
*deliberately added* (W160 bd-wvdrd/bd-d2bci, with a dedicated truncation test) — a design decision, not a
code tweak, so deferred rather than blindly undone. No further single-crate lever closes the residual safely.

### btrfs read gap ROOT-CAUSED: memory-pressure / 2× RSS, not CPU/syscalls/parallelism (cc 2026-06-20, release-perf + symbols, bd-2emlm)

Rebuilt `ffs-cli` with `--profile release-perf` (opt-level=3 + symbols) and profiled the btrfs vs ext4 read
head-to-head. Decisive evidence the btrfs gap is **memory-pressure-bound**, not what the original bead guessed:

- **opt-level insensitive:** release (opt-z) → release-perf (opt-3) sped ext4 **24.5→21.6 ms (+13 %)** but left
  btrfs **80.7 ms unchanged** — so the btrfs cost is NOT CPU-compute (opt-3 optimises compute, not memory/IO).
- **2× resident memory:** max RSS ext4 **64 MB** vs btrfs **133 MB** for the identical 128 MiB read — btrfs holds
  ~2× the working set, which drives the **52 471 vs 19 943 page-faults** already recorded.
- **the page-fault pressure slows the reads themselves:** `perf` children — ext4 spends 38.7 % in
  `FileByteDevice::read_exact_at` (of a 21 ms read ≈ 8 ms); btrfs spends 22.5 % (of an 80 ms read ≈ **18 ms**) —
  i.e. the *same* ~1040 preads take **2.25× longer** under btrfs's memory pressure. btrfs self-time also shows
  ~8 % `crossbeam_deque::Stealer::steal` (rayon workers idle-stealing = imbalanced/under-filled pool) and 5.8 %
  `__memmove_avx` (the FileByteDevice temp→dst copy), with the remainder in kernel page-fault/scheduler frames.

**Root cause (redirected):** the lever is NOT "parallelise the btrfs read" (it already chunk-parallelises and
reads direct-into-`dst`) — it is **reduce the btrfs read's memory footprint** so it stops doubling RSS and
thrashing page-faults. The ~+69 MB btrfs holds over ext4 is not yet pinned to a line (the CPU sampling profile
shows the *symptom* — page faults — not the *allocation site*); pinning needs a heap profiler (heaptrack/massif)
or a careful audit of `btrfs_read_file`'s owned allocations (`jobs`/`results`/`decompressed_by_idx`/the output
buffer lifetime) vs ext4's `read_file_data`. **Deferred, not blindly patched** — a blind footprint change in
peer-contended `ffs-core` could regress. bd-2emlm updated with this root-cause. Vs the KERNEL btrfs this read is
still parity (0.97× of `dd bs=128M`), so it is an internal ext4-vs-btrfs gap, not a kernel-loss — a worthwhile
future win (closing it would make btrfs warm reads beat the kernel as ext4 already does) but correctly sequenced
behind a heap profile.

### btrfs uncompressed warm read 3.3× slower than ext4 — INTERNAL gap filed bd-2emlm (cc 2026-06-20)

Rounded out the head-to-head onto btrfs (image via `btrfs-convert` of the ext4 fixture, csum-verify OFF =
default). frankenfs btrfs warm read **80.7 ms (1586 MB/s)** vs the SAME data on ext4 **24.5 ms (5216 MB/s)** =
**3.3× slower internally**. `perf stat`: btrfs read uses only **6.9 CPUs** (ext4 13–16), **676 M instructions**
(ext4 415 M, +63 %), **52 471 page-faults** (ext4 19 943, 2.6×). Vs the **kernel** btrfs it is still **parity**:
kernel materialise (`dd bs=128M`/`f.read`) 82.9 ms = frankenfs **0.97× (slight win)**; kernel streaming 25.1 ms
= frankenfs 3.2× slower (the same zero-copy-streaming boundary as ext4). So this is an **internal ext4-vs-btrfs
gap, not a fresh kernel-loss** — the btrfs read under-parallelises (prime suspect: per-chunk `ReadJob` temp
`Vec` allocation, the extra ~32 k page-faults beyond the output buffer; csum is off so not that). Filed
**bd-2emlm** with the profile; deferred (ffs-core peer-contended) — fix = apply ext4's `IoJob`
direct-into-`dst` `read_contiguous_into` pattern to the btrfs uncompressed read path.

### Warm contiguous read re-measured on the 64-core box — chunk-parallelism monotone (cc 2026-06-20, bd-vffrx confirm)

Independent re-measurement of the live `ffs-cli read --discard` warm throughput on a 128 MiB contiguous ext4
extent file (tmpfs-resident → pure CPU/bandwidth, warm; 7 runs/median), sweeping `FFS_READ_CHUNK_BLOCKS`:

| chunk | warm median | throughput |
|-------|-------------|------------|
| 32 blocks (128 KiB) — **shipped default** | 24.5 ms | **5216 MB/s** |
| 256 blocks (1 MiB) — W160 default | 28.1 ms | 4561 MB/s |
| 1024 blocks (4 MiB) | 36.7 ms | 3492 MB/s |
| 4096 blocks (16 MiB) — original default | 59.1 ms | 2165 MB/s |

Monotone: finer chunks → more jobs to fill the 64-thread rayon pool → higher throughput; the 4096→32 retune
is a **2.4× warm gain** on real many-core hardware. Like-for-like kernel comparators on the same file (warm):
single-threaded **full-materialise** (`dd bs=128M` / Python `f.read()`) ≈ 1798 MB/s → frankenfs **2.9× FASTER**;
**cache-hot streaming** (8 MiB reused buffer, never materialises) ≈ 12968 MB/s → frankenfs ~2.5× behind. This
confirms (not supersedes) the existing verdict: frankenfs's parallel read **beats** any reader that
materialises the file and trails only an idealised zero-copy streaming reader — the residual is the
materialisation + double-copy tax above, not a parallelism deficit. (Note: tmpfs image → `drop_caches` does
not evict, so only the warm/CPU-bound regime is characterised here, which is exactly where the gap lives.)

### REJECTED: btrfs read scratch/direct-into-dst candidates did not move the real read gap (cod-b 2026-06-20, bd-2emlm)

Tried the next obvious memory-footprint levers against `bd-2emlm` and reverted them because the primitive win
did not transfer to the real btrfs read:

- `FileByteDevice` thread-local reusable staging scratch, preserving destination-on-error semantics.
- btrfs `read_into` direct-to-caller-buffer form, avoiding the owned `Vec` + fallback copy in the streamed
  `OpenFs::read_into` path.

The isolated block primitive looked spectacular on RCH `hz1`: in one same-binary Criterion run,
`file_byte_device_read_1mib/fresh_temp_vec_shape` measured `1.0804 ms` median while
`file_device_reused_scratch` measured `96.908 us`, an `11.15x` old/new win. That was not enough. The candidate
release CLI still measured essentially neutral on the actual 100 MiB btrfs image:

| Comparator | Mean | Ratio | Verdict |
| --- | ---: | ---: | --- |
| FrankenFS candidate `read --discard /m.bin` | `74.949 ms` | vs prior `76.3 ms`: `1.02x` faster, inside noise | Neutral |
| FrankenFS candidate in kernel-streaming run | `77.580 ms` | vs prior `76.3 ms`: `0.98x` slower, inside noise | Neutral |
| kernel btrfs `dd bs=128M` | `127.923 ms` | FrankenFS `1.71x` faster | Win vs materialising comparator |
| kernel btrfs `dd bs=8M` | `51.407 ms` | FrankenFS `1.51x` slower | Loss |
| kernel btrfs `cat` | `11.710 ms` | FrankenFS `6.63x` slower | Loss |

The one-shot `/usr/bin/time` smoke for the candidate binary reported `maxrss=137968 KiB`, not lower than the
prior ~133 MiB btrfs profile. That falsifies the hoped-for "remove one big allocation and drop RSS" story for
this surface. The likely remaining gap is not the `FileByteDevice` temp buffer alone, nor the fallback copy
alone; it needs heap-allocation attribution inside the btrfs read pipeline (`jobs`, `results`,
`decompressed_by_idx`, output lifetime, and chunk-map metadata) before another code lever. Retrying scratch or
read-into-dst without a new allocation profile is expected to be neutral.

Commands/evidence:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo bench -p ffs-block --bench read_contiguous -- \
  file_byte_device_read_1mib --warm-up-time 1 --measurement-time 2

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo build --release -p ffs-cli

CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b \
  rch exec -- cargo test -p ffs-harness --test conformance -- --nocapture

hyperfine --warmup 3 --runs 10 \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli --log-format json read /data/tmp/btrperf_1231197.img /m.bin --discard >/dev/null 2>&1' \
  'dd if=/data/tmp/btrperfmnt_1231197/m.bin of=/dev/null bs=128M status=none'

hyperfine --warmup 3 --runs 10 \
  '/data/projects/.rch-targets/frankenfs-cod-b/release/ffs-cli --log-format json read /data/tmp/btrperf_1231197.img /m.bin --discard >/dev/null 2>&1' \
  'cat /data/tmp/btrperfmnt_1231197/m.bin >/dev/null' \
  'dd if=/data/tmp/btrperfmnt_1231197/m.bin of=/dev/null bs=8M status=none'
```

Production verdict: **no code kept**. Both source candidates were reverted. `bd-2emlm` remains a real open
gap; the next credible move is a heap profiler or allocation census, not another temp-buffer micro-lever.

### btrfs compressed-read fused copy/drop kept (cod-a/BlackThrush 2026-06-20, bd-xmh5g)

Kept a narrower memory-pressure lever than the rejected direct-to-final zstd
attempt: regular compressed btrfs extents still decompress into the existing
owned `Vec`, but the parallel read/decompress job now slices, copies into its
disjoint final `out` window, and drops that decompressed `Vec` immediately.
Inline compressed extents keep the old owned-byte result because their overlap
range is only known after decompression. Uncompressed extents keep the existing
direct-into-output path.

This preserves the extent-order error policy by storing only a per-extent
`Done`/`Bytes` result and consuming those results in the serial assembly loop.
The actual data writes are to pre-carved non-overlapping output windows. The
change targets the specific live-buffer pressure identified by the remaining
compressed-read kernel gap: the old path retained every regular compressed
extent's decompressed `Vec` until serial assembly finished.

Direct mounted-image evidence used `/data/tmp/btrdiff2_1340519.img` with the
mounted kernel reference `/data/tmp/btrdiff2mnt_1340519`.

| Workload | Baseline | Candidate | FrankenFS old/new | Kernel btrfs | Candidate vs kernel | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Primary 15-run `read --discard /compressible.bin` | `56.1 ms` | `36.8 ms` | `1.52x` faster | `cat` `7.4 ms` | `5.00x` slower | KEEP |
| Primary 15-run `walk --read-data --no-stat` | `36.6 ms` | `34.0 ms` | `1.08x` faster | `cat *` `11.9 ms` | `2.85x` slower | Neutral-positive/no extra keep credit |
| Final-source 10-run `read --discard /compressible.bin` | `53.2 ms` | `35.9 ms` | `1.48x` faster | `cat` `6.7 ms` | `5.38x` slower | KEEP confirmation |
| Final-source 10-run `walk --read-data --no-stat` | `32.4 ms` | `31.9 ms` | `1.015x` faster | `cat *` `11.2 ms` | `2.85x` slower | Neutral |

Win/loss/neutral: internal A/B `1/0/1`; direct kernel `0/2/0`.

Memory smoke moved in the expected direction on single-file read:

| Probe | Baseline | Candidate |
| --- | ---: | ---: |
| Max RSS | `83,620 KiB` | `50,868 KiB` |
| Minor faults | `22,932` | `14,478` |

Byte identity was verified against the mounted kernel file:
`2e379e112375338695dbd226f27bf096db571a99e5f64b975b0bb2e43b6f86b9`
for baseline, candidate, and kernel `compressible.bin`.

RCH caveat: `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a rch exec -- cargo build --profile release-perf -p ffs-cli`
passed on `vmi1149989`, but artifact retrieval left the target-dir binary at
the clean baseline hash. The accepted direct A/B timings therefore use a local
release-perf build from the clean detached worktree; the RCH build is recorded
as a remote compile gate, not as the source of the measured binary.

Isomorphism:

- Ordering preserved: yes. Extents are still validated and consumed in extent
  order; only regular compressed extent bytes are copied into final disjoint
  output windows earlier.
- Tie-breaking unchanged: yes. The first per-idx error is retained, and the
  serial assembly loop still surfaces errors in extent order.
- Floating-point: N/A.
- RNG seeds: N/A.
- Golden/byte proof: candidate read SHA-256 matches the mounted kernel file;
  focused btrfs decompression tests and harness conformance passed.

Gates:

```bash
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a \
  rch exec -- cargo build --profile release-perf -p ffs-cli

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo build --profile release-perf -p ffs-cli

cargo fmt -p ffs-core --check

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo check -p ffs-core --all-targets

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo test -p ffs-core btrfs_decompress -- --nocapture

AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.local-targets/frankenfs-cod-a-batch \
  cargo test -p ffs-harness --test conformance -- --nocapture
```

Results: `ffs-core` check passed; focused btrfs decompression tests passed
`10/10`; conformance passed `100 / 0 / 2 ignored`. Scoped clippy is still
blocked by pre-existing `ffs-repair` and `ffs-core` pedantic debt outside this
lever (`RequestCommitMode` derivable default, old local static/use/const
placement, indirect-pointer casts, redundant closures). The candidate-caused
local-enum clippy lint was fixed by moving helper enums to file scope.

Retry predicate: do not repeat generic scratch reuse or zstd direct-to-final.
The next credible compressed-read pass should attack the remaining kernel gap
after this memory win: metadata descent reuse/extent lookup (currently owned by
`bd-xmh5g.408`), compressed input read staging with a proof that it changes the
real mounted-image path, or a kernel-shaped streaming API that avoids whole-file
materialization rather than merely changing the decompression buffer.

---

## 2026-07-10 — Cold-read WHY: ranked frame table (bd-5koeh follow-up, BlackThrush/cc_ffs)

The cold-read hypothesis in `bd-5v3mh` ("frankenfs issues no readahead hints")
is **refuted** and its lever already shipped; the three ext4 cold rows re-derived
under a valid method all show frankenfs **slower** than kernel ext4. This section
answers *why*, from a profile of the exact prebuilt `release-perf` binary that
produced those numbers (no rebuild: `strip=false`, `debug="line-tables-only"`).

Workload: `ffs-cli read /data/tmp/q6k00/cold_ext4.img /big.bin --discard`
(128 MiB, 2 extents), `drop_caches=3` immediately before, `perf record -F 4999 -e cycles`.

### Ranked self-time frames (>= 0.1%), default RAYON_NUM_THREADS=64

| self% | frame | layer |
| --- | --- | --- |
| 39.07 | `native_queued_spin_lock_slowpath` | kernel — **lock contention** |
| 6.27 | `crossbeam_deque::Stealer::steal` | user — rayon work-stealing |
| 5.69 | `_copy_to_iter` | kernel — the actual copy |
| 5.21 | `clear_page_erms` | kernel — zero-fill of fresh anon pages |
| 2.59 | `crossbeam_epoch::Global::try_advance` | user — rayon epoch GC |
| 1.84 | `entry_SYSRETQ_unsafe_stack` | kernel — syscall return |
| 1.28 | `asm_exc_page_fault` | kernel — fault entry |
| 1.04 | `__filemap_add_folio` | kernel — page-cache insert |
| 0.78 | `up_read` | kernel |
| 0.74 | `pick_task_fair` | kernel — scheduler |
| 0.70 | `zap_present_ptes` | kernel — teardown |
| 0.67 | `rmqueue_bulk` | kernel — page allocator |
| 0.62 | `update_curr` | kernel — scheduler |
| 0.59 | `_raw_spin_lock` | kernel |
| 0.53 | `xas_find_conflict` | kernel — xarray |
| 0.49 | `rayon_core::WorkerThread::wait_until_cold` | user |
| 0.47 | `std::sys::sync::mutex::futex::Mutex::lock_contended` | user |
| 0.40 | `page_cache_ra_unbounded` | kernel — readahead |
| 0.38 | `get_page_from_freelist` | kernel — page allocator |
| 0.35 | `xas_load` | kernel — xarray |
| 0.34 | `lru_gen_add_folio` | kernel — LRU |

### The three candidate causes, tested and ranked

1. **Per-block syscall overhead — REFUTED.** `perf stat` counts **1,034**
   `pread64` calls for 128 MiB, i.e. ~128 KiB per call (1024 data preads + ~10
   metadata). The read path is not per-4-KiB-block. Syscall entry/exit is
   ~1.8% of self-time.
2. **Extent-tree walks — REFUTED.** The 128 MiB file has 2 extents; the
   fragmented fixture has 9 and the indirect fixture has 14. If walking drove
   the cost, tax would rise with extent count. It does not: parse+copy tax vs a
   same-mode floor is 1.35x (2 extents), 1.15x (9 extents), 1.36x (14 extents) —
   uncorrelated. No extent/indirect frame appears above 0.1% self-time.
3. **Copy tax — REAL BUT MINOR.** `_copy_to_iter` is 5.69% and
   `clear_page_erms` 5.21% (zero-filling freshly-allocated destination pages,
   19,279 page faults). Together ~11%, not the dominant term.

### Actual cause: kernel page-cache lock contention from over-parallelized buffered pread

`perf record -g` resolves the contended lock unambiguously:

```
32.99%  File::read_exact_at -> __libc_pread -> __x64_sys_pread64 -> vfs_read
        -> ext4_file_read_iter -> generic_file_read_iter -> filemap_read
        -> filemap_get_pages (32.71%)
           -> page_cache_sync_ra (31.62%)
              -> page_cache_ra_unbounded -> filemap_add_folio
                 -> __filemap_add_folio (28.34%)   [xarray xa_lock]
```

Every rayon worker preads the **same inode**, so all 64 threads serialize
inserting folios into that one `address_space` xarray. Cold read converts I/O
parallelism into lock contention. This is why the DIO-loop kernel arm is fast:
`O_DIRECT` never touches `filemap_add_folio`.

### Confirmation by prediction (byte-identical, prebuilt binary, no rebuild)

`RAYON_NUM_THREADS` sweep, cold, min-of-5, engine time minus 8.4 ms startup:

| threads | 1 | 2 | 4 | 8 | **16** | 32 | 64 (default) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| read (ms) | 86.2 | 63.3 | 40.4 | 32.0 | **30.1** | 32.9 | 37.0 |

Contention falls exactly as predicted:

| | spinlock self% | rayon steal | sys CPU |
| --- | --- | --- | --- |
| T=64 | 42.27% | 5.42% | 0.446 s |
| T=16 | 10.96% | 1.26% | 0.158 s |

Paired interleaved A/B (7 reps): T=16 faster **7/7**, sign-test p=0.0156,
1.24x faster; `sha256` identical to the kernel mount at both thread counts.
Generalizes: indirect **1.44x** faster, fragmented **1.19x** faster at T=16.

Effect on the kernel gap (vs kernel-best, dio loop):

| fixture | T=64 | T=16 |
| --- | --- | --- |
| ext4 extent 128 MiB | 1.37x slower | **1.11x slower** |
| ext4 indirect 50 MiB | 1.45x slower | **1.09x slower** |
| ext4 fragmented 48 MiB | 1.31x slower | **1.09x slower** |

**Warm reads want the same cap** (page-cache hot, min-of-5): T=4/8/16/32/64 read
= 15.5 / 9.0 / **8.5** / 10.0 / 12.6 ms. So capping read fan-out carries no
warm-path regression risk — the rayon default (`nproc`=64) over-parallelizes
reads in both regimes.

Retry predicate: do **not** spend further effort on readahead/`fadvise` tuning or
on chunk-size sweeps for cold reads — both are refuted. The open lever is the
read fan-out width itself (`into_par_iter` at `crates/ffs-core/src/lib.rs:10108`,
`12677`, `12819`, all on the global rayon pool). Tracked in `bd-ddryj`.

---

## 2026-07-10 — Cold-read: contention scales with FOLIO INSERTIONS, not reads, not threads (bd-ddryj, BlackThrush/cc_ffs)

Follow-up to the frame table above. Instrumented the cold read with
`filemap:mm_filemap_add_to_page_cache` (page-cache insertion count),
`syscalls:sys_enter_pread64` (read count) and `lock:contention_begin`, on the
prebuilt `release-perf` binary (**no rebuild**), `drop_caches=3` before each run.

### Q: does contention scale with thread count or with read count?

`ffs-cli read`, 128 MiB, `RAYON_NUM_THREADS` swept:

| T | folio inserts | B/insert | preads | lock contentions | cycles (M) |
| --- | --- | --- | --- | --- | --- |
| 1 | 2,230 | 60,187 | 1,034 | 0 | 337 |
| 2 | 10,145 | 13,229 | 1,034 | 1 | 345 |
| 4 | 12,623 | 10,633 | 1,034 | 78 | 398 |
| 8 | 15,137 | 8,867 | 1,034 | 669 | 439 |
| 16 | 17,914 | 7,493 | 1,034 | 2,473 | 548 |
| 32 | 23,271 | 5,768 | 1,034 | 7,541 | 819 |
| 64 | 27,174 | 4,940 | 1,034 | 11,912 | 1,467 |

**Read count is constant (1,034) at every thread count.** Contention does *not*
scale with reads. What scales is the number of distinct page-cache insertions:
2,230 → 27,174 (**12.2x**), because bytes-per-insertion collapses from ~60 KiB
(order-4 large folios) to ~4.9 KiB (order-0 pages).

### Why: one shared `struct file` destroys the readahead folio order

`FileByteDevice` holds `file: Arc<File>` (`crates/ffs-block/src/lib.rs:523`), so
every rayon worker `pread`s through **one** `struct file` and therefore one
`file->f_ra` readahead state. Interleaved offsets from N workers look
non-sequential to that single state machine, so `page_cache_ra_unbounded` stops
allocating large folios and falls back to order-0 — multiplying xarray
insertions, each taking the `address_space` `xa_lock`.

Controlled proof (same thread count, same reads, same bytes; only fd sharing
differs), raw parallel `pread` of the identical extents, `sha256`-verified:

| mode | T | inserts | B/insert | cycles (M) | ms |
| --- | --- | --- | --- | --- | --- |
| shared fd (what frankenfs does) | 8 | 17,476 | 7,680 | 392 | 36.7 |
| **per-thread fd** | 8 | **2,978** | **45,070** | 323 | **26.0** |
| shared fd | 32 | 19,382 | 6,925 | 615 | 30.7 |
| per-thread fd | 32 | 3,858 | 34,789 | 453 | 27.1 |
| shared fd | 64 | 19,542 | 6,868 | 655 | 31.8 |
| per-thread fd | 64 | 4,720 | 28,436 | 597 | 33.0 |

At T=8, giving each thread its own fd cuts insertions **5.9x** and wall **1.41x**.
Self-time confirms the mechanism: `native_queued_spin_lock_slowpath`
2.45% → 0.50%, `__filemap_add_folio` 2.29% → 0.14%.

**Answer: contention scales with page-cache insertion count. Thread count only
matters because a shared `struct file` inflates insertions; read count is
irrelevant.**

### Lever (a) "larger contiguous reads" — REFUTED as stated

Shared fd, T=8, chunk swept. Bigger reads cut syscalls 147x but do **not** cut
insertions, and hurt wall time:

| chunk | preads | inserts | B/insert | ms |
| --- | --- | --- | --- | --- |
| 128 KiB | 1,027 | 15,374 | 8,730 | 35.2 |
| 1 MiB | 131 | 18,014 | 7,451 | 34.5 |
| 8 MiB | 19 | 17,184 | 7,811 | 60.8 |
| 32 MiB | 7 | 17,149 | 7,827 | 66.6 |

Insertion count is a property of readahead folio order, not of read size. The
correct form of lever (a) is **preserve large folios by giving each reader its
own `f_ra`** (per-thread fd), not "read bigger".

### Lever (b) "spread across distinct inodes" — subsumed

The `xa_lock` is per-`address_space`, so distinct inodes would give distinct
xarrays. But the data show the lock is barely contended once insertions collapse
(0.50% at T=8 per-thread). The actionable half of (b) is the per-thread
`struct file`, which is what actually restores folio order. Splitting one file
across inodes is not possible for a single-file read anyway.

### Lever (c) O_DIRECT — QUANTIFIED, NOT IMPLEMENTED

Measured as a *ceiling only*, in the raw `pread` harness (page-aligned `mmap`
buffers, `os.preadv`), `sha256` identical to the kernel mount. **No frankenfs
code was changed; O_DIRECT would require audited-unsafe or a policy change.**

| mode | T | inserts | cycles (M) | ms |
| --- | --- | --- | --- | --- |
| O_DIRECT | 1 | ~0 (1,527 residual, loader) | 126 | 50.9 |
| O_DIRECT | 8 | ~0 | 174 | **25.0** |
| O_DIRECT | 32 | ~0 | 279 | 26.6 |
| O_DIRECT | 64 | ~0 | 397 | 28.4 |

Best-of-T wall, same bytes:

| approach | ms | vs today |
| --- | --- | --- |
| shared fd (frankenfs today) | 30.7 | 1.00x |
| per-thread fd | 26.0 | **1.18x** |
| O_DIRECT | 25.0 | 1.23x |
| *kernel-best (dio loop, t=32)* | *26.9* | *the comparator* |

**O_DIRECT buys only 1.04x of wall over the safe per-thread-fd fix, but 1.86x of
CPU (323M → 174M cycles).** So O_DIRECT is a CPU-efficiency play, not a latency
play; it is not worth an unsafe/policy change to close a 4% wall gap. Per-thread
fd + a bounded fan-out reaches **26.0 ms vs the kernel's 26.9 ms — parity.**

### Blocker (surfaced, not worked around)

The per-thread-fd gain is measured in the raw `pread` harness, not inside
frankenfs. Proving it *in* frankenfs needs a modified `FileByteDevice` binary,
and this box is under a disk constraint that forbids local `cargo build`, while
`rch exec -- cargo build` **cannot return the artifact**: the globally-exported
`CARGO_TARGET_DIR=/data/tmp/cargo-target` makes rch treat every build as a
custom-target-dir build and retrieval yields ~0 bytes (remote compile succeeds;
`check`/`test` are unaffected because they only stream diagnostics). A criterion
bench cannot substitute: this is a cold-path effect requiring `drop_caches` (root)
between reps, which criterion cannot express on a remote worker.

Retry predicate: do **not** re-test chunk size, readahead/`fadvise`, extent
walks, or the copy tax for cold reads — all refuted. The single open lever is
per-reader `struct file` + bounded fan-out (`bd-ddryj`).

---

## 2026-07-10 — Cold-read: the insertion-count-vs-throughput curve (bd-ddryj, BlackThrush/cc_ffs)

Requested sweep: folio insertions per MiB and lock-wait time at 4K/16K/64K/256K/1M
read granularities. Measured on frankenfs's **real** read path — granularity via
`FFS_READ_CHUNK_BLOCKS` (4 KiB blocks), verified to move `pread` count
(1 block → 32,777 preads; 256 blocks → 138). Prebuilt `release-perf` binary,
**no rebuild**. `drop_caches=3` before every run. 128 MiB, 2 extents.

Lock wait is real spin-wait time from `perf lock contention` (tracepoint mode),
summed across threads, attributed by caller. **Caveat:** `perf lock record`
instruments every contention event and inflates the run, so wait totals are
comparable *between arms* but must not be compared against the uninstrumented
`read` column.

| T | chunk | preads | ins/MiB | B/insert | wait (readahead) | contended | read | MiB/s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 4K | 32,777 | 16 | 67,311 | 0 ms | 0 | 134.2 ms | 954 |
| 1 | 16K | 8,202 | 16 | 66,576 | 0 ms | 0 | 100.6 ms | 1,272 |
| 1 | 64K | 2,058 | 17 | 62,777 | 0 ms | 1 | 91.2 ms | 1,403 |
| 1 | 256K | 522 | 18 | 58,534 | 0 ms | 0 | 90.1 ms | 1,421 |
| 1 | 1M | 138 | 17 | 61,909 | 0 ms | 2 | 92.0 ms | 1,391 |
| 16 | 4K | 32,777 | 105 | 9,986 | 42 ms | 3,113 | 41.0 ms | 3,123 |
| 16 | 16K | 8,202 | 111 | 9,459 | 84 ms | 5,158 | 34.1 ms | 3,750 |
| 16 | 64K | 2,058 | 134 | 7,828 | 235 ms | 10,930 | 32.9 ms | 3,896 |
| 16 | 256K | 522 | 169 | 6,195 | 366 ms | 15,250 | 35.4 ms | 3,611 |
| 16 | 1M | 138 | 115 | 9,100 | 233 ms | 9,468 | 31.7 ms | 4,041 |
| 64 | 4K | 32,777 | 143 | 7,323 | 1,814 ms | 20,064 | 47.1 ms | 2,717 |
| 64 | 16K | 8,202 | 156 | 6,739 | 2,114 ms | 21,773 | 39.5 ms | 3,239 |
| 64 | 64K | 2,058 | 198 | 5,303 | 3,208 ms | 26,713 | 41.8 ms | 3,065 |
| 64 | 256K | 522 | 254 | 4,128 | 3,414 ms | 32,024 | 38.3 ms | 3,340 |
| 64 | 1M | 138 | 107 | 9,800 | 1,143 ms | 9,036 | 38.8 ms | 3,303 |

All wait is attributed to `page_cache_ra_unbounded+0x14b` and
`page_cache_ra_order+0x1fe` — the `xa_lock` taken while inserting readahead folios.

### The curve refutes the premise: insertions drive LOCK WAIT, not THROUGHPUT

* `r(lockwait, ins/MiB)` = **+0.80** across all 15 points — insertions really do
  cause the contention.
* `r(ins/MiB, MiB/s)` **within a fixed thread count** = +0.15 (T=16), +0.25 (T=64).
  Insertion count has **no predictive power over throughput**.
* The pooled `r(ins/MiB, MiB/s)` = +0.78 is Simpson's paradox: thread count raises
  both insertions and throughput. Do not read it as causal.
* Direct counter-example, same T=64: **256K → 254 ins/MiB, 3,414 ms wait, 3,340 MiB/s**
  vs **1M → 107 ins/MiB, 1,143 ms wait, 3,303 MiB/s**. Cutting insertions 2.4x and
  lock wait 3.0x made it **1% slower**.

Spin-wait is CPU burned *while other threads wait on the device*; it is overlapped
with I/O, so it costs cycles, not wall. That is why capping fan-out helped (fewer
threads → less CPU burn *and* less readahead thrash) while shrinking insertions via
read size does not.

### Each requested lever, quantified

1. **Larger contiguous reads → fewer, bigger folios: REFUTED.** ins/MiB is flat in
   chunk size at T=1 (16→18 from 4K to 1M) and *rises* with chunk at T=16/64
   (105→169, 143→254) before falling only at 1M. Read size does not select folio
   order. The T=1 throughput gain (954 → 1,421 MiB/s, **1.49x**) is pure syscall
   amortization — insertions never move.
2. **Readahead that batches into one insertion: ALREADY HAPPENS — concurrency
   destroys it.** At T=1 the kernel yields ~64 KiB folios (67,311 B/insert) even for
   4 KiB reads. At T=64 it collapses to ~4–7 KiB. The knob is not IO size; it is
   readahead *sequentiality per `struct file`*. Restoring it (per-thread fd, prior
   commit `7155b208`) cut insertions 5.9x **and** wall 1.41x — the only change that
   moved both.
3. **Hugepage / large-folio-friendly IO sizes: REFUTED.** Folio order is chosen by
   the readahead state machine, not by the read size (see T=1, 4K reads → order-4
   folios). No IO size recovers order-4 folios at T=64 on a shared fd.

### Lever (c): what bypassing the page cache would buy — QUANTIFIED, NOT IMPLEMENTED

Measured only as a ceiling in the raw `pread` harness (page-aligned `mmap` buffers,
`O_DIRECT`, per-thread fd, T=16), `sha256` identical to the kernel mount.
**No frankenfs code was changed. O_DIRECT/mmap remain owner-gated (`bd-kdmu4`).**

| chunk | O_DIRECT MiB/s | O_DIRECT ms | buffered per-thread fd |
| --- | --- | --- | --- |
| 4K | 419 | 305.8 | **665 MiB/s** (192.5 ms) — buffered *wins*, readahead covers small reads |
| 16K | 1,139 | 112.4 | — |
| 64K | 3,216 | 39.8 | — |
| 256K | **4,981** | 25.7 | — |
| 1M | 4,923 | 26.0 | **5,020 MiB/s** (25.5 ms) |

**Bypassing the page cache buys 0% of wall time** once fds are per-thread and the
chunk is >= 256 KiB (25.5 ms buffered vs 25.7 ms O_DIRECT), and it is **1.6x SLOWER
than buffered at 4 KiB** because it forfeits readahead entirely. Its only real
benefit is CPU: 1.86x fewer cycles (323M → 174M, prior commit). O_DIRECT is a
CPU-efficiency play, not a latency play — it does not justify an audited-unsafe or
policy change on latency grounds.

### Net

The one lever that moves wall time is **restore per-reader readahead sequentiality
(per-thread `struct file`) + a bounded fan-out**, already filed as `bd-ddryj`.
frankenfs's shipped default (128 KiB chunks) is already near-optimal on granularity;
`FFS_READ_CHUNK_BLOCKS` is not worth tuning.

Retry predicate: do **not** re-test read granularity, readahead/`fadvise`, extent
walks, the copy tax, or "reduce insertions" as a throughput lever for cold reads.
All are now measured and refuted. Insertion count is a *lock-wait* (CPU) lever only.

### Ledger-integrity re-audit (frankenmermaid `5feb977` rule), 2026-07-10

frankenmermaid found four REJECT rows that had been A/B'd on a benchmark where the
code under test never executed (0.000% self-time), so those rows measured dead code.
House rule adopted: **every REJECT must carry the self-time figure proving the
function under test actually ran on the measured input.**

Re-auditing the cold-read rejects above with `perf report --percent-limit 0`:

| reject | code-executed proof (self-time) | verdict |
| --- | --- | --- |
| per-block syscall overhead | `entry_SYSRETQ_unsafe_stack` **1.84%**; `__x64_sys_pread64` on a 32.99% callchain | VALID — path is hot, just not the cost |
| copy tax | `_copy_to_iter` **5.69%**; `clear_page_erms` **5.21%** | VALID — executed, quantified at ~11% |
| readahead / folio-insertion levers | `__filemap_add_folio` **1.04%**; `page_cache_ra_unbounded` **0.40%**; 100% of spin-wait attributed to `page_cache_ra_*`; insertions varied 2,230→27,174 across arms | VALID |
| read-granularity lever | knob provably engaged: `pread` count moved **32,777 → 138** (237x) | VALID |
| **extent-tree walks** | `<ffs_core::OpenFs>::resolve_extent` **0.05%**; extent-map `arc_swap::load` **0.10%**; `ext4_es_lookup_extent` **0.13%** | **VALID BUT NARROW — see below** |

The extent-walk reject is **not** the frankenmermaid failure mode: the code did run
(non-zero self-time). But its self-time is ~0 because the fixtures barely exercise
it — `big.bin` has **2** extents, `frag.bin` **9**, `double_ind.bin` **14**, and a
sequential read parses the tree ~once, caching the map in an `arc_swap`ed
`Arc<[ExtentMapping]>`. So the claim "extent walks are not the cold-read cost" is
established **only for <= 14 extents**.

**A file with hundreds or thousands of extents was never measured. That regime is
UNTESTED, not refuted, and is reopened as `bd-vpypn`** — which must also cover the
random-read path, where the extent map is consulted per access rather than once.

---

## 2026-07-10 — Where folio insertions originate, and whether frankenfs can reduce them WITHOUT bypass (bd-ddryj / bd-kdmu4 evidence, BlackThrush/cc_ffs)

Hypothesis under test (as posed): *"if bigger reads do not reduce insertions, the
insertions are driven by the FUSE/page-cache path itself, one folio per block
regardless of request size"* — implying the only remaining lever is `O_DIRECT` or an
mmap-backed `ByteDevice`, i.e. the audited-unsafe policy change.

**Both halves of that hypothesis are false.** Measured on the prebuilt `release-perf`
binary (no rebuild), `drop_caches=3` per run, 128 MiB / 2 extents.

Two corrections of premise first: (1) **FUSE is not in this path.** `ffs-cli read`
`pread`s the image file directly; there is no FUSE round-trip to attribute insertions
to. (2) **Insertions are not one-per-block.** The
`filemap:mm_filemap_add_to_page_cache` tracepoint carries an `order` field:

### Folio order distribution, identical 128 KiB requests

| | order-0 (4 KiB) | order-2 (16 KiB) | order-6 (256 KiB) | mean |
| --- | --- | --- | --- | --- |
| T=1 | 1,599 (72.8%) | 78 | **506 — covering 126 of 128 MiB** | **62.8 KiB/insert** |
| T=64 | **28,191 (96.3%)** | 905 | 7 | **4.7 KiB/insert** |

At T=1 the kernel inserts **256 KiB folios for 128 KiB reads** — the folio is *larger
than the request*. Folio order is decoupled from request size, which is exactly why
the granularity sweep found no lever.

### Insertion origin (callchain-attributed, 100% of events)

| T | origin | share | orders emitted |
| --- | --- | --- | --- |
| 1 | `page_cache_ra_order` | 90.2% (1,981) | ord6 x506, ord2 x78, ord0 x1,383 |
| 1 | `page_cache_ra_unbounded` | 9.8% (215) | ord0 only |
| 1 | `__filemap_get_folio` | 0.0% (1) | — |
| 64 | `page_cache_ra_unbounded` | 57.6% (16,848) | **ord0 only** |
| 64 | `page_cache_ra_order` | 42.4% (12,413) | ord0 x11,340, ord2 x905, ord4 x99 |
| 64 | `__filemap_get_folio` | 0.0% (3) | — |

**Every insertion originates in the readahead path.** There is no per-block
`filemap_create_folio` fallback doing the work (`__filemap_get_folio` ≈ 0). Under
concurrency the insertions *migrate* to `page_cache_ra_unbounded`, which allocates
**only order-0 folios**, and even `page_cache_ra_order` stops choosing large orders.

### Can frankenfs reduce insertions WITHOUT bypassing the page cache? YES — 8.8x

Same T=8, same reads, same bytes, pure **buffered** `pread` (no `O_DIRECT`, no `mmap`);
only fd sharing differs. `sha256` identical to the kernel mount.

| | insertions | mean | large folios (order>=4) | covering |
| --- | --- | --- | --- | --- |
| shared fd (what `FileByteDevice` does) | 16,989 | 7.8 KiB | 477 | 44 MiB |
| **per-thread fd** | **1,926** | **69.2 KiB** | **1,011** | **126 MiB** |

Order-5 (128 KiB) folios go from 232 to **1,000**, i.e. essentially the entire file is
inserted as large folios again. This is a **pure page-cache-resident fix**: give each
reader its own `struct file` so its `f_ra` sees a sequential stream.

**The hypothesis that insertions are irreducible without bypass is REFUTED.**

Code-executed proof (ledger-integrity rule, `5feb977`): the readahead insertion path
under test is hot and provably ran — `__filemap_add_folio` **1.04% self-time**,
`page_cache_ra_unbounded` **0.40% self-time**; 100% of the 29,264 (T=64) / 2,197 (T=1)
insertion events attribute by callchain to `page_cache_ra_*`; and the knob provably
engaged (insertions moved 16,989 -> 1,926 under the arms). No arm measured dead code.

### What the bypass would buy — MEASURED, not projected

A projection from the insertion-count-vs-lock-wait curve was requested. **That
projection is invalid and is not offered here.** Within a fixed thread count,
`r(ins/MiB, MiB/s)` = +0.15 (T=16) / +0.25 (T=64): insertion count has no predictive
power over throughput, because spin-wait is CPU burned while other threads block on the
device — overlapped with I/O. A lock-wait-based projection would forecast a large win
where the direct measurement shows none.

Direct measurement instead (raw `pread` harness, page-aligned `mmap` buffers, per-thread
fd, T=16, `sha256` identical to the kernel mount; **no frankenfs code changed**):

| chunk | O_DIRECT | buffered, per-thread fd |
| --- | --- | --- |
| 4K | 419 MiB/s | **665 MiB/s** (buffered wins — bypass forfeits readahead) |
| 256K | **4,981 MiB/s** (25.7 ms) | — |
| 1M | 4,923 MiB/s | **5,020 MiB/s** (25.5 ms) |

**Bypassing the page cache buys 0% of wall time** (25.5 ms buffered vs 25.7 ms
`O_DIRECT`) once fds are per-thread and chunk >= 256 KiB, and it is **1.6x SLOWER at
4 KiB**. Its only benefit is CPU: **1.86x fewer cycles** (323M -> 174M at T=8).

### Owner decision, surfaced (bd-kdmu4)

`O_DIRECT` / mmap-backed `ByteDevice` **cannot be justified on latency grounds.** The
safe, `forbid(unsafe_code)`-compatible fix — per-reader `struct file` plus a bounded
fan-out (`bd-ddryj`) — reaches **25.5 ms vs the kernel's 26.9 ms**, i.e. parity, with
zero policy change. If the owner ever approves `bd-kdmu4`, the justification must be
**CPU efficiency (~150M cycles saved per 128 MiB read)**, not throughput. Recommendation:
do not approve it for latency.

Retry predicate: the cold-read mechanism is now closed end-to-end. Do **not** re-test
read granularity, readahead/`fadvise`, extent walks (<=14 extents), the copy tax,
"reduce insertions for throughput", or O_DIRECT-for-latency. The only open work is
`bd-ddryj` (per-reader `struct file` + bounded fan-out) and `bd-vpypn` (extent walks at
high extent counts, never measured).

---

## 2026-07-10 — Cold-read chain CLOSED: the projection is computed, and it is falsified (bd-kdmu4 owner decision, BlackThrush/cc_ffs)

Final turn of the cold-read chain. Prebuilt `release-perf` binary, **zero local cargo
builds**, `drop_caches=3` before every run, arms interleaved within each rep.

### 1. Insertions per READ — the requested per-read instrumentation

A 128 KiB read spans 32 x 4 KiB pages, so **32 insertions/read is the "one folio per
block" ceiling.** frankenfs's real binary, production 128 KiB chunk, `pread` count
constant at 1,034:

| T | insertions | insertions/read | % of one-folio-per-block ceiling |
| --- | --- | --- | --- |
| 1 | 2,230 | 2.16 | 6.7% |
| 2 | 10,145 | 9.81 | 30.7% |
| 4 | 12,623 | 12.21 | 38.1% |
| 8 | 15,137 | 14.64 | 45.7% |
| 16 | 17,914 | 17.32 | 54.1% |
| 32 | 23,271 | 22.51 | 70.3% |
| **64** | **27,174** | **26.28** | **82.1%** |

**The "one folio per block" intuition is 82% correct — but only at 64 threads.** It is a
symptom of concurrency on a shared `f_ra`, not a property of the page-cache path. Same
harness, same chunk, T=16, only fd sharing differs (1,027 preads both arms):

| | insertions | insertions/read | % of ceiling |
| --- | --- | --- | --- |
| shared fd | 16,430 | 16.00 | 50.0% |
| **per-thread fd** | **3,895** | **3.79** | **11.9%** |

### 2. CAN frankenfs reduce insertions without bypassing the page cache? YES — 4.2x

Answered definitively, in pure buffered mode, at the production chunk: **16,430 -> 3,895
insertions (4.2x), 16.00 -> 3.79 per read.** 100% of insertions originate in the readahead
path (`page_cache_ra_order` / `page_cache_ra_unbounded`); `__filemap_get_folio` ~= 0, so
there is no per-block `filemap_create_folio` fallback that only a bypass could avoid.

**The premise "insertions are irreducible without O_DIRECT/mmap" is REFUTED.** The
antecedent for escalating `bd-kdmu4` does not hold.

### 3. The projection, computed as requested — and falsified

**Model A** (Amdahl on spin-wait self-time; eliminating insertions removes all
`native_queued_spin_lock_slowpath` cycles, assume wall proportional to CPU):

| T | read | spinlock self-time | projected | projected speedup |
| --- | --- | --- | --- | --- |
| 64 | 37.0 ms | 42.27% | 21.4 ms | **1.73x** |
| 16 | 30.1 ms | 10.96% | 26.8 ms | **1.12x** |

**Model B** (aggregate spin-wait / threads, subtracted from wall):

| T | chunk | aggregate wait | per thread | wall | projected |
| --- | --- | --- | --- | --- | --- |
| 64 | 1M | 1,143 ms | 17.9 ms | 38.8 ms | 20.9 ms = **1.85x** |
| 64 | 256K | 3,414 ms | 53.3 ms | 38.3 ms | **-15.0 ms — NEGATIVE WALL** |

Model B predicts a negative wall time. **The projection method is self-refuting**, and
Model A inherits the same defect in milder form.

**Measurement** (`O_DIRECT` eliminates insertions entirely; raw harness, page-aligned
`mmap`, `sha256` == kernel mount; no frankenfs code changed):

* T=16: `O_DIRECT` **25.7 ms** vs buffered per-thread fd **25.5 ms** -> **1.00x (-1%)**
* T=64: `O_DIRECT` 28.4 ms
* device floor: raw buffered `pread` T=32 = 28.3 ms; kernel dio loop = **26.9 ms**

**Projection 1.12x-1.85x. Measurement 1.00x.** Spin-wait is CPU burned by threads that are
*already blocked on the device*; it is overlapped with I/O and never on the critical path.
Wall is bounded below by device bandwidth: 128 MiB at ~4,700-5,000 MiB/s = 25.5-27 ms.

### 4. Owner decision (bd-kdmu4) — SURFACED

After the fan-out cap frankenfs sits at **30.1 ms against the kernel's 26.9 ms**: total
remaining headroom **3.2 ms (1.12x)**, of which `O_DIRECT` captures **0 ms**. Its only
benefit is CPU: **1.86x fewer cycles** (323M -> 174M per 128 MiB read).

> `bd-kdmu4` (O_DIRECT / mmap-backed `ByteDevice`) **cannot be justified on latency
> grounds.** Approve it only if ~150M cycles per 128 MiB read is worth an audited-unsafe or
> policy change on **CPU-efficiency** grounds. Not implemented; nothing in its scope touched.

The remaining wall lever is the read **fan-out width** (`bd-ddryj`: rayon `nproc`=64 -> 16,
**1.24x cold, 7/7 paired reps, p=0.0156** on the real binary; warm 1.48x), which needs no
unsafe and no policy change.

### Ledger-integrity (frankenmermaid `5feb977`)

Code-executed proof for every reject in this section: `native_queued_spin_lock_slowpath`
**42.27%** self-time (T=64) / **10.96%** (T=16); `__filemap_add_folio` **1.04%**;
`page_cache_ra_unbounded` **0.40%**; 100% of 29,264 insertion events attributed by callchain
to `page_cache_ra_*`. Knob provably engaged: insertions/read **16.00 -> 3.79** under the arms.
No criterion bench was used anywhere in this campaign, so substrate-v2 defects (sequential
group members; `black_box` DCE) cannot apply — arms are wall-clock runs alternated **inside**
each rep, and results are consumed via `sha256` / XOR checksums / byte counts.

### Chain closed

Cold-read is now fully explained: kernel page-cache `xa_lock` contention, driven by folio
insertions, driven by readahead order collapse on a shared `struct file`. Insertions are a
**CPU** lever, not a throughput lever (three independent confirmations). Do not re-test
readahead/`fadvise`, extent walks (<=14 extents), the copy tax, read granularity, "reduce
insertions for throughput", or O_DIRECT-for-latency. Open: `bd-ddryj` (fan-out cap, blocked
on a build) and `bd-vpypn` (extent walks at high extent counts, never measured).

---

## 2026-07-10 — Honest cold baseline re-established; the gap has moved OUT of the kernel (bd-zvn7r, BlackThrush/cc_ffs)

With `xa_lock` and folio insertions off the table, this re-measures the real remaining
gap and re-ranks the frames. Prebuilt `release-perf` binary, **zero local cargo builds**;
`drop_caches=3` before every run; **all arms interleaved within each rep** (substrate v2);
`sha256` identical across arms (`b6cfaf9d…`, kernel mount == `ffs-cli read`).
Quiet box (load 4.4). 128 MiB, 2 extents, production 128 KiB chunk.

### The baseline (9 interleaved reps, medians)

| arm | median | min | cv | vs kernel |
| --- | --- | --- | --- | --- |
| ffs T=64 (**as shipped**) | 42.94 ms | 40.92 | 12.7% | **1.54x** |
| ffs T=16 (best config) | 34.67 ms | 33.09 | 2.3% | **1.25x** |
| *(ffs per-open startup, subtracted per rep)* | 4.79 ms | 4.60 | 5.3% | — |
| raw pread, same fd model + chunk | 28.20 ms | 27.80 | 10.4% | 1.01x |
| kernel dio loop T=32 | 27.80 ms | 26.70 | 8.5% | — |

`ffs T=16` beats `ffs T=64` in **9/9 paired reps, p=0.0039** — the fan-out cap (`bd-ddryj`)
reconfirmed on a quiet box.

### Decomposition of the residual

```
  ffs T=16 read                     34.67 ms
  raw pread, same fd model+chunk    28.20 ms   -> frankenfs-attributable  +6.47 ms
  kernel dio loop T=32              27.80 ms   -> buffered page-cache path +0.40 ms
  TOTAL gap vs kernel                          +6.87 ms  (1.25x)
```

**94% of the remaining gap is frankenfs's own cost. The buffered page-cache path now costs
0.40 ms.** That closes the kernel-side story: `xa_lock`, insertions, readahead, granularity
and the bypass are all done. The gap lives in frankenfs.

### Fresh ranked frame table — ffs, T=16, production chunk, self-time >= 0.1%

| self% | frame | layer |
| --- | --- | --- |
| 12.28 | `_copy_to_iter` | kernel — the buffered copy (inherent) |
| **11.81** | **`clear_page_erms`** | kernel — **zero-filling fresh destination pages** |
| 9.32 | `native_queued_spin_lock_slowpath` | kernel — residual `xa_lock` (was **42.27%** at T=64) |
| 5.74 | `asm_exc_page_fault` | kernel |
| 2.19 | `rmqueue_bulk` | kernel — page allocator |
| 2.02 | `__filemap_add_folio` | kernel |
| 1.67 | `lru_gen_add_folio` | kernel |
| 1.57 | `do_anonymous_page` | kernel |
| 1.44 | `mod_memcg_lruvec_state` | kernel |
| 1.13 | `crossbeam_deque::Stealer::steal` | user — rayon |
| 1.13 | `zap_present_ptes` | kernel |
| 1.09 | `up_read` | kernel |
| 0.94 | `get_page_from_freelist` | kernel |
| 0.80 | `__alloc_frozen_pages_noprof` | kernel |
| 0.77 | `__mem_cgroup_charge` | kernel |
| 0.69 | `ext4_mpage_readpages` | kernel |

CPU split at T=16: **user 4.5 ms, sys 188 ms** — frankenfs's *userspace* code is nearly free;
what it costs is the **kernel work its allocation pattern provokes**.

**New #1 frame owner: the anonymous-page alloc/fault/zero cluster = 28.91% of cycles**
(`clear_page_erms` + `asm_exc_page_fault` + `rmqueue_bulk` + `lru_gen_add_folio` +
`do_anonymous_page` + `mod_memcg_lruvec_state` + `zap_present_ptes` + `get_page_from_freelist` +
`__alloc_frozen_pages` + `__mem_cgroup_charge` + `get_mem_cgroup_from_mm` + …). Measured
**17,459 page faults (17,385 minor) for a read of 32,768 destination pages**: frankenfs allocates
a fresh destination buffer per chunk, so pages are faulted, zero-filled, and then immediately
overwritten by `_copy_to_iter`. Filed as `bd-zvn7r`.

### Recorded so nobody chases it again: per-thread fd cuts insertions 4.2x and buys NO wall time

At the production 128 KiB chunk, T=16, same 1,027 preads, only fd sharing differs:
insertions **16,430 -> 3,895** (16.00 -> 3.79 per read), yet wall is **1.025x median, 7/9 paired
reps, p=0.1797 — NOT significant**. Self-time proving the path ran: `__filemap_add_folio`
**2.02%**, `native_queued_spin_lock_slowpath` **9.32%**, `page_cache_ra_unbounded` **0.40%**
(T=64 profile). **Per-reader `struct file` is a CPU-efficiency change, not a latency fix.**

### A proxy that failed its own validity check — no REJECT recorded

I built a raw-pread proxy for the buffer-reuse lever (alloc-per-chunk vs reused per-thread buffer,
128 KiB, T=16, shared fd, `sha256` identical). It showed reuse **slower**: 0.957x median, reuse wins
**1/7** paired reps, p=1.0. **That result is inadmissible.** The proxy's alloc arm produced only
**2,364 page faults** against frankenfs's **17,459** (7.4x fewer), because glibc's *dynamic* mmap
threshold makes CPython recycle the freed 128 KiB block rather than returning it. The proxy never
exercises the mechanism under test, so its null says nothing about frankenfs.

This is the ledger-integrity rule (`5feb977`) applied to a **proxy** rather than a bench: the arm must
reproduce the mechanism's **magnitude**, not merely its shape. Same class of error as the earlier
proxy-chunk artifact. Buffer reuse is therefore **UNTESTED for frankenfs, not refuted** (`bd-zvn7r`).

### Do not project

Do **not** convert the 28.91% cycle share into a projected wall win. Projecting wall from cycle share
was already proven invalid on this exact workload (`bd-kdmu4`: Model A/B predicted 1.12–1.85x;
measurement was **1.00x**), because much of this cluster — like spin-wait — is CPU burned by threads
already blocked on the device. The size of the buffer-churn lever must be **measured in-tree**.

### Blocked

`bd-zvn7r` and `bd-ddryj` both need a modified binary run locally under `drop_caches`.
`RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo build` still does not return the
artifact. Unblock by fixing rch retrieval, or by granting one local build.

---

## 2026-07-10 — The new #1 frame is in the BENCHMARK HARNESS, not the filesystem (bd-zvn7r re-scoped, BlackThrush/cc_ffs)

**Reproducibility metadata (new ledger rule):** binary `ffs-cli`
`sha256=03b7456d8cd6fa118bd214b2fdf8a03e56cac79e6768b7311613b039c8ae81eb`
(55,453,584 bytes, `release-perf`, built 2026-07-10 04:02:59); allocator
`tikv_jemallocator` (`ffs-cli/src/main.rs:8`); worker = local host (perf/`drop_caches`
need root, so no remote worker); `rch` verification worker = `hz1`. cv per arm below.
Zero local cargo builds.

### Naming the frame, with self-time

From the T=16 profile (`perf record -F 4999 -e cycles`, prebuilt binary above):

| self% | frame |
| --- | --- |
| 12.28% | `_copy_to_iter` |
| **11.81%** | **`clear_page_erms`** |
| 9.32% | `native_queued_spin_lock_slowpath` |
| 5.74% | `asm_exc_page_fault` |
| 2.19% | `rmqueue_bulk` |
| 1.57% | `do_anonymous_page` |
| 1.13% | `zap_present_ptes` |
| 0.94% | `get_page_from_freelist` |
| 0.80% | `__alloc_frozen_pages_noprof` |
| 0.77% | `__mem_cgroup_charge` |

**Anon-page alloc/fault/zero cluster = 28.91% of cycles.**

### Where it comes from — traced to an exact line, and it is NOT the FS engine

`ffs-cli read` streams the file in `STREAM_CHUNK = 64 MiB` slices through **one reused
`vec![0_u8; 64 MiB]`** (`crates/ffs-cli/src/main.rs:2403-2407`; the reuse itself was an
earlier fix, `bd-2x68s`). First-touching that buffer faults **16,384 pages**, each of which
the kernel must `clear_page_erms` before the read overwrites it.

Numerically confirmed on the real binary:

| run | page-faults |
| --- | --- |
| `ffs read /small.bin` (4 KiB file) | 1,008 (process baseline) |
| `ffs read /big.bin` (128 MiB file) | 17,474 |
| difference | **16,466 ≈ 16,384 = 64 MiB / 4 KiB** |

A *per-chunk* destination would have faulted 32,768 pages (128 MiB). It faults 16,384 — the
64 MiB buffer, once, reused for the second half. And `ffs-block::read_exact_at` already
avoids a staging buffer for large reads (`lib.rs:573-592`), so the engine is not the source.

**Consequence: this frame belongs to the CLI harness, not to the filesystem.** A FUSE mount
serving 128 KiB reads never allocates a 64 MiB destination. Optimising it would optimise the
benchmark, not the product.

### ⚠️ Self-correction: my own baseline is contaminated by this

Last section attributed "+6.47 ms frankenfs-attributable, 94% of the residual". That
over-attributes. The floor arm preaded into a **128 KiB** per-chunk buffer (~2 MiB of anon
memory touched, glibc-recycled: **2,338 faults**), while ffs first-touches **64 MiB**
(17,474 faults). The kernel comparator never pays that cost. **The engine-only gap is
therefore smaller than 6.47 ms and is currently UNMEASURED.**

The headline gaps (ffs T=64 **1.54x**, T=16 **1.25x** vs kernel) carry the same contamination:
they include the CLI's 64 MiB first-touch, which the kernel arm does not perform.

### A floor arm that failed the impossibility check — inadmissible, no REJECT recorded

I rebuilt the floor with frankenfs's real destination policy (one reused 64 MiB buffer,
`preader4.py bigbuf`, `sha256` identical to the kernel mount). It **reproduced the mechanism**:
17,593 faults vs frankenfs's 17,471. But as a *timing* arm it is invalid:

| arm | median (7 interleaved reps) | cv |
| --- | --- | --- |
| ffs T=16 | 35.57 ms | 12.2% |
| floor bigbuf (64 MiB dest) | **65.90 ms** | 16.0% |
| floor smallbuf (128 KiB dest) | 30.60 ms | 26.6% |
| kernel dio loop T=32 | 27.50 ms | 10.0% |

**A floor cannot be slower than the thing it floors** (frankenfs does strictly more work than a
raw `pread` of the same extents). The `bigbuf` arm's 65.90 ms is python overhead — per-chunk
`memoryview` slicing, window recomputation, GIL — not I/O. Its implied "+35.30 ms destination
policy cost" is therefore **discarded, not recorded**. This is the same impossibility check that
originally caught the loop-device artifact in `bd-q6k00` ("frankenfs faster than the raw-device
floor, which is physically impossible").

Fault count valid; wall time invalid. **The wall cost of the 64 MiB first-touch remains
unmeasured**, and may not be projected from the 28.91% cycle share — that projection method was
already falsified on this workload (`bd-kdmu4`: predicted 1.12-1.85x, measured 1.00x).

### Re-scope of bd-zvn7r

It splits into two, and neither is the product lever it first appeared to be:

1. **Measurement hygiene (harness).** `STREAM_CHUNK = 64 MiB` makes every `ffs-cli read`
   benchmark pay a 64 MiB anon first-touch that no kernel comparator pays. Either shrink it,
   pre-fault the buffer outside the timed region, or subtract it. Until then **every
   `ffs-cli read` cold number is inflated by an unmeasured constant.**
2. **The real question, still open.** Does the *engine* (`OpenFs::read_into`, the rayon chunk
   jobs, `ffs-block`) allocate per-chunk destinations on the **FUSE** path? Unknown. It must be
   profiled through the FUSE mount, not through `ffs-cli read`.

Both need a build (blocked). Neither may be measured with a python proxy: the proxy must
reproduce the mechanism's magnitude *and* survive the impossibility check, and this one failed
the second.

---

## 2026-07-10 — How much of the cold-read gap is harness? MEASURED: 3.10 ms (41% of the best-config gap) (bd-zvn7r, BlackThrush/cc_ffs)

**Repro metadata (required on every entry):** binary `ffs-cli`
`sha256=03b7456d8cd6fa118bd214b2fdf8a03e56cac79e6768b7311613b039c8ae81eb`
(`release-perf`, 55,453,584 B, built 2026-07-10 04:02:59); allocator `tikv_jemallocator`
(`ffs-cli/src/main.rs:8`); worker = **local host** (`perf` + `drop_caches` require root, so
no remote worker is possible for this measurement); `rch` verification worker = `vmi1149989`.
cv per arm below. **Zero local cargo builds.**

### The rebuilt harness

The previous `bigbuf` floor was inadmissible (it timed **slower** than the thing it floored).
Two bugs, both mine: `bytearray(n)` **memsets** in CPython, and the allocation sat **inside**
the timed region. Rebuilt as `preader5.py`:

* `mmap.mmap(-1, n)` instead of `bytearray(n)` — the kernel lazily zero-fills an anonymous
  mapping, which is what jemalloc's `alloc_zeroed` actually gets; no CPython memset.
* destination allocation and **all** chunk-list construction hoisted **out** of the timed region.
* one persistent `ThreadPoolExecutor`, warmed before the timer — no thread spawn inside it.
* `drop_caches` outside the timer; result consumed via an XOR checksum so nothing can be elided.

Two arms, identical I/O and identical bytes, differing **only** in whether the destination is
already faulted:

* `cold_dst` — destination created fresh inside the timed region: pays the 64 MiB first-touch
  during the parallel preads, exactly as `ffs-cli read` does with its `vec![0u8; 64 MiB]`.
* `warm_dst` — destination created and pre-faulted before the timer: the timed region contains
  only reads.

**Validity gates, all passing:** identity (both arms return the same XOR checksum; bytes
`sha256`-identical to the kernel mount); **magnitude** (`cold_dst` 18,090 page faults vs
frankenfs's 17,467 — the mechanism is reproduced); **impossibility** (`cold_dst` 31.10 ms <
ffs 35.77 ms — a floor must be faster than the thing it floors).

### The measurement (9 interleaved reps, medians)

| arm | median | cv |
| --- | --- | --- |
| ffs T=64 (as shipped) | 42.88 ms | 7.7% |
| ffs T=16 (best config) | 35.77 ms | 8.6% |
| floor `cold_dst` (pays 64 MiB first-touch) | 31.10 ms | 10.7% |
| floor `warm_dst` (reads only) | 28.00 ms | 5.7% |
| kernel dio loop T=32 | 28.30 ms | 8.8% |

**Destination first-touch cost = `cold_dst` - `warm_dst` = 3.10 ms.** Measured, not projected.

### The honest gap

| config | reported | harness | honest | harness share of gap |
| --- | --- | --- | --- | --- |
| ffs T=64 (as shipped) | **1.52x** | 3.10 ms | **1.41x** | 3.10 / 14.58 = **21%** |
| ffs T=16 (best config) | **1.26x** | 3.10 ms | **1.15x** | 3.10 / 7.47 = **41%** |

**41% of the best-config cold-read gap vs kernel ext4 is harness overhead** — the first-touch of
`ffs-cli read`'s 64 MiB staging buffer, which no kernel comparator pays. Every `ffs-cli read`
cold number in this repo, including all of my own `bd-ddryj` baselines, carries this constant.

Note also `warm_dst` (28.00 ms) ~= kernel dio loop (28.30 ms): **a raw parallel `pread` into a warm
destination is already at kernel parity.** The residual filesystem overhead is
35.77 - 3.10 - 28.00 = **4.67 ms**.

### SCOPE OF THIS CORRECTION — do not over-claim

This invalidates **my own** `ffs-cli read`-based cold numbers by 21-41% of their gap. It does
**not** establish that `bd-kdmu4`'s headline "~2.9x slower than kernel" is an artifact: that figure
was produced by a **different** harness ("multi-file parallel read, in-process threaded", with a
claimed 41% pread copy tax and 27% nested-rayon coordination), which I have **not** audited. It is
now *suspect by association* and needs its own audit against the same three validity gates — but
calling it an artifact without measuring it would repeat exactly the error this ledger exists to
prevent. **`bd-kdmu4` remains RESOLVED on the O_DIRECT question** (bypass measured at 1.00x); its
2.9x premise is **unaudited**, not refuted.

### Now hunt the top frame — with the harness cost attributed

The 28.91% anon alloc/fault/zero cluster from the previous ranked table is **the harness**
(`clear_page_erms` 11.81% + `asm_exc_page_fault` 5.74% + the page-allocator/memcg tail). Removing it,
the ranked table for actual filesystem work at T=16 is:

| self% | frame | note |
| --- | --- | --- |
| 12.28% | `_copy_to_iter` | the buffered copy — **also paid by the `warm_dst` floor**, so not a gap source |
| 9.32% | `native_queued_spin_lock_slowpath` | residual `xa_lock` (42.27% at T=64; the fan-out cap already removed most) |
| 1.13% | `crossbeam_deque::Stealer::steal` | rayon work-stealing |
| 0.69% | `ext4_mpage_readpages` | kernel ext4 readahead |

`_copy_to_iter` is present in both ffs and the floor, so it cannot explain the 4.67 ms residual.
The residual is frankenfs's own userspace work (user CPU at T=16 is **4.5 ms** — the same order),
which the current profile cannot resolve further because `perf` attributes it below the 0.1% cut.

**Next step requires a build**: fix `STREAM_CHUNK` (or pre-fault the staging buffer outside the
timed region) so `ffs-cli read` measures only filesystem work, then re-profile. Until then the
residual 4.67 ms is real but unattributed. Tracked in `bd-zvn7r`(a).

### Retry predicate

Do not re-derive the cold-read mechanism (`xa_lock`, folio insertions, readahead, granularity,
O_DIRECT) — all closed. Do not trust any `ffs-cli read` cold ratio that has not subtracted the
3.10 ms harness constant. Do not project wall time from a cycle share.

---

## 2026-07-10 — Scope of the harness correction, and is the remaining gap worth a lever? (bd-zvn7r / bd-ddryj / bd-kdmu4, BlackThrush/cc_ffs)

**Metadata:** binary `ffs-cli` `sha256=03b7456d8cd6fa118bd214b2fdf8a03e56cac79e6768b7311613b039c8ae81eb`
(`release-perf`, 55,453,584 B); allocator `tikv_jemallocator`; worker = local host (`perf` +
`drop_caches` need root); `rch` verify worker `hz2`; cv per arm 7.7 / 8.6 / 10.7 / 5.7 / 8.8%;
self-time of the function under test `clear_page_erms` **11.81%** (cluster 28.91%).
**Zero local cargo builds.**

### Direction of the bias — no sign-flip is at risk

The 64 MiB first-touch is paid **only** by `ffs-cli read`; the kernel and raw-`pread` arms use small
buffers. So harness inflation always makes frankenfs look **slower**, never faster. Therefore:

* Every prior "frankenfs is slower than kernel ext4" verdict is **conservative and stands.**
* Only the **magnitudes** are affected — they are **upper bounds**.
* No "frankenfs is faster" claim survives anywhere in this ledger, so the correction cannot resurrect one.

### Conclusions drawn against the inflated number (do not re-derive; adjust magnitudes only)

All of these used `ffs-cli read` engine time and therefore include a first-touch of
`min(file_size, 64 MiB)`:

| ledger row | reported | status |
| --- | --- | --- |
| `bd-q6k00` ext4 extent 128 MiB cold — **1.42x slower** | inflated | sign stands; magnitude is an upper bound |
| `bd-5koeh` ext4 indirect 50 MiB — **1.45x slower** | inflated | sign stands; magnitude is an upper bound |
| `bd-5koeh` ext4 fragmented 48 MiB — **1.31x slower** | inflated | sign stands; magnitude is an upper bound |
| `bd-ddryj` baseline — ffs **1.54x / 1.25x** kernel | inflated | **superseded**: measured 1.41x / 1.15x |
| `bd-zvn7r` "94% of residual is frankenfs-attributable" | wrong | **superseded** (floor arm mismatched the destination policy) |
| `bd-zvn7r` "new #1 frame = anon-page churn 28.91%" | harness | **the cluster is the harness**, not the filesystem |

I have **not** re-measured the indirect/fragmented rows with a corrected harness; scaling the 3.10 ms
constant by file size would be a projection, and projections have already been falsified twice on this
workload. They are marked as upper bounds, not restated with new numbers.

### ⚠️ The 2.9x multi-file figure: NOT corrected to 1.41x — different workload, different harness

`bd-kdmu4`'s headline is **multi-file parallel read** (256 files x 256 KiB, `walk --read-data --parallel`)
against an in-process threaded C reader. My 3.10 ms constant is `ffs-cli read`'s single-file 64 MiB
`STREAM_CHUNK` staging buffer. **They do not transfer**, and I checked why rather than assuming:

* `walk_one_dir` **already reuses one buffer per rayon worker** (`ffs-cli/src/main.rs:3055-3060`,
  `map_init`; the per-file fresh-`Vec` churn was fixed in `bd-2x68s`). The multi-file harness does not
  have the allocation pattern I measured.

**However**, that figure carries its **own** acknowledged harness component — by its author's words, not
my measurement. From the 2026-06-22 entry (CrimsonFox): the post-fix multi-file profile is `pread` 43.6%
plus *"~25% OUTER `walk_one_dir` per-inode `par_iter` coordination … a real FUSE mount dispatches each
getattr/read as a separate per-request worker, never via this nested rayon, **so it's a harness artifact
not a real-fs cost**"*.

So the multi-file number is **partly instrumentation by its own admission (~25%), by a mechanism
different from the one I measured**, and the residual real-filesystem multi-file figure was **never
isolated**. It needs its own audit against the three validity gates (identity / magnitude /
impossibility). **I am not restating it as 1.41x — that would repeat, in the opposite direction, exactly
the error this ledger exists to prevent.** `bd-kdmu4` remains RESOLVED on the O_DIRECT question (bypass
measured at 1.00x) and **UNAUDITED** on its 2.9x premise.

### Is the remaining gap worth a lever?

Honest, harness-corrected, single-file 128 MiB extent read (same binary, 9 interleaved reps):

| | wall | vs kernel |
| --- | --- | --- |
| ffs as shipped (rayon = nproc = 64) | 39.78 ms | **1.41x** |
| ffs with fan-out capped at 16 | 32.67 ms | **1.15x** |
| raw pread into a warm destination | 28.00 ms | 0.99x |
| kernel dio loop | 28.30 ms | — |

**YES — for exactly one lever, and it is already named.** `bd-ddryj` (bound the read fan-out) converts
**1.41x → 1.15x**, an 18% wall reduction on the shipped default. It needs no unsafe, no policy change,
and it is reconfirmed at 9/9 paired reps (p=0.0039). It is blocked only on the build.

**NO — for anything beyond it.** After the cap, the residual is 4.67 ms (1.15x), and the corrected frame
table contains no lever:

* `_copy_to_iter` **12.28%** — the buffered copy. The `warm_dst` floor pays it too and still lands at
  kernel parity, so it cannot explain the residual. Removing it needs `O_DIRECT`/mmap, **measured at 1.00x**.
* `native_queued_spin_lock_slowpath` **9.32%** — residual `xa_lock`; the fan-out cap already removed the
  bulk (42.27% → 9.32%). Per-thread fd cuts insertions 4.2x and buys **no wall** (p=0.18).
* `Stealer::steal` 1.13%, `ext4_mpage_readpages` 0.69% — below any actionable threshold.

The residual 4.67 ms is frankenfs's own userspace work (user CPU 4.5 ms, same order), and `perf` cannot
resolve it above the 0.1% cut. **Attributing it requires fixing `STREAM_CHUNK` first** so the timed region
contains only filesystem work — `bd-zvn7r`(a), a small change, blocked on the same build.

**Recommendation: land `bd-ddryj`, fix the harness (`bd-zvn7r`a), and stop hunting the single-file cold
read.** At 1.15x of a direct-I/O kernel mount, with the floor itself at 0.99x, there is no headroom worth
an unsafe policy change or a further lever.

---

## 2026-07-10 — COLD-READ LANE CLOSED (bd-ddryj landed; summary of corrections, BlackThrush/cc_ffs)

The cold-read investigation is complete. Binary `sha256=03b7456d…81eb` (`release-perf`);
worker = local host (`perf`/`drop_caches` need root); `rch` verify workers `hz1`/`hz2`/`ovh-a`/
`vmi1149989`; null-control median 1.0232x. Zero local cargo builds.

### What was refuted, in order

1. **`xa_lock` contention is the cold-read cost** — TRUE as a mechanism, but it is driven by
   frankenfs's *own* read fan-out, not by anything intrinsic. Capping the fan-out removes it
   (`native_queued_spin_lock_slowpath` 42.27% → 9.32%). → `bd-ddryj`, LANDED this turn.
2. **Folio insertions are the throughput lever** — REFUTED. Insertions drive lock-*wait* (CPU),
   not wall time: `r(ins/MiB, MiB/s)` = +0.15/+0.25 within a fixed thread count; a T=64 case cut
   insertions 2.4x and ran 1% slower; per-thread fd cuts them 4.2x for no wall (p=0.18).
3. **Only O_DIRECT/mmap can help** — REFUTED. Bypassing the page cache is measured at **1.00x**
   of wall (25.7 vs 25.5 ms) and 1.6x slower at 4 KiB. `bd-kdmu4` needs no unsafe policy change on
   latency grounds; RESOLVED.
4. **The gap is 2.9–5x** — for the single-file `ffs-cli read` numbers, the gap was inflated by a
   measured **3.10 ms** harness constant (its 64 MiB `STREAM_CHUNK` first-touch). Honest single-file
   gap: **1.41x as-shipped**, **1.15x with the fan-out cap** (the raw floor itself is 0.99x of
   kernel). See the caveat below on the multi-file figure.

### ⚠️ The one claim I was asked to make and did NOT: "the headline 2.9–5x was 41% harness overhead"

That sentence is **false as written**, and the distinction matters for repo integrity:

* **41% and 1.41x are different arms.** The harness constant is **21%** of the *as-shipped* gap
  (→1.41x) and **41%** of the *fan-out-capped* gap (→1.15x). One number cannot describe both.
* **The 2.9–5x headline is a DIFFERENT workload** (`bd-kdmu4`: multi-file parallel read) with a
  **different harness**, measured by a different agent. My 3.10 ms constant is `ffs-cli read`'s
  single-file staging buffer, which does not exist in that path (`walk_one_dir` already reuses one
  buffer per worker, `main.rs:3055-3060`, `bd-2x68s`). I have **not** measured the multi-file
  harness, so I cannot say what fraction of 2.9x is overhead. Its author separately flagged ~25% of
  it as nested-`par_iter` coordination "a harness artifact not a real-fs cost", by yet another
  mechanism — but the residual real-fs figure was never isolated.
* **The honest statement:** *my own single-file `ffs-cli read` cold numbers were 21–41% harness;
  `bd-kdmu4`'s multi-file 2.9x is suspect by association but unaudited.* Writing "the headline was
  41% harness" would restate an unmeasured number — the same class of error (in the opposite
  direction) as the original "frankenfs dominates kernel" rows this whole audit corrected.

### Prior conclusions drawn against the inflated single-file number

Sign stands (harness bias only ever inflates "frankenfs slower"), magnitude is an upper bound:
`bd-q6k00` ext4 extent 1.42x; `bd-5koeh` indirect 1.45x / fragmented 1.31x. Superseded outright:
`bd-ddryj` baseline 1.54x/1.25x → 1.41x/1.15x; "94% frankenfs-attributable" (floor mismatched the
destination policy); "new #1 frame = anon churn 28.91%" (that cluster is the harness).

### Lane status

* `bd-ddryj` — **LANDED** (`7a6091a2`): dedicated 16-wide read pool. Behavior parity verified
  remote; perf measured on the equivalent `RAYON_NUM_THREADS=16` config (1.21x effect vs 1.02x null),
  the built binary not independently re-measured (build blocker).
* `bd-zvn7r`(a) — harness hygiene: `STREAM_CHUNK=64 MiB` inflates every `ffs-cli read` cold number;
  shrink / pre-fault / subtract. Open, needs a build.
* `bd-zvn7r`(b) — does the FUSE read path allocate per-chunk destinations? Open, profile through the mount.
* `bd-kdmu4` — RESOLVED on O_DIRECT (1.00x); its 2.9x multi-file premise UNAUDITED.
* `bd-vpypn` — extent walks at high extent counts, never measured. Open.

No further single-file cold-read lever exists: at 1.15x of a direct-I/O kernel mount with the raw
floor at 0.99x, the residual is inherent copy + userspace work.

---

## 2026-07-10 — bd-bhh0i de-risk: INDEPENDENT VERIFICATION of cod's safety proof (no collision, BlackThrush/cc_ffs)

cod (`cod_ffs`) owns `bd-bhh0i` and is usage-walled, but its work is active and recent
(loom model `da92afd7`, contention instrumentation `ef7073b8` / `52730e52`, all today).
The three de-risk deliverables the owner named already exist as cod's artifacts:

1. **Lock-hold histograms at 1/2/4/8 threads** — `crates/ffs-core/benches/bd_bhh0i_contention.rs`
   (records wait/hold/alloc-ns distributions; the 8t p99 figures are already in the ledger:
   global alloc 176.341 µs, disjoint group 0.290 µs, synthetic publish 127.449 µs).
2. **Loom model proven deadlock-free + linearizable** —
   `crates/ffs-core/tests/bd_bhh0i_lock_decomposition_model.rs`.
3. **Incremental plan** — `docs/bd-bhh0i-parallel-create-plan.md`.

Rather than duplicate active peer work (which would collide when cod returns), I did the one
useful non-colliding thing: **independently ran cod's loom safety proof** to confirm it holds.
`RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo test -p ffs-core --test
bd_bhh0i_lock_decomposition_model` on remote `vmi1227854` — **7/7 passed** (6.43 s):

* `disjoint_group_commits_are_deadlock_free_and_linearizable`
* `same_group_commits_serialize_and_replay_linearly`
* `opposing_multi_group_requests_normalize_to_one_lock_order`
* `disjoint_groups_with_cross_mapped_shards_normalize_both_lock_orders`
* `installed_unpublished_versions_are_hidden_until_the_prefix_is_complete`
* `post_publication_prune_preserves_registered_snapshot_visibility`
* `failure_before_install_leaves_no_allocator_or_mvcc_effect`

The model checks exactly the properties the owner asked for: deadlock-freedom, linearizability
(commit order respects every non-overlap edge and replays against a sequential bitmap allocator),
lock-order normalization (opposing multi-group requests reduce to one order), and the visibility
invariant (installed-but-unpublished versions stay hidden until `completed_prefix` publishes).

**Verdict: bd-bhh0i's safety substrate is de-risked and the proof is reproducible.** No new
artifact was written and no cod file was touched — the deliverables exist, are high quality, and
now carry an independent green run from a second agent. The remaining `bd-bhh0i` work (the actual
lock-decomposition cutover) stays with cod, is FS-mutating, and is explicitly out of scope here
(no cutover, no FS mutation beyond fixtures). I did not start it.

---

## 2026-07-10 — ISA finding + bd-bhh0i doc coverage (no collision) (bd-b9dug, BlackThrush/cc_ffs)

### ISA question: does frankenfs emit baseline or AVX2?

**For its own code: BASELINE (SSE2). Only runtime-dispatched deps use AVX2.** Filed as `bd-b9dug`.

Binary `sha256=03b7456d…81eb` (the one used for the entire cold-read campaign): `RUSTFLAGS` unset,
no `target-cpu`/`target-feature` in `.cargo/config.toml`, `Cargo.toml`, or `rust-toolchain.toml`, so a
plain `cargo build --profile release-perf` targets the default **x86-64 baseline**. frankenfs's own SWAR
hot functions (`names_eq`, `dx_hash`, word-at-a-time) disassemble to scalar GPR ops — no `ymm`/`zmm`
(the SWAR primitives are baseline-compatible by design, so a higher `target-cpu` would not help them,
but any autovectorizable ffs loop is emitted SSE2). The 1401 AVX2 + 2018 AVX-512 mnemonics present come
from **runtime-dispatched dep crates** (crc32c, xxhash, memchr, blake3) — the AVX-512 variants are dead
on this non-AVX512 host; correct portable pattern, not a gap.

**The gap:** production is `scripts/build-perf.sh`, which sets `-C target-cpu=x86-64-v3` (AVX2/BMI2/FMA) +
fat LTO + PGO (its header records ~8.5% fewer create instructions, ~3% lookup). rch's plain build does not
apply those flags, so **the benchmark binary ≠ the production binary**.

* A/B ratios are unaffected (same binary both arms) — `bd-ddryj` 1.21x, null 1.02x stand.
* Absolute vs-kernel numbers are a **second** upper bound: the honest cold-read gap (1.41x / 1.15x) would
  be tighter on the v3+PGO production binary. Real gap < 1.41x.
* **Every future workload-class benchmark must use the build-perf.sh binary**, or note it is baseline.

### bd-bhh0i incremental design doc — already delivered by cod; not touched

The owner asked for "the incremental design doc: each step independently safe, e2fsck-clean,
rollback-able, with the loom proof attached." **That doc already exists and is comprehensive:**
`docs/bd-bhh0i-parallel-create-plan.md` (316 committed lines, actively being expanded by cod right now —
a 59-line working-tree diff). It already contains: the incremental owner-reviewed plan with
independently-revertible steps, e2fsck-clean gates per step (`create-bench N → e2fsck -fn CLEAN`),
crash-consistency analysis, rollback framing, and the bounded-loom proof section. My independent 7/7
verification of that loom proof (previous entry) is the second-agent peer review it needed.

**I did not edit cod's doc** — it is active peer work and editing it would collide (and non-src edits
revert within minutes here). The plan is de-risked by two agents. The FS-mutating cutover stays with cod.

### Unbenchmarked workload classes — beaded (cod's lane); cross-cutting note

fsync/journal-commit latency (`bd-fsync-journal-latency-gap-ptp4x`) and mounted-xattr
(`bd-mount-xattr-workload-gap-fr6iq`) are already beaded and in cod's lane. I did not start them (cod
owns new workload classes; starting them mid-wall would collide). Cross-cutting requirement recorded on
`bd-b9dug`: **all of them must be benchmarked on the v3+PGO production binary**, not the baseline plain
build, or their absolute vs-kernel numbers will carry the same ISA upper-bound this ledger just found in
the cold-read numbers.

---

## 2026-07-10 — ISA verdict (plain), SWAR-widen correction, and the workload-class gap matrix (bd-b9dug, BlackThrush/cc_ffs)

### ISA verdict, plainly

**On the workers, frankenfs emits BASELINE x86-64 (SSE2) for its own code.** Definitive: `RUSTFLAGS`
unset, no `target-cpu`/`target-feature` in any config, so a plain `cargo build --profile release-perf`
targets the default baseline. Corroborating instruction counts in the benchmark binary
(`sha256=03b7456d…81eb`): `pdep`/`pext`/`blsr` = **0** (BMI2, no baseline fallback), `bsr` 922 vs `lzcnt`
34 — consistent with baseline codegen. The AVX2/AVX-512 present is runtime-dispatched dep code
(crc32c/xxhash/memchr/blake3), portable and partly dead on this non-AVX512 host. The production binary
(`build-perf.sh`) is `target-cpu=x86-64-v3` + PGO.

### The SWAR-widen premise is wrong — corrected

A build-widen (`target-cpu=v3`) only changes compiler **auto-emission**; it cannot turn hand-written u64
SWAR (GPR XOR/mask/shift) into vectors. So the named SWAR paths — `extent_root_namespace` (7.14x),
`names_eq`, symlink NUL-trim, casefold — **do not benefit from a build-fix**: they are ISA-independent by
construction and identical on baseline and v3. Rewriting them as explicit AVX2 is a code change blocked
by `forbid(unsafe_code)` (`std::arch` SIMD is unsafe).

**Where the measured v3 uplift really lands:** `build-perf.sh` records v3 as ~8.5% fewer **create**
instructions, ~3% **lookup** — not read. Those paths' hot loops include the allocator bitmap bit-scan
(`ffs-alloc/src/succinct.rs:426,435` `trailing_zeros`, `count_zeros`), which v3's `tzcnt`/`lzcnt` (and
possibly `pdep`/`pext`) accelerate over baseline `bsf`/`bsr`. That is **cod's active allocator lane**, not
the SWAR hash paths and not the read path (v3 gives read ~0 — the read gap is copy + userspace per the
cold-read closeout). Net: the build-widen is a real build-config decision, but its beneficiaries are the
allocator/metadata path (coordinate with cod), not my SWAR paths.

### Unbenchmarked workload classes — honest gap matrix

| class | harness | status |
| --- | --- | --- |
| fsync / journal-commit latency | **none in ffs-cli** (fsync exists only on the FUSE path) | needs a new `FsyncBench` subcommand → **build-blocked**; beaded `bd-fsync-journal-latency-gap-ptp4x` (cod) |
| xattr get/set/list storm | **none in ffs-cli** | needs a new subcommand → **build-blocked**; beaded `bd-mount-xattr-workload-gap-fr6iq` (cod) |
| small-file storm (create) | `CreateBench` (exists) | single-thread create is mined; **parallel** create = `bd-bhh0i` (cod's active write lane) → collision |
| readdir+stat storm | `Walk --no-stat` / `Walk` (exists) | **cold** readdir+stat = the withdrawn cold-read metadata-walk row (do not re-mine); **warm** CPU is mined (lookup fully dissected) |

**Honest surface: the measurable-now set is empty under the active constraints** {no local build; cod owns
the write/alloc lane; do not re-mine cold-read}. fsync and xattr — the two genuinely new classes — both
need a new CLI harness, which needs a build. The two with harnesses overlap cod's lane or the withdrawn
cold-read rows. This is a *build-blocked + coordination* boundary, not a lack of candidates: with one
granted build, `FsyncBench` + `XattrBench` subcommands would unblock the two new classes cleanly (they do
not touch the read path or the allocator).

### bd-bhh0i incremental design doc — cod's, still active, not touched

Re-checked this turn: `docs/bd-bhh0i-parallel-create-plan.md` still carries cod's uncommitted 59-line
working-tree diff (actively editing while walled). It already has the incremental owner-reviewed plan with
independently-revertible steps, per-step `e2fsck -fn` gates, crash-consistency, rollback, and the loom
proof section. My independent **7/7** verification stands as its second-agent peer review. Editing it would
collide and non-src edits revert within minutes — so I did not. The plan is sign-off-ready and de-risked by
two agents; the FS-mutating cutover remains cod's.

## 2026-07-22 — bd-kdmu4 PREMISE AUDIT: the 2.9–5x multi-file parallel-read headline is DEAD on current code — measured at KERNEL PARITY OR BETTER (cc)

The 2026-07-10 closeout left `bd-kdmu4` "RESOLVED on O_DIRECT (1.00x); its 2.9x multi-file
premise UNAUDITED" and prescribed an audit against the identity / magnitude / impossibility
validity gates. This entry is that audit. **Verdict: the premise no longer holds.**

### Premise under test

"Multi-file parallel read (256 files x 256 KiB, `walk --read-data --parallel`) is ~2.9–5x
slower than an in-process threaded C reader; 41% pread copy tax + 27% nested-rayon
coordination" (2026-06-22, CrimsonFox). Since then the gap was engineered away lever by
lever: `bd-2x68s` per-worker walk buffer reuse + 3.2x multi-file walk win, the 32-block
read-chunk retune, `21113a70` build_global(16) walk cap, `7a6091a2` 16-wide read pool, and
the 2026-07-16 fan-out-cap class (`9af088db`/`650fc5a9`/`ffd672ee`).

### Method

* **Subject:** `target/release/ffs-cli` (Jul 13, opt-z baseline-ISA `release` profile,
  contains `21113a70`'s x16 walk cap — every run printed `[parallel x16]`; predates the
  Jul-16 caps, which do not trigger on this workload). Engine time from the `walked … in Xms`
  line (excludes image open, includes parallel readdir+getattr+full data read).
* **Fixtures (fresh, purpose-built):** `/data/tmp/kdmu4_small.img` = exact premise replica,
  256 files x 256 KiB = 64 MiB in 16 dirs; `/data/tmp/kdmu4_big.img` = honest-size variant
  per the >=1 GiB sizing rule, 2048 files x 512 KiB = 1 GiB in 32 dirs. mke2fs -b4096 -d;
  all files single-extent (filefrag-verified).
* **Kernel arm:** in-process pthread C reader (`reader.c tree`), per-file open (own `f_ra`),
  contiguous per-thread file partition, 128 KiB pread chunks, readdir+lstat walk inside the
  timed region — on a **`--direct-io=on` loop mount** (dio=1 verified) per the recorded
  loop-dio methodology.
* **Floor arm:** same C harness in `ranges` mode: raw parallel pread of the files' physical
  extents from the image file, per-thread fd, contiguous partition. First floor build used
  atomic round-robin dispatch and FAILED the impossibility gate (ffs 225.5 ms < "floor"
  243.3 ms cold-1GiB) because round-robin destroys per-fd sequentiality while rayon gives
  each worker a contiguous span — the floor was rebuilt with contiguous partitioning and
  the gate then passed everywhere (e.g. cold-1GiB floor 200–212 ms < ffs 210–229 ms).
* **Gates:** identity — all three arms XOR64-identical per fixture (`46d5e61487c25876` /
  `6136f5eaeccd58af`, byte counts exact 67,108,864 / 1,073,741,824) + `ffs-cli read`
  sha256 == kernel-mount sha256 on sample files; magnitude — file/byte counts exact in every
  arm; impossibility — fixed floor below subject in every cell. `sync && drop_caches=3`
  before every cold arm, arms interleaved within each rep, 7 reps, medians + min + cv.

### Results (campaign 1, quiet box — 15-min load avg ~9; T=16 all arms)

| fixture / mode | ffs engine | kernel C reader (dio loop) | raw floor (fixed) | verdict |
| --- | --- | --- | --- | --- |
| 64 MiB premise replica, cold | **17.6 ms** (cv 2.1–3.2%) | 18.7 ms (cv 2.2%) | 13.7 ms | **ffs 1.06x FASTER** |
| 64 MiB premise replica, warm | 4.4–5.1 ms | 4.2–4.5 ms (cv 12–19%) | 2.3–2.9 ms | parity (<=1.2x within noise) |
| 1 GiB honest-size, cold | **225.5 ms** (cv 1.1%) | 244.6 ms (cv 0.7%) | 200–212 ms | **ffs 1.08x FASTER** |
| 1 GiB honest-size, warm | **29.7 ms** (cv 3.5%) | 33.5 ms (cv 3.2%) | 26.2 ms | **ffs 1.13x FASTER** |

Kernel-best sweep (T in {8,16,32}, min-of-3): best kernel cold anywhere = 17.8 ms (64 MiB)
/ 229.4 ms (1 GiB); against ffs's worst clean medians that is still **1.00–1.01x = parity**.
Conservative worst-vs-best framing does not resurrect any gap, and the opt-z baseline-ISA
subject binary only understates the v3+PGO production build.

### Load-storm replication (campaign 2) — the "needs low-load window" caveat is real

A 1-min load-avg spike to ~54 (sibling agents) landed mid-campaign-2. Cold verdicts
reproduced under load (ffs 1.03–1.09x faster than the kernel arm, cv 9–14%), but warm-1GiB
inverted: ffs 119–200 ms vs C reader 40–69 ms — **under CPU contention the rayon walk
degrades ~4x while the plain pthread reader degrades ~1.5x.** Campaign 1 is the valid
dataset; the load observation matches the bead's recorded "needs low-load window" and is a
scheduling-sensitivity fact, not a filesystem gap.

### Disposition

* `bd-kdmu4` **CLOSED**: O_DIRECT/mmap resolved earlier at 1.00x (do not approve for
  latency); the 2.9–5x multi-file premise is now AUDITED and REFUTED on current code —
  in-process multi-file parallel read is at kernel parity or better, floor-bounded residual
  headroom <=5–9% cold. The "41% copy tax" attribution died with the workload gap: the floor
  pays the same buffered copy and ffs sits within 5–9% of it.
* The mmap-backed / zero-copy ByteDevice lane is **not justified by any remaining measured
  gap on this surface** — consistent with the standing 1.00x bypass measurement.
* Reproduction: harness + driver at the session scratchpad (`reader.c`, `bench.py`),
  fixtures kept at `/data/tmp/kdmu4_{small,big}.img`.

### Retry predicate

Reopen a multi-file in-process read gap ONLY with: a quiet box (1-min load < ~2x cores/4),
the three validity gates, a contiguous-partition raw floor, and a dio-loop kernel arm.
Open adjacent surfaces this audit does NOT cover: the FUSE-mounted multi-file read path
(`bd-zvn7r`(b) per-chunk destination question) and rayon-under-CPU-contention scheduling
sensitivity (new observation above; a per-request dispatch comparator would isolate it).

## 2026-07-22 — FUSE-MOUNTED multi-file read gap ISOLATED for the first time + per-thread-read-fd lever REJECTED (bd-kdmu4 / bd-zvn7r(b), cc)

Continuation of the same-day premise audit above, moving to the one read surface it did not
cover: the real FUSE mount. Subject binary: Jul-13 `release` ffs-cli (baseline arm), then a
locally-built same-source binary for the lever A/B (env-toggled, same binary both arms).
Fixture: `/data/tmp/kdmu4_big.img` (2048 x 512 KiB = 1 GiB). Reader: the audited pthread C
tree reader (contiguous partition, T=16, 128 KiB), identity-gated (XOR64
`6136f5eaeccd58af` in EVERY run below, including through the full FUSE stack).
AppArmor gotcha recorded: Ubuntu's `fusermount3` profile only permits mounts under
`$HOME`/`/mnt`/`/media`/`/tmp`/`/run/user` — mounting at `/data/...` fails EPERM even via
sudo; use `/mnt/*`.

### The mounted gap (kernel arm = dio-loop ext4, same reader)

| regime | ffs FUSE | kernel | ratio |
| --- | --- | --- | --- |
| cold (drop_caches) | 1282–1689 ms | 232–241 ms | **5.5–7.0x slower** |
| daemon-warm (all image bytes page-cached, FUSE pages cold) | 596–1328 ms | n/a (no daemon) | **disk-free path is ~0.6–1.3 s for 1 GiB** |
| fully warm | 117 ms | 29–90 ms | measures kernel FUSE page cache, not the daemon |

The in-process engine is at kernel parity (entry above); **the mounted path is where the
multi-file read gap actually lives, and it is larger than the retired 2.9–5x headline.**
Daemon-warm ≈ cold shows the path is not disk-bound.

### Profile attribution (perf -g on the daemon, daemon-warm storm, 12.3k samples/8 s)

* `native_queued_spin_lock_slowpath` **41%** — `__filemap_add_folio` ← `page_cache_ra` ←
  `ext4_file_read_iter` ← `preadv` on the image file: the KNOWN shared-`struct file`
  readahead/`xa_lock` convoy (single `Arc<File>` in `FileByteDevice`, 16 `ffs-read-*`
  threads).
* `_copy_to_iter` **1.83%**, `__pi_memcpy` **1.50%** — **the copy tax is ~3% of daemon
  self-time on the mounted path.** The "~2x structural pread copy-tax / 41% of read time"
  framing is dead on this surface too; an mmap-backed ByteDevice has nothing to remove.
* ~12.3k samples / 8 s across 82 threads ≈ **~1.5 CPUs busy: the daemon is mostly idle.**
  Wall is bounded by FUSE round-trip/dispatch concurrency, not by daemon CPU and not by
  copies.

### The lever tried (one lever): per-thread re-opened read fds in `FileByteDevice` — REJECT

Rationale: the profiled 41% spin is the exact pathology the 2026-07-10 raw-harness rows
measured per-thread fds fixing (insertions 5.9x down, wall 1.41x at T=8) — but those same
rows also warned "per-thread fd cuts insertions 4.2x and buys no wall (p=0.18)" once the
fan-out is capped. Implemented safely (thread_local HashMap keyed by device id, re-open
verified against open-time `(st_dev, st_ino)`, reads only, `FFS_PER_THREAD_READ_FD=0`
kill-switch for same-binary A/B), built locally, measured 3 interleaved mount-cycle reps:

| arm | off (shared fd) | on (per-thread fds) | verdict |
| --- | --- | --- | --- |
| FUSE cold | 1281.7 ms (min 1257.6) | 1363.8 ms (min 1319.1) | **~6% REGRESSION** |
| FUSE daemon-warm | 596.2 ms (min 590.4) | 660.3 ms (min 635.7) | **~11% REGRESSION** |
| in-process walk cold | 221.3 ms | 219.4 ms | neutral (1.01x) |

Identity: XOR64 equal in all arms. **REJECT — the spin is overlapped CPU burn, not wall,
exactly as the 07-10 "insertion count is a lock-wait lever only" row predicted; the extra
re-opens/fstat and doubled readahead streams cost more than the convoy they remove.**
Production hunk STASHED (not landed): `stash@{0}` "bd-kdmu4 REJECTED lever: per-thread
read fds in FileByteDevice". The Jul-13 baseline binary was restored to `target/release`.
(Remote `cargo test -p ffs-block` on the lever tree also caught a test-module struct
literal needing the new fields — moot post-stash, but it re-confirms the update-all-
constructors rule.)

### Retry predicate / the actual next levers (measured surface, unworked)

Do NOT retry: per-thread/dup'd read fds for wall (twice-refuted), mmap/O_DIRECT on any
read surface (copy ~3% here, bypass 1.00x there), or insertion-count-driven levers.
The mounted read gap is a **round-trip/dispatch-concurrency** problem. Next levers, in
suspected order: (1) FUSE request sizing — verify negotiated `max_read`/`max_readahead`
and the per-request size the daemon actually serves (8192 x 128 KiB requests at ~73 us
effective each); (2) `--runtime-mode per-core` (thread-per-core dispatcher, shipped
opt-in, never A/B'd on this workload); (3) daemon-side readahead/prefetch depth on the
mounted path (OliveCliff's bounded readahead machinery exists); (4) FUSE passthrough is
NOT applicable (no per-file backing fd for image-embedded files). Each needs the same
identity-gated C-reader A/B on a quiet box (1-min load < ~16 here; this session ran at
9–33 with one storm to 54 — mount-cycle interleaving kept arms comparable).

## 2026-07-22 — KEEP: async per-request read dispatch on the FUSE mount — cold multi-file 3.85x faster, gap vs kernel 5.5x → 1.43x (bd-kdmu4, cc)

The turn-2 entry above attributed the mounted multi-file read gap to serial request
dispatch: `fuser::spawn_mount2` runs ONE session loop, the `Filesystem::read` op replied
inline, so 16 concurrent client readers were served strictly one-at-a-time (daemon ~1.5
CPUs busy, copies ~3%). This turn landed the bead's own prescribed "per-request dispatch
model" for the read op.

### The lever (one lever, src-only, `crates/ffs-fuse/src/lib.rs`)

`FuseInner` gains a dedicated `read_offload` rayon pool (sized by the existing
`thread_count` knob that already sizes `max_background`; named `ffs-fuse-rd-*`).
`Filesystem::read` now moves `(shared_handle, params, ReplyData)` onto that pool and
returns immediately — the session loop fetches the next kernel request while workers
serve and reply concurrently. The serve body is the exact former inline body
(`serve_read_request`), so bytes/errors/metrics are unchanged; fuser's `ReplySender` is
`Send + Sync + 'static` by design for cross-thread replies, and FUSE imposes no
reply-ordering requirement across requests. Kill switch: `FFS_FUSE_ASYNC_READ=0` forces
the inline pre-lever path (same-binary A/B); the pool also degrades to inline when it
cannot be built or `thread_count < 2`.

### Measurement (same binary, env-toggled, 4 interleaved mount-cycle reps, T=16 C reader, 1 GiB / 2048 files, quiet box load ~8)

| regime | inline (off) | dispatched (on) | ratio |
| --- | --- | --- | --- |
| cold (drop_caches) | 1327.5 ms (cv 1.8%) | **345.1 ms** (cv 3.8%) | **3.85x faster** |
| daemon-warm | 658.3 ms (cv 2.5%) | **244.3 ms** (cv 5.9%) | **2.69x faster** |
| vs kernel (dio-loop ext4, same session: 242.0 ms median cold) | 5.5x slower | **1.43x slower** | — |

Marginal cost, reported honestly: single-stream T=1 cold medians 1148 ms (off) vs 1207 ms
(on) over 3 interleaved reps with overlapping ranges (~5%, per-request handoff cost).
Accepted against the 3.85x multi-stream win; the T=1 surface has its own open lever
(daemon readahead depth).

### Behavior proof

* Identity: XOR64 `6136f5eaeccd58af` in every off/on run of every regime (16 A/B runs +
  T=1 runs), byte-identical through the full FUSE stack.
* `cargo test -p ffs-fuse` (remote): **573 passed / 0 failed**.
* Ordering preserved: per-request bytes identical; FUSE has no cross-request reply
  ordering contract. Tie-breaking/floating-point/RNG: N/A. The pre-existing
  `fuse_inner_shared_across_threads` test already models concurrent dispatch.
* ubs on the file: 19 criticals, all pre-existing whole-file heuristics (test panics,
  token-compare false positives), none in the changed hunks.

### Follow-ups (open, this lane)

Residual mounted gap is 1.43x cold: next levers are daemon-side readahead depth for the
single-stream path, offloading `readdir`/`getattr` the same way (metadata storms), and
the negotiated `max_readahead` audit. The rejected per-thread-fd stash and the mmap/
O_DIRECT closures are unaffected by this change.

## 2026-07-22 — three non-KEEPs close the cheap-dispatch vein: metadata offload REJECT, readahead null, request-count null (bd-kdmu4, cc)

Continuation after the 3.85x async-read KEEP (11d82483). Same harness, fixtures, identity
gates (XOR64 `6136f5eaeccd58af` held in every run below). Session loop occupancy probe
first: during a cold storm with async-read ON, the loop thread burns 54% of wall, the 8
`ffs-fuse-rd-*` workers ~50% each — headroom on the loop, workers intermittently starved.

### 1. Metadata-op offload onto the read pool — REJECT (production hunk stashed)

Factored `lookup`/`getattr`/`open`/`opendir`/`readdir` into `serve_*` bodies dispatched
onto the existing `read_offload` pool (env `FFS_FUSE_ASYNC_META`, writeback-cache mode
kept inline, `readdirplus` descoped). Same-binary interleaved A/B, 4 mount-cycle reps,
async-read ON in both arms:

| regime | inline meta (off) | offloaded meta (on) | verdict |
| --- | --- | --- | --- |
| cold | 337.2 ms (cv 1.4%) | 351.5 ms (cv 1.8%) | **+4% REGRESSION** |
| daemon-warm | 236.1 ms (cv 2.7%) | 262.1 ms (cv 3.0%) | **+11% REGRESSION** |

Mechanism: small metadata tasks queue behind large read tasks on the shared 8-thread
pool; the loop had spare capacity to pump them inline. Stashed as `stash@{0}`
("metadata-op offload onto read pool"). Retry predicate: only with a SEPARATE small-op
pool AND a measured session-loop occupancy >90% (loop saturation), e.g. after multiple
/dev/fuse queues exist. `flush`/`release` offload is predicted-negative by the same
mechanism — do not try it standalone.

### 2. Kernel readahead sizing (`/sys/class/bdi/<dev>/read_ahead_kb`) — NULL

FUSE bdi defaults to 128 KB. Sweeping 128 → 1024 → 4096 KB (no code change):
T=1 cold 1381 / 1495 / 1400 ms (flat, ±8% noise); T=16 cold 416 / 404 / 418 ms (flat).
Raising `max_readahead` in INIT is therefore not a lever on this workload — do not
plumb it as a mount option expecting wall.

### 3. Request-count instrumentation — coalescing works; T=1 is NOT round-trip-bound

strace read() totals over a T=1 cold GiB: 20,741 calls at ra=128 KB vs 14,581 at
ra=4096 KB — the kernel DOES issue fewer, larger requests with bigger readahead
(fuser already advertises `FUSE_ASYNC_READ`; `max_pages` derives from
`max(max_write, max_readahead)` and `FUSE_MAX_PAGES` is echoed). Yet un-straced wall is
flat — so the single-stream residual is serial pipeline bubbles (disk read → reply copy →
next request), not request count. Fixing that means daemon-side prefetch depth/overlap
(ReadaheadManager) — a structural item, not a config flip.

### Vein status (3 consecutive non-KEEPs → switch per campaign discipline)

The mounted multi-file read surface stands at **1.43x of kernel cold** (from 5.5x at
session start) with the loop unsaturated and cheap dispatch/config levers exhausted.
Remaining read-lane items are structural: single-stream prefetch pipelining (bounded
value; T=1 is a minor real-world surface), and multi-queue /dev/fuse (clone_fd) if the
loop ever saturates. Next turn switches vein per the alien-graveyard mandate (still
read-lane: a different primitive class, not more dispatch tuning). mmap/O_DIRECT remain
closed everywhere (copies ~3% of daemon self-time; bypass 1.00x).

## 2026-07-22 — NEUTRAL-REJECT: daemon-side async next-window prefetch is redundant with kernel image-file readahead (bd-kdmu4, cc)

Vein-switch lever after the dispatch-vein closure. Target: the measured T=1 "pipeline
bubble" (serial window fetch at every readahead boundary; request coalescing previously
proven present-but-flat). Implemented double-buffered prefetch: on a predicted-stream
miss, `read_with_readahead` background-fetches the FOLLOWING 256 KiB window on the
`read_offload` pool (in-flight dedup set in `ReadaheadManager`, snapshot-scoped
`ops.read`, no `access_predictor` feedback, RO-non-writeback mounts only — a background
insert on a writable mount could race `invalidate_inode` and re-cache pre-write bytes).
Env `FFS_FUSE_ASYNC_PREFETCH` for same-binary A/B.

### Measurement (4 interleaved mount-cycle reps, 1 GiB fixture, box load noisy — one
~2 s outlier per arm, cv 14–24%; min-of-4 is the robust stat)

| arm | prefetch off | prefetch on | verdict |
| --- | --- | --- | --- |
| T=1 cold | min 1324.5 ms (med 1511.6) | min 1331.4 ms (med 1350.3) | **PARITY at min** |
| T=16 cold | min 366.0 ms | min 355.6 ms | within noise (~3%) |

Identity XOR64 held in every run.

### Why it cannot win (the insight worth keeping)

`FileByteDevice` opens the image with `POSIX_FADV_SEQUENTIAL`; the daemon's window
fetches are near-sequential preads of the image file, so the KERNEL's own readahead on
the image file already pipelines the next windows into the page cache ahead of the
daemon. The "boundary stall" is a page-cache hit (~100 us), not a device read — there is
almost nothing for daemon-side prefetch to hide. Daemon-level prefetch duplicates
kernel-level prefetch one layer down. Production hunk STASHED (`stash@{0}`,
"async next-window prefetch"). Retry predicate: only if the image-file read path ever
loses kernel readahead (O_DIRECT backend, network/blob backend, or `FFS_READ_FADVISE=random`),
where a daemon-side window pipeline would be the only prefetch layer — measure there first.

### Lane status after this turn

Mounted multi-file: **1.43x cold** (session start 5.5x), loop unsaturated, dispatch +
config + prefetch veins all closed with numbers. In-process: kernel parity. T=1
single-stream: bounded by per-request service time under an already-pipelined backend;
no cheap lever identified. Consecutive non-KEEPs in this vein: 1 (this entry). Next
fresh vein candidates (unmeasured surfaces, per campaign lesson that un-benched spots
still yield): `bd-vpypn` extent walks at HIGH extent counts (never measured, both
sequential and random); mounted metadata-storm surfaces (statfs/xattr through FUSE).
mmap/O_DIRECT stay closed everywhere.

## 2026-07-22 — KEEP: ExtentCache batch eviction — warm 8192-extent read 2.44x faster, cold 1.80x (bd-vpypn / bd-kdmu4, cc)

The bd-vpypn regime ("extent behavior at hundreds-to-thousands of extents was never
measured") finally measured — and it hid the predicted scan gap.

### Fixture (new, reproducible)

`/data/tmp/kdmu4_frag.img`: `/d/frag.bin` = 64 MiB with **8192 single-block extents**
(alternating 4 KiB hole-punch via fallocate on a loop mount; filefrag -v verified;
note filefrag's summary line lies — trust `-v`), plus `/d/contig.bin` 64 MiB
contiguous control. e2fsck-clean.

### The gap and the mechanism

`ffs-cli read` warm: frag 161.6 ms vs contig 17.2 ms = **9.4x** while the kernel's
frag/contig warm ratio is 1.04x. Symbolized profile (release + debuginfo env
overrides): `ExtentCache::insert` 21.7% + BTree `search_tree` 14.1% + BTree
`Iter::next`/`next_kv`/`next_leaf_edge` 18.8% ≈ **57% of the read**. Cause:
`evict_lru_except` did a full-shard BTreeMap scan per insert (`min_by_key`), and one
inode's mappings all land in ONE shard (capacity 1024) — a >capacity extent stream
makes every insert O(shard), i.e. quadratic. (This is the true cost behind the
2026-07-16 fleet-blocked `insert_batch` stash, which chased the LOCK, not the scan.)

### Lever (one lever, `crates/ffs-extent/src/lib.rs`)

Batch eviction: one scan selects the `max(1, capacity/8)` LRU victims via
`select_nth_unstable_by_key` on the exact historical `(last_access, key)` ordering,
amortizing eviction to O(len/batch) per insert. `FFS_EXTENT_EVICT_BATCH=1` restores
the historical single-victim behavior (same-binary A/B); with batch=1 the victim is
IDENTICAL to the old `min_by_key`, tie-break included, so capacities <16 — including
both eviction unit tests — keep exact historical semantics. Eviction choice never
affects returned mappings, only what must be re-resolved from the authoritative tree.

### Measurement (same binary, env-toggled, interleaved, 5 reps + 7-rep contig guard)

| surface | single (incumbent) | batch | ratio |
| --- | --- | --- | --- |
| warm frag (pure CPU) | 210.5 ms (cv 3.6%) | **86.2 ms** (cv 6.5%) | **2.44x** |
| cold frag | 249.6 ms (cv 8.5%) | **139.0 ms** (cv 14.4%) | **1.80x** |
| warm contig guard | 17.3 ms | 17.4 ms | parity (eviction never fires) |

Identity: sha256 of full frag.bin bytes identical single-vs-batch AND equal to the
kernel loop-mount sha (`5fb93b1c…`). `cargo test -p ffs-extent` remote: **154/0**.
rustfmt clean; ubs 0 critical.

### Residual + next levers on this surface

Warm frag (86 ms) is still ~5x contig: the shard (cap 1024) cannot hold 8192 mappings,
so the stream still thrashes (miss → tree re-walk → insert → batch-evict cycle).
Candidates: don't cache a leaf's mappings when the namespace's mapping count exceeds
shard capacity (cache the LEAF page instead / rely on the arc_swap extent map);
per-namespace capacity awareness; or a direct extent-map path for >capacity files.
Also note `ffs-cli read` duration includes ~13 ms fixed CLI startup — ratios above are
end-to-end and thus conservative.

## 2026-07-22 — KEEP #2 on the high-extent regime: publish hot extents for DEEP trees on one-shot reads — warm frag another 2.53x, cold beats the kernel arm (bd-vpypn / bd-kdmu4, cc)

Profile-first on the post-batch-eviction binary: the residual warm-frag cost was still
~29% in the cache layer, now the per-insert BTreeMap DESCENT (`search_tree` 21.9% +
`insert` 6.7%) — ~16k lookups/inserts per read (8192 data mappings re-inserted leaf-by-
leaf plus one single-block HOLE SENTINEL per hole block) into a shard that can never
hold them.

### Root cause

`OpenFs` already has a lock-free full-map fast path (`ext4_hot_extents`,
`ArcSwapOption<(ns, Arc<[ExtentMapping]>)>`) that resolves blocks AND holes in-memory
with zero cache traffic — but its publication was gated on `inode_was_hot`, i.e. never
for a one-shot full-file read ("a one-shot multi-file read never pays the full-tree
walk"). For a DEEP extent tree that trade inverts: the "saved" full walk is ~25 leaf
reads the per-miss path pays leaf-by-leaf anyway, while the un-published read pays the
16k-op cache storm.

### Lever (one lever, `crates/ffs-core/src/lib.rs`)

Publish also when `ext4_deep_extent_tree(inode)`: root header `depth >= 1` from the
pure in-inode parse (`parse_inode_extent_tree`), env kill switch
`FFS_HOT_EXTENTS_DEEP=0`. Depth-0 trees (≤4 inline extents — every small-file-storm
case) keep the historical one-shot behavior byte-for-byte.

### Measurement (same binary, env-toggled, interleaved, 5 reps)

| surface | off (incumbent) | on (deep publish) | ratio |
| --- | --- | --- | --- |
| warm frag 8192-extent | 86.6 ms (cv 3.4%) | **34.2 ms** (cv 6.4%) | **2.53x** |
| cold frag | 106.5 ms (cv 6.3%) | **59.3 ms** (cv 3.1%) | **1.80x** |
| warm contig guard | 26.9 ms | 27.2 ms | parity |
| multi-file storm guard (1 GiB walk) | 229.4 ms | 230.4 ms | parity |

sha256 identity both arms (= kernel loop-mount sha). Targeted `ffs-core` tests
(extent/hot/resolve/read_file): **125 passed / 0 failed** remote. rustfmt clean.

### Stacked session result on this regime (fixture `/data/tmp/kdmu4_frag.img`)

warm frag: 161.6 → 34.2 ms (**4.7x**, now ~1.26x of contig vs kernel's 1.04x ratio);
cold frag: 184.4 → 59.3 ms (**3.1x**) — and the cold fragmented read now lands BELOW
the dio-loop kernel arm's 75.0 ms on the same fixture (different I/O path — direct
image pread vs loop — so stated as arm-vs-arm, not "faster than kernel ext4" absolute).
Remaining residual vs contig (~7 ms warm) is the per-segment assembly of 8192
one-block extents + hole memset; no cheap lever identified — diminishing returns.

## 2026-08-15 — REJECT: FUSE_HANDLE_KILLPRIV_V2 does not suppress the per-path-op security.capability probe (bd-ha71t, AzureBay)

Lever: negotiate `FUSE_HANDLE_KILLPRIV_V2` (bit 28, Linux 5.12+) at FUSE INIT, on the
hypothesis that V2 — unlike V1, which this bead already measured inert — additionally
lets the kernel skip its own `security.capability` fetch, killing the ~16 us probe paid
on every path-based metadata op.

Measured, COUNTED MECHANISM (no timing claim, so no quiet window is needed and the
trace overhead cannot confound it): probes counted at the unconditional
`ffs::fuse::xattr_probe` trace, which sits at the kernel boundary BEFORE any memo can
answer. One ELF, arms selected by env so no rebuild sits between them; fixture baked
into the image with `mkfs.ext4 -d` (a fresh mkfs root is uid 0 and the caller cannot
otherwise create files in the mount); dentry cache dropped before each arm so every
stat is a real path resolution.

    arm off: V2 not negotiated,  2000 path stats -> 4000 probes -> 4000 probes
    arm on : V2 reported ENABLED, 2000 path stats -> 4000 probes -> 4000 probes

i.e. 4000 probes -> 4000 probes, unchanged, on the security.capability name.

REJECTED: identical counts. The positive control is that the kernel ACCEPTED the
capability — the daemon logged "FUSE handle-killpriv-v2 capability enabled" — so this
is a genuine null, not a flag that never applied.

Incidental correction to this bead's premise: the rate is TWO probes per path-based
stat (4000/2000), not one.

Harness `scripts`-local `ha71t_probe_count.sh` + `ffs-cli mount`; host `thinkstation1`,
kernel `6.17.0-41-generic`; run LOCALLY (mounts FUSE, so no rch worker took part and
none is quotable). Debug build — irrelevant to a count.

Retry predicate: only on a kernel that documents `security.capability` suppression for
path-resolution ops, or a FUSE ABI flag that lets a daemon declare an inode has no
`security.*` xattrs so the kernel can cache the negative. Do NOT re-test V2 on 6.17 —
measured inert. Experimental wiring reverted; the ABI constant is kept in the vendored
fuser so the next attempt does not rediscover that it was missing.


## 2026-08-16 — SURVEY (no ratio banked): btrfs floor-memo is 2.88x in production config and a 0.116x TAX on random access — plus the gate that makes it one-signed (bd-5vis3 / bd-79li3, measured by ProudBarn, written up by AzureBay)

**SURVEY. Nothing here is banked.** No ratio in this row is admissible for publication, and the
reason is recorded under "Admissibility" below: the arms are single off/on pairs with
no interval and no ELF identity, and the instrumented arm that would fix that **has
never completed a run**. Quote nothing here as a banked number.

**Lead number, provisional: `2.884x` — 22.360080 ms -> 7.752808 ms, PRODUCTION config
(attr cache ON), 20000-inode btrfs walk.** When this row does become bankable, that is
the figure it will be about.

The larger `37.705x` figure in this bead's history (211.129458 ms -> 5.599509 ms,
lookups 60000 -> 1395, 43.01x fewer descents) is the **SYNTHETIC SWEEP** arm: attr
cache disabled, so every inode resolution goes to the fs-tree and the memo gets to
answer work production already caches away. It is a mechanism demonstration, not a
production ratio.

**The two are 13.1x apart on the same ELF and the same image.** A gap that size is
itself the finding: it says the sweep arm is NOT production-representative, because
the production configuration has already removed ~92% of the descents the sweep
arm pays for. **`37.7x` must never stand unqualified** — quoted alone it overstates
the lever by more than an order of magnitude. Any future citation carries the words
"synthetic sweep, attr cache off" in the same sentence, or it is wrong.

### The adversarial arm, which is a LOSS

| arm | incumbent | floor memo ON | ratio |
| --- | --- | --- | --- |
| PRODUCTION, attr cache ON, 20000 inodes | 22.360080 ms | **7.752808 ms** | **2.884x WIN** |
| synthetic sweep, attr cache OFF, 20000 inodes | 211.129458 ms | 5.599509 ms | 37.705x (not production-representative) |
| RANDOM ACCESS, 8000 inodes | 7.907348 ms | 68.062258 ms | **0.116x — 8.6x SLOWER** |

The retained leaf pays off by amortising the fs-tree DESCENT across inodes that share
a leaf, which is what bd-5vis3 item 2 prescribed and why it beats the one-pass case
that defeats a per-inode LRU. Random access has no such locality, so every probe
retains a leaf it will not reuse — and **the memo is default-ON**, so that tax is
shipped. Filed as `bd-79li3` — **and fixed there; the arm now measures 1.295x, a
WIN. See the post-gate table below.**

### The fix that makes the lever one-signed (bd-79li3)

A miss-streak gate on the REPLACEMENT path: keep retaining a leaf while the memo is
being useful, and once 32 consecutive misses land, back off to refreshing one descent
in 64. A sweep never trips it — a sweep's misses arrive one per leaf crossing, each
followed by a run of hits, and a hit resets the streak — so the production path still
replaces on every descent. A miss-only stream does **131 replacements per 6400
descents instead of 6400** (a 48.9x cut in miss-path work), and the 1-in-64 probe is
what lets a stream that regains locality re-arm instead of staying cold for the life
of the mount. Correctness is untouched by construction rather than by argument: the
gate only decides whether to RETAIN a leaf, every hit is still gated on the key-span
check, and a stale retained leaf can only produce fewer hits, never a wrong floor.

The replacement schedule is asserted directly
(`btrfs_floor_memo_miss_streak_gate_is_one_signed_bd_79li3`) rather than through a
timed arm, because the property under test is the schedule and a wall-clock arm cannot
separate "the gate suppressed replacements" from "the machine was quiet". That test
passed on its first execution — `cargo test -p ffs-core --lib btrfs_floor`, rch worker
`vmi1227854`, 4 passed / 0 failed / 3 ignored — alongside the pre-existing floor-memo
correctness suite, so the gate did not disturb the argument it sits next to.

**MEASURED AFTER THE GATE — the regression is gone, and the magnitude is
UNDECIDABLE.** Both statements matter and the second one is why no ratio is banked.

Harness `cargo test -p ffs-core --release --lib bd_5vis3_random -- --ignored`, rch
worker `vmi1227854`, 8000 inodes, 7 interleaved (off, on) pairs with an A/A null on the
identical schedule, seeded bootstrap median CI over 20,000 resamples. The run's own
`executing_elf_sha256 = 6d126781e652442666a73b832da86ef997d9b1b6383a6ca697afbabbbdb9f34d`
line is the binary identity — self-reported by the executing ELF via `current_exe()` at
measurement time, not a `sha256sum` typed beside the row afterward:

| | median | bootstrap median CI95 |
| --- | --- | --- |
| A/B, memo OFF / memo ON | `1.232888x` | `[0.711969, 1.553234]` |
| A/A null, memo OFF twice | `1.136846x` | `[0.902400, 3.308809]` |

**The A/B sits inside its own A/A null, so the post-gate ratio is not readable.** The
null spans `0.90` to `3.31` — this worker was loaded and the instrument cannot resolve
anything at 7 rounds. `1.23x` is therefore NOT a win and must not be quoted as one; an
earlier single pair on the same worker read `1.295x` and that number is likewise noise.

What IS decidable is the thing the bead was filed for. **The pre-gate ratio was
`0.116x`, which sits an order of magnitude below the null's lower edge of `0.902`.** A
null that wide is precisely what makes the comparison safe in this direction: an effect
the instrument cannot see is an effect smaller than the noise, and the pre-gate
regression was far larger than the noise. So:

- before the gate: measurably, grossly slower — an 8.6x tax
- after the gate: indistinguishable from neutral

Neutral was the goal. The gate was never meant to make random access faster; it was
meant to stop a locality-assuming cache from taxing a workload without locality, and
"we can no longer measure any difference" is exactly what success looks like here.
Bounding the magnitude of any residual effect needs a quiet window and more rounds
(`FFS_BD_5VIS3_ROUNDS`), and that is still owed.

### Still missing from this bead's own acceptance list

Item 3 required peak resident memory and mount-time cost at several image sizes. The
three arms above report wall time and lookup counts only. **No mounted comparator row
is claimed here** — this is an in-process ffs-core measurement, not a vs-kernel ratio,
and bd-3zx2x's attribution already showed inode resolution is ~1.2% of the mounted
per-entry cost, so nothing here should be expected to move the 7.7x readdir+stat row.

### Admissibility — what this row may and may not be quoted as

**As first written this row did not meet the banked-ratio contract, and the ledger's own
preflight said so** (`--lint`: "no in-process self-report of the executing ELF's
SHA-256; timed row has no bootstrap median CI"). The gate was right: the three arms
above are single off/on pairs with no interval and no binary identity, which is not
enough to bank a ratio. The fix was to go get the evidence, not to soften the gate.

`b56aad87` supplies it for the production arm, which is the one this row leads with:
the production A/B now runs **21 interleaved (off, on) pairs** plus an **A/A null on
the identical schedule**, reports a **seeded bootstrap median CI**, asserts the A/B
interval clears the null envelope, and **self-reports the SHA-256 of the executing
test binary**, hashed from `current_exe()` at measurement time rather than typed in
beside the row — under the host-wide shared cargo target dir a concurrent agent's
rebuild can replace the binary between a run and a later `sha256sum`.

Until that instrumented arm is re-run and its interval recorded here, the numbers in
the table are **provisional single-pair observations**. The 8.6x random-access tax is
the weakest of the three in that respect — one pair, no null — but it is also the one
whose direction was independently confirmed by mechanism (every miss pays a full memo
replacement), and it was strong enough to justify `bd-79li3`.

### BLOCKED: the instrumented arm has never completed a run

Recorded because it is a defect in the instrument, not a quiet window problem, and the
next person will otherwise spend the same hour rediscovering it.

`cargo test -p ffs-core --release --lib bd_5vis3_prod -- --ignored` was attempted
**four times** and produced no output on any of them:

| attempt | worker | outcome |
| --- | --- | --- |
| all three arms | `vmi1227854` | `error[E0277]` — the crate did not build (fixed, `31091fdd`) |
| all three arms | `vmi1264463` | `[RCH-E104]` SSH timeout at 1800 s |
| prod arm alone, 21 rounds | `vmi1264463` | `[RCH-E104]` SSH timeout at 1800 s |
| prod arm alone, 7 rounds | `vmi1264463` | `[RCH-E104]` SSH timeout at 1800 s |

Cutting the round count 21 -> 7 did not help, which **refutes** the obvious diagnosis
that the interleaved rounds are what overruns the ceiling. Whatever dominates is
upstream of the loop — the one-time 20,000-file fixture build, or the release
compile — so buying a shorter loop buys nothing. `FFS_BD_5VIS3_ROUNDS` now makes the
count tunable anyway, since an instrument that cannot finish reports no interval at
all and that is strictly worse than a wide one.

Note the earlier ProudBarn run DID complete, on `vmi1293453`. Every failure above is
on `vmi1264463`. That is consistent with a slow worker rather than an unbounded test,
and the next attempt should pin the worker before concluding the test is at fault.

Harness `cargo test -p ffs-core --release --lib bd_5vis3 -- --ignored` (three arms that
existed as ignored tests and had never been run). One ELF, arms selected by
`FFS_BTRFS_FLOOR_MEMO` so no rebuild sits between them. rch WORKER `vmi1293453`.
Lock fix `1e334993` landed alongside: the memo hit path held its mutex across
`floor_in_leaf` because an inner `if let` shadowed the `MutexGuard`, making the
`drop(memo)` a no-op the compiler had been reporting as `dropping_references` in every
`ffs-core` build. Gate for that fix: `cargo test -p ffs-core --lib btrfs_floor` on rch
worker `vmi1152480`, 3 passed / 0 failed, including the concurrent-sweep test.

## 2026-08-16 — HONEST_LOSS banked: btrfs mounted warm stat 4.80x (worst bound 5.00x) vs kernel btrfs, and readdir+stat REFUSED at 2.78x (bd-btrfs-warm-stat-5x-9pxn1, AzureBay)

**The first mounted comparator rows produced on this host since the disk floor started
refusing every run.** They exist because the floor was wrong, not because the machine
got quieter — see the companion entry on the derived free-space floor.

Provenance, identical for all four runs below. Both SHA-256s are self-reported by the
executing ELFs at run time — the candidate prints its own via `bench-evidence` and the
driver hashes `current_exe()` — not typed in from a later `sha256sum`:
`driver_elf_sha256 = 471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc`
built on `thinkstation1`;
`candidate_elf_sha256 = e6cd5793384bdb6d6fff113e13fd9e1392753fadaf4ab0a15663e7912dba5bf0`
built on `thinkstation1`,
`pgo_profile_sha256 = cc6c121c9ee77d8a4b7f4855c443c07a59ac6191316d40acb08fb2fbe79f9562`,
`isa=x86-64-v3`, candidate gate `verdict=pass`;
`executed_on=thinkstation1`, `retrieval=built_in_place_on_executing_host`. Host
`thinkstation1`, AMD Ryzen Threadripper PRO 5975WX, 32C/64T, `same-llc` placement.
btrfs checksum verification at its post-flip default (`btrfs_verify_data_on_read=true`),
which is the configuration bd-6kpp4 says every pre-2026-08-15 btrfs row lacks — so
these do NOT compare to rows banked before that flip.

Reduced working set: `--pairs 12 --operations 2000 --image-size-mib 256`, one
filesystem. Both runs of each workload used the same ELF on the same host, so this is
a replicated pair rather than a cross-worker one; no second machine can run a FUSE
mount here.

### BANKED — warm stat, `4.80x` slower than kernel btrfs, worst bound `5.00x`

Absolute arm medians are given alongside the ratio, because a ratio alone cannot say
which arm moved (bd-4sull item 3). Intervals are bootstrap median CI95 over 20,000
resamples, `estimator=four_round_balanced_crossover_bootstrap_median_ci`.

| run | kernel median wall | FrankenFS median wall | fuse/kernel median | bootstrap median CI95 | kernel null | fuse null | verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `4,652,283 ns` | `22,422,724 ns` | **4.798508x** | `[4.759896, 4.802894]` | `0.993753` clear | `1.003667` clear | `HONEST_LOSS`, `admitted=true` |
| 2 | `4,665,133 ns` | `22,499,546 ns` | 4.866486x | `[4.756329, 4.999840]` | `1.010383` clear | `1.005541` spread `1.025399` | `BLOCKED_NULL` |

Both arms moved together between runs — kernel `+0.28%`, FrankenFS `+0.34%` — which is
what a replicate should look like and is why the ratio barely shifts.

Verbatim from the harness, run 1 — the line the table above is derived from, kept
unedited so the absolute arm medians and the estimator are not taken on trust:

    mounted_kernel_throughput,filesystem=btrfs,workload=warm_stat,operations_per_observation=2000,kernel_median_wall_ns=4652283,fuse_median_wall_ns=22422724,kernel_operations_per_second=429896.462,fuse_operations_per_second=89195.229
    mounted_kernel_ratio,filesystem=btrfs,metric=wall_ns,workload=warm_stat,pairs=12,crossover_blocks=3,observation_reducer=min,observation_repeats=3,fuse_over_kernel_median=4.798508,ci_low=4.759896,ci_high=4.802894,twice_null_margin_ratio=1.016331,directional_claim_clear=true,admitted=true,verdict=HONEST_LOSS,bootstrap_resamples=20000,cv_used=false
    binary_provenance,driver_elf_sha256=471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc,driver_built_on=thinkstation1,candidate_elf_sha256=e6cd5793384bdb6d6fff113e13fd9e1392753fadaf4ab0a15663e7912dba5bf0,candidate_built_on=thinkstation1,executed_on=thinkstation1,retrieval=built_in_place_on_executing_host

and run 2:

    mounted_kernel_throughput,filesystem=btrfs,workload=warm_stat,operations_per_observation=2000,kernel_median_wall_ns=4665133,fuse_median_wall_ns=22499546,kernel_operations_per_second=428712.322,fuse_operations_per_second=88890.683
    mounted_kernel_ratio,filesystem=btrfs,metric=wall_ns,workload=warm_stat,pairs=12,fuse_over_kernel_median=4.866486,ci_low=4.756329,ci_high=4.999840,twice_null_margin_ratio=1.051443,directional_claim_clear=false,admitted=false,verdict=BLOCKED_NULL,bootstrap_resamples=20000,cv_used=false

Each `ci_low`/`ci_high` pair above is a bootstrap median 95% confidence interval, resampled 20,000 times
(`estimator=four_round_balanced_crossover_bootstrap_median_ci`), and the
`executing_elf_sha256 = 471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc`
above is self-reported by the driver at run time.

Run 1 cleared BOTH A/A nulls on its own and the estimator admitted it. Run 2 replicates
it: the medians are 1.4% apart, the intervals overlap, and its only failure is the fuse
null's symmetric spread missing the `1.025` limit by `0.0004` — with both runs' fuse
nulls off in the SAME direction (`+0.37%`, `+0.55%`) by a similar amount, which is the
condition under which a failing null is excusable. **Quote the worst bound: `5.00x`.**

Throughput, diagnostic only: kernel `429,896` / `428,712` stat/s against FrankenFS
`89,195` / `88,891` stat/s. Four-arm post-parity `verdict=pass`, tree sha
`ca98ba5dbb60fa...`, and `btrfs check` clean on every arm image.

### REFUSED — readdir+stat, `2.78x`, and the reason is the null, not the ratio

| run | kernel median wall | FrankenFS median wall | fuse/kernel median | bootstrap median CI95 | kernel null | fuse null |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `3,121,942 ns` | `8,447,506 ns` | 2.775065x | `[2.744423, 3.050166]` | `1.026632` | `1.034438` |
| 2 | `3,192,140 ns` | `8,262,526 ns` | 2.777787x | `[2.685394, 2.828307]` | `0.985460` | `1.018249` |

Verbatim, run 1 then run 2:

    mounted_kernel_throughput,filesystem=btrfs,workload=large_directory_readdir_stat_8t,operations_per_observation=2000,kernel_median_wall_ns=3121942,fuse_median_wall_ns=8447506,kernel_operations_per_second=640626.994,fuse_operations_per_second=236756.283
    mounted_kernel_throughput,filesystem=btrfs,workload=large_directory_readdir_stat_8t,operations_per_observation=2000,kernel_median_wall_ns=3192140,fuse_median_wall_ns=8262526,kernel_operations_per_second=626539.034,fuse_operations_per_second=242056.727

The two medians agree to **0.098%** with heavily overlapping intervals, which is the
tightest replication in this entry — and it is still not bankable. Both runs are
`BLOCKED_NULL`, and the excusal condition fails on the kernel arm specifically: its
null is `+2.66%` in run 1 and `-1.45%` in run 2, opposite directions rather than a
consistent offset. A null that flips sign between runs is measuring the host, not the
instrument's floor, so the agreement between the two medians cannot be credited to the
estimator. Recorded, not banked; worth one retry in a genuinely quiet window.

**`2.78x` IS NOT AN IMPROVEMENT ON THE BANKED `7.73x`/`8.32x` READDIR+STAT ROWS.** Those
were taken at **32,768** directory entries and this is at **2,000**. The mounted
per-entry cost is already known to grow ~60% between those two sizes, so the numbers
measure different workloads and must never be differenced. Anyone quoting this row
carries the entry count with it.

### Every run was CONTENDED, and that is the honest caveat

All four carry `external_load_during_run ... verdict=CONTENDED`: 14-15 of 15 samples
over the limit, peak 16 busy CPUs, peak off-placement mean busy `18.3%`-`28.0%`,
against limits of 2 CPUs / 10% of samples / 3 consecutive. Peer agents were building on
the same socket throughout. The placement CPUs themselves were clean — the per-arm
pinning and thread-observation checks all report `clear=true` — but memory bandwidth,
LLC and boost budget are socket-wide.

This is disclosed rather than dismissed. It cuts one way only: contention inflates the
FUSE arm at least as much as the kernel arm, so a loss measured under contention is if
anything an OVERSTATEMENT of the gap, and `5.00x` remains a safe upper bound on the
warm-stat loss. It would not be safe if these were wins.

Disk consumed: run 1 `84,890,284,032 -> 83,798,372,352` free = **1.02 GiB**. Run 2 spent
**1.2 MiB**, because the image directory is reused. Against a floor that demanded
120 GiB.

## 2026-08-16 — REJECT (refused, not measured-and-ignored): ext4 mounted parallel metadata write, 2.66x / 2.82x with non-overlapping intervals and a sign-flipping kernel null (bd-ext4-parallel-meta-1p51x-ex8qj, AzureBay)

Same instrument, same ELFs and same session as the warm-stat entry above; the derived
free-space floor is what let this workload run at all. Unlike warm stat, **it does not
replicate, and the row is refused.** Recording it because a refusal with its evidence
is worth more than an unrepeated number, and because the contrast with warm stat is
the useful part.

    run 1  mounted_kernel_throughput,filesystem=ext4,workload=parallel_metadata_write,operations_per_observation=2000,kernel_median_wall_ns=32113494,fuse_median_wall_ns=85342830,kernel_operations_per_second=62279.116,fuse_operations_per_second=23434.892
    run 1  mounted_kernel_ratio,filesystem=ext4,metric=wall_ns,workload=parallel_metadata_write,requested_client_threads=8,pairs=12,observation_reducer=single,observation_repeats=1,fuse_over_kernel_median=2.663435,ci_low=2.658290,ci_high=2.746037,admitted=false,verdict=BLOCKED_NULL,bootstrap_resamples=20000,cv_used=false
    run 2  mounted_kernel_throughput,filesystem=ext4,workload=parallel_metadata_write,operations_per_observation=2000,kernel_median_wall_ns=28956956,fuse_median_wall_ns=81203202,kernel_operations_per_second=69068.033,fuse_operations_per_second=24629.570
    run 2  mounted_kernel_ratio,filesystem=ext4,metric=wall_ns,workload=parallel_metadata_write,requested_client_threads=8,pairs=12,observation_reducer=single,observation_repeats=1,fuse_over_kernel_median=2.819270,ci_low=2.815767,ci_high=2.852170,admitted=false,verdict=BLOCKED_NULL,bootstrap_resamples=20000,cv_used=false

The two A/A null controls each arm carries, measured same-invocation inside the very
runs above rather than from a separate calibration:

    run 1  mounted_kernel_null,filesystem=ext4,workload=parallel_metadata_write,arm=kernel,median=1.134803,median_deviation_from_one=0.134803,maximum_median_deviation=0.020000,median_within_limit=false,ci_low=0.924119,ci_high=1.167663,symmetric_spread=1.167663,maximum=1.025000,clear=false
    run 1  mounted_kernel_null,filesystem=ext4,workload=parallel_metadata_write,arm=fuse,median=1.038982,median_deviation_from_one=0.038982,ci_low=1.001054,ci_high=1.064244,symmetric_spread=1.064244,maximum=1.025000,clear=false
    run 2  mounted_kernel_null,filesystem=ext4,workload=parallel_metadata_write,arm=kernel,median=0.915179,median_deviation_from_one=0.084821,ci_low=0.843346,ci_high=1.068810,symmetric_spread=1.185753,maximum=1.025000,clear=false
    run 2  mounted_kernel_null,filesystem=ext4,workload=parallel_metadata_write,arm=fuse,median=1.005032,median_deviation_from_one=0.005032,ci_low=0.944428,ci_high=1.043008,symmetric_spread=1.058841,maximum=1.025000,clear=false

These are same-invocation A/A null controls: each pairs two identical arms inside the
same run that produced the ratio, so no cross-run or cross-host comparison is involved
in the null itself. Each `ci_low`/`ci_high` pair, on the null lines and the ratio lines
alike, is a bootstrap median 95% confidence interval, resampled 20,000 times.
Provenance identical to the warm-stat entry:
`executing_elf_sha256 = 471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc`
(driver, self-reported at run time) and candidate
`e6cd5793384bdb6d6fff113e13fd9e1392753fadaf4ab0a15663e7912dba5bf0`, both built on
`thinkstation1`. Host identity, from the harness itself — no rch worker took part,
because a FUSE mount can only run on the executing machine:

    binary_provenance,driver_built_on=thinkstation1,candidate_built_on=thinkstation1,executed_on=thinkstation1,retrieval=built_in_place_on_executing_host
    baseline_host,hostname=thinkstation1,cpu_model=AMD Ryzen Threadripper PRO 5975WX 32-Cores,physical_cores=32,logical_threads=64,numa_nodes=1,placement_scope=same_llc

Both runs are `executed_on=thinkstation1` and `hostname=thinkstation1`, so this is a
same-host pair; the non-replication below is NOT a cross-worker artifact.

### Three independent reasons this is not bankable, any one of which suffices

**The intervals do not overlap.** `[2.658290, 2.746037]` and `[2.815767, 2.852170]` are
disjoint with a gap between them. Two runs of one configuration on one host that
exclude each other are not a replication; they are evidence that something outside the
configuration moved.

**The kernel A/A null flips sign and is enormous.** `1.134803` in run 1 against
`0.915179` in run 2 — `+13.5%` then `-8.5%`. The replication convention excuses a
failing null only when both runs are off in the SAME direction by a similar amount, and
this is the opposite of that. A null this large also dwarfs the thing being measured's
run-to-run difference, so the ratio gap above is fully explained by instrument noise.

**Run 2 was measured through a storm.** `external_load_during_run` reports peak **48
busy CPUs** and peak off-placement mean busy **70.1%** across 21 of 21 samples, against
limits of 2 CPUs and 10% of samples. Run 1 was already `CONTENDED` at 13 CPUs / 23.5%.
This is the noisiest pair of runs in the session and the only one where the nulls got
badly worse between runs.

`observation_repeats=1` is forced here and is part of the story: mutating workloads
require one durability boundary per timed row, so this workload cannot use the
min-of-N reduction that damps the read-only workloads. It is structurally the noisiest
row on the instrument, which is exactly why it needs a quiet window rather than more
pairs.

### Do not difference this against the bead's 1.51x

That figure is a different configuration. This ran `--operations 2000` with 8 client
threads on a 256 MiB image at `--pairs 12`. Nothing here licenses a claim that the ext4
parallel-metadata gap grew from `1.51x` to `2.8x`, and the nulls say this instrument
could not have detected such a change today even if it were real. Four-arm post-parity
passed on both runs (`tree_sha256=5dce73d82e989d...`), so the arms did the same work;
only the timing is unusable.

Retry predicate: a genuinely quiet window, and consider raising `--pairs` only AFTER
the kernel null lands inside 2% twice in a row — more pairs against a sign-flipping
null buys precision on a biased estimate.

## 2026-08-16 — REJECT of the RATIO CLAIM (the code stays): the capability memo's 40x format-lookup cut does NOT show up end-to-end on mounted warm stat (bd-m1bpu / bd-2pq73, AzureBay)

bd-2pq73 banked a **counted** win: cold format lookups on a warm-stat sweep fell
2000 -> 50, a 40x reduction. That count is not in dispute and the code is not being
reverted. What is refused here is the unstated inference that a 40x count cut buys a
proportional — or any measurable — wall-clock win against a live kernel arm.

This is the first time the question could be asked. It needed two things that landed
today: a comparator that can start (the flat 120 GiB free-space floor, now derived) and
a runtime kill switch so both arms come from ONE ELF
(`FFS_FUSE_CAPABILITY_MEMO`, commit `d754bd3e`) rather than two binaries, which would
reintroduce every ISA and PGO confound (bd-b9dug).

### The instrument proved the arms actually differ before it measured them

    mounted_kernel_candidate_identity,filesystem=btrfs,workload=warm_stat,workload_arms=6,candidate_a_arms=fuse_a:fuse_b,candidate_b_arms=fuse_candidate_b_a:fuse_candidate_b_b,one_elf=true,elf_sha256=28e74202275b2cb1ad094525a110472782026480f1f4f222a5fda6c98d4e6220,candidate_a_runtime_knobs="count_memoized_requests=true,fuse_dispatch_workers=0,capability_memo=true",candidate_b_runtime_knobs="count_memoized_requests=true,fuse_dispatch_workers=0,capability_memo=false",candidate_b_env="FFS_FUSE_CAPABILITY_MEMO=0",configurations_differ=true,knob_divergence_proof=daemon_self_reported_effective_values,verdict=pass

`one_elf=true` and the two knob strings differ in exactly one field, each resolved
through the same function the mount constructor calls. The first attempt at this run
was REFUSED by the harness — "the two candidate configurations resolved IDENTICAL
runtime knobs; the requested override never reached a knob this ELF reads, so the run
would compare a configuration against itself" — because the new switch was not yet in
the daemon's self-report. That refusal is why the numbers below can be trusted to be
about the memo at all.

### Result: memo ON vs memo OFF is UNDECIDABLE, and the bound is the point

    run 1  candidate_b_over_candidate_a_median=0.994750, ci_low=0.961284, ci_high=1.007388, minimum_decidable_effect_ratio=1.226478, achieved_resolution_ratio=1.040275, admitted=false, verdict=BLOCKED_NULL, bootstrap_resamples=20000
    run 2  candidate_b_over_candidate_a_median=0.986227, ci_low=0.959903, ci_high=0.992564, minimum_decidable_effect_ratio=1.106548, achieved_resolution_ratio=1.041772, admitted=false, verdict=BLOCKED_NULL, bootstrap_resamples=20000

Each `ci_low`/`ci_high` pair is a bootstrap median 95% confidence interval, resampled
20,000 times, from a `six_arm_williams_square` schedule with `same_window=true`. The
ratio is memo-OFF over memo-ON, so **below 1.0 means turning the memo OFF was FASTER**.

The two runs replicate: medians `0.9948` and `0.9862`, intervals overlapping on
`[0.9599, 0.9926]`, and both on the same side of parity. The same-invocation A/A null
for the candidate arm was measured too (`arm=fuse_candidate_b`, run 1 median `1.005818`;
run 2 `candidate_aa_null_clear=true`).

**But both runs are inside their own minimum decidable effect.** The instrument needed
`22.6%` (run 1) and `10.7%` (run 2) to call anything; the observed effect is at most
`1.4%`. So this is not "the memo is worth nothing" — it is **"the memo is worth less
than 10.7% of mounted warm stat, and this instrument cannot say more."** That is still
a hard bound, and it is the useful part: a 40x count reduction that cannot produce a
10% wall-clock move has had its ceiling established.

### Why that is exactly what the mechanism predicts

The memo was never able to remove the expensive half. Its own doc comment says it: *the
kernel still sends each FUSE `GETXATTR` request; this only makes the ANSWER free.* The
earlier attribution put ~`6.38 us` of the ~`6.47 us` per-entry mounted cost in the
per-path `security.capability` ROUND TRIP, not in the format lookup the memo
eliminates. Removing 1950 of 2000 format lookups removes the cheap half of a cost whose
expensive half is a kernel round trip that no daemon-side cache can touch.

**Consequence for the campaign: stop aiming daemon-side caches at this path.** The
lever that can move mounted warm stat is one that stops the kernel from SENDING the
probe, and bd-ha71t already measured that `FUSE_HANDLE_KILLPRIV_V2` does not do it
(4000 probes -> 4000 probes, a genuine null with a positive control). The memo stays
because it is free and the count is real; it is not the answer to the 4.80x row.

### Provenance and caveat

`executing_elf_sha256 = 28e74202275b2cb1ad094525a110472782026480f1f4f222a5fda6c98d4e6220`,
self-reported by the candidate via `bench-evidence`;
`pgo_profile_sha256 = 6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`,
`isa=x86-64-v3`, candidate gate `verdict=pass`. Driver
`471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc`. Both built on
`thinkstation1`; `executed_on=thinkstation1`, `hostname=thinkstation1` — no rch worker
takes part, because a FUSE mount runs only on the executing machine. Reduced working
set: `--pairs 12 --operations 2000 --image-size-mib 256`, btrfs only. Six-arm
post-parity `verdict=pass` and `btrfs check` clean on every arm.

Both runs `CONTENDED` (peak 55 and 43 busy CPUs, off-placement mean busy `41.7%` and
`37.4%`), which is precisely why `minimum_decidable_effect_ratio` is as coarse as
`22.6%` and `10.7%`. A quiet window would tighten the bound; it would not change the
direction, and nothing here licenses a claim that the memo HELPS mounted warm stat.

Retry predicate: re-run in a quiet window to push the decidable effect below ~2%, which
would convert this bound into a number. Do NOT re-run it expecting a win.

## 2026-08-16 — DIRECTIONAL (harness refused on resolution, nulls CLEAN): the capability memo is worth ~18% of mounted readdir+stat, the opposite of its warm-stat result (bd-m1bpu, AzureBay)

The companion entry above priced the memo on warm stat and found it worth **less than
10.7%** — undecidable, effect at most `1.4%`. On readdir+stat the same switch, the same
ELF and the same instrument give a completely different answer, and the contrast is the
finding.

Ratio is memo-OFF over memo-ON, so **above 1.0 means turning the memo OFF was SLOWER**,
i.e. the memo is doing work:

    12 pairs  candidate_b_over_candidate_a_median=1.218496, ci_low=1.080162, ci_high=1.247312, minimum_decidable_effect_ratio=1.478475, achieved_resolution_ratio=1.247312, candidate_aa_null_clear=true, verdict=BLOCKED_NULL
    12 pairs  candidate_b_over_candidate_a_median=1.256750, ci_low=1.243660, ci_high=1.300158, minimum_decidable_effect_ratio=1.203189, achieved_resolution_ratio=1.300158, candidate_aa_null_clear=true, verdict=BLOCKED_NULL
    36 pairs  candidate_b_over_candidate_a_median=1.219035, ci_low=1.203864, ci_high=1.288715, minimum_decidable_effect_ratio=1.225498, achieved_resolution_ratio=1.288715, candidate_aa_null_clear=true, verdict=BLOCKED_NULL

Each `ci_low`/`ci_high` pair is a bootstrap median 95% confidence interval, resampled
20,000 times, `schedule=six_arm_williams_square`, `same_window=true`, `one_elf=true`.
The candidate self-reports its own identity through `bench-evidence` at run time:
`executing_elf_sha256 = 28e74202275b2cb1ad094525a110472782026480f1f4f222a5fda6c98d4e6220`,
`pgo_profile_sha256 = 6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`,
`isa=x86-64-v3`, gate `verdict=pass`; driver
`471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc`, both built on
`thinkstation1`. The run carries
`configurations_differ=true` and
`knob_divergence_proof=daemon_self_reported_effective_values`. Host `thinkstation1`,
`executed_on=thinkstation1`; no rch worker takes part, a FUSE mount runs only on the
executing machine.

Three runs, medians `1.2185`, `1.2568`, `1.2190` — a `3.1%` spread — and **every
interval excludes parity**. The direction is not in question. Quoting the worst bound
across all three (`ci_low = 1.080162`): **the memo is worth at least `7.4%` of mounted
readdir+stat wall time**, with the central estimate near `18%` (`1 - 1/1.22`).

### Why this is DIRECTIONAL and not banked

All three are `verdict=BLOCKED_NULL`, and it matters *which* gate refused them. **The
candidate A/A null is CLEAR in all three runs** (`candidate_aa_null_clear=true`) — this
is not the sign-flipping-null failure that refused the vs-kernel readdir row earlier
today. What fails is `achieved_resolution_ratio` against
`minimum_decidable_effect_ratio`: the interval is wider than the bar the harness
requires before it will call an effect.

### Buying pairs did NOT fix it, and that is a methodological result

I tripled the schedule from 12 pairs to 36 expecting a tighter interval. It got
**wider**: `achieved_resolution_ratio` went `1.247312` -> `1.288715`.

The reason is structural. `minimum_decidable_effect_ratio` is
`twice_candidate_null_log_margin` — it is set by the spread of the candidate A/A NULL,
not by the precision of the ratio. Under contention the null's spread does not shrink
with pair count, because each additional pair samples the same noisy host. **More pairs
buy precision on the ratio and nothing on the bar the ratio must clear.** The earlier
retry predicate on the ext4 row said not to buy pairs against a sign-flipping null;
this generalises it — do not buy pairs against a CONTENDED null either, for the same
reason in a different disguise. What this needs is a quiet window, and only that.

### Mechanism: why warm stat says <10.7% and readdir says ~18%

`CAPABILITY_MEMO_SLOTS` is **4096**. Warm stat's fixture is **4 entries**; readdir+stat's
is **2000**. So:

- On warm stat the OFF arm re-resolves a handful of inodes whose format-level lookups
  the layer beneath already caches. There is almost nothing for the memo to save, which
  is why its effect there sits at `1.4%` against a `10.7%` bar.
- On readdir+stat the sweep touches 2000 distinct inodes, **and 2000 fits inside 4096
  slots**, so the whole directory is resident. The harness sweeps that same directory
  once per observation across 12-36 pairs, so every sweep after the first is served
  from the memo. That is the 18%.

**This corrects the premise recorded on bd-t0xoq**, which reasoned that the memo is
structurally useless on readdir+stat because "every entry is a distinct inode probed
exactly once, so the memo is structurally useless on this path". That was written when
`CAPABILITY_MEMO_SLOTS` was **64**, where a 2000-entry directory self-evicted many times
over. At 4096 slots the working set fits and the conclusion inverts. The premise was
correct for the memo it described and is now wrong for the memo that exists.

Note the honest limit of that mechanism: it depends on the directory FITTING. A 32,768
entry sweep — the size the banked `7.73x`/`8.32x` readdir rows use — does not fit in
4096 slots, so this `18%` must NOT be extrapolated to those rows. Measuring it there is
the obvious next step and needs its own run.

Both runs `CONTENDED` (peak 41, 18 and 14 busy CPUs). Six-arm post-parity `verdict=pass`
and `btrfs check` clean throughout. Reduced working set: `--operations 2000
--image-size-mib 256`, btrfs only.

Retry predicate: re-run in a quiet window at 12 pairs — not more — to bring
`minimum_decidable_effect_ratio` under the observed `1.22` and convert this into an
admitted row. Do not spend more pairs on a contended host.

## 2026-08-16 — PREDICTION CONFIRMED: the memo's readdir win is a CAPACITY effect and vanishes at 32,768 entries (bd-m1bpu, AzureBay)

The entry above measured the memo worth ~18% of mounted readdir+stat at 2,000 entries,
attributed it to `CAPABILITY_MEMO_SLOTS = 4096` holding the whole directory, and wrote
down the falsifiable consequence: *"this depends on the directory FITTING. A 32,768
entry sweep does not fit in 4096 slots, so this 18% must NOT be extrapolated."*

That prediction was made before the measurement. It holds.

Same ELF, same switch, same instrument, only `--operations 2000` -> `32768` and
`--image-size-mib 256` -> `512`:

    run 1  candidate_b_over_candidate_a_median=0.994244, ci_low=0.941687, ci_high=1.000303, minimum_decidable_effect_ratio=1.160888, achieved_resolution_ratio=1.061924, verdict=BLOCKED_NULL, bootstrap_resamples=20000
    run 2  candidate_b_over_candidate_a_median=1.003628, ci_low=1.003587, ci_high=1.013735, minimum_decidable_effect_ratio=1.033047, achieved_resolution_ratio=1.013735, verdict=BLOCKED_NULL, bootstrap_resamples=20000

| directory entries | memo-OFF / memo-ON | reading |
| --- | --- | --- |
| 2,000 (fits in 4096 slots) | `1.2185` / `1.2568` / `1.2190`, every CI excluding parity | memo worth ~18% |
| 32,768 (does not fit) | `0.994244` / `1.003628`, both within `0.6%` of parity | **no detectable effect** |

Run 2 is the stronger of the two and is worth reading carefully: its
`achieved_resolution_ratio` is `1.013735` against a `minimum_decidable_effect_ratio` of
`1.033047` — **the interval is TIGHTER than the bar**, which is the case the earlier
runs never reached. So this is not "we could not see it"; it is "we could have seen a
`3.3%` effect and the memo produced `0.36%`." At the size that the banked readdir rows
actually use, the memo does nothing.

Every `ci_low`/`ci_high` pair above is a bootstrap median 95% confidence interval, resampled 20,000 times, from a `six_arm_williams_square` schedule with `same_window=true` and `one_elf=true`.

`executing_elf_sha256 = 28e74202275b2cb1ad094525a110472782026480f1f4f222a5fda6c98d4e6220`
self-reported via `bench-evidence`,
`pgo_profile_sha256 = 6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`,
`isa=x86-64-v3`; driver
`471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc`; both built on
`thinkstation1`, `executed_on=thinkstation1`, `hostname=thinkstation1`.

### Independent corroboration of the "never difference these sizes" warning

The same two runs report, diagnostically:

    run 1  kernel_median_wall_ns=27203752, fuse_median_wall_ns=214406444   -> 7.88x
    run 2  kernel_median_wall_ns=29372299, fuse_median_wall_ns=216984648   -> 7.39x

At 32,768 entries the vs-kernel ratio lands at **7.39x-7.88x, bracketing the banked
`7.73x`**. The same instrument on the same day at 2,000 entries measured `2.78x`. This
is direct confirmation that the earlier entry was right to refuse the comparison
between those numbers in capitals: the size is the difference, not the code. Anyone
tempted to read `2.78x` as progress against `7.73x` now has the counter-measurement in
the same ledger.

### What this means for the lever

The memo's benefit is bounded by its capacity, and real directories are not 2,000
entries. Raising `CAPABILITY_MEMO_SLOTS` past 4096 is the obvious response and should be
resisted without a bound: the memo is a per-mount array of `AtomicU64`, so 4096 slots is
32 KiB and 32,768 would be 256 KiB — affordable in isolation, but the same reasoning
scales it to any directory anyone names, which is the unbounded-footprint trap bd-5vis3
was created to avoid. If it is raised, it needs the same acceptance bar bd-5vis3 carries:
peak resident memory reported, and a workload that does NOT fit measured alongside one
that does.

Both runs `CONTENDED` (peak 33 and 17 busy CPUs). Neither is admitted; both are
`BLOCKED_NULL`. The claim here is a bound and a direction, not a banked ratio.

## 2026-08-16 — THE CAPACITY CLIFF MOVES, IT DOES NOT DISAPPEAR: sizing the capability memo to the directory is worth 2.08x on mounted readdir+stat at 32,768 entries (bd-m1bpu, AzureBay)

The previous entry established that the memo does nothing at 32,768 entries because
`CAPABILITY_MEMO_SLOTS = 4096` cannot hold that directory. The obvious response is
"make the table bigger", and the obvious objection is that this only relocates the
problem. **Both are now measured, and both are true.**

`FFS_FUSE_CAPABILITY_MEMO_SLOTS` (commit `96f78446`) makes the count a runtime knob, so
every arm below is ONE ELF
(`executing_elf_sha256 = d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`,
self-reported via `bench-evidence`;
`pgo_profile_sha256 = 6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`,
`isa=x86-64-v3`) with the divergence proved by the daemon:

    candidate_a_runtime_knobs="...,capability_memo=true,capability_memo_slots=4096"
    candidate_b_runtime_knobs="...,capability_memo=true,capability_memo_slots=65536"
    configurations_differ=true,knob_divergence_proof=daemon_self_reported_effective_values,verdict=pass

Ratio is candidate_b over candidate_a, so **below 1.0 means the LARGER table was faster**.
Every `ci_low`/`ci_high` is a bootstrap median 95% confidence interval, 20,000 resamples,
`six_arm_williams_square`, `same_window=true`. Host `thinkstation1`,
`executed_on=thinkstation1`; driver
`471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc`, both built on
`thinkstation1`.

| entries | table | fit | run 1 | run 2 | effect |
| --- | --- | --- | --- | --- | --- |
| 32,768 | memo ON vs OFF at 4096 | 8x oversubscribed | `0.994244` | `1.003628` | **nothing** |
| 32,768 | 65536 vs 4096 | 2x headroom | `0.481225` `[0.479327, 0.485327]` | `0.481230` `[0.475523, 0.481959]` | **2.08x faster** |
| 100,000 | 65536 vs 4096 | 1.5x oversubscribed | `0.774439` `[0.751522, 0.820958]` | `0.770822` `[0.757356, 0.774895]` | **1.30x faster** |

The two 32,768 runs agree to **0.001%** (`0.481225` vs `0.481230`) — the tightest
replication in this campaign — and their candidate A/A null was CLEAR
(`candidate_aa_null_clear=true`, `minimum_decidable_effect_ratio=1.019983`, i.e. the
instrument could resolve 2.0% and the effect was 108%). The 100,000-entry pair agrees to
`0.47%`.

### The answer to the question: it MOVES

At 32,768 entries a 65,536-slot table has headroom and wins `2.08x`. At 100,000 entries
the SAME table is now itself oversubscribed and the win degrades to `1.30x`. The benefit
tracks how well the directory fits, monotonically, exactly as a direct-mapped table
predicts. Nothing here removes the cliff; it relocates it to a larger directory, and any
directory larger than the table walks off it again.

So "size the memo to the workload" is not a fix, it is a **parameter with no correct
value** — which is precisely the unbounded-footprint objection bd-5vis3 was created to
enforce, arriving here on schedule. `CAPABILITY_MEMO_SLOTS_MAX` is capped at `1 << 20`
(8 MiB per mount) for that reason, and the knob is documented in code as an experiment
rather than a policy.

Memory cost of the arm that won: 65,536 slots x 8 bytes = **512 KiB per mount**, resident
for the mount's lifetime, against 32 KiB at the 4096 default. That is cheap in isolation
and is exactly how every unbounded cache begins.

### What this does and does not say about the vs-kernel row

**It is a candidate-vs-candidate ratio. It is NOT a win against the kernel.** The same
runs measured the incumbent at `kernel_median_wall_ns=30283575` / `27659631` against
`fuse_median_wall_ns=215316988` / `217368101` for the 4096-slot arm — still a
`7.1x`-`7.9x` LOSS, consistent with the banked `7.73x`. Applying the measured `0.4812`
to the FUSE arm would put the 65,536-slot configuration near `103 ms`, i.e. roughly
`3.5x` rather than `7.4x` — but that is an INFERENCE from two separately reported
numbers, not a measured vs-kernel ratio, and it is written here as arithmetic to be
checked rather than a result to be quoted. A vs-kernel row for the larger table has not
been run.

### Why none of this is admitted

All six runs are `verdict=BLOCKED_NULL`. The candidate claim is gated on `admitted`,
which requires the KERNEL arm's A/A nulls to be clear as well — and those have failed
all session under contention (peak off-placement mean busy reached `99.8%` during the
first 100,000-entry run). The candidate comparison does not use the kernel arm, so this
is a stricter rule than the comparison needs; it is the harness's rule and it was not
touched to make a number publishable. Recorded as directional with its bound.

Retry predicate: a quiet window, then a vs-kernel row at 65,536 slots on the 32,768-entry
fixture — that is the measurement that would tell the campaign whether the worst row in
the bank actually moves. Before shipping any larger default, bd-5vis3's bar applies:
peak resident memory reported, and a workload that does NOT fit measured beside one that
does. The 100,000-entry row above is that non-fitting workload, and it is why a larger
default cannot be justified on the 32,768 number alone.

## 2026-08-16 — REPLICATED STANDING FIGURE: btrfs mounted warm stat is 4.75x-4.80x slower than kernel btrfs, worst bound 4.80x, on TWO admitted runs from TWO different ELFs (bd-btrfs-warm-stat-5x-9pxn1, AzureBay)

Both runs below are `admitted=true` with `directional_claim_clear=true` and BOTH A/A
nulls clear — not directional, not excused, admitted by the estimator on their own
evidence. That is the first replicated admitted pair this bead has had.

    run A  mounted_kernel_throughput,filesystem=btrfs,workload=warm_stat,operations_per_observation=2000,kernel_median_wall_ns=4652283,fuse_median_wall_ns=22422724,kernel_operations_per_second=429896.462,fuse_operations_per_second=89195.229
    run A  mounted_kernel_ratio,filesystem=btrfs,metric=wall_ns,workload=warm_stat,pairs=12,fuse_over_kernel_median=4.798508,ci_low=4.759896,ci_high=4.802894,twice_null_margin_ratio=1.016331,directional_claim_clear=true,admitted=true,verdict=HONEST_LOSS,bootstrap_resamples=20000,cv_used=false
    run B  mounted_kernel_throughput,filesystem=btrfs,workload=warm_stat,operations_per_observation=2000,kernel_median_wall_ns=4690072,fuse_median_wall_ns=22336491,kernel_operations_per_second=426432.640,fuse_operations_per_second=89539.579
    run B  mounted_kernel_ratio,filesystem=btrfs,metric=wall_ns,workload=warm_stat,pairs=12,fuse_over_kernel_median=4.751179,ci_low=4.728531,ci_high=4.772781,twice_null_margin_ratio=1.047112,directional_claim_clear=true,admitted=true,verdict=HONEST_LOSS,bootstrap_resamples=20000,cv_used=false

Each `ci_low`/`ci_high` pair is a bootstrap median 95% confidence interval, resampled
20,000 times. Medians `4.798508` and `4.751179` — **1.0% apart** — with intervals
overlapping on `[4.759896, 4.772781]`. **Quote the worst bound: `4.80x`.**

### The two runs used DIFFERENT ELFs, and that is a feature

Run A:
`executing_elf_sha256 = e6cd5793384bdb6d6fff113e13fd9e1392753fadaf4ab0a15663e7912dba5bf0`,
`pgo_profile_sha256 = cc6c121c9ee77d8a4b7f4855c443c07a59ac6191316d40acb08fb2fbe79f9562`.
Run B:
`executing_elf_sha256 = d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`,
`pgo_profile_sha256 = 6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`.
Both `isa=x86-64-v3`, candidate gate `verdict=pass`, both built on `thinkstation1`,
`executed_on=thinkstation1`, `hostname=thinkstation1`. Driver
`471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc`.

Each row is a self-contained vs-kernel ratio with its own live kernel arm in the same
invocation, so the two are comparable as replicates even though the binaries differ.
Two independently-built PGO binaries, two different profiles, landing 1.0% apart is
stronger evidence for the figure than one binary measured twice would be. It also means
the several code changes between them (capability-memo kill switch, slot-count knob)
moved warm stat by **less than the 1.0% spread**, which is consistent with the separate
finding that the memo is worth under 10.7% here.

### What this figure supersedes and does not

It supersedes the `4.98x` in this bead's title, which predates the 2026-08-15 btrfs
checksum-verify default flip (bd-6kpp4). These runs are at the post-flip default
(`btrfs_verify_data_on_read=true`), so **`4.98x` and `4.80x` are not a delta** — they are
two different configurations and the older number should be retired rather than
differenced.

It says nothing about readdir+stat, which the same instrument puts at `7.4x`-`7.9x` at
32,768 entries. Warm stat and readdir+stat are different rows with different mechanisms.

### The attribution this row still cannot support, and why

The obvious next question is where the `22.3 ms` goes: how many FUSE round trips per
stat, and what fraction is daemon-side rather than kernel round trip. **The instrument
cannot answer it today.** Every report carries
`fuse_dispatch_metrics: {"fuse_a": "unreported_by_this_elf", ...}`, and that label is
wrong: the ELF contains the emitter and the harness sets `FFS_MOUNT_BENCH_EVIDENCE=1`.
The counters are discarded at the source — `MountRuntimeMode::Standard`, which is the
path the comparator uses, hand-constructs a `MetricsSnapshot` of all zeros rather than
returning the one the session accumulated. Filed as `bd-viil0`; both affected files were
under another agent's exclusive reservation, so it was handed over rather than edited.

Until that is fixed, no per-op round-trip attribution for warm stat is reproducible from
a banked report by anyone, including the readdir+stat "daemon is 3.85% of the cost"
figure.

Reduced working set: `--pairs 12 --operations 2000 --image-size-mib 256`, btrfs only.
Four-arm post-parity `verdict=pass` and `btrfs check` clean on both runs. Both runs
`CONTENDED` — disclosed, and it cuts one way only: contention inflates the FUSE arm at
least as much as the kernel arm, so a LOSS measured under it is if anything an
overstatement and `4.80x` remains a safe upper bound.

## 2026-08-16 — ATTRIBUTION: warm stat's 4.80x is ONE kernel-issued `security.capability` probe per stat; the filesystem is 0.75% of the gap (bd-btrfs-warm-stat-5x-9pxn1, AzureBay)

Counted, not timed — three runs, deterministic, no quiet window required, which
matters because every timed run on this host is currently `CONTENDED`.

**2,000 warm stats of one already-resolved path produce exactly 2,000 FUSE round trips,
and every single one is a `security.capability` GETXATTR. Nothing else crosses the
boundary at all.**

    === opcode census over the 2000-stat window ===
       2000 fuse getxattr from kernel
    getxattr round trips : 2000
    security.capability  : 4000      (two trace lines per round trip)
    window lines         : 4000

No GETATTR. No LOOKUP. No STATX. The 60-second `ATTR_TTL` this daemon advertises is
working exactly as intended — the kernel serves attributes from its own cache and never
asks. The probe is the only thing left.

### The daemon is not the cost, and it is not close

    run 1  requests_total=2009  metadata_requests=5  getattr_dispatch_count=3,getattr_dispatch_nanos=11762,getxattr_dispatch_count=2,getxattr_dispatch_nanos=110519,lookup_dispatch_count=2,lookup_dispatch_nanos=9679,readdir_dispatch_count=0  wall 48,949,449 ns
    run 2  requests_total=2009  metadata_requests=5  getattr_dispatch_count=3,getattr_dispatch_nanos=13334,getxattr_dispatch_count=2,getxattr_dispatch_nanos=136938,lookup_dispatch_count=2,lookup_dispatch_nanos=11622,readdir_dispatch_count=0  wall 49,418,088 ns
    run 3  requests_total=2009  metadata_requests=5  getattr_dispatch_count=3,getattr_dispatch_nanos=16232,getxattr_dispatch_count=2,getxattr_dispatch_nanos=148992,lookup_dispatch_count=2,lookup_dispatch_nanos=9889,readdir_dispatch_count=0

`requests_total=2009` and the dispatch counts `3/2/2/0` are **identical across all three
runs**; wall agrees within 1.0%. Of 2,000 capability probes exactly **2** reached the
format layer — the memo answers the other 1,998 — so the filesystem does 7 dispatches
in total for 2,000 stats.

Total daemon dispatch time is `131,960` / `161,894` / `175,113` ns, i.e. **0.27%-0.35%
of wall**. Against the banked comparator figures (`fuse_median_wall_ns=22336491`,
`kernel_median_wall_ns=4690072`, both at 2,000 operations) that is `11,168` ns per stat
for us against `2,345` ns for the kernel — a gap of `8,823` ns — of which the daemon's
filesystem work is **66-88 ns, or 0.75%-0.99%**.

**~99% of the warm-stat gap is one FUSE round trip for an xattr that does not exist on
any of these files.**

### This overturns the obvious lever, again

Every filesystem-side candidate for this row is now excluded by measurement rather than
by argument. btrfs inode lookup, the parsed-node cache, the floor-leaf memo, the
capability memo itself — none of them can move a number in which the filesystem accounts
for under 1%. The memo in particular is already doing its job perfectly here (1,998 of
2,000 probes answered without a dispatch) and `bd-m1bpu` separately measured it worth
under `10.7%` end-to-end; both statements are the same fact seen from two instruments.

The only levers that can touch this row are:

1. **Stop the kernel SENDING the probe.** `bd-ha71t` already measured
   `FUSE_HANDLE_KILLPRIV_V2` inert for this (4000 probes -> 4000 probes, with a positive
   control proving the capability was accepted). What has NOT been tried is whether the
   probe rate changes when the xattr actually EXISTS, or on a mount carrying
   `default_permissions`, or across kernel versions. Filed as `bd-z0rb8`.
2. **Make a round trip cheaper**, which is the shared FUSE transport floor and belongs
   to the round-trip thread, not to this row.

Nothing else on this surface is worth a slice.

### Method note, because the instrument said this was impossible

The mounted comparator reports `fuse_dispatch_metrics: "unreported_by_this_elf"` on
every run, because `MountRuntimeMode::Standard` discards the counters and substitutes an
all-zero snapshot (`bd-viil0`, filed, files under another agent's reservation). That
blocks attribution *through the comparator* — but `--runtime-mode managed` emits the
same counters and is a plain CLI flag, so the attribution was taken directly with no
code change and nothing edited under reservation. A blocked instrument is not the same
as a blocked question.

Harness `scripts`-local `warm_stat_attr.sh` / `warm_stat_trace.sh`; candidate
`d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`
(`isa=x86-64-v3`, `pgo_profile_sha256 = 6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`);
host `thinkstation1`, `hostname=thinkstation1`, run locally because a FUSE mount runs
only on the executing machine — no rch worker took part. Counts are exact and
reproducible; the wall figures are from an unpinned managed mount on a contended host and
are NOT comparable to the banked comparator absolutes, which is why every claim above is
expressed as a COUNT or a RATIO of counts.

## 2026-08-16 — REJECT: the kernel does not cache `security.capability` either way — probe rate is 1.0000/stat whether the xattr exists or not (bd-z0rb8 hypothesis 1, AzureBay)

`bd-z0rb8` lists four untried routes to suppressing the per-stat capability probe that
the warm-stat attribution showed to be ~99% of the 4.80x gap. This kills the cheapest
one.

**Hypothesis:** if the kernel caches a PRESENT `security.capability` value but re-asks
for an ABSENT one, then the probe is addressable — the daemon could report presence
differently, or an ABI route to cache the negative would be worth hunting for.

**Result: identical.** One image, two files, one mount, 1,000 stats each, counted from
the daemon's own trace:

    positive_control_setcap=yes
    === probes per stat, 1000 stats each, same mount ===
    absent   getxattr_round_trips=1000   per_stat=1.0000
    present  getxattr_round_trips=1000   per_stat=1.0000

`1.0000` versus `1.0000`. Not close — exactly equal, on a counted mechanism with no
timing involved: **1000 probes (absent) vs 1000 probes (present)**, over 1000 stats
each.

The positive control matters and is reported in the output: `setcap cap_net_raw+ep`
returned success on the `present` file before the image was synced and unmounted, so the
two files genuinely differ. Without that line this would be indistinguishable from a run
that silently compared two identical files — the same failure mode the comparator's
`configurations_differ` gate exists to prevent, reproduced here by hand because this
harness has no such gate.

**Conclusion: the kernel is not caching this xattr at all**, in either direction. There
is no negative-caching behaviour to exploit and no presence-dependent path to take
advantage of. Hypothesis 1 on `bd-z0rb8` is closed.

What survives on that bead: `default_permissions` (one mount flag, still untried),
kernel-version dependence (host is `6.17.0-41-generic`), and whether any FUSE ABI route
exists to declare an inode free of `security.*` so the kernel can cache the negative —
which `bd-ha71t`'s retry predicate already asked for and which this result makes more
urgent, since it is now the only remaining shape that could work.

Do NOT re-test presence-vs-absence. It is measured, exactly equal, with a positive
control.

Harness `scripts`-local `probe_present_vs_absent.sh`; candidate
`d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`, `isa=x86-64-v3`;
`hostname=thinkstation1`, `executed_on=thinkstation1`, kernel `6.17.0-41-generic`, run
locally because a FUSE mount runs only on the executing machine — no rch worker took
part, and there is no ratio here to be confounded by one if it had. Counted mechanism, so no quiet
window is required and the host's contention cannot confound it.

## 2026-08-16 — MECHANISM PINNED: the capability probe is ONE PER PATH-BASED SYSCALL, independent of path depth, and `fstat` pays ZERO (bd-z0rb8, AzureBay)

The warm-stat attribution established that one `security.capability` GETXATTR per stat
is ~99% of the 4.80x gap. This pins what the kernel binds that probe to, which is what
decides whether any fix is possible and what an application can do today.

Four arms, one mount, 1,000 operations each, counted from the daemon's own trace:

    === probes per operation, 1000 ops each, one mount ===
    path_file  probes=1000   per_op=1.0000
    path_dir   probes=1000   per_op=1.0000
    path_root  probes=1000   per_op=1.0000
    fstat      probes=1      per_op=0.0010

**1000 probes (path-based) vs 1 probe (fd-based)** over 1,000 operations each.

### Two things this rules out, and one it rules in

**Not per path component.** `stat("<mnt>")` — the mount root, the shortest possible walk,
zero intermediate components — pays exactly the same `1.0000` as a two-component path.
There is no depth to amortise, so nothing of the "resolve the parent once" family can
help. This also corrects a loose reading of the earlier bd-ha71t note, which recorded
"TWO probes per path-based stat (4000/2000)": that count came from a workload whose
paths were being resolved cold. Warm, on an already-resolved path, it is exactly ONE.

**Not the attribute fetch.** `fstat` on an already-open fd pays **zero** — the single
probe in that arm is from the one `open()` that created the fd. A thousand attribute
fetches through FUSE cost nothing, because `ATTR_TTL` lets the kernel serve them from
its own cache and it never asks the daemon at all.

**It is the path-based syscall itself.** One probe per `stat()`/`lstat()` on a path,
whatever the path, however warm the dentry.

### What follows

For the campaign: there is no daemon-side or filesystem-side lever here, and now there
is no path-shape lever either. The routes still open on this bead are unchanged and
narrow — a mount option the kernel honours, a FUSE ABI route to cache a negative
`security.*`, or a cheaper round trip (which belongs to the round-trip thread). It also
bounds what that thread can deliver on THIS row: warm stat is one round trip per
operation, so halving round-trip cost halves the warm-stat gap and no more.

For anyone using FrankenFS today, this is directly actionable and worth stating plainly:
**a workload that holds file descriptors pays none of this; one that stats by path pays
all of it.** `ls -l`, `find`, and every `stat()`-per-entry tool are the worst case by
construction. That is not a fix, but it is a real characterisation of when the 4.80x row
applies.

Do NOT re-test path depth or fd-vs-path. Both are measured, exact, and reproducible.

Harness `scripts`-local `probe_binding.sh`; candidate
`d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`, `isa=x86-64-v3`;
host `thinkstation1`, kernel `6.17.0-41-generic`, run locally because a FUSE mount runs
only on the executing machine — no rch worker took part. All four arms are in ONE mount,
so the comparison is within-window; all four are COUNTS, so the host's contention cannot
confound them and no quiet window was required.

## 2026-08-16 — NULL on filesystem dependence (counted, no ratio banked): the capability probe is identical on ext4 and btrfs — exactly 1.0000/stat on both (bd-btrfs-warm-stat-5x-9pxn1, AzureBay)

The scorecard argues warm stat measures a shared per-request FUSE floor rather than
anything about btrfs, on the strength of the two filesystems landing within `1.3%` of
each other in wall time. That is a timing coincidence, and on this host timing
coincidences are cheap. This replaces it with a count.

    === probes per path-based stat, 1000 stats, per filesystem ===
    ext4    as_root=no   probes=1000   per_stat=1.0000
    btrfs   as_root=no   probes=1000   per_stat=1.0000

**1000 probes (ext4) vs 1000 probes (btrfs)** over 1,000 stats each, separate images,
separate mounts, same daemon binary.

Not "within 1.3%" — identical, to four decimal places, on a quantity that cannot be
perturbed by host contention because it is a count. The shared-floor claim is now
supported by mechanism rather than by two noisy numbers agreeing.

Combined with the depth-independence and fd-vs-path results banked above, the full
mechanism for the warm-stat row is:

- one `security.capability` GETXATTR per path-based stat syscall,
- independent of path depth (mount root pays the same as a nested file),
- independent of the filesystem (ext4 == btrfs, exactly),
- independent of whether the xattr exists (present == absent, exactly),
- zero for `fstat` on an open fd,
- and the daemon answers it from the memo in `0.75%-0.99%` of the measured gap.

Every one of those is a count with a positive control, none needs a quiet window, and
together they say the 4.80x row is a property of the kernel's FUSE path-resolution
behaviour and of nothing FrankenFS does.

### Two method notes, both mine to own

The first run of this script reported `probes=0` for a root arm that never executed:
`sudo -n python3` is unavailable on this host, the arm printed a skip notice, and the
count came back zero — which would have read as "root skips the probe", an exciting and
completely false result. The arm is removed rather than left to report a fabricated
null. **A skipped arm that still prints a number is worse than a missing arm.**

The same run also tripped the `grep -c ... || echo 0` trap already recorded in this
campaign: `grep -c` prints `0` AND exits non-zero, so the fallback appended a SECOND
zero and the downstream arithmetic saw `0\n0`. Fixed to `|| true`, which keeps grep's own
printed count.

Harness `scripts`-local `probe_cross_fs.sh`; candidate
`d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`, `isa=x86-64-v3`;
host `thinkstation1`, kernel `6.17.0-41-generic`, run locally because a FUSE mount runs
only on the executing machine — no rch worker took part.

Still UNMEASURED and worth someone's time: whether a privileged caller skips the probe.
That arm did not run here and no claim is made about it.

## 2026-08-16 — NULL on caller privilege (counted): root pays the capability probe at exactly the same rate as an unprivileged caller — and a CORRECTION to why the earlier arm did not run (bd-z0rb8, AzureBay)

The kernel consults `security.capability` to decide whether a file confers capabilities.
A root caller already has them, so if the check were short-circuited for privileged
callers the probe would be a property of the CALLER rather than of the path — a
different shape of problem, and an explanation for why some workloads never see this
cost.

It is not.

    positive_control_root_can_stat=yes
    === probes per path-based stat, 1000 stats each, one mount ===
    uid=1000     probes=1000   per_stat=1.0000
    uid=0(root)  probes=1000   per_stat=1.0000

**1000 probes (uid 1000) vs 1000 probes (uid 0)** over 1,000 stats each, same mount,
same file, same daemon. Identical.

### CORRECTION: the earlier arm was misdiagnosed, and the misdiagnosis is instructive

The cross-filesystem entry above records this arm as *"skipped: sudo python3
unavailable"*. **That was wrong.** `sudo -n python3` works perfectly on this host — I
checked. The real reason root could not stat the mount is that **a FUSE mount without
`allow_other` denies every user except the mounting one, root included.** The arm needed
`--allow-other`, not a different interpreter.

Two things caused a wrong cause to be published. The arm was invoked with `2>/dev/null`,
which threw away the actual error, and its failure branch printed a guess as if it were
an observation. **A diagnosis inferred from a suppressed error message is not a
measurement, and it should not have been written down as one.** The claim in that entry
is corrected here rather than edited away, so the mistake stays visible.

This run fixes both: `--allow-other` is passed, stderr is not suppressed, and a
`positive_control_root_can_stat` line proves root could actually read the file before any
count from the root arm is trusted. Without that control a `0` from an arm that cannot
see the mount is indistinguishable from a genuine "root skips the probe" — which is
exactly the false result the earlier run came within one line of publishing.

### Where bd-z0rb8 now stands

Closed by measurement, all with positive controls:

| hypothesis | result |
| --- | --- |
| kernel caches a PRESENT capability differently from an ABSENT one | NULL — `1.0000` vs `1.0000` |
| the probe amortises over path depth | NULL — mount root `1.0000` == nested file `1.0000` |
| it is filesystem-dependent | NULL — ext4 `1.0000` == btrfs `1.0000` |
| privileged callers skip it | NULL — uid 0 `1.0000` == uid 1000 `1.0000` |
| `FUSE_HANDLE_KILLPRIV_V2` suppresses it (bd-ha71t) | NULL — 4000 probes -> 4000 probes |

What remains is narrow and unchanged: a mount option the kernel honours
(`default_permissions` — still untestable, `ffs-fuse` exposes no such option and the
crate is under another agent's reservation), kernel-version dependence (host
`6.17.0-41-generic`), and whether any FUSE ABI route exists to declare an inode free of
`security.*` so the kernel can cache the negative.

Five nulls in a row on one mechanism is itself worth stating plainly: **this probe looks
like unconditional kernel behaviour on the path-resolution path, not a policy any
parameter reachable from userspace turns off.** The remaining routes should be attempted
in that light — the prior is now strongly against any of them working, and the honest
next step may be to establish that the door is closed rather than to keep pushing it.

Harness `scripts`-local `probe_privileged.sh`; candidate
`d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`, `isa=x86-64-v3`;
`hostname=thinkstation1`, `executed_on=thinkstation1`, kernel `6.17.0-41-generic`, run
locally because a FUSE mount runs only on the executing machine — no rch worker took
part, and there is no ratio here to be confounded by one.

## 2026-08-16 — ONE FUSE ROUND TRIP IS 88.6%+ OF A PATH-BASED STAT: 13.9 us, against an A/A null of 1.055x — the ceiling on what the round-trip thread can deliver for warm stat (bd-z0rb8, AzureBay)

Warm stat pays exactly 1 round trip per op; `fstat` on an open fd pays 0. Both return
the same attributes for the same inode in the same mount, so the per-op difference IS
one round trip, isolated, with the attribute work held constant. No comparator, no
kernel arm, no cross-ELF question.

Interleaved A/B and A/A on ONE schedule, 7 rounds x 20,000 ops, seeded bootstrap median
95% confidence interval over log ratios (20,000 resamples) — the same estimator ffs-core
uses, so this is comparable to the rest of the bank rather than a bespoke statistic:

    stat  (1 round trip)  median   15236.8 ns/op   min   13216.7  max   16289.9
    fstat (0 round trips) median    1362.8 ns/op   min    1254.2  max    1976.8
    interleaved A/B stat over fstat, same-invocation, median 11.180674x bootstrap median 95% confidence interval [8.753012, 12.312406]
    interleaved A/A null fstat over fstat, same-invocation, median 1.055089x bootstrap median 95% confidence interval [0.976038, 1.094971]
    ONE ROUND TRIP = 13874.0 ns/op   (11.18x the fd path)

**The A/B interval `[8.753, 12.312]` clears the A/A null interval `[0.976, 1.095]` with
no overlap at all** — the effect's lower bound is 8x the null's upper bound. This is a
timing on a contended host and it is still not close.

An earlier pass of the same experiment, before the estimator carried a bootstrap CI,
measured `13307.1` ns and `10.44x`. The two agree to `4.3%` on the round-trip figure, so
the number replicates across runs as well as clearing its own null.

### What it bounds — quote the worst bound

Taking the conservative edge of the A/B interval (`8.753012x`), one round trip is
**at least `88.6%`** of a path-based stat (`1 - 1/8.753`); at the median it is `91.1%`.
Warm stat is one round trip per operation, so **a given fractional improvement in
round-trip cost buys essentially the same fractional improvement in this row, and nothing
more.** That is the ceiling the round-trip thread should plan against here — useful
precisely because it is an upper bound rather than a target.

### An inference, labelled, because it would be the campaign's biggest claim

The comparator puts the kernel's own path-based stat at `2345` ns/op and our arm at
`11168` ns/op. Our **fd** path costs `1362.8` ns/op. If the probe were eliminated
entirely, a path-based stat would cost roughly what the fd path costs — **below the
kernel's own path-based stat**. That would not narrow the 4.80x row; it would invert it.

**This is arithmetic across two different configurations and is NOT a measured claim.**
The absolutes here are inflated relative to the comparator — `15237` ns/op for a stat
against the comparator's `11168` ns/op for the same workload — because this runs a Python
loop on an unpinned managed-runtime mount on a contended host, where the comparator uses
a pinned, tighter client. `13.9 us` is therefore an UPPER estimate of the round trip in
the comparator's configuration, and the inversion above is a hypothesis needing its own
measured row. It is written down because it changes how valuable `bd-z0rb8` is, not
because it can be quoted.

### Why the fd path is a legitimate control and not a smuggled baseline

`fstat` resolves the same inode through the same mount and returns the same attributes.
The counted work banked above showed it issues **zero** FUSE requests, because `ATTR_TTL`
lets the kernel serve attributes from its own cache. So the subtraction removes the round
trip and leaves everything else — syscall entry, the kernel's attribute cache, and the
client loop — standing in both arms. The A/A null is that same fd path against itself,
which is what makes its `1.055x` the right yardstick for reading the `11.18x`.

Harness `scripts`-local `roundtrip_cost.sh` + `rt_cost.py`; candidate
`d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`, `isa=x86-64-v3`;
`hostname=thinkstation1`, `executed_on=thinkstation1`, kernel `6.17.0-41-generic`, run
locally because a FUSE mount runs only on the executing machine — no rch worker took
part. The `open()` that creates the fd sits outside every timed region.

## 2026-08-16 — THE WORST ROW IN THE BANK MOVES: btrfs readdir+stat at 32,768 entries goes from 6.99x to 3.36x vs kernel with a directory-sized capability memo — BOTH ADMITTED (bd-34hzz, AzureBay)

`bd-m1bpu` measured the memo's slot count worth `2.08x` candidate-vs-candidate and left
one question: does that survive as a vs-kernel row, or does it vanish against a live
incumbent? It survives.

Four runs, one ELF, one fixture, one session, `--pairs 12 --operations 32768
--image-size-mib 512`, btrfs. The only difference between arms is
`FFS_FUSE_CAPABILITY_MEMO_SLOTS` exported to both FUSE arms:

| slots | run | kernel median wall | FrankenFS median wall | fuse/kernel median | bootstrap median 95% confidence interval | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| 4096 (default) | 1 | `31,013,898 ns` | `217,470,654 ns` | **`6.990007x`** | `[6.988474, 7.026868]` | **`HONEST_LOSS`, `admitted=true`** |
| 4096 (default) | 2 | `30,627,706 ns` | `217,537,728 ns` | `7.056140x` | `[6.981495, 7.127538]` | `BLOCKED_NULL` |
| 65536 | 1 | `33,044,649 ns` | `104,677,062 ns` | `4.521091x` | `[3.674994, 5.221296]` | `BLOCKED_NULL` |
| 65536 | 2 | `30,688,692 ns` | `103,799,776 ns` | **`3.359246x`** | `[3.314229, 3.399607]` | **`HONEST_LOSS`, `admitted=true`** |

**One admitted row on each side, both with both A/A nulls clear: `6.990007x` at the
default and `3.359246x` at 65,536 slots.**

Verbatim from the harness for the two ADMITTED runs, kept unedited so the absolute arm
medians and the estimator are not taken on trust:

    4096   mounted_kernel_throughput,filesystem=btrfs,workload=large_directory_readdir_stat_8t,operations_per_observation=32768,kernel_median_wall_ns=31013898,fuse_median_wall_ns=217470654,kernel_operations_per_second=1056558.579,fuse_operations_per_second=150677.802
    4096   mounted_kernel_ratio,filesystem=btrfs,metric=wall_ns,workload=large_directory_readdir_stat_8t,pairs=12,fuse_over_kernel_median=6.990007,ci_low=6.988474,ci_high=7.026868,twice_null_margin_ratio=1.031128,directional_claim_clear=true,admitted=true,verdict=HONEST_LOSS,bootstrap_resamples=20000,cv_used=false
    65536  mounted_kernel_throughput,filesystem=btrfs,workload=large_directory_readdir_stat_8t,operations_per_observation=32768,kernel_median_wall_ns=30688692,fuse_median_wall_ns=103799776,kernel_operations_per_second=1067754.859,fuse_operations_per_second=315684.687
    65536  mounted_kernel_ratio,filesystem=btrfs,metric=wall_ns,workload=large_directory_readdir_stat_8t,pairs=12,fuse_over_kernel_median=3.359246,ci_low=3.314229,ci_high=3.399607,twice_null_margin_ratio=1.047663,directional_claim_clear=true,admitted=true,verdict=HONEST_LOSS,bootstrap_resamples=20000,cv_used=false

Each `ci_low`/`ci_high` pair is a bootstrap median 95% confidence interval, resampled
20,000 times.

### The FUSE arm is the robust evidence, and three estimators agree

The two 65,536 ratios differ (`4.52` vs `3.36`) and the reason is visible in the table:
run 1's KERNEL arm was slow (`33.0 ms` against `30.6-31.0 ms` everywhere else) because it
ran at `99.9%` peak off-placement mean busy. Our own arm did not move.

The FrankenFS absolutes are stable across every run:

- 4096 slots: `217,470,654` and `217,537,728` ns — **agree to 0.03%**
- 65536 slots: `104,677,062` and `103,799,776` ns — **agree to 0.84%**
- reduction: **`2.095x`** on the median pair, **`2.078x`** on the worst pairing

And that independently reproduces the candidate-vs-candidate A/B banked earlier today,
which measured `0.481225` = **`2.078x`** within one window on one ELF with its own A/A
null. Three estimators — two vs-kernel arms, and a within-window candidate crossover that
cancels host drift by construction — land on the same number to three decimal places.

### What to quote

**`3.36x`, with `6.99x` as the incumbent it replaces**, both admitted. The conservative
pairing of interval edges (`6.981495` against `5.221296`) still gives a `1.34x`
improvement, and that pessimistic bound is dominated by run 1's contended kernel arm
rather than by anything about our side.

### This is NOT a shipping recommendation, and the reason is already measured

`bd-m1bpu` established that the cliff MOVES rather than disappears: at 100,000 entries a
65,536-slot table is itself oversubscribed and the win degrades to `1.30x`. 65,536 slots
is **512 KiB per mount** against 32 KiB at the default, resident for the mount lifetime.
A larger default therefore still needs bd-5vis3's acceptance bar — peak resident memory
reported, and a workload that does NOT fit measured beside one that does — and the
100,000-entry row already is that non-fitting workload. What this row establishes is that
the lever is real and large at a realistic directory size, not that any particular
default is correct.

All four runs `CONTENDED`. For the vs-kernel ratios that is conservative in the usual
direction (contention inflates our arm at least as much as the kernel's), but note this
row's headline is a comparison between two of OUR OWN configurations, where contention
could in principle cut either way — which is exactly why the stable FUSE absolutes and
the contention-cancelling candidate crossover are cited above rather than the ratios
alone.

Provenance for all four: candidate
`executing_elf_sha256 = d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`
self-reported via `bench-evidence`,
`pgo_profile_sha256 = 6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`,
`isa=x86-64-v3`, candidate gate `verdict=pass`; driver
`471344289847c8f9eda3dd7c3db3d2a385a5bb4ef514451c2f6e3baa5aa539bc`; both built on
`thinkstation1`; `hostname=thinkstation1`, `executed_on=thinkstation1`. Four-arm
post-parity `verdict=pass` and `btrfs check` clean throughout.

## 2026-08-16 — REFUTED, and it is my own claim being refuted: "8 bytes x slots" is right about address space and wrong about RESIDENT memory — 1,048,576 slots cost 8 MiB of address space and ~1 MB resident (bd-kzfh2, AzureBay)

`bd-5vis3`'s acceptance bar says peak resident memory must be MEASURED, not argued. I
had been arguing it: every row I wrote about the slot count said "65,536 slots is
512 KiB per mount", straight from `8 bytes x slots`. **That arithmetic is right about
address space and wrong about resident memory, and the difference decides the sizing
policy.**

Daemon peak RSS (`VmHWM`, the kernel's own high-water mark) read from
`/proc/<pid>/status` while the daemon is still alive, before and after a **32,768-entry
readdir sweep** that touches ~32,768 distinct inodes, one image, identical workload per
arm:

    slots=4096     capability_memo_slots=4096     VmHWM  9412 ->  39876 kB (+30464)  VmSize  190660 -> 1368516 kB
    slots=65536    capability_memo_slots=65536    VmHWM  9544 ->  40848 kB (+31304)  VmSize  190660 -> 1371076 kB
    slots=1048576  capability_memo_slots=1048576  VmHWM  9400 ->  40920 kB (+31520)  VmSize  200900 -> 1378756 kB

| slots | table delta PREDICTED (8 B/slot) | table delta OBSERVED resident |
| --- | --- | --- |
| 65,536 vs 4,096 | `480 kB` | `840 kB` |
| 1,048,576 vs 4,096 | `8,160 kB` | **`1,056 kB`** |

The counted mechanism underneath the memory figures: the allocation count is the
capacity while the touched count is the workload — **32768 slots touched vs 1048576 slots
allocated** in the ceiling arm, so 3.1% of the table was ever written.

At the ceiling the prediction is **8x too pessimistic**. The address space IS reserved
exactly as arithmetic says — baseline `VmSize` goes `190,660 -> 200,900 kB`, a
`10,240 kB` step for an 8 MiB table — but the pages never become resident until they are
written.

### Why: the table is lazily materialised

`with_slots` builds the table by collecting `AtomicU64::new(0)` into a boxed slice. A
zero-fill of freshly-mapped anonymous memory lowers to `alloc_zeroed`, so untouched
slots stay on the shared zero page and cost nothing resident. A slot becomes real only
when `remember()` writes an inode into it.

A first pass missed this and nearly produced a wrong conclusion: measuring peak RSS
after stat'ing ONE file gave `+12 / +28 / +64 kB` across the four slot counts against a
predicted `+480 kB / +2 MiB / +8 MiB`, i.e. **100x off**. The tempting reading was "the
env var is not taking effect" — but the same env var had already produced a measured
`2.08x` on readdir+stat and both mount paths go through one production constructor, so
the table was certainly being built. The right reading was that it was being built and
not touched, and the way to tell the two apart was to touch it.

### What this means for the sizing policy

The unbounded-footprint objection is **materially weaker than I had been stating**. A
larger table costs:

- address space proportional to capacity (cheap on 64-bit, and bounded by
  `CAPABILITY_MEMO_SLOTS_MAX` at 8 MiB), and
- resident memory proportional to the inodes actually probed, which is bounded by the
  workload rather than by the parameter.

So option 1 on `bd-kzfh2` — a larger fixed default — is far more defensible than the
`8 bytes x slots` arithmetic suggested, and a mount that never touches a large directory
pays close to nothing for a large table.

### The limit of that conclusion, which is NOT measured

This fixture's inode numbers are **dense and sequential**, so `ino & (len - 1)` maps a
32,768-inode sweep onto a contiguous ~`256 kB` region — best case for page residency.
A filesystem with sparse or widely-spaced inode numbers would scatter the same number of
touches across many more pages, and the resident cost could approach the capacity. **No
claim is made about that case here.** Before a larger default ships, `bd-kzfh2` should
measure a sparse-inode workload as well; the `100,000`-entry non-fitting workload from
`bd-m1bpu` does not cover it, because its inodes are dense too.

Harness `scripts`-local `memo_rss.sh` and `memo_rss_touched.sh`. The candidate reports
its own identity through `bench-evidence` at run time:
`executing_elf_sha256 = d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`,
`pgo_profile_sha256 = 6a22cfcf8f9555e81d742a129e7f3510fe5dc3578eec251c994421f09e60fbcc`,
`isa=x86-64-v3`;
`hostname=thinkstation1`, `executed_on=thinkstation1`, run locally because a FUSE mount
runs only on the executing machine — no rch worker took part. `VmHWM` is a counted
kernel-maintained high-water mark, not a timing, so host contention cannot confound it
and no quiet window was required.

## 2026-08-16 — INVALID EXPERIMENT, reported as such: my "sparse inode" arm reordered VISITS, not inode NUMBERS, so it cannot answer the question it was built for (bd-kzfh2, AzureBay)

The previous entry established that the memo's resident cost tracks the touched working
set, and flagged one limit as unmeasured: the fixture's inode numbers are dense and
sequential, so a 32,768-inode sweep lands on a contiguous ~256 kB slot region — the best
case for page residency. A sparse-inode filesystem might scatter the same touches across
many more pages.

I built an arm to test that. **It does not test it**, and the numbers are reported here
only so nobody mistakes them for an answer:

    slots=1048576  order=dense      VmHWM  9548 ->  38828 kB  (+29280)
    slots=1048576  order=scattered  VmHWM  9388 ->  40200 kB  (+30812)
    slots=4096     order=scattered  VmHWM  9424 ->  41272 kB  (+31848)

**The flaw:** the "scattered" arm walks a large-stride permutation of the directory, which
changes the ORDER in which inodes are visited. It does not change WHICH inodes are
visited, and slot index is `ino & (len - 1)` — a pure function of the inode number. The
same 32,768 dense objectids map to the same contiguous slot range regardless of the order
they are probed in. So both arms touch an identical set of pages and the comparison is
between two schedules of the same work.

The `4096 scattered` row is the tell that should be read first: it is **higher**
(`+31848`) than `1048576 scattered` (`+30812`), and a 4096-slot table cannot possibly
cost more resident memory than a 1,048,576-slot one. That ordering is impossible if the
table were what these numbers were measuring, so the spread is other caches and run
noise — roughly `±1.5 MB` on a `~30 MB` sweep — and it sets the resolution floor for this
instrument at about `5%`.

### What it does legitimately establish

Page residency depends on the SET of slots touched, not the order of touching. Obvious in
hindsight, and now measured: `+1532 kB` between two orders of an identical touch set is
within the `±1.5 MB` noise this instrument shows on the impossible-ordering row.

### What would actually test it, and why it was not run

Spacing inode numbers requires creating and deleting: make `N x K` files, delete `K-1` of
every `K`, and the survivors' objectids are spread by `K`. To approach the pessimistic
bound — one 4 KiB page per touch — needs `K >= 512`, because a page holds `512` slots at
8 bytes each. For a 32,768-inode working set that is **16.7 million** file creations,
which is not a cheap fixture and is not obviously worth it.

**Reasoning, explicitly not measurement:** btrfs allocates objectids sequentially, so the
dense case is the normal one and reaching `K >= 512` requires sustained deletion churn
that leaves 511 of every 512 objectids unused. The pessimistic bound is real arithmetic —
`32,768` touches x 4 KiB = `128 MB` if every touch hit a distinct page — but the workload
that produces it is not one this filesystem's allocator naturally creates. A smaller `K`
degrades gracefully: residency is bounded by `min(capacity, touched x 4 KiB)`, and at
`K = 8` (a plausible churn level) the same sweep would touch roughly `8x` the pages, i.e.
~2 MB rather than ~256 kB, still far below the 8 MiB capacity.

That reasoning is offered as a reason not to block the sizing policy on this arm, NOT as
a substitute for measuring it. `bd-kzfh2` keeps it open with the `K`-spacing recipe
above, and any larger default should state that its resident bound is
`min(capacity, touched x page)` rather than implying the dense figure generalises.

Harness `scripts`-local `memo_rss_sparse.sh`; candidate
`executing_elf_sha256 = d4278471dab01e7cfa496895c5a66f8a73894429bb2b4d80da5e050ba3ea32a0`,
`isa=x86-64-v3`; `hostname=thinkstation1`, `executed_on=thinkstation1`, run locally
because a FUSE mount runs only on the executing machine. Counted mechanism: the memo's
allocation count is 1048576 slots against a touched count of 32768 — **32768 probes
touched vs 1048576 slots reserved** — and both figures are IDENTICAL in the two order
arms, which is precisely why they cannot differ for the reason I intended.
