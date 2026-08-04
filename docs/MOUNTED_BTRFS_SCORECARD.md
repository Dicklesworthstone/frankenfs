# Btrfs scorecard: FrankenFS FUSE against the incumbent, Linux kernel btrfs

**Date:** 2026-07-31 · **Host:** `thinkstation1`, AMD Ryzen Threadripper PRO 5975WX,
32C/64T, 231.7 GB RAM, 1 NUMA node · **Kernel:** 6.17.0-35-generic · **Bead:** `bd-opb6l`

Before this run, btrfs had **never** produced an admitted vs-incumbent ratio: three
attempts on 2026-07-27 were all rejected on a null control. It now has five, on the same
instrument, the same frozen candidate, and the same parameters as the
[ext4 scorecard](MOUNTED_KERNEL_SCORECARD.md), so the two are directly comparable.

A ratio above `1.0` means FrankenFS is slower. Every row is a direct competitive
measurement in one invocation against four independent live mounts (`kernel_a`,
`kernel_b`, `fuse_a`, `fuse_b`) under a four-round Latin-square physical-arm crossover,
carrying two same-invocation A/A null controls.

**Score: 1 win / 4 losses / 0 neutral / 1 workload blocked by a functional defect.**

## The rows

| Workload | FrankenFS ÷ kernel btrfs | Kernel A/A | FUSE A/A | Threads req → obs | Verdict |
| --- | --- | --- | --- | --- | --- |
| **Large-directory readdir+stat**, 32,768 entries | **`8.322812x` `[8.289845, 8.358508]` slower** (margin `1.011474x`) | `0.999544x`, spread `1.004004x` | `0.999278x`, spread `1.005721x` | 8 → **8** | **LOSE** |
| **Warm stat**, 2,000 calls | **`4.977803x` `[4.949139, 5.014278]` slower**; replicate **`5.036433x` `[5.017720, 5.074796]`** | `0.996700x` / `1.000455x` | `1.002699x` / `1.001758x` | 1 → **1** | **LOSE** |
| **Small-file create/delete storm**, 2,000 files | **`2.358280x` `[2.322435, 2.430125]` slower** (margin `1.045128x`) | `0.996139x`, spread `1.018112x` | `0.992157x`, spread `1.022315x` | 1 → **1** | **LOSE** |
| **Parallel metadata writes**, 512 creates, 8 threads, **128 blocks** | **`1.930090x` `[1.916623, 1.940038]` slower** (margin `1.019214x`) | `1.002214x`, spread `1.009562x` | `0.997250x`, spread `1.009114x` | 8 → **8** | **LOSE** |
| **Multi-file parallel read**, 256 × 256 KiB, 8 threads | **`0.894290x` `[0.885022, 0.903489]` FASTER**; replicate **`0.830537x` `[0.823606, 0.835141]`** | `1.004459x` / `1.001984x` | `1.001891x` / `1.000228x` | 8 → **8** | **WIN — see caveat** |
| **Fsync/journal commit**, 8 × 4 KiB | not measurable | — | — | — | **BLOCKED — functional defect, below** |

Every admitted row: pinning attested with the observed CPU set equal to the bound set,
exact four-arm parity, clean post-unmount `btrfs check --readonly`, incumbent isolation
`pass`, wall-time bootstrap median CI as the gate (`cv_used=false`,
`instructions_used=false`), effect clearing twice the widest null log-margin.

## One sentence per row

- **readdir+stat: we lose badly.** The kernel enumerates and stats 32,768 entries in
  26.157 ms where we take 217.782 ms — our worst measured surface on any filesystem.
- **Warm stat: we lose.** About five times slower, replicated on two CPUs.
- **Create/delete storm: we lose.** About 2.36 times slower on a 2,000-file namespace
  transaction.
- **Parallel metadata writes: we lose.** About 1.93 times slower with eight workers
  creating 512 files and fsyncing their directories.
- **Parallel read: we are faster** — 10.6% and 16.9% faster across two runs — but I am
  not banking this as a campaign win yet, for the reason below.
- **Fsync/journal commit: we cannot run it at all** on btrfs. That is a defect, not a
  slow number.

## The win needs a mechanism before it counts

`parallel_read_multifile_8t` is the campaign's first `honest_win` against a real kernel
incumbent. The statistics are not the weak part:

- **replicated 2/2** on separate placements, `0.894290x` and `0.830537x`;
- all four A/A nulls clean, and **every one contains `1.0`**, so both runs clear the
  pre-`2198a47d` gate unaided — this does not depend on the schema-v6 correction;
- each clears its own twice-null margin by a wide factor.

The direction is robust. What is not settled is **why**, and the magnitude wobbles more
than I would like: `0.894290x` versus `0.830537x` is a 7.7% spread between two runs whose
own intervals are ~2% wide, so something not captured by the nulls is moving between
windows.

The specific worry is that per-block data checksumming is btrfs's headline feature.
I checked the source: FrankenFS has **no read-side checksum verification** — every
`crc32c`/csum path in `ffs-btrfs` builds csum items on the *write* side, and there is no
verify equivalent in the btrfs read path or the FUSE layer. If the incumbent verifies on
every read and we never do, this is not a like-for-like win; it is a different integrity
contract.

**But that does not settle it against us either.** This is a *warm-cache* workload, and
kernel btrfs does not re-verify checksums on page-cache hits — it verifies on the disk
read that populates the cache. So the incumbent may not be paying that cost in this
regime at all.

The question is genuinely open in both directions, and a **cold-cache read variant would
decide it**. That is a different workload and a separate row, not a silent substitution
of this one. Until it runs:

> Quote this row as *"FrankenFS is faster than kernel btrfs on warm multi-file parallel
> reads, mechanism unresolved, and FrankenFS performs no read-side checksum
> verification."* Do not quote it as a bare win.

## Blocked: FrankenFS cannot do positioned writes on btrfs

`fsync-journal-commit` failed **6/6 attempts**, deterministically, and not on a
contention or null gate:

```
mounted_kernel_gate,error=positioned write .../btrfs/fuse_a/fsync.bin:
  Input/output error (os error 5)
```

The workload performs 8 × 4 KiB positioned writes to one file and fsyncs after each. On a
FrankenFS-mounted btrfs image the first positioned write returns `EIO`. The same workload
runs fine on FrankenFS ext4 (it is the banked `0.997098x` neutral row), and the btrfs
kernel arms are unaffected.

Filed as **`bd-ftev0`**. This is a **capability gap, not a performance result**, and it is the honest headline of
the btrfs suite: four losses and one caveated win are numbers, but a workload we cannot
execute at all is a defect. Filed for triage rather than buried in a ratio table.

### Root cause found, 2026-07-31 — mount builds an inconsistent allocator

The write path is fully implemented for `offset > 0` and for mid-file overwrite; there is
no `unimplemented!` anywhere on it. The `EIO` is a real invariant failure:

1. At mount, `OpenFs` registers one block group per chunk with **`used_bytes = 0`**
   (`ffs-core/src/lib.rs:7494-7517`) — except a synthetic 128 KiB reservation for a chunk
   at logical 0, which no real `mkfs.btrfs` image has, since its first chunk starts at a
   non-zero logical offset.
2. Immediately below, the **real on-disk extent tree is loaded** (`bd-is7m1`), so every
   `EXTENT_ITEM` the image already contains is present.
3. The two now contradict each other: the extent tree says bytes are allocated, the
   accounting says the group is empty. Nothing ever reads the on-disk
   `BLOCK_GROUP_ITEM`s to seed the tally.
4. The first overwrite of a pre-existing extent removes it, which calls
   `free_extent` → `used_bytes.checked_sub(num_bytes)` on a zero tally → `None` →
   `BrokenInvariant("block group used bytes underflow")` (`ffs-btrfs/src/lib.rs:6988`) →
   `FfsError::Corruption` (`ffs-core:17235`) → **`EIO`** (`ffs-error:284`).

The failure is not offset-specific — the reported "positioned write" is at offset 0. What
makes it fire is that the write covers a full sector (so it is not inline) **and** an
extent already exists there. Small inline writes never call `free_extent`, which is why
btrfs writes appeared to work at all. ext4 is unaffected because it allocates against the
real on-disk bitmaps read at mount, with no synthesized tally to underflow.

The existing test `extent_allocator_adversarial_rejects_free_accounting_underflow`
(`ffs-btrfs:19750`) asserts precisely this failure as a *fail-closed contract*. The
contract is correct. The bug is that mount handed it an inconsistent state on every real
image, so a guard meant for corruption was firing on healthy filesystems.

**Fix — identified and pinned, not yet landed.** Call `sync_block_group_accounting()` at
mount, immediately after the extent tree
is loaded. That function already exists and is already run at commit; it recomputes each
group's `used_bytes` as the sum of the `EXTENT_ITEM`/`METADATA_ITEM` lengths physically
inside it — the same definition `btrfs check` enforces — so it is correct-by-construction
rather than a running tally. Its own doc comment already noted that the mount-time tally
is "seeded from a synthetic reservation, not the real on-disk figure".

Two things it deliberately does not disturb: the reserved-prefix fence lives in
`min_usable_offset`, which it does not touch; and allocation is unaffected because
`alloc_extent` gap-searches the extent tree whenever `tail_verified` is false, which it is
for every group at mount, so the bump cursor was only ever a hint.

Pinned by `reconciled_block_group_accounting_makes_a_preexisting_extent_freeable_bd_ftev0`
(`ffs-btrfs`), which builds the exact mount-time state and proves the same `free_extent`
call succeeds once reconciled. The underflow guard is not weakened — it stops being
reachable from a correctly mounted filesystem.

**Why the one-line call is not committed yet.** Making it live regresses
`btrfs_largest_contiguous_free_run_uses_allocator_gaps` (`ffs-core`), which asserts a
fixture leaves exactly 64 free blocks. That figure was computed against the *un*-reconciled
tally, so real accounting legitimately changes it — the test's expectation needs
recomputing, not the fix reverting. Measured, not assumed: with the call in place
`ffs-btrfs` is 375/375 and `ffs-core` is 1186 passed / 2 failed; running those two tests on
clean `HEAD` with no overlay shows `fast_commit_del_range_apply_punches_and_frees_passes_e2fsck`
already failing there (pre-existing, not ours) and the free-run test passing, which is what
isolates the regression to this change. Next step is to recompute the expectation and land
both together.

## Provenance

- Driver ELF `4b0f0889e637481ac9aac15737ced66aee59a53efcd38c77ff3c0cbf396f6cdb`, built by
  `rch exec --base HEAD --clean-overlay --no-overlay` on `ovh-a` so no co-tenant agent's
  working-tree edits could enter it; self-hashed in process.
- Candidate ELF `f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349`
  (x86-64-v3, PGO `6a22cfcf…`), hash-verified fail-closed before every run and
  **byte-identical to the candidate behind the five ext4 rows**, so the filesystem arm is
  the only thing that differs between the two scorecards.
- `codegen_isa` line emitted on every run. The driver is a baseline-ISA build and issues
  the timed syscalls for both arms identically, so its ISA cancels in the ratio; the
  candidate is the v3+PGO production shape.
- Governor recorded, not set (shared host): `amd-pstate-epp` / `powersave` /
  `performance`, `non_performance_or_mixed_governor_warning=true`.
- `--placement-scope same-llc`, matching the ext4 bank; `host_wide_quiescence` is
  therefore `not_applicable` on these rows, exactly as on the ext4 rows. Contention was
  still a full one-second per-CPU average with SMT sibling guards and driver/FUSE busy
  limits, and the preflight refused several windows outright rather than timing through
  them.
- Reports retained at
  `/data/tmp/frankenfs-mounted-btrfs/run_*/mounted-kernel-report.json`; run images were
  deleted after each run, which is why the whole artifact tree is ~150 MB.

## Comparison with ext4, same candidate, same instrument

| Workload | vs kernel ext4 | vs kernel btrfs |
| --- | --- | --- |
| readdir+stat | `4.967448x` slower | **`8.322812x` slower** |
| create/delete storm | `2.753659x` slower | `2.358280x` slower |
| parallel read | `1.287862x` slower | **`0.894290x` / `0.830537x` faster** |
| parallel metadata writes | `1.510822x` slower | `1.930090x` slower |
| fsync/journal commit | `0.997098x` neutral | **cannot run — `EIO`** |
| warm stat | not in the ext4 bank | `4.977803x` / `5.036433x` slower |

The parallel-read row is the only sign change anywhere in either scorecard, which is
another reason to resolve its mechanism before quoting it.

⚠️ **Do not confuse the `8.322812x` readdir+stat figure with the retired "8.3x"
folklore.** That folklore was ext4 parallel-metadata-writes derived from separate,
unmatched runs and is withdrawn. This is btrfs readdir+stat from a matched
same-invocation four-arm crossover with both nulls gated. The numeric collision is
coincidental.
