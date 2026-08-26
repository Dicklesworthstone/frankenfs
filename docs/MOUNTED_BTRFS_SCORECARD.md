# Btrfs scorecard: FrankenFS FUSE against the incumbent, Linux kernel btrfs

> ## ⛔⛔ THE fsync AND parallel-metadata WINS ARE SUBSTANTIALLY **TRANSPORT**, NOT FILESYSTEM
>
> **Measured 2026-08-17 (`bd-w2u82`).** Every row in this file puts the kernel arm on a LOOP
> DEVICE — kernel btrfs cannot mount a plain file — while the FrankenFS arm `pwrite`s the
> image directly. The incumbent therefore pays a block-layer and loop-worker hop per barrier
> that we do not. With the comparator's new `--fuse-transport loop` putting BOTH arms on a
> loop device, btrfs `fsync-journal-commit` goes:
>
> | FUSE arm transport | ratio |
> | --- | --- |
> | `file` — every row below | **`0.449–0.463x`** ("2.2x faster", admitted twice) |
> | `loop` — symmetric | **`1.491904x`** [1.476471, 1.505554] — **1.49x SLOWER** |
>
> A **3.2x swing from transport alone**. So `fsync/journal commit`, `parallel metadata writes`
> and any other durability-bound row here answers *"which is faster for a file-backed image on
> this host"* — a real operator question for VM images and container layers — and **NOT** *"is
> FrankenFS faster than btrfs"*. Do not quote them as filesystem wins.
>
> ⚠ Caveat that limits the clean-A/B reading: the kernel arm also slowed (~106 → 151 ms) when
> a second loop device joined the run, so the symmetric figure is not simply the asymmetric one
> with our transport corrected. The symmetric run is also `BLOCKED_NULL` (fuse null spread
> `1.032060`) and `CONTENDED`. What survives without over-reading: **the configuration that
> flattered us is the asymmetric one.**
>
> ## ⛔ FOUR ROWS DESCRIBE FRANKENFS AT `HEAD`. THE OTHER TWO DO NOT.
>
> **readdir+stat, parallel read and warm stat were re-measured 2026-08-08** on candidate
> `913c36a4…` (PGO `b30de364…`, x86-64-v3 attested) — each twice, all admitted.
>
> **fsync/journal commit was re-measured 2026-08-17** on candidate `c9fb745f…` (PGO
> `6a22cfcf…`, x86-64-v3) — five runs, admitted twice, and **the sign changed**: a
> `1.976308x` loss became `~0.45–0.46x`, about 2.2x faster. See the scored section below,
> including the two qualifications that travel with it. That candidate is also the first to
> contain the 2026-08-17 write-path work (`bd-fv9tc` GDT coalescing, `bd-42gtq` COW-only
> block writes, `bd-k74ef` per-block backrefs), which is why the row moved.
>
> **parallel metadata writes was re-measured 2026-08-17 on `c9fb745f…` and is ADMITTED at
> `0.798200x` — a SIGN CHANGE** from `1.930090x` slower to 1.25x faster, `HONEST_WIN`, 288
> pairs, both A/A nulls clear. Three readings agree (`0.775502` / `0.780774` / `0.798200`,
> 2.9% spread); `0.798200x` is quoted because it is both the admitted run and the least
> favourable. It needed 288 pairs because our arms carry ~1.55x the kernel arms'
> per-observation CV — a sample-size requirement computed in advance, not a defect
> (`bd-r9fix`).
>
> **create/delete storm was re-measured and is NOT admitted**: `2.358280x` -> `1.901025x`
> slower, gap narrowed 19%, both nulls clear, run refused by the post-hoc external-load veto
> (peak off-placement busy 57.2%). Still a LOSS. See `bd-3tqec`.
>
> This file needs the warning **more** than the ext4 one, because the commits landed since
> are all in the btrfs write path: `839eb708` (the durable commit built leaves it could not
> serialize, so `fsync` returned EINVAL and the unmount flush failed identically — data was
> never persisted above roughly 18 MiB per transaction), `241093de` and `9d64f4a1` (a write
> failing with ENOSPC destroyed the data it could not replace), and `7fac4779` (extent splits
> now reference the shared extent instead of copying it, removing a read and an allocation
> from every overwrite-split). The last one changes the write path's I/O profile directly.
>
> **No figure below EXCEPT readdir+stat, parallel read and warm stat may be presented as
> "FrankenFS today" until re-measured on a current ELF.** Quote the rest as historical, with their ELF, or not at all.
> The re-measured row uses a freshly trained PGO profile (`b30de364…`, not the bank's
> `5c6530a0…`, which was destroyed — `bd-v0igv`) and a different kernel, so it supersedes its
> own predecessor without re-baselining the others.
>
> The `bd-4sull` rule in the [ext4 scorecard](MOUNTED_KERNEL_SCORECARD.md) applies here
> unchanged: `core_contention_preflight … verdict=clear` certifies only that no competing
> load sat on the placement CPUs when sampling began. It is **not** evidence that a new run
> is comparable to a banked one — measured, the incumbent arm moved 8.26% between two runs
> that both printed `verdict=clear`.
>
> This file now carries its own instance. The two admitted readdir+stat runs above spread
> **1.36%**, against run 1's own CI width of **0.40%** — the spread is 3.4x the interval that
> would have been quoted. And it is a useful counter-example to the campaign's usual pattern:
> here the **incumbent was flat** (`+0.09%`) and **our** arm carried the movement (`−0.90%`),
> the reverse of the ext4 pair taken minutes earlier.
>
> ⚠ Do not generalise that into "the spread always exceeds the CI" — this file measured a
> counter-example the same day. The ext4 parallel-read pair spread `0.83%` against a `0.86%`
> CI width, i.e. *smaller*. Five measured pairs now: three where the spread exceeds the CI,
> one where it does not, and one (btrfs parallel read, `6.09%`) where it exceeds it sixfold
> and flips the verdict. The rule survives as **quote `max(CI, measured spread)`**, which is
> correct without assuming which dominates.

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

**Score: 1 win / 5 losses / 0 neutral / 0 unscored.** The campaign's only `honest_win` —
parallel read — was re-measured on 2026-08-08 and **CONFIRMED** at ≈`0.89–0.93x`, 2/2
admitted in a verified-quiet window. It briefly scored UNRESOLVED earlier the same day on
two runs taken under a peer's CPU load, which returned opposite verdicts; those are
inadmissible and the row's section explains why the gate could not see it.

## The rows

| Workload | FrankenFS ÷ kernel btrfs | Kernel A/A | FUSE A/A | Threads req → obs | Verdict |
| --- | --- | --- | --- | --- | --- |
| **Large-directory readdir+stat**, 32,768 entries | ⭐⭐⭐ **SUPPRESSING THE AUDIT PROBE TAKES THIS ROW TO PARITY TOO: TWO ADMITTED RUNS, `1.034152x` `[1.019777, 1.035149]` and `1.024643x` `[1.010881, 1.035601]`, both `verdict=HONEST_NEUTRAL` — spread **`0.93%`**, our arms `30,611,950`/`30,368,572 ns` `0.80%` apart** ⭐ **AND IT HOLDS UNDER SYMMETRIC TRANSPORT: `1.009472x` `[0.997166, 1.021366]`, ADMITTED, `HONEST_NEUTRAL`** (`--fuse-transport loop`, 48 pairs, nulls `0.996268` spread `1.009568` and `1.003474` spread `1.016777`, `parity=pass`; ours `28,015,063 ns` vs kernel `27,751,788 ns`, `0.95%` apart) — the ratio moves **`−1.48%`**, i.e. slightly BETTER, not worse. This was the parity claim most at risk, since readdir+stat reads directory blocks and should be the most transport-sensitive of the four — inside its own `1.026435x` null margin, so a TIE. `FFS_FUSE_XATTR_NO_SUPPORT=1`, `xattr_suppression=active`, `xattr_presence=proven_absent`; nulls `0.995727` spread `1.013131` and `0.998088` spread `1.012319`, both clear; `parity=pass`, `post_unmount_validation=clean`. Ours `30,611,949 ns` vs kernel btrfs `29,590,883 ns`. That is a **`3.955x` reduction** from this row's shipping `4.089855x`, our absolute going `110,972,246 → 30,611,950 ns` — **`72.4%` faster**. ⭐ **This is the row where the receive spin LOST `1.207084x`** (8 client threads saturate a serial dispatcher), so the two levers are complementary rather than competing: the spin helps only gappy low-concurrency streams, suppression removes the crossings outright and works precisely where the spin does not. Same restriction and the same proven-absent precondition as the warm-stat rows; NOT a default. **`3.832345x` `[3.752008, 3.873048]` slower** — ONE ADMITTED run 2026-08-25, `verdict=HONEST_LOSS`, twice-null margin `1.035479x`, 12 pairs / 3 crossover blocks, `--operations 32768 --image-size-mib 512`, candidate ELF `9b1517b8…` (PGO `f8a9d574…`, x86-64-v3 attested, in-process self-report). **Absolute medians: ours `112,538,224 ns`, kernel btrfs `29,614,922 ns`** (physical arms ours `112,767,838`/`112,283,492`, kernel `29,822,260`/`29,533,714`). ⛔ **SUPERSEDES `7.753405x` / `7.649395x`**: those were measured on the DIRECT-MAPPED 4096-slot capability memo, which stopped being the shipping default in `9f4e2811f` (2026-08-24) when the range-leaf bitmap took over. The admitted run self-reports the shipping knobs — `capability_memo_bitmap=true`, `btrfs_floor_memo_slots=4`. **The MECHANISM is unchanged** — still exactly 1.0000 `security.capability` GETXATTR per entry, still Linux AUDIT (see the 2026-08-16 attribution below, which stands). What moved is the DAEMON's cost of answering it: a 4096-slot direct-mapped table self-evicts on a 32,768-entry sweep and misses every probe, while one 4 KiB range leaf covers 32,768 inodes with no conflict misses at all. This is `bd-34hzz`'s hand-set `3.359246x` arriving as a BOUNDED shipping default rather than a tuned constant. ⚠ **ONE admitted run — no pair yet.** Four further readings the same day in worse windows, all `BLOCKED_NULL` and therefore corroboration only, bracket it: `3.771996x`, `3.811520x`, `3.857444x`, `4.097333x`. Quote this row to the **`2.3%`** spread of the three that agree, never to its own CI. Post-hoc `external_load_during_run=CONTENDED`; both A/A nulls clear. | `1.015408x`, spread `1.017585x` | `0.996297x`, spread `1.011426x` | 8 → **8** | **LOSE** |
| **Warm stat**, 2,000 calls | ⭐⭐⭐ **SUPPRESSING THE AUDIT PROBE ELIMINATES THIS ROW TOO: TWO ADMITTED RUNS, `0.988189x` `[0.982305, 0.988457]` and `0.986840x` `[0.977362, 0.992285]`, both `verdict=HONEST_NEUTRAL` — spread **`0.14%`**, our arms `4,498,362`/`4,504,386 ns` `0.13%` apart** ⭐ **HOLDS UNDER SYMMETRIC TRANSPORT: `0.984727x` `[0.977579, 0.990421]`, ADMITTED, `HONEST_NEUTRAL`** (`--fuse-transport loop`, 48 pairs, nulls `0.996353` spread `1.021685` and `0.998285` spread `1.012126`, `parity=pass`; ours `4,511,648 ns` vs kernel `4,579,611 ns`); ratio moves **`−0.21%`** — `FFS_FUSE_XATTR_NO_SUPPORT=1`, daemon self-reporting `xattr_suppression=active`/`xattr_setting=asserted`/`xattr_presence=proven_absent`; nulls `0.999987` spread `1.005581` and `0.997926` spread `1.011131`, both clear; `parity=pass`, `post_unmount_validation=clean`. Ours `4,498,361 ns` vs kernel btrfs `4,564,725 ns` — `1.2%` FASTER, inside the `1.022385x` null margin, so a TIE. That is a **`4.947x` reduction** from this row's own shipping `4.888392x`, our absolute going `22,550,593 → 4,498,362 ns`. ⭐⭐ **THE CONVERGENCE IS NOW EXACT:** suppressed, ext4 warm stat measures `0.999810x` and btrfs `0.988189x` — `1.16%` apart — and OUR OWN ARMS are `4,518,176 ns` (ext4) against `4,498,362 ns` (btrfs), **`0.44%` apart**. Two different on-disk formats, identical performance, both at kernel parity: proof that the whole gap was the kernel-issued probe and none of it was our filesystem work. ⚠ Same restriction as the ext4 row — this mount declares NO xattrs (`setxattr`/`removexattr` answer `ENOTSUP`) while the kernel arm keeps them; sound only because the image was PROVEN to carry none. Not a default. Shipping figure follows. | **`4.888392x` `[4.884244, 4.927371]` ADMITTED 2026-08-26 on candidate `3c7ff854…` (PGO `c1b9eb9f…`, x86-64-v3), margin `1.049856x`, ours `22,550,593 ns` vs kernel btrfs `4,567,125 ns` — reproducing the same day's `4.838761x` to `1.03%`. ⭐ **THE ADAPTIVE RECEIVE SPIN TAKES IT TO `3.977560x` `[3.971576, 4.123794]`, ALSO ADMITTED** (`FFS_FUSE_RECEIVE_SPIN=2000` + `ADAPTIVE=1` on both fuse arms, daemon self-reporting `receive_spin=2000`; margin `1.042742x`; nulls `0.999052` spread `1.013896` and `0.999746` spread `1.021147`, both clear; ours `18,394,308 ns` vs kernel `4,548,228 ns`) = **`1.2290x` better**, against the within-window six-arm A/B's `0.807907` `[0.792986, 0.815799]` = `1.2378x` — two estimators `0.7%` apart. ⭐⭐ **TWO PREDICTIONS CONFIRMED:** the concurrency SCOPE RULE said a 1-thread row must WIN (it did, where 8-thread readdir+stat LOSES `1.207084x`), and the arithmetic band `3.9494–4.0106` published before this row was taken contains the measured `3.977561`. **CROSS-FILESYSTEM CONVERGENCE:** ext4 warm stat with the same lever measures `3.949942x` — `0.70%` away. Two filesystems landing on one number is what a row whose cost is a single kernel-issued `security.capability` round trip has to do, and is the strongest corroboration the audit attribution has. ⚠ The spin is NOT a default: fixed mode costs `14.8–19.3%` of a core on a sparse stream, adaptive `2.3–2.6%`, and it LOSES on saturated multi-thread rows. Superseded: `4.838761x`, ≈`4.77–4.80x`.**`[4.821035, 4.841017]`, ADMITTED**, `verdict=HONEST_LOSS`, twice-null margin `1.010598x` (a very tight window — nulls `1.001490` spread `1.003610` and `0.996824` spread `1.005285`), 12 pairs, candidate `9b1517b8…` (PGO `f8a9d574…`, x86-64-v3), knobs `receive_spin=0`, `capability_memo_bitmap=true`, `btrfs_floor_memo_slots=4`. Ours `22,096,484 ns` vs kernel btrfs `4,572,285 ns`. Confirms and slightly exceeds the banked band. ⭐ **CROSS-CHECK OF THE AUDIT ATTRIBUTION:** ext4 warm stat measured the same day on the same ELF is `4.901194x` with ours at `22,616,482 ns` and kernel at `4,586,657 ns` — **our two arms agree to `2.3%` and the two KERNEL arms to `0.3%`**, i.e. warm stat is filesystem-independent on BOTH sides, exactly as a row whose cost is one kernel-issued `security.capability` round trip must be. Older: ≈`4.77–4.80x` slower.** Two admitted same-ELF runs on a current candidate, `4.769886x [4.736506, 4.801735]` and `4.802719x [4.775460, 4.816630]`, margins `1.040608x`/`1.021556x`, spread `0.69%`. ⛔ SUPERSEDES `4.977803x` / `5.036433x` — the new pair is ~4% lower on a current ELF. **ATTRIBUTED 2026-08-16**: 2,000 warm stats produce **exactly 2,000 FUSE round trips and every one is a `security.capability` GETXATTR** — no GETATTR/LOOKUP/STATX, because the 60 s `ATTR_TTL` works and the kernel serves attributes from its own cache. **`~99%` of this gap is that one kernel-issued probe**; the daemon is `0.75%–0.99%` of it. The probe is one per path-based syscall, independent of path depth, filesystem (ext4 `1.0000` == btrfs `1.0000`), xattr presence and caller privilege — five counted nulls, each with a positive control — and **`fstat` on an open fd pays zero**. **The probe is Linux AUDIT, and it is HOST-CONDITIONAL** — captured with `bpftrace` on `fuse_getxattr`, 300 of 300 stats: `get_vfs_caps_from_disk / audit_copy_inode / __audit_inode / filename_lookup / vfs_statx`, i.e. audit collecting file capabilities during path resolution, forced by this host's path-based `auditctl` rules over the working tree. So the honest scope of this row is *warm stat **on a host with path-based audit rules***; the reopen condition for `bd-z0rb8` is a host without them, checked with `auditctl -l`, not a different kernel. The ratio is **not** thereby invalidated — kernel ext4/btrfs were measured on the same host under the same rules and paid the same probe; what differs is the **cost** of paying it (a cached inode xattr read for an in-kernel fs, a full userspace round trip for FUSE), and that asymmetry is ours. ⇒ no filesystem-, daemon- or path-shape lever can move this row (`bd-z0rb8`); a workload holding fds pays none of it, one that stats by path pays all of it | run 1 `0.994703x`, spread `1.020102x` · run 2 `0.999117x` | run 1 `0.993281x`, spread `1.017402x` · run 2 `0.998908x` | 1 → **1** | **LOSE** |
| **Small-file create/delete storm**, 2,000 files | **`2.358280x` `[2.322435, 2.430125]` slower** (margin `1.045128x`) | `0.996139x`, spread `1.018112x` | `0.992157x`, spread `1.022315x` | 1 → **1** | **LOSE** |
| **Parallel metadata writes**, 512 creates, 8 threads, **128 blocks** | **`1.930090x` `[1.916623, 1.940038]` slower** (margin `1.019214x`) | `1.002214x`, spread `1.009562x` | `0.997250x`, spread `1.009114x` | 8 → **8** | **LOSE** |
| **Multi-file parallel read**, 256 × 256 KiB, 8 threads | ⛔⛔ **THE WIN IS WITHDRAWN — RE-MEASURED 2026-08-26 AS AN ADMITTED LOSS, `1.085668x` `[1.066436, 1.112998]`, `verdict=HONEST_LOSS`, `directional_claim_clear=true`** (margin `1.037809x`, **48 pairs**; nulls `1.001510` spread `1.011989` and `0.994063` spread `1.018729`, both clear; `parity=pass`). Ours `4,303,575 ns` vs kernel btrfs `4,005,059 ns`, candidate `3c7ff854…` (PGO `c1b9eb9f…`, x86-64-v3). **A SIGN CHANGE** from the banked `0.893282x`/`0.927352x` FASTER ⚠ **ONE admitted run per transport — NO PAIR YET**, corroborated by 20 blocked readings all above `1.0` (median `1.0842`); quote as single admitted runs — this is `1.171x` the banked band's own slowest figure, and the effect clears twice its null margin, so it is a directional loss and not a tie. It was found by checking the one read-only row never re-measured on the shipping binary, and it was preceded by 20 BLOCKED readings all above `1.0` (median `1.0842`) which the admitted row now confirms were real rather than window artefacts. Reaching admission needed 48 pairs: at 12 the kernel A/A spread ran to `1.242174`. `bd-mtita`. ⭐ **AND THE SYMMETRIC-TRANSPORT FIGURE IS WORSE STILL: `1.140683x` `[1.129301, 1.148922]`, ADMITTED**, `--fuse-transport loop` so BOTH arms cross the block layer, 48 pairs, nulls `1.000356` spread `1.019079` and `0.993778` spread `1.017190`, `parity=pass`; ours `4,468,259 ns` vs kernel `3,891,807 ns`. `--fuse-transport` moves only OUR arm (the kernel arm is loop-mounted either way, `bd-w2u82`), and ours goes `4,303,575 → 4,468,259 ns`, **`+3.83%`** — so the transport asymmetry was FAVOURING us and correcting it makes the loss BIGGER. By `bd-w2u82`'s own argument `1.140683x` is the honest answer to "is FrankenFS faster than kernel btrfs on parallel read", and the answer is no. ⇒ the loop-asymmetry hypothesis for the vanished win is REFUTED, as is the PGO/code one. ⭐ **ATTRIBUTED (`bd-ga4ug`), from the comparator's own deterministic dispatch counters — `handler_total_count=40,646` in BOTH transport runs:** `282.3` requests per observation for 256 files = **`1.103` per file, ONE read request per 256 KiB file**, `232.2 KiB` per request; daemon handler `0.731 ms`/observation = **`16.4%`** of our wall at `2,590 ns` per request. The gap — ours `4.468 ms`, kernel `3.892 ms`, **`0.576 ms` over `282.3` crossings = `2,042 ns` each** — IS the FUSE round trip. Throughput `14.0` vs `16.5 GB/s`, both page-cache speed, so this is not I/O-bound and our daemon is not the bottleneck. ⇒ **NO LEVER APPLIES, each exclusion measured:** fewer crossings is impossible (already one per file); the receive spin LOSES on 8-thread rows by the scope rule (`1.207084x`, `1.231481x`); xattr suppression is inapplicable because reads use OPEN FDS and draw no AUDIT probe (confirmed by the `~1.1` requests/file count, not `~2.1`); loop transport is measured `3.83%` worse. Only the per-crossing transport cost itself would move it. ⛔ DO NOT quote the old win. Superseded: 26 attempts on candidate `3c7ff854…` (PGO `c1b9eb9f…`, x86-64-v3) produced 17 ratios: `1.015434` … `1.544532`, **median `1.0842`, minimum `1.0154` — 17 of 17 ABOVE `1.0`**, not one reaching the banked band. ⛔ Every reading is `BLOCKED_NULL` (kernel A/A spreads to `1.242174`, fuse to `1.081662`, the same data-heavy instability the mutating rows show), so this **cannot and does not withdraw** the admitted claim below — but a banked win that cannot produce a single reading on its own side of `1.0` across 17 attempts on the current binary **must not be quoted as a live result until re-certified**. ⚠ Note the banked entry's own oddity, still unexplained: its CONTENDED runs (`3.887`/`3.943 ms`) were FASTER than its quiet ones (`4.742`/`4.143 ms`), which is backwards and makes a window artefact the first hypothesis to test. Older, admitted, now CHALLENGED: **≈`0.89–0.93x` FASTER — CONFIRMED in a verified-quiet window.** Two admitted runs, `0.893282x [0.891253, 0.896649]` and `0.927352x [0.923351, 0.930643]`, both `HONEST_WIN`, both `directional_claim_clear=true`, spread `3.81%`. **Quote the spread, not either CI.** Run 1 lands `0.11%` from the banked `0.894290x` on a *different* fixture construction. ⚠ Two EARLIER runs the same day under a peer's CPU load returned `1.019622x` NEUTRAL / `0.961107x` WIN — **inadmissible, see below** | quiet run 1 `1.002400x`, run 2 `1.003917x` | quiet run 1 `1.001901x`, run 2 `0.999706x` | 8 → **8** | **WIN** |
| **Fsync/journal commit**, 8 × 4 KiB | **`1.976308x` `[1.969150, 1.977948]` slower** (margin `1.021437x`) | `0.999326x` | `1.000634x` | 1 → **1** | **LOSE** |

Every admitted row: pinning attested with the observed CPU set equal to the bound set,
exact four-arm parity, clean post-unmount `btrfs check --readonly`, incumbent isolation
`pass`, wall-time bootstrap median CI as the gate (`cv_used=false`,
`instructions_used=false`), effect clearing twice the widest null log-margin.

## Absolute arm medians — REQUIRED per row, never a gate (`bd-4sull` item 3)

**Not a gate and not a claim** (`gate_input=false`), but **required to be recorded**. A row
that banks only its ratio cannot be diagnosed later: a ratio is a quotient and cannot say
which arm moved. The ext4 bank has already paid for this — the incumbent arm of one shape
drifted `+18.3%` across three gate-clear windows while our arm held to `1.4%`, which was
only decomposable because both absolutes were on record. The harness emits both on the
`mounted_kernel_throughput` line (`kernel_median_wall_ns`, `fuse_median_wall_ns`); the gap
was transcription, never measurement.

| Workload | Kernel median batch | FrankenFS median batch |
| --- | --- | --- |
| Large-directory readdir+stat, 32,768 entries | **27.772 / 27.796 ms** (runs 1/2, 2026-08-08; was 26.157 ms) | **214.816 / 212.881 ms** (runs 1/2; was 217.782 ms) |
| Fsync/journal commit, 8 × 4 KiB | 101.5 ms | 200.5 ms |
| Warm stat, 2,000 calls | **4.569 / 4.556 ms** (runs 1/2, 2026-08-08); banked run ⛔ **not recorded** | **21.916 / 21.910 ms** (runs 1/2); banked run ⛔ **not recorded** |
| Small-file create/delete storm, 2,000 files | ⛔ **not recorded** | ⛔ **not recorded** |
| Parallel metadata writes, 512 creates | ⛔ **not recorded** | ⛔ **not recorded** |
| Multi-file parallel read, 256 × 256 KiB | **4.742 / 4.143 ms** (quiet runs 1/2); contended runs 3.887/3.943 ⛔ inadmissible; banked run ⛔ **not recorded** | **4.311 / 3.820 ms** (quiet runs 1/2); contended runs 3.917/3.787 ⛔ inadmissible; banked run ⛔ **not recorded** |

**3 of 6 rows have no absolutes at all**, and one more — parallel read — has current
figures but **not** for its banked run. Those reports were deleted with the comparator
scratch (`bd-v0igv`) before this requirement existed.

⭐ **The predicted cost came due on 2026-08-08, exactly where this table said it would.**
This paragraph used to warn that the missing absolutes would hurt most on parallel read,
because "did we get faster, or did the incumbent get slower in that window?" is the question
a reader would ask and the row could not answer. That is now not hypothetical: the row's
re-measurement returned opposite verdicts, and the banked wins cannot be decomposed to say
whether they were ever *our* speed or the incumbent's slowness. The absolutes for the new
runs are recorded above precisely so this cannot recur for them.

## One sentence per row

- **readdir+stat: we lose badly.** The kernel enumerates and stats 32,768 entries in
  27.772 ms where we take 214.816 ms — our worst measured surface on any filesystem.
  Re-measured 2026-08-08 on the corrected fixture (`bd-plkzd`); the superseded row read
  26.157 ms / 217.782 ms for `8.322812x`. Note which arm moved: ours improved `1.4%` while
  the incumbent slowed `6.2%`, so most of the `8.32x → 7.75x` change is the kernel's, not
  ours, and none of it is attributable to the fixture alone (`bd-pb85e`).
  **⚡ 2026-08-16 — THIS ROW MOVES (AzureBay).** Sizing the capability memo to the
  directory takes it from **`6.990007x`** `[6.988474, 7.026868]` to **`3.359246x`**
  `[3.314229, 3.399607]`, **both `admitted=true` with both A/A nulls clear**, one ELF
  (`d4278471…`), one fixture, one session, differing only in
  `FFS_FUSE_CAPABILITY_MEMO_SLOTS` (4096 → 65536). Our own arm goes
  `217,470,654 ns` → `103,799,776 ns`; the FrankenFS absolutes replicate to `0.03%` and
  `0.84%`, giving `2.078x`–`2.095x`, which independently reproduces the within-window
  candidate crossover's `2.078x` (`bd-m1bpu`). Three estimators, three decimals.
  ⛔ **NOT a shipping recommendation and NOT a new default.** The cliff MOVES rather than
  disappears: at 100,000 entries the same 65,536-slot table is itself oversubscribed and
  the win falls to `1.30x`. 65,536 slots is 512 KiB per mount against 32 KiB today, so a
  larger default still owes bd-5vis3's bar — peak resident memory, plus a non-fitting
  workload measured beside a fitting one. What is established is that the lever is real
  and large at a realistic directory size (`bd-34hzz`).
  **Where the cost sits, attributed 2026-08-16 (AzureBay).** At 8 threads the steady-state
  boundary traffic is **exactly one `security.capability` GETXATTR per entry** — no
  GETATTR, no LOOKUP, no STATX — the same mechanism as the warm-stat row. Splitting our
  own arm by the daemon's internal dispatch counters (K=1 vs K=5 sweeps, differenced):
  at 4096 slots the daemon is `3148.3` ns/entry = **47.21%** of the `6669.2` ns/entry FUSE
  arm; at 65,536 it is **0% ± 2.5%** of the `3231.8` ns/entry arm. The counts settle it
  before any timing: `getxattr_dispatch_count` goes `32,770 → 163,842` over four extra
  sweeps at 4096 (every sweep re-descends every entry) and `32,770 → 32,770` at 65,536
  (nothing descends again).
  So **at the shipping default this row is about half our filesystem work and half
  transport; sized to the directory it is essentially all transport** — the same wall
  warm stat is against. Removing the measured daemon work predicts `1.894x` against the
  measured `2.064x`. ⚠ **CORRECTED 2026-08-16**: those daemon-share figures came from an
  UNPINNED daemon divided by the PINNED comparator arm — a mixed instrument, caught by the
  `--placement-audit` ratchet built for `bd-plt79`. Re-measured with the daemon pinned
  (observed affinity, not requested): **`41.62%` at 4096 slots, not `47.21%`**, and
  `0% ± 1.7%` at 65,536 on a floor 1.50x tighter. The dispatch COUNTS are byte-identical
  pinned and unpinned, which is what shows counts survive a placement change and nanos do
  not. Consequently the descent explains **`74%`** of the lever, not `88%`, and the
  unexplained residual **grows** to `~26%`. ⛔ Four hypotheses for that residual have now
  been eliminated or retracted; do not argue a lever from it.
- **Warm stat: we lose.** About `4.8` times slower, re-measured 2026-08-08 as an admitted
  pair on a current ELF (`4.769886x` / `4.802719x`, spread `0.69%`); the banked
  `4.977803x` / `5.036433x` is superseded. The ext4 twin, measured in the SAME invocations,
  lands at `4.812789x` / `4.864714x` — **within `1.3%`** of these. Two filesystems with
  entirely different metadata layouts agreeing that closely is the strongest evidence yet
  that this row measures the shared per-request FUSE floor rather than anything about btrfs
  inode lookup. The absolutes say the same thing: our arm is `21.91` ms on btrfs and
  `21.89` ms on ext4, a `0.1%` difference, while the two kernel arms differ by `1.2%`.
  **Confirmed again 2026-08-16 across TWO DIFFERENT ELFs** (AzureBay): `4.798508x`
  `[4.759896, 4.802894]` on `e6cd5793…` and `4.751179x` `[4.728531, 4.772781]` on
  `d4278471…`, both `admitted=true` with both A/A nulls clear, medians `1.0%` apart.
  The 2026-08-08 pair above was same-ELF; this one is not, so the figure now survives a
  change of binary AND of PGO profile. Worst bound across all four admitted runs remains
  **`4.80x`** — quote that. It also bounds everything that landed between the two
  binaries (capability-memo kill switch, memo slot-count knob) at under the `1.0%`
  spread, which is independently consistent with the memo measuring worth under `10.7%`
  on this workload (`bd-m1bpu`).
  ⚠ The per-op attribution this row invites — round trips per stat, daemon share versus
  kernel round trip — **cannot be produced by this instrument today**. Every report
  carries `fuse_dispatch_metrics: "unreported_by_this_elf"`, and that label is wrong:
  the ELF has the emitter and the harness sets `FFS_MOUNT_BENCH_EVIDENCE=1`. The
  standard mount runtime, which is the path the comparator uses, hand-constructs an
  all-zero `MetricsSnapshot` instead of returning the accumulated one (`bd-viil0`).
  **✅ ATTRIBUTED ANYWAY 2026-08-16** (AzureBay) — `--runtime-mode managed` emits the same
  counters and is a plain CLI flag, so the attribution was taken directly. 2,000 warm
  stats of one already-resolved path produce **exactly 2,000 FUSE round trips, every one
  a `security.capability` GETXATTR**. No GETATTR, no LOOKUP, no STATX: the 60 s
  `ATTR_TTL` works and the kernel serves attributes from its own cache. Of 2,000 probes
  exactly **2** reach the format layer (the memo answers 1,998), so daemon dispatch is
  `0.27%–0.35%` of wall and **`0.75%–0.99%` of the gap vs kernel**.
  The probe is **one per path-based syscall**, independent of path depth (mount root pays
  the same as a nested file), independent of the filesystem (**ext4 `1.0000` == btrfs
  `1.0000`**, which is what now supports the shared-floor claim above — a count, not the
  `1.3%` wall agreement), independent of whether the xattr exists, and **zero for `fstat`
  on an open fd**. So this row is a property of the kernel's FUSE path-resolution
  behaviour, not of anything FrankenFS does: no filesystem-side, daemon-side or
  path-shape lever can move it, and halving round-trip cost halves it and no more
  (`bd-z0rb8`). Practically: **a workload holding fds pays none of this; one that stats
  by path pays all of it.**
- **Create/delete storm: we lose.** About 2.36 times slower on a 2,000-file namespace
  transaction.
- **Parallel metadata writes: we lose.** About 1.93 times slower with eight workers
  creating 512 files and fsyncing their directories.
- **Parallel read: we are faster** — 10.6% and 16.9% faster across two runs — but I am
  not banking this as a campaign win yet, for the reason below.
- **Fsync/journal commit: we lose.** About 1.98 times slower — 101.5 ms per batch for the
  kernel against 200.5 ms for us. This workload could not execute at all until
  2026-08-04; it is the newest row and the only one taken with every CPU on the
  `performance` governor.

## The win is CONFIRMED — and the near-miss is the more useful lesson

⭐ **Resolved 2026-08-08 (`bd-ws9dg`). The win stands, at ≈`0.89–0.93x`.** Two admitted runs
in a window whose external load was sampled *continuously*, not just at the gate:

| Window | Run | Ratio | 95% CI | Verdict |
| --- | --- | --- | --- | --- |
| **quiet** | 1 | `0.893282x` | [0.891253, 0.896649] | **`HONEST_WIN`** |
| **quiet** | 2 | `0.927352x` | [0.923351, 0.930643] | **`HONEST_WIN`** |
| contended | 1 | `1.019622x` | [1.007602, 1.062585] | `HONEST_NEUTRAL` ⛔ inadmissible |
| contended | 2 | `0.961107x` | [0.958445, 0.971937] | `HONEST_WIN` ⛔ inadmissible |

In the quiet window the verdict is **stable 2/2** and the spread is `3.81%`. Under a peer's
CPU load, two runs of the *same ELF and same fixture* straddled the margin and returned
**opposite verdicts** with non-overlapping intervals, spread `6.09%`.

**And quiet run 1 lands `0.11%` from the banked `0.894290x`** — measured on a *different*
fixture construction, months apart. That agreement is why the win is restored rather than
merely un-withdrawn.

### The near-miss: this file said the win was gone, and it was wrong

Earlier on 2026-08-08 this section read "the win did not survive re-measurement" and scored
the row UNRESOLVED, on the strength of the two contended runs. That was premature. The
contended pair was **inadmissible evidence** and should not have been banked at all — the
lesson is not that the win was fragile, but that the *instrument* was, in a way its own gate
could not see.

**Why the gate cleared anyway, which is the transferable part.** The peer's `pytest` (254%
CPU) never touched the placement CPUs: max busy `0.020`, mean `0.006` across 0-7/32-39. The
preflight legitimately reported `verdict=clear`, because by its own definition the window
*was* clear. The load sat elsewhere on the same socket (CPUs 16, 19, 48, 51, 54 above 20%),
and memory bandwidth, LLC capacity and boost budget are socket-wide. **A start-of-run,
placement-CPU-only gate cannot certify a measurement window.** `bd-4sull` argued this from
drift; this row demonstrates it flipping a verdict.

**The ratio is robust where the absolutes are not** — the crossover design earning its keep.
Between the two quiet runs the kernel arm moved `−12.6%` (4.742 → 4.143 ms) while the ratio
moved only `+3.81%`. Common-mode effects cancel in the quotient; what the contention did was
hit the two arms *asymmetrically*, which no amount of averaging removes. Curiously both
absolute arms are **slower** in the quiet window than under load, consistent with deeper
C-state residency on an idle box — untested, and irrelevant to the ratio.

**Two caveats that remain live.**

1. ~~Co-tenant load~~ — **RESOLVED**: this was the cause. Verified by re-running with
   external CPU sampled every 3 s throughout (median `113.5%` of a `6400%` box, i.e. ~1.8%
   utilisation, no excursions).
2. **The banked runs' absolute arm medians were never recorded**, so the old wins cannot be
   decomposed into "we were fast" versus "the incumbent was slow." This is the exact cost
   this file warned about when it marked this row's absolutes ⛔ not recorded — and it landed
   on the one row where it hurts most.
3. ✅ **The btrfs extent layout HAS now been probed** (`scripts/cmp_btrfs_layout_probe.sh`)
   and the answer splits in two. Fragmentation is identical — exactly one extent per file
   under both constructions — but the **physical ordering is not**. Seeded-through-the-mount
   lays the files out in perfect ascending name order; the `-r` seed scrambles them:

   | file | `-r` seed | through mount |
   | --- | --- | --- |
   | read-000000 | 3584 | 3328 |
   | read-000001 | 3328 | 3392 |
   | read-000002 | 3456 | 3456 |
   | read-000003 | 3712 | 3520 |

   The workload sorts by name before reading, so the seeded fixture walks the disk forwards
   while the baked one jumps around — materially different jobs once readahead is involved.
   Mechanism, verified not guessed: the `-r` seeder copies in **host readdir order**, and the
   host directory is ext4 with an htree, so it inherits that filesystem's **hash order** as
   its physical layout. (`mke2fs -d` does not do this — ext4 comes out in name order under
   both constructions, which is why the ext4 probe did not predict this.)

   **So layout is ELIMINATED as an explanation for the run-1-vs-run-2 disagreement** — both
   used the seeded construction and byte-identical images. But it is **CONFIRMED as a
   disqualifying confound between the banked wins and the new numbers**: the banked
   `0.894290x` / `0.830537x` were measured against a scrambled fixture and the new figures
   against a sequential one. Those are not the same benchmark, and the move from "win" to
   "unresolved" cannot be read as a change in FrankenFS.

   The seeded construction is the correct one — a real btrfs filesystem populated by writing
   files has them in write order, not in another filesystem's hash order — so this row needs
   re-baselining from scratch rather than comparison with its predecessor.

**What would settle it:** the same pair in a genuinely quiet window with no co-tenant load,
and if the spread survives that, higher pair counts or an admission that this row is not
decidable by this instrument. Until then this row scores nothing.

The specific worry is that per-block data checksumming is btrfs's headline feature.

**Correction, 2026-08-04.** This section previously said FrankenFS has *no* read-side
checksum verification and that no verify path exists. That was wrong: `bd-tkv2n` landed
one on 2026-06-04 (`57d37c73`, with a perf pass in `e0aa5a1b`).
`crates/ffs-core/src/lib.rs:10836` verifies every regular extent overlapping the read
range against the csum tree for a datasum inode and returns `Corruption` → `EIO` before
returning any bytes, exactly as the kernel does, and it carries its own corruption-planting
negative test. The original audit grepped `ffs-btrfs`, where every `crc32c`/csum path is
indeed write-side only; the verify lives in `ffs-core`.

**The conclusion survives the correction, for a different reason.** The flag
(`OpenOptions.btrfs_verify_data_on_read`) defaulted to `false` and was reachable from
nowhere outside `ffs-core` — not the CLI, not the FUSE layer, not the harness. So no
*mounted* configuration could verify, and this row's FUSE arms did not. A capability no
mount can reach is, for benchmarking purposes, the same as not having one. The mount
option now exists (`--btrfs-verify-data-on-read`,
`bd-btrfs-no-read-side-csum-verify-xu3m6`), so what this row measured is unchanged and the
comparison is still not like-for-like.

> ⛔ **SUPERSEDED 2026-08-15 (`bd-6kpp4`): the default is no longer off.** This paragraph
> previously ended "and is still off by default". Two commits the same day flipped it:
> `1c85fc23` (00:15) set `OpenOptions::default().btrfs_verify_data_on_read` to **true** —
> the product default — and `e54146ee` (00:28) followed in the harness `Config`.
>
> Consequence for this file, scoped precisely rather than blanket-applied: the flag gates
> verification of **file data** against the csum tree for `datasum` inodes, so it can only
> affect a row that actually reads file data. Of the six rows above that is **exactly one —
> multi-file parallel read, the only `honest_win`.** Warm stat, readdir+stat and
> create/delete storm are metadata-only; parallel metadata writes, fsync/journal commit and
> bulk durable write are write-side. Those five are unaffected and need no re-scoping.
>
> The parallel-read row is re-scoped, not retracted: it remains a valid measurement of the
> arms that ran, and it is the baseline the verify=ON cost has to be measured against. But
> a NEW run of it is not configuration-comparable unless it passes
> `--btrfs-verify-data-on-read false` explicitly, because the harness now defaults to
> **true**.
>
> This was decided ahead of `bd-btrfs-verify-default-decision-v81jt`, the bead whose stated
> purpose is to choose this default and which is still OPEN and blocked on the cold-cache
> cost delta. That cost is still unmeasured.

**But that does not settle it against us either.** This is a *warm-cache* workload, and
kernel btrfs does not re-verify checksums on page-cache hits — it verifies on the disk
read that populates the cache. So the incumbent may not be paying that cost in this
regime at all.

The question is genuinely open in both directions, and a **cold-cache read variant would
decide it**. That is a different workload and a separate row, not a silent substitution
of this one. Until it runs:

> Quote this row as *"FrankenFS is faster than kernel btrfs on **warm** multi-file parallel
> reads, mechanism unresolved, and the measured FrankenFS arms did not verify data
> checksums — the capability existed but was off by default when this ran. Two cold-cache
> attempts both point the other way and both were refused for socket contention, so the
> warm result may be cache-regime-specific."* Do not quote it as a bare win, and do not
> generalise it to reads at large.

### Cold-cache attempt 1 — REFUSED, no number published (2026-08-15, `bd-btrfs-parallel-read-win-mechanism-iwzrx`)

The cold-cache arm (`parallel-read-8t-cold-cache`, added `3a5a5669`) **executed for the
first time** and is mechanically sound: four live mounts, exact four-arm parity
(`tree_sha256=c49f12e8…`, 261 entries / 68,157,468 bytes identical across arms), clean
post-unmount `btrfs check --readonly` on all four, `incumbent_isolation_proof=pass`,
threads 8→**8** observed, pinning `clear=true`. Host `thinkstation1`, kernel
`6.17.0-41-generic`, candidate ELF `10a4a264…`, PGO profile `cc6c121c…`,
`compile_avx2=true`; built and executed on the same host.

**The run is INADMISSIBLE on two independent gates and nothing from it is quotable:**

| Gate | Result |
| --- | --- |
| FUSE A/A null | median `0.985209` (inside 2%) but symmetric spread **`1.086963`** vs limit `1.025` → `clear=false` |
| Kernel A/A null | median `0.998724`, spread `1.007234` → clear |
| `external_load_during_run` | **`53/53` samples contended** (`contended_fraction=1.0000`, limit `0.10`), max 8 off-placement busy CPUs vs limit 2 |
| Verdict | **`BLOCKED_NULL`**, `admitted=false`, `directional_claim_clear=false` |

The ratio the run printed is deliberately **not** reproduced here as a result. Two reasons,
either sufficient: the FUSE arm could not reproduce itself against itself, and the socket
was contended for 100% of the measured region — the exact failure mode that made the
2026-08-08 contended pair return opposite verdicts.

**It also would not have answered the question even if admitted**, which is the more useful
finding. The harness now defaults `--btrfs-verify-data-on-read` to **true** (`e54146ee`),
so this run had checksum verification **ON** while the banked warm row it is meant to be
compared against ran with it **OFF**. That changes two variables at once — cache regime
*and* integrity contract — so it cannot attribute anything to cold cache. See `bd-6kpp4`.

### Cold-cache attempt 2 — verify=OFF, internally CLEAN, refused only by socket contention

Same ELF (`10a4a264…`), same PGO profile (`cc6c121c…`), same host, ~25 minutes later with
host load down from ~10 to ~4, this time with `--btrfs-verify-data-on-read false` so the
candidate configuration **matches the banked warm row** and only the cache regime differs.

Everything the instrument controls internally came out clean:

| Gate | Attempt 1 (verify=ON) | Attempt 2 (verify=OFF) |
| --- | --- | --- |
| kernel A/A null | `0.998724`, spread `1.007234` ✅ | `1.007592`, spread `1.023142` ✅ |
| FUSE A/A null | `0.985209`, spread **`1.086963`** ❌ | `0.998246`, spread `1.022767` ✅ |
| Four-arm parity | pass | pass (`tree_sha256=c49f12e8…`) |
| `directional_claim_clear` | false | **true** (margin `1.046819`) |
| `admitted` (null/pinning/parity) | false | **true** |
| Instrument verdict | `BLOCKED_NULL` | **`HONEST_LOSS`** |
| `external_load_during_run` | 53/53 contended ⛔ | 32/32 contended ⛔ |

**Attempt 2 is refused by exactly one thing: the post-hoc socket-contention veto.** Peak 6
off-placement busy CPUs against a limit of 2, peak off-placement mean busy 9.3%, 100% of
samples over limit against a 10% limit.

⛔ **Not bankable, recorded for direction only:** `1.392135x [1.351586, 1.394852]`
(`kernel_median_wall_ns=60738067`, `fuse_median_wall_ns=84493550`). Attempt 1, with verify
ON, printed a larger ratio on a failed null. **Neither is a result.**

**One prior refuted, which is why attempt 2 was worth running.** The section above predicted
a cold-cache A/A null might be *intrinsically* wider than `1.025`, because every timed batch
pays a host-wide `drop_caches` and re-warms from a shared disk. Attempt 2's FUSE null came
in at `1.022767` — inside the limit. **The instrument can produce a clean cold-cache null.**
The blocker is socket contention from co-tenants, not the workload design, and attempt 1's
dirty null was not intrinsic either.

**What this points at, stated as a direction and not a claim.** With the *same* candidate
configuration as the banked warm win, the cold-cache direction is a **loss**, where warm is
a `0.89–0.93x` win. If that survives a quiet window, the warm win is a **cache-regime
artifact** and the row must be restated — which is precisely the outcome
`bd-btrfs-parallel-read-win-mechanism-iwzrx` was opened to force. It has not survived a
quiet window yet, so the warm row stands as banked and this stays unresolved.

**On the veto itself, without touching it.** Every run it has refused on this workload
carries an instrument verdict of `HONEST_LOSS` or `BLOCKED_NULL` — never a win. Admitting
them could not manufacture a win, only record a loss, so the risk is asymmetric. That is an
argument for revisiting the gate's threshold *with its own evidence*, not for waiving it
here: it was added because the 2026-08-08 contended pair returned opposite verdicts, and
one contended run was published on the strength of it. The gate stays as it is; the runs
stay refused.

## The row that could not run, and what it took to score it (2026-08-04)

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

**Fix — landed in `32dd093f`, probes not yet run.** Call `sync_block_group_accounting()` at
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
call succeeds once reconciled. That test was written when this section was, then deleted
by `3b48b7b6`, which rolled `crates/ffs-btrfs/src/lib.rs` back by 6066 lines; it is
restored along with the rest of that file, and carries an added negative case —
unreconciled, the free must still fail closed with `BrokenInvariant`, so an
implementation that softened the guard instead of correcting the tally fails here. The
underflow guard is not weakened; it stops being reachable from a correctly mounted
filesystem.

A second test lands with it: `btrfs_positioned_write_over_mkfs_populated_file_conforms`
(`ffs-harness` conformance) reproduces the failing workload end to end — an image
populated by the format tool's `--rootdir` carrying a 4096-byte `fsync.bin`, then eight
4 KiB positioned writes at offset 0, each followed by `fsync`, a readback equality check,
and a size assertion.

**The predicted regression did not materialize, and the call is committed.** The concern
was that making it live regresses `btrfs_largest_contiguous_free_run_uses_allocator_gaps`
(`ffs-core`), whose fixture asserts exactly 64 free blocks against the *un*-reconciled
tally. The landed form guards the call on `extent_tree_items_loaded > 0`, and that
fixture (`build_btrfs_fsops_image`) carries no extent tree at all — there is nothing to
reconcile from, so its existing tally legitimately stands while every real image gets the
correct accounting. The guard is the more correct semantic, not a way around the
expectation.

### Scored, and it is a loss

```
fuse_over_kernel  median 1.9763082977790924  ci [1.9691498616922856, 1.9779483530792440]
                  twice_null_margin_ratio 1.0214374  directional_claim_clear true
kernel A/A 0.9993258   fuse A/A 1.0006339    (both medians within limit, both CIs contain 1.0)
admitted true   verdict honest_loss   parity pass   post_unmount_validation clean
pairs 32   crossover_blocks 8   threads requested 1 -> observed 1   pinning attested
kernel median batch 101.5 ms   FrankenFS median batch 200.5 ms
```

Provenance: candidate ELF `9e32e28f766368dd738c7d43e2d4f820a426394b0d1e72b6e565be622835408a`
(x86-64-v3, PGO profile `5c6530a0261f658ed0ace2a9d8bef7c6c63b6f94b4b955e4f7ccba038e011e96`),
driver ELF `8c1c4d35fd0a348e5e612d904f086567a4bd9f03a800127ff1ebedb6a2f2633f`, both
self-hashed in process and cross-checked against `/proc/self/exe`. Host `thinkstation1`,
`--placement-scope same-llc` like every other row.

**Two caveats this row carries that the other five do not.** Its candidate is a
*freshly trained* PGO profile, not the bank's frozen `6a22cfcf…`, so it is **not
byte-identical-candidate comparable** with the five ext4 rows — direction and rough
magnitude transfer, an exact cross-scorecard delta does not. And it is the only row taken
with every CPU on the `performance` governor
(`non_performance_or_mixed_governor_warning=false`), where the others carry that warning.
Both differences favour honesty about the comparison rather than the number itself: the
row is a loss either way.

**The workload now runs on a real four-arm mounted comparator** — this is the
confirmation the unit and conformance probes could not give, since those exercise
`OpenFs` in-process rather than a live FUSE mount:

```
mounted_kernel_incumbent_isolation,...,same_invocation=true,independent_physical_arms=true,verdict=pass
mounted_kernel_parity,...,arms=4,verdict=pass          (byte-identical trees, all four arms)
mounted_kernel_post_parity,...,arms=4,verdict=pass     (still identical after the writes)
worker threads 1 -> 1 observed on every arm, pinning attested
```

No `EIO` anywhere. **The run was still refused**, at the post-unmount integrity gate:

```
csum exists for 13631488-14684160 but there is no extent record
ERROR: errors found in csum tree
mounted_kernel_gate,error=btrfs check --readonly failed: exit status: 1
```

A FrankenFS btrfs mount that performs overwrites leaves orphaned csum items, so the image
it unmounts is not `btrfs check` clean — filed as `bd-btrfs-orphaned-csum-items-bmksa`
(P1), now blocking this row. That is not a `bd-ftev0` regression: before the fix the first
write returned `EIO`, so nothing was written and nothing could be orphaned; the fix made
the path reachable and this came with it.

The run did produce a ratio its statistical gates admitted — `1.959886x`
`[1.959096, 1.974165]`, `HONEST_LOSS` — and it is deliberately **not banked here**. A run
that fails its integrity gate does not yield a publishable number however clean its
statistics look, and this one is thin besides: `pairs=12` against the bank's 32,
`observation-repeats=1`, and a freshly trained PGO profile rather than the frozen
candidate, so it is not candidate-comparable with the five ext4 rows. It is recorded on
the bead as evidence of direction, not as a row.

**Both correctness probes pass** (they were blocked for several hours by
`bd-bulk-revert-incident-24k-lines-w5hkf`, which left the workspace uncompilable):

```
test btrfs_positioned_write_over_mkfs_populated_file_conforms ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 102 filtered out; finished in 0.12s

test tests::reconciled_block_group_accounting_makes_a_preexisting_extent_freeable_bd_ftev0 ... ok
test result: ok. 1 passed; 0 failed; 375 filtered out
```

`bd-ftev0` is closed on that evidence.

### SCORED 2026-08-17, and the sign changed: `~0.45–0.46x`, about 2.2x FASTER

The run `bd-score-btrfs-fsync-row-d98vj` asked for now exists — four-arm mounted comparator,
kernel incumbent live in the same invocation, both A/A nulls, observed thread count, and a
self-reported candidate ELF. **Five runs on candidate `c9fb745f…`** (x86-64-v3, PGO
`6a22cfcf…`, the same banked profile as every earlier candidate, so it is comparable):

| run | pairs | `peak_placement_mean_busy` | ratio | verdict |
| --- | --- | --- | --- | --- |
| E | 192 | 0.462 | `0.456284` [0.448364, 0.462696] | BLOCKED (fuse null spread 1.0307) |
| A | 96 | 0.747 | `0.461109` [0.452020, 0.470524] | **ADMITTED, HONEST_WIN** |
| D | 192 | 0.937 | `0.449048` [0.444672, 0.451959] | **ADMITTED, HONEST_WIN** |
| B | 96 | — | `0.463280` | BLOCKED (fuse null spread) |
| C | 96 | — | `0.533114` | BLOCKED (kernel null spread) — **outlier** |

Four runs cluster inside 3.1%. Run C sits 15% away and is unexplained: recorded, not
averaged in, not quoted. Run D's nulls were `0.995218` (spread 1.017305) and `0.991905`
(spread 1.015658), both clear, with the ratio CI at ±0.8%.

**This row needs 192 pairs, not 96** (`bd-ynqwx`). Six of seven attempts were `BLOCKED_NULL`
on null CI SPREAD and never on median — every null median across all of them was within 1.4%
of one. Spread narrows as `sqrt(pairs)`, and 96 → 192 took it from 1.022–1.033 to
1.0157/1.0173, inside the 1.025 limit with margin.

**No load dependence.** Ordered by `peak_placement_mean_busy` the ratio is flat — `0.456` at
0.462 busy, `0.461` at 0.747, `0.449` at 0.937. An earlier claim that it moved with load was
withdrawn: it rested on run C and on `loadavg`, a host-wide lagging covariate that ranked run
D — which peaked at 93.7% busy on the placement CPUs — as the *quiet* run because it
*launched* quiet. Use the run's own `peak_placement_mean_busy`; a pre-run `uptime` describes
only the starting line.

⚠️ **TWO QUALIFICATIONS TRAVEL WITH THIS ROW.**

1. **Transport asymmetry (`bd-w2u82`).** The kernel arm mounts `loop,rw,noatime,…` because
   kernel btrfs cannot mount a plain file; the FrankenFS arm `pwrite`s the image directly. The
   incumbent pays a block-layer and loop-worker hop per I/O that we do not, which is a credible
   share of the ratio. So this is a **file-backed-image** result, not a filesystem-vs-filesystem
   one. Counted evidence says the *counts* are transport-invariant (3.0000 barriers and 102400
   bytes per client fsync either way), so the question is the cost per request, and only a
   timed transport-symmetric run settles it.
2. **Durability equivalence unproven (`bd-5hqj2`).** We issue **more** barriers (3.0000 vs
   2.0000) and write **more** bytes (1.389x) per client fsync, yet are faster. The barrier
   count was taken from outside the process with `strace` and is higher, so we are not skipping
   flushes — but that is not the same claim as equal durability. **Do not quote this row as a
   durability claim until that closes.**

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
- ⛔ **Reports NO LONGER retained.** This bullet used to point at
  `/data/tmp/frankenfs-mounted-btrfs/run_*/mounted-kernel-report.json`. That tree is **gone**
  (verified 2026-08-08: the path does not exist, and a `/data/tmp`-wide search finds exactly
  one surviving `mounted-kernel-report.json` in the repo, belonging to an unrelated
  `bd-2i2ez` ext4 window). Run images were deleted after each run as stated, but the reports
  went with them. This is why four of the six rows above cannot have their absolute arm
  medians recovered, and it is the concrete damage behind `bd-v0igv` — the scratch cleanup
  must preserve reports, and until it demonstrably does, anything a scorecard needs has to be
  transcribed into the scorecard itself rather than referenced by path.

## Comparison with ext4, same candidate, same instrument

| Workload | vs kernel ext4 | vs kernel btrfs |
| --- | --- | --- |
| readdir+stat **(btrfs re-measured 2026-08-25 on the shipping range-leaf memo)** | ≈`4.1x` slower (`4.052605x` / `4.163402x`) — ⚠ still on the OLD memo, re-measure | **`3.832345x` slower** — ADMITTED 2026-08-25 on candidate `9b1517b8…`, superseding `7.753405x` (which was the direct-mapped 4096-slot memo, not the shipping default since `9f4e2811f`) — attributed 2026-08-16 to 1.0000 capability probes/entry; **`3.359246x` admitted with the memo sized to the directory** (`bd-34hzz`) |
| create/delete storm | `2.753659x` slower | `2.358280x` slower (frozen `f44b3dc4…`) — **re-measured 2026-08-17: `1.901025x` slower, gap narrowed 19%, both nulls clear but the run was VETOED for socket contention. Still a LOSS. `bd-3tqec`** |
| parallel read **(both re-measured 2026-08-08)** | ≈`0.98x` NEUTRAL (`0.986316x` / `0.978203x`) | **≈`0.89–0.93x` FASTER** (`0.893282x` / `0.927352x`, quiet window, 2/2 WIN) |
| parallel metadata writes | `1.510822x` slower | **`0.798200x` FASTER — ADMITTED 2026-08-17, `HONEST_WIN`, 288 pairs, both A/A nulls clear (`0.993329`/`0.998869`), CI [0.791613, 0.814795]. A SIGN CHANGE from the frozen `1.930090x` slower. Three readings agree within 2.9%; this is the least favourable and the admitted one. Needed 288 pairs because our arms carry ~1.55x the kernel's per-observation CV (`bd-r9fix`). Run window was CONTENDED — replicate in a quiet socket. `bd-3tqec`** |
| fsync/journal commit | `0.997098x` neutral | **`~0.45–0.46x` FASTER (re-measured 2026-08-17)** — admitted twice, `0.449048x` at 192 pairs and `0.461109x` at 96, four runs inside 3.1%. Supersedes the `1.976308x` slower figure, which predates the write-path work. **Qualified**: the kernel arm is loop-mounted and we are not (`bd-w2u82`), and durability equivalence is unproven (`bd-5hqj2`) |
| warm stat | `4.812194x` slower | `4.977803x` / `5.036433x` slower |

The parallel-read row remains the only sign change anywhere in either scorecard, and it
survived re-measurement: btrfs is a confirmed win, while the ext4 side moved from a loss to a
tie. Both sides were re-measured 2026-08-08 on the corrected fixture and a current ELF.

⚠️ **Do not confuse the retired `8.322812x` readdir+stat figure with the retired "8.3x"
folklore.** That folklore was ext4 parallel-metadata-writes derived from separate,
unmatched runs and is withdrawn. The `8.322812x` was btrfs readdir+stat from a matched
same-invocation four-arm crossover with both nulls gated — legitimate on its own terms, and
now itself superseded by `7.753405x` on the corrected fixture — and that in turn by **`3.832345x`** (2026-08-25) once the shipping capability memo became the range-leaf bitmap. The numeric collision was
coincidental.

### The btrfs-specific readdir+stat excess GREW when the fixture was fixed (`bd-3zx2x`)

`bd-3zx2x` exists to attribute the btrfs excess over its ext4 twin. On the corrected
fixtures, measured on ONE candidate ELF (`913c36a4…`) in one session, that quantity is
**larger**, not smaller:

| | btrfs | ext4 | ratio-of-ratios |
| --- | --- | --- | --- |
| Banked (unindexed ext4 fixture, ELF `f44b3dc4…`) | `8.322812x` | `4.967448x` | **`1.675x`** |
| Corrected (ELF `913c36a4…`, 2026-08-08) | `7.753405x` / `7.649395x` | `4.052605x` / `4.163402x` | **`1.875x`** (bounds `1.837`–`1.913`) |

**This confirms `bd-plkzd`'s stated direction.** It predicted the unindexed ext4 fixture
inflated the ext4 ratio and therefore *understated* the btrfs/ext4 ratio-of-ratios, and warned
that the defect must not be offered as the explanation for `bd-3zx2x`. Both hold: the excess
`bd-3zx2x` is chasing is **real and about 12% larger** than the banked figure suggested, so
fixing the fixture removes an excuse rather than the phenomenon.

Both sides of each row are same-ELF, so the ratio-of-ratios is an internally consistent
comparison in both the old and new rows. It is *not* immune to window drift: all four runs
were separate invocations minutes apart, the ext4 pair spread `2.73%` and the btrfs pair
`1.36%`, which is where the `1.837`–`1.913` bounds come from. The excess clears that band
comfortably; `1.675x` does not fall inside it.
