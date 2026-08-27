# Mounted-kernel scorecard: FrankenFS FUSE against the incumbent, Linux kernel ext4

> ## ⛔ FOUR ROWS DESCRIBE FRANKENFS AT `HEAD`. THE OTHER FOUR DO NOT.
>
> **readdir+stat, parallel read and warm stat were re-measured 2026-08-08** on candidate
> `913c36a4…` (PGO `b30de364…`, x86-64-v3 attested) — each twice, all admitted, the last of
> them under the during-run external-load gate (`bd-bt2dy`). **Every other row here was
> measured on an ELF that predates the current tree** and none has been re-measured. The
> provenance, row by row:
>
> | Rows | Candidate ELF | Measured |
> | --- | --- | --- |
> | **readdir+stat**, **parallel read**, **warm stat** | **`913c36a4…`** | **2026-08-08 (current)** |
| **create/delete storm** | **`edbaeb4e…`** | **2026-08-08 (current, post-`bd-pbyu0` fix)** |
> | fsync/journal, parallel metadata | `f44b3dc4…` | 2026-07-30/31 |
> > | Xattr get/list report, bulk durable write | `bcf2bc80…` | 2026-08-05 |
>
> ⛔ **ALL FOUR WRITE ROWS ALSO PREDATE THE 2026-08-17 EXT4 WRITE-PATH WORK** — create/delete
> storm, bulk durable write, parallel metadata writes and fsync/journal commit. `bd-fv9tc`
> landed that day and is measured, in exact integers with both arms in one invocation, to take
> ext4 from **5.00 to 3.00 blocks written per client fsync** against kernel ext4's 4.00 — i.e.
> write amplification `1.250x` -> `0.750x`, so FrankenFS now writes FEWER bytes than kernel
> ext4 per durability boundary. It coalesced the group-descriptor flush by descriptor block
> (it had been issuing one device write per GROUP, with 64 groups sharing a block) and stopped
> writing the superblock on a boundary that changed no free count.
>
> The same class of work moved the btrfs side hard: two btrfs rows changed SIGN on 2026-08-17
> (fsync/journal commit and parallel metadata writes — see the
> [btrfs scorecard](MOUNTED_BTRFS_SCORECARD.md)). The ext4 lever is much smaller (1.67x fewer
> metadata blocks per boundary, against btrfs's ~16x), so expect smaller movement and no sign
> change on the large losses — but **none of these four figures should be quoted as "FrankenFS
> today" until re-measured**. Tracked as `bd-jgq8e`.
>
> ⚠ The re-measured readdir+stat row is **not** comparable with the other seven as if one
> window produced them: it uses a freshly trained PGO profile (`b30de364…`, not the bank's
> `5c6530a0…` — the banked profile was destroyed, see `bd-v0igv`), a different kernel, and a
> corrected fixture. It supersedes its own predecessor; it does not re-baseline the others.
>
> Since the newest of the **stale** rows, **three btrfs correctness commits have landed** —
> `839eb708` (durable commit could not serialize its own leaves: `fsync` EINVAL and a failed
> unmount flush, so data was never persisted), `241093de` and `9d64f4a1` (a write that failed
> with ENOSPC destroyed the data it could not replace), and `7fac4779` (extent splits
> reference the shared extent instead of copying it, which removes a read and an allocation
> from every overwrite-split). The last of those changes the write path's I/O profile, so it
> can move those numbers in either direction.
>
> **Therefore: no figure below EXCEPT readdir+stat, parallel read, warm stat and create/delete
> storm may be presented as "FrankenFS today" until it is re-measured on a current ELF.** Quote
> the rest as historical, with their ELF, or not at all. This is not a hedge about precision —
> it is that the binary those four describe no longer exists in the tree.
>
> ⚠ **Every MUTATING row banked before 2026-08-08 was measured with the `bd-bhh0i` sharded
> create path active, which leaked one inode per delete from the group-descriptor counters
> (`bd-pbyu0`, now defaulted off).** Storm has been re-measured on the fixed candidate;
> **fsync/journal, parallel metadata and bulk durable write have not**, and were taken on a
> filesystem whose inode accounting was drifting mid-run. The read-only rows never mount
> `--rw` and are unaffected.

> ## ⚠ A CLEAR PREFLIGHT IS NOT EVIDENCE OF COMPARABILITY (`bd-4sull`)
>
> `core_contention_preflight … verdict=clear` certifies that **no competing load sat on the
> placement CPUs at the moment sampling started**. It does not certify that a run is
> comparable to a *previously banked* one, and it must never be cited as if it did.
>
> Measured, not argued: two 2,048-pair runs of the **identical** candidate ELF, PGO, kernel
> and governor both printed `verdict=clear` with five consecutive clear samples and
> `driver_busy_fraction=0.000000` — and the incumbent arm still moved **8.26%** between them
> (77.31 ms → 83.69 ms), carrying the published ratio from `2.898298x` to `2.655365x`, a
> 9.15% swing with non-overlapping intervals and roughly 3x the row's own admission margin.
> FrankenFS's own arm moved −1.30%. The entire difference was the incumbent.
>
> The gate cannot see this by construction: it samples CPU busy fractions on the placement
> CPUs immediately before the run, so it is blind to page-cache state, writeback backlog,
> thermal and boost history, and everything else that carries across invocation boundaries.
>
> ⭐ **2026-08-08: this was demonstrated flipping a verdict, not merely shifting a ratio.**
> Two btrfs parallel-read runs, same ELF and same fixture, minutes apart, both
> `verdict=clear`, returned `1.019622x` NEUTRAL and `0.961107x` WIN — non-overlapping
> intervals, `6.09%` spread. A peer's `pytest` was running on CPUs *outside* the placement
> set; the placement CPUs were genuinely idle (max busy `0.020`), so the gate was **correct**
> and still useless, because bandwidth, LLC and boost budget are socket-wide. Re-run in a
> window whose external load was sampled every 3 s throughout, the row is a stable win 2/2
> (`0.893282x`, `0.927352x`, spread `3.81%`).
>
> ✅ **FIXED (`bd-bt2dy`, 2026-08-08).** The harness now samples external load for the whole
> measured region and **fails closed**, and every report carries an `external_load_during_run`
> block whether clean or not — so a row banked from here on can be disqualified by a later
> reader without re-running it. Verified both ways on live runs: a quiet box passes
> (`samples=37, max_external_busy_cpus=2, verdict=clear`), and four off-placement CPUs pinned
> at 100% are refused (`23/23 samples over limit, verdict=CONTENDED`). In that refused run the
> **pre-run gate saw the placement CPUs at `0.011` busy and would have declared the window
> clear** — the exact failure, reproduced deliberately and caught. ⚠ Rows banked BEFORE this
> carry no such block, and its absence is itself informative.
>
> **The rule, which applies to every banked row in every repo, not just this file:**
> a row's A/A nulls and twice-null margin bound **within-invocation** error only. Cross-window
> reproducibility is a *separate, unmeasured* quantity unless a second same-ELF run exists.
> Where one does, quote the observed spread; where none does, quote the worst spread the
> campaign has measured. Eight same-ELF figures now exist: **4.71%** on one workload,
> **9.15%** on bulk durable write, **2.73%** on ext4 readdir+stat, **1.36%** on btrfs
> readdir+stat, **0.83%** on ext4 parallel read, **6.09%** on btrfs parallel read under
> co-tenant load and **3.81%** on the same row in a quiet window, **1.08%** on ext4 warm stat
> and **0.69%** on btrfs warm stat (all the 2026-08-08 ones banked *with* their spread rather
> than having it discovered later). A later measurement that disagrees with a banked row by less than that
> is **not** a regression, an improvement, or a disagreement — it is unresolved.
>
> **The readdir+stat pair is the cleanest demonstration of why this rule exists.** Two
> back-to-back admitted runs of the identical ELF, both `verdict=clear`, measured `4.052605x`
> and `4.163402x`. That **2.73%** spread is larger than run 1's own CI width (**1.84%**) and
> larger than its twice-null admission margin (**3.24%** — comparable, and the intervals
> barely overlap at all). And the split repeats the campaign's pattern: the incumbent arm
> moved **−3.40%** between the two runs while FrankenFS moved **−1.19%**. Since these ran
> back-to-back they share thermal and cache history, so 2.73% is a **lower bound** on this
> row's true cross-window spread, not a measurement of it.
>
> ⚠ **Two things this file said earlier, both now corrected by more data.**
>
> First, "the variance is the incumbent's" is **not** a law. The btrfs readdir+stat pair, run
> minutes later on the same box, spread **1.36%** with the incumbent essentially flat
> (`+0.09%`) and **our** arm carrying it (`−0.90%`) — the reverse split.
>
> Second, and this corrects a claim published in `4f4410a8`: it is **not** true that the
> cross-run spread always exceeds the within-invocation CI. Three measured pairs:
>
> | Pair | Spread | Run-1 CI width | Spread exceeds CI? |
> | --- | --- | --- | --- |
> | ext4 readdir+stat | 2.73% | 1.84% | yes |
> | btrfs readdir+stat | 1.36% | 0.40% | yes |
> | ext4 parallel read | 0.83% | 0.86% | **no** |
> | ext4 warm stat | 1.08% | 0.88% | yes |
> | btrfs warm stat | 0.69% | 1.37% | **no** |
>
> So the spread is *often* the larger quantity but not reliably, and neither number bounds the
> other. That is not a weakening of the rule — it is the reason the rule is stated as
> **quote `max(CI, measured spread)`**, which is correct in both directions and needs no
> assumption about which dominates.
>
> **The incumbent's own drift is larger than either figure.** Across three gate-clear windows
> on one kernel, the kernel ext4 arm of the bulk-durable-write shape moved 77.31 → 83.69 →
> 91.43 ms, **`+18.3%`**, while FrankenFS held 225.31 / 222.39 / 222.22 ms (`1.4%`). Since a
> ratio row is a quotient, that is the floor on how much a re-run can differ from a banked row
> for reasons that have nothing to do with our code. Recorded absolute arm medians are what
> make this decomposable — see the required-per-row table below.

**Date:** 2026-07-30 · **Host:** `thinkstation1`, AMD Ryzen Threadripper PRO 5975WX,
32C/64T, 231.7 GB RAM, 1 NUMA node · **Kernel:** 6.17.0-35-generic · **Bead:** `bd-opb6l`

The incumbent is **in-kernel ext4**, not a previous FrankenFS build. Every ratio below
is a direct competitive measurement taken inside **one invocation**, on **one host**,
from **one fixture's bytes**, against **four independent live mounts** (`kernel_a`,
`kernel_b`, `fuse_a`, `fuse_b`) under matched mount options, arranged as a four-round
Latin-square physical-arm crossover. Every row carries **two same-invocation A/A null
controls** — one per filesystem type — and both are printed. A ratio above `1.0` means
FrankenFS is **slower** than the kernel.

All eight ext4 surfaces now score. **0 wins / 6 losses / 2 neutral / 0 unscored** — parallel
read moved from LOSE to NEUTRAL on re-measurement (2026-08-08); see the row for why that is
not a FrankenFS improvement story.
(Warm stat added 2026-08-04 — it was the one shape btrfs banked and ext4 did not.
Xattr get/list report and bulk durable write added 2026-08-05,
bd-ext4-xattr-row-unscored-a21dz and bd-bulk-durable-write-unscored-orfck — the harness
could already run both and neither scorecard carried either.)

## The rows

| Workload (the job as timed) | FrankenFS ÷ kernel ext4, bootstrap median 95% CI | Kernel A/A null | FUSE A/A null | Governor / EPP on every involved CPU | Worker threads requested → observed | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| **Large-directory readdir+stat** — enumerate 32,768 zero-byte entries, then 8 workers stat every entry exactly once (ro) | ⭐⭐⭐ **SUPPRESSING THE AUDIT PROBE: TWO ADMITTED RUNS, `0.956087x` `[0.954025, 0.973255]` and `0.968970x` `[0.963117, 0.976400]` — spread **`1.35%`**, our arms `33,518,159`/`31,872,660 ns` `4.91%` apart; quote the spread. Both ⭐ **HOLDS UNDER SYMMETRIC TRANSPORT: `0.959046x` `[0.951529, 0.965197]`, ADMITTED, `HONEST_NEUTRAL`** (`--fuse-transport loop`, 48 pairs, nulls `1.008037` spread `1.024034` and `1.003011` spread `1.011948`, `parity=pass`; ours `32,707,029 ns` vs kernel `34,092,873 ns`); ratio moves **`−1.02%`**. `verdict=HONEST_NEUTRAL`** — ours `33,518,159 ns` vs kernel ext4 `34,700,361 ns`, i.e. `4.4%` FASTER but inside the `1.043431x` null margin, so a TIE. `FFS_FUSE_XATTR_NO_SUPPORT=1`, `xattr_suppression=active`, `xattr_presence=proven_absent`; nulls `1.006491` spread `1.010772` and `0.983672` spread `1.021485`, both clear; `parity=pass`, `post_unmount_validation=clean`. A **`4.114x` reduction** from this row's shipping `3.933124x`; our absolute goes `109,715,435 → 33,518,159 ns`, **`69.4%` faster**. **ALL FOUR read-only rows now land at parity with the probe suppressed** — ext4 warm stat `0.999810x`, btrfs warm stat `0.988189x`, btrfs readdir+stat `1.034152x`, ext4 readdir+stat `0.956087x` — a span of `0.956`–`1.034`, every one `HONEST_NEUTRAL`. Same restriction and proven-absent precondition; NOT a default. **RE-MEASURED 2026-08-26 ON THE SHIPPING RANGE-LEAF MEMO: `3.671116x` `[3.667265, 3.730489]`, ADMITTED**, `verdict=HONEST_LOSS`, twice-null margin `1.049240x`, 12 pairs, 8→8 threads, candidate `9b1517b8…` (PGO `f8a9d574…`, x86-64-v3), knobs `capability_memo_bitmap=true`, `receive_spin=0`. Ours `112,653,594 ns` vs kernel ext4 `30,385,176 ns`; nulls `0.985964` spread `1.024324` and `0.995740` spread `1.005143`, both clear. ⛔ **SUPERSEDES `4.052605x`/`4.163402x`**, which were measured on the DIRECT-MAPPED 4096-slot capability memo retired in `9f4e2811f` — the same staleness that took btrfs from `7.75x` to `3.83x`, smaller here (`10.4%`) because ext4's daemon work was already the cheaper half. ⭐⭐ **AND IT RETIRES THE btrfs-SPECIFIC-EXCESS CLAIM.** Our ext4 arm `112,653,594 ns` and our btrfs arm `112,538,224 ns` (measured on the same ELF) agree to **`0.10%`**. There is NO btrfs-specific readdir+stat excess any more; the two published ratios differ (`3.671116x` vs `3.832345x`) only because the two KERNEL arms differ by `2.6%` (`30,385,176` vs `29,614,922 ns`). Both arms are the same `1.0000` `security.capability` crossing per entry, and with the memo sized by range leaves the filesystem underneath it no longer shows | run 1 `1.006371x [0.998838, 1.016057]` · run 2 `1.005559x [0.981512, 1.010438]` | run 1 `1.001235x [0.999309, 0.999309, 1.003556]` · run 2 `0.999527x [0.997275, 1.008144]` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **8 → 8** on all four arms, pinning attested | **LOSE** |
| **Small-file create/delete storm** — serially create 2,000 empty files, fsync the parent, delete all 2,000, fsync again | **⭐ MECHANISM COUNTED 2026-08-26 (gate-free, `bpftrace` on the kernel's `fuse_*` entry points, reproduced EXACTLY on two independent runs), on the post-`bd-7s0p7` binary `818699c5…` — the wall ratio below is STALE (2026-08-08) and still owed.** A 2,000-create + 2,000-delete storm costs **18,009 FUSE crossings, `4.502` per user operation**: `getxattr` **8,007 (`44.46%`)**, `lookup` 4,002 (`22.22%`), `create_open` 2,000 (`11.11%`), `unlink` 2,000 (`11.11%`), `flush` 2,000 (`11.11%`); `mknod`, `setattr` and `fuse_fsync` are **0**. **Every one of the 8,007 `getxattr`s is `security.capability`** — `1.0006` per path-based operation (8,002 of them), the SAME law already counted at `1.0000`/stat on warm stat and `1.02524`/syscall on the xattr row, now confirmed a third time and on a MUTATING workload. ⇒ **`44.46%` of this row's crossings are Linux AUDIT, not our work**, which caps any filesystem-side lever here before the wall ratio is even taken. ⭐⭐ **AND THE DAEMON SHARE, NOW OBTAINED (2026-08-26), IS THE OPPOSITE OF EVERY READ-ONLY ROW.** Same rig, daemon launched directly so the pid is the daemon and not a `timeout` wrapper (verified by reading `/proc/<pid>/cmdline` back before trusting a number), 2 replicates: daemon CPU is **`0.510`/`0.500 s` per 2,000-create + 2,000-delete storm = `127.50`/`125.00` µs per USER OP, `28.32`/`27.77` µs per crossing, `37.64%`/`38.13%` of wall** — agreeing to `2%`. Against the read-only rows, where the whole-handler timer put dispatch at `1,703 ns` per request and FrankenFS's own handlers at `0.60%` of daemon CPU, this is **~16x more daemon CPU per crossing**. ⇒ **the mutating path is daemon-bound in a way no read-only row is, so unlike warm stat, xattr and readdir+stat this row DOES have a filesystem-side lever surface** — roughly `38%` of our arm, sitting alongside the `44.46%` of crossings that are Linux AUDIT. ⚠ The µs-per-op figures are the daemon's own accounted `utime+stime` and are robust; the SHARE-of-wall is rig-dependent and was taken at host loadavg ~126, where an inflated wall makes `38%` an UNDER-estimate rather than an over-estimate. | **`2.862033x` `[2.724405, 2.888338]` slower** (twice-null margin `1.048084x`), re-measured 2026-08-08 on candidate `edbaeb4e…`. ⛔ SUPERSEDES `2.753659x`. ⚠ **ONE admitted run — no pair yet**, so quote it to the campaign's worst measured spread, not this CI. A second run measured `2.869817x` (0.27% away) but was `BLOCKED_NULL` and is corroboration only | `0.999400x` (run 2, blocked) | `1.003846x` (run 2, blocked) | `amd-pstate-epp` / **`performance`** / `performance` | **1 → 1** on all four arms, pinning attested | **LOSE** |
| **Multi-file parallel read** — enumerate and byte-sort 256 × 256 KiB files, then 8 workers `pread` every file exactly once (ro) | ⛔⛔ **THE TIE IS SUPERSEDED — ADMITTED `1.209857x` `[1.207557, 1.236437]` LOSS 2026-08-26**, `verdict=HONEST_LOSS`, `directional_claim_clear=true`, margin `1.042148x`, **48 pairs**; nulls `1.000164` spread `1.018367` and `0.996178` spread `1.020856`, both clear; `parity=pass`. Ours `4,483,096 ns` vs kernel ext4 `3,667,556 ns`, candidate `3c7ff854…` (PGO `c1b9eb9f…`, x86-64-v3). A **23% swing** from the banked `0.986316x`/`0.978203x` "we TIE". ⚠ **ONE admitted run — NO PAIR YET.** A replicate attempt on 2026-08-26 produced 8 more readings (`1.133375`–`1.271788`, median `1.2299`, within **`1.65%`** of the admitted figure) but none cleared its nulls, and the window then closed at loadavg 17.5. Counting every attempt on the shipping ELF the supersession rests on **1 admitted + 19 blocked readings, all in `1.13`–`1.30`** — consistent in direction and magnitude, but quote it as a single admitted run until a second one lands. ⭐ **The two parallel-read ratios differ because the INCUMBENTS differ, not us:** our arms are `4,483,096 ns` (ext4) against `4,468,259 ns` (btrfs, symmetric) — **`0.33%` apart**, same ELF, same crossing structure (`282.3` requests/observation both) — while kernel ext4 is **`8.4%` faster** than kernel btrfs (`3,667,556` vs `4,005,059 ns`). Attribution per `bd-ga4ug` carries over: crossing-bound at one read per file, no lever applies. Older, now superseded: Shipping candidate `3c7ff854…`: 6 blocked readings `1.152609`–`1.300932`, median ≈`1.22`. OLD candidate `9b1517b8…`: 5 blocked readings `1.203536`–`1.254283`, median ≈`1.243`. **The two ELFs are indistinguishable**, which REFUTES the hypothesis that the new PGO profile (trained on `create-bench`, a METADATA workload) had deoptimized the read path — the old profile measures the same or slightly worse. ⛔ All 11 readings are `BLOCKED_NULL` (nulls `1.036`–`1.063` against a `1.025` limit even at 48 pairs), so the banked ≈`0.98x` TIE is **not withdrawn** — but it does not describe today's system, and the cause is NOT the candidate binary. Prime suspect is the loop-transport asymmetry (`bd-w2u82`): the kernel arm is loop-mounted and buffered while ours reads the image directly, so a READ-heavy row gives the incumbent double page-cache residency. See the btrfs twin, an ADMITTED sign change to `1.085668x`. **≈`0.98x` — a TIE, not a win.** Two admitted same-ELF runs, `0.986316x [0.981390, 0.989874]` and `0.978203x [0.968511, 0.981821]`; neither clears its margin (`1.016961x`/`1.020212x`), `directional_claim_clear=false` on both. Spread `0.83%`. ⛔ SUPERSEDES `1.287862x`, measured on an unindexed fixture and a since-destroyed ELF | run 1 `0.995873x [0.991626, 1.005511]` · run 2 `1.004181x [0.993028, 1.010056]` | run 1 `1.000388x [0.997640, 1.004583]` · run 2 `1.001259x [0.995212, 1.005430]` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **8 → 8** on all four arms, pinning attested | **NEUTRAL** |
| **Fsync/journal commit** — 8 × 4 KiB positioned writes to one file, `fsync` after each | ⛔⛔ **NOT COMPARABLE — THE ARMS ARE IN DIFFERENT DURABILITY CLASSES (`bd-4zjkz`, 2026-08-26).** A re-measurement on the shipping ELF `3c7ff854…` (self-reported `binary_sha256=3c7ff8544c34181b136e2c196872ea36cde1df3e625029b9452cbf87a2969389`, matching its on-disk `sha256sum`) ADMITTED this row at **`0.182706x`** (`verdict=HONEST_WIN`, `admitted=true`, `directional_claim_clear=true`, twice-null margin `1.041753x`, 12 pairs; nulls kernel `0.992797` spread `1.017327`, fuse `0.984921` spread `1.020663`) — FrankenFS **5.47x FASTER** than live kernel ext4 at `fsync`. **That figure is REJECTED, not banked.** Measured cause, gate-free: our daemon does flush — `strace -c` on the live daemon over 200 client `write+fsync` pairs counts **`fdatasync` 200, `pwrite64` 400 = `1.000` fdatasync and `2.000` block writes per client `fsync`** — but it writes **ZERO journal blocks**: with offsets, the daemon touches exactly blocks **2537 and 4651**, while that image's journal is inode 8, `EXTENTS (0-4095):32801-36896`. Kernel ext4 on the SAME image and the same 200 pairs (loop `--direct-io=on`, `rw,relatime` = `data=ordered`) writes **4.00 blocks/fsync** against our **2.00** — exactly **`2.00x`**, the extra two being the jbd2 descriptor and commit blocks (that rig: kernel `17,881.43 µs/op` vs ours `4,346.03 µs/op`). In the tree, `OpenFs` has `jbd2_writer: Option<Mutex<Jbd2Writer>>` (`crates/ffs-core/src/lib.rs:1462`) and a `commit_transaction_journaled`, but **`attach_jbd2_writer` has ZERO call sites outside `ffs-core`'s own unit tests** — and `lib.rs:75661` *asserts* `!fs.has_jbd2_writer()` on a fresh open, so unjournalled is the ASSERTED default. A mounted FrankenFS ext4 writes data + inode in place and `fdatasync`s; a crash between the two `pwrite`s leaves torn metadata with no journal to replay. ⇒ **the 5.47x is bought with a weaker crash guarantee, not with engineering.** ⭐ **DECOMPOSED AND CLOSED OUT 2026-08-26 — the 5.47x is TWO measurement artifacts and a null.** Three arms, all on ONE loop device with `--direct-io=on`, `N=200` write+fsync after a 20-pair warm, blocks from `/sys/block/loopN/stat`: kernel **WITH** journal `27,441.54 µs/op` / `4.40 blocks/op`; kernel **NO** journal (`e2fsck -fy; tune2fs -O ^has_journal; e2fsck -fy`) `9,268.66 µs/op` / `2.20 blocks/op`; **FrankenFS on the same loop dio `9,547.68 µs/op` / `2.20 blocks/op`**. (i) **The journal is `2.96x`** and exactly `2.00x` of the blocks — the jbd2 descriptor + commit we never write. (ii) **The transport is another `2.20x`, and that one was mine**: my first FrankenFS figure (`4,346.03 µs/op`) had the daemon on a BUFFERED image file while both kernel arms went through loop `--direct-io=on`; moving the same daemon onto the same loop device gives `9,547.68`. `2.96 × 2.20 = 6.5x` against the admitted `5.47x`. (iii) **The residual is a NULL**: alternating both arms round-robin on the SAME unjournalled image so drift hits both gives ratios `0.8365 / 0.9697 / 1.1373 / 1.0032`, **median `0.986`, spread `0.84`–`1.14`** — a `±15%` floor, so no claim in either direction, with **both arms writing an identical `2.20 blocks/op`**. ⇒ **FrankenFS ext4 `fsync` is indistinguishable from kernel ext4 with the journal stripped, doing the same work per boundary — neither `5.47x` faster nor measurably slower.** ⚠ That `±15%` is the same round-to-round variability `bd-w5ok5` reports on every mutating workload, now reproduced with a **kernel arm on both sides**, which corroborates that blocker as a property of the WORKLOAD, not of our daemon. The row stays NOT COMPARABLE against the shipping journalled incumbent. ⭐⭐ **AND ON tmpfs IT IS A `3.376x` LOSS — THE FIRST DAEMON-BOUND ROW IN THE CAMPAIGN (`bd-6tw2s`, 2026-08-26).** The null above is real ON `/data` AND ONLY THERE: both arms paid `~9,300 µs/op` of *shared device time* that buried everything else. Same unjournalled image on `/dev/shm`, same interleaved A/B, `N=200` after a 20-pair warm: kernel `33.93 / 36.02 / 34.59 / 32.72 µs/op` against ours `114.24 / 119.40 / 117.08 / 122.87` — ratios `3.3669 / 3.3148 / 3.3848 / 3.7552`, **median `3.376x`**, arm spreads `1.101` (kernel) and `1.075` (ours), effect ~25x the residual noise. **Daemon CPU is `75.00 µs/op` of a `101.69 µs/op` wall = `73.8%` of our wall, against a kernel arm that finishes the ENTIRE op in `~34.3 µs`** — the exact inverse of every read-only row (transport-bound, daemon `49.2%` of wall, `91.25%` of that inside the kernel, `ffs_*` at `0.95%` of wall). **`19.097` syscalls per client `fsync`** against `2.040` read-only: `futex` `3.000` (`59.51%` of syscall time), `writev` `4.020`, `read` `3.020`, `pread64` `6.003`, `pwrite64` `2.000`, `fdatasync` `1.000` — six `pread`s to service a 4 KiB overwrite. Profile (`--call-graph dwarf,16384 -F 397`, `RUST_LOG=off`, DSO+symbol, 8,658 samples): kernel `78.09%`, `ffs-cli` `16.71%`, libc `4.55%`; top ours `flush_to_device_after` `2.14%`, `ext4_chksum_skip_zero_tail` `0.99%`, `crc32c` `0.94%`; the kernel share is syscall entry/exit and scheduler, i.e. the cost of issuing 19 syscalls. ⇒ **this row has a genuine filesystem-side lever surface, unlike every read-only row.** ⛔ REJECTED same turn: the futexes are NOT the `KernelNotifyQueue` — `FFS_FUSE_ENTRY_INVAL=0` on one ELF gives `1.1127 / 0.8652 / 0.9242 / 0.9589`, median `0.94` against a 29% spread, daemon CPU if anything *higher* with it off. ⚠ LEAD, NOT A CLAIM: the daemon runs `ffs-read-0`, a rayon pool sized by `FFS_READ_PARALLELISM` (`crates/ffs-core/src/lib.rs:5109`) — a plausible partner for both the 6 `pread`s and the 3 futexes, but its A/B ran `0.6170 / 0.5435 / 0.8752 / 5.7863` with absolutes swinging `107`–`621 µs/op` because the host hit **loadavg 168, 64 of 64 CPUs >25% busy**. UNRESOLVED — do not quote it. ⚠ These are hand-rig numbers with an interleaved control, **not gated comparator rows** — `ffs-mounted-kernel-bench` refuses this workload shape (`bd-w5ok5`). ⭐⭐ **THE LARGEST COMPONENT OF THAT SYSCALL COUNT IS AVOIDABLE WORK WE OWN (`bd-1bh8i`, 2026-08-26).** Counted with offsets on the live daemon after a 30-op warm (so nothing is first-touch), over ~90 further ops: **`pread64` total 540 across just SIX DISTINCT BLOCKS — each re-read 90.00 times, `98.9%` of reads (534/540) repeating a block already read in-window** — against `pwrite64` total 180 over 2 blocks (`2537` inode, `4139` data). Named from the image's own `dumpe2fs` layout: **block `0` primary superblock, block `1` group descriptors, blocks `33`/`34` block bitmaps, blocks `35`/`36` inode bitmaps.** **The workload cannot dirty any of them** — it overwrites 4 KiB at offset 0 of an existing file, so no block or inode is allocated, the size does not change, and no free count changes; all four metadata classes are invariant across the op, and the kernel arm holds them in its buffer cache and issues none. ⇒ six of the `7.003` `pread`s per `fsync` are pure re-reads of unchanged metadata that was resident one operation earlier. Conservatively priced off the profile (`58.6 µs/op` daemon kernel time over `19.097` syscalls ≈ `3 µs`/syscall), removing them is `~18 µs` of a `118 µs/op` wall ≈ **`15%`, moving `3.376x` to roughly `2.9x`** — *not* the whole gap and not to be sold as such, but the clearest lever this campaign has found that is unambiguously **our code** rather than the kernel, the transport, or Linux AUDIT. ⛔ REJECTED en route, counted so host load is irrelevant: the reads and the futexes are **not** the ext4 read path's rayon fan-out — `FFS_READ_PARALLELISM=1` vs `16` on one ELF demonstrably works (**4 threads vs 19**, attested by the live thread list) yet leaves the syscall structure IDENTICAL (`pread64` `7.003` both arms, `futex` `3.500` vs `3.493`, everything else unchanged bar jemalloc `madvise`). The fsync path never uses the read pool. ⚠ STILL UNATTRIBUTED: the exact call site — `perf record -e syscalls:sys_enter_pread64 --call-graph dwarf,16384` gave 154,673 samples but resolves only `__syscall_cancel_arch_end` and the `ffs_fuse::FrankenFuse` entry; needs a targeted probe or a debug-symbol build, not another dwarf attempt. ⭐⭐ **ATTRIBUTION PROVEN AND THE LEVER ALREADY EXISTS (`bd-gb0gx`, 2026-08-26).** The six blocks were attributed to the boundary's group-descriptor + superblock persist from block numbers alone; that is now proven by counting, one ELF `11404c56cfce3458340e02e616c1b26dab239f45b8747e5ed04aa2f594b47e0b`, 300 ops after a 40-op warm: **default `pread` `7.000`/op over blocks `[0,1,33,34,35,36]`; `FFS_SKIP_GDT=0` `pread` `0.000`/op over ZERO blocks**, with `pwrite` `2.333`/op in both — the reads vanish without buying extra writes. `FFS_SKIP_GDT=0` selects EAGER per-op GD persistence, so a workload that allocates nothing leaves the boundary nothing to do, while the default re-reads all six blocks to discover exactly that. **Wall clock, 18 interleaved rounds (6+12), `N=2000`, image on `/dev/shm`, all three arms alternating, kernel arm loop-mounted ext4 WITH its journal (the harder incumbent): `FFS_SKIP_GDT=0`/default median `0.877`, 16 of 18 rounds below 1.0 (sign test p≈0.0007), range `0.7147`–`1.0093`; against the LIVE kernel the row moves `2.751x` → `2.356x`.** Arm spreads in a quiet window (loadavg 3.45–5.27): kernel `1.160`, default `1.212`, skipgdt0 `1.053` — the fastest arm is also the most stable, which is what removing seven syscalls per op should do. **e2fsck `-fn` rc=0 twice on the unstripped image both arms wrote.** ⚠ **NOT a default flip**: deferred persistence is the default because eager mode pays on every allocation, so a create-heavy workload should lose exactly what this no-allocation workload gains — quote it with the workload named. ⛔ **MY OWN CANDIDATE IS REJECTED**: `FFS_EXT4_GDT_SKIP_UNCHANGED` (fingerprint the mutable group state, skip the persist when unchanged — which would have kept deferred persistence *and* dropped the reads) is INERT — identical syscall counts, and an added `gdt_persist_decision` trace shows `gdt_fingerprint=0` on all 76 decisions, i.e. the fingerprint function returns `None` every time. Ruled out: wrong flavor, and the `bd-bhh0i` sharded guard (compiled in, runtime-off by default). Not established: env knob vs `require_alloc_state`. Stashed, not committed — redundant against `FFS_SKIP_GDT=0` whatever the cause. ⚠⚠ **METHOD CORRECTION**: e2fsck is **not** a valid gate on a `tune2fs -O ^has_journal` image — pristine source rc=0, after the strip and NEVER mounted rc=4, after a run with my code provably inert rc=4. The journal-strip step introduced two rows above does not invalidate those TIMINGS (both arms shared one image) but its e2fsck gate was meaningless; correctness gating needs an unstripped image, as used here. ⭐ **WHOLE-OP CENSUS IN THE NEW BEST CONFIG (2026-08-26).** Re-profiled so the next lever is chosen against what the op costs NOW: **default wall `113.10 µs/op`, daemon CPU `90.00 µs/op` (`79.6%` of wall), `22.200` syscalls/op; `FFS_SKIP_GDT=0` wall `97.19`, daemon CPU `65.00` (`66.9%`), `15.193` syscalls/op.** The difference is `7.007` syscalls/op — **exactly the seven `pread`s** — and `25 µs/op` of daemon CPU (`−27.8%`); the single-shot wall ratio `0.859` agrees with the 18-round median `0.877`. The remaining census is COMPLETE, nothing unaccounted: `writev` `4.683` + `read` `3.517` + `futex` `3.493` + `pwrite64` `2.333` + `fdatasync` `1.167` = `15.193`. So the row is still daemon-bound (`66.9%`), `read`+`writev` `8.200`/op is the FUSE round-trip floor for the two ops (write + fsync), and **`futex` `3.493`/op is the largest attackable non-transport item left**. ⚠ Futexes attributed by thread and by address, counted: the dispatch thread issues `2.333` `FUTEX_WAKE`/op and `ffs-fuse-notify` takes `1.170` `FUTEX_WAIT`/op; by address, `1.167`/op is a MATCHED wake/wait pair with the notify thread and `1.167`/op are wakes on two addresses with **no waiter at all**. **This is unexplained**: the `write` and `fsync` handlers make ZERO `notify_inode_invalidation` / `notify_entry_invalidation` calls (every call site is `symlink`/`setattr`/`mknod`/`mkdir`/`unlink`/`rmdir`/`rename`, none on this path), yet the notify thread is woken ~once per op on a pure `pwrite`+`fsync` workload. It also explains why `FFS_FUSE_ENTRY_INVAL` measured null earlier — that knob gates only `notify_entry_invalidation`, while `notify_inode_invalidation` is ungated. Naming the waker needs symbols the dwarf unwinder will not produce here. ⚠ CORRECTION: an earlier reading of `14.013` syscalls/op removed was wrong — the summing script double-counted by including strace's own `total` row; the true figure is `7.007`. The daemon-CPU figures come from `/proc/<pid>/stat` and are unaffected. ⛔⛔ **THAT CORRECTION WAS ITSELF INCOMPLETE — THE REAL FIGURE IS `6.000`/op, AND A SYSTEMATIC WARM-UP ERROR INFLATED EVERY PER-OP COUNT BY `1.1667` (2026-08-26).** `fsync_timed.py` runs **50 warm ops INSIDE the measured window** before its timed loop, so every figure divided by `N=300` actually covered 350 ops. That is why they kept landing on `7.003` / `3.517` / `2.333` / `1.167` instead of integers. Re-measured with the warm-up moved OUTSIDE the window (`fsync_body.py`, exactly `N` ops), everything lands on integers: **default `19.033`/op = `pread64` `6.000` + `writev` `4.017` + `read` `3.017` + `futex` `3.000` + `pwrite64` `2.000` + `fdatasync` `1.000`; `FFS_SKIP_GDT=0` `13.027`/op with `pread64` `0`. The reduction is EXACTLY `6.000` syscalls/op — one read per distinct metadata block**, which is the number the block census predicted all along and is far more convincing than either `7.007` or `14.013`. Corrected companions: `futex` is `3.000`/op (not `3.493`); the futex-by-thread split is `2.000` `FUTEX_WAKE`/op from dispatch and `1.003` `FUTEX_WAIT`/op on `ffs-fuse-notify`; by address `1.000`/op is the matched pair and `1.000`/op (2 × `0.500`) are wakes with no waiter. Daemon CPU at `N=2000` was inflated only `2.5%` (2050/2000): **default `87.8 µs/op`, `FFS_SKIP_GDT=0` `63.4 µs/op`**, i.e. `77.6%` and `65.2%` of their `113.10` / `97.19 µs/op` walls. ⚠ Daemon CPU at `N=300` is jiffy-quantized (`CLK_TCK=100` ⇒ ±33 µs/op at that N) and must NOT be quoted — the `100.00`/`33.33` pair from that run is 3 jiffies against 1. ✅ **WHAT IS UNAFFECTED**: every WALL and RATIO result, because `perf_counter` wraps only the timed loop in both arms — the 18-round median `0.877`, the `2.751x` → `2.356x` move, and the tmpfs `3.376x` all stand. ✅ Also vindicated: the ORIGINAL `19.097` syscalls/op from `bd-6tw2s` was measured with no warm inside its window and was RIGHT all along — now corroborated at `19.033`. It was the later `22.200`/`15.193` pair that was wrong. ⭐⭐ **THE ROW, ATTACKED TO `1.88x` — AND THE AUDIT LAW CONFIRMED A FOURTH TIME, NOW ON A WRITE WORKLOAD (`bd-pkioo`, `bd-q6xmd`, 2026-08-26).** Two levers landed on top of the GD-persist fix, each measured on ONE ELF `aeb66c636d71dc3370324a232d75f16efafdb45b3548fa09c26b414186e222dc` with an interleaved live-kernel arm. **(1) Every FUSE `write` invalidates the kernel's page cache for data the kernel just sent us** — counted exactly (`notify_send_counts entry_sends=1 inode_sends=502` over 501 ops = `1.000`/op), the sender being `write` itself at `crates/ffs-fuse/src/lib.rs:6256`. Behind `FFS_FUSE_WRITE_INVAL` (**default ON, shipping behaviour byte-identical**): `−3.000` syscalls/op (`futex` `2.993→1.000`, `writev` `4.017→3.013`) and **daemon CPU `70.00→55.00 µs/op`, `−21.4%`, 3 of 3 replicates lower with non-overlapping ranges** (ON {65,70,70} vs OFF {50,55,60}). Its wall move is only `0.963` median (8/10, p≈0.055, NOT decided) **because the invalidation runs on the notify thread, off the request critical path — it returns CPU, not latency**, which is why the CPU figure is the result and the wall figure is left undecided. Read-after-write correctness 60/60 in both arms three ways (same fd, fresh fd in a new process, and after `drop_caches`), e2fsck rc=0 — necessary but NOT sufficient (no mmap, shared writable mappings, concurrent readers, or writeback-cache coverage), so the default stays ON pending that argument. **(2) The third FUSE request on every `write`+`fsync` is Linux AUDIT**: traced at `ffs_fuse=trace` over exactly 100 ops, `FUSE write` `1.000`/op + `getxattr answered from capability memo` `1.010`/op + `fsync` `1.000`/op = `3.010`, matching `read` `3.013`/op. That is the same law counted at `1.0000`/stat (warm stat), `1.02524`/syscall (xattr row) and `1.0006`/path-op (storm) — **a fourth confirmation and the first on a MUTATING workload**. `FFS_FUSE_XATTR_NO_SUPPORT=1` takes syscalls `10.005→9.003`/op and daemon CPU `55.00→45.00`, **wall median `0.850`, 9 of 10 rounds below 1.0 (p≈0.011)**, e2fsck rc=0. ⚠ **An unexplained `pread64` `1.000`/op APPEARS when the probe is suppressed** — suppression should only remove work; it does not undo the win but is not understood and must not be quoted as such. **CUMULATIVE, live-kernel interleaved: shipping default `~2.75x` → `FFS_SKIP_GDT=0` `2.36x` → `+WRITE_INVAL=0` `2.21x` → `+XATTR_NO_SUPPORT` `1.88x`.** ⛔ **Only the first number describes what ships**: `XATTR_NO_SUPPORT` is a RESTRICTED mount (ENOSYS, no xattrs at all — sound only where `xattr_presence=proven_absent`, never a default), `WRITE_INVAL=0` needs the data-integrity argument, and `FFS_SKIP_GDT=0` is a workload trade that loses on create-heavy work. ⛔⛔ **CORRECTION — `FFS_SKIP_GDT=0` IS NOT A WORKLOAD TRADE, IT IS UNSAFE ON ANY ALLOCATING WORKLOAD (`bd-hyysq`, p0, 2026-08-26).** I attached "loses on create-heavy work" to a published number without measuring it. Measured: the arm is not slower on a create storm, it is **INCORRECT**. Fresh image per arm, 1000 create+unlink pairs, CLEAN unmount so `flush_on_destroy` runs, reproducible **2/2**: `default` e2fsck **rc=0 clean** both times; `FFS_SKIP_GDT=0` e2fsck **rc=4** both times with the identical complaint — **"Free blocks count wrong for group #0 (28125, counted=28117)"**, off by exactly 8, and the same for group #1. Mechanism: the knob makes `ffs_alloc::gdt_persistence_deferred()` false, and `ext4_flush_group_descriptors` opens with `if !gdt_persistence_deferred() { return Ok(()); }` — so the durability boundary persists NOTHING, assuming an eager per-allocation path already did. On an allocating workload that assumption does not hold and the counts never reach disk. That is exactly why the knob looked free on the fsync row: **that workload overwrites 4 KiB and allocates nothing**, so there is no descriptor movement to lose, and e2fsck there is rc=0 (verified twice). ⇒ **The `0.877x` and the `−6.000` syscalls/op STAND as figures on a no-allocation workload, but the knob must not be recommended**, and its `2.36x` / `2.21x` / `1.88x` cumulative entries above inherit that restriction. The defect is PRE-EXISTING (the knob predates this session). ⚠ The perf half of my caveat is refuted outright: on the storm both arms issue essentially the same syscalls per create+unlink pair — default `35.942` vs skipgdt0 `35.827` (`writev` `17.021` vs `17.013`, `read` `14.902` vs `14.892`) — there is no extra per-allocation cost to find. **Eager mode is not paying more; it is doing less.** Wall clock deliberately NOT reported for this row: the host sat at 64 of 64 CPUs >25% busy, loadavg 120–247, and an earlier timed attempt failed on ENOSPC (one image reused across 24 arm-runs against the fixture's 40,013 inodes) plus a formatting fault on an empty arm — both rig faults fixed; every figure quoted here is counted or e2fsck, neither of which host load can move. ⭐⭐⭐ **THE SAFE REPLACEMENT LANDED — `FFS_EXT4_GDT_SKIP_UNCHANGED`, `0.859x` ON 12/12 ROUNDS, AND IT PASSES THE GATE `FFS_SKIP_GDT=0` FAILS (`bd-1bh8i`, 2026-08-26).** Same six reads removed, without the defect: deferred persistence is KEPT and the boundary persist is skipped only when the mutable descriptor state provably has not moved — fingerprinted over both free counts, `used_dirs`, `flags`, and BOTH bitmap checksums (maintained in memory on every alloc/free, so a bitmap whose content moved necessarily moves the fingerprint). ONE ELF `74e477cff20251c4e5eee0e3de3aa8bfd92af4c64cb296981b5f8db60837ed64`, the knob the only difference. **COUNTED** (fsync row, `N=300`, no warm inside the window): knob off `19.003`/op with `pread64` `6.000`/op; knob on `13.033`/op with `pread64` **absent** — `−5.970` syscalls/op, the memo arming on the first boundary and holding (`gdt_skipped=true` on 30 of 31 decisions). **WALL** (12 interleaved rounds vs a LIVE kernel ext4 arm, same loop transport, `N=2000`): `0.8936 0.6972 0.8457 0.8457 0.7250 0.8727 0.8980 0.8922 0.8595 0.8940 0.8515 0.8576` — **median `0.859`, TWELVE OF TWELVE below 1.0, sign test p≈0.00024**; against the live kernel the row moves **`2.865x` → `2.388x`**; arm spreads kernel `1.393`, default `1.227`, fpskip `1.271`. **SAFETY GATE** (the test that catches this bug class — 1000 create+unlink pairs, clean unmount, e2fsck, 3 reps): default rc=0 ×3, fpskip **rc=0 ×3**, where `FFS_SKIP_GDT=0` fails the identical test 2/2 with "Free blocks count wrong for group #0 (28125, counted=28117)"; e2fsck rc=0 also on the image the 12-round A/B wrote. ⚠ **Why it was inert for three turns**: the fingerprint declined whenever `bhh0i_sharded_ops_active()`, which `bd-rmug7` showed is the PRODUCTION path on a plain `--rw` mount. It now fingerprints `sharded.reconciled_group_stats(&live)` — the same source `ext4_flush_group_descriptors` persists from there. Hashing `alloc.groups` on that path would not merely be inert but WRONG (sharded creates debit the per-group records and the on-disk GDs, not that array), which is exactly why the storm gate is run on the sharded path. A second, independent bug was fixed en route and kept: the fingerprint was stored BEFORE the persist, yet the persist restamps bitmap checksums back into `GroupStats`, so the stored value could never match the next boundary's — now recomputed after success. ⛔ **DEFAULT STAYS OFF**, shipping behaviour byte-identical. Proven: the fsync row and a 1000-pair storm under e2fsck. NOT yet covered: mkdir/rmdir-heavy work, xattr mutation, fallocate/truncate, and multi-group allocation churn touching several descriptors at once — those runs, in the storm gate's shape, should precede any default flip. **This supersedes `FFS_SKIP_GDT=0` as the way to remove these reads**; `bd-hyysq` stays open as a p0 against that knob. ⛔ **CORRECTION — THE STORM GATE CITED ABOVE IS VACUOUS FOR THIS KNOB (2026-08-26).** Measured: the 1000-pair create/delete storm produces **`decisions=0`** — it never calls `fsync`, so `ext4_sync_with_logging` never runs and the skip cannot engage. It "passes" because it is INERT there. `FFS_SKIP_GDT=0` fails that same test for an unrelated reason (it early-returns `ext4_flush_group_descriptors` EVERYWHERE, including the unmount flush), so the two knobs were never comparable on that workload and presenting them as such was wrong. ⭐ **THE GATES THAT DO EXERCISE IT**, each instrumented to prove the skip fires before its e2fsck result is credited: **`xattr` n=600 → 601 decisions, 398 skipped, e2fsck rc=0 both arms**, and **`falloc` n=400 → 400 decisions, 399 skipped, rc=0 both arms** — the skip firing hundreds of times on workloads that mutate xattrs and that allocate-and-free blocks, both ending clean. **NEGATIVE CONTROLS**: `mkdir` n=800 (1600 decisions, **0 skipped**, 1600 persisted) and `multigroup` n=120 (120 decisions, **0 skipped**, 120 persisted) — every boundary allocates, the fingerprint moves, and the skip correctly declines; a lever that skipped there would be the `bd-hyysq` defect. ⚠ `mkdir` and `xattr` were THEMSELVES vacuous on first run (`decisions=0`, no durability boundary) and became gates only once an fsync of the parent directory / of the file was added — the figures here are from the fixed workloads. ✅ The PERFORMANCE result is untouched by all of this: `0.859x` median, 12/12 rounds, `−5.970` syscalls/op, `2.865x` → `2.388x`. ⛔ **Still missing, and it is the gate that matters most**: a crash / power-fail test. e2fsck after a CLEAN unmount cannot distinguish "skipped correctly" from "skipped wrongly and the end state happened to converge", because the workloads return the free counts to where they started. That test — not more clean-unmount runs — is what a default flip requires. ⚠ **This reframes `bd-fv9tc` above**, recorded as taking ext4 to "FEWER bytes than kernel ext4 per durability boundary" (`0.750x` amplification): writing fewer bytes at a durability boundary is not an improvement when the bytes not written are the journal. ⚠ **Blast radius is all four write rows** — every mutating row compares an unjournalled FrankenFS against a journalled kernel ext4. Historical, superseded, and itself taken on the pre-`bd-fv9tc` ELF `f44b3dc4…`: `0.997098x [0.990808, 1.009108]` against a twice-null margin of **`1.030661x`**; `directional_claim_clear=false` | `1.001860x [0.991465, 1.004642]`, spread `1.008609x` | `0.997807x [0.991484, 1.015215]`, spread `1.015215x` | `amd-pstate-epp` / `powersave` / `balance_performance` | **1 → 1** on all four arms, pinning attested | **NEUTRAL** |
| **Parallel metadata writes** — 8 workers create exactly 512 empty files into private directories, then fsync every worker directory (**128 crossover blocks**) | **`1.510822x` `[1.493097, 1.539011]` slower** (twice-null margin `1.049223x`); replicated on a **disjoint CPU set** at `1.513052x [1.490837, 1.534711]`, agreeing to **0.15%** | `1.007184x [0.998479, 1.024316]`, spread `1.024316x` · replicate `0.998642x [0.990286, 1.009556]`, spread `1.009809x` | `0.995707x [0.978797, 1.000111]`, spread `1.021662x` · replicate `0.998780x [0.990819, 1.002688]`, spread `1.009266x` | `amd-pstate-epp` / `powersave` / **`performance`** (host EPP differed in this window; uniform across both metadata runs) | **8 → 8** on all four arms, pinning attested | **LOSE** |
| **Warm stat** — issue 2,000 `stat` calls against one mounted file and aggregate the metadata (ro) | ⭐⭐⭐ **SUPPRESSING THE PROBE ELIMINATES THIS ROW: TWO ADMITTED RUNS, `0.999810x` `[0.992366, 1.003664]` and `0.998620x` `[0.992702, 1.000534]` — spread **`0.12%`**, our arms `4,518,176`/`4,479,875 ns` `0.85%` apart; quote the spread, not either CI. ⭐ **AND IT SURVIVES SYMMETRIC TRANSPORT: `1.001805x` `[0.994085, 1.007566]`, ADMITTED, `HONEST_NEUTRAL`** with `--fuse-transport loop` so BOTH arms cross the block layer (48 pairs, nulls `1.006147` spread `1.013942` and `0.997324` spread `1.012280`, `parity=pass`; ours `4,845,551 ns` vs kernel `4,842,951 ns`, **`0.05%` apart**). The ratio moves only **`+0.32%`** from the file-transport pair, because BOTH arms pay the loop layer almost equally — ours `+8.16%`, the kernel arm `+7.61%` (it is loop-mounted either way; this is the second-loop-device effect `bd-w2u82` recorded). Warm stat moves no file data, so the block layer is a fixed tax on both sides. Contrast parallel read, which pushes 64 MiB/observation and moved **`+5.07%`** under the same change — so transport-sensitivity tracks I/O volume, and the parity results are NOT an artefact of the asymmetry. `verdict=HONEST_NEUTRAL` — a TIE with kernel ext4.** `FFS_FUSE_XATTR_NO_SUPPORT=1`, daemon self-reporting `xattr_suppression=active`, `xattr_setting=asserted`, `xattr_presence=proven_absent`; nulls `0.988502` spread `1.014111` and `1.007391` spread `1.020528`, both clear; `parity=pass`, `post_unmount_validation=clean`. **Ours `4,518,176 ns` against kernel `4,532,453 ns` — we are `0.3%` faster, inside the null margin, i.e. indistinguishable.** Against the same ELF's shipping `4.654964x` that is a **`4.656x` reduction**, and our absolute goes `22,667,816 → 4,518,176 ns`. ⇒ **The ENTIRE warm-stat gap is the Linux AUDIT `security.capability` probe**, exactly as the counted attribution said (1.0000 probes/stat), and `bd-z0rb8`'s conclusion holds precisely as written: no FILESYSTEM-side lever moves this row, because the lever is not filesystem-side. Answering `ENOSYS` once makes the kernel set `fc->no_getxattr` and stop asking for the life of the connection. ⚠⚠ **THIS IS A RESTRICTED MOUNT, NOT A FREE WIN, and the comparison is asymmetric on purpose:** the mount declares NO extended attributes, so `setxattr`/`removexattr` answer `ENOTSUP` and no xattr is readable, while the kernel arm keeps full xattr support and still pays its own (cached, in-kernel) probe. It is sound here only because the filesystem PROVED the image carries no xattrs (`proven_absent`, not merely asserted). It is a legitimate operator choice for an image with no xattrs and a workload that uses none; it is NOT a default and it would be wrong on any image that has them. | **SHIPPING `4.901194x` `[4.853442, 5.024887]`, admitted 2026-08-26** (`verdict=HONEST_LOSS`, margin `1.045267x`, 12 pairs), ours `22,616,482 ns` vs kernel ext4 `4,586,657 ns`, ELF `9b1517b8…` (PGO `f8a9d574…`, x86-64-v3) — consistent with, and slightly above, the banked `4.81–4.86x` band. **⭐ THE RECEIVE SPIN MOVES IT TO `3.949942x` `[3.938891, 3.972848]`, ALSO ADMITTED** (`FFS_FUSE_RECEIVE_SPIN=2000` on both fuse arms, daemon self-reported `receive_spin=2000`; margin `1.020861x`; nulls `1.003000` spread `1.006165` and `0.998169` spread `1.010377`, both clear; ours `18,137,291 ns` vs kernel `4,565,472 ns`). Corroborated within-window on ONE ELF by a six-arm candidate A/B in a separate invocation: **`0.785571` `[0.775136, 0.786576]`, `candidate_b_faster`, admitted, all THREE A/A nulls clear** (`0.987529`/`1.000951`/`0.998662`) — `1.273x` faster, against the direct ratio's `1.241x`, agreeing to `2.6%`. ⚠ **This does NOT reopen `bd-z0rb8`**: that bead closed FILESYSTEM-side levers on warm stat, and the counted attribution behind it (`~99%` of the gap is one kernel-issued `security.capability` round trip) still stands. The spin is a TRANSPORT lever — it makes each of those round trips cheaper, it does not remove one. The remaining `3.95x` is still the probe. ⚠ Not a default. **⛔ THE SPIN'S COST IS NOW MEASURED (2026-08-26, `bd-3d2c0`) AND IT IS LARGE.** Daemon-resource measurement on a separate rig (16 MiB e2e ext4 image, `ffs-cli mount --no-background-scrub`, python `os.stat` driver, daemon's OWN accounted `utime+stime` from `/proc/<pid>/stat`, ABAB, 2 replicates per arm at each N): daemon CPU per request is **`8.00`/`8.00` µs at `spin=0` and `18.50`/`19.00` µs at `spin=2000`** (N=20,000), replicating at **`8.133`/`8.267` vs `17.667`/`17.667` µs** (N=150,000, `CLK_TCK=100` so quantization is negligible). That is **`2.16–2.34x` the daemon CPU, `+9.5` to `+10.8` µs per request.** Against it, the admitted warm-stat win is `22,616,482 → 18,137,291 ns` over 2,000 stats = **`−2.24` µs of wall per stat**. So the spin spends roughly **`4.2–4.8` µs of extra daemon CPU per `1` µs of latency it saves.** The win is real as LATENCY on an otherwise-idle core and is a large net loss as THROUGHPUT/EFFICIENCY; on a shared or CPU-contended host it takes from other tenants what it gives to this one. **It must not become a default in fixed mode.** ⚠ That rig is not the comparator: its own wall figures are noisy (`19.0–30.3` µs/stat for the SAME config at host loadavg 145–190) and are NOT used here — the latency side comes only from the admitted comparator rows above. What transfers is the CPU RATIO, which replicated to within `1.6%`. **ADAPTIVE MODE MEASURED TOO (2026-08-26), and the SPARSE negative control is the decisive one.** Same rig, 1,000 stats paced at ~100/s over 10 s, 2 replicates: daemon CPU per request is `10`/`20` µs at `spin=0`, **`1930`/`1484` µs at fixed `spin=2000`** — i.e. the fixed spin burns **`14.8–19.3%` of a core to serve 100 requests/second**, `74–193x` `spin=0` — and `260`/`231` µs with `FFS_FUSE_RECEIVE_SPIN_ADAPTIVE=1`. So the decay is REAL and large (**~`7x` off the idle burn**) but does not reach `spin=0`: adaptive is still `12–23x` `spin=0` when requests are sparse. Under a DENSE stream adaptive costs the same as fixed (`17.8` vs `17.4` µs/req), which is the intended behaviour — it holds the budget while spinning pays. ⚠ One of two dense adaptive replicates went pathological at `72.6` µs/req (4x fixed) on a host at loadavg 164; recorded, not explained. ⭐ **ADAPTIVE'S WALL WIN IS NOW VERIFIED ON THE COMPARATOR (2026-08-26), TWO ESTIMATORS, AND IT RETAINS ALL OF FIXED'S WIN.** (a) direct vs live kernel ext4 with `FFS_FUSE_RECEIVE_SPIN=2000 FFS_FUSE_RECEIVE_SPIN_ADAPTIVE=1` on both fuse arms: **`4.252876x` `[4.246624, 4.260058]`, admitted**, margin `1.014470x`, ours `148,319,123 ns` vs kernel `34,813,122 ns`, nulls `1.001302`/`1.001865` both clear — against fixed's `4.281783x` and the `5.786301x` baseline, i.e. **`101.9%` of the fixed-spin win**. (b) six-arm within-window A/B on ONE ELF: **`0.741195` `[0.736567, 0.758748]`, `candidate_b_faster`, admitted**, all THREE A/A nulls clear (`0.996655`/`1.009888`/`1.001181`) = `1.349x`; that invocation's own baseline arm reproduced the banked row at `5.780905x`, **`0.09%`** away. The two estimators agree to **`0.75%`** (`5.780905/4.252876 = 1.3593` vs `1.3492`). ⚠⚠ **ATTESTATION GAP, disclosed:** the daemon's knob line reports `receive_spin=0` vs `receive_spin=2000` and **does NOT report the adaptive flag at all** (`knob_divergence_proof=daemon_self_reported_effective_values`, `configurations_differ=true` — but on the spin VALUE). Adaptive's activation in these two runs is attested by the environment the harness set (`candidate_b_env={FFS_FUSE_RECEIVE_SPIN:2000, FFS_FUSE_RECEIVE_SPIN_ADAPTIVE:1}`) plus the independent sparse measurement above, where that same variable on that same ELF moved daemon CPU `1930→260` µs/req. It is NOT attested in-process, and because adaptive and fixed are expected to be identical under a dense stream these wall numbers cannot discriminate them on their own. Fixing the knob line is `bd-087wt`. ⇒ **Adaptive is the shippable version of this lever**: full latency win, same dense CPU as fixed, `~7x` less idle burn — pending that attestation and a quiet-box repeat of the one pathological dense replicate. Post-hoc `external_load_during_run=CONTENDED` on both runs. | `0.999148x`–`1.000954x` | `0.999137x`–`1.005701x` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **1 → 1** on all four arms, pinning attested | **LOSE** |
| **Xattr get/list report** — repeat 2,000 five-call reports: read one inline value, read one external-block value, check one absent name, list one name, list 24 names (ro) | ⭐ **TRANSPORT-INSENSITIVE, CONFIRMED: `5.815136x` `[5.778830, 5.827806]`, ADMITTED**, `--fuse-transport loop` so BOTH arms cross the block layer (48 pairs, nulls `1.000687` spread `1.005109` and `0.999835` spread `1.012771`, `parity=pass`; ours `204,719,189 ns` vs kernel `35,308,904 ns`). Against the file-transport `5.833190x` the ratio moves **`−0.31%`** — our arm `+1.11%`, the kernel arm `+1.27%`, so the loop layer cancels. **This row's figure is NOT an artefact of the asymmetric transport that overturned both parallel-read rows.** **RE-MEASURED 2026-08-26 ON THE SHIPPING ELF `3c7ff854…`** (PGO `c1b9eb9f…`, x86-64-v3, the post-`bd-7s0p7` binary): **`5.833190x` `[5.777235, 5.837400]`, ADMITTED**, margin `1.037283x`, ours `202,461,788 ns` vs kernel ext4 `34,864,954 ns`. ⭐ **THE DEADLOCK FIX IS PERFORMANCE-NEUTRAL HERE:** our arm is `202,461,788 ns` against the old ELF's `201,575,922 ns` — **`+0.44%`**, inside noise. The `KernelNotifyQueue` thread costs nothing on a read-only path, which is what it should do since no invalidation is issued. ⭐ **The adaptive spin reproduces across ELFs:** within-window six-arm A/B **`0.736408` `[0.734440, 0.741343]`, `candidate_b_faster`, admitted**, all THREE A/A nulls clear (`0.996282`/`0.998134`/`0.997633`) = `1.3579x`, against the old ELF's `0.741195` = `1.3492x` — `0.65%` apart. Arms: spin=0 `201,223,394`/`205,372,287 ns`, spin+adaptive `148,815,564`/`149,297,445 ns`. ⭐ **AND THE SPIN ARM IS NOW MEASURED ON THIS ELF, NOT INFERRED: `4.215776x` `[4.197167, 4.219650]`, ADMITTED**, `verdict=HONEST_LOSS`, margin `1.014593x` (the tightest nulls of the session — `0.999868` spread `1.003672` and `1.001909` spread `1.007270`), ours `146,591,097 ns` vs kernel ext4 `34,901,579 ns`, daemon self-reporting `receive_spin=2000`. The arithmetic band published before the row was taken said `4.2955x`; the measurement came in `1.86%` BETTER, and sits `0.87%` from the `4.252876x` measured directly on the old ELF. Two estimators for the lever: direct `5.833190/4.215776 = 1.3837x`, within-window A/B `1.3579x` — `1.9%` apart. Fourth 1-thread row to obey the concurrency scope rule. **≈`5.93–5.98x` slower.** THREE admitted same-ELF runs 2026-08-25, `verdict=HONEST_LOSS`: `5.978094x [5.928505, 5.982041]`, `5.934653x [5.932786, 5.967857]`, `5.983909x [5.896958, 6.001141]`, margins `1.037710x`/`1.011434x`/`1.041444x`. A FOURTH admitted run 2026-08-25 measured `5.715105x [5.666602, 5.722846]` (margin `1.013444x`) in a much quieter window with `perf` attached to the daemon for 18 s of it, widening the honest band to **`5.72–5.98x`, spread `4.70%`**. **Quote the spread, not any one CI.** ⛔ SUPERSEDES `5.749816x` (this row is ~4% WORSE, not better). Candidate ELF `9b1517b8…` (PGO `f8a9d574…`, x86-64-v3, in-process self-report). **Absolute medians** (run 2): ours `217,218,022 ns`, kernel ext4 `36,570,745 ns`. **ATTRIBUTED 2026-08-25, COUNTED with `bpftrace` on `fuse_getxattr`/`fuse_listxattr` across three comparator invocations:** the workload's own 880,020 xattr syscalls (`user.inline` 176,004 + `user.external` 176,004 + `user.absent` 176,004 + `listxattr` 352,008) were accompanied by **902,231 kernel-issued `security.capability` GETXATTRs — `1.02524` per user xattr syscall**, i.e. `50.62%` of every FUSE xattr crossing on this mount is Linux AUDIT asking on its OWN behalf, not the caller's. `fuse_getxattr` saw NO name other than those four (`getxattr_total` 1,430,243 = 528,012 + 902,231 exactly). **Same mechanism as warm stat** (`bd-z0rb8`), here applied to a workload that ALSO crosses on its own behalf, so it pays the probe per CALL rather than per stat. ⇒ half this row is the closed audit door: `ENOSYS` suppression (`FFS_FUSE_XATTR_NO_SUPPORT`) is connection-wide and would break the workload it is measuring, and `FFS_FUSE_XATTR_PROVEN_ABSENT_SHORTCIRCUIT` is refused because this fixture's inodes DO carry xattrs. **ARITHMETIC, NOT A MEASUREMENT:** at an equal per-crossing cost the audit probes are ~50% of the `180,647,277 ns` gap, putting the floor for any daemon-side lever near `3x`. ⚠ `get_vfs_caps_from_disk` is host-wide and was dominated by other tenants (36.7M) — it is NOT usable as our counter; `fuse_getxattr` is. **THE NON-AUDIT HALF IS ALSO NOT OURS — PROFILED 2026-08-25** (`perf record -g -F 997` attached to the live FrankenFS daemon for 45 s during an admitted run, 4,220 samples): by DSO the daemon is **`92.10%` kernel, `5.41%` `ffs-cli`, `1.30%` vdso, `1.19%` libc**. Inside `ffs-cli` the top symbols are all vendored-`fuser` transport plumbing (`Request::dispatch` `0.63%`, `Session::dispatch_next` `0.60%`, `Request::parse` `0.56%`, `ReplyRaw::send_ll_mut` `0.44%`); **FrankenFS's own handlers are `FrankenFuse::getxattr` `0.52%` + `FrankenFuse::listxattr` `0.08%` = `0.60%` of the daemon's CPU.** The kernel side is the FUSE round trip itself — `entry_SYSRETQ_unsafe_stack` `5.87%`, `fuse_dev_do_read` `2.38%`, `fuse_dev_do_write` `1.33%`, `fuse_copy_fill` `1.21%` — plus ~`15%` of CFS bookkeeping (`dequeue_entity` `4.83%`, `update_load_avg` `3.06%`, `update_curr` `2.33%`, `update_entity_lag` `1.92%`, `dequeue_entities` `1.87%`) from the daemon SLEEPING AND WAKING once per request, and the daemon's own audit tax (`audit_reset_context` `1.28%`, `__audit_syscall_exit` `1.23%`, `auditd_test_task` `1.16%`). The whole-handler timer puts dispatch at `1,198,988,879 ns / 704,057` requests = **`1,703 ns` per request, `16.49%` of the arm's timed wall**, so all `ffs-cli` userspace is ~`0.89%` of our arm and FrankenFS's xattr handlers are ~`0.10%`. ⇒ **A DAEMON-SIDE XATTR LEVER CANNOT MOVE THIS ROW.** The read-only xattr cache's mutex + linear `Vec` scan + `Vec<u8>` clone per hit is real and was NOT optimized, because at `0.10%` of wall it is unmeasurable. The one lever the profile DOES point at is the per-request scheduler wake — `FFS_FUSE_RECEIVE_SPIN`. **MEASURED 2026-08-26 AND IT IS A WIN.** (a) Within-window candidate A/B, ONE ELF `9b1517b8…`, six-arm Williams square, arms differing only in `receive_spin=0` vs `receive_spin=2000` (daemon self-reported): **`candidate_b_over_candidate_a = 0.731107` `[0.727319, 0.745204]`, `verdict=CANDIDATE_B_FASTER`, admitted, margin `1.012835x`** — `1.368x` faster. All THREE A/A nulls clear (kernel `1.002456` spread `1.013958`; candidate A `1.000041` spread `1.006296`; candidate B `1.000288` spread `1.006397`). Absolute arms: spin=0 `201,715,150`/`202,837,744 ns`, spin=2000 `147,561,998`/`148,020,982 ns`, kernel `34,917,914`/`34,932,616 ns`; the shipping arm's own vs-kernel row in that same invocation was `5.786301x [5.652226, 5.827487]`, admitted. (b) The spin arm priced DIRECTLY against the live kernel, four arms, `FFS_FUSE_RECEIVE_SPIN=2000` on both fuse arms: **`4.281783x` `[4.246970, 4.298567]`, admitted, `verdict=HONEST_LOSS`, margin `1.024963x`**, ours `149,220,172 ns` vs kernel ext4 `34,894,573 ns`, nulls `0.999194`/`1.006482`. The two estimators agree to `1.2%` (`5.786301/4.281783 = 1.3514` vs the A/B's `1.3678`). **MECHANISM CONFIRMED:** the whole-handler timer is unchanged by the lever — `704,057` requests and `1,198,988,879 ns` at spin=0 against `704,057` and `1,231,073,031 ns` at spin=2000 — so the win is entirely in the RECEIVE path the daemon spends outside the handler, exactly where the profile put the CFS bookkeeping. ⚠ NOT PROPOSED AS A DEFAULT. **⛔ THE SPIN'S COST IS NOW MEASURED (2026-08-26, `bd-3d2c0`) AND IT IS LARGE.** Daemon-resource measurement on a separate rig (16 MiB e2e ext4 image, `ffs-cli mount --no-background-scrub`, python `os.stat` driver, daemon's OWN accounted `utime+stime` from `/proc/<pid>/stat`, ABAB, 2 replicates per arm at each N): daemon CPU per request is **`8.00`/`8.00` µs at `spin=0` and `18.50`/`19.00` µs at `spin=2000`** (N=20,000), replicating at **`8.133`/`8.267` vs `17.667`/`17.667` µs** (N=150,000, `CLK_TCK=100` so quantization is negligible). That is **`2.16–2.34x` the daemon CPU, `+9.5` to `+10.8` µs per request.** Against it, the admitted warm-stat win is `22,616,482 → 18,137,291 ns` over 2,000 stats = **`−2.24` µs of wall per stat**. So the spin spends roughly **`4.2–4.8` µs of extra daemon CPU per `1` µs of latency it saves.** The win is real as LATENCY on an otherwise-idle core and is a large net loss as THROUGHPUT/EFFICIENCY; on a shared or CPU-contended host it takes from other tenants what it gives to this one. **It must not become a default in fixed mode.** ⚠ That rig is not the comparator: its own wall figures are noisy (`19.0–30.3` µs/stat for the SAME config at host loadavg 145–190) and are NOT used here — the latency side comes only from the admitted comparator rows above. What transfers is the CPU RATIO, which replicated to within `1.6%`. **ADAPTIVE MODE MEASURED TOO (2026-08-26), and the SPARSE negative control is the decisive one.** Same rig, 1,000 stats paced at ~100/s over 10 s, 2 replicates: daemon CPU per request is `10`/`20` µs at `spin=0`, **`1930`/`1484` µs at fixed `spin=2000`** — i.e. the fixed spin burns **`14.8–19.3%` of a core to serve 100 requests/second**, `74–193x` `spin=0` — and `260`/`231` µs with `FFS_FUSE_RECEIVE_SPIN_ADAPTIVE=1`. So the decay is REAL and large (**~`7x` off the idle burn**) but does not reach `spin=0`: adaptive is still `12–23x` `spin=0` when requests are sparse. Under a DENSE stream adaptive costs the same as fixed (`17.8` vs `17.4` µs/req), which is the intended behaviour — it holds the budget while spinning pays. ⚠ One of two dense adaptive replicates went pathological at `72.6` µs/req (4x fixed) on a host at loadavg 164; recorded, not explained. ⭐ **ADAPTIVE'S WALL WIN IS NOW VERIFIED ON THE COMPARATOR (2026-08-26), TWO ESTIMATORS, AND IT RETAINS ALL OF FIXED'S WIN.** (a) direct vs live kernel ext4 with `FFS_FUSE_RECEIVE_SPIN=2000 FFS_FUSE_RECEIVE_SPIN_ADAPTIVE=1` on both fuse arms: **`4.252876x` `[4.246624, 4.260058]`, admitted**, margin `1.014470x`, ours `148,319,123 ns` vs kernel `34,813,122 ns`, nulls `1.001302`/`1.001865` both clear — against fixed's `4.281783x` and the `5.786301x` baseline, i.e. **`101.9%` of the fixed-spin win**. (b) six-arm within-window A/B on ONE ELF: **`0.741195` `[0.736567, 0.758748]`, `candidate_b_faster`, admitted**, all THREE A/A nulls clear (`0.996655`/`1.009888`/`1.001181`) = `1.349x`; that invocation's own baseline arm reproduced the banked row at `5.780905x`, **`0.09%`** away. The two estimators agree to **`0.75%`** (`5.780905/4.252876 = 1.3593` vs `1.3492`). ⚠⚠ **ATTESTATION GAP, disclosed:** the daemon's knob line reports `receive_spin=0` vs `receive_spin=2000` and **does NOT report the adaptive flag at all** (`knob_divergence_proof=daemon_self_reported_effective_values`, `configurations_differ=true` — but on the spin VALUE). Adaptive's activation in these two runs is attested by the environment the harness set (`candidate_b_env={FFS_FUSE_RECEIVE_SPIN:2000, FFS_FUSE_RECEIVE_SPIN_ADAPTIVE:1}`) plus the independent sparse measurement above, where that same variable on that same ELF moved daemon CPU `1930→260` µs/req. It is NOT attested in-process, and because adaptive and fixed are expected to be identical under a dense stream these wall numbers cannot discriminate them on their own. Fixing the knob line is `bd-087wt`. ⇒ **Adaptive is the shippable version of this lever**: full latency win, same dense CPU as fixed, `~7x` less idle burn — pending that attestation and a quiet-box repeat of the one pathological dense replicate. Post-hoc `external_load_during_run=CONTENDED` on both runs. | `0.999148x`–`1.000954x` | `0.999137x`–`1.005701x` | **1 → 1** on all four arms, pinning attested | **LOSE** |
| **Bulk durable write** — overwrite one preallocated 64 MiB file with 64 sequential 1 MiB positioned writes, then one file `fsync` (**2,048 pairs / 512 crossover blocks**) | **`2.898298x` `[2.874382, 2.920502]` slower** (twice-null margin `1.035235x`) — ⚠ **this interval is within-invocation only; a second admitted run of the identical ELF measured `2.655365x`, so quote this row as ≈`2.7–2.9x`, never to its own CI** | `1.001588x [0.997161, 1.009249]`, spread `1.009249x` | `0.989118x [0.982835, 0.994415]`, spread `1.017465x` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **1 → 1** on all four arms, pinning attested | **LOSE** |

Admission required, per row: both A/A symmetric spreads at most `1.025x` with intervals
containing `1.0`; the effect clearing **twice the widest null log-margin**; exact
four-arm tree and content parity; and a clean offline `e2fsck` after unmount. All five
rows satisfied all four. Wall time was the gate throughout — `cv_used=false`,
`instructions_used=false` — over deterministic 20,000-resample bootstrap median CIs.

**The xattr row was measured later than the rest and does not share their window.** It was
taken 2026-08-05 on kernel `6.17.0-41-generic` (the other rows: `6.17.0-35-generic`) with
candidate ELF `bcf2bc80f02154aa16681b87c64e1beddab996b20cc0bb5ec911b5743133c9d1`, PGO
profile `5c6530a0261f658ed0ace2a9d8bef7c6c63b6f94b4b955e4f7ccba038e011e96`, 32 pairs / 8
crossover blocks, `observation_reducer=min` over 3 repeats. Its own kernel arm is live in
its own invocation, so the ratio stands on its own; it is **not** pooled with the rows
above and must not be diffed against them as if one window produced both.

**Btrfs: UNRUNNABLE for this workload, by the harness's own refusal**, not by omission —
`xattr-get-list-report currently requires --filesystem ext4 because its inline/external
storage-shape proof is ext4-specific`. Recorded the way the btrfs fsync row was.

**The bulk durable write row also stands in its own window** (2026-08-05, kernel
`6.17.0-41-generic`, candidate ELF `bcf2bc80…`), and it needed **2,048 pairs** to be
admitted: this workload's variance is the durability boundary itself, since a mutating
workload is forced to `--observation-repeats 1` and has no min-of-3 to lean on. The
progression is worth recording so nobody re-derives it — 32 pairs blocked on both null
medians, 64 pairs fixed the medians but left spreads at `1.034978`/`1.053581`, 512 pairs
reached `1.021700`/`1.027309` (still over the `1.025` limit by a hair), and 2,048 pairs
cleared at `1.009249`/`1.017465`.

⚠ **This row is `2.898298x` where the 2026-07-31 ledger row measured `2.201986x`** for the
same job shape — about **32% worse**. Different candidate ELF, different kernel, different
window, so it is *not* proof of a regression, but it is the same instrument and contract on
both sides and the gap is far outside either interval. Filed as `bd-2i2ez` to be resolved by
measurement rather than assumed either way. The older figure should not be quoted as current.

⚠⚠ **This row's cross-window reproducibility is `9.15%`, about 3x its own admission margin,
and the variance is on the INCUMBENT side** (`bd-2i2ez` step 1, 2026-08-06). A second
2,048-pair run of the **identical** candidate ELF `bcf2bc80…`, PGO `5c6530a0…`, kernel
`6.17.0-41-generic` and `performance`/`performance` governor is also admitted
(`verdict=HONEST_LOSS`) and measures **`2.655365x` `[2.641224, 2.672899]`**. Absolute arm
medians across four runs of that one ELF, inside one ~2-hour span:

| Window | Pairs | Kernel arm | FrankenFS arm | Ratio | Admitted |
| --- | --- | --- | --- | --- | --- |
| 20:53 | 64 | 78.42 ms | 232.11 ms | `2.837345x` | no (`BLOCKED_NULL`) |
| 21:04 | 512 | 77.05 ms | 225.22 ms | `2.910966x` | no (`BLOCKED_NULL`) |
| 21:46 | 2,048 | 77.31 ms | 225.31 ms | **`2.898298x`** | yes — the row above |
| 22:57 | 2,048 | 83.69 ms | 222.39 ms | **`2.655365x`** | yes |

**FrankenFS is the stable arm** — 232.11 / 225.22 / 225.31 / 222.39 ms, the three
larger-pair runs agreeing to `1.3%`. The kernel ext4 arm holds 77.05 / 77.31 / 78.42 ms and
then moves to 83.69 ms, `+8.26%`. Between the two admitted runs our arm moved `−1.30%` and
the incumbent moved `+8.26%`, so **the whole ratio swing is the incumbent, not us.**

⚠⚠⚠ **A fifth run extends the incumbent's range to `+18.3%`** (recovered 2026-08-08 from
the surviving `bd-2i2ez` window-1 log, the only comparator log that outlived the scratch
deletion). Same workload shape (`bulk_durable_write`, 64 ops/observation, 2,048 pairs, 512
crossover blocks), same kernel `6.17.0-41-generic`, same `performance`/`performance`, and it
too printed `verdict=clear` with `driver_busy_fraction=0.000000` /
`fuse_busy_fractions=0.000000` and was admitted `HONEST_LOSS`:

| Window | Kernel arm | FrankenFS arm | Ratio | Candidate ELF |
| --- | --- | --- | --- | --- |
| 21:46 | 77.31 ms | 225.31 ms | `2.898298x` | `bcf2bc80…` |
| 22:57 | 83.69 ms | 222.39 ms | `2.655365x` | `bcf2bc80…` |
| 2026-08-06 w1 | **91.43 ms** | 222.22 ms | `2.430234x` | **`d34b21c0…`** |

**Read this carefully, because half of it counts and half of it does not.** The third run's
candidate ELF is *different*, so its **ratio is not a same-ELF replicate** and must not be
folded into the `9.15%` figure — that number still stands on the two `bcf2bc80…` runs alone.
But the **kernel arm does not execute our binary at all**, so its absolute median is a
legitimate third observation of the incumbent: 77.31 → 83.69 → 91.43 ms, a monotone `+18.3%`
climb across three gate-clear windows on one kernel, while our arm sat at 225.31 / 222.39 /
222.22 ms, agreeing to `1.4%`. The one confound worth naming is that the arms run
interleaved in the crossover, so a different candidate could in principle change the
interference the kernel arm sees — but our arm measured 222.22 ms here, inside the banked
222–232 ms band, so the co-load was comparable.

**The incumbent-side drift is therefore larger than this file previously said, and it is
the recorded absolute medians that made it visible.** Had the xattr row carried its own,
the same question could be asked of it; it cannot.

The consequence is general and not specific to this row: **the admission contract bounds
within-invocation error only.** A/A nulls and the twice-null margin say nothing about
whether the same ELF re-measures to the same ratio next window, and here it does not, by
3x the margin. Any row quoted to its own CI across windows is over-precise. Neither
bulk-durable figure is marked superseded — both are admitted under one contract, so
choosing between them would be selection, not measurement.

**Btrfs bulk durable write: UNMEASURED — no longer unrunnable.** The defect that blocked it
is FIXED (`bd-cjqhh`, closed 2026-08-06 in `839eb708`): the durable commit built leaves it
could not serialize, so `fsync` returned EINVAL and the unmount flush failed the same way,
meaning the data was never persisted at all. A mounted 64 MiB run — the full comparator job
shape — now completes with `fsync` OK and every chunk byte-identical across unmount and
remount.

**What is missing is the measurement, not the capability.** No btrfs bulk-durable-write ratio
has been taken since the fix, so this scorecard carries no such row and none may be quoted.
The prior text here read "UNRUNNABLE … by a DEFECT" and was correct when written; it is
retained only in history. For the record, the failure it described was
`fsync bulk durable workload …/btrfs/fuse_a/bulk-durable.bin: Invalid argument (os error 22)`
while the ext4 arm of the identical invocation completed.

Producing the row needs a quiet window and a v3+PGO build; it is measurement work, tracked
under the perf umbrella, and it is explicitly NOT claimed here.

## One sentence per row

- **Large-directory readdir+stat: we lose.** The kernel finishes the same 32,768-entry
  stat sweep about **four** times faster (28.0–29.0 ms against our 115.6–117.0 ms).
  Re-measured 2026-08-08 on a corrected, genuinely htree-indexed fixture (`bd-plkzd`); the
  old "about five times" figure came from a fixture no real ext4 filesystem has and is
  withdrawn. ⚠ **The correction moved this number in our favour, and the delta is NOT
  attributable to the fixture** — the candidate ELF, the PGO profile, the kernel version and
  the window all changed too. What the recorded absolutes do narrow: our arm moved `+3.1%`
  against the old row while the *kernel* arm moved `+26.9%`, and the kernel arm does not
  execute our binary, so the ELF and profile change cannot explain any of it. A plausible
  mechanism, untested: an htree makes `readdir` return **hash** order, scattering the
  subsequent stat pass across the inode table, where a linear directory returns creation
  order — which is also inode-allocation order — and therefore walks it sequentially. On that
  reading the old fixture flattered the *incumbent*, which is what inflated our published
  loss. **`bd-plkzd`'s predicted direction is confirmed**: it said the defect inflates the
  ext4 ratio and therefore *understates* the btrfs/ext4 ratio-of-ratios, and on the corrected
  fixtures that quantity moves `1.675x → 1.887x`. Only its intermediate phrasing ("inflates
  the ext4 arm") is imprecise — **both** arms were faster on the unindexed fixture; the
  kernel arm was just disproportionately so, which shrank the denominator. Attribution still
  needs a same-window A/B of the two fixture constructions on one ELF: `bd-pb85e`.
- **Small-file create/delete storm: we lose.** Creating and deleting 2,000 files with
  two directory fsyncs takes us about 2.75 times as long as ext4.
- **Multi-file parallel read: we TIE.** Re-measured 2026-08-08 on the corrected fixture and
  a current ELF: `0.986316x` and `0.978203x`, both admitted `HONEST_NEUTRAL`, neither
  clearing its margin. The banked "about 29% slower" is withdrawn.
  **This is not a FrankenFS improvement story, and it must not be told as one.** The arms:
  kernel `3.110 → 3.803` ms (**+22.3%**), ours `4.010 → 3.809` ms (**−5.0%**). Four fifths of
  the movement is the incumbent getting slower, not us getting faster — and `+22.3%` sits
  inside the `±18.3%` incumbent drift this file already documents, with a kernel version
  change (6.17.0-35 → 6.17.0-41) on top.
  The fixture fix is *not* the explanation either, and the direction is what rules it out: an
  htree makes this workload's 256 `File::open` lookups **cheaper** than a linear two-block
  scan, so correcting the fixture should have made the kernel arm *faster*. It got slower.
  The extent layout is separately verified identical under both constructions
  (`scripts/cmp_extent_layout_probe.sh`), so data layout is excluded too.
- **Fsync/journal commit: we neither win nor lose.** The measured `0.997098x` is a tie —
  it sits well inside the twice-null margin, so we are declaring no effect, not a win.
- **Warm stat: we lose, and not because of btrfs.** About 4.81 times slower — the kernel
  takes 4.42 ms for 2,000 warm `stat` calls where we take 21.30 ms. The btrfs bank measures the same shape
  at `4.977803x`, so the two agree to within 3.4%: this loss is the shared per-request
  FUSE floor, not btrfs inode lookup. That matters for where to spend effort — and it
  means the btrfs readdir+stat excess over ext4 (`8.32x` vs `4.97x`) is the part that
  really is btrfs-specific.
- **Parallel metadata writes: we lose.** Eight workers creating 512 files and fsyncing
  their directories run about 1.51 times slower than ext4, reproduced twice on disjoint
  CPU sets.

## Numbers that are withdrawn and must not be restated

- **The `8.3x` parallel-metadata figure is folklore and is retired.** It came from
  *separate* runs, never from a matched same-invocation comparison, and no instrument
  that produced it survives. The honest, admitted figure for that workload is
  **`1.512x` slower**.
- **`1.942477x` for parallel metadata writes is withdrawn.** It was overstated by about
  28% relative to the two admitted 128-block runs, and it came from a run whose kernel
  arm drifted `2.64x` within itself.
- **The fsync `1.005153x` win is withdrawn, not softened.** Re-measured it is
  `0.997098x` with `directional_claim_clear=false`; it was always a sub-null-margin
  effect.

Two of the losses got **worse**, not better, once the instrument was correct: readdir
moved `4.212274x → 4.967448x` and read moved `1.203230x → 1.287862x`. Pinning made the
*kernel* arm faster by preserving locality, so a correct instrument flatters the
incumbent. Storm moved the other way, `2.957531x → 2.753659x`.

## Absolute arm medians — REQUIRED per row, never a gate (`bd-4sull` item 3)

**Not a gate and not a claim** — `gate_input=false` for every value here. But **required
to be recorded**, which is a different thing from being optional: a row that banks only its
ratio cannot be diagnosed later, because a ratio is a quotient and cannot say which arm
moved. That is not hypothetical. The 2026-07-31 bulk-durable-write row transcribed only its
ratio; when it disagreed with the 2026-08-05 row by 32%, answering "was that us or the
incumbent?" required an entire re-run (`bd-2i2ez`) that a recorded kernel-arm median would
have made arithmetic. The report it would have come from has since been deleted
(`bd-v0igv`), so that number is gone permanently.

The harness already emits both, on the `mounted_kernel_throughput` line as
`kernel_median_wall_ns` and `fuse_median_wall_ns`. The gap was never measurement — it was
transcription. **Every future row must carry both**; `scripts/perf_ledger_preflight.py
--lint` refuses a new mounted-comparator ledger row that omits them.

| Workload | Kernel median batch | FrankenFS median batch |
| --- | --- | --- |
| Large-directory readdir+stat, 32,768 entries | **28.98 / 27.99 ms** (runs 1/2) | **117.00 / 115.62 ms** (runs 1/2) |
| Small-file create/delete storm, 2,000 files | **94.807 ms** (2026-08-08; was 100.99 ms) | **264.732 ms** (2026-08-08; was 276.60 ms) |
| Multi-file parallel read, 256 × 256 KiB | **3.803 / 3.917 ms** (runs 1/2, 2026-08-08; was 3.11 ms) | **3.809 / 3.847 ms** (runs 1/2; was 4.01 ms) |
| Fsync/journal commit, 8 × 4 KiB | 145.49 ms | 145.08 ms |
| Parallel metadata writes, 512 creates | 29.30 ms | 42.31 ms |
| Warm stat, 2,000 calls | **4.532 / 4.502 ms** (runs 1/2, 2026-08-08; was 4.42 ms) | **21.893 / 21.891 ms** (runs 1/2; was 21.30 ms) |
| Xattr get/list report, 2,000 five-call reports | ⛔ **not recorded** | ⛔ **not recorded** |
| Bulk durable write, 64 × 1 MiB + fsync | 77.31 ms | 225.31 ms |

**The xattr row is the one that got away.** It was banked with its ratio only, and its
report was deleted with the rest of the comparator scratch (`bd-v0igv`) before this
requirement existed. Nothing in the tree or in surviving logs carries either arm's absolute
median for it, so the row cannot be diagnosed the way bulk durable write was — its `5.749816x`
is un-decomposable into "our cost" and "the incumbent's cost" until it is re-run. **1 of 8
rows is unrecoverable; the other 7 are complete.**

## Replication

- **readdir** replicated at `5.026341x` on a second driver ELF in a second window,
  within **1.2%** of the banked `4.967448x`.
- **storm** replicated **3/3** on a single driver ELF at `2.760102x`, `2.780381x`,
  `2.795147x`, reproducing within **1.3%**.
- **parallel metadata writes** replicated on a **disjoint** CPU set
  (`24,25,26,29,31,56,59,60` versus `0,1,5,6,33,34,35,39`) at `1.513052x`, agreeing with
  the banked `1.510822x` to **0.15%**.
- **read** and **fsync** are each one admitted run at this exact shape.

## Provenance of the warm-stat row (2026-08-04, differs from the other five)

Candidate ELF `9e32e28f766368dd738c7d43e2d4f820a426394b0d1e72b6e565be622835408a`
(x86-64-v3, PGO profile `5c6530a0261f658ed0ace2a9d8bef7c6c63b6f94b4b955e4f7ccba038e011e96`),
driver ELF `8c1c4d35fd0a348e5e612d904f086567a4bd9f03a800127ff1ebedb6a2f2633f`, both
self-hashed in process. `pairs=32`, `observation-repeats=3` reduced by `min`, parity
`pass`, post-unmount `e2fsck` clean, `--placement-scope same-llc`.

**This row's candidate is NOT the frozen `f44b3dc4…` / PGO `6a22cfcf…` the other five use** —
it is a freshly trained profile, so the warm-stat number is not byte-identical-candidate
comparable with them. It is directly comparable with the btrfs warm-stat row, which is the
comparison it was taken for. Unlike the other five it also ran with every CPU on the
`performance` governor, so it carries no mixed-governor warning.

## Scope and limits of these five claims

- **Provenance.** Candidate ELF
  `f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349` (x86-64-v3, PGO
  profile `6a22cfcf…`, built on `vmi1167313`); driver ELF `75b400a9…` for the first four
  rows and `8c357460…` for both metadata rows, both built on `hz1`. Every arm
  self-hashed in process.
- ⛔ **Reports NO LONGER retained.** This bullet used to say the reports live under
  `/data/tmp/frankenfs-mounted-kernel-nullfix/run_*/mounted-kernel-report.json`
  (schema v5). That tree is **gone** — verified 2026-08-08: the directory does not
  exist, no `mounted-kernel-report*.json` survives anywhere under `/data/tmp`, and
  the volume moved from ~90% full to 696G free. The disk-pressure reclaimer did not
  distinguish the ~1.4 MiB of reports from the ~133 GiB of regenerable arm images,
  and the `.sbh-protect` marker that now guards report directories
  (`protect_report_dir_from_reclaim`) landed after these runs (bd-v0igv).
  **What this does and does not mean:** the ELF hashes, PGO profile, builder hosts
  and per-arm self-hashing above were transcribed into this document at the time and
  are unaffected. What is unavailable is the raw report JSON behind them, so these
  rows can no longer be re-derived from their artifacts or re-examined for fields
  the scorecard did not transcribe. Do not read the dead path as evidence the rows
  were fabricated, and do not treat them as re-verifiable — they are transcribed
  results whose backing artifact is lost. The btrfs scorecard carries the identical
  loss for all six of its rows.
- **Placement scope was `same_llc`, not host-wide.** `host_wide_quiescence` reads
  `not_applicable` on all five rows: the sustained five-consecutive-one-second host-wide
  quiet gate exists in the harness but only engages under `--placement-scope host-wide`,
  and it did not gate these runs. What did apply on every row: per-CPU busy fractions
  averaged over a **full one-second** interval, driver and FUSE busy-limit checks, SMT
  sibling guards on both, same-LLC placement, and a 1,000 ms pre-measurement settle.
- **What the one host-wide-scoped window says about that caveat.** The 2026-07-29
  governor-attested runs *did* run `--placement-scope host-wide` with the sustained
  five-consecutive-one-second gate clearing (`samples_observed` 106 and 55). Only
  **storm** was admitted there, at `2.691204x [2.675323, 2.717540]` and
  `2.676393x [2.657974, 2.701633]` — same verdict as the row published above and within
  about 3% of its `2.753659x`. That is corroboration of direction and rough magnitude,
  **not** a controlled scope comparison: those runs used a different candidate
  (`93ed…` / PGO `1410…`) and a different driver, and they predate worker pinning, which
  is why read and readdir were `blocked_null` in the same window. No host-wide-scoped
  admitted row exists for any of the other four workloads.
- **The governor was recorded, not set.** All 64 CPUs ran `amd-pstate-epp` with the
  `powersave` governor; the host is shared with other agents, so it was deliberately
  left alone and `non_performance_or_mixed_governor_warning=true` is carried on every
  row. EPP was uniform across the CPUs each row actually used, but it was
  `balance_performance` for the first four rows and `performance` for the two metadata
  runs, because the host-wide setting changed between the two windows.
- **These are not the frozen-candidate host-wide rerun.** A separate assignment in
  thread `bd-kdmu4` calls for the original shapes re-run with candidate `93ed…` / PGO
  profile `1410…` under `--placement-scope host-wide`. These five rows use candidate
  `f44b…` / PGO `6a22…` — the same profile the 2026-07-27 rows used, which is what makes
  this bank comparable to what it replaces. They are the current pinned bank, and the
  schema-v6 gate correction landed in `2198a47d` leaves their score unchanged.
- **Scope of the claims.** Each row applies only to its recorded operation count, thread
  count, durability shape, mount options, warm-cache regime, host, and ISA. Do not
  generalize any of them to other working sets, thread counts, or hardware.

## Retry predicate

Re-measure only with every timed thread — driver included — bound to one CPU, at least
32 crossover blocks (**128** for parallel metadata writes, which does not resolve at
32), both A/A spreads at most `1.025x`, the effect clearing twice its own null
log-margin, exact four-arm parity, and clean `e2fsck`. Never pool the blocked
`1.509x`–`1.688x` metadata estimates, and never restate `1.942477x`, the withdrawn fsync
`1.005153x` win, or the `8.3x` folklore.
