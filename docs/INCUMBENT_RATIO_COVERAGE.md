# Incumbent-ratio coverage: how much of what we claim is competitive evidence

**Date:** 2026-07-31 · **Bead:** `bd-opb6l` · **Re-runnable as**
`python3 scripts/perf_ledger_preflight.py --incumbent-audit`

A self-speedup is a claim about our own previous build. It says nothing about whether an
operator should choose FrankenFS over what they already run. Only a ratio whose
denominator is the incumbent — with the incumbent arm executing **live in the same
invocation** — is a competitive claim. This file counts how many of ours are.

## The three numbers

| | count |
| --- | --- |
| KEEP claims held across both ledgers | **678** |
| ...carrying a vs-incumbent ratio with the incumbent **live in the same invocation** | **5** |
| ...**not** carrying one | **673** |

**0.7%.** That is the honest figure and it is far worse than the `67 of 186` (36%
un-ratioed) previously published on 2026-07-30.

The two numbers are not comparable, and the difference is itself a finding:

- The earlier census asked *"does this row's ratio column contain any figure against
  ext4/btrfs-kernel?"* — which a quoted number satisfies. It was also computed by a
  one-off script whose scope **cannot be reproduced today**: no scoping in that script
  yields 186 from either ledger (whole-ledger KEEP is 678; the 8-column table region is
  260). A census that lives in a scratch script decays into folklore within a week.
  This one is a subcommand, so the number can be re-derived and challenged.
- This census applies the stricter predicate: the incumbent arm must have **run**, in the
  same invocation, for that row.

### The gap between the two predicates, quantified

| Provenance of the incumbent denominator | count |
| --- | --- |
| `live_same_invocation` — incumbent arm executed in the same process | **5** |
| `quoted_or_adjacent` — an incumbent number appears, inherited from another run | 176 |
| `none` — no incumbent number at all | 497 |

The 176 are the trap. They read like competitive claims and are not. The dominant idiom
is a row that speeds up an internal primitive and then appends *"live `bd-bhh0i` context
remains ext4 parallel create/write `0.120x` kernel throughput (`8.32x` slower)"*. That
`8.32x` is inherited context, restated across dozens of rows, from a run that produced
neither arm of the row quoting it. It has since been **withdrawn as folklore**
(`docs/MOUNTED_KERNEL_SCORECARD.md`) — but the rows that quote it still carry it.

### One hand-checked correction to the classifier

Three rows (`docs/NEGATIVE_EVIDENCE.md:88`, `:91`, `:92`) match a bare `A/A/B` token and
were initially classified `live_same_invocation`. Reading them, the `A/A/B` is the
**internal** frozen-control-vs-candidate design; the kernel figure in each
(`~27x`, `348.171x` slower, `33.842x` faster) came from a separate comparison. They are
`quoted_or_adjacent`. The predicate now requires the comparator instrument by name, so
those three no longer pass. All 5 survivors were confirmed by hand.

## What the 5 rows actually contain

The row count understates the measurement count: those 5 rows and the two scorecards they
feed hold **12 admitted competitive ratios** over 7 workload shapes on 2 filesystems.
This is everything the campaign has that is genuinely competitive:

| Workload | vs kernel ext4 | vs kernel btrfs |
| --- | --- | --- |
| Large-directory readdir+stat, 32,768 entries, 8t | `4.967448x` slower | `8.322812x` slower |
| Warm stat, 2,000 calls | `5.033559x` slower | `4.977803x` / `5.036433x` slower |
| Small-file create/delete storm, 2,000 files | `2.753659x` slower | `2.358280x` slower |
| Parallel metadata writes, 512 creates, 8t | `1.510822x` slower | `1.930090x` slower |
| Multi-file parallel read, 256 × 256 KiB, 8t | `1.287862x` slower | `0.894290x` / `0.830537x` **faster**, caveated |
| Fsync/journal commit, 8 × 4 KiB | `0.997098x` neutral | **cannot run — `EIO`** (`bd-ftev0`) |
| Xattr get/list whole-job report, 5,000 jobs | `6.059387x` slower | not applicable (ext4-specific fixture) |

**10 losses, 1 neutral, 1 caveated win, 1 workload we cannot execute.** Full provenance,
null controls and retry predicates in [`MOUNTED_KERNEL_SCORECARD.md`](MOUNTED_KERNEL_SCORECARD.md)
and [`MOUNTED_BTRFS_SCORECARD.md`](MOUNTED_BTRFS_SCORECARD.md).

Note that both scorecards live **outside** the two files the audit parses, so the ledger
row count of 5 is not the measurement count. The scorecards are summaries, not decision
rows, which is why they are not in the `LEDGERS` list; the consequence is that the
audited row count and the published ratio count must be read together.

## Why the other 673 are not converted

This is the distinction that decides whether a number is a *debt* or a *dead end*.

| | count | meaning |
| --- | --- | --- |
| `convertible_unmeasured` | **577** | the claim's workload is expressible as a POSIX operation kernel ext4/btrfs also implements. An incumbent arm **can** be built. Nobody has. |
| `not_a_filesystem_claim` | 66 | the row keeps an instrument, an audit, a methodology correction, or a preflight. There is no filesystem performance claim to convert. |
| `no_incumbent_arm_possible` | **2** | the incumbent implements no counterpart operation at all. |
| `unclassified` | 28 | the classifier could not decide; treat as unconverted debt. |

**Almost nothing is a dead end.** Only 2 rows — an `ffs-repair` RaptorQ no-corruption
decode fast path (`NEGATIVE_EVIDENCE.md:513`) and an `ffs-mvcc` sharded conflict-merge
materialization row (`:619`) — sit on surfaces with no incumbent counterpart. RaptorQ
fountain-coded repair has no ext4/btrfs equivalent, so no arm can ever exist.

The precedence rule that produces this is deliberate and is the opposite of flattering:
**convertibility is decided by the claim's workload, not by which subsystem implements
it.** A row that speeds up MVCC publication while making `create` faster is convertible,
because the comparator already has a create workload. Classifying by subsystem instead
moved 232 rows from "we owe a measurement" to "no arm exists" — an excuse, not a finding.

So the honest summary of the backlog is **577 owed measurements and 2 exemptions**, not
the reverse.

### How much of the backlog needs new instrument work

**477 of the 577 name an operation one of the seven existing comparator arms already
covers**, so they need no new instrument — only a run. Rows can name more than one
operation, so these overlap:

| Existing arm | rows naming its operation |
| --- | --- |
| `create-delete-storm` | 251 |
| `parallel-read-8t` | 198 |
| `fsync-journal-commit` | 72 |
| `warm-stat` | 65 |
| `readdir-stat-8t` | 57 |
| `parallel-metadata-write` | 50 |
| `xattr-get-list-report` | 45 |

The remaining **100** need a new workload built first — extent-tree lookups, keyed
backrefs, orphan reclaim, csum-tree cleanup, send-stream generation, queued repair.
`btrfs send` is a real incumbent operation, so send-stream rows are convertible in
principle; we simply have no send arm.

## The standing rule this produces

No ledger row may describe itself as a competitive result unless
`incumbent_denominator() == "live_same_invocation"`. Quoting an inherited kernel number as
context is allowed; presenting it as this row's ratio is not. The audit is re-runnable, so
this number can be tracked rather than re-discovered.
