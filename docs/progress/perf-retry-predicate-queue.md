# Retry-predicate obligation queue — which blocked rows the 2026-07-30 corrections unblock

A retry predicate is an obligation, not a suggestion. Two corrections landed on
2026-07-30 that can satisfy predicates written earlier:

- **the schema-v6 null gate** (`2198a47d`): a null control clears when its median is in
  `[0.98, 1.02]` **and** its symmetric CI spread is at most `1.025x`. Whether the CI
  contains `1.0` is now telemetry (`ci_contains_one_gate_input=false`). Every predicate
  phrased as *"require both same-invocation median CIs to contain 1"* must be re-read
  against the replacement clause.
- **the timed-thread CPU binding** (`c8a1de55`): every timed thread, driver included, is
  bound to one CPU and the observed CPU set is attested. This is the *counted mechanism*
  several predicates demanded before a retry was allowed.

This file records what those two corrections actually unblock. It is deliberately
short on candidates and long on exclusions, because most predicates are **not**
satisfied and re-running them would be ledger decay.

## 1. Ext4 mounted rows — nothing new is owed

I re-derived the counterfactual myself over every retained comparator artifact rather
than inheriting a count: apply the **old** predicate (spread ≤ `1.025x` **and** CI
contains `1.0`) and the **new** one (spread ≤ `1.025x` **and** median in `[0.98, 1.02]`)
to both A/A controls of every filesystem row, then test the effect against twice the
widest null log-margin.

Two rows change status, and both are the **same workload already published**:

| Artifact | Row | Old | New | Effect vs twice-null margin | Would-be verdict |
| --- | --- | --- | --- | --- | --- |
| `run_1785207688_2739056` | ext4 create/delete storm | straddle-only reject (kernel A/A CI `[1.001744, 1.013361]`) | clears (median `1.009041x`, spread `1.013361x`) | `2.957531x` vs margin `1.026900x` | LOSE |
| `run_1785208354_2831139` | ext4 create/delete storm | straddle-only reject (kernel A/A CI `[1.004432, 1.018412]`) | clears (median `1.009100x`, spread `1.018412x`) | `2.922395x` vs margin `1.037163x` | LOSE |

Both are schema-v1, pre-pinning (`worker_cpu_pinning_clear` absent, observed worker
threads not recorded), so neither is publishable, and both are superseded by the pinned
`2.753659x` row already banked. **Zero new wins, zero new surfaces, zero obligations.**
The correction shows none of the loosening signature that would invalidate it.

## 2. Btrfs — the live obligation, and the only one

Btrfs has **never produced an admitted vs-incumbent ratio**. Three final-ELF attempts on
2026-07-27 were all rejected, and re-reading their recorded nulls against the
replacement clause is decisive — every one of the three was **straddle-only**:

| Attempt | Vetoing null, as recorded | Median in `[0.98, 1.02]`? | Spread ≤ `1.025x`? | Under schema v6 |
| --- | --- | --- | --- | --- |
| First report-preserving combined run | btrfs FUSE A/A CI `[1.001021, 1.002657]` excluded 1 | yes (`≈1.0018x`) | yes (`1.002657x`) | **clears** |
| Second report-preserving combined run | btrfs FUSE A/A `0.996028x [0.994686, 0.998294]` excluded 1 | yes | yes (`1.005342x`) | **clears** |
| Third final-ELF btrfs attempt | btrfs kernel A/A `0.999286x [0.998196, 0.999924]` excluded 1 | yes | yes | **clears** |

Their unadmitted point estimates were `4.931910x`, `4.960432x`, and (superseded-source)
`4.951192x` — clustering within **0.6%** across three independent invocations, which is
what an effect looks like when only the gate, not the physics, was blocking it.

The stated predicate was: *"Retry btrfs only after continuous per-arm CPU attribution or
another counted mechanism explains and removes the alternating kernel/FUSE A/A
asymmetry; then require both same-invocation median CIs to contain 1. A fresh placement
alone is no longer a sufficient retry predicate."* Both halves are now addressable: the
counted mechanism is per-timed-thread CPU binding with observed-CPU attestation, shown
out-of-harness to convert 4 unpinned A/A failures into 4 passes; and the second half is
superseded by the median clause.

**This does not license republishing the old numbers.** Those three artifacts have since
been deleted from `/data/tmp/frankenfs-mounted-kernel/`, they predate worker pinning and
the schema-v6 driver, and pooling unadmitted estimates is forbidden. The obligation is a
**fresh measurement**, not a re-score.

### What the btrfs run must carry

Per standing campaign requirements, and identical to what the five ext4 rows carry:

- the corrected null gate **with the median clause**, `--maximum-null-ratio 1.025`
  unchanged, effect clearing twice the widest null log-margin;
- **actually observed** worker threads per arm, not requested, with pinning attested and
  the observed CPU set equal to the bound set;
- host identity recorded (`thinkstation1`, 32C/64T, kernel 6.17.0-35-generic);
- driver and candidate ELF SHA-256 **self-reported from inside the running process**;
- a driver built by `rch exec --base HEAD --clean-overlay --no-overlay`, so no co-tenant
  agent's working-tree edits can enter the binary;
- four independent live mounts, four-round physical-arm crossover, exact parity, and a
  clean post-unmount `btrfs check`.

Candidate stays frozen at
`f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349` (x86-64-v3, PGO
`6a22cfcf…`), the same candidate as the banked ext4 rows, so the btrfs result is
comparable to them and the only thing that changed is the filesystem arm.

## 2b. The same run also serves the largest incumbent-less claim family

Separately auditing every ledger row that asserts `KEEP`, `MEASURED`, or `WIN` against
its own *"Ratio vs ext4/btrfs-kernel"* column:

| | count |
| --- | --- |
| rows asserting KEEP / MEASURED / WIN | 186 |
| ...carrying **no** vs-incumbent ratio | **67 (36%)** |
| ...of those, btrfs surfaces | **26** |
| ...of those, ext4 surfaces | 11 |
| ...other or unclassified | 30 |

Those 67 are self-speedups: real, gated, reproducible internal A/B wins that say nothing
about whether an operator should choose FrankenFS over the incumbent. The single most
common recorded reason is literally *"no mounted/kernel comparator"*.

The btrfs share of that backlog — extent-tree lookups, keyed backrefs, orphan reclaim,
csum-tree cleanup, send-stream generation, queued repair — is **26 rows with no
incumbent arm in existence**, because btrfs has never scored one. So the btrfs mounted
comparator is not just the one satisfied predicate; it is the measurement that gives an
incumbent denominator to the largest incumbent-less family we hold. Priorities 1 and 2
point at the same run.

## 2c. RESULT — btrfs scores for the first time, and it is a loss

Run executed 2026-07-30 on `thinkstation1`. Report:
`/data/tmp/frankenfs-mounted-btrfs/run_1785468561_3195198/mounted-kernel-report.json`
(schema v6).

| | |
| --- | --- |
| Workload | btrfs `warm-stat`, 2,000 warm `stat` calls per observation, 128 pairs / **32 crossover blocks**, min-of-3 |
| **FrankenFS ÷ kernel btrfs** | **`4.977803x` `[4.949139, 5.014278]` slower** |
| Kernel A/A null | `0.996700x [0.985991, 1.006978]`, spread `1.014208x`, `ci_contains_one=true` |
| FUSE A/A null | `1.002699x [1.000474, 1.009358]`, spread `1.009358x`, **`ci_contains_one=false`** |
| Effect margin | clears twice the widest null log-margin, `1.028617x`; `directional_claim_clear=true` |
| Worker threads | requested 1, **observed 1** on all four arms; bound CPU `[30]`, observed CPU set equal to bound set |
| Governor / EPP | `amd-pstate-epp` / `powersave` / `performance` |
| Integrity | four-arm parity `pass`, `btrfs check --readonly` **clean**, incumbent isolation `pass` |
| Absolute medians | kernel `4.606 ms`, FrankenFS `23.017 ms` (diagnostic, `gate_input=false`) |
| Driver | `4b0f0889e637481ac9aac15737ced66aee59a53efcd38c77ff3c0cbf396f6cdb`, built by `rch exec --base HEAD --clean-overlay --no-overlay` on `ovh-a`, self-hashed in process |
| Candidate | frozen `f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349`, x86-64-v3 + PGO `6a22cfcf…`, identical to the five banked ext4 rows |

**Plain sentence: we lose.** On 2,000 warm `stat` calls against kernel btrfs, FrankenFS
is about five times slower.

### The disclosure that matters

`fuse_aa.ci_contains_one` is **false**. Under the pre-`2198a47d` gate this run would
have been `BLOCKED-NULL`, exactly like the three 2026-07-27 btrfs attempts. It is
admitted **solely** on the schema-v6 median clause — median `1.002699x` inside
`[0.98, 1.02]`, spread inside `1.025x`. This is the **first row in the campaign whose
admission depends on the gate correction**, and anyone auditing the correction should
start here.

It is a **loss**. A relaxed gate that produces a new loss is not the loosening signature;
a relaxed gate that produces a crop of new wins would be. That is the whole integrity
argument for the correction, and this row is the first live test of it rather than a
counterfactual re-score.

### Corroboration, explicitly not pooling

The three historical unadmitted btrfs estimates were `4.931910x`, `4.951192x`, and
`4.960432x`. This admitted `4.977803x` sits within **0.9%** of them. That is what the
queue predicted in section 2: the block was the gate, not the physics. Those three
remain unpublishable and unpooled — this row stands on its own invocation.

### Status: single run, replication pending

One admitted invocation. A second was attempted immediately and the harness's own
placement preflight **refused** it — *"no physical core has every SMT thread below the
driver contention limit"* — because a co-tenant agent's build loaded the host. That is
the fail-closed gate working, not a failed replicate. Until a second window lands, this
row is a **single-invocation result** and must be described that way. Do not upgrade its
language on the strength of the three historical estimates agreeing with it.

Instrument caveat found while retrying: piping the driver through `tail` masks its exit
code with `tail`'s, so a refused gate can read as success to a wrapper script. The retry
harness now captures the driver's own exit code directly. The four-arm reports were never
affected — this was my wrapper, not the comparator.

## 3. Predicates checked and *not* satisfied

Recorded so they are not re-attempted on the strength of these corrections:

- **Threadripper 1→128 thread sweep** (`bd-opb6l`, 2026-07-29). Predicate demands counted
  per-four-round attribution of FUSE mount identity, CPU migrations, faults, and
  host-wide busy state, *or* removal of the measured physical FUSE-arm asymmetry. Thread
  binding does not supply per-arm fault/migration counters. **Still blocked.**
- **Governor-attested mounted rerun** (2026-07-29). Predicate demands a machine-level
  exclusive lease plus either an owner-authorized `performance` governor on every CPU or
  counted per-arm frequency-residency evidence. The host is shared and the governor was
  deliberately not changed. **Still blocked**, and it is a decision for the owner, not
  for me.
- **The bd-b9dug ISA correction** unblocks less than it appears to. It re-states
  vs-kernel *losses* as overstated, but the overwhelming majority of REJECT rows are
  internal one-ELF A/B comparisons where the ISA cancels exactly (Class C). No REJECT is
  owed a retry merely because it predates the v3+PGO re-test; what it owes is the
  admissibility rule — no ratio publishable from a run lacking a `codegen_isa` line.
