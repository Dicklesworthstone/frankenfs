# bd-q0xnl — the measurement to run the moment the build freeze lifts

Written 2026-08-16 by ProudBarn under the freeze (`/data` at the 42G floor), so that
the run needs no re-derivation and no judgement calls at execution time. Every
number quoted as "expected" below is a prediction recorded **before** the run, so
the run can falsify it rather than be interpreted to fit.

## 0. Preconditions, in order

1. `df -h /data` — do not start below the standing floor. This plan starts a build.
2. Gate the uncompiled work first. Three commits are written but never compiled:
   `2e78f789` (readdirplus reports the real generation), `2b4ebbfa` (FORGET
   counted), and this turn's memo counters + knob. Gate with
   `cargo test -p ffs-fuse` **before** any measurement — a measurement against code
   that does not compile is not a measurement, and two of these touch the metrics
   struct that every arm reads.
3. Confirm the daemon is pinned and the client is on its SMT sibling. An unpinned
   mounted measurement is unstable to `1.4875x` on its own A/A null (bd-plt79), and
   that instability was observed **with** the daemon pinned on this very workload,
   so pinning is necessary and not sufficient — hence the null in §3.

## 1. Bench and fixture

- Binary: `ffs-cli mount --runtime-mode managed --no-background-scrub`, built from
  a tree containing the three ungated commits above. Record the in-process
  `mount_bench_evidence,binary_sha256=...` line; a neighbouring `sha256sum` is not
  proof of which binary ran.
- Fixture: `/data/tmp/ffs-pgo-train.img`, ext4, 20001 root entries. **This is a
  known gap**: the banked `7.728937x` row is btrfs and no btrfs fixture survives on
  this box (`ffs-cli mkfs` is ext4-only). Every conclusion below is ext4-scoped and
  must say so.
- Workload: `ls -lU <mnt>` — the readdir+stat sweep the banked row runs.
- Harness: `scripts/fuse_readdirplus_work_ab.sh` for the counted arms,
  `scripts/fuse_placement_workload_sweep.sh` shape for the timed arms.

## 2. Arms

Four arms, all from **one ELF**, all env-toggled so ISA and PGO cancel
(bd-b9dug class C):

| arm | `FFS_FUSE_READDIRPLUS_AUTO` | `FFS_FUSE_READDIRPLUS_ATTR_MEMO` | what it answers |
|---|---|---|---|
| `base`      | unset (AUTO) | unset (on)  | the post-fix baseline |
| `forced`    | `0`          | unset (on)  | does the generation fix flip bd-zsc7z? |
| `base_nomemo`   | unset    | `0`         | does the memo earn its lock? |
| `forced_nomemo` | `0`      | `0`         | memo value when readdirplus is forced |

## 3. Schedule and A/A null

- 4 mounts per arm; 10 reps per mount; **rep 1 of every mount discarded as cold** —
  that artefact produced a spurious `1.5630x` result that sign-flipped on replicate.
- Arms interleaved forward then reversed within each pass, so monotone drift loads
  every arm symmetrically.
- **36 warm reps per arm.** This is not a guess: at n=6 the A/A null was `1.4587x`
  and could not decide an ~11% effect; at n=36 the nulls came in at `1.0156x` and
  `1.0012x` and decided a 6.4% effect cleanly.
- A/A null: mounts 1+3 vs mounts 2+4 **within each arm**, same invocation. Report
  it per arm. An arm whose own null exceeds the effect it claims is refused.
- Estimator: seeded deterministic 20,000-resample paired bootstrap median CI.
  Report absolute medians and us/entry alongside every ratio.

## 4. Predictions recorded in advance

1. **`forced` vs `base`.** bd-zsc7z decided forcing readdirplus is `>= 1.0553x`
   SLOWER on the PRE-fix binary. If the generation fix makes the kernel accept
   readdirplus attributes, the kernel's ~1.0 getattr/entry disappears and this
   **flips to a win**. If it stays a loss of similar size, the generation
   hypothesis is wrong and should be recorded as such — the fix then stands only on
   its correctness argument, which is independent and still valid.
2. **Memo hit rate**, read from `readdirplus_memo_hits / readdirplus_memo_remembers`
   on the `base` and `forced` arms. Pre-fix this should be near 1.0. **Post-fix, a
   hit rate near 0 with remembers still near 1.0/entry is the signature of the memo
   having become dead weight**, and is the specific result that retires it.
3. **`base_nomemo` vs `base`.** The memo can save at most one `ops.getattr` per
   entry = `33.185 ns × 20001 = 0.66 ms` of a `~325 ms` sweep = **0.20%**, and its
   own `Mutex` traffic plausibly returns ~`0.80 ms`. So the expected result is
   **inside the null**, and the instrument cannot resolve 0.2% — which is itself
   the finding: do not spend further effort on a lever below the floor. Report it
   as bounded, not as a win or a loss.

## 5. Refusal conditions, agreed in advance

- Any arm whose same-invocation A/A null exceeds its claimed effect → refuse that
  arm, do not "interpret" it.
- `requests_total` must **not** be used as a boundary-crossing count: it counts
  request SCOPES and readdirplus opens one per entry. Use the per-op dispatch
  counters, and note that FORGET now has its own axis (`forget_nodes`) precisely so
  a reconciliation can say which quantity it means.
- Quote the WORST bound either run produced, not the headline.
- Name the host and state that no rch worker is quotable, since a mount is local by
  necessity.

## 6. What each outcome licenses

- Fix flips bd-zsc7z to a win → forcing readdirplus becomes a live default question,
  and the memo is then measured for removal on the post-fix binary.
- Fix leaves bd-zsc7z a loss → the generation hypothesis is refuted; keep the fix on
  correctness grounds, close the readdirplus line, and the unattributed bulk of
  `21.87 us/entry` becomes the open question again.
- Memo hit rate near zero → retire the memo, or gate it behind the knob's OFF
  default, on measured grounds rather than on this plan's arithmetic.
