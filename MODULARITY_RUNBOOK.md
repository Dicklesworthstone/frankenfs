+# FrankenFS Modularity Runbook

This runbook keeps FrankenFS from accumulating accidental monoliths while
preserving behavior, public APIs, source observers, performance, and compile
resources. File size is a triage signal, never permission to split a cohesive
owner.

## Governing principles

1. Start from `AGENTS.md`, the suite-wide instructions, and the current
   tracker/lease state.
2. Characterize before moving code. An uncovered cluster gets a test bead that
   blocks its extraction bead.
3. Predeclare the exact owner, source ranges, destination, visibility,
   dependency direction, and all allowed physical/provenance changes.
4. Make one mechanical move per commit: no rename, reformat, cleanup, body
   change, lint suppression, dependency change, or unrelated edit.
5. Preserve every observable contract. This includes test identity and order,
   panic text, source locations when observed, public paths, feature behavior,
   serialization, logs, artifacts, runtime, and compile resources.
6. A failed gate is a successful experiment result. Record the loss, preserve
   evidence, and do not repair the hypothesis after seeing the result.
7. Retain a large cohesive owner when splitting would create worse coupling.
   Document that B11 decision explicitly.

## File-size policy

Rust source uses a 5,000-line soft threshold and a 10,000-line hard threshold.

| Situation | CI treatment |
|---|---|
| New or previously sub-threshold file reaches 5,000 lines | warning plus owner/cohesion review |
| New or previously sub-threshold file reaches 10,000 lines | fail |
| Existing file already above 10,000 lines | fail any increase above its checked-in debt ceiling; allow reductions |
| Generated source | exclude only with a checked-in generator/provenance record |
| B11 justified monolith | retain only with explicit cohesion evidence and a reviewed exception |

The campaign baseline contains 19 Rust files above the soft threshold, nine of
them above the hard threshold. A CI implementation should check in a
path-to-line-ceiling manifest derived from a reviewed census. The gate must be
monotone: it may prevent new debt and accept reductions, but it must not force
an unproved split merely to make the count green.

Recommended CI stages:

1. Count logical Rust lines with one pinned `scc` or `tokei` version.
2. Compare every tracked `.rs` path with the checked-in debt manifest.
3. Fail new hard-threshold files and growth above grandfathered ceilings.
4. Emit soft-threshold warnings with churn and owning crate.
5. Verify every exception names its cohesion evidence and review date.

Changing thresholds, counters, or exception semantics is a gate change. It
requires evidence showing both newly admitted valid cases and invalid cases
that remain rejected.

## Dependency and import contracts

FrankenFS follows flat, domain-specific Rust modules with curated exports.

- Prefer focused names such as `writeback`, `degradation`, or
  `crash_consistency`; never create generic `utils` or `common` buckets.
- Keep `ffs` as a thin facade over `ffs-core`.
- Keep FUSE transport logic within `ffs-fuse`; format parsing remains
  independent of mount transport.
- Keep asupersync `Cx` flow explicit. A module move must not introduce a
  runtime, orphan task, ambient authority, or forbidden async dependency.
- Use curated `pub use` lists when a facade is required; do not broaden
  visibility or add wildcard exports to make a split compile.
- Treat a workspace-crate edge as an API and optimization boundary. Do not
  crate-split hot generic code without inlining, codegen, binary, and runtime
  evidence.

After each proposed move, capture and compare:

```text
cargo metadata --format-version 1 --no-deps
cargo tree --workspace --edges normal,build
br dep cycles
```

Use the repository's dependency-graph validator when available. Any new
logical cycle, feature edge, normal/build dependency, or Tokio-family
transitive dependency rejects the move.

## Module documentation template

Every genuinely new module begins with a substantive `//!` header:

```rust
//! <Domain owner>
//!
//! Purpose:
//! - <what this module owns>
//!
//! Key types and entry points:
//! - <type/function and role>
//!
//! Invariants:
//! - <ordering, state, cancellation, durability, or format invariant>
//!
//! Coupling:
//! - Inputs: <upstream modules/capabilities>
//! - Outputs: <downstream modules/artifacts>
//! - Must not depend on: <forbidden reverse edges>
//!
//! Evidence:
//! - <characterization tests and isomorphism experiment>
```

Do not create a new file solely to reduce a line count. The proposed file must
own a dependency-complete domain that cannot be expressed more clearly inside
an existing focused module.

## Extraction protocol

For every candidate:

1. Record an experiment before mutation with a falsifiable hypothesis, exact
   mechanical probe, expected signal, invocation, and all permitted physical
   deltas.
2. Freeze immediate-incumbent evidence. Historical snapshots are provenance,
   not substitutes for a current A/A control.
3. Claim one tracker item and reserve only the files being edited.
4. Add characterization tests first when coverage or observer evidence is
   incomplete.
5. Move one complete owner in one commit, preserving bodies and order.
6. Run direct formatting checks on every touched root and child before
   expensive builds.
7. Stop at the first terminal falsifier. Do not spend the remaining gate
   budget or weaken a gate.
8. If the source/format contract passes, use `rch exec -- cargo ...` for the
   required Rust build and test gates.
9. Merge only a fully proved candidate. Keep refuted and incomplete probes out
   of `main`.

The minimum Rust proof matrix is:

- exact source reconstruction and `git diff --check`;
- `cargo fmt --check`, with touched files independently formatter-clean;
- workspace check and clippy with no new warnings;
- target and workspace tests against an immediate incumbent;
- exact test names, ignores, expected-panic text, goldens, and failure set;
- public-API snapshot comparison;
- dependency/cycle and feature-matrix comparison;
- package, archive, dep-info, debug/source-observer, and clean-archive checks;
- production participation, codegen, symbol, section, and artifact checks;
- same-host compile wall/RSS and LLVM-line comparison within the declared
  bound; and
- same-invocation runtime A/A and A/B evidence whenever production execution
  can change.

A test-only move may classify runtime as not applicable only after production
nonparticipation is proved. Smaller parse/build work is maintenance evidence,
not a runtime win.

## Churn monitoring

Run the census and churn-coupling analysis on a schedule and on changes to any
grandfathered file.

Flag a file when any of these holds:

- it crosses 5,000 lines;
- it grows above its recorded debt ceiling;
- it becomes a top-decile churn hotspot;
- unrelated directories repeatedly co-change with it;
- one function dominates complexity;
- conditional compilation, embedded DSLs, or co-located tests hide ownership.

A flag opens investigation, not an automatic extraction. Update the debt
manifest only through a reviewed change that explains why the new ceiling is
necessary and how re-accretion will be prevented.

## Current justified leave-alone roots

The 2026-08-04 campaign retained these explicit B11 roots:

- `crates/ffs-repair/src/pipeline.rs`: the recovery policy, evidence, refresh,
  and shared state remain one owner.
- `crates/ffs-harness/src/permissioned_campaign_broker.rs`: an uncompiled
  mirror; independent movement would diverge from the compiled tools owner.
- `tools/ffs-ops/src/permissioned_campaign_broker.rs`: the central
  authorization and handoff identity remains cohesive.

Reopen these only when contradictory ownership evidence appears. Large size or
a desire for prettier directories is insufficient.

## Review checklist

Before approving a modularity change, answer yes to all of the following:

- Is the owner dependency-complete rather than a visual slice?
- Were characterization and physical-observer policies frozen first?
- Is the diff one mechanical move with no unrelated edits?
- Are public paths, privacy, feature behavior, and cancellation semantics exact?
- Are tests, API, dependency, artifacts, runtime, and compile resources proved?
- Is any accepted delta explicitly preapproved and narrowly attributed?
- Does the new module carry purpose, invariants, coupling, and evidence docs?
- Is the tracker graph cycle-free with proof and documentation prerequisites?
- Would reverting only this commit restore the incumbent structure cleanly?

If any answer is no, keep the candidate out of `main` and record the missing
proof or falsifier.
