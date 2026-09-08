# Tracker Hygiene Runbook

FrankenFS uses Beads as the source of truth for work selection, but the
JSONL store can occasionally contain rows that clearly belong to another
project. Treat those rows as triage pollution first, not as data to delete or
close.

This runbook covers source-scoped diagnosis, safe handoff, and the criteria
for enabling strict tracker hygiene gates.

## Current Classifier

FrankenFS-local tracker rows use IDs beginning with:

- `bd-`
- `frankenfs-`

Rows with other prefixes are reported as foreign-looking by
`scripts/e2e/ffs_tracker_source_hygiene_e2e.sh`. The classifier is deliberately
prefix-based because historical foreign rows may still have `source_repo: "."`
after JSONL import or cross-repo copy mistakes.

## Diagnosis

Use no-db or direct JSONL commands when SQLite state, `bv`, or `br ready`
appears polluted.

List foreign-looking open rows:

```bash
jq -s '[.[] | select(((.id // "") | test("^(bd|frankenfs)-") | not) and ((.status // "open") == "open")) | {id,title,status,priority,source_repo}]' .beads/issues.jsonl
```

List FrankenFS-local open rows:

```bash
jq -s '[.[] | select(((.id // "") | test("^(bd|frankenfs)-")) and ((.status // "open") == "open")) | {id,title,status,priority,issue_type,assignee,owner}] | sort_by(.priority, .id)' .beads/issues.jsonl
```

Emit the structured report:

```bash
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

Run the reusable Rust classifier directly when a tool wants the queue-state JSON
without the E2E wrapper artifacts:

```bash
ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl
```

The report writes `tracker_source_hygiene_report.json` under
`artifacts/e2e/<run>_ffs_tracker_source_hygiene/` and includes:

- `local_open_rows`
- `source_aware_ready_rows`
- `source_aware_queue_state`
- `local_graph_exports`
- `permission_gated_rows`
- `blocked_local_rows`
- `local_in_progress_rows`
- `stale_in_progress_rows`
- `excluded_foreign_open_count`
- `excluded_foreign_by_prefix`
- `foreign_group_summaries`
- `foreign_reconciliation_plan`
- `foreign_open_samples`
- `reproduction_commands`

`source_aware_ready_rows` excludes local rows that require an explicit
permission ACK until the ACK is present in the environment. Permission-gated
rows are still reported under `permission_gated_rows` with the required env
name and value so agents can distinguish "ready after operator authorization"
from ordinary ready work. Current gates are:

| Gate | Required environment |
|---|---|
| real xfstests execution | `XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices` |
| permissioned large-host swarm execution | `FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1` and `FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host` |

Rows that mention those lanes only to forbid execution can stay claimable when
they include explicit local-safe scope wording such as `non-permissioned`,
`read-only`, or `non-mutating fallback work` plus a clear negative action like
`must not run`, `does not execute`, `without running`, or `no xfstests`.

`source_aware_queue_state` is the one-field queue verdict for agents. It
includes `claimable_count`, `local_epic_count`, `blocked_local_count`,
`permission_gated_count`, `local_in_progress_count`,
`stale_in_progress_count`, `excluded_foreign_open_count`, the matching ID
lists, and `next_safe_actions`. If `verdict` is not `ready`, do not claim
ordinary work from raw `br` or `bv` output until you have checked this field.

`local_in_progress_rows` reports FrankenFS-local rows already claimed by an
agent. `stale_in_progress_rows` is the subset whose `updated_at` or `created_at`
timestamp is older than `TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS`
(default: 21600 seconds). Missing or unparsable activity timestamps are treated
as stale. A stale row is only a reclaim candidate after checking Agent Mail and
the worktree; the report does not reopen or mutate it.

Ordinary non-strict live runs also spawn the deterministic fixture/golden
self-check by default, so the standard agent queue probe catches report-shape
drift without extra environment variables. They also run a permission-ACK
self-check that proves the exact `XFSTESTS_REAL_RUN_ACK` and large-host swarm
ACK values move permission-gated rows into `source_aware_ready_rows` while
leaving blocked rows nonclaimable. Set
`TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0` or
`TRACKER_SOURCE_HYGIENE_PERMISSION_ACK_SELF_CHECK=0` only when debugging the
live tracker report in isolation.

For direct deterministic fixture runs,
`TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN` compares a canonicalized report against a
checked-in JSON golden. Canonicalization scrubs the run ID, timestamp, input
path, and generated artifact paths, but keeps queue state, local rows, stale
rows, permission gates, foreign summaries, export metadata, and reproduction
commands exact. Set `TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN_MISMATCH=1` with the
same golden to run a negative self-test that intentionally corrupts an
artifact-local golden copy and passes only if the diff rejects it.

The same run writes local-only JSONL graph inputs next to the report:

- `tracker_source_hygiene_local_open.jsonl`
- `tracker_source_hygiene_source_aware_ready.jsonl`
- `tracker_source_hygiene_local_nonclaimable.jsonl`
- matching `.sha256` checksum files

Use these exports when a graph or ready-work tool reads the contaminated full
JSONL store. `local_open` contains compact FrankenFS-local open work rows.
`source_aware_ready` contains only claimable local rows:
it excludes epics, blocked rows, foreign-looking rows, and permission-gated
rows until the required ACK is present. `local_nonclaimable` explains the
local open rows that are not claimable because they are epics, blocked, or
permission-gated. These artifacts are copies; generating them does not close,
rewrite, delete, or rename any tracker row.

For a local graph, use the wrapper rather than importing a prefix-filtered
copy by hand. Current `bv` rejects `wont_fix`, even though `br` imports it:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

The wrapper saves `tracker_source_hygiene_bv_projection.json` beside its report.
It accounts for every source row, retaining the complete original rows in
`included_source_rows` or `excluded_source_rows` with a reason. Unsupported
statuses are excluded from the temporary graph, not rewritten as completed
work. Referenced missing or excluded local dependencies become explicitly
blocked placeholders. Included statuses are preserved, and a checksum verifies
that the source JSONL did not change during projection.

`tracker_source_hygiene_bv_source_aware_triage_clean` requires complete source
authority, zero loading errors/skips, exact graph counts, and separate matching
open and in-progress counts. Negative fixtures reject partial graphs and verify
that refused, unknown, missing-dependency, and permissioned work cannot become
claimable. Existing report goldens remain unchanged.

Even a complete temporary graph establishes graph context only. Use the
source-aware report's `claimable_ids` and exact permission checks for work
selection; a local ID prefix alone does not establish semantic ownership.
Raw `bv` over the live store remains diagnostic when it reports partial source
authority. Reconcile foreign history only with its owner's authorization.

`foreign_reconciliation_plan` is also report-only. It turns each foreign group
into an owner-handoff packet with the recommended Agent Mail thread, owner
hints, sample IDs, authorization requirement, and conservation rule. It does
not authorize mutation by itself. Use it to contact the likely owner project and
to record the exact rule any later move, removal, rewrite, or `project` backfill
must satisfy.

## Standing Reality-Check Cadence

Run the source-aware tracker hygiene E2E at the start and close of each swarm
tick, and before promoting any public `release-ready` or readiness wording:

```bash
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

Any FrankenFS-local open row with `priority: 0` blocks release-ready/readiness
claims until that row is closed or explicitly reprioritized with evidence.
Foreign-looking P0 rows remain owner-handoff items, not FrankenFS release
blockers. The Rust unit test `release_readiness_blocked_by_open_p0` and E2E
scenario `tracker_source_hygiene_release_readiness_blocked_by_open_p0` enforce
the local-P0 blocker contract.

## Serialized Report Coverage Gate

When source-aware triage produces another missing JSON/report-shape bead, run
the report schema inventory gate before filing an ad hoc follow-up:

```bash
ffs-harness validate-report-schema-inventory \
  --out artifacts/report-schema-inventory/report.json \
  --summary-out artifacts/report-schema-inventory/report.md
```

The E2E wrapper is:

```bash
./scripts/e2e/ffs_report_schema_inventory_e2e.sh
```

This gate is non-permissioned and read-only. It emits
`product_evidence_claim=none`, `uncovered_required_report_ids`, deterministic
row results, row-scoped missing-evidence tokens, and a reproduction command.
Use uncovered required rows as the source for narrow report-coverage beads; do
not treat the report as a proof-bundle pass, xfstests result, mounted mutation
result, or large-host swarm campaign result.

## Source-Scope Tracked-Input Policy

Source-scope inventory reports are agent closeout and discovery inputs. Run the
manifest scanner through `rch` in agent sessions:

```bash
rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_source_scope \
  cargo run --quiet -p ffs-harness -- validate-source-scope-manifest \
  --manifest tests/source-scope-manifest/source_scope_manifest.json \
  --workspace-root . \
  --out artifacts/source-scope/source_scope_manifest.json
```

The scanner treats git-tracked files as canonical workspace evidence whenever
git metadata is available. Canonical evidence appears in each source row's
`matched_paths`, participates in `file_or_directory_hash`, and may be used for
source-family closeout decisions. If git metadata is unavailable or incomplete,
the report must say so through its workspace-file-source fields; do not treat a
silent live-directory scan as canonical proof.

Untracked paths are diagnostics, not canonical evidence. A dirty workspace may
still produce a valid report when generated E2E logs, temp artifacts, or local
backup files match a source-family glob. Those paths appear under
`untracked_matched_path_count` and `untracked_matched_paths` with an exclusion
reason, and their contents are excluded from `file_or_directory_hash`.

When dirty diagnostics appear:

1. Inspect the reported path, source family, and exclusion reason.
2. If the file is supposed to become evidence, make a deliberate checked-in
   artifact or a committed manifest/ledger entry that references it.
3. If it is local run output, leave it as a diagnostic and cite only committed
   evidence in bead closeout.
4. Preserve local artifacts during no-delete agent sessions; do not delete
   files merely to make a report look clean.
5. Do not close readiness gaps from untracked-only evidence.
6. Do not mutate foreign tracker rows as part of source-scope cleanup; follow
   the foreign-row handoff rules below.

## Reconciliation Rules

Do not delete, rewrite, close, or rename foreign-looking rows merely because
they pollute local triage. Those rows may be the only audit record for another
project.

Before any mutation is proposed:

1. Capture the source-scoped report artifact.
2. Group foreign rows by prefix and likely owner project.
3. Search Agent Mail for related threads if the owner is not obvious.
4. Contact the current or likely owner using Agent Mail.
5. Record the exact proposed mutation and wait for explicit authorization.

If authorization is absent, leave the rows intact. Work around the pollution
with the source-aware report or no-db JSONL filters.

## Agent Mail Handoff

Use a dedicated thread when foreign rows need owner review:

```text
thread_id: tracker-hygiene
subject: [tracker-hygiene] Foreign row ownership check: <prefix>
```

Include:

- Report artifact path
- Foreign prefix and sample IDs
- Why the rows appear non-FrankenFS
- Proposed action, if any
- Confirmation that no mutation has happened yet

Use `cc` sparingly. Message only agents likely to own the source project or the
current tracker operation. Agent Mail reservations on `.beads/issues.jsonl` are
advisory for manual JSONL edits; do not reserve that file for routine tracker
closeout, and do not block `br close` or `br sync --flush-only` on an advisory
reservation.

## Advisory Reservation Allocation

`ffs-harness claimability-plan` may consume an Agent Mail reservation snapshot
with `--reservation-report`. The planner remains report-only, but a fresh
snapshot can produce `reservation_allocation_plan` guidance for concurrent
agents.

The allocation plan is intentionally conservative:

- It only suggests exact target paths that do not overlap an active exclusive
  peer reservation.
- Active exclusive reservations held by the current agent are classified as
  self-held overlap, not peer blockers. Agents may continue only if that lease
  is intentionally theirs for the current task; they should renew it while
  working and release it before handoff.
- Broad peer reservations such as `**`, wildcard target paths, stale or missing
  snapshot freshness, and complete overlap all produce a blocked allocation
  status with no suggested paths.
- Suggested command text is advisory. Agents must still call Agent Mail
  `file_reservation_paths` themselves and respect any live conflict returned by
  the server.
- The harness never calls MCP, claims work, releases reservations, or mutates
  `.beads/issues.jsonl` from this report path.

### Live-To-Offline Reservation Snapshots

`claimability-plan --reservation-report` reads an offline reservation report,
not a live MCP response. Capture live Agent Mail state once, translate the facts
into the report shape, and pass that file to the planner. This preserves the
no-mutation boundary: the harness reads JSON only and never calls MCP.

Use `file_reservation_paths` conflict output as the authoritative conflict
source when it disagrees with a lightweight resource view such as
`resource://tooling/locks`. The report should record the snapshot timestamp and
set `source_freshness` to `fresh` only while `age_seconds <=
source_max_age_seconds`; otherwise use `stale` or omit the snapshot.

The required top-level fields are:

- `current_agent`: the agent that will interpret self-held leases.
- `generated_at`, `generated_at_epoch`, `age_seconds`,
  `source_max_age_seconds`, and `source_freshness`: freshness metadata for the
  captured observation.
- `target_paths`: exact files or globs the next claim wants to reserve.
- `conflict_classification`: aggregate status, usually
  `active_peer_conflict`, `self_held`, `shared_observation`,
  `no_active_conflict`, `expired`, or `malformed_timestamp`.
- `reservations`: one row per observed lease or conflict.

Each reservation row must include `holder`, `path_pattern`, `exclusive`,
`reason`, `created_ts`, `expires_ts`, `released_ts`, `active`,
`overlaps_target`, and row-level `conflict_classification`. Epoch fields are
included when known so downstream reports can compare freshness without
re-parsing timestamps.

Minimal report-shaped fixture:

```json
{
  "schema_version": 1,
  "snapshot_status": "present",
  "snapshot_schema_version": 1,
  "current_agent": "SapphireLotus",
  "target_paths": ["docs/tracker-hygiene.md"],
  "source": "agent-mail-live-copy",
  "source_freshness": "fresh",
  "generated_at": "2033-05-18T03:30:00Z",
  "generated_at_epoch": 1999999800,
  "age_seconds": 200,
  "source_max_age_seconds": 3600,
  "conflict_classification": "self_held",
  "reservations": [
    {
      "holder": "SapphireLotus",
      "path_pattern": "docs/tracker-hygiene.md",
      "exclusive": true,
      "reason": "bd-0chpv.10",
      "created_ts": "2033-05-18T03:00:00Z",
      "expires_ts": "2033-05-18T04:30:00Z",
      "released_ts": null,
      "created_epoch": 1999998000,
      "expires_epoch": 2000003400,
      "released_epoch": null,
      "active": true,
      "overlaps_target": true,
      "conflict_classification": "self_held"
    }
  ],
  "errors": []
}
```

The mixed current-agent plus peer fixture used by the planner tests is
`tests/fixtures/claimability_autopilot_live_reservation_snapshot.json`.

### Post-Close Reservation Reconciliation

At bead closeout, release the current agent's reservations and record the
result in the Agent Mail thread. If `release_file_reservations` reports
`released=0` but a later claim or snapshot still shows active leases held by
the same agent, do not treat that as a peer blocker and do not force-release
another agent's lease.

Use this deterministic check:

1. Call `release_file_reservations(project_key, agent_name)` or the exact
   scoped release for the files owned by the bead.
2. Capture a fresh, non-mutating reservation snapshot when available. If no
   non-mutating source is available, record the state as unknown instead of
   creating a probe lease.
3. Classify remaining overlaps:
   - `active_peer_conflict`: stop or request explicit handoff from the holder.
   - `self_held`: reuse or renew only when the same agent is immediately
     continuing related work; otherwise report the leftover lease in Agent
     Mail and attempt another normal release.
   - `shared_observation`, `expired`, or `no_active_conflict`: not blockers,
     but still include the snapshot path or summary in closeout evidence.
4. Send a final Agent Mail note with the release result, any fresh snapshot
   path, and whether self-held leftovers remain.

This check is advisory and fail-safe. It does not authorize deleting reservation
artifacts, bypassing `file_reservation_paths`, force-releasing peer leases, or
mutating `.beads/issues.jsonl` through a reservation conflict.

## Strict Mode

`TRACKER_SOURCE_HYGIENE_STRICT=1` fails when foreign-looking open rows exist.
Strict mode is suitable only after all of these are true:

- `excluded_foreign_open_count` is zero in a fresh report.
- Any previous foreign row group has an Agent Mail handoff or owner decision.
- `.beads/issues.jsonl` has no active peer reservation.
- `br dep cycles --no-db --json` reports zero cycles.
- A default non-strict report still emits valid `local_open_rows` and
  `source_aware_ready_rows`, a valid `source_aware_queue_state`, plus
  checksum-validated local graph exports.

Run strict mode as:

```bash
TRACKER_SOURCE_HYGIENE_STRICT=1 ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

If strict mode fails, do not weaken the gate or delete rows to make it pass.
Return to diagnosis and owner handoff.

## Fixture Validation

The deterministic classifier fixture lives at
`tests/fixtures/tracker_source_hygiene.jsonl`.

Validate the fixture contract:

```bash
TRACKER_SOURCE_HYGIENE_ISSUES=tests/fixtures/tracker_source_hygiene.jsonl \
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=6 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=27 \
TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=4 \
TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS=1 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_IN_PROGRESS=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_STALE_IN_PROGRESS=1 \
TRACKER_SOURCE_HYGIENE_NOW_EPOCH=2000000000 \
TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS=3600 \
TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN=tests/fixtures/tracker_source_hygiene_report.golden.json \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT=20 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_GROUP_COUNT=4 \
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

Verify that the xfstests permission ACK unlocks only the unblocked fixture row:

```bash
TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 \
TRACKER_SOURCE_HYGIENE_NON_MUTATING_FALLBACK_SELF_CHECK=0 \
TRACKER_SOURCE_HYGIENE_PERMISSION_GATED_BLOCKED_SELF_CHECK=0 \
TRACKER_SOURCE_HYGIENE_PERMISSION_ACK_SELF_CHECK=0 \
TRACKER_SOURCE_HYGIENE_ISSUES=tests/fixtures/tracker_source_hygiene.jsonl \
TRACKER_SOURCE_HYGIENE_NOW_EPOCH=2000000000 \
TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS=3600 \
XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices \
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

Strict fixture validation should fail closed while the fixture contains foreign
open rows:

```bash
TRACKER_SOURCE_HYGIENE_ISSUES=tests/fixtures/tracker_source_hygiene.jsonl \
TRACKER_SOURCE_HYGIENE_STRICT=1 \
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=6 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=27 \
TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=4 \
TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS=1 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_IN_PROGRESS=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_STALE_IN_PROGRESS=1 \
TRACKER_SOURCE_HYGIENE_NOW_EPOCH=2000000000 \
TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS=3600 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT=20 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_GROUP_COUNT=4 \
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

The strict command returning nonzero is expected for this fixture.
