#!/usr/bin/env python3
"""frankenfs perf-ledger preflight — make ledger decay structurally impossible.

Motivation (fleet broadcast 2, 2026-07-25): ledger integrity is not a one-time
cleanup, it DECAYS. Repos that audited once and institutionalized the check sit at
~1.7% VOID; repos that never did sit at 25-91%. frankenfs currently audits at
**73.0% VOID** (205 of 281 REJECT rows). This script is the institutionalization.

Four jobs, three exit classes:

  --candidate "<text>" --surface "<target>"
                         Grep the ledgers BEFORE proposing a lever. Exit 2 = BLOCKED
                         when a prior REJECT covers the target surface. Print the row
                         and retry predicate so the caller must satisfy the predicate
                         or pick a different vein.

  --lint --staged        Pre-commit mode. Refuse a new or modified REJECT with neither
                         an A/A null control nor a counted mechanism. Numeric A/A
                         decisions must record a bootstrap median CI. Refuse a KEEP
                         without both that CI and an in-process self-report of the
                         executing ELF's SHA-256. Refuse a competitive row (live
                         same-invocation incumbent arm) that records only its ratio and
                         not both arms' ABSOLUTE medians — bd-4sull item 3. Refuse every
                         CV gate, including one deferred into a retry predicate. Policy
                         failures exit 2; infrastructure failures 64.

  --lint [--since REF]   Apply the same rules to the whole ledger or committed rows
                         added since REF.

  --audit                Whole-ledger census (the §1 audit, re-runnable).

  --worker-scope [--list]
                         Retroactive half of the worker-identity gate, which is
                         otherwise forward-only. Flags every banked KEEP that quotes a
                         vs-incumbent ratio but names no execution host as WORKER-SCOPED
                         (re-scoped, not retracted) and ratchets the count so it can only
                         fall. Exit 2 when the count rises above the baseline, when a row
                         admits scheduling across several workers, or when the count fell
                         and the baseline was not lowered to match.

  --self-test            Exercise the policy predicates without Cargo or fixtures.

Wire staged lint into the active checkout with `--install-hook`.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# (path, entry_heading_level). The two ledgers nest differently and getting this
# wrong is not cosmetic: too shallow merges many entries into one and hides void
# rows; too deep splits an entry from the evidence table in its own subsection and
# reports a fully-evidenced row as unfalsifiable.
#   NEGATIVE_EVIDENCE.md      `##` groups by date,  `###` IS the entry
#   perf-negative-results.md  `##` IS the entry,    `###` are its subsections
LEDGERS: list[tuple[Path, int]] = [
    (ROOT / "docs" / "NEGATIVE_EVIDENCE.md", 3),
    (ROOT / "docs" / "progress" / "perf-negative-results.md", 2),
]

# --- what makes a REJECT row admissible -------------------------------------
# A rejection must be able to DISTINGUISH "the lever does nothing" from "this bench
# cannot see anything". An A/A null control or a counted mechanism establishes that.

NULL_CONTROL = re.compile(
    r"A/A|A/A/B|null control|null floor|null-control|duplicate (?:FFS )?controls|"
    r"two controls|frozen controls|null \d\.\d|null_median_ratio|null_floor_ratio",
    re.I,
)
COUNTED_MECHANISM = re.compile(
    r"instructions? (?:count )?(?:un)?changed|instructions? (?:BASE|DOWN|UP|~|-?\d)|"
    r"perf stat|\bIr\b|cycles? (?:NEUTRAL|neutral|~|unchanged|flat)|"
    r"syscall count|strace counted|\d+ vs \d+ fsync|allocation count|alloc count|"
    r"faults? unchanged|callgrind|identical code|generates ~identical|"
    r"same number of|byte-readback|readback|"
    r"\d+(?:\.\d+)?%\s+self",
    re.I,
)

# Forward enforcement is deliberately stricter than the historical census:
# mentioning a tool, parity readback, or a future retry does not prove that a
# mechanism was counted in the rejected run.
CONTRACT_COUNTED_MECHANISM = re.compile(
    r"instructions? (?:count )?(?:un)?changed|"
    r"instructions? (?:BASE|DOWN|UP|~|-?\d)|"
    r"cycles? (?:NEUTRAL|neutral|~|unchanged|flat)|"
    r"syscall count|strace counted|\d+ vs \d+ fsync|"
    r"allocation count|alloc count|faults? unchanged|callgrind|"
    r"\d+(?:\.\d+)?%\s+self|"
    # `requests?`/`probes?` added 2026-08-15 (bd-ha71t). The noun list was
    # instruction/cycle/syscall-shaped and could not express the most objective
    # counted mechanism a FUSE filesystem has: the number of REQUESTS the kernel
    # issues to the daemon. A getxattr probe count is exactly as deterministic as
    # a syscall count — it is read off an unconditional trace at the kernel
    # boundary — and rejecting a lever on "4000 probes -> 4000 probes" is a
    # stronger result than any wall-clock null, because it needs no quiet window.
    #
    # This is a gate FIX, not a widening: measured over the whole ledger at the
    # time of the change, it admitted ZERO previously-failing REJECT rows (232
    # failing before, 232 after). It buys expressiveness for new rows only, so it
    # cannot launder existing debt.
    r"\b\d[\d,]*\s+(?:instructions?|cycles?|syscalls?|allocations?|faults?"
    r"|requests?|probes?|dispatch scopes?|crossings?)"
    r"[^|\n]{0,80}(?:vs|->|→|to)\s*\d[\d,]*",
    re.I,
)
CONTRACT_NULL_VALUE = re.compile(
    r"(?:A/A(?:/B)?|null(?:[- ]control| floor)|null_median_ratio)"
    r"[^|\n]{0,120}(?:0|1|2)\.\d+(?:\s*(?:x|×))?"
    r"|(?:0|1|2)\.\d+(?:\s*(?:x|×))?[^|\n]{0,120}"
    r"(?:A/A(?:/B)?|null(?:[- ]control| floor)|null_median_ratio)",
    re.I,
)
SAME_INVOCATION_WITNESS = re.compile(
    r"same[- ]invocation|A/A/B|interleaved A/A",
    re.I,
)

# --- what makes a KEEP claim a *competitive* claim ---------------------------
# A self-speedup says nothing about whether an operator should choose FrankenFS.
# Only a ratio whose denominator is the incumbent, measured with the incumbent
# arm LIVE in the same invocation, is a competitive claim. Three provenance
# classes, deliberately ordered from strongest to weakest.

_RATIO = r"\d+(?:\.\d+)?\s*(?:x|×)"
_INCUMBENT_TOK = (
    r"kernel[- ]?(?:ext4|btrfs)|(?:ext4|btrfs)[- ]kernel|kernel arm|kernel median|"
    r"kernel_median|incumbent|vs\.? (?:the )?kernel|kernel throughput|kernel `?dd`?|"
    r"kernel `?cat`?|real kernel|kernel mount"
)
INCUMBENT_RATIO = re.compile(
    rf"(?:{_INCUMBENT_TOK})[^|\n]{{0,160}}?{_RATIO}"
    rf"|{_RATIO}[^|\n]{{0,160}}?(?:{_INCUMBENT_TOK})",
    re.I,
)
# The same-invocation witness must be the COMPARATOR INSTRUMENT, never a bare
# "A/A/B": three rows (NEGATIVE_EVIDENCE.md:88/91/92) carry an A/A/B that is the
# internal frozen-vs-candidate control, with the kernel number taken separately.
# Accepting the bare token reports a self-speedup as a competitive claim.
SAME_INVOCATION_INCUMBENT_ARM = re.compile(
    r"mounted-kernel-report|four[- ]arm|four[- ]round|physical[- ]arm crossover|"
    r"crossover block|owns four independent arms|four independent (?:live )?mounts|"
    r"same[- ]invocation (?:A/A|null|deterministic|ext4|btrfs)|ffs_mounted_kernel_bench",
    re.I,
)

# --- why an un-converted claim is un-converted -------------------------------
# "No incumbent arm exists" and "nobody has measured it yet" are different debts.
# Precedence matters: convertibility is decided by whether the CLAIM'S WORKLOAD is
# expressible as a POSIX operation the incumbent also implements, NOT by which
# internal subsystem implements it. A row that mentions MVCC while speeding up
# create is convertible -- the comparator already has a create workload.
NOT_A_FILESYSTEM_CLAIM = re.compile(
    r"instrument[- ]only|KEEP the (?:vs-incumbent )?instrument|instrument KEEP|"
    r"workload/instrument support only|no production tuning|no self-speedup lever|"
    r"CLAIM CORRECTION|AUDIT (?:COMPLETE|CORRECTED)|ledger resurrection|methodolog|"
    r"harness overhead|KEEP the (?:ext4 )?mounted-comparator workload|"
    r"this row banks an instrument|no FrankenFS (?:optimization|before/a)|"
    r"preflight|SURVEY",
    re.I,
)
POSIX_REACHABLE_SURFACE = re.compile(
    r"htree|dirent|readdir|lookup|create|unlink|rmdir|rename|mkdir|symlink|link\b|"
    r"extent|bitmap|inode|allocat|xattr|fsync|journal|jbd2|checksum|crc32c|"
    r"read path|write path|pread|pwrite|stat\b|getattr|truncate|block device|"
    r"page cache|prefetch|readahead|superblock|group descriptor|snapshot|send[- ]stream",
    re.I,
)
# Deliberately narrow: only surfaces where kernel ext4/btrfs offers no counterpart
# operation at all, so no incumbent arm could ever be built.
NO_INCUMBENT_SURFACE = re.compile(
    r"RaptorQ|repair symbol|fountain[- ]cod|scrub[- ]ledger|repair confidence|"
    r"durability autopilot|refresh polic|stale[- ]window|adaptive runtime|"
    r"topology advisor|proof bundle|release gate|evidence event|ParityReport|"
    r"expected loss|MergeProof|merge proof|ConflictPolicy|SafeMerge",
    re.I,
)

# --- absolute arm medians on a competitive row (bd-4sull item 3) -------------
# A ratio is a QUOTIENT: on its own it cannot say which arm moved. Measured, not
# argued -- the incumbent arm of one banked shape drifted +18.3% (77.31 -> 83.69
# -> 91.43 ms) across three gate-clear windows on one kernel while FrankenFS held
# to 1.4%, so a re-run disagreeing with a banked row says nothing until the arms
# are separated. That decomposition is only possible when BOTH absolute medians
# are on record. The harness already prints them on its `mounted_kernel_throughput`
# line; the historical gap was transcription, and rows that missed it (the ext4
# xattr row, four of six btrfs rows) are now permanently un-diagnosable because
# their reports were deleted (bd-v0igv). So: a row making a live same-invocation
# incumbent claim must carry an absolute median for each arm.
_DURATION = r"\d[\d,]*(?:\.\d+)?\s*(?:ns|[uµ]s|ms|s(?:ec(?:onds?)?)?)\b"
_INCUMBENT_ARM_TOK = r"kernel|incumbent"
_CANDIDATE_ARM_TOK = r"fuse|frankenfs|ffs|candidate|ours?|we\b"
# Either the machine field straight off the harness line, or prose naming the arm
# and a duration within a short window (kept tight so an unrelated sentence in the
# same cell cannot satisfy it).
INCUMBENT_ABSOLUTE_MEDIAN = re.compile(
    rf"kernel_median_wall_ns\s*[:=]\s*\d"
    rf"|(?:{_INCUMBENT_ARM_TOK})[^|\n]{{0,60}}median[^|\n]{{0,60}}{_DURATION}"
    rf"|median[^|\n]{{0,40}}(?:{_INCUMBENT_ARM_TOK})[^|\n]{{0,60}}{_DURATION}",
    re.I,
)
CANDIDATE_ABSOLUTE_MEDIAN = re.compile(
    rf"fuse_median_wall_ns\s*[:=]\s*\d"
    rf"|(?:{_CANDIDATE_ARM_TOK})[^|\n]{{0,60}}median[^|\n]{{0,60}}{_DURATION}"
    rf"|median[^|\n]{{0,40}}(?:{_CANDIDATE_ARM_TOK})[^|\n]{{0,60}}{_DURATION}",
    re.I,
)

# --- daemon placement on a MOUNTED row (bd-plt79) -----------------------------
# Observed defect class, measured twice on this host by two agents:
#   * a 5-placement sweep found the UNPINNED arm swinging to a 1.4875x A/A null
#     and disagreeing with itself 1.2613x across runs, while every PINNED arm in
#     the same sweep stayed inside 1.0946x (ProudBarn, bd-plt79);
#   * an unpinned managed-runtime harness measured a memo effect at 1.200033x
#     where the pinned comparator measured 2.063608x at MATCHED thread count --
#     a 1.72x instrument disagreement that invalidated a published decomposition
#     (AzureBay, retraction 263e70c8).
# In both cases requests_total was unchanged, so no work moved: the swing is pure
# scheduler placement of the FUSE daemon relative to its client. A within-run CI
# computed from reps that all shared one accidental placement looks tight while
# the placement itself is the uncontrolled variable -- the same shape as the
# worker-scope defect, one level down.
MOUNTED_ROW = re.compile(
    r"mounted[- ]kernel|mounted comparator|fuse_over_kernel|ffs-mounted-kernel-bench",
    re.I,
)
DAEMON_PLACEMENT = re.compile(
    r"placement_scope\s*[:=]|--fuse-cpus|fuse_cpu[s_]|daemon (?:is )?pinned|"
    r"pinned (?:the )?daemon|same_llc|cross[- ]ccd|smt[- ]sibling|unpinned",
    re.I,
)

FULL_SHA256 = r"[0-9a-f]{64}"
EXECUTING_ELF_SHA256 = re.compile(
    rf"(?:bench_elf_sha256|executing_elf_sha256|current_exe_sha256)"
    rf"\s*[:=]\s*`?{FULL_SHA256}`?"
    rf"|bench_evidence\s*,\s*binary_sha256\s*=\s*`?{FULL_SHA256}`?"
    rf"|(?:in[- ]process|self[- ]report(?:ed|ing)?|executing)"
    rf"[^|\n]{{0,96}}\bELF\b[^|\n]{{0,64}}`?\b{FULL_SHA256}\b`?"
    rf"|(?:in[- ]process|self[- ]report(?:ed|ing)?|executing)"
    rf"[^|\n]{{0,160}}\b(?:ELF|binary)\b[^|\n]{{0,160}}"
    rf"(?:sha-?256|hash)[^|\n]{{0,48}}\b{FULL_SHA256}\b"
    rf"|\b(?:ELF|binary)\b[^|\n]{{0,120}}(?:sha-?256|hash)"
    rf"[^|\n]{{0,48}}\b{FULL_SHA256}\b[^|\n]{{0,120}}"
    rf"(?:in[- ]process|self[- ]report(?:ed|ing)?|current_exe)",
    re.I,
)

# A row that does not name the machine it ran on cannot be compared to any other
# row. Measuring one cubic splu cell on two different rch workers produced 1.2693x
# and 0.0093x -- a 13.6x swing -- with BOTH A/A nulls passing, because the null only
# controls within-invocation noise and is blind to between-worker differences in CPU
# model, cache, memory bandwidth and contention. Worker identity is therefore
# provenance, not decoration. Searched over the whole row, not decision_evidence(),
# because provenance lives in the trailing column.
WORKER_IDENTITY = re.compile(
    r"\bRCH_WORKERS?\s*=\s*`?[A-Za-z0-9][A-Za-z0-9._-]*`?"
    r"|\bworkers?\s*[:=]?\s*`[A-Za-z0-9][A-Za-z0-9._-]*`"
    r"|\bpinned\s+(?:to\s+)?`[A-Za-z0-9][A-Za-z0-9._-]*`"
    r"|\b(?:host_identity|same_host|executed_on|hostname)\s*[:=]\s*"
    r"`?[A-Za-z0-9][A-Za-z0-9._-]*`?",
    re.I,
)

# A run that was allowed to schedule across more than one worker cannot place both
# arms on the same machine by construction, so the comparison is inadmissible
# regardless of how clean its null looks.
MULTI_WORKER = re.compile(
    r"\bRCH_WORKERS?\s*=\s*`?[A-Za-z0-9][A-Za-z0-9._-]*\s*,",
    re.I,
)

# --- the retroactive half: rows banked before the gate existed ---------------
# The WORKER_IDENTITY check above is FORWARD-only -- it inspects the staged index,
# so it can never reach a row that was already committed. Census run 2026-08-15
# through this module's own parser (never a line grep: a prior one-off script in
# this repo mis-split '##' entries at their '###' subsections and published a wrong
# void figure, 79.3 -> 75.1):
#
#   rows parsed 1209 | KEEP 686 (595 unnamed) | REJECT 318 (261) | SURVEY 143 (132)
#   rows explicitly allowing MULTIPLE workers: 0
#
# The sharp set is narrower than "unnamed": a KEEP that quotes no vs-incumbent
# ratio makes no competitive claim, so an unknown host costs it nothing. A KEEP
# that DOES quote one is asking to be compared, and cannot be.
#
# These rows are re-scoped, NOT retracted. 0 rows are known multi-worker and the
# campaign law already required same-invocation arms, so most are almost certainly
# worker-SCOPED (valid, unknown machine) rather than INVALID (arms split across
# machines). The defect is that the row cannot prove which. Per-row recovery was
# checked and is impossible: zero run report.json files survive under /data/tmp
# (sbh reaped them), so no host can be recovered for any banked row, and inventing
# one would be worse than the gap.
#
# This number is a RATCHET, not a target. It may only fall, and it falls exactly
# one way: a row gains the host it ran on. Raising it means an unnamed competitive
# claim got committed past the forward gate, which is the defect itself.
WORKER_SCOPE_BASELINE = 166

# Forward-only ratchet for bd-plt79, seeded from the tree at the time it was
# added. Like WORKER_SCOPE_BASELINE this is a floor that may only FALL: it does
# not retract a banked row, it stops a NEW mounted ratio being banked without
# saying where its daemon ran. Discovered by --placement-audit; do not raise it.
PLACEMENT_SCOPE_BASELINE = 39

# Forward-only ratchet for bd-4sull item 3, seeded from the tree at the time it
# was added. Same contract as the two above: a floor that may only FALL. It does
# not retract a banked row; it stops a NEW competitive ratio being banked without
# the incumbent's ABSOLUTE median beside it.
#
# WHY A RATIO ALONE IS NOT ENOUGH, and this is measured rather than argued. A row
# is a quotient, so incumbent volatility lands in the published number even when
# our own cost is stable: across four runs of one ELF, FrankenFS held
# 232.11/225.22/225.31/222.39 ms while the kernel arm held 77.05/77.31/78.42 and
# then 83.69 ms — our arm moved -1.30% and the incumbent moved +8.26%. With only
# the ratio transcribed, that is undiagnosable after the fact.
#
# And "look it up in the report" does not survive contact with this host: the
# 2026-07-31 bulk-durable row could not be diagnosed because its report had been
# deleted (bd-v0igv), and 45 of 46 banked reports were reaped once already. The
# ledger row is the only durable artefact, so the number has to be IN it.
# Discovered by --incumbent-absolute-audit; do not raise it.
INCUMBENT_ABSOLUTE_BASELINE: int | None = 98

# Forward-only ratchet for bd-4sull item 2, seeded from the tree. Same contract as
# the three above: a floor that may only FALL.
#
# THE RULE, in the bead's words: a row's quotable precision is max(its own CI, its
# measured cross-window spread), and a row with no second run is quoted to the
# campaign's worst observed spread until it has one.
#
# It exists because the published CI describes error INSIDE one invocation and
# nothing else, while the numbers a reader compares rows with are cross-window.
# Both quantities are now measured from the 87 surviving reports rather than
# argued (scripts/cross_window_spread.py):
#
#   admitted rows re-measure to a median spread of 1.1022x, worst 1.1314x, over
#   the only 3 like-for-like groups in the entire bank that HAVE a second admitted
#   run -- against a published CI of typically 0.5-1%, an order of magnitude
#   narrower;
#   and 35 of 38 like-for-like groups have never had a second admitted run at all,
#   so for almost every banked row the CI is the ONLY figure and it is a lower
#   bound on the truth.
#
# A row satisfies this by saying so: naming its cross-window spread, citing a
# second same-ELF run, or carrying an explicit within-invocation-only caveat.
# Discovered by --precision-scope-audit; do not raise it.
PRECISION_SCOPE_BASELINE: int | None = 33

# A row that has ACKNOWLEDGED the scope of its own precision, in any of the forms
# the ledger uses. Deliberately generous about wording and strict about intent: it
# must reference the cross-window/re-measurement question, not merely contain the
# word "window" (every quiet-window note would match that).
PRECISION_SCOPE_ACKNOWLEDGED = re.compile(
    r"cross[- ]window"
    r"|between[- ]window"
    r"|window[- ]to[- ]window"
    r"|re[- ]measure(?:d|ment|s)?\s+(?:spread|delta|reproducib)"
    r"|reproducib\w*\s+(?:across|between)\s+\w*\s*windows?"
    r"|within[- ]invocation"
    r"|same[- ]ELF\s+(?:re[- ]?run|second run)"
    r"|second\s+(?:same[- ]ELF\s+)?(?:admitted\s+)?run",
    re.I,
)

# An absolute incumbent cost, in any of the forms the ledger actually uses: the
# harness's own machine-readable key, or prose naming the kernel/incumbent arm
# next to a time unit. Deliberately does NOT accept a bare number near the word
# "kernel" — "kernel 6.17.0-41" would match and the row would pass while carrying
# no measurement at all.
INCUMBENT_ABSOLUTE = re.compile(
    r"kernel_median_wall_ns\s*[=:]"
    r"|kernel_operations_per_second\s*[=:]"
    r"|incumbent_median_wall_ns\s*[=:]"
    r"|(?:kernel|incumbent)[^|\n]{0,60}?\b\d+(?:[.,]\d+)?\s*(?:ns|us|\u00b5s|ms|s)\b"
    r"|\b\d+(?:[.,]\d+)?\s*(?:ns|us|\u00b5s|ms|s)\b[^|\n]{0,60}?(?:kernel|incumbent)",
    re.I,
)

BOOTSTRAP = re.compile(r"\bbootstrap(?:ped|ping)?\b|\bresampl(?:e|ed|es|ing)\b", re.I)
MEDIAN = re.compile(r"\bmedian\b", re.I)
CONFIDENCE_INTERVAL = re.compile(r"\bCI\b|\bconfidence interval\b", re.I)
CV_MENTION = re.compile(r"\bCVs?\b|\bcoefficients? of variation\b", re.I)
CV_DISCLAIMER = re.compile(
    r"\bcv_used\s*=\s*false\b|"
    r"\b(?:no|not an?|without an?)\s+"
    r"(?:CVs?|coefficients? of variation)\s+"
    r"(?:gate|threshold|decision|input)\b|"
    r"\b(?:never|not|no)\b[^.;|\n]{0,48}"
    r"\b(?:gate(?:d|s|ing)?|input|decision|consult(?:ed|s|ing)?|used?)\b"
    r"[^.;|\n]{0,48}\b(?:CVs?|coefficients? of variation)\b|"
    r"\b(?:CVs?|coefficients? of variation)\b[^.;|\n]{0,48}"
    r"\b(?:never|not|no)\b[^.;|\n]{0,48}"
    r"\b(?:gate(?:d|s|ing)?|input|inputs|decision|consulted|used)\b",
    re.I,
)
CV_GATE_WORD = re.compile(
    r"\b(?:gate(?:d|s|ing)?|threshold|ceiling|admission|admitted|acceptance|"
    r"accepted|rejection|rejected|decide(?:d|s)?|decision|verdict|required?|"
    r"requirement|mandatory)\b",
    re.I,
)
CV_COMPARISON = re.compile(
    r"(?:\bCVs?\b|\bcoefficients? of variation\b)"
    r"[^.;|\n]{0,40}(?:<=|>=|<|>|≤|≥|\bbelow\b|\bunder\b|\babove\b|\bover\b)"
    r"|(?:<=|>=|<|>|≤|≥|\bbelow\b|\bunder\b|\babove\b|\bover\b)"
    r"[^.;|\n]{0,40}(?:\bCVs?\b|\bcoefficients? of variation\b)",
    re.I,
)

REJECT_VERDICT = re.compile(
    r"(?:\*\*)?(?:⭐+\s*)?(REJECT|REFUTED|NULL\b|INVALID|NO-SHIP|NOT[- ]A[- ]LEVER|"
    r"NEGATIVE\s*/|BLOCKED|REVERTED|NEG-LEVER)",
    re.I,
)
KEEP_VERDICT = re.compile(
    r"(?:\*\*)?(?:⭐+\s*)?(KEEP|SHIPPED|LANDED|WIN\b|FLIPPED|PASS\b|CONFIRMED)", re.I
)
SURVEY_VERDICT = re.compile(
    r"(?:\*\*)?(SURVEY\b|SURFACE|N/A|NO CODE\b|NO-GAP|AUDIT (?:COMPLETE|CORRECTED)\b)",
    re.I,
)

RETRY = re.compile(r"[Rr]etry (?:only )?(?:predicate|condition|if|on|when)[^|]{0,400}")
RETRY_START = re.compile(
    r"(?:\*\*)?[Rr]etry (?:only )?(?:predicate|condition|if|on|when)",
)


def decision_evidence(text: str) -> str:
    """Exclude a future retry clause from evidence about the run that just happened."""
    retry = RETRY_START.search(text)
    return text[: retry.start()] if retry else text


class Row:
    __slots__ = ("path", "line", "text", "verdict")

    def __init__(self, path: Path, line: int, text: str, verdict: str) -> None:
        self.path, self.line, self.text, self.verdict = path, line, text, verdict

    @property
    def ref(self) -> str:
        return f"{_display_path(self.path)}:{self.line}"

    def admissible(self) -> tuple[bool, str]:
        if NULL_CONTROL.search(self.text):
            return True, "A/A null control"
        if COUNTED_MECHANISM.search(self.text):
            return True, "counted mechanism"
        return False, "none"

    def reject_contract_basis(self) -> tuple[bool, str]:
        evidence = decision_evidence(self.text)
        if CONTRACT_COUNTED_MECHANISM.search(evidence):
            return True, "counted mechanism"
        if self.has_same_invocation_null_control():
            return True, "same-invocation A/A null control"
        return False, "none"

    def has_same_invocation_null_control(self) -> bool:
        evidence = decision_evidence(self.text)
        return bool(
            CONTRACT_NULL_VALUE.search(evidence)
            and SAME_INVOCATION_WITNESS.search(evidence)
        )

    def incumbent_denominator(self) -> str:
        """Provenance of this row's incumbent ratio, strongest class first."""
        evidence = decision_evidence(self.text)
        if not INCUMBENT_RATIO.search(evidence):
            return "none"
        if SAME_INVOCATION_INCUMBENT_ARM.search(evidence):
            return "live_same_invocation"
        return "quoted_or_adjacent"

    def convertibility(self) -> str:
        """Why an un-converted claim is un-converted."""
        evidence = decision_evidence(self.text)
        if NOT_A_FILESYSTEM_CLAIM.search(evidence):
            return "not_a_filesystem_claim"
        if POSIX_REACHABLE_SURFACE.search(evidence):
            return "convertible_unmeasured"
        if NO_INCUMBENT_SURFACE.search(evidence):
            return "no_incumbent_arm_possible"
        return "unclassified"

    def has_executing_elf_sha256(self) -> bool:
        return bool(EXECUTING_ELF_SHA256.search(decision_evidence(self.text)))

    def has_worker_identity(self) -> bool:
        return bool(WORKER_IDENTITY.search(self.text))

    def allows_multiple_workers(self) -> bool:
        return bool(MULTI_WORKER.search(self.text))

    @property
    def title(self) -> str:
        """Stable identity for a row across edits that shift line numbers.

        A table row is identified by its Bead/surface cell (cell 1), an entry by
        its heading text -- both are the first physical line, which parse_text()
        puts at the head of `text` for either shape.
        """
        first = self.text.splitlines()[0] if self.text else ""
        if first.startswith("| 2026"):
            cells = [c.strip() for c in first.strip().strip("|").split(" | ")]
            return cells[1] if len(cells) > 1 else cells[0]
        return first.lstrip("#").strip()

    def is_worker_scoped_ratio(self) -> bool:
        """A banked competitive claim that cannot name the machine it ran on.

        KEEP + quotes a vs-incumbent ratio + no worker/host identity. Deliberately
        NARROWER than "unnamed": an unnamed KEEP that quotes no incumbent ratio is
        making no cross-machine comparison, so it is not in scope here.
        """
        return (
            self.verdict == "KEEP"
            and not self.has_worker_identity()
            and bool(INCUMBENT_RATIO.search(decision_evidence(self.text)))
        )

    def lacks_precision_scope(self) -> bool:
        """A banked competitive claim quoting a CI without saying what it bounds.

        Fourth sibling of is_worker_scoped_ratio (which machine),
        is_placement_scoped_mounted_ratio (where on it) and
        lacks_incumbent_absolute (what the incumbent cost). This one asks whether
        the row says its interval is a WITHIN-INVOCATION bound.

        Narrower than "quotes a ratio", on purpose. A row carrying no interval is
        making no precision claim to overstate, so only rows that quote BOTH a
        vs-incumbent ratio and a confidence interval are in scope; those are the
        rows a reader will compare against a later measurement.
        """
        if self.verdict != "KEEP":
            return False
        evidence = decision_evidence(self.text)
        if not INCUMBENT_RATIO.search(evidence):
            return False
        if not CONFIDENCE_INTERVAL.search(evidence):
            return False
        return not PRECISION_SCOPE_ACKNOWLEDGED.search(evidence)

    def lacks_incumbent_absolute(self) -> bool:
        """A banked competitive claim that transcribes the QUOTIENT but not the
        incumbent's absolute cost (bd-4sull item 3).

        Third sibling of is_worker_scoped_ratio (which machine) and
        is_placement_scoped_mounted_ratio (where on it). This one asks what the
        INCUMBENT actually cost, because a ratio cannot be re-derived into its
        parts, and incumbent volatility lands in the published number even when
        our own cost is stable.

        Same narrowing as its siblings: a KEEP quoting no vs-incumbent ratio makes
        no competitive claim, so it is out of scope.
        """
        if self.verdict != "KEEP":
            return False
        evidence = decision_evidence(self.text)
        return bool(INCUMBENT_RATIO.search(evidence)) and not INCUMBENT_ABSOLUTE.search(
            evidence
        )

    def is_placement_scoped_mounted_ratio(self) -> bool:
        """A banked MOUNTED competitive claim that does not say where the daemon ran.

        Narrower than "mounted": a mounted row quoting no incumbent ratio makes no
        cross-configuration comparison, so an undeclared placement costs it
        nothing. This is the bd-plt79 analogue of `is_worker_scoped_ratio` -- that
        one asks which MACHINE, this one asks where on it.
        """
        if self.verdict != "KEEP":
            return False
        evidence = decision_evidence(self.text)
        return (
            bool(MOUNTED_ROW.search(evidence))
            and bool(INCUMBENT_RATIO.search(evidence))
            and not DAEMON_PLACEMENT.search(evidence)
        )

    def has_bootstrap_median_ci(self) -> bool:
        evidence = decision_evidence(self.text)
        return any(
            BOOTSTRAP.search(clause)
            and MEDIAN.search(clause)
            and CONFIDENCE_INTERVAL.search(clause)
            for clause in re.split(r"\n|\|", evidence)
        )

    def missing_absolute_arm_medians(self) -> list[str]:
        """Arms whose ABSOLUTE median this competitive row fails to record.

        Empty for any row that is not a live same-invocation incumbent claim --
        the requirement is about decomposing a *competitive ratio*, so it does not
        apply to internal A/B rows, which have no incumbent arm to separate.
        """
        if self.incumbent_denominator() != "live_same_invocation":
            return []
        evidence = decision_evidence(self.text)
        missing = []
        if not INCUMBENT_ABSOLUTE_MEDIAN.search(evidence):
            missing.append("incumbent")
        if not CANDIDATE_ABSOLUTE_MEDIAN.search(evidence):
            missing.append("candidate")
        return missing

    def uses_cv_as_gate(self) -> bool:
        # Unlike run evidence, the CV prohibition includes retry predicates: a
        # newly-written row must not instruct the next agent to resurrect the old
        # CV gate. Split into short clauses so an explicit "cv_used=false" does
        # not accidentally excuse a positive CV threshold elsewhere in the row.
        for clause in re.split(r"(?<=[.;])\s+|\n|\|", self.text):
            if not CV_MENTION.search(clause):
                continue
            if CV_DISCLAIMER.search(clause):
                continue
            if CV_GATE_WORD.search(clause) or CV_COMPARISON.search(clause):
                return True
        return False


def structure_violations(row: Row) -> list[str]:
    """A STRUCTURE row is exempt from the decision contract, so it must not be
    carrying a decision. This closes the only evasion route the exemption opens:
    dropping the date and bead id from a heading to escape the KEEP contract."""
    evidence = decision_evidence(row.text)
    carries = [
        name
        for name, rx in (
            ("a vs-incumbent ratio", INCUMBENT_RATIO),
            ("an executing-ELF SHA-256", EXECUTING_ELF_SHA256),
        )
        if rx.search(evidence)
    ]
    if row.has_bootstrap_median_ci():
        carries.append("a bootstrap median CI")
    if not carries:
        return []
    return [
        "unattributable decision: this heading names neither a date nor a bead id, "
        "so it is treated as document structure and exempted from the decision "
        "contract, but it carries " + " and ".join(carries) + ". Give the heading "
        "its date or bead id so it is linted as the decision row it is."
    ]


def contract_violations(row: Row) -> list[str]:
    """Return forward-contract violations for one staged decision row."""
    bad: list[str] = []
    if row.uses_cv_as_gate():
        bad.append("CV is used as a gate or threshold (median CI is mandatory)")
    missing_arms = row.missing_absolute_arm_medians()
    if missing_arms:
        bad.append(
            "competitive row records no absolute median for the "
            + " and ".join(missing_arms)
            + " arm (bd-4sull item 3: a ratio alone cannot say which arm moved; "
            "the harness prints kernel_median_wall_ns / fuse_median_wall_ns)"
        )
    if row.allows_multiple_workers():
        bad.append(
            "the run was allowed to schedule across more than one worker "
            "(RCH_WORKERS lists several), so its arms cannot be same-worker by "
            "construction; pin a single worker and re-run"
        )
    timed = row.verdict == "KEEP" or (
        row.verdict == "REJECT" and row.has_same_invocation_null_control()
    )
    if timed and not row.has_worker_identity():
        bad.append(
            "no worker/host identity recorded (a passing A/A null does not make a "
            "cross-worker comparison valid: the same cell measured 1.2693x on one "
            "worker and 0.0093x on another with both nulls passing; an unnamed row "
            "cannot be compared to any other row)"
        )
    if row.verdict == "REJECT":
        ok, _ = row.reject_contract_basis()
        if not ok:
            bad.append("no A/A null control and no counted mechanism")
        elif (
            row.has_same_invocation_null_control()
            and not row.has_bootstrap_median_ci()
        ):
            bad.append("numeric same-invocation A/A decision has no bootstrap median CI")
    elif row.verdict == "KEEP":
        if not row.has_executing_elf_sha256():
            bad.append("no in-process self-report of the executing ELF's SHA-256")
        if not row.has_bootstrap_median_ci():
            bad.append("timed KEEP has no bootstrap median CI")
    return bad


# --- document structure is not a decision (bd-eqm8s) -------------------------
# The last-resort branch of verdict_of() scans the whole BODY for a verdict word,
# case-insensitively. That makes any prose containing the word "keep" a banked KEEP:
# the '## Rules' section of perf-negative-results.md says "record the exact
# keep/reject/pending status" and was classified KEEP, so editing the ledger's own
# rules list made --lint --staged demand a bootstrap CI and an ELF SHA-256 from it.
#
# A banked decision is ATTRIBUTABLE: to WHEN it was decided (a date) or to the work
# item it decided (a bead id). A heading carrying neither is document structure.
# Table rows are never affected -- their date lives in cell 0.
#
# Measured before/after over both ledgers (1209 rows): exactly 5 heading entries
# carry neither, and all 5 improve.
#   KEEP    -> STRUCTURE  perf-negative-results.md  'Rules'
#   KEEP    -> STRUCTURE  perf-negative-results.md  'Seeded Do-Not-Retry Rows From Prior No-Gaps Work'
#   KEEP    -> STRUCTURE  NEGATIVE_EVIDENCE.md      'Also characterized (NOT landed) - MVCC prune ...'
#   UNKNOWN -> STRUCTURE  perf-negative-results.md  'Gauntlet Release-Readiness Scorecard'
#   UNKNOWN -> STRUCTURE  perf-negative-results.md  'Current Campaign Rows'
# The first two are prose containers. The third is an explicitly NOT-landed
# characterized candidate -- it was never kept, so KEEP was wrong there too.
#
# REJECTED alternative, measured, do not retry: "require the verdict word in the
# body fallback to be UPPERCASE and standalone". It reclassifies 217 of 1209 rows,
# because legitimate entries narrate in lowercase ("frankenfs dominates", "we keep
# the lever"). A fix that moves 217 rows to correct 1 is not a fix.
#
# This cannot become an evasion route ("drop the date to dodge the KEEP contract"):
# a structure row whose body carries decision evidence is refused outright below.
TITLE_DATE = re.compile(r"20\d{2}-\d{2}-\d{2}")
TITLE_BEAD = re.compile(r"\bbd-[a-z0-9]", re.I)


def is_document_structure(cells: list[str], title: str) -> bool:
    """A heading entry attributable to neither a date nor a bead id."""
    if cells:  # a table row: its date is cell 0
        return False
    return not TITLE_DATE.search(title) and not TITLE_BEAD.search(title)


def verdict_of(cells: list[str], title: str, body: str) -> str:
    """Verdict from the table's Verdict column, else the prose title, else the body."""
    if is_document_structure(cells, title):
        return "STRUCTURE"
    for idx in (3, 2, 4):
        if idx < len(cells):
            head = cells[idx][:400]
            best, pos = "", 10**9
            for rx, name in (
                (KEEP_VERDICT, "KEEP"),
                (REJECT_VERDICT, "REJECT"),
                (SURVEY_VERDICT, "SURVEY"),
            ):
                m = rx.search(head)
                if m and m.start() < pos:
                    best, pos = name, m.start()
            if best:
                return best
    if REJECT_VERDICT.search(title) and not KEEP_VERDICT.search(title):
        return "REJECT"
    if KEEP_VERDICT.search(title):
        return "KEEP"
    blob = title + "\n" + body
    for rx, name in ((KEEP_VERDICT, "KEEP"), (REJECT_VERDICT, "REJECT")):
        if rx.search(blob):
            return name
    return "UNKNOWN"


def parse_text(path: Path, text: str, entry_level: int = 3) -> list[Row]:
    """Parse a ledger into rows. Handles both the 8-column table and prose sections."""
    rows: list[Row] = []
    lines = text.splitlines(keepends=True)
    # (line, level, title, body). `level` matters: a well-written entry uses `###`
    # SUBSECTIONS to hold its evidence tables, and treating those as new entries
    # orphans the evidence from its heading — which reports a fully-evidenced row
    # as unfalsifiable. A false positive is worse than a miss here, because a guard
    # that cries wolf gets disabled. So a heading only starts a NEW row when it is
    # at the same level as, or shallower than, the row it interrupts.
    pending: tuple[int, int, str, str] | None = None

    def flush() -> None:
        if pending:
            pl, _, pt, pb = pending
            rows.append(Row(path, pl, pt + "\n" + pb, verdict_of([], pt, pb)))

    for i, ln in enumerate(lines, 1):
        if ln.startswith("| 2026"):
            cells = [c.strip() for c in ln.strip().strip("|").split(" | ")]
            title = cells[1] if len(cells) > 1 else cells[0]
            rows.append(Row(path, i, ln, verdict_of(cells, title, ln)))
            continue
        heading = re.match(r"(#{1,6})\s", ln)
        if heading:
            depth = len(heading.group(1))
            if depth < entry_level:      # grouping heading (e.g. a date section)
                flush()
                pending = None
                continue
            if depth == entry_level:     # a new entry
                flush()
                pending = (i, depth, ln.lstrip("#").strip(), "")
                continue
            # deeper: a subsection of the current entry -> body
        if pending:
            pl, lv, pt, pb = pending
            pending = (pl, lv, pt, pb + ln)
    flush()
    return rows


def parse(path: Path, entry_level: int = 3) -> list[Row]:
    if not path.exists():
        return []
    return parse_text(path, path.read_text(errors="replace"), entry_level)


def all_rows() -> list[Row]:
    return [r for p, lvl in LEDGERS for r in parse(p, lvl)]


# --- mode: candidate preflight ----------------------------------------------

STOP = {
    "the", "a", "an", "and", "or", "of", "for", "to", "in", "on", "is", "it", "with",
    "per", "via", "into", "from", "that", "this", "then", "than", "not", "but", "by",
    "lever", "perf", "fast", "slow", "faster", "make", "use", "using", "new", "add",
    "src", "lib", "mod",
}


def terms(text: str) -> list[str]:
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text.lower())
    return [w for w in dict.fromkeys(words) if w not in STOP]


def candidate_match(
    row: Row,
    candidate_terms: list[str],
    surface_terms: list[str],
    threshold: int,
) -> tuple[int, list[str], list[str]] | None:
    low = row.text.lower()
    surface_hits = [word for word in surface_terms if word in low]
    candidate_hits = [word for word in candidate_terms if word in low]
    all_hits = list(dict.fromkeys(surface_hits + candidate_hits))
    if not surface_hits or len(all_hits) < threshold:
        return None
    # A caller who supplies a qualified function/module identifier is naming an
    # exact surface, not merely a bag of generic nouns. Require that identifier
    # (or a more-qualified member of its family) in the prior row. Without this,
    # `generate_send_stream inode grouping BTreeMap` falsely matched an unrelated
    # snapshot-diff row through only "inode", "BTreeMap", and "ordered".
    qualified_surface = [word for word in surface_terms if "_" in word]
    if qualified_surface and not any(word in surface_hits for word in qualified_surface):
        return None
    # Target-surface matches dominate proposal wording when ranking results.
    return 100 * len(surface_hits) + len(all_hits), surface_hits, candidate_hits


def cmd_candidate(text: str, surface: str, threshold: int) -> int:
    want = terms(text)
    target = terms(surface)
    if not want:
        print("preflight: candidate description has no searchable terms", file=sys.stderr)
        return 64
    if not target:
        print("preflight: target surface has no searchable terms", file=sys.stderr)
        return 64
    hits = []
    for r in all_rows():
        if r.verdict != "REJECT":
            continue
        matched = candidate_match(r, want, target, threshold)
        if matched:
            score, surface_hits, candidate_hits = matched
            hits.append((score, surface_hits, candidate_hits, r))
    if not hits:
        print(
            "preflight: OK — no prior REJECT covers "
            f"surface={target[:6]} proposal={want[:6]}"
        )
        return 0
    hits.sort(key=lambda h: -h[0])
    print("preflight: BLOCKED — a prior REJECT covers this surface.\n")
    for _, surface_hits, candidate_hits, r in hits[:5]:
        print(f"  {r.ref}")
        print(f"    target matches: {', '.join(surface_hits[:8])}")
        print(f"    proposal matches: {', '.join(candidate_hits[:8]) or '(none)'}")
        title = r.text.split("\n")[0][:200]
        print(f"    {title}")
        m = RETRY.search(r.text)
        print(f"    retry: {m.group(0)[:300].strip() if m else '(none recorded)'}\n")
    print("Satisfy the retry predicate and cite it, or pick a different vein.")
    print("Overriding without satisfying it is how a repo re-derives a closed frontier.")
    return 2


# --- mode: lint (the anti-decay gate) ---------------------------------------


def git_capture(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"git {' '.join(args)} failed: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def changed_line_numbers(
    path: Path,
    *,
    since: str | None = None,
    staged: bool = False,
) -> set[int]:
    """Return new-file line numbers touched by a committed or staged diff."""
    rel = path.relative_to(ROOT).as_posix()
    args = ["diff"]
    if staged:
        args.append("--cached")
    args.append("-U0")
    if since:
        args.append(f"{since}...HEAD")
    args.extend(["--", rel])
    diff = git_capture(args)
    added: set[int] = set()
    for hunk in re.finditer(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", diff, re.M):
        start = int(hunk.group(1))
        count = int(hunk.group(2) or 1)
        added.update(range(start, start + count))
    return added


def ledger_text(path: Path, *, staged: bool, at_head: bool) -> str:
    # Only the git-backed reads need a repo-relative path. Computing it eagerly made
    # a plain filesystem read raise for any ledger outside ROOT, which is exactly the
    # shape the ratchet and structure tests use.
    if staged or at_head:
        rel = path.relative_to(ROOT).as_posix()
        return git_capture(["show", f"{'' if staged else 'HEAD'}:{rel}"])
    return path.read_text(errors="replace")


def row_line_span(row: Row) -> range:
    """Physical source lines occupied by a row, excluding a trailing-newline phantom.

    Trailing BLANK lines are excluded too (bd-ha71t). A row's body runs until the
    next heading, so it absorbs the blank separator before that heading. Appending
    a new entry therefore added a line inside the PREVIOUS row's span and marked it
    "touched", forcing an untouched historical row through the forward contract —
    i.e. you could not append a compliant row without first repairing whatever came
    before it. The contract is meant to bind new and modified rows only, so the
    separator is not part of either neighbour.
    """
    lines = row.text.splitlines()
    while len(lines) > 1 and not lines[-1].strip():
        lines.pop()
    return range(row.line, row.line + max(1, len(lines)))


def cmd_lint(since: str | None, staged: bool) -> int:
    if staged and since:
        print("preflight lint: --staged and --since are mutually exclusive", file=sys.stderr)
        return 64
    bad: list[tuple[Row, str]] = []
    checked = {"REJECT": 0, "KEEP": 0}
    structure_checked = 0
    selective = staged or since is not None
    try:
        for path, lvl in LEDGERS:
            touched = (
                changed_line_numbers(path, since=since, staged=staged)
                if selective
                else None
            )
            if selective and not touched:
                continue
            text = ledger_text(path, staged=staged, at_head=since is not None)
            for row in parse_text(path, text, lvl):
                if row.verdict == "STRUCTURE":
                    if touched is not None and not touched.intersection(
                        row_line_span(row)
                    ):
                        continue
                    structure_checked += 1
                    violations = structure_violations(row)
                    if violations:
                        bad.append((row, "; ".join(violations)))
                    continue
                if row.verdict not in checked:
                    continue
                if touched is not None:
                    if not touched.intersection(row_line_span(row)):
                        continue
                checked[row.verdict] += 1
                violations = contract_violations(row)
                if violations:
                    bad.append((row, "; ".join(violations)))
    except (OSError, RuntimeError) as exc:
        print(f"preflight lint: infrastructure failure: {exc}", file=sys.stderr)
        return 64

    scope = "staged index" if staged else (f"committed since {since}" if since else "whole ledger")
    total = sum(checked.values()) + structure_checked
    structure_note = (
        f", {structure_checked} document-structure" if structure_checked else ""
    )
    if not bad:
        print(
            f"preflight lint: OK — {total} row(s) in {scope} "
            f"({checked['REJECT']} REJECT, {checked['KEEP']} KEEP{structure_note})"
        )
        return 0
    print(
        f"preflight lint: BLOCKED — {len(bad)} of {total} row(s) "
        f"in {scope} violate the ledger contract:\n"
    )
    for row, why in bad:
        print(f"  {row.ref}\n    {row.text.splitlines()[0][:180]}\n    reason: {why}\n")
    print("A REJECT must record either:")
    print("  - an A/A null control in the same invocation with a bootstrap median CI, or")
    print("  - a counted mechanism (instructions/cycles/syscalls/allocs/profile count).")
    print("A KEEP must record a bootstrap median CI and a full SHA-256")
    print("self-reported by the executing ELF.")
    print("CV may be reported as provenance, but it must never be a gate or threshold.")
    print("A neighboring sha256sum is not proof of which binary ran.")
    return 2


def _display_path(path: Path) -> str:
    """Repo-relative when possible. A ledger can sit outside ROOT under test, and a
    reporting helper must never be the thing that raises."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def worker_scoped_rows(rows: list[Row] | None = None) -> list[Row]:
    return [r for r in (all_rows() if rows is None else rows) if r.is_worker_scoped_ratio()]


def placement_scoped_rows(rows: list[Row] | None = None) -> list[Row]:
    return [
        r
        for r in (all_rows() if rows is None else rows)
        if r.is_placement_scoped_mounted_ratio()
    ]


def precision_scope_missing_rows(rows: list[Row] | None = None) -> list[Row]:
    return [r for r in (all_rows() if rows is None else rows) if r.lacks_precision_scope()]


def cmd_precision_scope_audit(list_rows: bool) -> int:
    """Enumerate banked competitive rows that quote a CI without scoping it.

    bd-4sull item 2. The interval these rows publish bounds error INSIDE one
    invocation; the comparison a reader makes with it is across windows, where the
    measured spread is roughly an order of magnitude wider.
    """
    scoped = precision_scope_missing_rows()
    n = len(scoped)
    print(f"precision-scope-audit: {n} banked KEEP ratio(s) quote a CI without scoping it")
    if list_rows:
        for r in scoped:
            print(f"  {r.ref}\n    {r.title[:160]}")
    if PRECISION_SCOPE_BASELINE is None:
        print(
            f"\nprecision-scope-audit: baseline UNSEEDED - {n} row(s) found. Set "
            f"PRECISION_SCOPE_BASELINE = {n} to arm the ratchet. Measured stake: "
            "admitted rows re-measure to a median 1.1022x (worst 1.1314x) across "
            "windows, against a published CI of typically 0.5-1%; and 35 of 38 "
            "like-for-like groups have never had a second admitted run, so for "
            "almost every row the CI is the only figure and is a lower bound."
        )
        return 0
    if n > PRECISION_SCOPE_BASELINE:
        print(
            f"precision-scope-audit: FAIL - {n} exceeds the {PRECISION_SCOPE_BASELINE} "
            "floor; a new competitive ratio was banked quoting an interval without "
            "saying it bounds one invocation only."
        )
        return 1
    return 0


def incumbent_absolute_missing_rows(rows: list[Row] | None = None) -> list[Row]:
    return [
        r for r in (all_rows() if rows is None else rows) if r.lacks_incumbent_absolute()
    ]


def cmd_incumbent_absolute_audit(list_rows: bool) -> int:
    """Enumerate banked competitive ratios that never record the incumbent's cost.

    bd-4sull item 3. The bead calls this the cheap one that stops the class of
    question recurring, and the reason is durability: reports are reaped on this
    host (45 of 46 once already, and the 2026-07-31 bulk-durable row was left
    undiagnosable by exactly that), so the ledger row is the only artefact that
    survives. A ratio alone cannot be decomposed after the fact.
    """
    scoped = incumbent_absolute_missing_rows()
    n = len(scoped)
    print(f"incumbent-absolute-audit: {n} banked KEEP ratio(s) carry no incumbent median")
    if list_rows:
        for r in scoped:
            print(f"  {r.ref}\n    {r.title[:160]}")
    if INCUMBENT_ABSOLUTE_BASELINE is None:
        print(
            f"\nincumbent-absolute-audit: baseline UNSEEDED - {n} row(s) found. Set "
            f"INCUMBENT_ABSOLUTE_BASELINE = {n} to arm the ratchet. Measured stake: "
            "admitted rows re-measure ~10% between windows (median 1.1022x over the "
            "3 like-for-like groups that have a second admitted run), against a "
            "published CI of 0.5-1%; with only the quotient banked, none of that "
            "can be attributed to an arm after the report is reaped."
        )
        return 0
    if n > INCUMBENT_ABSOLUTE_BASELINE:
        print(
            f"incumbent-absolute-audit: FAIL - {n} exceeds the "
            f"{INCUMBENT_ABSOLUTE_BASELINE} floor; a new competitive ratio was banked "
            "without the incumbent's absolute median. Record it in the row."
        )
        return 1
    return 0


def cmd_placement_audit(list_rows: bool) -> int:
    """Enumerate the banked MOUNTED ratios that never say where the daemon ran.

    bd-plt79 item 3. The sibling of --worker-scope one level down: that asks
    which machine a row ran on, this asks where on that machine the FUSE daemon
    was placed. Both exist because a number that looks precise is not thereby
    comparable to another number.

    Reports rather than blocks on the first run, because the baseline has to be
    discovered before it can be ratcheted, and because this finding explicitly
    does NOT retract any banked row -- it says the uncertainty on those rows is
    larger than recorded and gives its size.
    """
    rows = all_rows()
    scoped = placement_scoped_rows(rows)
    mounted = [
        r
        for r in rows
        if r.verdict == "KEEP" and MOUNTED_ROW.search(decision_evidence(r.text))
    ]
    n = len(scoped)

    from collections import Counter

    per_file = Counter(_display_path(r.path) for r in scoped)
    print(f"rows_parsed                 {len(rows)}")
    print(f"mounted_keep_rows           {len(mounted)}")
    print(f"placement_scoped_ratio_rows {n}")
    for f, k in sorted(per_file.items()):
        print(f"  {f:<40s} {k}")

    if list_rows:
        print("\nflagged (mounted KEEP quoting a ratio, no daemon placement declared):")
        for r in scoped:
            print(f"  {r.ref}\n    {r.title[:160]}")

    if PLACEMENT_SCOPE_BASELINE is None:
        print(
            f"\nplacement-audit: baseline UNSEEDED — {n} row(s) found. Set "
            f"PLACEMENT_SCOPE_BASELINE = {n} to arm the ratchet. Measured instrument "
            "floor for an unpinned mounted row: A/A null to 1.4875x and cross-run "
            "disagreement 1.2613x (bd-plt79), and a 1.72x disagreement against the "
            "pinned comparator at matched threads (263e70c8). Neither retracts a "
            "banked row; both say its recorded CI understates the uncertainty."
        )
        return 0

    if n > PLACEMENT_SCOPE_BASELINE:
        print(
            f"\nplacement-audit: BLOCKED — {n} placement-scoped mounted ratios "
            f"exceeds the {PLACEMENT_SCOPE_BASELINE}-row ratchet by "
            f"{n - PLACEMENT_SCOPE_BASELINE}. A new mounted ratio was banked without "
            "saying where its daemon ran. Record `--fuse-cpus N` or the report's "
            "`placement_scope=`; do not raise the baseline."
        )
        return 2

    print(f"\nplacement-audit: OK — {n} <= {PLACEMENT_SCOPE_BASELINE}")
    return 0


def _placement_scope_ratchet_checks() -> list[tuple[str, bool]]:
    """bd-plt79: the mounted-placement ratchet, and the predicate under it.

    Pinned to the same shape as the worker-scope checks so the two cannot drift:
    a synthetic mounted ratio that declares no placement must be flagged, one
    that declares any of the recognised forms must not, and a mounted row that
    quotes no incumbent ratio must be out of scope entirely.
    """
    sha = "b" * 64
    body = (
        "mounted_kernel_ratio,filesystem=btrfs,fuse_over_kernel_median=3.36 "
        "vs kernel btrfs 3.36x slower; median 95% CI [3.3, 3.4]; "
        f"executing_elf_sha256 = {sha}. hostname=thinkstation1.\n"
    )
    undeclared = Row(Path("x.md"), 1, "## 2026-08-16 — KEEP: m (bd-x)\n" + body, "KEEP")
    declared = Row(
        Path("x.md"),
        1,
        "## 2026-08-16 — KEEP: m (bd-x)\n" + body + "placement_scope=same_llc, --fuse-cpus 1.\n",
        "KEEP",
    )
    no_ratio = Row(
        Path("x.md"),
        1,
        "## 2026-08-16 — KEEP: m (bd-x)\nmounted_kernel_ratio counted 4000 probes -> 4000 probes.\n",
        "KEEP",
    )
    return [
        (
            "a mounted ratio declaring no daemon placement is placement-scoped",
            undeclared.is_placement_scoped_mounted_ratio(),
        ),
        (
            "placement_scope=/--fuse-cpus clears the placement scope",
            not declared.is_placement_scoped_mounted_ratio(),
        ),
        (
            "a mounted row quoting no incumbent ratio is out of placement scope",
            not no_ratio.is_placement_scoped_mounted_ratio(),
        ),
        (
            f"placement ratchet holds at {PLACEMENT_SCOPE_BASELINE}",
            len(placement_scoped_rows()) == PLACEMENT_SCOPE_BASELINE,
        ),
    ] + _incumbent_absolute_selftests()


def _incumbent_absolute_selftests() -> list[tuple[str, bool]]:
    """bd-4sull item 3. Kept separate so the discriminations are readable.

    The regex has to reject two things that LOOK like an incumbent measurement and
    are not: a kernel VERSION string, and our own arm's absolute time. Both appear
    verbatim in banked rows, so both are tested rather than assumed.
    """
    def keep(body: str) -> Row:
        return Row(Path("x.md"), 1, "## 2026-08-16 - KEEP: m (bd-x)\n" + body, "KEEP")

    ratio = "mounted 5.753947x SLOWER than kernel ext4, ci95 [5.642761, 5.776242]. "
    return [
        (
            "a competitive ratio with no incumbent absolute is flagged",
            keep(ratio).lacks_incumbent_absolute(),
        ),
        (
            "the harness key clears it",
            not keep(ratio + "kernel_median_wall_ns=47935843.").lacks_incumbent_absolute(),
        ),
        (
            "prose naming the incumbent beside a time clears it",
            not keep(ratio + "the kernel arm held 77.05 ms.").lacks_incumbent_absolute(),
        ),
        (
            "a kernel VERSION is not a measurement and must not clear it",
            keep(ratio + "kernel 6.17.0-41-generic.").lacks_incumbent_absolute(),
        ),
        (
            "OUR arm's absolute time is not the incumbent's and must not clear it",
            keep(ratio + "fuse_median_wall_ns=275860548 (13.792 us/op).").lacks_incumbent_absolute(),
        ),
        (
            "a KEEP quoting no vs-incumbent ratio is out of scope",
            not Row(
                Path("x.md"),
                1,
                "## 2026-08-16 - KEEP: m (bd-x)\ncounted 4000 probes -> 4000 probes.\n",
                "KEEP",
            ).lacks_incumbent_absolute(),
        ),
        (
            "a REJECT makes no competitive claim and is out of scope",
            not Row(Path("x.md"), 1, "## 2026-08-16 - REJECT: m (bd-x)\n" + ratio, "REJECT").lacks_incumbent_absolute(),
        ),
        (
            f"incumbent-absolute ratchet holds at {INCUMBENT_ABSOLUTE_BASELINE}",
            len(incumbent_absolute_missing_rows()) == INCUMBENT_ABSOLUTE_BASELINE,
        ),
    ] + _precision_scope_selftests()


def _precision_scope_selftests() -> list[tuple[str, bool]]:
    """bd-4sull item 2.

    The predicate must be narrow in two directions at once: a row carrying no
    INTERVAL is making no precision claim to overstate, and a row that already
    scopes its interval is compliant however it words it.
    """

    def keep(body: str) -> Row:
        return Row(Path("x.md"), 1, "## 2026-08-16 - KEEP: m (bd-x)\n" + body, "KEEP")

    ratio_ci = (
        "mounted 5.753947x SLOWER than kernel ext4, median 95% CI [5.642761, 5.776242]. "
    )
    return [
        (
            "a competitive ratio quoting a CI with no scope is flagged",
            keep(ratio_ci).lacks_precision_scope(),
        ),
        (
            "naming the cross-window spread clears it",
            not keep(ratio_ci + "cross-window spread 1.1022x.").lacks_precision_scope(),
        ),
        (
            "an explicit within-invocation caveat clears it",
            not keep(ratio_ci + "this CI is within-invocation only.").lacks_precision_scope(),
        ),
        (
            "citing a second same-ELF run clears it",
            not keep(ratio_ci + "a second same-ELF run agreed.").lacks_precision_scope(),
        ),
        (
            "a bare mention of a quiet window does NOT clear it",
            keep(ratio_ci + "taken in a quiet window on thinkstation1.").lacks_precision_scope(),
        ),
        (
            "a ratio with no interval is making no precision claim",
            not keep("mounted 5.75x SLOWER than kernel ext4.").lacks_precision_scope(),
        ),
        (
            "a REJECT makes no competitive claim",
            not Row(
                Path("x.md"), 1, "## 2026-08-16 - REJECT: m (bd-x)\n" + ratio_ci, "REJECT"
            ).lacks_precision_scope(),
        ),
        (
            f"precision-scope ratchet holds at {PRECISION_SCOPE_BASELINE}",
            len(precision_scope_missing_rows()) == PRECISION_SCOPE_BASELINE,
        ),
    ]


def cmd_worker_scope(list_rows: bool) -> int:
    """Enumerate and ratchet the banked competitive rows that name no host.

    This is the retroactive counterpart to the staged WORKER_IDENTITY check. It
    flags those rows as worker-scoped -- readable to a human via --list, and
    enforced as a monotone ratchet so the count can only fall.
    """
    rows = all_rows()
    scoped = worker_scoped_rows(rows)
    multi = [r for r in rows if r.allows_multiple_workers()]
    n = len(scoped)

    from collections import Counter

    per_file = Counter(_display_path(r.path) for r in scoped)
    print(f"rows_parsed              {len(rows)}")
    print(f"keep_rows                {sum(1 for r in rows if r.verdict == 'KEEP')}")
    print(f"worker_scoped_ratio_rows {n}")
    for f, k in sorted(per_file.items()):
        print(f"  {f:<40s} {k}")
    print(f"known_multi_worker_rows  {len(multi)}")
    print(f"ratchet_baseline         {WORKER_SCOPE_BASELINE}")

    if list_rows:
        print("\nflagged worker-scoped (KEEP quoting a vs-incumbent ratio, no host named):")
        for r in scoped:
            print(f"  {r.ref}\n    {r.title[:160]}")

    if multi:
        print(
            f"\nworker-scope: BLOCKED — {len(multi)} row(s) admit scheduling across "
            "several workers, so their arms cannot be same-machine by construction:"
        )
        for r in multi:
            print(f"  {r.ref}\n    {r.title[:160]}")
        return 2

    if n > WORKER_SCOPE_BASELINE:
        print(
            f"\nworker-scope: BLOCKED — {n} worker-scoped competitive rows exceeds the "
            f"{WORKER_SCOPE_BASELINE}-row ratchet by {n - WORKER_SCOPE_BASELINE}. A new "
            "banked ratio row named no execution host. Record the host it ran on "
            "(`RCH_WORKER=<id>`, or `same_host=<hostname>` for a local mounted run); "
            "do not raise the baseline."
        )
        return 2

    if n < WORKER_SCOPE_BASELINE:
        print(
            f"\nworker-scope: RATCHET LOOSE — {n} < baseline {WORKER_SCOPE_BASELINE}. "
            f"Rows gained their host; lower WORKER_SCOPE_BASELINE to {n} in this file "
            "so the gain cannot be silently given back."
        )
        return 2

    print(
        f"\nworker-scope: OK — {n} row(s) at the ratchet. Each is worker-SCOPED, not "
        "retracted: its arms were same-invocation by campaign law and no row is known "
        "multi-worker, but the machine is unrecorded, so it is not comparable to a row "
        "measured elsewhere."
    )
    return 0


def cmd_audit() -> int:
    rows = all_rows()
    from collections import Counter

    verdicts = Counter(r.verdict for r in rows)
    rejects = [r for r in rows if r.verdict == "REJECT"]
    reasons = Counter(r.admissible()[1] for r in rejects)
    void = sum(1 for r in rejects if not r.admissible()[0])
    print(f"entries_parsed   {len(rows)}")
    for k, n in verdicts.most_common():
        print(f"  {k:<10s}     {n}")
    print(f"reject_audited   {len(rejects)}")
    for k, n in reasons.most_common():
        print(f"  {k:<24s} {n}")
    pct = (100.0 * void / len(rejects)) if rejects else 0.0
    print(f"void_total       {void}")
    print(f"void_pct         {pct:.1f}")
    return 0


def cmd_incumbent_audit(show: str | None) -> int:
    """Three numbers: KEEP claims held, how many carry a LIVE same-invocation
    incumbent ratio, how many do not -- then why the rest do not."""
    from collections import Counter

    keeps = [r for r in all_rows() if r.verdict == "KEEP"]
    prov = Counter(r.incumbent_denominator() for r in keeps)
    live = prov["live_same_invocation"]
    print(f"keep_claims_total            {len(keeps)}")
    print(f"  live_same_invocation       {live}")
    print(f"  quoted_or_adjacent         {prov['quoted_or_adjacent']}")
    print(f"  no_incumbent_ratio         {prov['none']}")
    print(f"unconverted_total            {len(keeps) - live}")
    unconverted = [r for r in keeps
                   if r.incumbent_denominator() != "live_same_invocation"]
    why = Counter(r.convertibility() for r in unconverted)
    for key in ("convertible_unmeasured", "no_incumbent_arm_possible",
                "not_a_filesystem_claim", "unclassified"):
        print(f"  {key:<26s} {why[key]}")
    if show:
        for r in (keeps if show == "live_same_invocation"
                  else unconverted):
            if (r.incumbent_denominator() if show in
                    ("live_same_invocation", "quoted_or_adjacent", "none")
                    else r.convertibility()) == show:
                head = re.sub(r"\s+", " ", r.text)[:150]
                print(f"    {r.ref}  {head}")
    return 0


def _worker_scope_ratchet_checks() -> list[tuple[str, bool]]:
    """Drive cmd_worker_scope end to end against a synthetic ledger.

    The predicate tests above prove the row classifier. These prove the GATE: that
    the exit code actually moves. A classifier that is right while the gate always
    returns 0 is the failure mode worth catching, and only an end-to-end run sees it.
    """
    import io
    import tempfile
    from contextlib import redirect_stdout

    sha = "a" * 64
    named = "### 2026-08-15 — KEEP: named\n\nKEEP: 3.4x vs kernel ext4, bootstrap "
    named += f"median 95% CI [3.2, 3.6]; sha256 {sha}. RCH_WORKER=vmi1227854.\n"
    unnamed = "### 2026-08-15 — KEEP: unnamed\n\nKEEP: 3.4x vs kernel ext4, bootstrap "
    unnamed += f"median 95% CI [3.2, 3.6]; sha256 {sha}.\n"
    multi = "### 2026-08-15 — KEEP: multi\n\nKEEP: 3.4x vs kernel ext4; sha256 "
    multi += f"{sha}. RCH_WORKERS=ovh-a,hz2.\n"

    saved_ledgers, saved_baseline = LEDGERS[:], WORKER_SCOPE_BASELINE
    results: list[tuple[str, bool]] = []
    try:
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "synthetic-ledger.md"

            def run(body: str, baseline: int) -> int:
                global WORKER_SCOPE_BASELINE
                ledger.write_text("# Synthetic ledger\n\n" + body)
                LEDGERS[:] = [(ledger, 3)]
                WORKER_SCOPE_BASELINE = baseline
                with redirect_stdout(io.StringIO()):
                    return cmd_worker_scope(True)

            results = [
                (
                    "ratchet: a ledger sitting at its baseline passes",
                    run(named + unnamed, 1) == 0,
                ),
                (
                    "ratchet: one MORE unnamed competitive row is blocked",
                    run(named + unnamed + unnamed.replace("unnamed", "unnamed2"), 1) == 2,
                ),
                (
                    "ratchet: adding a row that NAMES its worker is not blocked",
                    run(named + unnamed + named.replace("named", "named2"), 1) == 0,
                ),
                (
                    "ratchet: a count BELOW baseline is blocked until the baseline drops",
                    run(named, 1) == 2,
                ),
                (
                    "ratchet: a multi-worker row is refused even at the baseline",
                    run(named + unnamed + multi, 1) == 2,
                ),
                (
                    "ratchet: --list on a ledger outside the repo root does not raise",
                    run(unnamed, 1) == 0,
                ),
            ]
    finally:
        LEDGERS[:] = saved_ledgers
        globals()["WORKER_SCOPE_BASELINE"] = saved_baseline
    return results


def cmd_self_test() -> int:
    sha = "a" * 64
    sample_path = ROOT / "docs" / "NEGATIVE_EVIDENCE.md"

    def row(text: str, verdict: str) -> Row:
        return Row(sample_path, 1, text, verdict)

    checks = [
        (
            "null-less reject is refused",
            not row(
                "REJECT: wall ratio was 1.01",
                "REJECT",
            ).reject_contract_basis()[0],
        ),
        (
            "same-invocation A/A admits reject",
            row("REJECT: A/A null control 1.004 in the same invocation", "REJECT")
            .reject_contract_basis()[0],
        ),
        (
            "timed row with no worker identity is refused",
            "worker/host identity"
            in " ".join(
                contract_violations(
                    row(
                        "KEEP: median 1.21, deterministic bootstrap median 95% CI "
                        f"[1.19, 1.23]; in-process self-reported ELF sha256 {sha}.",
                        "KEEP",
                    )
                )
            ),
        ),
        (
            "a named pinned worker satisfies the provenance rule",
            "worker/host identity"
            not in " ".join(
                contract_violations(
                    row(
                        "KEEP: median 1.21, deterministic bootstrap median 95% CI "
                        f"[1.19, 1.23]; in-process self-reported ELF sha256 {sha}. "
                        "Strict-remote pinned `ovh-a`.",
                        "KEEP",
                    )
                )
            ),
        ),
        (
            "a local same_host row also satisfies the provenance rule",
            row(
                "mounted comparator, same_host=thinkstation1", "KEEP"
            ).has_worker_identity(),
        ),
        (
            "a multi-worker run is refused outright",
            "more than one worker"
            in " ".join(
                contract_violations(
                    row("KEEP: RCH_WORKERS=ovh-a,hz2 median 1.21", "KEEP")
                )
            ),
        ),
        (
            "a single-worker RCH_WORKER is not mistaken for a multi-worker run",
            not row("RCH_WORKER=vmi1227854", "KEEP").allows_multiple_workers(),
        ),
        (
            "A/A reject without bootstrap median CI violates the contract",
            "bootstrap median CI"
            in " ".join(
                contract_violations(
                    row(
                        "REJECT: A/A null control 1.004 in the same invocation",
                        "REJECT",
                    )
                )
            ),
        ),
        (
            "A/A reject with bootstrap median CI satisfies the timing contract",
            not contract_violations(
                row(
                    "REJECT: A/A null control 1.004 in the same invocation; "
                    "deterministic bootstrap median 95% CI [0.998, 1.009]. "
                    "Strict-remote pinned `ovh-a`.",
                    "REJECT",
                )
            ),
        ),
        (
            "unrelated bootstrap and median statistics do not synthesize a CI",
            not row(
                "REJECT: bootstrap mean CI [0.99, 1.01] | "
                "A/A null control median 1.004 in the same invocation",
                "REJECT",
            ).has_bootstrap_median_ci(),
        ),
        (
            "numeric profile admits reject as counted mechanism",
            row(
                "REJECT: perf profile frame was 3.2% self",
                "REJECT",
            ).reject_contract_basis()[0],
        ),
        (
            "counted-mechanism reject does not invent a timing CI",
            not contract_violations(
                row(
                    "REJECT: perf profile frame was 3.2% self",
                    "REJECT",
                )
            ),
        ),
        (
            "A/A without same-invocation witness is refused",
            not row("REJECT: A/A ratio 1.004", "REJECT").reject_contract_basis()[0],
        ),
        (
            "retry requirements do not count as run evidence",
            not row(
                "REJECT: wall ratio 1.01. "
                "Retry only when same-invocation A/A is 1.001x.",
                "REJECT",
            ).reject_contract_basis()[0],
        ),
        (
            "KEEP without hash is refused",
            not row("KEEP: median ratio 1.08", "KEEP").has_executing_elf_sha256(),
        ),
        (
            "adjacent sha256sum is not execution proof",
            not row(
                f"KEEP: binary SHA-256 {sha} from sha256sum beside the run",
                "KEEP",
            ).has_executing_elf_sha256(),
        ),
        (
            "future hash retry is not execution proof",
            not row(
                f"KEEP: ratio 1.08. Retry only when bench_elf_sha256={sha}.",
                "KEEP",
            ).has_executing_elf_sha256(),
        ),
        (
            "machine-readable ELF self-report admits KEEP",
            row(f"KEEP: bench_elf_sha256={sha}", "KEEP").has_executing_elf_sha256(),
        ),
        (
            "bench-evidence binary self-report admits KEEP",
            row(
                f"KEEP: bench_evidence,binary_sha256={sha},worker=ovh-a",
                "KEEP",
            ).has_executing_elf_sha256(),
        ),
        (
            "prose ELF self-report admits KEEP",
            row(
                f"KEEP: in-process executing ELF SHA-256 {sha}",
                "KEEP",
            ).has_executing_elf_sha256(),
        ),
        (
            "KEEP with self-hash but no bootstrap median CI is refused",
            "bootstrap median CI"
            in " ".join(
                contract_violations(
                    row(f"KEEP: bench_elf_sha256={sha}; ratio 1.08.", "KEEP")
                )
            ),
        ),
        (
            "KEEP with self-hash and bootstrap median CI is admitted",
            not contract_violations(
                row(
                    f"KEEP: bench_elf_sha256={sha}; deterministic bootstrap "
                    "median 95% CI [1.06, 1.10]. RCH_WORKER=vmi1227854.",
                    "KEEP",
                )
            ),
        ),
        (
            "positive CV gate is refused",
            row(
                "REJECT: perf profile frame was 3.2% self; CV gate passed at 4%.",
                "REJECT",
            ).uses_cv_as_gate(),
        ),
        (
            "CV gate hidden in retry predicate is refused",
            row(
                "REJECT: perf profile frame was 3.2% self. "
                "Retry only when all-arm CV < 5%.",
                "REJECT",
            ).uses_cv_as_gate(),
        ),
        (
            "machine-readable CV non-use witness is admitted",
            not row(
                f"KEEP: bench_elf_sha256={sha}; deterministic bootstrap median "
                "95% CI [1.06, 1.10]; cv_used=false.",
                "KEEP",
            ).uses_cv_as_gate(),
        ),
        (
            "prose never-CV witness is admitted",
            not row(
                "REJECT: perf profile frame was 3.2% self; never gate on CV.",
                "REJECT",
            ).uses_cv_as_gate(),
        ),
        (
            "literal SURVEY verdict outranks REJECT wording in the surface",
            verdict_of(
                [
                    "2026-07-27",
                    "audit refresh",
                    "281 REJECT decisions audited",
                    "SURVEY / no performance lever",
                ],
                "audit refresh",
                "",
            )
            == "SURVEY",
        ),
    ]
    candidate_row = row(
        "REJECT SnapshotRegistry publication prefix batching; "
        "Retry only when publication exceeds 5% self.",
        "REJECT",
    )
    checks.append(
        (
            "candidate requires a target-surface hit",
            candidate_match(
                candidate_row,
                terms("batch atomic publication stores"),
                terms("SnapshotRegistry publication"),
                3,
            )
            is not None
            and candidate_match(
                candidate_row,
                terms("batch atomic publication stores"),
                terms("unrelated extent decoder"),
                3,
            )
            is None,
        )
    )
    unrelated_map_row = row(
        "REJECT Btrfs snapshot-diff dual-map fusion retained inode BTreeMap "
        "entries in ordered form.",
        "REJECT",
    )
    exact_send_row = row(
        "REJECT generate_send_stream_impl inode grouping BTreeMap layout.",
        "REJECT",
    )
    send_candidate = terms(
        "replace BTreeMap inode grouping with an ordered-span representation"
    )
    send_surface = terms("generate_send_stream inode grouping BTreeMap")
    checks.append(
        (
            "qualified surface rejects generic false positives",
            candidate_match(unrelated_map_row, send_candidate, send_surface, 3) is None
            and candidate_match(exact_send_row, send_candidate, send_surface, 3)
            is not None,
        )
    )
    checks.append(
        (
            "table-row span does not consume the following row",
            list(row_line_span(Row(sample_path, 17, "one row\n", "KEEP"))) == [17],
        )
    )

    # --- bd-4sull item 3: absolute arm medians on a competitive row ----------
    competitive = (
        "KEEP: four-arm mounted-kernel-report crossover, FrankenFS is 2.898298x "
        "slower than kernel ext4, deterministic bootstrap median 95% CI "
        "[2.874382, 2.920502]. executing_elf_sha256: " + sha + ". "
    )
    checks.extend(
        [
            (
                "competitive row without either absolute arm median is refused",
                row(competitive, "KEEP").missing_absolute_arm_medians()
                == ["incumbent", "candidate"],
            ),
            (
                "recording only the incumbent arm still names the candidate arm",
                row(
                    competitive + "kernel median batch 77.31 ms.", "KEEP"
                ).missing_absolute_arm_medians() == ["candidate"],
            ),
            (
                "both prose arm medians satisfy the requirement",
                not row(
                    competitive
                    + "kernel median batch 77.31 ms, FrankenFS median batch 225.31 ms.",
                    "KEEP",
                ).missing_absolute_arm_medians(),
            ),
            (
                "the raw harness throughput fields satisfy the requirement",
                not row(
                    competitive
                    + "kernel_median_wall_ns=77310000,fuse_median_wall_ns=225310000",
                    "KEEP",
                ).missing_absolute_arm_medians(),
            ),
            (
                "the requirement fires through contract_violations on a staged KEEP",
                any(
                    "absolute median" in v
                    for v in contract_violations(row(competitive, "KEEP"))
                ),
            ),
            (
                "an internal A/B row has no incumbent arm and is exempt",
                not row(
                    "KEEP: same-invocation A/A null control 1.004, candidate is "
                    "1.70x faster than the frozen control, deterministic bootstrap "
                    "median 95% CI [1.62, 1.79]. executing_elf_sha256: " + sha,
                    "KEEP",
                ).missing_absolute_arm_medians(),
            ),
            (
                "a future retry clause does not supply the medians",
                row(
                    competitive
                    + "Retry only when kernel median batch is under 77.31 ms and "
                    "FrankenFS median batch is under 225.31 ms.",
                    "KEEP",
                ).missing_absolute_arm_medians() == ["incumbent", "candidate"],
            ),
        ]
    )

    # --- the retroactive worker-scope flag (bd-4w2mf) ------------------------
    # The scope is deliberately narrower than "unnamed KEEP" (595 rows) -- it is
    # the 166 that quote a vs-incumbent ratio. The negative cases below are the
    # ones a naive "flag every unnamed KEEP" implementation gets wrong.
    unnamed_ratio = (
        "KEEP: FrankenFS readdir+stat is 4.98x the kernel ext4 median, "
        f"deterministic bootstrap median 95% CI [4.81, 5.12]; ELF sha256 {sha}."
    )
    checks.extend(
        [
            (
                "an unnamed KEEP quoting an incumbent ratio is flagged worker-scoped",
                row(unnamed_ratio, "KEEP").is_worker_scoped_ratio(),
            ),
            (
                "the same row naming its worker is NOT flagged",
                not row(
                    unnamed_ratio + " RCH_WORKER=vmi1227854.", "KEEP"
                ).is_worker_scoped_ratio(),
            ),
            (
                "a local mounted row naming same_host is NOT flagged",
                not row(
                    unnamed_ratio + " Host `thinkstation1`, same_host=thinkstation1.",
                    "KEEP",
                ).is_worker_scoped_ratio(),
            ),
            (
                "an unnamed KEEP with NO incumbent ratio is NOT flagged "
                "(a self-speedup makes no cross-machine claim)",
                not row(
                    "KEEP: candidate is 1.70x faster than the frozen control, "
                    f"deterministic bootstrap median 95% CI [1.62, 1.79]; sha256 {sha}.",
                    "KEEP",
                ).is_worker_scoped_ratio(),
            ),
            (
                "an unnamed REJECT quoting an incumbent ratio is NOT flagged "
                "(the scope is banked competitive CLAIMS)",
                not row(unnamed_ratio, "REJECT").is_worker_scoped_ratio(),
            ),
            (
                "an incumbent ratio that appears only in a future retry clause "
                "does not make the row a banked competitive claim",
                not row(
                    "KEEP: instrument only, no production tuning. Retry once the "
                    "kernel ext4 arm lands within 1.20x of the FUSE mount.",
                    "KEEP",
                ).is_worker_scoped_ratio(),
            ),
            (
                "a table row is identified by its bead/surface cell, not its date",
                Row(
                    sample_path,
                    1,
                    "| 2026-07-31 | `bd-mounted-bulk-durable-write-kvmfd` | surface | "
                    "KEEP | 2.20x | n/a | n/a | gates |",
                    "KEEP",
                ).title
                == "`bd-mounted-bulk-durable-write-kvmfd`",
            ),
            (
                "an entry row is identified by its heading text without the hashes",
                Row(
                    sample_path, 1, "### 2026-07-22 — KEEP: async read dispatch\nbody", "KEEP"
                ).title
                == "2026-07-22 — KEEP: async read dispatch",
            ),
            (
                "the ratchet baseline matches the flagged set in the live ledgers",
                len(worker_scoped_rows()) == WORKER_SCOPE_BASELINE,
            ),
        ]
    )
    checks.extend(
        [
            (
                "a FUSE request/probe count is a counted mechanism (bd-ha71t)",
                row(
                    "REJECT: FUSE_HANDLE_KILLPRIV_V2 negotiated ENABLED and inert — "
                    "4000 probes -> 4000 probes for 2000 path stats.",
                    "REJECT",
                )
                .reject_contract_basis()[0],
            ),
            (
                "the word 'probes' alone is still not a counted mechanism",
                not row(
                    "REJECT: the capability probes did not go away.", "REJECT"
                )
                .reject_contract_basis()[0],
            ),
            (
                "a request count needs BOTH sides, not just one number",
                not row("REJECT: we measured 4000 requests.", "REJECT")
                .reject_contract_basis()[0],
            ),
            (
                "a row's span excludes the blank separator before the next heading "
                "(bd-ha71t: appending a row must not mark the previous one touched)",
                row_line_span(Row(sample_path, 10, "### t\nbody\n\n\n", "REJECT"))
                == range(10, 12),
            ),
            (
                "a row that is only a heading still occupies one line",
                row_line_span(Row(sample_path, 10, "### t", "REJECT")) == range(10, 11),
            ),
        ]
    )
    checks.extend(_worker_scope_ratchet_checks())
    checks.extend(_placement_scope_ratchet_checks())

    # --- document structure is not a decision (bd-eqm8s) ---------------------
    # The bug: prose saying "record the exact keep/reject/pending status" was
    # classified KEEP by the body-scan fallback, so touching the ledger's own rules
    # list demanded a bootstrap CI from it.
    rules_body = (
        "- One lever per row.\n"
        "- Record the benchmark surface, result, and exact keep/reject/pending status.\n"
        "- Rejected ideas require a concrete retry predicate.\n"
    )
    checks.extend(
        [
            (
                "prose whose body merely mentions keep/reject is NOT a decision row",
                verdict_of([], "Rules", rules_body) == "STRUCTURE",
            ),
            (
                "a dated heading is still a decision row",
                verdict_of([], "2026-06-22 KEEP: htree fast path", rules_body) == "KEEP",
            ),
            (
                "a bead-attributed heading with no date is still a decision row",
                verdict_of([], "`bd-4w2mf` — REJECT: no lever", "body") == "REJECT",
            ),
            (
                "a table row is never treated as document structure "
                "(its date is in cell 0, not the title)",
                not is_document_structure(
                    ["2026-07-31", "`bd-kvmfd`", "surface", "KEEP", "2.20x"],
                    "`bd-kvmfd`",
                ),
            ),
            (
                "the body fallback still classifies an undated BEAD row from its body",
                verdict_of([], "`bd-zvn7r` follow-up", "we REJECT this lever") == "REJECT",
            ),
            (
                "evasion closed: an unattributable heading carrying a vs-incumbent "
                "ratio is refused, not exempted",
                "unattributable decision"
                in " ".join(
                    structure_violations(
                        Row(
                            sample_path,
                            1,
                            "### Some prose heading\n\nFrankenFS is 3.4x the kernel "
                            "ext4 median.",
                            "STRUCTURE",
                        )
                    )
                ),
            ),
            (
                "evasion closed: an unattributable heading carrying an ELF SHA-256 "
                "is refused",
                "unattributable decision"
                in " ".join(
                    structure_violations(
                        Row(
                            sample_path,
                            1,
                            f"### Some prose heading\n\nexecuting ELF sha256 {sha}.",
                            "STRUCTURE",
                        )
                    )
                ),
            ),
            (
                "genuine prose carrying no decision evidence is left alone",
                not structure_violations(
                    Row(sample_path, 1, "### Rules\n" + rules_body, "STRUCTURE")
                ),
            ),
            (
                "the live ledgers hold exactly the 5 measured structure sections",
                sum(1 for r in all_rows() if r.verdict == "STRUCTURE") == 5,
            ),
        ]
    )

    failures = [name for name, passed in checks if not passed]
    if failures:
        print("preflight self-test: FAILED", file=sys.stderr)
        for name in failures:
            print(f"  {name}", file=sys.stderr)
        return 1
    print(f"preflight self-test: OK — {len(checks)} policy checks")
    return 0


HOOK = """#!/usr/bin/env bash
# frankenfs perf-ledger preflight (installed by scripts/perf_ledger_preflight.py)
# Refuses a staged REJECT without A/A/count evidence, any CV gate, and a timed
# decision without bootstrap median-CI evidence. KEEP also requires an
# executing-ELF SHA-256 self-report. A competitive row must also record both
# arms' absolute medians, not only the ratio (bd-4sull item 3).
# See fleet broadcast 2, 2026-07-25.
set -e
PREFLIGHT="$(git rev-parse --show-toplevel)/scripts/perf_ledger_preflight.py"
python3 "$PREFLIGHT" --lint --staged
# Retroactive half: the staged lint cannot see a row that is already committed, so
# also hold the worker-scope ratchet. A commit may not raise the count of banked
# competitive rows that name no execution host.
python3 "$PREFLIGHT" --worker-scope >/dev/null
"""


def cmd_install_hook() -> int:
    try:
        hook_path = subprocess.run(
            ["git", "rev-parse", "--git-path", "hooks/pre-commit"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"cannot locate .git: {exc}", file=sys.stderr)
        return 64
    hook = Path(hook_path)
    if not hook.is_absolute():
        hook = ROOT / hook
    if hook.exists():
        if hook.read_text(errors="replace") == HOOK:
            print(f"already installed {hook}")
            return 0
        print(f"refusing to overwrite existing hook: {hook}", file=sys.stderr)
        print("append the --lint line to it by hand instead", file=sys.stderr)
        return 64
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(HOOK)
    hook.chmod(0o755)
    print(f"installed {hook}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--candidate", metavar="TEXT",
                   help="describe the lever; exit 2 if a prior REJECT covers it")
    g.add_argument("--lint", action="store_true",
                   help="exit 2 if a decision row violates the evidence contract")
    g.add_argument("--audit", action="store_true", help="whole-ledger census")
    g.add_argument("--worker-scope", action="store_true",
                   help="ratchet the banked competitive rows that name no "
                        "execution host (retroactive half of the worker gate)")
    g.add_argument("--placement-audit", action="store_true",
                   help="enumerate banked MOUNTED ratios that never say where the "
                        "FUSE daemon ran (bd-plt79; sibling of --worker-scope)")
    g.add_argument("--incumbent-absolute-audit", action="store_true",
                   help="enumerate banked competitive ratios that record no "
                        "INCUMBENT absolute median (bd-4sull item 3)")
    g.add_argument("--precision-scope-audit", action="store_true",
                   help="enumerate banked competitive ratios quoting a CI without "
                        "scoping it to one invocation (bd-4sull item 2)")
    g.add_argument("--incumbent-audit", action="store_true",
                   help="how many KEEP claims carry a live same-invocation "
                        "incumbent ratio, and why the rest do not")
    g.add_argument("--self-test", action="store_true",
                   help="exercise policy predicates without Cargo or fixtures")
    g.add_argument("--install-hook", action="store_true",
                   help="install the lint as a git pre-commit hook")
    ap.add_argument("--surface", metavar="TEXT", default=None,
                    help="with --candidate: target function/module/benchmark surface")
    ap.add_argument("--since", metavar="REF", default=None,
                    help="with --lint: only rows added since REF (default: all rows)")
    ap.add_argument("--staged", action="store_true",
                    help="with --lint: inspect the staged index (pre-commit mode)")
    ap.add_argument("--threshold", type=int, default=3,
                    help="with --candidate: term overlap needed to call it covered")
    ap.add_argument("--show", metavar="CLASS", default=None,
                    help="with --incumbent-audit: list the rows in one class")
    ap.add_argument("--list", action="store_true",
                    help="with --worker-scope: print every flagged row")
    a = ap.parse_args()
    if a.worker_scope:
        return cmd_worker_scope(a.list)
    if a.placement_audit:
        return cmd_placement_audit(a.list)
    if a.incumbent_absolute_audit:
        return cmd_incumbent_absolute_audit(a.list)
    if a.precision_scope_audit:
        return cmd_precision_scope_audit(a.list)
    if a.incumbent_audit:
        return cmd_incumbent_audit(a.show)
    if a.candidate:
        if not a.surface:
            print("preflight: --candidate requires --surface", file=sys.stderr)
            return 64
        return cmd_candidate(a.candidate, a.surface, a.threshold)
    if a.lint:
        return cmd_lint(a.since, a.staged)
    if a.surface or a.since or a.staged:
        print(
            "preflight: --surface/--since/--staged require their documented mode",
            file=sys.stderr,
        )
        return 64
    if a.audit:
        return cmd_audit()
    if a.self_test:
        return cmd_self_test()
    return cmd_install_hook()


if __name__ == "__main__":
    sys.exit(main())
