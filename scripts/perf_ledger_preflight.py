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
                         an A/A null control nor a counted mechanism. Refuse a KEEP
                         without an in-process self-report of the executing ELF's
                         SHA-256. Policy failures exit 2; infrastructure failures 64.

  --lint [--since REF]   Apply the same rules to the whole ledger or committed rows
                         added since REF.

  --audit                Whole-ledger census (the §1 audit, re-runnable).

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
    r"\b\d[\d,]*\s+(?:instructions?|cycles?|syscalls?|allocations?|faults?)"
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
        return f"{self.path.relative_to(ROOT)}:{self.line}"

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
        if (
            CONTRACT_NULL_VALUE.search(evidence)
            and SAME_INVOCATION_WITNESS.search(evidence)
        ):
            return True, "same-invocation A/A null control"
        return False, "none"

    def has_executing_elf_sha256(self) -> bool:
        return bool(EXECUTING_ELF_SHA256.search(decision_evidence(self.text)))


def verdict_of(cells: list[str], title: str, body: str) -> str:
    """Verdict from the table's Verdict column, else the prose title, else the body."""
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
    rel = path.relative_to(ROOT).as_posix()
    if staged:
        return git_capture(["show", f":{rel}"])
    if at_head:
        return git_capture(["show", f"HEAD:{rel}"])
    return path.read_text(errors="replace")


def row_line_span(row: Row) -> range:
    """Physical source lines occupied by a row, excluding a trailing-newline phantom."""
    return range(row.line, row.line + max(1, len(row.text.splitlines())))


def cmd_lint(since: str | None, staged: bool) -> int:
    if staged and since:
        print("preflight lint: --staged and --since are mutually exclusive", file=sys.stderr)
        return 64
    bad: list[tuple[Row, str]] = []
    checked = {"REJECT": 0, "KEEP": 0}
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
                if row.verdict not in checked:
                    continue
                if touched is not None:
                    if not touched.intersection(row_line_span(row)):
                        continue
                checked[row.verdict] += 1
                if row.verdict == "REJECT":
                    ok, _ = row.reject_contract_basis()
                    if not ok:
                        bad.append((row, "no A/A null control and no counted mechanism"))
                elif not row.has_executing_elf_sha256():
                    bad.append(
                        (
                            row,
                            "no in-process self-report of the executing ELF's SHA-256",
                        )
                    )
    except (OSError, RuntimeError) as exc:
        print(f"preflight lint: infrastructure failure: {exc}", file=sys.stderr)
        return 64

    scope = "staged index" if staged else (f"committed since {since}" if since else "whole ledger")
    total = sum(checked.values())
    if not bad:
        print(
            f"preflight lint: OK — {total} decision row(s) in {scope} "
            f"({checked['REJECT']} REJECT, {checked['KEEP']} KEEP)"
        )
        return 0
    print(
        f"preflight lint: BLOCKED — {len(bad)} of {total} decision row(s) "
        f"in {scope} violate the ledger contract:\n"
    )
    for row, why in bad:
        print(f"  {row.ref}\n    {row.text.splitlines()[0][:180]}\n    reason: {why}\n")
    print("A REJECT must record either:")
    print("  - an A/A null control in the same invocation, or")
    print("  - a counted mechanism (instructions/cycles/syscalls/allocs/profile count).")
    print("A KEEP must record a full SHA-256 self-reported by the executing ELF.")
    print("A neighboring sha256sum is not proof of which binary ran.")
    return 2


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
            "numeric profile admits reject as counted mechanism",
            row(
                "REJECT: perf profile frame was 3.2% self",
                "REJECT",
            ).reject_contract_basis()[0],
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
# Refuses a staged REJECT without A/A/count evidence and a staged KEEP without an
# executing-ELF SHA-256 self-report. See fleet broadcast 2, 2026-07-25.
exec python3 "$(git rev-parse --show-toplevel)/scripts/perf_ledger_preflight.py" \\
     --lint --staged
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
    a = ap.parse_args()
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
