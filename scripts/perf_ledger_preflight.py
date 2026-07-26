#!/usr/bin/env python3
"""frankenfs perf-ledger preflight — make ledger decay structurally impossible.

Motivation (fleet broadcast 2, 2026-07-25): ledger integrity is not a one-time
cleanup, it DECAYS. Repos that audited once and institutionalized the check sit at
~1.7% VOID; repos that never did sit at 25-91%. frankenfs audited at **79.3% VOID**
(219 of 276 REJECT rows). This script is the institutionalization.

Two jobs, two exit codes:

  --candidate "<text>"   Grep the ledgers BEFORE proposing a lever. Exit 2 = BLOCKED:
                         a prior REJECT covers this surface. Print it and its retry
                         predicate so the caller must satisfy the predicate or pick a
                         different vein.

  --lint [--since REF]   Refuse a REJECT row that cannot decide anything. Exit 1 if a
                         REJECT row added since REF carries neither an A/A null
                         control, nor a counted mechanism, nor a profile-first
                         attribution. This is what makes a null-less REJECT
                         IMPOSSIBLE rather than merely discouraged.

  --audit                Whole-ledger census (the §1 audit, re-runnable).

Wire the lint as a pre-commit guard with `--install-hook`.
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
# cannot see anything". Exactly one of these three establishes that.

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
    r"same number of|byte-readback|readback",
    re.I,
)
PROFILE_FIRST = re.compile(
    r"REJECT before source edit|profile-first rejection|before any source edit|"
    r"no source (?:or harness )?changed|No A/B was permitted|"
    r"below the[^.\n]{0,40}(?:5%|admission) floor|prevented a below-floor A/B|"
    r"\d+(?:\.\d+)?% self",
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
SURVEY_VERDICT = re.compile(r"(?:\*\*)?(SURFACE|N/A|NO CODE\b|NO-GAP)", re.I)

RETRY = re.compile(r"[Rr]etry (?:only )?(?:predicate|condition|if|on|when)[^|]{0,400}")


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
        if PROFILE_FIRST.search(self.text):
            return True, "profile-first attribution"
        return False, "none"


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


def parse(path: Path, entry_level: int = 3) -> list[Row]:
    """Parse a ledger into rows. Handles both the 8-column table and prose sections."""
    rows: list[Row] = []
    if not path.exists():
        return rows
    lines = path.read_text(errors="replace").splitlines(keepends=True)
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


def all_rows() -> list[Row]:
    return [r for p, lvl in LEDGERS for r in parse(p, lvl)]


# --- mode: candidate preflight ----------------------------------------------

STOP = {
    "the", "a", "an", "and", "or", "of", "for", "to", "in", "on", "is", "it", "with",
    "per", "via", "into", "from", "that", "this", "then", "than", "not", "but", "by",
    "lever", "perf", "fast", "slow", "faster", "make", "use", "using", "new", "add",
}


def terms(text: str) -> list[str]:
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", text.lower())
    return [w for w in dict.fromkeys(words) if w not in STOP]


def cmd_candidate(text: str, threshold: int) -> int:
    want = terms(text)
    if not want:
        print("preflight: candidate description has no searchable terms", file=sys.stderr)
        return 1
    hits = []
    for r in all_rows():
        if r.verdict != "REJECT":
            continue
        low = r.text.lower()
        matched = [w for w in want if w in low]
        if len(matched) >= threshold:
            hits.append((len(matched), matched, r))
    if not hits:
        print(f"preflight: OK — no prior REJECT covers {want[:6]}")
        return 0
    hits.sort(key=lambda h: -h[0])
    print("preflight: BLOCKED — a prior REJECT covers this surface.\n")
    for score, matched, r in hits[:5]:
        print(f"  {r.ref}  (matched {score}: {', '.join(matched[:8])})")
        title = r.text.split("\n")[0][:200]
        print(f"    {title}")
        m = RETRY.search(r.text)
        print(f"    retry: {m.group(0)[:300].strip() if m else '(none recorded)'}\n")
    print("Satisfy the retry predicate and cite it, or pick a different vein.")
    print("Overriding without satisfying it is how a repo re-derives a closed frontier.")
    return 2


# --- mode: lint (the anti-decay gate) ---------------------------------------


def changed_line_numbers(path: Path, since: str) -> set[int] | None:
    """Line numbers added to `path` since `since`. None if git cannot tell us."""
    try:
        diff = subprocess.run(
            ["git", "diff", "-U0", f"{since}...HEAD", "--", str(path)],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        if diff.returncode != 0:
            return None
    except (OSError, subprocess.SubprocessError):
        return None
    added: set[int] = set()
    for hunk in re.finditer(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", diff.stdout, re.M):
        start = int(hunk.group(1))
        count = int(hunk.group(2) or 1)
        added.update(range(start, start + count))
    return added


def cmd_lint(since: str | None) -> int:
    bad: list[tuple[Row, str]] = []
    checked = 0
    for path, lvl in LEDGERS:
        touched = changed_line_numbers(path, since) if since else None
        if since and touched is not None and not touched:
            continue
        for r in parse(path, lvl):
            if r.verdict != "REJECT":
                continue
            if touched is not None:
                span = range(r.line, r.line + r.text.count("\n") + 1)
                if not touched.intersection(span):
                    continue
            checked += 1
            ok, _ = r.admissible()
            if not ok:
                bad.append((r, "no A/A null, no counted mechanism, no profile attribution"))
    scope = f"added since {since}" if since else "whole ledger"
    if not bad:
        print(f"preflight lint: OK — {checked} REJECT row(s) {scope}, all admissible")
        return 0
    print(f"preflight lint: FAILED — {len(bad)} of {checked} REJECT row(s) {scope} "
          f"cannot decide anything:\n")
    for r, why in bad:
        print(f"  {r.ref}\n    {r.text.splitlines()[0][:180]}\n    reason: {why}\n")
    print("A REJECT must distinguish 'the lever does nothing' from 'this bench cannot")
    print("see anything'. Record ONE of:")
    print("  - an A/A null control (paired arms, same invocation), or")
    print("  - a counted mechanism (instructions/cycles/syscalls/allocs unchanged), or")
    print("  - a profile-first attribution (named frame, non-zero self-time, ceiling).")
    print("\nThis repo audited at 79.3% VOID because rows without one of these are")
    print("unfalsifiable. Do not add another.")
    return 1


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


HOOK = """#!/usr/bin/env bash
# frankenfs perf-ledger preflight (installed by scripts/perf_ledger_preflight.py)
# Refuses a commit that adds a REJECT row carrying no A/A null control, no counted
# mechanism, and no profile-first attribution. See fleet broadcast 2, 2026-07-25.
exec python3 "$(git rev-parse --show-toplevel)/scripts/perf_ledger_preflight.py" \\
     --lint --since HEAD
"""


def cmd_install_hook() -> int:
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--git-dir"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"cannot locate .git: {exc}", file=sys.stderr)
        return 1
    hook = (ROOT / top / "hooks" / "pre-commit")
    if hook.exists():
        print(f"refusing to overwrite existing hook: {hook}", file=sys.stderr)
        print("append the --lint line to it by hand instead", file=sys.stderr)
        return 1
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
                   help="exit 1 if a REJECT row lacks a null/mechanism/profile basis")
    g.add_argument("--audit", action="store_true", help="whole-ledger census")
    g.add_argument("--install-hook", action="store_true",
                   help="install the lint as a git pre-commit hook")
    ap.add_argument("--since", metavar="REF", default=None,
                    help="with --lint: only rows added since REF (default: all rows)")
    ap.add_argument("--threshold", type=int, default=3,
                    help="with --candidate: term overlap needed to call it covered")
    a = ap.parse_args()
    if a.candidate:
        return cmd_candidate(a.candidate, a.threshold)
    if a.lint:
        return cmd_lint(a.since)
    if a.audit:
        return cmd_audit()
    return cmd_install_hook()


if __name__ == "__main__":
    sys.exit(main())
