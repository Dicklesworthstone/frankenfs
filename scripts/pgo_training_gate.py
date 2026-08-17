#!/usr/bin/env python3
"""Decide whether a PGO training run actually trained anything.

WHY. `scripts/build-perf.sh` runs five training commands and every one of them
ends in `|| true`. That is deliberate -- a training failure should not abort a
20-minute build -- but it means a run where four of the five silently failed
produces a NON-EMPTY profile that trained a fraction of the hot paths, and the
resulting binary is described as "real PGO" in every row it measures. The
existing check (`[ -s merged.profdata ]`) only catches the case where ALL of
them failed.

This is the same defect class as the harness guard that ended in `|| true` and
could never fail: a check that cannot distinguish "worked" from "did nothing" is
worse than no check, because the next person believes it.

WHAT COUNTS AS TRAINED. Exit status alone is not enough -- a command can exit 0
and write no profile at all, which is exactly what happens when the build was
offloaded and `$INSTR` is a stub. So each command reports BOTH its exit status
and how many `.profraw` files appeared while it ran, and a command counts as
trained only if it exited 0 AND produced at least one.

Input is a TSV on stdin or at a path, one row per command:

    name<TAB>exit_status<TAB>profraw_delta

    scripts/pgo_training_gate.py --selftest
    scripts/pgo_training_gate.py results.tsv
    scripts/pgo_training_gate.py results.tsv --allow-partial   # loud override
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Command:
    name: str
    status: int
    profraw: int

    @property
    def trained(self) -> bool:
        """Exit 0 AND at least one profile written.

        Both halves are load-bearing. A non-zero exit with profiles means the
        command did some work before dying -- still not trustworthy, because we
        cannot say WHICH paths it covered. A zero exit with no profiles is the
        offloaded-build case, where the instrumented binary never ran at all.
        """
        return self.status == 0 and self.profraw > 0


def parse(text: str) -> list[Command]:
    commands = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError(f"line {line_number}: expected 3 tab-separated fields, got {len(fields)}")
        name, status, profraw = fields
        try:
            commands.append(Command(name, int(status), int(profraw)))
        except ValueError as err:
            raise ValueError(f"line {line_number}: {err}") from err
    return commands


def report(commands: list[Command]) -> str:
    width = max((len(c.name) for c in commands), default=0)
    lines = []
    for c in commands:
        mark = "trained" if c.trained else "DID NOT TRAIN"
        lines.append(f"  {c.name:<{width}}  exit={c.status}  profraw={c.profraw}  {mark}")
    trained = sum(1 for c in commands if c.trained)
    lines.append(f"  -> {trained} of {len(commands)} training commands actually trained")
    return "\n".join(lines)


def verdict(commands: list[Command], allow_partial: bool) -> tuple[bool, str]:
    """Pass only if EVERY training command trained.

    Not a threshold, and deliberately not "most of them": the point of PGO here
    is that the profile describes the paths the binary will be measured on, and
    a partial profile silently changes WHICH code is optimized. A row citing
    "real PGO" as provenance cannot be qualified after the fact by which of five
    commands happened to run.
    """
    if not commands:
        return False, "no training commands were recorded at all; the profile describes nothing"
    failed = [c.name for c in commands if not c.trained]
    if not failed:
        return True, f"all {len(commands)} training commands trained"
    detail = ", ".join(failed)
    if allow_partial:
        return True, (
            f"PARTIAL PROFILE ACCEPTED by --allow-partial: {len(failed)} of "
            f"{len(commands)} commands did not train ({detail}). The binary built "
            f"from this profile is NOT the standard artifact and any row measured "
            f"from it must say so."
        )
    return False, (
        f"{len(failed)} of {len(commands)} training commands did not train ({detail}). "
        f"The merged profile is non-empty but covers only part of the hot paths, so a "
        f"binary built from it would be described as 'real PGO' while being trained on "
        f"a subset. Re-run training, or pass --allow-partial to accept it deliberately."
    )


def selftest() -> int:
    cases = 0
    ok = Command("create-bench", 0, 4)
    assert ok.trained
    cases += 1
    # Exit 0 with no profile: the offloaded-build case the script's own header
    # warns about, where $INSTR never really ran.
    assert not Command("lookup-bench", 0, 0).trained
    cases += 1
    # Non-zero exit with profiles: it did something, but we cannot say what.
    assert not Command("walk", 1, 9).trained
    cases += 1
    assert not Command("walk", 137, 0).trained
    cases += 1

    passed, why = verdict([ok, Command("walk", 0, 2)], allow_partial=False)
    assert passed and "all 2" in why
    cases += 1
    passed, why = verdict([ok, Command("walk", 0, 0)], allow_partial=False)
    assert not passed and "walk" in why and "part of the hot paths" in why
    cases += 1
    # The override must pass, and must say the artifact is non-standard.
    passed, why = verdict([ok, Command("walk", 0, 0)], allow_partial=True)
    assert passed and "NOT the standard artifact" in why
    cases += 1
    # No commands at all is a failure, not a vacuous pass -- that is the exact
    # shape of the bug this gate exists for.
    passed, why = verdict([], allow_partial=False)
    assert not passed and "nothing" in why
    cases += 1
    passed, _ = verdict([], allow_partial=True)
    assert not passed, "--allow-partial must not turn an empty run into a pass"
    cases += 1

    parsed = parse("a\t0\t3\n# comment\n\nb\t1\t0\n")
    assert [c.name for c in parsed] == ["a", "b"] and parsed[0].profraw == 3
    cases += 1
    for bad in ["a\t0", "a\t0\t1\t2", "a\tzero\t1"]:
        try:
            parse(bad)
            raise AssertionError(f"{bad!r} must not parse")
        except ValueError:
            pass
    cases += 1
    assert parse("") == []
    cases += 1

    text = report([ok, Command("walk", 0, 0)])
    assert "DID NOT TRAIN" in text and "1 of 2" in text
    cases += 1

    print(f"selftest: {cases} cases OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", nargs="?", help="TSV path, or '-' for stdin")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--allow-partial", action="store_true",
                        help="accept a profile that trained only some commands; the "
                             "binary is then NOT the standard artifact and rows must say so")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.results:
        parser.error("a results TSV is required unless --selftest is given")
    text = sys.stdin.read() if args.results == "-" else open(args.results).read()
    commands = parse(text)
    print(report(commands))
    passed, why = verdict(commands, args.allow_partial)
    print(("PGO training OK: " if passed else "!! PGO training gate FAILED: ") + why)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
