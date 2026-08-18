#!/usr/bin/env python3
"""Measure CROSS-WINDOW reproducibility from the banked comparator reports (bd-4sull).

THE PROBLEM. Every banked row publishes a within-invocation bootstrap median CI
(typically +/-0.5% to +/-1%) and is admitted against a twice-widest-null margin.
Both bound error INSIDE one invocation. Neither says whether the SAME ELF on the
SAME host re-measures to the same ratio in the next window — which is the number a
reader actually uses when comparing a row to a later run.

bd-4sull had exactly two such figures (4.71% and 9.15%), from one workload each.
The bank already contains the repeats; nobody had aggregated them. This does.

LIKE-FOR-LIKE GROUPING is the whole difficulty, and the key is deliberately strict:

    ffs_binary_sha256           same compiled candidate
    fuse arm's self_reported_runtime_knobs   same runtime configuration
    filesystem, workload
    pairs, placement_scope, requested_client_threads, operations_per_observation

Anything looser silently compares different experiments and reports the difference
as irreproducibility.

⚠️ REPORT BOTH POPULATIONS, because they answer different questions and the gap
between them IS a result. Across ALL runs the tail is dominated by windows the
instrument itself REFUSED (blocked_null); restricting to admitted runs is what
tells you how reproducible a PUBLISHABLE row is.

    scripts/cross_window_spread.py --survey /data/tmp
    scripts/cross_window_spread.py --selftest
"""

from __future__ import annotations

import argparse
import json
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path


def fuse_runtime_knobs(fs: dict) -> str:
    """The FrankenFS arm's self-reported effective knobs, or '' when absent.

    Two runs of one ELF with different knobs are different experiments, not two
    windows of one experiment, so this belongs in the grouping key.
    """
    for identity in fs.get("identities") or []:
        if str(identity.get("arm", "")).startswith("fuse_a"):
            return str(identity.get("self_reported_runtime_knobs", ""))
    return ""


# Report fields that change WHAT WAS MEASURED rather than when, and so must split
# a group (bd-6kpp4). Not runtime knobs -- those come from fuse_runtime_knobs --
# but recorded configuration the harness sets per run.
#
# btrfs_verify_data_on_read is the concrete case and it is not hypothetical: the
# product default was flipped false -> true on 2026-08-15 (1c85fc23, and the
# harness default in e54146ee) while the bead meant to decide it sat blocked. Every
# surviving btrfs report in the bank is verify=ON, so nothing mixes TODAY -- but
# bd-6kpp4 item 3 is precisely a verify-on-vs-off 2x2, and the moment its runs land
# a key without this would merge the two arms and report the checksum cost as
# irreproducibility.
CONFIG_FIELDS = ("btrfs_verify_data_on_read", "cache_regime", "fixture_construction")


def group_key(doc: dict, fs: dict) -> tuple:
    return (
        str(doc.get("ffs_binary_sha256"))[:12],
        fuse_runtime_knobs(fs),
        fs.get("filesystem"),
        str(fs.get("workload")),
        fs.get("pairs"),
        fs.get("placement_scope"),
        fs.get("requested_client_threads"),
        fs.get("operations_per_observation"),
    ) + tuple(fs.get(field) for field in CONFIG_FIELDS)


def collect(paths: list[Path]) -> dict:
    groups = defaultdict(list)
    for path in paths:
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        for fs in doc.get("filesystems", []):
            ratio = (fs.get("fuse_over_kernel") or {}).get("median")
            if not isinstance(ratio, (int, float)) or ratio <= 0:
                continue
            groups[group_key(doc, fs)].append(
                {"ratio": ratio, "admitted": fs.get("admitted") is True}
            )
    return groups


def spreads(groups: dict, admitted_only: bool) -> list[tuple[tuple, float, int]]:
    out = []
    for key, runs in groups.items():
        ratios = [r["ratio"] for r in runs if r["admitted"] or not admitted_only]
        if len(ratios) >= 2:
            out.append((key, max(ratios) / min(ratios), len(ratios)))
    return sorted(out, key=lambda row: -row[1])


def summarise(rows: list, label: str) -> None:
    if not rows:
        print(f"{label:<16} no group has two or more runs")
        return
    values = [r[1] for r in rows]
    print(
        f"{label:<16} groups={len(rows):<3} runs={sum(r[2] for r in rows):<3} "
        f"worst={max(values):.4f}x  median={st.median(values):.4f}x  "
        f">1.10x: {sum(1 for v in values if v > 1.10)}  "
        f">1.05x: {sum(1 for v in values if v > 1.05)}"
    )


def admission_skew(groups: dict) -> list[tuple]:
    """Compare ADMITTED against BLOCKED ratios inside each like-for-like group.

    If admission were independent of the outcome, the two medians would track. Any
    systematic gap means the banked (admitted) numbers are drawn from one side of
    their own configuration's distribution.

    ⚠️ MUST USE group_key. An earlier hand-rolled key that omitted the runtime
    knobs reported a 2x skew that was entirely the capability-memo A/B: one group
    mixed memo-sized runs (3.36x) with default ones (6.99x), which are bd-34hzz's
    two published arms, and called the mixture irreproducibility. Sharing the key
    with the spread analysis is what stops that recurring.
    """
    out = []
    for key, runs in groups.items():
        admitted = [r["ratio"] for r in runs if r["admitted"]]
        blocked = [r["ratio"] for r in runs if not r["admitted"]]
        if admitted and blocked:
            out.append(
                (
                    key,
                    st.median(admitted),
                    st.median(blocked),
                    len(admitted),
                    len(blocked),
                )
            )
    return sorted(out, key=lambda row: -(row[1] / row[2]))


def selftest() -> int:
    failures = []
    doc_a = {"ffs_binary_sha256": "a" * 64}
    fs_common = {
        "filesystem": "btrfs",
        "workload": "w",
        "pairs": 12,
        "placement_scope": "host-wide",
        "requested_client_threads": 8,
        "operations_per_observation": 100,
        "identities": [{"arm": "fuse_a", "self_reported_runtime_knobs": "memo=on"}],
    }
    # Different knobs must NOT be grouped together.
    other = dict(fs_common)
    other["identities"] = [{"arm": "fuse_a", "self_reported_runtime_knobs": "memo=off"}]
    if group_key(doc_a, fs_common) == group_key(doc_a, other):
        failures.append("differing runtime knobs must split the group")
    # Different ELF must not be grouped together.
    if group_key(doc_a, fs_common) == group_key({"ffs_binary_sha256": "b" * 64}, fs_common):
        failures.append("differing ELF must split the group")
    # bd-6kpp4: a recorded configuration difference is a different EXPERIMENT, not a
    # different window. Checked for every field, so adding one cannot be forgotten.
    for field in CONFIG_FIELDS:
        flipped = dict(fs_common)
        flipped[field] = "OTHER"
        if group_key(doc_a, fs_common) == group_key(doc_a, flipped):
            failures.append(f"differing {field} must split the group")
    # admitted_only really filters.
    groups = {
        ("k",): [
            {"ratio": 1.0, "admitted": True},
            {"ratio": 2.0, "admitted": False},
            {"ratio": 1.1, "admitted": True},
        ]
    }
    all_rows = spreads(groups, admitted_only=False)
    adm_rows = spreads(groups, admitted_only=True)
    if not all_rows or abs(all_rows[0][1] - 2.0) > 1e-9:
        failures.append("all-runs spread must include the refused window")
    if not adm_rows or abs(adm_rows[0][1] - 1.1) > 1e-9:
        failures.append("admitted-only spread must exclude the refused window")
    # A group with a single admitted run yields no spread at all.
    if spreads({("k",): [{"ratio": 1.0, "admitted": True}, {"ratio": 9.0, "admitted": False}]}, True):
        failures.append("one admitted run is not a cross-window pair")
    # admission_skew must only report groups holding BOTH populations, and must
    # take its medians from the right side.
    skew_groups = {
        ("both",): [
            {"ratio": 2.0, "admitted": True},
            {"ratio": 4.0, "admitted": False},
        ],
        ("admitted_only",): [{"ratio": 1.0, "admitted": True}],
        ("blocked_only",): [{"ratio": 1.0, "admitted": False}],
    }
    skew = admission_skew(skew_groups)
    if len(skew) != 1:
        failures.append("only groups holding BOTH populations can be compared")
    elif abs(skew[0][1] - 2.0) > 1e-9 or abs(skew[0][2] - 4.0) > 1e-9:
        failures.append("admission_skew put the medians on the wrong side")

    for f in failures:
        print(f"SELFTEST FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print(
        "selftest OK: knob/ELF/config splitting, admitted filtering, single-run rejection"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("reports", nargs="*", type=Path)
    parser.add_argument("--survey", type=Path, help="walk this root for reports")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    paths = list(args.reports)
    if args.survey:
        paths += sorted(args.survey.rglob("mounted-kernel-report.json"))
    if not paths:
        sys.exit("give report paths or --survey ROOT")

    groups = collect(paths)
    all_rows = spreads(groups, admitted_only=False)
    adm_rows = spreads(groups, admitted_only=True)

    print("ADMITTED-ONLY groups (reproducibility of a PUBLISHABLE row):")
    for key, spread, n in adm_rows:
        print(f"  {key[2]:<6}{key[3][:32]:<34}n={n}  spread={spread:.4f}x")
    print()
    summarise(all_rows, "ALL runs")
    summarise(adm_rows, "ADMITTED only")
    print()
    print(f"like-for-like groups seen        : {len(groups)}")
    print(f"  with >=2 runs of ANY kind      : {len(all_rows)}")
    print(f"  with >=2 ADMITTED runs         : {len(adm_rows)}")
    print(
        "  -> a row with no second ADMITTED run has never had its cross-window\n"
        "     spread characterised, and its published CI is a LOWER BOUND on its\n"
        "     true uncertainty (bd-4sull)."
    )

    skew = admission_skew(groups)
    if skew:
        print()
        print("ADMISSION SKEW (admitted vs blocked WITHIN one configuration):")
        for key, med_adm, med_blk, n_adm, n_blk in skew:
            print(
                f"  {key[2]:<6}{key[3][:28]:<30}n_adm={n_adm:<3}n_blk={n_blk:<3}"
                f"adm={med_adm:.4f} blk={med_blk:.4f} adm/blk={med_adm / med_blk:.4f}"
            )
        values = [row[1] / row[2] for row in skew]
        favourable = sum(1 for v in values if v < 1.0)
        print(
            f"  median adm/blk {st.median(values):.4f} over {len(values)} group(s); "
            f"admitted is the more favourable side in {favourable}/{len(values)}"
        )
        print(
            "  -> TWO readings, and the bank cannot separate them: the gate may be\n"
            "     correctly discarding load-contaminated windows (bd-fj2dg shows drift\n"
            "     on the slower arm INFLATES a loss, and blocked runs are the loaded\n"
            "     ones), or admission may be selecting on the outcome. Either way the\n"
            "     direction is the same, so banked numbers sit on the favourable side\n"
            "     of their own distribution and should be quoted knowing that."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
