#!/usr/bin/env python3
"""Harvest the comparator's iowait fields WITHOUT paying for a comparator run (bd-xhl2g).

bd-xhl2g's acceptance asks for `peak_off_placement_mean_iowait` from >= 6 runs
spanning known-quiet and known-I/O-loaded windows, then asks whether the two
populations separate. As written that is gated on being able to take comparator
runs, and on this host the placement and external-load gates refuse most attempts
(bd-d5pdz: ~70 samples across eight turns, zero admissible). So the calibration
would wait on the very instrument whose gate it is trying to calibrate.

It does not have to. The two fields are pure `/proc/stat` arithmetic over a
1000 ms window; nothing about them needs a mounted arm. This probe reproduces
`sample_cpu_load` + `ExternalLoad::observe` EXACTLY:

    busy_i   = (total_i - (idle_i + iowait_i)) / total_i        <- iowait is IDLE here
    iowait_i =  iowait_i / total_i
    peak_off_placement_mean_X = max over samples of mean(X_i : i not in placement)
    peak_placement_mean_X     = max over samples of mean(X_i : i in     placement)
    external busy count       = |{i not in placement : busy_i > 0.25}|, refused if > 2

so a value harvested here is the same quantity the harness would print, and the
populations it builds are comparable to the ones a run would build.

THE ONE DIFFERENCE, stated rather than buried: a comparator run samples DURING its
own timed region, so its on-placement numbers include its own arms' load. This
probe has no arms, so `peak_placement_mean_busy` here describes the host's use of
those CPUs and nothing else. The OFF-placement fields -- which is what the veto
and this bead are about -- are unaffected, because our arms never run there.

WHAT IT ALSO ANSWERS (bd-xhl2g item 4): whether an iowait storm can be attributed
to a DEVICE, which decides whether a gate could ever be device-scoped rather than
host-wide. Read from /proc/diskstats field 10 (ms spent doing I/O) over the same
window, so the attribution shares the sample.

    scripts/iowait_population_probe.py --label loaded --samples 20
    scripts/iowait_population_probe.py --label quiet --placement 8-15,18 --json out.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Mirrors of the harness constants. Changing one here without changing it there
# makes the harvested population incomparable to a real run, which is the whole
# point of the probe, so they are named rather than inlined.
CPU_SAMPLE_INTERVAL_S = 1.0  # CPU_SAMPLE_INTERVAL_MS = 1_000
EXTERNAL_BUSY_CPU_FRACTION = 0.25
MAX_EXTERNAL_BUSY_CPUS = 2


def read_cpu_ticks() -> dict[int, tuple[int, int, int]]:
    """(total, idle_including_iowait, iowait) per CPU -- `read_cpu_ticks` in Rust."""
    out: dict[int, tuple[int, int, int]] = {}
    for line in Path("/proc/stat").read_text().splitlines():
        if not line.startswith("cpu") or not line[3:4].isdigit():
            continue
        head, _, rest = line.partition(" ")
        ticks = [int(x) for x in rest.split()]
        # fields: user nice system idle iowait irq softirq steal guest guest_nice
        out[int(head[3:])] = (sum(ticks), ticks[3] + ticks[4], ticks[4])
    return out


def read_disk_ms() -> dict[str, int]:
    """Per-device ms spent doing I/O (/proc/diskstats field 10, 1-indexed 13)."""
    out: dict[str, int] = {}
    for line in Path("/proc/diskstats").read_text().splitlines():
        f = line.split()
        if len(f) < 13:
            continue
        name = f[2]
        # Skip partitions' parents double-counting is fine here: we only want to
        # know WHICH device is busy, not a total.
        out[name] = int(f[12])
    return out


def parse_cpu_list(value: str) -> set[int]:
    cpus: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            cpus.update(range(int(lo), int(hi) + 1))
        else:
            cpus.add(int(part))
    return cpus


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", type=int, default=12,
                    help="1-second samples to take (default 12)")
    ap.add_argument("--placement", default="",
                    help="CPU list our arms would occupy, e.g. 8-15,18. Empty means "
                         "every CPU is off-placement, which is the right reading when "
                         "asking what a run would have SEEN had it started now.")
    ap.add_argument("--label", default="unlabelled",
                    help="known-quiet / known-loaded / whatever the window is")
    ap.add_argument("--json", default=None, help="also write the record here")
    a = ap.parse_args()

    placement = parse_cpu_list(a.placement)
    peak_off_busy = peak_on_busy = peak_off_iowait = peak_on_iowait = 0.0
    max_busy_cpus = 0
    over_limit = 0
    per_sample = []

    disk_before = read_disk_ms()
    t_start = time.time()
    for _ in range(a.samples):
        before = read_cpu_ticks()
        time.sleep(CPU_SAMPLE_INTERVAL_S)
        after = read_cpu_ticks()
        busy: dict[int, float] = {}
        wait: dict[int, float] = {}
        for cpu, (t0, i0, w0) in before.items():
            if cpu not in after:
                continue
            t1, i1, w1 = after[cpu]
            total = max(t1 - t0, 0)
            if total == 0:
                busy[cpu], wait[cpu] = 1.0, 0.0
                continue
            busy[cpu] = max(total - max(i1 - i0, 0), 0) / total
            wait[cpu] = max(w1 - w0, 0) / total

        off = [v for c, v in busy.items() if c not in placement]
        on = [v for c, v in busy.items() if c in placement]
        off_w = [v for c, v in wait.items() if c not in placement]
        on_w = [v for c, v in wait.items() if c in placement]
        count = sum(1 for v in off if v > EXTERNAL_BUSY_CPU_FRACTION)
        max_busy_cpus = max(max_busy_cpus, count)
        if count > MAX_EXTERNAL_BUSY_CPUS:
            over_limit += 1
        m_off = sum(off) / len(off) if off else 0.0
        m_on = sum(on) / len(on) if on else 0.0
        m_off_w = sum(off_w) / len(off_w) if off_w else 0.0
        m_on_w = sum(on_w) / len(on_w) if on_w else 0.0
        peak_off_busy = max(peak_off_busy, m_off)
        peak_on_busy = max(peak_on_busy, m_on)
        peak_off_iowait = max(peak_off_iowait, m_off_w)
        peak_on_iowait = max(peak_on_iowait, m_on_w)
        per_sample.append({"off_busy": m_off, "off_iowait": m_off_w,
                           "busy_cpus_over_limit": count})

    elapsed_ms = (time.time() - t_start) * 1000.0
    disk_after = read_disk_ms()
    # Fraction of wall time each device spent with I/O in flight, over the whole
    # probe. This is the device attribution bd-xhl2g item 4 needs; a host-wide
    # iowait number cannot say whether the storm shares OUR backing store.
    devices = sorted(
        (
            (name, (disk_after[name] - ms) / elapsed_ms)
            for name, ms in disk_before.items()
            if name in disk_after and disk_after[name] - ms > 0
        ),
        key=lambda kv: -kv[1],
    )[:8]

    veto = "CONTENDED" if over_limit > a.samples * 0.10 else "CLEAR"
    record = {
        "label": a.label,
        "samples": a.samples,
        "placement": sorted(placement),
        "loadavg": Path("/proc/loadavg").read_text().split()[0],
        "peak_off_placement_mean_busy": round(peak_off_busy, 6),
        "peak_placement_mean_busy": round(peak_on_busy, 6),
        "peak_off_placement_mean_iowait": round(peak_off_iowait, 6),
        "peak_placement_mean_iowait": round(peak_on_iowait, 6),
        "max_external_busy_cpus": max_busy_cpus,
        "over_limit_samples": over_limit,
        "external_load_verdict": veto,
        "busy_devices_io_time_fraction": [
            {"device": n, "io_time_fraction": round(f, 4)} for n, f in devices
        ],
    }

    for k, v in record.items():
        if k != "busy_devices_io_time_fraction":
            print(f"{k}={v}")
    print("busy_devices_io_time_fraction=" + ", ".join(
        f"{d['device']}:{d['io_time_fraction']}" for d in record["busy_devices_io_time_fraction"]
    ) or "busy_devices_io_time_fraction=(none)")

    # The finding this probe exists to make legible: the busy verdict and the
    # iowait reading can disagree, because iowait is counted as idle in `busy`.
    if veto == "CLEAR" and peak_off_iowait > EXTERNAL_BUSY_CPU_FRACTION:
        print(
            f"\nBLIND SPOT DEMONSTRATED: external_load_during_run says {veto} while "
            f"off-placement iowait peaked at {peak_off_iowait:.4f}. The busy gate "
            "cannot see this window's I/O load at all."
        )

    if a.json:
        Path(a.json).write_text(json.dumps(record, indent=2) + "\n")
        print(f"\nwrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
