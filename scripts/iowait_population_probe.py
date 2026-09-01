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
    external busy count       = |{i not in placement : busy_i > 0.25}|

    a sample is CONTENDED iff that count exceeds the sample's EFFECTIVE limit,
    which is MAX_EXTERNAL_BUSY_CPUS normally and the stricter
    MAX_EXTERNAL_BUSY_CPUS_UNDER_IO_STORM on a sample whose off-placement mean
    iowait exceeds IO_STORM_OFF_PLACEMENT_MEAN_IOWAIT (bd-d5pdz); the window is
    REFUSED iff the contended FRACTION exceeds MAX_CONTENDED_SAMPLE_FRACTION or a
    run of MAX_CONSECUTIVE_CONTENDED_SAMPLES contended samples occurs

so a value harvested here is the same quantity the harness would print, and the
populations it builds are comparable to the ones a run would build.

CORRECTED 2026-09-01 (cc). This probe shipped with `MAX_EXTERNAL_BUSY_CPUS = 2`
and no consecutive-run rule, and bd-d5pdz's recalibration (23264bce7) moved the
harness to 4 with an I/O-storm scoping WITHOUT updating this file -- exactly the
drift the constants comment below warns about. The probe therefore reported a
STRICTER verdict than the code it claims to mirror: `external_load_verdict` here
could read CONTENDED on a window the harness would admit. Every field other than
`over_limit_samples` / `external_load_verdict` was unaffected, so iowait
populations harvested before this fix remain valid; the VERDICT column does not.

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
MAX_EXTERNAL_BUSY_CPUS = 4  # was 2 until bd-d5pdz, 2026-09-01
# A sample taken during an I/O storm keeps the pre-relaxation limit. This is the
# SCOPE of bd-d5pdz's relaxation, not bd-xhl2g's iowait gate: it can only withhold
# the relaxation, never refuse a sample the pre-2026-09-01 code admitted.
MAX_EXTERNAL_BUSY_CPUS_UNDER_IO_STORM = 2
IO_STORM_OFF_PLACEMENT_MEAN_IOWAIT = 0.10
# The window-level refusal predicate: `ExternalLoadWitness::clean`.
MAX_CONTENDED_SAMPLE_FRACTION = 0.10
MAX_CONSECUTIVE_CONTENDED_SAMPLES = 3


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
    io_storm_samples = 0
    consecutive = 0
    max_consecutive = 0
    per_sample = []

    disk_before = read_disk_ms()
    t_start = time.time()
    peak_device_io_fraction = 0.0
    busiest_device = None
    for _ in range(a.samples):
        # bd-xhl2g: bracket each sample so the probe reports the PEAK per-sample
        # device utilisation, which is exactly what `ExternalLoadWitness`
        # records. The window-average below is a different quantity and a
        # 40-second average hides a 3-second stall; keeping only the average
        # would make the harvested population incomparable to a real run, which
        # is the drift this file's header warns about.
        sample_disk_before = read_disk_ms()
        sample_start = time.time()
        before = read_cpu_ticks()
        time.sleep(CPU_SAMPLE_INTERVAL_S)
        after = read_cpu_ticks()
        sample_elapsed_ms = (time.time() - sample_start) * 1000.0
        sample_disk_after = read_disk_ms()
        if sample_elapsed_ms > 0:
            for name, ms in sample_disk_before.items():
                if name not in sample_disk_after:
                    continue
                frac = min(1.0, (sample_disk_after[name] - ms) / sample_elapsed_ms)
                if frac > peak_device_io_fraction:
                    peak_device_io_fraction = frac
                    busiest_device = name
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
        m_off = sum(off) / len(off) if off else 0.0
        m_on = sum(on) / len(on) if on else 0.0
        m_off_w = sum(off_w) / len(off_w) if off_w else 0.0
        m_on_w = sum(on_w) / len(on_w) if on_w else 0.0
        # `ExternalLoadWitness::observe`: the per-sample limit is chosen by THIS
        # sample's off-placement mean iowait, before the count is compared.
        if m_off_w > IO_STORM_OFF_PLACEMENT_MEAN_IOWAIT:
            io_storm_samples += 1
            effective_limit = min(MAX_EXTERNAL_BUSY_CPUS,
                                  MAX_EXTERNAL_BUSY_CPUS_UNDER_IO_STORM)
        else:
            effective_limit = MAX_EXTERNAL_BUSY_CPUS
        if count > effective_limit:
            over_limit += 1
            consecutive += 1
            max_consecutive = max(max_consecutive, consecutive)
        else:
            consecutive = 0
        peak_off_busy = max(peak_off_busy, m_off)
        peak_on_busy = max(peak_on_busy, m_on)
        peak_off_iowait = max(peak_off_iowait, m_off_w)
        peak_on_iowait = max(peak_on_iowait, m_on_w)
        per_sample.append({"off_busy": m_off, "off_iowait": m_off_w,
                           "busy_cpus_over_limit": count,
                           "effective_limit": effective_limit})

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

    # `ExternalLoadWitness::clean`: BOTH rules, not just the fraction.
    contended_fraction = over_limit / a.samples if a.samples else 0.0
    clean = (contended_fraction <= MAX_CONTENDED_SAMPLE_FRACTION
             and max_consecutive < MAX_CONSECUTIVE_CONTENDED_SAMPLES)
    veto = "CLEAR" if clean else "CONTENDED"
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
        "contended_fraction": round(contended_fraction, 4),
        "max_consecutive_over_limit": max_consecutive,
        "io_storm_samples": io_storm_samples,
        "max_external_busy_cpus_limit": MAX_EXTERNAL_BUSY_CPUS,
        "max_external_busy_cpus_limit_under_io_storm":
            MAX_EXTERNAL_BUSY_CPUS_UNDER_IO_STORM,
        "external_load_verdict": veto,
        # The harness's own fields, same definition, so a probe row and a run row
        # can be compared directly (bd-xhl2g).
        "peak_device_io_fraction": round(peak_device_io_fraction, 4),
        "busiest_device": busiest_device,
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
