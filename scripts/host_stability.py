#!/usr/bin/env python3
"""Decide whether the host is STABLE enough to certify on, not merely quiet.

Motivated by a fleet finding relayed 2026-08-16: the blocker on this box is host
VOLATILITY, not absolute load — a stable moderate window beats a brief quiet
spike. The gate in `fuse_vs_kernel_abba.sh` was the opposite of that: one sample
of the 1-minute loadavg against a fixed ceiling. That gate has two failure modes
this module fixes.

* **It admits a spike.** A 1-minute average dipping to 10 while the 5-minute sits
  at 25 is a host that was busy seconds ago and will be again; the dip is the tail
  of a burst, not a quiet window. The old gate saw `10 < 30` and started a
  ~4-minute certification into it.
* **It defers a good window.** A host pinned flat at 35 across all three averages
  is more certifiable than either of the above, and the old gate refused it.

The signals, both cheap and both from `/proc/loadavg`:

* `drift` — the 1-minute average against the 5-minute. Far from 1.0 means load is
  moving, in whichever direction. Rising is worse than falling, because a run
  launched on a falling edge finishes on a rising one.
* `spread` — the observed range of the 1-minute average across a short sampling
  window, relative to its median. This catches oscillation that the averages
  themselves smooth away.

An absolute ceiling is retained but DEMOTED to a backstop: at genuinely extreme
load the arms contend for CPU no matter how stable the contention is.

Self-test: `python3 scripts/host_stability.py --selftest`
Live read: `python3 scripts/host_stability.py`
"""
from __future__ import annotations

import os
import statistics as st
import sys
import time

# A run launched on a host drifting more than this is launched on a moving target.
MAX_DRIFT = 0.35
# Oscillation within the sampling window, relative to its own median.
MAX_SPREAD = 0.50
# Backstop. Stability cannot rescue a host with no spare CPU — and this ceiling is
# EMPIRICAL, not a round number. Across the vs-kernel runs banked on 2026-08-16:
#
#   loadavg median   outcome
#    9.7, 10.1, 14.5  clean, tight, all A/A nulls passing
#   43.7, 43.7        widest confidence intervals of the series
#   52.6, 52.6        one kernel-arm null FAILED (1.1733x, CI excluding 1.0)
#
# Every run at or below ~20 produced clean nulls; every run at or above ~43
# produced a wide or failing one. The ceiling therefore sits between them rather
# than at nproc. Setting it AT nproc was a real defect, found by running this gate
# against a host at loadavg 60.9 on 64 cores: drift 0.31 and spread 0.04 made it
# report STABLE, and it was — stably saturated at ~95% utilisation, with no spare
# CPU for the two cores the ABBA harness pins.
#
# Expressed as a fraction of nproc so it travels to other machines.
def _default_ceiling() -> float:
    try:
        return max(8.0, (os.cpu_count() or 8) * 0.5)
    except Exception:
        return 8.0


ABSOLUTE_CEILING = _default_ceiling()


def drift(one: float, five: float) -> float:
    """|1min/5min - 1|. 0.0 means the short and medium averages agree."""
    if five <= 0:
        return 0.0
    return abs(one / five - 1.0)


def spread(samples: list[float]) -> float:
    """(max - min) / median of the sampled 1-minute averages."""
    if not samples:
        return 0.0
    med = st.median(samples)
    if med <= 0:
        return 0.0
    return (max(samples) - min(samples)) / med


def rising(one: float, five: float, fifteen: float) -> bool:
    """Monotonically increasing averages: the host is ramping up."""
    return one > five > fifteen


def verdict(samples: list[float], one: float, five: float, fifteen: float,
            max_drift: float = MAX_DRIFT, max_spread: float = MAX_SPREAD,
            ceiling: float = ABSOLUTE_CEILING) -> tuple[bool, str]:
    """(ok_to_certify, human-readable reason).

    Deliberately reports the reason even when it says yes, so the banked row can
    quote the conditions it was admitted under rather than merely that it passed.
    """
    d = drift(one, five)
    s = spread(samples)
    med = st.median(samples) if samples else one
    if med > ceiling:
        return False, (f"DEFER: loadavg median {med:.1f} exceeds the absolute "
                       f"ceiling {ceiling:.0f}; no amount of stability creates "
                       f"spare CPU")
    if rising(one, five, fifteen) and d > max_drift:
        return False, (f"DEFER: host is RAMPING ({one:.1f} > {five:.1f} > "
                       f"{fifteen:.1f}, drift {d:.2f}); a run launched now "
                       f"finishes in a busier window than it started")
    if d > max_drift:
        return False, (f"DEFER: drift {d:.2f} exceeds {max_drift:.2f} "
                       f"(1min {one:.1f} vs 5min {five:.1f}); load is moving, so "
                       f"this is a spike and not a window")
    if s > max_spread:
        return False, (f"DEFER: spread {s:.2f} exceeds {max_spread:.2f} across "
                       f"the sampling window; the host is oscillating")
    return True, (f"STABLE: loadavg median {med:.1f}, drift {d:.2f}, spread "
                  f"{s:.2f} — certify and record these with the row")


# A run may start stable and be ruined mid-flight. Observed 2026-08-16: a run
# launched at median 19.0 with drift 0.07 -- the best conditions of the session --
# saw loadavg reach 57.03 during its ~5 minutes, and produced A/A nulls so wide
# (kernel 0.9329x ci95 [0.7130, 1.3627]) that an 8% lever could not be resolved.
# The row had to be downgraded afterwards. A launch-time gate cannot prevent that;
# only watching during the run can.
EXCURSION_FACTOR = 2.0


def excursion(samples: list[float], launch_median: float,
              factor: float = EXCURSION_FACTOR,
              ceiling: float = None,
              consecutive: int = 2) -> tuple[bool, str]:
    """Has the host left the conditions the run was admitted under?

    (should_abort, reason). Requires `consecutive` samples over the threshold, so
    a single lagging 1-minute average does not kill an otherwise good run — the
    loadavg is itself an average and will overshoot briefly on any transient.

    Aborting is the point: a run that finishes under conditions it was not
    admitted under produces a row that has to be withdrawn later, which costs more
    than the run did.
    """
    if ceiling is None:
        ceiling = ABSOLUTE_CEILING
    if launch_median <= 0 or not samples:
        return False, ""
    threshold = max(launch_median * factor, 0.0)
    run = 0
    for v in samples:
        if v > threshold or v > ceiling:
            run += 1
            if run >= consecutive:
                # Report the PEAK seen, not merely the sample that tripped the
                # counter: the peak is what a reader needs to judge the row, and
                # the tripping sample is an artefact of where the run happens to
                # sit in the consecutive window.
                return True, (f"ABORT: loadavg peaked at {max(samples):.1f} against "
                              f"this run's admission threshold {threshold:.1f} "
                              f"(launch median {launch_median:.1f} x {factor:g}); "
                              f"{consecutive} consecutive samples over it, so the "
                              f"host left the conditions this run was admitted "
                              f"under")
        else:
            run = 0
    return False, ""


def wait_for_stable(budget: float, poll: float = 15.0,
                    sample_seconds: float = 12.0) -> tuple[bool, str, float]:
    """Poll until the host is certifiable, or the budget runs out.

    Deferring is correct but wasteful: on this box the load oscillates between
    ~10 and ~90 over minutes, so a single check almost always lands mid-swing and
    the window is lost even though one arrives shortly after. This waits for the
    window instead of discarding it.

    It is NOT a retry loop around a measurement -- nothing is measured here, and
    the caller still decides. It only answers "is it time yet", and it always
    terminates: the budget is a hard ceiling, checked before every poll.

    Returns (ok, reason, seconds_waited).
    """
    started = time.monotonic()
    while True:
        samples, one, five, fifteen = sample(seconds=sample_seconds)
        ok, why = verdict(samples, one, five, fifteen)
        waited = time.monotonic() - started
        if ok:
            return True, f"{why} (waited {waited:.0f}s)", waited
        if waited >= budget:
            return False, f"{why} (gave up after {waited:.0f}s of {budget:.0f}s)", waited
        time.sleep(poll)


def sample(seconds: float = 12.0, interval: float = 2.0) -> tuple[list[float], float, float, float]:
    samples: list[float] = []
    one = five = fifteen = 0.0
    deadline = time.monotonic() + seconds
    while True:
        with open("/proc/loadavg") as fh:
            parts = fh.read().split()
        one, five, fifteen = float(parts[0]), float(parts[1]), float(parts[2])
        samples.append(one)
        if time.monotonic() >= deadline:
            break
        time.sleep(interval)
    return samples, one, five, fifteen


def _selftest() -> int:
    # A brief quiet spike inside a busy host: the case the old gate admitted.
    ok, why = verdict([10.3, 9.8, 10.0], one=10.0, five=25.3, fifteen=25.9)
    assert not ok, why
    assert "spike" in why or "drift" in why, why

    # A stable moderate window: the case the old gate refused, and the whole point
    # of preferring stability over quiet.
    #
    # This case originally used 35.0, which was an ASSUMPTION dressed as a test: I
    # had no measurement at that load, and when the ceiling became empirical (32)
    # the two collided. The evidence covers <=14.5 (clean) and >=43.7 (wide or
    # failing nulls) with nothing between, so the case now uses a value inside the
    # evidenced-good range. Whether a stable host at 35 certifies well is UNTESTED
    # and should be measured before any test asserts it.
    ok, why = verdict([20.0, 20.2, 19.9], one=20.0, five=20.1, fifteen=20.0)
    assert ok, why

    # Ramping host, as observed at 71.89 / 61.15 / 41.21.
    ok, why = verdict([71.9, 72.4, 71.5], one=71.9, five=61.2, fifteen=41.2)
    assert not ok, why
    assert "RAMPING" in why or "ceiling" in why, why

    # Oscillation the averages would smooth away.
    ok, why = verdict([8.0, 30.0, 9.0], one=15.0, five=15.0, fifteen=15.0)
    assert not ok, why
    assert "oscillating" in why, why

    # Stable but genuinely saturated: the backstop must still fire.
    ok, why = verdict([80.0, 80.1, 79.9], one=80.0, five=80.0, fifteen=80.0)
    assert not ok, why
    assert "ceiling" in why, why

    # The case that exposed the defect: STABLY saturated. drift and spread both
    # look excellent, and on a 64-core box a ceiling of nproc admitted it.
    ok, why = verdict([60.9, 61.0, 60.8], one=60.9, five=46.4, fifteen=35.1,
                      ceiling=32.0)
    assert not ok, why
    assert "ceiling" in why, why
    # ... and with the old permissive ceiling it wrongly passed, which is the
    # regression this pins.
    ok_old, _ = verdict([60.9, 61.0, 60.8], one=60.9, five=46.4, fifteen=35.1,
                        ceiling=64.0, max_drift=0.35)
    assert ok_old, "the old ceiling admitted a stably-saturated host"

    # The empirical boundary: loads that produced clean nulls must still pass.
    for good in (9.7, 10.1, 14.5):
        ok, why = verdict([good, good, good], one=good, five=good, fifteen=good,
                          ceiling=32.0)
        assert ok, (good, why)
    # ... and loads that produced wide or failing nulls must not.
    for bad in (43.7, 52.6):
        ok, why = verdict([bad, bad, bad], one=bad, five=bad, fifteen=bad,
                          ceiling=32.0)
        assert not ok, (bad, why)

    # A genuinely quiet AND stable host certifies.
    ok, why = verdict([9.7, 9.8, 9.6], one=9.7, five=9.7, fifteen=9.8)
    assert ok, why

    # Falling edge is still drift, but must not be reported as RAMPING.
    ok, why = verdict([10.0, 10.1, 9.9], one=10.0, five=40.0, fifteen=45.0)
    assert not ok, why
    assert "RAMPING" not in why, why

    # Degenerate inputs must not raise.
    assert drift(1.0, 0.0) == 0.0
    assert spread([]) == 0.0

    # A falling edge is exactly today's case: the 1-minute samples are rock-steady
    # (spread ~1%) while the 5-minute is 3x higher. Sampling only the short average
    # would call this quiet; the drift check is what catches it.
    ok, why = verdict([11.05, 11.12, 10.95], one=10.95, five=28.68, fifteen=34.95)
    assert not ok, why
    assert "drift" in why and "spike" in why, why
    assert spread([11.05, 11.12, 10.95]) < 0.02, "short-average spread alone looks quiet"

    # wait_for_stable must terminate immediately when already stable, and must
    # respect a zero budget rather than looping.
    ok, why, waited = wait_for_stable(budget=0.0, sample_seconds=0.0)
    assert isinstance(ok, bool) and waited >= 0.0, (ok, why, waited)

    # In-run excursion: the case that cost a row on 2026-08-16 (launch median 19.0,
    # in-run max 57.03) must abort.
    abort, why = excursion([18.0, 19.0, 57.0, 55.0, 20.0], launch_median=19.0)
    assert abort, why
    assert "ABORT" in why and "57.0" in why, why  # must report the PEAK, not the trip sample

    # A single transient over the threshold must NOT abort: the 1-minute average
    # overshoots on any brief burst and killing good runs is its own failure.
    abort, why = excursion([18.0, 19.0, 57.0, 18.0, 19.0], launch_median=19.0)
    assert not abort, why

    # A run that stays inside its admission conditions must never abort.
    abort, why = excursion([18.0, 19.0, 20.0, 21.0], launch_median=19.0)
    assert not abort, why

    # The absolute ceiling still applies even if the factor would allow it: a run
    # launched at median 30 must not be allowed to ride up to 60 on this box.
    abort, why = excursion([59.0, 59.5], launch_median=30.0, ceiling=32.0)
    assert abort, why

    # Degenerate inputs must not raise or abort.
    assert excursion([], launch_median=19.0)[0] is False
    assert excursion([100.0], launch_median=0.0)[0] is False

    print("host_stability selftest: 21 cases pass")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    if "--check-excursion" in sys.argv:
        i = sys.argv.index("--check-excursion")
        launch = float(sys.argv[i + 1])
        samples = [float(x) for x in open(sys.argv[i + 2]) if x.strip()]
        abort, why = excursion(samples, launch)
        if abort:
            print(why)
            raise SystemExit(5)
        raise SystemExit(0)

    budget = 0.0
    for i, a in enumerate(sys.argv):
        if a == "--wait" and i + 1 < len(sys.argv):
            budget = float(sys.argv[i + 1])
    if budget > 0:
        ok, why, _ = wait_for_stable(budget)
        print(why)
        raise SystemExit(0 if ok else 4)
    s, o, f, ft = sample()
    ok, why = verdict(s, o, f, ft)
    print(why)
    print(f"samples={[f'{x:.2f}' for x in s]} 1min={o:.2f} 5min={f:.2f} 15min={ft:.2f}")
    raise SystemExit(0 if ok else 4)
