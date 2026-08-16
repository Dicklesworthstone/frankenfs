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

import statistics as st
import sys
import time

# A run launched on a host drifting more than this is launched on a moving target.
MAX_DRIFT = 0.35
# Oscillation within the sampling window, relative to its own median.
MAX_SPREAD = 0.50
# Backstop only. Stability cannot rescue a host with no spare CPU.
ABSOLUTE_CEILING = 64.0


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

    # A stable moderate window: the case the old gate refused. This is the whole
    # point of the change.
    ok, why = verdict([35.0, 35.2, 34.9], one=35.0, five=35.1, fifteen=35.0)
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

    print("host_stability selftest: 10 cases pass")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
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
