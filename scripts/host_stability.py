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


# The ADMISSION ceiling and the IN-RUN ceiling answer different questions and must
# not share a number. Admission asks "is this a good place to start"; in-run asks
# "has it changed enough to invalidate what I already have". A run admitted at
# loadavg 23.3 was killed by a 33.5 blip because both used 32 -- even though the
# factor rule (46.6) was nowhere near tripping, and 33.5 on 64 cores is ~52%
# utilisation, inside the band where this box has no evidence either way. Losing a
# run that far inside its own admission conditions is a false positive.
RUN_CEILING_MULTIPLE = 1.5


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
        ceiling = ABSOLUTE_CEILING * RUN_CEILING_MULTIPLE
    if launch_median <= 0 or not samples:
        return False, ""
    # Never abort at a load we would happily ADMIT a fresh run at. Without this
    # floor the factor rule is hypersensitive exactly when conditions are best: a
    # run launched at 13.7 got a threshold of 27.4 and died to a rise to 30.9,
    # while one launched at 30 would have tolerated 60. Starting in a quiet window
    # must not make a run more fragile than starting in a mediocre one.
    threshold = max(launch_median * factor, ABSOLUTE_CEILING)
    run = 0
    tripped_by = ""
    for v in samples:
        over_factor = v > threshold
        over_ceiling = v > ceiling
        if over_factor or over_ceiling:
            run += 1
            # Name the rule that actually fired. Reporting the factor threshold
            # when the ceiling tripped tells the reader the run exceeded a number
            # it never reached, which is worse than saying nothing.
            tripped_by = (f"drifted past {threshold:.1f} (launch median "
                          f"{launch_median:.1f} x {factor:g})" if over_factor
                          else f"exceeded the in-run ceiling {ceiling:.1f}")
            if run >= consecutive:
                # Report the PEAK seen, not merely the sample that tripped the
                # counter: the peak is what a reader needs to judge the row, and
                # the tripping sample is an artefact of where the run happens to
                # sit in the consecutive window.
                return True, (f"ABORT: loadavg peaked at {max(samples):.1f} and "
                              f"{tripped_by}, for {consecutive} consecutive "
                              f"samples; the host left the conditions this run was "
                              f"admitted under")
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


def siblings(cpu: int) -> set[int]:
    """Logical CPUs sharing a physical core with `cpu` (SMT siblings)."""
    try:
        with open(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list") as fh:
            raw = fh.read().strip()
    except OSError:
        return {cpu}
    out: set[int] = set()
    for part in raw.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.update(range(int(a), int(b) + 1))
        elif part:
            out.add(int(part))
    return out or {cpu}


def sibling_of(cpu: int) -> int | None:
    """The SMT sibling of `cpu`, or None if it has none (SMT off / single-thread)."""
    others = sorted(siblings(cpu) - {cpu})
    return others[0] if others else None


def cores_comparable(daemon_cpu: int, client_cpu: int) -> tuple[bool, str]:
    """Refuse a pinning where the two arms cannot be compared.

    Found 2026-08-16, after a full day of measurements: this harness defaulted to
    daemon `cpu8` and client `cpu40`, which on a 5975WX are SMT SIBLINGS of one
    physical core (`core_id 8`). That made the FrankenFS arm run its daemon and its
    client on two threads of a single core, contending for one core's execution
    units, while the kernel arm ran its client alone on that core with the sibling
    idle. Every vs-kernel ratio measured that way is biased AGAINST FrankenFS by an
    unknown amount, and no A/A null could see it: both arms of a null share the
    same pinning.

    A ratio whose arms sit on structurally different hardware is a hardware ratio
    in disguise, exactly as a ratio whose arms sit at different clocks is a
    frequency ratio in disguise.
    """
    if daemon_cpu == client_cpu:
        return False, (f"REFUSE: daemon and client are both pinned to cpu{daemon_cpu}; "
                       f"they would timeshare one thread")
    sib = siblings(daemon_cpu)
    if client_cpu in sib:
        return False, (f"REFUSE: cpu{daemon_cpu} and cpu{client_cpu} are SMT siblings "
                       f"of one physical core (siblings {sorted(sib)}). The FrankenFS "
                       f"arm would contend with itself on a single core while the "
                       f"kernel arm gets that core to itself — the ratio would be a "
                       f"hardware artefact, and no A/A null can detect it because "
                       f"both arms of a null share the pinning")
    return True, (f"cores comparable: cpu{daemon_cpu} and cpu{client_cpu} are on "
                  f"different physical cores")


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

    # THE THIRD FALSE POSITIVE of this family, observed 2026-08-16: a run launched
    # in the BEST window of the day (median 13.7) was killed by a rise to 30.9,
    # because 13.7 x 2 = 27.4. A load of 30.9 is one we admit new runs at, so it
    # cannot be grounds for aborting a run already in flight.
    abort, why = excursion([13.9, 15.0, 30.9, 30.5, 15.0], launch_median=13.7)
    assert not abort, why

    # The floor must not rescue a genuinely bad excursion: the run that cost a row
    # (launch 19.0, peak 57.03) must still abort.
    abort, why = excursion([19.0, 20.0, 57.0, 55.0], launch_median=19.0)
    assert abort, why

    # THE FALSE POSITIVE observed 2026-08-16: a run admitted at 23.3 saw 33.5,
    # which is far inside its own factor threshold (46.6). It must NOT abort now
    # that the in-run ceiling is separated from the admission ceiling.
    abort, why = excursion([23.0, 24.0, 33.5, 33.4, 24.0], launch_median=23.3)
    assert not abort, why

    # ...but the same trace against an ADMISSION-tight ceiling would abort, which
    # is the conflation that caused it. Pinning both halves.
    abort, why = excursion([23.0, 24.0, 33.5, 33.4], launch_median=23.3, ceiling=32.0)
    assert abort, why

    # The message must name the rule that actually fired, not the other one.
    abort, why = excursion([80.0, 81.0], launch_median=19.0)
    assert abort and "drifted past" in why, why          # factor rule
    abort, why = excursion([50.0, 50.5], launch_median=40.0, ceiling=48.0)
    assert abort and "in-run ceiling" in why, why        # ceiling rule
    assert "38.0" not in why, "must not quote the factor threshold when the ceiling fired"

    # THE DEFECT FOUND 2026-08-16: the harness default was daemon cpu8 / client
    # cpu40, which are SMT siblings on this box. It must be refused.
    ok, why = cores_comparable(8, 40)
    if 40 in siblings(8):          # only assert where the topology actually says so
        assert not ok, why
        assert "SMT siblings" in why, why
    # Same CPU for both is always refused, on any topology.
    ok, why = cores_comparable(8, 8)
    assert not ok, why
    # A pairing on genuinely different physical cores must be admitted.
    ok, why = cores_comparable(8, 12)
    if 12 not in siblings(8):
        assert ok, why
    # sibling_of must return the partner thread, or None when SMT is unavailable.
    sib8 = sibling_of(8)
    if 40 in siblings(8):
        assert sib8 == 40, sib8
    assert sibling_of(999999) is None      # missing sysfs -> no sibling, no raise

    # Sibling parsing must handle both list and range forms without raising.
    assert isinstance(siblings(0), set) and siblings(0)
    assert siblings(999999) == {999999}   # missing sysfs must not raise

    print("host_stability selftest: 35 cases pass")
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
