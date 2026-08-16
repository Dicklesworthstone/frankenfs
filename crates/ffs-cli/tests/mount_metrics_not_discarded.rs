//! bd-viil0 regression pin: the STANDARD mount runtime must not discard FUSE counters.
//!
//! The defect class here is *silent zeros*, which no behavioural assertion catches —
//! a run with the bug produces a perfectly well-formed report whose every dispatch
//! counter reads 0, and the mounted comparator then labels it
//! "unreported_by_this_elf" as though the ELF were at fault. It was not: it was
//! never asked. `mount_with_fuse` returned `()`, and the Standard branch
//! hand-constructed an all-zero `MetricsSnapshot` to feed the shutdown summary.
//!
//! Both halves of the fix are structural rather than observable from outside, so
//! they are pinned structurally. A behavioural test would have to complete a real
//! mount, which needs a FUSE device and a fixture image and so cannot run in the
//! ordinary unit-test gate — exactly why this regressed unnoticed in the first place.

const MAIN_RS: &str = include_str!("../src/main.rs");

/// Production code only. `main.rs`'s own `#[cfg(test)]` module legitimately builds
/// zeroed `MetricsSnapshot` fixtures to exercise the summary formatter, and those
/// are not the defect — the defect is a fabricated snapshot on the live mount path.
fn production_source() -> &'static str {
    // `rsplit_once`, not `split_once`: main.rs carries several inline `#[cfg(test)]`
    // modules and the production items this file inspects sit after the first of
    // them, so splitting at the first marker would hide real code from the guard.
    MAIN_RS
        .rsplit_once("\n#[cfg(test)]\n")
        .map_or(MAIN_RS, |(before, _)| before)
}

/// The Standard branch must consume the real snapshot returned by `mount_with_fuse`
/// rather than fabricating one. A literal `requests_total: 0` is the fingerprint of
/// the fabricated snapshot; nothing else in the CLI constructs a `MetricsSnapshot`.
#[test]
fn standard_mount_runtime_does_not_fabricate_a_zero_metrics_snapshot_bd_viil0() {
    assert!(
        !production_source().contains("requests_total: 0,"),
        "ffs-cli hand-constructs a zeroed MetricsSnapshot again (bd-viil0). The \
         Standard mount runtime must pass through the snapshot returned by \
         mount_with_fuse; a fabricated all-zero snapshot silently blocks every \
         per-op attribution on the mounted comparator surface while still \
         producing a well-formed report."
    );
}

/// `mount_with_fuse` must return the counters, not `()`. This is what makes the
/// Standard runtime symmetric with the managed one, which already got its metrics
/// from `MountHandle::wait`.
#[test]
fn mount_with_fuse_returns_the_metrics_snapshot_bd_viil0() {
    let signature = production_source()
        .split_once("fn mount_with_fuse(")
        .expect("mount_with_fuse must exist")
        .1;
    let header = signature
        .split_once('{')
        .expect("mount_with_fuse must have a body")
        .0;
    assert!(
        header.contains("Result<ffs_fuse::MetricsSnapshot>"),
        "mount_with_fuse must return Result<ffs_fuse::MetricsSnapshot> so the \
         Standard runtime has real counters to report (bd-viil0); found signature: \
         {header}"
    );
}

/// The Standard branch must actually emit the shutdown metrics line. Returning the
/// snapshot is not enough on its own: before the fix, `mount_dispatch_metrics` was
/// emitted only by `log_mount_shutdown_metrics`, whose sole caller sat inside
/// `mount_with_managed_fuse`, so the standard path emitted nothing at all.
#[test]
fn standard_mount_runtime_emits_shutdown_metrics_bd_viil0() {
    let standard_branch = production_source()
        .split_once("MountRuntimeMode::Standard => {")
        .expect("the Standard runtime branch must exist")
        .1;
    let branch_head = &standard_branch[..standard_branch
        .find("MountRuntimeMode::")
        .unwrap_or(standard_branch.len().min(4096))];
    assert!(
        branch_head.contains("log_mount_shutdown_metrics("),
        "the Standard mount runtime must call log_mount_shutdown_metrics so that \
         mount_dispatch_metrics is emitted on the path the mounted comparator \
         actually uses (bd-viil0)"
    );
}

/// bd-i353e / bd-q0xnl: every counter on `MetricsSnapshot` must reach the emitted
/// `mount_dispatch_metrics` line, or the measurement that needs it cannot read it.
///
/// This is the `bd-viil0` failure class one level out. There, the Standard runtime
/// held real counters and never emitted them; here a counter can exist, be
/// correctly incremented, be visible in `Debug`, and still be missing from the one
/// line a harness actually parses — and nothing fails. A run then reports a
/// perfectly well-formed metrics line with a counter silently absent, which is
/// indistinguishable from that counter reading zero.
///
/// Deliberately checked against the STRUCT rather than a fixed list: a list would
/// need updating in lockstep with the struct, which is the tax `bd-k3g3g` removed
/// and which this test would silently reintroduce.
#[test]
fn every_metrics_snapshot_counter_reaches_the_emitted_line_bd_i353e() {
    const FUSE_LIB: &str = include_str!("../../ffs-fuse/src/lib.rs");

    let decl = FUSE_LIB
        .split_once("pub struct MetricsSnapshot {")
        .expect("MetricsSnapshot must exist")
        .1;
    let body = decl.split_once("\n}").expect("struct must close").0;

    let fields: Vec<&str> = body
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| l.split_once(": u64,"))
        .map(|(name, _)| name)
        .collect();
    assert!(
        fields.len() >= 15,
        "parsed only {} fields; the struct shape changed and this guard is no \
         longer reading it correctly -- fix the parse rather than the assertion",
        fields.len()
    );

    let emitted = production_source();
    // requests_* are summary counters carried on other lines; the dispatch line is
    // specifically the per-op/per-mechanism surface.
    let exempt = [
        "requests_total",
        "requests_ok",
        "requests_err",
        "bytes_read",
        "metadata_requests",
        "requests_throttled",
        "requests_shed",
    ];
    let missing: Vec<&str> = fields
        .iter()
        .filter(|f| !exempt.contains(*f))
        .filter(|f| !emitted.contains(&format!("metrics.{f}")))
        .copied()
        .collect();
    assert!(
        missing.is_empty(),
        "these MetricsSnapshot counters are never emitted, so no harness can read \
         them and a run reports a well-formed line with them silently absent: {missing:?}"
    );
}
