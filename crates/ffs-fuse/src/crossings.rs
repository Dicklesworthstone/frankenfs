//! Per-opcode counts of requests that actually CROSSED the FUSE boundary.
//!
//! ⚠️ NOT YET WIRED, and deliberately not declared as a module. Disk is at 100%
//! and no build, test or benchmark may run, so this file is inert to cargo: it
//! is referenced by no `mod` statement and cannot break anyone's build while it
//! cannot be compiled. Wiring it is a one-line `mod crossings;` plus two call
//! sites, to be done in the same change that first compiles it.
//!
//! WHY A NEW COUNTER WHEN `requests_total` EXISTS. It counts request SCOPES, not
//! crossings. bdd0fd1b fixed a case where 6001 warm stats counted 22 requests,
//! because the capability-probe memo answered and returned BEFORE
//! `with_request_scope` was reached -- the counter sat inside the branch it was
//! meant to measure. Every request count banked before that fix under-reports,
//! and the counter still cannot answer "which opcode crossed", only "how many
//! scopes were opened".
//!
//! WHAT IT IS FOR. bd-xfe7z asks what the `1.143 us/op` residue in readdir+stat
//! is once the `security.capability` probe is suppressed: transport (batching)
//! or daemon per-entry work. `scripts/fuse_crossing_count.py` answers the total
//! from outside via `strace`, which is trustworthy precisely because it cannot
//! be fooled by the daemon's own bookkeeping -- but it cannot say WHICH opcodes
//! remain. That attribution is what turns a count into a lever.
//!
//! WHERE IT MUST BE INCREMENTED, since that is the whole lesson of bdd0fd1b:
//! at the dispatch site, immediately after a request is decoded from the device
//! read and BEFORE any handler, memo, cache or early return can answer it. Not
//! inside a handler, not inside `with_request_scope`, not behind any `if`.
//! One device read is one crossing; anything that can be skipped is not the
//! boundary.

use std::sync::atomic::{AtomicU64, Ordering};

/// The opcodes worth attributing separately on the metadata path.
///
/// Deliberately not every `RequestOp`: this is a hot-path array indexed by
/// `usize`, and the metadata rows (warm stat, readdir+stat) turn on a handful
/// of opcodes. `Other` keeps the total honest -- a bucket that silently dropped
/// unlisted opcodes would make crossings-per-entry look better than it is,
/// which is the direction an instrument must never be wrong in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossingOp {
    Lookup,
    Getattr,
    Getxattr,
    Readdir,
    Readdirplus,
    Open,
    Opendir,
    Release,
    Releasedir,
    Other,
}

impl CrossingOp {
    /// Stable index for the counter array.
    const fn index(self) -> usize {
        match self {
            Self::Lookup => 0,
            Self::Getattr => 1,
            Self::Getxattr => 2,
            Self::Readdir => 3,
            Self::Readdirplus => 4,
            Self::Open => 5,
            Self::Opendir => 6,
            Self::Release => 7,
            Self::Releasedir => 8,
            Self::Other => 9,
        }
    }

    /// Name used in the metrics line.
    const fn label(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Getattr => "getattr",
            Self::Getxattr => "getxattr",
            Self::Readdir => "readdir",
            Self::Readdirplus => "readdirplus",
            Self::Open => "open",
            Self::Opendir => "opendir",
            Self::Release => "release",
            Self::Releasedir => "releasedir",
            Self::Other => "other",
        }
    }

    /// Every variant, in index order. Used for rendering and by the tests that
    /// pin index/label agreement.
    const ALL: [Self; 10] = [
        Self::Lookup,
        Self::Getattr,
        Self::Getxattr,
        Self::Readdir,
        Self::Readdirplus,
        Self::Open,
        Self::Opendir,
        Self::Release,
        Self::Releasedir,
        Self::Other,
    ];
}

/// Per-opcode crossing counters.
#[derive(Debug, Default)]
pub struct Crossings {
    counts: [AtomicU64; 10],
}

impl Crossings {
    /// Record one crossing. Relaxed because these are counters read at the end
    /// of a run, never used to order anything.
    pub fn record(&self, op: CrossingOp) {
        self.counts[op.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Count for one opcode.
    #[must_use]
    pub fn get(&self, op: CrossingOp) -> u64 {
        self.counts[op.index()].load(Ordering::Relaxed)
    }

    /// Total crossings across every opcode.
    ///
    /// This must equal the `strace` read count for the same window. If it does
    /// not, the increment is in the wrong place -- which is the failure this
    /// whole module exists to avoid, so the divergence is the signal, not noise.
    #[must_use]
    pub fn total(&self) -> u64 {
        CrossingOp::ALL.iter().map(|op| self.get(*op)).sum()
    }

    /// `key=value` pairs for the metrics line, in index order, always emitting
    /// every opcode.
    ///
    /// Zero-valued opcodes are emitted rather than skipped: "getxattr=0" is the
    /// entire evidence that suppression worked, and an instrument that prints
    /// nothing when a count is zero cannot distinguish "did not happen" from
    /// "was not measured".
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for op in CrossingOp::ALL {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&format!("crossings_{}={}", op.label(), self.get(op)));
        }
        out.push_str(&format!(" crossings_total={}", self.total()));
        out
    }

    /// Crossings per unit of client work, the figure bd-xfe7z turns on.
    #[must_use]
    pub fn per_operation(&self, operations: u64) -> f64 {
        if operations == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            self.total() as f64 / operations as f64
        }
    }
}

/// Ingest the raw per-slot counts the vendored `fuser` records at dispatch.
///
/// The counting lives in `fuser::Request::dispatch` because that is the single
/// point every decoded request passes through before any handler; this side
/// owns the vocabulary (labels, ordering, rendering) so the metrics line and the
/// ledger speak one language.
#[must_use]
pub fn render_fuser_counts(counts: [u64; fuser::CROSSING_SLOTS]) -> String {
    let mut out = String::new();
    let mut total = 0_u64;
    for op in CrossingOp::ALL {
        if !out.is_empty() {
            out.push(' ');
        }
        let value = counts[op.index()];
        total += value;
        out.push_str(&format!("crossings_{}={}", op.label(), value));
    }
    out.push_str(&format!(" crossings_total={total}"));
    out
}

/// Render per-opcode dispatch nanoseconds alongside the counts.
///
/// Emitted as totals rather than averages so a reader can divide by whatever
/// denominator the workload actually had. An average computed here would bake in
/// an assumption about the client, and the last two counts in this bead were
/// wrong precisely because the client was not what the reader assumed.
#[must_use]
pub fn render_fuser_nanos(nanos: [u64; fuser::CROSSING_SLOTS]) -> String {
    let mut out = String::new();
    let mut total = 0_u64;
    for op in CrossingOp::ALL {
        if !out.is_empty() {
            out.push(' ');
        }
        let value = nanos[op.index()];
        total += value;
        out.push_str(&format!("dispatch_ns_{}={}", op.label(), value));
    }
    out.push_str(&format!(" dispatch_ns_total={total}"));
    out
}

/// Live counts and dispatch times, rendered for the metrics line.
#[must_use]
pub fn render_live_timed() -> String {
    format!(
        "{} {}",
        render_fuser_counts(fuser::crossing_counts()),
        render_fuser_nanos(fuser::crossing_nanos())
    )
}

/// Live counts from the daemon, rendered for the metrics line.
#[must_use]
pub fn render_live() -> String {
    render_fuser_counts(fuser::crossing_counts())
}

#[cfg(test)]
mod tests {

    /// Nanoseconds must render per opcode with the same labels and ordering as
    /// the counts, so the two lines can be divided by each other without a
    /// mapping step -- that mapping is exactly where a reader would go wrong.
    #[test]
    fn nanos_render_with_the_same_labels_as_counts_bd_xfe7z() {
        let mut nanos = [0_u64; fuser::CROSSING_SLOTS];
        nanos[CrossingOp::Readdirplus.index()] = 22_000;
        nanos[CrossingOp::Getxattr.index()] = 3;
        let line = super::render_fuser_nanos(nanos);
        assert!(line.contains("dispatch_ns_readdirplus=22000"), "{line}");
        assert!(line.contains("dispatch_ns_getxattr=3"), "{line}");
        assert!(line.contains("dispatch_ns_lookup=0"), "{line}");
        assert!(line.contains("dispatch_ns_total=22003"), "{line}");
        for op in CrossingOp::ALL {
            assert!(line.contains(&format!("dispatch_ns_{}=", op.label())), "{line}");
        }
    }

    /// The two index tables live in different crates -- `fuser::crossing_slot`
    /// assigns them, `CrossingOp::index` names them -- and a silent drift would
    /// mislabel every count while still summing correctly, which is the worst
    /// kind of instrument bug. This pins the shape they must share.
    #[test]
    fn the_slot_count_matches_the_vendored_counter_bd_xfe7z() {
        assert_eq!(
            CrossingOp::ALL.len(),
            fuser::CROSSING_SLOTS,
            "fuser records {} slots and this module names {}; adding an opcode on \
             one side without the other mislabels every count after it",
            fuser::CROSSING_SLOTS,
            CrossingOp::ALL.len()
        );
    }

    /// Ingest must preserve position: slot i is the opcode at index i, and the
    /// total is the sum of what was handed in, not a recount.
    #[test]
    fn ingest_preserves_slot_position_and_total_bd_xfe7z() {
        let mut counts = [0_u64; fuser::CROSSING_SLOTS];
        counts[CrossingOp::Getxattr.index()] = 7;
        counts[CrossingOp::Readdirplus.index()] = 11;
        let line = super::render_fuser_counts(counts);
        assert!(line.contains("crossings_getxattr=7"), "{line}");
        assert!(line.contains("crossings_readdirplus=11"), "{line}");
        assert!(line.contains("crossings_lookup=0"), "{line}");
        assert!(line.contains("crossings_total=18"), "{line}");
    }
    use super::{CrossingOp, Crossings};

    /// Indices must be unique and dense, or two opcodes share a counter and
    /// every attribution built on it is wrong.
    #[test]
    fn opcode_indices_are_unique_and_dense_bd_xfe7z() {
        let mut seen: Vec<usize> = CrossingOp::ALL.iter().map(|op| op.index()).collect();
        seen.sort_unstable();
        assert_eq!(seen, (0..CrossingOp::ALL.len()).collect::<Vec<_>>());
    }

    /// Labels must be unique too: two opcodes rendering the same key would
    /// silently merge in whatever parses the metrics line.
    #[test]
    fn opcode_labels_are_unique_bd_xfe7z() {
        let mut labels: Vec<&str> = CrossingOp::ALL.iter().map(|op| op.label()).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), before);
    }

    #[test]
    fn recording_counts_only_the_opcode_recorded_bd_xfe7z() {
        let c = Crossings::default();
        c.record(CrossingOp::Lookup);
        c.record(CrossingOp::Lookup);
        c.record(CrossingOp::Getxattr);
        assert_eq!(c.get(CrossingOp::Lookup), 2);
        assert_eq!(c.get(CrossingOp::Getxattr), 1);
        assert_eq!(c.get(CrossingOp::Getattr), 0);
        assert_eq!(c.total(), 3);
    }

    /// The total must include `Other`. A bucket that dropped unlisted opcodes
    /// would make crossings-per-entry look SMALLER than it is, and an
    /// instrument must never be wrong in the flattering direction.
    #[test]
    fn the_total_includes_unattributed_opcodes_bd_xfe7z() {
        let c = Crossings::default();
        c.record(CrossingOp::Other);
        c.record(CrossingOp::Other);
        assert_eq!(c.total(), 2, "Other must count toward the total");
    }

    /// Zero-valued opcodes must still be rendered: `getxattr=0` is the entire
    /// evidence that suppression worked.
    #[test]
    fn render_emits_every_opcode_including_zeroes_bd_xfe7z() {
        let c = Crossings::default();
        c.record(CrossingOp::Readdirplus);
        let line = c.render();
        assert!(line.contains("crossings_getxattr=0"), "{line}");
        assert!(line.contains("crossings_readdirplus=1"), "{line}");
        assert!(line.contains("crossings_total=1"), "{line}");
        for op in CrossingOp::ALL {
            assert!(line.contains(&format!("crossings_{}=", op.label())), "{line}");
        }
    }

    #[test]
    fn per_operation_is_the_figure_bd_xfe7z_turns_on() {
        let c = Crossings::default();
        for _ in 0..3140 {
            c.record(CrossingOp::Readdirplus);
        }
        let per = c.per_operation(20001);
        assert!((per - 0.157).abs() < 0.001, "{per}");
        // A workload that recorded no operations must not divide by zero.
        assert!((c.per_operation(0) - 0.0).abs() < f64::EPSILON);
    }
}
