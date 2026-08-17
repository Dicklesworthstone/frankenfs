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

/// Nanoseconds spent INSIDE the ops layer, per opcode (bd-xfe7z).
///
/// `dispatch_ns` times everything the daemon does for a request. This times only
/// the `FsOps` call within it, so `dispatch_ns - ops_ns` is the FUSE layer's own
/// overhead and `ops_ns` is the format layer's work.
///
/// That split is the next question and nothing currently answers it. bd-xfe7z
/// established that `getattr` owns 60.80% of dispatch time and that neither
/// removing the per-entry request scope (REJECT, inside the null) nor memoizing
/// the result (REJECT, 120630 stashes and 0 hits) moves it. What is left is the
/// cost of producing one inode's attributes -- but "producing" spans an
/// inode-table read, an attr-only parse and an `InodeAttr` construction on one
/// side of the boundary, and handler plumbing on the other. A lever aimed at the
/// wrong side of that line is the third rejected lever in a row.
static OPS_NANOS: [std::sync::atomic::AtomicU64; 10] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 10];

/// Accumulates ops-layer time on DROP, so no early return can skip it.
///
/// RAII because the first dispatch timer was not: it added elapsed time after
/// the reply was sent, and `dispatch` returns early for handlers that answer
/// through their reply object. It reported `crossings_readdirplus=209` with
/// `dispatch_ns_readdirplus=0` -- a timer that missed the one handler it was
/// built for.
pub struct OpsTimer {
    slot: usize,
    started: std::time::Instant,
}

impl OpsTimer {
    /// Start timing an ops-layer call, or return `None` when evidence is off.
    #[must_use]
    pub fn start(op: CrossingOp) -> Option<Self> {
        ops_timing_enabled().then(|| Self {
            slot: op.index(),
            started: std::time::Instant::now(),
        })
    }
}

impl Drop for OpsTimer {
    fn drop(&mut self) {
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        OPS_NANOS[self.slot].fetch_add(elapsed, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Gated on the same flag as the rest of the mount evidence, read once, so a
/// default mount pays nothing on the hot path.
fn ops_timing_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var("FFS_MOUNT_BENCH_EVIDENCE").is_ok_and(|value| value != "0"))
}

/// Render ops-layer nanoseconds with the same labels and ordering as the counts.
#[must_use]
pub fn render_ops_nanos() -> String {
    let mut out = String::new();
    let mut total = 0_u64;
    for op in CrossingOp::ALL {
        if !out.is_empty() {
            out.push(' ');
        }
        let value = OPS_NANOS[op.index()].load(std::sync::atomic::Ordering::Relaxed);
        total += value;
        out.push_str(&format!("ops_ns_{}={}", op.label(), value));
    }
    out.push_str(&format!(" ops_ns_total={total}"));
    out
}

/// Nanoseconds spent building the FUSE reply, per opcode (bd-xfe7z).
///
/// The third and last term of the readdirplus decomposition. With
/// `dispatch_ns` (everything), `ops_ns` (the FsOps call) and this, the
/// remainder is the handler's own bookkeeping:
///
///     dispatch_ns - ops_ns - reply_ns = per-entry handler work
///
/// It exists because the split so far only narrowed the target by half: the
/// format layer is 33.6% of readdirplus dispatch and the handler is 66.4%, and
/// "the handler" still spans reply construction, name conversion and iteration.
/// A lever aimed at the wrong one of those is the third rejected lever in a row.
static REPLY_NANOS: [std::sync::atomic::AtomicU64; 10] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 10];

/// Accumulates reply-construction time on DROP.
///
/// RAII for the same reason as [`OpsTimer`]: `reply.add` sits inside a loop with
/// a `break` on a full buffer, and a timer that accumulated after the loop would
/// miss every entry of the batch that filled it.
pub struct ReplyTimer {
    slot: usize,
    started: std::time::Instant,
}

impl ReplyTimer {
    /// Start timing reply construction, or return `None` when evidence is off.
    #[must_use]
    pub fn start(op: CrossingOp) -> Option<Self> {
        ops_timing_enabled().then(|| Self {
            slot: op.index(),
            started: std::time::Instant::now(),
        })
    }
}

impl Drop for ReplyTimer {
    fn drop(&mut self) {
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        REPLY_NANOS[self.slot].fetch_add(elapsed, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Render reply-construction nanoseconds with the shared labels and ordering.
#[must_use]
pub fn render_reply_nanos() -> String {
    let mut out = String::new();
    let mut total = 0_u64;
    for op in CrossingOp::ALL {
        if !out.is_empty() {
            out.push(' ');
        }
        let value = REPLY_NANOS[op.index()].load(std::sync::atomic::Ordering::Relaxed);
        total += value;
        out.push_str(&format!("reply_ns_{}={}", op.label(), value));
    }
    out.push_str(&format!(" reply_ns_total={total}"));
    out
}

/// Whether the three timing families are internally consistent, per opcode.
///
/// `ops_ns` and `reply_ns` both measure work that happens INSIDE a dispatch, so
/// for every opcode `ops_ns + reply_ns <= dispatch_ns` must hold. A violation
/// means one of three things, all of which invalidate the decomposition:
///
/// - a timer attributes to the wrong slot, so time from opcode A lands on B;
/// - a timer double-counts, e.g. nested starts on the same call;
/// - a timer outlives its dispatch, which RAII is supposed to prevent.
///
/// This exists because the decomposition is a SUBTRACTION I have been doing by
/// hand -- `dispatch - ops - reply` is quoted as "per-entry handler bookkeeping"
/// -- and I have already published one wrong attribution from this bead by
/// conflating scopes with nanoseconds. A subtraction whose terms are never
/// checked against each other is a number nobody has validated.
///
/// Returns the offending `(label, dispatch, ops, reply)` for the first opcode
/// that violates it, or `None` when every opcode is consistent.
#[must_use]
pub fn decomposition_violation(
    dispatch: [u64; fuser::CROSSING_SLOTS],
) -> Option<(&'static str, u64, u64, u64)> {
    for op in CrossingOp::ALL {
        let index = op.index();
        let ops = OPS_NANOS[index].load(std::sync::atomic::Ordering::Relaxed);
        let reply = REPLY_NANOS[index].load(std::sync::atomic::Ordering::Relaxed);
        if !decomposition_is_consistent(dispatch[index], ops, reply) {
            return Some((op.label(), dispatch[index], ops, reply));
        }
    }
    None
}

/// Same check against explicit values, so the invariant is testable without
/// touching the process-global counters.
#[must_use]
pub fn decomposition_is_consistent(dispatch: u64, ops: u64, reply: u64) -> bool {
    // `checked_add`, not `saturating_add`. Saturating makes an OVERFLOWING sum
    // compare equal to a maximal dispatch and report "consistent" -- the exact
    // blind spot this check exists to close. An overflow is a violation: two
    // timers that between them accumulated more than u64 nanoseconds are not
    // measuring what they claim.
    ops.checked_add(reply).is_some_and(|sum| sum <= dispatch)
}

/// Live counts and dispatch times, rendered for the metrics line.
#[must_use]
pub fn render_live_timed() -> String {
    format!(
        "{} {}",
        render_fuser_counts(fuser::crossing_counts()),
        render_fuser_nanos(fuser::crossing_nanos())
    ) + " "
        + &render_ops_nanos()
        + " "
        + &render_reply_nanos()
}

/// Live counts from the daemon, rendered for the metrics line.
#[must_use]
pub fn render_live() -> String {
    render_fuser_counts(fuser::crossing_counts())
}

#[cfg(test)]
mod tests {

    /// The invariant the decomposition rests on: ops and reply both happen
    /// inside a dispatch, so their sum cannot exceed it.
    #[test]
    fn ops_plus_reply_may_not_exceed_dispatch_bd_xfe7z() {
        assert!(super::decomposition_is_consistent(100, 30, 40));
        assert!(super::decomposition_is_consistent(100, 60, 40), "equality is allowed");
        assert!(
            !super::decomposition_is_consistent(100, 61, 40),
            "a sum over dispatch means a timer is mis-slotted, double-counting, or \
             outliving its dispatch -- all of which invalidate the subtraction"
        );
        // Zero dispatch with nonzero parts is the shape a wrong-slot bug makes:
        // time landing on an opcode that never dispatched.
        assert!(!super::decomposition_is_consistent(0, 1, 0));
        assert!(super::decomposition_is_consistent(0, 0, 0));
    }

    /// Saturating arithmetic: two near-u64::MAX terms must report a violation
    /// rather than wrapping into a value that looks consistent.
    #[test]
    fn the_consistency_check_does_not_wrap_bd_xfe7z() {
        assert!(!super::decomposition_is_consistent(u64::MAX, u64::MAX, 1));
        assert!(!super::decomposition_is_consistent(10, u64::MAX, u64::MAX));
    }

    /// All four families -- counts, dispatch, ops and reply -- must share labels
    /// and ordering, because the decomposition is a SUBTRACTION across them:
    /// dispatch_ns - ops_ns - reply_ns is the handler's own work, and a reader
    /// doing that arithmetic must not have to map names between families.
    #[test]
    fn reply_nanos_share_the_label_vocabulary_bd_xfe7z() {
        let line = super::render_reply_nanos();
        for op in CrossingOp::ALL {
            assert!(
                line.contains(&format!("reply_ns_{}=", op.label())),
                "{line}"
            );
        }
        assert!(line.contains("reply_ns_total="), "{line}");
    }

    /// Inert without the evidence flag, like the ops timer: this one sits inside
    /// the per-entry loop, so an unconditional Instant::now() pair would be paid
    /// 20000 times per readdir pass on a default mount.
    #[test]
    fn the_reply_timer_is_inert_without_the_evidence_flag_bd_xfe7z() {
        assert_eq!(
            super::ReplyTimer::start(CrossingOp::Readdirplus).is_some(),
            super::ops_timing_enabled(),
            "the reply timer must be active exactly when mount evidence is on"
        );
    }

    /// Ops-layer nanoseconds must render with the same labels and ordering as
    /// the counts and the dispatch times, so `dispatch_ns_X - ops_ns_X` is a
    /// subtraction a reader can do without a mapping step.
    #[test]
    fn ops_nanos_render_with_the_same_labels_bd_xfe7z() {
        let line = super::render_ops_nanos();
        for op in CrossingOp::ALL {
            assert!(line.contains(&format!("ops_ns_{}=", op.label())), "{line}");
        }
        assert!(line.contains("ops_ns_total="), "{line}");
    }

    /// The timer must be inert when evidence is off, because it sits on the path
    /// whose cost is under investigation. `start` returning None is what makes a
    /// default mount pay nothing.
    #[test]
    fn the_ops_timer_is_inert_without_the_evidence_flag_bd_xfe7z() {
        // Whatever the ambient flag is, `start` must agree with it rather than
        // timing unconditionally.
        let enabled = super::ops_timing_enabled();
        assert_eq!(
            super::OpsTimer::start(CrossingOp::Getattr).is_some(),
            enabled,
            "the timer must be active exactly when mount evidence is on"
        );
    }

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
            assert!(
                line.contains(&format!("dispatch_ns_{}=", op.label())),
                "{line}"
            );
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
            assert!(
                line.contains(&format!("crossings_{}=", op.label())),
                "{line}"
            );
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
