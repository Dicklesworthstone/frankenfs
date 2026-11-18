//! Formal decision contract for self-healing repair policy.
//!
//! Defines the states the system can be in, actions available in each
//! state, a loss function for state/action pairs, and a policy engine
//! that selects the optimal action given current state and risk.

use serde::{Deserialize, Serialize};

// ── States ──────────────────────────────────────────────────────────────────

/// Observable system states for repair policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RepairState {
    /// No corruption detected, all checksums pass.
    Clean,
    /// Less than 1% of blocks corrupted; local repair symbols should suffice.
    MinorCorruption,
    /// 1–5% of blocks corrupted; repair may be insufficient.
    SevereCorruption,
    /// I/O errors prevent reading some blocks (hardware degradation).
    IoStall,
}

impl RepairState {
    /// Classify a corruption observation into a state.
    #[must_use]
    pub fn classify(corrupted_blocks: u64, total_blocks: u64, io_errors: bool) -> Self {
        if io_errors {
            return Self::IoStall;
        }
        if total_blocks == 0 || corrupted_blocks == 0 {
            return Self::Clean;
        }
        let ratio = corrupted_blocks as f64 / total_blocks as f64;
        if ratio < 0.01 {
            Self::MinorCorruption
        } else {
            Self::SevereCorruption
        }
    }
}

// ── Actions ─────────────────────────────────────────────────────────────────

/// Available repair actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RepairAction {
    /// Repair using local RaptorQ symbols (low cost, bounded capability).
    RepairLocal,
    /// Full block group re-encode (higher cost, resets redundancy).
    RepairGlobal,
    /// Schedule repair for next scrub cycle (risk of further degradation).
    DeferRepair,
    /// Switch to read-only mode (preserve data, lose writability).
    DegradeReadonly,
    /// Trigger backup to external storage (highest cost, highest safety).
    EmergencyBackup,
}

impl RepairAction {
    /// All available actions.
    pub const ALL: [Self; 5] = [
        Self::RepairLocal,
        Self::RepairGlobal,
        Self::DeferRepair,
        Self::DegradeReadonly,
        Self::EmergencyBackup,
    ];
}

// ── Loss function ───────────────────────────────────────────────────────────

/// Compute the loss (cost) for taking `action` in `state`.
///
/// Lower values are better. The units are abstract "cost units" that
/// weigh data-loss risk against operational overhead.
#[must_use]
#[allow(clippy::enum_glob_use, clippy::match_same_arms)]
pub fn loss(state: RepairState, action: RepairAction) -> f64 {
    use RepairAction::*;
    use RepairState::*;

    // Loss matrix: each cell is an intentional design choice.
    // Coincidental value equality across rows is expected.
    match (state, action) {
        // Clean state: repairs are unnecessary overhead.
        (Clean, RepairLocal) => 5.0,
        (Clean, RepairGlobal) => 20.0,
        (Clean, DeferRepair) => 0.0,      // correct: do nothing
        (Clean, DegradeReadonly) => 50.0, // massive over-reaction
        (Clean, EmergencyBackup) => 100.0,

        // Minor corruption: local repair is the expected case.
        (MinorCorruption, RepairLocal) => 2.0,   // best action
        (MinorCorruption, RepairGlobal) => 10.0, // overkill
        (MinorCorruption, DeferRepair) => 15.0,  // risky delay
        (MinorCorruption, DegradeReadonly) => 40.0, // over-reaction
        (MinorCorruption, EmergencyBackup) => 80.0,

        // Severe corruption: need stronger intervention.
        (SevereCorruption, RepairLocal) => 30.0, // may not suffice
        (SevereCorruption, RepairGlobal) => 8.0, // best action
        (SevereCorruption, DeferRepair) => 60.0, // high data-loss risk
        (SevereCorruption, DegradeReadonly) => 20.0, // safe but costly
        (SevereCorruption, EmergencyBackup) => 25.0,

        // I/O stall: repairs are unreliable, safety first.
        (IoStall, RepairLocal) => 50.0,     // repair may fail
        (IoStall, RepairGlobal) => 50.0,    // repair may fail
        (IoStall, DeferRepair) => 70.0,     // hardware degrading
        (IoStall, DegradeReadonly) => 10.0, // best action
        (IoStall, EmergencyBackup) => 15.0, // also reasonable
    }
}

// ── Safety envelope ─────────────────────────────────────────────────────────

/// Hard safety threshold for corruption posterior.
/// If posterior exceeds this, force immediate repair.
pub const SAFETY_POSTERIOR_THRESHOLD: f64 = 0.05;

/// Check whether the safety envelope forces an override action.
///
/// Returns `Some(action)` if the safety envelope requires an immediate
/// override, `None` if the normal policy engine can decide.
#[must_use]
pub fn safety_override(
    corruption_posterior: f64,
    repair_symbols_sufficient: bool,
) -> Option<RepairAction> {
    if corruption_posterior > SAFETY_POSTERIOR_THRESHOLD {
        if repair_symbols_sufficient {
            Some(RepairAction::RepairLocal)
        } else {
            // Insufficient symbols: go read-only to preserve data.
            Some(RepairAction::DegradeReadonly)
        }
    } else {
        None
    }
}

// ── Policy engine ───────────────────────────────────────────────────────────

/// Decision output from the repair policy engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairDecision {
    /// The state that was observed.
    pub state: RepairState,
    /// The action selected.
    pub action: RepairAction,
    /// The loss of the selected action.
    pub loss: f64,
    /// Whether the safety envelope forced this decision.
    pub safety_override: bool,
    /// Corruption posterior at decision time.
    pub corruption_posterior: f64,
}

/// Select the optimal action for the given state.
///
/// Checks the safety envelope first. If no override is needed, picks
/// the action with the lowest loss.
#[must_use]
pub fn select_action(
    state: RepairState,
    corruption_posterior: f64,
    repair_symbols_sufficient: bool,
) -> RepairDecision {
    // Safety envelope check.
    if let Some(forced) = safety_override(corruption_posterior, repair_symbols_sufficient) {
        return RepairDecision {
            state,
            action: forced,
            loss: loss(state, forced),
            safety_override: true,
            corruption_posterior,
        };
    }

    // Normal policy: minimize loss.
    let mut best_action = RepairAction::DeferRepair;
    let mut best_loss = f64::MAX;

    for action in RepairAction::ALL {
        let l = loss(state, action);
        if l < best_loss {
            best_loss = l;
            best_action = action;
        }
    }

    RepairDecision {
        state,
        action: best_action,
        loss: best_loss,
        safety_override: false,
        corruption_posterior,
    }
}

// ── Two-Stage Calibrated Automatic-Repair Authorization Gate (`bd-tqrnc`) ───

/// Non-negotiable ownership, generation, digest, provenance, and pre-writeback
/// invariants that MUST all hold before any quantitative expected-loss comparison
/// is permitted to authorize automatic repair writeback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandatoryRepairPreconditions {
    /// Exclusive ownership locks are held on every required storage member and archive.
    pub exclusive_ownership: bool,
    /// Complete storage-set identity, member roles, topology, and slice bounds match.
    pub storage_set_identity_match: bool,
    /// Native durable generation/commit token is current and no write epoch is pending.
    pub native_generation_fresh: bool,
    /// Every peer source digest in the group matches the admitted clean generation.
    pub group_peer_digests_unchanged: bool,
    /// Surviving repair symbols and every reconstructed block digest verified cleanly.
    pub symbol_and_decoded_digests_valid: bool,
    /// Trusted-root provenance passed (either keyed MAC verified or unkeyed allowed by policy).
    pub trusted_root_authenticated: bool,
    /// Target block bytes on media have not changed since pre-decode observation.
    pub target_prewrite_unchanged: bool,
}

impl MandatoryRepairPreconditions {
    /// Construct a precondition vector where all mandatory checks passed.
    #[must_use]
    pub const fn all_passed() -> Self {
        Self {
            exclusive_ownership: true,
            storage_set_identity_match: true,
            native_generation_fresh: true,
            group_peer_digests_unchanged: true,
            symbol_and_decoded_digests_valid: true,
            trusted_root_authenticated: true,
            target_prewrite_unchanged: true,
        }
    }

    /// Return the first failed mandatory precondition in deterministic order.
    #[must_use]
    pub const fn first_failure(&self) -> Option<HardCheckFailure> {
        if !self.exclusive_ownership {
            return Some(HardCheckFailure::MissingExclusiveOwnership);
        }
        if !self.storage_set_identity_match {
            return Some(HardCheckFailure::StorageSetIdentityMismatch);
        }
        if !self.native_generation_fresh {
            return Some(HardCheckFailure::StaleOrDirtyNativeGeneration);
        }
        if !self.group_peer_digests_unchanged {
            return Some(HardCheckFailure::GroupPeerDigestsChanged);
        }
        if !self.symbol_and_decoded_digests_valid {
            return Some(HardCheckFailure::InvalidSymbolOrDecodedDigest);
        }
        if !self.trusted_root_authenticated {
            return Some(HardCheckFailure::UnauthenticatedProvenance);
        }
        if !self.target_prewrite_unchanged {
            return Some(HardCheckFailure::TargetChangedBeforeWriteback);
        }
        None
    }
}

/// Specific hard invariant failure blocking automatic repair before loss evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardCheckFailure {
    MissingExclusiveOwnership,
    StorageSetIdentityMismatch,
    StaleOrDirtyNativeGeneration,
    GroupPeerDigestsChanged,
    InvalidSymbolOrDecodedDigest,
    UnauthenticatedProvenance,
    TargetChangedBeforeWriteback,
}

/// Explicit loss-matrix and correctness calibration for automatic repair writeback.
///
/// Loss comparison:
///   `E[L(repair)] = (1 - q_correct) * l_wrong + c_repair` vs `l_refusal`.
///
/// A numeric score NEVER overrides [`MandatoryRepairPreconditions`]; missing or
/// malformed calibration selects refusal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairLossCalibration {
    /// Cost `C_repair >= 0` of executing a verified repair writeback + sync.
    pub c_repair: f64,
    /// Loss `L_wrong > 0` of publishing wrong or stale bytes over a valid image.
    pub l_wrong: f64,
    /// Loss `L_refusal >= 0` of refusing automatic writeback and surfacing an error.
    pub l_refusal: f64,
    /// Calibrated probability `q in [0, 1]` that a verified reconstruction is exact.
    pub q_correct: f64,
    /// Explicit non-empty provenance string binding where `(q, C_repair, L_wrong, L_refusal)` came from.
    pub provenance: String,
}

impl RepairLossCalibration {
    /// Default operator-authorized calibration used ONLY when the operator explicitly
    /// supplies `--exclusive-image --allow-repair` and all 256-bit BLAKE3 generation,
    /// table, symbol, and block-digest checks pass.
    #[must_use]
    pub fn default_operator_exclusive() -> Self {
        Self {
            c_repair: 1.0,
            l_wrong: 1_000_000.0,
            l_refusal: 100.0,
            q_correct: 0.999_999,
            provenance: "operator_exclusive_allow_repair:blake3_256_verified_v1".to_owned(),
        }
    }

    /// Validate finiteness, domain bounds, and non-empty provenance.
    pub fn validate(&self) -> Result<(), String> {
        if !self.c_repair.is_finite() || self.c_repair < 0.0 {
            return Err("c_repair must be finite and >= 0".to_owned());
        }
        if !self.l_wrong.is_finite() || self.l_wrong <= 0.0 {
            return Err("l_wrong must be finite and > 0".to_owned());
        }
        if !self.l_refusal.is_finite() || self.l_refusal < 0.0 {
            return Err("l_refusal must be finite and >= 0".to_owned());
        }
        if !self.q_correct.is_finite() || !(0.0..=1.0).contains(&self.q_correct) {
            return Err("q_correct must be finite and in 0.0..=1.0".to_owned());
        }
        if self.provenance.trim().is_empty() {
            return Err("calibration provenance must be non-empty".to_owned());
        }
        Ok(())
    }

    /// Compute `(1 - q_correct) * l_wrong + c_repair`.
    #[must_use]
    pub fn expected_repair_loss(&self) -> f64 {
        (1.0 - self.q_correct).mul_add(self.l_wrong, self.c_repair)
    }
}

/// Structured refusal reason when [`evaluate_automatic_repair_gate`] denies writeback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
pub enum RepairRefusalReason {
    HardInvariantFailed(HardCheckFailure),
    MissingCalibration,
    InvalidCalibration(String),
    ExpectedLossNotLowerThanRefusal,
}

/// Verdict of the two-stage automatic-repair authorization gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum AutomaticRepairVerdict {
    Authorize {
        expected_repair_loss: f64,
        refusal_loss: f64,
        calibration: RepairLossCalibration,
    },
    Refuse {
        reason: RepairRefusalReason,
        expected_repair_loss: Option<f64>,
        refusal_loss: Option<f64>,
        calibration_provenance: Option<String>,
    },
}

impl AutomaticRepairVerdict {
    /// Returns `true` iff automatic repair writeback is authorized.
    #[must_use]
    pub const fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorize { .. })
    }
}

/// Evaluate the two-stage automatic-repair authorization gate:
/// 1. Every mandatory ownership/identity/freshness/digest/provenance precondition
///    MUST hold first; any failure refuses immediately without consulting `calibration`.
/// 2. Missing or malformed calibration refuses immediately.
/// 3. Authorize iff `(1 - q) * L_wrong + C_repair < L_refusal` with finite arithmetic.
#[must_use]
pub fn evaluate_automatic_repair_gate(
    preconditions: &MandatoryRepairPreconditions,
    calibration: Option<&RepairLossCalibration>,
) -> AutomaticRepairVerdict {
    if let Some(failure) = preconditions.first_failure() {
        return AutomaticRepairVerdict::Refuse {
            reason: RepairRefusalReason::HardInvariantFailed(failure),
            expected_repair_loss: None,
            refusal_loss: None,
            calibration_provenance: calibration.map(|c| c.provenance.clone()),
        };
    }
    let Some(cal) = calibration else {
        return AutomaticRepairVerdict::Refuse {
            reason: RepairRefusalReason::MissingCalibration,
            expected_repair_loss: None,
            refusal_loss: None,
            calibration_provenance: None,
        };
    };
    if let Err(detail) = cal.validate() {
        return AutomaticRepairVerdict::Refuse {
            reason: RepairRefusalReason::InvalidCalibration(detail),
            expected_repair_loss: None,
            refusal_loss: None,
            calibration_provenance: Some(cal.provenance.clone()),
        };
    }
    let expected = cal.expected_repair_loss();
    if expected.is_finite() && expected < cal.l_refusal {
        AutomaticRepairVerdict::Authorize {
            expected_repair_loss: expected,
            refusal_loss: cal.l_refusal,
            calibration: cal.clone(),
        }
    } else {
        AutomaticRepairVerdict::Refuse {
            reason: RepairRefusalReason::ExpectedLossNotLowerThanRefusal,
            expected_repair_loss: Some(expected),
            refusal_loss: Some(cal.l_refusal),
            calibration_provenance: Some(cal.provenance.clone()),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn state_classify_clean_when_no_corruption() {
        assert_eq!(RepairState::classify(0, 10_000, false), RepairState::Clean);
        assert_eq!(RepairState::classify(0, 0, false), RepairState::Clean);
    }

    #[test]
    fn state_classify_minor_under_1pct() {
        // 50 out of 10_000 = 0.5% → MinorCorruption
        assert_eq!(
            RepairState::classify(50, 10_000, false),
            RepairState::MinorCorruption
        );
    }

    #[test]
    fn state_classify_severe_above_1pct() {
        // 200 out of 10_000 = 2% → SevereCorruption
        assert_eq!(
            RepairState::classify(200, 10_000, false),
            RepairState::SevereCorruption
        );
    }

    #[test]
    fn state_classify_io_stall_overrides_corruption() {
        // Even with zero corrupted blocks, I/O errors → IoStall.
        assert_eq!(RepairState::classify(0, 10_000, true), RepairState::IoStall);
        assert_eq!(
            RepairState::classify(500, 10_000, true),
            RepairState::IoStall
        );
    }

    #[test]
    fn policy_clean_selects_defer() {
        let decision = select_action(RepairState::Clean, 0.001, true);
        assert_eq!(decision.action, RepairAction::DeferRepair);
        assert!(!decision.safety_override);
        assert!(decision.loss < 1.0); // DeferRepair in Clean has loss 0.0
    }

    #[test]
    fn policy_minor_corruption_selects_repair_local() {
        let decision = select_action(RepairState::MinorCorruption, 0.005, true);
        assert_eq!(decision.action, RepairAction::RepairLocal);
        assert!(!decision.safety_override);
    }

    #[test]
    fn policy_severe_corruption_selects_repair_global() {
        let decision = select_action(RepairState::SevereCorruption, 0.03, true);
        assert_eq!(decision.action, RepairAction::RepairGlobal);
        assert!(!decision.safety_override);
    }

    #[test]
    fn policy_io_stall_selects_degrade_readonly() {
        let decision = select_action(RepairState::IoStall, 0.01, true);
        assert_eq!(decision.action, RepairAction::DegradeReadonly);
        assert!(!decision.safety_override);
    }

    #[test]
    fn safety_override_forces_repair_when_posterior_exceeds_threshold() {
        // Corruption posterior > 0.05 with sufficient symbols → force RepairLocal.
        let decision = select_action(RepairState::Clean, 0.08, true);
        assert_eq!(decision.action, RepairAction::RepairLocal);
        assert!(decision.safety_override);
    }

    #[test]
    fn safety_override_degrades_readonly_when_symbols_insufficient() {
        // Corruption posterior > 0.05 without sufficient symbols → DegradeReadonly.
        let decision = select_action(RepairState::MinorCorruption, 0.10, false);
        assert_eq!(decision.action, RepairAction::DegradeReadonly);
        assert!(decision.safety_override);
    }

    #[test]
    fn loss_monotonicity_deferred_repair_risk_increases_with_severity() {
        // DeferRepair loss should increase as state gets worse.
        let clean = loss(RepairState::Clean, RepairAction::DeferRepair);
        let minor = loss(RepairState::MinorCorruption, RepairAction::DeferRepair);
        let severe = loss(RepairState::SevereCorruption, RepairAction::DeferRepair);
        let stall = loss(RepairState::IoStall, RepairAction::DeferRepair);

        assert!(clean < minor, "clean < minor defer loss");
        assert!(minor < severe, "minor < severe defer loss");
        assert!(severe < stall, "severe < stall defer loss");
    }

    #[test]
    fn decision_json_round_trip() {
        let decision = select_action(RepairState::SevereCorruption, 0.03, true);
        let json = serde_json::to_string(&decision).expect("serialize");
        let parsed: RepairDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.state, decision.state);
        assert_eq!(parsed.action, decision.action);
        assert!((parsed.loss - decision.loss).abs() < f64::EPSILON);
        assert_eq!(parsed.safety_override, decision.safety_override);
    }

    #[test]
    fn every_state_has_a_well_defined_optimal_action() {
        // For every possible state, the policy engine should return a valid decision.
        let states = [
            RepairState::Clean,
            RepairState::MinorCorruption,
            RepairState::SevereCorruption,
            RepairState::IoStall,
        ];
        for state in states {
            let decision = select_action(state, 0.01, true);
            assert!(decision.loss.is_finite(), "finite loss for {state:?}");
            assert!(!decision.safety_override);
        }
    }

    #[test]
    fn safety_threshold_boundary() {
        // At exactly the threshold, no override (>= vs >).
        let at_threshold = select_action(RepairState::Clean, SAFETY_POSTERIOR_THRESHOLD, true);
        assert!(!at_threshold.safety_override);

        // Just above threshold, override kicks in.
        let above = select_action(RepairState::Clean, SAFETY_POSTERIOR_THRESHOLD + 0.001, true);
        assert!(above.safety_override);
    }

    fn arb_state() -> impl Strategy<Value = RepairState> {
        prop_oneof![
            Just(RepairState::Clean),
            Just(RepairState::MinorCorruption),
            Just(RepairState::SevereCorruption),
            Just(RepairState::IoStall),
        ]
    }

    fn severity_rank(state: RepairState) -> u8 {
        match state {
            RepairState::Clean => 0,
            RepairState::MinorCorruption => 1,
            RepairState::SevereCorruption => 2,
            RepairState::IoStall => 3,
        }
    }

    proptest! {
        /// `classify()` always returns IoStall when io_errors is true.
        #[test]
        fn proptest_classify_io_errors_always_stall(
            corrupted in 0_u64..1_000_000,
            total in 0_u64..1_000_000,
        ) {
            prop_assert_eq!(
                RepairState::classify(corrupted, total, true),
                RepairState::IoStall
            );
        }

        /// `classify()` returns Clean when corrupted_blocks == 0 and no io_errors.
        #[test]
        fn proptest_classify_zero_corruption_is_clean(total in 0_u64..1_000_000) {
            prop_assert_eq!(
                RepairState::classify(0, total, false),
                RepairState::Clean
            );
        }

        /// `loss()` is always non-negative and finite for all state/action pairs.
        #[test]
        fn proptest_loss_nonneg_finite(state in arb_state()) {
            for action in RepairAction::ALL {
                let l = loss(state, action);
                prop_assert!(l >= 0.0, "loss({:?}, {:?}) = {} < 0", state, action, l);
                prop_assert!(l.is_finite(), "loss({:?}, {:?}) is not finite", state, action);
            }
        }

        /// `select_action()` always returns finite loss and a valid action.
        #[test]
        fn proptest_select_action_valid(
            state in arb_state(),
            posterior in 0.0_f64..1.0,
            sufficient in any::<bool>(),
        ) {
            let decision = select_action(state, posterior, sufficient);
            prop_assert!(decision.loss.is_finite(), "decision loss not finite");
            prop_assert!(decision.loss >= 0.0, "decision loss < 0");
            prop_assert_eq!(decision.state, state);
        }

        /// Safety override fires iff posterior > SAFETY_POSTERIOR_THRESHOLD.
        #[test]
        fn proptest_safety_override_threshold(
            posterior in 0.0_f64..1.0,
            sufficient in any::<bool>(),
        ) {
            let result = safety_override(posterior, sufficient);
            if posterior > SAFETY_POSTERIOR_THRESHOLD {
                prop_assert!(result.is_some(), "should override at posterior={}", posterior);
            } else {
                prop_assert!(result.is_none(), "should not override at posterior={}", posterior);
            }
        }

        /// DeferRepair loss monotonically increases with severity.
        #[test]
        fn proptest_defer_loss_monotonic_with_severity(
            corrupted in 0_u64..100_000,
            total in 1_u64..100_000,
        ) {
            let corrupted = corrupted.min(total);
            let state = RepairState::classify(corrupted, total, false);
            let defer_loss = loss(state, RepairAction::DeferRepair);

            // Clean should have the lowest DeferRepair loss
            let clean_loss = loss(RepairState::Clean, RepairAction::DeferRepair);
            prop_assert!(defer_loss >= clean_loss - f64::EPSILON);
        }

        /// MR: with I/O errors fixed false and total blocks fixed, increasing
        /// observed corruption must not lower the classified repair severity.
        #[test]
        fn proptest_classify_corruption_severity_monotonic(
            low in 0_u64..100_000,
            delta in 0_u64..100_000,
            total in 1_u64..100_000,
        ) {
            let low = low.min(total);
            let high = low.saturating_add(delta).min(total);
            let low_state = RepairState::classify(low, total, false);
            let high_state = RepairState::classify(high, total, false);

            prop_assert!(
                severity_rank(high_state) >= severity_rank(low_state),
                "classification severity decreased: {low}/{total} -> {low_state:?}, \
                 {high}/{total} -> {high_state:?}"
            );
        }

        /// Safety override is a hard envelope: when it fires, the selected
        /// action and reported loss must match the forced action exactly.
        #[test]
        fn proptest_safety_override_selects_forced_action_and_loss(
            state in arb_state(),
            posterior in (SAFETY_POSTERIOR_THRESHOLD + f64::EPSILON)..1.0_f64,
            sufficient in any::<bool>(),
        ) {
            let expected_action = if sufficient {
                RepairAction::RepairLocal
            } else {
                RepairAction::DegradeReadonly
            };
            let decision = select_action(state, posterior, sufficient);

            prop_assert!(decision.safety_override);
            prop_assert_eq!(decision.action, expected_action);
            prop_assert!((decision.loss - loss(state, expected_action)).abs() <= f64::EPSILON);
            prop_assert!((decision.corruption_posterior - posterior).abs() <= f64::EPSILON);
        }

        /// No calibration score — even `q = 1.0` and `L_refusal = 1e12` — can
        /// grant automatic repair writeback when any mandatory check is false.
        #[test]
        fn proptest_hard_preconditions_strictly_dominate_calibration(
            fail_idx in 0_usize..7,
            q in 0.0_f64..=1.0,
            l_refusal in 1.0_f64..1.0e12,
        ) {
            let mut pre = MandatoryRepairPreconditions::all_passed();
            match fail_idx {
                0 => pre.exclusive_ownership = false,
                1 => pre.storage_set_identity_match = false,
                2 => pre.native_generation_fresh = false,
                3 => pre.group_peer_digests_unchanged = false,
                4 => pre.symbol_and_decoded_digests_valid = false,
                5 => pre.trusted_root_authenticated = false,
                _ => pre.target_prewrite_unchanged = false,
            }
            let cal = RepairLossCalibration {
                c_repair: 0.0,
                l_wrong: 1.0,
                l_refusal,
                q_correct: q,
                provenance: "prop-test".to_owned(),
            };
            let verdict = evaluate_automatic_repair_gate(&pre, Some(&cal));
            prop_assert!(!verdict.is_authorized());
            if let AutomaticRepairVerdict::Refuse {
                reason: RepairRefusalReason::HardInvariantFailed(_),
                expected_repair_loss,
                ..
            } = verdict
            {
                prop_assert!(expected_repair_loss.is_none());
            } else {
                prop_assert!(false, "expected HardInvariantFailed, got {verdict:?}");
            }
        }
    }

    #[test]
    fn calibrated_gate_refuses_missing_invalid_or_unfavorable_loss_and_authorizes_favorable() {
        let pre = MandatoryRepairPreconditions::all_passed();
        // Missing calibration -> Refuse
        assert_eq!(
            evaluate_automatic_repair_gate(&pre, None),
            AutomaticRepairVerdict::Refuse {
                reason: RepairRefusalReason::MissingCalibration,
                expected_repair_loss: None,
                refusal_loss: None,
                calibration_provenance: None,
            }
        );
        // Empty provenance -> Refuse
        let bad_prov = RepairLossCalibration {
            provenance: "   ".to_owned(),
            ..RepairLossCalibration::default_operator_exclusive()
        };
        assert!(matches!(
            evaluate_automatic_repair_gate(&pre, Some(&bad_prov)),
            AutomaticRepairVerdict::Refuse {
                reason: RepairRefusalReason::InvalidCalibration(_),
                ..
            }
        ));
        // Unfavorable expected loss: (1 - 0.90) * 1000 + 5 = 105 >= 50 -> Refuse
        let unfavorable = RepairLossCalibration {
            c_repair: 5.0,
            l_wrong: 1_000.0,
            l_refusal: 50.0,
            q_correct: 0.90,
            provenance: "test-unfavorable-v1".to_owned(),
        };
        assert!(matches!(
            evaluate_automatic_repair_gate(&pre, Some(&unfavorable)),
            AutomaticRepairVerdict::Refuse {
                reason: RepairRefusalReason::ExpectedLossNotLowerThanRefusal,
                ..
            }
        ));
        // Default operator-exclusive calibration -> Authorize
        let def = RepairLossCalibration::default_operator_exclusive();
        let verdict = evaluate_automatic_repair_gate(&pre, Some(&def));
        assert!(verdict.is_authorized());
    }
}
