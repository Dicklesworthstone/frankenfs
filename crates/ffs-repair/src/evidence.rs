//! Append-only JSONL evidence ledger for repair and scrub actions.
//!
//! Every repair action, corruption detection, policy decision, and scrub cycle
//! produces a durable, auditable [`EvidenceRecord`]. Records are persisted as
//! one-JSON-object-per-line (JSONL) for streaming reads and crash safety.
//!
//! # Format
//!
//! Each line is a self-contained [`EvidenceRecord`] serialized as JSON.
//! The [`EvidenceLedger`] writer flushes after every record to minimize
//! data loss on crash.
//!
//! # Usage
//!
//! ```ignore
//! let mut ledger = EvidenceLedger::new(file);
//! let detail = CorruptionDetail { blocks_affected: 3, .. };
//! ledger.append(&EvidenceRecord::corruption_detected(0, detail))?;
//! ```

use serde::{Deserialize, Serialize};
use std::io::{self, Write};

use crate::recovery::{RecoveryDecoderStats, RecoveryEvidence, RecoveryOutcome};
use crate::scrub::ScrubReport;

// ── Timestamp ───────────────────────────────────────────────────────────────

/// Current wall-clock time as nanoseconds since the Unix epoch.
///
/// Returns 0 if the system clock is unavailable or before the epoch.
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

// ── Event type ──────────────────────────────────────────────────────────────

/// Category of evidence event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceEventType {
    /// Corruption was detected during a scrub or read.
    CorruptionDetected,
    /// A repair attempt was initiated.
    RepairAttempted,
    /// A repair attempt completed successfully.
    RepairSucceeded,
    /// A repair attempt failed.
    RepairFailed,
    /// A full scrub cycle completed.
    ScrubCycleComplete,
    /// The Bayesian autopilot made an overhead adjustment decision.
    PolicyDecision,
    /// Repair symbols were regenerated for a block group.
    SymbolRefresh,
    /// WAL recovery completed (replay after crash or restart).
    WalRecovery,
}

// ── Detail structs ──────────────────────────────────────────────────────────

/// Detail payload for corruption detection events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorruptionDetail {
    /// Number of blocks affected by this corruption event.
    pub blocks_affected: u32,
    /// Category of corruption (e.g., "checksum_mismatch", "bad_magic").
    pub corruption_kind: String,
    /// Severity level (e.g., "error", "critical").
    pub severity: String,
    /// Human-readable description of the corruption.
    pub detail: String,
}

/// Detail payload for repair attempt/success/failure events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairDetail {
    /// Repair symbol generation used.
    pub generation: u64,
    /// Number of corrupt blocks targeted for recovery.
    pub corrupt_count: usize,
    /// Number of repair symbols consumed during decode.
    pub symbols_used: usize,
    /// Total repair symbols available for the group.
    pub symbols_available: usize,
    /// RaptorQ decoder statistics.
    pub decoder_stats: RecoveryDecoderStats,
    /// Whether post-repair block verification passed.
    pub verify_pass: bool,
    /// Human-readable reason for partial/failed outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Detail payload for scrub cycle completion events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubCycleDetail {
    /// Total blocks scanned during the cycle.
    pub blocks_scanned: u64,
    /// Number of blocks with at least one corruption finding.
    pub blocks_corrupt: u64,
    /// Number of blocks that returned I/O errors.
    pub blocks_io_error: u64,
    /// Total number of individual findings.
    pub findings_count: usize,
}

/// Detail payload for Bayesian autopilot policy decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecisionDetail {
    /// Posterior probability of corruption.
    pub corruption_posterior: f64,
    /// Beta posterior alpha parameter.
    #[serde(default)]
    pub posterior_alpha: f64,
    /// Beta posterior beta parameter.
    #[serde(default)]
    pub posterior_beta: f64,
    /// Current or proposed overhead ratio.
    pub overhead_ratio: f64,
    /// Risk bound threshold.
    pub risk_bound: f64,
    /// Expected loss at `overhead_ratio`.
    #[serde(default)]
    pub expected_loss: f64,
    /// Number of repair symbols selected for next refresh.
    #[serde(default)]
    pub symbols_selected: u32,
    /// Whether metadata-specific multiplier was applied.
    #[serde(default)]
    pub metadata_group: bool,
    /// Human-readable description of the policy decision.
    pub decision: String,
}

/// Detail payload for symbol refresh (re-encoding) events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRefreshDetail {
    /// Previous repair symbol generation.
    pub previous_generation: u64,
    /// New repair symbol generation after refresh.
    pub new_generation: u64,
    /// Number of repair symbols generated.
    pub symbols_generated: u32,
}

/// Detail payload for WAL recovery events.
///
/// Emitted when a persistent MVCC store replays its WAL on startup.
/// Captures enough detail to audit crash recovery behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalRecoveryDetail {
    /// Number of commit records successfully replayed.
    pub commits_replayed: u64,
    /// Number of individual block versions restored.
    pub versions_replayed: u64,
    /// Number of WAL records discarded (corrupt CRC or truncated tail).
    pub records_discarded: u64,
    /// Byte offset where valid WAL data ends.
    pub wal_valid_bytes: u64,
    /// Total WAL file size in bytes.
    pub wal_total_bytes: u64,
    /// Whether a checkpoint was loaded before WAL replay.
    pub used_checkpoint: bool,
    /// Highest commit sequence restored from checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_commit_seq: Option<u64>,
}

// ── Evidence record ─────────────────────────────────────────────────────────

/// A single evidence record in the JSONL ledger.
///
/// Each record is self-contained: it includes a timestamp, event type,
/// block group, and event-specific detail. Only the detail field matching
/// `event_type` is populated; the rest are `None` (and omitted from JSON).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Nanoseconds since the Unix epoch when this record was created.
    pub timestamp_ns: u64,
    /// Category of event.
    pub event_type: EvidenceEventType,
    /// Block group this event pertains to.
    pub block_group: u32,
    /// Optional affected block range `(start, end_exclusive)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_range: Option<(u64, u64)>,
    /// Corruption detail (present when `event_type` is `CorruptionDetected`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corruption: Option<CorruptionDetail>,
    /// Repair detail (present when `event_type` is `Repair*`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair: Option<RepairDetail>,
    /// Scrub cycle summary (present when `event_type` is `ScrubCycleComplete`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scrub_cycle: Option<ScrubCycleDetail>,
    /// Policy decision detail (present when `event_type` is `PolicyDecision`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyDecisionDetail>,
    /// Symbol refresh detail (present when `event_type` is `SymbolRefresh`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_refresh: Option<SymbolRefreshDetail>,
    /// WAL recovery detail (present when `event_type` is `WalRecovery`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wal_recovery: Option<WalRecoveryDetail>,
}

impl EvidenceRecord {
    fn base(event_type: EvidenceEventType, block_group: u32) -> Self {
        Self {
            timestamp_ns: now_ns(),
            event_type,
            block_group,
            block_range: None,
            corruption: None,
            repair: None,
            scrub_cycle: None,
            policy: None,
            symbol_refresh: None,
            wal_recovery: None,
        }
    }

    /// Create a corruption-detected evidence record.
    #[must_use]
    pub fn corruption_detected(block_group: u32, detail: CorruptionDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::CorruptionDetected, block_group);
        r.corruption = Some(detail);
        r
    }

    /// Create a repair-attempted evidence record.
    #[must_use]
    pub fn repair_attempted(block_group: u32, detail: RepairDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::RepairAttempted, block_group);
        r.repair = Some(detail);
        r
    }

    /// Create a repair-succeeded evidence record.
    #[must_use]
    pub fn repair_succeeded(block_group: u32, detail: RepairDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::RepairSucceeded, block_group);
        r.repair = Some(detail);
        r
    }

    /// Create a repair-failed evidence record.
    #[must_use]
    pub fn repair_failed(block_group: u32, detail: RepairDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::RepairFailed, block_group);
        r.repair = Some(detail);
        r
    }

    /// Create a scrub-cycle-complete evidence record.
    #[must_use]
    pub fn scrub_cycle_complete(block_group: u32, detail: ScrubCycleDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::ScrubCycleComplete, block_group);
        r.scrub_cycle = Some(detail);
        r
    }

    /// Create a policy-decision evidence record.
    #[must_use]
    pub fn policy_decision(block_group: u32, detail: PolicyDecisionDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::PolicyDecision, block_group);
        r.policy = Some(detail);
        r
    }

    /// Create a symbol-refresh evidence record.
    #[must_use]
    pub fn symbol_refresh(block_group: u32, detail: SymbolRefreshDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::SymbolRefresh, block_group);
        r.symbol_refresh = Some(detail);
        r
    }

    /// Create a WAL-recovery evidence record.
    #[must_use]
    pub fn wal_recovery(detail: WalRecoveryDetail) -> Self {
        let mut r = Self::base(EvidenceEventType::WalRecovery, 0);
        r.wal_recovery = Some(detail);
        r
    }

    /// Set the affected block range.
    #[must_use]
    pub fn with_block_range(mut self, start: u64, end: u64) -> Self {
        self.block_range = Some((start, end));
        self
    }

    /// Override the auto-generated timestamp.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp_ns: u64) -> Self {
        self.timestamp_ns = timestamp_ns;
        self
    }

    /// Serialize this record to a single-line JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize a record from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or missing required fields.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Create an evidence record from a [`RecoveryEvidence`].
    ///
    /// Maps outcome to event type:
    /// - `Recovered` → `RepairSucceeded`
    /// - `Partial` / `Failed` → `RepairFailed`
    #[must_use]
    pub fn from_recovery(evidence: &RecoveryEvidence) -> Self {
        let event_type = match evidence.outcome {
            RecoveryOutcome::Recovered => EvidenceEventType::RepairSucceeded,
            RecoveryOutcome::Partial | RecoveryOutcome::Failed => EvidenceEventType::RepairFailed,
        };
        let detail = RepairDetail {
            generation: evidence.generation,
            corrupt_count: evidence.corrupt_count,
            symbols_used: evidence.symbols_used,
            symbols_available: evidence.symbols_available,
            decoder_stats: evidence.decoder_stats.clone(),
            verify_pass: evidence.outcome == RecoveryOutcome::Recovered,
            reason: evidence.reason.clone(),
        };
        let mut r = Self::base(event_type, evidence.group);
        r.repair = Some(detail);
        r
    }

    /// Create a scrub-cycle-complete evidence record from a [`ScrubReport`].
    #[must_use]
    pub fn from_scrub_report(block_group: u32, report: &ScrubReport) -> Self {
        Self::scrub_cycle_complete(
            block_group,
            ScrubCycleDetail {
                blocks_scanned: report.blocks_scanned,
                blocks_corrupt: report.blocks_corrupt,
                blocks_io_error: report.blocks_io_error,
                findings_count: report.findings.len(),
            },
        )
    }
}

// ── JSONL ledger ────────────────────────────────────────────────────────────

/// Append-only JSONL evidence writer.
///
/// Writes one JSON object per line. Each [`append`](Self::append) call
/// produces exactly one line and flushes the underlying writer to minimize
/// data loss on crash.
pub struct EvidenceLedger<W: Write> {
    writer: W,
}

impl<W: Write> EvidenceLedger<W> {
    /// Create a new evidence ledger writing to the given sink.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Append a record as a single JSONL line and flush.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if serialization or writing fails.
    pub fn append(&mut self, record: &EvidenceRecord) -> io::Result<()> {
        serde_json::to_writer(&mut self.writer, record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    /// Consume the ledger, returning the underlying writer.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }
}

/// Parse all evidence records from JSONL data.
///
/// Skips blank lines and lines that fail to parse (e.g., from torn writes).
/// Returns successfully parsed records in order.
#[must_use]
pub fn parse_evidence_ledger(data: &[u8]) -> Vec<EvidenceRecord> {
    let text = String::from_utf8_lossy(data);
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_corruption_detail() -> CorruptionDetail {
        CorruptionDetail {
            blocks_affected: 3,
            corruption_kind: "checksum_mismatch".to_owned(),
            severity: "error".to_owned(),
            detail: "CRC32C expected 0x1234, got 0x5678".to_owned(),
        }
    }

    fn sample_repair_detail() -> RepairDetail {
        RepairDetail {
            generation: 7,
            corrupt_count: 2,
            symbols_used: 4,
            symbols_available: 8,
            decoder_stats: RecoveryDecoderStats {
                peeled: 10,
                inactivated: 2,
                gauss_ops: 50,
                pivots_selected: 3,
            },
            verify_pass: true,
            reason: None,
        }
    }

    fn sample_scrub_cycle_detail() -> ScrubCycleDetail {
        ScrubCycleDetail {
            blocks_scanned: 32768,
            blocks_corrupt: 5,
            blocks_io_error: 1,
            findings_count: 7,
        }
    }

    fn sample_policy_detail() -> PolicyDecisionDetail {
        PolicyDecisionDetail {
            corruption_posterior: 0.023,
            posterior_alpha: 23.0,
            posterior_beta: 977.0,
            overhead_ratio: 0.05,
            risk_bound: 1e-9,
            expected_loss: 0.051,
            symbols_selected: 5,
            metadata_group: false,
            decision: "maintain current overhead ratio".to_owned(),
        }
    }

    fn sample_symbol_refresh_detail() -> SymbolRefreshDetail {
        SymbolRefreshDetail {
            previous_generation: 6,
            new_generation: 7,
            symbols_generated: 1639,
        }
    }

    #[test]
    fn corruption_detected_round_trip() {
        let record = EvidenceRecord::corruption_detected(0, sample_corruption_detail())
            .with_timestamp(1_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::CorruptionDetected);
        assert_eq!(parsed.block_group, 0);
        assert_eq!(parsed.timestamp_ns, 1_000_000);
        assert_eq!(parsed.corruption, Some(sample_corruption_detail()));
        assert!(parsed.repair.is_none());
        assert!(parsed.scrub_cycle.is_none());
        assert!(parsed.policy.is_none());
        assert!(parsed.symbol_refresh.is_none());
    }

    #[test]
    fn repair_attempted_round_trip() {
        let record =
            EvidenceRecord::repair_attempted(1, sample_repair_detail()).with_timestamp(7_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::RepairAttempted);
        assert_eq!(parsed.repair, Some(sample_repair_detail()));
    }

    #[test]
    fn repair_succeeded_round_trip() {
        let record = EvidenceRecord::repair_succeeded(5, sample_repair_detail())
            .with_timestamp(2_000_000)
            .with_block_range(100, 200);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::RepairSucceeded);
        assert_eq!(parsed.block_group, 5);
        assert_eq!(parsed.block_range, Some((100, 200)));
        assert_eq!(parsed.repair, Some(sample_repair_detail()));
    }

    #[test]
    fn repair_failed_round_trip() {
        let mut detail = sample_repair_detail();
        detail.verify_pass = false;
        detail.reason = Some("insufficient symbols".to_owned());
        let record = EvidenceRecord::repair_failed(3, detail).with_timestamp(3_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::RepairFailed);
        assert!(!parsed.repair.as_ref().expect("repair detail").verify_pass);
        assert_eq!(
            parsed
                .repair
                .as_ref()
                .expect("repair detail")
                .reason
                .as_deref(),
            Some("insufficient symbols")
        );
    }

    #[test]
    fn scrub_cycle_round_trip() {
        let record = EvidenceRecord::scrub_cycle_complete(10, sample_scrub_cycle_detail())
            .with_timestamp(4_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::ScrubCycleComplete);
        assert_eq!(parsed.scrub_cycle, Some(sample_scrub_cycle_detail()));
    }

    #[test]
    fn policy_decision_round_trip() {
        let record =
            EvidenceRecord::policy_decision(0, sample_policy_detail()).with_timestamp(5_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::PolicyDecision);
        let policy = parsed.policy.expect("policy detail present");
        assert!(
            (policy.corruption_posterior - 0.023).abs() < 1e-15,
            "corruption_posterior mismatch"
        );
        assert!(
            (policy.posterior_alpha - 23.0).abs() < 1e-15,
            "posterior_alpha mismatch"
        );
        assert!(
            (policy.posterior_beta - 977.0).abs() < 1e-15,
            "posterior_beta mismatch"
        );
        assert!(
            (policy.overhead_ratio - 0.05).abs() < 1e-15,
            "overhead_ratio mismatch"
        );
        assert!(
            (policy.risk_bound - 1e-9).abs() < 1e-20,
            "risk_bound mismatch"
        );
        assert!(
            (policy.expected_loss - 0.051).abs() < 1e-15,
            "expected_loss mismatch"
        );
        assert_eq!(policy.symbols_selected, 5);
        assert!(!policy.metadata_group);
        assert_eq!(policy.decision, "maintain current overhead ratio");
    }

    #[test]
    fn symbol_refresh_round_trip() {
        let record = EvidenceRecord::symbol_refresh(2, sample_symbol_refresh_detail())
            .with_timestamp(6_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::SymbolRefresh);
        assert_eq!(parsed.symbol_refresh, Some(sample_symbol_refresh_detail()));
    }

    #[test]
    fn from_recovery_evidence_recovered() {
        let ev = RecoveryEvidence {
            group: 4,
            generation: 3,
            corrupt_count: 2,
            symbols_available: 10,
            symbols_used: 10,
            decoder_stats: RecoveryDecoderStats {
                peeled: 5,
                inactivated: 1,
                gauss_ops: 20,
                pivots_selected: 2,
            },
            outcome: RecoveryOutcome::Recovered,
            reason: None,
        };
        let record = EvidenceRecord::from_recovery(&ev);
        assert_eq!(record.event_type, EvidenceEventType::RepairSucceeded);
        assert_eq!(record.block_group, 4);
        let repair = record.repair.expect("repair detail");
        assert!(repair.verify_pass);
        assert_eq!(repair.generation, 3);
        assert_eq!(repair.corrupt_count, 2);
    }

    #[test]
    fn from_recovery_evidence_failed() {
        let ev = RecoveryEvidence {
            group: 1,
            generation: 5,
            corrupt_count: 4,
            symbols_available: 2,
            symbols_used: 2,
            decoder_stats: RecoveryDecoderStats::default(),
            outcome: RecoveryOutcome::Failed,
            reason: Some("insufficient symbols".to_owned()),
        };
        let record = EvidenceRecord::from_recovery(&ev);
        assert_eq!(record.event_type, EvidenceEventType::RepairFailed);
        let repair = record.repair.expect("repair detail");
        assert!(!repair.verify_pass);
        assert_eq!(repair.reason.as_deref(), Some("insufficient symbols"));
    }

    #[test]
    fn from_scrub_report_conversion() {
        let report = ScrubReport {
            findings: vec![crate::scrub::ScrubFinding {
                block: ffs_types::BlockNumber(42),
                kind: crate::scrub::CorruptionKind::ChecksumMismatch,
                severity: crate::scrub::Severity::Error,
                detail: "bad crc".to_owned(),
            }],
            blocks_scanned: 1000,
            blocks_corrupt: 1,
            blocks_io_error: 0,
        };
        let record = EvidenceRecord::from_scrub_report(7, &report);
        assert_eq!(record.event_type, EvidenceEventType::ScrubCycleComplete);
        assert_eq!(record.block_group, 7);
        let cycle = record.scrub_cycle.expect("scrub cycle detail");
        assert_eq!(cycle.blocks_scanned, 1000);
        assert_eq!(cycle.blocks_corrupt, 1);
        assert_eq!(cycle.findings_count, 1);
    }

    #[test]
    fn ledger_append_and_parse() {
        let mut buf = Vec::new();
        {
            let mut ledger = EvidenceLedger::new(&mut buf);
            ledger
                .append(
                    &EvidenceRecord::corruption_detected(0, sample_corruption_detail())
                        .with_timestamp(100),
                )
                .expect("append 1");
            ledger
                .append(
                    &EvidenceRecord::repair_succeeded(0, sample_repair_detail())
                        .with_timestamp(200),
                )
                .expect("append 2");
            ledger
                .append(
                    &EvidenceRecord::scrub_cycle_complete(0, sample_scrub_cycle_detail())
                        .with_timestamp(300),
                )
                .expect("append 3");
        }

        let records = parse_evidence_ledger(&buf);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].event_type, EvidenceEventType::CorruptionDetected);
        assert_eq!(records[1].event_type, EvidenceEventType::RepairSucceeded);
        assert_eq!(records[2].event_type, EvidenceEventType::ScrubCycleComplete);
    }

    #[test]
    fn parse_skips_invalid_lines() {
        let mut data = Vec::new();
        // Valid record
        let record =
            EvidenceRecord::corruption_detected(0, sample_corruption_detail()).with_timestamp(100);
        serde_json::to_writer(&mut data, &record).expect("serialize");
        data.extend_from_slice(b"\n");
        // Invalid line
        data.extend_from_slice(b"not valid json\n");
        // Blank line
        data.extend_from_slice(b"\n");
        // Another valid record
        let second =
            EvidenceRecord::repair_succeeded(0, sample_repair_detail()).with_timestamp(200);
        serde_json::to_writer(&mut data, &second).expect("serialize");
        data.extend_from_slice(b"\n");

        let parsed = parse_evidence_ledger(&data);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].event_type, EvidenceEventType::CorruptionDetected);
        assert_eq!(parsed[1].event_type, EvidenceEventType::RepairSucceeded);
    }

    #[test]
    fn none_fields_omitted_from_json() {
        let record =
            EvidenceRecord::corruption_detected(0, sample_corruption_detail()).with_timestamp(100);
        let json = record.to_json().expect("serialize");
        assert!(json.contains("\"corruption\""));
        assert!(!json.contains("\"repair\""));
        assert!(!json.contains("\"scrub_cycle\""));
        assert!(!json.contains("\"policy\""));
        assert!(!json.contains("\"symbol_refresh\""));
        assert!(!json.contains("\"block_range\""));
        assert!(!json.contains("\"wal_recovery\""));
    }

    #[test]
    fn wal_recovery_round_trip() {
        let detail = WalRecoveryDetail {
            commits_replayed: 42,
            versions_replayed: 128,
            records_discarded: 1,
            wal_valid_bytes: 65536,
            wal_total_bytes: 65600,
            used_checkpoint: true,
            checkpoint_commit_seq: Some(30),
        };
        let record = EvidenceRecord::wal_recovery(detail.clone()).with_timestamp(9_000_000);
        let json = record.to_json().expect("serialize");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize");
        assert_eq!(parsed.event_type, EvidenceEventType::WalRecovery);
        assert_eq!(parsed.block_group, 0);
        assert_eq!(parsed.wal_recovery, Some(detail));
        assert!(parsed.corruption.is_none());
        assert!(parsed.repair.is_none());
    }

    #[test]
    fn wal_recovery_no_checkpoint() {
        let detail = WalRecoveryDetail {
            commits_replayed: 5,
            versions_replayed: 10,
            records_discarded: 0,
            wal_valid_bytes: 1024,
            wal_total_bytes: 1024,
            used_checkpoint: false,
            checkpoint_commit_seq: None,
        };
        let record = EvidenceRecord::wal_recovery(detail).with_timestamp(10_000_000);
        let json = record.to_json().expect("serialize");
        // checkpoint_commit_seq should be omitted from JSON
        assert!(!json.contains("checkpoint_commit_seq"));
    }
}
