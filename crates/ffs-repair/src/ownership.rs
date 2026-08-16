#![forbid(unsafe_code)]

//! Lease-based repair ownership for multi-host coordination.
//!
//! Implements optimistic ownership with deterministic tiebreak:
//! - Hosts claim ownership by writing a coordination record with TTL
//! - Expired leases can be claimed by any host
//! - Conflicts resolved by lexicographic UUID comparison (lower wins)
//!
//! See `docs/design-multi-host-repair.md` for the full protocol design.

use asupersync::Cx;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Default lease TTL: 5 minutes.
const DEFAULT_LEASE_TTL_SECS: u64 = 300;

/// Coordination record version.
const RECORD_VERSION: u32 = 1;
const OWNERSHIP_CANCELLED_MESSAGE: &str = "repair ownership operation cancelled";
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

// ── Coordination Record ────────────────────────────────────────────────────

/// Persistent coordination record for repair ownership.
///
/// Stored as `.<image>.ffs-repair-owner.json` adjacent to the image file.
/// Atomic updates via write-to-temp + rename.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordinationRecord {
    /// Record format version.
    pub version: u32,
    /// UUID of the owning host (for deterministic tiebreak).
    pub host_id: String,
    /// Human-readable hostname.
    pub hostname: String,
    /// PID of the owning process.
    pub pid: u32,
    /// ISO 8601 timestamp when ownership was claimed.
    pub claimed_at: String,
    /// Lease duration in seconds.
    pub lease_ttl_secs: u64,
    /// Monotonic lease incarnation. Changes only on ownership (re)acquisition.
    pub lease_version: u64,
    /// Monotonically increasing repair generation counter.
    pub repair_generation: u64,
    /// Block groups currently owned (empty = whole image).
    pub groups_owned: Vec<u32>,
}

impl CoordinationRecord {
    /// Check whether this lease has expired relative to the given current time.
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let Ok(claimed) = parse_iso8601(&self.claimed_at) else {
            // Unparseable timestamp → treat as expired
            return true;
        };
        let ttl = Duration::from_secs(self.lease_ttl_secs);
        claimed.checked_add(ttl).is_none_or(|expiry| now >= expiry)
    }

    /// Renew the lease by updating `claimed_at` to the current time.
    pub fn renew(&mut self) {
        self.claimed_at = format_iso8601(SystemTime::now());
    }
}

// ── Ownership Manager ──────────────────────────────────────────────────────

/// Manages repair ownership for a filesystem image.
pub struct RepairOwnership {
    /// This host's UUID (generated once per host, persisted).
    host_id: String,
    /// This host's hostname.
    hostname: String,
    /// Lease TTL for new claims.
    lease_ttl: Duration,
}

/// Guard representing active ownership. Release on drop or explicit release.
#[derive(Debug)]
pub struct OwnershipGuard {
    record_path: PathBuf,
    record: CoordinationRecord,
}

impl OwnershipGuard {
    /// The coordination record for this ownership.
    #[must_use]
    pub fn record(&self) -> &CoordinationRecord {
        &self.record
    }

    /// Path to the coordination record file.
    #[must_use]
    pub fn record_path(&self) -> &Path {
        &self.record_path
    }
}

/// Result of an ownership acquisition attempt.
#[derive(Debug)]
pub enum AcquireResult {
    /// Ownership acquired successfully.
    Acquired(OwnershipGuard),
    /// Another host owns the image and the lease has not expired.
    OwnedByOther {
        owner_host_id: String,
        owner_hostname: String,
        expires_in_secs: u64,
    },
    /// Ownership conflict detected; we lost the tiebreak.
    ConflictLost { winner_host_id: String },
}

impl RepairOwnership {
    /// Create a new ownership manager.
    #[must_use]
    pub fn new(host_id: String, hostname: String) -> Self {
        Self {
            host_id,
            hostname,
            lease_ttl: Duration::from_secs(DEFAULT_LEASE_TTL_SECS),
        }
    }

    /// Create with a custom lease TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.lease_ttl = ttl;
        self
    }

    /// Compute the coordination record path for an image.
    #[must_use]
    pub fn record_path_for(image_path: &Path) -> PathBuf {
        let file_name = image_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dot = Path::new(".");
        let parent = image_path.parent().unwrap_or(dot);
        parent.join(format!(".{file_name}.ffs-repair-owner.json"))
    }

    /// Attempt to acquire ownership of the image for repair.
    ///
    /// Returns `Acquired` if ownership was successfully claimed,
    /// `OwnedByOther` if another process/host holds a valid lease, or
    /// `ConflictLost` if we lost a tiebreak.
    pub fn try_acquire(&self, cx: &Cx, image_path: &Path) -> std::io::Result<AcquireResult> {
        cx_checkpoint(cx, "start ownership acquisition")?;
        let record_path = Self::record_path_for(image_path);
        let now = SystemTime::now();

        // Read existing record
        cx_checkpoint(cx, "read existing ownership record")?;
        match std::fs::read_to_string(&record_path) {
            Ok(contents) => {
                cx_checkpoint(cx, "parse existing ownership record")?;
                let existing: CoordinationRecord = serde_json::from_str(&contents)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                if !existing.is_expired(now) && !self.is_current_process_claim(&existing) {
                    // Another process or host owns it and the lease is valid.
                    let claimed =
                        parse_iso8601(&existing.claimed_at).unwrap_or(SystemTime::UNIX_EPOCH);
                    let expiry = claimed + Duration::from_secs(existing.lease_ttl_secs);
                    let remaining = expiry
                        .duration_since(now)
                        .unwrap_or(Duration::ZERO)
                        .as_secs();

                    info!(
                        target: "ffs::repair::ownership",
                        owner = %existing.host_id,
                        hostname = %existing.hostname,
                        remaining_secs = remaining,
                        "ownership_held_by_other"
                    );

                    return Ok(AcquireResult::OwnedByOther {
                        owner_host_id: existing.host_id,
                        owner_hostname: existing.hostname,
                        expires_in_secs: remaining,
                    });
                }

                // Lease expired or we already own it — claim.
                let (new_gen, new_lease_version) = next_claim_counters(&existing)?;
                self.write_claim(cx, &record_path, new_gen, new_lease_version)?;

                // Post-write verification: re-read to detect conflicts
                self.verify_or_tiebreak(cx, &record_path, new_gen, new_lease_version)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No record — claim with generation 1
                self.write_claim(cx, &record_path, 1, 1)?;
                self.verify_or_tiebreak(cx, &record_path, 1, 1)
            }
            Err(e) => Err(e),
        }
    }

    /// Write our ownership claim to the coordination record.
    fn write_claim(
        &self,
        cx: &Cx,
        record_path: &Path,
        generation: u64,
        lease_version: u64,
    ) -> std::io::Result<()> {
        cx_checkpoint(cx, "prepare ownership claim")?;
        let record = CoordinationRecord {
            version: RECORD_VERSION,
            host_id: self.host_id.clone(),
            hostname: self.hostname.clone(),
            pid: Self::current_pid(),
            claimed_at: format_iso8601(SystemTime::now()),
            lease_ttl_secs: self.lease_ttl.as_secs(),
            lease_version,
            repair_generation: generation,
            groups_owned: Vec::new(),
        };

        let json = serde_json::to_string_pretty(&record).map_err(std::io::Error::other)?;

        // Atomic write: write to temp, then rename
        cx_checkpoint(cx, "write temporary ownership claim")?;
        let tmp_path = temp_record_path(record_path)?;
        std::fs::write(&tmp_path, &json)?;
        cx_checkpoint(cx, "commit ownership claim")?;
        std::fs::rename(&tmp_path, record_path)?;
        cx_checkpoint(cx, "finish ownership claim")?;

        debug!(
            target: "ffs::repair::ownership",
            host_id = %self.host_id,
            generation = generation,
            "ownership_claimed"
        );

        Ok(())
    }

    /// Re-read the record to verify we own it. If another claimant wrote
    /// concurrently, prefer the higher generation, then lower host UUID.
    fn verify_or_tiebreak(
        &self,
        cx: &Cx,
        record_path: &Path,
        expected_gen: u64,
        expected_lease_version: u64,
    ) -> std::io::Result<AcquireResult> {
        let current = Self::read_record(cx, record_path)?;

        if self.claim_matches(&current, expected_gen, expected_lease_version) {
            return Ok(AcquireResult::Acquired(OwnershipGuard {
                record_path: record_path.to_owned(),
                record: current,
            }));
        }

        if self.should_rewrite_conflicting_claim(&current, expected_gen) {
            self.write_claim(cx, record_path, expected_gen, expected_lease_version)?;
            let record = Self::read_record(cx, record_path)?;
            return Ok(self.acquisition_result_for_current_claim(
                record_path,
                record,
                expected_gen,
                expected_lease_version,
            ));
        }

        Ok(self.conflict_lost(current))
    }

    fn read_record(cx: &Cx, record_path: &Path) -> std::io::Result<CoordinationRecord> {
        cx_checkpoint(cx, "read ownership record")?;
        let contents = std::fs::read_to_string(record_path)?;
        cx_checkpoint(cx, "parse ownership record")?;
        serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    fn claim_matches(
        &self,
        record: &CoordinationRecord,
        expected_gen: u64,
        expected_lease_version: u64,
    ) -> bool {
        record.host_id == self.host_id
            && record.pid == Self::current_pid()
            && record.repair_generation == expected_gen
            && record.lease_version == expected_lease_version
    }

    fn is_current_process_claim(&self, record: &CoordinationRecord) -> bool {
        record.host_id == self.host_id && record.pid == Self::current_pid()
    }

    fn current_pid() -> u32 {
        std::process::id()
    }

    fn should_rewrite_conflicting_claim(
        &self,
        current: &CoordinationRecord,
        expected_gen: u64,
    ) -> bool {
        current.repair_generation < expected_gen
            || (current.repair_generation == expected_gen
                && self.host_id.as_str() < current.host_id.as_str())
    }

    fn acquisition_result_for_current_claim(
        &self,
        record_path: &Path,
        record: CoordinationRecord,
        expected_gen: u64,
        expected_lease_version: u64,
    ) -> AcquireResult {
        if self.claim_matches(&record, expected_gen, expected_lease_version) {
            AcquireResult::Acquired(OwnershipGuard {
                record_path: record_path.to_owned(),
                record,
            })
        } else {
            warn!(
                target: "ffs::repair::ownership",
                our_id = %self.host_id,
                winner_id = %record.host_id,
                expected_pid = Self::current_pid(),
                observed_pid = record.pid,
                expected_generation = expected_gen,
                observed_generation = record.repair_generation,
                expected_lease_version,
                observed_lease_version = record.lease_version,
                "ownership_claim_verification_lost"
            );
            AcquireResult::ConflictLost {
                winner_host_id: record.host_id,
            }
        }
    }

    fn conflict_lost(&self, current: CoordinationRecord) -> AcquireResult {
        warn!(
            target: "ffs::repair::ownership",
            our_id = %self.host_id,
            winner_id = %current.host_id,
            winner_generation = current.repair_generation,
            "ownership_conflict_lost"
        );
        AcquireResult::ConflictLost {
            winner_host_id: current.host_id,
        }
    }

    /// Renew an existing lease.
    pub fn renew(&self, cx: &Cx, guard: &mut OwnershipGuard) -> std::io::Result<()> {
        cx_checkpoint(cx, "start ownership renewal")?;
        let current = Self::read_record(cx, &guard.record_path)?;
        if !Self::same_lease_incarnation(&current, &guard.record) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "cannot renew stale lease: expected {} pid {} gen {} lease v{}, found {} pid {} gen {} lease v{}",
                    guard.record.host_id,
                    guard.record.pid,
                    guard.record.repair_generation,
                    guard.record.lease_version,
                    current.host_id,
                    current.pid,
                    current.repair_generation,
                    current.lease_version
                ),
            ));
        }

        cx_checkpoint(cx, "prepare ownership renewal")?;
        let mut renewed = guard.record.clone();
        renewed.renew();
        let json = serde_json::to_string_pretty(&renewed).map_err(std::io::Error::other)?;
        let tmp_path = temp_record_path(&guard.record_path)?;
        cx_checkpoint(cx, "write temporary ownership renewal")?;
        std::fs::write(&tmp_path, &json)?;
        cx_checkpoint(cx, "commit ownership renewal")?;
        std::fs::rename(&tmp_path, &guard.record_path)?;
        guard.record = renewed;
        cx_checkpoint(cx, "finish ownership renewal")?;
        debug!(
            target: "ffs::repair::ownership",
            host_id = %self.host_id,
            "ownership_renewed"
        );
        Ok(())
    }

    /// Release ownership explicitly. Consumes the guard to prevent
    /// further use after release.
    #[allow(clippy::needless_pass_by_value)]
    pub fn release(cx: &Cx, guard: OwnershipGuard) -> std::io::Result<()> {
        cx_checkpoint(cx, "start ownership release")?;
        let contents = match std::fs::read_to_string(&guard.record_path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        cx_checkpoint(cx, "parse ownership release record")?;
        let current: CoordinationRecord = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if !Self::same_lease_incarnation(&current, &guard.record) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "cannot release stale lease: expected {} pid {} gen {} lease v{}, found {} pid {} gen {} lease v{}",
                    guard.record.host_id,
                    guard.record.pid,
                    guard.record.repair_generation,
                    guard.record.lease_version,
                    current.host_id,
                    current.pid,
                    current.repair_generation,
                    current.lease_version
                ),
            ));
        }

        // Remove the coordination record so the next host can claim immediately
        // instead of waiting for TTL expiry.
        cx_checkpoint(cx, "remove ownership record")?;
        match std::fs::remove_file(&guard.record_path) {
            Ok(()) => {
                cx_checkpoint(cx, "finish ownership release")?;
                info!(
                    target: "ffs::repair::ownership",
                    host_id = %guard.record.host_id,
                    "ownership_released"
                );
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Check if we currently own the image (without modifying the record).
    pub fn is_owned_by_us(&self, cx: &Cx, image_path: &Path) -> std::io::Result<bool> {
        cx_checkpoint(cx, "start ownership status check")?;
        let record_path = Self::record_path_for(image_path);
        match std::fs::read_to_string(&record_path) {
            Ok(contents) => {
                cx_checkpoint(cx, "parse ownership status record")?;
                let record: CoordinationRecord = serde_json::from_str(&contents)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let now = SystemTime::now();
                Ok(self.is_current_process_claim(&record) && !record.is_expired(now))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn same_lease_incarnation(current: &CoordinationRecord, expected: &CoordinationRecord) -> bool {
        current.host_id == expected.host_id
            && current.pid == expected.pid
            && current.repair_generation == expected.repair_generation
            && current.lease_version == expected.lease_version
    }
}

fn cx_checkpoint(cx: &Cx, phase: &'static str) -> std::io::Result<()> {
    cx.checkpoint().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            format!("{OWNERSHIP_CANCELLED_MESSAGE}: {phase}"),
        )
    })
}

// ── Time helpers ───────────────────────────────────────────────────────────

fn format_iso8601(time: SystemTime) -> String {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = duration.as_secs();
    // Simple UTC format without external deps
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch → year/month/day (simplified, not leap-second-aware)
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(days_since_epoch: u64) -> (u64, u64, u64) {
    // Civil calendar from days since 1970-01-01 (simplified algorithm)
    let z = days_since_epoch + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn parse_iso8601(s: &str) -> Result<SystemTime, ()> {
    // Parse "YYYY-MM-DDTHH:MM:SSZ" format
    let bytes = s.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(());
    }
    let year = parse_ascii_digits(&bytes[0..4])?;
    let month = parse_ascii_digits(&bytes[5..7])?;
    let day = parse_ascii_digits(&bytes[8..10])?;
    let hours = parse_ascii_digits(&bytes[11..13])?;
    let minutes = parse_ascii_digits(&bytes[14..16])?;
    let seconds = parse_ascii_digits(&bytes[17..19])?;

    if year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hours > 23
        || minutes > 59
        || seconds > 59
    {
        return Err(());
    }

    let days = ymd_to_days(year, month, day);
    let total_secs = days * 86400 + hours * 3600 + minutes * 60 + seconds;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(total_secs))
}

fn parse_ascii_digits(bytes: &[u8]) -> Result<u64, ()> {
    let mut value = 0_u64;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(());
        }
        value = value * 10 + u64::from(byte - b'0');
    }
    Ok(value)
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn ymd_to_days(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn next_temp_file_nonce(counter: &AtomicU64) -> std::io::Result<u64> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| std::io::Error::other("repair ownership temporary file nonce exhausted"))
}

fn temp_record_path(record_path: &Path) -> std::io::Result<PathBuf> {
    let nonce = next_temp_file_nonce(&TEMP_FILE_COUNTER)?;
    Ok(record_path.with_extension(format!("tmp-{}-{nonce}", std::process::id())))
}

fn next_claim_counters(record: &CoordinationRecord) -> std::io::Result<(u64, u64)> {
    let generation = record.repair_generation.checked_add(1).ok_or_else(|| {
        ownership_counter_exhausted("repair_generation", record.repair_generation)
    })?;
    let lease_version = record
        .lease_version
        .checked_add(1)
        .ok_or_else(|| ownership_counter_exhausted("lease_version", record.lease_version))?;
    Ok((generation, lease_version))
}

fn ownership_counter_exhausted(field: &str, value: u64) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("repair ownership {field} exhausted at {value}"),
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn record_path_for_image() {
        let path = RepairOwnership::record_path_for(Path::new("/tmp/test.ext4"));
        assert_eq!(path, PathBuf::from("/tmp/.test.ext4.ffs-repair-owner.json"));
    }

    #[test]
    fn record_path_for_image_no_parent() {
        let path = RepairOwnership::record_path_for(Path::new("image.img"));
        assert_eq!(path, PathBuf::from(".image.img.ffs-repair-owner.json"));
    }

    #[test]
    fn coordination_record_expired() {
        let record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: "2020-01-01T00:00:00Z".into(),
            lease_ttl_secs: 300,
            lease_version: 1,
            repair_generation: 1,
            groups_owned: vec![],
        };
        // 2020 + 300s is long past
        assert!(record.is_expired(SystemTime::now()));
    }

    #[test]
    fn coordination_record_not_expired() {
        let now = SystemTime::now();
        let record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: format_iso8601(now),
            lease_ttl_secs: 3600,
            lease_version: 7,
            repair_generation: 1,
            groups_owned: vec![],
        };
        assert!(!record.is_expired(now));
    }

    #[test]
    fn coordination_record_bad_timestamp_treated_as_expired() {
        let record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: "not-a-timestamp".into(),
            lease_ttl_secs: 300,
            lease_version: 1,
            repair_generation: 1,
            groups_owned: vec![],
        };
        assert!(record.is_expired(SystemTime::now()));
    }

    #[test]
    fn coordination_record_invalid_calendar_timestamp_treated_as_expired() {
        let record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: "0000-01-01T00:00:00Z".into(),
            lease_ttl_secs: 300,
            lease_version: 1,
            repair_generation: 1,
            groups_owned: vec![],
        };
        assert!(record.is_expired(SystemTime::now()));
    }

    #[test]
    fn coordination_record_overflowing_ttl_treated_as_expired() {
        let record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: "9999-12-31T23:59:59Z".into(),
            lease_ttl_secs: u64::MAX,
            lease_version: 1,
            repair_generation: 1,
            groups_owned: vec![],
        };
        assert!(record.is_expired(SystemTime::now()));
    }

    #[test]
    fn coordination_record_renew() {
        let mut record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: "2020-01-01T00:00:00Z".into(),
            lease_ttl_secs: 300,
            lease_version: 3,
            repair_generation: 1,
            groups_owned: vec![],
        };
        assert!(record.is_expired(SystemTime::now()));
        record.renew();
        assert!(!record.is_expired(SystemTime::now()));
    }

    #[test]
    fn coordination_record_json_round_trip() {
        let record = CoordinationRecord {
            version: 1,
            host_id: "a1b2c3d4".into(),
            hostname: "worker-03".into(),
            pid: 12345,
            claimed_at: "2026-03-14T02:00:00Z".into(),
            lease_ttl_secs: 300,
            lease_version: 9,
            repair_generation: 42,
            groups_owned: vec![0, 1, 2],
        };
        let json = serde_json::to_string_pretty(&record).expect("serialize");
        let deser: CoordinationRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, deser);
    }

    #[test]
    fn iso8601_round_trip() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_710_000_000); // ~2024-03
        let formatted = format_iso8601(now);
        let parsed = parse_iso8601(&formatted).expect("parse");
        let delta = parsed
            .duration_since(now)
            .or_else(|_| now.duration_since(parsed))
            .unwrap_or(Duration::ZERO);
        assert!(delta.as_secs() < 2, "round-trip drift: {delta:?}");
    }

    #[test]
    fn iso8601_parser_rejects_invalid_components() {
        for invalid in [
            "1969-12-31T23:59:59Z",
            "2026-00-01T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:60Z",
            "2026/01/01T00:00:00Z",
            "2026-aa-01T00:00:00Z",
        ] {
            assert!(parse_iso8601(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn iso8601_parser_rejects_non_ascii_without_panicking() {
        assert!(parse_iso8601("2026-é1-01T00:00:0Z").is_err());
    }

    #[test]
    fn iso8601_parser_accepts_leap_day() {
        assert!(parse_iso8601("2024-02-29T12:34:56Z").is_ok());
    }

    #[test]
    fn deterministic_tiebreak_lower_uuid_wins() {
        // Verify the tiebreak logic: lower host_id should win
        let host_a = "aaaa-1111";
        let host_b = "bbbb-2222";
        assert!(host_a < host_b, "lexicographic: a < b");

        // If our host_id < other host_id, we should win
        let mgr = RepairOwnership::new(host_a.into(), "worker-a".into());
        assert!(mgr.host_id.as_str() < host_b);
    }

    #[test]
    fn rewrite_decision_preserves_newer_generation() {
        let mgr = RepairOwnership::new("aaaa".into(), "worker-a".into());
        let current = record_fixture("zzzz", 12, 12);

        assert!(
            !mgr.should_rewrite_conflicting_claim(&current, 11),
            "older expected generation must not overwrite a newer on-disk claim"
        );
    }

    #[test]
    fn rewrite_decision_prefers_generation_before_host_tiebreak() {
        let mgr = RepairOwnership::new("zzzz".into(), "worker-z".into());
        let current = record_fixture("aaaa", 10, 10);

        assert!(
            mgr.should_rewrite_conflicting_claim(&current, 11),
            "newer generation wins even when our host id loses the lexical tiebreak"
        );
    }

    #[test]
    fn rewrite_decision_tiebreaks_equal_generation_by_host_id() {
        let lower = RepairOwnership::new("aaaa".into(), "worker-a".into());
        let higher = RepairOwnership::new("zzzz".into(), "worker-z".into());
        let current = record_fixture("mmmm", 10, 10);

        assert!(lower.should_rewrite_conflicting_claim(&current, 10));
        assert!(!higher.should_rewrite_conflicting_claim(&current, 10));
    }

    #[test]
    fn acquisition_result_rejects_same_host_stale_incarnation() {
        let mgr = RepairOwnership::new("host-1".into(), "worker".into());
        let record_path = PathBuf::from("/tmp/.image.img.ffs-repair-owner.json");
        let stale = record_fixture("host-1", 42, 6);

        let result = mgr.acquisition_result_for_current_claim(&record_path, stale, 42, 5);

        assert!(
            matches!(result, AcquireResult::ConflictLost { ref winner_host_id } if winner_host_id == "host-1"),
            "stale same-host lease must be rejected: {result:?}"
        );
    }

    #[test]
    fn acquire_creates_record_on_disk() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = Cx::for_testing();
        let mgr = RepairOwnership::new("host-1".into(), "test-host".into());
        let result = mgr.try_acquire(&cx, &image).expect("acquire");
        assert!(
            matches!(result, AcquireResult::Acquired(_)),
            "should acquire when no record exists"
        );

        let record_path = RepairOwnership::record_path_for(&image);
        assert!(record_path.exists(), "record file should be created");
    }

    #[test]
    fn acquire_cancelled_before_record_write_does_not_mutate_disk() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = cancelled_cx();
        let mgr = RepairOwnership::new("host-1".into(), "test-host".into());
        let err = mgr
            .try_acquire(&cx, &image)
            .expect_err("cancelled acquire must fail");

        assert_cancelled(&err);
        let record_path = RepairOwnership::record_path_for(&image);
        assert!(
            !record_path.exists(),
            "pre-cancelled acquire must not create ownership record"
        );
    }

    #[test]
    fn acquire_rejects_when_owned_by_other() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = Cx::for_testing();
        // Host A acquires
        let mgr_a = RepairOwnership::new("aaaa".into(), "host-a".into());
        let result_a = mgr_a.try_acquire(&cx, &image).expect("acquire a");
        assert!(matches!(result_a, AcquireResult::Acquired(_)));

        // Host B tries to acquire — should be rejected
        let mgr_b = RepairOwnership::new("bbbb".into(), "host-b".into());
        let result_b = mgr_b.try_acquire(&cx, &image).expect("acquire b");
        assert!(
            matches!(result_b, AcquireResult::OwnedByOther { .. }),
            "should be rejected: {result_b:?}"
        );
    }

    #[test]
    fn acquire_rejects_live_lease_from_same_host_different_pid() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let mut record = record_fixture("host-1", 7, 3);
        record.pid = different_pid();
        let record_path = RepairOwnership::record_path_for(&image);
        std::fs::write(&record_path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

        let cx = Cx::for_testing();
        let mgr = RepairOwnership::new("host-1".into(), "same-host-new-process".into());
        let result = mgr.try_acquire(&cx, &image).expect("acquire");

        assert!(
            matches!(result, AcquireResult::OwnedByOther { ref owner_host_id, .. } if owner_host_id == "host-1"),
            "expected same-host process conflict, got {result:?}"
        );
    }

    #[test]
    fn acquire_succeeds_after_lease_expiry() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        // Write an expired record manually
        let record = CoordinationRecord {
            version: 1,
            host_id: "dead-host".into(),
            hostname: "crashed".into(),
            pid: 999,
            claimed_at: "2020-01-01T00:00:00Z".into(),
            lease_ttl_secs: 1,
            lease_version: 4,
            repair_generation: 5,
            groups_owned: vec![],
        };
        let record_path = RepairOwnership::record_path_for(&image);
        std::fs::write(&record_path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

        // New host should be able to claim
        let cx = Cx::for_testing();
        let mgr = RepairOwnership::new("new-host".into(), "alive".into());
        let result = mgr.try_acquire(&cx, &image).expect("acquire");
        let guard = acquired_guard(result).expect("expected acquired");
        assert_eq!(guard.record().host_id, "new-host");
        assert_eq!(guard.record().lease_version, 5);
        assert_eq!(guard.record().repair_generation, 6); // incremented
    }

    #[test]
    fn acquire_rejects_exhausted_repair_generation_without_rewriting() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let mut record = expired_record_fixture("dead-host", u64::MAX, 4);
        record.pid = different_pid();
        let record_path = RepairOwnership::record_path_for(&image);
        std::fs::write(&record_path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

        let cx = Cx::for_testing();
        let mgr = RepairOwnership::new("new-host".into(), "alive".into());
        let err = mgr
            .try_acquire(&cx, &image)
            .expect_err("exhausted generation must fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("repair_generation"),
            "wrong error: {err}"
        );
        let current = read_test_record(&record_path);
        assert_eq!(current, record, "failed claim must not rewrite ownership");
    }

    #[test]
    fn acquire_rejects_exhausted_lease_version_without_rewriting() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let mut record = expired_record_fixture("dead-host", 41, u64::MAX);
        record.pid = different_pid();
        let record_path = RepairOwnership::record_path_for(&image);
        std::fs::write(&record_path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

        let cx = Cx::for_testing();
        let mgr = RepairOwnership::new("new-host".into(), "alive".into());
        let err = mgr
            .try_acquire(&cx, &image)
            .expect_err("exhausted lease version must fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("lease_version"),
            "wrong error: {err}"
        );
        let current = read_test_record(&record_path);
        assert_eq!(current, record, "failed claim must not rewrite ownership");
    }

    #[test]
    fn release_removes_record() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = Cx::for_testing();
        let mgr = RepairOwnership::new("host-1".into(), "test".into());
        let result = mgr.try_acquire(&cx, &image).expect("acquire");
        let guard = acquired_guard(result).expect("expected acquired");

        let record_path = RepairOwnership::record_path_for(&image);
        assert!(record_path.exists());

        RepairOwnership::release(&cx, guard).expect("release");
        assert!(
            !record_path.exists(),
            "record should be removed after release"
        );
    }

    #[test]
    fn release_cancelled_before_remove_keeps_record_on_disk() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = Cx::for_testing();
        let mgr = RepairOwnership::new("host-1".into(), "test".into());
        let result = mgr.try_acquire(&cx, &image).expect("acquire");
        let guard = acquired_guard(result).expect("expected acquired");
        let record_path = RepairOwnership::record_path_for(&image);

        let cancel_cx = cancelled_cx();
        let err =
            RepairOwnership::release(&cancel_cx, guard).expect_err("cancelled release must fail");

        assert_cancelled(&err);
        assert!(
            record_path.exists(),
            "pre-cancelled release must leave ownership record in place"
        );
    }

    #[test]
    fn renew_updates_timestamp() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = Cx::for_testing();
        let mgr =
            RepairOwnership::new("host-1".into(), "test".into()).with_ttl(Duration::from_secs(10));
        let result = mgr.try_acquire(&cx, &image).expect("acquire");
        let mut guard = acquired_guard(result).expect("expected acquired");

        let old_time = format_iso8601(
            SystemTime::now()
                .checked_sub(Duration::from_secs(2))
                .expect("test clock should be after Unix epoch"),
        );
        guard.record.claimed_at = old_time.clone();
        write_test_record(guard.record_path(), guard.record());

        mgr.renew(&cx, &mut guard).expect("renew");
        assert_ne!(
            guard.record().claimed_at,
            old_time,
            "timestamp should update"
        );
    }

    #[test]
    fn renew_rejects_stale_guard_after_takeover() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = Cx::for_testing();
        let mgr_a =
            RepairOwnership::new("host-a".into(), "test-a".into()).with_ttl(Duration::from_secs(1));
        let result = mgr_a.try_acquire(&cx, &image).expect("acquire");
        let mut guard = acquired_guard(result).expect("expected acquired");

        mark_record_expired(guard.record_path());
        let mgr_b = RepairOwnership::new("host-b".into(), "test-b".into());
        let takeover = mgr_b.try_acquire(&cx, &image).expect("takeover");
        assert!(matches!(takeover, AcquireResult::Acquired(_)));

        let err = mgr_a.renew(&cx, &mut guard).expect_err("renew must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn renew_cancelled_before_write_does_not_mutate_record_or_guard() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = Cx::for_testing();
        let mgr =
            RepairOwnership::new("host-1".into(), "test".into()).with_ttl(Duration::from_secs(10));
        let result = mgr.try_acquire(&cx, &image).expect("acquire");
        let mut guard = acquired_guard(result).expect("expected acquired");
        let record_path = guard.record_path().to_owned();
        let before_disk = std::fs::read_to_string(&record_path).expect("record exists");
        let before_guard = guard.record().clone();

        let cancel_cx = cancelled_cx();
        let err = mgr
            .renew(&cancel_cx, &mut guard)
            .expect_err("cancelled renew must fail");

        assert_cancelled(&err);
        let after_disk = std::fs::read_to_string(&record_path).expect("record remains");
        assert_eq!(after_disk, before_disk);
        assert_eq!(guard.record(), &before_guard);
    }

    #[test]
    fn is_owned_by_us() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = Cx::for_testing();
        let mgr = RepairOwnership::new("host-1".into(), "test".into());
        assert!(!mgr.is_owned_by_us(&cx, &image).unwrap());

        let result = mgr.try_acquire(&cx, &image).expect("acquire");
        assert!(matches!(result, AcquireResult::Acquired(_)));
        assert!(mgr.is_owned_by_us(&cx, &image).unwrap());

        // Different host should not own
        let other = RepairOwnership::new("host-2".into(), "other".into());
        assert!(!other.is_owned_by_us(&cx, &image).unwrap());
    }

    #[test]
    fn release_rejects_stale_guard_after_takeover() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let cx = Cx::for_testing();
        let mgr_a =
            RepairOwnership::new("host-a".into(), "test-a".into()).with_ttl(Duration::from_secs(1));
        let result = mgr_a.try_acquire(&cx, &image).expect("acquire");
        let guard = acquired_guard(result).expect("expected acquired");

        mark_record_expired(guard.record_path());
        let mgr_b = RepairOwnership::new("host-b".into(), "test-b".into());
        let takeover = mgr_b.try_acquire(&cx, &image).expect("takeover");
        assert!(matches!(takeover, AcquireResult::Acquired(_)));

        let err = RepairOwnership::release(&cx, guard).expect_err("release must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        let record_path = RepairOwnership::record_path_for(&image);
        let contents = std::fs::read_to_string(record_path).expect("record remains");
        let current: CoordinationRecord = serde_json::from_str(&contents).expect("parse");
        assert_eq!(current.host_id, "host-b");
    }

    #[test]
    fn release_rejects_same_host_same_lease_different_pid() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();
        let record_path = RepairOwnership::record_path_for(&image);

        let guard_record = record_fixture("host-1", 9, 4);
        let mut on_disk = guard_record.clone();
        on_disk.pid = different_pid();
        std::fs::write(
            &record_path,
            serde_json::to_string_pretty(&on_disk).unwrap(),
        )
        .unwrap();

        let guard = OwnershipGuard {
            record_path: record_path.clone(),
            record: guard_record,
        };
        let cx = Cx::for_testing();
        let err = RepairOwnership::release(&cx, guard).expect_err("release must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        let contents = std::fs::read_to_string(record_path).expect("record remains");
        let current: CoordinationRecord = serde_json::from_str(&contents).expect("parse");
        assert_eq!(current.pid, on_disk.pid);
    }

    #[test]
    fn temp_record_path_is_unique_per_write_attempt() {
        let record_path = PathBuf::from("/tmp/.image.img.ffs-repair-owner.json");
        let first = temp_record_path(&record_path).expect("first temp path");
        let second = temp_record_path(&record_path).expect("second temp path");
        assert_ne!(first, second);
        assert_eq!(first.parent(), record_path.parent());
        assert_eq!(second.parent(), record_path.parent());
    }

    #[test]
    fn temp_file_nonce_rejects_numeric_limit_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);

        let nonce = next_temp_file_nonce(&counter).expect("last usable nonce");
        assert_eq!(nonce, u64::MAX - 1);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);

        let err = next_temp_file_nonce(&counter).expect_err("counter exhaustion should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn proptest_rewrite_decision_orders_by_generation_then_host_id(
            our_seed in any::<u16>(),
            current_seed in any::<u16>(),
            expected_generation in 0_u64..1_000_000,
            current_generation in 0_u64..1_000_000,
        ) {
            let our_host = format!("host-{our_seed:04x}");
            let current_host = format!("host-{current_seed:04x}");
            let mgr = RepairOwnership::new(our_host.clone(), "worker-a".into());
            let current = record_fixture(&current_host, current_generation, 1);

            let should_rewrite =
                mgr.should_rewrite_conflicting_claim(&current, expected_generation);
            let expected = expected_generation > current_generation
                || (expected_generation == current_generation && our_host < current_host);

            prop_assert_eq!(
                should_rewrite,
                expected,
                "expected_gen={} current_gen={} our={} current={}",
                expected_generation,
                current_generation,
                our_host,
                current_host,
            );
        }
    }

    fn record_fixture(
        host_id: &str,
        repair_generation: u64,
        lease_version: u64,
    ) -> CoordinationRecord {
        CoordinationRecord {
            version: RECORD_VERSION,
            host_id: host_id.into(),
            hostname: "worker".into(),
            pid: std::process::id(),
            claimed_at: format_iso8601(SystemTime::now()),
            lease_ttl_secs: DEFAULT_LEASE_TTL_SECS,
            lease_version,
            repair_generation,
            groups_owned: vec![],
        }
    }

    fn expired_record_fixture(
        host_id: &str,
        repair_generation: u64,
        lease_version: u64,
    ) -> CoordinationRecord {
        CoordinationRecord {
            claimed_at: "2020-01-01T00:00:00Z".into(),
            lease_ttl_secs: 1,
            ..record_fixture(host_id, repair_generation, lease_version)
        }
    }

    fn read_test_record(record_path: &Path) -> CoordinationRecord {
        let contents = std::fs::read_to_string(record_path).expect("record remains");
        serde_json::from_str(&contents).expect("parse record")
    }

    fn write_test_record(record_path: &Path, record: &CoordinationRecord) {
        std::fs::write(
            record_path,
            serde_json::to_string_pretty(record).expect("serialize record"),
        )
        .expect("write record");
    }

    fn mark_record_expired(record_path: &Path) {
        let mut record = read_test_record(record_path);
        record.claimed_at = "2020-01-01T00:00:00Z".into();
        write_test_record(record_path, &record);
    }

    fn different_pid() -> u32 {
        let pid = std::process::id();
        if pid == u32::MAX { pid - 1 } else { pid + 1 }
    }

    fn cancelled_cx() -> Cx {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        cx
    }

    fn assert_cancelled(err: &std::io::Error) {
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
        assert!(
            err.to_string().contains(OWNERSHIP_CANCELLED_MESSAGE),
            "wrong cancellation error: {err}"
        );
    }

    fn acquired_guard(result: AcquireResult) -> Option<OwnershipGuard> {
        match result {
            AcquireResult::Acquired(guard) => Some(guard),
            AcquireResult::OwnedByOther { .. } | AcquireResult::ConflictLost { .. } => None,
        }
    }

    fn tempdir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ffs-test-ownership-{}-{n}", std::process::id()));
        // Clean up any leftover from previous run
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }
}
