//! MFT bitmap and base/extension ownership checks, independent of cluster claims.
//!
//! Reuse the reader's bidirectional ATTRIBUTE_LIST validator. A physically
//! accounted extension is not necessarily owned by a valid base catalog. An
//! incomplete scan cannot prove the absence of an owner or authorize reuse.
//! Native contract: Microsoft NTFS v3 Master File Table / ATTRIBUTE_LIST_ENTRY.

use super::{
    AllocationIssue, Cx, FfsError, MAX_ISSUES, MAX_RECORDS, NtfsValue, NtfsVolume, Result,
    bit, buffer, checkpoint, corrupt, parse, read_bitmap, unsupported,
};
use crate::reader::attributes::{AttributeSet, read_list, resolve_catalog};
use crate::reader::{ATTRIBUTE_LIST, NtfsFileRecord};

#[derive(Debug, Clone, Copy)]
pub struct RecordOwnershipLimits {
    /// Maximum logical MFT slots; checked before any checker I/O.
    pub records: u64,
    /// FILE reads, list values and bitmap bytes, including repeated metadata.
    /// Resident list/bitmap values are charged too; this is not unique disk I/O.
    pub metadata_bytes: u64,
}

impl Default for RecordOwnershipLimits {
    fn default() -> Self {
        Self { records: 1_048_576, metadata_bytes: 1 << 30 }
    }
}

impl RecordOwnershipLimits {
    pub fn validate(self) -> Result<()> {
        if !(1..=MAX_RECORDS).contains(&self.records)
            || !(1..=(1_u64 << 40)).contains(&self.metadata_bytes)
        {
            return Err(FfsError::Format(
                "record ownership requires 1..=16777216 slots and 1..=1099511627776 metadata bytes".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RecordOwnershipReport {
    pub logical_records: u64,
    pub initialized_records: u64,
    pub record_slots_examined: u64,
    pub base_records_examined: u64,
    pub extension_records_examined: u64,
    /// Unique extensions belonging to fully validated, allocated base catalogs.
    pub referenced_extension_records: u64,
    pub metadata_bytes_attempted: u64,
    /// Unknown unless every allocated record and base catalog was inspected.
    /// A nonzero count is a consistency defect, never reclamation authority.
    pub extensions_without_owner: Option<u64>,
    pub complete: bool,
    pub limit_reached: Option<&'static str>,
    pub errors: u64,
    pub unsupported: u64,
    pub issues: Vec<AllocationIssue>,
    pub omitted_issues: u64,
}

impl RecordOwnershipReport {
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.complete && self.limit_reached.is_none() && self.errors == 0
            && self.unsupported == 0 && self.extensions_without_owner == Some(0)
    }

    fn stop(&mut self, reason: &'static str) {
        self.complete = false;
        self.limit_reached = Some(reason);
    }

    fn issue(&mut self, record: u64, category: &'static str, detail: String) {
        if category == "unsupported" { self.unsupported += 1; } else { self.errors += 1; }
        if self.issues.len() == MAX_ISSUES {
            self.omitted_issues += 1;
            return;
        }
        self.issues.push(AllocationIssue {
            category, record: Some(record), attribute_id: None,
            other_record: None, other_attribute_id: None,
            first_cluster: None, clusters: 0,
            detail: detail.chars().take(512).collect(),
        });
    }

    fn failed_record(&mut self, number: u64, error: FfsError) -> Result<()> {
        if matches!(error, FfsError::Cancelled) { return Err(FfsError::Cancelled); }
        self.complete = false;
        let category = match &error {
            FfsError::UnsupportedFeature(_) => "unsupported",
            FfsError::Io(_) => "io",
            _ => "record_catalog",
        };
        self.issue(number, category, error.to_string());
        Ok(())
    }
}

struct Work {
    used: u64,
    limit: u64,
    stopped: bool,
}

impl Work {
    fn reserve(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.limit - self.used {
            self.stopped = true;
            return Err(unsupported("record ownership metadata work budget exhausted"));
        }
        self.used += bytes;
        Ok(())
    }
}

/// Charge list values before their read and each unique catalog extension
/// before its FILE read. The normal parser retains all of its existing rules.
/// During bitmap bootstrap, native sequence/bounds are checked but the bitmap
/// cannot validate itself. Record zero is rechecked with bitmap authority in
/// the scan; that bootstrap exception never certifies a free extension.
fn catalog<'a>(
    volume: &NtfsVolume,
    cx: &Cx,
    base: &'a NtfsFileRecord,
    work: &mut Work,
    allocated: Option<&[u8]>,
    records: u64,
) -> Result<AttributeSet<'a>> {
    for attr in base.attributes().map_err(|error| parse(&error))? {
        checkpoint(cx)?;
        if attr.kind == ATTRIBUTE_LIST {
            let bytes = match attr.value {
                NtfsValue::Resident(value) => value.len() as u64,
                NtfsValue::NonResident(value) => value.data_bytes,
            };
            work.reserve(bytes)?;
        }
    }
    let list = read_list(&volume.source, &volume.geometry, cx, base)?;
    resolve_catalog(cx, &volume.geometry, base, list.as_deref(), |reference| {
        checkpoint(cx)?;
        if reference.record >= records || reference.record >= volume.record_count() {
            return Err(corrupt(0, format!(
                "catalog references MFT record {} outside initialized record bounds", reference.record,
            )));
        }
        if allocated.is_some_and(|bits| !bit(bits, reference.record)) {
            return Err(corrupt(0, format!(
                "catalog references MFT record {} marked free by $MFT::$BITMAP", reference.record,
            )));
        }
        work.reserve(u64::from(volume.geometry.record_bytes()))?;
        volume.record(cx, reference.record, Some(reference.sequence))
    })
}

fn mark(bits: &mut [u8], number: u64) {
    bits[number as usize / 8] |= 1 << (number % 8);
}

impl NtfsVolume {
    /// Cross-check allocated FILE records against complete base catalogs.
    /// No file payload, namespace traversal, journal replay or backing writes.
    /// This is separate from check_allocations: neither result substitutes for
    /// the other, a complete native checker, or writable admission.
    pub fn check_record_ownership(
        &self,
        cx: &Cx,
        limits: RecordOwnershipLimits,
    ) -> Result<RecordOwnershipReport> {
        checkpoint(cx)?;
        limits.validate()?;
        if self.volume_flags != 0 || self.logfile_recovery.is_some() || !self.source.overlay.is_empty() {
            return Err(unsupported("record ownership checking requires original clean-flag bytes without a recovery overlay"));
        }
        let record_bytes = u64::from(self.geometry.record_bytes());
        let records = self.mft.size / record_bytes;
        let mut report = RecordOwnershipReport {
            logical_records: records,
            initialized_records: self.record_count(),
            complete: true,
            ..RecordOwnershipReport::default()
        };
        if records > limits.records {
            report.stop("MFT record budget");
            checkpoint(cx)?;
            return Ok(report);
        }
        let mut work = Work { used: 0, limit: limits.metadata_bytes, stopped: false };
        let bitmap = (|| -> Result<Vec<u8>> {
            work.reserve(record_bytes)?;
            let mft = self.record(cx, 0, None)?;
            let catalog = catalog(self, cx, &mft, &mut work, None, records)?;
            let stream = catalog.select(&self.geometry, 0xB0, &[])?;
            work.reserve(records.div_ceil(8))?;
            read_bitmap(cx, self, &stream, records)
        })();
        let allocated = match bitmap {
            Ok(bits) => bits,
            Err(_) if work.stopped => {
                report.stop("metadata work budget");
                report.metadata_bytes_attempted = work.used;
                checkpoint(cx)?;
                return Ok(report);
            }
            // Failure of the allocation authority is not a partial success.
            Err(error) => return Err(error),
        };
        if records == 0 || !bit(&allocated, 0) {
            return Err(corrupt(0, "$MFT::$BITMAP does not allocate its own base record"));
        }
        let mut extensions = buffer(allocated.len())?;
        let mut owned = buffer(allocated.len())?;
        for number in 0..records {
            checkpoint(cx)?;
            report.record_slots_examined += 1;
            if !bit(&allocated, number) { continue; }
            if number >= report.initialized_records {
                report.failed_record(number, corrupt(0, "allocated FILE is beyond initialized MFT data"))?;
                continue;
            }
            if work.reserve(record_bytes).is_err() {
                report.stop("metadata work budget");
                break;
            }
            let record = match self.record(cx, number, None) {
                Ok(record) => record,
                Err(error) => { report.failed_record(number, error)?; continue; }
            };
            if record.base.record != 0 || record.base.sequence != 0 {
                report.extension_records_examined += 1;
                mark(&mut extensions, number);
                if let Err(error) = record.attributes() {
                    report.failed_record(number, parse(&error))?;
                }
                continue;
            }
            report.base_records_examined += 1;
            match catalog(self, cx, &record, &mut work, Some(&allocated), records) {
                Ok(catalog) => {
                    // Publish ownership only after the entire catalog passes
                    // its forward and reverse identity/sequence checks.
                    for extension in catalog.extension_numbers() {
                        checkpoint(cx)?;
                        if !bit(&owned, extension) {
                            mark(&mut owned, extension);
                            report.referenced_extension_records += 1;
                        }
                    }
                }
                Err(_) if work.stopped => {
                    report.stop("metadata work budget");
                    break;
                }
                Err(error) => report.failed_record(number, error)?,
            }
        }
        report.metadata_bytes_attempted = work.used;
        if report.complete {
            let mut unowned = 0;
            for number in 0..records {
                if number.is_multiple_of(4096) { checkpoint(cx)?; }
                if bit(&extensions, number) && !bit(&owned, number) {
                    unowned += 1;
                    report.issue(number, "extension_without_owner",
                        "allocated extension is absent from every validated base catalog; not authority to reclaim it".into());
                }
            }
            report.extensions_without_owner = Some(unowned);
        }
        checkpoint(cx)?;
        Ok(report)
    }
}
