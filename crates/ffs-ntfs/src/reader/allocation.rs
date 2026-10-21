//! Read-only physical-allocation accounting for the initialized native MFT.
//!
//! Scan each $MFT::$BITMAP-allocated FILE record once, including extension
//! records, then compare every nonresident run with $Bitmap. This deliberately
//! does not walk directory names, follow hard links, read file data, or turn an
//! unexplained allocation into authority to free it. It is not journal replay
//! or a complete NTFS consistency checker.

use super::{
    Cx, FfsError, NtfsVolume, NtfsValue, Result, Storage, Stream, buffer, checkpoint,
    corrupt, decode_mapping_pairs, parse, unsupported,
};

const MAX_RECORDS: u64 = 16_777_216;
const MAX_CLUSTERS: u64 = 268_435_456;
const MAX_RUNS: usize = 1_048_576;
const MAX_ISSUES: usize = 128;
const READ_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct AllocationLimits {
    pub records: u64,
    pub clusters: u64,
    /// Includes sparse runs, even though they own no physical allocation.
    pub runs: usize,
}

impl Default for AllocationLimits {
    fn default() -> Self {
        Self {
            records: 1_048_576,
            clusters: 33_554_432,
            runs: MAX_RUNS,
        }
    }
}

impl AllocationLimits {
    pub fn validate(self) -> Result<()> {
        if !(1..=MAX_RECORDS).contains(&self.records)
            || !(1..=MAX_CLUSTERS).contains(&self.clusters)
            || !(1..=MAX_RUNS).contains(&self.runs)
        {
            return Err(FfsError::Format(
                "allocation limits require 1..=16777216 records, 1..=268435456 clusters and 1..=1048576 runs".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AllocationIssue {
    pub category: &'static str,
    pub record: Option<u64>,
    pub attribute_id: Option<u16>,
    pub other_record: Option<u64>,
    pub other_attribute_id: Option<u16>,
    pub first_cluster: Option<u64>,
    pub clusters: u64,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct AllocationReport {
    pub initialized_records: u64,
    pub logical_records: u64,
    pub volume_clusters: u64,
    pub record_slots_examined: u64,
    pub allocated_records_examined: u64,
    pub extension_records_examined: u64,
    pub attributes_examined: u64,
    pub runs_examined: u64,
    pub sparse_clusters: u64,
    /// Unique physical clusters, not a sum that double-counts cross-links.
    pub referenced_clusters: u64,
    pub bitmap_allocated_clusters: u64,
    pub bitmap_free_clusters: u64,
    pub cross_linked_clusters: u64,
    pub referenced_free_clusters: u64,
    /// None when any allocated record/mapping was unreadable or not scanned.
    /// These clusters are unexplained, not proven reclaimable orphans.
    pub allocated_without_reference: Option<u64>,
    pub complete: bool,
    pub limit_reached: Option<&'static str>,
    pub errors: u64,
    pub unsupported: u64,
    pub issues: Vec<AllocationIssue>,
    pub omitted_issues: u64,
}

impl AllocationReport {
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.complete
            && self.limit_reached.is_none()
            && self.errors == 0
            && self.unsupported == 0
            && self.allocated_without_reference == Some(0)
    }

    fn stop(&mut self, reason: &'static str) {
        self.complete = false;
        if self.limit_reached.is_none() {
            self.limit_reached = Some(reason);
        }
    }

    fn issue(&mut self, issue: AllocationIssue) {
        if issue.category == "unsupported" {
            self.unsupported += 1;
        } else {
            self.errors += 1;
        }
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(issue);
        } else {
            self.omitted_issues += 1;
        }
    }

    fn record_error(&mut self, number: u64, attribute: Option<u16>, error: FfsError) -> Result<()> {
        if matches!(error, FfsError::Cancelled) {
            return Err(FfsError::Cancelled);
        }
        self.complete = false;
        let category = match &error {
            FfsError::UnsupportedFeature(_) => "unsupported",
            FfsError::Io(_) => "io",
            _ => "record_or_mapping",
        };
        self.issue(AllocationIssue {
            category,
            record: Some(number),
            attribute_id: attribute,
            other_record: None,
            other_attribute_id: None,
            first_cluster: None,
            clusters: 0,
            detail: error.to_string().chars().take(512).collect(),
        });
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Claim {
    first: u64,
    end: u64,
    record: u64,
    attribute: u16,
}

fn bit(bytes: &[u8], index: u64) -> bool {
    bytes[index as usize / 8] & (1 << (index % 8)) != 0
}

fn read_bitmap(cx: &Cx, volume: &NtfsVolume, stream: &Stream, bits: u64) -> Result<Vec<u8>> {
    let length = bits.div_ceil(8);
    if stream.size < length || stream.initialized != stream.size {
        return Err(corrupt(0, "allocation bitmap is short or incompletely initialized"));
    }
    match &stream.storage {
        Storage::Resident(_) => (),
        Storage::Mapped(runs) if runs.iter().all(|run| run.lcn.is_some()) => (),
        _ => return Err(unsupported("allocation checking requires plain, nonsparse bitmaps")),
    }
    let length = usize::try_from(length).map_err(|_| corrupt(0, "bitmap length overflows"))?;
    let mut bytes = buffer(length)?;
    for (index, chunk) in bytes.chunks_mut(READ_BYTES).enumerate() {
        checkpoint(cx)?;
        let read = volume.read(cx, stream, (index * READ_BYTES) as u64, chunk.len())?;
        if read.len() != chunk.len() {
            return Err(corrupt(0, "short allocation bitmap read"));
        }
        chunk.copy_from_slice(&read);
    }
    checkpoint(cx)?;
    Ok(bytes)
}

impl NtfsVolume {
    /// Account for record-local physical runs without replay, repair or writes.
    /// A consistent result is NOT writable admission or a namespace/log check.
    /// Errors in the authority bitmaps fail the call; errors in individual FILE
    /// records produce an incomplete report and suppress absence conclusions.
    pub fn check_allocations(&self, cx: &Cx, limits: AllocationLimits) -> Result<AllocationReport> {
        checkpoint(cx)?;
        limits.validate()?;
        if self.volume_flags != 0 || self.logfile_recovery.is_some() || !self.source.overlay.is_empty() {
            return Err(unsupported("allocation checking requires the original clean-flag image, not a recovery overlay"));
        }
        let records = self.mft.size / u64::from(self.geometry.record_bytes());
        let clusters = self.geometry.cluster_count();
        let mut report = AllocationReport {
            initialized_records: self.record_count(),
            logical_records: records,
            volume_clusters: clusters,
            complete: true,
            ..AllocationReport::default()
        };
        // Reject excessive geometry before materializing either bitmap.
        if records > limits.records {
            report.stop("MFT record budget");
            return Ok(report);
        }
        if clusters > limits.clusters {
            report.stop("volume cluster budget");
            return Ok(report);
        }
        let mft = self.record(cx, 0, None)?;
        let mft_bitmap = self.select_stream(cx, &mft, 0xB0, &[])?;
        let allocated_records = read_bitmap(cx, self, &mft_bitmap, records)?;
        let bitmap_record = self.record(cx, 6, None)?;
        let bitmap_stream = self.select_stream(cx, &bitmap_record, super::DATA, &[])?;
        let allocated_clusters = read_bitmap(cx, self, &bitmap_stream, clusters)?;
        let mut claims = Vec::new();
        'records: for number in 0..records {
            checkpoint(cx)?;
            report.record_slots_examined += 1;
            if !bit(&allocated_records, number) {
                continue;
            }
            report.allocated_records_examined += 1;
            if number >= report.initialized_records {
                report.record_error(number, None, corrupt(0, "MFT bitmap allocates a record beyond initialized MFT data"))?;
                continue;
            }
            let record = match self.record(cx, number, None) {
                Ok(record) => record,
                Err(error) => {
                    report.record_error(number, None, error)?;
                    continue;
                }
            };
            if record.base.record != 0 || record.base.sequence != 0 {
                report.extension_records_examined += 1;
            }
            let attributes = match record.attributes() {
                Ok(attributes) => attributes,
                Err(error) => {
                    report.record_error(number, None, parse(&error))?;
                    continue;
                }
            };
            // Do not expand ATTRIBUTE_LIST here: each allocated extension is
            // visited by its own MFT bitmap bit exactly once. Resident values,
            // hard-link names and sparse runs own no separate physical clusters.
            for attr in attributes {
                checkpoint(cx)?;
                report.attributes_examined += 1;
                let NtfsValue::NonResident(value) = attr.value else { continue };
                if attr.flags & !(super::SPARSE | super::COMPRESSED | 0x4000) != 0 {
                    report.record_error(number, Some(attr.id), unsupported("unknown nonresident storage flags in allocation scan"))?;
                    continue;
                }
                let runs = match decode_mapping_pairs(value.mapping_pairs, value.first_vcn, value.last_vcn, clusters) {
                    Ok(runs) => runs,
                    Err(error) => {
                        report.record_error(number, Some(attr.id), parse(&error))?;
                        continue;
                    }
                };
                if runs.len() as u64 > limits.runs as u64 - report.runs_examined {
                    report.stop("mapping run budget");
                    break 'records;
                }
                report.runs_examined += runs.len() as u64;
                claims.try_reserve(runs.len())
                    .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
                for run in runs {
                    checkpoint(cx)?;
                    if let Some(first) = run.lcn {
                        let end = first.checked_add(run.clusters)
                            .filter(|end| *end <= clusters)
                            .ok_or_else(|| corrupt(0, "allocation claim exceeds volume"))?;
                        claims.push(Claim { first, end, record: number, attribute: attr.id });
                    } else {
                        report.sparse_clusters = report.sparse_clusters.checked_add(run.clusters)
                            .ok_or_else(|| corrupt(0, "sparse allocation accounting overflows"))?;
                    }
                }
            }
        }
        reconcile(cx, &allocated_clusters, &mut claims, &mut report)?;
        checkpoint(cx)?;
        Ok(report)
    }
}

fn span_issue(report: &mut AllocationReport, category: &'static str, first: u64, end: u64) {
    report.issue(AllocationIssue {
        category,
        record: None,
        attribute_id: None,
        other_record: None,
        other_attribute_id: None,
        first_cluster: Some(first),
        clusters: end - first,
        detail: match category {
            "referenced_free" => "a native mapping references clusters marked free by $Bitmap",
            _ => "allocated clusters have no observed reference; this is not authority to reclaim them",
        }.into(),
    });
}

/// Sorting and a sweep keep work O(runs log runs + volume clusters), even for
/// adversarial million-way overlaps. Never visit every cluster of every run.
fn reconcile(cx: &Cx, bitmap: &[u8], claims: &mut [Claim], report: &mut AllocationReport) -> Result<()> {
    checkpoint(cx)?;
    claims.sort_unstable_by_key(|claim| (claim.first, claim.end, claim.record, claim.attribute));
    checkpoint(cx)?;
    let mut farthest: Option<Claim> = None;
    let mut overlap_end = 0;
    for &claim in claims.iter() {
        checkpoint(cx)?;
        if let Some(previous) = farthest {
            let end = claim.end.min(previous.end);
            if claim.first < end {
                report.cross_linked_clusters += end.saturating_sub(claim.first.max(overlap_end));
                overlap_end = overlap_end.max(end);
                report.issue(AllocationIssue {
                    category: "cross_link",
                    record: Some(claim.record),
                    attribute_id: Some(claim.attribute),
                    other_record: Some(previous.record),
                    other_attribute_id: Some(previous.attribute),
                    first_cluster: Some(claim.first),
                    clusters: end - claim.first,
                    detail: "native mapping claims overlap; no rightful owner is selected".into(),
                });
            }
        }
        if farthest.is_none_or(|previous| claim.end > previous.end) {
            farthest = Some(claim);
        }
    }
    let mut next = 0;
    let mut covered_end = 0;
    let mut referenced_free_start = None;
    let mut unexplained_start = None;
    let mut unexplained = 0;
    for cluster in 0..report.volume_clusters {
        if cluster.is_multiple_of(4096) { checkpoint(cx)?; }
        while next < claims.len() && claims[next].first <= cluster {
            covered_end = covered_end.max(claims[next].end);
            next += 1;
        }
        let allocated = bit(bitmap, cluster);
        let referenced = cluster < covered_end;
        report.bitmap_allocated_clusters += u64::from(allocated);
        report.bitmap_free_clusters += u64::from(!allocated);
        report.referenced_clusters += u64::from(referenced);
        if referenced && !allocated {
            report.referenced_free_clusters += 1;
            referenced_free_start.get_or_insert(cluster);
        } else if let Some(first) = referenced_free_start.take() {
            span_issue(report, "referenced_free", first, cluster);
        }
        if report.complete && allocated && !referenced {
            unexplained += 1;
            unexplained_start.get_or_insert(cluster);
        } else if let Some(first) = unexplained_start.take() {
            span_issue(report, "allocated_without_reference", first, cluster);
        }
    }
    if let Some(first) = referenced_free_start {
        span_issue(report, "referenced_free", first, report.volume_clusters);
    }
    if let Some(first) = unexplained_start {
        span_issue(report, "allocated_without_reference", first, report.volume_clusters);
    }
    report.allocated_without_reference = report.complete.then_some(unexplained);
    checkpoint(cx)
}

#[cfg(test)]
mod tests;
