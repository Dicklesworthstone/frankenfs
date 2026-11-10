//! Read-only comparison of the native $MFTMirr stream with its MFT prefix.
//!
//! The first four records are the recovery bootstrap. Later mirrored records
//! can differ on Windows volumes with large clusters; report those differences
//! separately, without selecting a repair source or granting write authority.

use super::ownership::{Work, catalog};
use super::{
    AllocationIssue, Cx, FfsError, MAX_ISSUES, NtfsVolume, RecordOwnershipLimits, Result, Storage,
    Stream, bit, checkpoint, corrupt, parse, read_bitmap, unsupported,
};
use crate::reader::{DATA, NtfsFileRecord, validate_identity};

const REQUIRED_RECORDS: u64 = 4;

#[derive(Debug, Default)]
pub struct MftMirrorReport {
    pub declared_records: u64,
    pub record_pairs_examined: u64,
    pub matching_records: u64,
    pub different_records: u64,
    /// Differences after record 3 are reported without assuming that Windows
    /// keeps the larger mirror tail synchronized on every update.
    pub extended_record_differences: u64,
    /// Unknown until all four required records have been compared successfully.
    pub required_prefix_matches: Option<bool>,
    pub metadata_bytes_attempted: u64,
    pub complete: bool,
    pub limit_reached: Option<&'static str>,
    pub errors: u64,
    pub unsupported: u64,
    pub issues: Vec<AllocationIssue>,
    pub omitted_issues: u64,
}

impl MftMirrorReport {
    /// True only for a completely inspected, equal native mirror. A difference
    /// is not evidence of which copy is correct, or authority to repair either.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.complete
            && self.limit_reached.is_none()
            && self.errors == 0
            && self.unsupported == 0
            && self.different_records == 0
            && self.required_prefix_matches == Some(true)
            && self.record_pairs_examined == self.declared_records
    }

    fn issue(&mut self, number: u64, category: &'static str, detail: String) {
        if category == "unsupported" {
            self.unsupported += 1;
        } else if category != "extended_mirror_difference" {
            self.errors += 1;
        }
        if self.issues.len() == MAX_ISSUES {
            self.omitted_issues += 1;
            return;
        }
        self.issues.push(AllocationIssue {
            category,
            record: Some(number),
            attribute_id: None,
            other_record: None,
            other_attribute_id: None,
            first_cluster: None,
            clusters: 0,
            detail: detail.chars().take(512).collect(),
        });
    }

    fn failed(&mut self, number: u64, error: FfsError) -> Result<()> {
        if matches!(error, FfsError::Cancelled) {
            return Err(error);
        }
        self.complete = false;
        let category = match &error {
            FfsError::UnsupportedFeature(_) => "unsupported",
            FfsError::Io(_) => "io",
            _ => "mirror_metadata",
        };
        self.issue(number, category, error.to_string());
        Ok(())
    }

    fn stop(&mut self, reason: &'static str) {
        self.complete = false;
        self.limit_reached = Some(reason);
    }
}

/// Compare logical used bytes after USA validation. The USA is transport
/// protection: its token and copies of unused trailers are not file metadata.
/// Restored trailers still participate wherever they lie within the used bytes.
fn same_record(primary: &NtfsFileRecord, mirror: &NtfsFileRecord) -> bool {
    let left = primary.used_bytes();
    let right = mirror.used_bytes();
    let usa = usize::from(u16::from_le_bytes([left[4], left[5]]));
    let usa_end = usa + 2 * usize::from(u16::from_le_bytes([left[6], left[7]]));
    left.len() == right.len() && left[..usa] == right[..usa] && left[usa_end..] == right[usa_end..]
}

fn mirror_stream(volume: &NtfsVolume, stream: &Stream) -> Result<()> {
    let record_bytes = u64::from(volume.geometry.record_bytes());
    if stream.size < REQUIRED_RECORDS * record_bytes
        || !stream.size.is_multiple_of(record_bytes)
        || stream.initialized != stream.size
        || stream.size > volume.mft.initialized
    {
        return Err(corrupt(
            0,
            "$MFTMirr must contain at least four complete initialized records within the MFT",
        ));
    }
    let Storage::Mapped(runs) = &stream.storage else {
        return Err(unsupported("$MFTMirr requires plain nonresident storage"));
    };
    let Storage::Mapped(mft_runs) = &volume.mft.storage else {
        return Err(corrupt(0, "MFT bootstrap has no physical mappings"));
    };
    let mut mirror_spans = Vec::with_capacity(runs.len());
    let first_record_clusters = record_bytes.div_ceil(u64::from(volume.geometry.cluster_bytes()));
    for run in runs {
        let first = run
            .lcn
            .ok_or_else(|| corrupt(0, "$MFTMirr contains a sparse mapping"))?;
        let end = first
            .checked_add(run.clusters)
            .ok_or_else(|| corrupt(0, "$MFTMirr physical extent overflow"))?;
        if run.vcn < first_record_clusters
            && Some(first) != volume.geometry.mirror_cluster().checked_add(run.vcn)
        {
            return Err(corrupt(
                0,
                "$MFTMirr record-zero mapping disagrees with the boot mirror location",
            ));
        }
        mirror_spans.push((first, end));
    }
    mirror_spans.sort_unstable();
    if mirror_spans.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(corrupt(0, "$MFTMirr aliases its own physical storage"));
    }
    for run in mft_runs {
        let Some(first) = run.lcn else {
            return Err(corrupt(0, "MFT bootstrap contains a sparse mapping"));
        };
        let end = first
            .checked_add(run.clusters)
            .ok_or_else(|| corrupt(0, "MFT physical extent overflow"))?;
        let candidate = mirror_spans.partition_point(|&(_, end)| end <= first);
        if mirror_spans
            .get(candidate)
            .is_some_and(|&(start, _)| start < end)
        {
            return Err(corrupt(0, "$MFTMirr aliases primary MFT storage"));
        }
    }
    Ok(())
}

fn select_mirror(volume: &NtfsVolume, cx: &Cx, work: &mut Work, records: u64) -> Result<Stream> {
    let record_bytes = u64::from(volume.geometry.record_bytes());
    work.reserve(record_bytes)?;
    let mft = volume.record(cx, 0, None)?;
    let attrs = catalog(volume, cx, &mft, work, None, records)?;
    let bitmap = attrs.select(&volume.geometry, 0xB0, &[])?;
    work.reserve(records.div_ceil(8))?;
    let allocated = read_bitmap(cx, volume, &bitmap, records)?;
    if records < REQUIRED_RECORDS || (0..REQUIRED_RECORDS).any(|number| !bit(&allocated, number)) {
        return Err(corrupt(
            0,
            "MFT bitmap does not allocate all four bootstrap records",
        ));
    }
    work.reserve(record_bytes)?;
    let record = volume.record(cx, 1, None)?;
    if record.is_directory() {
        return Err(corrupt(0, "$MFTMirr is a directory"));
    }
    let attrs = catalog(volume, cx, &record, work, Some(&allocated), records)?;
    for attr in attrs.all()? {
        if attr.kind == DATA && attr.name.is_empty() && attr.flags != 0 {
            return Err(unsupported("transformed $MFTMirr DATA is not admitted"));
        }
    }
    let stream = attrs.select(&volume.geometry, DATA, &[])?;
    mirror_stream(volume, &stream)?;
    Ok(stream)
}

fn record_pair(
    volume: &NtfsVolume,
    cx: &Cx,
    stream: &Stream,
    number: u64,
) -> Result<(NtfsFileRecord, NtfsFileRecord)> {
    let record_bytes = volume.geometry.record_bytes() as usize;
    let offset = number * record_bytes as u64;
    let left = volume.read(cx, &volume.mft, offset, record_bytes)?;
    let right = volume.read(cx, stream, offset, record_bytes)?;
    if left.len() != record_bytes || right.len() != record_bytes {
        return Err(corrupt(offset, "short MFT mirror record pair"));
    }
    let primary = NtfsFileRecord::parse(&left).map_err(|error| parse(&error))?;
    let mirror = NtfsFileRecord::parse(&right).map_err(|error| parse(&error))?;
    if number < REQUIRED_RECORDS {
        validate_identity(&primary, number, None)?;
        validate_identity(&mirror, number, None)?;
    }
    Ok((primary, mirror))
}

impl NtfsVolume {
    /// Compare every declared $MFTMirr record through its native attribute map.
    /// The caller must retain an offline, immutable original source. This does
    /// not inspect the log, repair either copy, or establish writer admission.
    /// `records` limits the volume's logical MFT slots, as in the other checks;
    /// `metadata_bytes` independently bounds all checker reads/catalog work.
    pub fn check_mft_mirror(
        &self,
        cx: &Cx,
        limits: RecordOwnershipLimits,
    ) -> Result<MftMirrorReport> {
        checkpoint(cx)?;
        limits.validate()?;
        if self.volume_flags != 0
            || self.logfile_recovery.is_some()
            || !self.source.overlay.is_empty()
        {
            return Err(unsupported(
                "MFT mirror checking requires original clean-flag bytes without a recovery overlay",
            ));
        }
        let record_bytes = u64::from(self.geometry.record_bytes());
        let records = self.mft.size / record_bytes;
        let mut report = MftMirrorReport {
            complete: true,
            ..MftMirrorReport::default()
        };
        if records > limits.records {
            report.stop("MFT record budget");
            return Ok(report);
        }
        let mut work = Work {
            used: 0,
            limit: limits.metadata_bytes,
            stopped: false,
        };
        let selected = select_mirror(self, cx, &mut work, records);
        let stream = match selected {
            Ok(stream) => stream,
            Err(_) if work.stopped => {
                report.stop("metadata work budget");
                report.metadata_bytes_attempted = work.used;
                checkpoint(cx)?;
                return Ok(report);
            }
            Err(error) => {
                report.failed(1, error)?;
                report.metadata_bytes_attempted = work.used;
                checkpoint(cx)?;
                return Ok(report);
            }
        };
        report.declared_records = stream.size / record_bytes;
        let mut required_compared = 0;
        let mut required_equal = true;
        for number in 0..report.declared_records {
            checkpoint(cx)?;
            // Reserve both copies before reading either: a truncated budget
            // cannot accidentally certify one unpaired copy.
            if work.reserve(2 * record_bytes).is_err() {
                report.stop("metadata work budget");
                break;
            }
            let pair = record_pair(self, cx, &stream, number);
            match pair {
                Ok((primary, mirror)) => {
                    report.record_pairs_examined += 1;
                    let equal = same_record(&primary, &mirror);
                    if number < REQUIRED_RECORDS {
                        required_compared += 1;
                        required_equal &= equal;
                    }
                    if equal {
                        report.matching_records += 1;
                    } else {
                        report.different_records += 1;
                        let category = if number < REQUIRED_RECORDS {
                            "required_mirror_difference"
                        } else {
                            report.extended_record_differences += 1;
                            "extended_mirror_difference"
                        };
                        report.issue(number, category, format!(
                            "MFT and $MFTMirr record {number} have different used metadata; neither copy is selected for recovery"
                        ));
                    }
                }
                Err(error) => report.failed(number, error)?,
            }
        }
        if required_compared == REQUIRED_RECORDS {
            report.required_prefix_matches = Some(required_equal);
        }
        report.metadata_bytes_attempted = work.used;
        checkpoint(cx)?;
        Ok(report)
    }
}
