//! Logged hole punching without reading or rewriting untouched DATA extents.
//! LZNT1 streams retire whole compression units and COW at most two edge units.

use super::{
    EditableDataStream, EditableStreamStorage, FILE_ATTR_ENCRYPTED, FILE_ATTR_REPARSE_POINT,
    FILE_ATTR_SPARSE_FILE, MIN_USER_MFT_SLOT, NtfsTransactionEngine, NtfsTxOutcome, PreparedTxPlan,
    TxWorkspace, checkpoint, compression, corrupt, read_editable_stream_prefix,
    splice_vcn_interval, stage_runs_writes, unsupported, validate_ntfs_stream_name_utf16,
};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::usn::{
    USN_REASON_BASIC_INFO_CHANGE, USN_REASON_CLOSE, USN_REASON_DATA_OVERWRITE,
    USN_REASON_NAMED_DATA_OVERWRITE,
};
use ffs_ondisk::ntfs::{NtfsReference, NtfsRun};
use std::ops::Range;

fn invalid_range(errno: i32, detail: &'static str) -> FfsError {
    FfsError::RequestRejected {
        errno,
        detail: detail.into(),
    }
}

impl NtfsTransactionEngine {
    /// Zero a byte range and reclaim fully covered clusters without changing EOF.
    ///
    /// Empty `stream_utf16` selects unnamed DATA; a named stream uses its exact
    /// native UTF-16 identity. Resident values remain resident. Nonresident DATA
    /// becomes sparse when allocation is removed, while at most two initialized
    /// boundary clusters are copied before the native WAL publishes the result.
    /// LZNT1 streams retain compression: whole units become sparse, and at most
    /// two boundary units are decoded and recompressed with bounded buffers.
    /// `ValidDataLength`, unrelated streams and metadata remain intact. Zero length
    /// is EINVAL; ranges outside the signed native byte domain are EFBIG.
    pub fn punch_hole_at(
        &mut self,
        cx: &Cx,
        target: NtfsReference,
        stream_utf16: &[u16],
        offset: u64,
        length: u64,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        let plan = (|| {
            checkpoint(cx)?;
            self.require_clean_writer()?;
            validate_ntfs_stream_name_utf16(stream_utf16)?;
            if length == 0 {
                return Err(invalid_range(
                    libc::EINVAL,
                    "NTFS hole-punch length is zero",
                ));
            }
            let end = offset
                .checked_add(length)
                .filter(|&end| i64::try_from(end).is_ok())
                .ok_or_else(|| {
                    invalid_range(
                        libc::EFBIG,
                        "NTFS hole-punch range exceeds the signed native limit",
                    )
                })?;
            let mut digest = blake3::Hasher::new();
            digest.update(b"ntfs.punch_hole_at:");
            digest.update(&target.record.to_le_bytes());
            digest.update(&target.sequence.to_le_bytes());
            digest.update(&(stream_utf16.len() as u64).to_le_bytes());
            for unit in stream_utf16 {
                digest.update(&unit.to_le_bytes());
            }
            digest.update(&offset.to_le_bytes());
            digest.update(&length.to_le_bytes());
            digest.update(&now_ticks.to_le_bytes());
            self.plan_punch_hole(
                cx,
                target,
                stream_utf16,
                offset..end,
                now_ticks,
                *digest.finalize().as_bytes(),
            )
        })();
        match plan {
            Ok(plan)
                if plan.pre_payload_writes.is_empty()
                    && plan.mft_zero_writes.is_empty()
                    && plan.open_attr_registrations.is_empty()
                    && plan.mutation_specs.is_empty()
                    && plan.target_writes.is_empty() =>
            {
                // The planner has checked the target sequence, complete
                // stream and transform/provider semantics. An admitted range
                // past EOF changes nothing, including $LogFile. Preserve the
                // current clean authority without initializing a journal or
                // issuing a barrier for an empty transaction.
                if let Err(error) = checkpoint(cx).and_then(|()| self.require_clean_writer()) {
                    return NtfsTxOutcome::NotCommitted(error);
                }
                let current_lsn = self
                    .ring
                    .as_ref()
                    .map_or(1, |ring| ring.current_lsn().max(1));
                let checkpoint_lsn = self
                    .ring
                    .as_ref()
                    .map(ffs_ondisk::ntfs::logfile_writer::NtfsLogRingWriter::client_restart_lsn);
                let token = self.make_token(0, current_lsn, checkpoint_lsn, plan.operation_digest);
                NtfsTxOutcome::Committed { value: (), token }
            }
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    fn plan_punch_hole(
        &self,
        cx: &Cx,
        target: NtfsReference,
        stream_utf16: &[u16],
        mut range: Range<u64>,
        now_ticks: u64,
        digest: [u8; 32],
    ) -> Result<PreparedTxPlan<()>> {
        let mut ws = TxWorkspace::load(self, cx)?;
        let catalog = ws.load_catalog(self, cx, target)?.clone();
        if catalog.is_directory {
            return Err(FfsError::IsDirectory);
        }
        if target.record < MIN_USER_MFT_SLOT {
            return Err(FfsError::PermissionDenied);
        }
        // A provider's unnamed DATA may only be a placeholder, and an EFS
        // file can carry encryption authority outside its DATA header. Do not
        // acknowledge raw edits as logical hole punching in either case.
        if stream_utf16.is_empty() {
            if catalog.std_flags() & FILE_ATTR_ENCRYPTED != 0 {
                return Err(unsupported("cannot punch hole in an encrypted NTFS file"));
            }
            if catalog.reparse_point.is_some() || catalog.std_flags() & FILE_ATTR_REPARSE_POINT != 0
            {
                return Err(unsupported("cannot punch hole in an NTFS reparse point"));
            }
        }
        let stream_index = catalog
            .data_streams
            .iter()
            .position(|stream| stream.name == stream_utf16)
            .ok_or_else(|| FfsError::NotFound("NTFS exact DATA stream not found".into()))?;
        let stream = &catalog.data_streams[stream_index];
        if let EditableStreamStorage::NonResident {
            compressed,
            encrypted,
            compression_unit,
            sparse,
            ..
        } = &stream.storage
        {
            if *encrypted {
                return Err(unsupported(
                    "punch_hole is not supported on encrypted NTFS streams",
                ));
            }
            if *compressed {
                compression::check_lznt1_geometry(&self.geometry)?;
                if *compression_unit != compression::COMPRESSION_UNIT_SHIFT {
                    return Err(unsupported(
                        "unsupported NTFS LZNT1 compression-unit encoding",
                    ));
                }
                // Full-unit removal and ranges past EOF need no payload decode,
                // so admit the complete compressed mapping before either fast
                // path can bypass the ordinary reader's extent/unit checks.
                let volume = self.volume_view(cx)?;
                let record = volume.record(cx, target.record, Some(target.sequence))?;
                let _ = volume.data_stream(cx, &record, stream_utf16)?;
            } else if *compression_unit != 0 && !(*sparse && *compression_unit == 4) {
                return Err(unsupported(
                    "unsupported NTFS sparse compression-unit encoding",
                ));
            }
        }
        range.end = range.end.min(stream.logical_size());
        if range.start >= range.end {
            // Still resolve the sequence and stream before acknowledging a
            // range past EOF. No catalog repack or allocation is needed.
            return Ok(PreparedTxPlan {
                operation: "punch_hole_at",
                operation_digest: digest,
                result_value: (),
                pre_payload_writes: Vec::new(),
                mft_zero_writes: Vec::new(),
                open_attr_registrations: Vec::new(),
                mutation_specs: Vec::new(),
                target_writes: Vec::new(),
            });
        }
        let storage = match &stream.storage {
            EditableStreamStorage::Resident(bytes) => {
                let mut bytes = bytes.clone();
                bytes[range.start as usize..range.end as usize].fill(0);
                EditableStreamStorage::Resident(bytes)
            }
            EditableStreamStorage::NonResident { .. } => {
                punch_nonresident(self, cx, &mut ws, stream, &range)?
            }
        };
        let sparse = matches!(
            &storage,
            EditableStreamStorage::NonResident { sparse: true, .. }
        );
        let mut reason = if stream_utf16.is_empty() {
            USN_REASON_DATA_OVERWRITE
        } else {
            USN_REASON_NAMED_DATA_OVERWRITE
        } | USN_REASON_CLOSE;
        let usn_snapshot = {
            let catalog = ws.catalog_mut(self, cx, target)?;
            catalog.data_streams[stream_index].storage = storage;
            // Native FILE flags describe unnamed DATA, not independent ADS flags.
            // Preserve an existing sparse bit even if a resident value was edited.
            if stream_utf16.is_empty() && sparse {
                if catalog.std_flags() & FILE_ATTR_SPARSE_FILE == 0 {
                    reason |= USN_REASON_BASIC_INFO_CHANGE;
                }
                catalog.set_std_flags(catalog.std_flags() | FILE_ATTR_SPARSE_FILE);
            }
            catalog.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
            catalog.clone()
        };
        // Finalization publishes the data change, journal record, and target
        // STANDARD_INFORMATION.usn in the same logged native transaction.
        ws.push_usn_event_for_catalog(&usn_snapshot, reason, now_ticks);
        ws.sync_target_into_parent_dirs(self, cx, target)?;
        ws.finalize(self, cx, "punch_hole_at", digest, ())
    }
}

fn punch_nonresident(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    ws: &mut TxWorkspace,
    stream: &EditableDataStream,
    range: &Range<u64>,
) -> Result<EditableStreamStorage> {
    let EditableStreamStorage::NonResident {
        runs,
        sparse,
        compressed,
        compression_unit,
        data_bytes,
        initialized_bytes,
        ..
    } = &stream.storage
    else {
        return Err(corrupt(0, "hole-punch source is not nonresident"));
    };
    let cb = u64::from(engine.geometry.cluster_bytes());
    if *data_bytes > i64::MAX as u64
        || runs
            .last()
            .is_some_and(|run| run.vcn + run.clusters > i64::MAX as u64 / cb)
    {
        return Err(invalid_range(
            libc::EFBIG,
            "NTFS DATA exceeds the signed native limit",
        ));
    }
    if *compressed {
        return punch_compressed(engine, cx, ws, stream, range);
    }
    let mut working = runs.clone();
    let full_start = range.start.div_ceil(cb);
    let full_end = range.end / cb;
    if full_start < full_end {
        let (next, retired) = splice_vcn_interval(&working, full_start, full_end, &[], true)?;
        working = next;
        ws.free_clusters_deferred(&retired);
    }
    let first = range.start / cb;
    let last = (range.end - 1) / cb;
    clear_boundary_cluster(engine, cx, ws, stream, &mut working, range, first)?;
    if last != first {
        clear_boundary_cluster(engine, cx, ws, stream, &mut working, range, last)?;
    }
    let sparse = *sparse || working.iter().any(|run| run.lcn.is_none());
    Ok(EditableStreamStorage::NonResident {
        runs: working,
        sparse,
        compressed: false,
        encrypted: false,
        compression_unit: *compression_unit,
        data_bytes: *data_bytes,
        initialized_bytes: *initialized_bytes,
    })
}

fn punch_compressed(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    ws: &mut TxWorkspace,
    stream: &EditableDataStream,
    range: &Range<u64>,
) -> Result<EditableStreamStorage> {
    let EditableStreamStorage::NonResident {
        runs,
        sparse,
        compression_unit,
        data_bytes,
        initialized_bytes,
        ..
    } = &stream.storage
    else {
        return Err(corrupt(
            0,
            "compressed hole-punch source is not nonresident",
        ));
    };
    let unit_bytes = compression::UNIT_CLUSTERS * u64::from(engine.geometry.cluster_bytes());
    let mut working = runs.clone();
    let full_start = range.start.div_ceil(unit_bytes);
    let full_end = range.end / unit_bytes;
    if full_start < full_end {
        // Work is proportional to the runlist, never to the logical range: a
        // multi-terabyte sparse interval needs just one replacement run. A
        // compressed prefix and its sparse padding must always retire together.
        let replacement = vec![NtfsRun {
            vcn: full_start * compression::UNIT_CLUSTERS,
            clusters: (full_end - full_start) * compression::UNIT_CLUSTERS,
            lcn: None,
        }];
        let (next, retired) =
            compression::splice_compressed_units(&working, full_start, full_end, replacement);
        working = next;
        ws.free_clusters_deferred(&retired);
    }
    let first = range.start / unit_bytes;
    let last = (range.end - 1) / unit_bytes;
    clear_boundary_compression_unit(engine, cx, ws, stream, &mut working, range, first)?;
    if last != first {
        clear_boundary_compression_unit(engine, cx, ws, stream, &mut working, range, last)?;
    }
    Ok(EditableStreamStorage::NonResident {
        runs: working,
        // Sparse compression padding is not the independent SPARSE attribute.
        // Preserve the native stream flags instead of changing file policy.
        sparse: *sparse,
        compressed: true,
        encrypted: false,
        compression_unit: *compression_unit,
        data_bytes: *data_bytes,
        initialized_bytes: *initialized_bytes,
    })
}

fn clear_boundary_compression_unit(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    ws: &mut TxWorkspace,
    stream: &EditableDataStream,
    working: &mut Vec<NtfsRun>,
    range: &Range<u64>,
    unit: u64,
) -> Result<()> {
    let EditableStreamStorage::NonResident {
        runs,
        initialized_bytes,
        ..
    } = &stream.storage
    else {
        return Err(corrupt(
            0,
            "compressed hole-punch boundary is not nonresident",
        ));
    };
    let unit_bytes = compression::UNIT_CLUSTERS * u64::from(engine.geometry.cluster_bytes());
    let start = unit * unit_bytes;
    let end = start + unit_bytes;
    if start >= *initialized_bytes || (range.start <= start && range.end >= end) {
        return Ok(());
    }
    // Always decode from the original mapping. Earlier planned COW payloads
    // are not written yet, and the two boundary units never overlap.
    let mut bytes =
        compression::read_compressed_unit_plaintext(engine, cx, runs, *initialized_bytes, unit)?;
    let from = (range.start.max(start) - start) as usize;
    let to = (range.end.min(end) - start) as usize;
    if bytes[from..to].iter().all(|&byte| byte == 0) {
        return Ok(());
    }
    bytes[from..to].fill(0);
    let mut pre = Vec::new();
    let replacement = compression::encode_compressed_unit_cow(
        &engine.geometry,
        unit,
        &bytes,
        &mut pre,
        |count| ws.alloc_clusters(count, 1),
    )?;
    ws.pre_payload_writes.extend(pre);
    let (next, retired) =
        compression::splice_compressed_units(working, unit, unit + 1, replacement);
    *working = next;
    ws.free_clusters_deferred(&retired);
    Ok(())
}

fn clear_boundary_cluster(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    ws: &mut TxWorkspace,
    stream: &EditableDataStream,
    working: &mut Vec<NtfsRun>,
    range: &Range<u64>,
    vcn: u64,
) -> Result<()> {
    let EditableStreamStorage::NonResident {
        initialized_bytes, ..
    } = &stream.storage
    else {
        return Err(corrupt(0, "hole-punch boundary is not nonresident"));
    };
    let cb = u64::from(engine.geometry.cluster_bytes());
    let start = vcn * cb;
    let end = start + cb;
    if start >= *initialized_bytes || (range.start <= start && range.end >= end) {
        return Ok(());
    }
    let run = working
        .iter()
        .find(|run| run.vcn <= vcn && vcn - run.vcn < run.clusters)
        .ok_or_else(|| corrupt(start, "missing NTFS hole-punch boundary mapping"))?;
    if run.lcn.is_none() {
        return Ok(());
    }
    let mut bytes = read_editable_stream_prefix(engine, cx, stream, start, cb as usize)?;
    let from = (range.start.max(start) - start) as usize;
    let to = (range.end.min(end) - start) as usize;
    if bytes[from..to].iter().all(|&byte| byte == 0) {
        return Ok(());
    }
    bytes[from..to].fill(0);
    let spans = ws.alloc_clusters(1, 1)?;
    let staged = [NtfsRun {
        vcn: 0,
        clusters: 1,
        lcn: Some(spans[0].0),
    }];
    stage_runs_writes(
        &engine.geometry,
        &staged,
        &bytes,
        &mut ws.pre_payload_writes,
    )?;
    let (next, retired) = splice_vcn_interval(working, vcn, vcn + 1, &spans, true)?;
    *working = next;
    ws.free_clusters_deferred(&retired);
    Ok(())
}
