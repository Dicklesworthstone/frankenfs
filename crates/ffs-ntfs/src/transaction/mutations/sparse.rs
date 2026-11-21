//! Logged hole punching without reading or rewriting untouched DATA extents.

use super::{
    EditableDataStream, EditableStreamStorage, MIN_USER_MFT_SLOT, NtfsTransactionEngine,
    NtfsTxOutcome, PreparedTxPlan, TxWorkspace, checkpoint, corrupt, read_editable_stream_prefix,
    splice_vcn_interval, stage_runs_writes, unsupported, validate_ntfs_stream_name_utf16,
};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::{NtfsReference, NtfsRun};
use std::ops::Range;

const FILE_ATTR_SPARSE_FILE: u32 = 0x0000_0200;

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
        let stream_index = catalog
            .data_streams
            .iter()
            .position(|stream| stream.name == stream_utf16)
            .ok_or_else(|| FfsError::NotFound("NTFS exact DATA stream not found".into()))?;
        let stream = &catalog.data_streams[stream_index];
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
        let catalog = ws.catalog_mut(self, cx, target)?;
        catalog.data_streams[stream_index].storage = storage;
        // Native FILE flags describe unnamed DATA, not independent ADS flags.
        // Preserve an existing sparse bit even if a resident value was edited.
        if stream_utf16.is_empty() && sparse {
            catalog.set_std_flags(catalog.std_flags() | FILE_ATTR_SPARSE_FILE);
        }
        catalog.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
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
        compression_unit,
        data_bytes,
        initialized_bytes,
    } = &stream.storage
    else {
        return Err(corrupt(0, "hole-punch source is not nonresident"));
    };
    if *compression_unit != 0 && !(*sparse && *compression_unit == 4) {
        return Err(unsupported(
            "unsupported NTFS sparse compression-unit encoding",
        ));
    }
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
        compression_unit: *compression_unit,
        data_bytes: *data_bytes,
        initialized_bytes: *initialized_bytes,
    })
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
