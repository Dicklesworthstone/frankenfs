//! Transactional COW writers for native NTFS LZNT1 compressed streams
//! (`FILE_ATTRIBUTE_COMPRESSED`, 16-cluster compression units) and WOF
//! decompression-on-write materialization.

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::lznt1::{compress_unit, decompress_unit};
use ffs_ondisk::ntfs::{NtfsGeometry, NtfsRun};

use super::catalog::{
    EditableStreamStorage, normalize_ntfs_runs, physical_spans_of_runs, stage_runs_writes,
};
use super::dir_index::DirPrePayloadWrite;
use super::ops::MAX_RESIDENT_DATA_PAYLOAD;
use super::{NtfsTransactionEngine, checkpoint, corrupt, parse_err, unsupported};

pub(super) const COMPRESSION_UNIT_SHIFT: u16 = 4;
pub(super) const UNIT_CLUSTERS: u64 = 16;

/// Ensure this volume's cluster geometry supports native NTFS LZNT1 compression
/// (`cluster_bytes <= 4096`).
pub(super) fn check_lznt1_geometry(geometry: &NtfsGeometry) -> Result<()> {
    if geometry.cluster_bytes() > 4096 {
        return Err(unsupported(
            "native NTFS LZNT1 compression requires cluster size <= 4 KiB",
        ));
    }
    Ok(())
}

/// Extract all physical runs and total logical span belonging to 16-cluster
/// compression unit `unit_index` (`vcn = unit_index * 16 .. (unit_index + 1) * 16`).
fn extract_unit_runs(runs: &[NtfsRun], unit_index: u64) -> Result<(Vec<NtfsRun>, u64)> {
    let start_vcn = unit_index
        .checked_mul(UNIT_CLUSTERS)
        .ok_or_else(|| corrupt(0, "compression unit VCN overflow"))?;
    let end_vcn = start_vcn + UNIT_CLUSTERS;
    let mut phys = Vec::new();
    let mut covered = 0_u64;
    let mut saw_sparse = false;

    for run in runs {
        let r_start = run.vcn;
        let r_end = run.vcn + run.clusters;
        if r_end <= start_vcn {
            continue;
        }
        if r_start >= end_vcn {
            break;
        }
        let ov_start = r_start.max(start_vcn);
        let ov_end = r_end.min(end_vcn);
        let cnt = ov_end - ov_start;
        if let Some(base_lcn) = run.lcn {
            if saw_sparse {
                return Err(corrupt(
                    0,
                    "physical cluster follows sparse suffix inside LZNT1 unit",
                ));
            }
            phys.push(NtfsRun {
                vcn: covered,
                clusters: cnt,
                lcn: Some(base_lcn + (ov_start - r_start)),
            });
        } else {
            saw_sparse = true;
        }
        covered += cnt;
    }
    Ok((phys, covered))
}

/// Decode one 16-cluster compression unit `unit_index` to its full logical
/// `unit_bytes` (`16 * cluster_bytes`) plaintext buffer, zero-filling unmapped
/// or uninitialized tail bytes.
pub(super) fn read_compressed_unit_plaintext(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    runs: &[NtfsRun],
    initialized_bytes: u64,
    unit_index: u64,
) -> Result<Vec<u8>> {
    checkpoint(cx)?;
    check_lznt1_geometry(&engine.geometry)?;
    let cb = u64::from(engine.geometry.cluster_bytes());
    let unit_bytes = (UNIT_CLUSTERS * cb) as usize;
    let unit_byte_start = unit_index
        .checked_mul(unit_bytes as u64)
        .ok_or_else(|| corrupt(0, "compression unit byte offset overflow"))?;
    let mut out = vec![0_u8; unit_bytes];
    if unit_byte_start >= initialized_bytes {
        return Ok(out);
    }

    let (phys_runs, covered_clusters) = extract_unit_runs(runs, unit_index)?;
    let phys_clusters: u64 = phys_runs.iter().map(|r| r.clusters).sum();
    if phys_clusters == 0 || covered_clusters == 0 {
        // Wholly sparse unit -> all zeros.
        return Ok(out);
    }
    let stored_bytes = (phys_clusters * cb) as usize;
    let raw_stored = super::read_mapped_runs(
        &engine.device,
        cx,
        &engine.geometry,
        &phys_runs,
        0,
        stored_bytes,
    )?;

    if phys_clusters == covered_clusters {
        // Uncompressed literal unit (either full 16 clusters or raw partial final unit).
        let valid = initialized_bytes
            .saturating_sub(unit_byte_start)
            .min(stored_bytes as u64) as usize;
        out[..valid].copy_from_slice(&raw_stored[..valid]);
        return Ok(out);
    }

    // Compressed prefix (< 16 physical clusters followed by sparse suffix).
    let decoded = decompress_unit(&raw_stored, unit_bytes).map_err(|err| parse_err(&err))?;
    let required = initialized_bytes
        .saturating_sub(unit_byte_start)
        .min(unit_bytes as u64) as usize;
    if decoded.len() < required {
        return Err(corrupt(
            unit_byte_start,
            "LZNT1 compressed unit ended before initialized_bytes",
        ));
    }
    out[..required].copy_from_slice(&decoded[..required]);
    Ok(out)
}

/// Encode one full 16-cluster `logical_unit` (`len == 16 * cluster_bytes`) via COW:
/// - All-zero unit -> pure 16-cluster sparse run (`lcn = None`, zero clusters allocated).
/// - Compressible unit (`compressed_clusters < 16`) -> allocate `compressed_clusters`,
///   stage LZNT1 bytes, append `(16 - compressed_clusters)` sparse suffix run.
/// - Incompressible unit (`compressed_clusters >= 16`) -> allocate 16 clusters and
///   stage literal raw bytes.
pub(super) fn encode_compressed_unit_cow<FAlloc>(
    geometry: &NtfsGeometry,
    unit_index: u64,
    logical_unit: &[u8],
    pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
    mut alloc_clusters: FAlloc,
) -> Result<Vec<NtfsRun>>
where
    FAlloc: FnMut(u64) -> Result<Vec<(u64, u64)>>,
{
    check_lznt1_geometry(geometry)?;
    let cb = u64::from(geometry.cluster_bytes());
    let unit_bytes = (UNIT_CLUSTERS * cb) as usize;
    if logical_unit.len() != unit_bytes {
        return Err(corrupt(
            0,
            "LZNT1 unit buffer length disagrees with 16 clusters",
        ));
    }
    let base_vcn = unit_index
        .checked_mul(UNIT_CLUSTERS)
        .ok_or_else(|| corrupt(0, "LZNT1 unit VCN overflow"))?;

    // All-zero unit -> pure 16-cluster sparse run.
    if logical_unit.iter().all(|&b| b == 0) {
        return Ok(vec![NtfsRun {
            vcn: base_vcn,
            clusters: UNIT_CLUSTERS,
            lcn: None,
        }]);
    }

    let packed = compress_unit(logical_unit).map_err(|err| parse_err(&err))?;
    let packed_clusters = (packed.len() as u64).div_ceil(cb);

    if packed_clusters < UNIT_CLUSTERS {
        let spans = alloc_clusters(packed_clusters)?;
        let mut phys_runs = Vec::with_capacity(spans.len());
        let mut cur_vcn = 0_u64;
        for &(lcn, cnt) in &spans {
            phys_runs.push(NtfsRun {
                vcn: cur_vcn,
                clusters: cnt,
                lcn: Some(lcn),
            });
            cur_vcn += cnt;
        }
        let mut padded = vec![0_u8; (packed_clusters * cb) as usize];
        padded[..packed.len()].copy_from_slice(&packed);
        stage_runs_writes(geometry, &phys_runs, &padded, pre_payload_writes)?;

        let mut unit_runs = Vec::with_capacity(phys_runs.len() + 1);
        let mut vcn = base_vcn;
        for r in phys_runs {
            unit_runs.push(NtfsRun {
                vcn,
                clusters: r.clusters,
                lcn: r.lcn,
            });
            vcn += r.clusters;
        }
        unit_runs.push(NtfsRun {
            vcn,
            clusters: UNIT_CLUSTERS - packed_clusters,
            lcn: None,
        });
        Ok(unit_runs)
    } else {
        let spans = alloc_clusters(UNIT_CLUSTERS)?;
        let mut stage_runs = Vec::with_capacity(spans.len());
        let mut cur_vcn = 0_u64;
        for &(lcn, cnt) in &spans {
            stage_runs.push(NtfsRun {
                vcn: cur_vcn,
                clusters: cnt,
                lcn: Some(lcn),
            });
            cur_vcn += cnt;
        }
        stage_runs_writes(geometry, &stage_runs, logical_unit, pre_payload_writes)?;

        let mut unit_runs = Vec::with_capacity(stage_runs.len());
        let mut vcn = base_vcn;
        for r in stage_runs {
            unit_runs.push(NtfsRun {
                vcn,
                clusters: r.clusters,
                lcn: r.lcn,
            });
            vcn += r.clusters;
        }
        Ok(unit_runs)
    }
}

/// Splice newly encoded runs for compression unit range `[first_unit .. end_unit)` into
/// `old_runs`, padding any preceding gap with 16-cluster sparse units and returning
/// `(normalized_runs, displaced_physical_spans)`.
pub(super) fn splice_compressed_units(
    old_runs: &[NtfsRun],
    first_unit: u64,
    end_unit: u64,
    replacement_runs: Vec<NtfsRun>,
) -> (Vec<NtfsRun>, Vec<(u64, u64)>) {
    let start_vcn = first_unit * UNIT_CLUSTERS;
    let end_vcn = end_unit * UNIT_CLUSTERS;
    let mut prefix = Vec::new();
    let mut suffix = Vec::new();
    let mut displaced = Vec::new();

    for run in old_runs {
        let r_start = run.vcn;
        let r_end = run.vcn + run.clusters;
        if r_start < start_vcn {
            let keep = r_end.min(start_vcn) - r_start;
            prefix.push(NtfsRun {
                vcn: r_start,
                clusters: keep,
                lcn: run.lcn,
            });
        }
        let ov_start = r_start.max(start_vcn);
        let ov_end = r_end.min(end_vcn);
        if ov_start < ov_end
            && let Some(base_lcn) = run.lcn
        {
            displaced.push((base_lcn + (ov_start - r_start), ov_end - ov_start));
        }
        if r_end > end_vcn {
            let tail_start = r_start.max(end_vcn);
            let cnt = r_end - tail_start;
            let lcn = run.lcn.map(|b| b + (tail_start - r_start));
            suffix.push(NtfsRun {
                vcn: tail_start,
                clusters: cnt,
                lcn,
            });
        }
    }

    let prefix_cov: u64 = prefix.iter().map(|r| r.clusters).sum();
    if prefix_cov < start_vcn {
        prefix.push(NtfsRun {
            vcn: prefix_cov,
            clusters: start_vcn - prefix_cov,
            lcn: None,
        });
    }
    prefix.extend(replacement_runs);
    prefix.extend(suffix);
    (
        normalize_ntfs_runs(prefix),
        super::catalog::coalesce_physical_spans(displaced),
    )
}

/// Apply a positioned write `[offset .. offset + data.len())` to a compressed
/// (`COMPRESSED`) non-resident stream via COW 16-cluster unit recompression.
#[allow(clippy::too_many_arguments)]
pub(super) fn rewrite_compressed_stream_range<FAlloc>(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    old_runs: &[NtfsRun],
    old_size: u64,
    old_init: u64,
    offset: u64,
    data: &[u8],
    pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
    mut alloc_clusters: FAlloc,
) -> Result<(EditableStreamStorage, Vec<(u64, u64)>)>
where
    FAlloc: FnMut(u64) -> Result<Vec<(u64, u64)>>,
{
    check_lznt1_geometry(&engine.geometry)?;
    let cb = u64::from(engine.geometry.cluster_bytes());
    let unit_bytes = UNIT_CLUSTERS * cb;
    let end_offset = offset
        .checked_add(data.len() as u64)
        .filter(|&e| i64::try_from(e).is_ok())
        .ok_or_else(|| FfsError::RequestRejected {
            errno: libc::EFBIG,
            detail: "compressed write offset overflow".into(),
        })?;
    let new_size = old_size.max(end_offset);
    let new_init = old_init.max(end_offset);

    if data.is_empty() {
        return Ok((
            EditableStreamStorage::NonResident {
                runs: old_runs.to_vec(),
                sparse: false,
                compressed: true,
                encrypted: false,
                compression_unit: COMPRESSION_UNIT_SHIFT,
                data_bytes: new_size,
                initialized_bytes: new_init,
            },
            Vec::new(),
        ));
    }

    let first_unit = offset / unit_bytes;
    let end_unit = end_offset.div_ceil(unit_bytes);
    // Also ensure any partial-unit old tail before `first_unit` (if `old_runs` ended
    // mid-unit) gets normalized up to `first_unit * 16`.
    let old_total_vcns: u64 = old_runs.iter().map(|r| r.clusters).sum();
    let rewrite_start_unit = if old_total_vcns.is_multiple_of(UNIT_CLUSTERS) {
        first_unit
    } else {
        let partial_unit = old_total_vcns / UNIT_CLUSTERS;
        first_unit.min(partial_unit)
    };
    let rewrite_end_unit = end_unit.max(old_total_vcns.div_ceil(UNIT_CLUSTERS).min(first_unit + 1));

    let mut replacement = Vec::new();
    for u in rewrite_start_unit..rewrite_end_unit {
        checkpoint(cx)?;
        let mut logical = read_compressed_unit_plaintext(engine, cx, old_runs, old_init, u)?;
        let u_start = u * unit_bytes;
        let u_end = u_start + unit_bytes;
        let ov_start = offset.max(u_start);
        let ov_end = end_offset.min(u_end);
        if ov_start < ov_end {
            let dst_off = (ov_start - u_start) as usize;
            let src_off = (ov_start - offset) as usize;
            let cnt = (ov_end - ov_start) as usize;
            logical[dst_off..dst_off + cnt].copy_from_slice(&data[src_off..src_off + cnt]);
        }
        let u_runs = encode_compressed_unit_cow(
            &engine.geometry,
            u,
            &logical,
            pre_payload_writes,
            &mut alloc_clusters,
        )?;
        replacement.extend(u_runs);
    }

    // If the file still had an unaligned final raw unit AFTER `rewrite_end_unit`, pad or
    // leave it intact (it remains raw-only, satisfying CompressedStorage::new).
    let (new_runs, displaced) =
        splice_compressed_units(old_runs, rewrite_start_unit, rewrite_end_unit, replacement);
    Ok((
        EditableStreamStorage::NonResident {
            runs: new_runs,
            sparse: false,
            compressed: true,
            encrypted: false,
            compression_unit: COMPRESSION_UNIT_SHIFT,
            data_bytes: new_size,
            initialized_bytes: new_init,
        },
        displaced,
    ))
}

/// Truncate or extend a compressed (`COMPRESSED`) non-resident stream to `new_size`.
#[allow(clippy::too_many_arguments)]
pub(super) fn truncate_compressed_stream<FAlloc>(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    old_runs: &[NtfsRun],
    old_size: u64,
    old_init: u64,
    new_size: u64,
    pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
    mut alloc_clusters: FAlloc,
) -> Result<(EditableStreamStorage, Vec<(u64, u64)>)>
where
    FAlloc: FnMut(u64) -> Result<Vec<(u64, u64)>>,
{
    check_lznt1_geometry(&engine.geometry)?;
    let cb = u64::from(engine.geometry.cluster_bytes());
    let unit_bytes = UNIT_CLUSTERS * cb;

    if new_size == 0 {
        let freed = physical_spans_of_runs(old_runs);
        return Ok((
            EditableStreamStorage::NonResident {
                runs: Vec::new(),
                sparse: false,
                compressed: true,
                encrypted: false,
                compression_unit: COMPRESSION_UNIT_SHIFT,
                data_bytes: 0,
                initialized_bytes: 0,
            },
            freed,
        ));
    }

    if new_size > old_size {
        let target_units = new_size.div_ceil(unit_bytes);
        let old_vcns: u64 = old_runs.iter().map(|r| r.clusters).sum();
        let mut working = old_runs.to_vec();
        let mut freed = Vec::new();
        // If `old_runs` ended with a partial raw unit (< 16 clusters), re-encode that unit
        // into a full 16-cluster unit before appending sparse units!
        if !old_vcns.is_multiple_of(UNIT_CLUSTERS) {
            let partial_u = old_vcns / UNIT_CLUSTERS;
            let logical =
                read_compressed_unit_plaintext(engine, cx, old_runs, old_init, partial_u)?;
            let u_runs = encode_compressed_unit_cow(
                &engine.geometry,
                partial_u,
                &logical,
                pre_payload_writes,
                &mut alloc_clusters,
            )?;
            let (spliced, disp) =
                splice_compressed_units(&working, partial_u, partial_u + 1, u_runs);
            working = spliced;
            freed.extend(disp);
        }
        let cur_vcns: u64 = working.iter().map(|r| r.clusters).sum();
        let need_vcns = target_units * UNIT_CLUSTERS;
        if need_vcns > cur_vcns {
            working.push(NtfsRun {
                vcn: cur_vcns,
                clusters: need_vcns - cur_vcns,
                lcn: None,
            });
            working = normalize_ntfs_runs(working);
        }
        return Ok((
            EditableStreamStorage::NonResident {
                runs: working,
                sparse: false,
                compressed: true,
                encrypted: false,
                compression_unit: COMPRESSION_UNIT_SHIFT,
                data_bytes: new_size,
                initialized_bytes: old_init,
            },
            freed,
        ));
    }

    // Shrinking: re-encode the boundary unit (zeroing bytes >= new_size) and drop all
    // units strictly beyond `keep_units`.
    let keep_units = new_size.div_ceil(unit_bytes);
    let last_unit = keep_units - 1;
    let mut logical = read_compressed_unit_plaintext(engine, cx, old_runs, old_init, last_unit)?;
    let keep_in_last = (new_size - last_unit * unit_bytes) as usize;
    if keep_in_last < logical.len() {
        logical[keep_in_last..].fill(0);
    }
    let last_runs = encode_compressed_unit_cow(
        &engine.geometry,
        last_unit,
        &logical,
        pre_payload_writes,
        &mut alloc_clusters,
    )?;
    let old_total_units = old_runs
        .iter()
        .map(|r| r.clusters)
        .sum::<u64>()
        .div_ceil(UNIT_CLUSTERS);
    let (mut new_runs, displaced) = splice_compressed_units(
        old_runs,
        last_unit,
        old_total_units.max(keep_units),
        last_runs,
    );
    let max_vcns = keep_units * UNIT_CLUSTERS;
    new_runs.retain_mut(|r| {
        if r.vcn >= max_vcns {
            return false;
        }
        r.clusters = r.clusters.min(max_vcns - r.vcn);
        true
    });
    Ok((
        EditableStreamStorage::NonResident {
            runs: normalize_ntfs_runs(new_runs),
            sparse: false,
            compressed: true,
            encrypted: false,
            compression_unit: COMPRESSION_UNIT_SHIFT,
            data_bytes: new_size,
            initialized_bytes: old_init.min(new_size),
        },
        displaced,
    ))
}

/// Convert a whole plaintext buffer into either compressed (`enable == true`) or
/// plain uncompressed (`enable == false`) storage via COW.
pub(super) fn rebuild_stream_for_compression_toggle<FAlloc>(
    geometry: &NtfsGeometry,
    plaintext: &[u8],
    enable_compression: bool,
    pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
    mut alloc_clusters: FAlloc,
) -> Result<EditableStreamStorage>
where
    FAlloc: FnMut(u64) -> Result<Vec<(u64, u64)>>,
{
    let cb = u64::from(geometry.cluster_bytes());
    if enable_compression {
        check_lznt1_geometry(geometry)?;
        if plaintext.is_empty() {
            return Ok(EditableStreamStorage::NonResident {
                runs: Vec::new(),
                sparse: false,
                compressed: true,
                encrypted: false,
                compression_unit: COMPRESSION_UNIT_SHIFT,
                data_bytes: 0,
                initialized_bytes: 0,
            });
        }
        let unit_bytes = (UNIT_CLUSTERS * cb) as usize;
        let num_units = plaintext.len().div_ceil(unit_bytes);
        let mut all_runs = Vec::new();
        for u in 0..num_units {
            let start = u * unit_bytes;
            let end = (start + unit_bytes).min(plaintext.len());
            let mut buf = vec![0_u8; unit_bytes];
            buf[..end - start].copy_from_slice(&plaintext[start..end]);
            let u_runs = encode_compressed_unit_cow(
                geometry,
                u as u64,
                &buf,
                pre_payload_writes,
                &mut alloc_clusters,
            )?;
            all_runs.extend(u_runs);
        }
        return Ok(EditableStreamStorage::NonResident {
            runs: normalize_ntfs_runs(all_runs),
            sparse: false,
            compressed: true,
            encrypted: false,
            compression_unit: COMPRESSION_UNIT_SHIFT,
            data_bytes: plaintext.len() as u64,
            initialized_bytes: plaintext.len() as u64,
        });
    }

    // Decompressing to plain stream (resident if small enough).
    if plaintext.len() <= MAX_RESIDENT_DATA_PAYLOAD {
        return Ok(EditableStreamStorage::Resident(plaintext.to_vec()));
    }
    let need_clusters = (plaintext.len() as u64).div_ceil(cb);
    let spans = alloc_clusters(need_clusters)?;
    let mut runs = Vec::with_capacity(spans.len());
    let mut cur_vcn = 0_u64;
    for &(lcn, cnt) in &spans {
        runs.push(NtfsRun {
            vcn: cur_vcn,
            clusters: cnt,
            lcn: Some(lcn),
        });
        cur_vcn += cnt;
    }
    let runs = normalize_ntfs_runs(runs);
    let mut padded = vec![0_u8; (need_clusters * cb) as usize];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    stage_runs_writes(geometry, &runs, &padded, pre_payload_writes)?;
    Ok(EditableStreamStorage::NonResident {
        runs,
        sparse: false,
        compressed: false,
        encrypted: false,
        compression_unit: 0,
        data_bytes: plaintext.len() as u64,
        initialized_bytes: plaintext.len() as u64,
    })
}
