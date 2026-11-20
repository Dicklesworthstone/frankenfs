//! Physical cluster copy, lossless MFT attribute mapping-pair rewriter, and
//! metadata synchronization (`$MFT`, `$MFTMirr`, `$Bitmap`, `$Boot`) for
//! source-preserving offline NTFS resize.

use std::sync::Arc;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::logfile_writer::next_usa_token;
use ffs_ondisk::ntfs::{
    COMPRESSED, NtfsFileRecord, NtfsRun, SPARSE, encode_mapping_pairs, protect_record,
    restore_record,
};
use ffs_types::ByteOffset;

use super::planner::{AttrRemapPlan, InternalResizePlan};
use crate::reader::checkpoint;

const COPY_CHUNK_BYTES: usize = 64 * 1024;

fn fmt_err(detail: impl Into<String>) -> FfsError {
    FfsError::Format(detail.into())
}

fn parse_err(err: &ffs_types::ParseError) -> FfsError {
    FfsError::Format(err.to_string())
}

/// Rewrite selected non-resident attributes inside a raw USA-protected `FILE`
/// record while preserving every other attribute byte-for-byte.
#[allow(clippy::too_many_lines)]
pub(super) fn rewrite_single_file_record(
    raw_record: &[u8],
    remaps: &[AttrRemapPlan],
    new_clusters: u64,
    cluster_bytes: u64,
    ntfs_version: [u8; 2],
) -> Result<Vec<u8>> {
    let record_len = raw_record.len();
    let restored = restore_record(raw_record, b"FILE").map_err(|e| parse_err(&e))?;
    let usa_off = usize::from(u16::from_le_bytes([restored[4], restored[5]]));
    let old_token = u16::from_le_bytes([raw_record[usa_off], raw_record[usa_off + 1]]);
    let first_attr = usize::from(u16::from_le_bytes([restored[20], restored[21]]));
    let old_used = usize::try_from(u32::from_le_bytes([
        restored[24],
        restored[25],
        restored[26],
        restored[27],
    ]))
    .map_err(|_| fmt_err("record used overflow"))?;

    if first_attr < 42 || old_used > record_len || first_attr > old_used {
        return Err(fmt_err("corrupt FILE record header bounds during resize"));
    }

    let mut rebuilt_attrs: Vec<u8> = Vec::with_capacity(old_used.saturating_sub(first_attr) + 64);
    let mut pos = first_attr;
    let mut matched = 0_usize;

    while pos + 4 <= old_used {
        let kind = u32::from_le_bytes([
            restored[pos],
            restored[pos + 1],
            restored[pos + 2],
            restored[pos + 3],
        ]);
        if kind == u32::MAX {
            break;
        }
        if pos + 24 > old_used {
            return Err(fmt_err("truncated attribute header during resize"));
        }
        let attr_len = usize::try_from(u32::from_le_bytes([
            restored[pos + 4],
            restored[pos + 5],
            restored[pos + 6],
            restored[pos + 7],
        ]))
        .map_err(|_| fmt_err("attribute length overflow"))?;
        if attr_len < 24 || pos + attr_len > old_used {
            return Err(fmt_err("attribute exceeds FILE record bounds"));
        }
        let attr_raw = &restored[pos..pos + attr_len];
        let non_resident = attr_raw[8];
        let id = u16::from_le_bytes([attr_raw[14], attr_raw[15]]);

        if non_resident == 1
            && let Some(plan) = remaps
                .iter()
                .find(|p| p.attr_kind == kind && p.attr_id == id)
        {
            matched += 1;
            let rewritten = rewrite_nonresident_attr(attr_raw, plan, new_clusters, cluster_bytes)?;
            rebuilt_attrs.extend_from_slice(&rewritten);
        } else {
            rebuilt_attrs.extend_from_slice(attr_raw);
        }
        pos += attr_len;
    }

    if matched != remaps.len() {
        return Err(fmt_err(format!(
            "resize expected to rewrite {} attribute(s) in FILE record but matched {matched}",
            remaps.len()
        )));
    }

    let new_used = first_attr
        .checked_add(rebuilt_attrs.len())
        .and_then(|v| v.checked_add(8))
        .ok_or_else(|| fmt_err("rewritten FILE record size overflow"))?;
    if new_used > record_len {
        return Err(FfsError::NoSpace);
    }

    let mut out = vec![0_u8; record_len];
    out[..first_attr].copy_from_slice(&restored[..first_attr]);
    let used_u32 = u32::try_from(new_used).map_err(|_| fmt_err("new_used overflow"))?;
    out[24..28].copy_from_slice(&used_u32.to_le_bytes());
    out[first_attr..first_attr + rebuilt_attrs.len()].copy_from_slice(&rebuilt_attrs);
    let term_at = first_attr + rebuilt_attrs.len();
    out[term_at..term_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());

    let token = next_usa_token(old_token);
    out[usa_off..usa_off + 2].copy_from_slice(&token.to_le_bytes());
    let protected = protect_record(&out).map_err(|e| parse_err(&e))?;
    let parsed = NtfsFileRecord::parse(&protected).map_err(|e| parse_err(&e))?;
    if ntfs_version == [3, 1] && parsed.usa_offset < 48 {
        return Err(fmt_err(
            "rewritten NTFS 3.1 FILE record lost 48-byte header",
        ));
    }
    Ok(protected)
}

fn rewrite_nonresident_attr(
    orig: &[u8],
    plan: &AttrRemapPlan,
    new_clusters: u64,
    cluster_bytes: u64,
) -> Result<Vec<u8>> {
    if orig.len() < 64 {
        return Err(fmt_err("short non-resident attribute during resize"));
    }
    let name_len = usize::from(orig[9]);
    let old_name_off = usize::from(u16::from_le_bytes([orig[10], orig[11]]));
    let flags = u16::from_le_bytes([orig[12], orig[13]]);
    let first_vcn = u64::from_le_bytes(
        orig[16..24]
            .try_into()
            .map_err(|_| fmt_err("first_vcn slice"))?,
    );
    let base_hdr: usize = if flags & (SPARSE | COMPRESSED) != 0 {
        72
    } else {
        64
    };
    if orig.len() < base_hdr || old_name_off + name_len * 2 > orig.len() {
        return Err(fmt_err("corrupt non-resident attribute header/name"));
    }
    let name_bytes = &orig[old_name_off..old_name_off + name_len * 2];

    let (pairs, computed_last_vcn) =
        encode_mapping_pairs(&plan.new_runs, first_vcn, new_clusters).map_err(|e| parse_err(&e))?;
    let last_vcn = if plan.new_runs.is_empty() {
        plan.new_last_vcn
    } else {
        computed_last_vcn
    };

    let mapping_off = (base_hdr + name_bytes.len()).next_multiple_of(8);
    let total_len = (mapping_off + pairs.len()).next_multiple_of(8);
    let total_u32 = u32::try_from(total_len).map_err(|_| fmt_err("rewritten attr len overflow"))?;
    let name_off_u16 = u16::try_from(base_hdr).map_err(|_| fmt_err("name_off overflow"))?;
    let map_off_u16 = u16::try_from(mapping_off).map_err(|_| fmt_err("mapping_off overflow"))?;

    let mut out = vec![0_u8; total_len];
    out[..base_hdr].copy_from_slice(&orig[..base_hdr]);
    out[4..8].copy_from_slice(&total_u32.to_le_bytes());
    out[10..12].copy_from_slice(&name_off_u16.to_le_bytes());
    out[24..32].copy_from_slice(&last_vcn.to_le_bytes());
    out[32..34].copy_from_slice(&map_off_u16.to_le_bytes());
    if let Some(alloc) = plan.new_allocated_bytes {
        out[40..48].copy_from_slice(&alloc.to_le_bytes());
    }
    if let Some(data) = plan.new_data_bytes {
        out[48..56].copy_from_slice(&data.to_le_bytes());
    }
    if let Some(init) = plan.new_initialized_bytes {
        out[56..64].copy_from_slice(&init.to_le_bytes());
    }
    if base_hdr == 72 && flags & SPARSE != 0 && flags & COMPRESSED == 0 {
        let phys_clusters: u64 = plan
            .new_runs
            .iter()
            .filter_map(|r| r.lcn.map(|_| r.clusters))
            .sum();
        let phys_bytes = phys_clusters
            .checked_mul(cluster_bytes)
            .ok_or_else(|| fmt_err("sparse physical bytes overflow"))?;
        out[64..72].copy_from_slice(&phys_bytes.to_le_bytes());
    }
    out[base_hdr..base_hdr + name_bytes.len()].copy_from_slice(name_bytes);
    out[mapping_off..mapping_off + pairs.len()].copy_from_slice(&pairs);
    Ok(out)
}

/// Copy all retained live clusters `< new_clusters` from `source` to `output`,
/// keeping offset `0..sector_bytes` strictly zeroed (primary VBR withheld).
pub(super) fn copy_retained_clusters(
    cx: &Cx,
    source: &Arc<dyn ByteDevice>,
    output: &Arc<dyn ByteDevice>,
    plan: &InternalResizePlan,
) -> Result<()> {
    let cb = u64::from(plan.public.cluster_bytes);
    let sec_u64 = u64::from(plan.public.sector_bytes);
    let mut buf = vec![0_u8; COPY_CHUNK_BYTES];

    for &(start_lcn, clusters) in &plan.retained_spans {
        let mut off = start_lcn
            .checked_mul(cb)
            .ok_or_else(|| fmt_err("retained offset overflow"))?;
        let mut remaining = clusters
            .checked_mul(cb)
            .ok_or_else(|| fmt_err("retained len overflow"))?;
        while remaining > 0 {
            checkpoint(cx)?;
            let n = (remaining.min(COPY_CHUNK_BYTES as u64)) as usize;
            source.read_exact_at(cx, ByteOffset(off), &mut buf[..n])?;
            // Never publish old primary VBR at offset 0..sector_bytes prematurely!
            if off < sec_u64 {
                let zero_end = ((sec_u64 - off).min(n as u64)) as usize;
                buf[..zero_end].fill(0);
            }
            output.write_all_at(cx, ByteOffset(off), &buf[..n])?;
            off += n as u64;
            remaining -= n as u64;
        }
    }
    Ok(())
}

/// Copy every relocated physical cluster span from `old_lcn` on `source` to
/// `new_lcn` on `output`.
pub(super) fn copy_relocated_clusters(
    cx: &Cx,
    source: &Arc<dyn ByteDevice>,
    output: &Arc<dyn ByteDevice>,
    plan: &InternalResizePlan,
) -> Result<()> {
    let cb = u64::from(plan.public.cluster_bytes);
    let mut buf = vec![0_u8; COPY_CHUNK_BYTES];

    for reloc in &plan.relocations {
        let mut src_off = reloc
            .old_lcn
            .checked_mul(cb)
            .ok_or_else(|| fmt_err("reloc src offset overflow"))?;
        let mut dst_off = reloc
            .new_lcn
            .checked_mul(cb)
            .ok_or_else(|| fmt_err("reloc dst offset overflow"))?;
        let mut remaining = reloc
            .clusters
            .checked_mul(cb)
            .ok_or_else(|| fmt_err("reloc len overflow"))?;
        while remaining > 0 {
            checkpoint(cx)?;
            let n = (remaining.min(COPY_CHUNK_BYTES as u64)) as usize;
            source.read_exact_at(cx, ByteOffset(src_off), &mut buf[..n])?;
            output.write_all_at(cx, ByteOffset(dst_off), &buf[..n])?;
            src_off += n as u64;
            dst_off += n as u64;
            remaining -= n as u64;
        }
    }
    Ok(())
}

fn write_stream_via_runs(
    cx: &Cx,
    device: &Arc<dyn ByteDevice>,
    runs: &[NtfsRun],
    cluster_bytes: u64,
    mut stream_offset: u64,
    data: &[u8],
) -> Result<()> {
    let mut done = 0_usize;
    while done < data.len() {
        checkpoint(cx)?;
        let vcn = stream_offset / cluster_bytes;
        let within = stream_offset % cluster_bytes;
        let run = runs
            .iter()
            .find(|r| vcn >= r.vcn && vcn < r.vcn + r.clusters)
            .ok_or_else(|| fmt_err("stream write VCN outside mapped runs"))?;
        let lcn = run
            .lcn
            .ok_or_else(|| fmt_err("cannot write metadata into sparse run"))?;
        let phys = (lcn + (vcn - run.vcn))
            .checked_mul(cluster_bytes)
            .and_then(|v| v.checked_add(within))
            .ok_or_else(|| fmt_err("metadata physical offset overflow"))?;
        let avail = ((run.vcn + run.clusters - vcn) * cluster_bytes) - within;
        let chunk = (avail.min((data.len() - done) as u64)) as usize;
        device.write_all_at(cx, ByteOffset(phys), &data[done..done + chunk])?;
        done += chunk;
        stream_offset += chunk as u64;
    }
    Ok(())
}

fn read_stream_via_runs(
    cx: &Cx,
    device: &Arc<dyn ByteDevice>,
    runs: &[NtfsRun],
    cluster_bytes: u64,
    mut stream_offset: u64,
    out: &mut [u8],
) -> Result<()> {
    let mut done = 0_usize;
    while done < out.len() {
        checkpoint(cx)?;
        let vcn = stream_offset / cluster_bytes;
        let within = stream_offset % cluster_bytes;
        let run = runs
            .iter()
            .find(|r| vcn >= r.vcn && vcn < r.vcn + r.clusters)
            .ok_or_else(|| fmt_err("stream read VCN outside mapped runs"))?;
        let lcn = run
            .lcn
            .ok_or_else(|| fmt_err("cannot read metadata from sparse run"))?;
        let phys = (lcn + (vcn - run.vcn))
            .checked_mul(cluster_bytes)
            .and_then(|v| v.checked_add(within))
            .ok_or_else(|| fmt_err("metadata physical offset overflow"))?;
        let avail = ((run.vcn + run.clusters - vcn) * cluster_bytes) - within;
        let chunk = (avail.min((out.len() - done) as u64)) as usize;
        device.read_exact_at(cx, ByteOffset(phys), &mut out[done..done + chunk])?;
        done += chunk;
        stream_offset += chunk as u64;
    }
    Ok(())
}

/// Apply all planned MFT attribute mapping updates, write the new `$Bitmap`,
/// and re-synchronize `$MFTMirr` on `output`.
pub(super) fn rewrite_metadata(
    cx: &Cx,
    output: &Arc<dyn ByteDevice>,
    plan: &InternalResizePlan,
) -> Result<()> {
    let cb = u64::from(plan.public.cluster_bytes);
    let rec_len =
        usize::try_from(plan.record_bytes).map_err(|_| fmt_err("record_bytes overflow"))?;
    let mut raw_rec = vec![0_u8; rec_len];

    // 1. Update every remapped FILE record directly in `output`'s new $MFT runs.
    for (&slot, remaps) in &plan.record_remaps {
        checkpoint(cx)?;
        let mft_off = slot
            .checked_mul(u64::from(plan.record_bytes))
            .ok_or_else(|| fmt_err("MFT record offset overflow"))?;
        read_stream_via_runs(cx, output, &plan.new_mft_runs, cb, mft_off, &mut raw_rec)?;
        let updated = rewrite_single_file_record(
            &raw_rec,
            remaps,
            plan.public.new_clusters,
            cb,
            plan.public.ntfs_version,
        )?;
        write_stream_via_runs(cx, output, &plan.new_mft_runs, cb, mft_off, &updated)?;
    }

    // 2. Write exact post-resize `$Bitmap` bytes (padded with zeroes to allocated cluster boundary).
    let bm_alloc_len = usize::try_from(plan.new_bitmap_allocated_bytes)
        .map_err(|_| fmt_err("bitmap allocated size overflow"))?;
    let mut padded_bm = vec![0_u8; bm_alloc_len];
    padded_bm[..plan.new_bitmap_bytes.len()].copy_from_slice(&plan.new_bitmap_bytes);
    write_stream_via_runs(cx, output, &plan.new_bitmap_runs, cb, 0, &padded_bm)?;

    // 3. Synchronize `$MFTMirr` (first `mirror_records` records) from updated `$MFT` on `output`.
    let mirr_bytes_len = usize::try_from(plan.mirror_records * u64::from(plan.record_bytes))
        .map_err(|_| fmt_err("mirror bytes overflow"))?;
    let mut mirr_buf = vec![0_u8; mirr_bytes_len];
    read_stream_via_runs(cx, output, &plan.new_mft_runs, cb, 0, &mut mirr_buf)?;
    write_stream_via_runs(cx, output, &plan.new_mirror_runs, cb, 0, &mirr_buf)?;

    Ok(())
}
