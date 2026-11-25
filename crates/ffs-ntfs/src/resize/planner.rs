//! Read-only planning and physical LCN relocation solver for offline NTFS resize.

use std::collections::BTreeMap;
use std::sync::Arc;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::{
    DATA, NtfsGeometry, NtfsRun, NtfsValue, decode_mapping_pairs, ntfs_boot_sector_checksum,
};
use ffs_types::ByteOffset;

use super::{NtfsClusterRelocation, NtfsResizeDirection, NtfsResizeOptions, NtfsResizePlan};
use crate::reader::allocation::{bit, empty_volume_bitmap, read_bitmap};
use crate::reader::check::{NtfsCheckLimits, NtfsCheckStatus, check_volume_device};
use crate::reader::{NtfsVolume, checkpoint};

const BAD_NAME: [u16; 4] = [b'$' as u16, b'B' as u16, b'a' as u16, b'd' as u16];

/// One non-resident attribute's complete remapping instruction for `relocator`.
#[derive(Debug, Clone)]
pub(super) struct AttrRemapPlan {
    pub(super) attr_kind: u32,
    pub(super) attr_id: u16,
    pub(super) new_runs: Vec<NtfsRun>,
    pub(super) new_last_vcn: u64,
    pub(super) new_allocated_bytes: Option<u64>,
    pub(super) new_data_bytes: Option<u64>,
    pub(super) new_initialized_bytes: Option<u64>,
}

/// Complete, verified, zero-write execution plan for [`super::relocator`].
#[derive(Debug)]
pub(super) struct InternalResizePlan {
    pub(super) public: NtfsResizePlan,
    pub(super) new_vbr: Vec<u8>,
    pub(super) record_bytes: u32,
    /// Every live physical cluster span `< new_clusters` that stays at its same LCN.
    pub(super) retained_spans: Vec<(u64, u64)>,
    /// Every physical cluster span moved from `old_lcn` -> `new_lcn`.
    pub(super) relocations: Vec<NtfsClusterRelocation>,
    /// Per-record attribute mapping updates (`record_no -> Vec<AttrRemapPlan>`).
    pub(super) record_remaps: BTreeMap<u64, Vec<AttrRemapPlan>>,
    /// New physical runs of `$MFT::$DATA` (record 0) after resize/relocation.
    pub(super) new_mft_runs: Vec<NtfsRun>,
    /// New physical runs of `$MFTMirr::$DATA` (record 1) after resize/relocation.
    pub(super) new_mirror_runs: Vec<NtfsRun>,
    /// Number of mirrored records in `$MFTMirr`.
    pub(super) mirror_records: u64,
    /// New physical runs of `$Bitmap::$DATA` (record 6) after resize/relocation.
    pub(super) new_bitmap_runs: Vec<NtfsRun>,
    /// Exact post-resize `$Bitmap` bytes (length == `public.new_bitmap_bytes`).
    pub(super) new_bitmap_bytes: Vec<u8>,
    /// New allocated byte size of `$Bitmap::$DATA`.
    pub(super) new_bitmap_allocated_bytes: u64,
}

fn fmt_err(detail: impl Into<String>) -> FfsError {
    FfsError::Format(detail.into())
}

fn set_bit(bitmap: &mut [u8], idx: u64) {
    let byte = (idx / 8) as usize;
    if byte < bitmap.len() {
        bitmap[byte] |= 1_u8 << (idx % 8);
    }
}

fn clear_bit(bitmap: &mut [u8], idx: u64) {
    let byte = (idx / 8) as usize;
    if byte < bitmap.len() {
        bitmap[byte] &= !(1_u8 << (idx % 8));
    }
}

fn allocate_free_runs(
    bitmap: &mut [u8],
    start_lcn: u64,
    end_lcn: u64,
    needed: u64,
) -> Result<Vec<(u64, u64)>> {
    if needed == 0 {
        return Ok(Vec::new());
    }
    // First pass: look for a single contiguous free run in [start_lcn, end_lcn).
    let mut run_start = start_lcn;
    let mut run_len = 0_u64;
    for lcn in start_lcn..end_lcn {
        if bit(bitmap, lcn) {
            run_start = lcn + 1;
            run_len = 0;
        } else {
            run_len += 1;
            if run_len == needed {
                for c in run_start..run_start + needed {
                    set_bit(bitmap, c);
                }
                return Ok(vec![(run_start, needed)]);
            }
        }
    }
    // Second pass: deterministic fragmented allocation in ascending LCN order.
    let mut rem = needed;
    let mut spans = Vec::new();
    let mut cur = start_lcn;
    while cur < end_lcn && rem > 0 {
        if bit(bitmap, cur) {
            cur += 1;
            continue;
        }
        let s = cur;
        while cur < end_lcn && !bit(bitmap, cur) && (cur - s) < rem {
            set_bit(bitmap, cur);
            cur += 1;
        }
        let got = cur - s;
        spans.push((s, got));
        rem -= got;
    }
    if rem != 0 {
        return Err(FfsError::NoSpace);
    }
    Ok(spans)
}

fn coalesce_runs(runs: Vec<NtfsRun>) -> Vec<NtfsRun> {
    let mut out: Vec<NtfsRun> = Vec::with_capacity(runs.len());
    for run in runs {
        if run.clusters == 0 {
            continue;
        }
        if let Some(last) = out.last_mut()
            && last.vcn + last.clusters == run.vcn
            && match (last.lcn, run.lcn) {
                (None, None) => true,
                (Some(a), Some(b)) => a + last.clusters == b,
                _ => false,
            }
        {
            last.clusters += run.clusters;
            continue;
        }
        out.push(run);
    }
    out
}

/// Inspect `source` strictly read-only and compute a complete, verified resize plan.
#[allow(clippy::too_many_lines)]
pub(super) fn build_resize_plan(
    cx: &Cx,
    source: &Arc<dyn ByteDevice>,
    slice_len: u64,
    opts: &NtfsResizeOptions,
) -> Result<InternalResizePlan> {
    checkpoint(cx)?;
    let new_backing_bytes = match (opts.size_bytes, opts.size_mib) {
        (Some(b), None) => b,
        (None, Some(mib)) => mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| FfsError::InvalidGeometry("target size_mib overflows u64".into()))?,
        (Some(_), Some(_)) => {
            return Err(fmt_err("specify exactly one of size_bytes or size_mib"));
        }
        (None, None) => {
            return Err(fmt_err(
                "must specify target size_bytes or size_mib for resize",
            ));
        }
    };

    // 1. Full non-mutating structural check on source: refuse dirty, hibernated, or corrupt volumes!
    let check = check_volume_device(
        cx,
        Arc::clone(source),
        0,
        slice_len,
        NtfsCheckLimits::default(),
    )?;
    if !check.clean || check.status != NtfsCheckStatus::Clean {
        return Err(FfsError::UnsupportedFeature(format!(
            "NTFS resize requires a structurally clean, cleanly unmounted source volume (status={:?}, volume_flags={:#06x}, hibernated={}, issues={})",
            check.status,
            check.volume_flags,
            check.hibernated,
            check.issues.len()
        )));
    }

    let volume =
        NtfsVolume::from_device(cx, Box::new(ArcDevice(Arc::clone(source))), 0, slice_len)?;
    let geom = &volume.geometry;
    let sector_bytes = geom.sector_bytes();
    let cluster_bytes = geom.cluster_bytes();
    let cb = u64::from(cluster_bytes);
    let sectors_per_cluster = cluster_bytes / sector_bytes;
    let old_clusters = geom.cluster_count();

    if new_backing_bytes < 4 * 1024 * 1024
        || !new_backing_bytes.is_multiple_of(u64::from(sector_bytes))
    {
        return Err(FfsError::InvalidGeometry(format!(
            "target size {new_backing_bytes} must be >= 4 MiB and a multiple of sector_bytes ({sector_bytes})"
        )));
    }
    let new_total_sectors = (new_backing_bytes / u64::from(sector_bytes))
        .checked_sub(1)
        .ok_or_else(|| {
            FfsError::InvalidGeometry("target too small for backup boot sector".into())
        })?;
    let new_volume_bytes = new_total_sectors * u64::from(sector_bytes);
    let new_clusters = new_total_sectors / u64::from(sectors_per_cluster);
    if new_clusters < 64 {
        return Err(FfsError::InvalidGeometry(format!(
            "target cluster_count ({new_clusters}) is too small for NTFS"
        )));
    }

    let direction = match new_clusters.cmp(&old_clusters) {
        std::cmp::Ordering::Greater => NtfsResizeDirection::Grow,
        std::cmp::Ordering::Less => NtfsResizeDirection::Shrink,
        std::cmp::Ordering::Equal => NtfsResizeDirection::Unchanged,
    };

    // Read source VBR.
    let sec_len = usize::try_from(sector_bytes).map_err(|_| fmt_err("sector_bytes overflow"))?;
    let mut source_vbr = vec![0_u8; sec_len];
    source.read_exact_at(cx, ByteOffset(0), &mut source_vbr)?;

    // Read $MFT::$BITMAP and $Bitmap::$DATA.
    let record_bytes = geom.record_bytes();
    let mft_logical_records = volume.mft_stream().size / u64::from(record_bytes);
    let mft_rec = volume.record(cx, 0, None)?;
    let mft_bm_stream = volume.select_stream(cx, &mft_rec, 0xB0, &[])?;
    let mft_bitmap = read_bitmap(cx, &volume, &mft_bm_stream, mft_logical_records)?;

    let bm_rec = volume.record(cx, 6, None)?;
    let bm_stream = volume.select_stream(cx, &bm_rec, DATA, &[])?;
    let old_bitmap = read_bitmap(cx, &volume, &bm_stream, old_clusters)?;
    let old_bitmap_bytes = bm_stream.size;
    let new_bitmap_bytes = new_clusters.div_ceil(8).next_multiple_of(8);
    let new_bitmap_clusters_needed = new_bitmap_bytes.div_ceil(cb);

    // Prepare new_bitmap_bytes initialized with retained allocated bits (< new_clusters).
    let mut new_bitmap = empty_volume_bitmap(new_clusters)?;
    let common_clusters = old_clusters.min(new_clusters);
    for lcn in 0..common_clusters {
        if bit(&old_bitmap, lcn) {
            set_bit(&mut new_bitmap, lcn);
        }
    }

    // Collect every non-resident attribute across all allocated MFT records.
    struct ScannedAttr {
        record: u64,
        attr_kind: u32,
        attr_id: u16,
        name: Vec<u16>,
        first_vcn: u64,
        last_vcn: u64,
        allocated_bytes: u64,
        data_bytes: u64,
        initialized_bytes: u64,
        runs: Vec<NtfsRun>,
    }

    let mut scanned = Vec::new();
    let mut bad_tail_lcn: Option<u64> = None;
    let mut tail_clusters_total = 0_u64;
    let mut old_mft_runs: Vec<NtfsRun> = Vec::new();
    let mut old_mirror_runs: Vec<NtfsRun> = Vec::new();
    let mut mirror_records = 4_u64;
    let mut old_bitmap_runs: Vec<NtfsRun> = Vec::new();
    let mut old_bitmap_attr_id = 2_u16;
    let mut old_bitmap_allocated_bytes = bm_stream.allocated;

    for slot in 0..mft_logical_records {
        checkpoint(cx)?;
        if !bit(&mft_bitmap, slot) {
            continue;
        }
        let rec = volume.record(cx, slot, None)?;
        let attrs = rec.attributes().map_err(|e| fmt_err(e.to_string()))?;
        for attr in attrs {
            let NtfsValue::NonResident(nr) = attr.value else {
                continue;
            };
            let runs =
                decode_mapping_pairs(nr.mapping_pairs, nr.first_vcn, nr.last_vcn, old_clusters)
                    .map_err(|e| fmt_err(e.to_string()))?;

            let is_bad_stream = slot == 8 && attr.kind == DATA && attr.name == BAD_NAME;
            for r in &runs {
                if let Some(lcn) = r.lcn {
                    let end = lcn + r.clusters;
                    if end > new_clusters {
                        if is_bad_stream {
                            bad_tail_lcn.get_or_insert_with(|| lcn.max(new_clusters));
                        } else {
                            let tail_start = lcn.max(new_clusters);
                            tail_clusters_total += end - tail_start;
                        }
                    }
                }
            }

            if slot == 0 && attr.kind == DATA && attr.name.is_empty() && nr.first_vcn == 0 {
                old_mft_runs.clone_from(&runs);
            }
            if slot == 1 && attr.kind == DATA && attr.name.is_empty() && nr.first_vcn == 0 {
                old_mirror_runs.clone_from(&runs);
                mirror_records = nr.data_bytes / u64::from(record_bytes);
            }
            if slot == 6 && attr.kind == DATA && attr.name.is_empty() && nr.first_vcn == 0 {
                old_bitmap_runs.clone_from(&runs);
                old_bitmap_attr_id = attr.id;
                old_bitmap_allocated_bytes = nr.allocated_bytes;
            }

            scanned.push(ScannedAttr {
                record: slot,
                attr_kind: attr.kind,
                attr_id: attr.id,
                name: attr.name,
                first_vcn: nr.first_vcn,
                last_vcn: nr.last_vcn,
                allocated_bytes: nr.allocated_bytes,
                data_bytes: nr.data_bytes,
                initialized_bytes: nr.initialized_bytes,
                runs,
            });
        }
    }

    // Refuse shrinking across physical bad clusters in $BadClus:$Bad even with --relocate!
    if let Some(bad_lcn) = bad_tail_lcn {
        return Err(FfsError::UnsupportedFeature(format!(
            "cannot shrink NTFS volume across physical bad cluster LCN {bad_lcn} in $BadClus:$Bad"
        )));
    }

    // Refuse shrinking across live tail clusters without explicit --relocate!
    if tail_clusters_total > 0 && !opts.relocate {
        return Err(FfsError::UnsupportedFeature(format!(
            "NTFS shrink to {new_clusters} clusters crosses {tail_clusters_total} live tail cluster(s); re-run with --relocate to move live tail clusters"
        )));
    }

    // Count total allocated clusters on source for reporting and space pre-check.
    let mut total_source_allocated = 0_u64;
    for lcn in 0..old_clusters {
        if bit(&old_bitmap, lcn) {
            total_source_allocated += 1;
        }
    }
    let old_bm_clusters = old_bitmap_allocated_bytes / cb;
    let extra_bm_clusters = new_bitmap_clusters_needed.saturating_sub(old_bm_clusters);
    if total_source_allocated + extra_bm_clusters > new_clusters {
        return Err(FfsError::NoSpace);
    }

    let mut relocations: Vec<NtfsClusterRelocation> = Vec::new();
    let mut record_remaps: BTreeMap<u64, Vec<AttrRemapPlan>> = BTreeMap::new();
    let mut retained_spans: Vec<(u64, u64)> = Vec::new();

    // Never relocate LCN 0 ($Boot); reserve 0..boot_clusters from free allocation.
    let boot_clusters = 8_192_u64.div_ceil(cb);

    let mut new_mft_runs = old_mft_runs;
    let mut new_mirror_runs = old_mirror_runs;
    let mut new_bitmap_runs = old_bitmap_runs;

    // Process every scanned non-resident attribute.
    for attr in scanned {
        checkpoint(cx)?;

        // Special case 1: $BadClus:$Bad (record 8, named $Bad) spans 0..new_clusters.
        if attr.record == 8 && attr.attr_kind == DATA && attr.name == BAD_NAME {
            let mut bad_runs: Vec<NtfsRun> = Vec::new();
            let mut vcn_cur = 0_u64;
            for r in &attr.runs {
                if vcn_cur >= new_clusters {
                    break;
                }
                let take = r.clusters.min(new_clusters - vcn_cur);
                if let Some(lcn) = r.lcn {
                    retained_spans.push((lcn, take));
                }
                bad_runs.push(NtfsRun {
                    vcn: vcn_cur,
                    clusters: take,
                    lcn: r.lcn,
                });
                vcn_cur += take;
            }
            if vcn_cur < new_clusters {
                bad_runs.push(NtfsRun {
                    vcn: vcn_cur,
                    clusters: new_clusters - vcn_cur,
                    lcn: None,
                });
            }
            let coalesced = coalesce_runs(bad_runs);
            let bad_bytes = new_clusters * cb;
            record_remaps.entry(8).or_default().push(AttrRemapPlan {
                attr_kind: DATA,
                attr_id: attr.attr_id,
                new_runs: coalesced,
                new_last_vcn: new_clusters - 1,
                new_allocated_bytes: Some(bad_bytes),
                new_data_bytes: Some(bad_bytes),
                new_initialized_bytes: Some(0),
            });
            continue;
        }

        // General case: check if any run exceeds `new_clusters`.
        let mut modified = false;
        let mut remapped_runs: Vec<NtfsRun> = Vec::with_capacity(attr.runs.len());

        for r in &attr.runs {
            let Some(lcn) = r.lcn else {
                remapped_runs.push(*r);
                continue;
            };
            let end = lcn + r.clusters;
            if end <= new_clusters {
                retained_spans.push((lcn, r.clusters));
                remapped_runs.push(*r);
                continue;
            }

            // Partial or full tail run: keep any prefix < new_clusters, relocate suffix >= new_clusters.
            modified = true;
            let mut cur_vcn = r.vcn;
            if lcn < new_clusters {
                let keep = new_clusters - lcn;
                retained_spans.push((lcn, keep));
                remapped_runs.push(NtfsRun {
                    vcn: cur_vcn,
                    clusters: keep,
                    lcn: Some(lcn),
                });
                cur_vcn += keep;
            }
            let move_old_start = lcn.max(new_clusters);
            let move_count = end - move_old_start;
            let dest_spans =
                allocate_free_runs(&mut new_bitmap, boot_clusters, new_clusters, move_count)?;
            let mut moved_so_far = 0_u64;
            for (dst_lcn, dst_len) in dest_spans {
                relocations.push(NtfsClusterRelocation {
                    record: attr.record,
                    attr_kind: attr.attr_kind,
                    attr_id: attr.attr_id,
                    first_vcn: cur_vcn,
                    clusters: dst_len,
                    old_lcn: move_old_start + moved_so_far,
                    new_lcn: dst_lcn,
                });
                remapped_runs.push(NtfsRun {
                    vcn: cur_vcn,
                    clusters: dst_len,
                    lcn: Some(dst_lcn),
                });
                cur_vcn += dst_len;
                moved_so_far += dst_len;
            }
        }

        // Special case 2: $Bitmap (record 6, unnamed DATA) size/cluster growth or shrink.
        if attr.record == 6 && attr.attr_kind == DATA && attr.name.is_empty() && attr.first_vcn == 0
        {
            let mut bm_runs = coalesce_runs(remapped_runs);
            let cur_bm_clusters: u64 = bm_runs.iter().map(|r| r.clusters).sum();
            if new_bitmap_clusters_needed > cur_bm_clusters {
                let need_more = new_bitmap_clusters_needed - cur_bm_clusters;
                let extra_spans =
                    allocate_free_runs(&mut new_bitmap, boot_clusters, new_clusters, need_more)?;
                let mut vcn_cur = cur_bm_clusters;
                for (dst_lcn, dst_len) in extra_spans {
                    bm_runs.push(NtfsRun {
                        vcn: vcn_cur,
                        clusters: dst_len,
                        lcn: Some(dst_lcn),
                    });
                    vcn_cur += dst_len;
                }
                bm_runs = coalesce_runs(bm_runs);
            } else if new_bitmap_clusters_needed < cur_bm_clusters {
                // Free excess $Bitmap clusters at the end of its run list.
                let mut kept = Vec::new();
                let mut vcn_cur = 0_u64;
                for r in bm_runs {
                    if vcn_cur >= new_bitmap_clusters_needed {
                        if let Some(lcn) = r.lcn {
                            for c in lcn..lcn + r.clusters {
                                clear_bit(&mut new_bitmap, c);
                            }
                        }
                        continue;
                    }
                    let take = r.clusters.min(new_bitmap_clusters_needed - vcn_cur);
                    if take < r.clusters
                        && let Some(lcn) = r.lcn
                    {
                        for c in (lcn + take)..(lcn + r.clusters) {
                            clear_bit(&mut new_bitmap, c);
                        }
                    }
                    kept.push(NtfsRun {
                        vcn: vcn_cur,
                        clusters: take,
                        lcn: r.lcn,
                    });
                    vcn_cur += take;
                }
                bm_runs = coalesce_runs(kept);
            }
            let new_bm_alloc = new_bitmap_clusters_needed * cb;
            new_bitmap_runs.clone_from(&bm_runs);
            old_bitmap_allocated_bytes = new_bm_alloc;
            record_remaps.entry(6).or_default().push(AttrRemapPlan {
                attr_kind: DATA,
                attr_id: old_bitmap_attr_id,
                new_runs: bm_runs,
                new_last_vcn: new_bitmap_clusters_needed.saturating_sub(1),
                new_allocated_bytes: Some(new_bm_alloc),
                new_data_bytes: Some(new_bitmap_bytes),
                new_initialized_bytes: Some(new_bitmap_bytes),
            });
            continue;
        }

        if modified {
            let coalesced = coalesce_runs(remapped_runs);
            if attr.record == 0
                && attr.attr_kind == DATA
                && attr.name.is_empty()
                && attr.first_vcn == 0
            {
                new_mft_runs.clone_from(&coalesced);
            }
            if attr.record == 1
                && attr.attr_kind == DATA
                && attr.name.is_empty()
                && attr.first_vcn == 0
            {
                new_mirror_runs.clone_from(&coalesced);
            }
            record_remaps
                .entry(attr.record)
                .or_default()
                .push(AttrRemapPlan {
                    attr_kind: attr.attr_kind,
                    attr_id: attr.attr_id,
                    new_runs: coalesced,
                    new_last_vcn: attr.last_vcn,
                    new_allocated_bytes: if attr.first_vcn == 0 {
                        Some(attr.allocated_bytes)
                    } else {
                        None
                    },
                    new_data_bytes: if attr.first_vcn == 0 {
                        Some(attr.data_bytes)
                    } else {
                        None
                    },
                    new_initialized_bytes: if attr.first_vcn == 0 {
                        Some(attr.initialized_bytes)
                    } else {
                        None
                    },
                });
        }
    }

    // Dry-run preflight: verify every remapped FILE record fits cleanly inside `record_bytes`!
    for (&slot, remaps) in &record_remaps {
        checkpoint(cx)?;
        let raw = volume.read_mft_record_raw(cx, slot)?;
        let _ = super::relocator::rewrite_single_file_record(
            &raw,
            remaps,
            new_clusters,
            cb,
            volume.version(),
        )?;
    }

    let new_mft_cluster = new_mft_runs
        .first()
        .and_then(|r| r.lcn)
        .ok_or_else(|| fmt_err("missing new $MFT cluster"))?;
    let new_mirror_cluster = new_mirror_runs
        .first()
        .and_then(|r| r.lcn)
        .ok_or_else(|| fmt_err("missing new $MFTMirr cluster"))?;
    let relocated_clusters: u64 = relocations.iter().map(|r| r.clusters).sum();
    let relocated_extents = relocations.len();

    let mut allocated_after = 0_u64;
    for lcn in 0..new_clusters {
        if bit(&new_bitmap, lcn) {
            allocated_after += 1;
        }
    }

    // Coalesce retained_spans for fast bulk copying.
    retained_spans.sort_unstable();
    let mut merged_retained: Vec<(u64, u64)> = Vec::new();
    for (start, len) in retained_spans {
        if let Some((prev_s, prev_l)) = merged_retained.last_mut()
            && start <= *prev_s + *prev_l
        {
            let new_end = (*prev_s + *prev_l).max(start + len);
            *prev_l = new_end - *prev_s;
            continue;
        }
        merged_retained.push((start, len));
    }

    let public = NtfsResizePlan {
        direction,
        ntfs_version: volume.version(),
        sector_bytes,
        cluster_bytes,
        old_backing_bytes: slice_len,
        new_backing_bytes,
        old_volume_bytes: geom.volume_bytes(),
        new_volume_bytes,
        old_clusters,
        new_clusters,
        allocated_clusters: allocated_after,
        relocated_clusters,
        relocated_extents,
        old_mft_cluster: geom.mft_cluster(),
        new_mft_cluster,
        old_mirror_cluster: geom.mirror_cluster(),
        new_mirror_cluster,
        old_bitmap_bytes,
        new_bitmap_bytes,
    };

    // Keep the source bootstrap, BPB encodings and all producer-specific bytes.
    // An all-zero checksum field is unused on many native NTFS volumes.
    let mut new_vbr = source_vbr;
    new_vbr[40..48].copy_from_slice(&new_total_sectors.to_le_bytes());
    new_vbr[48..56].copy_from_slice(&new_mft_cluster.to_le_bytes());
    new_vbr[56..64].copy_from_slice(&new_mirror_cluster.to_le_bytes());
    if new_vbr[80..84] != [0; 4] {
        let checksum = ntfs_boot_sector_checksum(&new_vbr).map_err(|e| fmt_err(e.to_string()))?;
        new_vbr[80..84].copy_from_slice(&checksum.to_le_bytes());
    }
    NtfsGeometry::parse(&new_vbr, new_backing_bytes).map_err(|e| fmt_err(e.to_string()))?;

    Ok(InternalResizePlan {
        public,
        new_vbr,
        record_bytes,
        retained_spans: merged_retained,
        relocations,
        record_remaps,
        new_mft_runs,
        new_mirror_runs,
        mirror_records,
        new_bitmap_runs,
        new_bitmap_bytes: new_bitmap,
        new_bitmap_allocated_bytes: old_bitmap_allocated_bytes,
    })
}

struct ArcDevice(Arc<dyn ByteDevice>);

impl ByteDevice for ArcDevice {
    fn len_bytes(&self) -> u64 {
        self.0.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        self.0.read_exact_at(cx, offset, data)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Err(FfsError::ReadOnly)
    }
}
