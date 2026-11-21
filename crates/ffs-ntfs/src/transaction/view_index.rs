//! Shared COW multi-level view-index (`attr_type == 0`) loader and B-tree rebalancer
//! for `$Secure::$SII`, `$Secure::$SDH`, `$Extend/$Reparse::$R`, and `$Extend/$ObjId::$O`.

use std::collections::BTreeSet;

use asupersync::Cx;
use ffs_error::Result;
use ffs_ondisk::ntfs::view_index::{
    ViewCollation, encode_view_index_block, encode_view_index_entry, encode_view_index_root,
    parse_view_index_block, parse_view_index_root,
};
use ffs_ondisk::ntfs::{NtfsGeometry, NtfsRun};

use super::catalog::{normalize_ntfs_runs, stage_runs_writes};
use super::dir_index::DirPrePayloadWrite;
use super::{
    NtfsTransactionEngine, SECTOR_BYTES, checkpoint, corrupt, parse_err, read_mapped_runs,
    unsupported,
};

const MAX_VIEW_DEPTH: usize = 32;
const MAX_VIEW_BLOCKS: usize = 16_384;
const MAX_VIEW_ENTRIES: usize = 65_536;

/// Mutable view-index (`0x90` + optional `0xA0` / `0xB0`) representation attached to
/// an [`super::catalog::EditableCatalog`].
#[derive(Debug, Clone)]
pub(super) struct EditableViewIndex {
    pub(super) index_name: Vec<u16>,
    pub(super) collation: ViewCollation,
    pub(super) index_root: Vec<u8>,
    pub(super) external: Option<(Vec<NtfsRun>, u64, Vec<u8>)>,
}

/// One live `(key, data)` pair in a view-index B-tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ViewRawEntry {
    pub(super) key: Vec<u8>,
    pub(super) data: Vec<u8>,
}

/// Output of rebalancing a view-index into `INDEX_ROOT` + COW `INDX` blocks.
#[derive(Debug)]
pub(super) struct RebalancedViewIndex {
    pub(super) view_index: EditableViewIndex,
    pub(super) pre_payload_writes: Vec<DirPrePayloadWrite>,
}

impl NtfsTransactionEngine {
    /// Collect all live `(key, data)` entries in canonical collation order from `view`.
    pub(super) fn collect_view_index_entries(
        &self,
        cx: &Cx,
        view: &EditableViewIndex,
    ) -> Result<Vec<ViewRawEntry>> {
        checkpoint(cx)?;
        let root = parse_view_index_root(
            &view.index_root,
            self.geometry.cluster_bytes(),
            Some(view.collation),
        )
        .map_err(|err| parse_err(&err))?;
        let mut out = Vec::new();
        let mut visited = BTreeSet::new();
        self.collect_view_recursive(
            cx,
            view,
            root.block_bytes,
            root.vcn_bytes,
            &root.entries,
            0,
            &mut visited,
            &mut out,
        )?;
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_view_recursive(
        &self,
        cx: &Cx,
        view: &EditableViewIndex,
        block_bytes: u32,
        vcn_bytes: u32,
        entries: &[ffs_ondisk::ntfs::view_index::ViewIndexEntry],
        depth: usize,
        visited: &mut BTreeSet<u64>,
        out: &mut Vec<ViewRawEntry>,
    ) -> Result<()> {
        checkpoint(cx)?;
        if depth > MAX_VIEW_DEPTH {
            return Err(corrupt(0, "NTFS view-index B-tree depth exceeds 32"));
        }
        for entry in entries {
            if let Some(child_vcn) = entry.child_vcn {
                let (a0_runs, a0_size, _) = view
                    .external
                    .as_ref()
                    .ok_or_else(|| corrupt(0, "view-index child_vcn without INDEX_ALLOCATION"))?;
                if !visited.insert(child_vcn) {
                    return Err(corrupt(0, "cycle in NTFS view-index B-tree"));
                }
                if visited.len() > MAX_VIEW_BLOCKS {
                    return Err(unsupported("NTFS view-index exceeds 16384 blocks"));
                }
                let byte_off = child_vcn
                    .checked_mul(u64::from(vcn_bytes))
                    .ok_or_else(|| corrupt(0, "view-index child VCN overflow"))?;
                if byte_off + u64::from(block_bytes) > *a0_size {
                    return Err(corrupt(
                        byte_off,
                        "view-index child VCN exceeds INDEX_ALLOCATION",
                    ));
                }
                let raw_blk = read_mapped_runs(
                    &self.device,
                    cx,
                    &self.geometry,
                    a0_runs,
                    byte_off,
                    block_bytes as usize,
                )?;
                let (_, child_entries) =
                    parse_view_index_block(&raw_blk, child_vcn, view.collation)
                        .map_err(|err| parse_err(&err))?;
                self.collect_view_recursive(
                    cx,
                    view,
                    block_bytes,
                    vcn_bytes,
                    &child_entries,
                    depth + 1,
                    visited,
                    out,
                )?;
            }
            if !entry.is_terminal {
                if out.len() >= MAX_VIEW_ENTRIES {
                    return Err(unsupported("NTFS view-index entry count exceeds 65536"));
                }
                out.push(ViewRawEntry {
                    key: entry.key.clone(),
                    data: entry.data.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Rebuild a balanced multi-level view-index (`SMALL_INDEX` when it fits within
/// `max_root_value_bytes`, otherwise `LARGE_INDEX` with COW `INDX` blocks)
/// strictly ordered by `collation`.
pub(super) fn rebalance_view_index_tree<FAlloc>(
    geometry: &NtfsGeometry,
    index_name: &[u16],
    collation: ViewCollation,
    mut entries: Vec<ViewRawEntry>,
    max_root_value_bytes: usize,
    mut alloc_clusters: FAlloc,
) -> Result<RebalancedViewIndex>
where
    FAlloc: FnMut(u64, u64) -> Result<Vec<(u64, u64)>>,
{
    entries.sort_by(|a, b| collation.compare_keys(&a.key, &b.key));
    for pair in entries.windows(2) {
        if collation.compare_keys(&pair[0].key, &pair[1].key) == std::cmp::Ordering::Equal {
            return Err(corrupt(0, "duplicate key in NTFS view-index rebalance"));
        }
    }

    let block_bytes = geometry.index_bytes();
    let cluster_bytes = geometry.cluster_bytes();
    let vcn_bytes = if block_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let vcn_step = u64::from(block_bytes / vcn_bytes);

    let leaf_encoded: Vec<Vec<u8>> = entries
        .iter()
        .map(|e| {
            encode_view_index_entry(&e.key, &e.data, None, collation).map_err(|err| parse_err(&err))
        })
        .collect::<Result<Vec<_>>>()?;
    let total_leaf_bytes: usize = leaf_encoded.iter().map(Vec::len).sum();

    // Try SMALL_INDEX inside INDEX_ROOT first.
    if 32 + total_leaf_bytes + 16 <= max_root_value_bytes {
        let root =
            encode_view_index_root(collation, block_bytes, cluster_bytes, &leaf_encoded, None)
                .map_err(|err| parse_err(&err))?;
        return Ok(RebalancedViewIndex {
            view_index: EditableViewIndex {
                index_name: index_name.to_vec(),
                collation,
                index_root: root,
                external: None,
            },
            pre_payload_writes: Vec::new(),
        });
    }

    // Build bottom-up balanced B-tree in external INDX blocks.
    let blk_len = block_bytes as usize;
    let usa_count = blk_len / SECTOR_BYTES + 1;
    let raw_entries_off = (40 + usa_count * 2).next_multiple_of(8);
    let max_leaf_payload = blk_len
        .checked_sub(raw_entries_off + 16)
        .ok_or_else(|| corrupt(0, "INDX block too small for leaf entries"))?;
    let max_internal_payload = blk_len
        .checked_sub(raw_entries_off + 24)
        .ok_or_else(|| corrupt(0, "INDX block too small for internal entries"))?;
    let max_root_sep_payload = max_root_value_bytes.saturating_sub(32 + 24);

    // Partition entries into leaf buckets + promoted separator entries.
    // Every non-final bucket is followed by a promoted separator entry stored in its parent.
    let mut blocks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut leaf_vcns: Vec<u64> = Vec::new();
    let mut separators: Vec<ViewRawEntry> = Vec::new();

    let mut cur_leaf_raw: Vec<Vec<u8>> = Vec::new();
    let mut cur_leaf_bytes = 0_usize;
    for (idx, (entry, enc)) in entries.into_iter().zip(leaf_encoded).enumerate() {
        let _ = idx;
        if !cur_leaf_raw.is_empty() && cur_leaf_bytes + enc.len() > max_leaf_payload {
            let vcn = (blocks.len() as u64) * vcn_step;
            let blk = encode_view_index_block(collation, block_bytes, vcn, &cur_leaf_raw, None)
                .map_err(|err| parse_err(&err))?;
            blocks.push((vcn, blk));
            leaf_vcns.push(vcn);
            cur_leaf_raw.clear();
            cur_leaf_bytes = 0;
            // Promote this entry as the separator between the flushed leaf and the next leaf.
            separators.push(entry);
            continue;
        }
        cur_leaf_bytes += enc.len();
        cur_leaf_raw.push(enc);
    }
    // Always flush the final leaf block (may be empty if the last entry was promoted).
    let final_vcn = (blocks.len() as u64) * vcn_step;
    let final_blk = encode_view_index_block(collation, block_bytes, final_vcn, &cur_leaf_raw, None)
        .map_err(|err| parse_err(&err))?;
    blocks.push((final_vcn, final_blk));
    leaf_vcns.push(final_vcn);

    // Build internal levels bottom-up until the remaining separators fit inside INDEX_ROOT.
    let mut level_children = leaf_vcns;
    let mut level_seps = separators;
    let mut depth = 1_usize;

    loop {
        if depth > MAX_VIEW_DEPTH {
            return Err(corrupt(0, "rebalanced NTFS view-index exceeded depth 32"));
        }
        let encoded_seps: Vec<Vec<u8>> = level_seps
            .iter()
            .zip(level_children.iter())
            .map(|(sep, &left_vcn)| {
                encode_view_index_entry(&sep.key, &sep.data, Some(left_vcn), collation)
                    .map_err(|err| parse_err(&err))
            })
            .collect::<Result<Vec<_>>>()?;
        let total_sep_bytes: usize = encoded_seps.iter().map(Vec::len).sum();
        if total_sep_bytes <= max_root_sep_payload {
            let terminal_vcn = *level_children
                .last()
                .ok_or_else(|| corrupt(0, "empty view-index child list"))?;
            let root = encode_view_index_root(
                collation,
                block_bytes,
                cluster_bytes,
                &encoded_seps,
                Some(terminal_vcn),
            )
            .map_err(|err| parse_err(&err))?;

            let num_blocks = blocks.len();
            if num_blocks > MAX_VIEW_BLOCKS {
                return Err(unsupported("NTFS view-index exceeds 16384 INDX blocks"));
            }
            let total_bytes = (num_blocks as u64)
                .checked_mul(u64::from(block_bytes))
                .ok_or_else(|| corrupt(0, "view-index allocation size overflow"))?;
            let cb = u64::from(cluster_bytes);
            let need_clusters = total_bytes.div_ceil(cb);
            let min_chunk = u64::from(block_bytes).div_ceil(cb);
            let spans = alloc_clusters(need_clusters, min_chunk)?;
            let mut a0_runs = Vec::with_capacity(spans.len());
            let mut cur_vcn = 0_u64;
            for &(lcn, cnt) in &spans {
                a0_runs.push(NtfsRun {
                    vcn: cur_vcn,
                    clusters: cnt,
                    lcn: Some(lcn),
                });
                cur_vcn += cnt;
            }
            let a0_runs = normalize_ntfs_runs(a0_runs);
            let mut full_a0 = vec![0_u8; (need_clusters * cb) as usize];
            for (idx, (_, blk)) in blocks.iter().enumerate() {
                let off = idx * blk_len;
                full_a0[off..off + blk_len].copy_from_slice(blk);
            }
            let mut pre_payload_writes = Vec::new();
            stage_runs_writes(geometry, &a0_runs, &full_a0, &mut pre_payload_writes)?;

            let bm_bytes = num_blocks.div_ceil(8).max(8);
            let mut bitmap = vec![0_u8; bm_bytes];
            for bit_idx in 0..num_blocks {
                bitmap[bit_idx / 8] |= 1_u8 << (bit_idx % 8);
            }

            return Ok(RebalancedViewIndex {
                view_index: EditableViewIndex {
                    index_name: index_name.to_vec(),
                    collation,
                    index_root: root,
                    external: Some((a0_runs, total_bytes, bitmap)),
                },
                pre_payload_writes,
            });
        }

        // Pack `level_seps` + `level_children` into internal INDX blocks and promote dividers up.
        let mut next_children: Vec<u64> = Vec::new();
        let mut next_seps: Vec<ViewRawEntry> = Vec::new();
        let mut cur_raw: Vec<Vec<u8>> = Vec::new();
        let mut cur_bytes = 0_usize;

        for (i, (sep, enc)) in level_seps.into_iter().zip(encoded_seps).enumerate() {
            if !cur_raw.is_empty() && cur_bytes + enc.len() > max_internal_payload {
                let term_vcn = level_children[i];
                let vcn = (blocks.len() as u64) * vcn_step;
                let blk =
                    encode_view_index_block(collation, block_bytes, vcn, &cur_raw, Some(term_vcn))
                        .map_err(|err| parse_err(&err))?;
                blocks.push((vcn, blk));
                next_children.push(vcn);
                cur_raw.clear();
                cur_bytes = 0;
                next_seps.push(sep);
                continue;
            }
            cur_bytes += enc.len();
            cur_raw.push(enc);
        }
        let last_term_vcn = *level_children
            .last()
            .ok_or_else(|| corrupt(0, "empty view-index level children"))?;
        let vcn = (blocks.len() as u64) * vcn_step;
        let blk =
            encode_view_index_block(collation, block_bytes, vcn, &cur_raw, Some(last_term_vcn))
                .map_err(|err| parse_err(&err))?;
        blocks.push((vcn, blk));
        next_children.push(vcn);

        level_children = next_children;
        level_seps = next_seps;
        depth += 1;
    }
}
