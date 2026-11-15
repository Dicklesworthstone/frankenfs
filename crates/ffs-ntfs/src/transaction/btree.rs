//! General multi-level (`depth <= 32`) `$UpCase`-collated `$I30` directory B-tree
//! reader, case-aware lookup, and COW structural rebalancer (leaf/internal/root
//! splits, separator deletion, underflow merge, and `SMALL_INDEX` collapse).

use std::cmp::Ordering;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::index::{NtfsFileName, NtfsIndexRoot, encode_index_entry, parse_index_block};
use ffs_ondisk::ntfs::{NtfsReference, NtfsRun, restore_record};

use super::catalog::{EditableDirIndex, normalize_ntfs_runs};
use super::dir_index::{
    DirPrePayloadWrite, RawIndexEntrySpan, build_fresh_leaf_indx_block, parse_node_spans,
    protect_indx_block,
};
use super::{
    NtfsTransactionEngine, SECTOR_BYTES, checkpoint, corrupt, map_logical_offset, parse_err,
    read_mapped_runs, unsupported,
};

const MAX_BTREE_DEPTH: usize = 32;
const MAX_DIR_BLOCKS: usize = 16_384;
const MAX_DIR_ENTRIES: usize = 65_536;

#[derive(Debug, Clone)]
pub(super) struct I30RawEntry {
    pub(super) reference: NtfsReference,
    pub(super) file_name: NtfsFileName,
    pub(super) raw_fn_bytes: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct RebalancedI30Output {
    pub(super) dir_index: EditableDirIndex,
    pub(super) pre_payload_writes: Vec<DirPrePayloadWrite>,
}

/// Build a USA-protected internal (`flags = 1`, `LARGE_INDEX`) `INDX` block at `vcn`
/// from separator entries (each already encoded with `Some(left_child_vcn)`) plus
/// the rightmost `terminal_child_vcn`.
fn build_fresh_internal_indx_block(
    block_bytes: u32,
    vcn: u64,
    separator_entries: &[Vec<u8>],
    terminal_child_vcn: u64,
) -> Result<Vec<u8>> {
    let len = block_bytes as usize;
    if !(512..=65_536).contains(&len) || !len.is_power_of_two() {
        return Err(corrupt(0, "invalid internal INDX block_bytes"));
    }
    let usa_offset: u16 = 40;
    let usa_count = u16::try_from(len / SECTOR_BYTES + 1).map_err(|_| corrupt(0, "usa_count"))?;
    let raw_entries_off = (usize::from(usa_offset) + usize::from(usa_count) * 2 + 7) & !7;
    let rel_entries_off = raw_entries_off - 24;
    let allocated = len - 24;
    let payload_len: usize = separator_entries.iter().map(Vec::len).sum();
    // Internal terminal entry is 24 bytes (16B header + 8B child_vcn, flags = 3).
    let used = rel_entries_off + payload_len + 24;
    if used > allocated {
        return Err(FfsError::NoSpace);
    }

    let mut buf = vec![0_u8; len];
    buf[0..4].copy_from_slice(b"INDX");
    buf[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    buf[6..8].copy_from_slice(&usa_count.to_le_bytes());
    buf[8..16].copy_from_slice(&0_u64.to_le_bytes());
    buf[16..24].copy_from_slice(&vcn.to_le_bytes());
    buf[24..28].copy_from_slice(&(rel_entries_off as u32).to_le_bytes());
    buf[28..32].copy_from_slice(&(used as u32).to_le_bytes());
    buf[32..36].copy_from_slice(&(allocated as u32).to_le_bytes());
    buf[36..40].copy_from_slice(&1_u32.to_le_bytes()); // internal node flags = 1

    let mut pos = raw_entries_off;
    for ent in separator_entries {
        buf[pos..pos + ent.len()].copy_from_slice(ent);
        pos += ent.len();
    }
    // Terminal internal entry: length = 24, flags = 3 (HAS_SUBNODE | END), trailing VCN.
    buf[pos + 8..pos + 10].copy_from_slice(&24_u16.to_le_bytes());
    buf[pos + 12..pos + 14].copy_from_slice(&3_u16.to_le_bytes());
    buf[pos + 16..pos + 24].copy_from_slice(&terminal_child_vcn.to_le_bytes());

    let protected = protect_indx_block(buf, 1)?;
    let _ = parse_index_block(&protected, vcn).map_err(|err| parse_err(&err))?;
    Ok(protected)
}

fn build_small_index_root_with_entries(
    index_bytes: u32,
    cluster_bytes: u32,
    leaf_entries: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let vcn_bytes = if index_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let units = u8::try_from(index_bytes / vcn_bytes).map_err(|_| corrupt(0, "index units"))?;
    let payload_len: usize = leaf_entries.iter().map(Vec::len).sum();
    let hdr_used = 16 + payload_len + 16;
    let total_len = 16 + hdr_used;
    let mut root = vec![0_u8; total_len];
    root[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root[4..8].copy_from_slice(&1_u32.to_le_bytes());
    root[8..12].copy_from_slice(&index_bytes.to_le_bytes());
    root[12] = units;
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&(hdr_used as u32).to_le_bytes());
    root[24..28].copy_from_slice(&(hdr_used as u32).to_le_bytes());
    root[28..32].copy_from_slice(&0_u32.to_le_bytes()); // SMALL_INDEX
    let mut pos = 32_usize;
    for ent in leaf_entries {
        root[pos..pos + ent.len()].copy_from_slice(ent);
        pos += ent.len();
    }
    root[pos + 8..pos + 10].copy_from_slice(&16_u16.to_le_bytes());
    root[pos + 12..pos + 14].copy_from_slice(&2_u16.to_le_bytes());
    let _ = NtfsIndexRoot::parse(&root, cluster_bytes).map_err(|err| parse_err(&err))?;
    Ok(root)
}

fn build_large_index_root_with_separators(
    index_bytes: u32,
    cluster_bytes: u32,
    separator_entries: &[Vec<u8>],
    terminal_child_vcn: u64,
) -> Result<Vec<u8>> {
    let vcn_bytes = if index_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let units = u8::try_from(index_bytes / vcn_bytes).map_err(|_| corrupt(0, "index units"))?;
    let payload_len: usize = separator_entries.iter().map(Vec::len).sum();
    let hdr_used = 16 + payload_len + 24;
    let total_len = 16 + hdr_used;
    let mut root = vec![0_u8; total_len];
    root[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root[4..8].copy_from_slice(&1_u32.to_le_bytes());
    root[8..12].copy_from_slice(&index_bytes.to_le_bytes());
    root[12] = units;
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&(hdr_used as u32).to_le_bytes());
    root[24..28].copy_from_slice(&(hdr_used as u32).to_le_bytes());
    root[28..32].copy_from_slice(&1_u32.to_le_bytes()); // LARGE_INDEX
    let mut pos = 32_usize;
    for ent in separator_entries {
        root[pos..pos + ent.len()].copy_from_slice(ent);
        pos += ent.len();
    }
    root[pos + 8..pos + 10].copy_from_slice(&24_u16.to_le_bytes());
    root[pos + 12..pos + 14].copy_from_slice(&3_u16.to_le_bytes());
    root[pos + 16..pos + 24].copy_from_slice(&terminal_child_vcn.to_le_bytes());
    let _ = NtfsIndexRoot::parse(&root, cluster_bytes).map_err(|err| parse_err(&err))?;
    Ok(root)
}

impl NtfsTransactionEngine {
    /// Collect all live `$I30` entries in canonical in-order traversal from `dir_idx`.
    pub(super) fn collect_catalog_i30_entries(
        &self,
        cx: &Cx,
        dir_idx: &EditableDirIndex,
    ) -> Result<Vec<I30RawEntry>> {
        checkpoint(cx)?;
        let root_parsed = NtfsIndexRoot::parse(&dir_idx.index_root, self.geometry.cluster_bytes())
            .map_err(|err| parse_err(&err))?;
        let root_spans = parse_node_spans(&dir_idx.index_root, 16)?;
        let mut out = Vec::new();
        let mut visited_blocks = 0_usize;
        self.collect_spans_recursive(
            cx,
            dir_idx,
            root_parsed.block_bytes,
            root_parsed.vcn_bytes,
            root_spans,
            0,
            &mut visited_blocks,
            &mut out,
        )?;
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_spans_recursive(
        &self,
        cx: &Cx,
        dir_idx: &EditableDirIndex,
        block_bytes: u32,
        vcn_bytes: u32,
        spans: Vec<RawIndexEntrySpan>,
        depth: usize,
        visited_blocks: &mut usize,
        out: &mut Vec<I30RawEntry>,
    ) -> Result<()> {
        checkpoint(cx)?;
        if depth > MAX_BTREE_DEPTH {
            return Err(corrupt(0, "NTFS $I30 B-tree depth exceeds 32"));
        }
        for span in spans {
            if let Some(child_vcn) = span.child_vcn {
                let (a0_runs, a0_size, _) = dir_idx
                    .external
                    .as_ref()
                    .ok_or_else(|| corrupt(0, "missing $I30 INDEX_ALLOCATION for child_vcn"))?;
                *visited_blocks += 1;
                if *visited_blocks > MAX_DIR_BLOCKS {
                    return Err(corrupt(0, "$I30 traversal exceeded block budget"));
                }
                let byte_off = child_vcn
                    .checked_mul(u64::from(vcn_bytes))
                    .ok_or_else(|| corrupt(0, "$I30 VCN overflow"))?;
                if byte_off + u64::from(block_bytes) > *a0_size {
                    return Err(corrupt(byte_off, "$I30 child VCN exceeds INDEX_ALLOCATION"));
                }
                let raw_block = read_mapped_runs(
                    &self.device,
                    cx,
                    &self.geometry,
                    a0_runs,
                    byte_off,
                    block_bytes as usize,
                )?;
                let _ = parse_index_block(&raw_block, child_vcn).map_err(|err| parse_err(&err))?;
                let restored =
                    restore_record(&raw_block, b"INDX").map_err(|err| parse_err(&err))?;
                let child_spans = parse_node_spans(&restored, 24)?;
                self.collect_spans_recursive(
                    cx,
                    dir_idx,
                    block_bytes,
                    vcn_bytes,
                    child_spans,
                    depth + 1,
                    visited_blocks,
                    out,
                )?;
            }
            if let Some((reference, file_name, raw_fn_bytes)) = span.key {
                if out.len() >= MAX_DIR_ENTRIES {
                    return Err(unsupported("NTFS directory entry count exceeds 65536"));
                }
                out.push(I30RawEntry {
                    reference,
                    file_name,
                    raw_fn_bytes,
                });
            }
        }
        Ok(())
    }

    pub(super) fn catalog_directory_is_empty(
        &self,
        cx: &Cx,
        dir_idx: &EditableDirIndex,
    ) -> Result<bool> {
        let root_spans = parse_node_spans(&dir_idx.index_root, 16)?;
        if root_spans.iter().any(|s| s.key.is_some()) {
            return Ok(false);
        }
        if root_spans.iter().all(|s| s.child_vcn.is_none()) {
            return Ok(true);
        }
        Ok(self.collect_catalog_i30_entries(cx, dir_idx)?.is_empty())
    }

    /// Resolve `query_utf16` inside `dir_idx`, preferring exact UTF-16 match first,
    /// then unique `$UpCase` folded match (matching `NtfsVolume` & `NtfsFs` semantics).
    pub(super) fn lookup_in_catalog_i30(
        &self,
        cx: &Cx,
        dir_idx: &EditableDirIndex,
        query_utf16: &[u16],
    ) -> Result<Option<I30RawEntry>> {
        checkpoint(cx)?;
        let root_parsed = NtfsIndexRoot::parse(&dir_idx.index_root, self.geometry.cluster_bytes())
            .map_err(|err| parse_err(&err))?;
        let target_upper = self.fold_upcase(query_utf16);
        let root_spans = parse_node_spans(&dir_idx.index_root, 16)?;
        let mut matches = Vec::new();
        let mut visited_blocks = 0_usize;
        self.search_equal_range_recursive(
            cx,
            dir_idx,
            root_parsed.block_bytes,
            root_parsed.vcn_bytes,
            root_spans,
            &target_upper,
            0,
            &mut visited_blocks,
            &mut matches,
        )?;
        if matches.is_empty() {
            return Ok(None);
        }
        // 1. Exact UTF-16 match (prefers non-DOS if somehow paired, though exact names are unique).
        if let Some(exact) = matches
            .iter()
            .find(|m| m.file_name.name == query_utf16 && m.file_name.namespace != 2)
            .or_else(|| matches.iter().find(|m| m.file_name.name == query_utf16))
        {
            return Ok(Some(exact.clone()));
        }
        // 2. Folded `$UpCase` match: check if all folded matches point to the same base record.
        let first_ref = matches[0].reference;
        if matches.iter().any(|m| m.reference != first_ref) {
            return Err(unsupported(
                "ambiguous POSIX case-variant collision in case-folded NTFS lookup",
            ));
        }
        if let Some(non_dos) = matches.iter().find(|m| m.file_name.namespace != 2) {
            return Ok(Some(non_dos.clone()));
        }
        Ok(Some(matches[0].clone()))
    }

    #[allow(clippy::too_many_arguments)]
    fn search_equal_range_recursive(
        &self,
        cx: &Cx,
        dir_idx: &EditableDirIndex,
        block_bytes: u32,
        vcn_bytes: u32,
        spans: Vec<RawIndexEntrySpan>,
        target_upper: &[u16],
        depth: usize,
        visited_blocks: &mut usize,
        matches: &mut Vec<I30RawEntry>,
    ) -> Result<()> {
        checkpoint(cx)?;
        if depth > MAX_BTREE_DEPTH {
            return Err(corrupt(0, "NTFS $I30 lookup depth exceeds 32"));
        }
        for span in spans {
            let cmp = match &span.key {
                Some((_, fname, _)) => self.fold_upcase(&fname.name).as_slice().cmp(target_upper),
                None => Ordering::Greater,
            };
            // If `span.key >= target_upper` (or terminal), `span.child_vcn` may contain keys == target_upper!
            if matches!(cmp, Ordering::Equal | Ordering::Greater)
                && let Some(child_vcn) = span.child_vcn
            {
                let (a0_runs, a0_size, _) = dir_idx
                    .external
                    .as_ref()
                    .ok_or_else(|| corrupt(0, "missing $I30 INDEX_ALLOCATION"))?;
                *visited_blocks += 1;
                if *visited_blocks > MAX_DIR_BLOCKS {
                    return Err(corrupt(0, "$I30 search exceeded block budget"));
                }
                let byte_off = child_vcn * u64::from(vcn_bytes);
                if byte_off + u64::from(block_bytes) > *a0_size {
                    return Err(corrupt(byte_off, "$I30 child out of bounds"));
                }
                let raw_block = read_mapped_runs(
                    &self.device,
                    cx,
                    &self.geometry,
                    a0_runs,
                    byte_off,
                    block_bytes as usize,
                )?;
                let _ = parse_index_block(&raw_block, child_vcn).map_err(|err| parse_err(&err))?;
                let restored =
                    restore_record(&raw_block, b"INDX").map_err(|err| parse_err(&err))?;
                let child_spans = parse_node_spans(&restored, 24)?;
                self.search_equal_range_recursive(
                    cx,
                    dir_idx,
                    block_bytes,
                    vcn_bytes,
                    child_spans,
                    target_upper,
                    depth + 1,
                    visited_blocks,
                    matches,
                )?;
            }
            if cmp == Ordering::Equal
                && let Some((reference, file_name, raw_fn_bytes)) = span.key
            {
                matches.push(I30RawEntry {
                    reference,
                    file_name,
                    raw_fn_bytes,
                });
            }
            if cmp == Ordering::Greater {
                break;
            }
        }
        Ok(())
    }

    /// Rebuild a canonical `$I30` B-tree (collapsing to `SMALL_INDEX` when small/empty,
    /// or building dense multi-level `INDX` blocks `0..N` in newly allocated clusters).
    #[allow(clippy::too_many_lines)]
    pub(super) fn rebalance_catalog_i30_tree<FClus>(
        &self,
        mut items: Vec<I30RawEntry>,
        max_root_value_bytes: usize,
        mut alloc_indx_clusters: FClus,
    ) -> Result<RebalancedI30Output>
    where
        FClus: FnMut(u64, u64) -> Result<Vec<(u64, u64)>>,
    {
        items.sort_by(|a, b| {
            self.fold_upcase(&a.file_name.name)
                .cmp(&self.fold_upcase(&b.file_name.name))
                .then_with(|| a.file_name.name.cmp(&b.file_name.name))
                .then_with(|| a.file_name.namespace.cmp(&b.file_name.namespace))
        });

        let index_bytes = self.geometry.index_bytes();
        let cluster_bytes = self.geometry.cluster_bytes();
        let vcn_bytes = if index_bytes < cluster_bytes {
            512
        } else {
            cluster_bytes
        };
        let units_per_block = u64::from(index_bytes / vcn_bytes);

        let encoded_leaves: Vec<Vec<u8>> = items
            .iter()
            .map(|it| {
                encode_index_entry(it.reference, &it.raw_fn_bytes, None)
                    .map_err(|err| parse_err(&err))
            })
            .collect::<Result<Vec<_>>>()?;

        let small_root_payload: usize = encoded_leaves.iter().map(Vec::len).sum();
        if 32 + small_root_payload + 16 <= max_root_value_bytes {
            let index_root =
                build_small_index_root_with_entries(index_bytes, cluster_bytes, &encoded_leaves)?;
            return Ok(RebalancedI30Output {
                dir_index: EditableDirIndex {
                    index_root,
                    external: None,
                },
                pre_payload_writes: Vec::new(),
            });
        }

        let usa_count = (index_bytes as usize) / SECTOR_BYTES + 1;
        let raw_entries_off = (40 + usa_count * 2 + 7) & !7;
        let max_leaf_payload = (index_bytes as usize) - raw_entries_off - 16;
        // Target ~70% fill so subsequent inserts hit the 0-allocation fast path!
        let target_leaf_payload = (max_leaf_payload * 7 / 10).max(600).min(max_leaf_payload);
        let max_internal_payload = (index_bytes as usize) - raw_entries_off - 24;
        let target_internal_payload = (max_internal_payload * 7 / 10)
            .max(600)
            .min(max_internal_payload);

        let mut all_blocks: Vec<Vec<u8>> = Vec::new();

        // Level 0: partition `items` into leaf blocks `0..L` with promoted separators between leaves!
        // Specifically: leaf 0 holds `[0..p0)`, separator `p0` is promoted, leaf 1 holds `[p0+1..p1)`, ...
        // Wait: in NTFS B-trees (NOT B+-trees!), separator keys LIVE ONLY IN INTERNAL NODES (not duplicated in leaves)!
        let mut cur_level_child_vcns: Vec<u64> = Vec::new();
        let mut cur_level_separators: Vec<I30RawEntry> = Vec::new();
        {
            let mut idx = 0_usize;
            while idx < items.len() {
                let mut leaf_vecs = Vec::new();
                let mut used = 0_usize;
                while idx < items.len() {
                    let ent_len = encoded_leaves[idx].len();
                    if ent_len > max_leaf_payload {
                        return Err(FfsError::NoSpace);
                    }
                    // Ensure if we stop here and promote `items[idx]` as separator, at least 1 item remains for the right leaf!
                    let limit = if leaf_vecs.is_empty() {
                        max_leaf_payload
                    } else {
                        target_leaf_payload
                    };
                    if !leaf_vecs.is_empty() && used + ent_len > limit && idx + 1 < items.len() {
                        break;
                    }
                    if used + ent_len > max_leaf_payload {
                        break;
                    }
                    leaf_vecs.push(encoded_leaves[idx].clone());
                    used += ent_len;
                    idx += 1;
                }
                let block_idx = all_blocks.len() as u64;
                let block_vcn = block_idx * units_per_block;
                let block_raw = build_fresh_leaf_indx_block(index_bytes, block_vcn, &leaf_vecs)?;
                all_blocks.push(block_raw);
                cur_level_child_vcns.push(block_vcn);

                if idx < items.len() {
                    // If `idx == items.len() - 1`, we cannot leave an empty rightmost leaf unless we create an empty leaf or put the last item in a new leaf with previous item promoted!
                    if idx + 1 == items.len() {
                        // Pop the last item from the leaf we just built so `items[idx - 1]` becomes the separator and `items[idx]` forms the 1-entry rightmost leaf!
                        if leaf_vecs.len() >= 2 {
                            leaf_vecs.pop();
                            let rebuilt =
                                build_fresh_leaf_indx_block(index_bytes, block_vcn, &leaf_vecs)?;
                            *all_blocks.last_mut().expect("non-empty") = rebuilt;
                            cur_level_separators.push(items[idx - 1].clone());
                            // `idx` remains `items.len() - 1` for next iteration!
                            continue;
                        }
                    }
                    cur_level_separators.push(items[idx].clone());
                    idx += 1;
                }
            }
            if cur_level_child_vcns.len() == cur_level_separators.len() {
                let block_idx = all_blocks.len() as u64;
                let block_vcn = block_idx * units_per_block;
                let empty_leaf = build_fresh_leaf_indx_block(index_bytes, block_vcn, &[])?;
                all_blocks.push(empty_leaf);
                cur_level_child_vcns.push(block_vcn);
            }
        }

        // Iteratively promote internal levels while `(cur_level_separators + terminal)` exceeds `max_root_value_bytes`!
        let mut depth = 1_usize;
        loop {
            if depth > MAX_BTREE_DEPTH {
                return Err(unsupported("rebalanced NTFS $I30 depth exceeds 32"));
            }
            let encoded_seps: Vec<Vec<u8>> = cur_level_separators
                .iter()
                .zip(cur_level_child_vcns.iter())
                .map(|(sep, &left_vcn)| {
                    encode_index_entry(sep.reference, &sep.raw_fn_bytes, Some(left_vcn))
                        .map_err(|err| parse_err(&err))
                })
                .collect::<Result<Vec<_>>>()?;
            let root_needed = 32 + encoded_seps.iter().map(Vec::len).sum::<usize>() + 24;
            if root_needed <= max_root_value_bytes {
                let term_vcn = *cur_level_child_vcns
                    .last()
                    .ok_or_else(|| corrupt(0, "missing terminal child VCN"))?;
                let index_root = build_large_index_root_with_separators(
                    index_bytes,
                    cluster_bytes,
                    &encoded_seps,
                    term_vcn,
                )?;
                return self.materialize_rebalanced_i30(
                    index_root,
                    &all_blocks,
                    &mut alloc_indx_clusters,
                );
            }

            // Pack `cur_level_separators` + `cur_level_child_vcns` into internal `INDX` blocks!
            let mut next_child_vcns: Vec<u64> = Vec::new();
            let mut next_separators: Vec<I30RawEntry> = Vec::new();
            let n_seps = cur_level_separators.len();
            let mut idx = 0_usize;
            while idx <= n_seps {
                if idx == n_seps {
                    // Single remaining child_vcn (`cur_level_child_vcns[n_seps]`): wrap in a 0-separator internal block!
                    let block_idx = all_blocks.len() as u64;
                    let block_vcn = block_idx * units_per_block;
                    let blk = build_fresh_internal_indx_block(
                        index_bytes,
                        block_vcn,
                        &[],
                        cur_level_child_vcns[n_seps],
                    )?;
                    all_blocks.push(blk);
                    next_child_vcns.push(block_vcn);
                    break;
                }
                let mut node_seps = Vec::new();
                let mut used = 0_usize;
                while idx < n_seps {
                    let ent_len = encoded_seps[idx].len();
                    if ent_len > max_internal_payload {
                        return Err(FfsError::NoSpace);
                    }
                    let limit = if node_seps.is_empty() {
                        max_internal_payload
                    } else {
                        target_internal_payload
                    };
                    if !node_seps.is_empty() && used + ent_len > limit {
                        break;
                    }
                    if used + ent_len > max_internal_payload {
                        break;
                    }
                    node_seps.push(encoded_seps[idx].clone());
                    used += ent_len;
                    idx += 1;
                }
                let term_child = cur_level_child_vcns[idx];
                let block_idx = all_blocks.len() as u64;
                let block_vcn = block_idx * units_per_block;
                let blk = build_fresh_internal_indx_block(
                    index_bytes,
                    block_vcn,
                    &node_seps,
                    term_child,
                )?;
                all_blocks.push(blk);
                next_child_vcns.push(block_vcn);

                if idx < n_seps {
                    next_separators.push(cur_level_separators[idx].clone());
                    idx += 1;
                } else {
                    break;
                }
            }
            cur_level_child_vcns = next_child_vcns;
            cur_level_separators = next_separators;
            depth += 1;
        }
    }

    fn materialize_rebalanced_i30<FClus>(
        &self,
        index_root: Vec<u8>,
        all_blocks: &[Vec<u8>],
        alloc_indx_clusters: &mut FClus,
    ) -> Result<RebalancedI30Output>
    where
        FClus: FnMut(u64, u64) -> Result<Vec<(u64, u64)>>,
    {
        let index_bytes = self.geometry.index_bytes();
        let cluster_bytes = self.geometry.cluster_bytes();
        let total_blocks = all_blocks.len();
        if total_blocks > MAX_DIR_BLOCKS {
            return Err(unsupported("NTFS directory exceeds 16384 INDX blocks"));
        }
        let a0_size = (total_blocks as u64) * u64::from(index_bytes);
        let needed_clusters = a0_size.div_ceil(u64::from(cluster_bytes));
        let min_chunk = u64::from(index_bytes.max(cluster_bytes) / cluster_bytes);
        let spans = alloc_indx_clusters(needed_clusters, min_chunk)?;

        let mut raw_runs = Vec::with_capacity(spans.len());
        let mut cur_vcn = 0_u64;
        for &(lcn, cnt) in &spans {
            raw_runs.push(NtfsRun {
                vcn: cur_vcn,
                clusters: cnt,
                lcn: Some(lcn),
            });
            cur_vcn += cnt;
        }
        let a0_runs = normalize_ntfs_runs(raw_runs);

        let mut pre_payload_writes = Vec::with_capacity(total_blocks);
        for (i, blk) in all_blocks.iter().enumerate() {
            let logical_off = (i as u64) * u64::from(index_bytes);
            let (phys, avail, _) = map_logical_offset(&self.geometry, &a0_runs, logical_off)?;
            if avail < u64::from(index_bytes) {
                return Err(corrupt(logical_off, "sub-INDX fragmented cluster run"));
            }
            pre_payload_writes.push(DirPrePayloadWrite {
                phys_offset: phys,
                bytes: blk.clone(),
            });
        }

        // Dense 8-byte-aligned `$I30::$BITMAP` with bits `0..total_blocks` set to 1!
        let bm_len = total_blocks.div_ceil(8).max(8).next_multiple_of(8);
        let mut b0_bytes = vec![0_u8; bm_len];
        for b in 0..total_blocks {
            b0_bytes[b / 8] |= 1_u8 << (b % 8);
        }

        Ok(RebalancedI30Output {
            dir_index: EditableDirIndex {
                index_root,
                external: Some((a0_runs, a0_size, b0_bytes)),
            },
            pre_payload_writes,
        })
    }
}
