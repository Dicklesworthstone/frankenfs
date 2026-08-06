// ── Hash-tree (htree/DX) structures and algorithms ──────────────────────────

/// Parsed DX root (block 0 of an htree directory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext4DxRoot {
    /// Hash version (0=legacy, 1=half_md4, 2=tea, 3=legacy_unsigned, 4=half_md4_unsigned, 5=tea_unsigned).
    pub hash_version: u8,
    /// Indirect levels (0 = single level, 1 = two levels).
    pub indirect_levels: u8,
    /// DX entries (hash → block pairs).
    pub entries: Vec<Ext4DxEntry>,
}

/// A single DX index entry: hash value → directory block number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ext4DxEntry {
    pub hash: u32,
    pub block: u32,
}

/// Parse the DX root from the first block of a hash-indexed directory.
///
/// Layout of the DX root (after the fake "." and ".." dir entries):
///   Byte 0x18: reserved (u32)
///   Byte 0x1C: hash_version (u8)
///   Byte 0x1D: info_length (u8)
///   Byte 0x1E: indirect_levels (u8)
///   Byte 0x1F: unused_flags (u8)
///   Byte 0x20: count/limit (u16, u16)
///   Byte 0x24+: DX entries (8 bytes each: hash(4) + block(4))
pub fn parse_dx_root(block: &[u8]) -> Result<Ext4DxRoot, ParseError> {
    parse_dx_root_with_large_dir(block, false)
}

/// Parse a DX root, applying the `INCOMPAT_LARGEDIR` depth rule when requested.
///
/// ext4 permits up to 2 indirect levels for normal indexed directories, and up
/// to 3 indirect levels when the filesystem advertises `INCOMPAT_LARGEDIR`.
pub fn parse_dx_root_with_large_dir(
    block: &[u8],
    large_dir: bool,
) -> Result<Ext4DxRoot, ParseError> {
    let (hash_version, indirect_levels) = parse_dx_root_info_with_large_dir(block, large_dir)?;
    // Entries start at 0x20, with the first 8 bytes being dx_countlimit
    let entries = parse_dx_entries(block, 0x20)?;

    Ok(Ext4DxRoot {
        hash_version,
        indirect_levels,
        entries,
    })
}

fn parse_dx_root_info_with_large_dir(
    block: &[u8],
    large_dir: bool,
) -> Result<(u8, u8), ParseError> {
    // The DX root info starts at byte 0x1C in the directory block
    // (after the fake "." entry at 0x00 and ".." entry at 0x0C)
    if block.len() < 0x28 {
        return Err(ParseError::InsufficientData {
            needed: 0x28,
            offset: 0,
            actual: block.len(),
        });
    }

    let reserved_zero = read_le_u32(block, 0x18)?;
    let hash_version = block[0x1C];
    let info_length = block[0x1D];
    let indirect_levels = block[0x1E];
    let unused_flags = block[0x1F];

    // Validate
    if reserved_zero != 0 {
        return Err(ParseError::InvalidField {
            field: "dx_reserved_zero",
            reason: "expected 0",
        });
    }
    if info_length != 8 {
        return Err(ParseError::InvalidField {
            field: "dx_root_info_length",
            reason: "expected 8",
        });
    }
    let max_indirect_levels = if large_dir { 3 } else { 2 };
    if indirect_levels > max_indirect_levels {
        return Err(ParseError::InvalidField {
            field: "dx_indirect_levels",
            reason: if large_dir {
                "exceeds maximum (3) with LARGEDIR"
            } else {
                "exceeds maximum (2) without LARGEDIR"
            },
        });
    }
    if unused_flags != 0 {
        return Err(ParseError::InvalidField {
            field: "dx_unused_flags",
            reason: "expected 0",
        });
    }
    Ok((hash_version, indirect_levels))
}

/// Parse DX entries starting at `count_limit_offset` in a block.
///
/// The `count_limit_offset` points to a `dx_countlimit` structure (8 bytes),
/// followed by an array of 8-byte `Ext4DxEntry` structures.
fn parse_dx_entries(
    data: &[u8],
    count_limit_offset: usize,
) -> Result<Vec<Ext4DxEntry>, ParseError> {
    if count_limit_offset + 4 > data.len() {
        return Err(ParseError::InsufficientData {
            needed: count_limit_offset + 4,
            offset: 0,
            actual: data.len(),
        });
    }

    // dx_countlimit is 8 bytes total: limit(u16), count(u16), block(u32).
    // It doubles as the first entry (hash 0).
    let limit = usize::from(read_le_u16(data, count_limit_offset)?);
    let count = usize::from(read_le_u16(data, count_limit_offset + 2)?);
    if count > limit {
        return Err(ParseError::InvalidField {
            field: "dx_count",
            reason: "count exceeds limit",
        });
    }
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut entries = Vec::with_capacity(count);

    // Entry 0: hash is implicitly 0, block is at offset +4.
    let first_block = read_le_u32(data, count_limit_offset + 4)?;
    entries.push(Ext4DxEntry {
        hash: 0,
        block: first_block,
    });

    // Subsequent entries start at offset +8.
    let mut off = count_limit_offset + 8;
    for _ in 1..count {
        if off + 8 > data.len() {
            break;
        }
        let hash = read_le_u32(data, off)?;
        let block = read_le_u32(data, off + 4)?;
        entries.push(Ext4DxEntry { hash, block });
        off += 8;
    }

    Ok(entries)
}

fn dx_entries_materialized_len(
    data: &[u8],
    count_limit_offset: usize,
) -> Result<usize, ParseError> {
    if count_limit_offset + 4 > data.len() {
        return Err(ParseError::InsufficientData {
            needed: count_limit_offset + 4,
            offset: 0,
            actual: data.len(),
        });
    }

    let limit = usize::from(read_le_u16(data, count_limit_offset)?);
    let count = usize::from(read_le_u16(data, count_limit_offset + 2)?);
    if count > limit {
        return Err(ParseError::InvalidField {
            field: "dx_count",
            reason: "count exceeds limit",
        });
    }
    if count == 0 {
        return Ok(0);
    }

    // Match `parse_dx_entries`: entry 0's block lives in the count/limit slot,
    // and later entries are consumed only while full 8-byte records are present.
    let _ = read_le_u32(data, count_limit_offset + 4)?;
    let following = data
        .len()
        .saturating_sub(count_limit_offset.saturating_add(8))
        / 8;
    Ok(count.min(1 + following))
}

fn dx_entry_offset(count_limit_offset: usize, idx: usize) -> Result<usize, ParseError> {
    let prev = idx.checked_sub(1).ok_or(ParseError::InvalidField {
        field: "dx_entries",
        reason: "entry 0 has no explicit hash slot",
    })?;
    count_limit_offset
        .checked_add(8)
        .and_then(|base| {
            prev.checked_mul(8)
                .and_then(|delta| base.checked_add(delta))
        })
        .ok_or(ParseError::InvalidField {
            field: "dx_entries",
            reason: "entry offset overflow",
        })
}

fn dx_entry_hash_at(data: &[u8], count_limit_offset: usize, idx: usize) -> Result<u32, ParseError> {
    if idx == 0 {
        return Ok(0);
    }
    read_le_u32(data, dx_entry_offset(count_limit_offset, idx)?)
}

fn dx_entry_block_at(
    data: &[u8],
    count_limit_offset: usize,
    idx: usize,
) -> Result<u32, ParseError> {
    if idx == 0 {
        return read_le_u32(data, count_limit_offset + 4);
    }
    read_le_u32(data, dx_entry_offset(count_limit_offset, idx)? + 4)
}

fn dx_find_leaf_block_in_data(
    data: &[u8],
    count_limit_offset: usize,
    hash: u32,
) -> Result<Option<u32>, ParseError> {
    let entry_count = dx_entries_materialized_len(data, count_limit_offset)?;
    if entry_count == 0 {
        return Ok(None);
    }

    // Same rightmost <= binary search as `dx_find_leaf_idx`, but read entries
    // directly from the on-disk table instead of materializing a Vec.
    let mut lo = 0_usize;
    let mut hi = entry_count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if dx_entry_hash_at(data, count_limit_offset, mid)? <= hash {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let idx = lo.saturating_sub(1);
    dx_entry_block_at(data, count_limit_offset, idx).map(Some)
}

/// Maximum number of DX entries (including the implicit entry 0) that fit in a
/// DX root block of `block_size` bytes.
///
/// The DX entry area begins at offset `0x20` (the `dx_countlimit`, which doubles
/// as entry 0) and each slot is 8 bytes. When `metadata_csum` is enabled the
/// final 8-byte slot holds a `dx_tail` (reserved + CRC32C), so one slot is
/// reserved. This is the value the kernel stores in the `limit` field.
#[must_use]
pub fn dx_root_entry_limit(block_size: usize, has_metadata_csum: bool) -> u16 {
    let slots = block_size.saturating_sub(0x20) / 8;
    let usable = if has_metadata_csum {
        slots.saturating_sub(1)
    } else {
        slots
    };
    u16::try_from(usable).unwrap_or(u16::MAX)
}

/// Maximum number of DX entries (including the implicit entry 0) that fit in an
/// interior `dx_node` block (an indirect level) of `block_size` bytes.
///
/// Unlike a DX root, an interior node has no `.`/`..` dirents: its entry area
/// begins at [`DX_NODE_COUNT_OFFSET`] (`0x08`, just past the 8-byte fake
/// dirent), so it fits one more slot than the root. As with the root, a
/// `metadata_csum` filesystem reserves the trailing 8-byte slot for the
/// `dx_tail`. This is the `limit` the kernel stores in an interior node.
#[must_use]
pub fn dx_node_entry_limit(block_size: usize, has_metadata_csum: bool) -> u16 {
    let slots = block_size.saturating_sub(DX_NODE_COUNT_OFFSET) / 8;
    let usable = if has_metadata_csum {
        slots.saturating_sub(1)
    } else {
        slots
    };
    u16::try_from(usable).unwrap_or(u16::MAX)
}

/// Serialize the DX root index structures into directory block 0, in place.
///
/// Writes the `dx_root_info` (`0x18..0x20`), the `dx_countlimit` (`0x20`), and
/// the DX entry array. Entry 0 is the implicit-hash-0 sentinel whose block is
/// stored in the `dx_countlimit` slot at `0x24`; subsequent entries follow as
/// `(hash, block)` pairs at `0x28+`. The caller must have already written the
/// fake "." and ".." directory entries into `0x00..0x18` (and, when
/// `metadata_csum` is enabled, must stamp the `dx_tail` after this call). This
/// is the exact inverse of [`parse_dx_root`]; the byte layout is pinned against
/// the kernel by `write_dx_root_round_trips_with_parse`.
///
/// `entries[0].hash` is ignored (the kernel stores no hash for entry 0).
pub fn write_dx_root(
    block: &mut [u8],
    hash_version: u8,
    indirect_levels: u8,
    limit: u16,
    entries: &[Ext4DxEntry],
) -> Result<(), ParseError> {
    if entries.is_empty() {
        return Err(ParseError::InvalidField {
            field: "dx_entries",
            reason: "must contain at least the implicit entry 0",
        });
    }
    let count = u16::try_from(entries.len()).map_err(|_| ParseError::InvalidField {
        field: "dx_count",
        reason: "entry count does not fit in u16",
    })?;
    if count > limit {
        return Err(ParseError::InvalidField {
            field: "dx_count",
            reason: "entry count exceeds limit",
        });
    }
    // Bytes consumed: dx_root_info ends at 0x20; countlimit+entry0 occupy
    // 0x20..0x28; each remaining entry is 8 bytes from 0x28.
    let needed = 0x28 + (entries.len() - 1) * 8;
    if needed > block.len() {
        return Err(ParseError::InsufficientData {
            needed,
            offset: 0,
            actual: block.len(),
        });
    }

    // dx_root_info @ 0x18..0x20
    block[0x18..0x1C].copy_from_slice(&0_u32.to_le_bytes()); // reserved_zero
    block[0x1C] = hash_version;
    block[0x1D] = 8; // info_length (parser-required)
    block[0x1E] = indirect_levels;
    block[0x1F] = 0; // unused_flags

    // dx_countlimit @ 0x20: limit(u16), count(u16); doubles as entry 0.
    block[0x20..0x22].copy_from_slice(&limit.to_le_bytes());
    block[0x22..0x24].copy_from_slice(&count.to_le_bytes());
    block[0x24..0x28].copy_from_slice(&entries[0].block.to_le_bytes());

    // Entries 1.. @ 0x28: (hash, block) pairs.
    let mut off = 0x28;
    for entry in &entries[1..] {
        block[off..off + 4].copy_from_slice(&entry.hash.to_le_bytes());
        block[off + 4..off + 8].copy_from_slice(&entry.block.to_le_bytes());
        off += 8;
    }

    Ok(())
}

/// Serialize an interior DX node (an indirect index level) into a directory
/// block, in place.
///
/// Mirrors [`write_dx_root`] but for the interior-node layout the read-half
/// parses at [`DX_NODE_COUNT_OFFSET`] (`0x08`): an 8-byte fake dirent (inode 0,
/// `rec_len` spanning the whole block, so a linear scan treats the block as one
/// empty record), then the `dx_countlimit` at `0x08` (doubling as entry 0, whose
/// block is at `0x0C`), then `(hash, block)` pairs from `0x10`. As in the root,
/// `entries[0].hash` is ignored (the read-half forces entry 0's hash to 0). When
/// `metadata_csum` is enabled the caller must stamp the `dx_tail` afterwards via
/// [`stamp_dx_block_checksum`] with [`DX_NODE_COUNT_OFFSET`]. This is the inverse
/// of the interior-node case of [`parse_dx_entries`].
pub fn write_dx_node(
    block: &mut [u8],
    limit: u16,
    entries: &[Ext4DxEntry],
) -> Result<(), ParseError> {
    if entries.is_empty() {
        return Err(ParseError::InvalidField {
            field: "dx_entries",
            reason: "must contain at least the implicit entry 0",
        });
    }
    let count = u16::try_from(entries.len()).map_err(|_| ParseError::InvalidField {
        field: "dx_count",
        reason: "entry count does not fit in u16",
    })?;
    if count > limit {
        return Err(ParseError::InvalidField {
            field: "dx_count",
            reason: "entry count exceeds limit",
        });
    }
    // Bytes consumed: fake dirent 0x00..0x08; countlimit+entry0 occupy
    // 0x08..0x10; each remaining entry is 8 bytes from 0x10.
    let needed = DX_NODE_COUNT_OFFSET + 8 + (entries.len() - 1) * 8;
    if needed > block.len() {
        return Err(ParseError::InsufficientData {
            needed,
            offset: 0,
            actual: block.len(),
        });
    }

    // Fake dirent @ 0x00..0x08: inode 0, rec_len spanning the block.
    let bs = block.len();
    block[0..4].copy_from_slice(&0_u32.to_le_bytes());
    block[4..6].copy_from_slice(&rec_len_to_disk(bs).to_le_bytes());
    block[6] = 0; // name_len
    block[7] = 0; // file_type

    // dx_countlimit @ 0x08: limit(u16), count(u16); doubles as entry 0.
    block[0x08..0x0A].copy_from_slice(&limit.to_le_bytes());
    block[0x0A..0x0C].copy_from_slice(&count.to_le_bytes());
    block[0x0C..0x10].copy_from_slice(&entries[0].block.to_le_bytes());

    // Entries 1.. @ 0x10: (hash, block) pairs.
    let mut off = 0x10;
    for entry in &entries[1..] {
        block[off..off + 4].copy_from_slice(&entry.hash.to_le_bytes());
        block[off + 4..off + 8].copy_from_slice(&entry.block.to_le_bytes());
        off += 8;
    }

    Ok(())
}

/// Choose where to split a full htree leaf during directory growth (write-half
/// STEP 2 of bd-gauub).
///
/// `entries` is the leaf's contents as `(name_hash, on_disk_record_len)` in
/// ascending hash order (the caller hashes each name with the directory's hash
/// version + seed and sorts). Returns `(split_index, split_hash)` where:
/// `entries[..split_index]` stay in the original leaf and
/// `entries[split_index..]` move to the new leaf, and `split_hash =
/// entries[split_index].hash` is inserted into the DX index. Because
/// `dx_find_leaf_idx` routes a lookup to the rightmost entry with
/// `hash <= target`, the new (right) leaf must hold exactly the hashes
/// `>= split_hash`; therefore the split MUST fall on a clean hash boundary
/// (`entries[i].hash != entries[i-1].hash`) so that no run of equal-hash names
/// is straddled across two leaves (which dx navigation would then miss).
///
/// Among the clean boundaries, the one whose byte split is closest to 50/50 is
/// chosen for balance. Returns `None` when no clean boundary exists (fewer than
/// two distinct hashes) — the caller must then fall back (hash-collision
/// continuation is a separate, deferred concern; a linear leaf stays correct).
///
/// A subset of a single block's entries always re-fits in one block, so no
/// size-overflow check is needed beyond the caller's normal packing.
#[must_use]
pub fn choose_htree_leaf_split(entries: &[(u32, usize)]) -> Option<(usize, u32)> {
    if entries.len() < 2 {
        return None;
    }
    let total: usize = entries.iter().map(|&(_, len)| len).sum();
    let target = total / 2;

    let mut bytes_before = 0_usize; // sum of entries[..i] record lengths
    let mut best: Option<(usize, usize)> = None; // (split_index, |bytes_before - target|)
    for i in 1..entries.len() {
        bytes_before += entries[i - 1].1;
        // A clean boundary: the hash strictly increases here (entries sorted).
        if entries[i].0 != entries[i - 1].0 {
            let dist = bytes_before.abs_diff(target);
            if best.is_none_or(|(_, best_dist)| dist < best_dist) {
                best = Some((i, dist));
            }
        }
    }
    best.map(|(i, _)| (i, entries[i].0))
}

/// On-disk record length of a directory entry with `name_len` bytes of name:
/// the 8-byte header plus the name, rounded up to 4-byte alignment
/// (`EXT4_DIR_REC_LEN`).
#[must_use]
pub fn dir_entry_rec_len(name_len: usize) -> usize {
    (8 + name_len + 3) & !3
}

/// Encode a 4-byte-aligned `rec_len` into the on-disk `u16` field (inverse of
/// `rec_len_from_disk` for `block_size <= 65536`). A length equal to a 64 KiB
/// block is stored as 0 per the kernel convention.
fn rec_len_to_disk(rec_len: usize) -> u16 {
    // Exactly 64 KiB does not fit u16 and is encoded as 0 (kernel convention);
    // all other 4-byte-aligned, < 64 KiB lengths store directly.
    u16::try_from(rec_len).unwrap_or(0)
}

/// Pack directory entries into a fresh directory/leaf block (write-half STEP 3
/// of bd-gauub).
///
/// Entries `(inode, file_type_raw, name)` are laid out from offset 0, each with
/// `rec_len = dir_entry_rec_len(name_len)`; the final entry's `rec_len` is
/// extended to span the remaining free space up to the checksum tail. When
/// `with_csum_tail` is set, the last 12 bytes hold a dirent checksum tail
/// (inode=0, rec_len=12, file_type=`EXT4_FT_DIR_CSUM`) whose CRC32C field is left
/// zero for the caller to stamp via [`stamp_dir_block_checksum`]. An empty entry
/// list yields a single empty filler entry spanning the usable area. This is the
/// inverse of the entry walk in [`parse_dir_block`]; round-trip pinned by
/// `pack_dir_block_entries_round_trips`.
pub fn pack_dir_block_entries(
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    with_csum_tail: bool,
) -> Result<Vec<u8>, ParseError> {
    if !(12..=65536).contains(&block_size) {
        return Err(ParseError::InvalidField {
            field: "block_size",
            reason: "directory block size must be in 12..=65536",
        });
    }
    let usable_end = if with_csum_tail {
        block_size - 12
    } else {
        block_size
    };

    let mut block = vec![0_u8; block_size];

    if entries.is_empty() {
        // One empty filler entry spanning the usable area (inode 0, name_len 0).
        block[4..6].copy_from_slice(&rec_len_to_disk(usable_end).to_le_bytes());
    } else {
        let mut offset = 0_usize;
        for (i, &(inode, file_type_raw, name)) in entries.iter().enumerate() {
            let name_len = name.len();
            if name_len == 0 || name_len > EXT4_MAX_NAME_BYTES {
                return Err(ParseError::InvalidField {
                    field: "name_len",
                    reason: "directory entry name length must be 1..=255",
                });
            }
            let min_rec = dir_entry_rec_len(name_len);
            if offset + min_rec > usable_end {
                return Err(ParseError::InvalidField {
                    field: "dir_block",
                    reason: "entries do not fit in the directory block",
                });
            }
            let is_last = i == entries.len() - 1;
            let rec_len = if is_last {
                usable_end - offset
            } else {
                min_rec
            };

            block[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
            block[offset + 4..offset + 6].copy_from_slice(&rec_len_to_disk(rec_len).to_le_bytes());
            block[offset + 6] = u8::try_from(name_len).map_err(|_| ParseError::InvalidField {
                field: "name_len",
                reason: "directory entry name length exceeds 255",
            })?;
            block[offset + 7] = file_type_raw;
            block[offset + 8..offset + 8 + name_len].copy_from_slice(name);

            offset += rec_len;
        }
    }

    if with_csum_tail {
        let t = usable_end;
        // inode (0) already zero; rec_len = 12; name_len (0) already zero.
        block[t + 4..t + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[t + 7] = EXT4_FT_DIR_CSUM;
        // CRC32C field at t+8..t+12 stays zero for the caller to stamp.
    }

    Ok(block)
}

/// Build a complete single-level hash-indexed (htree) directory from a set of
/// entries (write-half STEP 4 of bd-gauub).
///
/// Composes the write-half building blocks: hashes each name (`dx_hash`), sorts
/// by major hash, distributes entries into leaf blocks at clean hash boundaries,
/// packs each leaf ([`pack_dir_block_entries`]), and builds the DX root in block
/// 0 ([`write_dx_root`]) inside the space owned by the fake ".."/"." entries.
///
/// Returns the directory's logical blocks `[dx_root, leaf_0, leaf_1, ...]`
/// (leaf *i* is logical block `i + 1`). Checksums are NOT stamped (the caller
/// stamps leaf + dx_tail CRC32C when `metadata_csum` is enabled); pass
/// `with_csum_tail` to reserve the per-leaf tail slot so sizes are accounted.
///
/// Returns `None` when the directory cannot be represented as a single-level
/// htree: more leaves than the DX root can index (needs indirect levels), or a
/// single hash value whose entries overflow one leaf (needs collision-chain
/// continuation). Both are deferred; the caller falls back to a linear directory
/// (which stays correct). The produced index is navigable by the read-half
/// [`htree_find_entry`] — pinned by `build_htree_directory_is_navigable`.
#[must_use]
#[allow(clippy::type_complexity)] // local (hash, entry) staging tuples
pub fn build_htree_directory(
    dot_inode: u32,
    dotdot_inode: u32,
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    with_csum_tail: bool,
) -> Option<Vec<Vec<u8>>> {
    build_htree_directory_with_large_dir(
        dot_inode,
        dotdot_inode,
        entries,
        block_size,
        hash_version,
        hash_seed,
        with_csum_tail,
        false,
    )
}

/// Build a hash-indexed directory, allowing the extra `large_dir` index depth.
///
/// Like [`build_htree_directory`] but allows a third indirect level
/// (`indirect_levels == 3`) when `has_large_dir` is set, matching the kernel's
/// `INCOMPAT_LARGEDIR` depth rule (and [`parse_dx_root_with_large_dir`]). With
/// `has_large_dir == false` this is identical to [`build_htree_directory`].
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_htree_directory_with_large_dir(
    dot_inode: u32,
    dotdot_inode: u32,
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    with_csum_tail: bool,
    has_large_dir: bool,
) -> Option<Vec<Vec<u8>>> {
    build_htree_layout(
        dot_inode,
        dotdot_inode,
        entries,
        block_size,
        hash_version,
        hash_seed,
        with_csum_tail,
        has_large_dir,
        false,
        false,
    )
    .map(|layout| layout.blocks)
}

/// Casefold counterpart of [`build_htree_directory_with_large_dir`] (no checksum
/// tail).
///
/// Hashes each entry by its case-folded name while storing the original case.
/// ASCII-only; see the stamped casefold builder for the rationale.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_htree_directory_with_large_dir_casefold(
    dot_inode: u32,
    dotdot_inode: u32,
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    with_csum_tail: bool,
    has_large_dir: bool,
) -> Option<Vec<Vec<u8>>> {
    build_htree_layout(
        dot_inode,
        dotdot_inode,
        entries,
        block_size,
        hash_version,
        hash_seed,
        with_csum_tail,
        has_large_dir,
        true,
        false,
    )
    .map(|layout| layout.blocks)
}

/// A freshly-built hash-indexed directory in logical-block order
/// `[dx_root, leaf_0 .. leaf_{L-1}, node_0 .. node_{N-1}]`, plus the leaf count
/// `L` so the stamped builder can checksum leaves (as dir blocks) and interior
/// `dx_node` blocks (as index blocks) with the right formulas. `N == 0` for a
/// single-level index (`indirect_levels == 0`).
struct HtreeLayout {
    blocks: Vec<Vec<u8>>,
    leaf_count: usize,
}

/// Build the block images for a hash-indexed directory, choosing a single-level
/// index (`indirect_levels == 0`) when the leaves fit in the DX root, or a
/// two-level index (`indirect_levels == 1`) when they do not. Returns `None`
/// when even two levels cannot hold the directory (a third indirect level would
/// be required) or when a single hash value's run overflows one leaf (needs a
/// collision chain), matching the cases the read-half cannot otherwise resolve.
#[allow(clippy::type_complexity)] // local (hash, entry) staging tuples
#[allow(clippy::too_many_lines)] // single + multi-level construction in one pass
#[allow(clippy::too_many_arguments)] // mirrors the build_htree_directory surface
#[allow(clippy::fn_params_excessive_bools)] // with_csum/large_dir/casefold/loose flags
fn build_htree_layout(
    dot_inode: u32,
    dotdot_inode: u32,
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    with_csum_tail: bool,
    has_large_dir: bool,
    casefold: bool,
    loose_pack: bool,
) -> Option<HtreeLayout> {
    if !(64..=65536).contains(&block_size) || entries.is_empty() {
        return None;
    }
    let usable = if with_csum_tail {
        block_size - 12
    } else {
        block_size
    };
    // Soft fill limit: a `loose_pack` build (the rebuild path) leaves ~50% leaf
    // slack so a growing directory's rebuilds follow a doubling schedule —
    // bounding total work for N inserts to O(N) instead of rebuilding the whole
    // directory on (nearly) every create (O(N^2)). The hard `usable` cap still
    // applies to un-splittable equal-hash runs.
    let fill_limit = if loose_pack {
        (usable / 2).max(1)
    } else {
        usable
    };

    // Casefold directories index by the case-folded name (byte-exact for ASCII),
    // while the leaf still stores the original-case name; non-casefold hashes the
    // name verbatim.
    let name_hash = |name: &[u8]| -> u32 {
        if casefold {
            dx_hash(hash_version, &casefold_name(name), hash_seed).0
        } else {
            dx_hash(hash_version, name, hash_seed).0
        }
    };

    // Hash every name and sort by major hash (the value stored in DX entries).
    let mut hashed: Vec<(u32, (u32, u8, &[u8]))> = entries
        .iter()
        .map(|&(ino, ft, name)| (name_hash(name), (ino, ft, name)))
        .collect();
    // Unstable: only ever start a new leaf on a clean hash boundary (below), so
    // equal-hash ties stay in one leaf and their order is irrelevant — avoid the
    // stable sort's temp buffer (1.47x, bench htree_split_sort).
    hashed.sort_unstable_by_key(|&(h, _)| h);

    // Distribute into leaves, only ever starting a new leaf on a clean hash
    // boundary (so the read-half routes every name to the leaf that holds it).
    let mut leaves: Vec<Vec<(u32, u8, &[u8])>> = Vec::new();
    let mut current: Vec<(u32, u8, &[u8])> = Vec::new();
    let mut current_bytes = 0_usize;
    let mut last_hash: Option<u32> = None;
    for (hash, entry) in hashed {
        let rec = dir_entry_rec_len(entry.2.len());
        if rec > usable {
            return None; // a single entry cannot fit a block
        }
        let same_hash_as_prev = last_hash == Some(hash);
        // Hard cap: an equal-hash run that cannot be split must fit one full leaf.
        if !current.is_empty() && current_bytes + rec > usable && same_hash_as_prev {
            return None; // equal-hash run overflows one leaf — needs collision chain
        }
        // Soft cap: start a new leaf at the fill limit, only on a clean hash
        // boundary (never split an equal-hash run).
        if !current.is_empty() && current_bytes + rec > fill_limit && !same_hash_as_prev {
            leaves.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current.push(entry);
        current_bytes += rec;
        last_hash = Some(hash);
    }
    leaves.push(current);

    let leaf_count = leaves.len();

    // The minimum hash a leaf covers: entry 0's hash is implicitly 0; every
    // later leaf is identified by the hash of its first (lowest-hash) name.
    let leaf_min_hash = |i: usize| -> Option<u32> {
        if i == 0 {
            Some(0)
        } else {
            Some(name_hash(leaves[i].first()?.2))
        }
    };

    // Leaf blocks occupy logical blocks 1..=L regardless of index depth.
    let mut leaf_blocks = Vec::with_capacity(leaf_count);
    for leaf in &leaves {
        leaf_blocks.push(pack_dir_block_entries(leaf, block_size, with_csum_tail).ok()?);
    }

    // Block 0: fake "." and ".." entries; the ".." rec_len spans the DX area.
    let mut root = vec![0_u8; block_size];
    root[0..4].copy_from_slice(&dot_inode.to_le_bytes());
    root[4..6].copy_from_slice(&12_u16.to_le_bytes());
    root[6] = 1; // name_len
    root[7] = EXT4_FT_DIR;
    root[8] = b'.';
    root[12..16].copy_from_slice(&dotdot_inode.to_le_bytes());
    root[16..18].copy_from_slice(&rec_len_to_disk(block_size - 12).to_le_bytes());
    root[18] = 2; // name_len
    root[19] = EXT4_FT_DIR;
    root[20] = b'.';
    root[21] = b'.';

    let root_limit = dx_root_entry_limit(block_size, with_csum_tail);

    if leaf_count <= usize::from(root_limit) {
        // Single level: DX root entries point straight at the leaves.
        let mut dx_entries = Vec::with_capacity(leaf_count);
        for i in 0..leaf_count {
            dx_entries.push(Ext4DxEntry {
                hash: leaf_min_hash(i)?,
                block: u32::try_from(i + 1).ok()?,
            });
        }
        write_dx_root(&mut root, hash_version, 0, root_limit, &dx_entries).ok()?;
        let mut blocks = Vec::with_capacity(leaf_count + 1);
        blocks.push(root);
        blocks.extend(leaf_blocks);
        return Some(HtreeLayout { blocks, leaf_count });
    }

    // Multi-level: build interior dx_node levels bottom-up. Each interior node
    // indexes up to `node_limit` children; the DX root indexes up to
    // `root_limit`. A child is represented to its parent by `(min_hash, block)`,
    // where `min_hash` is the lowest hash in its subtree — its leftmost leaf.
    // Because the leaves are hash-sorted and every level groups contiguously,
    // these representative hashes stay monotonic, so the read-half's
    // `dx_find_leaf_idx` routes correctly at every level (entry 0's hash is
    // ignored, which is exactly the leftmost child that covers hash 0).
    //
    // The kernel caps a non-`large_dir` index at `indirect_levels <= 2` (three
    // block levels), which is what `parse_dx_root` accepts; the `large_dir`
    // feature raises that to `indirect_levels <= 3`, matching
    // `parse_dx_root_with_large_dir`. We refuse to build a depth the on-disk
    // feature flags would make unreadable, returning `None` past the cap (a
    // two-level index already addresses tens of millions of entries).
    let max_indirect_levels: u8 = if has_large_dir { 3 } else { 2 };
    let node_limit_u16 = dx_node_entry_limit(block_size, with_csum_tail);
    let node_limit = usize::from(node_limit_u16);
    if node_limit < 2 {
        return None;
    }

    // Interior nodes occupy logical blocks (L+1).., appended in creation order
    // (bottom level first), which matches their assigned logical numbers.
    let mut interior_blocks: Vec<Vec<u8>> = Vec::new();
    let mut next_logical = u32::try_from(leaf_count + 1).ok()?;

    // The children the current level must index: start with the leaves.
    let mut children: Vec<Ext4DxEntry> = Vec::with_capacity(leaf_count);
    for p in 0..leaf_count {
        children.push(Ext4DxEntry {
            hash: leaf_min_hash(p)?,
            block: u32::try_from(p + 1).ok()?,
        });
    }

    let mut indirect_levels: u8 = 0;
    while children.len() > usize::from(root_limit) {
        if indirect_levels >= max_indirect_levels {
            return None; // would exceed the readable depth for this feature set
        }
        let mut parents: Vec<Ext4DxEntry> = Vec::with_capacity(children.len().div_ceil(node_limit));
        let mut i = 0;
        while i < children.len() {
            let end = (i + node_limit).min(children.len());
            let chunk = &children[i..end];
            let node_logical = next_logical;
            next_logical = next_logical.checked_add(1)?;
            // Representative hash = this node's leftmost child's hash (the lowest
            // hash in its subtree). For the very first node it is 0, which the
            // read-half assumes for entry 0 anyway.
            let rep_hash = chunk[0].hash;
            let mut node = vec![0_u8; block_size];
            write_dx_node(&mut node, node_limit_u16, chunk).ok()?;
            interior_blocks.push(node);
            parents.push(Ext4DxEntry {
                hash: rep_hash,
                block: node_logical,
            });
            i = end;
        }
        children = parents;
        indirect_levels += 1;
    }

    write_dx_root(
        &mut root,
        hash_version,
        indirect_levels,
        root_limit,
        &children,
    )
    .ok()?;

    let mut blocks = Vec::with_capacity(1 + leaf_count + interior_blocks.len());
    blocks.push(root);
    blocks.extend(leaf_blocks);
    blocks.extend(interior_blocks);
    Some(HtreeLayout { blocks, leaf_count })
}

/// Build a complete `metadata_csum`-ready hash-indexed directory.
///
/// Like [`build_htree_directory`] (with checksum tails reserved) but with every
/// block's CRC32C stamped — the DX root via [`stamp_dx_block_checksum`] and each
/// leaf via [`stamp_dir_block_checksum`], all under the directory inode's
/// per-inode seed. The returned `[dx_root, leaf_0, ...]` blocks are ready to
/// write to disk and pass `e2fsck` on a `metadata_csum` filesystem. This is the
/// artifact the linear->htree conversion path writes. Returns `None` for the
/// same deferred cases as [`build_htree_directory`].
///
/// Validated by `build_htree_directory_stamped_is_navigable_and_checksummed`:
/// the result is navigable by the read-half AND every block's checksum verifies
/// under the e2fsprogs-pinned formulas.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_htree_directory_stamped(
    dot_inode: u32,
    dotdot_inode: u32,
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    csum_seed: u32,
    dir_ino: u32,
    generation: u32,
) -> Option<Vec<Vec<u8>>> {
    build_htree_directory_stamped_with_large_dir(
        dot_inode,
        dotdot_inode,
        entries,
        block_size,
        hash_version,
        hash_seed,
        csum_seed,
        dir_ino,
        generation,
        false,
    )
}

/// Build a checksummed hash-indexed directory, allowing `large_dir` depth.
///
/// Like [`build_htree_directory_stamped`] but allows a third indirect level
/// when `has_large_dir` is set (the checksummed analogue of
/// [`build_htree_directory_with_large_dir`]). The extra interior level is
/// stamped as a `dx_node` index block exactly like the existing levels, so the
/// result stays e2fsck-clean on a `metadata_csum` + `large_dir` filesystem.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_htree_directory_stamped_with_large_dir(
    dot_inode: u32,
    dotdot_inode: u32,
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    csum_seed: u32,
    dir_ino: u32,
    generation: u32,
    has_large_dir: bool,
) -> Option<Vec<Vec<u8>>> {
    build_htree_directory_stamped_with_large_dir_inner(
        dot_inode,
        dotdot_inode,
        entries,
        block_size,
        hash_version,
        hash_seed,
        csum_seed,
        dir_ino,
        generation,
        has_large_dir,
        false,
        false,
    )
}

/// Casefold counterpart of [`build_htree_directory_stamped_with_large_dir`].
///
/// Hashes each entry by its case-folded name (byte-exact to the kernel for ASCII)
/// while storing the original-case name in the leaf, so a rebuilt casefold
/// directory keeps the same fold-indexed layout the kernel would produce. Callers
/// must restrict this to entries whose fold is exact (ASCII).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_htree_directory_stamped_with_large_dir_casefold(
    dot_inode: u32,
    dotdot_inode: u32,
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    csum_seed: u32,
    dir_ino: u32,
    generation: u32,
    has_large_dir: bool,
) -> Option<Vec<Vec<u8>>> {
    build_htree_directory_stamped_with_large_dir_inner(
        dot_inode,
        dotdot_inode,
        entries,
        block_size,
        hash_version,
        hash_seed,
        csum_seed,
        dir_ino,
        generation,
        has_large_dir,
        true,
        false,
    )
}

/// Build a hash-indexed directory for the REBUILD path, with explicit
/// `with_csum` / `casefold` / `loose_pack` options.
///
/// `loose_pack` leaves ~50% leaf slack so a growing directory's rebuilds follow a
/// doubling schedule — total work for N inserts is O(N) instead of O(N^2) when
/// every create would otherwise re-pack and re-rebuild the whole directory.
/// `with_csum` selects the metadata_csum-stamped layout. Used only by the
/// directory-rebuild path; one-shot builders stay tightly packed.
#[must_use]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)] // large_dir/casefold/with_csum/loose flags
pub fn build_htree_directory_for_rebuild(
    dot_inode: u32,
    dotdot_inode: u32,
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    csum_seed: u32,
    dir_ino: u32,
    generation: u32,
    has_large_dir: bool,
    casefold: bool,
    with_csum: bool,
    loose_pack: bool,
) -> Option<Vec<Vec<u8>>> {
    if with_csum {
        build_htree_directory_stamped_with_large_dir_inner(
            dot_inode,
            dotdot_inode,
            entries,
            block_size,
            hash_version,
            hash_seed,
            csum_seed,
            dir_ino,
            generation,
            has_large_dir,
            casefold,
            loose_pack,
        )
    } else {
        build_htree_layout(
            dot_inode,
            dotdot_inode,
            entries,
            block_size,
            hash_version,
            hash_seed,
            false,
            has_large_dir,
            casefold,
            loose_pack,
        )
        .map(|layout| layout.blocks)
    }
}

#[allow(clippy::too_many_arguments)]
fn build_htree_directory_stamped_with_large_dir_inner(
    dot_inode: u32,
    dotdot_inode: u32,
    entries: &[(u32, u8, &[u8])],
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    csum_seed: u32,
    dir_ino: u32,
    generation: u32,
    has_large_dir: bool,
    casefold: bool,
    loose_pack: bool,
) -> Option<Vec<Vec<u8>>> {
    let HtreeLayout {
        mut blocks,
        leaf_count,
    } = build_htree_layout(
        dot_inode,
        dotdot_inode,
        entries,
        block_size,
        hash_version,
        hash_seed,
        true,
        has_large_dir,
        casefold,
        loose_pack,
    )?;
    // Layout is [dx_root, leaf_0..leaf_{L-1}, node_0..node_{N-1}]: the root and
    // any interior nodes are index blocks (dx_tail CRC32C), the leaves are
    // directory blocks (dir-tail CRC32C).
    stamp_dx_block_checksum(
        &mut blocks[0],
        csum_seed,
        dir_ino,
        generation,
        DX_ROOT_COUNT_OFFSET,
    );
    for leaf in &mut blocks[1..=leaf_count] {
        stamp_dir_block_checksum(leaf, csum_seed, dir_ino, generation);
    }
    for node in &mut blocks[leaf_count + 1..] {
        stamp_dx_block_checksum(node, csum_seed, dir_ino, generation, DX_NODE_COUNT_OFFSET);
    }
    Some(blocks)
}

/// Find the rightmost entry index whose hash is <= target_hash.
#[must_use]
pub fn dx_find_leaf_idx(entries: &[Ext4DxEntry], hash: u32) -> usize {
    // Binary search: find rightmost entry where entry.hash <= hash
    let mut lo = 0_usize;
    let mut hi = entries.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if entries[mid].hash <= hash {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    // lo-1 is the rightmost entry with hash <= target (lo >= 1 due to sentinel)
    if lo > 0 { lo - 1 } else { 0 }
}

// ── Raw dx-index accessors (no `Vec<Ext4DxEntry>` materialization) ──────────
//
// A dx index block packs 8-byte entries after an 8-byte countlimit header at
// `count_offset`: entry 0 stores only a block ptr at `+4` (its hash is implicitly
// 0); entry `i>=1` stores hash at `+8*i` and block ptr at `+8*i+4`. Reading the
// few entries a binary search actually touches — instead of parsing all of them
// into a Vec on every lookup — is the point of these (bd-cc-dxraw).

#[inline]
fn dx_entry_hash_raw(block: &[u8], count_offset: usize, idx: usize) -> Option<u32> {
    if idx == 0 {
        return Some(0);
    }
    let off = count_offset.checked_add(idx.checked_mul(8)?)?;
    read_le_u32(block, off).ok()
}

#[inline]
fn dx_entry_block_raw(block: &[u8], count_offset: usize, idx: usize) -> Option<u32> {
    let base = if idx == 0 {
        count_offset.checked_add(4)?
    } else {
        count_offset
            .checked_add(idx.checked_mul(8)?)?
            .checked_add(4)?
    };
    read_le_u32(block, base).ok()
}

/// dx entry count from the raw countlimit header — but only when `count <= limit`
/// and every entry lies within the block; otherwise 0, so the caller falls back to
/// the validating [`parse_dx_entries`] path rather than trusting a malformed header.
#[inline]
fn dx_count_raw(block: &[u8], count_offset: usize) -> usize {
    let (Ok(limit), Ok(count)) = (
        read_le_u16(block, count_offset),
        read_le_u16(block, count_offset + 2),
    ) else {
        return 0;
    };
    let count = usize::from(count);
    if count == 0 || count > usize::from(limit) {
        return 0;
    }
    match dx_entry_block_raw(block, count_offset, count - 1) {
        Some(_) => count,
        None => 0,
    }
}

/// Raw analogue of [`dx_find_leaf_idx`]: the rightmost entry with `hash <= target`,
/// reading hashes on demand from `block` instead of a parsed slice.
#[inline]
fn dx_find_leaf_idx_raw(
    block: &[u8],
    count_offset: usize,
    count: usize,
    hash: u32,
) -> Option<usize> {
    let mut lo = 0_usize;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if dx_entry_hash_raw(block, count_offset, mid)? <= hash {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Some(if lo > 0 { lo - 1 } else { 0 })
}

/// Find the leaf block for a given hash in a sorted DX entry list.
#[cfg(test)]
fn dx_find_leaf(entries: &[Ext4DxEntry], hash: u32) -> u32 {
    let idx = dx_find_leaf_idx(entries, hash);
    entries[idx].block
}

/// Whether a successor DX entry stays in the same collision chain as the
/// queried hash.
///
/// ext4 stores directory major hashes with the low bit cleared. If a leaf is
/// split because colliding names do not fit, the successor DX entry sets the
/// low bit to 1 while keeping the same major hash prefix. Lookups must follow
/// those successors but stop before the next distinct major-hash range.
#[must_use]
fn dx_hash_extends_collision_chain(target_hash: u32, next_hash: u32) -> bool {
    (target_hash & !1) == (next_hash & !1)
}

#[derive(Debug, Clone)]
struct Ext4DxFrame {
    entries: Vec<Ext4DxEntry>,
    idx: usize,
}

/// Outcome of an htree/DX directory index lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtreeFindResult {
    /// The name was found in a leaf reachable through the index.
    Found(Ext4DirEntry),
    /// The index is present and was navigated successfully, but the name is not
    /// in the leaf/collision-chain the hash maps to. A reader that trusts the
    /// index treats this as "absent"; a reader whose index may be stale relative
    /// to linearly-appended entries should fall back to a linear scan.
    NotFoundInIndex,
    /// The index is absent/unparseable/unreadable — the caller must do a linear
    /// scan (the index cannot be relied upon).
    IndexInvalid,
}

/// Hash-tree (htree/DX) directory entry lookup, generic over how directory
/// blocks are read.
///
/// `read_logical_dir_block(n)` returns the bytes of logical directory block `n`
/// (resolving its extent and reading it), or `None` if it cannot be resolved or
/// read. `effective_hash_version(v)` maps the DX root's base hash version to the
/// effective version (applying the superblock signed/unsigned flag).
///
/// Infallible by design: any read/parse failure yields [`HtreeFindResult::IndexInvalid`]
/// and a successful navigation that does not contain the name yields
/// [`HtreeFindResult::NotFoundInIndex`], so this can never return a *wrong*
/// entry — only "found", "not in index", or "index unusable". Callers gate on
/// the directory's INDEX flag and choose their not-found policy (trust the index
/// vs. linear fallback for a possibly-stale index).
// 107 lines against a 100-line lint threshold, for the same reason as
// `walk_dir_block_entries`: one descent through the htree where each step's
// validation is what licenses the next read (bd-g9l54).
#[allow(clippy::too_many_lines)]
fn htree_find_entry_inner<F, H, B>(
    block_size: u32,
    hash_seed: &[u32; 4],
    has_large_dir: bool,
    name: &[u8],
    effective_hash_version: H,
    mut read_logical_dir_block: F,
    casefold: bool,
) -> HtreeFindResult
where
    F: FnMut(u32) -> Option<B>,
    H: Fn(u8) -> u8,
    B: AsRef<[u8]>,
{
    macro_rules! invalid_unless {
        ($e:expr) => {
            match $e {
                Some(v) => v,
                None => return HtreeFindResult::IndexInvalid,
            }
        };
    }

    let block0 = invalid_unless!(read_logical_dir_block(0));

    // Compute the name hash from the root header alone (hash version + depth), with
    // no entry-Vec materialization yet.
    let (root_hash_version, root_indirect_levels) =
        invalid_unless!(parse_dx_root_info_with_large_dir(block0.as_ref(), has_large_dir).ok());
    let hash_version = effective_hash_version(root_hash_version);
    // For casefold dirs the kernel hashes the case-folded name; matching that
    // (byte-exact for ASCII, where casefold == ASCII-lowercase) lets the htree
    // index resolve case-insensitive lookups. An exotic-Unicode fold that
    // differs from the kernel's simply misses here, and the caller falls back
    // to the linear casefold scan, so correctness is never at risk.
    let folded = if casefold {
        Some(casefold_name(name))
    } else {
        None
    };
    let hash_input = folded.as_deref().unwrap_or(name);
    let (hash, _minor) = dx_hash(hash_version, hash_input, hash_seed);
    let indirect_levels = usize::from(root_indirect_levels);

    // Fast path (bd-cc-dxraw): a single-level htree — the common shape for moderate
    // directories — reaches the leaf in ONE raw binary search over the root index
    // block, so a present, non-colliding name resolves without parsing the ~hundreds
    // of dx entries into a Vec (`parse_dx_entries` was ~10% of an ext4 lookup). A hit
    // is self-verifying: `lookup_in_dir_block` confirms the name is in the chosen
    // leaf, so a wrong leaf (or any header quirk) simply misses and falls through to
    // the authoritative frame path below — the fast path can NEVER return a wrong
    // result. Multi-level dirs and collision chains take the slow path.
    if indirect_levels == 0 {
        let count = dx_count_raw(block0.as_ref(), 0x20);
        if count > 0
            && let Some(idx) = dx_find_leaf_idx_raw(block0.as_ref(), 0x20, count, hash)
            && let Some(leaf_block) = dx_entry_block_raw(block0.as_ref(), 0x20, idx)
            && let Some(leaf_data) = read_logical_dir_block(leaf_block)
        {
            let matched = if casefold {
                lookup_in_dir_block_casefold(leaf_data.as_ref(), block_size, name)
                    .ok()
                    .flatten()
            } else {
                lookup_in_dir_block(leaf_data.as_ref(), block_size, name)
                    .ok()
                    .flatten()
            };
            if let Some(entry) = matched {
                return HtreeFindResult::Found(entry);
            }
        }
    }

    // Slow path: parse the full index and descend with collision handling.
    let dx_root =
        invalid_unless!(parse_dx_root_with_large_dir(block0.as_ref(), has_large_dir).ok());
    if dx_root.entries.is_empty() {
        return HtreeFindResult::IndexInvalid;
    }
    let root_idx = dx_find_leaf_idx(&dx_root.entries, hash);
    let mut frames = vec![Ext4DxFrame {
        entries: dx_root.entries,
        idx: root_idx,
    }];

    for _ in 0..indirect_levels {
        let frame = invalid_unless!(frames.last());
        let child_block = invalid_unless!(frame.entries.get(frame.idx)).block;
        let child_data = invalid_unless!(read_logical_dir_block(child_block));
        let child_entries = invalid_unless!(parse_dx_entries(child_data.as_ref(), 8).ok());
        if child_entries.is_empty() {
            return HtreeFindResult::IndexInvalid;
        }
        let child_idx = dx_find_leaf_idx(&child_entries, hash);
        frames.push(Ext4DxFrame {
            entries: child_entries,
            idx: child_idx,
        });
    }

    loop {
        let frame = invalid_unless!(frames.last());
        let leaf_block = invalid_unless!(frame.entries.get(frame.idx)).block;
        let leaf_data = invalid_unless!(read_logical_dir_block(leaf_block));
        // Search the leaf in place (`lookup_in_dir_block` walks it and allocates
        // only the one matching entry) instead of `parse_dir_block` materializing
        // a `Vec<Ext4DirEntry>` with an owned name `Vec` per entry just to find
        // ONE. This leaf search is ~40% of every htree lookup (`parse_dir_block`
        // 21.6% self + the ~N per-entry allocs' jemalloc churn) and lookup is in
        // every metadata op. Both helpers validate the whole block identically,
        // so the accept/reject (`IndexInvalid`) behaviour is unchanged.
        let matched = if casefold {
            invalid_unless!(lookup_in_dir_block_casefold(leaf_data.as_ref(), block_size, name).ok())
        } else {
            invalid_unless!(lookup_in_dir_block(leaf_data.as_ref(), block_size, name).ok())
        };
        if let Some(entry) = matched {
            return HtreeFindResult::Found(entry);
        }

        // Advance to the next leaf in the collision chain (if any).
        let mut level = frames.len() - 1;
        loop {
            frames[level].idx += 1;
            if frames[level].idx < frames[level].entries.len() {
                break;
            }
            if level == 0 {
                break;
            }
            level -= 1;
        }
        if level == 0 && frames[level].idx >= frames[level].entries.len() {
            return HtreeFindResult::NotFoundInIndex;
        }
        let next_hash = frames[level].entries[frames[level].idx].hash;
        if !dx_hash_extends_collision_chain(hash, next_hash) {
            return HtreeFindResult::NotFoundInIndex;
        }
        while level + 1 < frames.len() {
            let child_block = frames[level].entries[frames[level].idx].block;
            let child_data = invalid_unless!(read_logical_dir_block(child_block));
            let child_entries = invalid_unless!(parse_dx_entries(child_data.as_ref(), 8).ok());
            if child_entries.is_empty() {
                return HtreeFindResult::IndexInvalid;
            }
            level += 1;
            frames[level].entries = child_entries;
            frames[level].idx = 0;
        }
    }
}

/// Locate a directory entry through the htree (DX) index by exact name match.
pub fn htree_find_entry<F, H, B>(
    block_size: u32,
    hash_seed: &[u32; 4],
    has_large_dir: bool,
    name: &[u8],
    effective_hash_version: H,
    read_logical_dir_block: F,
) -> HtreeFindResult
where
    F: FnMut(u32) -> Option<B>,
    H: Fn(u8) -> u8,
    B: AsRef<[u8]>,
{
    htree_find_entry_inner(
        block_size,
        hash_seed,
        has_large_dir,
        name,
        effective_hash_version,
        read_logical_dir_block,
        false,
    )
}

/// Locate a directory entry through the htree (DX) index using case-insensitive
/// (casefold) matching, for `EXT4_CASEFOLD_FL` directories.
///
/// Descends the DX index hashing the case-folded query name (the kernel hashes
/// the folded name for casefold dirs) and compares leaf entries with casefold
/// collision. This is byte-exact to the kernel for ASCII names (where casefold
/// is ASCII-lowercase). For exotic Unicode whose fold differs from the kernel's,
/// the descent simply misses and returns `NotFoundInIndex` — callers MUST keep
/// their linear casefold-scan fallback, which remains the source of truth.
pub fn htree_find_entry_casefold<F, H, B>(
    block_size: u32,
    hash_seed: &[u32; 4],
    has_large_dir: bool,
    name: &[u8],
    effective_hash_version: H,
    read_logical_dir_block: F,
) -> HtreeFindResult
where
    F: FnMut(u32) -> Option<B>,
    H: Fn(u8) -> u8,
    B: AsRef<[u8]>,
{
    htree_find_entry_inner(
        block_size,
        hash_seed,
        has_large_dir,
        name,
        effective_hash_version,
        read_logical_dir_block,
        true,
    )
}

/// Resolve the htree/DX leaf block that *covers* `name`'s hash — i.e. the leaf a
/// new entry with that name must be inserted into to keep the index consistent.
///
/// This descends the same DX index frames as [`htree_find_entry`] (root, then any
/// indirect levels) using [`dx_find_leaf_idx`] at each level, but stops at the
/// target leaf instead of searching it / following the collision chain. It is the
/// insert-side counterpart to the lookup walk: adding the entry to this block and
/// nowhere else preserves the invariant that `htree_find_entry` checks (the entry
/// lives in the leaf whose hash range contains `dx_hash(name)`). Returns `None` if
/// the index cannot be parsed/read, so callers must refuse to mutate rather than
/// fall back to a linear write into the DX root.
fn htree_target_leaf_block_inner<F, H, B>(
    hash_seed: &[u32; 4],
    has_large_dir: bool,
    name: &[u8],
    effective_hash_version: H,
    mut read_logical_dir_block: F,
    casefold: bool,
) -> Option<u32>
where
    F: FnMut(u32) -> Option<B>,
    H: Fn(u8) -> u8,
    B: AsRef<[u8]>,
{
    let block0 = read_logical_dir_block(0)?;
    let (root_hash_version, indirect_levels) =
        parse_dx_root_info_with_large_dir(block0.as_ref(), has_large_dir).ok()?;

    let hash_version = effective_hash_version(root_hash_version);
    // Casefold dirs index by the folded name (byte-exact for ASCII), so the
    // target leaf for an insert is the one the folded hash maps to.
    let folded = if casefold {
        Some(casefold_name(name))
    } else {
        None
    };
    let hash_input = folded.as_deref().unwrap_or(name);
    let (hash, _minor) = dx_hash(hash_version, hash_input, hash_seed);

    let mut block_data = block0;
    let mut count_limit_offset = 0x20;
    for level in 0..=usize::from(indirect_levels) {
        let target_block =
            dx_find_leaf_block_in_data(block_data.as_ref(), count_limit_offset, hash)
                .ok()
                .flatten()?;
        if level == usize::from(indirect_levels) {
            return Some(target_block);
        }
        block_data = read_logical_dir_block(target_block)?;
        count_limit_offset = 8;
    }
    None
}

/// Resolve the DX leaf block that a new entry named `name` must be inserted into
/// (exact-name hashing). See [`htree_target_leaf_block_inner`].
pub fn htree_target_leaf_block<F, H, B>(
    hash_seed: &[u32; 4],
    has_large_dir: bool,
    name: &[u8],
    effective_hash_version: H,
    read_logical_dir_block: F,
) -> Option<u32>
where
    F: FnMut(u32) -> Option<B>,
    H: Fn(u8) -> u8,
    B: AsRef<[u8]>,
{
    htree_target_leaf_block_inner(
        hash_seed,
        has_large_dir,
        name,
        effective_hash_version,
        read_logical_dir_block,
        false,
    )
}

/// Casefold counterpart of [`htree_target_leaf_block`].
///
/// Resolves the insert target leaf by hashing the case-folded name, matching how
/// the kernel indexes `EXT4_CASEFOLD_FL` directories. Byte-exact to the kernel
/// for ASCII names; callers must restrict casefold inserts to names where the
/// fold is exact.
pub fn htree_target_leaf_block_casefold<F, H, B>(
    hash_seed: &[u32; 4],
    has_large_dir: bool,
    name: &[u8],
    effective_hash_version: H,
    read_logical_dir_block: F,
) -> Option<u32>
where
    F: FnMut(u32) -> Option<B>,
    H: Fn(u8) -> u8,
    B: AsRef<[u8]>,
{
    htree_target_leaf_block_inner(
        hash_seed,
        has_large_dir,
        name,
        effective_hash_version,
        read_logical_dir_block,
        true,
    )
}

/// Enumerate the logical block numbers of *every* leaf in a hash-indexed
/// directory, descending all indirect levels of the DX index.
///
/// `block0` is the dx_root (logical block 0); `read_logical(n)` returns the
/// bytes of logical directory block `n` (for reading interior `dx_node` blocks).
/// Returns the leaf logical-block numbers in DX (hash-sorted) order, or `None`
/// if the index cannot be parsed.
///
/// This is the gather-side counterpart to [`htree_find_entry`]: where the lookup
/// descends to the *one* leaf a hash maps to, this breadth-first-walks the whole
/// index to list *all* leaves — what a directory rebuild needs so it reads only
/// real leaf blocks and never mis-parses an interior `dx_node` as a leaf. At
/// `indirect_levels == 0` the root entries already point at leaves; each further
/// level descends every interior node via [`DX_NODE_COUNT_OFFSET`]. Pinned by
/// `htree_leaf_logical_blocks_enumerates_every_leaf_*`.
pub fn htree_leaf_logical_blocks<F, B>(
    block0: &[u8],
    has_large_dir: bool,
    mut read_logical: F,
) -> Option<Vec<u32>>
where
    F: FnMut(u32) -> Option<B>,
    B: AsRef<[u8]>,
{
    let dx_root = parse_dx_root_with_large_dir(block0, has_large_dir).ok()?;
    let indirect_levels = usize::from(dx_root.indirect_levels);

    // Start at the root's entries; descend one level per indirect level. After
    // `indirect_levels` descents the accumulated block numbers are the leaves.
    let mut level_blocks: Vec<u32> = dx_root.entries.iter().map(|e| e.block).collect();
    for _ in 0..indirect_levels {
        let mut next = Vec::with_capacity(level_blocks.len());
        for interior in level_blocks {
            let data = read_logical(interior)?;
            let entries = parse_dx_entries(data.as_ref(), DX_NODE_COUNT_OFFSET).ok()?;
            for e in entries {
                next.push(e.block);
            }
        }
        level_blocks = next;
    }
    Some(level_blocks)
}

/// Outcome of an incremental single-level htree leaf split (bd-gauub fast path).
///
/// All three returned blocks are fully serialized AND checksum-stamped (when the
/// directory uses `metadata_csum`); the caller writes them through the block
/// device unchanged. `new_leaf_logical` is the logical block number the caller
/// passed in for the freshly-allocated leaf; `split_hash` is the boundary hash
/// inserted into the DX root (the lowest hash now living in the new leaf).
#[derive(Debug, Clone)]
pub struct HtreeLeafSplit {
    /// Repacked original (left) leaf — keeps the lower-hash half.
    pub old_leaf: Vec<u8>,
    /// Freshly packed new (right) leaf — holds the upper-hash half.
    pub new_leaf: Vec<u8>,
    /// Updated DX root block with the new `(split_hash -> new_leaf)` entry
    /// inserted in sorted position and `count` bumped.
    pub dx_root: Vec<u8>,
    /// The boundary hash inserted into the DX index.
    pub split_hash: u32,
}

/// Incremental htree split result when the parent index block is an interior
/// `dx_node` rather than the DX root.
#[derive(Debug, Clone)]
pub struct HtreeNodeLeafSplit {
    /// Repacked original (left) leaf — keeps the lower-hash half.
    pub old_leaf: Vec<u8>,
    /// Freshly packed new (right) leaf — holds the upper-hash half.
    pub new_leaf: Vec<u8>,
    /// Updated interior DX node with the new `(split_hash -> new_leaf)` entry.
    pub dx_node: Vec<u8>,
    /// The boundary hash inserted into the interior DX node.
    pub split_hash: u32,
}

/// Why an incremental htree leaf split could not be performed and the caller must
/// fall back to a full rebuild (correctness over speed for these rarer cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtreeSplitFallback {
    /// The DX index has interior levels (`indirect_levels > 0`); inserting into
    /// the correct interior node is out of scope for the single-level fast path.
    MultiLevelIndex,
    /// The DX root has no free entry slot (`count == limit`); a split would grow
    /// the index a level, which the rebuild handles.
    DxRootFull,
    /// The interior DX node has no free entry slot; splitting that node is a
    /// separate promotion step, so callers must fall back.
    DxNodeFull,
    /// The full leaf has fewer than two distinct hashes, so there is no clean
    /// hash boundary to split on (an equal-hash collision run needs a chain).
    NoCleanBoundary,
    /// The DX root, the leaf, or the directory shape could not be parsed / is
    /// unsupported here (e.g. casefold is handled by the caller, not this fn).
    Unsupported,
}

/// Incrementally split one full htree leaf and insert a single DX entry, instead
/// of rebuilding the whole directory (bd-gauub: the O(log N) rename fast path).
///
/// `dx_root_block` is logical block 0 (the DX root); `target_leaf` is the full
/// leaf the lookup descent routed the new name to; `new_leaf_logical` is the
/// logical block number the caller has allocated for the new (right) leaf.
///
/// On success the entries of `target_leaf` are split at the clean hash boundary
/// closest to a 50/50 byte split: hashes `< split_hash` stay in `old_leaf`,
/// hashes `>= split_hash` move to `new_leaf`. A `(split_hash -> new_leaf_logical)`
/// entry is inserted into the DX root's sorted entry array and `count` is bumped.
/// All three blocks are repacked and (when `has_metadata_csum`) checksum-stamped,
/// ready to write. After the split the caller re-descends (or selects old/new by
/// hash) and retries the `add_entry` — both leaves now have room.
///
/// Returns `Err(HtreeSplitFallback)` for the cases the single-level fast path
/// does not handle (multi-level index, full DX root, no clean hash boundary,
/// unparseable input); the caller falls back to the proven full rebuild, which
/// stays correct. This function performs hashing with the SAME `hash_version` /
/// `hash_seed` the lookup descent uses, so split placement is consistent with
/// `htree_target_leaf_block`. Casefold directories must be handled by the caller
/// (it knows `EXT4_CASEFOLD_FL`); pass already-exact names only.
///
/// Promote a FULL single-level htree dx_root to two levels (bd-rename-2lvl, the
/// rename O(N²) fix's first half). When `split_htree_leaf` would decline with
/// `DxRootFull`, the dir's index is a single-level dx_root packed with leaf
/// pointers and the kernel/ext4 answer is NOT a full directory rebuild — it is to
/// insert an interior level: split the dx_root's leaf-pointer entries at a clean
/// hash boundary into TWO interior dx_nodes (each ~half-full so a subsequent
/// leaf-split has room — NOT the full-pack `build_htree_directory` chunking), and
/// rebuild the dx_root as `indirect_levels=1` pointing at the two nodes. The
/// caller allocates+maps two new blocks and passes their LOGICAL numbers.
///
/// Returns `(new_dx_root_block, dx_node_a_block, dx_node_b_block)` — three full
/// `block_size` buffers, checksum-stamped when `has_metadata_csum`. The `.`/`..`
/// dirent header of the dx_root (bytes `0x00..0x18`) is preserved; only the index
/// (`0x18+`) is rewritten. Returns `None` when promotion does not apply: not
/// single-level, fewer than two entries, no clean hash boundary, or a half would
/// exceed `dx_node_entry_limit`.
///
/// This is piece (1) of the rename dx-split (see docs/NEGATIVE_EVIDENCE.md); piece
/// (2) — splitting a dx_node on later adds — and the `split_htree_leaf`/caller
/// wiring are the remaining work. Validated in isolation by
/// `promote_dx_root_to_two_level_routes_every_entry`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn promote_dx_root_to_two_level(
    dx_root_block: &[u8],
    block_size: usize,
    has_metadata_csum: bool,
    large_dir: bool,
    left_child_logical: u32,
    right_child_logical: u32,
    csum_seed: u32,
    dir_ino: u32,
    generation: u32,
) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if dx_root_block.len() != block_size {
        return None;
    }
    let dx_root = parse_dx_root_with_large_dir(dx_root_block, large_dir).ok()?;
    if dx_root.indirect_levels != 0 || dx_root.entries.len() < 2 {
        return None;
    }
    let entries = &dx_root.entries;

    // Clean hash boundary nearest the middle (each dx_entry is one fixed-size
    // slot, so weight every entry equally). `choose_htree_leaf_split` only returns
    // a boundary where the hash strictly increases, preserving the routing
    // invariant (left covers [.., split_hash), right covers [split_hash, ..)).
    let split_input: Vec<(u32, usize)> = entries.iter().map(|e| (e.hash, 1usize)).collect();
    let (split_index, split_hash) = choose_htree_leaf_split(&split_input)?;

    let node_limit = dx_node_entry_limit(block_size, has_metadata_csum);
    let (left, right) = entries.split_at(split_index);
    if left.is_empty()
        || right.is_empty()
        || left.len() > usize::from(node_limit)
        || right.len() > usize::from(node_limit)
    {
        return None;
    }

    let mut node_a = vec![0_u8; block_size];
    write_dx_node(&mut node_a, node_limit, left).ok()?;
    let mut node_b = vec![0_u8; block_size];
    write_dx_node(&mut node_b, node_limit, right).ok()?;

    // New dx_root: two entries, `indirect_levels = 1`. Entry 0's hash is implicit
    // (0); entry 1 routes hashes >= `split_hash` to node B. Preserve `.`/`..`
    // (0x00..0x18) by starting from the original block.
    let root_entries = [
        Ext4DxEntry {
            hash: 0,
            block: left_child_logical,
        },
        Ext4DxEntry {
            hash: split_hash,
            block: right_child_logical,
        },
    ];
    let root_limit = dx_root_entry_limit(block_size, has_metadata_csum);
    let mut new_root = dx_root_block.to_vec();
    write_dx_root(
        &mut new_root,
        dx_root.hash_version,
        1,
        root_limit,
        &root_entries,
    )
    .ok()?;

    if has_metadata_csum {
        stamp_dx_block_checksum(
            &mut node_a,
            csum_seed,
            dir_ino,
            generation,
            DX_NODE_COUNT_OFFSET,
        );
        stamp_dx_block_checksum(
            &mut node_b,
            csum_seed,
            dir_ino,
            generation,
            DX_NODE_COUNT_OFFSET,
        );
        stamp_dx_block_checksum(
            &mut new_root,
            csum_seed,
            dir_ino,
            generation,
            DX_ROOT_COUNT_OFFSET,
        );
    }

    Some((new_root, node_a, node_b))
}

/// Pinned by `htree_leaf_split_*` unit tests: the split is navigable by the
/// read-half for every entry and every block's checksum verifies.
#[allow(clippy::too_many_arguments)]
pub fn split_htree_leaf(
    dx_root_block: &[u8],
    target_leaf: &[u8],
    target_leaf_logical: u32,
    new_leaf_logical: u32,
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    has_metadata_csum: bool,
    has_large_dir: bool,
    csum_seed: u32,
    dir_ino: u32,
    generation: u32,
) -> Result<HtreeLeafSplit, HtreeSplitFallback> {
    if dx_root_block.len() != block_size || target_leaf.len() != block_size {
        return Err(HtreeSplitFallback::Unsupported);
    }

    // Parse the DX root. Only the single-level (indirect_levels == 0) shape is
    // handled here; deeper indices fall back to rebuild.
    let dx_root = parse_dx_root_with_large_dir(dx_root_block, has_large_dir)
        .map_err(|_| HtreeSplitFallback::Unsupported)?;
    if dx_root.indirect_levels != 0 {
        return Err(HtreeSplitFallback::MultiLevelIndex);
    }
    let root_limit = usize::from(dx_root_entry_limit(block_size, has_metadata_csum));
    if dx_root.entries.len() >= root_limit {
        return Err(HtreeSplitFallback::DxRootFull);
    }

    // Collect the full leaf's real entries (skip ./.. and the csum tail).
    // Borrow the names straight from `target_leaf` via `DirBlockIter` instead of
    // `parse_dir_block` (which allocates an owned `Vec<u8>` per entry). The names
    // only feed `dx_hash` and the borrowed `(ino, ft, &[u8])` pack refs below —
    // all within this function while `target_leaf` is live — so the ~N per-leaf
    // name allocations + frees per split are pure churn (jemalloc `do_rallocx`/
    // `extent_recycle` in the rename/create profile). DirBlockIter already skips
    // deleted (inode 0) entries and the csum tail; a parse error → rebuild
    // fallback, exactly as parse_dir_block did.
    let block_size_u32 = u32::try_from(block_size).map_err(|_| HtreeSplitFallback::Unsupported)?;
    let mut real: Vec<(u32, u32, u8, &[u8])> = Vec::new();
    for e in DirBlockIter::new(target_leaf, block_size_u32) {
        let e = e.map_err(|_| HtreeSplitFallback::Unsupported)?;
        if e.name.is_empty() || e.name == b"." || e.name == b".." {
            continue;
        }
        let hash = dx_hash(hash_version, e.name, hash_seed).0;
        real.push((hash, e.inode, e.file_type.to_raw(), e.name));
    }

    // Sort by hash so we can split on a clean boundary (matches the read-half's
    // hash-sorted leaf invariant). Ties keep insertion order — irrelevant since
    // an equal-hash run never straddles the boundary.
    // Unstable: ties are irrelevant (an equal-hash run never straddles the
    // split boundary; within-leaf order is a linear scan), so we avoid the
    // stable sort's O(n) temp buffer + tie-preservation cost (1.47x, bench
    // htree_split_sort).
    real.sort_unstable_by_key(|&(h, _, _, _)| h);

    // Choose the split point: (hash, on-disk rec_len) per entry.
    let split_input: Vec<(u32, usize)> = real
        .iter()
        .map(|(h, _, _, name)| (*h, dir_entry_rec_len(name.len())))
        .collect();
    let (split_index, split_hash) =
        choose_htree_leaf_split(&split_input).ok_or(HtreeSplitFallback::NoCleanBoundary)?;

    // Pack the two halves. A subset of one block's entries always re-fits one
    // block, so neither pack can overflow.
    let left_refs: Vec<(u32, u8, &[u8])> = real[..split_index]
        .iter()
        .map(|(_, ino, ft, name)| (*ino, *ft, *name))
        .collect();
    let right_refs: Vec<(u32, u8, &[u8])> = real[split_index..]
        .iter()
        .map(|(_, ino, ft, name)| (*ino, *ft, *name))
        .collect();
    let mut old_leaf = pack_dir_block_entries(&left_refs, block_size, has_metadata_csum)
        .map_err(|_| HtreeSplitFallback::Unsupported)?;
    let mut new_leaf = pack_dir_block_entries(&right_refs, block_size, has_metadata_csum)
        .map_err(|_| HtreeSplitFallback::Unsupported)?;

    // Insert (split_hash -> new_leaf_logical) into the DX root, keeping the entry
    // array sorted by hash. Entry 0 has an implicit hash of 0 and stays first;
    // dx_find_leaf_idx routes a lookup to the rightmost entry with hash <= target,
    // so the new right leaf must be reachable at exactly split_hash.
    let mut dx_entries = dx_root.entries;
    let insert_at = dx_entries.partition_point(|e| e.hash <= split_hash);
    dx_entries.insert(
        insert_at,
        Ext4DxEntry {
            hash: split_hash,
            block: new_leaf_logical,
        },
    );

    let mut dx_root_out = dx_root_block.to_vec();
    let root_limit_u16 = u16::try_from(root_limit).map_err(|_| HtreeSplitFallback::Unsupported)?;
    write_dx_root(
        &mut dx_root_out,
        hash_version,
        0,
        root_limit_u16,
        &dx_entries,
    )
    .map_err(|_| HtreeSplitFallback::Unsupported)?;

    // The old leaf must keep its existing logical->physical mapping; its identity
    // in the DX root (the entry pointing at target_leaf_logical) is unchanged.
    debug_assert!(
        dx_entries.iter().any(|e| e.block == target_leaf_logical),
        "old leaf logical block dropped from DX root during split"
    );

    if has_metadata_csum {
        stamp_dir_block_checksum(&mut old_leaf, csum_seed, dir_ino, generation);
        stamp_dir_block_checksum(&mut new_leaf, csum_seed, dir_ino, generation);
        stamp_dx_block_checksum(
            &mut dx_root_out,
            csum_seed,
            dir_ino,
            generation,
            DX_ROOT_COUNT_OFFSET,
        );
    }

    Ok(HtreeLeafSplit {
        old_leaf,
        new_leaf,
        dx_root: dx_root_out,
        split_hash,
    })
}

/// Incrementally split one full htree leaf whose parent is an interior `dx_node`.
///
/// This is the two-level counterpart to [`split_htree_leaf`]: it repacks the
/// target leaf into left/right halves, inserts one `(split_hash -> new_leaf)` DX
/// entry into the already-selected parent node, and leaves the DX root unchanged.
/// It intentionally handles only the common "node has spare slot" case; a full
/// `dx_node` still falls back to the proven full rebuild until node promotion is
/// wired separately.
#[allow(clippy::too_many_arguments)]
pub fn split_htree_leaf_in_dx_node(
    dx_node_block: &[u8],
    target_leaf: &[u8],
    target_leaf_logical: u32,
    new_leaf_logical: u32,
    block_size: usize,
    hash_version: u8,
    hash_seed: &[u32; 4],
    has_metadata_csum: bool,
    csum_seed: u32,
    dir_ino: u32,
    generation: u32,
) -> Result<HtreeNodeLeafSplit, HtreeSplitFallback> {
    if dx_node_block.len() != block_size || target_leaf.len() != block_size {
        return Err(HtreeSplitFallback::Unsupported);
    }

    let node_limit = usize::from(dx_node_entry_limit(block_size, has_metadata_csum));
    let mut dx_entries = parse_dx_entries(dx_node_block, DX_NODE_COUNT_OFFSET)
        .map_err(|_| HtreeSplitFallback::Unsupported)?;
    if dx_entries.is_empty() {
        return Err(HtreeSplitFallback::Unsupported);
    }
    if dx_entries.len() >= node_limit {
        return Err(HtreeSplitFallback::DxNodeFull);
    }
    if !dx_entries.iter().any(|e| e.block == target_leaf_logical) {
        return Err(HtreeSplitFallback::Unsupported);
    }

    let block_size_u32 = u32::try_from(block_size).map_err(|_| HtreeSplitFallback::Unsupported)?;
    let mut real: Vec<(u32, u32, u8, &[u8])> = Vec::new();
    for e in DirBlockIter::new(target_leaf, block_size_u32) {
        let e = e.map_err(|_| HtreeSplitFallback::Unsupported)?;
        if e.name.is_empty() || e.name == b"." || e.name == b".." {
            continue;
        }
        let hash = dx_hash(hash_version, e.name, hash_seed).0;
        real.push((hash, e.inode, e.file_type.to_raw(), e.name));
    }
    // Unstable: ties are irrelevant (an equal-hash run never straddles the
    // split boundary; within-leaf order is a linear scan), so we avoid the
    // stable sort's O(n) temp buffer + tie-preservation cost (1.47x, bench
    // htree_split_sort).
    real.sort_unstable_by_key(|&(h, _, _, _)| h);

    let split_input: Vec<(u32, usize)> = real
        .iter()
        .map(|(h, _, _, name)| (*h, dir_entry_rec_len(name.len())))
        .collect();
    let (split_index, split_hash) =
        choose_htree_leaf_split(&split_input).ok_or(HtreeSplitFallback::NoCleanBoundary)?;

    let left_refs: Vec<(u32, u8, &[u8])> = real[..split_index]
        .iter()
        .map(|(_, ino, ft, name)| (*ino, *ft, *name))
        .collect();
    let right_refs: Vec<(u32, u8, &[u8])> = real[split_index..]
        .iter()
        .map(|(_, ino, ft, name)| (*ino, *ft, *name))
        .collect();
    let mut old_leaf = pack_dir_block_entries(&left_refs, block_size, has_metadata_csum)
        .map_err(|_| HtreeSplitFallback::Unsupported)?;
    let mut new_leaf = pack_dir_block_entries(&right_refs, block_size, has_metadata_csum)
        .map_err(|_| HtreeSplitFallback::Unsupported)?;

    let insert_at = dx_entries.partition_point(|e| e.hash <= split_hash);
    dx_entries.insert(
        insert_at,
        Ext4DxEntry {
            hash: split_hash,
            block: new_leaf_logical,
        },
    );

    let mut dx_node = vec![0_u8; block_size];
    let node_limit_u16 = u16::try_from(node_limit).map_err(|_| HtreeSplitFallback::Unsupported)?;
    write_dx_node(&mut dx_node, node_limit_u16, &dx_entries)
        .map_err(|_| HtreeSplitFallback::Unsupported)?;

    if has_metadata_csum {
        stamp_dir_block_checksum(&mut old_leaf, csum_seed, dir_ino, generation);
        stamp_dir_block_checksum(&mut new_leaf, csum_seed, dir_ino, generation);
        stamp_dx_block_checksum(
            &mut dx_node,
            csum_seed,
            dir_ino,
            generation,
            DX_NODE_COUNT_OFFSET,
        );
    }

    Ok(HtreeNodeLeafSplit {
        old_leaf,
        new_leaf,
        dx_node,
        split_hash,
    })
}

// ── ext4 directory hash functions ───────────────────────────────────────────

/// Hash version constants from the ext4 DX root.
const DX_HASH_LEGACY: u8 = 0;
const DX_HASH_HALF_MD4: u8 = 1;
const DX_HASH_TEA: u8 = 2;
const DX_HASH_LEGACY_UNSIGNED: u8 = 3;
const DX_HASH_HALF_MD4_UNSIGNED: u8 = 4;
const DX_HASH_TEA_UNSIGNED: u8 = 5;
const _DX_HASH_SIPHASH: u8 = 6;
const EXT4_HTREE_EOF_32BIT: u32 = (1_u32 << 31) - 1;
const DX_HASH_DEFAULT_SEED: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// Compute the ext4 directory hash for a filename.
///
/// Returns (major_hash, minor_hash). The `hash_version` selects the algorithm
/// and whether characters are treated as signed or unsigned.
#[must_use]
pub fn dx_hash(hash_version: u8, name: &[u8], seed: &[u32; 4]) -> (u32, u32) {
    let (major_hash, minor_hash) = match hash_version {
        DX_HASH_LEGACY => dx_hash_legacy(name, true),
        DX_HASH_LEGACY_UNSIGNED => dx_hash_legacy(name, false),
        DX_HASH_HALF_MD4 => dx_hash_half_md4(name, seed, true),
        DX_HASH_TEA => dx_hash_tea(name, seed, true),
        DX_HASH_TEA_UNSIGNED => dx_hash_tea(name, seed, false),
        // DX_HASH_HALF_MD4_UNSIGNED and any unknown versions default to half_md4 unsigned
        _ => dx_hash_half_md4(name, seed, false),
    };

    (normalize_dx_major_hash(major_hash), minor_hash)
}

/// ext4 stores directory hash cursors as signed 32-bit values, so the major
/// hash reserves the low bit and skips the sentinel EOF position.
#[must_use]
fn normalize_dx_major_hash(hash: u32) -> u32 {
    let hash = hash & !1;
    if hash == (EXT4_HTREE_EOF_32BIT << 1) {
        (EXT4_HTREE_EOF_32BIT - 1) << 1
    } else {
        hash
    }
}

#[must_use]
fn dx_hash_seed_state(seed: &[u32; 4]) -> [u32; 4] {
    if seed.iter().any(|word| *word != 0) {
        *seed
    } else {
        DX_HASH_DEFAULT_SEED
    }
}

/// Legacy (r5) hash function — matches the kernel's `dx_hack_hash_*` helpers.
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)] // intentional signed char semantics
fn dx_hash_legacy(name: &[u8], signed: bool) -> (u32, u32) {
    let mut h0: u32 = 0x12a3_fe2d;
    let mut h1: u32 = 0x37ab_e8f9;

    for &b in name {
        let val = if signed {
            i32::from(b as i8) as u32
        } else {
            u32::from(b)
        };
        let mut hash = h1.wrapping_add(h0 ^ val.wrapping_mul(7_152_373));
        if (hash & 0x8000_0000) != 0 {
            hash = hash.wrapping_sub(0x7fff_ffff);
        }
        h1 = h0;
        h0 = hash;
    }

    (h0.wrapping_shl(1), 0)
}

/// Half-MD4 hash function — used by most ext4 filesystems.
///
/// This implements the str2hashbuf + half-MD4 transform from the kernel.
#[allow(clippy::cast_possible_wrap)] // intentional signed char semantics
fn dx_hash_half_md4(name: &[u8], seed: &[u32; 4], signed: bool) -> (u32, u32) {
    let [mut a, mut b, mut c, mut d] = dx_hash_seed_state(seed);

    let mut offset = 0;
    while offset < name.len() {
        let chunk_len = (name.len() - offset).min(32);
        let buf = str2hashbuf(&name[offset..offset + chunk_len], 8, signed);
        half_md4_transform(&mut a, &mut b, &mut c, &mut d, &buf[..8]);
        offset += chunk_len;
    }

    (normalize_dx_major_hash(b), c)
}

/// TEA (Tiny Encryption Algorithm) hash — an alternative ext4 hash.
#[allow(clippy::cast_possible_wrap)]
fn dx_hash_tea(name: &[u8], seed: &[u32; 4], signed: bool) -> (u32, u32) {
    let [mut a, mut b, _, _] = dx_hash_seed_state(seed);

    let mut offset = 0;
    while offset < name.len() {
        let chunk_len = (name.len() - offset).min(16);
        let buf = str2hashbuf(&name[offset..offset + chunk_len], 4, signed);
        tea_transform(&mut a, &mut b, &buf[..4]);
        offset += chunk_len;
    }

    (normalize_dx_major_hash(a), b)
}

/// Convert a filename chunk to a u32 buffer for hashing.
///
/// Matches the Linux kernel's `str2hashbuf_signed` / `str2hashbuf_unsigned`
/// from `fs/ext4/hash.c`. Characters are packed big-endian within each u32
/// word via `val = char + (val << 8)`. Unused slots are filled with a pad
/// value derived from the name length.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
// Returns a fixed [u32; 8] (max `buf_size` across callers is 8) on the STACK —
// avoids the per-call `vec![0; buf_size]` heap allocation this ran on EVERY htree
// hash (dx_hash_half_md4 / dx_hash_tea, i.e. every create/mkdir/rename dir-entry
// insert). Callers use `&buf[..buf_size]`; entries past `buf_size` stay 0 and are
// never read (bd-cc-str2hashbuf-stack).
fn str2hashbuf(name: &[u8], buf_size: usize, signed: bool) -> [u32; 8] {
    debug_assert!(buf_size <= 8);
    let mut buf = [0_u32; 8];
    let len = name.len();

    // Pad = length byte replicated across all 4 bytes of a u32 (kernel convention).
    let pad = {
        let p = (len as u32) | ((len as u32) << 8);
        p | (p << 16)
    };

    let mut val = pad;
    let effective_len = len.min(buf_size * 4);
    let mut num = buf_size;
    let mut buf_idx = 0;

    for (i, &byte_val) in name.iter().enumerate().take(effective_len) {
        let ch = if signed {
            // Sign-extend: 0xC3 → -61 → 0xFFFF_FFC3, then wrapping add
            i32::from(byte_val as i8) as u32
        } else {
            u32::from(byte_val)
        };
        val = ch.wrapping_add(val << 8);
        if (i % 4) == 3 {
            buf[buf_idx] = val;
            buf_idx += 1;
            val = pad;
            num -= 1;
        }
    }

    // Store remaining partial word, then fill rest with pad.
    // Mirrors kernel: `if (--num >= 0) *buf++ = val; while (--num >= 0) *buf++ = pad;`
    if num > 0 {
        buf[buf_idx] = val;
        buf_idx += 1;
        num -= 1;
        while num > 0 {
            buf[buf_idx] = pad;
            buf_idx += 1;
            num -= 1;
        }
    }

    buf
}

/// Half-MD4 transform — the core of the half-MD4 hash.
///
/// This is a simplified version of MD4 that operates on a single 32-byte
/// block (8 u32 words) and produces a 128-bit intermediate state.
fn half_md4_transform(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, buf: &[u32]) {
    const K2: u32 = 0x5A82_7999; // Round 2 constant
    const K3: u32 = 0x6ED9_EBA1; // Round 3 constant

    // Ensure we have 8 words; pad with zero if shorter
    let get = |i: usize| -> u32 { buf.get(i).copied().unwrap_or(0) };
    let orig_a = *a;
    let orig_b = *b;
    let orig_c = *c;
    let orig_d = *d;

    // Round 1: F(x,y,z) = (x & y) | (!x & z)
    macro_rules! ff {
        ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(($b & $c) | (!$b & $d))
                .wrapping_add(get($k));
            $a = $a.rotate_left($s);
        };
    }

    ff!(*a, *b, *c, *d, 0, 3);
    ff!(*d, *a, *b, *c, 1, 7);
    ff!(*c, *d, *a, *b, 2, 11);
    ff!(*b, *c, *d, *a, 3, 19);
    ff!(*a, *b, *c, *d, 4, 3);
    ff!(*d, *a, *b, *c, 5, 7);
    ff!(*c, *d, *a, *b, 6, 11);
    ff!(*b, *c, *d, *a, 7, 19);

    // Round 2: G(x,y,z) = (x & y) | (x & z) | (y & z)
    macro_rules! gg {
        ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(($b & $c) | ($b & $d) | ($c & $d))
                .wrapping_add(get($k))
                .wrapping_add(K2);
            $a = $a.rotate_left($s);
        };
    }

    gg!(*a, *b, *c, *d, 1, 3);
    gg!(*d, *a, *b, *c, 3, 5);
    gg!(*c, *d, *a, *b, 5, 9);
    gg!(*b, *c, *d, *a, 7, 13);
    gg!(*a, *b, *c, *d, 0, 3);
    gg!(*d, *a, *b, *c, 2, 5);
    gg!(*c, *d, *a, *b, 4, 9);
    gg!(*b, *c, *d, *a, 6, 13);

    // Round 3: H(x,y,z) = x ^ y ^ z
    macro_rules! hh {
        ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add($b ^ $c ^ $d)
                .wrapping_add(get($k))
                .wrapping_add(K3);
            $a = $a.rotate_left($s);
        };
    }

    hh!(*a, *b, *c, *d, 3, 3);
    hh!(*d, *a, *b, *c, 7, 9);
    hh!(*c, *d, *a, *b, 2, 11);
    hh!(*b, *c, *d, *a, 6, 15);
    hh!(*a, *b, *c, *d, 1, 3);
    hh!(*d, *a, *b, *c, 5, 9);
    hh!(*c, *d, *a, *b, 0, 11);
    hh!(*b, *c, *d, *a, 4, 15);

    *a = orig_a.wrapping_add(*a);
    *b = orig_b.wrapping_add(*b);
    *c = orig_c.wrapping_add(*c);
    *d = orig_d.wrapping_add(*d);
}

/// TEA (Tiny Encryption Algorithm) transform.
///
/// Operates on 2 u32 words of state (a, b) using 4 words of input (buf).
fn tea_transform(a: &mut u32, b: &mut u32, buf: &[u32]) {
    let get = |i: usize| -> u32 { buf.get(i).copied().unwrap_or(0) };

    let mut sum: u32 = 0;
    let delta: u32 = 0x9E37_79B9;

    let k0 = get(0);
    let k1 = get(1);
    let k2 = get(2);
    let k3 = get(3);

    let mut b0 = *a;
    let mut b1 = *b;

    // 16 rounds of TEA on (a, b) pair
    for _ in 0..16 {
        sum = sum.wrapping_add(delta);
        b0 = b0.wrapping_add(
            (b1.wrapping_shl(4).wrapping_add(k0))
                ^ b1.wrapping_add(sum)
                ^ (b1.wrapping_shr(5).wrapping_add(k1)),
        );
        b1 = b1.wrapping_add(
            (b0.wrapping_shl(4).wrapping_add(k2))
                ^ b0.wrapping_add(sum)
                ^ (b0.wrapping_shr(5).wrapping_add(k3)),
        );
    }

    *a = a.wrapping_add(b0);
    *b = b.wrapping_add(b1);
}
