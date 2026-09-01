#![forbid(unsafe_code)]
//! Directory operations.
//!
//! Linear directory entry scan, htree (hashed B-tree) lookup with
//! dx_hash computation (half-MD4 and TEA), directory entry creation
//! and deletion, and `..`/`.` management.

use ffs_error::{FfsError, Result};
use ffs_ondisk::Ext4FileType;

/// ext4 directory entry header size (`ext4_dir_entry_2`).
const DIR_ENTRY_HEADER_LEN: usize = 8;

/// Word-at-a-time (SWAR) byte-slice equality. Faster than the byte-wise lowering
/// of `&[u8] == &[u8]` for same-length directory-name comparisons on the hot
/// dup-scan (create) / name-find (unlink/rename) / existence paths, where the
/// length gate does not filter (numbered / log / hash / maildir workloads —
/// profiled: `add_entry_reject_existing` is the #1 create self-time function and
/// its inner name compare lowered to a byte loop). A length mismatch still
/// short-circuits, so varied-length names are unaffected. Bit-identical to
/// `a == b` (bench `dirent_dup_scan`: 1.43x scanning 203 same-length entries).
#[inline]
fn names_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len();
    if n != b.len() {
        return false;
    }
    if n < 8 {
        return a == b;
    }
    // Full 8-byte words up to (but not including) the final 8-byte window.
    let mut i = 0;
    while i + 8 < n {
        if u64::from_ne_bytes(a[i..i + 8].try_into().unwrap())
            != u64::from_ne_bytes(b[i..i + 8].try_into().unwrap())
        {
            return false;
        }
        i += 8;
    }
    // Final (possibly OVERLAPPING) word over the last 8 bytes — one word-compare
    // instead of a byte-wise tail loop, so non-multiple-of-8 lengths (12/13/… —
    // common dir names) stay all-word-compares (~1.3-1.6x faster than the old
    // byte tail, which LOST to `==` there; bench ffs-ondisk names_eq_crossover).
    u64::from_ne_bytes(a[n - 8..n].try_into().unwrap())
        == u64::from_ne_bytes(b[n - 8..n].try_into().unwrap())
}
/// Fake file type for metadata checksum tail.
const EXT4_FT_DIR_CSUM: u8 = 0xDE;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn required_rec_len(name_len: usize) -> usize {
    align4(DIR_ENTRY_HEADER_LEN + name_len)
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let bytes = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u16_le(buf: &mut [u8], off: usize, value: u16) -> Result<()> {
    let dst = buf
        .get_mut(off..off + 2)
        .ok_or_else(|| FfsError::Corruption {
            block: 0,
            detail: "u16 write out of bounds".to_owned(),
        })?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32_le(buf: &mut [u8], off: usize, value: u32) -> Result<()> {
    let dst = buf
        .get_mut(off..off + 4)
        .ok_or_else(|| FfsError::Corruption {
            block: 0,
            detail: "u32 write out of bounds".to_owned(),
        })?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// SWAR one-pass test for a `/` or NUL byte, via the has-zero-byte trick
/// (`haszero(w) | haszero(w ^ '/'*0x0101..)`), replacing two byte-by-byte
/// `slice::contains` passes on the hot `validate_name` (every add/remove entry).
/// Bit-identical to `name.contains(&b'/') || name.contains(&0)` (ffs-ondisk bench
/// `path_validate`: ~3.4x on an 11-byte name — `slice::contains` for `u8` is not
/// vectorized). Same has-zero SWAR primitive as ffs-core's path-component check.
#[inline]
fn name_has_slash_or_nul(name: &[u8]) -> bool {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    const SLASH: u64 = 0x2F2F_2F2F_2F2F_2F2F;
    #[inline]
    fn haszero(v: u64) -> u64 {
        v.wrapping_sub(ONES) & !v & HIGHS
    }
    let mut i = 0;
    while i + 8 <= name.len() {
        let w = u64::from_le_bytes(name[i..i + 8].try_into().unwrap());
        if (haszero(w) | haszero(w ^ SLASH)) != 0 {
            return true;
        }
        i += 8;
    }
    while i < name.len() {
        let b = name[i];
        if b == b'/' || b == 0 {
            return true;
        }
        i += 1;
    }
    false
}

fn validate_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(FfsError::Format(
            "directory entry name cannot be empty".to_owned(),
        ));
    }
    if name.len() > u8::MAX as usize {
        return Err(FfsError::Format(
            "directory entry name exceeds 255 bytes".to_owned(),
        ));
    }
    // One SWAR pass for '/' or NUL; pinpoint the precise error on the cold path.
    if name_has_slash_or_nul(name) {
        if name.contains(&b'/') {
            return Err(FfsError::Format(
                "directory entry name cannot contain '/'".to_owned(),
            ));
        }
        return Err(FfsError::Format(
            "directory entry name cannot contain NUL".to_owned(),
        ));
    }
    Ok(())
}

fn validate_reserved_tail(block_len: usize, reserved_tail: usize) -> Result<usize> {
    if reserved_tail != 0 {
        if reserved_tail < 12 {
            return Err(FfsError::Format(
                "directory reserved tail must be 0 or at least 12 bytes".to_owned(),
            ));
        }
        if !reserved_tail.is_multiple_of(4) {
            return Err(FfsError::Format(
                "directory reserved tail must be 4-byte aligned".to_owned(),
            ));
        }
    }
    block_len
        .checked_sub(reserved_tail)
        .ok_or_else(|| FfsError::Format("directory reserved tail exceeds block length".to_owned()))
}

fn is_interior_htree_dx_node_block(block: &[u8]) -> bool {
    if read_u32_le(block, 0) != Some(0)
        || read_u16_le(block, 4).map(usize::from) != Some(block.len())
    {
        return false;
    }

    let Some(limit) = read_u16_le(block, 8) else {
        return false;
    };
    let Some(count) = read_u16_le(block, 10) else {
        return false;
    };
    if count == 0 || count > limit {
        return false;
    }

    8_usize
        .checked_add(usize::from(count) * 8)
        .is_some_and(|end| end <= block.len())
}

fn write_entry(
    block: &mut [u8],
    offset: usize,
    ino: u32,
    rec_len: usize,
    file_type: Ext4FileType,
    name: &[u8],
) -> Result<()> {
    let name_len_u8 = u8::try_from(name.len())
        .map_err(|_| FfsError::Format("directory entry name exceeds 255 bytes".to_owned()))?;
    let rec_len_u16 = u16::try_from(rec_len)
        .map_err(|_| FfsError::Format("directory entry rec_len exceeds u16".to_owned()))?;
    let end = offset
        .checked_add(rec_len)
        .ok_or_else(|| FfsError::Format("directory entry offset overflow".to_owned()))?;
    if end > block.len() {
        return Err(FfsError::Corruption {
            block: 0,
            detail: "directory entry exceeds block boundary".to_owned(),
        });
    }
    let min_size = required_rec_len(name.len());
    if rec_len < min_size {
        return Err(FfsError::Format(
            "directory entry rec_len smaller than minimum".to_owned(),
        ));
    }

    // `end <= block.len()` (above) plus `rec_len >= min_size >= HEADER_LEN`
    // proves `offset + HEADER_LEN <= block.len()`, but the compiler does not
    // chain that transitively — the 4 per-field writes each re-check bounds.
    // Reslice the header to a fixed-size array ref once (a single check, no
    // copy) and write the fields at const offsets through it (1.16x, bench
    // `entry_header_write`). Byte-identical to the 4 checked writes.
    let header: &mut [u8; DIR_ENTRY_HEADER_LEN] = (&mut block
        [offset..offset + DIR_ENTRY_HEADER_LEN])
        .try_into()
        .map_err(|_| FfsError::Corruption {
            block: 0,
            detail: "directory entry header slice".to_owned(),
        })?;
    header[0..4].copy_from_slice(&ino.to_le_bytes());
    header[4..6].copy_from_slice(&rec_len_u16.to_le_bytes());
    header[6] = name_len_u8;
    header[7] = file_type as u8;
    block[offset + DIR_ENTRY_HEADER_LEN..offset + DIR_ENTRY_HEADER_LEN + name.len()]
        .copy_from_slice(name);
    // Zero remaining bytes in slot for deterministic tests and clean replay.
    if rec_len > DIR_ENTRY_HEADER_LEN + name.len() {
        block[offset + DIR_ENTRY_HEADER_LEN + name.len()..end].fill(0);
    }
    Ok(())
}

/// Largest changed-span (bytes) worth an *incremental* dir-block checksum update.
///
/// Above this span, [`ffs_ondisk::stamp_dir_block_checksum_incremental`] no
/// longer beats a full ~4 KiB CRC recompute and the caller must full-recompute.
///
/// An insert into a near-full block splits a small slack, so the changed span is
/// ~one entry (tens of bytes) — well under this — capturing the common
/// large-directory create/rename. An insert into a near-*empty* block splits the
/// one huge free slot (span ≈ whole block), and its zero-fill of the vacated
/// slack can touch arbitrary stale bytes, so the span exceeds this and we fall
/// back to a full recompute (which is exactly today's behaviour).
///
/// ⚠ THE 256 IS NOT JUSTIFIED BY A MEASUREMENT, and the claim that used to stand
/// here — "the bench `dir_csum_incremental` crosses over well below 256 B, so this
/// is conservative" — is REFUTED (bd-4sull, 2026-08-31). That bench had no span
/// sweep at all: every arm used one fixed 28-byte delta and never varied it, so no
/// crossover could be read off it in either direction.
///
/// Measured with the sweep now in that bench (`dir_csum_span`, release-perf, rch
/// worker hz4), full recompute against incremental, nanoseconds:
///
/// | span | full | incremental | incremental is |
/// |------|------|-------------|----------------|
/// | 8    | 962.95 | 38.91  | 24.7x faster |
/// | 128  | 869.13 | 73.15  | 11.9x faster |
/// | 256  | 870.91 | 112.13 | 7.77x faster |
/// | 1024 | 885.05 | 260.76 | 3.39x faster |
/// | 3072 | 869.59 | 672.85 | 1.29x faster |
///
/// Incremental wins at EVERY span up to 3072 B, and the equivalence assertion in
/// that bench passes at every one of them. The crossover is therefore above the
/// widest span the coverage region admits, not below 256 — so this threshold sits
/// far under it and the full recompute it forces on wider spans is pure loss.
///
/// The value is deliberately LEFT AT 256 pending one more measurement: the caller
/// ([`dir_block_edit`]) also snapshots the pre-mutation region with `to_vec()`,
/// an allocation and copy that grow with the span while the full path carries
/// neither. The `incremental_with_snapshot` arm exists to price that and has not
/// been run (the fleet refused the bench four times on `queue_timeout`). Raising
/// this constant on the stamp-only numbers would be the counted-proxy error this
/// campaign has already made once: a counted win reversed by wall clock.
pub const INCREMENTAL_DIR_CSUM_MAX_SPAN: usize = 256;

/// Build a [`DirBlockEdit`] snapshotting `block[region_start..region_end]` — but
/// only when the span is non-empty and small enough for an incremental checksum
/// to win ([`INCREMENTAL_DIR_CSUM_MAX_SPAN`]); otherwise `None`, signalling the
/// caller to full-recompute. Must be called on the PRE-mutation block.
fn dir_block_edit(block: &[u8], region_start: usize, region_end: usize) -> Option<DirBlockEdit> {
    let len = region_end.checked_sub(region_start)?;
    if len == 0 || len > INCREMENTAL_DIR_CSUM_MAX_SPAN {
        return None;
    }
    Some(DirBlockEdit {
        region_start,
        old_bytes: block[region_start..region_end].to_vec(),
    })
}

/// Add a directory entry into a single directory block.
///
/// Uses ext4-style `rec_len` management:
/// - Reuses deleted slots (`inode == 0`) when large enough.
/// - Otherwise splits a live slot when it has enough slack.
/// - Returns the byte offset where the new entry was inserted.
///
/// `reserved_tail` is the number of bytes at the end of the block reserved
/// for metadata checksums (typically 12 for `METADATA_CSUM`).
pub fn add_entry(
    block: &mut [u8],
    ino: u32,
    name: &[u8],
    file_type: Ext4FileType,
    reserved_tail: usize,
) -> Result<usize> {
    add_entry_tracked(block, ino, name, file_type, reserved_tail).map(|(off, _)| off)
}

/// Like [`add_entry`], but also returns an optional [`DirBlockEdit`].
///
/// The edit describes the changed byte span, so a `metadata_csum` caller can
/// update the dir-block checksum tail *incrementally* instead of re-CRCing the
/// whole block. It is `Some` only when the change span is small enough to win
/// ([`INCREMENTAL_DIR_CSUM_MAX_SPAN`]) — an insert into a near-empty block
/// (huge slack + zero-fill) returns `None`, telling the caller to full-recompute.
pub fn add_entry_tracked(
    block: &mut [u8],
    ino: u32,
    name: &[u8],
    file_type: Ext4FileType,
    reserved_tail: usize,
) -> Result<(usize, Option<DirBlockEdit>)> {
    if ino == 0 {
        return Err(FfsError::Format(
            "directory entry inode cannot be zero".to_owned(),
        ));
    }
    validate_name(name)?;

    let need = required_rec_len(name.len());
    let limit = validate_reserved_tail(block.len(), reserved_tail)?;
    if need > limit {
        return Err(FfsError::NoSpace);
    }
    if is_interior_htree_dx_node_block(block) {
        return Err(FfsError::NoSpace);
    }

    let mut off = 0usize;
    while off + DIR_ENTRY_HEADER_LEN <= limit {
        // Reslice the 8-byte header once (one bounds check, NO copy) then read
        // the 3 fields at const offsets. The loop guard `off + HEADER_LEN <=
        // limit <= block.len()` proves the reslice in-bounds, but the compiler
        // does not chain that through `limit`, so the 3 separate checked reads
        // (rec_len @off+4, inode @off, name_len @off+6) each re-check per entry.
        // An array-REF reslice (not read_fixed's array COPY) is 1.56x on a full
        // block walk (bench entry_header_read). Value-identical.
        let header: &[u8; DIR_ENTRY_HEADER_LEN] = block[off..off + DIR_ENTRY_HEADER_LEN]
            .try_into()
            .map_err(|_| FfsError::Corruption {
                block: 0,
                detail: "unable to read directory entry header".to_owned(),
            })?;
        let rec_len = usize::from(u16::from_le_bytes([header[4], header[5]]));
        if rec_len < DIR_ENTRY_HEADER_LEN || (rec_len % 4) != 0 {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "invalid directory entry rec_len".to_owned(),
            });
        }
        let end = off
            .checked_add(rec_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry offset overflow".to_owned(),
            })?;
        if end > limit {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry exceeds usable block area".to_owned(),
            });
        }

        let cur_ino = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let cur_name_len = usize::from(header[6]);

        // Validate name_len against rec_len to prevent out-of-bounds access.
        if DIR_ENTRY_HEADER_LEN + cur_name_len > rec_len {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "directory entry name_len {cur_name_len} exceeds rec_len {rec_len} at offset {off}"
                ),
            });
        }

        if cur_ino == 0 {
            if rec_len >= need {
                // Tombstone reuse overwrites the whole slot `[off, off+rec_len)`
                // (header + name + zero-fill). Snapshot before the write.
                let edit = dir_block_edit(block, off, end);
                write_entry(block, off, ino, rec_len, file_type, name)?;
                return Ok((off, edit));
            }
            off = end;
            continue;
        }

        let actual = required_rec_len(cur_name_len);
        if actual > rec_len {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry name length exceeds rec_len".to_owned(),
            });
        }

        let slack = rec_len - actual;
        if slack >= need {
            // The split rewrites the shortened entry's `rec_len` (at `off+4`) and
            // writes the new entry into the vacated slack `[off+actual, end)`; the
            // untouched interior (the shortened entry's name) yields a zero delta.
            // The enclosing changed span is `[off+4, end)`. Snapshot before the
            // writes.
            let edit = dir_block_edit(block, off + 4, end);
            let actual_u16 = u16::try_from(actual)
                .map_err(|_| FfsError::Format("actual rec_len exceeds u16".to_owned()))?;
            write_u16_le(block, off + 4, actual_u16)?;
            let new_off = off + actual;
            write_entry(block, new_off, ino, slack, file_type, name)?;
            return Ok((new_off, edit));
        }

        off = end;
    }

    Err(FfsError::NoSpace)
}

/// Scan a single directory block for a live entry whose name matches `name`.
///
/// Returns `Ok(true)` if a non-tombstone entry with this exact name exists in
/// the block, `Ok(false)` otherwise. Interior htree index (dx_node) blocks have
/// no addressable entries and always return `Ok(false)`. Performs the same
/// `rec_len`/`name_len` bounds validation as the other single-block scanners, so
/// a corrupt entry surfaces as [`FfsError::Corruption`] rather than a silent
/// miss.
pub fn block_contains_live_name(block: &[u8], name: &[u8], reserved_tail: usize) -> Result<bool> {
    validate_name(name)?;
    let limit = validate_reserved_tail(block.len(), reserved_tail)?;
    if is_interior_htree_dx_node_block(block) {
        return Ok(false);
    }
    let mut off = 0usize;
    while off + DIR_ENTRY_HEADER_LEN <= limit {
        let rec_len =
            usize::from(
                read_u16_le(block, off + 4).ok_or_else(|| FfsError::Corruption {
                    block: 0,
                    detail: "unable to read directory entry rec_len".to_owned(),
                })?,
            );
        if rec_len < DIR_ENTRY_HEADER_LEN || (rec_len % 4) != 0 {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "invalid directory entry rec_len".to_owned(),
            });
        }
        let end = off
            .checked_add(rec_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry offset overflow".to_owned(),
            })?;
        if end > limit {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry exceeds usable block area".to_owned(),
            });
        }
        let cur_ino = read_u32_le(block, off).ok_or_else(|| FfsError::Corruption {
            block: 0,
            detail: "unable to read directory entry inode".to_owned(),
        })?;
        let cur_name_len = usize::from(block[off + 6]);
        let name_end = off
            .checked_add(DIR_ENTRY_HEADER_LEN + cur_name_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry name offset overflow".to_owned(),
            })?;
        if name_end > end {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "directory entry name_len {cur_name_len} exceeds rec_len {rec_len} at offset {off}"
                ),
            });
        }
        if cur_ino != 0 && names_eq(&block[off + DIR_ENTRY_HEADER_LEN..name_end], name) {
            return Ok(true);
        }
        off = end;
    }
    Ok(false)
}

/// Like [`add_entry`], but first verifies `name` is not already present as a
/// live entry in this block, returning [`FfsError::Exists`] if it is.
///
/// This lets an htree insert fold the duplicate-name (EEXIST) check into the
/// same target-leaf scan it already performs, so the create-family paths
/// (`create`/`mkdir`/`mknod`/`symlink`) can skip a separate positive
/// `lookup_name` descent — a full second htree traversal — when the directory
/// is hash-indexed: the hash-correct leaf is the only block any duplicate of
/// `name` could occupy, so scanning it here is a complete duplicate check.
/// Linear directories must keep their own full-directory pre-check, since a
/// duplicate may live in a different block than the one with free space.
pub fn add_entry_reject_existing(
    block: &mut [u8],
    ino: u32,
    name: &[u8],
    file_type: Ext4FileType,
    reserved_tail: usize,
) -> Result<usize> {
    add_entry_reject_existing_tracked(block, ino, name, file_type, reserved_tail)
        .map(|(off, _)| off)
}

/// First fitting slot for a new directory entry.
///
/// Recorded during the single scan of [`add_entry_reject_existing_tracked`] and
/// applied only once the whole block is confirmed free of a live duplicate. Kept
/// at module scope rather than inside that function because an item declared
/// after statements reads as if it came into existence at that point, when it is
/// in fact in scope from the start of the block.
enum Slot {
    Tombstone {
        off: usize,
        rec_len: usize,
    },
    Split {
        off: usize,
        actual: usize,
        slack: usize,
    },
}

/// Like [`add_entry_reject_existing`], but also returns an optional
/// [`DirBlockEdit`] describing the changed byte span.
///
/// The span drives an incremental `metadata_csum` tail update (see
/// [`add_entry_tracked`]). The edit is `Some` only when the change span is small
/// enough to win ([`INCREMENTAL_DIR_CSUM_MAX_SPAN`]).
pub fn add_entry_reject_existing_tracked(
    block: &mut [u8],
    ino: u32,
    name: &[u8],
    file_type: Ext4FileType,
    reserved_tail: usize,
) -> Result<(usize, Option<DirBlockEdit>)> {
    // Single pass: reject a duplicate live `name` AND locate the first fitting
    // slot in ONE scan, instead of `block_contains_live_name` + `add_entry` each
    // walking the whole ~4 KiB block (the two scans were ~4% and ~3% of a create,
    // perf). Semantics are identical to the two-pass form: the whole block is
    // scanned for a live duplicate before any write (we insert only after the
    // loop completes dup-free), and the chosen slot is exactly the first-fitting
    // one `add_entry` would pick — a leading tombstone with `rec_len >= need`, or
    // the first live entry with `slack >= need` split in place (bd-cc-1pass-add).
    if ino == 0 {
        return Err(FfsError::Format(
            "directory entry inode cannot be zero".to_owned(),
        ));
    }
    validate_name(name)?;
    let need = required_rec_len(name.len());
    let limit = validate_reserved_tail(block.len(), reserved_tail)?;
    if need > limit {
        return Err(FfsError::NoSpace);
    }
    if is_interior_htree_dx_node_block(block) {
        return Err(FfsError::NoSpace);
    }

    let mut slot: Option<Slot> = None;

    let mut off = 0usize;
    while off + DIR_ENTRY_HEADER_LEN <= limit {
        // Reslice the 8-byte header once (one bounds check, NO copy) then read
        // the 3 fields at const offsets. The loop guard `off + HEADER_LEN <=
        // limit <= block.len()` proves the reslice in-bounds, but the compiler
        // does not chain that through `limit`, so the 3 separate checked reads
        // (rec_len @off+4, inode @off, name_len @off+6) each re-check per entry.
        // An array-REF reslice (not read_fixed's array COPY) is 1.56x on a full
        // block walk (bench entry_header_read). Value-identical.
        let header: &[u8; DIR_ENTRY_HEADER_LEN] = block[off..off + DIR_ENTRY_HEADER_LEN]
            .try_into()
            .map_err(|_| FfsError::Corruption {
                block: 0,
                detail: "unable to read directory entry header".to_owned(),
            })?;
        let rec_len = usize::from(u16::from_le_bytes([header[4], header[5]]));
        if rec_len < DIR_ENTRY_HEADER_LEN || (rec_len % 4) != 0 {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "invalid directory entry rec_len".to_owned(),
            });
        }
        let end = off
            .checked_add(rec_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry offset overflow".to_owned(),
            })?;
        if end > limit {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry exceeds usable block area".to_owned(),
            });
        }

        let cur_ino = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let cur_name_len = usize::from(header[6]);

        // Validate name_len against rec_len to prevent out-of-bounds access.
        if DIR_ENTRY_HEADER_LEN + cur_name_len > rec_len {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "directory entry name_len {cur_name_len} exceeds rec_len {rec_len} at offset {off}"
                ),
            });
        }

        if cur_ino == 0 {
            if slot.is_none() && rec_len >= need {
                slot = Some(Slot::Tombstone { off, rec_len });
            }
            off = end;
            continue;
        }

        // Live entry: duplicate check (mirrors `block_contains_live_name`).
        if names_eq(
            &block[off + DIR_ENTRY_HEADER_LEN..off + DIR_ENTRY_HEADER_LEN + cur_name_len],
            name,
        ) {
            return Err(FfsError::Exists);
        }

        let actual = required_rec_len(cur_name_len);
        if actual > rec_len {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry name length exceeds rec_len".to_owned(),
            });
        }
        if slot.is_none() && rec_len - actual >= need {
            slot = Some(Slot::Split {
                off,
                actual,
                slack: rec_len - actual,
            });
        }

        off = end;
    }

    match slot {
        Some(Slot::Tombstone { off, rec_len }) => {
            let end = off + rec_len;
            let edit = dir_block_edit(block, off, end);
            write_entry(block, off, ino, rec_len, file_type, name)?;
            Ok((off, edit))
        }
        Some(Slot::Split { off, actual, slack }) => {
            let end = off + actual + slack;
            let edit = dir_block_edit(block, off + 4, end);
            let actual_u16 = u16::try_from(actual)
                .map_err(|_| FfsError::Format("actual rec_len exceeds u16".to_owned()))?;
            write_u16_le(block, off + 4, actual_u16)?;
            let new_off = off + actual;
            write_entry(block, new_off, ino, slack, file_type, name)?;
            Ok((new_off, edit))
        }
        None => Err(FfsError::NoSpace),
    }
}

/// The contiguous byte span a directory-block mutation changed, captured so the
/// caller can update the block's `metadata_csum` tail *incrementally* instead of
/// re-CRCing the whole ~4 KiB block.
///
/// `old_bytes` is the pre-image of `block[region_start .. region_start +
/// old_bytes.len())`. A mutation may write two disjoint fields (e.g. a
/// predecessor's `rec_len` and the removed entry's header); the span is the
/// single enclosing range, with the untouched interior bytes contributing a zero
/// delta — exactly what [`ffs_ondisk::stamp_dir_block_checksum_incremental`]
/// expects.
#[derive(Debug, Clone)]
pub struct DirBlockEdit {
    /// Offset of the first byte the mutation could have changed.
    pub region_start: usize,
    /// Pre-image of the changed span (before the mutation was applied).
    pub old_bytes: Vec<u8>,
}

impl DirBlockEdit {
    /// XOR delta of the changed span against the post-mutation `block`
    /// (`delta[i] = old_bytes[i] ^ block[region_start + i]`). Feed this to
    /// [`ffs_ondisk::stamp_dir_block_checksum_incremental`] with `region_start`.
    #[must_use]
    pub fn delta(&self, block: &[u8]) -> Vec<u8> {
        let mut d = self.old_bytes.clone();
        for (i, byte) in d.iter_mut().enumerate() {
            *byte ^= block[self.region_start + i];
        }
        d
    }
}

/// Remove a directory entry by name from a single directory block.
///
/// On success:
/// - If there is a previous live entry, its `rec_len` is expanded to absorb
///   the removed slot (coalescing free space).
/// - Otherwise the target entry is marked deleted (`inode = 0`).
pub fn remove_entry(block: &mut [u8], name: &[u8], reserved_tail: usize) -> Result<bool> {
    Ok(remove_entry_take_inode(block, name, reserved_tail)?.is_some())
}

/// Like [`remove_entry`], but returns the removed entry's inode number.
///
/// The value is read from the matched dirent's `inode` field, instead of just a
/// found/not-found bool. This lets a caller that needs the child inode — e.g.
/// `unlink`/`rmdir`, which otherwise does a separate positive `lookup_name` (a
/// second htree descent + leaf read + scan) just to learn it — collapse "find the
/// child" and "remove the entry" into one descent + scan.
pub fn remove_entry_take_inode(
    block: &mut [u8],
    name: &[u8],
    reserved_tail: usize,
) -> Result<Option<u32>> {
    Ok(remove_entry_take_inode_tracked(block, name, reserved_tail)?.map(|(ino, _)| ino))
}

/// Like [`remove_entry_take_inode`], but also returns a [`DirBlockEdit`].
///
/// The edit describes the exact byte span the removal changed, so a
/// `metadata_csum` caller can update the dir-block checksum tail incrementally
/// ([`ffs_ondisk::stamp_dir_block_checksum_incremental`]) rather than re-CRCing
/// the whole block. The removal touches at most two small disjoint fields (the
/// predecessor's `rec_len` and the removed entry's 8-byte header), so the
/// enclosing span is tiny — a ~10x checksum saving on the unlink/rmdir/rename
/// hot path (bench `dir_csum_incremental`).
pub fn remove_entry_take_inode_tracked(
    block: &mut [u8],
    name: &[u8],
    reserved_tail: usize,
) -> Result<Option<(u32, DirBlockEdit)>> {
    validate_name(name)?;

    let mut off = 0usize;
    let mut prev_off_opt: Option<usize> = None;
    let limit = validate_reserved_tail(block.len(), reserved_tail)?;

    // An interior htree index node (dx_node): its leading fake dirent has
    // inode 0 and a rec_len spanning the ENTIRE block (past the usable directory
    // area and any metadata_csum tail). It carries the hash index, not removable
    // directory entries. ext4's entry-removal and rename paths scan every
    // directory block, so report "not present here" rather than rejecting the
    // block as corrupt — otherwise removing from a multi-level htree dir whose
    // interior node precedes the target leaf would spuriously fail (on
    // metadata_csum the fake dirent's rec_len exceeds `limit`). bd-y8tcx.
    if is_interior_htree_dx_node_block(block) {
        return Ok(None);
    }

    while off + DIR_ENTRY_HEADER_LEN <= limit {
        // Reslice the 8-byte header once (one bounds check, NO copy) then read
        // the 3 fields at const offsets. The loop guard `off + HEADER_LEN <=
        // limit <= block.len()` proves the reslice in-bounds, but the compiler
        // does not chain that through `limit`, so the 3 separate checked reads
        // (rec_len @off+4, inode @off, name_len @off+6) each re-check per entry.
        // An array-REF reslice (not read_fixed's array COPY) is 1.56x on a full
        // block walk (bench entry_header_read). Value-identical.
        let header: &[u8; DIR_ENTRY_HEADER_LEN] = block[off..off + DIR_ENTRY_HEADER_LEN]
            .try_into()
            .map_err(|_| FfsError::Corruption {
                block: 0,
                detail: "unable to read directory entry header".to_owned(),
            })?;
        let rec_len = usize::from(u16::from_le_bytes([header[4], header[5]]));
        if rec_len < DIR_ENTRY_HEADER_LEN || (rec_len % 4) != 0 {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "invalid directory entry rec_len".to_owned(),
            });
        }
        let end = off
            .checked_add(rec_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry offset overflow".to_owned(),
            })?;
        if end > limit {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry exceeds usable block area".to_owned(),
            });
        }

        let cur_ino = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let cur_name_len = usize::from(header[6]);
        let name_end = off
            .checked_add(DIR_ENTRY_HEADER_LEN + cur_name_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry name offset overflow".to_owned(),
            })?;
        if name_end > end {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "directory entry name_len {cur_name_len} exceeds rec_len {rec_len} at offset {off}"
                ),
            });
        }

        if cur_ino != 0 && names_eq(&block[off + DIR_ENTRY_HEADER_LEN..name_end], name) {
            // Snapshot the enclosing changed span BEFORE mutating so the caller
            // can update the metadata_csum tail incrementally. Two disjoint
            // writes: the predecessor's `rec_len` (when present) at `prev_off+4`
            // and this entry's 8-byte header at `off`. `prev_off < off` (forward
            // scan), so the enclosing span is `[region_start, off + 8)`; the
            // untouched interior bytes yield a zero delta.
            let region_start = prev_off_opt.map_or(off, |prev_off| prev_off + 4);
            let region_end = off + DIR_ENTRY_HEADER_LEN;
            let old_bytes = block[region_start..region_end].to_vec();

            if let Some(prev_off) = prev_off_opt {
                let merged = (off + rec_len)
                    .checked_sub(prev_off)
                    .ok_or_else(|| FfsError::Format("merged rec_len underflow".to_owned()))?;
                let merged_u16 = u16::try_from(merged)
                    .map_err(|_| FfsError::Format("merged rec_len exceeds u16".to_owned()))?;
                write_u16_le(block, prev_off + 4, merged_u16)?;
            }

            write_u32_le(block, off, 0)?;
            // Clear metadata for cleanliness.
            block[off + 6] = 0;
            block[off + 7] = 0;
            return Ok(Some((
                cur_ino,
                DirBlockEdit {
                    region_start,
                    old_bytes,
                },
            )));
        }

        if cur_ino != 0 {
            prev_off_opt = Some(off);
        }
        off = end;
    }

    Ok(None)
}

fn update_live_entry_header(
    block: &mut [u8],
    name: &[u8],
    new_ino: u32,
    new_file_type: Option<Ext4FileType>,
    reserved_tail: usize,
) -> Result<bool> {
    validate_name(name)?;
    if new_ino == 0 {
        return Err(FfsError::Format(
            "directory entry inode cannot be zero".to_owned(),
        ));
    }

    let mut off = 0usize;
    let limit = validate_reserved_tail(block.len(), reserved_tail)?;
    if is_interior_htree_dx_node_block(block) {
        return Ok(false);
    }

    while off + DIR_ENTRY_HEADER_LEN <= limit {
        // Reslice the 8-byte header once (one bounds check, NO copy) then read
        // the 3 fields at const offsets. The loop guard `off + HEADER_LEN <=
        // limit <= block.len()` proves the reslice in-bounds, but the compiler
        // does not chain that through `limit`, so the 3 separate checked reads
        // (rec_len @off+4, inode @off, name_len @off+6) each re-check per entry.
        // An array-REF reslice (not read_fixed's array COPY) is 1.56x on a full
        // block walk (bench entry_header_read). Value-identical.
        let header: &[u8; DIR_ENTRY_HEADER_LEN] = block[off..off + DIR_ENTRY_HEADER_LEN]
            .try_into()
            .map_err(|_| FfsError::Corruption {
                block: 0,
                detail: "unable to read directory entry header".to_owned(),
            })?;
        let rec_len = usize::from(u16::from_le_bytes([header[4], header[5]]));
        if rec_len < DIR_ENTRY_HEADER_LEN || (rec_len % 4) != 0 {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "invalid directory entry rec_len".to_owned(),
            });
        }
        let end = off
            .checked_add(rec_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry offset overflow".to_owned(),
            })?;
        if end > limit {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry exceeds usable block area".to_owned(),
            });
        }

        let cur_ino = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let cur_name_len = usize::from(header[6]);
        let name_end = off
            .checked_add(DIR_ENTRY_HEADER_LEN + cur_name_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry name offset overflow".to_owned(),
            })?;
        if name_end > end {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "directory entry name_len {cur_name_len} exceeds rec_len {rec_len} at offset {off}"
                ),
            });
        }
        if cur_ino != 0 && names_eq(&block[off + DIR_ENTRY_HEADER_LEN..name_end], name) {
            write_u32_le(block, off, new_ino)?;
            if let Some(file_type) = new_file_type {
                block[off + 7] = file_type as u8;
            }
            return Ok(true);
        }
        off = end;
    }
    Ok(false)
}

/// Swap the inode number on the live entry whose name matches `name`.
///
/// This intentionally leaves the ext4 `file_type` tag unchanged. Use
/// [`retarget_entry`] when the target inode's kind may differ.
///
/// Returns `Ok(true)` on swap, `Ok(false)` if `name` is not present
/// in this block. Tombstones (entries with `inode == 0`) are skipped
/// so a deleted entry that happens to share the name is never matched.
pub fn swap_inode_in_entry(
    block: &mut [u8],
    name: &[u8],
    new_ino: u32,
    reserved_tail: usize,
) -> Result<bool> {
    update_live_entry_header(block, name, new_ino, None, reserved_tail)
}

/// Retarget a live directory entry to a different inode and file type.
///
/// `renameat2(RENAME_EXCHANGE)` needs this for mixed-type exchanges:
/// swapping only inode numbers would leave stale d_type/file_type tags
/// attached to the old names.
pub fn retarget_entry(
    block: &mut [u8],
    name: &[u8],
    new_ino: u32,
    new_file_type: Ext4FileType,
    reserved_tail: usize,
) -> Result<bool> {
    update_live_entry_header(block, name, new_ino, Some(new_file_type), reserved_tail)
}

/// Initialize an empty directory block with `.` and `..` entries.
pub fn init_dir_block(
    block: &mut [u8],
    self_ino: u32,
    parent_ino: u32,
    reserved_tail: usize,
) -> Result<()> {
    if self_ino == 0 {
        return Err(FfsError::Format(
            "directory self inode cannot be zero".to_owned(),
        ));
    }
    if parent_ino == 0 {
        return Err(FfsError::Format(
            "directory parent inode cannot be zero".to_owned(),
        ));
    }

    let usable_len = validate_reserved_tail(block.len(), reserved_tail)?;
    let min_entries = required_rec_len(1)
        .checked_add(required_rec_len(2))
        .ok_or_else(|| FfsError::Format("directory minimum entry size overflow".to_owned()))?;
    if usable_len < min_entries {
        return Err(FfsError::Format(
            "directory block too small for . and .. entries".to_owned(),
        ));
    }
    block.fill(0);

    let dot_len = required_rec_len(1);
    let dotdot_len = usable_len - dot_len;

    write_entry(block, 0, self_ino, dot_len, Ext4FileType::Dir, b".")?;
    write_entry(
        block,
        dot_len,
        parent_ino,
        dotdot_len,
        Ext4FileType::Dir,
        b"..",
    )?;

    if reserved_tail >= 12 {
        let off = block.len() - reserved_tail;
        // struct ext4_dir_entry_tail: { 0(4), rec_len=12(2), 0(1), 0xDE(1), checksum(4) }
        write_u32_le(block, off, 0)?;
        write_u16_le(block, off + 4, 12)?;
        block[off + 6] = 0;
        block[off + 7] = EXT4_FT_DIR_CSUM;
        write_u32_le(block, off + 8, 0)?; // checksum initially 0
    }

    Ok(())
}

/// Hash/index entry for ext4 htree directory indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtreeEntry {
    pub hash: u32,
    pub block: u32,
}

/// Compute ext4 DX hash major value for a directory name.
#[must_use]
pub fn compute_dx_hash(hash_version: u8, name: &[u8], seed: &[u32; 4]) -> u32 {
    ffs_ondisk::dx_hash(hash_version, name, seed).0
}

/// Insert an htree mapping entry while preserving hash ordering.
///
/// Returns the insertion index.
pub fn htree_insert(entries: &mut Vec<HtreeEntry>, hash: u32, block: u32) -> usize {
    let idx = entries.partition_point(|e| e.hash <= hash);
    entries.insert(idx, HtreeEntry { hash, block });
    idx
}

/// Remove one matching htree mapping entry (`hash`, `block`).
///
/// Returns `true` when an entry was removed.
pub fn htree_remove(entries: &mut Vec<HtreeEntry>, hash: u32, block: u32) -> bool {
    let Some(pos) = entries
        .iter()
        .position(|e| e.hash == hash && e.block == block)
    else {
        return false;
    };
    entries.remove(pos);
    true
}

/// Find the rightmost entry index whose hash is <= target_hash.
#[must_use]
pub fn htree_find_leaf_idx(entries: &[HtreeEntry], target_hash: u32) -> usize {
    if entries.is_empty() {
        return 0;
    }
    let idx = entries.partition_point(|e| e.hash <= target_hash);
    if idx == 0 { 0 } else { idx - 1 }
}

/// Find the leaf block using the "rightmost hash <= target" rule.
#[must_use]
pub fn htree_find_leaf(entries: &[HtreeEntry], target_hash: u32) -> Option<u32> {
    if entries.is_empty() {
        return None;
    }
    let idx = htree_find_leaf_idx(entries, target_hash);
    entries.get(idx).map(|e| e.block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::{Ext4FileType, parse_dir_block};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn valid_dir_name_strategy(max_len: usize) -> BoxedStrategy<Vec<u8>> {
        proptest::collection::vec(b'a'..=b'z', 1..=max_len).boxed()
    }

    fn dir_block_geometry_strategy() -> BoxedStrategy<(usize, usize)> {
        (6_usize..=1024)
            .prop_map(|units| units * 4)
            .prop_flat_map(|block_len| {
                let max_tail_units = (block_len - 24) / 4;
                if max_tail_units >= 3 {
                    prop_oneof![
                        Just((block_len, 0_usize)),
                        (3_usize..=max_tail_units)
                            .prop_map(move |tail_units| { (block_len, tail_units * 4) }),
                    ]
                    .boxed()
                } else {
                    Just((block_len, 0_usize)).boxed()
                }
            })
            .boxed()
    }

    fn unique_htree_entries_strategy() -> BoxedStrategy<Vec<(u32, u32)>> {
        proptest::collection::btree_map(any::<u32>(), 1_u32..=u32::MAX, 1..32)
            .prop_map(|entries| entries.into_iter().collect())
            .boxed()
    }

    const REPRESENTATIVE_DIR_BLOCK_GOLDEN: &str = concat!(
        "slot_headers\n",
        "  [0] inode=17 rec_len=12 name_len=1 file_type=Dir\n",
        "  [12] inode=2 rec_len=28 name_len=2 file_type=Dir\n",
        "  [24] inode=0 rec_len=16 name_len=0 file_type_raw=0\n",
        "  [40] inode=99 rec_len=12 name_len=3 file_type=Dir\n",
        "tail\n",
        "  checksum=0 raw=[00, 00, 00, 00, 0c, 00, 00, de, 00, 00, 00, 00]\n",
        "parsed\n",
        "  inode=17 rec_len=12 file_type=Dir name=\".\"\n",
        "  inode=2 rec_len=28 file_type=Dir name=\"..\"\n",
        "  inode=99 rec_len=12 file_type=Dir name=\"sub\"\n",
        "block=[11, 00, 00, 00, 0c, 00, 01, 02, 2e, 00, 00, 00, 02, 00, 00, 00, 1c, 00, 02, 02, 2e, 2e, 00, 00, 00, 00, 00, 00, 10, 00, 00, 00, 68, 69, 2e, 74, 78, 74, 00, 00, 63, 00, 00, 00, 0c, 00, 03, 02, 73, 75, 62, 00, 00, 00, 00, 00, 0c, 00, 00, de, 00, 00, 00, 00]"
    );

    fn representative_dir_block_golden_contract_actual() -> String {
        let mut block = vec![0_u8; 64];
        init_dir_block(&mut block, 17, 2, 12).expect("init representative dir block");
        add_entry(&mut block, 41, b"hi.txt", Ext4FileType::RegFile, 12)
            .expect("insert representative file");
        add_entry(&mut block, 99, b"sub", Ext4FileType::Dir, 12)
            .expect("insert representative subdir");
        assert!(
            remove_entry(&mut block, b"hi.txt", 12).expect("remove representative file"),
            "representative file entry should be removed"
        );

        let (entries, tail) = parse_dir_block(&block, 64).expect("parse representative dir block");
        let tail = tail.expect("representative dir block should preserve checksum tail");
        let parsed_lines = entries
            .iter()
            .map(|entry| {
                format!(
                    "  inode={} rec_len={} file_type={:?} name={:?}",
                    entry.inode,
                    entry.rec_len,
                    entry.file_type,
                    entry.name_str()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            concat!(
                "slot_headers\n",
                "  [0] inode={} rec_len={} name_len={} file_type={:?}\n",
                "  [12] inode={} rec_len={} name_len={} file_type={:?}\n",
                "  [24] inode={} rec_len={} name_len={} file_type_raw={}\n",
                "  [40] inode={} rec_len={} name_len={} file_type={:?}\n",
                "tail\n",
                "  checksum={} raw={:02x?}\n",
                "parsed\n",
                "{}\n",
                "block={:02x?}"
            ),
            read_u32_le(&block, 0).expect("read dot inode"),
            read_u16_le(&block, 4).expect("read dot rec_len"),
            block[6],
            Ext4FileType::from_raw(block[7]),
            read_u32_le(&block, 12).expect("read dotdot inode"),
            read_u16_le(&block, 16).expect("read dotdot rec_len"),
            block[18],
            Ext4FileType::from_raw(block[19]),
            read_u32_le(&block, 24).expect("read deleted inode"),
            read_u16_le(&block, 28).expect("read deleted rec_len"),
            block[30],
            block[31],
            read_u32_le(&block, 40).expect("read sub inode"),
            read_u16_le(&block, 44).expect("read sub rec_len"),
            block[46],
            Ext4FileType::from_raw(block[47]),
            tail.checksum,
            &block[52..64],
            parsed_lines,
            block,
        )
    }

    fn live_name_set(block: &[u8]) -> BTreeSet<Vec<u8>> {
        parse_dir_block(block, u32::try_from(block.len()).unwrap())
            .unwrap()
            .0
            .into_iter()
            .filter(|entry| entry.inode != 0)
            .map(|entry| entry.name)
            .collect()
    }

    fn assert_add_entry_alignment_boundary(name_len: usize) {
        let mut block = vec![0u8; 12 + required_rec_len(name_len)];
        let block_len = block.len();
        write_entry(&mut block, 0, 1, block_len, Ext4FileType::Dir, b".").unwrap();

        let name = vec![b'x'; name_len];
        let off = add_entry(&mut block, 99, &name, Ext4FileType::RegFile, 0).unwrap();

        assert_eq!(off, 12);
        assert_eq!(usize::from(read_u16_le(&block, 4).unwrap()), 12);
        assert_eq!(
            usize::from(read_u16_le(&block, off + 4).unwrap()),
            required_rec_len(name_len)
        );

        let (entries, _) = parse_dir_block(&block, u32::try_from(block.len()).unwrap()).unwrap();
        let entry = entries
            .iter()
            .find(|entry| entry.inode == 99)
            .expect("new entry must be parseable");
        assert_eq!(entry.name.len(), name_len);
    }

    fn make_interior_htree_dx_node_block(block_size: usize) -> Vec<u8> {
        let mut node = vec![0u8; block_size];
        node[4..6].copy_from_slice(&u16::try_from(block_size).unwrap().to_le_bytes());
        node[8..10].copy_from_slice(&7_u16.to_le_bytes()); // dx_countlimit.limit
        node[10..12].copy_from_slice(&1_u16.to_le_bytes()); // dx_countlimit.count
        node[12..16].copy_from_slice(&3_u32.to_le_bytes()); // entry 0 block
        node
    }

    macro_rules! add_entry_alignment_boundary_test {
        ($name:ident, $len:expr) => {
            #[test]
            fn $name() {
                assert_add_entry_alignment_boundary($len);
            }
        };
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// retarget_entry (renameat2 RENAME_EXCHANGE) must update BOTH the inode
        /// and the file_type of a live entry, leave the block parseable, and
        /// report no change for a name that is not present (bd-xmh5g.215).
        #[test]
        fn proptest_retarget_entry_updates_inode_and_file_type(
            ino in 3_u32..1_000_000,
            new_ino in 3_u32..1_000_000,
            reserved_tail in prop_oneof![Just(0_usize), Just(12_usize), Just(24_usize)],
            name in valid_dir_name_strategy(200),
        ) {
            let mut block = vec![0u8; 4096];
            init_dir_block(&mut block, 2, 2, reserved_tail).unwrap();
            add_entry(&mut block, ino, &name, Ext4FileType::RegFile, reserved_tail).unwrap();

            // Retarget to a new inode AND a different file type.
            let retargeted =
                retarget_entry(&mut block, &name, new_ino, Ext4FileType::Dir, reserved_tail)
                    .unwrap();
            prop_assert!(retargeted);

            let (entries, _) = parse_dir_block(&block, 4096).unwrap();
            let entry = entries
                .iter()
                .find(|e| e.name == name)
                .expect("retargeted entry must still parse");
            prop_assert_eq!(entry.inode, new_ino);
            prop_assert_eq!(entry.file_type, Ext4FileType::Dir);

            let second_ino = new_ino + 1;
            let retargeted_again = retarget_entry(
                &mut block,
                &name,
                second_ino,
                Ext4FileType::Symlink,
                reserved_tail,
            )
            .unwrap();
            prop_assert!(retargeted_again);
            let (entries, _) = parse_dir_block(&block, 4096).unwrap();
            let entry = entries
                .iter()
                .find(|e| e.name == name)
                .expect("retargeted entry must still parse after a second update");
            prop_assert_eq!(entry.inode, second_ino);
            prop_assert_eq!(entry.file_type, Ext4FileType::Symlink);

            // Retargeting a name that is not present reports no change.
            let probe: &[u8] = b"\x01zz_absent_probe_zz\x01";
            if name.as_slice() != probe {
                let absent =
                    retarget_entry(&mut block, probe, 9, Ext4FileType::RegFile, reserved_tail)
                        .unwrap();
                prop_assert!(!absent);
            }
        }

        #[test]
        fn proptest_add_remove_roundtrip_preserves_parseability(
            ino in 3_u32..=u32::MAX,
            reserved_tail in prop_oneof![Just(0_usize), Just(12_usize), Just(24_usize)],
            name in valid_dir_name_strategy(255),
        ) {
            let mut block = vec![0u8; 4096];
            init_dir_block(&mut block, 2, 2, reserved_tail).unwrap();

            let off = add_entry(&mut block, ino, &name, Ext4FileType::RegFile, reserved_tail)
                .unwrap();
            prop_assert!(off + required_rec_len(name.len()) <= block.len() - reserved_tail);

            let (entries, tail) = parse_dir_block(&block, 4096).unwrap();
            prop_assert_eq!(tail.is_some(), reserved_tail >= 12);
            prop_assert!(entries.iter().any(|entry| entry.inode == ino && entry.name == name));

            let removed = remove_entry(&mut block, &name, reserved_tail).unwrap();
            prop_assert!(removed);

            let (entries_after, tail_after) = parse_dir_block(&block, 4096).unwrap();
            prop_assert_eq!(tail_after.is_some(), reserved_tail >= 12);
            prop_assert_eq!(
                entries_after.iter().filter(|entry| entry.inode != 0).count(),
                2
            );
            prop_assert!(!entries_after
                .iter()
                .any(|entry| entry.inode != 0 && entry.name == name));
        }

        #[test]
        fn proptest_distinct_add_order_preserves_live_names(
            reserved_tail in prop_oneof![Just(0_usize), Just(12_usize), Just(24_usize)],
            (name_a, name_b) in (valid_dir_name_strategy(48), valid_dir_name_strategy(48))
                .prop_filter("directory names must be distinct", |(a, b)| a != b),
        ) {
            let mut first_order = vec![0u8; 1024];
            let mut second_order = vec![0u8; 1024];
            init_dir_block(&mut first_order, 2, 2, reserved_tail).unwrap();
            init_dir_block(&mut second_order, 2, 2, reserved_tail).unwrap();

            add_entry(&mut first_order, 3, &name_a, Ext4FileType::RegFile, reserved_tail)
                .unwrap();
            add_entry(&mut first_order, 4, &name_b, Ext4FileType::Dir, reserved_tail).unwrap();

            add_entry(&mut second_order, 4, &name_b, Ext4FileType::Dir, reserved_tail).unwrap();
            add_entry(&mut second_order, 3, &name_a, Ext4FileType::RegFile, reserved_tail)
                .unwrap();

            prop_assert_eq!(live_name_set(&first_order), live_name_set(&second_order));

            let (_, first_tail) = parse_dir_block(&first_order, 1024).unwrap();
            let (_, second_tail) = parse_dir_block(&second_order, 1024).unwrap();
            prop_assert_eq!(first_tail.is_some(), reserved_tail >= 12);
            prop_assert_eq!(second_tail.is_some(), reserved_tail >= 12);
        }

        #[test]
        fn proptest_add_sequence_remains_parseable_until_enospc(
            reserved_tail in prop_oneof![Just(0_usize), Just(12_usize), Just(24_usize)],
            operations in proptest::collection::vec(
                (3_u32..=u32::MAX, valid_dir_name_strategy(32)),
                0..40
            ),
        ) {
            let mut block = vec![0u8; 1024];
            init_dir_block(&mut block, 2, 2, reserved_tail).unwrap();

            let mut successes = 0usize;
            for (ino, name) in operations {
                let before = block.clone();
                match add_entry(&mut block, ino, &name, Ext4FileType::RegFile, reserved_tail) {
                    Ok(off) => {
                        successes += 1;
                        prop_assert!(off < block.len() - reserved_tail);
                        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
                        prop_assert_eq!(tail.is_some(), reserved_tail >= 12);
                        prop_assert_eq!(
                            entries.iter().filter(|entry| entry.inode != 0).count(),
                            2 + successes
                        );
                    }
                    Err(FfsError::NoSpace) => {
                        prop_assert_eq!(block.as_slice(), before.as_slice());
                        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
                        prop_assert_eq!(tail.is_some(), reserved_tail >= 12);
                        prop_assert_eq!(
                            entries.iter().filter(|entry| entry.inode != 0).count(),
                            2 + successes
                        );
                    }
                    Err(err) => prop_assert!(false, "unexpected add_entry error: {err:?}"),
                }
            }
        }

        #[test]
        fn proptest_init_dir_block_roundtrip_preserves_inode_numbers(
            geometry in dir_block_geometry_strategy(),
            self_ino in 1_u32..=u32::MAX,
            parent_ino in 1_u32..=u32::MAX,
        ) {
            let (block_len, reserved_tail) = geometry;
            let mut block = vec![0u8; block_len];

            init_dir_block(&mut block, self_ino, parent_ino, reserved_tail).unwrap();

            let (entries, tail) =
                parse_dir_block(&block, u32::try_from(block_len).unwrap()).unwrap();
            prop_assert_eq!(entries.len(), 2);
            prop_assert_eq!(&entries[0].name, b".");
            prop_assert_eq!(entries[0].inode, self_ino);
            prop_assert_eq!(&entries[1].name, b"..");
            prop_assert_eq!(entries[1].inode, parent_ino);
            prop_assert_eq!(
                usize::try_from(entries[1].rec_len).unwrap(),
                block_len - required_rec_len(1) - reserved_tail
            );
            prop_assert_eq!(tail.is_some(), reserved_tail >= 12);
        }

        #[test]
        fn proptest_htree_insert_and_lookup_matches_manual_model(
            operations in proptest::collection::vec((any::<u32>(), any::<u32>()), 0..128),
            target_hash in any::<u32>(),
        ) {
            let mut entries = Vec::new();
            for (hash, block) in operations {
                htree_insert(&mut entries, hash, block);
                prop_assert!(entries.windows(2).all(|pair| pair[0].hash <= pair[1].hash));
            }

            let expected = if entries.is_empty() {
                None
            } else {
                let mut chosen = entries[0].block;
                for entry in &entries {
                    if entry.hash <= target_hash {
                        chosen = entry.block;
                    } else {
                        break;
                    }
                }
                Some(chosen)
            };

            prop_assert_eq!(htree_find_leaf(&entries, target_hash), expected);
        }

        #[test]
        fn proptest_htree_insert_order_invariance_for_unique_hashes(
            canonical_entries in unique_htree_entries_strategy(),
            queries in proptest::collection::vec(any::<u32>(), 0..32),
        ) {
            let mut forward = Vec::new();
            for (hash, block) in &canonical_entries {
                htree_insert(&mut forward, *hash, *block);
            }

            let mut reversed = Vec::new();
            for (hash, block) in canonical_entries.iter().rev() {
                htree_insert(&mut reversed, *hash, *block);
            }

            let expected: Vec<HtreeEntry> = canonical_entries
                .iter()
                .map(|(hash, block)| HtreeEntry {
                    hash: *hash,
                    block: *block,
                })
                .collect();

            prop_assert_eq!(&forward, &expected);
            prop_assert_eq!(&reversed, &expected);

            for query in queries {
                prop_assert_eq!(htree_find_leaf_idx(&forward, query), htree_find_leaf_idx(&reversed, query));
                prop_assert_eq!(htree_find_leaf(&forward, query), htree_find_leaf(&reversed, query));
            }
        }

        // Metamorphic relation: swap_inode_in_entry is involutive — swapping
        // to a new inode and back to the original must restore the block
        // bytes exactly. The corresponding rename/unlink/link sequence the
        // VFS issues relies on this round-trip; a regression that altered
        // any other byte of the entry header would silently corrupt the
        // d_type tag or the rec_len chain.
        #[test]
        fn proptest_swap_inode_in_entry_is_involutive(
            ino_orig in 3_u32..=u32::MAX,
            ino_new in 3_u32..=u32::MAX,
            reserved_tail in prop_oneof![Just(0_usize), Just(12_usize), Just(24_usize)],
            name in valid_dir_name_strategy(255),
        ) {
            prop_assume!(ino_orig != ino_new);

            let mut block = vec![0u8; 4096];
            init_dir_block(&mut block, 2, 2, reserved_tail).unwrap();
            add_entry(&mut block, ino_orig, &name, Ext4FileType::RegFile, reserved_tail)
                .unwrap();

            let baseline = block.clone();

            let swapped_once = swap_inode_in_entry(&mut block, &name, ino_new, reserved_tail)
                .unwrap();
            prop_assert!(swapped_once, "first swap must report the entry as live");
            prop_assert_ne!(block.as_slice(), baseline.as_slice(),
                "swap to a different inode must change at least the inode bytes");

            let swapped_back =
                swap_inode_in_entry(&mut block, &name, ino_orig, reserved_tail).unwrap();
            prop_assert!(swapped_back, "second swap must report the entry as live");
            prop_assert_eq!(
                block.as_slice(),
                baseline.as_slice(),
                "swap-then-swap-back must restore the block byte-for-byte"
            );
        }
    }

    #[test]
    fn required_rec_len_rounds_up_to_four_byte_alignment() {
        // DIR_ENTRY_HEADER_LEN is 8; required_rec_len = align4(8 + name_len).
        assert_eq!(required_rec_len(1), 12);
        assert_eq!(required_rec_len(3), 12);
        assert_eq!(required_rec_len(4), 12);
        assert_eq!(required_rec_len(5), 16);
        assert_eq!(required_rec_len(8), 16);
        // Invariant: always a multiple of 4 and large enough for header + name.
        for name_len in 0..=255usize {
            let r = required_rec_len(name_len);
            assert_eq!(
                r % 4,
                0,
                "rec_len must be 4-byte aligned (name_len {name_len})"
            );
            assert!(
                r >= DIR_ENTRY_HEADER_LEN + name_len,
                "rec_len must fit header + name (name_len {name_len})"
            );
        }
    }

    #[test]
    fn init_dir_block_contains_dot_and_dotdot() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 11, 2, 0).unwrap();
        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
        assert!(tail.is_none());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b".".to_vec());
        assert_eq!(entries[0].inode, 11);
        assert_eq!(entries[1].name, b"..".to_vec());
        assert_eq!(entries[1].inode, 2);
    }

    #[test]
    fn init_dir_block_with_tail() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 11, 2, 12).unwrap();
        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries[1].rec_len, 1024 - 12 - 12);
        assert!(tail.is_some());
    }

    #[test]
    fn representative_dir_block_mutation_exact_golden_contract() {
        assert_eq!(
            representative_dir_block_golden_contract_actual(),
            REPRESENTATIVE_DIR_BLOCK_GOLDEN
        );
    }

    #[test]
    fn add_entry_rejects_invalid_rec_len() {
        // A block whose first entry has rec_len 0 — without the guard the
        // iterator would never advance (infinite loop).
        let mut block = vec![0_u8; 64];
        block[0..4].copy_from_slice(&11_u32.to_le_bytes()); // inode
        block[4..6].copy_from_slice(&0_u16.to_le_bytes()); // rec_len = 0
        block[6] = 1; // name_len
        block[7] = 2; // file_type
        block[8] = b'.';
        let err = add_entry(&mut block, 42, b"x", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }), "got {err:?}");

        // A misaligned rec_len (10, not a multiple of 4) is also rejected.
        let mut block2 = vec![0_u8; 64];
        block2[0..4].copy_from_slice(&11_u32.to_le_bytes());
        block2[4..6].copy_from_slice(&10_u16.to_le_bytes()); // rec_len = 10
        block2[6] = 1;
        block2[7] = 2;
        block2[8] = b'.';
        let err2 = add_entry(&mut block2, 42, b"x", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err2, FfsError::Corruption { .. }), "got {err2:?}");
    }

    #[test]
    fn retarget_entry_rejects_invalid_rec_len() {
        // A block whose first entry has rec_len 0 (the infinite-loop hazard) is
        // rejected by the rename/swap path's iteration guard.
        let mut block = vec![0_u8; 64];
        block[0..4].copy_from_slice(&11_u32.to_le_bytes()); // inode
        block[4..6].copy_from_slice(&0_u16.to_le_bytes()); // rec_len = 0
        block[6] = 1; // name_len
        block[7] = 2; // file_type
        block[8] = b'.';
        let err = retarget_entry(&mut block, b"x", 42, Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }), "got {err:?}");
    }

    #[test]
    fn add_entry_splits_live_slot_slack() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 2, 1024, Ext4FileType::Dir, b".").unwrap();
        let off = add_entry(&mut block, 33, b"hello", Ext4FileType::RegFile, 0).unwrap();
        assert_eq!(off, 12);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b".".to_vec());
        assert_eq!(entries[1].name, b"hello".to_vec());
        assert_eq!(entries[1].inode, 33);
    }

    #[test]
    fn add_entry_reuses_deleted_slot() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 2, 12, Ext4FileType::Dir, b".").unwrap();
        write_entry(&mut block, 12, 0, 1012, Ext4FileType::Unknown, b"x").unwrap();
        let off = add_entry(&mut block, 44, b"new", Ext4FileType::RegFile, 0).unwrap();
        assert_eq!(off, 12);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].inode, 44);
        assert_eq!(entries[1].name, b"new".to_vec());
    }

    #[test]
    fn retarget_entry_updates_inode_and_file_type_without_moving_slot() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 33, 1024, Ext4FileType::RegFile, b"node").unwrap();

        assert!(
            retarget_entry(&mut block, b"node", 44, Ext4FileType::Dir, 0).expect("retarget entry")
        );

        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].inode, 44);
        assert_eq!(entries[0].rec_len, 1024);
        assert_eq!(entries[0].name, b"node".to_vec());
        assert_eq!(entries[0].file_type, Ext4FileType::Dir);
    }

    #[test]
    fn add_entry_no_space_returns_enospc() {
        let mut block = vec![0u8; 24];
        write_entry(&mut block, 0, 1, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 2, 12, Ext4FileType::RegFile, b"b").unwrap();
        let err = add_entry(&mut block, 3, b"c", Ext4FileType::RegFile, 0).unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOSPC);
    }

    #[test]
    fn add_entry_reject_existing_rejects_duplicate_live_name() {
        // A live "a" exists with slack; add_entry would happily split that slack
        // and insert a SECOND "a" (directory corruption). The reject variant must
        // refuse with EEXIST instead, while still allowing a distinct name.
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 10, 1024, Ext4FileType::RegFile, b"a").unwrap();

        let err =
            add_entry_reject_existing(&mut block, 11, b"a", Ext4FileType::RegFile, 0).unwrap_err();
        assert_eq!(err.to_errno(), libc::EEXIST);

        // A different name still inserts (folds the EEXIST check into the scan).
        let off =
            add_entry_reject_existing(&mut block, 12, b"b", Ext4FileType::RegFile, 0).unwrap();
        assert!(off > 0);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.name == b"a" && e.inode == 10));
        assert!(entries.iter().any(|e| e.name == b"b" && e.inode == 12));
    }

    #[test]
    fn add_entry_reject_existing_ignores_deleted_tombstone_with_same_name() {
        // A tombstone (inode 0) carrying the same name must NOT block reuse — the
        // name is not live, so the entry should be (re)inserted successfully.
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 0, 1024, Ext4FileType::RegFile, b"a").unwrap();
        let off = add_entry_reject_existing(&mut block, 7, b"a", Ext4FileType::RegFile, 0).unwrap();
        assert_eq!(off, 0);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert!(entries.iter().any(|e| e.name == b"a" && e.inode == 7));
    }

    #[test]
    fn remove_entry_coalesces_prev_rec_len() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 10, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 11, 12, Ext4FileType::RegFile, b"b").unwrap();
        write_entry(&mut block, 24, 12, 1000, Ext4FileType::RegFile, b"c").unwrap();

        let removed = remove_entry(&mut block, b"b", 0).unwrap();
        assert!(removed);
        let merged = read_u16_le(&block, 4).unwrap();
        assert_eq!(merged, 24);
    }

    #[test]
    fn remove_entry_coalesces_into_previous_live_entry_after_deleted_slot() {
        // Layout: [a(live)][x(deleted)][b(live)][c(live)]
        // Removing "b" should coalesce "a" through the deleted "x" and removed "b",
        // giving "a" a rec_len that spans from offset 0 to offset 36 (where "c" starts).
        let mut block = vec![0u8; 64];
        write_entry(&mut block, 0, 10, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 0, 12, Ext4FileType::Unknown, b"x").unwrap();
        write_entry(&mut block, 24, 11, 12, Ext4FileType::RegFile, b"b").unwrap();
        write_entry(&mut block, 36, 12, 28, Ext4FileType::RegFile, b"c").unwrap();

        let removed = remove_entry(&mut block, b"b", 0).unwrap();
        assert!(removed);
        // "a" at offset 0 absorbs deleted "x" (12 bytes) + removed "b" (12 bytes) = 36 total.
        assert_eq!(read_u16_le(&block, 4).unwrap(), 36);
        // "b" at offset 24 has inode zeroed.
        assert_eq!(read_u32_le(&block, 24).unwrap(), 0);
        // "c" at offset 36 is untouched.
        assert_eq!(read_u32_le(&block, 36).unwrap(), 12);
        assert_eq!(read_u16_le(&block, 40).unwrap(), 28);
    }

    #[test]
    fn remove_entry_skips_interior_htree_dx_node_block_bd_y8tcx() {
        // An interior htree dx_node: leading fake dirent inode=0 with rec_len
        // spanning the whole block. On a metadata_csum filesystem the removal
        // scan reaches such a block when it precedes the target leaf; it holds
        // the hash index, not entries, so remove_entry must report Ok(false)
        // (not present here) rather than rejecting it as corrupt. Before the fix
        // this returned Err(Corruption) for reserved_tail > 0 because the fake
        // dirent's rec_len (block_size) exceeds the usable area (block_size-12).
        let bs = 4096_usize;
        let mut node = make_interior_htree_dx_node_block(bs);
        // metadata_csum dir (reserved_tail = 12): must be skipped, not rejected.
        assert!(
            !remove_entry(&mut node, b"victim.txt", 12).unwrap(),
            "dx_node must be reported as not-present on metadata_csum"
        );
        // Non-csum (reserved_tail = 0) must behave identically.
        let mut node2 = make_interior_htree_dx_node_block(bs);
        assert!(!remove_entry(&mut node2, b"victim.txt", 0).unwrap());
    }

    #[test]
    fn retarget_entry_skips_interior_htree_dx_node_block_bd_xmh5g_347() {
        let bs = 4096_usize;
        let mut node = make_interior_htree_dx_node_block(bs);
        let before = node.clone();

        assert!(
            !retarget_entry(&mut node, b"victim.txt", 42, Ext4FileType::RegFile, 12).unwrap(),
            "metadata-csum dx_node must be reported as not-present, not corrupt"
        );
        assert_eq!(node, before, "skipping a dx_node must not mutate it");

        let mut node2 = make_interior_htree_dx_node_block(bs);
        assert!(!swap_inode_in_entry(&mut node2, b"victim.txt", 42, 0).unwrap());
    }

    #[test]
    fn add_entry_skips_interior_htree_dx_node_block_bd_dir_add_skips_dx_node() {
        let bs = 4096_usize;
        let mut node = make_interior_htree_dx_node_block(bs);
        let before = node.clone();

        let err = add_entry(&mut node, 42, b"new", Ext4FileType::RegFile, 12).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace), "got {err:?}");
        assert_eq!(node, before, "metadata-csum dx_node must not be mutated");

        let mut node2 = make_interior_htree_dx_node_block(bs);
        let before2 = node2.clone();
        let err = add_entry(&mut node2, 42, b"new", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace), "got {err:?}");
        assert_eq!(
            node2, before2,
            "non-csum dx_node must not be reused as a deleted slot"
        );
    }

    #[test]
    fn remove_first_entry_marks_deleted() {
        let mut block = vec![0u8; 128];
        write_entry(&mut block, 0, 10, 128, Ext4FileType::RegFile, b"a").unwrap();
        let removed = remove_entry(&mut block, b"a", 0).unwrap();
        assert!(removed);
        assert_eq!(read_u32_le(&block, 0).unwrap(), 0);
    }

    #[test]
    fn remove_entry_last_entry_extends_previous_to_block_end() {
        let mut block = vec![0u8; 64];
        write_entry(&mut block, 0, 10, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 11, 52, Ext4FileType::RegFile, b"b").unwrap();

        assert!(remove_entry(&mut block, b"b", 0).unwrap());
        assert_eq!(read_u16_le(&block, 4).unwrap(), 64);
    }

    #[test]
    fn htree_insert_preserves_sorted_hash_order() {
        let mut entries = Vec::new();
        htree_insert(&mut entries, 0x2000, 2);
        htree_insert(&mut entries, 0x1000, 1);
        htree_insert(&mut entries, 0x5000, 5);
        htree_insert(&mut entries, 0x3000, 3);
        let hashes: Vec<u32> = entries.iter().map(|e| e.hash).collect();
        assert_eq!(hashes, vec![0x1000, 0x2000, 0x3000, 0x5000]);
    }

    #[test]
    fn htree_find_leaf_uses_rightmost_lte() {
        let entries = vec![
            HtreeEntry {
                hash: 0x0000,
                block: 1,
            },
            HtreeEntry {
                hash: 0x1000,
                block: 2,
            },
            HtreeEntry {
                hash: 0x8000,
                block: 3,
            },
        ];
        assert_eq!(htree_find_leaf(&entries, 0x0500), Some(1));
        assert_eq!(htree_find_leaf(&entries, 0x1000), Some(2));
        assert_eq!(htree_find_leaf(&entries, 0xFFFF), Some(3));
        assert_eq!(htree_find_leaf(&[], 0xFFFF), None);
    }

    #[test]
    fn htree_remove_specific_entry() {
        let mut entries = vec![
            HtreeEntry {
                hash: 0x1000,
                block: 2,
            },
            HtreeEntry {
                hash: 0x1000,
                block: 8,
            },
        ];
        assert!(htree_remove(&mut entries, 0x1000, 8));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].block, 2);
        assert!(!htree_remove(&mut entries, 0x1000, 8));
    }

    #[test]
    fn compute_dx_hash_is_deterministic() {
        let seed = [1, 2, 3, 4];
        let h1 = compute_dx_hash(1, b"hello", &seed);
        let h2 = compute_dx_hash(1, b"hello", &seed);
        let h3 = compute_dx_hash(1, b"world", &seed);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn add_entry_rejects_zero_inode() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 1, 1024, Ext4FileType::Dir, b".").unwrap();
        let err = add_entry(&mut block, 0, b"bad", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn add_entry_rejects_empty_name() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 1, 1024, Ext4FileType::Dir, b".").unwrap();
        let err = add_entry(&mut block, 10, b"", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(
            matches!(err, FfsError::Format(ref m) if m.contains("cannot be empty")),
            "got {err:?}",
        );
    }

    #[test]
    fn add_entry_rejects_invalid_reserved_tail() {
        let mut block = vec![0u8; 4096];
        write_entry(&mut block, 0, 1, 4096, Ext4FileType::Dir, b".").unwrap();

        // A nonzero reserved_tail below 12 bytes is rejected.
        let err = add_entry(&mut block, 10, b"x", Ext4FileType::RegFile, 8).unwrap_err();
        assert!(
            matches!(err, FfsError::Format(ref m) if m.contains("at least 12 bytes")),
            "got {err:?}",
        );

        // A reserved_tail >= 12 but not 4-byte aligned is rejected.
        let err = add_entry(&mut block, 10, b"x", Ext4FileType::RegFile, 13).unwrap_err();
        assert!(
            matches!(err, FfsError::Format(ref m) if m.contains("4-byte aligned")),
            "got {err:?}",
        );

        // A reserved_tail exceeding the block length is rejected.
        let err = add_entry(&mut block, 10, b"x", Ext4FileType::RegFile, 5000).unwrap_err();
        assert!(
            matches!(err, FfsError::Format(ref m) if m.contains("exceeds block length")),
            "got {err:?}",
        );
    }

    #[test]
    fn remove_nonexistent_entry_returns_false() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 10, 1024, Ext4FileType::RegFile, b"a").unwrap();
        let removed = remove_entry(&mut block, b"nonexistent", 0).unwrap();
        assert!(!removed);
    }

    #[test]
    fn init_dir_block_too_small_fails() {
        let mut block = vec![0u8; 16]; // Too small for . and ..
        let err = init_dir_block(&mut block, 1, 2, 0).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn init_dir_block_rejects_zero_dot_inodes_without_mutation() {
        for (self_ino, parent_ino) in [(0, 2), (2, 0)] {
            let mut block = vec![0xA5; 1024];
            let before = block.clone();

            let err = init_dir_block(&mut block, self_ino, parent_ino, 0).unwrap_err();

            assert!(matches!(err, FfsError::Format(_)));
            assert_eq!(block, before);
        }
    }

    #[test]
    fn init_dir_block_rejects_invalid_reserved_tail_geometry_without_mutation() {
        for reserved_tail in [1_usize, 8, 13, 128] {
            let mut block = vec![0xA5; 64];
            let before = block.clone();

            let err = init_dir_block(&mut block, 1, 2, reserved_tail).unwrap_err();

            assert!(matches!(err, FfsError::Format(_)));
            assert_eq!(block, before);
        }
    }

    #[test]
    fn mutation_paths_reject_invalid_reserved_tail_geometry_without_mutation() {
        let mut block = vec![0u8; 128];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        let before_add = block.clone();
        let err = add_entry(&mut block, 10, b"new", Ext4FileType::RegFile, 8).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(block, before_add);

        let before_remove = block.clone();
        let err = remove_entry(&mut block, b".", 13).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(block, before_remove);

        let before_retarget = block.clone();
        let err = retarget_entry(&mut block, b".", 3, Ext4FileType::Dir, 256).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(block, before_retarget);
    }

    #[test]
    fn add_entry_after_remove_reclaims_space() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        // Add, then remove, then add again to same slot.
        add_entry(&mut block, 100, b"temp", Ext4FileType::RegFile, 0).unwrap();
        remove_entry(&mut block, b"temp", 0).unwrap();
        add_entry(&mut block, 200, b"repl", Ext4FileType::RegFile, 0).unwrap();

        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert!(entries.iter().any(|e| e.inode == 200 && e.name == b"repl"));
        assert!(!entries.iter().any(|e| e.name == b"temp"));
    }

    #[test]
    fn add_entry_detects_corrupt_rec_len_zero() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap(); // inode
        write_u16_le(&mut block, 4, 0).unwrap(); // rec_len = 0 (invalid)
        block[6] = 1; // name_len
        block[7] = 1; // file_type
        block[8] = b'a'; // name

        let err = add_entry(&mut block, 20, b"new", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn add_entry_detects_name_len_exceeding_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 12).unwrap(); // rec_len = 12
        block[6] = 100; // name_len = 100 (exceeds rec_len - 8 = 4)
        block[7] = 1;
        block[8] = b'a';
        write_u32_le(&mut block, 12, 0).unwrap();
        write_u16_le(&mut block, 16, 116).unwrap();

        let err = add_entry(&mut block, 20, b"new", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn remove_entry_detects_name_exceeding_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 12).unwrap(); // rec_len = 12
        block[6] = 50; // name_len = 50 (exceeds rec_len - 8 = 4)
        block[7] = 1;
        block[8] = b'x';
        write_u32_le(&mut block, 12, 0).unwrap();
        write_u16_le(&mut block, 16, 116).unwrap();

        let err = remove_entry(&mut block, b"x", 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn add_entry_all_zero_block_is_rejected_as_corruption() {
        let mut block = vec![0u8; 128];
        let err = add_entry(&mut block, 10, b"new", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn remove_entry_detects_zero_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 0).unwrap();
        block[6] = 1;
        block[7] = Ext4FileType::RegFile as u8;
        block[8] = b'a';

        let err = remove_entry(&mut block, b"a", 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn remove_entry_detects_misaligned_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 13).unwrap();
        block[6] = 1;
        block[7] = Ext4FileType::RegFile as u8;
        block[8] = b'a';

        let err = remove_entry(&mut block, b"a", 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn remove_entry_detects_rec_len_exceeds_block() {
        let mut block = vec![0u8; 32];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 64).unwrap();
        block[6] = 1;
        block[7] = Ext4FileType::RegFile as u8;
        block[8] = b'a';

        let err = remove_entry(&mut block, b"a", 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn test_remove_entry_overlap_bug() {
        let mut block = vec![0u8; 256];
        write_entry(&mut block, 0, 10, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 0, 12, Ext4FileType::Unknown, b"x").unwrap();
        write_entry(&mut block, 24, 11, 100, Ext4FileType::RegFile, b"b").unwrap();
        write_entry(&mut block, 124, 12, 132, Ext4FileType::RegFile, b"c").unwrap();

        let removed = remove_entry(&mut block, b"b", 0).unwrap();
        assert!(removed);

        let _rec_len_0 = read_u16_le(&block, 4).unwrap();

        let (entries, _) = ffs_ondisk::parse_dir_block(&block, 256).unwrap();
        assert_eq!(entries.len(), 2, "Expected 2 entries left (a and c)");
        assert_eq!(entries[0].name, b"a".to_vec());
        assert_eq!(entries[1].name, b"c".to_vec());
    }

    // ── reserved_tail tests ─────────────────────────────────────────────

    #[test]
    fn add_entry_with_reserved_tail_12() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 2, 2, 12).unwrap();
        add_entry(&mut block, 100, b"file.txt", Ext4FileType::RegFile, 12).unwrap();
        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
        assert!(tail.is_some());
        assert!(
            entries
                .iter()
                .any(|e| e.name == b"file.txt" && e.inode == 100)
        );
    }

    #[test]
    fn remove_entry_with_reserved_tail() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 2, 2, 12).unwrap();
        add_entry(&mut block, 100, b"temp", Ext4FileType::RegFile, 12).unwrap();
        let removed = remove_entry(&mut block, b"temp", 12).unwrap();
        assert!(removed);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert!(!entries.iter().any(|e| e.name == b"temp"));
    }

    #[test]
    fn add_entry_respects_reserved_tail_capacity() {
        // 1024-byte block, init with reserved_tail=12, then try to add when
        // reserved_tail leaves no room beyond existing entries
        let mut block = vec![0u8; 36];
        init_dir_block(&mut block, 2, 2, 12).unwrap();
        // Usable area is 36 - 12 = 24 bytes, entirely consumed by . and ..
        let err = add_entry(&mut block, 10, b"x", Ext4FileType::RegFile, 12).unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOSPC);
    }

    // ── name length edge cases ──────────────────────────────────────────

    #[test]
    fn add_entry_max_name_length_255() {
        let mut block = vec![0u8; 4096];
        write_entry(&mut block, 0, 1, 4096, Ext4FileType::Dir, b".").unwrap();
        let long_name = vec![b'a'; 255];
        let off = add_entry(&mut block, 99, &long_name, Ext4FileType::RegFile, 0).unwrap();
        assert!(off > 0);
        let (entries, _) = parse_dir_block(&block, 4096).unwrap();
        assert!(entries.iter().any(|e| e.name.len() == 255 && e.inode == 99));
    }

    #[test]
    fn add_entry_rejects_name_over_255() {
        let mut block = vec![0u8; 4096];
        write_entry(&mut block, 0, 1, 4096, Ext4FileType::Dir, b".").unwrap();
        let too_long = vec![b'a'; 256];
        let err = add_entry(&mut block, 10, &too_long, Ext4FileType::RegFile, 0).unwrap_err();
        assert!(
            matches!(err, FfsError::Format(ref m) if m.contains("exceeds 255 bytes")),
            "got {err:?}",
        );
    }

    #[test]
    fn add_entry_rejects_path_separator_and_nul_names() {
        let mut block = vec![0u8; 4096];
        write_entry(&mut block, 0, 1, 4096, Ext4FileType::Dir, b".").unwrap();

        let slash_err =
            add_entry(&mut block, 10, b"bad/name", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(
            matches!(slash_err, FfsError::Format(ref m) if m.contains("cannot contain '/'")),
            "got {slash_err:?}",
        );

        let nul_err =
            add_entry(&mut block, 10, b"bad\0name", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(
            matches!(nul_err, FfsError::Format(ref m) if m.contains("cannot contain NUL")),
            "got {nul_err:?}",
        );
    }

    #[test]
    fn add_entry_single_byte_name() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 1, 1024, Ext4FileType::Dir, b".").unwrap();
        let off = add_entry(&mut block, 50, b"x", Ext4FileType::RegFile, 0).unwrap();
        assert!(off > 0);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries[1].name, b"x".to_vec());
    }

    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_1, 1);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_2, 2);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_3, 3);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_4, 4);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_5, 5);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_8, 8);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_12, 12);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_16, 16);

    #[test]
    fn add_entry_reuses_deleted_slot_exact_fit() {
        let mut block = vec![0u8; 36];
        write_entry(&mut block, 0, 1, 12, Ext4FileType::Dir, b".").unwrap();
        write_entry(&mut block, 12, 0, 12, Ext4FileType::Unknown, b"x").unwrap();
        write_entry(&mut block, 24, 2, 12, Ext4FileType::Dir, b"..").unwrap();

        let off = add_entry(&mut block, 77, b"z", Ext4FileType::RegFile, 0).unwrap();

        assert_eq!(off, 12);
        assert_eq!(usize::from(read_u16_le(&block, 16).unwrap()), 12);
        let (entries, _) = parse_dir_block(&block, 36).unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.inode == 77 && entry.name == b"z")
        );
    }

    #[test]
    fn add_entry_exact_capacity_with_reserved_tail_succeeds() {
        let mut block = vec![0u8; 48];
        init_dir_block(&mut block, 2, 2, 12).unwrap();

        let off = add_entry(&mut block, 55, b"x", Ext4FileType::RegFile, 12).unwrap();

        assert_eq!(off, 24);
        let (entries, tail) = parse_dir_block(&block, 48).unwrap();
        assert!(tail.is_some());
        assert!(
            entries
                .iter()
                .any(|entry| entry.inode == 55 && entry.name == b"x")
        );
    }

    // ── htree edge cases ────────────────────────────────────────────────

    #[test]
    fn htree_insert_duplicate_hashes() {
        let mut entries = Vec::new();
        htree_insert(&mut entries, 0x5000, 1);
        htree_insert(&mut entries, 0x5000, 2);
        htree_insert(&mut entries, 0x5000, 3);
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e.hash == 0x5000));
    }

    #[test]
    fn htree_find_leaf_single_entry() {
        let entries = vec![HtreeEntry {
            hash: 0x1000,
            block: 5,
        }];
        // With a single entry, partition_point fallback returns index 0 for any target
        assert_eq!(htree_find_leaf(&entries, 0x0), Some(5));
        assert_eq!(htree_find_leaf(&entries, 0x1000), Some(5));
        assert_eq!(htree_find_leaf(&entries, 0xFFFF_FFFF), Some(5));
    }

    #[test]
    fn htree_find_leaf_zero_hash() {
        let entries = vec![
            HtreeEntry { hash: 0, block: 1 },
            HtreeEntry {
                hash: 0x8000,
                block: 2,
            },
        ];
        assert_eq!(htree_find_leaf(&entries, 0), Some(1));
        assert_eq!(htree_find_leaf(&entries, 0x7FFF), Some(1));
        assert_eq!(htree_find_leaf(&entries, 0x8000), Some(2));
    }

    #[test]
    fn htree_find_leaf_u32_max_hash() {
        let entries = vec![
            HtreeEntry { hash: 0, block: 1 },
            HtreeEntry {
                hash: u32::MAX,
                block: 2,
            },
        ];
        assert_eq!(htree_find_leaf(&entries, u32::MAX), Some(2));
        assert_eq!(htree_find_leaf(&entries, u32::MAX - 1), Some(1));
    }

    #[test]
    fn htree_remove_from_empty() {
        let mut entries = Vec::new();
        assert!(!htree_remove(&mut entries, 0x1000, 1));
    }

    #[test]
    fn htree_remove_wrong_block_same_hash() {
        let mut entries = vec![HtreeEntry {
            hash: 0x1000,
            block: 5,
        }];
        assert!(!htree_remove(&mut entries, 0x1000, 99));
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn htree_insert_into_empty() {
        let mut entries = Vec::new();
        let idx = htree_insert(&mut entries, 42, 7);
        assert_eq!(idx, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], HtreeEntry { hash: 42, block: 7 });
    }

    // ── compute_dx_hash edge cases ──────────────────────────────────────

    #[test]
    fn compute_dx_hash_different_seeds_differ() {
        let h1 = compute_dx_hash(1, b"test", &[0, 0, 0, 0]);
        let h2 = compute_dx_hash(1, b"test", &[1, 2, 3, 4]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_dx_hash_long_name() {
        let seed = [1, 2, 3, 4];
        let long_name = vec![b'z'; 255];
        let h1 = compute_dx_hash(1, &long_name, &seed);
        // Deterministic: same input produces same output
        let h2 = compute_dx_hash(1, &long_name, &seed);
        assert_eq!(h1, h2, "hash of max-length name must be deterministic");
        // Different from shorter name
        let short_name = vec![b'z'; 10];
        let h3 = compute_dx_hash(1, &short_name, &seed);
        assert_ne!(
            h1, h3,
            "hash should differ between 255-byte and 10-byte names"
        );
    }

    #[test]
    fn compute_dx_hash_single_byte_name() {
        let seed = [1, 2, 3, 4];
        let h = compute_dx_hash(1, b"a", &seed);
        let h2 = compute_dx_hash(1, b"b", &seed);
        assert_ne!(h, h2);
    }

    // ── block size variations ───────────────────────────────────────────

    #[test]
    fn init_dir_block_4096() {
        let mut block = vec![0u8; 4096];
        init_dir_block(&mut block, 2, 2, 0).unwrap();
        let (entries, _) = parse_dir_block(&block, 4096).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b".".to_vec());
        assert_eq!(entries[1].name, b"..".to_vec());
    }

    #[test]
    fn init_dir_block_minimum_viable_size() {
        // Minimum: . needs 12 bytes, .. needs 12 bytes = 24 total
        let mut block = vec![0u8; 24];
        init_dir_block(&mut block, 5, 3, 0).unwrap();
        let (entries, _) = parse_dir_block(&block, 24).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn init_dir_block_reserved_tail_equal_to_block_minus_minimum_entries() {
        let mut block = vec![0u8; 64];
        init_dir_block(&mut block, 7, 9, 40).unwrap();

        let (entries, tail) = parse_dir_block(&block, 64).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].rec_len, 12);
        assert!(tail.is_some());
    }

    // ── multiple operations ─────────────────────────────────────────────

    #[test]
    fn fill_block_then_enospc() {
        let mut block = vec![0u8; 128];
        init_dir_block(&mut block, 2, 2, 0).unwrap();
        // Fill up with entries
        let mut count = 0;
        for i in 3..100_u32 {
            let name = format!("f{i}");
            match add_entry(&mut block, i, name.as_bytes(), Ext4FileType::RegFile, 0) {
                Ok(_) => count += 1,
                Err(_) => break,
            }
        }
        assert!(count > 0, "should fit at least one entry");
        // Next add should fail
        let err = add_entry(&mut block, 999, b"overflow", Ext4FileType::RegFile, 0);
        assert!(err.is_err());
    }

    #[test]
    fn fill_4096_block_parses_every_inserted_entry() {
        let mut block = vec![0u8; 4096];
        let mut inserted = BTreeSet::new();
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        for ino in 3..512_u32 {
            let name = format!("bulk{ino:03}");
            match add_entry(&mut block, ino, name.as_bytes(), Ext4FileType::RegFile, 0) {
                Ok(_) => {
                    inserted.insert(name.into_bytes());
                }
                Err(err) => {
                    assert!(
                        matches!(err, FfsError::NoSpace),
                        "unexpected add_entry failure: {err:?}"
                    );
                    break;
                }
            }
        }

        let live_names = live_name_set(&block);
        assert!(live_names.contains(b".".as_slice()));
        assert!(live_names.contains(b"..".as_slice()));
        for name in inserted {
            assert!(
                live_names.contains(&name),
                "missing inserted entry {name:?}"
            );
        }
    }

    #[test]
    fn add_remove_add_cycle_multiple() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        for i in 0..5_u32 {
            let name = format!("cycle{i}");
            add_entry(
                &mut block,
                100 + i,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
            remove_entry(&mut block, name.as_bytes(), 0).unwrap();
        }

        // After all cycles, only . and .. should remain (as live entries)
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.iter().filter(|e| e.inode != 0).count(), 2);
    }

    #[test]
    fn remove_every_other_then_add() {
        let mut block = vec![0u8; 4096];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        // Add 10 entries
        for i in 0..10_u32 {
            let name = format!("entry{i:02}");
            add_entry(
                &mut block,
                100 + i,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
        }

        // Remove odd-indexed entries
        for i in (1..10_u32).step_by(2) {
            let name = format!("entry{i:02}");
            remove_entry(&mut block, name.as_bytes(), 0).unwrap();
        }

        // Re-add to reclaimed slots
        for i in 0..5_u32 {
            let name = format!("new{i:02}");
            add_entry(
                &mut block,
                200 + i,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
        }

        let (entries, _) = parse_dir_block(&block, 4096).unwrap();
        // . + .. + 5 even originals + 5 new = 12
        assert_eq!(entries.iter().filter(|e| e.inode != 0).count(), 12);
    }

    #[test]
    fn add_100_remove_50_add_50_preserves_expected_live_set() {
        let mut block = vec![0u8; 8192];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        for ino in 0..100_u32 {
            let name = format!("seed{ino:03}");
            add_entry(
                &mut block,
                1_000 + ino,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
        }

        for ino in 0..50_u32 {
            let name = format!("seed{ino:03}");
            assert!(remove_entry(&mut block, name.as_bytes(), 0).unwrap());
        }

        for ino in 0..50_u32 {
            let name = format!("fresh{ino:03}");
            add_entry(
                &mut block,
                2_000 + ino,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
        }

        let live_names = live_name_set(&block);
        assert_eq!(live_names.len(), 102);
        assert!(live_names.contains(b".".as_slice()));
        assert!(live_names.contains(b"..".as_slice()));
        for ino in 0..50_u32 {
            assert!(!live_names.contains(format!("seed{ino:03}").as_bytes()));
        }
        for ino in 50..100_u32 {
            assert!(live_names.contains(format!("seed{ino:03}").as_bytes()));
        }
        for ino in 0..50_u32 {
            assert!(live_names.contains(format!("fresh{ino:03}").as_bytes()));
        }
    }

    // ── corruption detection ────────────────────────────────────────────

    #[test]
    fn add_entry_detects_misaligned_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap(); // inode
        write_u16_le(&mut block, 4, 13).unwrap(); // rec_len = 13 (not 4-aligned)
        block[6] = 1;
        block[7] = 1;
        block[8] = b'a';

        let err = add_entry(&mut block, 20, b"new", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn add_entry_detects_rec_len_exceeds_block() {
        let mut block = vec![0u8; 32];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 64).unwrap(); // rec_len > block size
        block[6] = 1;
        block[7] = 1;
        block[8] = b'a';

        let err = add_entry(&mut block, 20, b"x", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    // ── init_dir_block edge cases ───────────────────────────────────────

    #[test]
    fn init_dir_block_reserved_tail_zero() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 5, 3, 0).unwrap();
        let (_, tail) = parse_dir_block(&block, 1024).unwrap();
        assert!(tail.is_none());
    }

    #[test]
    fn init_dir_block_large_reserved_tail() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 5, 3, 24).unwrap();
        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(tail.is_some());
    }

    #[test]
    fn init_dir_block_preserves_inode_numbers() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 0xFFFF_FFFE, 0xFFFF_FFFF, 0).unwrap();
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries[0].inode, 0xFFFF_FFFE);
        assert_eq!(entries[1].inode, 0xFFFF_FFFF);
    }

    // ── file type preservation ──────────────────────────────────────────

    #[test]
    fn add_entry_preserves_file_types() {
        let types = [
            (Ext4FileType::RegFile, b"file" as &[u8]),
            (Ext4FileType::Dir, b"dir"),
            (Ext4FileType::Symlink, b"link"),
            (Ext4FileType::Chrdev, b"cdev"),
            (Ext4FileType::Blkdev, b"bdev"),
            (Ext4FileType::Fifo, b"fifo"),
            (Ext4FileType::Sock, b"sock"),
        ];
        let mut block = vec![0u8; 4096];
        write_entry(&mut block, 0, 1, 4096, Ext4FileType::Dir, b".").unwrap();

        for (i, (ft, name)) in types.iter().enumerate() {
            add_entry(&mut block, u32::try_from(i + 10).unwrap(), name, *ft, 0).unwrap();
        }

        let (entries, _) = parse_dir_block(&block, 4096).unwrap();
        assert!(entries.len() >= 8);
        for (ft, name) in &types {
            let entry = entries.iter().find(|e| e.name == *name).unwrap();
            assert_eq!(entry.file_type, *ft);
        }
    }

    // ── HtreeEntry derive trait coverage ────────────────────────────────

    #[test]
    fn htree_find_leaf_handles_collisions_correctly() {
        let entries = vec![
            HtreeEntry { hash: 0, block: 1 },
            HtreeEntry {
                hash: 100,
                block: 2,
            },
            HtreeEntry {
                hash: 101,
                block: 3,
            }, // 101 means 100 | 1 (collision bit)
            HtreeEntry {
                hash: 200,
                block: 4,
            },
        ];
        // Looking for hash 100.
        let mut idx = htree_find_leaf_idx(&entries, 100);
        assert_eq!(idx, 1);
        assert_eq!(entries[idx].block, 2);

        // Simulate not found in block 2, check next
        idx += 1;
        assert!(idx < entries.len());
        // Hash 101 has bit 1 set, meaning it's a collision continuation of 100.
        assert_eq!(entries[idx].hash & 1, 1);
        assert_eq!(entries[idx].hash & !1, 100);
        assert_eq!(entries[idx].block, 3);
    }

    proptest! {
        /// Removing an entry then updating the metadata_csum tail *incrementally*
        /// from the [`DirBlockEdit`] must yield a byte-identical block to a full
        /// checksum recompute — for any dir layout, removed entry (with or
        /// without a live predecessor to coalesce into), seed/ino/generation.
        #[test]
        fn remove_tracked_incremental_matches_full_stamp(
            seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
            names in proptest::collection::btree_set(valid_dir_name_strategy(16), 1..12),
            victim_idx in any::<prop::sample::Index>(),
        ) {
            let block_len = 512_usize;
            let reserved_tail = 12_usize;
            let mut block = vec![0_u8; block_len];
            init_dir_block(&mut block, 2, 2, reserved_tail).unwrap();

            // Insert as many names as fit; track which actually landed.
            let mut inserted: Vec<Vec<u8>> = Vec::new();
            for (i, name) in names.iter().enumerate() {
                let child_ino = u32::try_from(i + 3).unwrap();
                if add_entry(&mut block, child_ino, name, Ext4FileType::RegFile, reserved_tail).is_ok() {
                    inserted.push(name.clone());
                }
            }
            prop_assume!(!inserted.is_empty());

            // Stamp the pre-removal block fully (the on-disk starting state).
            ffs_ondisk::stamp_dir_block_checksum(&mut block, seed, ino, generation);

            let victim = victim_idx.get(&inserted);
            let (_removed_ino, edit) =
                remove_entry_take_inode_tracked(&mut block, victim, reserved_tail)
                    .unwrap()
                    .expect("victim was inserted, so it must be present");

            // Incremental tail update from the reported edit span.
            let delta = edit.delta(&block);
            let applied = ffs_ondisk::ext4::stamp_dir_block_checksum_incremental(
                &mut block,
                edit.region_start,
                &delta,
            );
            prop_assert!(applied, "incremental update should apply for an in-region edit");

            // Full recompute of the post-removal block must match byte-for-byte.
            let mut reference = block.clone();
            ffs_ondisk::stamp_dir_block_checksum(&mut reference, seed, ino, generation);
            prop_assert_eq!(block, reference);
        }

        /// Adding an entry then updating the metadata_csum tail *incrementally*
        /// from the tracked [`DirBlockEdit`] (when `Some`) must yield a
        /// byte-identical block to a full recompute — covering both the
        /// tombstone-reuse and slack-split insert cases across block fills. When
        /// the edit is `None` (span too large) the caller full-recomputes, which
        /// is trivially identical, so we assert only the `Some` path here.
        #[test]
        fn add_tracked_incremental_matches_full_stamp(
            seed in any::<u32>(),
            ino in any::<u32>(),
            generation in any::<u32>(),
            preload in proptest::collection::btree_set(valid_dir_name_strategy(16), 0..24),
            new_name in valid_dir_name_strategy(16),
            reuse_tombstone in any::<bool>(),
        ) {
            let block_len = 512_usize;
            let reserved_tail = 12_usize;
            let mut block = vec![0_u8; block_len];
            init_dir_block(&mut block, 2, 2, reserved_tail).unwrap();

            // Preload entries to vary block fill (near-empty .. near-full).
            let mut next_ino = 3_u32;
            for name in &preload {
                if *name == new_name {
                    continue;
                }
                if add_entry(&mut block, next_ino, name, Ext4FileType::RegFile, reserved_tail).is_ok() {
                    next_ino += 1;
                }
            }
            // Optionally create a leading tombstone by removing the first added
            // entry, exercising the tombstone-reuse branch.
            if reuse_tombstone
                && let Some(first) = preload.iter().find(|n| **n != new_name)
            {
                let _ = remove_entry(&mut block, first, reserved_tail);
            }

            // Stamp the pre-insert block fully (the on-disk starting state).
            ffs_ondisk::stamp_dir_block_checksum(&mut block, seed, ino, generation);

            let Ok((_off, maybe_edit)) =
                add_entry_tracked(&mut block, next_ino, &new_name, Ext4FileType::RegFile, reserved_tail)
            else {
                return Ok(()); // NoSpace: nothing to check.
            };

            if let Some(edit) = maybe_edit {
                prop_assert!(edit.old_bytes.len() <= INCREMENTAL_DIR_CSUM_MAX_SPAN);
                let delta = edit.delta(&block);
                let applied = ffs_ondisk::ext4::stamp_dir_block_checksum_incremental(
                    &mut block,
                    edit.region_start,
                    &delta,
                );
                prop_assert!(applied, "incremental update should apply for an in-region edit");

                let mut reference = block.clone();
                ffs_ondisk::stamp_dir_block_checksum(&mut reference, seed, ino, generation);
                prop_assert_eq!(block, reference);
            }
        }
    }
}
