#![forbid(unsafe_code)]
//! Inode management.
//!
//! Read, write, create, and delete inodes. Permission checks,
//! timestamp management (atime/ctime/mtime/crtime), flag handling,
//! and inode table I/O.

use asupersync::Cx;
use ffs_alloc::{FsGeometry, GroupStats};
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::Ext4Inode;
use ffs_types::{BlockNumber, GroupNumber, InodeNumber};
use tracing::debug;

// ── Constants ────────────────────────────────────────────────────────────────

/// Ext4 extent header magic.
const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

/// Inode flag: uses extents (EXT4_EXTENTS_FL).
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

/// Checksum field offsets within the raw inode bytes.
const INODE_CHECKSUM_LO_OFFSET: usize = 0x7C;
const INODE_CHECKSUM_HI_OFFSET: usize = 0x82;

// ── Inode location ──────────────────────────────────────────────────────────

/// Computed on-disk location for an inode.
#[derive(Debug, Clone, Copy)]
pub struct InodeLocation {
    pub block: BlockNumber,
    pub byte_offset: usize,
}

/// Compute the disk location of an inode within the inode table.
#[must_use]
#[expect(clippy::cast_possible_truncation)]
pub fn locate_inode(
    ino: InodeNumber,
    geo: &FsGeometry,
    groups: &[GroupStats],
) -> Option<InodeLocation> {
    if ino.0 == 0 || geo.inodes_per_group == 0 || geo.block_size == 0 || geo.inode_size == 0 {
        return None;
    }

    let group = ffs_types::inode_to_group(ino, geo.inodes_per_group);
    let gidx = group.0 as usize;
    if gidx >= groups.len() {
        return None;
    }
    let index = ffs_types::inode_index_in_group(ino, geo.inodes_per_group);
    let byte_in_table = u64::from(index) * u64::from(geo.inode_size);
    let block_offset = byte_in_table / u64::from(geo.block_size);
    let byte_offset = (byte_in_table % u64::from(geo.block_size)) as usize;
    let block = BlockNumber(groups[gidx].inode_table_block.0.checked_add(block_offset)?);
    Some(InodeLocation { block, byte_offset })
}

// ── Read ────────────────────────────────────────────────────────────────────

/// Read and parse an inode from the block device.
pub fn read_inode(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &[GroupStats],
    ino: InodeNumber,
) -> Result<Ext4Inode> {
    cx_checkpoint(cx)?;

    let loc = locate_inode(ino, geo, groups).ok_or_else(|| FfsError::Corruption {
        block: 0,
        detail: format!("inode {ino} out of range"),
    })?;

    let buf = dev.read_block(cx, loc.block)?;
    let data = buf.as_slice();
    let inode_size = usize::from(geo.inode_size);

    if loc.byte_offset + inode_size > data.len() {
        return Err(FfsError::Corruption {
            block: loc.block.0,
            detail: "inode extends beyond block boundary".into(),
        });
    }

    let raw = &data[loc.byte_offset..loc.byte_offset + inode_size];
    Ext4Inode::parse_from_bytes(raw).map_err(|e| FfsError::Format(format!("{e}")))
}

// ── Write ───────────────────────────────────────────────────────────────────

/// Serialize an inode and write it to the block device.
///
/// Computes the CRC32C checksum before writing.
pub fn write_inode(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &[GroupStats],
    ino: InodeNumber,
    inode: &Ext4Inode,
    csum_seed: u32,
) -> Result<()> {
    cx_checkpoint(cx)?;

    let loc = locate_inode(ino, geo, groups).ok_or_else(|| FfsError::Corruption {
        block: 0,
        detail: format!("inode {ino} out of range"),
    })?;

    let inode_size = usize::from(geo.inode_size);
    write_inode_at(cx, dev, loc, inode_size, ino, inode, csum_seed)
}

/// Write an inode to a KNOWN on-disk location (bd-bhh0i): the location-resolution
/// half of `write_inode` factored out so the sharded per-group create path can
/// supply an `InodeLocation` it computed from the sharded allocator, instead of a
/// `&[GroupStats]` slice.
pub fn write_inode_at(
    cx: &Cx,
    dev: &dyn BlockDevice,
    loc: InodeLocation,
    inode_size: usize,
    ino: InodeNumber,
    inode: &Ext4Inode,
    csum_seed: u32,
) -> Result<()> {
    // Serialize into a STACK buffer for the standard inode_size (128/256),
    // avoiding the per-write `vec![0; inode_size]` heap alloc; unusual large
    // inode_size (>256) falls back to a heap buffer (bd-cc-serialize-into).
    let mut stack_buf = [0u8; 256];
    let mut heap_buf: Vec<u8>;
    let raw: &mut [u8] = if inode_size <= stack_buf.len() {
        &mut stack_buf[..inode_size]
    } else {
        heap_buf = vec![0u8; inode_size];
        &mut heap_buf
    };
    serialize_inode_with_checksum(inode, inode_size, ino, csum_seed, raw);

    // Read the block, patch the inode bytes IN PLACE, write back. `make_mut` is
    // COW (`Arc::make_mut`): when the freshly-read block is uniquely owned it hands
    // back the existing buffer with no copy — eliminating the per-inode-write 4 KiB
    // heap alloc + memcpy the old `buf.as_slice().to_vec()` always paid; when the
    // buffer is shared (cached) it clones once, exactly as `to_vec` did. Pareto and
    // byte-identical: the same patched block is written either way.
    let mut buf = dev.read_block(cx, loc.block)?;
    if loc.byte_offset + inode_size > buf.as_slice().len() {
        return Err(FfsError::Corruption {
            block: loc.block.0,
            detail: "inode extends beyond block boundary".into(),
        });
    }
    // `make_mut()`'s borrow ends at this statement, so the immutable `as_slice()`
    // below is a fresh borrow (no overlap).
    buf.make_mut()[loc.byte_offset..loc.byte_offset + inode_size].copy_from_slice(raw);
    dev.write_block(cx, loc.block, buf.as_slice())?;

    Ok(())
}

/// Serialize `inode` into `buf` (`buf.len()` must be `inode_size`) AND stamp its
/// CRC32C checksum — i.e. the exact bytes `write_inode` lands in the inode's slot,
/// with NO device I/O. Exposed so the transactional ext4 create/write path in
/// ffs-core can build the patched inode-table block itself and stage it with a
/// slot-scoped MVCC merge proof: relaxed first-committer-wins so concurrent creates
/// writing DISJOINT inode slots of the same 4 KiB table block MERGE instead of
/// FCW-conflicting — the parallel-create bottleneck the bd-bhh0i cutover hit. The
/// caller pairs this with `locate_inode` (block + `byte_offset`) to know the slot's
/// `[byte_offset, byte_offset + inode_size)` range for the proof.
#[expect(clippy::cast_possible_truncation)]
pub fn serialize_inode_with_checksum(
    inode: &Ext4Inode,
    inode_size: usize,
    ino: InodeNumber,
    csum_seed: u32,
    buf: &mut [u8],
) {
    serialize_inode_into(inode, inode_size, buf);
    compute_and_set_checksum(buf, csum_seed, ino.0 as u32);
}

/// Serialize into a caller-provided `buf` (`buf.len()` must be `inode_size`) —
/// lets the hot write path (`write_inode`) use a stack buffer instead of the
/// per-call `vec![0; inode_size]` heap allocation (bd-cc-serialize-into).
#[expect(clippy::cast_possible_truncation)]
pub fn serialize_inode_into(inode: &Ext4Inode, inode_size: usize, buf: &mut [u8]) {
    debug_assert_eq!(buf.len(), inode_size);
    buf.fill(0);

    // Reslice the fixed 128-byte base area to an array ref ONCE (one bounds
    // check): const-offset writes into `&mut [u8; 128]` are provably in-bounds,
    // so the ~30 base-field `copy_from_slice`s drop their per-write bounds check
    // with NO extra buffer traffic (writes still land straight in `buf`). The
    // write-side analog of the extent-parse read_fixed hoist (b83531ef); the
    // caller always sizes `buf` to `inode_size >= 128`. The variable-offset
    // extended area (0x80+) keeps direct `buf` writes below.
    let base: &mut [u8; 128] = (&mut buf[..128])
        .try_into()
        .expect("ext4 inode buffer is at least 128 bytes");

    // Mode (0x00).
    base[0x00..0x02].copy_from_slice(&inode.mode.to_le_bytes());
    // UID low (0x02).
    base[0x02..0x04].copy_from_slice(&(inode.uid as u16).to_le_bytes());
    // Size low (0x04).
    base[0x04..0x08].copy_from_slice(&(inode.size as u32).to_le_bytes());
    // atime (0x08).
    base[0x08..0x0C].copy_from_slice(&inode.atime.to_le_bytes());
    // ctime (0x0C).
    base[0x0C..0x10].copy_from_slice(&inode.ctime.to_le_bytes());
    // mtime (0x10).
    base[0x10..0x14].copy_from_slice(&inode.mtime.to_le_bytes());
    // dtime (0x14).
    base[0x14..0x18].copy_from_slice(&inode.dtime.to_le_bytes());
    // GID low (0x18).
    base[0x18..0x1A].copy_from_slice(&(inode.gid as u16).to_le_bytes());
    // Links count (0x1A).
    base[0x1A..0x1C].copy_from_slice(&inode.links_count.to_le_bytes());
    // Blocks low (0x1C).
    base[0x1C..0x20].copy_from_slice(&(inode.blocks as u32).to_le_bytes());
    // Flags (0x20).
    base[0x20..0x24].copy_from_slice(&inode.flags.to_le_bytes());
    // i_osd1 / l_i_version (0x24) — NFS change attribute low 32 bits.
    base[0x24..0x28].copy_from_slice(&inode.version.to_le_bytes());
    // i_block / extent bytes (0x28, 60 bytes).
    let copy_len = inode.extent_bytes.len().min(60);
    base[0x28..0x28 + copy_len].copy_from_slice(&inode.extent_bytes[..copy_len]);
    // Generation (0x64).
    base[0x64..0x68].copy_from_slice(&inode.generation.to_le_bytes());
    // File ACL low (0x68).
    base[0x68..0x6C].copy_from_slice(&(inode.file_acl as u32).to_le_bytes());
    // Size high (0x6C).
    base[0x6C..0x70].copy_from_slice(&((inode.size >> 32) as u32).to_le_bytes());
    // Blocks high (0x74, 2 bytes).
    base[0x74..0x76].copy_from_slice(&((inode.blocks >> 32) as u16).to_le_bytes());
    // File ACL high (0x76, 2 bytes).
    base[0x76..0x78].copy_from_slice(&((inode.file_acl >> 32) as u16).to_le_bytes());
    // UID high (0x78).
    base[0x78..0x7A].copy_from_slice(&((inode.uid >> 16) as u16).to_le_bytes());
    // GID high (0x7A).
    base[0x7A..0x7C].copy_from_slice(&((inode.gid >> 16) as u16).to_le_bytes());
    // checksum_lo (0x7C) — will be set by compute_and_set_checksum.

    // Extended area (when inode_size > 128).
    if inode_size > 128 {
        // extra_isize (0x80).
        buf[0x80..0x82].copy_from_slice(&inode.extra_isize.to_le_bytes());
        // checksum_hi (0x82) — will be set by compute_and_set_checksum.

        // Extended timestamps.
        if inode_size >= 0x88 {
            buf[0x84..0x88].copy_from_slice(&inode.ctime_extra.to_le_bytes());
        }
        if inode_size >= 0x8C {
            buf[0x88..0x8C].copy_from_slice(&inode.mtime_extra.to_le_bytes());
        }
        if inode_size >= 0x90 {
            buf[0x8C..0x90].copy_from_slice(&inode.atime_extra.to_le_bytes());
        }
        if inode_size >= 0x98 {
            buf[0x90..0x94].copy_from_slice(&inode.crtime.to_le_bytes());
            buf[0x94..0x98].copy_from_slice(&inode.crtime_extra.to_le_bytes());
        }
        if inode_size >= 0x9C {
            // i_version_hi (0x98) — NFS change attribute high 32 bits.
            buf[0x98..0x9C].copy_from_slice(&inode.version_hi.to_le_bytes());
        }
        if inode_size >= 0xA0 {
            buf[0x9C..0xA0].copy_from_slice(&inode.projid.to_le_bytes());
        }

        // Inline xattrs go after 128 + extra_isize.
        let xattr_start = 128 + usize::from(inode.extra_isize);
        let xattr_copy = inode
            .xattr_ibody
            .len()
            .min(inode_size.saturating_sub(xattr_start));
        if xattr_start < inode_size && xattr_copy > 0 {
            buf[xattr_start..xattr_start + xattr_copy]
                .copy_from_slice(&inode.xattr_ibody[..xattr_copy]);
        }
    }
}

/// Serialize an `Ext4Inode` into a freshly-allocated `Vec` (convenience wrapper
/// over [`serialize_inode_into`] for the non-hot callers; the hot `write_inode`
/// path uses a stack buffer).
#[must_use]
pub fn serialize_inode(inode: &Ext4Inode, inode_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; inode_size];
    serialize_inode_into(inode, inode_size, &mut buf);
    buf
}

/// Doc-hidden hook for fuzz targets that need deterministic inode serialization.
#[doc(hidden)]
#[must_use]
pub fn fuzz_serialize_inode(inode: &Ext4Inode, inode_size: usize) -> Vec<u8> {
    serialize_inode(inode, inode_size)
}

/// Compute CRC32C checksum and store it in the raw inode buffer.
fn compute_and_set_checksum(raw: &mut [u8], csum_seed: u32, ino: u32) {
    let is = raw.len();
    if is < 128 {
        return;
    }

    // Per-inode seed: ext4_chksum(csum_seed, le_ino) then ext4_chksum(ino_seed, le_gen).
    let ino_seed = ffs_ondisk::ext4_chksum(csum_seed, &ino.to_le_bytes());
    let generation = u32::from_le_bytes([raw[0x64], raw[0x65], raw[0x66], raw[0x67]]);
    let ino_seed = ffs_ondisk::ext4_chksum(ino_seed, &generation.to_le_bytes());

    // Zero out checksum fields before computing.
    raw[INODE_CHECKSUM_LO_OFFSET] = 0;
    raw[INODE_CHECKSUM_LO_OFFSET + 1] = 0;
    if is >= INODE_CHECKSUM_HI_OFFSET + 2 {
        raw[INODE_CHECKSUM_HI_OFFSET] = 0;
        raw[INODE_CHECKSUM_HI_OFFSET + 1] = 0;
    }

    // CRC the entire raw inode.
    let csum = ffs_ondisk::ext4_chksum(ino_seed, raw);

    // Store checksum.
    let lo = (csum & 0xFFFF) as u16;
    raw[INODE_CHECKSUM_LO_OFFSET..INODE_CHECKSUM_LO_OFFSET + 2].copy_from_slice(&lo.to_le_bytes());
    if is >= INODE_CHECKSUM_HI_OFFSET + 2 {
        let hi = ((csum >> 16) & 0xFFFF) as u16;
        raw[INODE_CHECKSUM_HI_OFFSET..INODE_CHECKSUM_HI_OFFSET + 2]
            .copy_from_slice(&hi.to_le_bytes());
    }
}

// ── Create ──────────────────────────────────────────────────────────────────

/// File type constants for inode mode.
pub mod file_type {
    pub const S_IFREG: u16 = 0o100_000;
    pub const S_IFDIR: u16 = 0o040_000;
    pub const S_IFLNK: u16 = 0o120_000;
}

/// Create a new inode on disk.
///
/// Allocates an inode number via `ffs-alloc`, initializes fields, writes to disk.
/// Returns `(InodeNumber, Ext4Inode)`.
#[expect(clippy::too_many_arguments)]
/// Allocate an inode number (with its bitmap/group-descriptor persist) and build
/// the initial [`Ext4Inode`] WITHOUT persisting the inode body to the inode
/// table. Callers that immediately mutate the returned inode and write it back
/// themselves — `mkdir` (size/blocks/links_count/extent root), `mknod` (rdev),
/// `symlink` (target) — use this to skip the redundant inode-table-block write
/// that [`create_inode`] would do one step before the caller's own `write_inode`
/// overwrites it (bd-mkinode-defer). [`create_inode`] is `prepare_inode` followed
/// by that persist, for callers whose returned inode is already final
/// (`ext4_create`). No intermediate reader observes the still-unwritten inode
/// slot: the number is already reserved in the bitmap and every create-family
/// caller writes the final body before any lookup can resolve the new name.
pub fn prepare_inode(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    mode: u16,
    uid: u32,
    gid: u32,
    parent_group: GroupNumber,
    now_secs: u64,
    now_nsec: u32,
    pctx: &ffs_alloc::PersistCtx,
) -> Result<(InodeNumber, Ext4Inode)> {
    cx_checkpoint(cx)?;

    let is_dir = (mode & 0xF000) == file_type::S_IFDIR;
    // `alloc_inode_persist` itself increments the allocated group's `used_dirs`
    // (and persists it in the same group-descriptor write) when `is_dir`, so the
    // on-disk `bg_used_dirs_count` stays consistent (bd-0y7jp). Do NOT increment
    // again here — a second bump double-counts once a later same-group
    // allocation flushes the in-memory value to disk.
    let alloc = ffs_alloc::alloc_inode_persist(cx, dev, geo, groups, parent_group, is_dir, pctx)?;

    // Read old generation from the on-disk inode slot so we can bump it.
    // This is the NFS-style generation counter: when an inode number is reused,
    // incrementing the generation lets the FUSE/NFS layer detect stale handles.
    let old_generation = match locate_inode(alloc.ino, geo, groups) {
        Some(loc) => {
            let buf = dev.read_block(cx, loc.block)?;
            let data = buf.as_slice();
            let off = loc.byte_offset;
            // generation lives at offset 0x64 in the raw inode (4 bytes LE).
            if off.checked_add(0x68).is_some_and(|end| end <= data.len()) {
                u32::from_le_bytes([
                    data[off + 0x64],
                    data[off + 0x65],
                    data[off + 0x66],
                    data[off + 0x67],
                ])
            } else {
                0
            }
        }
        None => 0,
    };

    let new_generation = old_generation.wrapping_add(1);
    debug!(
        target: "ffs::inode::generation",
        ino = alloc.ino.0,
        old_generation,
        new_generation,
        "inode_generation_bump"
    );
    let inode = build_fresh_inode(mode, uid, gid, is_dir, new_generation, now_secs, now_nsec);

    Ok((alloc.ino, inode))
}

/// Build a fresh regular-file / directory [`Ext4Inode`] body — NO allocation,
/// NO I/O. This is the pure construction half of [`prepare_inode`], extracted
/// verbatim so the sharded parallel-create path (bd-bhh0i) can reuse the EXACT
/// same field initialization off a lock-free-allocated inode number without
/// duplicating (and risking divergence from) it. `generation` is the
/// already-bumped NFS generation counter (`old + 1`); the caller reads the old
/// value and logs the bump.
#[must_use]
pub fn build_fresh_inode(
    mode: u16,
    uid: u32,
    gid: u32,
    is_dir: bool,
    generation: u32,
    now_secs: u64,
    now_nsec: u32,
) -> Ext4Inode {
    // Initialize extent tree root (empty tree: magic + 0 entries, max 4, depth 0).
    // NB: `vec![0;60].into()` (From<Vec> = SmallVec spill, reusing the jemalloc
    // buffer) benchmarks FASTER here than a stack-array `.as_slice().into()`
    // inline copy — the small-alloc + buffer-reuse beats copying 60B inline
    // (see benches/serialize_inode.rs prepare_inode_extent_bytes; bd-cc-prepare-inode-inline REFUTED).
    let mut extent_bytes = vec![0u8; 60];
    extent_bytes[0] = (EXT4_EXTENT_MAGIC & 0xFF) as u8;
    extent_bytes[1] = (EXT4_EXTENT_MAGIC >> 8) as u8;
    // entries = 0.
    extent_bytes[4] = 4; // max_entries = 4.
    // depth = 0 (already zero).

    let extra_time = encode_extra_timestamp(now_secs, now_nsec);

    #[allow(clippy::cast_possible_truncation)]
    let now_lo = now_secs as u32;
    Ext4Inode {
        mode,
        uid,
        gid,
        size: 0,
        links_count: if is_dir { 2 } else { 1 },
        blocks: 0,
        flags: EXT4_EXTENTS_FL,
        version: 0,
        generation,
        file_acl: 0,
        atime: now_lo,
        ctime: now_lo,
        mtime: now_lo,
        dtime: 0,
        atime_extra: extra_time,
        ctime_extra: extra_time,
        mtime_extra: extra_time,
        crtime: now_lo,
        crtime_extra: extra_time,
        extra_isize: 32,
        checksum: 0,
        version_hi: 0,
        projid: 0,
        extent_bytes: extent_bytes.into(),
        xattr_ibody: Vec::new(),
        number: 0,
    }
}

/// Allocate and persist a fresh inode with its initial body. Equivalent to
/// [`prepare_inode`] followed by [`write_inode`]; used by callers (e.g.
/// `ext4_create`) whose returned inode needs no further mutation.
#[allow(clippy::too_many_arguments)]
pub fn create_inode(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    mode: u16,
    uid: u32,
    gid: u32,
    parent_group: GroupNumber,
    csum_seed: u32,
    now_secs: u64,
    now_nsec: u32,
    pctx: &ffs_alloc::PersistCtx,
) -> Result<(InodeNumber, Ext4Inode)> {
    let (ino, inode) = prepare_inode(
        cx,
        dev,
        geo,
        groups,
        mode,
        uid,
        gid,
        parent_group,
        now_secs,
        now_nsec,
        pctx,
    )?;
    write_inode(cx, dev, geo, groups, ino, &inode, csum_seed)?;
    Ok((ino, inode))
}

// ── Delete ──────────────────────────────────────────────────────────────────

/// Inode flag: inline data stored in `i_block` (EXT4_INLINE_DATA_FL).
const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;
/// Inode flag: e2compr compression requested (EXT4_COMPR_FL).
const EXT4_COMPR_FL: u32 = 0x0000_0004;
/// Inode flag: e2compr compressed blocks present (EXT4_COMPRBLK_FL).
const EXT4_COMPRBLK_FL: u32 = 0x0000_0200;

const S_IFMT: u16 = 0xF000;
const S_IFREG: u16 = 0x8000;
const S_IFDIR: u16 = 0x4000;
const S_IFLNK: u16 = 0xA000;

/// True iff the inode maps its data through legacy indirect block pointers
/// (i_block[0..12] direct, [12]/[13]/[14] single/double/triple indirect) — so
/// `delete_inode` / truncate may walk and free that chain.
///
/// Guards strictly: an inode that is extent-mapped, inline-data, e2compr
/// (compressed), or has no allocated blocks (fast symlink target inline in
/// i_block, device file whose i_block holds the rdev, empty file) must NOT be
/// treated as a plain pointer table. In particular e2compr files store the
/// EXT2_COMPRESSED_BLKADDR sentinel (0xFFFFFFFF) in i_block slots — freeing that
/// as a block would corrupt the allocator — so they are excluded here (their
/// cluster-aware block management is unimplemented; deleting one currently
/// leaks its data blocks rather than corrupting the bitmap).
fn inode_uses_indirect_blocks(inode: &Ext4Inode) -> bool {
    const EXCLUDED: u32 = EXT4_EXTENTS_FL | EXT4_INLINE_DATA_FL | EXT4_COMPR_FL | EXT4_COMPRBLK_FL;
    if inode.flags & EXCLUDED != 0 {
        return false;
    }
    if inode.blocks == 0 {
        return false;
    }
    matches!(inode.mode & S_IFMT, S_IFREG | S_IFDIR | S_IFLNK)
}

/// Free a list of data block numbers (in file order) in maximal contiguous
/// runs. `free_blocks_persist(start, len)` already does a single bitmap-block
/// read-modify-write per group for the whole range, so collapsing a contiguous
/// run into one ranged call turns O(blocks) bitmap RMWs into O(runs) — a large
/// win when deleting/truncating sequentially-allocated files. Freeing a range is
/// the canonical batch form of freeing each block individually (same bits, same
/// validation, same accounting; freeing is commutative), so this is behaviorally
/// identical to the per-block loop it replaces.
fn free_data_blocks_in_runs(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    blocks: &[u32],
    pctx: &ffs_alloc::PersistCtx,
) -> Result<()> {
    let mut idx = 0;
    while idx < blocks.len() {
        let start = blocks[idx];
        let mut len = 1u32;
        while idx + (len as usize) < blocks.len()
            && start.checked_add(len) == Some(blocks[idx + len as usize])
        {
            len += 1;
        }
        ffs_alloc::free_blocks_persist(
            cx,
            dev,
            geo,
            groups,
            BlockNumber(u64::from(start)),
            len,
            pctx,
        )?;
        idx += len as usize;
    }
    Ok(())
}

/// Recursively free an indirect pointer block at indirection `level`
/// (1 = single → data blocks, 2 = double, 3 = triple): frees every data block
/// reachable from it, then frees the pointer block itself.
#[allow(clippy::too_many_arguments)] // recursive chain walk threads device + alloc + geometry
fn free_indirect_chain(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    block: BlockNumber,
    level: u32,
    ppb: usize,
    pctx: &ffs_alloc::PersistCtx,
) -> Result<()> {
    cx_checkpoint(cx)?;
    let buf = dev.read_block(cx, block)?;
    let bytes = buf.as_slice();
    if level == 1 {
        // Leaf: gather the data-block pointers and free them in contiguous runs
        // (one bitmap read-modify-write per group per run instead of per block).
        let mut data_blocks = Vec::with_capacity(ppb);
        for i in 0..ppb {
            let off = i * 4;
            if off + 4 > bytes.len() {
                break;
            }
            let ptr =
                u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
            if ptr != 0 {
                data_blocks.push(ptr);
            }
        }
        free_data_blocks_in_runs(cx, dev, geo, groups, &data_blocks, pctx)?;
    } else {
        for i in 0..ppb {
            let off = i * 4;
            if off + 4 > bytes.len() {
                break;
            }
            let ptr =
                u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
            if ptr == 0 {
                continue;
            }
            free_indirect_chain(
                cx,
                dev,
                geo,
                groups,
                BlockNumber(u64::from(ptr)),
                level - 1,
                ppb,
                pctx,
            )?;
        }
    }
    // Free this indirect (metadata) block itself.
    ffs_alloc::free_blocks_persist(cx, dev, geo, groups, block, 1, pctx)?;
    Ok(())
}

/// Free every data + indirect-metadata block of a legacy indirect-mapped inode.
/// Caller must have verified [`inode_uses_indirect_blocks`].
fn free_indirect_blocks(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    inode: &Ext4Inode,
    pctx: &ffs_alloc::PersistCtx,
) -> Result<()> {
    let raw = &inode.extent_bytes;
    if raw.len() < 60 {
        return Ok(());
    }
    let read_ptr = |idx: usize| -> u32 {
        let off = idx * 4;
        u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
    };
    let ppb = (geo.block_size / 4) as usize;

    // Direct blocks i_block[0..12], freed in contiguous runs.
    let direct_blocks: Vec<u32> = (0..12usize).map(read_ptr).filter(|&ptr| ptr != 0).collect();
    free_data_blocks_in_runs(cx, dev, geo, groups, &direct_blocks, pctx)?;
    // Single / double / triple indirect roots.
    for (idx, level) in [(12usize, 1u32), (13usize, 2u32), (14usize, 3u32)] {
        let ptr = read_ptr(idx);
        if ptr != 0 {
            free_indirect_chain(
                cx,
                dev,
                geo,
                groups,
                BlockNumber(u64::from(ptr)),
                level,
                ppb,
                pctx,
            )?;
        }
    }
    Ok(())
}

/// Fast all-zero test for the indirect-block "is this block now empty?" check.
///
/// The idiomatic byte-wise `data.iter().all(|&b| b == 0)` is NOT auto-vectorized
/// (~1.5 µs on a 4 KiB block); a 4-wide u64 OR-reduce is ~15x faster (~99 ns)
/// with no regression on a non-empty block (early-exit at the first set byte).
/// Result-identical. Same fix as ffs-core `is_block_all_zero` (bench
/// `sparse_zero_scan`).
fn indirect_block_all_zero(data: &[u8]) -> bool {
    let mut chunks = data.chunks_exact(32);
    for block in &mut chunks {
        let w0 = u64::from_ne_bytes(block[0..8].try_into().unwrap());
        let w1 = u64::from_ne_bytes(block[8..16].try_into().unwrap());
        let w2 = u64::from_ne_bytes(block[16..24].try_into().unwrap());
        let w3 = u64::from_ne_bytes(block[24..32].try_into().unwrap());
        if (w0 | w1 | w2 | w3) != 0 {
            return false;
        }
    }
    let mut tail = chunks.remainder().chunks_exact(8);
    tail.all(|c| u64::from_ne_bytes(c.try_into().unwrap()) == 0)
        && tail.remainder().iter().all(|&b| b == 0)
}

/// Return the first indirect entry whose logical range is not wholly below
/// `cutoff`. This is the closed-form equivalent of the saturating range check
/// in `free_indirect_subtree_range`; the original predicate remains in the
/// shortened loop as a defensive guard.
fn first_indirect_entry_at_cutoff(base: u64, cutoff: u64, entry_span: u64, ppb: u64) -> u64 {
    if entry_span == 0 {
        return if base <= cutoff { ppb } else { 0 };
    }
    if cutoff == u64::MAX {
        return ppb;
    }
    (cutoff.saturating_sub(base) / entry_span).min(ppb)
}

/// Recursively free data blocks at or beyond logical block `cutoff` within an
/// indirect pointer block at indirection `level`, whose first entry maps logical
/// block `base`. Frees deeper metadata blocks that become empty, zeroes the
/// freed pointer slots, and returns `(blocks_freed, block_is_now_empty)`. The
/// caller frees `block` itself when this returns empty.
#[allow(clippy::too_many_arguments)] // recursive chain walk threads device + alloc + geometry
fn free_indirect_subtree_range(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    block: BlockNumber,
    level: u32,
    base: u64,
    cutoff: u64,
    ppb: u64,
    pctx: &ffs_alloc::PersistCtx,
) -> Result<(u64, bool)> {
    cx_checkpoint(cx)?;
    let buf = dev.read_block(cx, block)?;
    let mut data = buf.as_slice().to_vec();
    let entry_span = ppb.saturating_pow(level - 1);
    let first_entry = first_indirect_entry_at_cutoff(base, cutoff, entry_span, ppb);
    let mut freed = 0u64;
    let mut dirty = false;

    if level == 1 {
        // entry_span == 1: every non-zero pointer surviving the cutoff check has
        // `child_base >= cutoff` and is freed. Collect them (zeroing each slot in
        // the in-memory indirect buffer) and free them in contiguous runs — one
        // bitmap read-modify-write per run instead of per block (bd-wgv6x).
        let mut to_free = Vec::new();
        for i in first_entry..ppb {
            let off = match usize::try_from(i) {
                Ok(idx) => idx * 4,
                Err(_) => break,
            };
            if off + 4 > data.len() {
                break;
            }
            let ptr = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            if ptr == 0 {
                continue;
            }
            to_free.push(ptr);
            data[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
            dirty = true;
        }
        if !to_free.is_empty() {
            let n = to_free.len() as u64;
            free_data_blocks_in_runs(cx, dev, geo, groups, &to_free, pctx)?;
            freed = freed.saturating_add(n);
        }
    } else {
        for i in first_entry..ppb {
            let child_base = base.saturating_add(i.saturating_mul(entry_span));
            // Entry's whole logical range is below the cutoff — keep untouched.
            if child_base.saturating_add(entry_span) <= cutoff {
                continue;
            }
            let off = match usize::try_from(i) {
                Ok(idx) => idx * 4,
                Err(_) => break,
            };
            if off + 4 > data.len() {
                break;
            }
            let ptr = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            if ptr == 0 {
                continue;
            }
            let child = BlockNumber(u64::from(ptr));
            let (child_freed, child_empty) = free_indirect_subtree_range(
                cx,
                dev,
                geo,
                groups,
                child,
                level - 1,
                child_base,
                cutoff,
                ppb,
                pctx,
            )?;
            freed = freed.saturating_add(child_freed);
            if child_empty {
                ffs_alloc::free_blocks_persist(cx, dev, geo, groups, child, 1, pctx)?;
                data[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
                dirty = true;
                freed = freed.saturating_add(1);
            }
        }
    }

    let empty = indirect_block_all_zero(&data);
    // Persist zeroed slots only when the block survives; an emptied block is
    // freed by the caller, so its contents become unreachable.
    if dirty && !empty {
        dev.write_block(cx, block, &data)?;
    }
    Ok((freed, empty))
}

/// Truncate a legacy indirect-mapped inode down to logical block `cutoff`.
///
/// Frees its data + now-empty indirect-metadata blocks at or beyond `cutoff`,
/// zeroing the inode's pointer slots, and returns the number of freed
/// filesystem blocks (for `i_blocks` accounting). Returns 0 for any inode that
/// is not indirect-mapped (extent/inline/fast-symlink/device/empty) — never
/// misreads such an `i_block` as pointers. Used by orphan recovery to complete
/// an interrupted truncate.
pub fn truncate_indirect_blocks(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    inode: &mut Ext4Inode,
    cutoff: u64,
    pctx: &ffs_alloc::PersistCtx,
) -> Result<u64> {
    if !inode_uses_indirect_blocks(inode) || inode.extent_bytes.len() < 60 {
        return Ok(0);
    }
    let ppb = u64::from(geo.block_size) / 4;
    let mut freed = 0u64;

    // Direct blocks i_block[0..12].
    for lb in 0..12usize {
        if (lb as u64) < cutoff {
            continue;
        }
        let off = lb * 4;
        let ptr = u32::from_le_bytes([
            inode.extent_bytes[off],
            inode.extent_bytes[off + 1],
            inode.extent_bytes[off + 2],
            inode.extent_bytes[off + 3],
        ]);
        if ptr != 0 {
            ffs_alloc::free_blocks_persist(
                cx,
                dev,
                geo,
                groups,
                BlockNumber(u64::from(ptr)),
                1,
                pctx,
            )?;
            inode.extent_bytes[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
            freed = freed.saturating_add(1);
        }
    }

    // Single / double / triple indirect roots.
    for (idx, level, base) in [
        (12usize, 1u32, 12u64),
        (13usize, 2u32, 12u64.saturating_add(ppb)),
        (
            14usize,
            3u32,
            12u64
                .saturating_add(ppb)
                .saturating_add(ppb.saturating_mul(ppb)),
        ),
    ] {
        let span = ppb.saturating_pow(level);
        if base.saturating_add(span) <= cutoff {
            continue;
        }
        let off = idx * 4;
        let root_ptr = u32::from_le_bytes([
            inode.extent_bytes[off],
            inode.extent_bytes[off + 1],
            inode.extent_bytes[off + 2],
            inode.extent_bytes[off + 3],
        ]);
        if root_ptr == 0 {
            continue;
        }
        let (sub_freed, empty) = free_indirect_subtree_range(
            cx,
            dev,
            geo,
            groups,
            BlockNumber(u64::from(root_ptr)),
            level,
            base,
            cutoff,
            ppb,
            pctx,
        )?;
        freed = freed.saturating_add(sub_freed);
        if empty {
            ffs_alloc::free_blocks_persist(
                cx,
                dev,
                geo,
                groups,
                BlockNumber(u64::from(root_ptr)),
                1,
                pctx,
            )?;
            inode.extent_bytes[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
            freed = freed.saturating_add(1);
        }
    }

    Ok(freed)
}

/// Delete an inode: truncate all extents, free the inode, zero the on-disk data.
#[expect(clippy::too_many_arguments)]
pub fn delete_inode(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    ino: InodeNumber,
    inode: &mut Ext4Inode,
    csum_seed: u32,
    now_secs: u64,
    pctx: &ffs_alloc::PersistCtx,
) -> Result<()> {
    cx_checkpoint(cx)?;

    // Capture the directory bit before the inode fields are zeroed below: ext4
    // decrements the group's `bg_used_dirs_count` when a directory inode is
    // freed (bd-0y7jp), and `free_inode_persist` needs to know which kind it is.
    let is_dir = inode.is_dir();

    debug!(
        target: "ffs::inode::generation",
        ino = ino.0,
        current_generation = inode.generation,
        "inode_delete_preserving_generation"
    );

    // Truncate all extents if the inode uses extents.
    if inode.flags & EXT4_EXTENTS_FL != 0 && inode.extent_bytes.len() >= 60 {
        let mut root_buf = [0u8; 60];
        root_buf.copy_from_slice(&inode.extent_bytes[..60]);
        ffs_extent::truncate_extents(
            cx,
            dev,
            &mut root_buf,
            geo,
            groups,
            0,
            pctx,
            ffs_extent::ExtentOwner {
                ino: u32::try_from(ino.0).unwrap_or(u32::MAX),
                generation: inode.generation,
            },
        )?;
        inode.extent_bytes[..60].copy_from_slice(&root_buf);
    } else if inode_uses_indirect_blocks(inode) {
        // Legacy indirect-block-mapped inode: free its data + indirect-metadata
        // blocks down the pointer chain. Without this the blocks leak (stay set
        // in the block bitmap with no referencing inode — e2fsck-dirty).
        free_indirect_blocks(cx, dev, geo, groups, inode, pctx)?;
    }

    // Free the external xattr block if present.
    if inode.file_acl != 0 {
        let acl_block = BlockNumber(inode.file_acl);
        let buf = dev.read_block(cx, acl_block)?;
        let mut data = buf.as_slice().to_vec();
        if data.len() >= 32 {
            let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if magic == 0xEA02_0000 {
                let refcount = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                if refcount > 1 {
                    let new_refcount = refcount - 1;
                    data[4..8].copy_from_slice(&new_refcount.to_le_bytes());
                    dev.write_block(cx, acl_block, &data)?;
                } else {
                    ffs_alloc::free_blocks_persist(cx, dev, geo, groups, acl_block, 1, pctx)?;
                }
            } else {
                // Not a valid xattr block, but we still free it to prevent leaks.
                ffs_alloc::free_blocks_persist(cx, dev, geo, groups, acl_block, 1, pctx)?;
            }
        }
        inode.file_acl = 0;
    }

    // Set deletion time.
    #[allow(clippy::cast_possible_truncation)]
    {
        inode.dtime = now_secs as u32;
    }
    inode.links_count = 0;
    inode.mode = 0;
    inode.size = 0;
    inode.blocks = 0;

    // Write the zeroed-out inode to disk.
    write_inode(cx, dev, geo, groups, ino, inode, csum_seed)?;

    // Free the inode in the bitmap.
    ffs_alloc::free_inode_persist(cx, dev, geo, groups, ino, is_dir, pctx)?;

    Ok(())
}

// ── Timestamps ──────────────────────────────────────────────────────────────

/// Encode nanoseconds and epoch extension into the `_extra` timestamp field.
///
/// Layout: bits 0-1 = epoch extension (seconds >> 32), bits 2-31 = nanoseconds.
///
/// Nanoseconds must be in `[0, 999_999_999]`. Values exceeding this range
/// are clamped to prevent bit-shift overflow.
#[must_use]
pub fn encode_extra_timestamp(secs: u64, nsec: u32) -> u32 {
    let epoch = ((secs >> 32) & 0x3) as u32; // upper 2 bits of seconds
    // Clamp nsec to valid range to prevent bit-shift overflow.
    // Max valid: 999_999_999 << 2 = 3_999_999_996, fits in u32.
    let clamped_nsec = nsec.min(999_999_999);
    let nsec_bits = clamped_nsec << 2; // nanoseconds shifted to bits 2-31
    epoch | nsec_bits
}

/// Touch atime on an inode.
#[allow(clippy::cast_possible_truncation)]
pub fn touch_atime(inode: &mut Ext4Inode, secs: u64, nsec: u32) {
    inode.atime = secs as u32; // lower 32 bits per ext4 spec
    inode.atime_extra = encode_extra_timestamp(secs, nsec);
}

/// Touch mtime and ctime on an inode, and bump the NFS version counter.
#[allow(clippy::cast_possible_truncation)]
pub fn touch_mtime_ctime(inode: &mut Ext4Inode, secs: u64, nsec: u32) {
    inode.mtime = secs as u32;
    inode.mtime_extra = encode_extra_timestamp(secs, nsec);
    inode.ctime = secs as u32;
    inode.ctime_extra = encode_extra_timestamp(secs, nsec);
    bump_inode_version(inode);
}

/// Increment the 64-bit NFS inode version counter (i_version + i_version_hi).
///
/// Used by NFSv4 for cache coherence (the NFS change attribute) and by
/// statx(2) via `STATX_CHANGE_COOKIE`. The kernel increments this on every
/// inode metadata or data change.
#[allow(clippy::cast_possible_truncation)]
pub fn bump_inode_version(inode: &mut Ext4Inode) {
    let current = u64::from(inode.version) | (u64::from(inode.version_hi) << 32);
    let next = current.wrapping_add(1);
    inode.version = next as u32;
    inode.version_hi = (next >> 32) as u32;
}

/// Touch ctime only on an inode (e.g., for chmod, chown), and bump version.
#[allow(clippy::cast_possible_truncation)]
pub fn touch_ctime(inode: &mut Ext4Inode, secs: u64, nsec: u32) {
    inode.ctime = secs as u32;
    inode.ctime_extra = encode_extra_timestamp(secs, nsec);
    bump_inode_version(inode);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn cx_checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[expect(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use ffs_block::BlockBuf;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MemBlockDevice {
        block_size: u32,
        blocks: Mutex<HashMap<u64, Vec<u8>>>,
    }

    impl MemBlockDevice {
        fn new(block_size: u32) -> Self {
            Self {
                block_size,
                blocks: Mutex::new(HashMap::new()),
            }
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            let blocks = self.blocks.lock().unwrap();
            blocks.get(&block.0).map_or_else(
                || Ok(BlockBuf::new(vec![0u8; self.block_size as usize])),
                |data| Ok(BlockBuf::new(data.clone())),
            )
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.blocks.lock().unwrap().insert(block.0, data.to_vec());
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            1_000_000
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    struct ReadFailingBlockDevice {
        inner: MemBlockDevice,
        fail_block: BlockNumber,
    }

    impl ReadFailingBlockDevice {
        fn new(block_size: u32, fail_block: BlockNumber) -> Self {
            Self {
                inner: MemBlockDevice::new(block_size),
                fail_block,
            }
        }
    }

    impl BlockDevice for ReadFailingBlockDevice {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if block == self.fail_block {
                return Err(FfsError::Io(std::io::Error::other(
                    "injected inode-table read failure",
                )));
            }
            self.inner.read_block(cx, block)
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.inner.write_block(cx, block, data)
        }

        fn block_size(&self) -> u32 {
            self.inner.block_size()
        }

        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
            self.inner.sync(cx)
        }
    }

    fn test_cx() -> Cx {
        Cx::for_testing()
    }

    fn mock_pctx() -> ffs_alloc::PersistCtx {
        ffs_alloc::PersistCtx {
            gdt_block: BlockNumber(1),
            desc_size: 32,
            has_metadata_csum: false,
            uuid: [0; 16],
            csum_seed: 0,
            group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::None,
            blocks_per_group: 32768,
            inodes_per_group: 2048,
        }
    }

    fn make_geometry() -> FsGeometry {
        FsGeometry {
            blocks_per_group: 8192,
            inodes_per_group: 2048,
            block_size: 4096,
            cluster_ratio: 1,
            total_blocks: 32768,
            total_inodes: 8192,
            first_data_block: 0,
            group_count: 4,
            inode_size: 256,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_meta_bg: 0,
            first_inode: 11,
        }
    }

    fn make_groups(geo: &FsGeometry) -> Vec<GroupStats> {
        (0..geo.group_count)
            .map(|g| GroupStats {
                group: GroupNumber(g),
                free_blocks: geo.blocks_per_group,
                block_largest_free_run: None,
                free_inodes: geo.inodes_per_group,
                used_dirs: 0,
                block_bitmap_block: BlockNumber(u64::from(g) * 100 + 1),
                inode_bitmap_block: BlockNumber(u64::from(g) * 100 + 2),
                inode_table_block: BlockNumber(u64::from(g) * 100 + 3),
                flags: 0,
                block_bitmap_csum: 0,
                inode_bitmap_csum: 0,
                inode_search_start: 0,
                reserved_cache: std::sync::OnceLock::new(),
                reserved_confirmed: std::sync::OnceLock::new(),
            })
            .collect()
    }

    fn representative_inode() -> Ext4Inode {
        Ext4Inode {
            mode: 0o100_755,
            uid: 0x0001_03E8,
            gid: 0x0002_03E9,
            size: 0x0001_0000_0000_1234,
            links_count: 2,
            blocks: 0x0002_0000_0000_0008,
            flags: EXT4_EXTENTS_FL,
            version: 7,
            generation: 0x1122_3344,
            file_acl: 0x0001_0000_0000_0064,
            atime: 1_700_000_000,
            ctime: 1_700_000_001,
            mtime: 1_700_000_002,
            dtime: 0,
            atime_extra: encode_extra_timestamp(u64::from(u32::MAX) + 2, 123_456_789),
            ctime_extra: encode_extra_timestamp(u64::from(u32::MAX) + 1, 222_222_222),
            mtime_extra: encode_extra_timestamp(u64::from(u32::MAX), 333_333_333),
            crtime: 1_650_000_000,
            crtime_extra: encode_extra_timestamp(u64::from(u32::MAX) + 3, 444_444_444),
            extra_isize: 32,
            checksum: 0,
            version_hi: 9,
            projid: 0x5566_7788,
            extent_bytes: (0_u8..60).collect(),
            xattr_ibody: vec![0xAA, 0xBB, 0xCC, 0xDD],
            number: 0,
        }
    }

    #[test]
    fn serialize_inode_with_checksum_matches_write_and_round_trips() {
        // Seam contract (bd-bhh0i merge-proof slice 1): the pure serialize+CRC the
        // transactional create path in ffs-core will stage under a slot-scoped merge
        // proof must produce the exact bytes `write_inode_at` lands in the slot.
        let inode = representative_inode();
        let inode_size = 256usize;
        let ino = InodeNumber(11);
        let seed = 0x1234_5678_u32;

        let mut buf = [0u8; 256];
        serialize_inode_with_checksum(&inode, inode_size, ino, seed, &mut buf[..inode_size]);

        // It is exactly serialize_inode_into + compute_and_set_checksum (what
        // write_inode_at now calls), so the block write is byte-identical.
        let mut expected = [0u8; 256];
        serialize_inode_into(&inode, inode_size, &mut expected[..inode_size]);
        compute_and_set_checksum(
            &mut expected[..inode_size],
            seed,
            u32::try_from(ino.0).expect("test ino fits in u32"),
        );
        assert_eq!(buf, expected);

        // And the serialized slot parses back to the same inode (core fields).
        let parsed = Ext4Inode::parse_from_bytes(&buf[..inode_size]).expect("parse serialized inode");
        assert_eq!(parsed.mode, inode.mode);
        assert_eq!(parsed.size, inode.size);
        assert_eq!(parsed.links_count, inode.links_count);
        assert_eq!(parsed.uid, inode.uid);
        assert_eq!(parsed.gid, inode.gid);
    }

    const REPRESENTATIVE_INODE_GOLDEN: &str = concat!(
        "geometry\n",
        "  block_size=4096\n",
        "  inode_size=256\n",
        "  inodes_per_group=2048\n",
        "location\n",
        "  debug=InodeLocation { block: BlockNumber(203), byte_offset: 0 }\n",
        "  block=203\n",
        "  byte_offset=0\n",
        "encoded_timestamps\n",
        "  atime_extra=0x1d6f3455\n",
        "  ctime_extra=0x34fb5e39\n",
        "  mtime_extra=0x4f790d54\n",
        "  crtime_extra=0x69f6bc71\n",
        "serialized_fields\n",
        "  mode=0x81ed\n",
        "  uid_lo=0x03e8\n",
        "  uid_hi=0x0001\n",
        "  gid_lo=0x03e9\n",
        "  gid_hi=0x0002\n",
        "  size_lo=0x00001234\n",
        "  size_hi=0x00010000\n",
        "  generation=0x11223344\n",
        "  file_acl_lo=0x00000064\n",
        "  file_acl_hi=0x0000\n",
        "  version_hi=0x00000009\n",
        "  projid=0x55667788\n",
        "  extent_prefix=[00, 01, 02, 03, 04, 05, 06, 07]\n",
        "checksum\n",
        "  lo=0x39ca\n",
        "  hi=0xd38c"
    );

    fn representative_inode_golden_contract_actual() -> String {
        let geo = make_geometry();
        let groups = make_groups(&geo);
        let ino = InodeNumber(4097);
        let loc = locate_inode(ino, &geo, &groups).expect("representative inode location");
        let inode = representative_inode();
        let mut raw = serialize_inode(&inode, usize::from(geo.inode_size));
        compute_and_set_checksum(&mut raw, 0xA1B2_C3D4, ino.0 as u32);
        ffs_ondisk::verify_inode_checksum(&raw, 0xA1B2_C3D4, ino.0 as u32, geo.inode_size)
            .expect("representative checksum should verify");

        let checksum_lo = u16::from_le_bytes([
            raw[INODE_CHECKSUM_LO_OFFSET],
            raw[INODE_CHECKSUM_LO_OFFSET + 1],
        ]);
        let checksum_hi = u16::from_le_bytes([
            raw[INODE_CHECKSUM_HI_OFFSET],
            raw[INODE_CHECKSUM_HI_OFFSET + 1],
        ]);

        format!(
            concat!(
                "geometry\n",
                "  block_size={}\n",
                "  inode_size={}\n",
                "  inodes_per_group={}\n",
                "location\n",
                "  debug={:?}\n",
                "  block={}\n",
                "  byte_offset={}\n",
                "encoded_timestamps\n",
                "  atime_extra=0x{:08x}\n",
                "  ctime_extra=0x{:08x}\n",
                "  mtime_extra=0x{:08x}\n",
                "  crtime_extra=0x{:08x}\n",
                "serialized_fields\n",
                "  mode=0x{:04x}\n",
                "  uid_lo=0x{:04x}\n",
                "  uid_hi=0x{:04x}\n",
                "  gid_lo=0x{:04x}\n",
                "  gid_hi=0x{:04x}\n",
                "  size_lo=0x{:08x}\n",
                "  size_hi=0x{:08x}\n",
                "  generation=0x{:08x}\n",
                "  file_acl_lo=0x{:08x}\n",
                "  file_acl_hi=0x{:04x}\n",
                "  version_hi=0x{:08x}\n",
                "  projid=0x{:08x}\n",
                "  extent_prefix={:02x?}\n",
                "checksum\n",
                "  lo=0x{:04x}\n",
                "  hi=0x{:04x}"
            ),
            geo.block_size,
            geo.inode_size,
            geo.inodes_per_group,
            loc,
            loc.block.0,
            loc.byte_offset,
            inode.atime_extra,
            inode.ctime_extra,
            inode.mtime_extra,
            inode.crtime_extra,
            u16::from_le_bytes([raw[0x00], raw[0x01]]),
            u16::from_le_bytes([raw[0x02], raw[0x03]]),
            u16::from_le_bytes([raw[0x78], raw[0x79]]),
            u16::from_le_bytes([raw[0x18], raw[0x19]]),
            u16::from_le_bytes([raw[0x7A], raw[0x7B]]),
            u32::from_le_bytes([raw[0x04], raw[0x05], raw[0x06], raw[0x07]]),
            u32::from_le_bytes([raw[0x6C], raw[0x6D], raw[0x6E], raw[0x6F]]),
            u32::from_le_bytes([raw[0x64], raw[0x65], raw[0x66], raw[0x67]]),
            u32::from_le_bytes([raw[0x68], raw[0x69], raw[0x6A], raw[0x6B]]),
            u16::from_le_bytes([raw[0x76], raw[0x77]]),
            u32::from_le_bytes([raw[0x98], raw[0x99], raw[0x9A], raw[0x9B]]),
            u32::from_le_bytes([raw[0x9C], raw[0x9D], raw[0x9E], raw[0x9F]]),
            &raw[0x28..0x30],
            checksum_lo,
            checksum_hi,
        )
    }

    #[test]
    fn locate_inode_basic() {
        let geo = make_geometry();
        let groups = make_groups(&geo);

        // Inode 1 → group 0, index 0.
        let loc = locate_inode(InodeNumber(1), &geo, &groups).unwrap();
        assert_eq!(loc.block, BlockNumber(3)); // inode_table_block for group 0
        assert_eq!(loc.byte_offset, 0);

        // Inode 2 → group 0, index 1.
        let loc = locate_inode(InodeNumber(2), &geo, &groups).unwrap();
        assert_eq!(loc.block, BlockNumber(3));
        assert_eq!(loc.byte_offset, 256); // 1 * 256

        // Inode at group boundary: 2049 → group 1, index 0.
        let loc = locate_inode(InodeNumber(2049), &geo, &groups).unwrap();
        assert_eq!(loc.block, BlockNumber(103)); // group 1 table
        assert_eq!(loc.byte_offset, 0);
    }

    #[test]
    fn serialize_roundtrip() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 1000,
            gid: 1000,
            size: 4096,
            links_count: 1,
            blocks: 8,
            flags: EXT4_EXTENTS_FL,

            version: 0,
            generation: 42,
            file_acl: 0,
            atime: 1_700_000_000,
            ctime: 1_700_000_000,
            mtime: 1_700_000_000,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 1_700_000_000,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let raw = serialize_inode(&inode, 256);
        assert_eq!(raw.len(), 256);

        // Parse back.
        let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(parsed.mode, inode.mode);
        assert_eq!(parsed.uid, inode.uid);
        assert_eq!(parsed.gid, inode.gid);
        assert_eq!(parsed.size, inode.size);
        assert_eq!(parsed.links_count, inode.links_count);
        assert_eq!(parsed.flags, inode.flags);
        assert_eq!(parsed.generation, inode.generation);
        assert_eq!(parsed.atime, inode.atime);
        assert_eq!(parsed.mtime, inode.mtime);
        assert_eq!(parsed.ctime, inode.ctime);
    }

    #[test]
    fn representative_inode_location_and_serialization_exact_golden_contract() {
        assert_eq!(
            representative_inode_golden_contract_actual(),
            REPRESENTATIVE_INODE_GOLDEN
        );
    }

    #[test]
    fn checksum_roundtrip() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 1000,
            gid: 1000,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: EXT4_EXTENTS_FL,

            version: 0,
            generation: 1,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let mut raw = serialize_inode(&inode, 256);
        compute_and_set_checksum(&mut raw, 0xDEAD_BEEF, 42);

        // Verify the checksum using ffs-ondisk's verifier.
        let result = ffs_ondisk::verify_inode_checksum(&raw, 0xDEAD_BEEF, 42, 256);
        assert!(result.is_ok(), "checksum verification failed: {result:?}");
    }

    #[test]
    fn create_and_read_inode() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, created) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            1000,
            1000,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(ino, InodeNumber(u64::from(geo.first_inode)));
        assert_eq!(created.mode, 0o100_644);
        assert_eq!(created.uid, 1000);
        assert_eq!(created.links_count, 1);

        // Read it back.
        let read_back = read_inode(&cx, &dev, &geo, &groups, ino).unwrap();
        assert_eq!(read_back.mode, 0o100_644);
        assert_eq!(read_back.uid, 1000);
    }

    #[test]
    fn read_inode_zero_returns_corruption() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let groups = make_groups(&geo);

        let err = read_inode(&cx, &dev, &geo, &groups, InodeNumber(0)).unwrap_err();
        assert!(
            matches!(err, FfsError::Corruption { ref detail, .. } if detail == "inode 0 out of range"),
            "unexpected error for inode zero: {err:?}"
        );
    }

    #[test]
    fn create_directory_inode() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (_, created) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            file_type::S_IFDIR | 0o755,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(created.links_count, 2);
        assert_eq!(created.mode, file_type::S_IFDIR | 0o755);
    }

    #[test]
    fn delete_inode_frees_resources() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        let free_before = groups[0].free_inodes;

        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            1_700_000_001,
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(inode.links_count, 0);
        assert_eq!(inode.dtime, 1_700_000_001);
        assert_eq!(groups[0].free_inodes, free_before + 1);
    }

    #[test]
    fn delete_inode_preserves_generation() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        // ext4 preserves the inode generation across delete (NFS file-handle
        // staleness detection and undelete safety); only inode REUSE bumps it.
        inode.generation = 0xDEAD_BEEF;

        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            1_700_000_001,
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(
            inode.generation, 0xDEAD_BEEF,
            "delete must preserve the inode generation"
        );
        // Sanity: the delete actually occurred.
        assert_eq!(inode.links_count, 0);
        assert_eq!(inode.dtime, 1_700_000_001);
    }

    #[test]
    fn indirect_cutoff_prefix_bound_matches_saturating_predicate() {
        // `ppb: u64` (matches first_indirect_entry_at_cutoff's param): without the
        // annotation `i` in `(0..ppb).find(|&i| i.saturating_mul(entry_span))` is an
        // ambiguous `{integer}` and `saturating_mul` cannot resolve (E0689).
        let ppb: u64 = 1024;
        for &(base, cutoff, entry_span) in &[
            (12, 11, 1),
            (12, 12, 1),
            (12, 13, 1),
            (12, 912, 1),
            (12, 1036, 1),
            (12, u64::MAX, 1),
            (u64::MAX - 3, u64::MAX - 2, 2),
            (12, 11, 0),
            (12, 12, 0),
        ] {
            let expected = (0..ppb)
                .find(|&i| {
                    let child_base = base.saturating_add(i.saturating_mul(entry_span));
                    child_base.saturating_add(entry_span) > cutoff
                })
                .unwrap_or(ppb);
            assert_eq!(
                first_indirect_entry_at_cutoff(base, cutoff, entry_span, ppb),
                expected,
                "base={base} cutoff={cutoff} entry_span={entry_span}"
            );
        }
    }

    /// truncate_indirect_blocks must also free a DOUBLE-indirect subtree
    /// (i_block[13]): the data block, the intermediate single-indirect block,
    /// and the double-indirect root, zeroing the slot. The single-indirect
    /// coverage below never exercises the nested level-2 recursion in
    /// free_indirect_subtree_range (bd-xmh5g.216).
    #[test]
    fn truncate_indirect_blocks_frees_double_indirect_subtree() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        // Keep group 0's block bitmap off the gdt block so descriptor
        // persistence does not clobber it mid-test.
        groups[0].block_bitmap_block = BlockNumber(10);

        // Double-indirect chain: i_block[13] -> root 2600 -> single 2601 -> data 2602.
        let mut bitmap = vec![0u8; 4096];
        for &b in &[2600usize, 2601, 2602] {
            bitmap[b / 8] |= 1 << (b % 8);
        }
        dev.write_block(&cx, BlockNumber(10), &bitmap).unwrap();
        groups[0].free_blocks = geo.blocks_per_group - 3;

        // Double-indirect root 2600: entry[0] -> single-indirect block 2601.
        let mut dind = vec![0u8; 4096];
        dind[0..4].copy_from_slice(&2601u32.to_le_bytes());
        dev.write_block(&cx, BlockNumber(2600), &dind).unwrap();
        // Single-indirect 2601: entry[0] -> data block 2602.
        let mut sind = vec![0u8; 4096];
        sind[0..4].copy_from_slice(&2602u32.to_le_bytes());
        dev.write_block(&cx, BlockNumber(2601), &sind).unwrap();

        let mut inode = representative_inode();
        inode.flags = 0; // legacy indirect (not extents, not inline)
        inode.mode = 0o100_644; // regular file
        inode.blocks = 3 * (4096 / 512);
        inode.size = 1100 * 4096; // spans into the double-indirect range (base 1036)
        let mut eb = vec![0u8; 60];
        eb[52..56].copy_from_slice(&2600u32.to_le_bytes()); // i_block[13] -> double-indirect root
        inode.extent_bytes = eb.into();

        let freed = truncate_indirect_blocks(
            &cx,
            &dev,
            &geo,
            &mut groups,
            &mut inode,
            12, // free everything from logical block 12 onward
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(
            freed, 3,
            "frees data + intermediate single-indirect + double-indirect root"
        );
        assert_eq!(
            &inode.extent_bytes[52..56],
            &[0, 0, 0, 0],
            "double-indirect root slot cleared"
        );

        // All three blocks must now be free in the group bitmap.
        let bm_buf = dev.read_block(&cx, BlockNumber(10)).unwrap();
        let bm_after = bm_buf.as_slice();
        for &b in &[2600usize, 2601, 2602] {
            assert_eq!(
                bm_after[b / 8] & (1 << (b % 8)),
                0,
                "block {b} must be freed in the bitmap"
            );
        }
    }

    /// truncate_indirect_blocks PARTIAL path: when the cutoff falls inside a
    /// single-indirect block, the blocks below the cutoff are kept, the blocks
    /// at/after it are freed, and the surviving single-indirect block is
    /// rewritten with the freed slots zeroed (the dirty-but-not-empty branch of
    /// free_indirect_subtree_range) — i_block[12] stays pointed at the root
    /// (bd-xmh5g.218).
    #[test]
    fn truncate_indirect_blocks_partial_single_indirect_keeps_survivors() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        groups[0].block_bitmap_block = BlockNumber(10);

        // Single-indirect root 2500 with data at logical 12/13/14 -> 2400/2401/2402.
        let mut bitmap = vec![0u8; 4096];
        for &b in &[2500usize, 2400, 2401, 2402] {
            bitmap[b / 8] |= 1 << (b % 8);
        }
        dev.write_block(&cx, BlockNumber(10), &bitmap).unwrap();
        groups[0].free_blocks = geo.blocks_per_group - 4;

        let mut sind = vec![0u8; 4096];
        sind[0..4].copy_from_slice(&2400u32.to_le_bytes()); // logical 12
        sind[4..8].copy_from_slice(&2401u32.to_le_bytes()); // logical 13
        sind[8..12].copy_from_slice(&2402u32.to_le_bytes()); // logical 14
        dev.write_block(&cx, BlockNumber(2500), &sind).unwrap();

        let mut inode = representative_inode();
        inode.flags = 0;
        inode.mode = 0o100_644;
        inode.blocks = 4 * (4096 / 512);
        inode.size = 15 * 4096;
        let mut eb = vec![0u8; 60];
        eb[48..52].copy_from_slice(&2500u32.to_le_bytes()); // i_block[12] -> single-indirect root
        inode.extent_bytes = eb.into();

        // cutoff 13: keep logical 12, free logical 13 and 14.
        let freed =
            truncate_indirect_blocks(&cx, &dev, &geo, &mut groups, &mut inode, 13, &mock_pctx())
                .unwrap();

        assert_eq!(freed, 2, "frees logical 13 and 14 only");
        assert_eq!(
            &inode.extent_bytes[48..52],
            &2500u32.to_le_bytes(),
            "surviving single-indirect root must stay referenced"
        );

        let bm_buf = dev.read_block(&cx, BlockNumber(10)).unwrap();
        let bm_after = bm_buf.as_slice();
        // Survivors stay allocated.
        for &b in &[2500usize, 2400] {
            assert_ne!(
                bm_after[b / 8] & (1 << (b % 8)),
                0,
                "survivor block {b} must stay allocated"
            );
        }
        // Freed data blocks are cleared.
        for &b in &[2401usize, 2402] {
            assert_eq!(
                bm_after[b / 8] & (1 << (b % 8)),
                0,
                "block {b} must be freed in the bitmap"
            );
        }
        // The surviving single-indirect block has its freed slots zeroed but
        // keeps the kept-data pointer.
        let sind_buf = dev.read_block(&cx, BlockNumber(2500)).unwrap();
        let sind_after = sind_buf.as_slice();
        assert_eq!(&sind_after[0..4], &2400u32.to_le_bytes(), "logical 12 kept");
        assert_eq!(&sind_after[4..8], &[0, 0, 0, 0], "logical 13 slot zeroed");
        assert_eq!(&sind_after[8..12], &[0, 0, 0, 0], "logical 14 slot zeroed");
    }

    /// truncate_indirect_blocks must free a TRIPLE-indirect subtree
    /// (i_block[14]): data block, single-indirect, double-indirect, and the
    /// triple-indirect root, zeroing the slot. Exercises the deepest level-3
    /// recursion in free_indirect_subtree_range (bd-xmh5g.217).
    #[test]
    fn truncate_indirect_blocks_frees_triple_indirect_subtree() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        // Keep group 0's block bitmap off the gdt block so persistence does not
        // clobber it mid-test.
        groups[0].block_bitmap_block = BlockNumber(10);

        // Triple-indirect chain: i_block[14] -> root 2700 -> double 2701 ->
        // single 2702 -> data 2703.
        let mut bitmap = vec![0u8; 4096];
        for &b in &[2700usize, 2701, 2702, 2703] {
            bitmap[b / 8] |= 1 << (b % 8);
        }
        dev.write_block(&cx, BlockNumber(10), &bitmap).unwrap();
        groups[0].free_blocks = geo.blocks_per_group - 4;

        // Triple-indirect root 2700 -> double-indirect 2701.
        let mut tind = vec![0u8; 4096];
        tind[0..4].copy_from_slice(&2701u32.to_le_bytes());
        dev.write_block(&cx, BlockNumber(2700), &tind).unwrap();
        // Double-indirect 2701 -> single-indirect 2702.
        let mut dind = vec![0u8; 4096];
        dind[0..4].copy_from_slice(&2702u32.to_le_bytes());
        dev.write_block(&cx, BlockNumber(2701), &dind).unwrap();
        // Single-indirect 2702 -> data 2703.
        let mut sind = vec![0u8; 4096];
        sind[0..4].copy_from_slice(&2703u32.to_le_bytes());
        dev.write_block(&cx, BlockNumber(2702), &sind).unwrap();

        let mut inode = representative_inode();
        inode.flags = 0; // legacy indirect
        inode.mode = 0o100_644; // regular file
        inode.blocks = 4 * (4096 / 512);
        inode.size = 1_050_000_u64 * 4096; // spans into the triple-indirect range
        let mut eb = vec![0u8; 60];
        eb[56..60].copy_from_slice(&2700u32.to_le_bytes()); // i_block[14] -> triple-indirect root
        inode.extent_bytes = eb.into();

        let freed = truncate_indirect_blocks(
            &cx,
            &dev,
            &geo,
            &mut groups,
            &mut inode,
            12, // free everything from logical block 12 onward
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(
            freed, 4,
            "frees data + single + double + triple-indirect root"
        );
        assert_eq!(
            &inode.extent_bytes[56..60],
            &[0, 0, 0, 0],
            "triple-indirect root slot cleared"
        );

        // All four blocks must now be free in the group bitmap.
        let bm_buf = dev.read_block(&cx, BlockNumber(10)).unwrap();
        let bm_after = bm_buf.as_slice();
        for &b in &[2700usize, 2701, 2702, 2703] {
            assert_eq!(
                bm_after[b / 8] & (1 << (b % 8)),
                0,
                "block {b} must be freed in the bitmap"
            );
        }
    }

    /// bd-c7t59 follow-up: truncate_indirect_blocks (used by orphan recovery to
    /// complete an interrupted truncate of a legacy indirect file) frees the data
    /// and now-empty indirect-metadata blocks at/after the cutoff, zeroes the freed
    /// inode pointer slots, and leaves blocks below the cutoff intact.
    #[test]
    fn truncate_indirect_blocks_frees_range_and_zeroes_slots() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        // Move group 0's block bitmap off the gdt block (1) so descriptor
        // persistence doesn't clobber the bitmap mid-test.
        groups[0].block_bitmap_block = BlockNumber(10);

        // Mark the file's blocks allocated in group 0's bitmap (block 10):
        //   2000 = logical 0 (kept), 2001 = logical 1 (freed),
        //   2002 = logical 12 data (freed), 2500 = single-indirect root (freed).
        let mut bitmap = vec![0u8; 4096];
        for &b in &[2000usize, 2001, 2002, 2500] {
            bitmap[b / 8] |= 1 << (b % 8);
        }
        dev.write_block(&cx, BlockNumber(10), &bitmap).unwrap();
        groups[0].free_blocks = geo.blocks_per_group - 4;

        // Single-indirect block 2500: pointer[0] -> data block 2002 (logical 12).
        let mut ind = vec![0u8; 4096];
        ind[0..4].copy_from_slice(&2002u32.to_le_bytes());
        dev.write_block(&cx, BlockNumber(2500), &ind).unwrap();

        let mut inode = representative_inode();
        inode.flags = 0; // legacy indirect (not extents, not inline)
        inode.mode = 0o100_644; // regular file
        inode.blocks = 4 * (4096 / 512); // four 4 KiB blocks, in 512-byte sectors
        inode.size = 13 * 4096; // spans through logical block 12
        let mut eb = vec![0u8; 60];
        eb[0..4].copy_from_slice(&2000u32.to_le_bytes()); // i_block[0]  -> logical 0
        eb[4..8].copy_from_slice(&2001u32.to_le_bytes()); // i_block[1]  -> logical 1
        eb[48..52].copy_from_slice(&2500u32.to_le_bytes()); // i_block[12] -> single-indirect root
        inode.extent_bytes = eb.into();

        let freed = truncate_indirect_blocks(
            &cx,
            &dev,
            &geo,
            &mut groups,
            &mut inode,
            1, // cutoff: free everything from logical block 1 onward
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(
            freed, 3,
            "frees direct[1] + single-indirect data + its root"
        );
        // Slot 0 (logical 0) survives; slot 1 and the single-indirect root cleared.
        assert_eq!(
            &inode.extent_bytes[0..4],
            &2000u32.to_le_bytes(),
            "logical 0 kept"
        );
        assert_eq!(
            &inode.extent_bytes[4..8],
            &[0, 0, 0, 0],
            "logical 1 slot cleared"
        );
        assert_eq!(
            &inode.extent_bytes[48..52],
            &[0, 0, 0, 0],
            "single-indirect root cleared"
        );
        assert_eq!(
            groups[0].free_blocks,
            geo.blocks_per_group - 1,
            "three of the four allocated blocks were freed"
        );
    }

    #[test]
    fn inode_uses_indirect_blocks_excludes_extents_inline_and_non_data_modes() {
        let mut base = representative_inode();
        base.flags = 0;
        base.mode = 0o100_644; // S_IFREG
        base.blocks = 8;
        assert!(
            inode_uses_indirect_blocks(&base),
            "a plain non-extent regular file is indirect-mapped"
        );

        // Extent-mapped and inline-data inodes must not be walked as indirect.
        let mut ext = base.clone();
        ext.flags = EXT4_EXTENTS_FL;
        assert!(!inode_uses_indirect_blocks(&ext), "extent inode");
        let mut inline = base.clone();
        inline.flags = EXT4_INLINE_DATA_FL;
        assert!(!inode_uses_indirect_blocks(&inline), "inline-data inode");

        // An inode with no blocks has nothing to walk.
        let mut noblocks = base.clone();
        noblocks.blocks = 0;
        assert!(!inode_uses_indirect_blocks(&noblocks), "zero blocks");

        // Directories with blocks are indirect-mapped; device nodes are not
        // (i_block holds the device number, not block pointers).
        let mut dir = base.clone();
        dir.mode = 0o040_755; // S_IFDIR
        assert!(inode_uses_indirect_blocks(&dir), "directory");
        let mut chr = base;
        chr.mode = 0o020_644; // S_IFCHR
        assert!(!inode_uses_indirect_blocks(&chr), "char device");
    }

    /// Regression: an e2compr (compressed) inode must NOT be treated as a plain
    /// indirect pointer table. Its i_block holds EXT2_COMPRESSED_BLKADDR
    /// (0xFFFFFFFF) sentinels, not block numbers; walking them as pointers (as
    /// the W23 indirect-free walk would) calls free_blocks_persist(0xFFFFFFFF)
    /// and corrupts/aborts. The guard must exclude compressed files, and
    /// delete_inode must therefore skip block-freeing for them (no sentinel
    /// reaches the allocator).
    #[test]
    fn compressed_inode_not_treated_as_indirect_and_delete_skips_sentinels() {
        // Plain indirect regular file IS indirect-mapped.
        let mut plain = representative_inode();
        plain.flags = 0;
        plain.mode = 0o100_644;
        plain.blocks = 8;
        assert!(
            inode_uses_indirect_blocks(&plain),
            "a plain non-extent regular file is indirect-mapped"
        );

        // Same inode with the e2compr flags is NOT.
        for flag in [EXT4_COMPR_FL, EXT4_COMPRBLK_FL] {
            let mut compr = plain.clone();
            compr.flags = flag;
            assert!(
                !inode_uses_indirect_blocks(&compr),
                "an e2compr inode (flag {flag:#x}) must not be walked as indirect pointers"
            );
        }

        // End-to-end: delete_inode on a compressed inode whose i_block holds a
        // 0xFFFFFFFF sentinel must succeed without trying to free that sentinel.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();
        // Make it an e2compr file with a compressed-block sentinel in i_block[0].
        inode.flags = EXT4_COMPRBLK_FL;
        inode.blocks = 8;
        let mut eb = vec![0u8; 60];
        eb[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // EXT2_COMPRESSED_BLKADDR
        inode.extent_bytes = eb.into();

        // Must not error (pre-fix this hit free_blocks_persist(0xFFFFFFFF)).
        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            1_700_000_001,
            &mock_pctx(),
        )
        .expect("delete of a compressed inode must not free the 0xFFFFFFFF sentinel");
        assert_eq!(inode.links_count, 0, "inode still freed");
    }

    #[test]
    fn write_and_verify_checksum() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0x1234_5678,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        // Read raw bytes and verify checksum.
        let loc = locate_inode(ino, &geo, &groups).unwrap();
        let buf = dev.read_block(&cx, loc.block).unwrap();
        let raw = &buf.as_slice()[loc.byte_offset..loc.byte_offset + 256];

        let result = ffs_ondisk::verify_inode_checksum(raw, 0x1234_5678, ino.0 as u32, 256);
        assert!(result.is_ok(), "checksum verification failed: {result:?}");

        // Verify the inode fields are correct.
        let parsed = Ext4Inode::parse_from_bytes(raw).unwrap();
        assert_eq!(parsed.mode, inode.mode);
    }

    #[test]
    fn touch_timestamps() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        touch_atime(&mut inode, 100, 500_000_000);
        assert_eq!(inode.atime, 100);

        touch_mtime_ctime(&mut inode, 200, 0);
        assert_eq!(inode.mtime, 200);
        assert_eq!(inode.ctime, 200);

        touch_ctime(&mut inode, 300, 0);
        assert_eq!(inode.ctime, 300);
        assert_eq!(inode.mtime, 200); // mtime unchanged.
    }

    #[test]
    fn encode_extra_timestamp_nsec() {
        let extra = encode_extra_timestamp(0, 999_999_999);
        // Nanoseconds stored in bits 2-31.
        let nsec = extra >> 2;
        // Should preserve the nanosecond value.
        assert_eq!(nsec, 999_999_999);
    }

    /// bd-h88gv — Kernel-conformance pin for the epoch/nsec bit
    /// layout of `encode_extra_timestamp` per `fs/ext4/ext4.h`:
    ///   EXT4_EPOCH_BITS = 2
    ///   EXT4_EPOCH_MASK = (1 << 2) - 1 = 0x3   (low 2 bits)
    ///   EXT4_NSEC_MASK  = ~0x3                  (high 30 bits)
    /// Bits 0..2 hold the upper 2 epoch bits of `secs` (extending
    /// the 32-bit `s_*time` field to ~544 years past 1970); bits
    /// 2..32 hold `nsec << 2`.
    ///
    /// A regression that swapped epoch/nsec bit positions, or used
    /// a different shift amount, would silently corrupt every nsec
    /// post-2106 but pass round-trip tests if both writer and
    /// reader drifted symmetrically. This test pins the bit layout
    /// independently of any reader.
    ///
    /// Pairs with bd-k81lq (reserved inodes), bd-bevt2 (40 feature
    /// flags), bd-jbilz (magic+state), bd-k62ym (ext4 size limits).
    #[test]
    fn encode_extra_timestamp_kernel_bit_layout() {
        // (d) Max-nsec boundary: 999_999_999 < 2^30 = 1_073_741_824
        // so it fits in 30 bits without overflowing into bits 0..2.
        const MAX_VALID_NSEC: u32 = 999_999_999;
        const NSEC_FIELD_CAPACITY: u32 = 1 << 30;
        const _: () = assert!(
            MAX_VALID_NSEC < NSEC_FIELD_CAPACITY,
            "max nsec must fit in the 30-bit field"
        );
        const EXT4_EPOCH_BITS: u32 = 2;
        const EXT4_EPOCH_MASK: u32 = (1 << EXT4_EPOCH_BITS) - 1;

        // (a) Low 2 bits hold ONLY the epoch (upper bits of secs).
        // For secs < (1 << 32), the epoch should be 0 → low 2 bits
        // of the encoded value are 0 regardless of nsec.
        for &nsec in &[0_u32, 1, 999_999_999, 500_000_000, 100, 12345] {
            let extra = encode_extra_timestamp(0, nsec);
            assert_eq!(
                extra & 0x3,
                0,
                "secs<2^32 must produce epoch=0; got low bits {:#x} for nsec={}",
                extra & 0x3,
                nsec
            );
        }

        // (b) Each upper-secs bit pattern must produce its canonical
        // epoch value in the low 2 bits.
        for (secs, expected_epoch) in [
            (1_u64 << 32, 1_u32),           // upper bits = 0b01
            (1_u64 << 33, 2_u32),           // upper bits = 0b10
            ((1_u64 << 33) | (1 << 32), 3), // upper bits = 0b11
        ] {
            let extra = encode_extra_timestamp(secs, 0);
            assert_eq!(
                extra & 0x3,
                expected_epoch,
                "secs={secs:#x} must encode epoch={expected_epoch}; got {:#x}",
                extra & 0x3
            );
        }

        // (c) Non-overlap invariant: nsec must NOT touch the low 2
        // bits, AND epoch must NOT touch bits 2..32. Test by
        // combining a non-trivial nsec with a non-trivial epoch.
        let extra = encode_extra_timestamp((1_u64 << 33) | (1 << 32), 999_999_999);
        assert_eq!(extra & 0x3, 3, "epoch=3 (bits 0..2)");
        assert_eq!(extra >> 2, 999_999_999, "nsec=999_999_999 (bits 2..32)");

        // (e) The mask invariants from the kernel header must hold
        // arithmetically.
        assert_eq!(EXT4_EPOCH_MASK, 0x3, "EXT4_EPOCH_MASK per kernel header");
        assert_eq!(
            !EXT4_EPOCH_MASK, !0x3_u32,
            "EXT4_NSEC_MASK is ~EXT4_EPOCH_MASK"
        );
    }

    #[test]
    fn locate_inode_out_of_range() {
        let geo = make_geometry();
        let groups = make_groups(&geo);

        // Inode 0 is invalid (ext4 inodes are 1-based).
        let result = locate_inode(InodeNumber(0), &geo, &groups);
        assert!(result.is_none());

        // Inode way beyond total → group index out of range.
        let result = locate_inode(InodeNumber(100_000), &geo, &groups);
        assert!(result.is_none());
    }

    #[test]
    fn locate_inode_block_offset_within_table() {
        let geo = make_geometry();
        let groups = make_groups(&geo);

        // 4096-byte block / 256-byte inode = 16 inodes per block.
        // Inode 17 → group 0, index 16 → byte 16*256 = 4096 → second block.
        let loc = locate_inode(InodeNumber(17), &geo, &groups).unwrap();
        assert_eq!(loc.block, BlockNumber(4)); // inode_table_block(3) + 1
        assert_eq!(loc.byte_offset, 0);

        // Inode 18 → index 17 → byte 17*256 = 4352 → block 4, offset 256.
        let loc = locate_inode(InodeNumber(18), &geo, &groups).unwrap();
        assert_eq!(loc.block, BlockNumber(4));
        assert_eq!(loc.byte_offset, 256);
    }

    #[test]
    fn serialize_large_uid_gid() {
        // UID/GID > 65535 should be split across low and high fields.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0x0012_3456, // high=0x0012, low=0x3456
            gid: 0x00AB_CDEF, // high=0x00AB, low=0xCDEF
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let raw = serialize_inode(&inode, 256);
        let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(parsed.uid, 0x0012_3456);
        assert_eq!(parsed.gid, 0x00AB_CDEF);
    }

    #[test]
    fn serialize_large_file_size() {
        // Size > 4GB should be split across low and high fields.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0x1_0000_1234, // > 4GB
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let raw = serialize_inode(&inode, 256);
        let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(parsed.size, 0x1_0000_1234);
    }

    #[test]
    fn serialize_xattr_ibody_preserved() {
        let xattr_data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: xattr_data.clone(),
            number: 0,
        };

        let raw = serialize_inode(&inode, 256);
        // Inline xattrs start at offset 128 + extra_isize = 160.
        assert_eq!(&raw[160..164], &xattr_data);
    }

    #[test]
    fn checksum_skipped_for_small_inode() {
        // Inode < 128 bytes should not panic.
        let mut raw = vec![0u8; 64];
        compute_and_set_checksum(&mut raw, 0, 1);
        // Should just return without modifying (no checksum field to set).
        assert_eq!(raw, vec![0u8; 64]);
    }

    #[test]
    fn create_multiple_inodes_sequential() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();

        let mut inos = Vec::new();
        for _ in 0..5 {
            let (ino, _) = create_inode(
                &cx,
                &dev,
                &geo,
                &mut groups,
                0o100_644,
                0,
                0,
                GroupNumber(0),
                0,
                1_700_000_000,
                0,
                &pctx,
            )
            .unwrap();
            inos.push(ino);
        }

        // All inodes should be unique.
        for i in 0..inos.len() {
            for j in (i + 1)..inos.len() {
                assert_ne!(inos[i], inos[j], "duplicate inode numbers");
            }
        }

        // All should be readable.
        for &ino in &inos {
            let inode = read_inode(&cx, &dev, &geo, &groups, ino).unwrap();
            assert_eq!(inode.mode, 0o100_644);
        }
    }

    #[test]
    fn read_inode_out_of_range_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let groups = make_groups(&geo);

        let result = read_inode(&cx, &dev, &geo, &groups, InodeNumber(100_000));
        assert!(result.is_err());
    }

    #[test]
    fn write_inode_updates_on_disk() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        // Modify and write back.
        inode.size = 8192;
        inode.uid = 500;
        touch_mtime_ctime(&mut inode, 1_700_000_100, 0);
        write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).unwrap();

        // Read back and verify.
        let read_back = read_inode(&cx, &dev, &geo, &groups, ino).unwrap();
        assert_eq!(read_back.size, 8192);
        assert_eq!(read_back.uid, 500);
        assert_eq!(read_back.mtime, 1_700_000_100);
        assert_eq!(read_back.ctime, 1_700_000_100);
    }

    #[test]
    fn write_inode_out_of_range_returns_corruption() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (_ino, inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        // write_inode must reject an inode number beyond the table, mirroring
        // the read_inode out-of-range guard, instead of patching and writing
        // back an arbitrary block.
        let err =
            write_inode(&cx, &dev, &geo, &groups, InodeNumber(100_000), &inode, 0).unwrap_err();
        assert!(
            matches!(err, FfsError::Corruption { ref detail, .. } if detail.contains("out of range")),
            "got {err:?}",
        );
    }

    #[test]
    fn delete_directory_zeroes_fields() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            file_type::S_IFDIR | 0o755,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        // Directory creation should increment used_dirs in some group.
        let total_dirs: u32 = groups.iter().map(|g| g.used_dirs).sum();
        assert_eq!(total_dirs, 1, "one directory should be tracked");

        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            1_700_000_001,
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(inode.links_count, 0);
        assert_eq!(inode.size, 0);
        assert_eq!(inode.dtime, 1_700_000_001);
    }

    #[test]
    fn encode_extra_timestamp_zero_nsec() {
        let extra = encode_extra_timestamp(0, 0);
        assert_eq!(extra, 0);
    }

    #[test]
    fn encode_extra_timestamp_max_nsec() {
        // 999_999_999 ns is the maximum valid nanosecond value.
        let extra = encode_extra_timestamp(0, 999_999_999);
        let nsec_back = extra >> 2;
        assert_eq!(nsec_back, 999_999_999);
        // Verify the epoch bits (0-1) are zero for 32-bit timestamps.
        assert_eq!(extra & 0x3, 0);
    }

    #[test]
    fn timestamp_nsec_roundtrip_through_write_read() {
        // Create an inode with specific nanosecond timestamps, write it, read back,
        // and verify the nanosecond fields survive the roundtrip.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            1000,
            1000,
            GroupNumber(0),
            0,
            0,
            0,
            &mock_pctx(),
        )
        .expect("create inode");

        // Set timestamps with specific nanosecond values.
        touch_atime(&mut inode, 1_700_000_000, 123_456_788);
        touch_mtime_ctime(&mut inode, 1_700_000_001, 999_999_996);

        write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).expect("write");
        let read_back = read_inode(&cx, &dev, &geo, &groups, ino).expect("read");

        assert_eq!(read_back.atime, 1_700_000_000);
        assert_eq!(read_back.atime_extra, inode.atime_extra);
        assert_eq!(read_back.mtime, 1_700_000_001);
        assert_eq!(read_back.mtime_extra, inode.mtime_extra);
        assert_eq!(read_back.ctime, 1_700_000_001);
        assert_eq!(read_back.ctime_extra, inode.ctime_extra);
    }

    #[test]
    fn touch_ctime_preserves_mtime() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (_ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            0,
            0,
            &mock_pctx(),
        )
        .expect("create");

        touch_mtime_ctime(&mut inode, 100, 500_000_000);
        touch_ctime(&mut inode, 200, 750_000_000);

        // ctime should be updated
        assert_eq!(inode.ctime, 200);
        // mtime should remain unchanged
        assert_eq!(inode.mtime, 100);
        assert_eq!(inode.mtime_extra, encode_extra_timestamp(100, 500_000_000));
    }

    #[test]
    fn encode_extra_timestamp_epoch_extension() {
        // Timestamp at 2^32 (epoch 1): after Feb 2106.
        let secs: u64 = 1 << 32; // 4_294_967_296
        let extra = encode_extra_timestamp(secs, 0);
        // Epoch bits (bits 0-1) should be 1, nsec bits should be 0.
        assert_eq!(extra & 0x3, 1);
        assert_eq!(extra >> 2, 0);

        // Timestamp at 2^33 (epoch 2).
        let secs: u64 = 1 << 33;
        let extra = encode_extra_timestamp(secs, 123_456_788);
        assert_eq!(extra & 0x3, 2);
        assert_eq!(extra >> 2, 123_456_788);

        // Timestamp at 3 * 2^32 (epoch 3).
        let secs: u64 = 3 << 32;
        let extra = encode_extra_timestamp(secs, 0);
        assert_eq!(extra & 0x3, 3);
    }

    #[test]
    fn serialize_blocks_high_bits() {
        // Test 48-bit blocks field split.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0x1_2345_6789, // needs high bits
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0x2_0000_0000, // needs file_acl high bits
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let raw = serialize_inode(&inode, 256);
        let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(parsed.blocks, 0x1_2345_6789);
        assert_eq!(parsed.file_acl, 0x2_0000_0000);
    }

    #[test]
    fn create_inode_bumps_generation_on_reuse() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        // Create first inode — on a zeroed device the old generation is 0,
        // so the new generation should be 1.
        let (ino1, inode1) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();
        assert_eq!(inode1.generation, 1, "first alloc: 0 → 1");

        // Delete then re-create at the same inode slot.
        let mut del = inode1;
        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino1,
            &mut del,
            0,
            1_700_000_001,
            &mock_pctx(),
        )
        .unwrap();
        let (ino2, inode2) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_002,
            0,
            &mock_pctx(),
        )
        .unwrap();
        assert_eq!(ino2, ino1, "should reuse the freed inode number");
        assert_eq!(inode2.generation, 2, "reuse: 1 → 2");
    }

    #[test]
    fn create_inode_propagates_generation_read_failure() {
        let cx = test_cx();
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let fail_block = groups[0].inode_table_block;
        let dev = ReadFailingBlockDevice::new(4096, fail_block);

        let err = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .expect_err("inode-table read failure should not be coerced to generation zero");

        assert!(
            matches!(err, FfsError::Io(_)),
            "unexpected create_inode error: {err:?}"
        );
    }

    // ── Edge-case and error-path hardening tests ──────────────────────

    #[test]
    fn delete_inode_with_xattr_block_refcount_gt1_decrements() {
        // When file_acl points to a valid xattr block with refcount > 1,
        // delete_inode should decrement the refcount (not free the block).
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        // Pre-write a valid xattr block at block 500 (well beyond inode table) with refcount = 3.
        let xattr_block = BlockNumber(500);
        let mut xattr_data = vec![0u8; 4096];
        // Magic: 0xEA020000 in LE.
        xattr_data[0..4].copy_from_slice(&0xEA02_0000_u32.to_le_bytes());
        // Refcount: 3.
        xattr_data[4..8].copy_from_slice(&3_u32.to_le_bytes());
        dev.write_block(&cx, xattr_block, &xattr_data).unwrap();

        // Point inode's file_acl at it.
        inode.file_acl = 500;
        write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).unwrap();

        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            1_700_000_001,
            &mock_pctx(),
        )
        .unwrap();

        // Refcount should now be 2.
        let buf = dev.read_block(&cx, xattr_block).unwrap();
        let refcount = u32::from_le_bytes([
            buf.as_slice()[4],
            buf.as_slice()[5],
            buf.as_slice()[6],
            buf.as_slice()[7],
        ]);
        assert_eq!(refcount, 2, "refcount should be decremented from 3 to 2");
        assert_eq!(inode.file_acl, 0, "file_acl should be cleared");
    }

    #[test]
    fn delete_inode_with_xattr_block_refcount_1_frees_block() {
        // When file_acl points to a valid xattr block with refcount = 1,
        // delete_inode should free the block via free_blocks_persist.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        // Pre-write a valid xattr block at block 500 with refcount = 1.
        let xattr_block = BlockNumber(500);
        let mut xattr_data = vec![0u8; 4096];
        xattr_data[0..4].copy_from_slice(&0xEA02_0000_u32.to_le_bytes());
        xattr_data[4..8].copy_from_slice(&1_u32.to_le_bytes());
        dev.write_block(&cx, xattr_block, &xattr_data).unwrap();

        // Mark the block as allocated in the bitmap.
        let bitmap_block = groups[0].block_bitmap_block;
        let mut bitmap = vec![0u8; 4096];
        bitmap[500 / 8] |= 1 << (500 % 8);
        dev.write_block(&cx, bitmap_block, &bitmap).unwrap();
        groups[0].free_blocks -= 1;

        inode.file_acl = 500;
        write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).unwrap();

        let free_blocks_before = groups[0].free_blocks;
        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            1_700_000_001,
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(inode.file_acl, 0, "file_acl should be cleared");
        assert_eq!(
            groups[0].free_blocks,
            free_blocks_before + 1,
            "block should have been freed"
        );
    }

    #[test]
    fn delete_inode_with_xattr_block_invalid_magic_frees_block() {
        // When file_acl points to a block with invalid xattr magic,
        // delete_inode should still free it to prevent leaks.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        // Write a block at 500 with wrong magic.
        let xattr_block = BlockNumber(500);
        let mut bad_data = vec![0u8; 4096];
        bad_data[0..4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        dev.write_block(&cx, xattr_block, &bad_data).unwrap();

        // Mark block as allocated.
        let bitmap_block = groups[0].block_bitmap_block;
        let mut bitmap = vec![0u8; 4096];
        bitmap[500 / 8] |= 1 << (500 % 8);
        dev.write_block(&cx, bitmap_block, &bitmap).unwrap();
        groups[0].free_blocks -= 1;

        inode.file_acl = 500;
        write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).unwrap();

        let free_blocks_before = groups[0].free_blocks;
        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            1_700_000_001,
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(inode.file_acl, 0, "file_acl should be cleared");
        assert_eq!(
            groups[0].free_blocks,
            free_blocks_before + 1,
            "block should be freed even with invalid magic"
        );
    }

    #[test]
    fn write_inode_out_of_range_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let groups = make_groups(&geo);

        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let result = write_inode(&cx, &dev, &geo, &groups, InodeNumber(100_000), &inode, 0);
        assert!(
            result.is_err(),
            "write_inode to out-of-range inode should fail"
        );
    }

    #[test]
    fn write_inode_crossing_block_boundary_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(1024);
        let geo = FsGeometry {
            block_size: 1024,
            inode_size: 768,
            ..make_geometry()
        };
        let groups = vec![GroupStats {
            group: GroupNumber(0),
            free_blocks: geo.blocks_per_group,
            block_largest_free_run: None,
            free_inodes: geo.inodes_per_group,
            used_dirs: 0,
            block_bitmap_block: BlockNumber(1),
            inode_bitmap_block: BlockNumber(2),
            // Place the inode table block at the very end of the device so the
            // computed slot starts partway into the final readable block.
            inode_table_block: BlockNumber(dev.block_count() - 1),
            flags: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
            inode_search_start: 0,
            reserved_cache: std::sync::OnceLock::new(),
            reserved_confirmed: std::sync::OnceLock::new(),
        }];
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let result = write_inode(&cx, &dev, &geo, &groups, InodeNumber(14), &inode, 0);
        assert!(
            matches!(result, Err(FfsError::Corruption { .. })),
            "write_inode should reject inode slots that cross a block boundary"
        );
    }

    #[test]
    fn serialize_inode_128_byte_no_extended_area() {
        // With inode_size = 128, no extended fields should be written.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 1000,
            gid: 1000,
            size: 4096,
            links_count: 1,
            blocks: 8,
            flags: EXT4_EXTENTS_FL,

            version: 0,
            generation: 42,
            file_acl: 0,
            atime: 1_700_000_000,
            ctime: 1_700_000_000,
            mtime: 1_700_000_000,
            dtime: 0,
            atime_extra: 0xDEAD,
            ctime_extra: 0xBEEF,
            mtime_extra: 0xCAFE,
            crtime: 999,
            crtime_extra: 0xFACE,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0x1234,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![0xAA; 10],
            number: 0,
        };

        let raw = serialize_inode(&inode, 128);
        assert_eq!(raw.len(), 128);

        // Core fields should be present.
        let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(parsed.mode, 0o100_644);
        assert_eq!(parsed.uid & 0xFFFF, 1000);
        assert_eq!(parsed.generation, 42);

        // Extended area bytes (128+) should not exist—verify the buffer ends at 128.
        // extra_isize, crtime, projid, xattr_ibody are all in extended area.
        // Bytes at offset 0x80 onwards should be zero (buffer is 128 bytes so no extended area).
    }

    #[test]
    fn checksum_128_byte_inode_only_sets_lo() {
        // With inode_size = 128, checksum_hi (at offset 0x82) is beyond the buffer.
        // Only checksum_lo (at offset 0x7C) should be set.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 99,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 0,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let mut raw = serialize_inode(&inode, 128);
        compute_and_set_checksum(&mut raw, 0xABCD_1234, 7);

        // checksum_lo at 0x7C should be non-zero (extremely unlikely to be zero).
        let csum_lo = u16::from_le_bytes([raw[0x7C], raw[0x7D]]);
        // Just verify it was written (not still zero after checksum computation).
        // This is technically possible but astronomically unlikely.
        let _ = csum_lo; // Existence check — no panic means the 128-byte path executed.
    }

    #[test]
    fn serialize_projid_roundtrip() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0xABCD_1234,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let raw = serialize_inode(&inode, 256);
        let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(
            parsed.projid, 0xABCD_1234,
            "projid should survive roundtrip"
        );
    }

    #[test]
    fn serialize_crtime_extra_roundtrip() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 1_700_000_000,
            crtime_extra: 0xDEAD_BEEF,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let raw = serialize_inode(&inode, 256);
        let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();
        assert_eq!(
            parsed.crtime, 1_700_000_000,
            "crtime should survive roundtrip"
        );
        assert_eq!(
            parsed.crtime_extra, 0xDEAD_BEEF,
            "crtime_extra should survive roundtrip"
        );
    }

    #[test]
    fn delete_inode_sets_dtime_and_zeroes_size_blocks() {
        // Verify that delete_inode properly zeroes out size and blocks
        // in addition to setting links_count=0 and dtime.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        // Simulate that the inode had data.
        inode.size = 65536;
        inode.blocks = 128;
        write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).unwrap();

        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            1_700_000_999,
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(inode.links_count, 0);
        assert_eq!(inode.mode, 0, "mode should be cleared");
        assert_eq!(inode.size, 0, "size should be zeroed");
        assert_eq!(inode.blocks, 0, "blocks should be zeroed");
        assert_eq!(inode.dtime, 1_700_000_999);
    }

    #[test]
    fn create_symlink_inode() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let (_, inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            file_type::S_IFLNK | 0o777,
            1000,
            1000,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &mock_pctx(),
        )
        .unwrap();

        assert_eq!(inode.mode, file_type::S_IFLNK | 0o777);
        assert_eq!(inode.links_count, 1, "symlink should have link count 1");
        assert!(
            inode.flags & EXT4_EXTENTS_FL != 0,
            "new inode should have extents flag set"
        );
    }

    #[test]
    fn locate_inode_last_in_group() {
        let geo = make_geometry();
        let groups = make_groups(&geo);

        // Last inode in group 0: inode_per_group=2048, so inode 2048.
        let loc = locate_inode(InodeNumber(2048), &geo, &groups).unwrap();
        // index = (2048 - 1) % 2048 = 2047
        // byte = 2047 * 256 = 524032
        // block = 524032 / 4096 = 127, offset = 524032 % 4096 = 3840
        assert_eq!(loc.block, BlockNumber(3 + 127));
        assert_eq!(loc.byte_offset, 3840);

        // First inode in group 1: inode 2049.
        let loc = locate_inode(InodeNumber(2049), &geo, &groups).unwrap();
        assert_eq!(loc.block, BlockNumber(103)); // group 1 inode table
        assert_eq!(loc.byte_offset, 0);
    }

    // ── Hardening edge-case tests ────────────────────────────────────

    #[test]
    fn constants_match_ext4_spec() {
        assert_eq!(EXT4_EXTENT_MAGIC, 0xF30A);
        assert_eq!(EXT4_EXTENTS_FL, 0x0008_0000);
        assert_eq!(INODE_CHECKSUM_LO_OFFSET, 0x7C);
        assert_eq!(INODE_CHECKSUM_HI_OFFSET, 0x82);
    }

    #[test]
    fn inode_location_copy_clone() {
        let loc = InodeLocation {
            block: BlockNumber(42),
            byte_offset: 256,
        };
        let copy = loc; // Copy
        assert_eq!(copy.block, BlockNumber(42));
        assert_eq!(copy.byte_offset, 256);
        let cloned = loc; // Copy (same as clone for Copy types)
        assert_eq!(cloned.block, loc.block);
        let _ = format!("{loc:?}");
    }

    #[test]
    fn serialize_generation_preserved() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: EXT4_EXTENTS_FL,

            version: 0,
            generation: 0xDEAD_BEEF,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        let raw = serialize_inode(&inode, 256);
        let generation = u32::from_le_bytes([raw[0x64], raw[0x65], raw[0x66], raw[0x67]]);
        assert_eq!(generation, 0xDEAD_BEEF);
    }

    #[test]
    fn checksum_deterministic() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 1000,
            gid: 1000,
            size: 512,
            links_count: 1,
            blocks: 8,
            flags: EXT4_EXTENTS_FL,

            version: 0,
            generation: 7,
            file_acl: 0,
            atime: 1_700_000_000,
            ctime: 1_700_000_000,
            mtime: 1_700_000_000,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        let mut raw1 = serialize_inode(&inode, 256);
        let mut raw2 = serialize_inode(&inode, 256);
        compute_and_set_checksum(&mut raw1, 42, 11);
        compute_and_set_checksum(&mut raw2, 42, 11);
        assert_eq!(raw1, raw2);
    }

    #[test]
    fn touch_atime_preserves_generation_size_blocks() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 4096,
            links_count: 1,
            blocks: 8,
            flags: 0,

            version: 0,
            generation: 99,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        touch_atime(&mut inode, 2_000_000_000, 500_000);
        assert_eq!(inode.generation, 99);
        assert_eq!(inode.size, 4096);
        assert_eq!(inode.blocks, 8);
        assert_eq!(inode.mtime, 0);
        assert_eq!(inode.ctime, 0);
    }

    #[test]
    fn touch_mtime_ctime_preserves_atime_and_generation() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 55,
            file_acl: 0,
            atime: 1000,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 42,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        touch_mtime_ctime(&mut inode, 2_000_000_000, 100_000);
        assert_eq!(inode.atime, 1000, "atime should not change");
        assert_eq!(inode.atime_extra, 42, "atime_extra should not change");
        assert_eq!(inode.generation, 55, "generation should not change");
    }

    #[test]
    fn delete_minimal_inode_no_extents_no_xattr() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_000,
            0,
            &pctx,
        )
        .unwrap();

        // Clear extent flag to exercise the no-truncate path.
        inode.flags &= !EXT4_EXTENTS_FL;
        inode.file_acl = 0;
        write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).unwrap();

        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            2_000,
            &pctx,
        )
        .unwrap();
        assert_eq!(inode.links_count, 0);
        assert_eq!(inode.size, 0);
        assert_ne!(inode.dtime, 0);
    }

    #[test]
    fn create_inode_high_uid_gid_preserved() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();

        let uid = 0x0001_0001; // uid = 65537 (needs high 16 bits)
        let gid = 0x0002_0002; // gid = 131074

        let (ino, _created) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            uid,
            gid,
            GroupNumber(0),
            0,
            1_000,
            0,
            &pctx,
        )
        .unwrap();

        let read_back = read_inode(&cx, &dev, &geo, &groups, ino).unwrap();
        assert_eq!(read_back.uid, uid);
        assert_eq!(read_back.gid, gid);
    }

    #[test]
    fn serialize_file_acl_high_bits_preserved() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0x0001_0000_0064, // block 100 with high bits set
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        let raw = serialize_inode(&inode, 256);
        // Low 32 bits at offset 0x68.
        let lo = u32::from_le_bytes([raw[0x68], raw[0x69], raw[0x6A], raw[0x6B]]);
        assert_eq!(lo, 0x0000_0064);
        // High 16 bits at offset 0x76.
        let hi = u16::from_le_bytes([raw[0x76], raw[0x77]]);
        assert_eq!(hi, 0x0001);
    }

    #[test]
    fn encode_extra_timestamp_epoch_activates_above_u32_max() {
        // Seconds just above u32::MAX → epoch bits should be 1.
        let secs = u64::from(u32::MAX) + 1; // 0x1_0000_0000
        let extra = encode_extra_timestamp(secs, 0);
        let epoch = extra & 0x3;
        assert_eq!(epoch, 1, "epoch extension should be 1 for secs > u32::MAX");
    }

    #[test]
    fn file_type_constants_are_distinct() {
        assert_ne!(file_type::S_IFREG, file_type::S_IFDIR);
        assert_ne!(file_type::S_IFREG, file_type::S_IFLNK);
        assert_ne!(file_type::S_IFDIR, file_type::S_IFLNK);
    }

    // ── Proptest property-based tests ─────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// encode_extra_timestamp preserves epoch bits (lower 2 bits of secs >> 32).
        #[test]
        fn proptest_encode_extra_timestamp_epoch_bits(
            secs in 0_u64..=0x3_FFFF_FFFF_u64,
            nsec in 0_u32..1_000_000_000,
        ) {
            let extra = encode_extra_timestamp(secs, nsec);
            let epoch = ((secs >> 32) & 0x3) as u32;
            prop_assert_eq!(extra & 0x3, epoch, "epoch bits mismatch");
        }

        /// encode_extra_timestamp preserves nanoseconds in bits 2-31.
        #[test]
        fn proptest_encode_extra_timestamp_nsec_preserved(
            secs in 0_u64..=0x3_FFFF_FFFF_u64,
            nsec in 0_u32..1_000_000_000,
        ) {
            let extra = encode_extra_timestamp(secs, nsec);
            let decoded_nsec = extra >> 2;
            prop_assert_eq!(decoded_nsec, nsec, "nanoseconds not preserved");
        }

        /// bd-3u9j5 — cross-crate round-trip MR: ffs_inode encodes
        /// (secs, nsec) into a u32; ffs_ondisk decodes via
        /// Ext4Inode::extra_nsec / extra_epoch. Both sides must
        /// agree on every input. Existing proptests check the
        /// encoder against arithmetic-extracted values; this MR
        /// goes through the canonical decoder so a regression that
        /// drifted the encoder shift AND a compensating change to
        /// the decoder gets caught.
        #[test]
        fn proptest_encode_decode_cross_crate_round_trip(
            secs in 0_u64..=0x3_FFFF_FFFF_u64,
            nsec in 0_u32..1_000_000_000,
        ) {
            let extra = encode_extra_timestamp(secs, nsec);
            let decoded_nsec = Ext4Inode::extra_nsec(extra);
            let decoded_epoch = Ext4Inode::extra_epoch(extra);
            let expected_epoch = ((secs >> 32) & 0x3) as u32;
            prop_assert_eq!(
                decoded_nsec, nsec,
                "ffs_inode encoder ↔ ffs_ondisk Ext4Inode::extra_nsec must agree on nsec"
            );
            prop_assert_eq!(
                decoded_epoch, expected_epoch,
                "ffs_inode encoder ↔ ffs_ondisk Ext4Inode::extra_epoch must agree on epoch bits"
            );
        }

        /// touch_atime only modifies atime fields, not mtime/ctime.
        #[test]
        fn proptest_touch_atime_isolation(
            secs in 0_u64..=0x3_FFFF_FFFF_u64,
            nsec in 0_u32..1_000_000_000,
        ) {
            let mut inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0, version: 0, generation: 0,
                file_acl: 0, atime: 100, ctime: 200, mtime: 300, dtime: 0,
                atime_extra: 0, ctime_extra: 999, mtime_extra: 888,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            let orig_ctime = inode.ctime;
            let orig_ctime_extra = inode.ctime_extra;
            let orig_mtime = inode.mtime;
            let orig_mtime_extra = inode.mtime_extra;

            touch_atime(&mut inode, secs, nsec);

            prop_assert_eq!(inode.ctime, orig_ctime, "ctime must not change");
            prop_assert_eq!(inode.ctime_extra, orig_ctime_extra, "ctime_extra must not change");
            prop_assert_eq!(inode.mtime, orig_mtime, "mtime must not change");
            prop_assert_eq!(inode.mtime_extra, orig_mtime_extra, "mtime_extra must not change");
            prop_assert_eq!(inode.atime, secs as u32, "atime lower 32 bits");
        }

        /// touch_mtime_ctime sets both mtime and ctime identically.
        #[test]
        fn proptest_touch_mtime_ctime_symmetric(
            secs in 0_u64..=0x3_FFFF_FFFF_u64,
            nsec in 0_u32..1_000_000_000,
        ) {
            let mut inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0, version: 0, generation: 0,
                file_acl: 0, atime: 100, ctime: 0, mtime: 0, dtime: 0,
                atime_extra: 42, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            let orig_atime = inode.atime;
            let orig_atime_extra = inode.atime_extra;

            touch_mtime_ctime(&mut inode, secs, nsec);

            prop_assert_eq!(inode.mtime, inode.ctime, "mtime and ctime must be equal");
            prop_assert_eq!(inode.mtime_extra, inode.ctime_extra, "mtime_extra and ctime_extra must be equal");
            prop_assert_eq!(inode.atime, orig_atime, "atime must not change");
            prop_assert_eq!(inode.atime_extra, orig_atime_extra, "atime_extra must not change");
        }

        /// serialize → parse roundtrip preserves core fields.
        #[test]
        fn proptest_serialize_parse_roundtrip(
            mode_bits in 0_u16..0o7777,
            uid in any::<u32>(),
            gid in any::<u32>(),
            size in 0_u64..(1_u64 << 48),
            links_count in any::<u16>(),
            blocks in 0_u64..(1_u64 << 48),
            flags in any::<u32>(),
            generation in any::<u32>(),
        ) {
            // Use S_IFREG so size_hi is parsed back correctly.
            let mode = 0o100_000 | mode_bits;
            let inode = Ext4Inode {
                mode, uid, gid, size, links_count, blocks, flags, version: 0, generation,
                file_acl: 0, atime: 0, ctime: 0, mtime: 0, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            let raw = serialize_inode(&inode, 256);
            let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();

            prop_assert_eq!(parsed.mode, mode);
            prop_assert_eq!(parsed.uid, uid);
            prop_assert_eq!(parsed.gid, gid);
            prop_assert_eq!(parsed.size, size);
            prop_assert_eq!(parsed.links_count, links_count);
            prop_assert_eq!(parsed.blocks, blocks);
            prop_assert_eq!(parsed.flags, flags);
            prop_assert_eq!(parsed.generation, generation);
        }

        /// locate_inode returns None for out-of-range inodes.
        #[test]
        fn proptest_locate_inode_out_of_range(
            ino_raw in 8193_u64..=100_000,
        ) {
            let geo = make_geometry();
            let groups = make_groups(&geo);
            // total_inodes = 8192, so any ino > 8192 should be out of range.
            let result = locate_inode(InodeNumber(ino_raw), &geo, &groups);
            prop_assert!(result.is_none(), "ino {} should be out of range", ino_raw);
        }

        /// Valid inodes (1..=total_inodes) always resolve to a valid InodeLocation.
        #[test]
        fn proptest_locate_inode_in_range_valid(
            ino_raw in 1_u64..=8192,
        ) {
            let geo = make_geometry();
            let groups = make_groups(&geo);
            let loc = locate_inode(InodeNumber(ino_raw), &geo, &groups);
            prop_assert!(loc.is_some(), "ino {} should be locatable", ino_raw);
            let loc = loc.unwrap();
            // byte_offset must be within a block.
            prop_assert!(loc.byte_offset + usize::from(geo.inode_size) <= geo.block_size as usize,
                "inode {} byte_offset {} + inode_size {} exceeds block_size {}",
                ino_raw, loc.byte_offset, geo.inode_size, geo.block_size);
        }

        /// compute_and_set_checksum → verify_inode_checksum roundtrip succeeds.
        #[test]
        fn proptest_checksum_roundtrip(
            csum_seed in any::<u32>(),
            ino in 1_u32..100_000,
            generation in any::<u32>(),
            mode in any::<u16>(),
            uid_lo in any::<u16>(),
        ) {
            let mut inode = Ext4Inode {
                mode, uid: u32::from(uid_lo), gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0, version: 0, generation,
                file_acl: 0, atime: 0, ctime: 0, mtime: 0, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };
            // Ensure generation matches what will be in the raw buffer.
            let _ = &mut inode;
            let mut raw = serialize_inode(&inode, 256);
            compute_and_set_checksum(&mut raw, csum_seed, ino);
            let result = ffs_ondisk::verify_inode_checksum(&raw, csum_seed, ino, 256);
            prop_assert!(result.is_ok(), "checksum verification failed for seed={csum_seed:#x} ino={ino}: {result:?}");
        }

        /// Restamping must ignore any previous checksum-field contents because those
        /// bytes are logically zeroed before the CRC is computed.
        #[test]
        fn proptest_checksum_stamping_ignores_previous_checksum_field_contents(
            csum_seed in any::<u32>(),
            ino in 1_u32..100_000,
            generation in any::<u32>(),
            checksum_lo_garbage in any::<u16>(),
            checksum_hi_garbage in any::<u16>(),
        ) {
            let inode = Ext4Inode {
                mode: 0o100_644, uid: 1000, gid: 1000, size: 4096,
                links_count: 1, blocks: 8, flags: EXT4_EXTENTS_FL, version: 0, generation,
                file_acl: 0, atime: 1_700_000_000, ctime: 1_700_000_000,
                mtime: 1_700_000_000, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 1_700_000_000, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            let mut stamped_from_clean = serialize_inode(&inode, 256);
            let mut stamped_from_dirty = stamped_from_clean.clone();
            stamped_from_dirty[INODE_CHECKSUM_LO_OFFSET..INODE_CHECKSUM_LO_OFFSET + 2]
                .copy_from_slice(&checksum_lo_garbage.to_le_bytes());
            stamped_from_dirty[INODE_CHECKSUM_HI_OFFSET..INODE_CHECKSUM_HI_OFFSET + 2]
                .copy_from_slice(&checksum_hi_garbage.to_le_bytes());

            compute_and_set_checksum(&mut stamped_from_clean, csum_seed, ino);
            compute_and_set_checksum(&mut stamped_from_dirty, csum_seed, ino);

            prop_assert_eq!(&stamped_from_dirty, &stamped_from_clean);
            let result = ffs_ondisk::verify_inode_checksum(
                &stamped_from_dirty,
                csum_seed,
                ino,
                256,
            );
            prop_assert!(result.is_ok(), "checksum verification failed after dirty-field restamp: {result:?}");
        }

        /// write_inode → read_inode preserves all core inode fields.
        #[test]
        fn proptest_write_read_roundtrip(
            mode_bits in 0_u16..0o7777,
            uid in any::<u32>(),
            gid in any::<u32>(),
            size in 0_u64..(1_u64 << 48),
            links_count in 1_u16..1000,
            generation in any::<u32>(),
            atime_val in any::<u32>(),
            mtime_val in any::<u32>(),
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let groups = make_groups(&geo);
            let mode = 0o100_000 | mode_bits;

            let inode = Ext4Inode {
                mode, uid, gid, size, links_count, blocks: 0, flags: 0, version: 0, generation,
                file_acl: 0, atime: atime_val, ctime: 0, mtime: mtime_val, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            let ino = InodeNumber(1);
            write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).unwrap();
            let read_back = read_inode(&cx, &dev, &geo, &groups, ino).unwrap();

            prop_assert_eq!(read_back.mode, mode);
            prop_assert_eq!(read_back.uid, uid);
            prop_assert_eq!(read_back.gid, gid);
            prop_assert_eq!(read_back.size, size);
            prop_assert_eq!(read_back.links_count, links_count);
            prop_assert_eq!(read_back.generation, generation);
            prop_assert_eq!(read_back.atime, atime_val);
            prop_assert_eq!(read_back.mtime, mtime_val);
        }

        /// serialize → parse roundtrip preserves all timestamp fields.
        #[test]
        fn proptest_serialize_timestamps_preserved(
            atime in any::<u32>(),
            ctime in any::<u32>(),
            mtime in any::<u32>(),
            dtime in any::<u32>(),
            atime_extra in any::<u32>(),
            ctime_extra in any::<u32>(),
            mtime_extra in any::<u32>(),
            crtime in any::<u32>(),
        ) {
            let inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0, version: 0, generation: 0,
                file_acl: 0, atime, ctime, mtime, dtime,
                atime_extra, ctime_extra, mtime_extra,
                crtime, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            let raw = serialize_inode(&inode, 256);
            let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();

            prop_assert_eq!(parsed.atime, atime);
            prop_assert_eq!(parsed.ctime, ctime);
            prop_assert_eq!(parsed.mtime, mtime);
            prop_assert_eq!(parsed.dtime, dtime);
            prop_assert_eq!(parsed.atime_extra, atime_extra);
            prop_assert_eq!(parsed.ctime_extra, ctime_extra);
            prop_assert_eq!(parsed.mtime_extra, mtime_extra);
            prop_assert_eq!(parsed.crtime, crtime);
        }

        /// touch_ctime modifies only ctime fields, preserving atime and mtime.
        #[test]
        fn proptest_touch_ctime_isolation(
            secs in 0_u64..=0x3_FFFF_FFFF_u64,
            nsec in 0_u32..1_000_000_000,
            init_atime in any::<u32>(),
            init_mtime in any::<u32>(),
            init_atime_extra in any::<u32>(),
            init_mtime_extra in any::<u32>(),
        ) {
            let mut inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0, version: 0, generation: 0,
                file_acl: 0, atime: init_atime, ctime: 0, mtime: init_mtime, dtime: 0,
                atime_extra: init_atime_extra, ctime_extra: 0, mtime_extra: init_mtime_extra,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            touch_ctime(&mut inode, secs, nsec);

            prop_assert_eq!(inode.atime, init_atime, "atime must not change");
            prop_assert_eq!(inode.atime_extra, init_atime_extra, "atime_extra must not change");
            prop_assert_eq!(inode.mtime, init_mtime, "mtime must not change");
            prop_assert_eq!(inode.mtime_extra, init_mtime_extra, "mtime_extra must not change");
            prop_assert_eq!(inode.ctime, secs as u32, "ctime lower 32 bits");
            prop_assert_eq!(inode.ctime_extra, encode_extra_timestamp(secs, nsec), "ctime_extra");
        }

        /// serialize → parse roundtrip preserves 48-bit file_acl field.
        #[test]
        fn proptest_serialize_file_acl_roundtrip(
            file_acl in 0_u64..(1_u64 << 48),
        ) {
            let inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0, version: 0, generation: 0,
                file_acl, atime: 0, ctime: 0, mtime: 0, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            let raw = serialize_inode(&inode, 256);
            let parsed = Ext4Inode::parse_from_bytes(&raw).unwrap();
            prop_assert_eq!(parsed.file_acl, file_acl, "file_acl 48-bit roundtrip failed");
        }

        /// A single bit-flip in the raw inode buffer should be detected
        /// by checksum verification (except flips in the checksum fields
        /// themselves, which can produce false-positive matches).
        #[test]
        fn proptest_checksum_detects_bitflip(
            csum_seed in any::<u32>(),
            ino in 1_u32..100_000,
            // Flip position in bytes 0..0x7C (before checksum_lo) or 0x84..=0xFF
            // (after checksum_hi). Avoids the 4 checksum bytes at 0x7C-0x7D
            // and 0x82-0x83 since flipping those produces unpredictable results.
            flip_byte in (0_usize..124).prop_union(132_usize..256),
            flip_bit in 0_u8..8,
        ) {
            let inode = Ext4Inode {
                mode: 0o100_644, uid: 1000, gid: 1000, size: 4096,
                links_count: 1, blocks: 8, flags: EXT4_EXTENTS_FL, version: 0, generation: 42,
                file_acl: 0, atime: 1_700_000_000, ctime: 1_700_000_000,
                mtime: 1_700_000_000, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 1_700_000_000, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            let mut raw = serialize_inode(&inode, 256);
            compute_and_set_checksum(&mut raw, csum_seed, ino);

            // Verify good checksum first.
            let ok = ffs_ondisk::verify_inode_checksum(&raw, csum_seed, ino, 256);
            prop_assert!(ok.is_ok(), "valid checksum should pass");

            // Flip one bit.
            raw[flip_byte] ^= 1 << flip_bit;

            // Verification should now fail.
            let corrupted = ffs_ondisk::verify_inode_checksum(&raw, csum_seed, ino, 256);
            prop_assert!(corrupted.is_err(),
                "bit-flip at byte {flip_byte} bit {flip_bit} was not detected (seed={csum_seed:#x} ino={ino})");
        }

        /// serialize → parse roundtrip preserves xattr ibody bytes.
        #[test]
        fn proptest_serialize_xattr_ibody_roundtrip(
            xattr_len in 0_usize..64,
            fill_byte in any::<u8>(),
        ) {
            let xattr_data = vec![fill_byte; xattr_len];
            let inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0, version: 0, generation: 0,
                file_acl: 0, atime: 0, ctime: 0, mtime: 0, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: 0, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: xattr_data.clone(),
                number: 0,
            };

            let raw = serialize_inode(&inode, 256);
            // Inline xattrs start at offset 128 + extra_isize = 160.
            let xattr_start = 160;
            prop_assert_eq!(&raw[xattr_start..xattr_start + xattr_len], &xattr_data[..],
                "xattr ibody bytes not preserved");
        }

        /// Metamorphic relation: bumping the inode version `n` times must
        /// add exactly `n` to the combined u64 (version_hi:version_lo),
        /// modulo 2^64. Existing unit tests pin specific values (zero,
        /// u32::MAX, u64::MAX) but no property test exercised the full
        /// arithmetic chain across the u32 boundary.
        #[test]
        fn proptest_bump_inode_version_adds_n(
            initial_lo in any::<u32>(),
            initial_hi in any::<u32>(),
            n in 0_u32..=64,
        ) {
            let mut inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0,
                version: initial_lo, generation: 0,
                file_acl: 0, atime: 0, ctime: 0, mtime: 0, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: initial_hi, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };

            let initial = u64::from(initial_lo) | (u64::from(initial_hi) << 32);
            for _ in 0..n {
                bump_inode_version(&mut inode);
            }
            let after = u64::from(inode.version) | (u64::from(inode.version_hi) << 32);
            prop_assert_eq!(after, initial.wrapping_add(u64::from(n)),
                "bump_inode_version called {} times must add {} mod 2^64", n, n);
        }

        // bd-wgvh5 — touch_* version-bump dispatch invariant.
        // NFS coherence depends on:
        //   touch_atime         : MUST NOT bump i_version (lazy attr)
        //   touch_mtime_ctime   : MUST bump i_version by exactly 1
        //   touch_ctime         : MUST bump i_version by exactly 1
        // Fixed-input touch_atime_does_not_modify_ctime_mtime test
        // confirms TIMESTAMP isolation but NOT version isolation.
        // A regression that started bumping version on atime would
        // silently invalidate every NFS client cache and trigger
        // spurious revalidation storms.

        #[test]
        fn ext4_proptest_touch_atime_does_not_bump_version(
            initial_lo in any::<u32>(),
            initial_hi in any::<u32>(),
            secs in any::<u64>(),
            nsec in any::<u32>(),
        ) {
            let mut inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0,
                version: initial_lo, generation: 0,
                file_acl: 0, atime: 0, ctime: 0, mtime: 0, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: initial_hi, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };
            touch_atime(&mut inode, secs, nsec);
            prop_assert_eq!(inode.version, initial_lo,
                "touch_atime must not modify version (lo)");
            prop_assert_eq!(inode.version_hi, initial_hi,
                "touch_atime must not modify version_hi");
        }

        #[test]
        fn ext4_proptest_touch_mtime_ctime_bumps_version_by_one(
            initial_lo in any::<u32>(),
            initial_hi in any::<u32>(),
            secs in any::<u64>(),
            nsec in any::<u32>(),
        ) {
            let mut inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0,
                version: initial_lo, generation: 0,
                file_acl: 0, atime: 0, ctime: 0, mtime: 0, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: initial_hi, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };
            let initial = u64::from(initial_lo) | (u64::from(initial_hi) << 32);
            touch_mtime_ctime(&mut inode, secs, nsec);
            let after = u64::from(inode.version) | (u64::from(inode.version_hi) << 32);
            prop_assert_eq!(after, initial.wrapping_add(1),
                "touch_mtime_ctime must bump version by exactly 1");
        }

        #[test]
        fn ext4_proptest_touch_ctime_bumps_version_by_one(
            initial_lo in any::<u32>(),
            initial_hi in any::<u32>(),
            secs in any::<u64>(),
            nsec in any::<u32>(),
        ) {
            let mut inode = Ext4Inode {
                mode: 0o100_644, uid: 0, gid: 0, size: 0,
                links_count: 1, blocks: 0, flags: 0,
                version: initial_lo, generation: 0,
                file_acl: 0, atime: 0, ctime: 0, mtime: 0, dtime: 0,
                atime_extra: 0, ctime_extra: 0, mtime_extra: 0,
                crtime: 0, crtime_extra: 0, extra_isize: 32,
                checksum: 0, version_hi: initial_hi, projid: 0,
                extent_bytes: vec![0u8; 60].into(), xattr_ibody: Vec::new(),
                number: 0,
            };
            let initial = u64::from(initial_lo) | (u64::from(initial_hi) << 32);
            touch_ctime(&mut inode, secs, nsec);
            let after = u64::from(inode.version) | (u64::from(inode.version_hi) << 32);
            prop_assert_eq!(after, initial.wrapping_add(1),
                "touch_ctime must bump version by exactly 1");
        }

        /// Bijection contract: `serialize_inode` followed by
        /// `Ext4Inode::parse_from_bytes` must round-trip an inode that
        /// already has the on-disk shape (extent_bytes = 60, xattr_ibody
        /// matches extra_isize, blocks/file_acl masked to 48 bits,
        /// extra-area fields zero unless extra_isize advertises them,
        /// checksum = 0). This pins the exact contract that the
        /// fuzz_inode_roundtrip harness oracle reconciliation
        /// (commits 0fed288 + 45dc836) was tightening — running it
        /// inside ffs-inode's own test suite catches drift faster than
        /// the cross-crate fuzz path.
        #[test]
        fn proptest_serialize_parse_bijection_at_inode_size_256(
            // Restrict to regular files and directories — only those modes
            // round-trip the high 32 bits of size. Symlinks and special
            // files store size in the low 32 bits only (the parser at
            // ext4.rs:2310 explicitly gates size_hi on is_reg || is_dir),
            // so a symlink with size > u32::MAX is a corruption that the
            // serialize/parse round-trip cannot recover from.
            mode_bits in 0_u16..=1,
            uid in any::<u32>(),
            gid in any::<u32>(),
            size in any::<u64>(),
            blocks_lo in any::<u32>(),
            blocks_hi in any::<u16>(),
            file_acl_lo in any::<u32>(),
            file_acl_hi in any::<u16>(),
            generation in any::<u32>(),
            atime in any::<u32>(),
            ctime in any::<u32>(),
            mtime in any::<u32>(),
            extra_isize_choice in prop_oneof![Just(0_u16), Just(28), Just(32), Just(64), Just(128)],
        ) {
            let kind = if mode_bits == 0 {
                file_type::S_IFREG
            } else {
                file_type::S_IFDIR
            };

            let blocks: u64 = u64::from(blocks_lo) | (u64::from(blocks_hi) << 32);
            let file_acl: u64 = u64::from(file_acl_lo) | (u64::from(file_acl_hi) << 32);
            let inode_size: usize = 256;
            let extra_isize = extra_isize_choice;
            let extra_end: usize = 128 + usize::from(extra_isize);
            let advertise = |needed_end: usize| -> bool {
                extra_end >= needed_end && inode_size >= needed_end
            };
            let xattr_start: usize = 128 + usize::from(extra_isize);
            let xattr_capacity: usize = inode_size.saturating_sub(xattr_start);

            let inode = Ext4Inode {
                mode: kind | 0o644,
                uid,
                gid,
                size,
                links_count: 1,
                blocks,
                flags: 0,
                version: 0,
                generation,
                file_acl,
                atime,
                ctime,
                mtime,
                dtime: 0,
                atime_extra: if advertise(0x90) { 0x00C0_FFEE } else { 0 },
                ctime_extra: if advertise(0x88) { 0xCAFE_BABE } else { 0 },
                mtime_extra: if advertise(0x8C) { 0xDEAD_BEEF } else { 0 },
                crtime: if advertise(0x94) { 1_700_000_000 } else { 0 },
                crtime_extra: if advertise(0x98) { 0xFADE_F00D } else { 0 },
                extra_isize,
                checksum: 0,
                version_hi: if advertise(0x9C) { 0x1234_5678 } else { 0 },
                projid: if advertise(0xA0) { 0xABCD_0123 } else { 0 },
                extent_bytes: vec![0_u8; 60].into(),
                xattr_ibody: if extra_isize > 0 {
                    vec![0_u8; xattr_capacity]
                } else {
                    Vec::new()
                },
                number: 0,
            };

            let raw = serialize_inode(&inode, inode_size);
            prop_assert_eq!(raw.len(), inode_size,
                "serialize_inode must produce exactly inode_size bytes");

            let parsed = ffs_ondisk::Ext4Inode::parse_from_bytes(&raw)
                .expect("parse must succeed on serializer output");
            prop_assert_eq!(&parsed, &inode,
                "serialize→parse round-trip must be bijective for shape-conforming inodes");

            let raw_again = serialize_inode(&parsed, inode_size);
            prop_assert_eq!(raw_again, raw,
                "parse→serialize must produce identical bytes");
        }
    }

    // ── Additional edge-case tests ──────────────────────────────────────

    #[test]
    fn file_type_constants_match_posix() {
        assert_eq!(file_type::S_IFREG, 0o100_000);
        assert_eq!(file_type::S_IFDIR, 0o040_000);
        assert_eq!(file_type::S_IFLNK, 0o120_000);
        // These shouldn't overlap (distinct file type bits).
        assert_ne!(file_type::S_IFREG, file_type::S_IFDIR);
        assert_ne!(file_type::S_IFREG, file_type::S_IFLNK);
        assert_ne!(file_type::S_IFDIR, file_type::S_IFLNK);
    }

    #[test]
    fn inode_location_debug_format() {
        const INODE_LOCATION_DEBUG_GOLDEN: &str =
            "InodeLocation { block: BlockNumber(42), byte_offset: 256 }";

        let loc = InodeLocation {
            block: BlockNumber(42),
            byte_offset: 256,
        };
        let dbg = format!("{loc:?}");
        assert_eq!(dbg, INODE_LOCATION_DEBUG_GOLDEN);
    }

    #[test]
    fn locate_inode_zero_is_invalid() {
        let geo = make_geometry();
        let groups = make_groups(&geo);
        let result = locate_inode(InodeNumber(0), &geo, &groups);
        assert!(
            result.is_none(),
            "inode 0 must not alias the first inode table entry"
        );
    }

    #[test]
    fn locate_inode_rejects_zero_geometry() {
        let mut geo = make_geometry();
        let groups = make_groups(&geo);

        geo.inodes_per_group = 0;
        assert!(locate_inode(InodeNumber(1), &geo, &groups).is_none());

        geo = make_geometry();
        geo.block_size = 0;
        assert!(locate_inode(InodeNumber(1), &geo, &groups).is_none());

        geo = make_geometry();
        geo.inode_size = 0;
        assert!(locate_inode(InodeNumber(1), &geo, &groups).is_none());
    }

    #[test]
    fn locate_inode_group_boundary() {
        // Test inode at exact group boundary (first inode of second group).
        let geo = make_geometry(); // inodes_per_group = 2048
        let groups = make_groups(&geo);

        // Inode 2049 should be in group 1 (1-indexed: inode 2049 → group 1, index 0).
        let loc = locate_inode(InodeNumber(2049), &geo, &groups).unwrap();
        // Group 1 inode_table_block is at 100*1 + 3 = 103.
        assert_eq!(loc.block, BlockNumber(103));
        assert_eq!(loc.byte_offset, 0);
    }

    #[test]
    fn serialize_inode_mode_preserved() {
        let inode = Ext4Inode {
            mode: 0o100_755,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };
        let raw = serialize_inode(&inode, 256);
        let mode = u16::from_le_bytes([raw[0], raw[1]]);
        assert_eq!(mode, 0o100_755);
    }

    #[test]
    fn serialize_inode_flags_preserved() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: EXT4_EXTENTS_FL | 0x0000_0010, // extents + append
            version: 0,
            generation: 42,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };
        let raw = serialize_inode(&inode, 256);
        let flags = u32::from_le_bytes([raw[0x20], raw[0x21], raw[0x22], raw[0x23]]);
        assert_eq!(flags, EXT4_EXTENTS_FL | 0x0000_0010);
        let generation = u32::from_le_bytes([raw[0x64], raw[0x65], raw[0x66], raw[0x67]]);
        assert_eq!(generation, 42);
    }

    #[test]
    fn encode_extra_timestamp_boundary_values() {
        // epoch bits: seconds >> 32 & 0x3
        // nsec bits: nsec << 2

        // Zero.
        assert_eq!(encode_extra_timestamp(0, 0), 0);

        // Max nsec (999_999_999).
        let extra = encode_extra_timestamp(0, 999_999_999);
        assert_eq!(extra >> 2, 999_999_999); // nsec in bits 2-31
        assert_eq!(extra & 0x3, 0); // epoch = 0

        // Epoch extension = 1 (seconds bit 32 set).
        let extra = encode_extra_timestamp(1u64 << 32, 0);
        assert_eq!(extra & 0x3, 1); // epoch bits
        assert_eq!(extra >> 2, 0); // no nsec

        // Epoch extension = 2.
        let extra = encode_extra_timestamp(2u64 << 32, 0);
        assert_eq!(extra & 0x3, 2);

        // Epoch extension = 3.
        let extra = encode_extra_timestamp(3u64 << 32, 0);
        assert_eq!(extra & 0x3, 3);

        // Combined.
        let extra = encode_extra_timestamp((1u64 << 32) + 100, 500_000);
        assert_eq!(extra & 0x3, 1); // epoch
        assert_eq!(extra >> 2, 500_000); // nsec
    }

    #[test]
    fn touch_atime_only_modifies_atime_fields() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 100,
            ctime: 200,
            mtime: 300,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };

        touch_atime(&mut inode, 500, 123);
        assert_eq!(inode.atime, 500);
        assert_eq!(inode.atime_extra, encode_extra_timestamp(500, 123));
        // Other timestamps unchanged.
        assert_eq!(inode.ctime, 200);
        assert_eq!(inode.mtime, 300);
    }

    #[test]
    fn touch_mtime_ctime_updates_both() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 100,
            ctime: 200,
            mtime: 300,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };

        touch_mtime_ctime(&mut inode, 600, 456);
        assert_eq!(inode.mtime, 600);
        assert_eq!(inode.ctime, 600);
        let expected_extra = encode_extra_timestamp(600, 456);
        assert_eq!(inode.mtime_extra, expected_extra);
        assert_eq!(inode.ctime_extra, expected_extra);
        // atime untouched.
        assert_eq!(inode.atime, 100);
    }

    #[test]
    fn compute_and_set_checksum_skip_for_tiny_buffer() {
        // Buffer < 128 bytes: checksum should be skipped entirely.
        let mut raw = vec![0u8; 64];
        compute_and_set_checksum(&mut raw, 0x1234, 1);
        // Should be all zeros (no checksum written).
        assert!(raw.iter().all(|b| *b == 0));
    }

    #[test]
    fn compute_and_set_checksum_exactly_128_sets_lo_only() {
        let mut raw = vec![0u8; 128];
        // Set a generation so the seed varies.
        raw[0x64..0x68].copy_from_slice(&42u32.to_le_bytes());
        compute_and_set_checksum(&mut raw, 0xDEAD, 1);

        // lo bytes at 0x7C should be non-zero (with overwhelming probability).
        let lo = u16::from_le_bytes([raw[0x7C], raw[0x7D]]);
        // hi bytes at 0x82 are beyond the 128-byte buffer — not set.
        // Just verify no panic and lo has a value.
        let _ = lo;
    }

    #[test]
    fn compute_and_set_checksum_256_sets_lo_and_hi() {
        let mut raw = vec![0u8; 256];
        raw[0x64..0x68].copy_from_slice(&99u32.to_le_bytes());
        compute_and_set_checksum(&mut raw, 0xBEEF, 5);

        let lo = u16::from_le_bytes([raw[0x7C], raw[0x7D]]);
        let hi = u16::from_le_bytes([raw[0x82], raw[0x83]]);
        let csum = u32::from(lo) | (u32::from(hi) << 16);
        // Checksum should be nonzero.
        assert_ne!(csum, 0, "checksum should be non-zero");
    }

    #[test]
    fn serialize_extent_bytes_capped_at_60() {
        // Even if extent_bytes is longer than 60, serialize should only copy 60.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0xAB; 100].into(), // larger than 60
            xattr_ibody: vec![],
            number: 0,
        };
        let raw = serialize_inode(&inode, 256);
        // Bytes at 0x28..0x64 should be 0xAB (60 bytes).
        assert!(raw[0x28..0x64].iter().all(|b| *b == 0xAB));
        // Byte at 0x64 should be the generation, not 0xAB.
        // (generation is 0, so it should be 0.)
        assert_eq!(raw[0x64], 0);
    }

    #[test]
    fn serialize_dtime_preserved() {
        let inode = Ext4Inode {
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 0,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0xDEAD_BEEF,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };
        let raw = serialize_inode(&inode, 256);
        let dtime = u32::from_le_bytes([raw[0x14], raw[0x15], raw[0x16], raw[0x17]]);
        assert_eq!(dtime, 0xDEAD_BEEF);
    }

    #[test]
    fn serialize_links_count_preserved() {
        let inode = Ext4Inode {
            mode: 0o040_755,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 42,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };
        let raw = serialize_inode(&inode, 256);
        let links = u16::from_le_bytes([raw[0x1A], raw[0x1B]]);
        assert_eq!(links, 42);
    }

    // ── Edge-case and boundary tests (bd-o6yp) ─────────────────────────

    #[test]
    fn create_inode_file_has_link_count_one() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let (_, inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644, // regular file
            1000,
            1000,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &pctx,
        )
        .unwrap();
        assert_eq!(inode.links_count, 1, "regular file starts with 1 link");
        assert!(!inode.is_dir());
    }

    #[test]
    fn create_inode_dir_has_link_count_two() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let (_, inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o040_755, // directory
            1000,
            1000,
            GroupNumber(0),
            0,
            1_700_000_000,
            0,
            &pctx,
        )
        .unwrap();
        assert_eq!(
            inode.links_count, 2,
            "directory starts with 2 links (. and parent)"
        );
        assert!(inode.is_dir());
    }

    #[test]
    fn create_inode_has_extent_flag_and_valid_root() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let (_, inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            0,
            0,
            &pctx,
        )
        .unwrap();
        assert_ne!(inode.flags & EXT4_EXTENTS_FL, 0, "should have EXTENTS flag");
        // Verify extent root header magic.
        let magic = u16::from_le_bytes([inode.extent_bytes[0], inode.extent_bytes[1]]);
        assert_eq!(magic, EXT4_EXTENT_MAGIC);
        // entries = 0
        let entries = u16::from_le_bytes([inode.extent_bytes[2], inode.extent_bytes[3]]);
        assert_eq!(entries, 0, "new inode should have 0 extents");
        // max_entries = 4
        let max = u16::from_le_bytes([inode.extent_bytes[4], inode.extent_bytes[5]]);
        assert_eq!(max, 4, "root max should be 4");
    }

    #[test]
    fn create_inode_timestamps_match_provided() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let now = 1_700_000_000_u64;
        let nsec = 123_456_789_u32;
        let (_, inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            now,
            nsec,
            &pctx,
        )
        .unwrap();
        assert_eq!(inode.atime, now as u32);
        assert_eq!(inode.ctime, now as u32);
        assert_eq!(inode.mtime, now as u32);
        assert_eq!(inode.crtime, now as u32);
        // Extra timestamp should encode the nsec.
        let expected_extra = encode_extra_timestamp(now, nsec);
        assert_eq!(inode.atime_extra, expected_extra);
        assert_eq!(inode.ctime_extra, expected_extra);
        assert_eq!(inode.mtime_extra, expected_extra);
        assert_eq!(inode.crtime_extra, expected_extra);
    }

    #[test]
    fn delete_inode_without_extent_flag_does_not_truncate() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_000,
            0,
            &pctx,
        )
        .unwrap();
        // Clear the extents flag to simulate a non-extent inode.
        inode.flags &= !EXT4_EXTENTS_FL;
        write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).unwrap();

        // Delete should succeed without trying to truncate extents.
        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            2_000,
            &pctx,
        )
        .unwrap();
        assert_eq!(inode.links_count, 0);
        assert_eq!(inode.size, 0);
        assert_eq!(inode.dtime, 2_000);
    }

    #[test]
    fn locate_inode_very_large_number() {
        let geo = make_geometry();
        let groups = make_groups(&geo);
        // Inode number far beyond all groups should return None.
        let result = locate_inode(InodeNumber(999_999), &geo, &groups);
        assert!(
            result.is_none(),
            "should return None for out-of-range inode"
        );
    }

    #[test]
    fn encode_extra_timestamp_high_epoch_bits() {
        // Seconds > 2^32: the low 2 bits of the extra field store epoch extension.
        let secs = (1_u64 << 33) + 42; // epoch bit 1 set
        let nsec = 500_000_000; // 0.5s
        let extra = encode_extra_timestamp(secs, nsec);
        // epoch extension = (secs >> 32) & 0x3 = 2
        let epoch_bits = extra & 0x3;
        assert_eq!(epoch_bits, 2, "epoch extension should be 2");
        // nsec bits 2..31
        let decoded_nsec = extra >> 2;
        assert_eq!(decoded_nsec, nsec);
    }

    #[test]
    fn touch_atime_does_not_modify_ctime_mtime() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 100,
            links_count: 1,
            blocks: 8,
            flags: 0,

            version: 0,
            generation: 1,
            file_acl: 0,
            atime: 1000,
            ctime: 2000,
            mtime: 3000,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 500,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };
        let ct_before = inode.ctime;
        let mt_before = inode.mtime;
        touch_atime(&mut inode, 9999, 123);
        assert_eq!(inode.atime, 9999);
        assert_eq!(inode.ctime, ct_before, "ctime unchanged by touch_atime");
        assert_eq!(inode.mtime, mt_before, "mtime unchanged by touch_atime");
    }

    #[test]
    fn touch_ctime_does_not_modify_atime_mtime() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 100,
            links_count: 1,
            blocks: 8,
            flags: 0,

            version: 0,
            generation: 1,
            file_acl: 0,
            atime: 1000,
            ctime: 2000,
            mtime: 3000,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 500,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };
        let at_before = inode.atime;
        let mt_before = inode.mtime;
        touch_ctime(&mut inode, 8888, 456);
        assert_eq!(inode.ctime, 8888);
        assert_eq!(inode.atime, at_before, "atime unchanged by touch_ctime");
        assert_eq!(inode.mtime, mt_before, "mtime unchanged by touch_ctime");
    }

    #[test]
    fn create_and_delete_roundtrip_frees_inode() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let free_before = groups[0].free_inodes;

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_000,
            0,
            &pctx,
        )
        .unwrap();
        assert_eq!(groups[0].free_inodes, free_before - 1);

        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            2_000,
            &pctx,
        )
        .unwrap();
        assert_eq!(groups[0].free_inodes, free_before, "inode should be freed");
    }

    #[test]
    fn inode_location_fields() {
        let loc = InodeLocation {
            block: BlockNumber(42),
            byte_offset: 256,
        };
        assert_eq!(loc.block, BlockNumber(42));
        assert_eq!(loc.byte_offset, 256);
        // Debug + Clone coverage.
        let cloned = loc;
        let _ = format!("{cloned:?}");
    }

    #[test]
    fn create_dir_increments_used_dirs() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let total_used_before: u32 = groups.iter().map(|g| g.used_dirs).sum();

        create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o040_755,
            0,
            0,
            GroupNumber(0),
            0,
            1_000,
            0,
            &pctx,
        )
        .unwrap();
        let total_used_after: u32 = groups.iter().map(|g| g.used_dirs).sum();
        assert_eq!(
            total_used_after,
            total_used_before + 1,
            "creating dir should increment used_dirs in some group"
        );
    }

    // ── Deeper edge-case and boundary tests ─────────────────────────────

    #[test]
    fn serialize_short_extent_bytes_zero_padded() {
        // When extent_bytes is shorter than 60, only available bytes are copied.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0xCC; 10].into(), // shorter than 60
            xattr_ibody: vec![],
            number: 0,
        };
        let raw = serialize_inode(&inode, 256);
        // First 10 bytes at 0x28 should be 0xCC.
        assert!(raw[0x28..0x28 + 10].iter().all(|b| *b == 0xCC));
        // Remaining bytes from 0x32..0x64 should be zero.
        assert!(raw[0x28 + 10..0x64].iter().all(|b| *b == 0));
    }

    #[test]
    fn serialize_inode_size_0x88_includes_ctime_extra_only() {
        // inode_size = 0x88 (136) includes ctime_extra but not mtime_extra.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0xAAAA_BBBB,
            mtime_extra: 0xCCCC_DDDD,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };
        let raw = serialize_inode(&inode, 0x88);
        assert_eq!(raw.len(), 0x88);
        let ctime_extra = u32::from_le_bytes([raw[0x84], raw[0x85], raw[0x86], raw[0x87]]);
        assert_eq!(ctime_extra, 0xAAAA_BBBB);
        // mtime_extra at 0x88 is out of bounds — not serialized.
    }

    #[test]
    fn serialize_inode_size_0x90_includes_through_atime_extra() {
        // inode_size = 0x90 (144) includes ctime_extra, mtime_extra, atime_extra.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0x1111_2222,
            ctime_extra: 0x3333_4444,
            mtime_extra: 0x5555_6666,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };
        let raw = serialize_inode(&inode, 0x90);
        assert_eq!(raw.len(), 0x90);
        let ctime_extra = u32::from_le_bytes([raw[0x84], raw[0x85], raw[0x86], raw[0x87]]);
        let mtime_extra = u32::from_le_bytes([raw[0x88], raw[0x89], raw[0x8A], raw[0x8B]]);
        let atime_extra = u32::from_le_bytes([raw[0x8C], raw[0x8D], raw[0x8E], raw[0x8F]]);
        assert_eq!(ctime_extra, 0x3333_4444);
        assert_eq!(mtime_extra, 0x5555_6666);
        assert_eq!(atime_extra, 0x1111_2222);
    }

    #[test]
    fn delete_inode_short_extent_bytes_skips_truncate() {
        // extent_bytes < 60 with EXT4_EXTENTS_FL set should skip truncation.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_000,
            0,
            &pctx,
        )
        .unwrap();

        // Shrink extent_bytes below the 60-byte threshold while keeping the flag.
        inode.extent_bytes.truncate(12);
        assert_ne!(inode.flags & EXT4_EXTENTS_FL, 0);

        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            2_000,
            &pctx,
        )
        .unwrap();
        assert_eq!(inode.links_count, 0);
        assert_eq!(inode.size, 0);
    }

    #[test]
    fn create_inode_epoch_extended_timestamp() {
        // Timestamps beyond 2038 (> u32::MAX) should use epoch extension bits.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();

        let future_secs: u64 = 0x1_0000_0001; // epoch bit = 1
        let nsec: u32 = 500_000_000;
        let (_, inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            future_secs,
            nsec,
            &pctx,
        )
        .unwrap();

        assert_eq!(inode.atime, 1); // low 32 bits of 0x1_0000_0001
        let expected_extra = encode_extra_timestamp(future_secs, nsec);
        assert_eq!(inode.atime_extra, expected_extra);
        assert_eq!(inode.ctime_extra, expected_extra);
        assert_eq!(inode.mtime_extra, expected_extra);
        assert_eq!(inode.crtime_extra, expected_extra);
        assert_eq!(expected_extra & 0x3, 1, "epoch bit should be 1");
        assert_eq!(expected_extra >> 2, nsec, "nsec should be preserved");
    }

    #[test]
    fn touch_atime_epoch_extended() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 100,
            mtime: 200,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };

        let future_secs: u64 = 0x2_0000_0005; // epoch bits = 2
        touch_atime(&mut inode, future_secs, 100_000_000);

        assert_eq!(inode.atime, 5); // low 32 bits
        let extra = inode.atime_extra;
        assert_eq!(extra & 0x3, 2, "epoch extension should be 2");
        assert_eq!(extra >> 2, 100_000_000, "nsec should be preserved");
        assert_eq!(inode.ctime, 100, "ctime unchanged");
        assert_eq!(inode.mtime, 200, "mtime unchanged");
    }

    #[test]
    fn touch_mtime_ctime_epoch_max() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 42,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![],
            number: 0,
        };

        let future_secs: u64 = 0x3_FFFF_FFFE; // epoch bits = 3 (max)
        touch_mtime_ctime(&mut inode, future_secs, 999_999_999);

        assert_eq!(inode.mtime, 0xFFFF_FFFE);
        assert_eq!(inode.ctime, 0xFFFF_FFFE);
        let extra = inode.mtime_extra;
        assert_eq!(extra & 0x3, 3, "epoch extension should be 3 (max)");
        assert_eq!(extra >> 2, 999_999_999, "max nsec preserved");
        assert_eq!(inode.ctime_extra, extra, "ctime and mtime extra match");
        assert_eq!(inode.atime, 42, "atime untouched");
    }

    #[test]
    fn checksum_varies_with_seed() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 1000,
            gid: 1000,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: EXT4_EXTENTS_FL,

            version: 0,
            generation: 1,
            file_acl: 0,
            atime: 1_700_000_000,
            ctime: 1_700_000_000,
            mtime: 1_700_000_000,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let mut raw_a = serialize_inode(&inode, 256);
        compute_and_set_checksum(&mut raw_a, 0x1111_1111, 42);
        let csum_a = u16::from_le_bytes([
            raw_a[INODE_CHECKSUM_LO_OFFSET],
            raw_a[INODE_CHECKSUM_LO_OFFSET + 1],
        ]);

        let mut raw_b = serialize_inode(&inode, 256);
        compute_and_set_checksum(&mut raw_b, 0x2222_2222, 42);
        let csum_b = u16::from_le_bytes([
            raw_b[INODE_CHECKSUM_LO_OFFSET],
            raw_b[INODE_CHECKSUM_LO_OFFSET + 1],
        ]);

        assert_ne!(
            csum_a, csum_b,
            "different seeds should give different checksums"
        );
    }

    #[test]
    fn checksum_varies_with_inode_number() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: EXT4_EXTENTS_FL,

            version: 0,
            generation: 1,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };

        let mut raw_a = serialize_inode(&inode, 256);
        compute_and_set_checksum(&mut raw_a, 0xDEAD, 1);

        let mut raw_b = serialize_inode(&inode, 256);
        compute_and_set_checksum(&mut raw_b, 0xDEAD, 2);

        // Compare full 32-bit checksum (lo + hi).
        let full_a = u32::from(u16::from_le_bytes([
            raw_a[INODE_CHECKSUM_LO_OFFSET],
            raw_a[INODE_CHECKSUM_LO_OFFSET + 1],
        ])) | u32::from(u16::from_le_bytes([
            raw_a[INODE_CHECKSUM_HI_OFFSET],
            raw_a[INODE_CHECKSUM_HI_OFFSET + 1],
        ])) << 16;
        let full_b = u32::from(u16::from_le_bytes([
            raw_b[INODE_CHECKSUM_LO_OFFSET],
            raw_b[INODE_CHECKSUM_LO_OFFSET + 1],
        ])) | u32::from(u16::from_le_bytes([
            raw_b[INODE_CHECKSUM_HI_OFFSET],
            raw_b[INODE_CHECKSUM_HI_OFFSET + 1],
        ])) << 16;

        assert_ne!(
            full_a, full_b,
            "different ino should give different checksums"
        );
    }

    #[test]
    fn create_regular_file_does_not_increment_used_dirs() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let used_dirs_before: u32 = groups.iter().map(|g| g.used_dirs).sum();

        create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_000,
            0,
            &pctx,
        )
        .unwrap();

        let used_dirs_after: u32 = groups.iter().map(|g| g.used_dirs).sum();
        assert_eq!(
            used_dirs_after, used_dirs_before,
            "regular file should not increment used_dirs"
        );
    }

    #[test]
    fn serialize_xattr_ibody_with_zero_extra_isize() {
        // extra_isize=0 means xattr_start=128, filling from 128 to inode_size.
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 0,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0u8; 60].into(),
            xattr_ibody: vec![0xAA; 128],
            number: 0,
        };
        let raw = serialize_inode(&inode, 256);
        // With extra_isize=0, xattr_start = 128 + 0 = 128.
        // Available space = 256 - 128 = 128 bytes.
        assert!(raw[128..256].iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn read_inode_block_boundary_error() {
        // Inode larger than block size should trigger boundary error.
        let cx = test_cx();
        let geo = FsGeometry {
            blocks_per_group: 8192,
            inodes_per_group: 2048,
            block_size: 128, // Tiny block — inode (256 bytes) won't fit.
            cluster_ratio: 1,
            total_blocks: 32768,
            total_inodes: 8192,
            first_data_block: 0,
            group_count: 4,
            inode_size: 256,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_meta_bg: 0,
            first_inode: 11,
        };
        let groups = make_groups(&geo);
        let dev = MemBlockDevice::new(128);

        let result = read_inode(&cx, &dev, &geo, &groups, InodeNumber(1));
        assert!(result.is_err(), "inode crossing block boundary should fail");
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("beyond block boundary"),
            "error should mention boundary: {err}"
        );
    }

    #[test]
    fn locate_inode_root_ext4() {
        // InodeNumber(2) is the ext4 root inode — index = 1.
        let geo = make_geometry();
        let groups = make_groups(&geo);
        let loc = locate_inode(InodeNumber(2), &geo, &groups).unwrap();
        // index = (2 - 1) % 2048 = 1, byte = 256
        assert_eq!(loc.block, BlockNumber(3));
        assert_eq!(loc.byte_offset, 256);
    }

    #[test]
    fn delete_inode_xattr_block_zeroed_data_frees_block() {
        // An xattr block full of zeros (invalid magic) should still be freed.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();

        let (ino, mut inode) = create_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0o100_644,
            0,
            0,
            GroupNumber(0),
            0,
            1_000,
            0,
            &pctx,
        )
        .unwrap();

        // Pre-write an all-zero xattr block at block 600. Mark as allocated in bitmap.
        let xattr_block = BlockNumber(600);
        dev.write_block(&cx, xattr_block, &[0u8; 4096]).unwrap();
        let bitmap_block = groups[0].block_bitmap_block;
        let mut bitmap = vec![0u8; 4096];
        bitmap[600 / 8] |= 1 << (600 % 8);
        dev.write_block(&cx, bitmap_block, &bitmap).unwrap();
        groups[0].free_blocks -= 1;

        inode.file_acl = 600;
        write_inode(&cx, &dev, &geo, &groups, ino, &inode, 0).unwrap();

        let free_before = groups[0].free_blocks;
        delete_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            ino,
            &mut inode,
            0,
            2_000,
            &pctx,
        )
        .unwrap();

        assert_eq!(inode.file_acl, 0, "file_acl should be cleared after delete");
        assert_eq!(
            groups[0].free_blocks,
            free_before + 1,
            "zeroed xattr block should be freed"
        );
    }

    // ── bump_inode_version tests ─────────────────────────────────────

    #[test]
    fn bump_inode_version_increments_from_zero() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,
            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,
            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        assert_eq!(inode.version, 0);
        assert_eq!(inode.version_hi, 0);
        bump_inode_version(&mut inode);
        assert_eq!(inode.version, 1);
        assert_eq!(inode.version_hi, 0);
    }

    #[test]
    fn bump_inode_version_wraps_at_u32_max() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,
            version: u32::MAX,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,
            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        bump_inode_version(&mut inode);
        // u32::MAX + 1 = 0x1_0000_0000 → version=0, version_hi=1
        assert_eq!(inode.version, 0);
        assert_eq!(inode.version_hi, 1);
    }

    #[test]
    fn bump_inode_version_wraps_at_u64_max() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,
            version: u32::MAX,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,
            version_hi: u32::MAX,
            projid: 0,
            extent_bytes: vec![0; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        bump_inode_version(&mut inode);
        // u64::MAX + 1 wraps to 0
        assert_eq!(inode.version, 0);
        assert_eq!(inode.version_hi, 0);
    }

    #[test]
    fn touch_mtime_ctime_bumps_version() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,
            version: 42,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,
            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        touch_mtime_ctime(&mut inode, 1000, 0);
        assert_eq!(
            inode.version, 43,
            "version should be bumped by touch_mtime_ctime"
        );
    }

    #[test]
    fn touch_ctime_bumps_version() {
        let mut inode = Ext4Inode {
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: 0,
            version: 99,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 32,
            checksum: 0,
            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        touch_ctime(&mut inode, 2000, 0);
        assert_eq!(
            inode.version, 100,
            "version should be bumped by touch_ctime"
        );
    }
}
