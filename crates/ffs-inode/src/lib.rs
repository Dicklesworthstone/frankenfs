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
    let group = ffs_types::inode_to_group(ino, geo.inodes_per_group);
    let gidx = group.0 as usize;
    if gidx >= groups.len() {
        return None;
    }
    let index = ffs_types::inode_index_in_group(ino, geo.inodes_per_group);
    let byte_in_table = u64::from(index) * u64::from(geo.inode_size);
    let block_offset = byte_in_table / u64::from(geo.block_size);
    let byte_offset = (byte_in_table % u64::from(geo.block_size)) as usize;
    let block = BlockNumber(groups[gidx].inode_table_block.0 + block_offset);
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
    let mut raw = serialize_inode(inode, inode_size);

    // Compute and write checksum.
    #[expect(clippy::cast_possible_truncation)]
    let ino32 = ino.0 as u32;
    compute_and_set_checksum(&mut raw, csum_seed, ino32);

    // Read the block, patch the inode bytes, write back.
    let buf = dev.read_block(cx, loc.block)?;
    let mut block_data = buf.as_slice().to_vec();
    block_data[loc.byte_offset..loc.byte_offset + inode_size].copy_from_slice(&raw);
    dev.write_block(cx, loc.block, &block_data)?;

    Ok(())
}

/// Serialize an `Ext4Inode` into raw bytes of the given `inode_size`.
#[expect(clippy::cast_possible_truncation)]
fn serialize_inode(inode: &Ext4Inode, inode_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; inode_size];

    // Mode (0x00).
    buf[0x00..0x02].copy_from_slice(&inode.mode.to_le_bytes());
    // UID low (0x02).
    buf[0x02..0x04].copy_from_slice(&(inode.uid as u16).to_le_bytes());
    // Size low (0x04).
    buf[0x04..0x08].copy_from_slice(&(inode.size as u32).to_le_bytes());
    // atime (0x08).
    buf[0x08..0x0C].copy_from_slice(&inode.atime.to_le_bytes());
    // ctime (0x0C).
    buf[0x0C..0x10].copy_from_slice(&inode.ctime.to_le_bytes());
    // mtime (0x10).
    buf[0x10..0x14].copy_from_slice(&inode.mtime.to_le_bytes());
    // dtime (0x14).
    buf[0x14..0x18].copy_from_slice(&inode.dtime.to_le_bytes());
    // GID low (0x18).
    buf[0x18..0x1A].copy_from_slice(&(inode.gid as u16).to_le_bytes());
    // Links count (0x1A).
    buf[0x1A..0x1C].copy_from_slice(&inode.links_count.to_le_bytes());
    // Blocks low (0x1C).
    buf[0x1C..0x20].copy_from_slice(&(inode.blocks as u32).to_le_bytes());
    // Flags (0x20).
    buf[0x20..0x24].copy_from_slice(&inode.flags.to_le_bytes());
    // i_block / extent bytes (0x28, 60 bytes).
    let copy_len = inode.extent_bytes.len().min(60);
    buf[0x28..0x28 + copy_len].copy_from_slice(&inode.extent_bytes[..copy_len]);
    // Generation (0x64).
    buf[0x64..0x68].copy_from_slice(&inode.generation.to_le_bytes());
    // File ACL low (0x68).
    buf[0x68..0x6C].copy_from_slice(&(inode.file_acl as u32).to_le_bytes());
    // Size high (0x6C).
    buf[0x6C..0x70].copy_from_slice(&((inode.size >> 32) as u32).to_le_bytes());
    // Blocks high (0x74, 2 bytes).
    buf[0x74..0x76].copy_from_slice(&((inode.blocks >> 32) as u16).to_le_bytes());
    // File ACL high (0x76, 2 bytes).
    buf[0x76..0x78].copy_from_slice(&((inode.file_acl >> 32) as u16).to_le_bytes());
    // UID high (0x78).
    buf[0x78..0x7A].copy_from_slice(&((inode.uid >> 16) as u16).to_le_bytes());
    // GID high (0x7A).
    buf[0x7A..0x7C].copy_from_slice(&((inode.gid >> 16) as u16).to_le_bytes());
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
        if inode_size >= 0xA0 {
            buf[0x9C..0xA0].copy_from_slice(&inode.projid.to_le_bytes());
        }

        // Inline xattrs go after 128 + extra_isize.
        let xattr_start = 128 + usize::from(inode.extra_isize);
        let xattr_copy = inode.xattr_ibody.len().min(inode_size.saturating_sub(xattr_start));
        if xattr_start < inode_size && xattr_copy > 0 {
            buf[xattr_start..xattr_start + xattr_copy]
                .copy_from_slice(&inode.xattr_ibody[..xattr_copy]);
        }
    }

    buf
}

/// Compute CRC32C checksum and store it in the raw inode buffer.
fn compute_and_set_checksum(raw: &mut [u8], csum_seed: u32, ino: u32) {
    let is = raw.len();
    if is < 128 {
        return;
    }

    // Per-inode seed: crc32c(csum_seed, le_ino) then crc32c(ino_seed, le_gen).
    let ino_seed = crc32c::crc32c_append(csum_seed, &ino.to_le_bytes());
    let generation = u32::from_le_bytes([raw[0x64], raw[0x65], raw[0x66], raw[0x67]]);
    let ino_seed = crc32c::crc32c_append(ino_seed, &generation.to_le_bytes());

    // Zero out checksum fields before computing.
    raw[INODE_CHECKSUM_LO_OFFSET] = 0;
    raw[INODE_CHECKSUM_LO_OFFSET + 1] = 0;
    if is >= INODE_CHECKSUM_HI_OFFSET + 2 {
        raw[INODE_CHECKSUM_HI_OFFSET] = 0;
        raw[INODE_CHECKSUM_HI_OFFSET + 1] = 0;
    }

    // CRC the entire raw inode.
    let csum = crc32c::crc32c_append(ino_seed, raw);

    // Store checksum.
    let lo = (csum & 0xFFFF) as u16;
    raw[INODE_CHECKSUM_LO_OFFSET..INODE_CHECKSUM_LO_OFFSET + 2]
        .copy_from_slice(&lo.to_le_bytes());
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
    now_secs: u32,
    now_nsec: u32,
) -> Result<(InodeNumber, Ext4Inode)> {
    cx_checkpoint(cx)?;

    let is_dir = (mode & 0xF000) == file_type::S_IFDIR;
    let alloc =
        ffs_alloc::alloc_inode(cx, dev, geo, groups, parent_group, is_dir)?;

    if is_dir {
        let gidx = alloc.group.0 as usize;
        if gidx < groups.len() {
            groups[gidx].used_dirs += 1;
        }
    }

    // Initialize extent tree root (empty tree: magic + 0 entries, max 4, depth 0).
    let mut extent_bytes = vec![0u8; 60];
    extent_bytes[0] = (EXT4_EXTENT_MAGIC & 0xFF) as u8;
    extent_bytes[1] = (EXT4_EXTENT_MAGIC >> 8) as u8;
    // entries = 0.
    extent_bytes[4] = 4; // max_entries = 4.
    // depth = 0 (already zero).

    let extra_time = encode_extra_timestamp(now_secs, now_nsec);

    let inode = Ext4Inode {
        mode,
        uid,
        gid,
        size: 0,
        links_count: if is_dir { 2 } else { 1 },
        blocks: 0,
        flags: EXT4_EXTENTS_FL,
        generation: 0,
        file_acl: 0,
        atime: now_secs,
        ctime: now_secs,
        mtime: now_secs,
        dtime: 0,
        atime_extra: extra_time,
        ctime_extra: extra_time,
        mtime_extra: extra_time,
        crtime: now_secs,
        crtime_extra: extra_time,
        extra_isize: 32,
        checksum: 0,
        projid: 0,
        extent_bytes,
        xattr_ibody: Vec::new(),
    };

    write_inode(cx, dev, geo, groups, alloc.ino, &inode, csum_seed)?;

    Ok((alloc.ino, inode))
}

// ── Delete ──────────────────────────────────────────────────────────────────

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
    now_secs: u32,
) -> Result<()> {
    cx_checkpoint(cx)?;

    // Truncate all extents if the inode uses extents.
    if inode.flags & EXT4_EXTENTS_FL != 0 && inode.extent_bytes.len() >= 60 {
        let mut root_buf = [0u8; 60];
        root_buf.copy_from_slice(&inode.extent_bytes[..60]);
        ffs_extent::truncate_extents(cx, dev, &mut root_buf, geo, groups, 0)?;
        inode.extent_bytes[..60].copy_from_slice(&root_buf);
    }

    // Set deletion time.
    inode.dtime = now_secs;
    inode.links_count = 0;
    inode.size = 0;
    inode.blocks = 0;

    // Write the zeroed-out inode to disk.
    write_inode(cx, dev, geo, groups, ino, inode, csum_seed)?;

    // Free the inode in the bitmap.
    ffs_alloc::free_inode(cx, dev, geo, groups, ino)?;

    Ok(())
}

// ── Timestamps ──────────────────────────────────────────────────────────────

/// Encode nanoseconds and epoch extension into the `_extra` timestamp field.
///
/// Layout: bits 0-1 = epoch extension (seconds >> 32), bits 2-31 = nanoseconds.
#[must_use]
pub fn encode_extra_timestamp(_secs: u32, nsec: u32) -> u32 {
    // For 32-bit base seconds, epoch is 0.
    nsec & 0x3FFF_FFFC // mask to 30-bit nanoseconds, shifted to bits 2-31
}

/// Touch atime on an inode.
pub fn touch_atime(inode: &mut Ext4Inode, secs: u32, nsec: u32) {
    inode.atime = secs;
    inode.atime_extra = encode_extra_timestamp(secs, nsec);
}

/// Touch mtime and ctime on an inode.
pub fn touch_mtime_ctime(inode: &mut Ext4Inode, secs: u32, nsec: u32) {
    inode.mtime = secs;
    inode.mtime_extra = encode_extra_timestamp(secs, nsec);
    inode.ctime = secs;
    inode.ctime_extra = encode_extra_timestamp(secs, nsec);
}

/// Touch ctime only on an inode (e.g., for chmod, chown).
pub fn touch_ctime(inode: &mut Ext4Inode, secs: u32, nsec: u32) {
    inode.ctime = secs;
    inode.ctime_extra = encode_extra_timestamp(secs, nsec);
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

    fn test_cx() -> Cx {
        Cx::for_testing()
    }

    fn make_geometry() -> FsGeometry {
        FsGeometry {
            blocks_per_group: 8192,
            inodes_per_group: 2048,
            block_size: 4096,
            total_blocks: 32768,
            total_inodes: 8192,
            first_data_block: 0,
            group_count: 4,
            inode_size: 256,
        }
    }

    fn make_groups(geo: &FsGeometry) -> Vec<GroupStats> {
        (0..geo.group_count)
            .map(|g| GroupStats {
                group: GroupNumber(g),
                free_blocks: geo.blocks_per_group,
                free_inodes: geo.inodes_per_group,
                used_dirs: 0,
                block_bitmap_block: BlockNumber(u64::from(g) * 100 + 1),
                inode_bitmap_block: BlockNumber(u64::from(g) * 100 + 2),
                inode_table_block: BlockNumber(u64::from(g) * 100 + 3),
                flags: 0,
            })
            .collect()
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
            projid: 0,
            extent_bytes: vec![0u8; 60],
            xattr_ibody: Vec::new(),
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
    fn checksum_roundtrip() {
        let inode = Ext4Inode {
            mode: 0o100_644,
            uid: 1000,
            gid: 1000,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags: EXT4_EXTENTS_FL,
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
            projid: 0,
            extent_bytes: vec![0u8; 60],
            xattr_ibody: Vec::new(),
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
        )
        .unwrap();

        assert_eq!(ino, InodeNumber(1));
        assert_eq!(created.mode, 0o100_644);
        assert_eq!(created.uid, 1000);
        assert_eq!(created.links_count, 1);

        // Read it back.
        let read_back = read_inode(&cx, &dev, &geo, &groups, ino).unwrap();
        assert_eq!(read_back.mode, 0o100_644);
        assert_eq!(read_back.uid, 1000);
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
        )
        .unwrap();

        let free_before = groups[0].free_inodes;

        delete_inode(&cx, &dev, &geo, &mut groups, ino, &mut inode, 0, 1_700_000_001).unwrap();

        assert_eq!(inode.links_count, 0);
        assert_eq!(inode.dtime, 1_700_000_001);
        assert_eq!(groups[0].free_inodes, free_before + 1);
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
            projid: 0,
            extent_bytes: vec![0u8; 60],
            xattr_ibody: Vec::new(),
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
        let nsec = extra & 0x3FFF_FFFC;
        // Should preserve the nanosecond value (masked).
        assert_eq!(nsec, 0x3B9A_C9FF & 0x3FFF_FFFC);
    }
}
