//! Offline preparation of allocator-owned ext4 repair tails.
//!
//! Preparation creates ownership, not usable parity. The immutable owner's
//! unwritten extents reserve physical space without exposing previous contents
//! through normal file reads. Headers are read through physical block mappings.

use super::{
    AllocHint, BTreeSet, BlockDevice, BlockNumber, Cx, EXT4_SECTOR_SIZE, EXT4_VALID_FS,
    Ext4AllocState, Ext4Extent, Ext4FileType, Ext4Inode, Ext4Superblock, ExtentTree, FfsError,
    FsGeometry, GroupNumber, InodeNumber, Jbd2Superblock, Mutex, OpenFs, OsStr, Serialize,
    SingleLockDirAlloc, TransactionBlockAdapter, debug, ext4_superblock_requires_journal_recovery,
    parse_extent_tree, parse_to_ffs_error,
};

const OWNER_NAME: &str = ".frankenfs-repair";
const OWNER_MAGIC: &[u8; 8] = b"FFSNAT01";
const OWNER_HEADER_BYTES: usize = 64;
const DESCRIPTOR_BLOCKS: u32 = 2;

/// An ext4 allocation group's owned native repair tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeRepairTail {
    pub group: GroupNumber,
    pub group_start: BlockNumber,
    pub blocks_per_group: u32,
    /// One ownership block, followed by validation storage, symbols and two descriptors.
    pub start: BlockNumber,
    /// Space for a 32-byte digest per group block, excluding the ownership header.
    pub validation_blocks: u32,
    pub repair_blocks: u32,
}

impl NativeRepairTail {
    fn blocks(&self) -> u32 {
        self.validation_blocks + self.repair_blocks + DESCRIPTOR_BLOCKS + 1
    }
}

/// Persisted allocation ownership. This does not certify repair freshness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeRepairStorage {
    pub owner_inode: InodeNumber,
    /// Hundredths of a percent: 500 means five percent of each allocation group.
    pub repair_basis_points: u32,
    pub tails: Vec<NativeRepairTail>,
}

fn tail_plan(sb: &Ext4Superblock, basis_points: u32) -> Result<Vec<NativeRepairTail>, FfsError> {
    if !(100..=1000).contains(&basis_points) {
        return Err(FfsError::Format(
            "native repair overhead must be 1–10 percent".into(),
        ));
    }
    let geo = FsGeometry::from_superblock(sb);
    if geo.group_count > 65_536 {
        return Err(FfsError::InvalidGeometry(
            "native repair group limit exceeded".into(),
        ));
    }
    let mut tails = Vec::with_capacity(geo.group_count as usize);
    let mut logical_blocks = 0_u32;
    for group in 0..geo.group_count {
        let group = GroupNumber(group);
        let blocks = geo.blocks_in_group(group);
        let repair = u32::try_from((u64::from(blocks) * u64::from(basis_points)).div_ceil(10_000))
            .map_err(|_| FfsError::InvalidGeometry("native repair count overflow".into()))?;
        // The full-group digest bound includes more than actual source coverage,
        // which excludes this tail. Encoding can fit its validation table
        // without moving the already-owned symbol and descriptor region.
        let validation_blocks = u32::try_from(
            (u64::from(blocks) * 32).div_ceil(u64::from(sb.block_size)),
        )
        .map_err(|_| FfsError::InvalidGeometry("native validation count overflow".into()))?;
        let reserved = repair
            .checked_add(validation_blocks)
            .and_then(|count| count.checked_add(DESCRIPTOR_BLOCKS + 1))
            .ok_or_else(|| FfsError::InvalidGeometry("native tail overflow".into()))?;
        if repair == 0 || reserved >= blocks {
            return Err(FfsError::InvalidGeometry(format!(
                "native tail leaves no source blocks in group {}",
                group.0
            )));
        }
        logical_blocks = logical_blocks.checked_add(reserved).ok_or_else(|| {
            FfsError::InvalidGeometry("native owner exceeds ext4 logical block limit".into())
        })?;
        let first = geo.group_block_to_absolute(group, 0);
        tails.push(NativeRepairTail {
            group,
            group_start: first,
            blocks_per_group: blocks,
            start: BlockNumber(first.0 + u64::from(blocks - reserved)),
            validation_blocks,
            repair_blocks: repair,
        });
    }
    Ok(tails)
}

fn owner_header(
    sb: &Ext4Superblock,
    owner: InodeNumber,
    generation: u32,
    basis_points: u32,
    tail: &NativeRepairTail,
) -> Vec<u8> {
    let mut bytes = vec![0; sb.block_size as usize];
    bytes[..8].copy_from_slice(OWNER_MAGIC);
    bytes[8..24].copy_from_slice(&sb.uuid);
    bytes[24..28].copy_from_slice(&tail.group.0.to_le_bytes());
    bytes[28..32].copy_from_slice(&sb.groups_count().to_le_bytes());
    bytes[32..40].copy_from_slice(&owner.0.to_le_bytes());
    bytes[40..44].copy_from_slice(&generation.to_le_bytes());
    bytes[44..48].copy_from_slice(&basis_points.to_le_bytes());
    bytes[48..56].copy_from_slice(&tail.start.0.to_le_bytes());
    bytes[56..60].copy_from_slice(&tail.blocks().to_le_bytes());
    let checksum = ffs_ondisk::ext4::ext4_chksum(!0, &bytes[..60]);
    bytes[60..OWNER_HEADER_BYTES].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

fn owner_extents(tails: &[NativeRepairTail]) -> Vec<Ext4Extent> {
    let mut logical = 0;
    let mut extents = Vec::new();
    for tail in tails {
        let mut physical = tail.start.0;
        let mut remaining = tail.blocks();
        while remaining != 0 {
            // 0x8000 alone denotes INITIALIZED length 32768 in ext4.
            let count = remaining.min(32_767) as u16;
            extents.push(Ext4Extent {
                logical_block: logical,
                raw_len: count | 0x8000,
                physical_start: physical,
            });
            logical += u32::from(count);
            physical += u64::from(count);
            remaining -= u32::from(count);
        }
    }
    extents
}

impl OpenFs {
    /// Reserve native repair storage in a clean, exclusively held ext4 image.
    ///
    /// Consumes the view: reopen after success or any ambiguous I/O failure.
    /// All allocation and namespace changes are staged privately and persisted
    /// as one JBD2 transaction. No symbols are encoded and no repair is enabled.
    /// The caller must exclude other image writers for this entire operation.
    ///
    /// # Errors
    /// Refuses unsupported or dirty images, occupied tails, duplicate ownership,
    /// insufficient journal capacity, cancellation, and storage errors.
    pub fn prepare_native_ext4_repair(
        mut self,
        cx: &Cx,
        basis_points: u32,
    ) -> Result<NativeRepairStorage, FfsError> {
        self.require_native_mode("prepare_native_repair_storage")?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if self.is_writable() || self.mvcc_version_count() != 0 {
            return Err(FfsError::Format(
                "native preparation requires a fresh offline view".into(),
            ));
        }
        let sb = self
            .ext4_superblock()
            .ok_or_else(|| {
                FfsError::UnsupportedFeature("native preparation currently requires ext4".into())
            })?
            .clone();
        if sb.state != EXT4_VALID_FS
            || ext4_superblock_requires_journal_recovery(&sb)
            || sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::RECOVER)
        {
            return Err(FfsError::Format(
                "native preparation requires clean ext4; recover offline first".into(),
            ));
        }
        if let Some(reason) = Self::ext4_writer_unsupported_features(&sb) {
            return Err(FfsError::UnsupportedFeature(reason));
        }
        if !sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::EXTENTS) {
            return Err(FfsError::UnsupportedFeature(
                "native repair owner requires extents".into(),
            ));
        }
        let tails = tail_plan(&sb, basis_points)?;
        let root = self.read_native_owner_inode(cx, &sb, InodeNumber(2))?;
        if !root.is_dir() {
            return Err(FfsError::Format(
                "native repair root is not a directory".into(),
            ));
        }
        if root.flags & (ffs_types::EXT4_IMMUTABLE_FL | ffs_types::EXT4_APPEND_FL) != 0 {
            return Err(FfsError::PermissionDenied);
        }
        self.ext4_create_duplicate_precheck(cx, &root, OWNER_NAME.as_bytes())?;
        // Verify persisted checksums and all metadata exclusions while the view
        // is still read-only. One occupied tail refuses the WHOLE conversion.
        for tail in &tails {
            if self.ext4_allocated_blocks_in_range(
                cx,
                tail.group,
                tail.start.0,
                tail.start.0 + u64::from(tail.blocks()),
            )? != 0
            {
                return Err(FfsError::NoSpace);
            }
        }
        self.attach_empty_native_journal(cx, &sb)?;
        let mut alloc = self.load_ext4_alloc_state(cx)?;
        let base = self.direct_block_device_adapter();
        let mut txn = self.mvcc_store.begin();
        let (owner, inode) = {
            let dev = TransactionBlockAdapter {
                base: &base,
                tx: Mutex::new(&mut txn),
            };
            // Claims precede EVERY allocation: the owner tree and root-directory
            // growth must not select a future repair tail as their own storage.
            for tail in &tails {
                if alloc.groups[tail.group.0 as usize].free_blocks < tail.blocks() {
                    return Err(FfsError::NoSpace);
                }
                let claimed = ffs_alloc::claim_blocks(
                    cx,
                    &dev,
                    &alloc.geo,
                    &mut alloc.groups,
                    tail.start,
                    tail.blocks(),
                )?;
                if claimed != tail.blocks() {
                    return Err(FfsError::Corruption {
                        block: tail.start.0,
                        detail: "native reservation did not exclusively claim its entire tail"
                            .into(),
                    });
                }
            }
            let (owner, inode) = Self::stage_native_owner(cx, &dev, &sb, &mut alloc, &tails)?;
            for tail in &tails {
                dev.write_block(
                    cx,
                    tail.start,
                    &owner_header(&sb, owner, inode.generation, basis_points, tail),
                )?;
                let end = tail.start.0 + u64::from(tail.blocks());
                let zero = vec![0; sb.block_size as usize];
                for block in [end - 2, end - 1] {
                    dev.write_block(cx, BlockNumber(block), &zero)?;
                }
            }
            (owner, inode)
        };
        let (secs, nanos) = Self::now_timestamp();
        self.ext4_stage_dir_entry(
            cx,
            &mut txn,
            &mut SingleLockDirAlloc { alloc: &mut alloc },
            InodeNumber(2),
            &root,
            OWNER_NAME.as_bytes(),
            owner,
            Ext4FileType::RegFile,
            sb.csum_seed(),
            secs,
            nanos,
        )?;
        {
            let dev = TransactionBlockAdapter {
                base: &base,
                tx: Mutex::new(&mut txn),
            };
            Self::ext4_write_group_descriptors_to(cx, &alloc, &dev)?;
            let (free_blocks, free_inodes) = Self::ext4_fold_group_free_totals(&alloc);
            self.ext4_write_superblock_free_totals(cx, &dev, free_blocks, free_inodes)?;
        }
        let mut writes = txn
            .write_set()
            .keys()
            .map(|block| {
                (
                    *block,
                    txn.staged_write(*block).expect("write-set entry").to_vec(),
                )
            })
            .collect();
        let mut journal = self.jbd2_writer.as_ref().expect("attached above").lock();
        self.ext4_journal_and_checkpoint(cx, &mut journal, &mut writes)?;
        debug!(
            owner = owner.0,
            generation = inode.generation,
            groups = tails.len(),
            "native_repair_storage_prepared"
        );
        Ok(NativeRepairStorage {
            owner_inode: owner,
            repair_basis_points: basis_points,
            tails,
        })
    }

    fn attach_empty_native_journal(
        &mut self,
        cx: &Cx,
        sb: &Ext4Superblock,
    ) -> Result<(), FfsError> {
        if sb.journal_inum == 0 {
            return Err(FfsError::UnsupportedFeature(
                "native preparation requires an internal ext4 journal".into(),
            ));
        }
        let inode =
            self.read_native_owner_inode(cx, sb, InodeNumber(u64::from(sb.journal_inum)))?;
        self.validate_native_journal_extents(cx, sb, &inode)?;
        let segments = self.collect_ext4_journal_segments(cx, &inode)?;
        let first = segments
            .first()
            .ok_or_else(|| FfsError::Format("native preparation journal is empty".into()))?;
        let raw = self.read_block_vec(cx, first.start)?;
        let journal = Jbd2Superblock::parse(&raw)
            .ok_or_else(|| FfsError::Format("invalid native preparation journal".into()))?;
        // The segmented writer uses block 1 through the complete mapped region.
        // Refuse layouts or feature modes whose interpretation differs from it.
        let supported_incompat = 0x01 | 0x02 | 0x08 | 0x10; // revoke, 64bit, csum v2/v3
        if journal.uuid != sb.uuid
            || journal.block_size != sb.block_size
            || journal.first_log_block != 1
            || u64::from(journal.max_len) != segments.iter().map(|s| s.blocks).sum::<u64>()
            || journal.num_fc_blocks != 0
            || journal.feature_ro_compat != 0
            || journal.feature_compat & !1 != 0
            || journal.feature_incompat & !supported_incompat != 0
            || journal.feature_incompat & 0x18 == 0x18
        {
            return Err(FfsError::UnsupportedFeature(
                "native preparation journal geometry, identity, or features are unsupported".into(),
            ));
        }
        if journal.feature_incompat & 0x18 != 0 {
            let mut checksum_bytes = raw[..1024].to_vec();
            let stored = u32::from_be_bytes(
                checksum_bytes[0xFC..0x100]
                    .try_into()
                    .expect("journal checksum"),
            );
            checksum_bytes[0xFC..0x100].fill(0);
            if raw[0x50] != 4 || ffs_ondisk::ext4::ext4_chksum(!0, &checksum_bytes) != stored {
                return Err(FfsError::Corruption {
                    block: first.start.0,
                    detail: "native preparation journal checksum mismatch".into(),
                });
            }
        }
        if journal.start_block != 0 {
            return Err(FfsError::Format(
                "native preparation requires an empty journal; recover offline first".into(),
            ));
        }
        if !self.attach_ext4_internal_jbd2_writer(cx)? {
            return Err(FfsError::UnsupportedFeature(
                "native preparation requires an internal ext4 journal".into(),
            ));
        }
        Ok(())
    }

    fn validate_native_journal_extents(
        &self,
        cx: &Cx,
        sb: &Ext4Superblock,
        inode: &Ext4Inode,
    ) -> Result<(), FfsError> {
        if inode.flags & ffs_types::EXT4_EXTENTS_FL == 0 {
            return Err(FfsError::UnsupportedFeature(
                "native preparation requires an extent-mapped internal journal".into(),
            ));
        }
        let (extents, nodes) = self.read_native_owner_extents(cx, sb, inode)?;
        let geo = FsGeometry::from_superblock(sb);
        let mut logical = 0_u64;
        let mut physical = Vec::with_capacity(extents.len());
        for extent in extents {
            if extent.is_unwritten()
                || extent.actual_len() == 0
                || u64::from(extent.logical_block) != logical
            {
                return Err(FfsError::Format(
                    "native preparation journal must be initialized and hole-free".into(),
                ));
            }
            let length = u64::from(extent.actual_len());
            logical += length;
            let start = extent.physical_start;
            let end = start.checked_add(length).ok_or_else(|| {
                FfsError::InvalidGeometry("native journal extent overflow".into())
            })?;
            if nodes.range(start..end).next().is_some() {
                return Err(FfsError::Format(
                    "native journal data aliases its extent tree".into(),
                ));
            }
            physical.push((start, end));
            let mut block = start;
            while block < end {
                let relative = block
                    .checked_sub(u64::from(geo.first_data_block))
                    .ok_or_else(|| {
                        FfsError::InvalidGeometry(
                            "native journal extent precedes data blocks".into(),
                        )
                    })?;
                let in_group = relative % u64::from(geo.blocks_per_group);
                let count = (u64::from(geo.blocks_per_group) - in_group).min(end - block);
                self.validate_native_owned_range(
                    cx,
                    block,
                    u32::try_from(count).expect("group-sized range"),
                )?;
                block += count;
            }
        }
        physical.sort_unstable();
        if physical.windows(2).any(|ranges| ranges[0].1 > ranges[1].0)
            || logical.checked_mul(u64::from(sb.block_size)) != Some(inode.size)
        {
            return Err(FfsError::Format(
                "native journal extents alias or disagree with inode size".into(),
            ));
        }
        Ok(())
    }

    fn stage_native_owner(
        cx: &Cx,
        dev: &dyn BlockDevice,
        sb: &Ext4Superblock,
        alloc: &mut Ext4AllocState,
        tails: &[NativeRepairTail],
    ) -> Result<(InodeNumber, Ext4Inode), FfsError> {
        let (secs, nanos) = Self::now_timestamp();
        let (owner, mut inode) = ffs_inode::create_inode(
            cx,
            dev,
            &alloc.geo,
            &mut alloc.groups,
            0o100_400,
            0,
            0,
            GroupNumber(0),
            sb.csum_seed(),
            secs,
            nanos,
            &alloc.persist_ctx,
        )?;
        let mut extent_root = Self::extent_root(&inode);
        for extent in owner_extents(tails) {
            let mut tree_alloc = ffs_extent::GroupBlockAllocator {
                cx,
                dev,
                geo: &alloc.geo,
                groups: &mut alloc.groups,
                hint: AllocHint::default(),
                pctx: &alloc.persist_ctx,
                ino: u32::try_from(owner.0)
                    .map_err(|_| FfsError::InvalidGeometry("owner inode exceeds u32".into()))?,
                generation: inode.generation,
            };
            ffs_btree::insert(cx, dev, &mut extent_root, extent, &mut tree_alloc)?;
        }
        let data_blocks: u64 = tails.iter().map(|tail| u64::from(tail.blocks())).sum();
        let tree_blocks = Self::ext4_count_extent_tree_meta_blocks_via_dev(cx, dev, &extent_root)?;
        Self::set_extent_root(&mut inode, &extent_root);
        inode.size = data_blocks * u64::from(sb.block_size);
        inode.blocks = (data_blocks + tree_blocks) * u64::from(sb.block_size / EXT4_SECTOR_SIZE);
        inode.flags |= ffs_types::EXT4_IMMUTABLE_FL;
        ffs_inode::write_inode(
            cx,
            dev,
            &alloc.geo,
            &alloc.groups,
            owner,
            &inode,
            sb.csum_seed(),
        )?;
        Ok((owner, inode))
    }

    /// Validate persisted ext4 tail ownership after reopening the image.
    /// Does not authorize decoding: zero descriptors mean protection is absent.
    ///
    /// # Errors
    /// Refuses missing, malformed, or incompletely allocated ownership and
    /// propagates storage errors and cancellation.
    pub fn native_ext4_repair_storage(&self, cx: &Cx) -> Result<NativeRepairStorage, FfsError> {
        let sb = self.ext4_superblock().ok_or_else(|| {
            FfsError::UnsupportedFeature("native repair storage requires ext4".into())
        })?;
        if let Some(reason) = Self::ext4_writer_unsupported_features(sb) {
            return Err(FfsError::UnsupportedFeature(reason));
        }
        if sb.state != EXT4_VALID_FS || sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::RECOVER) {
            return Err(FfsError::Format(
                "native ownership discovery requires a clean image".into(),
            ));
        }
        let attr = self.lookup(cx, InodeNumber(2), OsStr::new(OWNER_NAME))?;
        if self.is_writable() || self.mvcc_version_count() != 0 {
            return Err(FfsError::Format(
                "native ownership discovery requires a fresh offline view".into(),
            ));
        }
        let inode = self.read_native_owner_inode(cx, sb, attr.ino)?;
        if inode.mode != 0o100_400
            || inode.flags != ffs_types::EXT4_IMMUTABLE_FL | ffs_types::EXT4_EXTENTS_FL
            || inode.links_count != 1
            || inode.uid != 0
            || inode.gid != 0
        {
            return Err(FfsError::Format("invalid native repair owner inode".into()));
        }
        let (extents, tree_blocks) = self.read_native_owner_extents(cx, sb, &inode)?;
        let first = extents
            .first()
            .ok_or_else(|| FfsError::Format("native repair owner has no extents".into()))?;
        let header = self.read_block_vec(cx, BlockNumber(first.physical_start))?;
        if header.len() < OWNER_HEADER_BYTES || &header[..8] != OWNER_MAGIC {
            return Err(FfsError::Format(
                "native repair ownership header missing".into(),
            ));
        }
        let basis_points =
            u32::from_le_bytes(header[44..48].try_into().expect("checked header length"));
        let tails = tail_plan(sb, basis_points)?;
        if extents != owner_extents(&tails)
            || inode.size
                != tails
                    .iter()
                    .map(|tail| u64::from(tail.blocks()) * u64::from(sb.block_size))
                    .sum::<u64>()
        {
            return Err(FfsError::Format(
                "native repair owner mapping disagrees with group tails".into(),
            ));
        }
        if inode.blocks
            != (inode.size / u64::from(sb.block_size) + tree_blocks.len() as u64)
                * u64::from(sb.block_size / EXT4_SECTOR_SIZE)
        {
            return Err(FfsError::Format(
                "native repair owner block accounting disagrees with extents".into(),
            ));
        }
        for tail in &tails {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            let stored = self.read_block_vec(cx, tail.start)?;
            if stored != owner_header(sb, attr.ino, inode.generation, basis_points, tail) {
                return Err(FfsError::Corruption {
                    block: tail.start.0,
                    detail: "native repair ownership header mismatch".into(),
                });
            }
            self.validate_native_owned_range(cx, tail.start.0, tail.blocks())?;
            if tree_blocks
                .range(tail.start.0..tail.start.0 + u64::from(tail.blocks()))
                .next()
                .is_some()
            {
                return Err(FfsError::Corruption {
                    block: tail.start.0,
                    detail: "native repair tail aliases its extent tree".into(),
                });
            }
        }
        Ok(NativeRepairStorage {
            owner_inode: attr.ino,
            repair_basis_points: basis_points,
            tails,
        })
    }

    fn read_native_owner_inode(
        &self,
        cx: &Cx,
        sb: &Ext4Superblock,
        ino: InodeNumber,
    ) -> Result<Ext4Inode, FfsError> {
        let number = u32::try_from(ino.0)
            .map_err(|_| FfsError::InvalidGeometry("native owner inode exceeds u32".into()))?;
        let loc = sb.locate_inode(ino).map_err(|e| parse_to_ffs_error(&e))?;
        let gd = self.read_group_desc(cx, loc.group)?;
        let bitmap = self.read_inode_bitmap(cx, loc.group)?;
        if gd.flags & ffs_ondisk::ext4::EXT4_BG_INODE_UNINIT != 0
            || !ffs_alloc::bitmap_get(&bitmap, loc.index)
        {
            return Err(FfsError::Corruption {
                block: gd.inode_bitmap,
                detail: "native owner inode is not allocated".into(),
            });
        }
        self.with_latest_scope(|scope| {
            self.read_inode_raw_with_scope_using(cx, scope, ino, |bytes| {
                if sb.has_metadata_csum() {
                    ffs_ondisk::ext4::verify_inode_checksum(
                        bytes,
                        sb.csum_seed(),
                        number,
                        sb.inode_size,
                    )?;
                }
                Ext4Inode::parse_from_bytes(bytes)
            })
        })
    }

    fn validate_native_owned_range(
        &self,
        cx: &Cx,
        start: u64,
        blocks: u32,
    ) -> Result<(), FfsError> {
        let alloc = self.load_ext4_alloc_state(cx)?;
        let geo = &alloc.geo;
        let relative = start
            .checked_sub(u64::from(geo.first_data_block))
            .ok_or_else(|| {
                FfsError::InvalidGeometry("native ownership precedes data blocks".into())
            })?;
        let group = GroupNumber(
            u32::try_from(relative / u64::from(geo.blocks_per_group))
                .map_err(|_| FfsError::InvalidGeometry("native ownership group overflow".into()))?,
        );
        let offset = relative % u64::from(geo.blocks_per_group);
        let end = offset + u64::from(blocks);
        if group.0 >= geo.group_count || end > u64::from(geo.blocks_in_group(group)) {
            return Err(FfsError::InvalidGeometry(
                "native ownership crosses allocation group".into(),
            ));
        }
        if Self::ext4_repair_metadata_clusters(geo, &alloc.groups, group)?
            .iter()
            .any(|&(a, b)| a < end && offset < b)
        {
            return Err(FfsError::Corruption {
                block: start,
                detail: "native ownership overlaps filesystem metadata".into(),
            });
        }
        let gd = self.read_group_desc(cx, group)?;
        let bitmap = self.read_block_bitmap(cx, group)?;
        if gd.flags & ffs_ondisk::ext4::EXT4_BG_BLOCK_UNINIT != 0
            || (offset..end).any(|bit| {
                !ffs_alloc::bitmap_get(&bitmap, u32::try_from(bit).expect("group bitmap index"))
            })
        {
            return Err(FfsError::Corruption {
                block: start,
                detail: "native ownership block is not allocated".into(),
            });
        }
        Ok(())
    }

    fn read_native_owner_extents(
        &self,
        cx: &Cx,
        sb: &Ext4Superblock,
        inode: &Ext4Inode,
    ) -> Result<(Vec<Ext4Extent>, BTreeSet<u64>), FfsError> {
        let (header, root) =
            parse_extent_tree(&Self::extent_root(inode)).map_err(|e| parse_to_ffs_error(&e))?;
        if header.depth > 5 {
            return Err(FfsError::Format(
                "native owner extent tree is too deep".into(),
            ));
        }
        let mut stack = vec![(header.depth, root)];
        let mut extents = Vec::new();
        let mut nodes = BTreeSet::new();
        while let Some((depth, tree)) = stack.pop() {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            match tree {
                ExtentTree::Leaf(leaves) => extents.extend(leaves),
                ExtentTree::Index(indices) => {
                    for index in indices.into_iter().rev() {
                        if nodes.len() >= 262_144 || !nodes.insert(index.leaf_block) {
                            return Err(FfsError::Format(
                                "native owner has an oversized or aliased extent tree".into(),
                            ));
                        }
                        self.validate_native_owned_range(cx, index.leaf_block, 1)?;
                        let bytes = self.read_block_vec(cx, BlockNumber(index.leaf_block))?;
                        if sb.has_metadata_csum() {
                            ffs_ondisk::ext4::verify_extent_block_checksum(
                                &bytes,
                                sb.csum_seed(),
                                u32::try_from(inode.number).expect("verified owner inode"),
                                inode.generation,
                            )
                            .map_err(|e| parse_to_ffs_error(&e))?;
                        }
                        let (child, tree) =
                            parse_extent_tree(&bytes).map_err(|e| parse_to_ffs_error(&e))?;
                        if child.depth.checked_add(1) != Some(depth) {
                            return Err(FfsError::Format(
                                "native owner extent tree depth mismatch".into(),
                            ));
                        }
                        stack.push((child.depth, tree));
                    }
                }
            }
        }
        Ok((extents, nodes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_owner_unwritten_extents_split_before_initialized_length_sentinel() {
        let extents = owner_extents(&[NativeRepairTail {
            group: GroupNumber(0),
            group_start: BlockNumber(0),
            blocks_per_group: 524_288,
            start: BlockNumber(470_000),
            validation_blocks: 256,
            repair_blocks: 52_429,
        }]);
        assert_eq!(
            extents,
            vec![
                Ext4Extent {
                    logical_block: 0,
                    physical_start: 470_000,
                    raw_len: 0xFFFF
                },
                Ext4Extent {
                    logical_block: 32_767,
                    physical_start: 502_767,
                    raw_len: 0x8000 | 0x4DD1
                },
            ]
        );
        assert!(extents.iter().all(|extent| extent.is_unwritten()));
    }
}
