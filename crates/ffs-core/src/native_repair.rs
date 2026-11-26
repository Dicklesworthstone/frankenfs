//! Allocator-owned ext4 and btrfs repair storage, source validation and active freshness.
//!
//! Preparation creates ownership, not usable parity. The immutable owner's
//! unwritten/preallocated extents reserve physical space without exposing
//! previous contents through normal file reads. Headers are read through
//! physical block mappings.

use super::{
    AllocHint, BTRFS_FILE_EXTENT_PREALLOC, BTRFS_FIRST_FREE_OBJECTID, BTRFS_FS_TREE_OBJECTID,
    BTRFS_INODE_IMMUTABLE, BTRFS_INODE_NODATASUM, BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_INODE_ITEM,
    BTreeSet, BlockDevice, BlockNumber, BtrfsAllocState, BtrfsExtentData, BtrfsKey,
    BtrfsSuperblock, ByteDeviceBlockAdapter, Cx, EXT4_SECTOR_SIZE, EXT4_VALID_FS, Ext4AllocState,
    Ext4Extent, Ext4FileType, Ext4Inode, Ext4Superblock, ExtentTree, FfsError, FsGeometry,
    GroupNumber, InodeNumber, Jbd2Superblock, Mutex, OpenFs, OsStr, Serialize, SingleLockDirAlloc,
    TransactionBlockAdapter, btrfs_mutation_to_ffs, debug,
    ext4_superblock_requires_journal_recovery, map_logical_to_physical, parse_extent_data,
    parse_extent_tree, parse_to_ffs_error, read_ext4_superblock_region,
};
use asupersync::raptorq::systematic::EmittedSymbol;
use asupersync::sync::{
    LockError, Mutex as NativeMutex, MutexGuard as NativeMutexGuard, OnceCell, TryLockError,
};
use ffs_block::{BlockBuf, ByteDevice};
use ffs_btrfs::{BTRFS_INODE_NODATACOW, BtrfsBTree};
use ffs_repair::codec::{
    BlockDelta, DirectEncodeRequest, EncodedGroup, direct_encode_workspace_bytes,
    encode_group_direct, update_encoded_group_delta, warm_group_delta_encoder,
};
use ffs_repair::evidence::AnytimeScrubMonitorDetail;
use ffs_repair::recovery::{GroupRecoveryOrchestrator, RecoveryWriteback, RecoveryWritebackBlock};
use ffs_repair::scrub::{
    BlockValidator, BlockVerdict, CorruptionKind, Severity, VilleWaldConfig, VilleWaldScrubMonitor,
};
use ffs_repair::storage::{RawRefreshAdmission, RepairGroupLayout, RepairGroupStorage};
use ffs_repair::symbol::{RepairGroupDescExt, repair_seed};
use ffs_types::{BTRFS_SUPER_INFO_OFFSET, ByteOffset};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

const OWNER_NAME: &str = ".frankenfs-repair";
const OWNER_MAGIC: &[u8; 8] = b"FFSNAT01";
const OWNER_HEADER_BYTES: usize = 64;
const DESCRIPTOR_BLOCKS: u32 = 2;
const VALIDATION_MAGIC: &[u8; 8] = b"FFSVAL01";
const VALIDATION_HEADER_BYTES: usize = 128;
const MAX_VALIDATION_TABLE_BYTES: usize = 32 * 1024 * 1024;
const VALIDATION_PENDING: u32 = 1;
const VALIDATION_SEALED: u32 = 2;
const PLAN_PREPARED: u32 = 3;
const PLAN_DIRTY: u32 = 4;
const PLAN_MAGIC: &[u8; 8] = b"FFSPLN01";
const PLAN_HEADER_START: usize = OWNER_HEADER_BYTES + VALIDATION_HEADER_BYTES;
const PLAN_HEADER_END: usize = PLAN_HEADER_START + VALIDATION_HEADER_BYTES;
const PARITY_MAGIC: &[u8; 8] = b"FFSRPR01";
const PARITY_HEADER_START: usize = PLAN_HEADER_END;
const PARITY_HEADER_END: usize = PARITY_HEADER_START + VALIDATION_HEADER_BYTES;
const EPOCH_TOKEN_MAGIC: &[u8; 8] = b"FFSEPK02";
const EPOCH_TOKEN_START: usize = PARITY_HEADER_END;
const EPOCH_TOKEN_BYTES: usize = 160;
const EPOCH_TOKEN_END: usize = EPOCH_TOKEN_START + EPOCH_TOKEN_BYTES;
const EPOCH_TOKEN_FLAG_FORMAT_COMMIT: u32 = 1 << 0;
const DIRTY_BUCKET_COUNT: usize = 512;
const MAX_DELTA_BEFOREIMAGE_BLOCKS: usize = 512;
const BTRFS_NATIVE_GROUP_MAX_BLOCKS: u32 = 512;
const BTRFS_NATIVE_OWNER_FLAGS: u64 =
    BTRFS_INODE_IMMUTABLE | BTRFS_INODE_NODATASUM | BTRFS_INODE_NODATACOW;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeFsIdentity {
    uuid: [u8; 16],
    block_size: u32,
    group_count: u32,
}

impl NativeFsIdentity {
    fn from_ext4(sb: &Ext4Superblock) -> Self {
        Self {
            uuid: sb.uuid,
            block_size: sb.block_size,
            group_count: sb.groups_count(),
        }
    }

    fn from_btrfs(sb: &BtrfsSuperblock, group_count: u32) -> Self {
        Self {
            uuid: sb.fsid,
            block_size: sb.sectorsize,
            group_count,
        }
    }
}

/// Format-bound crash recovery token persisted in `tails[0].start[448..608)`
/// while a journaled/COW durability commit or epoch publication is in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeEpochToken {
    owner_inode: InodeNumber,
    owner_generation: u32,
    target_epoch: u32,
    prev_sealed_epoch: u32,
    flags: u32,
    pre_epoch_commit_seq: u64,
    prev_sealed_plan_root: [u8; 32],
    dirty_group_buckets: [u8; 64],
}

impl NativeEpochToken {
    fn bucket_bit(group: GroupNumber) -> (usize, u8) {
        let bucket = (group.0 as usize) & (DIRTY_BUCKET_COUNT - 1);
        (bucket / 8, 1_u8 << (bucket % 8))
    }

    fn mark_bucket(buckets: &mut [u8; 64], group: GroupNumber) {
        let (byte, mask) = Self::bucket_bit(group);
        buckets[byte] |= mask;
    }

    fn bucket_contains(buckets: &[u8; 64], group: GroupNumber) -> bool {
        let (byte, mask) = Self::bucket_bit(group);
        buckets[byte] & mask != 0
    }

    fn is_group_dirty(&self, group: GroupNumber) -> bool {
        Self::bucket_contains(&self.dirty_group_buckets, group)
    }

    fn encode(&self, id: &NativeFsIdentity) -> [u8; EPOCH_TOKEN_BYTES] {
        let mut bytes = [0_u8; EPOCH_TOKEN_BYTES];
        bytes[..8].copy_from_slice(EPOCH_TOKEN_MAGIC);
        bytes[8..24].copy_from_slice(&id.uuid);
        bytes[24..32].copy_from_slice(&self.owner_inode.0.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.owner_generation.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.target_epoch.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.prev_sealed_epoch.to_le_bytes());
        bytes[44..48].copy_from_slice(&self.flags.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.pre_epoch_commit_seq.to_le_bytes());
        bytes[56..88].copy_from_slice(&self.prev_sealed_plan_root);
        bytes[88..152].copy_from_slice(&self.dirty_group_buckets);
        let checksum = ffs_ondisk::ext4::ext4_chksum(!0, &bytes[..152]);
        bytes[152..156].copy_from_slice(&checksum.to_le_bytes());
        bytes
    }

    fn decode_optional(
        bytes: &[u8],
        id: &NativeFsIdentity,
        owner_inode: InodeNumber,
        owner_generation: u32,
        tail0: &NativeRepairTail,
    ) -> Result<Option<Self>, FfsError> {
        if bytes.len() != EPOCH_TOKEN_BYTES {
            return Err(validation_error(tail0, "epoch token length mismatch"));
        }
        if bytes.iter().all(|&byte| byte == 0) {
            return Ok(None);
        }
        if &bytes[..8] != EPOCH_TOKEN_MAGIC || bytes[156..160] != [0; 4] {
            return Err(validation_error(tail0, "epoch token magic or pad invalid"));
        }
        let target_epoch = u32::from_le_bytes(bytes[36..40].try_into().expect("fixed slice"));
        let prev_sealed_epoch = u32::from_le_bytes(bytes[40..44].try_into().expect("fixed slice"));
        let flags = u32::from_le_bytes(bytes[44..48].try_into().expect("fixed slice"));
        let pre_epoch_commit_seq =
            u64::from_le_bytes(bytes[48..56].try_into().expect("fixed slice"));
        let prev_sealed_plan_root: [u8; 32] = bytes[56..88].try_into().expect("fixed slice");
        let dirty_group_buckets: [u8; 64] = bytes[88..152].try_into().expect("fixed slice");
        let token = Self {
            owner_inode,
            owner_generation,
            target_epoch,
            prev_sealed_epoch,
            flags,
            pre_epoch_commit_seq,
            prev_sealed_plan_root,
            dirty_group_buckets,
        };
        if prev_sealed_epoch == 0
            || target_epoch != prev_sealed_epoch.saturating_add(1)
            || flags & !EPOCH_TOKEN_FLAG_FORMAT_COMMIT != 0
            || bytes != token.encode(id)
        {
            return Err(validation_error(
                tail0,
                "epoch token identity or checksum mismatch",
            ));
        }
        Ok(Some(token))
    }
}

/// An allocation group's owned native repair storage (in-group tail on ext4,
/// or detached `PREALLOC` extent slice on btrfs).
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
    #[must_use]
    pub fn blocks(&self) -> u32 {
        self.validation_blocks + self.repair_blocks + DESCRIPTOR_BLOCKS + 1
    }

    #[must_use]
    pub fn is_detached(&self) -> bool {
        let Some(group_end) = self
            .group_start
            .0
            .checked_add(u64::from(self.blocks_per_group))
        else {
            return true;
        };
        self.start.0 < self.group_start.0 || self.start.0 >= group_end
    }

    #[must_use]
    pub fn source_end_exclusive(&self) -> BlockNumber {
        if self.is_detached() {
            BlockNumber(
                self.group_start
                    .0
                    .saturating_add(u64::from(self.blocks_per_group)),
            )
        } else {
            self.start
        }
    }

    fn source_blocks(&self) -> Result<u32, FfsError> {
        if self.is_detached() {
            let group_end = self
                .group_start
                .0
                .checked_add(u64::from(self.blocks_per_group))
                .ok_or_else(|| validation_error(self, "detached source range overflows"))?;
            let tail_end = self
                .start
                .0
                .checked_add(u64::from(self.blocks()))
                .ok_or_else(|| validation_error(self, "detached storage range overflows"))?;
            if self.start.0 < group_end && self.group_start.0 < tail_end {
                return Err(validation_error(
                    self,
                    "detached storage overlaps source range",
                ));
            }
            Ok(self.blocks_per_group)
        } else {
            let sources = self
                .start
                .0
                .checked_sub(self.group_start.0)
                .ok_or_else(|| validation_error(self, "source range underflows"))?;
            u32::try_from(sources).map_err(|_| validation_error(self, "source count exceeds u32"))
        }
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

/// Source data checked against persisted native validation records.
/// This does not certify repair-symbol freshness or authorize decoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeValidationReport {
    pub owner_inode: InodeNumber,
    pub groups: u32,
    pub source_blocks: u64,
}

/// Complete offline parity checked against the immutable native baseline.
/// Does not authorize mounted repair or establish freshness after later writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeRepairReport {
    pub owner_inode: InodeNumber,
    pub groups: u32,
    pub source_blocks: u64,
    pub repair_blocks: u64,
    pub generations: Vec<u64>,
}

/// Summary of an active native scrub + self-healing pass across all groups.
#[derive(Debug, Clone, PartialEq)]
pub struct NativeScrubHealReport {
    pub groups_scanned: u32,
    pub source_blocks_scanned: u64,
    pub corrupted_blocks_detected: u64,
    pub blocks_healed: u64,
    pub recommended_interval_divisor: u32,
    pub recommended_overhead_bps: u32,
    pub monitor: AnytimeScrubMonitorDetail,
}

/// A reconstructed block from the sealed baseline, without image writeback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeReconstruction {
    pub block: BlockNumber,
    pub generation: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParityIntent {
    Prepared,
    Pending {
        generation: u64,
        source_root: [u8; 32],
    },
    Sealed {
        generation: u64,
        source_root: [u8; 32],
        manifest: [u8; 32],
    },
}

impl ParityIntent {
    fn generation(self) -> u64 {
        match self {
            Self::Prepared => 0,
            Self::Pending { generation, .. } | Self::Sealed { generation, .. } => generation,
        }
    }

    fn source_root(self) -> [u8; 32] {
        match self {
            Self::Prepared => [0; 32],
            Self::Pending { source_root, .. } | Self::Sealed { source_root, .. } => source_root,
        }
    }
}

struct NativeBaseline {
    storage: NativeRepairStorage,
    owner_generation: u32,
    epoch: u32,
    plan_root: [u8; 32],
    roots: Vec<[u8; 32]>,
    group_epochs: Vec<u32>,
}

struct NativeGroupAdmission {
    intent: ParityIntent,
    raw: RawRefreshAdmission,
    retained: bool,
    codec_budget: u64,
    next_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationIntent {
    Empty,
    Prepared,
    Dirty([u8; 32]),
    Pending([u8; 32]),
    Sealed([u8; 32]),
}

struct ValidationAdmission {
    epoch: u32,
    root: [u8; 32],
    intent: ValidationIntent,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FreshnessPhase {
    Clean,
    Dirty,
    Poisoned,
}

struct NativeFreshnessState {
    baseline: NativeBaseline,
    tables: Vec<Vec<u8>>,
    parity: Vec<ParityIntent>,
    intended: BTreeMap<BlockNumber, [u8; 32]>,
    beforeimages: BTreeMap<BlockNumber, Vec<u8>>,
    dirty_groups: Vec<bool>,
    persisted_dirty_buckets: [u8; 64],
    defer_seal: u32,
    format_commit_seq: Option<u64>,
    pending_dirty_buckets: [u8; 64],
    scrub_monitor: VilleWaldScrubMonitor,
    phase: FreshnessPhase,
}

/// Guard holding a multi-barrier format commit (`ext4_journal_and_checkpoint`,
/// `btrfs_commit_locked`, `btrfs_sync_ephemeral_tree_log`) in deferred-seal
/// mode until its final durability sync.
pub(crate) struct DurabilityCommitGuard<'a> {
    device: Option<&'a NativeFreshnessDevice>,
    byte_deferral: Option<ffs_block::DurabilityCommitDeferral<'a>>,
    armed: bool,
}

impl Drop for DurabilityCommitGuard<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Some(device) = self.device
        {
            device.abort_durability_commit();
        }
    }
}

impl DurabilityCommitGuard<'_> {
    pub(crate) fn arm_final_seal(&mut self, cx: &Cx) -> Result<(), FfsError> {
        if self.armed {
            self.armed = false;
            if let Some(device) = self.device {
                device.arm_final_seal(cx)?;
            }
        }
        if let Some(mut deferral) = self.byte_deferral.take() {
            deferral.complete();
        }
        Ok(())
    }
}

/// The only writable handle published after native freshness admission.
/// Source reads validate current digests and durably repair clean generations.
/// Internal ownership publication uses `inner` under the same state lock.
pub(super) struct NativeFreshnessDevice {
    inner: Arc<dyn ByteDevice>,
    id: NativeFsIdentity,
    state: NativeMutex<NativeFreshnessState>,
    codec_budget: u64,
    ownership: NativeOwnershipConstraints,
}

struct NativeLockWake(std::thread::Thread);

impl Wake for NativeLockWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

struct NativeOwnedBytes {
    expected: Vec<u8>,
    mask: Vec<u8>,
}

struct NativeOwnershipConstraints {
    blocks: BTreeMap<BlockNumber, NativeOwnedBytes>,
    remaining_budget: u64,
}

impl NativeOwnershipConstraints {
    fn protect(
        &mut self,
        cx: &Cx,
        dev: &dyn BlockDevice,
        offset: u64,
        length: u64,
        mask: u8,
    ) -> Result<(), FfsError> {
        let size = u64::from(dev.block_size());
        let end = offset
            .checked_add(length)
            .ok_or_else(|| freshness_error("ownership constraint range overflows"))?;
        let mut cursor = offset;
        while cursor < end {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            let block = BlockNumber(cursor / size);
            if let std::collections::btree_map::Entry::Vacant(entry) = self.blocks.entry(block) {
                // Two retained vectors plus one transient read and map margin.
                let charge = size
                    .checked_mul(3)
                    .and_then(|bytes| bytes.checked_add(256))
                    .ok_or_else(|| freshness_error("ownership constraint budget overflows"))?;
                self.remaining_budget =
                    self.remaining_budget.checked_sub(charge).ok_or_else(|| {
                        freshness_error("working budget is below ownership constraints")
                    })?;
                let expected = dev.read_block(cx, block)?.into_inner();
                if expected.len() != size as usize {
                    return Err(freshness_error("short ownership constraint block"));
                }
                entry.insert(NativeOwnedBytes {
                    mask: vec![0; expected.len()],
                    expected,
                });
            }
            let start = (cursor % size) as usize;
            let count = (end - cursor).min(size - cursor % size) as usize;
            let entry = self.blocks.get_mut(&block).expect("constraint inserted");
            for byte in &mut entry.mask[start..start + count] {
                *byte |= mask;
            }
            cursor += count as u64;
        }
        Ok(())
    }

    fn check(&self, block: BlockNumber, bytes: &[u8]) -> Result<(), FfsError> {
        if let Some(guard) = self.blocks.get(&block)
            && (bytes.len() != guard.expected.len()
                || bytes
                    .iter()
                    .zip(&guard.expected)
                    .zip(&guard.mask)
                    .any(|((&actual, &expected), &mask)| (actual ^ expected) & mask != 0))
        {
            return Err(freshness_error(
                "write changes permanent native allocation ownership",
            ));
        }
        Ok(())
    }

    fn protect_allocated(
        &mut self,
        cx: &Cx,
        dev: &dyn BlockDevice,
        bitmap: BlockNumber,
        bit: u64,
    ) -> Result<(), FfsError> {
        let offset = bitmap
            .0
            .checked_mul(u64::from(dev.block_size()))
            .and_then(|offset| offset.checked_add(bit / 8))
            .ok_or_else(|| freshness_error("ownership bitmap offset overflows"))?;
        let mask = 1_u8 << (bit % 8);
        self.protect(cx, dev, offset, 1, mask)?;
        let block = BlockNumber(offset / u64::from(dev.block_size()));
        let index = (offset % u64::from(dev.block_size())) as usize;
        if self.blocks[&block].expected[index] & mask == 0 {
            return Err(freshness_error("native ownership allocation bit is clear"));
        }
        Ok(())
    }

    fn protect_geometry(&mut self, cx: &Cx, dev: &dyn BlockDevice) -> Result<(), FfsError> {
        // Primary ext4 geometry/identity and routing fields. RECOVER, free
        // counts, timestamps, mount state, last_orphan and checksum remain writable.
        for (start, end) in [
            (0x00, 0x0C),
            (0x14, 0x2C),
            (0x38, 0x3A),
            (0x48, 0x60),
            (0x61, 0x78),
            (0xCE, 0xE8),
            (0xEC, 0xFC),
            (0xFE, 0x100),
            (0x104, 0x108),
            (0x150, 0x158),
            (0x15C, 0x164),
            (0x174, 0x176),
            (0x270, 0x274),
        ] {
            self.protect(cx, dev, 1024 + start, end - start, u8::MAX)?;
        }
        self.protect(cx, dev, 1024 + 0x60, 1, !0x04)
    }

    fn protect_btrfs_superblock(&mut self, cx: &Cx, dev: &dyn BlockDevice) -> Result<(), FfsError> {
        // Primary btrfs identity, geometry, incompat flags and embedded dev_item
        // identity. Mutable commit fields (csum, generation, root, chunk_root,
        // log_root, bytes_used, compat_ro_flags, sys_chunk_array, dev bytes_used)
        // remain writable for COW commits.
        let base = BTRFS_SUPER_INFO_OFFSET as u64;
        for (start, end) in [
            (0x20, 0x38),
            (0x40, 0x48),
            (0x70, 0x78),
            (0x80, 0x88),
            (0x90, 0x9C),
            (0xAC, 0xB4),
            (0xC4, 0xC6),
            (0xC9, 0xD9),
            (0x109, 0x129),
        ] {
            self.protect(cx, dev, base + start, end - start, u8::MAX)?;
        }
        Ok(())
    }

    fn protect_groups(
        &mut self,
        cx: &Cx,
        dev: &dyn BlockDevice,
        sb: &Ext4Superblock,
        storage: &NativeRepairStorage,
        owner_group: GroupNumber,
    ) -> Result<(), FfsError> {
        for tail in &storage.tails {
            let gd = read_native_group_desc(cx, dev, sb, tail.group)?;
            let offset = sb
                .group_desc_offset(tail.group)
                .ok_or_else(|| freshness_error("native descriptor address overflows"))?;
            self.protect(cx, dev, offset, 12, u8::MAX)?;
            self.protect(cx, dev, offset + 0x14, 4, u8::MAX)?;
            if sb.group_desc_size() >= 64 {
                self.protect(cx, dev, offset + 0x20, 12, u8::MAX)?;
                self.protect(cx, dev, offset + 0x34, 4, u8::MAX)?;
            }
            let flags = if tail.group == owner_group {
                0x03
            } else {
                0x02
            };
            if gd.flags & u16::from(flags) != 0 {
                return Err(freshness_error(
                    "native ownership descriptor is uninitialized",
                ));
            }
            self.protect(cx, dev, offset + 0x12, 1, flags)?;
            for block in tail.start.0..tail.start.0 + u64::from(tail.blocks()) {
                self.protect_allocated(
                    cx,
                    dev,
                    BlockNumber(gd.block_bitmap),
                    block - tail.group_start.0,
                )?;
            }
        }
        Ok(())
    }
}

fn freshness_error(detail: &str) -> FfsError {
    FfsError::RepairFailed(format!("native freshness: {detail}"))
}

fn freshness_codec_budget(
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    allowed: u64,
) -> Result<u64, FfsError> {
    let mut retained = 0_u64;
    for tail in &storage.tails {
        let (sources, capacity, _) = validation_sizes(id, tail)?;
        // Old/next tables plus transient publication/readback copies. The
        // per-source allowance covers the intended BTreeMap and staged hashes;
        // codec allocations are admitted separately. This is not an RSS cap.
        let group = (capacity as u64)
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(u64::from(sources) * 128))
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or_else(|| freshness_error("retained metadata budget overflows"))?;
        retained = retained
            .checked_add(group)
            .ok_or_else(|| freshness_error("retained metadata budget overflows"))?;
    }
    allowed
        .checked_sub(retained)
        .ok_or_else(|| freshness_error("working budget is below retained metadata estimate"))
}

fn read_native_group_desc(
    cx: &Cx,
    dev: &dyn BlockDevice,
    sb: &Ext4Superblock,
    group: GroupNumber,
) -> Result<ffs_ondisk::Ext4GroupDesc, FfsError> {
    let offset = sb
        .group_desc_offset(group)
        .ok_or_else(|| freshness_error("native descriptor address overflows"))?;
    let size = u64::from(sb.block_size);
    let block = dev.read_block(cx, BlockNumber(offset / size))?;
    let start = (offset % size) as usize;
    let bytes = block
        .as_slice()
        .get(start..start + usize::from(sb.group_desc_size()))
        .ok_or_else(|| freshness_error("native descriptor crosses its block"))?;
    ffs_ondisk::ext4::verify_group_desc_checksum(
        bytes,
        &sb.uuid,
        sb.csum_seed(),
        group.0,
        sb.group_desc_size(),
        sb.group_desc_checksum_kind(),
    )
    .map_err(|error| parse_to_ffs_error(&error))?;
    ffs_ondisk::Ext4GroupDesc::parse_from_bytes(bytes, sb.group_desc_size())
        .map_err(|error| parse_to_ffs_error(&error))
}

impl NativeFreshnessDevice {
    fn lock(&self, cx: &Cx) -> Result<NativeMutexGuard<'_, NativeFreshnessState>, FfsError> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Locked) => self.wait_for_lock(cx)?,
            Err(TryLockError::Poisoned) => return Err(freshness_error("state mutex is poisoned")),
        };
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if state.phase == FreshnessPhase::Poisoned {
            return Err(freshness_error(
                "device is poisoned after an incomplete operation",
            ));
        }
        Ok(state)
    }

    fn wait_for_lock(
        &self,
        cx: &Cx,
    ) -> Result<NativeMutexGuard<'_, NativeFreshnessState>, FfsError> {
        // ByteDevice operations are synchronous. Poll only this mutex future;
        // its holder performs synchronous I/O and never needs this thread's
        // executor to release the guard. Retain FIFO queueing and cancellation
        // cleanup instead of returning EAGAIN for ordinary concurrent reads.
        let waker = Waker::from(Arc::new(NativeLockWake(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut waiting = std::pin::pin!(self.state.lock(cx));
        loop {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            match waiting.as_mut().poll(&mut context) {
                Poll::Ready(result) => {
                    return result.map_err(|error| match error {
                        LockError::Cancelled => FfsError::Cancelled,
                        other => freshness_error(&format!("state mutex wait failed: {other}")),
                    });
                }
                Poll::Pending => {
                    // Unlock unparks immediately; cancellation does not notify
                    // the mutex waker, so periodically recheck its Cx as well.
                    std::thread::park_timeout(Duration::from_millis(10));
                }
            }
        }
    }

    fn begin_durability_commit<'a>(
        &'a self,
        cx: &Cx,
        pre_commit_seq: u64,
        hinted_blocks: &[BlockNumber],
    ) -> Result<DurabilityCommitGuard<'a>, FfsError> {
        let mut state = self.lock(cx)?;
        for &block in hinted_blocks {
            if let Some(group) = native_source_tail(&state.baseline.storage, block).map(|t| t.group)
            {
                NativeEpochToken::mark_bucket(&mut state.pending_dirty_buckets, group);
            }
        }
        if state.format_commit_seq.is_none() {
            state.format_commit_seq = Some(pre_commit_seq);
        }
        let byte_deferral = ffs_block::DurabilityCommitDeferral::enter(cx, self.inner.as_ref())?;
        state.defer_seal = state
            .defer_seal
            .checked_add(1)
            .ok_or_else(|| freshness_error("durability commit nesting overflow"))?;
        Ok(DurabilityCommitGuard {
            device: Some(self),
            byte_deferral: Some(byte_deferral),
            armed: true,
        })
    }

    fn arm_final_seal(&self, cx: &Cx) -> Result<(), FfsError> {
        let mut state = self.lock(cx)?;
        state.defer_seal = state
            .defer_seal
            .checked_sub(1)
            .ok_or_else(|| freshness_error("durability commit guard underflow"))?;
        Ok(())
    }

    fn abort_durability_commit(&self) {
        let guard = loop {
            match self.state.try_lock() {
                Ok(state) => break Some(state),
                Err(TryLockError::Poisoned) => break None,
                Err(TryLockError::Locked) => {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        if let Some(mut state) = guard {
            state.defer_seal = state.defer_seal.saturating_sub(1);
            if state.defer_seal == 0 {
                state.format_commit_seq = None;
                state.pending_dirty_buckets = [0; 64];
                if state.phase == FreshnessPhase::Dirty {
                    // Physical writes escaped before the format transaction sealed;
                    // poison the live handle so only cold recovery + reconciliation
                    // can admit subsequent I/O.
                    state.phase = FreshnessPhase::Poisoned;
                }
            }
        }
    }

    pub(super) fn backing_device(&self) -> Arc<dyn ByteDevice> {
        Arc::clone(&self.inner)
    }

    fn device(&self) -> ByteDeviceBlockAdapter<'_> {
        ByteDeviceBlockAdapter {
            dev: self.inner.as_ref(),
            block_size: self.id.block_size,
        }
    }

    fn check_plan(
        &self,
        cx: &Cx,
        baseline: &NativeBaseline,
        intent: ValidationIntent,
    ) -> Result<(), FfsError> {
        let owner = self
            .device()
            .read_block(cx, baseline.storage.tails[0].start)?;
        let bytes = &owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END];
        if validation_plan_intent(
            bytes,
            &self.id,
            &baseline.storage,
            baseline.owner_generation,
        )? != intent
            || validation_plan_epoch(bytes)? != baseline.epoch
        {
            return Err(freshness_error("whole-plan authority changed"));
        }
        Ok(())
    }

    fn check_group_validation_authority(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
        index: usize,
    ) -> Result<(), FfsError> {
        let baseline = &state.baseline;
        let tail = &baseline.storage.tails[index];
        let dev = self.device();
        let owner = check_native_validation_owner_prefix(
            cx,
            &dev,
            &self.id,
            &baseline.storage,
            baseline.owner_generation,
            tail,
        )?;
        if owner[OWNER_HEADER_BYTES..PLAN_HEADER_START]
            != state.tables[index][..VALIDATION_HEADER_BYTES]
        {
            return Err(validation_error(
                tail,
                "native ownership changed during active epoch",
            ));
        }
        let (root, table) = read_sealed_table(
            cx,
            &dev,
            &self.id,
            &baseline.storage,
            baseline.owner_generation,
            tail,
        )?;
        if root != baseline.roots[index] || table != state.tables[index] {
            return Err(validation_error(
                tail,
                "native validation authority changed",
            ));
        }
        Ok(())
    }

    fn check_group_authority(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
        index: usize,
        degraded_parity: bool,
    ) -> Result<(), FfsError> {
        self.check_group_validation_authority(cx, state, index)?;
        if read_native_parity_intent(
            cx,
            &self.device(),
            &self.id,
            &state.baseline,
            &state.baseline.storage.tails[index],
        )? != state.parity[index]
        {
            return Err(validation_error(
                &state.baseline.storage.tails[index],
                "native parity ownership changed during active epoch",
            ));
        }
        native_sealed_generation(
            cx,
            &self.device(),
            &self.id,
            &state.baseline,
            &state.baseline.storage.tails[index],
            degraded_parity,
        )?;
        Ok(())
    }

    fn inspect_clean_validation(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
    ) -> Result<(), FfsError> {
        if state.phase != FreshnessPhase::Clean {
            return Err(freshness_error(
                "read-only inspection requires a sealed clean epoch",
            ));
        }
        self.check_plan(
            cx,
            &state.baseline,
            ValidationIntent::Sealed(state.baseline.plan_root),
        )?;
        for (index, tail) in state.baseline.storage.tails.iter().enumerate() {
            self.check_group_validation_authority(cx, state, index)?;
            verify_validation_table(
                cx,
                &self.device(),
                &self.id,
                tail,
                &state.tables[index],
                &state.baseline.roots[index],
            )?;
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)
    }

    fn inspect_validation(&self, cx: &Cx) -> Result<NativeValidationReport, FfsError> {
        let state = self.lock(cx)?;
        self.inspect_clean_validation(cx, &state)?;
        native_validation_report(&self.id, &state.baseline.storage)
    }

    fn inspect_repair(&self, cx: &Cx) -> Result<NativeRepairReport, FfsError> {
        let state = self.lock(cx)?;
        self.inspect_clean_validation(cx, &state)?;
        for index in 0..state.baseline.storage.tails.len() {
            self.check_group_authority(cx, &state, index, false)?;
        }
        native_repair_report(
            &self.id,
            &state.baseline,
            state
                .parity
                .iter()
                .map(|intent| intent.generation())
                .collect(),
        )
    }

    fn scrub_and_heal_all_groups(&self, cx: &Cx) -> Result<NativeScrubHealReport, FfsError> {
        let mut state = self.lock(cx)?;
        if state.phase != FreshnessPhase::Clean || state.defer_seal != 0 {
            return Err(freshness_error(
                "background native scrub requires a sealed clean epoch",
            ));
        }
        self.check_plan(
            cx,
            &state.baseline,
            ValidationIntent::Sealed(state.baseline.plan_root),
        )?;
        let group_count = state.baseline.storage.tails.len();
        let mut source_blocks_scanned = 0_u64;
        let mut corrupted_blocks_detected = 0_u64;
        let mut blocks_healed = 0_u64;
        let mut last_monitor = None;
        for index in 0..group_count {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            self.check_group_authority(cx, &state, index, true)?;
            let tail = state.baseline.storage.tails[index].clone();
            let (sources, _, _) = validation_sizes(&self.id, &tail)?;
            let corrupt =
                native_corrupt_indices(cx, &self.device(), &self.id, &tail, &state.tables[index])?;
            let corrupt_len = corrupt.len() as u64;
            source_blocks_scanned = source_blocks_scanned.saturating_add(u64::from(sources));
            corrupted_blocks_detected = corrupted_blocks_detected.saturating_add(corrupt_len);
            last_monitor = Some(
                state
                    .scrub_monitor
                    .observe_counts(u64::from(sources), corrupt_len),
            );
            if let Some(&first_corrupt) = corrupt.first() {
                let target = BlockNumber(tail.group_start.0 + u64::from(first_corrupt));
                self.repair_clean_read(cx, &mut state, target)?;
                blocks_healed = blocks_healed.saturating_add(corrupt_len);
            }
        }
        let monitor = last_monitor.unwrap_or_else(|| state.scrub_monitor.observe_counts(0, 0));
        let recommended_interval_divisor = state.scrub_monitor.recommended_interval_divisor();
        let recommended_overhead_bps = state
            .scrub_monitor
            .recommended_overhead_bps()
            .max(state.baseline.storage.repair_basis_points);
        Ok(NativeScrubHealReport {
            groups_scanned: u32::try_from(group_count).unwrap_or(u32::MAX),
            source_blocks_scanned,
            corrupted_blocks_detected,
            blocks_healed,
            recommended_interval_divisor,
            recommended_overhead_bps,
            monitor,
        })
    }

    fn check_authority(&self, cx: &Cx, state: &NativeFreshnessState) -> Result<(), FfsError> {
        let root = state.baseline.plan_root;
        let intent = if state.phase == FreshnessPhase::Clean {
            ValidationIntent::Sealed(root)
        } else {
            ValidationIntent::Dirty(root)
        };
        self.check_plan(cx, &state.baseline, intent)?;
        for index in 0..state.baseline.storage.tails.len() {
            self.check_group_authority(cx, state, index, false)?;
        }
        Ok(())
    }

    fn check_read_repair_authority(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
        index: usize,
    ) -> Result<(), FfsError> {
        self.check_plan(
            cx,
            &state.baseline,
            ValidationIntent::Sealed(state.baseline.plan_root),
        )?;
        self.check_group_authority(cx, state, index, true)
    }

    /// Restore a clean generation without changing its source authority. The
    /// caller holds the freshness lock, excluding writes and epoch publication.
    fn repair_clean_read(
        &self,
        cx: &Cx,
        state: &mut NativeFreshnessState,
        block: BlockNumber,
    ) -> Result<(), FfsError> {
        if state.phase != FreshnessPhase::Clean {
            return Err(FfsError::Corruption {
                block: block.0,
                detail: "native read digest mismatch; dirty epochs cannot use stale parity".into(),
            });
        }
        let baseline = &state.baseline;
        let tail = native_target(&baseline.storage, block)?;
        let index = tail.group.0 as usize;
        native_codec_budget(&self.id, &baseline.storage, tail, self.codec_budget, true)?;
        self.check_read_repair_authority(cx, state, index)?;
        let dev = self.device();
        let table = &state.tables[index];
        let corrupt = native_corrupt_indices(cx, &dev, &self.id, tail, table)?;
        let requested =
            u32::try_from(block.0 - tail.group_start.0).expect("admitted native source index");
        if !corrupt.contains(&requested) {
            return Err(validation_error(
                tail,
                "read repair target changed before decoding",
            ));
        }
        let view = NativeDigestDevice {
            dev: &dev,
            tail,
            table,
            corrupt: &corrupt,
        };
        let capture = NativeReconstructionCapture {
            blocks: OnceCell::new(),
        };
        let (layout, expected) = native_layout(&self.id, tail)?;
        let result = GroupRecoveryOrchestrator::new_with_writeback(
            &view,
            &capture,
            self.id.uuid,
            layout,
            tail.group_start,
            u32::from(expected.source_block_count),
        )?
        .with_decoded_block_validator(&view)
        .recover_from_indices(cx, &corrupt);
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if !result.is_success() || result.evidence.generation != state.parity[index].generation() {
            return Err(FfsError::RepairFailed(format!(
                "native read reconstruction failed: {:?}",
                result.evidence.reason
            )));
        }
        let recovered = capture.blocks.into_inner().ok_or_else(|| {
            validation_error(tail, "native read reconstruction produced no capture")
        })?;
        // All intact inputs and the complete compare gate must still agree
        // before the first source write, not merely when the decoder read them.
        for source in 0..u32::from(expected.source_block_count) {
            view.read_block(cx, BlockNumber(tail.group_start.0 + u64::from(source)))?;
        }
        for recovered in &recovered {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            if dev.read_block(cx, recovered.block)?.as_slice() != recovered.expected_current {
                return Err(validation_error(tail, "native read repair target changed"));
            }
            self.ownership.check(recovered.block, &recovered.data)?;
        }
        self.check_read_repair_authority(cx, state, index)?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;

        // Restoration writes only already-attested bytes. It neither creates
        // a Dirty epoch nor derives new digests from the damaged device. Any
        // failure from this point leaves durability ambiguous and poisons the
        // live handle, including cancellation after a partial write or sync.
        state.phase = FreshnessPhase::Poisoned;
        for recovered in &recovered {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            dev.write_block(cx, recovered.block, &recovered.data)?;
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.inner.sync(cx)?;
        verify_validation_table(cx, &dev, &self.id, tail, table, &baseline.roots[index])?;
        self.check_read_repair_authority(cx, state, index)?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        state.phase = FreshnessPhase::Clean;
        Ok(())
    }

    fn read_verified(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<(), FfsError> {
        let mut state = self.lock(cx)?;
        let end = offset
            .0
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= self.inner.len_bytes())
            .ok_or_else(|| freshness_error("read exceeds admitted image"))?;
        let size = u64::from(self.id.block_size);
        let mut cursor = offset.0;
        let mut repaired = false;
        let result = (|| {
            while cursor < end {
                cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
                let block = BlockNumber(cursor / size);
                let start = (cursor % size) as usize;
                let count = (end - cursor).min(size - cursor % size) as usize;
                let output = (cursor - offset.0) as usize;
                if let Some(tail) = native_source_tail(&state.baseline.storage, block) {
                    let digest_offset =
                        VALIDATION_HEADER_BYTES + (block.0 - tail.group_start.0) as usize * 32;
                    let expected: [u8; 32] =
                        state.intended.get(&block).copied().unwrap_or_else(|| {
                            state.tables[tail.group.0 as usize][digest_offset..digest_offset + 32]
                                .try_into()
                                .expect("admitted native source digest")
                        });
                    let mut data = self.device().read_block(cx, block)?;
                    if blake3::hash(data.as_slice()).as_bytes() != &expected {
                        self.repair_clean_read(cx, &mut state, block)?;
                        repaired = true;
                        data = self.device().read_block(cx, block)?;
                        if blake3::hash(data.as_slice()).as_bytes() != &expected {
                            state.phase = FreshnessPhase::Poisoned;
                            return Err(FfsError::Corruption {
                                block: block.0,
                                detail: "native read repair changed after durable verification"
                                    .into(),
                            });
                        }
                    }
                    bytes[output..output + count]
                        .copy_from_slice(&data.as_slice()[start..start + count]);
                } else {
                    // Owned control/parity storage and uncovered bytes (including
                    // ext4's 1 KiB boot block or btrfs's 64 KiB boot pad) retain
                    // their physical-read contract.
                    self.inner.read_exact_at(
                        cx,
                        ByteOffset(cursor),
                        &mut bytes[output..output + count],
                    )?;
                }
                cursor += count as u64;
            }
            cx.checkpoint().map_err(|_| FfsError::Cancelled)
        })();
        if result.is_err() && repaired {
            state.phase = FreshnessPhase::Poisoned;
        }
        result
    }

    #[expect(clippy::type_complexity)]
    fn stage_intended(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
        offset: u64,
        end: u64,
        buffers: &[&[u8]],
    ) -> Result<Vec<(BlockNumber, GroupNumber, [u8; 32], Option<Vec<u8>>)>, FfsError> {
        let size = u64::from(self.id.block_size);
        let mut staged = Vec::new();
        let mut input = 0;
        let mut consumed = 0;
        for number in offset / size..=(end - 1) / size {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            let block = BlockNumber(number);
            let tail = native_target(&state.baseline.storage, block)?;
            let table = &state.tables[tail.group.0 as usize];
            let digest_offset =
                VALIDATION_HEADER_BYTES + (number - tail.group_start.0) as usize * 32;
            let expected = state
                .intended
                .get(&block)
                .map_or(&table[digest_offset..digest_offset + 32], |digest| {
                    digest.as_slice()
                });
            let mut bytes = self.device().read_block(cx, block)?.into_inner();
            if blake3::hash(&bytes).as_bytes() != expected {
                return Err(FfsError::Corruption {
                    block: number,
                    detail: "native freshness beforeimage digest mismatch".into(),
                });
            }
            let first_beforeimage = (!state.beforeimages.contains_key(&block)
                && state.beforeimages.len().saturating_add(staged.len())
                    < MAX_DELTA_BEFOREIMAGE_BLOCKS)
                .then(|| bytes.clone());
            let start = offset.max(number * size);
            let stop = end.min((number + 1) * size);
            let mut cursor = (start - number * size) as usize;
            let limit = (stop - number * size) as usize;
            while cursor < limit {
                while consumed == buffers[input].len() {
                    input += 1;
                    consumed = 0;
                }
                let count = (limit - cursor).min(buffers[input].len() - consumed);
                bytes[cursor..cursor + count]
                    .copy_from_slice(&buffers[input][consumed..consumed + count]);
                cursor += count;
                consumed += count;
            }
            self.ownership.check(block, &bytes)?;
            staged.push((
                block,
                tail.group,
                *blake3::hash(&bytes).as_bytes(),
                first_beforeimage,
            ));
        }
        Ok(staged)
    }

    fn write_buffers(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        buffers: &[&[u8]],
    ) -> Result<(), FfsError> {
        let length = buffers.iter().try_fold(0_u64, |length, bytes| {
            length
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| freshness_error("write length overflows"))
        })?;
        let mut state = self.lock(cx)?;
        if length == 0 {
            return Ok(());
        }
        let end = offset
            .0
            .checked_add(length)
            .filter(|end| *end <= self.inner.len_bytes())
            .ok_or_else(|| freshness_error("write exceeds admitted image"))?;
        let size = u64::from(self.id.block_size);
        let mut write_buckets = [0_u8; 64];
        for number in offset.0 / size..=(end - 1) / size {
            let tail = native_target(&state.baseline.storage, BlockNumber(number))?;
            NativeEpochToken::mark_bucket(&mut write_buckets, tail.group);
        }
        let next_epoch = state
            .baseline
            .epoch
            .checked_add(1)
            .ok_or_else(|| freshness_error("validation epoch exhausted before source write"))?;
        for intent in &state.parity {
            intent.generation().checked_add(1).ok_or_else(|| {
                freshness_error("parity generation exhausted before source write")
            })?;
        }
        let result = (|| {
            let staged = self.stage_intended(cx, &state, offset.0, end, buffers)?;
            if let Some(pre_seq) = state.format_commit_seq {
                let mut combined = state.pending_dirty_buckets;
                for (dst, src) in combined.iter_mut().zip(&write_buckets) {
                    *dst |= *src;
                }
                for (idx, &dirty) in state.dirty_groups.iter().enumerate() {
                    if dirty {
                        NativeEpochToken::mark_bucket(&mut combined, GroupNumber(idx as u32));
                    }
                }
                let uncovered_bucket = write_buckets
                    .iter()
                    .zip(&state.persisted_dirty_buckets)
                    .any(|(&need, &have)| need & !have != 0);
                if state.phase == FreshnessPhase::Clean || uncovered_bucket {
                    self.check_authority(cx, &state)?;
                    let token = NativeEpochToken {
                        owner_inode: state.baseline.storage.owner_inode,
                        owner_generation: state.baseline.owner_generation,
                        target_epoch: next_epoch,
                        prev_sealed_epoch: state.baseline.epoch,
                        flags: EPOCH_TOKEN_FLAG_FORMAT_COMMIT,
                        pre_epoch_commit_seq: pre_seq,
                        prev_sealed_plan_root: state.baseline.plan_root,
                        dirty_group_buckets: combined,
                    };
                    state.phase = FreshnessPhase::Poisoned;
                    publish_validation_plan_with_token(
                        cx,
                        &self.device(),
                        &self.id,
                        &state.baseline.storage,
                        state.baseline.owner_generation,
                        state.baseline.epoch,
                        ValidationIntent::Dirty(state.baseline.plan_root),
                        Some(&token),
                    )?;
                    state.pending_dirty_buckets = combined;
                    state.persisted_dirty_buckets = combined;
                    state.phase = FreshnessPhase::Dirty;
                }
            } else if state.phase == FreshnessPhase::Clean {
                self.check_authority(cx, &state)?;
                state.phase = FreshnessPhase::Poisoned;
                publish_validation_plan(
                    cx,
                    &self.device(),
                    &self.id,
                    &state.baseline.storage,
                    state.baseline.owner_generation,
                    state.baseline.epoch,
                    ValidationIntent::Dirty(state.baseline.plan_root),
                )?;
                state.phase = FreshnessPhase::Dirty;
            }
            self.inner.write_vectored_all_at(cx, offset, buffers)?;
            for (block, group, digest, maybe_beforeimage) in staged {
                state.dirty_groups[group.0 as usize] = true;
                if let Some(beforeimage) = maybe_beforeimage {
                    state.beforeimages.entry(block).or_insert(beforeimage);
                }
                state.intended.insert(block, digest);
            }
            cx.checkpoint().map_err(|_| FfsError::Cancelled)
        })();
        if result.is_err() {
            state.phase = FreshnessPhase::Poisoned;
        }
        result
    }

    fn next_tables(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
        epoch: u32,
    ) -> Result<(Vec<Vec<u8>>, Vec<ValidationAdmission>), FfsError> {
        let mut tables = Vec::with_capacity(state.tables.len());
        let mut admissions = Vec::with_capacity(state.tables.len());
        for (index, tail) in state.baseline.storage.tails.iter().enumerate() {
            if !state.dirty_groups[index] {
                let table = state.tables[index].clone();
                let root = state.baseline.roots[index];
                let group_epoch = state.baseline.group_epochs[index];
                verify_validation_table(cx, &self.device(), &self.id, tail, &table, &root)?;
                tables.push(table);
                admissions.push(ValidationAdmission {
                    epoch: group_epoch,
                    root,
                    intent: ValidationIntent::Sealed(root),
                });
                continue;
            }
            let mut table = state.tables[index].clone();
            table[..VALIDATION_HEADER_BYTES].copy_from_slice(&validation_header(
                &self.id,
                state.baseline.storage.owner_inode,
                state.baseline.owner_generation,
                tail,
                epoch,
                VALIDATION_PENDING,
                &[0; 32],
            )?);
            for (block, digest) in state
                .intended
                .range(tail.group_start..tail.source_end_exclusive())
            {
                let offset = VALIDATION_HEADER_BYTES + (block.0 - tail.group_start.0) as usize * 32;
                table[offset..offset + 32].copy_from_slice(digest);
            }
            let (_, _, used) = validation_sizes(&self.id, tail)?;
            let root = validation_root(&table, used);
            table[..VALIDATION_HEADER_BYTES].copy_from_slice(&validation_header(
                &self.id,
                state.baseline.storage.owner_inode,
                state.baseline.owner_generation,
                tail,
                epoch,
                VALIDATION_PENDING,
                &root,
            )?);
            // The expected hashes came only from admitted tables or verified
            // caller writes. Reading current bytes cannot redefine them.
            verify_validation_table(cx, &self.device(), &self.id, tail, &table, &root)?;
            tables.push(table);
            admissions.push(ValidationAdmission {
                epoch,
                root,
                intent: ValidationIntent::Pending(root),
            });
        }
        Ok((tables, admissions))
    }

    fn publish_groups(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
        next: &NativeBaseline,
        tables: &mut [Vec<u8>],
        admissions: &[NativeGroupAdmission],
    ) -> Result<(), FfsError> {
        let dev = self.device();
        for (index, tail) in next.storage.tails.iter().enumerate() {
            self.check_plan(cx, next, ValidationIntent::Pending(next.plan_root))?;
            self.check_group_authority(cx, state, index, false)?;
            if !state.dirty_groups[index] {
                continue;
            }
            let group_epoch = next.group_epochs[index];
            let validation = ValidationAdmission {
                epoch: group_epoch,
                root: next.roots[index],
                intent: ValidationIntent::Pending(next.roots[index]),
            };
            publish_validation_group(
                cx,
                &dev,
                &self.id,
                &next.storage,
                next.owner_generation,
                tail,
                &validation,
            )?;
            let (root, table) = read_sealed_table(
                cx,
                &dev,
                &self.id,
                &next.storage,
                next.owner_generation,
                tail,
            )?;
            tables[index][..VALIDATION_HEADER_BYTES].copy_from_slice(&validation_header(
                &self.id,
                next.storage.owner_inode,
                next.owner_generation,
                tail,
                group_epoch,
                VALIDATION_SEALED,
                &validation.root,
            )?);
            if root != validation.root || table != tables[index] {
                return Err(validation_error(
                    tail,
                    "freshness table publication disagrees with intended bytes",
                ));
            }
            encode_and_publish_native_group(
                cx,
                &dev,
                &self.id,
                next,
                tail,
                &admissions[index],
                &table,
                Some(&state.beforeimages),
            )?;
        }
        Ok(())
    }

    fn verified_parity(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
        next: &NativeBaseline,
        tables: &[Vec<u8>],
        admissions: &[NativeGroupAdmission],
    ) -> Result<Vec<ParityIntent>, FfsError> {
        self.check_plan(cx, next, ValidationIntent::Pending(next.plan_root))?;
        let dev = self.device();
        let mut parity = Vec::with_capacity(next.storage.tails.len());
        for (index, tail) in next.storage.tails.iter().enumerate() {
            check_native_owner_prefix(
                cx,
                &dev,
                &self.id,
                &next.storage,
                next.owner_generation,
                tail,
            )?;
            let (root, table) = read_sealed_table(
                cx,
                &dev,
                &self.id,
                &next.storage,
                next.owner_generation,
                tail,
            )?;
            if root != next.roots[index] || table != tables[index] {
                return Err(validation_error(
                    tail,
                    "freshness authority changed before final seal",
                ));
            }
            verify_validation_table(cx, &dev, &self.id, tail, &table, &root)?;
            let generation = native_sealed_generation(cx, &dev, &self.id, next, tail, false)?;
            let expected_generation = if state.dirty_groups[index] {
                admissions[index].next_generation
            } else {
                admissions[index].intent.generation()
            };
            if generation != expected_generation {
                return Err(validation_error(
                    tail,
                    "freshness parity generation changed before final seal",
                ));
            }
            parity.push(read_native_parity_intent(cx, &dev, &self.id, next, tail)?);
        }
        Ok(parity)
    }

    fn refresh(&self, cx: &Cx, state: &mut NativeFreshnessState) -> Result<(), FfsError> {
        self.inner.sync(cx)?;
        self.check_authority(cx, state)?;
        let epoch = state
            .baseline
            .epoch
            .checked_add(1)
            .ok_or_else(|| freshness_error("validation epoch exhausted"))?;
        let (mut tables, validations) = self.next_tables(cx, state, epoch)?;
        let plan_root = validation_plan_root(
            &self.id,
            &state.baseline.storage,
            state.baseline.owner_generation,
            epoch,
            &validations,
        )?;
        let next = NativeBaseline {
            storage: state.baseline.storage.clone(),
            owner_generation: state.baseline.owner_generation,
            epoch,
            plan_root,
            roots: validations.iter().map(|admission| admission.root).collect(),
            group_epochs: validations
                .iter()
                .map(|admission| admission.epoch)
                .collect(),
        };
        let dev = self.device();
        let mut admissions = Vec::with_capacity(next.storage.tails.len());
        for (index, tail) in next.storage.tails.iter().enumerate() {
            let mut admission =
                admit_native_group(cx, &dev, &self.id, &state.baseline, tail, self.codec_budget)?;
            if state.dirty_groups[index] {
                // Source-root changes require a new parity generation even when
                // current raw parity is intact. Retain its exact high-water and seal.
                admission.retained = false;
            }
            admissions.push(admission);
        }
        let pending_token = state.format_commit_seq.map(|pre_seq| NativeEpochToken {
            owner_inode: state.baseline.storage.owner_inode,
            owner_generation: state.baseline.owner_generation,
            target_epoch: epoch,
            prev_sealed_epoch: state.baseline.epoch,
            flags: EPOCH_TOKEN_FLAG_FORMAT_COMMIT,
            pre_epoch_commit_seq: pre_seq,
            prev_sealed_plan_root: state.baseline.plan_root,
            dirty_group_buckets: state.persisted_dirty_buckets,
        });
        publish_validation_plan_with_token(
            cx,
            &dev,
            &self.id,
            &next.storage,
            next.owner_generation,
            epoch,
            ValidationIntent::Pending(plan_root),
            pending_token.as_ref(),
        )?;
        self.publish_groups(cx, state, &next, &mut tables, &admissions)?;
        let parity = self.verified_parity(cx, state, &next, &tables, &admissions)?;
        publish_validation_plan_with_token(
            cx,
            &dev,
            &self.id,
            &next.storage,
            next.owner_generation,
            epoch,
            ValidationIntent::Sealed(plan_root),
            None,
        )?;
        self.check_plan(cx, &next, ValidationIntent::Sealed(plan_root))?;
        self.inner.sync(cx)?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        state.baseline = next;
        state.tables = tables;
        state.parity = parity;
        state.intended.clear();
        state.beforeimages.clear();
        state.dirty_groups.fill(false);
        state.persisted_dirty_buckets = [0; 64];
        state.pending_dirty_buckets = [0; 64];
        state.format_commit_seq = None;
        state.phase = FreshnessPhase::Clean;
        Ok(())
    }

    fn sync_clean(&self, cx: &Cx, state: &NativeFreshnessState) -> Result<(), FfsError> {
        self.check_authority(cx, state)?;
        for (index, tail) in state.baseline.storage.tails.iter().enumerate() {
            verify_validation_table(
                cx,
                &self.device(),
                &self.id,
                tail,
                &state.tables[index],
                &state.baseline.roots[index],
            )?;
        }
        self.inner.sync(cx)?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)
    }
}

impl ByteDevice for NativeFreshnessDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<(), FfsError> {
        self.read_verified(cx, offset, bytes)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> Result<(), FfsError> {
        self.write_buffers(cx, offset, &[bytes])
    }

    fn write_vectored_all_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        buffers: &[&[u8]],
    ) -> Result<(), FfsError> {
        self.write_buffers(cx, offset, buffers)
    }

    fn sync(&self, cx: &Cx) -> Result<(), FfsError> {
        let mut state = self.lock(cx)?;
        let result = if state.defer_seal > 0 {
            self.inner
                .sync(cx)
                .and_then(|()| cx.checkpoint().map_err(|_| FfsError::Cancelled))
        } else if state.phase == FreshnessPhase::Clean {
            self.sync_clean(cx, &state)
        } else {
            self.refresh(cx, &mut state)
        };
        if result.is_err() {
            state.phase = FreshnessPhase::Poisoned;
        }
        result
    }

    fn begin_durability_commit(&self, cx: &Cx) -> Result<(), FfsError> {
        self.inner.begin_durability_commit(cx)
    }

    fn complete_durability_commit(&self) {
        self.inner.complete_durability_commit();
    }

    fn abort_durability_commit(&self) {
        self.inner.abort_durability_commit();
    }
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
    id: &NativeFsIdentity,
    owner: InodeNumber,
    generation: u32,
    basis_points: u32,
    tail: &NativeRepairTail,
) -> Vec<u8> {
    let mut bytes = vec![0; id.block_size as usize];
    bytes[..8].copy_from_slice(OWNER_MAGIC);
    bytes[8..24].copy_from_slice(&id.uuid);
    bytes[24..28].copy_from_slice(&tail.group.0.to_le_bytes());
    bytes[28..32].copy_from_slice(&id.group_count.to_le_bytes());
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

fn check_native_owner_prefix(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
    tail: &NativeRepairTail,
) -> Result<Vec<u8>, FfsError> {
    let bytes = check_native_validation_owner_prefix(cx, dev, id, storage, generation, tail)?;
    parity_intent(
        &bytes[PARITY_HEADER_START..PARITY_HEADER_END],
        id,
        storage,
        generation,
        tail,
    )?;
    Ok(bytes)
}

fn check_native_validation_owner_prefix(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
    tail: &NativeRepairTail,
) -> Result<Vec<u8>, FfsError> {
    let bytes = dev.read_block(cx, tail.start)?.into_inner();
    let expected = owner_header(
        id,
        storage.owner_inode,
        generation,
        storage.repair_basis_points,
        tail,
    );
    let zero_tail_start = if tail.group.0 == 0 {
        EPOCH_TOKEN_END
    } else {
        PARITY_HEADER_END
    };
    if bytes.len() != id.block_size as usize
        || bytes.len() < zero_tail_start
        || bytes[..OWNER_HEADER_BYTES] != expected[..OWNER_HEADER_BYTES]
        || bytes[zero_tail_start..].iter().any(|byte| *byte != 0)
        || (tail.group.0 != 0
            && bytes[PLAN_HEADER_START..PLAN_HEADER_END]
                .iter()
                .any(|byte| *byte != 0))
    {
        return Err(validation_error(tail, "native ownership prefix changed"));
    }
    validation_intent(
        &bytes[OWNER_HEADER_BYTES..PLAN_HEADER_START],
        id,
        storage.owner_inode,
        generation,
        tail,
    )?;
    if tail.group.0 == 0 {
        validation_plan_intent(
            &bytes[PLAN_HEADER_START..PLAN_HEADER_END],
            id,
            storage,
            generation,
        )?;
        NativeEpochToken::decode_optional(
            &bytes[EPOCH_TOKEN_START..EPOCH_TOKEN_END],
            id,
            storage.owner_inode,
            generation,
            tail,
        )?;
    }
    Ok(bytes)
}

fn validation_error(tail: &NativeRepairTail, detail: &str) -> FfsError {
    FfsError::Corruption {
        block: tail.start.0,
        detail: format!("native validation group {}: {detail}", tail.group.0),
    }
}

fn validation_sizes(
    id: &NativeFsIdentity,
    tail: &NativeRepairTail,
) -> Result<(u32, usize, usize), FfsError> {
    let sources = tail.source_blocks()?;
    let capacity = usize::try_from(u64::from(tail.validation_blocks) * u64::from(id.block_size))
        .map_err(|_| validation_error(tail, "table capacity exceeds usize"))?;
    let used = usize::try_from(u64::from(sources) * 32)
        .ok()
        .and_then(|bytes| bytes.checked_add(VALIDATION_HEADER_BYTES))
        .ok_or_else(|| validation_error(tail, "table length overflows"))?;
    if sources == 0 || used > capacity || capacity > MAX_VALIDATION_TABLE_BYTES {
        return Err(validation_error(
            tail,
            "table does not fit bounded validation storage",
        ));
    }
    Ok((sources, capacity, used))
}

fn validation_header(
    id: &NativeFsIdentity,
    owner: InodeNumber,
    owner_generation: u32,
    tail: &NativeRepairTail,
    epoch: u32,
    state: u32,
    root: &[u8; 32],
) -> Result<[u8; VALIDATION_HEADER_BYTES], FfsError> {
    let (sources, _, _) = validation_sizes(id, tail)?;
    if epoch == 0 {
        return Err(validation_error(tail, "zero validation epoch"));
    }
    let mut bytes = [0; VALIDATION_HEADER_BYTES];
    bytes[..8].copy_from_slice(VALIDATION_MAGIC);
    bytes[8..24].copy_from_slice(&id.uuid);
    bytes[24..32].copy_from_slice(&owner.0.to_le_bytes());
    bytes[32..36].copy_from_slice(&owner_generation.to_le_bytes());
    bytes[36..40].copy_from_slice(&tail.group.0.to_le_bytes());
    bytes[40..48].copy_from_slice(&tail.group_start.0.to_le_bytes());
    bytes[48..52].copy_from_slice(&sources.to_le_bytes());
    bytes[52..56].copy_from_slice(&id.block_size.to_le_bytes());
    bytes[56..64].copy_from_slice(&(tail.start.0 + 1).to_le_bytes());
    bytes[64..68].copy_from_slice(&tail.validation_blocks.to_le_bytes());
    bytes[68..72].copy_from_slice(&epoch.to_le_bytes());
    bytes[72..104].copy_from_slice(root);
    bytes[104..108].copy_from_slice(&state.to_le_bytes());
    let checksum = ffs_ondisk::ext4::ext4_chksum(!0, &bytes[..108]);
    bytes[108..112].copy_from_slice(&checksum.to_le_bytes());
    Ok(bytes)
}

fn validation_intent(
    bytes: &[u8],
    id: &NativeFsIdentity,
    owner: InodeNumber,
    owner_generation: u32,
    tail: &NativeRepairTail,
) -> Result<ValidationIntent, FfsError> {
    if bytes.len() != VALIDATION_HEADER_BYTES {
        return Err(validation_error(tail, "record length mismatch"));
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(ValidationIntent::Empty);
    }
    let root: [u8; 32] = bytes[72..104].try_into().expect("fixed record length");
    let epoch = u32::from_le_bytes(bytes[68..72].try_into().expect("fixed record length"));
    let state = u32::from_le_bytes(bytes[104..108].try_into().expect("fixed record length"));
    if !matches!(state, VALIDATION_PENDING | VALIDATION_SEALED)
        || bytes != validation_header(id, owner, owner_generation, tail, epoch, state, &root)?
    {
        return Err(validation_error(
            tail,
            "record identity or checksum mismatch",
        ));
    }
    Ok(if state == VALIDATION_PENDING {
        ValidationIntent::Pending(root)
    } else {
        ValidationIntent::Sealed(root)
    })
}

fn validation_root(table: &[u8], used: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FrankenFS native source validation v1");
    hasher.update(&table[..72]);
    hasher.update(&table[VALIDATION_HEADER_BYTES..used]);
    *hasher.finalize().as_bytes()
}

fn read_validation_table(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    tail: &NativeRepairTail,
) -> Result<Vec<u8>, FfsError> {
    let (_, capacity, _) = validation_sizes(id, tail)?;
    let mut table = Vec::with_capacity(capacity);
    for index in 0..tail.validation_blocks {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        table.extend_from_slice(
            dev.read_block(cx, BlockNumber(tail.start.0 + 1 + u64::from(index)))?
                .as_slice(),
        );
    }
    if table.len() != capacity {
        return Err(validation_error(tail, "short validation read"));
    }
    Ok(table)
}

fn build_validation_table(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    owner: InodeNumber,
    owner_generation: u32,
    tail: &NativeRepairTail,
    epoch: u32,
) -> Result<Vec<u8>, FfsError> {
    let (sources, capacity, used) = validation_sizes(id, tail)?;
    let mut table = vec![0; capacity];
    table[..VALIDATION_HEADER_BYTES].copy_from_slice(&validation_header(
        id,
        owner,
        owner_generation,
        tail,
        epoch,
        VALIDATION_PENDING,
        &[0; 32],
    )?);
    for index in 0..sources {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let block = dev.read_block(cx, BlockNumber(tail.group_start.0 + u64::from(index)))?;
        let offset = VALIDATION_HEADER_BYTES + index as usize * 32;
        table[offset..offset + 32].copy_from_slice(blake3::hash(block.as_slice()).as_bytes());
    }
    let root = validation_root(&table, used);
    table[..VALIDATION_HEADER_BYTES].copy_from_slice(&validation_header(
        id,
        owner,
        owner_generation,
        tail,
        epoch,
        VALIDATION_PENDING,
        &root,
    )?);
    Ok(table)
}

fn verify_validation_table_integrity(
    id: &NativeFsIdentity,
    tail: &NativeRepairTail,
    table: &[u8],
    root: &[u8; 32],
) -> Result<(), FfsError> {
    let (_, capacity, used) = validation_sizes(id, tail)?;
    if table.len() != capacity
        || &validation_root(table, used) != root
        || table[used..].iter().any(|byte| *byte != 0)
    {
        return Err(validation_error(tail, "digest table integrity mismatch"));
    }
    Ok(())
}

fn verify_validation_table(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    tail: &NativeRepairTail,
    table: &[u8],
    root: &[u8; 32],
) -> Result<(), FfsError> {
    verify_validation_table_integrity(id, tail, table, root)?;
    let (sources, _, _) = validation_sizes(id, tail)?;
    for index in 0..sources {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let number = BlockNumber(tail.group_start.0 + u64::from(index));
        let block = dev.read_block(cx, number)?;
        let offset = VALIDATION_HEADER_BYTES + index as usize * 32;
        if blake3::hash(block.as_slice()).as_bytes() != &table[offset..offset + 32] {
            return Err(FfsError::Corruption {
                block: number.0,
                detail: format!("native source digest mismatch in group {}", tail.group.0),
            });
        }
    }
    Ok(())
}

fn parity_header(
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    owner_generation: u32,
    tail: &NativeRepairTail,
    intent: ParityIntent,
) -> [u8; VALIDATION_HEADER_BYTES] {
    let mut bytes = [0; VALIDATION_HEADER_BYTES];
    bytes[..8].copy_from_slice(PARITY_MAGIC);
    bytes[8..24].copy_from_slice(&id.uuid);
    bytes[24..32].copy_from_slice(&storage.owner_inode.0.to_le_bytes());
    bytes[32..36].copy_from_slice(&owner_generation.to_le_bytes());
    bytes[36..40].copy_from_slice(&tail.group.0.to_le_bytes());
    bytes[40..48].copy_from_slice(&intent.generation().to_le_bytes());
    bytes[48..80].copy_from_slice(&intent.source_root());
    let state = match intent {
        ParityIntent::Prepared => PLAN_PREPARED,
        ParityIntent::Pending { .. } => VALIDATION_PENDING,
        ParityIntent::Sealed { manifest, .. } => {
            bytes[80..112].copy_from_slice(&manifest);
            VALIDATION_SEALED
        }
    };
    bytes[112..116].copy_from_slice(&state.to_le_bytes());
    let checksum = ffs_ondisk::ext4::ext4_chksum(!0, &bytes[..116]);
    bytes[116..120].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

fn parity_intent(
    bytes: &[u8],
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    owner_generation: u32,
    tail: &NativeRepairTail,
) -> Result<ParityIntent, FfsError> {
    if bytes.len() != VALIDATION_HEADER_BYTES {
        return Err(validation_error(
            tail,
            "native parity record length mismatch",
        ));
    }
    let generation = u64::from_le_bytes(bytes[40..48].try_into().expect("fixed record"));
    let source_root = bytes[48..80].try_into().expect("fixed record");
    let state = u32::from_le_bytes(bytes[112..116].try_into().expect("fixed record"));
    let intent = match state {
        PLAN_PREPARED if generation == 0 => ParityIntent::Prepared,
        VALIDATION_PENDING if generation > 0 => ParityIntent::Pending {
            generation,
            source_root,
        },
        VALIDATION_SEALED if generation > 0 => ParityIntent::Sealed {
            generation,
            source_root,
            manifest: bytes[80..112].try_into().expect("fixed record"),
        },
        _ => {
            return Err(validation_error(
                tail,
                "native parity record missing or invalid state",
            ));
        }
    };
    if bytes != parity_header(id, storage, owner_generation, tail, intent) {
        return Err(validation_error(
            tail,
            "native parity record identity or checksum mismatch",
        ));
    }
    Ok(intent)
}

fn native_layout(
    id: &NativeFsIdentity,
    tail: &NativeRepairTail,
) -> Result<(RepairGroupLayout, RepairGroupDescExt), FfsError> {
    let (sources, _, _) = validation_sizes(id, tail)?;
    let validation_span = tail
        .validation_blocks
        .checked_add(1)
        .ok_or_else(|| validation_error(tail, "validation span overflows"))?;
    let layout = if tail.is_detached() {
        RepairGroupLayout::with_detached_storage(
            tail.group,
            tail.group_start,
            tail.blocks_per_group,
            validation_span,
            tail.repair_blocks,
            tail.start,
        )?
    } else {
        RepairGroupLayout::new(
            tail.group,
            tail.group_start,
            tail.blocks_per_group,
            validation_span,
            tail.repair_blocks,
        )?
    };
    if layout.validation_start_block() != tail.start
        || layout
            .source_end_exclusive()
            .saturating_sub(layout.group_start.0)
            != u64::from(sources)
    {
        return Err(validation_error(
            tail,
            "native layout includes owned metadata in sources",
        ));
    }
    let descriptor = RepairGroupDescExt {
        transfer_length: u64::from(sources) * u64::from(id.block_size),
        symbol_size: u16::try_from(id.block_size)
            .map_err(|_| validation_error(tail, "native symbol size exceeds u16"))?,
        source_block_count: u16::try_from(sources)
            .map_err(|_| validation_error(tail, "native source count exceeds u16"))?,
        sub_blocks: 1,
        symbol_alignment: 4,
        repair_start_block: layout.repair_start_block(),
        repair_block_count: tail.repair_blocks,
        repair_generation: 0,
        checksum: 0,
    };
    Ok((layout, descriptor))
}

fn read_sealed_table(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
    tail: &NativeRepairTail,
) -> Result<([u8; 32], Vec<u8>), FfsError> {
    let owner = dev.read_block(cx, tail.start)?;
    let intent = validation_intent(
        &owner.as_slice()[OWNER_HEADER_BYTES..PLAN_HEADER_START],
        id,
        storage.owner_inode,
        generation,
        tail,
    )?;
    let ValidationIntent::Sealed(root) = intent else {
        return Err(validation_error(
            tail,
            "validation is uninitialized or pending",
        ));
    };
    let table = read_validation_table(cx, dev, id, tail)?;
    if validation_intent(
        &table[..VALIDATION_HEADER_BYTES],
        id,
        storage.owner_inode,
        generation,
        tail,
    )? != intent
        || owner.as_slice()[OWNER_HEADER_BYTES..PLAN_HEADER_START]
            != table[..VALIDATION_HEADER_BYTES]
    {
        return Err(validation_error(tail, "sealed intent and table disagree"));
    }
    verify_validation_table_integrity(id, tail, &table, &root)?;
    Ok((root, table))
}

fn read_native_baseline(fs: &OpenFs, cx: &Cx) -> Result<NativeBaseline, FfsError> {
    let (id, storage, generation) = fs.native_identity_storage_and_generation(cx)?;
    let dev = ByteDeviceBlockAdapter {
        dev: fs.dev.as_ref(),
        block_size: id.block_size,
    };
    let owner = dev.read_block(cx, storage.tails[0].start)?;
    if NativeEpochToken::decode_optional(
        &owner.as_slice()[EPOCH_TOKEN_START..EPOCH_TOKEN_END],
        &id,
        storage.owner_inode,
        generation,
        &storage.tails[0],
    )?
    .is_some()
    {
        return Err(validation_error(
            &storage.tails[0],
            "sealed baseline carries an unretired epoch token",
        ));
    }
    let plan = validation_plan_intent(
        &owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END],
        &id,
        &storage,
        generation,
    )?;
    let epoch = validation_plan_epoch(&owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END])?;
    let ValidationIntent::Sealed(plan_root) = plan else {
        return Err(validation_error(
            &storage.tails[0],
            "whole-plan validation is uninitialized or pending",
        ));
    };
    read_native_group_baseline(cx, &dev, &id, storage, generation, epoch, plan_root)
}

/// Bind every local validation table to one previously persisted whole-plan
/// root before using any table to authorize source recovery.
fn read_native_group_baseline(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    storage: NativeRepairStorage,
    generation: u32,
    epoch: u32,
    plan_root: [u8; 32],
) -> Result<NativeBaseline, FfsError> {
    let mut admissions = Vec::with_capacity(storage.tails.len());
    for tail in &storage.tails {
        let (root, table) = read_sealed_table(cx, dev, id, &storage, generation, tail)?;
        let local_epoch = u32::from_le_bytes(table[68..72].try_into().expect("checked table"));
        if local_epoch == 0 || local_epoch > epoch {
            return Err(validation_error(
                tail,
                "whole-plan and local epochs disagree",
            ));
        }
        admissions.push(ValidationAdmission {
            epoch: local_epoch,
            root,
            intent: ValidationIntent::Sealed(root),
        });
    }
    if validation_plan_root(id, &storage, generation, epoch, &admissions)? != plan_root {
        return Err(validation_error(
            &storage.tails[0],
            "sealed whole-plan root mismatch",
        ));
    }
    let group_epochs = admissions.iter().map(|group| group.epoch).collect();
    let roots = admissions.into_iter().map(|group| group.root).collect();
    Ok(NativeBaseline {
        storage,
        owner_generation: generation,
        epoch,
        plan_root,
        roots,
        group_epochs,
    })
}

/// A Dirty token records where writes may have happened, not their intended
/// bytes. Only the old sealed digests survive this cut. Check every possibly
/// written group before healing even a clean group, and never infer new source
/// authority from the bytes currently on disk.
fn verify_dirty_recovery_sources(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    baseline: &NativeBaseline,
    token: &NativeEpochToken,
    recovery_dirty_groups: &BTreeSet<GroupNumber>,
) -> Result<(), FfsError> {
    for (index, tail) in baseline.storage.tails.iter().enumerate() {
        if !token.is_group_dirty(tail.group) && !recovery_dirty_groups.contains(&tail.group) {
            continue;
        }
        let (root, table) = read_sealed_table(
            cx,
            dev,
            id,
            &baseline.storage,
            baseline.owner_generation,
            tail,
        )?;
        if root != baseline.roots[index] {
            return Err(validation_error(tail, "dirty recovery baseline changed"));
        }
        if !native_corrupt_indices(cx, dev, id, tail, &table)?.is_empty() {
            return Err(validation_error(
                tail,
                "dirty epoch source changed without persisted intended-source authority",
            ));
        }
    }
    Ok(())
}

fn ensure_native_baseline(fs: &OpenFs, cx: &Cx, expected: &NativeBaseline) -> Result<(), FfsError> {
    let current = read_native_baseline(fs, cx)?;
    if current.plan_root != expected.plan_root
        || current.storage != expected.storage
        || current.owner_generation != expected.owner_generation
        || current.epoch != expected.epoch
        || current.roots != expected.roots
        || current.group_epochs != expected.group_epochs
    {
        return Err(FfsError::RepairFailed(
            "native baseline authority changed during operation".into(),
        ));
    }
    Ok(())
}

fn native_target(
    storage: &NativeRepairStorage,
    block: BlockNumber,
) -> Result<&NativeRepairTail, FfsError> {
    native_source_tail(storage, block).ok_or_else(|| {
        FfsError::RepairFailed("requested block is outside native source coverage".into())
    })
}

fn native_source_tail(
    storage: &NativeRepairStorage,
    block: BlockNumber,
) -> Option<&NativeRepairTail> {
    // Admission orders tails strictly by group_start. Avoid scanning every
    // group for every block in the physical read path on large images.
    let index = storage
        .tails
        .partition_point(|tail| tail.group_start.0 <= block.0)
        .checked_sub(1)?;
    let tail = &storage.tails[index];
    (block.0 < tail.source_end_exclusive().0).then_some(tail)
}

fn read_native_parity_intent(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
) -> Result<ParityIntent, FfsError> {
    let owner = dev.read_block(cx, tail.start)?;
    let intent = parity_intent(
        &owner.as_slice()[PARITY_HEADER_START..PARITY_HEADER_END],
        id,
        &baseline.storage,
        baseline.owner_generation,
        tail,
    )?;
    if intent != ParityIntent::Prepared
        && intent.source_root() != baseline.roots[tail.group.0 as usize]
    {
        return Err(validation_error(
            tail,
            "native parity binds a different source baseline",
        ));
    }
    Ok(intent)
}

fn write_native_parity_intent(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    intent: ParityIntent,
) -> Result<(), FfsError> {
    let mut owner = dev.read_block(cx, tail.start)?.into_inner();
    let current = parity_intent(
        &owner[PARITY_HEADER_START..PARITY_HEADER_END],
        id,
        &baseline.storage,
        baseline.owner_generation,
        tail,
    )?;
    let allowed = match (current, intent) {
        (ParityIntent::Prepared, ParityIntent::Pending { generation, .. }) => generation > 0,
        (
            ParityIntent::Pending {
                generation: previous,
                ..
            }
            | ParityIntent::Sealed {
                generation: previous,
                ..
            },
            ParityIntent::Pending { generation, .. },
        ) => generation > previous,
        (
            ParityIntent::Pending {
                generation: previous,
                source_root: root,
            },
            ParityIntent::Sealed {
                generation,
                source_root,
                ..
            },
        ) => generation == previous && source_root == root,
        _ => false,
    };
    let expected = owner_header(
        id,
        baseline.storage.owner_inode,
        baseline.owner_generation,
        baseline.storage.repair_basis_points,
        tail,
    );
    if !allowed
        || owner[..OWNER_HEADER_BYTES] != expected[..OWNER_HEADER_BYTES]
        || validation_intent(
            &owner[OWNER_HEADER_BYTES..PLAN_HEADER_START],
            id,
            baseline.storage.owner_inode,
            baseline.owner_generation,
            tail,
        )? != ValidationIntent::Sealed(intent.source_root())
    {
        return Err(validation_error(
            tail,
            "native parity ownership changed before publication",
        ));
    }
    owner[PARITY_HEADER_START..PARITY_HEADER_END].copy_from_slice(&parity_header(
        id,
        &baseline.storage,
        baseline.owner_generation,
        tail,
        intent,
    ));
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    dev.write_block(cx, tail.start, &owner)?;
    dev.sync(cx)
}

fn native_manifest(
    cx: &Cx,
    dev: &dyn BlockDevice,
    layout: RepairGroupLayout,
    expected_generation: u64,
) -> Result<[u8; 32], FfsError> {
    let mut selected = None;
    for number in layout.descriptor_blocks() {
        let block = dev.read_block(cx, number)?;
        if let Ok(desc) = RepairGroupDescExt::parse(block.as_slice())
            && desc.repair_generation == expected_generation
            && &block.as_slice()[48..56] == b"RQHASH01"
        {
            let digest: [u8; 32] = block.as_slice()[64..96]
                .try_into()
                .expect("full descriptor block");
            if selected.is_some_and(|previous| previous != digest) {
                return Err(FfsError::RepairFailed(
                    "ambiguous native manifest digests".into(),
                ));
            }
            selected = Some(digest);
        }
    }
    selected.ok_or_else(|| FfsError::RepairFailed("native committed manifest missing".into()))
}

fn native_codec_budget(
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    tail: &NativeRepairTail,
    allowed: u64,
    decoding: bool,
) -> Result<u64, FfsError> {
    let (sources, _, _) = validation_sizes(id, tail)?;
    let max_capacity = storage.tails.iter().try_fold(0_usize, |acc, candidate| {
        validation_sizes(id, candidate).map(|(_, capacity, _)| acc.max(capacity))
    })?;
    if id.block_size < 1024 || tail.repair_blocks > sources {
        return Err(validation_error(
            tail,
            "unsupported native codec resource geometry",
        ));
    }
    // Serial groups, at most two tables and whole-plan admission/identity buffers.
    // The decoder margin includes pinned dense/wavefront equation retention;
    // this admission estimates allocations, not total process RSS.
    let metadata = (max_capacity as u64)
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(storage.tails.len() as u64 * 4096))
        .and_then(|bytes| bytes.checked_add(u64::from(id.block_size) * 16))
        .ok_or_else(|| validation_error(tail, "native resource estimate overflows"))?;
    let metadata = if decoding {
        // The codec estimate excludes caller-owned allocations. The recovery
        // orchestrator retains beforeimages and decoded blocks while capture
        // copies both; charge four payloads plus headers/indices per source.
        // Beforeimages are captured before the redundancy feasibility check,
        // so this must cover every source, not only the parity symbol count.
        u64::from(id.block_size)
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(256))
            .and_then(|bytes| bytes.checked_mul(u64::from(sources)))
            .and_then(|bytes| bytes.checked_add(metadata))
            .ok_or_else(|| validation_error(tail, "native recovery capture estimate overflows"))?
    } else {
        metadata
    };
    let budget = allowed.checked_sub(metadata).ok_or_else(|| {
        validation_error(tail, "native working budget is below metadata estimate")
    })?;
    let estimate = direct_encode_workspace_bytes(sources, id.block_size, tail.repair_blocks)?
        .checked_mul(if decoding { 8 } else { 1 })
        .ok_or_else(|| validation_error(tail, "native codec estimate overflows"))?;
    if estimate > budget {
        return Err(validation_error(
            tail,
            &format!(
                "native working budget exceeded: required={} allowed={allowed}",
                estimate.saturating_add(metadata)
            ),
        ));
    }
    Ok(budget)
}

#[expect(clippy::too_many_arguments)]
fn admit_native_group_unconstrained_root(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    storage_meta: &NativeRepairStorage,
    owner_generation: u32,
    tail: &NativeRepairTail,
    allowed: u64,
    expected_root: Option<[u8; 32]>,
) -> Result<NativeGroupAdmission, FfsError> {
    let codec_budget = native_codec_budget(id, storage_meta, tail, allowed, false)?;
    let owner = dev.read_block(cx, tail.start)?;
    let intent = parity_intent(
        &owner.as_slice()[PARITY_HEADER_START..PARITY_HEADER_END],
        id,
        storage_meta,
        owner_generation,
        tail,
    )?;
    if let Some(root) = expected_root
        && intent != ParityIntent::Prepared
        && intent.source_root() != root
    {
        return Err(validation_error(
            tail,
            "native parity binds a different source baseline",
        ));
    }
    let (layout, expected) = native_layout(id, tail)?;
    let storage = RepairGroupStorage::new(dev, layout);
    let raw = storage.preflight_raw_refresh(cx, &expected)?;
    if raw.descriptor.repair_generation > intent.generation()
        || (intent == ParityIntent::Prepared && !raw.pristine)
        || (!raw.pristine && raw.descriptor.repair_generation == 0)
    {
        return Err(validation_error(
            tail,
            "descriptor generation exceeds native ownership authority",
        ));
    }
    let mut retained = false;
    if let ParityIntent::Sealed {
        generation,
        manifest,
        ..
    } = intent
        && raw.committed
        && raw.descriptor.repair_generation == generation
    {
        if native_manifest(cx, dev, layout, generation)? != manifest {
            return Err(validation_error(tail, "native manifest ownership mismatch"));
        }
        match storage.read_verified_raw_generation(cx, false) {
            Ok((descriptor, symbols)) => {
                retained =
                    descriptor == raw.descriptor && symbols.len() == tail.repair_blocks as usize;
            }
            Err(FfsError::RepairFailed(_) | FfsError::Corruption { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    let next_generation = intent
        .generation()
        .checked_add(1)
        .ok_or_else(|| validation_error(tail, "native parity generation exhausted"))?
        .max(raw.next_generation);
    Ok(NativeGroupAdmission {
        intent,
        raw,
        retained,
        codec_budget,
        next_generation,
    })
}

fn admit_native_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    allowed: u64,
) -> Result<NativeGroupAdmission, FfsError> {
    admit_native_group_unconstrained_root(
        cx,
        dev,
        id,
        &baseline.storage,
        baseline.owner_generation,
        tail,
        allowed,
        Some(baseline.roots[tail.group.0 as usize]),
    )
}

fn native_sealed_generation(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    degraded: bool,
) -> Result<u64, FfsError> {
    let ParityIntent::Sealed {
        generation,
        manifest,
        ..
    } = read_native_parity_intent(cx, dev, id, baseline, tail)?
    else {
        return Err(validation_error(
            tail,
            "native parity is uninitialized or pending",
        ));
    };
    let (layout, expected) = native_layout(id, tail)?;
    let storage = RepairGroupStorage::new(dev, layout);
    let admission = storage.preflight_raw_refresh(cx, &expected)?;
    if !admission.committed
        || admission.descriptor.repair_generation != generation
        || native_manifest(cx, dev, layout, generation)? != manifest
    {
        return Err(validation_error(
            tail,
            "native parity generation or manifest mismatch",
        ));
    }
    let (descriptor, symbols) = storage.read_verified_raw_generation(cx, degraded)?;
    if descriptor != admission.descriptor
        || (!degraded && symbols.len() != tail.repair_blocks as usize)
    {
        return Err(validation_error(
            tail,
            "native parity is incomplete or changed",
        ));
    }
    Ok(generation)
}

fn publish_native_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    admission: &NativeGroupAdmission,
) -> Result<(), FfsError> {
    if read_native_parity_intent(cx, dev, id, baseline, tail)? != admission.intent {
        return Err(validation_error(
            tail,
            "native ownership changed after admission",
        ));
    }
    let (root, table) = read_sealed_table(
        cx,
        dev,
        id,
        &baseline.storage,
        baseline.owner_generation,
        tail,
    )?;
    if root != baseline.roots[tail.group.0 as usize] {
        return Err(validation_error(
            tail,
            "native source authority changed after admission",
        ));
    }
    verify_validation_table(cx, dev, id, tail, &table, &root)?;
    let (layout, expected) = native_layout(id, tail)?;
    let storage = RepairGroupStorage::new(dev, layout);
    if storage.preflight_raw_refresh(cx, &expected)? != admission.raw {
        return Err(validation_error(
            tail,
            "native descriptors changed after admission",
        ));
    }
    if admission.retained {
        native_sealed_generation(cx, dev, id, baseline, tail, false)?;
        return dev.sync(cx);
    }
    encode_and_publish_native_group(cx, dev, id, baseline, tail, admission, &table, None)
}

#[expect(clippy::too_many_arguments)]
fn encode_and_publish_native_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    admission: &NativeGroupAdmission,
    table: &[u8],
    beforeimages: Option<&BTreeMap<BlockNumber, Vec<u8>>>,
) -> Result<(), FfsError> {
    // A live epoch changes the validation root before parity. Only this
    // already-admitted transition accepts the exact preceding parity anchor;
    // cold readers continue to require the new root and a sealed whole plan.
    let owner = dev.read_block(cx, tail.start)?;
    if parity_intent(
        &owner.as_slice()[PARITY_HEADER_START..PARITY_HEADER_END],
        id,
        &baseline.storage,
        baseline.owner_generation,
        tail,
    )? != admission.intent
    {
        return Err(validation_error(
            tail,
            "native parity changed during transition",
        ));
    }
    let root = baseline.roots[tail.group.0 as usize];
    let (layout, expected) = native_layout(id, tail)?;
    let storage = RepairGroupStorage::new(dev, layout);
    if storage.preflight_raw_refresh(cx, &expected)? != admission.raw {
        return Err(validation_error(
            tail,
            "native descriptors changed during transition",
        ));
    }
    let view = NativeDigestDevice {
        dev,
        tail,
        table,
        corrupt: &[],
    };
    let (sources, _, _) = validation_sizes(id, tail)?;
    let delta_budget_ok = u64::from(sources)
        .saturating_mul(u64::from(sources))
        .saturating_mul(3)
        <= admission.codec_budget;
    let delta_symbols = if let Some(beforeimages) = beforeimages
        && beforeimages.len() < MAX_DELTA_BEFOREIMAGE_BLOCKS
        && admission.raw.committed
        && matches!(admission.intent, ParityIntent::Sealed { .. })
        && delta_budget_ok
    {
        match storage.read_verified_raw_generation(cx, false) {
            Ok((descriptor, existing))
                if descriptor == admission.raw.descriptor
                    && existing.len() == tail.repair_blocks as usize =>
            {
                let mut new_blocks = Vec::new();
                for (&block, old_bytes) in
                    beforeimages.range(tail.group_start..tail.source_end_exclusive())
                {
                    let source_index =
                        u32::try_from(block.0 - tail.group_start.0).expect("bounded source index");
                    let new_bytes = view.read_block(cx, block)?.into_inner();
                    new_blocks.push((source_index, old_bytes.as_slice(), new_bytes));
                }
                let deltas: Vec<BlockDelta<'_>> = new_blocks
                    .iter()
                    .map(|(source_index, old_block, new_block)| BlockDelta {
                        source_index: *source_index,
                        old_block,
                        new_block: new_block.as_slice(),
                    })
                    .collect();
                let mut group_encoded = EncodedGroup {
                    group: tail.group,
                    source_block_count: sources,
                    symbol_size: id.block_size,
                    seed: repair_seed(&id.uuid, tail.group),
                    repair_symbols: existing
                        .into_iter()
                        .map(|(esi, data)| EmittedSymbol {
                            esi,
                            data,
                            is_source: false,
                            degree: 0,
                        })
                        .collect(),
                };
                update_encoded_group_delta(&mut group_encoded, &deltas)?;
                Some(
                    group_encoded
                        .repair_symbols
                        .into_iter()
                        .map(|symbol| (symbol.esi, symbol.data))
                        .collect::<Vec<_>>(),
                )
            }
            _ => None,
        }
    } else {
        None
    };
    let symbols = if let Some(symbols) = delta_symbols {
        symbols
    } else {
        let encoded = encode_group_direct(
            cx,
            &view,
            &id.uuid,
            DirectEncodeRequest {
                group: tail.group,
                first_block: tail.group_start,
                source_block_count: sources,
                repair_count: tail.repair_blocks,
                max_working_bytes: admission.codec_budget,
            },
        )?;
        encoded
            .repair_symbols
            .into_iter()
            .map(|symbol| (symbol.esi, symbol.data))
            .collect()
    };
    verify_validation_table(cx, dev, id, tail, table, &root)?;
    write_native_parity_intent(
        cx,
        dev,
        id,
        baseline,
        tail,
        ParityIntent::Pending {
            generation: admission.next_generation,
            source_root: root,
        },
    )?;
    if admission.raw.pristine {
        storage.initialize_raw_repair_symbols(
            cx,
            &expected,
            &symbols,
            admission.next_generation,
        )?;
    } else {
        storage.write_repair_symbols(cx, &symbols, admission.next_generation)?;
    }
    let (descriptor, readback) = storage.read_verified_raw_generation(cx, false)?;
    if descriptor.repair_generation != admission.next_generation {
        return Err(validation_error(
            tail,
            "native parity readback generation mismatch",
        ));
    }
    if readback != symbols {
        return Err(validation_error(
            tail,
            "native parity readback differs from encoded symbols",
        ));
    }
    verify_validation_table(cx, dev, id, tail, table, &root)?;
    let manifest = native_manifest(cx, dev, layout, admission.next_generation)?;
    write_native_parity_intent(
        cx,
        dev,
        id,
        baseline,
        tail,
        ParityIntent::Sealed {
            generation: admission.next_generation,
            source_root: root,
            manifest,
        },
    )
}

fn native_repair_report(
    id: &NativeFsIdentity,
    baseline: &NativeBaseline,
    generations: Vec<u64>,
) -> Result<NativeRepairReport, FfsError> {
    let validation = native_validation_report(id, &baseline.storage)?;
    Ok(NativeRepairReport {
        owner_inode: validation.owner_inode,
        groups: validation.groups,
        source_blocks: validation.source_blocks,
        repair_blocks: baseline
            .storage
            .tails
            .iter()
            .map(|tail| u64::from(tail.repair_blocks))
            .sum(),
        generations,
    })
}

fn native_corrupt_indices(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    tail: &NativeRepairTail,
    table: &[u8],
) -> Result<Vec<u32>, FfsError> {
    let (sources, _, _) = validation_sizes(id, tail)?;
    let mut corrupt = Vec::new();
    for index in 0..sources {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let bytes = dev.read_block(cx, BlockNumber(tail.group_start.0 + u64::from(index)))?;
        let offset = VALIDATION_HEADER_BYTES + index as usize * 32;
        if bytes.len() != id.block_size as usize
            || blake3::hash(bytes.as_slice()).as_bytes() != &table[offset..offset + 32]
        {
            corrupt.push(index);
        }
    }
    Ok(corrupt)
}

struct NativeDigestDevice<'a> {
    dev: &'a dyn BlockDevice,
    tail: &'a NativeRepairTail,
    table: &'a [u8],
    corrupt: &'a [u32],
}

impl BlockDevice for NativeDigestDevice<'_> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf, FfsError> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let source_end = self.tail.source_end_exclusive().0;
        let in_sources = block.0 >= self.tail.group_start.0 && block.0 < source_end;
        let tail_end = self.tail.start.0 + u64::from(self.tail.blocks());
        let in_owned_storage = block.0 >= self.tail.start.0 && block.0 < tail_end;
        if !in_sources && !in_owned_storage {
            return Err(validation_error(
                self.tail,
                "codec read outside admitted native group",
            ));
        }
        let bytes = self.dev.read_block(cx, block)?;
        if in_sources {
            let index =
                u32::try_from(block.0 - self.tail.group_start.0).expect("bounded native group");
            let offset = VALIDATION_HEADER_BYTES + index as usize * 32;
            if !self.corrupt.contains(&index)
                && (bytes.len() != self.block_size() as usize
                    || blake3::hash(bytes.as_slice()).as_bytes()
                        != &self.table[offset..offset + 32])
            {
                return Err(FfsError::Corruption {
                    block: block.0,
                    detail: "native codec input differs from sealed source digest".into(),
                });
            }
        }
        Ok(bytes)
    }
    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<(), FfsError> {
        Err(FfsError::RepairFailed(
            "native codec view is read-only".into(),
        ))
    }
    fn block_size(&self) -> u32 {
        self.dev.block_size()
    }
    fn block_count(&self) -> u64 {
        self.dev.block_count()
    }
    fn sync(&self, _cx: &Cx) -> Result<(), FfsError> {
        Err(FfsError::RepairFailed(
            "native codec view cannot sync input".into(),
        ))
    }
}

impl BlockValidator for NativeDigestDevice<'_> {
    fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        let index = block.0.checked_sub(self.tail.group_start.0);
        if let Some(index) = index.filter(|_| block.0 < self.tail.source_end_exclusive().0) {
            let offset = VALIDATION_HEADER_BYTES + index as usize * 32;
            if data.len() == self.block_size() as usize
                && blake3::hash(data.as_slice()).as_bytes() == &self.table[offset..offset + 32]
            {
                return BlockVerdict::Clean;
            }
        }
        BlockVerdict::Corrupt(vec![(
            CorruptionKind::ChecksumMismatch,
            Severity::Error,
            "reconstructed bytes differ from the sealed native baseline".into(),
        )])
    }
}

#[derive(Debug)]
struct NativeRecoveredBlock {
    block: BlockNumber,
    expected_current: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Debug)]
struct NativeReconstructionCapture {
    blocks: OnceCell<Vec<NativeRecoveredBlock>>,
}

impl RecoveryWriteback for NativeReconstructionCapture {
    fn writeback_recovered(
        &self,
        cx: &Cx,
        device: &dyn BlockDevice,
        blocks: &[RecoveryWritebackBlock<'_>],
    ) -> Result<(), FfsError> {
        let mut captured = Vec::with_capacity(blocks.len());
        for block in blocks {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            if device.read_block(cx, block.block)?.as_slice() != block.expected_current {
                return Err(FfsError::RepairFailed(
                    "native reconstruction target changed during decode".into(),
                ));
            }
            captured.push(NativeRecoveredBlock {
                block: block.block,
                expected_current: block.expected_current.to_vec(),
                data: block.data.to_vec(),
            });
        }
        self.blocks
            .set(captured)
            .map_err(|_| FfsError::RepairFailed("native reconstruction capture repeated".into()))
    }
    fn authority_name(&self) -> &'static str {
        "native-read-only-baseline-reconstruction"
    }
}

fn native_validation_report(
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
) -> Result<NativeValidationReport, FfsError> {
    let mut source_blocks = 0;
    for tail in &storage.tails {
        source_blocks += u64::from(validation_sizes(id, tail)?.0);
    }
    Ok(NativeValidationReport {
        owner_inode: storage.owner_inode,
        groups: u32::try_from(storage.tails.len())
            .map_err(|_| FfsError::InvalidGeometry("validation group count exceeds u32".into()))?,
        source_blocks,
    })
}

fn validation_plan_header(
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
    epoch: u32,
    state: u32,
    root: &[u8; 32],
) -> Result<[u8; VALIDATION_HEADER_BYTES], FfsError> {
    let report = native_validation_report(id, storage)?;
    if epoch == 0 {
        return Err(FfsError::RepairFailed(
            "zero native whole-plan epoch".into(),
        ));
    }
    let mut bytes = [0; VALIDATION_HEADER_BYTES];
    bytes[..8].copy_from_slice(PLAN_MAGIC);
    bytes[8..24].copy_from_slice(&id.uuid);
    bytes[24..32].copy_from_slice(&storage.owner_inode.0.to_le_bytes());
    bytes[32..36].copy_from_slice(&generation.to_le_bytes());
    bytes[36..40].copy_from_slice(&report.groups.to_le_bytes());
    bytes[40..44].copy_from_slice(&storage.repair_basis_points.to_le_bytes());
    bytes[44..48].copy_from_slice(&id.block_size.to_le_bytes());
    bytes[48..56].copy_from_slice(&report.source_blocks.to_le_bytes());
    bytes[56..64].copy_from_slice(&u64::from(epoch).to_le_bytes());
    bytes[64..96].copy_from_slice(root);
    bytes[96..100].copy_from_slice(&state.to_le_bytes());
    let checksum = ffs_ondisk::ext4::ext4_chksum(!0, &bytes[..100]);
    bytes[100..104].copy_from_slice(&checksum.to_le_bytes());
    Ok(bytes)
}

fn validation_plan_epoch(bytes: &[u8]) -> Result<u32, FfsError> {
    let encoded = bytes
        .get(56..64)
        .ok_or_else(|| FfsError::RepairFailed("short native whole-plan epoch".into()))?;
    let epoch = u64::from_le_bytes(encoded.try_into().expect("checked epoch length"));
    u32::try_from(epoch)
        .ok()
        .filter(|epoch| *epoch != 0)
        .ok_or_else(|| FfsError::RepairFailed("invalid native whole-plan epoch".into()))
}

fn validation_plan_intent(
    bytes: &[u8],
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
) -> Result<ValidationIntent, FfsError> {
    let tail = &storage.tails[0];
    if bytes.len() != VALIDATION_HEADER_BYTES {
        return Err(validation_error(tail, "whole-plan record length mismatch"));
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(validation_error(tail, "whole-plan record missing"));
    }
    let root: [u8; 32] = bytes[64..96].try_into().expect("fixed record length");
    let epoch = validation_plan_epoch(bytes)?;
    let state = u32::from_le_bytes(bytes[96..100].try_into().expect("fixed record length"));
    if !matches!(
        state,
        PLAN_PREPARED | VALIDATION_PENDING | VALIDATION_SEALED | PLAN_DIRTY
    ) || (state == PLAN_PREPARED && (root != [0; 32] || epoch != 1))
        || bytes != validation_plan_header(id, storage, generation, epoch, state, &root)?
    {
        return Err(validation_error(
            tail,
            "whole-plan identity or checksum mismatch",
        ));
    }
    Ok(if state == PLAN_PREPARED {
        ValidationIntent::Prepared
    } else if state == PLAN_DIRTY {
        ValidationIntent::Dirty(root)
    } else if state == VALIDATION_PENDING {
        ValidationIntent::Pending(root)
    } else {
        ValidationIntent::Sealed(root)
    })
}

fn validation_plan_root(
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
    plan_epoch: u32,
    admissions: &[ValidationAdmission],
) -> Result<[u8; 32], FfsError> {
    if admissions.is_empty()
        || plan_epoch == 0
        || admissions.len() != storage.tails.len()
        || admissions
            .iter()
            .any(|admission| admission.epoch == 0 || admission.epoch > plan_epoch)
    {
        return Err(FfsError::RepairFailed(
            "native whole-plan epoch mismatch".into(),
        ));
    }
    let header = validation_plan_header(
        id,
        storage,
        generation,
        plan_epoch,
        VALIDATION_PENDING,
        &[0; 32],
    )?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FrankenFS native whole-plan validation v1");
    hasher.update(&header[..64]);
    for (tail, admission) in storage.tails.iter().zip(admissions) {
        let group = validation_header(
            id,
            storage.owner_inode,
            generation,
            tail,
            admission.epoch,
            VALIDATION_PENDING,
            &admission.root,
        )?;
        hasher.update(&group[..104]);
    }
    Ok(*hasher.finalize().as_bytes())
}

#[expect(clippy::too_many_arguments)]
fn publish_validation_plan_with_token(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
    epoch: u32,
    intent: ValidationIntent,
    epoch_token: Option<&NativeEpochToken>,
) -> Result<(), FfsError> {
    let (state, root) = match intent {
        ValidationIntent::Dirty(root) => (PLAN_DIRTY, root),
        ValidationIntent::Pending(root) => (VALIDATION_PENDING, root),
        ValidationIntent::Sealed(root) => (VALIDATION_SEALED, root),
        ValidationIntent::Empty | ValidationIntent::Prepared => {
            return Err(FfsError::RepairFailed(
                "invalid native plan publication".into(),
            ));
        }
    };
    if state == VALIDATION_SEALED && epoch_token.is_some() {
        return Err(FfsError::RepairFailed(
            "sealed native plan cannot carry an epoch token".into(),
        ));
    }
    let first = storage.tails[0].start;
    let mut owner = check_native_owner_prefix(cx, dev, id, storage, generation, &storage.tails[0])?;
    owner[PLAN_HEADER_START..PLAN_HEADER_END].copy_from_slice(&validation_plan_header(
        id, storage, generation, epoch, state, &root,
    )?);
    if let Some(token) = epoch_token {
        owner[EPOCH_TOKEN_START..EPOCH_TOKEN_END].copy_from_slice(&token.encode(id));
    } else {
        owner[EPOCH_TOKEN_START..EPOCH_TOKEN_END].fill(0);
    }
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    dev.write_block(cx, first, &owner)?;
    dev.sync(cx)
}

fn publish_validation_plan(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
    epoch: u32,
    intent: ValidationIntent,
) -> Result<(), FfsError> {
    publish_validation_plan_with_token(cx, dev, id, storage, generation, epoch, intent, None)
}

fn admit_validation_plan(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
    admissions: &[ValidationAdmission],
) -> Result<(ValidationIntent, [u8; 32]), FfsError> {
    let first = &storage.tails[0];
    let owner = dev.read_block(cx, first.start)?;
    let plan = validation_plan_intent(
        &owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END],
        id,
        storage,
        generation,
    )?;
    let epoch = validation_plan_epoch(&owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END])?;
    if admissions.iter().any(|admission| admission.epoch != epoch) {
        return Err(validation_error(
            first,
            "whole-plan and local epochs disagree",
        ));
    }
    let root = validation_plan_root(id, storage, generation, epoch, admissions)?;
    match plan {
        ValidationIntent::Prepared => {
            if admissions
                .iter()
                .any(|group| group.intent != ValidationIntent::Empty)
            {
                return Err(validation_error(
                    first,
                    "group evidence has no whole-plan intent",
                ));
            }
        }
        ValidationIntent::Pending(expected) | ValidationIntent::Sealed(expected) => {
            if expected != root {
                return Err(validation_error(
                    first,
                    "whole-plan initialization source changed",
                ));
            }
            if matches!(plan, ValidationIntent::Sealed(_))
                && admissions
                    .iter()
                    .any(|group| !matches!(group.intent, ValidationIntent::Sealed(_)))
            {
                return Err(validation_error(first, "sealed plan has an unsealed group"));
            }
        }
        ValidationIntent::Empty => {
            return Err(validation_error(first, "whole-plan record missing"));
        }
        ValidationIntent::Dirty(_) => {
            return Err(validation_error(
                first,
                "native source write epoch is dirty",
            ));
        }
    }
    Ok((plan, root))
}

fn admit_validation_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    owner: InodeNumber,
    generation: u32,
    tail: &NativeRepairTail,
) -> Result<ValidationAdmission, FfsError> {
    let end = tail.start.0 + u64::from(tail.blocks());
    for number in [end - 2, end - 1] {
        if dev
            .read_block(cx, BlockNumber(number))?
            .as_slice()
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(validation_error(tail, "symbol descriptors already present"));
        }
    }
    let block = dev.read_block(cx, tail.start)?;
    let intent = validation_intent(
        &block.as_slice()[OWNER_HEADER_BYTES..OWNER_HEADER_BYTES + VALIDATION_HEADER_BYTES],
        id,
        owner,
        generation,
        tail,
    )?;
    let table = read_validation_table(cx, dev, id, tail)?;
    let epoch = if intent == ValidationIntent::Empty {
        1
    } else {
        u32::from_le_bytes(block.as_slice()[132..136].try_into().expect("owner header"))
    };
    if let ValidationIntent::Sealed(root) = intent {
        if validation_intent(
            &table[..VALIDATION_HEADER_BYTES],
            id,
            owner,
            generation,
            tail,
        )? != ValidationIntent::Sealed(root)
            || block.as_slice()[OWNER_HEADER_BYTES..PLAN_HEADER_START]
                != table[..VALIDATION_HEADER_BYTES]
        {
            return Err(validation_error(tail, "sealed intent and table disagree"));
        }
        verify_validation_table(cx, dev, id, tail, &table, &root)?;
        return Ok(ValidationAdmission {
            epoch,
            root,
            intent,
        });
    }
    if intent == ValidationIntent::Empty
        && table[..id.block_size as usize]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(validation_error(tail, "table has no initialization intent"));
    }
    let expected = build_validation_table(cx, dev, id, owner, generation, tail, epoch)?;
    let (_, _, used) = validation_sizes(id, tail)?;
    let root = validation_root(&expected, used);
    if let ValidationIntent::Pending(persisted) = intent
        && persisted != root
    {
        return Err(validation_error(
            tail,
            "pending initialization source changed",
        ));
    }
    Ok(ValidationAdmission {
        epoch,
        root,
        intent,
    })
}

fn publish_validation_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    id: &NativeFsIdentity,
    storage: &NativeRepairStorage,
    generation: u32,
    tail: &NativeRepairTail,
    admission: &ValidationAdmission,
) -> Result<(), FfsError> {
    let owner = storage.owner_inode;
    let root = &admission.root;
    let epoch = admission.epoch;
    let mut table = build_validation_table(cx, dev, id, owner, generation, tail, epoch)?;
    let (_, _, used) = validation_sizes(id, tail)?;
    if &validation_root(&table, used) != root {
        return Err(validation_error(
            tail,
            "source changed after initialization admission",
        ));
    }
    let pending = validation_header(id, owner, generation, tail, epoch, VALIDATION_PENDING, root)?;
    // Preserve the entire immutable ownership prefix verbatim.
    let mut ownership = check_native_owner_prefix(cx, dev, id, storage, generation, tail)?;
    ownership[OWNER_HEADER_BYTES..OWNER_HEADER_BYTES + VALIDATION_HEADER_BYTES]
        .copy_from_slice(&pending);
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    dev.write_block(cx, tail.start, &ownership)?;
    dev.sync(cx)?;
    for (index, block) in table.chunks_exact(id.block_size as usize).enumerate() {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let index = u32::try_from(index)
            .map_err(|_| validation_error(tail, "validation index exceeds u32"))?;
        dev.write_block(cx, BlockNumber(tail.start.0 + 1 + u64::from(index)), block)?;
    }
    dev.sync(cx)?;
    if read_validation_table(cx, dev, id, tail)? != table {
        return Err(validation_error(
            tail,
            "table readback mismatch before sealing",
        ));
    }
    verify_validation_table(cx, dev, id, tail, &table, root)?;
    let sealed = validation_header(id, owner, generation, tail, epoch, VALIDATION_SEALED, root)?;
    table[..VALIDATION_HEADER_BYTES].copy_from_slice(&sealed);
    dev.write_block(
        cx,
        BlockNumber(tail.start.0 + 1),
        &table[..id.block_size as usize],
    )?;
    dev.sync(cx)?;
    // Re-read the owner after the table barriers. Never restore an admission
    // snapshot over damage to the prefix or another authority record.
    let current = check_native_owner_prefix(cx, dev, id, storage, generation, tail)?;
    if current != ownership {
        return Err(validation_error(
            tail,
            "ownership changed before local validation seal",
        ));
    }
    ownership = current;
    ownership[OWNER_HEADER_BYTES..OWNER_HEADER_BYTES + VALIDATION_HEADER_BYTES]
        .copy_from_slice(&sealed);
    dev.write_block(cx, tail.start, &ownership)?;
    dev.sync(cx)?;
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn btrfs_first_source_block(block_size: u32) -> Result<u64, FfsError> {
    if !(1024..=65_536).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(FfsError::InvalidGeometry(
            "native btrfs repair requires a power-of-two sector size in 1024..=65536".into(),
        ));
    }
    let boot = BTRFS_SUPER_INFO_OFFSET as u64;
    if !boot.is_multiple_of(u64::from(block_size)) {
        return Err(FfsError::InvalidGeometry(
            "btrfs superblock offset is not aligned to sector size".into(),
        ));
    }
    Ok(boot / u64::from(block_size))
}

fn btrfs_group_overhead_blocks(
    block_size: u32,
    source_blocks: u32,
    basis_points: u32,
) -> Result<(u32, u32, u32), FfsError> {
    let validation_blocks = u32::try_from(
        (u64::from(source_blocks) * 32 + VALIDATION_HEADER_BYTES as u64)
            .div_ceil(u64::from(block_size)),
    )
    .map_err(|_| FfsError::InvalidGeometry("btrfs validation block count overflow".into()))?;
    let repair_blocks =
        u32::try_from((u64::from(source_blocks) * u64::from(basis_points)).div_ceil(10_000))
            .map_err(|_| FfsError::InvalidGeometry("btrfs repair block count overflow".into()))?;
    if repair_blocks == 0 || repair_blocks > source_blocks {
        return Err(FfsError::InvalidGeometry(
            "btrfs native group leaves insufficient source blocks for parity".into(),
        ));
    }
    let total = validation_blocks
        .checked_add(repair_blocks)
        .and_then(|count| count.checked_add(DESCRIPTOR_BLOCKS + 1))
        .ok_or_else(|| FfsError::InvalidGeometry("btrfs native group overhead overflow".into()))?;
    Ok((validation_blocks, repair_blocks, total))
}

fn btrfs_reserve_blocks_estimate(
    block_size: u32,
    total_blocks: u64,
    basis_points: u32,
) -> Result<u32, FfsError> {
    if !(100..=1000).contains(&basis_points) {
        return Err(FfsError::Format(
            "native repair overhead must be 1–10 percent".into(),
        ));
    }
    let first_source = btrfs_first_source_block(block_size)?;
    let usable = total_blocks
        .checked_sub(first_source)
        .filter(|&blocks| blocks >= 64)
        .ok_or_else(|| {
            FfsError::InvalidGeometry("btrfs image too small for native repair".into())
        })?;
    let max_group = u64::from(BTRFS_NATIVE_GROUP_MAX_BLOCKS);
    let est_groups = usable.div_ceil(max_group);
    if est_groups > 65_530 {
        return Err(FfsError::InvalidGeometry(
            "native btrfs repair group limit exceeded".into(),
        ));
    }
    let mut needed = 0_u64;
    let mut remaining = usable;
    while remaining > 0 {
        let chunk = u32::try_from(remaining.min(max_group)).expect("bounded by max_group");
        let (_, _, overhead) = btrfs_group_overhead_blocks(block_size, chunk, basis_points)?;
        needed = needed
            .checked_add(u64::from(overhead))
            .ok_or_else(|| FfsError::InvalidGeometry("btrfs native reserve overflow".into()))?;
        remaining -= u64::from(chunk);
    }
    let margin = u64::from(DESCRIPTOR_BLOCKS + 1 + 8);
    let total_reserve = needed
        .checked_add(margin)
        .ok_or_else(|| FfsError::InvalidGeometry("btrfs native reserve overflow".into()))?;
    if total_reserve.saturating_add(32) >= usable {
        return Err(FfsError::NoSpace);
    }
    u32::try_from(total_reserve)
        .map_err(|_| FfsError::InvalidGeometry("btrfs native reserve exceeds u32".into()))
}

fn btrfs_tail_plan_from_extents(
    block_size: u32,
    total_blocks: u64,
    basis_points: u32,
    physical_extents: &[(u64, u32)],
) -> Result<Vec<NativeRepairTail>, FfsError> {
    if !(100..=1000).contains(&basis_points) {
        return Err(FfsError::Format(
            "native repair overhead must be 1–10 percent".into(),
        ));
    }
    if physical_extents.is_empty() {
        return Err(FfsError::Format(
            "native btrfs repair owner has no extents".into(),
        ));
    }
    let first_source = btrfs_first_source_block(block_size)?;
    let mut sorted_extents = physical_extents.to_vec();
    sorted_extents.sort_by_key(|&(start, _)| start);
    let mut prev_end = first_source;
    let mut source_chunks: Vec<(u64, u32)> = Vec::new();
    for &(ext_start, ext_blocks) in &sorted_extents {
        if ext_blocks == 0 {
            return Err(FfsError::Format(
                "native btrfs repair extent has zero length".into(),
            ));
        }
        let ext_end = ext_start
            .checked_add(u64::from(ext_blocks))
            .filter(|&end| ext_start >= prev_end && end <= total_blocks)
            .ok_or_else(|| {
                FfsError::Format(
                    "native btrfs repair extents overlap or fall outside image bounds".into(),
                )
            })?;
        let mut cursor = prev_end;
        while cursor < ext_start {
            let chunk =
                u32::try_from((ext_start - cursor).min(u64::from(BTRFS_NATIVE_GROUP_MAX_BLOCKS)))
                    .expect("bounded by BTRFS_NATIVE_GROUP_MAX_BLOCKS");
            source_chunks.push((cursor, chunk));
            cursor += u64::from(chunk);
        }
        prev_end = ext_end;
    }
    let mut cursor = prev_end;
    while cursor < total_blocks {
        let chunk =
            u32::try_from((total_blocks - cursor).min(u64::from(BTRFS_NATIVE_GROUP_MAX_BLOCKS)))
                .expect("bounded by BTRFS_NATIVE_GROUP_MAX_BLOCKS");
        source_chunks.push((cursor, chunk));
        cursor += u64::from(chunk);
    }
    if source_chunks.is_empty() || source_chunks.len() > 65_536 {
        return Err(FfsError::InvalidGeometry(
            "native btrfs repair source partition count out of bounds".into(),
        ));
    }

    let mut tails: Vec<NativeRepairTail> = Vec::with_capacity(source_chunks.len());
    let mut ext_idx = 0_usize;
    let mut ext_cursor = sorted_extents[0].0;
    let mut ext_remaining = sorted_extents[0].1;
    let mut ext_tail_range_start = 0_usize;

    for (group_idx, &(group_start, source_blocks)) in source_chunks.iter().enumerate() {
        let (validation_blocks, repair_blocks, needed) =
            btrfs_group_overhead_blocks(block_size, source_blocks, basis_points)?;
        while ext_remaining < needed {
            if ext_remaining > 0 {
                let mut slack = ext_remaining;
                for tail in &mut tails[ext_tail_range_start..] {
                    let cap = tail.blocks_per_group.saturating_sub(tail.repair_blocks);
                    let add = slack.min(cap);
                    tail.repair_blocks += add;
                    slack -= add;
                    if slack == 0 {
                        break;
                    }
                }
                if slack != 0 {
                    return Err(FfsError::InvalidGeometry(
                        "btrfs native repair extent slack cannot fit in preceding groups".into(),
                    ));
                }
                let mut repack = sorted_extents[ext_idx].0;
                for tail in &mut tails[ext_tail_range_start..] {
                    tail.start = BlockNumber(repack);
                    repack += u64::from(tail.blocks());
                }
            }
            ext_idx += 1;
            if ext_idx >= sorted_extents.len() {
                return Err(FfsError::Format(
                    "native btrfs repair owner extents are smaller than required parity storage"
                        .into(),
                ));
            }
            ext_cursor = sorted_extents[ext_idx].0;
            ext_remaining = sorted_extents[ext_idx].1;
            ext_tail_range_start = tails.len();
        }
        let group = GroupNumber(
            u32::try_from(group_idx)
                .map_err(|_| FfsError::InvalidGeometry("btrfs group index overflow".into()))?,
        );
        tails.push(NativeRepairTail {
            group,
            group_start: BlockNumber(group_start),
            blocks_per_group: source_blocks,
            start: BlockNumber(ext_cursor),
            validation_blocks,
            repair_blocks,
        });
        ext_cursor += u64::from(needed);
        ext_remaining -= needed;
    }

    if ext_idx + 1 != sorted_extents.len() {
        return Err(FfsError::Format(
            "native btrfs repair owner has unmapped trailing extents".into(),
        ));
    }
    if ext_remaining > 0 {
        let mut slack = ext_remaining;
        for tail in tails[ext_tail_range_start..].iter_mut().rev() {
            let cap = tail.blocks_per_group.saturating_sub(tail.repair_blocks);
            let add = slack.min(cap);
            tail.repair_blocks += add;
            slack -= add;
            if slack == 0 {
                break;
            }
        }
        if slack != 0 {
            return Err(FfsError::InvalidGeometry(
                "btrfs native repair trailing slack exceeds group source capacity".into(),
            ));
        }
        let mut repack = sorted_extents[ext_idx].0;
        for tail in &mut tails[ext_tail_range_start..] {
            tail.start = BlockNumber(repack);
            repack += u64::from(tail.blocks());
        }
    }
    Ok(tails)
}

fn btrfs_resolve_single_data_extent(
    chunks: &[ffs_ondisk::BtrfsChunkEntry],
    expected_devid: u64,
    sectorsize: u32,
    disk_bytenr: u64,
    disk_num_bytes: u64,
) -> Result<(u64, u32), FfsError> {
    if disk_bytenr == 0
        || disk_num_bytes == 0
        || !disk_bytenr.is_multiple_of(u64::from(sectorsize))
        || !disk_num_bytes.is_multiple_of(u64::from(sectorsize))
    {
        return Err(FfsError::Format(
            "native btrfs repair extent is unaligned or sparse".into(),
        ));
    }
    let chunk = chunks
        .iter()
        .find(|entry| {
            let Some(end) = entry.key.offset.checked_add(entry.length) else {
                return false;
            };
            disk_bytenr >= entry.key.offset && disk_bytenr < end
        })
        .ok_or_else(|| {
            FfsError::Format("native btrfs repair extent is missing from CHUNK_TREE".into())
        })?;
    let chunk_end = chunk
        .key
        .offset
        .checked_add(chunk.length)
        .ok_or_else(|| FfsError::InvalidGeometry("btrfs chunk range overflow".into()))?;
    let extent_end = disk_bytenr
        .checked_add(disk_num_bytes)
        .ok_or_else(|| FfsError::InvalidGeometry("btrfs repair extent overflow".into()))?;
    if extent_end > chunk_end
        || chunk.chunk_type & super::BTRFS_BLOCK_GROUP_DATA == 0
        || chunk.chunk_type & ffs_ondisk::chunk_type_flags::RAID_MASK != 0
        || chunk.stripes.len() != 1
    {
        return Err(FfsError::UnsupportedFeature(
            "native btrfs repair requires contiguous SINGLE-profile DATA extents".into(),
        ));
    }
    let mapping = map_logical_to_physical(chunks, disk_bytenr)
        .map_err(|error| parse_to_ffs_error(&error))?
        .ok_or_else(|| FfsError::Format("native btrfs repair logical mapping missing".into()))?;
    if mapping.devid != expected_devid || mapping.physical % u64::from(sectorsize) != 0 {
        return Err(FfsError::Format(
            "native btrfs repair physical stripe disagrees with primary device".into(),
        ));
    }
    let start_block = mapping.physical / u64::from(sectorsize);
    let blocks = u32::try_from(disk_num_bytes / u64::from(sectorsize))
        .map_err(|_| FfsError::InvalidGeometry("btrfs repair extent blocks exceed u32".into()))?;
    Ok((start_block, blocks))
}

#[expect(clippy::too_many_arguments)]
fn heal_clean_group_sources(
    cx: &Cx,
    dev: &dyn BlockDevice,
    raw_sync: &dyn ByteDevice,
    id: &NativeFsIdentity,
    tail: &NativeRepairTail,
    table: &[u8],
    root: &[u8; 32],
    expected_generation: u64,
    corrupt: &[u32],
) -> Result<(), FfsError> {
    let view = NativeDigestDevice {
        dev,
        tail,
        table,
        corrupt,
    };
    let capture = NativeReconstructionCapture {
        blocks: OnceCell::new(),
    };
    let (layout, expected) = native_layout(id, tail)?;
    let result = GroupRecoveryOrchestrator::new_with_writeback(
        &view,
        &capture,
        id.uuid,
        layout,
        tail.group_start,
        u32::from(expected.source_block_count),
    )?
    .with_decoded_block_validator(&view)
    .recover_from_indices(cx, corrupt);
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    if !result.is_success() || result.evidence.generation != expected_generation {
        return Err(FfsError::RepairFailed(format!(
            "native cold source healing failed in group {}: {:?}",
            tail.group.0, result.evidence.reason
        )));
    }
    let recovered = capture
        .blocks
        .into_inner()
        .ok_or_else(|| validation_error(tail, "native cold source healing produced no capture"))?;
    for source in 0..u32::from(expected.source_block_count) {
        view.read_block(cx, BlockNumber(tail.group_start.0 + u64::from(source)))?;
    }
    for block in &recovered {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if dev.read_block(cx, block.block)?.as_slice() != block.expected_current {
            return Err(validation_error(tail, "native heal target changed"));
        }
        dev.write_block(cx, block.block, &block.data)?;
    }
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    raw_sync.sync(cx)?;
    verify_validation_table(cx, dev, id, tail, table, root)
}

impl OpenFs {
    pub(crate) fn begin_durability_commit(
        &self,
        cx: &Cx,
        pre_commit_seq: u64,
        hinted_blocks: &[BlockNumber],
    ) -> Result<DurabilityCommitGuard<'_>, FfsError> {
        let Some(device) = self.native_repair_device.as_deref() else {
            let byte_deferral = ffs_block::DurabilityCommitDeferral::enter(cx, self.dev.as_ref())?;
            return Ok(DurabilityCommitGuard {
                device: None,
                byte_deferral: Some(byte_deferral),
                armed: false,
            });
        };
        device.begin_durability_commit(cx, pre_commit_seq, hinted_blocks)
    }

    #[must_use]
    pub fn shared_fenced_device(&self) -> Arc<dyn ByteDevice> {
        Arc::clone(&self.dev)
    }

    #[must_use]
    pub fn shared_backing_device(&self) -> Arc<dyn ByteDevice> {
        self.native_repair_device
            .as_ref()
            .map_or_else(|| Arc::clone(&self.dev), |dev| dev.backing_device())
    }

    #[must_use]
    pub fn native_recovery_touched_blocks(&self) -> &BTreeSet<BlockNumber> {
        &self.native_recovery_touched_blocks
    }

    /// Run a full verified scrub + self-healing pass across all native groups
    /// under `NativeFreshnessDevice`'s mutex, updating the Ville/Wald monitor.
    pub fn scrub_and_heal_native(&self, cx: &Cx) -> Result<NativeScrubHealReport, FfsError> {
        let device = self
            .native_repair_device
            .as_ref()
            .ok_or_else(|| freshness_error("native repair device is not active"))?;
        device.scrub_and_heal_all_groups(cx)
    }

    pub(crate) fn verify_btrfs_native_owner_in_tree(
        &self,
        alloc: &BtrfsAllocState,
    ) -> Result<(), FfsError> {
        let Some(device) = self.native_repair_device.as_ref() else {
            return Ok(());
        };
        let Some(sb) = self.btrfs_superblock() else {
            return Ok(());
        };
        let Ok(state) = device.state.try_lock() else {
            return Ok(());
        };
        let storage = &state.baseline.storage;
        let owner_oid = storage.owner_inode.0;
        let inode = self.btrfs_read_inode_from_tree(alloc, owner_oid)?;
        let expected_blocks: u64 = storage
            .tails
            .iter()
            .map(|tail| u64::from(tail.blocks()))
            .sum();
        let expected_bytes = expected_blocks * u64::from(sb.sectorsize);
        if inode.mode != 0o100_400
            || inode.flags & BTRFS_NATIVE_OWNER_FLAGS != BTRFS_NATIVE_OWNER_FLAGS
            || inode.nlink != 1
            || inode.size != expected_bytes
            || inode.nbytes != expected_bytes
        {
            return Err(freshness_error(
                "btrfs commit altered native repair owner inode invariants",
            ));
        }
        Ok(())
    }

    fn capture_native_ownership(
        &self,
        cx: &Cx,
        sb: &Ext4Superblock,
        storage: &NativeRepairStorage,
        remaining_budget: u64,
    ) -> Result<NativeOwnershipConstraints, FfsError> {
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.block_size,
        };
        let mut constraints = NativeOwnershipConstraints {
            blocks: BTreeMap::new(),
            remaining_budget,
        };
        constraints.protect_geometry(cx, &dev)?;
        let location = sb
            .locate_inode(storage.owner_inode)
            .map_err(|error| parse_to_ffs_error(&error))?;
        constraints.protect_groups(cx, &dev, sb, storage, location.group)?;
        let gd = read_native_group_desc(cx, &dev, sb, location.group)?;
        constraints.protect_allocated(
            cx,
            &dev,
            BlockNumber(gd.inode_bitmap),
            u64::from(location.index),
        )?;
        let inode_offset = sb
            .inode_device_offset(&location, gd.inode_table)
            .map_err(|error| parse_to_ffs_error(&error))?;
        let inode = self.read_native_owner_inode(cx, sb, storage.owner_inode)?;
        for index in 0..u64::from(sb.inode_size) {
            let atime = (0x08..0x0C).contains(&index)
                || (inode.extra_isize >= 16 && (0x8C..0x90).contains(&index));
            let checksum = (0x7C..0x7E).contains(&index)
                || (inode.extra_isize >= 4 && (0x82..0x84).contains(&index));
            if !atime && !checksum {
                constraints.protect(cx, &dev, inode_offset + index, 1, u8::MAX)?;
            }
        }
        let (_, nodes) = self.read_native_owner_extents(cx, sb, &inode)?;
        for node in nodes {
            let relative = node - u64::from(sb.first_data_block);
            let group = GroupNumber(
                u32::try_from(relative / u64::from(sb.blocks_per_group))
                    .map_err(|_| freshness_error("owner extent node group overflows"))?,
            );
            let gd = read_native_group_desc(cx, &dev, sb, group)?;
            constraints.protect_allocated(
                cx,
                &dev,
                BlockNumber(gd.block_bitmap),
                relative % u64::from(sb.blocks_per_group),
            )?;
            constraints.protect(
                cx,
                &dev,
                node * u64::from(sb.block_size),
                u64::from(sb.block_size),
                u8::MAX,
            )?;
        }
        Ok(constraints)
    }

    fn capture_native_btrfs_ownership(
        &self,
        cx: &Cx,
        sb: &BtrfsSuperblock,
        remaining_budget: u64,
    ) -> Result<NativeOwnershipConstraints, FfsError> {
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.sectorsize,
        };
        let mut constraints = NativeOwnershipConstraints {
            blocks: BTreeMap::new(),
            remaining_budget,
        };
        constraints.protect_btrfs_superblock(cx, &dev)?;
        Ok(constraints)
    }

    fn native_identity_storage_and_generation(
        &self,
        cx: &Cx,
    ) -> Result<(NativeFsIdentity, NativeRepairStorage, u32), FfsError> {
        if let Some(sb) = self.ext4_superblock() {
            let storage = self.native_ext4_repair_storage(cx)?;
            let inode = self.read_native_owner_inode(cx, sb, storage.owner_inode)?;
            return Ok((NativeFsIdentity::from_ext4(sb), storage, inode.generation));
        }
        if let Some(sb) = self.btrfs_superblock() {
            let (storage, generation) = self.native_btrfs_repair_storage_with_generation(cx)?;
            let groups = u32::try_from(storage.tails.len()).map_err(|_| {
                FfsError::InvalidGeometry("btrfs native group count exceeds u32".into())
            })?;
            return Ok((
                NativeFsIdentity::from_btrfs(sb, groups),
                storage,
                generation,
            ));
        }
        Err(FfsError::UnsupportedFeature(
            "native repair storage requires ext4 or btrfs".into(),
        ))
    }

    pub(crate) fn finalize_replayed_ext4_journal_for_native_repair(
        &mut self,
        cx: &Cx,
    ) -> Result<(), FfsError> {
        let Some(sb) = self.ext4_superblock().cloned() else {
            return Ok(());
        };
        if sb.journal_inum == 0 || self.ext4_replay_overlay {
            return Ok(());
        }
        let inode = self.read_inode(cx, InodeNumber(u64::from(sb.journal_inum)))?;
        let segments = self.collect_ext4_journal_segments(cx, &inode)?;
        let Some(first) = segments.first() else {
            return Ok(());
        };
        let raw = self.read_block_vec(cx, first.start)?;
        let journal_dirty = Jbd2Superblock::parse(&raw).is_some_and(|jsb| jsb.start_block != 0);
        let sb_dirty = sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::RECOVER)
            || ext4_superblock_requires_journal_recovery(&sb);
        if !journal_dirty && !sb_dirty {
            return Ok(());
        }
        self.dev.sync(cx)?;
        if let Some(writer) = self.open_ext4_internal_jbd2_writer(cx)? {
            let direct = self.direct_block_device_adapter();
            writer
                .mark_log_empty(cx, &direct)
                .map_err(|err| FfsError::Io(std::io::Error::other(err.to_string())))?;
            self.ext4_write_needs_recovery(cx, &direct, false)?;
            self.dev.sync(cx)?;
            let sb_region = read_ext4_superblock_region(cx, self.dev.as_ref())?;
            if let super::FsFlavor::Ext4(slot) = &mut self.flavor {
                **slot = Ext4Superblock::parse_superblock_region(&sb_region)
                    .map_err(|e| parse_to_ffs_error(&e))?;
            }
            self.invalidate_ext4_read_caches_after_recovery();
        }
        Ok(())
    }

    /// Reconcile root-bound pending epochs and dirty fences whose possible
    /// write targets still match the old sealed sources, then activate native
    /// read verification and write fencing. Changed Dirty sources require
    /// durable per-source intent and are refused; a group bitmap alone cannot
    /// distinguish a legitimate write from corruption.
    #[expect(clippy::too_many_lines)]
    pub fn reconcile_and_activate_native_repair(
        &mut self,
        cx: &Cx,
        max_working_bytes: u64,
        recovery_touched_blocks: &BTreeSet<BlockNumber>,
    ) -> Result<NativeRepairReport, FfsError> {
        self.require_write_authority()?;
        self.require_native_mode("activate_native_repair")?;
        if self.native_repair_device.is_some() {
            return Err(freshness_error("device is already active"));
        }
        if self.ext4_replay_overlay {
            return Err(freshness_error(
                "simulated replay cannot certify image durability",
            ));
        }
        if self.metadata_log.is_some() || self.metadata_compactor.lock().is_some() {
            return Err(freshness_error("external metadata WAL is not admitted"));
        }
        self.finalize_replayed_ext4_journal_for_native_repair(cx)?;

        let (id, storage, owner_generation) = self.native_identity_storage_and_generation(cx)?;
        let retained_budget = freshness_codec_budget(&id, &storage, max_working_bytes)?;
        let probe_constraints = if let Some(sb) = self.ext4_superblock() {
            sb.validate_v1().map_err(|e| parse_to_ffs_error(&e))?;
            self.capture_native_ownership(cx, sb, &storage, retained_budget)?
        } else if let Some(sb) = self.btrfs_superblock() {
            self.capture_native_btrfs_ownership(cx, sb, retained_budget)?
        } else {
            return Err(freshness_error("native freshness requires ext4 or btrfs"));
        };
        let codec_budget = probe_constraints.remaining_budget;
        for tail in &storage.tails {
            native_codec_budget(&id, &storage, tail, codec_budget, false)?;
        }

        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: id.block_size,
        };
        let owner0 = check_native_owner_prefix(
            cx,
            &dev,
            &id,
            &storage,
            owner_generation,
            &storage.tails[0],
        )?;
        let plan_bytes = &owner0[PLAN_HEADER_START..PLAN_HEADER_END];
        let plan_intent = validation_plan_intent(plan_bytes, &id, &storage, owner_generation)?;
        let plan_epoch = validation_plan_epoch(plan_bytes)?;
        let maybe_token = NativeEpochToken::decode_optional(
            &owner0[EPOCH_TOKEN_START..EPOCH_TOKEN_END],
            &id,
            storage.owner_inode,
            owner_generation,
            &storage.tails[0],
        )?;

        let mut recovery_dirty_groups = BTreeSet::new();
        for &blk in recovery_touched_blocks {
            if let Some(tail) = native_source_tail(&storage, blk) {
                recovery_dirty_groups.insert(tail.group);
            }
        }

        match (plan_intent, maybe_token) {
            (ValidationIntent::Sealed(_), None) => {
                if !recovery_dirty_groups.is_empty() {
                    return Err(freshness_error(
                        "uncoordinated recovery modified a sealed native baseline without an epoch token",
                    ));
                }
                let baseline = read_native_baseline(self, cx)?;
                for (index, tail) in storage.tails.iter().enumerate() {
                    let (root, table) =
                        read_sealed_table(cx, &dev, &id, &storage, owner_generation, tail)?;
                    let corrupt = native_corrupt_indices(cx, &dev, &id, tail, &table)?;
                    if corrupt.is_empty() {
                        if root != baseline.roots[index] {
                            return Err(validation_error(tail, "sealed root changed"));
                        }
                        native_sealed_generation(cx, &dev, &id, &baseline, tail, false)?;
                    } else {
                        native_codec_budget(&id, &storage, tail, codec_budget, true)?;
                        let generation =
                            native_sealed_generation(cx, &dev, &id, &baseline, tail, true)?;
                        heal_clean_group_sources(
                            cx,
                            &dev,
                            self.dev.as_ref(),
                            &id,
                            tail,
                            &table,
                            &baseline.roots[index],
                            generation,
                            &corrupt,
                        )?;
                    }
                }
            }
            (ValidationIntent::Sealed(_), Some(_)) => {
                return Err(validation_error(
                    &storage.tails[0],
                    "sealed plan carries an unretired epoch token",
                ));
            }
            (ValidationIntent::Dirty(prev_root), Some(token))
                if token.flags & EPOCH_TOKEN_FLAG_FORMAT_COMMIT != 0
                    && token.prev_sealed_plan_root == prev_root
                    && token.prev_sealed_epoch == plan_epoch =>
            {
                let baseline = read_native_group_baseline(
                    cx,
                    &dev,
                    &id,
                    storage.clone(),
                    owner_generation,
                    token.prev_sealed_epoch,
                    prev_root,
                )?;
                verify_dirty_recovery_sources(
                    cx,
                    &dev,
                    &id,
                    &baseline,
                    &token,
                    &recovery_dirty_groups,
                )?;
                for (index, tail) in storage.tails.iter().enumerate() {
                    let (root, table) =
                        read_sealed_table(cx, &dev, &id, &storage, owner_generation, tail)?;
                    if root != baseline.roots[index] {
                        return Err(validation_error(tail, "dirty recovery baseline changed"));
                    }
                    let corrupt = native_corrupt_indices(cx, &dev, &id, tail, &table)?;
                    if corrupt.is_empty() {
                        native_sealed_generation(cx, &dev, &id, &baseline, tail, false)?;
                    } else {
                        if token.is_group_dirty(tail.group)
                            || recovery_dirty_groups.contains(&tail.group)
                        {
                            return Err(validation_error(
                                tail,
                                "dirty epoch source changed without persisted intended-source authority",
                            ));
                        }
                        native_codec_budget(&id, &storage, tail, codec_budget, true)?;
                        let generation =
                            native_sealed_generation(cx, &dev, &id, &baseline, tail, true)?;
                        heal_clean_group_sources(
                            cx,
                            &dev,
                            self.dev.as_ref(),
                            &id,
                            tail,
                            &table,
                            &root,
                            generation,
                            &corrupt,
                        )?;
                    }
                }
                // No source change survived the interrupted write. Retire the
                // fence against the original sealed epoch instead of blessing
                // freshly observed bytes as a new baseline.
                publish_validation_plan_with_token(
                    cx,
                    &dev,
                    &id,
                    &storage,
                    owner_generation,
                    token.prev_sealed_epoch,
                    ValidationIntent::Sealed(prev_root),
                    None,
                )?;
                self.dev.sync(cx)?;
            }
            (ValidationIntent::Pending(expected_plan_root), Some(token))
                if token.flags & EPOCH_TOKEN_FLAG_FORMAT_COMMIT != 0
                    && token.target_epoch == plan_epoch =>
            {
                let target_epoch = token.target_epoch;
                let mut validations = Vec::with_capacity(storage.tails.len());
                let mut needs_table_publish = Vec::with_capacity(storage.tails.len());
                let mut needs_parity_publish = Vec::with_capacity(storage.tails.len());
                let mut needs_source_heal = Vec::new();
                for (index, tail) in storage.tails.iter().enumerate() {
                    if !token.is_group_dirty(tail.group) {
                        let (root, table) =
                            read_sealed_table(cx, &dev, &id, &storage, owner_generation, tail)?;
                        let local_epoch =
                            u32::from_le_bytes(table[68..72].try_into().expect("checked table"));
                        if local_epoch == 0 || local_epoch > token.prev_sealed_epoch {
                            return Err(validation_error(
                                tail,
                                "clean group epoch exceeds pre-crash sealed epoch",
                            ));
                        }
                        let temp_baseline = NativeBaseline {
                            storage: storage.clone(),
                            owner_generation,
                            epoch: token.prev_sealed_epoch,
                            plan_root: token.prev_sealed_plan_root,
                            roots: storage.tails.iter().map(|_| root).collect(),
                            group_epochs: vec![local_epoch; storage.tails.len()],
                        };
                        let corrupt = native_corrupt_indices(cx, &dev, &id, tail, &table)?;
                        if corrupt.is_empty() {
                            verify_validation_table(cx, &dev, &id, tail, &table, &root)?;
                            native_sealed_generation(cx, &dev, &id, &temp_baseline, tail, false)?;
                        } else {
                            native_codec_budget(&id, &storage, tail, codec_budget, true)?;
                            native_sealed_generation(cx, &dev, &id, &temp_baseline, tail, true)?;
                            needs_source_heal.push(index);
                        }
                        validations.push(ValidationAdmission {
                            epoch: local_epoch,
                            root,
                            intent: ValidationIntent::Sealed(root),
                        });
                        needs_table_publish.push(false);
                        needs_parity_publish.push(false);
                    } else if let Ok((root, table)) =
                        read_sealed_table(cx, &dev, &id, &storage, owner_generation, tail)
                        && u32::from_le_bytes(table[68..72].try_into().expect("checked table"))
                            == target_epoch
                    {
                        let temp_baseline = NativeBaseline {
                            storage: storage.clone(),
                            owner_generation,
                            epoch: target_epoch,
                            plan_root: expected_plan_root,
                            roots: storage.tails.iter().map(|_| root).collect(),
                            group_epochs: vec![target_epoch; storage.tails.len()],
                        };
                        let already_parity_sealed =
                            native_sealed_generation(cx, &dev, &id, &temp_baseline, tail, true)
                                .is_ok();
                        if already_parity_sealed {
                            let corrupt = native_corrupt_indices(cx, &dev, &id, tail, &table)?;
                            if corrupt.is_empty() {
                                verify_validation_table(cx, &dev, &id, tail, &table, &root)?;
                            } else {
                                native_codec_budget(&id, &storage, tail, codec_budget, true)?;
                                native_sealed_generation(
                                    cx,
                                    &dev,
                                    &id,
                                    &temp_baseline,
                                    tail,
                                    true,
                                )?;
                                needs_source_heal.push(index);
                            }
                            needs_parity_publish.push(false);
                        } else {
                            verify_validation_table(cx, &dev, &id, tail, &table, &root)?;
                            needs_parity_publish.push(true);
                        }
                        validations.push(ValidationAdmission {
                            epoch: target_epoch,
                            root,
                            intent: ValidationIntent::Sealed(root),
                        });
                        needs_table_publish.push(false);
                    } else {
                        let table = build_validation_table(
                            cx,
                            &dev,
                            &id,
                            storage.owner_inode,
                            owner_generation,
                            tail,
                            target_epoch,
                        )?;
                        let (_, _, used) = validation_sizes(&id, tail)?;
                        let root = validation_root(&table, used);
                        validations.push(ValidationAdmission {
                            epoch: target_epoch,
                            root,
                            intent: ValidationIntent::Pending(root),
                        });
                        needs_table_publish.push(true);
                        needs_parity_publish.push(true);
                    }
                }
                let computed_plan_root = validation_plan_root(
                    &id,
                    &storage,
                    owner_generation,
                    target_epoch,
                    &validations,
                )?;
                if computed_plan_root != expected_plan_root {
                    return Err(validation_error(
                        &storage.tails[0],
                        "pending epoch source blocks disagree with committed plan root",
                    ));
                }
                let next = NativeBaseline {
                    storage: storage.clone(),
                    owner_generation,
                    epoch: target_epoch,
                    plan_root: expected_plan_root,
                    roots: validations.iter().map(|v| v.root).collect(),
                    group_epochs: validations.iter().map(|v| v.epoch).collect(),
                };
                // Local checksums and parity do not by themselves authorize
                // restoration. Bind every group's source root to the persisted
                // plan first, then reread authority before the first heal.
                for index in needs_source_heal {
                    let tail = &storage.tails[index];
                    let (root, table) =
                        read_sealed_table(cx, &dev, &id, &storage, owner_generation, tail)?;
                    if root != next.roots[index] {
                        return Err(validation_error(tail, "pending recovery baseline changed"));
                    }
                    let corrupt = native_corrupt_indices(cx, &dev, &id, tail, &table)?;
                    let generation = native_sealed_generation(cx, &dev, &id, &next, tail, true)?;
                    heal_clean_group_sources(
                        cx,
                        &dev,
                        self.dev.as_ref(),
                        &id,
                        tail,
                        &table,
                        &root,
                        generation,
                        &corrupt,
                    )?;
                }
                let mut admissions = Vec::with_capacity(storage.tails.len());
                for (index, tail) in storage.tails.iter().enumerate() {
                    let expected_root = (!needs_parity_publish[index]).then_some(next.roots[index]);
                    let mut adm = admit_native_group_unconstrained_root(
                        cx,
                        &dev,
                        &id,
                        &storage,
                        owner_generation,
                        tail,
                        codec_budget,
                        expected_root,
                    )?;
                    if needs_parity_publish[index] {
                        adm.retained = false;
                    }
                    admissions.push(adm);
                }
                self.dev.sync(cx)?;
                for (index, tail) in storage.tails.iter().enumerate() {
                    if needs_table_publish[index] {
                        publish_validation_group(
                            cx,
                            &dev,
                            &id,
                            &storage,
                            owner_generation,
                            tail,
                            &validations[index],
                        )?;
                    }
                    if needs_parity_publish[index] {
                        let (_, sealed_table) =
                            read_sealed_table(cx, &dev, &id, &storage, owner_generation, tail)?;
                        encode_and_publish_native_group(
                            cx,
                            &dev,
                            &id,
                            &next,
                            tail,
                            &admissions[index],
                            &sealed_table,
                            None,
                        )?;
                    }
                }
                publish_validation_plan_with_token(
                    cx,
                    &dev,
                    &id,
                    &storage,
                    owner_generation,
                    target_epoch,
                    ValidationIntent::Sealed(expected_plan_root),
                    None,
                )?;
                self.dev.sync(cx)?;
            }
            _ => {
                return Err(validation_error(
                    &storage.tails[0],
                    "whole-plan validation is uninitialized, dirty without commit token, or pending",
                ));
            }
        }

        self.activate_native_repair(cx, max_working_bytes)
    }

    /// Admit sealed native protection, verify reads and fence source writes on
    /// either ext4 or btrfs.
    pub fn activate_native_repair(
        &mut self,
        cx: &Cx,
        max_working_bytes: u64,
    ) -> Result<NativeRepairReport, FfsError> {
        self.require_write_authority()?;
        self.require_native_mode("activate_native_repair")?;
        if self.native_repair_device.is_some() {
            return Err(freshness_error("device is already active"));
        }
        if self.ext4_replay_overlay {
            return Err(freshness_error(
                "simulated replay cannot certify image durability",
            ));
        }
        if self.metadata_log.is_some() || self.metadata_compactor.lock().is_some() {
            return Err(freshness_error("external metadata WAL is not admitted"));
        }
        let (id, storage, _) = self.native_identity_storage_and_generation(cx)?;
        let retained_budget = freshness_codec_budget(&id, &storage, max_working_bytes)?;
        let ownership = if let Some(sb) = self.ext4_superblock() {
            sb.validate_v1()
                .map_err(|error| parse_to_ffs_error(&error))?;
            self.capture_native_ownership(cx, sb, &storage, retained_budget)?
        } else if let Some(sb) = self.btrfs_superblock() {
            self.capture_native_btrfs_ownership(cx, sb, retained_budget)?
        } else {
            return Err(freshness_error("native freshness requires ext4 or btrfs"));
        };
        let codec_budget = ownership.remaining_budget;
        for tail in &storage.tails {
            native_codec_budget(&id, &storage, tail, codec_budget, false)?;
        }
        let baseline = read_native_baseline(self, cx)?;
        baseline
            .epoch
            .checked_add(1)
            .ok_or_else(|| freshness_error("validation epoch exhausted before activation"))?;
        let report = self.check_native_repair(cx)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: id.block_size,
        };
        let group_count = storage.tails.len();
        let mut tables = Vec::with_capacity(group_count);
        let mut parity = Vec::with_capacity(group_count);
        for (index, tail) in storage.tails.iter().enumerate() {
            let (root, table) =
                read_sealed_table(cx, &dev, &id, &storage, baseline.owner_generation, tail)?;
            if root != baseline.roots[index] {
                return Err(validation_error(
                    tail,
                    "source authority changed during activation",
                ));
            }
            verify_validation_table(cx, &dev, &id, tail, &table, &root)?;
            let admission = admit_native_group(cx, &dev, &id, &baseline, tail, codec_budget)?;
            if !admission.retained || admission.intent.generation() != report.generations[index] {
                return Err(validation_error(
                    tail,
                    "parity authority changed during activation",
                ));
            }
            tables.push(table);
            parity.push(admission.intent);
        }
        ensure_native_baseline(self, cx, &baseline)?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        {
            use rayon::prelude::*;
            let warm_targets: Vec<(u32, u64)> = storage
                .tails
                .iter()
                .take(16)
                .filter_map(|tail| {
                    let (sources, _, _) = validation_sizes(&id, tail).ok()?;
                    let delta_ok = u64::from(sources)
                        .saturating_mul(u64::from(sources))
                        .saturating_mul(3)
                        <= codec_budget;
                    (sources <= 2_048 && delta_ok)
                        .then(|| (sources, repair_seed(&id.uuid, tail.group)))
                })
                .collect();
            warm_targets.into_par_iter().for_each(|(sources, seed)| {
                warm_group_delta_encoder(sources, seed);
            });
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let device = Arc::new(NativeFreshnessDevice {
            inner: Arc::clone(&self.dev),
            id,
            state: NativeMutex::new(NativeFreshnessState {
                baseline,
                tables,
                parity,
                intended: BTreeMap::new(),
                beforeimages: BTreeMap::new(),
                dirty_groups: vec![false; group_count],
                persisted_dirty_buckets: [0; 64],
                defer_seal: 0,
                format_commit_seq: None,
                pending_dirty_buckets: [0; 64],
                scrub_monitor: VilleWaldScrubMonitor::new(VilleWaldConfig::default())?,
                phase: FreshnessPhase::Clean,
            }),
            codec_budget,
            ownership,
        });
        self.dev = device.clone();
        self.native_repair_device = Some(device);
        Ok(report)
    }

    /// Admit sealed native ext4 protection, verify reads and fence source writes.
    pub fn activate_native_ext4_repair(
        &mut self,
        cx: &Cx,
        max_working_bytes: u64,
    ) -> Result<NativeRepairReport, FfsError> {
        if self.ext4_superblock().is_none() {
            return Err(freshness_error("native freshness requires ext4"));
        }
        self.activate_native_repair(cx, max_working_bytes)
    }

    /// Admit sealed native btrfs protection, verify reads and fence source writes.
    pub fn activate_native_btrfs_repair(
        &mut self,
        cx: &Cx,
        max_working_bytes: u64,
    ) -> Result<NativeRepairReport, FfsError> {
        if self.btrfs_superblock().is_none() {
            return Err(freshness_error("native freshness requires btrfs"));
        }
        self.activate_native_repair(cx, max_working_bytes)
    }

    /// Publish native parity from the existing sealed source baseline (ext4 or btrfs).
    pub fn initialize_native_repair(
        self,
        cx: &Cx,
        max_working_bytes: u64,
    ) -> Result<NativeRepairReport, FfsError> {
        self.require_write_authority()?;
        self.require_native_mode("initialize_native_repair")?;
        let (id, owned, _) = self.native_identity_storage_and_generation(cx)?;
        for tail in &owned.tails {
            native_codec_budget(&id, &owned, tail, max_working_bytes, false)?;
        }
        let baseline = read_native_baseline(&self, cx)?;
        self.check_native_validation(cx)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: id.block_size,
        };
        let mut admissions = Vec::with_capacity(baseline.storage.tails.len());
        for tail in &baseline.storage.tails {
            admissions.push(admit_native_group(
                cx,
                &dev,
                &id,
                &baseline,
                tail,
                max_working_bytes,
            )?);
        }
        for (tail, admission) in baseline.storage.tails.iter().zip(&admissions) {
            publish_native_group(cx, &dev, &id, &baseline, tail, admission)?;
        }
        ensure_native_baseline(&self, cx, &baseline)?;
        let report = self.check_native_repair(cx)?;
        dev.sync(cx)?;
        Ok(report)
    }

    /// Publish native parity from the existing sealed ext4 source baseline.
    pub fn initialize_native_ext4_repair(
        self,
        cx: &Cx,
        max_working_bytes: u64,
    ) -> Result<NativeRepairReport, FfsError> {
        if self.ext4_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires ext4".into(),
            ));
        }
        self.initialize_native_repair(cx, max_working_bytes)
    }

    /// Publish native parity from the existing sealed btrfs source baseline.
    pub fn initialize_native_btrfs_repair(
        self,
        cx: &Cx,
        max_working_bytes: u64,
    ) -> Result<NativeRepairReport, FfsError> {
        if self.btrfs_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires btrfs".into(),
            ));
        }
        self.initialize_native_repair(cx, max_working_bytes)
    }

    /// Read-only check of current sources and all committed native parity.
    pub fn check_native_repair(&self, cx: &Cx) -> Result<NativeRepairReport, FfsError> {
        self.require_native_mode("check_native_repair")?;
        if let Some(device) = &self.native_repair_device {
            return device.inspect_repair(cx);
        }
        let (id, _, _) = self.native_identity_storage_and_generation(cx)?;
        let baseline = read_native_baseline(self, cx)?;
        self.check_native_validation(cx)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: id.block_size,
        };
        let mut generations = Vec::with_capacity(baseline.storage.tails.len());
        for tail in &baseline.storage.tails {
            generations.push(native_sealed_generation(
                cx, &dev, &id, &baseline, tail, false,
            )?);
        }
        native_repair_report(&id, &baseline, generations)
    }

    /// Read-only check of current ext4 sources and all committed native parity.
    pub fn check_native_ext4_repair(&self, cx: &Cx) -> Result<NativeRepairReport, FfsError> {
        if self.ext4_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires ext4".into(),
            ));
        }
        self.check_native_repair(cx)
    }

    /// Read-only check of current btrfs sources and all committed native parity.
    pub fn check_native_btrfs_repair(&self, cx: &Cx) -> Result<NativeRepairReport, FfsError> {
        if self.btrfs_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires btrfs".into(),
            ));
        }
        self.check_native_repair(cx)
    }

    /// Reconstruct a changed source block from the immutable sealed baseline.
    pub fn reconstruct_native_block(
        &self,
        cx: &Cx,
        block: BlockNumber,
        max_working_bytes: u64,
    ) -> Result<NativeReconstruction, FfsError> {
        self.require_native_mode("reconstruct_native_block")?;
        if self.native_repair_device.is_some() {
            return Err(freshness_error(
                "offline reconstruction requires an inactive device",
            ));
        }
        let (id, owned, _) = self.native_identity_storage_and_generation(cx)?;
        let selected = native_target(&owned, block)?;
        native_codec_budget(&id, &owned, selected, max_working_bytes, true)?;
        let baseline = read_native_baseline(self, cx)?;
        let tail = native_target(&baseline.storage, block)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: id.block_size,
        };
        let admitted_intent = read_native_parity_intent(cx, &dev, &id, &baseline, tail)?;
        let generation = native_sealed_generation(cx, &dev, &id, &baseline, tail, true)?;
        let (root, table) = read_sealed_table(
            cx,
            &dev,
            &id,
            &baseline.storage,
            baseline.owner_generation,
            tail,
        )?;
        let corrupt = native_corrupt_indices(cx, &dev, &id, tail, &table)?;
        let requested =
            u32::try_from(block.0 - tail.group_start.0).expect("bounded native source index");
        if !corrupt.contains(&requested) {
            return Err(validation_error(
                tail,
                "requested source already matches sealed baseline",
            ));
        }
        let view = NativeDigestDevice {
            dev: &dev,
            tail,
            table: &table,
            corrupt: &corrupt,
        };
        let capture = NativeReconstructionCapture {
            blocks: OnceCell::new(),
        };
        let (layout, expected) = native_layout(&id, tail)?;
        let result = GroupRecoveryOrchestrator::new_with_writeback(
            &view,
            &capture,
            id.uuid,
            layout,
            tail.group_start,
            u32::from(expected.source_block_count),
        )?
        .with_decoded_block_validator(&view)
        .recover_from_indices(cx, &corrupt);
        if !result.is_success() || result.evidence.generation != generation {
            return Err(FfsError::RepairFailed(format!(
                "native baseline reconstruction failed: {:?}",
                result.evidence.reason
            )));
        }
        ensure_native_baseline(self, cx, &baseline)?;
        if root != baseline.roots[tail.group.0 as usize]
            || read_native_parity_intent(cx, &dev, &id, &baseline, tail)? != admitted_intent
            || native_sealed_generation(cx, &dev, &id, &baseline, tail, true)? != generation
        {
            return Err(validation_error(
                tail,
                "native recovery authority changed during decoding",
            ));
        }
        for index in 0..u32::from(expected.source_block_count) {
            view.read_block(cx, BlockNumber(tail.group_start.0 + u64::from(index)))?;
        }
        let captured = capture
            .blocks
            .into_inner()
            .ok_or_else(|| validation_error(tail, "native reconstruction produced no capture"))?;
        let data = captured
            .into_iter()
            .find_map(|recovered| (recovered.block == block).then_some(recovered.data))
            .ok_or_else(|| validation_error(tail, "requested block missing from reconstruction"))?;
        Ok(NativeReconstruction {
            block,
            generation,
            data,
        })
    }

    /// Reconstruct a changed ext4 source block from the immutable sealed baseline.
    pub fn reconstruct_native_ext4_block(
        &self,
        cx: &Cx,
        block: BlockNumber,
        max_working_bytes: u64,
    ) -> Result<NativeReconstruction, FfsError> {
        if self.ext4_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires ext4".into(),
            ));
        }
        self.reconstruct_native_block(cx, block, max_working_bytes)
    }

    /// Reconstruct a changed btrfs source block from the immutable sealed baseline.
    pub fn reconstruct_native_btrfs_block(
        &self,
        cx: &Cx,
        block: BlockNumber,
        max_working_bytes: u64,
    ) -> Result<NativeReconstruction, FfsError> {
        if self.btrfs_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires btrfs".into(),
            ));
        }
        self.reconstruct_native_block(cx, block, max_working_bytes)
    }

    /// Persist generation-one source digests in owned native storage (ext4 or btrfs).
    pub fn initialize_native_validation(self, cx: &Cx) -> Result<NativeValidationReport, FfsError> {
        self.require_write_authority()?;
        self.require_native_mode("initialize_native_validation")?;
        let (id, storage, generation) = self.native_identity_storage_and_generation(cx)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: id.block_size,
        };
        let mut admissions = Vec::with_capacity(storage.tails.len());
        for tail in &storage.tails {
            admissions.push(admit_validation_group(
                cx,
                &dev,
                &id,
                storage.owner_inode,
                generation,
                tail,
            )?);
        }
        let (plan, root) = admit_validation_plan(cx, &dev, &id, &storage, generation, &admissions)?;
        if plan == ValidationIntent::Prepared {
            publish_validation_plan(
                cx,
                &dev,
                &id,
                &storage,
                generation,
                admissions[0].epoch,
                ValidationIntent::Pending(root),
            )?;
        } else if matches!(plan, ValidationIntent::Pending(_)) {
            dev.sync(cx)?;
        }
        for (tail, admission) in storage.tails.iter().zip(&admissions) {
            if matches!(admission.intent, ValidationIntent::Sealed(_)) {
                continue;
            }
            publish_validation_group(cx, &dev, &id, &storage, generation, tail, admission)?;
        }
        if !matches!(plan, ValidationIntent::Sealed(_)) {
            publish_validation_plan(
                cx,
                &dev,
                &id,
                &storage,
                generation,
                admissions[0].epoch,
                ValidationIntent::Sealed(root),
            )?;
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        dev.sync(cx)?;
        native_validation_report(&id, &storage)
    }

    /// Persist generation-one source digests in owned native ext4 storage.
    pub fn initialize_native_ext4_validation(
        self,
        cx: &Cx,
    ) -> Result<NativeValidationReport, FfsError> {
        if self.ext4_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires ext4".into(),
            ));
        }
        self.initialize_native_validation(cx)
    }

    /// Persist generation-one source digests in owned native btrfs storage.
    pub fn initialize_native_btrfs_validation(
        self,
        cx: &Cx,
    ) -> Result<NativeValidationReport, FfsError> {
        if self.btrfs_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires btrfs".into(),
            ));
        }
        self.initialize_native_validation(cx)
    }

    /// Check persisted native source digests without writing the image.
    pub fn check_native_validation(&self, cx: &Cx) -> Result<NativeValidationReport, FfsError> {
        self.require_native_mode("check_native_validation")?;
        if let Some(device) = &self.native_repair_device {
            return device.inspect_validation(cx);
        }
        let (id, storage, generation) = self.native_identity_storage_and_generation(cx)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: id.block_size,
        };
        let first_owner = dev.read_block(cx, storage.tails[0].start)?;
        if NativeEpochToken::decode_optional(
            &first_owner.as_slice()[EPOCH_TOKEN_START..EPOCH_TOKEN_END],
            &id,
            storage.owner_inode,
            generation,
            &storage.tails[0],
        )?
        .is_some()
        {
            return Err(validation_error(
                &storage.tails[0],
                "sealed validation carries an unretired epoch token",
            ));
        }
        let plan = validation_plan_intent(
            &first_owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END],
            &id,
            &storage,
            generation,
        )?;
        let epoch =
            validation_plan_epoch(&first_owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END])?;
        let ValidationIntent::Sealed(plan_root) = plan else {
            return Err(validation_error(
                &storage.tails[0],
                "whole-plan validation is uninitialized or pending",
            ));
        };
        let mut admissions = Vec::with_capacity(storage.tails.len());
        for tail in &storage.tails {
            let owner = dev.read_block(cx, tail.start)?;
            let intent = validation_intent(
                &owner.as_slice()[OWNER_HEADER_BYTES..OWNER_HEADER_BYTES + VALIDATION_HEADER_BYTES],
                &id,
                storage.owner_inode,
                generation,
                tail,
            )?;
            let ValidationIntent::Sealed(root) = intent else {
                return Err(validation_error(
                    tail,
                    "validation is uninitialized or pending",
                ));
            };
            let table = read_validation_table(cx, &dev, &id, tail)?;
            let local_epoch = u32::from_le_bytes(table[68..72].try_into().expect("checked table"));
            if validation_intent(
                &table[..VALIDATION_HEADER_BYTES],
                &id,
                storage.owner_inode,
                generation,
                tail,
            )? != ValidationIntent::Sealed(root)
                || owner.as_slice()[OWNER_HEADER_BYTES..PLAN_HEADER_START]
                    != table[..VALIDATION_HEADER_BYTES]
                || local_epoch == 0
                || local_epoch > epoch
            {
                return Err(validation_error(tail, "sealed intent and table disagree"));
            }
            verify_validation_table(cx, &dev, &id, tail, &table, &root)?;
            admissions.push(ValidationAdmission {
                epoch: local_epoch,
                root,
                intent,
            });
        }
        if validation_plan_root(&id, &storage, generation, epoch, &admissions)? != plan_root {
            return Err(validation_error(
                &storage.tails[0],
                "sealed whole-plan root mismatch",
            ));
        }
        native_validation_report(&id, &storage)
    }

    /// Check persisted native ext4 source digests without writing the image.
    pub fn check_native_ext4_validation(
        &self,
        cx: &Cx,
    ) -> Result<NativeValidationReport, FfsError> {
        if self.ext4_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires ext4".into(),
            ));
        }
        self.check_native_validation(cx)
    }

    /// Check persisted native btrfs source digests without writing the image.
    pub fn check_native_btrfs_validation(
        &self,
        cx: &Cx,
    ) -> Result<NativeValidationReport, FfsError> {
        if self.btrfs_superblock().is_none() {
            return Err(FfsError::UnsupportedFeature(
                "native repair storage requires btrfs".into(),
            ));
        }
        self.check_native_validation(cx)
    }

    /// Reserve native repair storage in a clean, exclusively held ext4 or btrfs image.
    pub fn prepare_native_repair(
        self,
        cx: &Cx,
        basis_points: u32,
    ) -> Result<NativeRepairStorage, FfsError> {
        if self.ext4_superblock().is_some() {
            return self.prepare_native_ext4_repair(cx, basis_points);
        }
        if self.btrfs_superblock().is_some() {
            return self.prepare_native_btrfs_repair(cx, basis_points);
        }
        Err(FfsError::UnsupportedFeature(
            "native preparation requires ext4 or btrfs".into(),
        ))
    }

    /// Reserve native repair storage in a clean, exclusively held btrfs image.
    pub fn prepare_native_btrfs_repair(
        mut self,
        cx: &Cx,
        basis_points: u32,
    ) -> Result<NativeRepairStorage, FfsError> {
        self.require_write_authority()?;
        self.require_native_mode("prepare_native_repair_storage")?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if self.is_writable() || self.mvcc_version_count() != 0 {
            return Err(FfsError::Format(
                "native preparation requires a fresh offline view".into(),
            ));
        }
        let sb = self
            .btrfs_superblock()
            .ok_or_else(|| {
                FfsError::UnsupportedFeature("native btrfs preparation requires btrfs".into())
            })?
            .clone();
        if sb.num_devices != 1
            || self.btrfs_devices.is_some()
            || !self.btrfs_inventory_verified
            || sb.is_seeding()
        {
            return Err(FfsError::UnsupportedFeature(
                "native btrfs preparation requires a verified single-device non-seeding image"
                    .into(),
            ));
        }
        if sb.log_root != 0
            || self
                .btrfs_tree_log_overlay_active
                .load(std::sync::atomic::Ordering::Acquire)
            || *self.btrfs_semantic_view_stale.read()
        {
            return Err(FfsError::Format(
                "native btrfs preparation requires a clean image without an unretired tree log"
                    .into(),
            ));
        }
        let ctx = self
            .btrfs_context()
            .ok_or_else(|| FfsError::Format("missing btrfs context".into()))?;
        if ctx.subvol_objectid != BTRFS_FS_TREE_OBJECTID
            || ctx.subvol_root_dirid != BTRFS_FIRST_FREE_OBJECTID
        {
            return Err(FfsError::UnsupportedFeature(
                "native btrfs preparation requires mounting the default FS_TREE root".into(),
            ));
        }
        let image_len = self.dev.len_bytes();
        if !image_len.is_multiple_of(u64::from(sb.sectorsize)) {
            return Err(FfsError::InvalidGeometry(
                "btrfs image byte length is not a multiple of sectorsize".into(),
            ));
        }
        let total_blocks = image_len / u64::from(sb.sectorsize);
        let reserve_blocks =
            btrfs_reserve_blocks_estimate(sb.sectorsize, total_blocks, basis_points)?;
        match self.lookup(
            cx,
            InodeNumber(BTRFS_FIRST_FREE_OBJECTID),
            OsStr::new(OWNER_NAME),
        ) {
            Err(FfsError::NotFound(_)) => {}
            Ok(_) => return Err(FfsError::Exists),
            Err(err) => return Err(err),
        }

        self.enable_writes(cx)?;
        let created = self.btrfs_create(
            cx,
            InodeNumber(BTRFS_FIRST_FREE_OBJECTID),
            OWNER_NAME.as_bytes(),
            0o400,
            0,
            0,
        )?;
        let owner_oid = created.ino.0;
        let reserve_bytes = u64::from(reserve_blocks)
            .checked_mul(u64::from(sb.sectorsize))
            .ok_or_else(|| FfsError::InvalidGeometry("btrfs reserve byte overflow".into()))?;

        let (owner_generation, physical_extents) = {
            let alloc_mutex = self.require_btrfs_alloc_state()?;
            let mut alloc = alloc_mutex.write();
            let allocation = self.btrfs_alloc_data_with_growth(&mut alloc, reserve_bytes)?;
            let extent = BtrfsExtentData::Regular {
                generation: alloc.generation,
                ram_bytes: reserve_bytes,
                extent_type: BTRFS_FILE_EXTENT_PREALLOC,
                compression: 0,
                disk_bytenr: allocation.bytenr,
                disk_num_bytes: reserve_bytes,
                extent_offset: 0,
                num_bytes: reserve_bytes,
            };
            let extent_key = BtrfsKey {
                objectid: owner_oid,
                item_type: BTRFS_ITEM_EXTENT_DATA,
                offset: 0,
            };
            alloc
                .fs_tree
                .insert(extent_key, &extent.to_bytes())
                .map_err(|e| btrfs_mutation_to_ffs(&e))?;
            if let Err(err) = Self::btrfs_register_data_extent_backref(
                &mut alloc,
                allocation.bytenr,
                reserve_bytes,
                owner_oid,
                0,
            ) {
                let _ = alloc.fs_tree.delete(&extent_key);
                let _ = alloc
                    .extent_alloc
                    .free_extent(allocation.bytenr, reserve_bytes, false);
                return Err(err);
            }
            let mut inode = self.btrfs_read_inode_from_tree(&alloc, owner_oid)?;
            let generation = u32::try_from(inode.generation).map_err(|_| {
                FfsError::InvalidGeometry("btrfs native owner generation exceeds u32".into())
            })?;
            inode.mode = 0o100_400;
            inode.uid = 0;
            inode.gid = 0;
            inode.size = reserve_bytes;
            inode.nbytes = reserve_bytes;
            inode.flags = BTRFS_NATIVE_OWNER_FLAGS;
            let inode_key = BtrfsKey {
                objectid: owner_oid,
                item_type: BTRFS_ITEM_INODE_ITEM,
                offset: 0,
            };
            alloc
                .fs_tree
                .update(&inode_key, &inode.to_bytes())
                .map_err(|e| btrfs_mutation_to_ffs(&e))?;
            let chunks = ffs_btrfs::chunk_entries_from_chunk_tree(&alloc.chunk_tree)
                .map_err(|e| btrfs_mutation_to_ffs(&e))?;
            let phys = btrfs_resolve_single_data_extent(
                &chunks,
                self.btrfs_primary_devid(),
                sb.sectorsize,
                allocation.bytenr,
                reserve_bytes,
            )?;
            (generation, vec![phys])
        };

        let tails = btrfs_tail_plan_from_extents(
            sb.sectorsize,
            total_blocks,
            basis_points,
            &physical_extents,
        )?;
        let group_count = u32::try_from(tails.len())
            .map_err(|_| FfsError::InvalidGeometry("btrfs group count exceeds u32".into()))?;
        let id = NativeFsIdentity::from_btrfs(&sb, group_count);
        let storage = NativeRepairStorage {
            owner_inode: InodeNumber(owner_oid),
            repair_basis_points: basis_points,
            tails,
        };
        let direct = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.sectorsize,
        };
        let zero = vec![0_u8; sb.sectorsize as usize];
        for tail in &storage.tails {
            let mut header = owner_header(
                &id,
                storage.owner_inode,
                owner_generation,
                basis_points,
                tail,
            );
            if tail.group.0 == 0 {
                header[PLAN_HEADER_START..PLAN_HEADER_END].copy_from_slice(
                    &validation_plan_header(
                        &id,
                        &storage,
                        owner_generation,
                        1,
                        PLAN_PREPARED,
                        &[0; 32],
                    )?,
                );
            }
            header[PARITY_HEADER_START..PARITY_HEADER_END].copy_from_slice(&parity_header(
                &id,
                &storage,
                owner_generation,
                tail,
                ParityIntent::Prepared,
            ));
            direct.write_block(cx, tail.start, &header)?;
            let end = tail.start.0 + u64::from(tail.blocks());
            for block in [tail.start.0 + 1, end - 2, end - 1] {
                direct.write_block(cx, BlockNumber(block), &zero)?;
            }
        }
        self.btrfs_full_transaction_commit(cx, "prepare_native_btrfs_repair")?;
        debug!(
            owner = owner_oid,
            generation = owner_generation,
            groups = storage.tails.len(),
            "native_btrfs_repair_storage_prepared"
        );
        Ok(storage)
    }

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
        self.require_write_authority()?;
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
        let id = NativeFsIdentity::from_ext4(&sb);
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
        let (owner, inode, storage) = {
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
            let storage = NativeRepairStorage {
                owner_inode: owner,
                repair_basis_points: basis_points,
                tails,
            };
            for tail in &storage.tails {
                let mut header = owner_header(&id, owner, inode.generation, basis_points, tail);
                if tail.group.0 == 0 {
                    header[PLAN_HEADER_START..PLAN_HEADER_END].copy_from_slice(
                        &validation_plan_header(
                            &id,
                            &storage,
                            inode.generation,
                            1,
                            PLAN_PREPARED,
                            &[0; 32],
                        )?,
                    );
                }
                header[PARITY_HEADER_START..PARITY_HEADER_END].copy_from_slice(&parity_header(
                    &id,
                    &storage,
                    inode.generation,
                    tail,
                    ParityIntent::Prepared,
                ));
                dev.write_block(cx, tail.start, &header)?;
                let end = tail.start.0 + u64::from(tail.blocks());
                let zero = vec![0; sb.block_size as usize];
                // Unwritten extents may still contain arbitrary old physical
                // bytes. A prepared plan and empty local header grant first-init authority.
                for block in [tail.start.0 + 1, end - 2, end - 1] {
                    dev.write_block(cx, BlockNumber(block), &zero)?;
                }
            }
            (owner, inode, storage)
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
            groups = storage.tails.len(),
            "native_repair_storage_prepared"
        );
        Ok(storage)
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

    /// Validate persisted native storage ownership (ext4 or btrfs).
    pub fn native_repair_storage(&self, cx: &Cx) -> Result<NativeRepairStorage, FfsError> {
        if self.ext4_superblock().is_some() {
            return self.native_ext4_repair_storage(cx);
        }
        if self.btrfs_superblock().is_some() {
            return self.native_btrfs_repair_storage(cx);
        }
        Err(FfsError::UnsupportedFeature(
            "native repair storage requires ext4 or btrfs".into(),
        ))
    }

    /// Validate persisted btrfs native repair ownership after reopening the image.
    pub fn native_btrfs_repair_storage(&self, cx: &Cx) -> Result<NativeRepairStorage, FfsError> {
        self.native_btrfs_repair_storage_with_generation(cx)
            .map(|(storage, _)| storage)
    }

    fn native_btrfs_repair_storage_with_generation(
        &self,
        cx: &Cx,
    ) -> Result<(NativeRepairStorage, u32), FfsError> {
        let sb = self.btrfs_superblock().ok_or_else(|| {
            FfsError::UnsupportedFeature("native repair storage requires btrfs".into())
        })?;
        if sb.num_devices != 1
            || self.btrfs_devices.is_some()
            || !self.btrfs_inventory_verified
            || sb.is_seeding()
        {
            return Err(FfsError::UnsupportedFeature(
                "native btrfs ownership discovery requires a verified single-device image".into(),
            ));
        }
        if self.is_writable() || self.mvcc_version_count() != 0 {
            return Err(FfsError::Format(
                "native ownership discovery requires a fresh offline view".into(),
            ));
        }
        let ctx = self
            .btrfs_context()
            .ok_or_else(|| FfsError::Format("missing btrfs context".into()))?;
        if ctx.subvol_objectid != BTRFS_FS_TREE_OBJECTID
            || ctx.subvol_root_dirid != BTRFS_FIRST_FREE_OBJECTID
        {
            return Err(FfsError::UnsupportedFeature(
                "native btrfs ownership requires the default FS_TREE root".into(),
            ));
        }
        let image_len = self.dev.len_bytes();
        if !image_len.is_multiple_of(u64::from(sb.sectorsize)) {
            return Err(FfsError::InvalidGeometry(
                "btrfs image byte length is not a multiple of sectorsize".into(),
            ));
        }
        let total_blocks = image_len / u64::from(sb.sectorsize);
        let attr = self.lookup(
            cx,
            InodeNumber(BTRFS_FIRST_FREE_OBJECTID),
            OsStr::new(OWNER_NAME),
        )?;
        let owner_oid = attr.ino.0;
        let items = self.walk_btrfs_fs_tree_object(cx, owner_oid)?;
        let inode_entry = Self::btrfs_find_inode_item(&items, owner_oid)?;
        let inode =
            super::parse_inode_item(&inode_entry.data).map_err(|e| parse_to_ffs_error(&e))?;
        let generation = u32::try_from(inode.generation).map_err(|_| {
            FfsError::InvalidGeometry("btrfs native owner generation exceeds u32".into())
        })?;
        if inode.mode != 0o100_400
            || inode.flags != BTRFS_NATIVE_OWNER_FLAGS
            || inode.nlink != 1
            || inode.uid != 0
            || inode.gid != 0
            || inode.size == 0
            || inode.size != inode.nbytes
            || inode.size % u64::from(sb.sectorsize) != 0
        {
            return Err(FfsError::Format(
                "invalid native btrfs repair owner inode".into(),
            ));
        }
        let mut expected_logical_offset = 0_u64;
        let mut physical_extents = Vec::new();
        for item in &items {
            if item.key.objectid != owner_oid || item.key.item_type != BTRFS_ITEM_EXTENT_DATA {
                continue;
            }
            if item.key.offset != expected_logical_offset {
                return Err(FfsError::Format(
                    "native btrfs repair owner extents are non-contiguous".into(),
                ));
            }
            let parsed = parse_extent_data(&item.data).map_err(|e| parse_to_ffs_error(&e))?;
            let BtrfsExtentData::Regular {
                extent_type,
                compression,
                disk_bytenr,
                disk_num_bytes,
                extent_offset,
                num_bytes,
                ram_bytes,
                ..
            } = parsed
            else {
                return Err(FfsError::Format(
                    "native btrfs repair owner cannot use inline extents".into(),
                ));
            };
            if extent_type != BTRFS_FILE_EXTENT_PREALLOC
                || compression != 0
                || extent_offset != 0
                || num_bytes != disk_num_bytes
                || ram_bytes != disk_num_bytes
            {
                return Err(FfsError::Format(
                    "native btrfs repair owner extent must be uncompressed PREALLOC".into(),
                ));
            }
            let phys = btrfs_resolve_single_data_extent(
                &ctx.chunks,
                self.btrfs_primary_devid(),
                sb.sectorsize,
                disk_bytenr,
                disk_num_bytes,
            )?;
            physical_extents.push(phys);
            expected_logical_offset =
                expected_logical_offset
                    .checked_add(num_bytes)
                    .ok_or_else(|| {
                        FfsError::InvalidGeometry("btrfs owner logical offset overflow".into())
                    })?;
        }
        if expected_logical_offset != inode.size || physical_extents.is_empty() {
            return Err(FfsError::Format(
                "native btrfs repair owner extents disagree with inode size".into(),
            ));
        }
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.sectorsize,
        };
        let mut sorted_phys = physical_extents;
        sorted_phys.sort_by_key(|&(start, _)| start);
        let header = dev
            .read_block(cx, BlockNumber(sorted_phys[0].0))?
            .into_inner();
        if header.len() < OWNER_HEADER_BYTES || &header[..8] != OWNER_MAGIC {
            return Err(FfsError::Format(
                "native btrfs repair ownership header missing".into(),
            ));
        }
        let basis_points =
            u32::from_le_bytes(header[44..48].try_into().expect("checked header length"));
        let tails =
            btrfs_tail_plan_from_extents(sb.sectorsize, total_blocks, basis_points, &sorted_phys)?;
        let group_count = u32::try_from(tails.len())
            .map_err(|_| FfsError::InvalidGeometry("btrfs group count exceeds u32".into()))?;
        let id = NativeFsIdentity::from_btrfs(sb, group_count);
        let storage = NativeRepairStorage {
            owner_inode: attr.ino,
            repair_basis_points: basis_points,
            tails,
        };
        for tail in &storage.tails {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            let stored = dev.read_block(cx, tail.start)?.into_inner();
            let expected = owner_header(&id, attr.ino, generation, basis_points, tail);
            let zero_tail_start = if tail.group.0 == 0 {
                EPOCH_TOKEN_END
            } else {
                PARITY_HEADER_END
            };
            if stored[..OWNER_HEADER_BYTES] != expected[..OWNER_HEADER_BYTES]
                || stored[zero_tail_start..].iter().any(|byte| *byte != 0)
                || (tail.group.0 != 0
                    && stored[PLAN_HEADER_START..PLAN_HEADER_END]
                        .iter()
                        .any(|byte| *byte != 0))
            {
                return Err(FfsError::Corruption {
                    block: tail.start.0,
                    detail: "native btrfs repair ownership header mismatch".into(),
                });
            }
            let validation = validation_intent(
                &stored[OWNER_HEADER_BYTES..OWNER_HEADER_BYTES + VALIDATION_HEADER_BYTES],
                &id,
                attr.ino,
                generation,
                tail,
            )?;
            let parity = parity_intent(
                &stored[PARITY_HEADER_START..PARITY_HEADER_END],
                &id,
                &storage,
                generation,
                tail,
            )?;
            if parity != ParityIntent::Prepared
                && validation != ValidationIntent::Sealed(parity.source_root())
            {
                return Err(validation_error(
                    tail,
                    "parity and validation ownership disagree",
                ));
            }
            if tail.group.0 == 0 {
                validation_plan_intent(
                    &stored[PLAN_HEADER_START..PLAN_HEADER_END],
                    &id,
                    &storage,
                    generation,
                )?;
                NativeEpochToken::decode_optional(
                    &stored[EPOCH_TOKEN_START..EPOCH_TOKEN_END],
                    &id,
                    attr.ino,
                    generation,
                    tail,
                )?;
            }
        }
        Ok((storage, generation))
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
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.block_size,
        };
        let header = dev
            .read_block(cx, BlockNumber(first.physical_start))?
            .into_inner();
        if header.len() < OWNER_HEADER_BYTES || &header[..8] != OWNER_MAGIC {
            return Err(FfsError::Format(
                "native repair ownership header missing".into(),
            ));
        }
        let basis_points =
            u32::from_le_bytes(header[44..48].try_into().expect("checked header length"));
        let tails = tail_plan(sb, basis_points)?;
        let id = NativeFsIdentity::from_ext4(sb);
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
        let storage = NativeRepairStorage {
            owner_inode: attr.ino,
            repair_basis_points: basis_points,
            tails,
        };
        for tail in &storage.tails {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            let stored = dev.read_block(cx, tail.start)?.into_inner();
            let expected = owner_header(&id, attr.ino, inode.generation, basis_points, tail);
            let zero_tail_start = if tail.group.0 == 0 {
                EPOCH_TOKEN_END
            } else {
                PARITY_HEADER_END
            };
            if stored[..OWNER_HEADER_BYTES] != expected[..OWNER_HEADER_BYTES]
                || stored[zero_tail_start..].iter().any(|byte| *byte != 0)
                || (tail.group.0 != 0
                    && stored[PLAN_HEADER_START..PLAN_HEADER_END]
                        .iter()
                        .any(|byte| *byte != 0))
            {
                return Err(FfsError::Corruption {
                    block: tail.start.0,
                    detail: "native repair ownership header mismatch".into(),
                });
            }
            let validation = validation_intent(
                &stored[OWNER_HEADER_BYTES..OWNER_HEADER_BYTES + VALIDATION_HEADER_BYTES],
                &id,
                attr.ino,
                inode.generation,
                tail,
            )?;
            let parity = parity_intent(
                &stored[PARITY_HEADER_START..PARITY_HEADER_END],
                &id,
                &storage,
                inode.generation,
                tail,
            )?;
            if parity != ParityIntent::Prepared
                && validation != ValidationIntent::Sealed(parity.source_root())
            {
                return Err(validation_error(
                    tail,
                    "parity and validation ownership disagree",
                ));
            }
            if tail.group.0 == 0 {
                validation_plan_intent(
                    &stored[PLAN_HEADER_START..PLAN_HEADER_END],
                    &id,
                    &storage,
                    inode.generation,
                )?;
                NativeEpochToken::decode_optional(
                    &stored[EPOCH_TOKEN_START..EPOCH_TOKEN_END],
                    &id,
                    attr.ino,
                    inode.generation,
                    tail,
                )?;
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
        Ok(storage)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NativeReadCountDevice {
        reads: Arc<AtomicUsize>,
    }

    impl ByteDevice for NativeReadCountDevice {
        fn len_bytes(&self) -> u64 {
            1024
        }

        fn read_exact_at(
            &self,
            _cx: &Cx,
            offset: ByteOffset,
            bytes: &mut [u8],
        ) -> Result<(), FfsError> {
            if offset
                .0
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > 1024)
            {
                return Err(FfsError::Format("test read is out of bounds".into()));
            }
            self.reads.fetch_add(1, Ordering::SeqCst);
            bytes.fill(0xA7);
            Ok(())
        }

        fn write_all_at(
            &self,
            _cx: &Cx,
            _offset: ByteOffset,
            _bytes: &[u8],
        ) -> Result<(), FfsError> {
            Err(FfsError::ReadOnly)
        }

        fn sync(&self, _cx: &Cx) -> Result<(), FfsError> {
            Err(FfsError::ReadOnly)
        }
    }

    fn native_read_lock_fixture() -> (NativeFreshnessDevice, Arc<AtomicUsize>) {
        // Only the physical intact-read/locking path is under test here. Real
        // native fixtures in lib.rs separately admit ownership and parity.
        let mut region = [0; 1024];
        region[0x38..0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
        let sb = Ext4Superblock::parse_superblock_region(&region).unwrap();
        let id = NativeFsIdentity::from_ext4(&sb);
        let reads = Arc::new(AtomicUsize::new(0));
        let mut table = vec![0; 1024];
        table[VALIDATION_HEADER_BYTES..VALIDATION_HEADER_BYTES + 32]
            .copy_from_slice(blake3::hash(&[0xA7; 1024]).as_bytes());
        let device = NativeFreshnessDevice {
            inner: Arc::new(NativeReadCountDevice {
                reads: Arc::clone(&reads),
            }),
            id,
            state: NativeMutex::new(NativeFreshnessState {
                baseline: NativeBaseline {
                    storage: NativeRepairStorage {
                        owner_inode: InodeNumber(12),
                        repair_basis_points: 500,
                        tails: vec![NativeRepairTail {
                            group: GroupNumber(0),
                            group_start: BlockNumber(0),
                            blocks_per_group: 6,
                            start: BlockNumber(1),
                            validation_blocks: 1,
                            repair_blocks: 1,
                        }],
                    },
                    owner_generation: 1,
                    epoch: 1,
                    plan_root: [0; 32],
                    roots: vec![[0; 32]],
                    group_epochs: vec![1],
                },
                tables: vec![table],
                parity: vec![ParityIntent::Sealed {
                    generation: 1,
                    source_root: [0; 32],
                    manifest: [0; 32],
                }],
                intended: BTreeMap::new(),
                beforeimages: BTreeMap::new(),
                dirty_groups: vec![false],
                persisted_dirty_buckets: [0; 64],
                defer_seal: 0,
                format_commit_seq: None,
                pending_dirty_buckets: [0; 64],
                scrub_monitor: VilleWaldScrubMonitor::new(VilleWaldConfig::default()).unwrap(),
                phase: FreshnessPhase::Clean,
            }),
            codec_budget: 0,
            ownership: NativeOwnershipConstraints {
                blocks: BTreeMap::new(),
                remaining_budget: 0,
            },
        };
        (device, reads)
    }

    fn wait_for_native_readers(device: &NativeFreshnessDevice, count: usize) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while device.state.waiters() != count {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::park_timeout(Duration::from_millis(1));
        }
        true
    }

    #[test]
    fn native_freshness_concurrent_reads_wait_for_shared_authority() {
        let (device, reads) = native_read_lock_fixture();
        let held = device.state.try_lock().unwrap();
        std::thread::scope(|scope| {
            let read = || {
                let cx = Cx::for_testing();
                let mut bytes = [0; 31];
                device
                    .read_exact_at(&cx, ByteOffset(17), &mut bytes)
                    .map(|()| bytes)
            };
            let first = scope.spawn(read);
            let second = scope.spawn(read);
            let queued = wait_for_native_readers(&device, 2);
            let before = reads.load(Ordering::SeqCst);
            // Release before assertions, including failure paths, so scoped
            // threads cannot remain blocked while unwinding a failed test.
            drop(held);
            let first = first.join().unwrap();
            let second = second.join().unwrap();
            assert!(
                queued,
                "physical readers returned early instead of joining the mutex queue"
            );
            assert_eq!(before, 0, "queued read bypassed the held source authority");
            assert_eq!(first.unwrap(), [0xA7; 31]);
            assert_eq!(second.unwrap(), [0xA7; 31]);
        });
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(device.state.waiters(), 0);
    }

    #[test]
    fn native_freshness_waiting_read_cancellation_removes_mutex_waiter() {
        let (device, reads) = native_read_lock_fixture();
        let held = device.state.try_lock().unwrap();
        let waiting_cx = Cx::for_testing();
        std::thread::scope(|scope| {
            let (sender, receiver) = std::sync::mpsc::channel();
            let reader = &device;
            let request = &waiting_cx;
            let worker = scope.spawn(move || {
                let result = reader.read_exact_at(request, ByteOffset(17), &mut [0; 31]);
                sender.send(result).unwrap();
            });
            let queued = wait_for_native_readers(&device, 1);
            waiting_cx.set_cancel_requested(true);
            let cancelled_while_held = receiver.recv_timeout(Duration::from_secs(1));
            let remaining = device.state.waiters();
            let before = reads.load(Ordering::SeqCst);
            drop(held);
            worker.join().unwrap();
            assert!(queued, "request did not join the mutex queue");
            assert!(matches!(cancelled_while_held, Ok(Err(FfsError::Cancelled))));
            assert_eq!(
                remaining, 0,
                "cancelled request left a queued or granted waiter"
            );
            assert_eq!(before, 0, "cancelled waiter performed physical I/O");
        });
        let mut bytes = [0; 31];
        device
            .read_exact_at(&Cx::for_testing(), ByteOffset(17), &mut bytes)
            .unwrap();
        assert_eq!(bytes, [0xA7; 31]);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_freshness_decode_budget_includes_recovery_captures() {
        let mut region = [0; 1024];
        region[0x38..0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
        let sb = Ext4Superblock::parse_superblock_region(&region).unwrap();
        let id = NativeFsIdentity::from_ext4(&sb);
        let storage = NativeRepairStorage {
            owner_inode: InodeNumber(12),
            repair_basis_points: 500,
            tails: vec![NativeRepairTail {
                group: GroupNumber(0),
                group_start: BlockNumber(1),
                blocks_per_group: 1124,
                start: BlockNumber(1025),
                validation_blocks: 33,
                repair_blocks: 64,
            }],
        };
        let tail = &storage.tails[0];
        let encoder = direct_encode_workspace_bytes(1024, 1024, 64).unwrap();
        let decoder = encoder * 8;
        // 33 KiB validation capacity, one group and 16 temporary blocks.
        let metadata = 155_648;
        // Four 1 KiB copies and 256 bytes of bookkeeping for all 1024 sources.
        let capture = 4_456_448;
        assert_eq!(
            native_codec_budget(&id, &storage, tail, metadata + encoder, false).unwrap(),
            encoder,
            "encoding must not be charged for recovery captures"
        );
        assert!(native_codec_budget(&id, &storage, tail, metadata + decoder, true).is_err());
        assert!(
            native_codec_budget(&id, &storage, tail, metadata + capture + decoder - 1, true)
                .is_err()
        );
        assert_eq!(
            native_codec_budget(&id, &storage, tail, metadata + capture + decoder, true).unwrap(),
            decoder,
            "exact capture-inclusive admission boundary must remain usable"
        );
    }

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

    #[test]
    fn epoch_token_roundtrip_and_tamper_rejection() {
        let id = NativeFsIdentity {
            uuid: [0x42; 16],
            block_size: 4096,
            group_count: 4,
        };
        let tail0 = NativeRepairTail {
            group: GroupNumber(0),
            group_start: BlockNumber(16),
            blocks_per_group: 1000,
            start: BlockNumber(4000),
            validation_blocks: 9,
            repair_blocks: 50,
        };
        assert!(tail0.is_detached());
        assert_eq!(tail0.source_blocks().unwrap(), 1000);
        let mut buckets = [0_u8; 64];
        NativeEpochToken::mark_bucket(&mut buckets, GroupNumber(0));
        NativeEpochToken::mark_bucket(&mut buckets, GroupNumber(3));
        let token = NativeEpochToken {
            owner_inode: InodeNumber(257),
            owner_generation: 7,
            target_epoch: 5,
            prev_sealed_epoch: 4,
            flags: EPOCH_TOKEN_FLAG_FORMAT_COMMIT,
            pre_epoch_commit_seq: 99,
            prev_sealed_plan_root: [0xAB; 32],
            dirty_group_buckets: buckets,
        };
        let encoded = token.encode(&id);
        let decoded = NativeEpochToken::decode_optional(&encoded, &id, InodeNumber(257), 7, &tail0)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, token);
        assert!(decoded.is_group_dirty(GroupNumber(0)));
        assert!(!decoded.is_group_dirty(GroupNumber(1)));
        assert!(decoded.is_group_dirty(GroupNumber(3)));

        let mut tampered = encoded;
        tampered[48] ^= 1;
        assert!(
            NativeEpochToken::decode_optional(&tampered, &id, InodeNumber(257), 7, &tail0).is_err()
        );
        assert!(
            NativeEpochToken::decode_optional(
                &[0; EPOCH_TOKEN_BYTES],
                &id,
                InodeNumber(257),
                7,
                &tail0
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn btrfs_tail_plan_conserves_source_and_owned_blocks() {
        let total_blocks = 16_384_u64;
        let reserve = btrfs_reserve_blocks_estimate(4096, total_blocks, 500).unwrap();
        let phys_start = 5_120_u64;
        let tails = btrfs_tail_plan_from_extents(4096, total_blocks, 500, &[(phys_start, reserve)])
            .unwrap();
        assert!(tails.len() >= 2);
        let total_tail_blocks: u32 = tails.iter().map(NativeRepairTail::blocks).sum();
        assert_eq!(total_tail_blocks, reserve);
        let total_sources: u64 = tails.iter().map(|t| u64::from(t.blocks_per_group)).sum();
        assert_eq!(total_sources + u64::from(reserve), total_blocks - 16);
        let id = NativeFsIdentity {
            uuid: [0x11; 16],
            block_size: 4096,
            group_count: u32::try_from(tails.len()).unwrap(),
        };
        for tail in &tails {
            assert!(tail.is_detached());
            let (layout, desc) = native_layout(&id, tail).unwrap();
            assert_eq!(layout.validation_start_block(), tail.start);
            assert_eq!(u32::from(desc.source_block_count), tail.blocks_per_group);
        }
    }
}
