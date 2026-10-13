//! Offline preparation of allocator-owned ext4 repair tails.
//!
//! Preparation creates ownership, not usable parity. The immutable owner's
//! unwritten extents reserve physical space without exposing previous contents
//! through normal file reads. Headers are read through physical block mappings.

use super::{
    AllocHint, BTreeSet, BlockDevice, BlockNumber, ByteDeviceBlockAdapter, Cx, EXT4_SECTOR_SIZE,
    EXT4_VALID_FS, Ext4AllocState, Ext4Extent, Ext4FileType, Ext4Inode, Ext4Superblock, ExtentTree,
    FfsError, FsGeometry, GroupNumber, InodeNumber, Jbd2Superblock, Mutex, OpenFs, OsStr,
    Serialize, SingleLockDirAlloc, TransactionBlockAdapter, debug,
    ext4_superblock_requires_journal_recovery, parse_extent_tree, parse_to_ffs_error,
};
use asupersync::sync::{
    Mutex as NativeMutex, MutexGuard as NativeMutexGuard, OnceCell, TryLockError,
};
use ffs_block::{BlockBuf, ByteDevice};
use ffs_repair::codec::{DirectEncodeRequest, direct_encode_workspace_bytes, encode_group_direct};
use ffs_repair::recovery::{GroupRecoveryOrchestrator, RecoveryWriteback, RecoveryWritebackBlock};
use ffs_repair::scrub::{BlockValidator, BlockVerdict, CorruptionKind, Severity};
use ffs_repair::storage::{RawRefreshAdmission, RepairGroupLayout, RepairGroupStorage};
use ffs_repair::symbol::RepairGroupDescExt;
use ffs_types::ByteOffset;
use std::collections::BTreeMap;
use std::sync::Arc;

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
    phase: FreshnessPhase,
}

/// The only writable handle published after native freshness admission.
/// Internal ownership publication uses `inner` under the same state lock.
struct NativeFreshnessDevice {
    inner: Arc<dyn ByteDevice>,
    sb: Ext4Superblock,
    state: NativeMutex<NativeFreshnessState>,
    codec_budget: u64,
    ownership: NativeOwnershipConstraints,
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
        // counts, timestamps, mount state and checksum remain writable.
        for (start, end) in [
            (0x00, 0x0C),
            (0x14, 0x2C),
            (0x38, 0x3A),
            (0x48, 0x60),
            (0x61, 0x78),
            (0xCE, 0xFC),
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
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    allowed: u64,
) -> Result<u64, FfsError> {
    let mut retained = 0_u64;
    for tail in &storage.tails {
        let (sources, capacity, _) = validation_sizes(sb, tail)?;
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
        let state = self.state.try_lock().map_err(|error| match error {
            TryLockError::Locked => {
                FfsError::Io(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
            TryLockError::Poisoned => freshness_error("state mutex is poisoned"),
        })?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if state.phase == FreshnessPhase::Poisoned {
            return Err(freshness_error(
                "device is poisoned after an incomplete operation",
            ));
        }
        Ok(state)
    }

    fn device(&self) -> ByteDeviceBlockAdapter<'_> {
        ByteDeviceBlockAdapter {
            dev: self.inner.as_ref(),
            block_size: self.sb.block_size,
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
            &self.sb,
            &baseline.storage,
            baseline.owner_generation,
        )? != intent
            || validation_plan_epoch(bytes)? != baseline.epoch
        {
            return Err(freshness_error("whole-plan authority changed"));
        }
        Ok(())
    }

    fn check_group_authority(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
        index: usize,
    ) -> Result<(), FfsError> {
        let baseline = &state.baseline;
        let tail = &baseline.storage.tails[index];
        let dev = self.device();
        let owner = check_native_owner_prefix(
            cx,
            &dev,
            &self.sb,
            &baseline.storage,
            baseline.owner_generation,
            tail,
        )?;
        if owner[OWNER_HEADER_BYTES..PLAN_HEADER_START]
            != state.tables[index][..VALIDATION_HEADER_BYTES]
            || read_native_parity_intent(cx, &dev, &self.sb, baseline, tail)? != state.parity[index]
        {
            return Err(validation_error(
                tail,
                "native ownership changed during active epoch",
            ));
        }
        let (root, table) = read_sealed_table(
            cx,
            &dev,
            &self.sb,
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
        native_sealed_generation(cx, &dev, &self.sb, baseline, tail, false)?;
        Ok(())
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
            self.check_group_authority(cx, state, index)?;
        }
        Ok(())
    }

    fn stage_intended(
        &self,
        cx: &Cx,
        state: &NativeFreshnessState,
        offset: u64,
        end: u64,
        buffers: &[&[u8]],
    ) -> Result<Vec<(BlockNumber, [u8; 32])>, FfsError> {
        let size = u64::from(self.sb.block_size);
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
            staged.push((block, *blake3::hash(&bytes).as_bytes()));
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
        let size = u64::from(self.sb.block_size);
        for number in offset.0 / size..=(end - 1) / size {
            native_target(&state.baseline.storage, BlockNumber(number))?;
        }
        state
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
            if state.phase == FreshnessPhase::Clean {
                self.check_authority(cx, &state)?;
                state.phase = FreshnessPhase::Poisoned;
                publish_validation_plan(
                    cx,
                    &self.device(),
                    &self.sb,
                    &state.baseline.storage,
                    state.baseline.owner_generation,
                    state.baseline.epoch,
                    ValidationIntent::Dirty(state.baseline.plan_root),
                )?;
                state.phase = FreshnessPhase::Dirty;
            }
            self.inner.write_vectored_all_at(cx, offset, buffers)?;
            state.intended.extend(staged);
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
            let mut table = state.tables[index].clone();
            table[..VALIDATION_HEADER_BYTES].copy_from_slice(&validation_header(
                &self.sb,
                state.baseline.storage.owner_inode,
                state.baseline.owner_generation,
                tail,
                epoch,
                VALIDATION_PENDING,
                &[0; 32],
            )?);
            for (block, digest) in state.intended.range(tail.group_start..tail.start) {
                let offset = VALIDATION_HEADER_BYTES + (block.0 - tail.group_start.0) as usize * 32;
                table[offset..offset + 32].copy_from_slice(digest);
            }
            let (_, _, used) = validation_sizes(&self.sb, tail)?;
            let root = validation_root(&table, used);
            table[..VALIDATION_HEADER_BYTES].copy_from_slice(&validation_header(
                &self.sb,
                state.baseline.storage.owner_inode,
                state.baseline.owner_generation,
                tail,
                epoch,
                VALIDATION_PENDING,
                &root,
            )?);
            // The expected hashes came only from admitted tables or verified
            // caller writes. Reading current bytes cannot redefine them.
            verify_validation_table(cx, &self.device(), &self.sb, tail, &table, &root)?;
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
            self.check_group_authority(cx, state, index)?;
            let validation = ValidationAdmission {
                epoch: next.epoch,
                root: next.roots[index],
                intent: ValidationIntent::Pending(next.roots[index]),
            };
            publish_validation_group(
                cx,
                &dev,
                &self.sb,
                &next.storage,
                next.owner_generation,
                tail,
                &validation,
            )?;
            let (root, table) = read_sealed_table(
                cx,
                &dev,
                &self.sb,
                &next.storage,
                next.owner_generation,
                tail,
            )?;
            tables[index][..VALIDATION_HEADER_BYTES].copy_from_slice(&validation_header(
                &self.sb,
                next.storage.owner_inode,
                next.owner_generation,
                tail,
                next.epoch,
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
                &self.sb,
                next,
                tail,
                &admissions[index],
                &table,
            )?;
        }
        Ok(())
    }

    fn verified_parity(
        &self,
        cx: &Cx,
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
                &self.sb,
                &next.storage,
                next.owner_generation,
                tail,
            )?;
            let (root, table) = read_sealed_table(
                cx,
                &dev,
                &self.sb,
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
            verify_validation_table(cx, &dev, &self.sb, tail, &table, &root)?;
            let generation = native_sealed_generation(cx, &dev, &self.sb, next, tail, false)?;
            if generation != admissions[index].next_generation {
                return Err(validation_error(
                    tail,
                    "freshness parity generation changed before final seal",
                ));
            }
            parity.push(read_native_parity_intent(cx, &dev, &self.sb, next, tail)?);
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
            &self.sb,
            &state.baseline.storage,
            state.baseline.owner_generation,
            &validations,
        )?;
        let next = NativeBaseline {
            storage: state.baseline.storage.clone(),
            owner_generation: state.baseline.owner_generation,
            epoch,
            plan_root,
            roots: validations.iter().map(|admission| admission.root).collect(),
        };
        let dev = self.device();
        let mut admissions = Vec::with_capacity(next.storage.tails.len());
        for tail in &next.storage.tails {
            let mut admission =
                admit_native_group(cx, &dev, &self.sb, &state.baseline, tail, self.codec_budget)?;
            // Source-root changes require a new parity generation even when
            // current raw parity is intact. Retain its exact high-water and seal.
            admission.retained = false;
            admissions.push(admission);
        }
        publish_validation_plan(
            cx,
            &dev,
            &self.sb,
            &next.storage,
            next.owner_generation,
            epoch,
            ValidationIntent::Pending(plan_root),
        )?;
        self.publish_groups(cx, state, &next, &mut tables, &admissions)?;
        let parity = self.verified_parity(cx, &next, &tables, &admissions)?;
        publish_validation_plan(
            cx,
            &dev,
            &self.sb,
            &next.storage,
            next.owner_generation,
            epoch,
            ValidationIntent::Sealed(plan_root),
        )?;
        self.check_plan(cx, &next, ValidationIntent::Sealed(plan_root))?;
        self.inner.sync(cx)?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        state.baseline = next;
        state.tables = tables;
        state.parity = parity;
        state.intended.clear();
        state.phase = FreshnessPhase::Clean;
        Ok(())
    }

    fn sync_clean(&self, cx: &Cx, state: &NativeFreshnessState) -> Result<(), FfsError> {
        self.check_authority(cx, state)?;
        for (index, tail) in state.baseline.storage.tails.iter().enumerate() {
            verify_validation_table(
                cx,
                &self.device(),
                &self.sb,
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
        self.inner.read_exact_at(cx, offset, bytes)
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
        let result = if state.phase == FreshnessPhase::Clean {
            self.sync_clean(cx, &state)
        } else {
            self.refresh(cx, &mut state)
        };
        if result.is_err() {
            state.phase = FreshnessPhase::Poisoned;
        }
        result
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

fn check_native_owner_prefix(
    cx: &Cx,
    dev: &dyn BlockDevice,
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    generation: u32,
    tail: &NativeRepairTail,
) -> Result<Vec<u8>, FfsError> {
    let bytes = dev.read_block(cx, tail.start)?.into_inner();
    let expected = owner_header(
        sb,
        storage.owner_inode,
        generation,
        storage.repair_basis_points,
        tail,
    );
    if bytes.len() != sb.block_size as usize
        || bytes[..OWNER_HEADER_BYTES] != expected[..OWNER_HEADER_BYTES]
        || bytes[PARITY_HEADER_END..].iter().any(|byte| *byte != 0)
        || (tail.group.0 != 0
            && bytes[PLAN_HEADER_START..PLAN_HEADER_END]
                .iter()
                .any(|byte| *byte != 0))
    {
        return Err(validation_error(tail, "native ownership prefix changed"));
    }
    validation_intent(
        &bytes[OWNER_HEADER_BYTES..PLAN_HEADER_START],
        sb,
        storage.owner_inode,
        generation,
        tail,
    )?;
    parity_intent(
        &bytes[PARITY_HEADER_START..PARITY_HEADER_END],
        sb,
        storage,
        generation,
        tail,
    )?;
    if tail.group.0 == 0 {
        validation_plan_intent(
            &bytes[PLAN_HEADER_START..PLAN_HEADER_END],
            sb,
            storage,
            generation,
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
    sb: &Ext4Superblock,
    tail: &NativeRepairTail,
) -> Result<(u32, usize, usize), FfsError> {
    let sources = tail
        .start
        .0
        .checked_sub(tail.group_start.0)
        .ok_or_else(|| validation_error(tail, "source range underflows"))?;
    let sources =
        u32::try_from(sources).map_err(|_| validation_error(tail, "source count exceeds u32"))?;
    let capacity = usize::try_from(u64::from(tail.validation_blocks) * u64::from(sb.block_size))
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
    sb: &Ext4Superblock,
    owner: InodeNumber,
    owner_generation: u32,
    tail: &NativeRepairTail,
    epoch: u32,
    state: u32,
    root: &[u8; 32],
) -> Result<[u8; VALIDATION_HEADER_BYTES], FfsError> {
    let (sources, _, _) = validation_sizes(sb, tail)?;
    if epoch == 0 {
        return Err(validation_error(tail, "zero validation epoch"));
    }
    let mut bytes = [0; VALIDATION_HEADER_BYTES];
    bytes[..8].copy_from_slice(VALIDATION_MAGIC);
    bytes[8..24].copy_from_slice(&sb.uuid);
    bytes[24..32].copy_from_slice(&owner.0.to_le_bytes());
    bytes[32..36].copy_from_slice(&owner_generation.to_le_bytes());
    bytes[36..40].copy_from_slice(&tail.group.0.to_le_bytes());
    bytes[40..48].copy_from_slice(&tail.group_start.0.to_le_bytes());
    bytes[48..52].copy_from_slice(&sources.to_le_bytes());
    bytes[52..56].copy_from_slice(&sb.block_size.to_le_bytes());
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
    sb: &Ext4Superblock,
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
        || bytes != validation_header(sb, owner, owner_generation, tail, epoch, state, &root)?
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
    sb: &Ext4Superblock,
    tail: &NativeRepairTail,
) -> Result<Vec<u8>, FfsError> {
    let (_, capacity, _) = validation_sizes(sb, tail)?;
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
    sb: &Ext4Superblock,
    owner: InodeNumber,
    owner_generation: u32,
    tail: &NativeRepairTail,
    epoch: u32,
) -> Result<Vec<u8>, FfsError> {
    let (sources, capacity, used) = validation_sizes(sb, tail)?;
    let mut table = vec![0; capacity];
    table[..VALIDATION_HEADER_BYTES].copy_from_slice(&validation_header(
        sb,
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
        sb,
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
    sb: &Ext4Superblock,
    tail: &NativeRepairTail,
    table: &[u8],
    root: &[u8; 32],
) -> Result<(), FfsError> {
    let (_, capacity, used) = validation_sizes(sb, tail)?;
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
    sb: &Ext4Superblock,
    tail: &NativeRepairTail,
    table: &[u8],
    root: &[u8; 32],
) -> Result<(), FfsError> {
    verify_validation_table_integrity(sb, tail, table, root)?;
    let (sources, _, _) = validation_sizes(sb, tail)?;
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
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    owner_generation: u32,
    tail: &NativeRepairTail,
    intent: ParityIntent,
) -> [u8; VALIDATION_HEADER_BYTES] {
    let mut bytes = [0; VALIDATION_HEADER_BYTES];
    bytes[..8].copy_from_slice(PARITY_MAGIC);
    bytes[8..24].copy_from_slice(&sb.uuid);
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
    sb: &Ext4Superblock,
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
    if bytes != parity_header(sb, storage, owner_generation, tail, intent) {
        return Err(validation_error(
            tail,
            "native parity record identity or checksum mismatch",
        ));
    }
    Ok(intent)
}

fn native_layout(
    sb: &Ext4Superblock,
    tail: &NativeRepairTail,
) -> Result<(RepairGroupLayout, RepairGroupDescExt), FfsError> {
    let (sources, _, _) = validation_sizes(sb, tail)?;
    let layout = RepairGroupLayout::new(
        tail.group,
        tail.group_start,
        tail.blocks_per_group,
        tail.validation_blocks
            .checked_add(1)
            .ok_or_else(|| validation_error(tail, "validation span overflows"))?,
        tail.repair_blocks,
    )?;
    if layout.validation_start_block() != tail.start {
        return Err(validation_error(
            tail,
            "native layout includes owned metadata in sources",
        ));
    }
    let descriptor = RepairGroupDescExt {
        transfer_length: u64::from(sources) * u64::from(sb.block_size),
        symbol_size: u16::try_from(sb.block_size)
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
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    generation: u32,
    tail: &NativeRepairTail,
) -> Result<([u8; 32], Vec<u8>), FfsError> {
    let owner = dev.read_block(cx, tail.start)?;
    let intent = validation_intent(
        &owner.as_slice()[OWNER_HEADER_BYTES..PLAN_HEADER_START],
        sb,
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
    let table = read_validation_table(cx, dev, sb, tail)?;
    if validation_intent(
        &table[..VALIDATION_HEADER_BYTES],
        sb,
        storage.owner_inode,
        generation,
        tail,
    )? != intent
        || owner.as_slice()[OWNER_HEADER_BYTES..PLAN_HEADER_START]
            != table[..VALIDATION_HEADER_BYTES]
    {
        return Err(validation_error(tail, "sealed intent and table disagree"));
    }
    verify_validation_table_integrity(sb, tail, &table, &root)?;
    Ok((root, table))
}

fn read_native_baseline(fs: &OpenFs, cx: &Cx) -> Result<NativeBaseline, FfsError> {
    let storage = fs.native_ext4_repair_storage(cx)?;
    let sb = fs.ext4_superblock().expect("validated native ownership");
    let generation = fs
        .read_native_owner_inode(cx, sb, storage.owner_inode)?
        .generation;
    let dev = ByteDeviceBlockAdapter {
        dev: fs.dev.as_ref(),
        block_size: sb.block_size,
    };
    let owner = dev.read_block(cx, storage.tails[0].start)?;
    let plan = validation_plan_intent(
        &owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END],
        sb,
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
    let mut admissions = Vec::with_capacity(storage.tails.len());
    for tail in &storage.tails {
        let (root, table) = read_sealed_table(cx, &dev, sb, &storage, generation, tail)?;
        let local_epoch = u32::from_le_bytes(table[68..72].try_into().expect("checked table"));
        if local_epoch != epoch {
            return Err(validation_error(
                tail,
                "whole-plan and local epochs disagree",
            ));
        }
        admissions.push(ValidationAdmission {
            epoch,
            root,
            intent: ValidationIntent::Sealed(root),
        });
    }
    if validation_plan_root(sb, &storage, generation, &admissions)? != plan_root {
        return Err(validation_error(
            &storage.tails[0],
            "sealed whole-plan root mismatch",
        ));
    }
    Ok(NativeBaseline {
        storage,
        owner_generation: generation,
        epoch,
        plan_root,
        roots: admissions.into_iter().map(|group| group.root).collect(),
    })
}

fn ensure_native_baseline(fs: &OpenFs, cx: &Cx, expected: &NativeBaseline) -> Result<(), FfsError> {
    let current = read_native_baseline(fs, cx)?;
    if current.plan_root != expected.plan_root
        || current.storage != expected.storage
        || current.owner_generation != expected.owner_generation
        || current.epoch != expected.epoch
        || current.roots != expected.roots
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
    storage
        .tails
        .iter()
        .find(|tail| block.0 >= tail.group_start.0 && block.0 < tail.start.0)
        .ok_or_else(|| {
            FfsError::RepairFailed("requested block is outside native source coverage".into())
        })
}

fn read_native_parity_intent(
    cx: &Cx,
    dev: &dyn BlockDevice,
    sb: &Ext4Superblock,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
) -> Result<ParityIntent, FfsError> {
    let owner = dev.read_block(cx, tail.start)?;
    let intent = parity_intent(
        &owner.as_slice()[PARITY_HEADER_START..PARITY_HEADER_END],
        sb,
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
    sb: &Ext4Superblock,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    intent: ParityIntent,
) -> Result<(), FfsError> {
    let mut owner = dev.read_block(cx, tail.start)?.into_inner();
    let current = parity_intent(
        &owner[PARITY_HEADER_START..PARITY_HEADER_END],
        sb,
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
        sb,
        baseline.storage.owner_inode,
        baseline.owner_generation,
        baseline.storage.repair_basis_points,
        tail,
    );
    if !allowed
        || owner[..OWNER_HEADER_BYTES] != expected[..OWNER_HEADER_BYTES]
        || validation_intent(
            &owner[OWNER_HEADER_BYTES..PLAN_HEADER_START],
            sb,
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
        sb,
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
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    tail: &NativeRepairTail,
    allowed: u64,
    decoding: bool,
) -> Result<u64, FfsError> {
    let (sources, _, _) = validation_sizes(sb, tail)?;
    let (_, capacity, _) = validation_sizes(sb, &storage.tails[0])?;
    if sb.block_size < 1024 || tail.repair_blocks > sources {
        return Err(validation_error(
            tail,
            "unsupported native codec resource geometry",
        ));
    }
    // Serial groups, at most two tables and whole-plan admission/identity buffers.
    // The decoder margin includes pinned dense/wavefront equation retention;
    // this admission estimates allocations, not total process RSS.
    let metadata = (capacity as u64)
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(storage.tails.len() as u64 * 4096))
        .and_then(|bytes| bytes.checked_add(u64::from(sb.block_size) * 16))
        .ok_or_else(|| validation_error(tail, "native resource estimate overflows"))?;
    let budget = allowed.checked_sub(metadata).ok_or_else(|| {
        validation_error(tail, "native working budget is below metadata estimate")
    })?;
    let estimate = direct_encode_workspace_bytes(sources, sb.block_size, tail.repair_blocks)?
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

fn admit_native_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    sb: &Ext4Superblock,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    allowed: u64,
) -> Result<NativeGroupAdmission, FfsError> {
    let codec_budget = native_codec_budget(sb, &baseline.storage, tail, allowed, false)?;
    let intent = read_native_parity_intent(cx, dev, sb, baseline, tail)?;
    let (layout, expected) = native_layout(sb, tail)?;
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

fn native_sealed_generation(
    cx: &Cx,
    dev: &dyn BlockDevice,
    sb: &Ext4Superblock,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    degraded: bool,
) -> Result<u64, FfsError> {
    let ParityIntent::Sealed {
        generation,
        manifest,
        ..
    } = read_native_parity_intent(cx, dev, sb, baseline, tail)?
    else {
        return Err(validation_error(
            tail,
            "native parity is uninitialized or pending",
        ));
    };
    let (layout, expected) = native_layout(sb, tail)?;
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
    sb: &Ext4Superblock,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    admission: &NativeGroupAdmission,
) -> Result<(), FfsError> {
    if read_native_parity_intent(cx, dev, sb, baseline, tail)? != admission.intent {
        return Err(validation_error(
            tail,
            "native ownership changed after admission",
        ));
    }
    let (root, table) = read_sealed_table(
        cx,
        dev,
        sb,
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
    verify_validation_table(cx, dev, sb, tail, &table, &root)?;
    let (layout, expected) = native_layout(sb, tail)?;
    let storage = RepairGroupStorage::new(dev, layout);
    if storage.preflight_raw_refresh(cx, &expected)? != admission.raw {
        return Err(validation_error(
            tail,
            "native descriptors changed after admission",
        ));
    }
    if admission.retained {
        native_sealed_generation(cx, dev, sb, baseline, tail, false)?;
        return dev.sync(cx);
    }
    encode_and_publish_native_group(cx, dev, sb, baseline, tail, admission, &table)
}

fn encode_and_publish_native_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    sb: &Ext4Superblock,
    baseline: &NativeBaseline,
    tail: &NativeRepairTail,
    admission: &NativeGroupAdmission,
    table: &[u8],
) -> Result<(), FfsError> {
    // A live epoch changes the validation root before parity. Only this
    // already-admitted transition accepts the exact preceding parity anchor;
    // cold readers continue to require the new root and a sealed whole plan.
    let owner = dev.read_block(cx, tail.start)?;
    if parity_intent(
        &owner.as_slice()[PARITY_HEADER_START..PARITY_HEADER_END],
        sb,
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
    let (layout, expected) = native_layout(sb, tail)?;
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
    let (sources, _, _) = validation_sizes(sb, tail)?;
    let encoded = encode_group_direct(
        cx,
        &view,
        &sb.uuid,
        DirectEncodeRequest {
            group: tail.group,
            first_block: tail.group_start,
            source_block_count: sources,
            repair_count: tail.repair_blocks,
            max_working_bytes: admission.codec_budget,
        },
    )?;
    let symbols: Vec<_> = encoded
        .repair_symbols
        .into_iter()
        .map(|symbol| (symbol.esi, symbol.data))
        .collect();
    verify_validation_table(cx, dev, sb, tail, table, &root)?;
    write_native_parity_intent(
        cx,
        dev,
        sb,
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
    verify_validation_table(cx, dev, sb, tail, table, &root)?;
    let manifest = native_manifest(cx, dev, layout, admission.next_generation)?;
    write_native_parity_intent(
        cx,
        dev,
        sb,
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
    sb: &Ext4Superblock,
    baseline: &NativeBaseline,
    generations: Vec<u64>,
) -> Result<NativeRepairReport, FfsError> {
    let validation = native_validation_report(sb, &baseline.storage)?;
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
    sb: &Ext4Superblock,
    tail: &NativeRepairTail,
    table: &[u8],
) -> Result<Vec<u32>, FfsError> {
    let (sources, _, _) = validation_sizes(sb, tail)?;
    let mut corrupt = Vec::new();
    for index in 0..sources {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let bytes = dev.read_block(cx, BlockNumber(tail.group_start.0 + u64::from(index)))?;
        let offset = VALIDATION_HEADER_BYTES + index as usize * 32;
        if bytes.len() != sb.block_size as usize
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
        if block.0 < self.tail.group_start.0
            || block.0 >= self.tail.group_start.0 + u64::from(self.tail.blocks_per_group)
        {
            return Err(validation_error(
                self.tail,
                "codec read outside admitted native group",
            ));
        }
        let bytes = self.dev.read_block(cx, block)?;
        if block.0 < self.tail.start.0 {
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
        if let Some(index) = index.filter(|_| block.0 < self.tail.start.0) {
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
struct NativeReconstructionCapture {
    blocks: OnceCell<Vec<(BlockNumber, Vec<u8>)>>,
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
            captured.push((block.block, block.data.to_vec()));
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
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
) -> Result<NativeValidationReport, FfsError> {
    let mut source_blocks = 0;
    for tail in &storage.tails {
        source_blocks += u64::from(validation_sizes(sb, tail)?.0);
    }
    Ok(NativeValidationReport {
        owner_inode: storage.owner_inode,
        groups: u32::try_from(storage.tails.len())
            .map_err(|_| FfsError::InvalidGeometry("validation group count exceeds u32".into()))?,
        source_blocks,
    })
}

fn validation_plan_header(
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    generation: u32,
    epoch: u32,
    state: u32,
    root: &[u8; 32],
) -> Result<[u8; VALIDATION_HEADER_BYTES], FfsError> {
    let report = native_validation_report(sb, storage)?;
    if epoch == 0 {
        return Err(FfsError::RepairFailed(
            "zero native whole-plan epoch".into(),
        ));
    }
    let mut bytes = [0; VALIDATION_HEADER_BYTES];
    bytes[..8].copy_from_slice(PLAN_MAGIC);
    bytes[8..24].copy_from_slice(&sb.uuid);
    bytes[24..32].copy_from_slice(&storage.owner_inode.0.to_le_bytes());
    bytes[32..36].copy_from_slice(&generation.to_le_bytes());
    bytes[36..40].copy_from_slice(&report.groups.to_le_bytes());
    bytes[40..44].copy_from_slice(&storage.repair_basis_points.to_le_bytes());
    bytes[44..48].copy_from_slice(&sb.block_size.to_le_bytes());
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
    sb: &Ext4Superblock,
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
        || bytes != validation_plan_header(sb, storage, generation, epoch, state, &root)?
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
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    generation: u32,
    admissions: &[ValidationAdmission],
) -> Result<[u8; 32], FfsError> {
    let epoch = admissions
        .first()
        .ok_or_else(|| FfsError::RepairFailed("native whole-plan has no groups".into()))?
        .epoch;
    if admissions.len() != storage.tails.len()
        || admissions.iter().any(|admission| admission.epoch != epoch)
    {
        return Err(FfsError::RepairFailed(
            "native whole-plan epoch mismatch".into(),
        ));
    }
    let header =
        validation_plan_header(sb, storage, generation, epoch, VALIDATION_PENDING, &[0; 32])?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FrankenFS native whole-plan validation v1");
    hasher.update(&header[..64]);
    for (tail, admission) in storage.tails.iter().zip(admissions) {
        let group = validation_header(
            sb,
            storage.owner_inode,
            generation,
            tail,
            epoch,
            VALIDATION_PENDING,
            &admission.root,
        )?;
        hasher.update(&group[..104]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn publish_validation_plan(
    cx: &Cx,
    dev: &dyn BlockDevice,
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    generation: u32,
    epoch: u32,
    intent: ValidationIntent,
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
    let first = storage.tails[0].start;
    let mut owner = check_native_owner_prefix(cx, dev, sb, storage, generation, &storage.tails[0])?;
    owner[PLAN_HEADER_START..PLAN_HEADER_END].copy_from_slice(&validation_plan_header(
        sb, storage, generation, epoch, state, &root,
    )?);
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    dev.write_block(cx, first, &owner)?;
    dev.sync(cx)
}

fn admit_validation_plan(
    cx: &Cx,
    dev: &dyn BlockDevice,
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    generation: u32,
    admissions: &[ValidationAdmission],
) -> Result<(ValidationIntent, [u8; 32]), FfsError> {
    let root = validation_plan_root(sb, storage, generation, admissions)?;
    let first = &storage.tails[0];
    let owner = dev.read_block(cx, first.start)?;
    let plan = validation_plan_intent(
        &owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END],
        sb,
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
    sb: &Ext4Superblock,
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
        sb,
        owner,
        generation,
        tail,
    )?;
    let table = read_validation_table(cx, dev, sb, tail)?;
    let epoch = if intent == ValidationIntent::Empty {
        1
    } else {
        u32::from_le_bytes(block.as_slice()[132..136].try_into().expect("owner header"))
    };
    if let ValidationIntent::Sealed(root) = intent {
        if validation_intent(
            &table[..VALIDATION_HEADER_BYTES],
            sb,
            owner,
            generation,
            tail,
        )? != ValidationIntent::Sealed(root)
            || block.as_slice()[OWNER_HEADER_BYTES..PLAN_HEADER_START]
                != table[..VALIDATION_HEADER_BYTES]
        {
            return Err(validation_error(tail, "sealed intent and table disagree"));
        }
        verify_validation_table(cx, dev, sb, tail, &table, &root)?;
        return Ok(ValidationAdmission {
            epoch,
            root,
            intent,
        });
    }
    if intent == ValidationIntent::Empty
        && table[..sb.block_size as usize]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(validation_error(tail, "table has no initialization intent"));
    }
    let expected = build_validation_table(cx, dev, sb, owner, generation, tail, epoch)?;
    let (_, _, used) = validation_sizes(sb, tail)?;
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
    sb: &Ext4Superblock,
    storage: &NativeRepairStorage,
    generation: u32,
    tail: &NativeRepairTail,
    admission: &ValidationAdmission,
) -> Result<(), FfsError> {
    let owner = storage.owner_inode;
    let root = &admission.root;
    let epoch = admission.epoch;
    let mut table = build_validation_table(cx, dev, sb, owner, generation, tail, epoch)?;
    let (_, _, used) = validation_sizes(sb, tail)?;
    if &validation_root(&table, used) != root {
        return Err(validation_error(
            tail,
            "source changed after initialization admission",
        ));
    }
    let pending = validation_header(sb, owner, generation, tail, epoch, VALIDATION_PENDING, root)?;
    // Preserve the entire immutable ownership prefix verbatim.
    let mut ownership = check_native_owner_prefix(cx, dev, sb, storage, generation, tail)?;
    ownership[OWNER_HEADER_BYTES..OWNER_HEADER_BYTES + VALIDATION_HEADER_BYTES]
        .copy_from_slice(&pending);
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    dev.write_block(cx, tail.start, &ownership)?;
    dev.sync(cx)?;
    for (index, block) in table.chunks_exact(sb.block_size as usize).enumerate() {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let index = u32::try_from(index)
            .map_err(|_| validation_error(tail, "validation index exceeds u32"))?;
        dev.write_block(cx, BlockNumber(tail.start.0 + 1 + u64::from(index)), block)?;
    }
    dev.sync(cx)?;
    if read_validation_table(cx, dev, sb, tail)? != table {
        return Err(validation_error(
            tail,
            "table readback mismatch before sealing",
        ));
    }
    verify_validation_table(cx, dev, sb, tail, &table, root)?;
    let sealed = validation_header(sb, owner, generation, tail, epoch, VALIDATION_SEALED, root)?;
    table[..VALIDATION_HEADER_BYTES].copy_from_slice(&sealed);
    dev.write_block(
        cx,
        BlockNumber(tail.start.0 + 1),
        &table[..sb.block_size as usize],
    )?;
    dev.sync(cx)?;
    ownership[OWNER_HEADER_BYTES..OWNER_HEADER_BYTES + VALIDATION_HEADER_BYTES]
        .copy_from_slice(&sealed);
    dev.write_block(cx, tail.start, &ownership)?;
    dev.sync(cx)?;
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

impl OpenFs {
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
        // Preserve every inode byte except atime and the checksum fields.
        // Other inodes sharing this physical table block remain writable.
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

    /// Admit sealed native protection and fence all subsequent source writes.
    /// The caller must exclusively own the image and activate before recovery
    /// or writable operation. No unwrapped device handle is returned.
    ///
    /// # Errors
    /// Refuses unsealed or changed protection, insufficient resources, active
    /// external metadata logs, repeated activation and unsupported ownership.
    pub fn activate_native_ext4_repair(
        &mut self,
        cx: &Cx,
        max_working_bytes: u64,
    ) -> Result<NativeRepairReport, FfsError> {
        self.require_native_mode("activate_native_repair")?;
        if self.native_repair_active {
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
        let sb = self
            .ext4_superblock()
            .ok_or_else(|| freshness_error("native freshness requires ext4"))?
            .clone();
        sb.validate_v1()
            .map_err(|error| parse_to_ffs_error(&error))?;
        let storage = self.native_ext4_repair_storage(cx)?;
        let retained_budget = freshness_codec_budget(&sb, &storage, max_working_bytes)?;
        let ownership = self.capture_native_ownership(cx, &sb, &storage, retained_budget)?;
        let codec_budget = ownership.remaining_budget;
        for tail in &storage.tails {
            native_codec_budget(&sb, &storage, tail, codec_budget, false)?;
        }
        let baseline = read_native_baseline(self, cx)?;
        baseline
            .epoch
            .checked_add(1)
            .ok_or_else(|| freshness_error("validation epoch exhausted before activation"))?;
        let report = self.check_native_ext4_repair(cx)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.block_size,
        };
        let mut tables = Vec::with_capacity(storage.tails.len());
        let mut parity = Vec::with_capacity(storage.tails.len());
        for (index, tail) in storage.tails.iter().enumerate() {
            let (root, table) =
                read_sealed_table(cx, &dev, &sb, &storage, baseline.owner_generation, tail)?;
            if root != baseline.roots[index] {
                return Err(validation_error(
                    tail,
                    "source authority changed during activation",
                ));
            }
            verify_validation_table(cx, &dev, &sb, tail, &table, &root)?;
            let admission = admit_native_group(cx, &dev, &sb, &baseline, tail, codec_budget)?;
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
        self.dev = Arc::new(NativeFreshnessDevice {
            inner: Arc::clone(&self.dev),
            sb,
            state: NativeMutex::new(NativeFreshnessState {
                baseline,
                tables,
                parity,
                intended: BTreeMap::new(),
                phase: FreshnessPhase::Clean,
            }),
            codec_budget,
            ownership,
        });
        self.native_repair_active = true;
        Ok(report)
    }

    /// Publish native parity from the existing sealed source baseline.
    /// The caller must exclude all writers for this consumed offline view.
    /// Resource and whole-plan admission precede writes; protection stays inactive.
    ///
    /// # Errors
    /// Refuses changed sources, malformed ownership/descriptors, exhausted
    /// generations, insufficient working budget, cancellation and I/O failures.
    pub fn initialize_native_ext4_repair(
        self,
        cx: &Cx,
        max_working_bytes: u64,
    ) -> Result<NativeRepairReport, FfsError> {
        self.require_native_mode("initialize_native_repair")?;
        let owned = self.native_ext4_repair_storage(cx)?;
        let sb = self
            .ext4_superblock()
            .expect("validated native ext4 ownership");
        for tail in &owned.tails {
            native_codec_budget(sb, &owned, tail, max_working_bytes, false)?;
        }
        let baseline = read_native_baseline(&self, cx)?;
        self.check_native_ext4_validation(cx)?;
        let sb = self
            .ext4_superblock()
            .expect("validated native ext4 ownership");
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.block_size,
        };
        let mut admissions = Vec::with_capacity(baseline.storage.tails.len());
        for tail in &baseline.storage.tails {
            admissions.push(admit_native_group(
                cx,
                &dev,
                sb,
                &baseline,
                tail,
                max_working_bytes,
            )?);
        }
        for (tail, admission) in baseline.storage.tails.iter().zip(&admissions) {
            publish_native_group(cx, &dev, sb, &baseline, tail, admission)?;
        }
        ensure_native_baseline(&self, cx, &baseline)?;
        let report = self.check_native_ext4_repair(cx)?;
        dev.sync(cx)?;
        Ok(report)
    }

    /// Read-only check of current sources and all committed native parity.
    ///
    /// # Errors
    /// Refuses pending/missing authority, damaged or changed data and I/O errors.
    pub fn check_native_ext4_repair(&self, cx: &Cx) -> Result<NativeRepairReport, FfsError> {
        self.require_native_mode("check_native_repair")?;
        let baseline = read_native_baseline(self, cx)?;
        self.check_native_ext4_validation(cx)?;
        let sb = self
            .ext4_superblock()
            .expect("validated native ext4 ownership");
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.block_size,
        };
        let mut generations = Vec::with_capacity(baseline.storage.tails.len());
        for tail in &baseline.storage.tails {
            generations.push(native_sealed_generation(
                cx, &dev, sb, &baseline, tail, false,
            )?);
        }
        native_repair_report(sb, &baseline, generations)
    }

    /// Reconstruct a changed source block from the immutable sealed baseline.
    /// Reads and validates every source in its group and all reconstructed bytes.
    /// Never writes or syncs the image. The caller must exclude image writers.
    /// This establishes historical baseline bytes, not freshness after client writes.
    ///
    /// # Errors
    /// Refuses intact/non-source targets, missing or changed authority, resource
    /// excess, insufficient parity, invalid decoded bytes, cancellation and I/O.
    pub fn reconstruct_native_ext4_block(
        &self,
        cx: &Cx,
        block: BlockNumber,
        max_working_bytes: u64,
    ) -> Result<NativeReconstruction, FfsError> {
        self.require_native_mode("reconstruct_native_block")?;
        let owned = self.native_ext4_repair_storage(cx)?;
        let selected = native_target(&owned, block)?;
        let sb = self
            .ext4_superblock()
            .expect("validated native ext4 ownership");
        native_codec_budget(sb, &owned, selected, max_working_bytes, true)?;
        let baseline = read_native_baseline(self, cx)?;
        let tail = native_target(&baseline.storage, block)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.block_size,
        };
        let admitted_intent = read_native_parity_intent(cx, &dev, sb, &baseline, tail)?;
        let generation = native_sealed_generation(cx, &dev, sb, &baseline, tail, true)?;
        let (root, table) = read_sealed_table(
            cx,
            &dev,
            sb,
            &baseline.storage,
            baseline.owner_generation,
            tail,
        )?;
        let corrupt = native_corrupt_indices(cx, &dev, sb, tail, &table)?;
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
        let (layout, expected) = native_layout(sb, tail)?;
        let result = GroupRecoveryOrchestrator::new_with_writeback(
            &view,
            &capture,
            sb.uuid,
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
            || read_native_parity_intent(cx, &dev, sb, &baseline, tail)? != admitted_intent
            || native_sealed_generation(cx, &dev, sb, &baseline, tail, true)? != generation
        {
            return Err(validation_error(
                tail,
                "native recovery authority changed during decoding",
            ));
        }
        // Re-read intact input through its digest guard after decoding; changed
        // targets were compare-checked by capture and are never written back.
        for index in 0..u32::from(expected.source_block_count) {
            view.read_block(cx, BlockNumber(tail.group_start.0 + u64::from(index)))?;
        }
        let captured = capture
            .blocks
            .into_inner()
            .ok_or_else(|| validation_error(tail, "native reconstruction produced no capture"))?;
        let data = captured
            .into_iter()
            .find_map(|(number, bytes)| (number == block).then_some(bytes))
            .ok_or_else(|| validation_error(tail, "requested block missing from reconstruction"))?;
        Ok(NativeReconstruction {
            block,
            generation,
            data,
        })
    }

    /// Persist generation-one source digests in owned native ext4 storage.
    ///
    /// The caller must exclude other image writers throughout this offline
    /// operation. Consumes the view; reopen after success or ambiguous failure.
    /// All groups are admitted before writes. A durable whole-plan root precedes
    /// every group publication, so interrupted initialization can resume only
    /// against all originally admitted sources. Sealed evidence is never rebaselined.
    /// This initializes validation only; repair protection remains inactive.
    ///
    /// # Errors
    /// Refuses unsupported ownership, symbols already present, damaged sealed
    /// tables, changed sources, cancellation and storage failures.
    pub fn initialize_native_ext4_validation(
        self,
        cx: &Cx,
    ) -> Result<NativeValidationReport, FfsError> {
        self.require_native_mode("initialize_native_validation")?;
        let storage = self.native_ext4_repair_storage(cx)?;
        let sb = self.ext4_superblock().expect("validated ext4 ownership");
        let inode = self.read_native_owner_inode(cx, sb, storage.owner_inode)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.block_size,
        };
        let mut admissions = Vec::with_capacity(storage.tails.len());
        for tail in &storage.tails {
            admissions.push(admit_validation_group(
                cx,
                &dev,
                sb,
                storage.owner_inode,
                inode.generation,
                tail,
            )?);
        }
        let (plan, root) =
            admit_validation_plan(cx, &dev, sb, &storage, inode.generation, &admissions)?;
        if plan == ValidationIntent::Prepared {
            publish_validation_plan(
                cx,
                &dev,
                sb,
                &storage,
                inode.generation,
                admissions[0].epoch,
                ValidationIntent::Pending(root),
            )?;
        } else if matches!(plan, ValidationIntent::Pending(_)) {
            // An earlier plan sync may have failed after its write became visible.
            // Establish durability again before publishing any local intent.
            dev.sync(cx)?;
        }
        for (tail, admission) in storage.tails.iter().zip(&admissions) {
            if matches!(admission.intent, ValidationIntent::Sealed(_)) {
                continue;
            }
            publish_validation_group(cx, &dev, sb, &storage, inode.generation, tail, admission)?;
        }
        if !matches!(plan, ValidationIntent::Sealed(_)) {
            publish_validation_plan(
                cx,
                &dev,
                sb,
                &storage,
                inode.generation,
                admissions[0].epoch,
                ValidationIntent::Sealed(root),
            )?;
        }
        // A previous failed sync may leave sealing visible but undurable.
        // Idempotent retries must also establish a successful durability barrier.
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        dev.sync(cx)?;
        native_validation_report(sb, &storage)
    }

    /// Check persisted native source digests without writing the image.
    ///
    /// # Errors
    /// Refuses empty/pending records, identity or table damage, and source
    /// digest mismatches; propagates cancellation and read failures.
    pub fn check_native_ext4_validation(
        &self,
        cx: &Cx,
    ) -> Result<NativeValidationReport, FfsError> {
        self.require_native_mode("check_native_validation")?;
        let storage = self.native_ext4_repair_storage(cx)?;
        let sb = self.ext4_superblock().expect("validated ext4 ownership");
        let inode = self.read_native_owner_inode(cx, sb, storage.owner_inode)?;
        let dev = ByteDeviceBlockAdapter {
            dev: self.dev.as_ref(),
            block_size: sb.block_size,
        };
        let first_owner = dev.read_block(cx, storage.tails[0].start)?;
        let plan = validation_plan_intent(
            &first_owner.as_slice()[PLAN_HEADER_START..PLAN_HEADER_END],
            sb,
            &storage,
            inode.generation,
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
                sb,
                storage.owner_inode,
                inode.generation,
                tail,
            )?;
            let ValidationIntent::Sealed(root) = intent else {
                return Err(validation_error(
                    tail,
                    "validation is uninitialized or pending",
                ));
            };
            let table = read_validation_table(cx, &dev, sb, tail)?;
            if validation_intent(
                &table[..VALIDATION_HEADER_BYTES],
                sb,
                storage.owner_inode,
                inode.generation,
                tail,
            )? != ValidationIntent::Sealed(root)
                || owner.as_slice()[OWNER_HEADER_BYTES..PLAN_HEADER_START]
                    != table[..VALIDATION_HEADER_BYTES]
                || u32::from_le_bytes(table[68..72].try_into().expect("checked table")) != epoch
            {
                return Err(validation_error(tail, "sealed intent and table disagree"));
            }
            verify_validation_table(cx, &dev, sb, tail, &table, &root)?;
            admissions.push(ValidationAdmission {
                epoch,
                root,
                intent,
            });
        }
        if validation_plan_root(sb, &storage, inode.generation, &admissions)? != plan_root {
            return Err(validation_error(
                &storage.tails[0],
                "sealed whole-plan root mismatch",
            ));
        }
        native_validation_report(sb, &storage)
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
                let mut header = owner_header(&sb, owner, inode.generation, basis_points, tail);
                if tail.group.0 == 0 {
                    header[PLAN_HEADER_START..PLAN_HEADER_END].copy_from_slice(
                        &validation_plan_header(
                            &sb,
                            &storage,
                            inode.generation,
                            1,
                            PLAN_PREPARED,
                            &[0; 32],
                        )?,
                    );
                }
                header[PARITY_HEADER_START..PARITY_HEADER_END].copy_from_slice(&parity_header(
                    &sb,
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
            let expected = owner_header(sb, attr.ino, inode.generation, basis_points, tail);
            if stored[..OWNER_HEADER_BYTES] != expected[..OWNER_HEADER_BYTES]
                || stored[PARITY_HEADER_END..].iter().any(|byte| *byte != 0)
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
                sb,
                attr.ino,
                inode.generation,
                tail,
            )?;
            let parity = parity_intent(
                &stored[PARITY_HEADER_START..PARITY_HEADER_END],
                sb,
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
                    sb,
                    &storage,
                    inode.generation,
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
