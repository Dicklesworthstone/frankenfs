//! Explicitly admitted native NTFS 3.1 journal publication and allocator/MFT transactions.
//!
//! Preserves read-only admission on [`crate::NtfsVolume`] and [`crate::NtfsFs`]:
//! durable writes and persistent `$LogFile` ARIES recovery require opening an
//! [`NtfsTransactionEngine`] with explicit [`NtfsWriteOptions`].

mod btree;
mod catalog;
mod dir_index;
mod mutations;
mod ops;
mod recovery;

pub use mutations::{
    NtfsRenameOutcome, validate_ntfs_component_utf16, validate_ntfs_stream_name_utf16,
};

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_block::io_engine::{VolumeAccess, VolumeDevice};
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::logfile_writer::{
    LFS_RECORD_CLIENT, LFS_RECORD_CLIENT_RESTART, NtfsCheckpointPayload, NtfsClientUpdateSpec,
    NtfsLogRingWriter, StagedLogPage, encode_attribute_names_dump, encode_client_update_payload,
    encode_open_attribute_entry, encode_restart_table,
};
use ffs_ondisk::ntfs::{
    ATTRIBUTE_LIST, COMPRESSED, DATA, ENCRYPTED, NtfsFileRecord, NtfsGeometry, NtfsLogOp,
    NtfsReference, NtfsRun, NtfsValue, SPARSE, VOLUME_INFORMATION, decode_mapping_pairs,
    parse_attr_def_table, validate_ntfs31_attr_def_table,
};
use ffs_types::{ByteOffset, ParseError};
use serde::Serialize;

use crate::NtfsVolume;
use crate::reader::allocation::{AllocationLimits, NamespaceLimits, RecordOwnershipLimits};
use crate::reader::security::SecurityCheckLimits;

pub(super) const LOG_PAGE_BYTES: u32 = 4096;
pub(super) const SECTOR_BYTES: usize = 512;
const UPCASE_BYTES: usize = 131_072;
/// Maximum resulting stream length for nonempty positioned writes, and maximum
/// requested truncate length. These operations stage a complete replacement
/// before native WAL publication; the bound prevents memory exhaustion. Empty
/// writes validate the target but preserve larger streams without staging data.
pub const MAX_FILE_EDIT_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_ERASED_LOG_BYTES: u64 = 64 * 1024 * 1024;
const USNJRNL_UPPER: [u16; 8] = [
    b'$' as u16,
    b'U' as u16,
    b'S' as u16,
    b'N' as u16,
    b'J' as u16,
    b'R' as u16,
    b'N' as u16,
    b'L' as u16,
];
const QUOTA_UPPER: [u16; 6] = [
    b'$' as u16,
    b'Q' as u16,
    b'U' as u16,
    b'O' as u16,
    b'T' as u16,
    b'A' as u16,
];
const DOLLAR_Q_NAME: [u16; 2] = [b'$' as u16, b'Q' as u16];
const HIBERFIL_UPPER: [u16; 12] = [
    b'H' as u16,
    b'I' as u16,
    b'B' as u16,
    b'E' as u16,
    b'R' as u16,
    b'F' as u16,
    b'I' as u16,
    b'L' as u16,
    b'.' as u16,
    b'S' as u16,
    b'Y' as u16,
    b'S' as u16,
];

pub(super) fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

pub(super) fn corrupt(offset: u64, detail: impl Into<String>) -> FfsError {
    FfsError::Corruption {
        block: offset / 512,
        detail: detail.into(),
    }
}

pub(super) fn parse_err(error: &ParseError) -> FfsError {
    corrupt(0, error.to_string())
}

pub(super) fn unsupported(detail: impl Into<String>) -> FfsError {
    FfsError::UnsupportedFeature(detail.into())
}

/// Explicit authorization flags required to open an NTFS 3.1 image for native mutation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct NtfsWriteOptions {
    /// Caller confirms the backing image is offline and not mounted elsewhere.
    pub offline_image: bool,
    /// Caller explicitly authorizes native on-disk NTFS mutations.
    pub allow_write: bool,
    /// Authorize persistent ARIES `$LogFile` redo/undo recovery when dirty.
    pub recover_dirty: bool,
}

/// Storage and bootstrap identity bound into every [`NtfsDurableToken`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NtfsStorageIdentity {
    pub volume_serial: u64,
    pub volume_bytes: u64,
    pub cluster_bytes: u32,
    pub record_bytes: u32,
    pub index_bytes: u32,
    pub mft_cluster: u64,
    pub mirror_cluster: u64,
    pub boot_blake3: [u8; 32],
    pub file_dev_ino: Option<(u64, u64)>,
}

/// Unforgeable native commit token bound to a specific NTFS volume/storage identity
/// and `$LogFile` commit LSN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NtfsDurableToken {
    storage: NtfsStorageIdentity,
    transaction_id: u32,
    commit_lsn: u64,
    checkpoint_lsn: Option<u64>,
    generation: u64,
    operation_digest: [u8; 32],
}

impl NtfsDurableToken {
    #[must_use]
    pub const fn storage(&self) -> &NtfsStorageIdentity {
        &self.storage
    }

    #[must_use]
    pub const fn transaction_id(&self) -> u32 {
        self.transaction_id
    }

    #[must_use]
    pub const fn commit_lsn(&self) -> u64 {
        self.commit_lsn
    }

    #[must_use]
    pub const fn checkpoint_lsn(&self) -> Option<u64> {
        self.checkpoint_lsn
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn operation_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }

    /// Verify that this token belongs to `engine`'s exact storage/view identity
    /// and a monotonically committed generation.
    #[must_use]
    pub fn matches_engine(&self, engine: &NtfsTransactionEngine) -> bool {
        self.storage == engine.storage_identity
            && self.commit_lsn != 0
            && self.generation <= engine.generation
    }
}

/// Outcome of a native NTFS transaction, distinguishing pre-commit failure,
/// durable commit, and post-log-write barrier/cancellation uncertainty.
#[derive(Debug)]
pub enum NtfsTxOutcome<T> {
    /// `$LogFile` commit record and target barriers completed durably.
    Committed { value: T, token: NtfsDurableToken },
    /// Rejected or failed strictly before `$LogFile` `CommitTransaction` became durable.
    NotCommitted(FfsError),
    /// Failed or cancelled at/after `$LogFile` `CommitTransaction` write; native
    /// ARIES recovery must be consulted before assuming commit or rollback.
    Uncertain {
        reason: FfsError,
        transaction_id: u32,
        commit_lsn: u64,
    },
}

impl<T> NtfsTxOutcome<T> {
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }

    pub fn into_result(self) -> Result<(T, NtfsDurableToken)> {
        match self {
            Self::Committed { value, token } => Ok((value, token)),
            Self::NotCommitted(err) => Err(err),
            Self::Uncertain { reason, .. } => Err(reason),
        }
    }
}

/// Ordered persistence stages recorded per transaction for persistence-prefix verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NtfsPersistenceStage {
    PayloadDataWrite,
    PayloadBarrier,
    MftSlotZeroWrite,
    MftSlotZeroBarrier,
    DirtyRestartWrite,
    DirtyRestartBarrier,
    LogRecordWrite,
    LogCommitBarrier,
    TargetMetadataWrite,
    TargetMetadataBarrier,
    CheckpointWrite,
    CleanRestartSlotAWrite,
    CleanRestartSlotABarrier,
    CleanRestartSlotBWrite,
    CleanRestartSlotBBarrier,
    AckPublished,
}

/// Structured persistence trace event emitted by [`NtfsTransactionEngine`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NtfsPersistenceEvent {
    pub seq: u64,
    pub operation: String,
    pub stage: NtfsPersistenceStage,
    pub transaction_id: u32,
    pub lsn: u64,
    pub offset: u64,
    pub bytes: usize,
}

/// Summary of inspected `$LogFile` state during admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NtfsLogStateSummary {
    pub erased: bool,
    pub clean: bool,
    pub version: (u16, u16),
    pub page_size: u32,
    pub file_size: u64,
    pub oldest_lsn: u64,
    pub current_lsn: u64,
    pub client_restart_lsn: u64,
    pub torn_rstr_slot: Option<usize>,
}

/// Summary of persistent ARIES `$LogFile` recovery.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NtfsRecoverySummary {
    pub was_dirty: bool,
    pub healed_torn_rstr_slot: Option<usize>,
    pub committed_winners: Vec<u32>,
    pub undone_losers: Vec<u32>,
    pub redo_applied: usize,
    pub undo_applied: usize,
    pub clr_written: usize,
    pub final_checkpoint_lsn: u64,
}

/// Diagnostic admission report returned by read-only or writable admission checks.
#[derive(Debug, Clone, Serialize)]
pub struct NtfsAdmissionReport {
    pub admitted_clean_write: bool,
    pub requires_recovery: bool,
    pub volume_serial: u64,
    pub volume_bytes: u64,
    pub cluster_bytes: u32,
    pub record_bytes: u32,
    pub index_bytes: u32,
    pub volume_flags: u16,
    pub mft_records_logical: u64,
    pub mft_records_initialized: u64,
    pub log_state: NtfsLogStateSummary,
    pub recovery: Option<NtfsRecoverySummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileStamp {
    fn of(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            length: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

struct ExclusiveImageDevice {
    file: File,
    length: u64,
    writable: bool,
}

impl ByteDevice for ExclusiveImageDevice {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        if offset
            .0
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(corrupt(offset.0, "NTFS read outside backing file"));
        }
        self.file.read_exact_at(buf, offset.0)?;
        checkpoint(cx)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        if self.file.metadata()?.len() != self.length {
            return Err(corrupt(
                offset.0,
                "NTFS backing image length changed during session",
            ));
        }
        if offset
            .0
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(corrupt(offset.0, "NTFS write outside backing file"));
        }
        self.file.write_all_at(buf, offset.0)?;
        checkpoint(cx)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        self.file.sync_all()?;
        checkpoint(cx)
    }
}

struct ReadOnlyDeviceRef(Arc<dyn ByteDevice>);

impl ByteDevice for ReadOnlyDeviceRef {
    fn len_bytes(&self) -> u64 {
        self.0.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        self.0.read_exact_at(cx, offset, buf)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OpenAttrRuntime {
    pub(super) reference_raw: u64,
    pub(super) kind: u32,
    pub(super) name: Vec<u16>,
    pub(super) index_bytes: u32,
    pub(super) opened_lsn: u64,
}

/// Optional post-stage callback invoked immediately after a persistence event is recorded.
pub type NtfsStageHook = Box<dyn FnMut(&NtfsPersistenceEvent) -> Result<()> + Send + Sync>;

/// Explicitly admitted native NTFS 3.1 transaction & ARIES `$LogFile` recovery engine.
pub struct NtfsTransactionEngine {
    pub(super) device: Arc<dyn ByteDevice>,
    pub(super) geometry: NtfsGeometry,
    pub(super) storage_identity: NtfsStorageIdentity,
    pub(super) upcase: Box<[u16]>,
    pub(super) logfile_runs: Vec<NtfsRun>,
    pub(super) logfile_bytes: u64,
    pub(super) ring: Option<NtfsLogRingWriter>,
    /// A publication/recovery attempt has touched journal state and has not
    /// completed every required clean-state barrier. This is independent of
    /// whether that attempt's user operation reached its commit point.
    pub(super) recovery_required: bool,
    pub(super) open_attrs: BTreeMap<u32, OpenAttrRuntime>,
    pub(super) next_tx_slot_index: u32,
    pub(super) generation: u64,
    pub(super) last_recovery: Option<NtfsRecoverySummary>,
    pub(super) trace: Vec<NtfsPersistenceEvent>,
    pub(super) next_seq: u64,
    /// Committed `(src_path, dst_path, source_ref)` keys in this or recovered views
    /// to prevent duplicate rename execution after post-commit pre-reply uncertainty.
    pub(super) committed_renames: BTreeMap<(String, String), NtfsReference>,
    pub(super) stage_hook: Option<NtfsStageHook>,
}

impl NtfsTransactionEngine {
    /// Inspect an offline NTFS image for writable admission without modifying a single byte.
    pub fn admit_read_only_probe(
        cx: &Cx,
        path: &Path,
        base: u64,
        length: Option<u64>,
    ) -> Result<NtfsAdmissionReport> {
        checkpoint(cx)?;
        let before = fs::symlink_metadata(path)?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(unsupported(
                "NTFS admission probe requires a regular offline image file",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let after = file.metadata()?;
        if !after.is_file() || FileStamp::of(&before) != FileStamp::of(&after) {
            return Err(corrupt(0, "NTFS image file changed while opening"));
        }
        file.try_lock_shared()
            .map_err(|err| FfsError::Io(std::io::Error::other(err)))?;
        let file_len = after.len();
        let selected_len = length.unwrap_or_else(|| file_len.saturating_sub(base));
        let dev: Arc<dyn ByteDevice> = Arc::new(ExclusiveImageDevice {
            file,
            length: file_len,
            writable: false,
        });
        Self::probe_device_admission(
            cx,
            dev,
            base,
            selected_len,
            Some((after.dev(), after.ino())),
        )
    }

    /// Open a regular offline NTFS 3.1 image exclusively for native transactions.
    pub fn open(
        cx: &Cx,
        path: &Path,
        base: u64,
        length: Option<u64>,
        options: NtfsWriteOptions,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if !options.offline_image || !options.allow_write {
            return Err(FfsError::PermissionDenied);
        }
        let before = fs::symlink_metadata(path)?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(unsupported(
                "NTFS writable admission requires an offline regular file, not a symlink or device",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let after = file.metadata()?;
        if !after.is_file() || FileStamp::of(&before) != FileStamp::of(&after) {
            return Err(corrupt(0, "NTFS image identity changed during open"));
        }
        file.try_lock()
            .map_err(|err| FfsError::Io(std::io::Error::other(err)))?;
        let file_len = after.len();
        let selected_len = length.unwrap_or_else(|| file_len.saturating_sub(base));
        let dev: Arc<dyn ByteDevice> = Arc::new(ExclusiveImageDevice {
            file,
            length: file_len,
            writable: true,
        });
        Self::from_device_with_file_id(
            cx,
            dev,
            base,
            selected_len,
            options,
            Some((after.dev(), after.ino())),
        )
    }

    /// Open a caller-owned writable [`ByteDevice`] slice for native NTFS 3.1 transactions.
    pub fn from_device(
        cx: &Cx,
        device: Arc<dyn ByteDevice>,
        base: u64,
        length: u64,
        options: NtfsWriteOptions,
    ) -> Result<Self> {
        Self::from_device_with_file_id(cx, device, base, length, options, None)
    }

    fn from_device_with_file_id(
        cx: &Cx,
        device: Arc<dyn ByteDevice>,
        base: u64,
        length: u64,
        options: NtfsWriteOptions,
        file_dev_ino: Option<(u64, u64)>,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if !options.offline_image || !options.allow_write {
            return Err(FfsError::PermissionDenied);
        }
        let window = VolumeDevice::new(device, ByteOffset(base), length, VolumeAccess::ReadWrite)?;
        let bounded: Arc<dyn ByteDevice> = Arc::new(window);
        let mut engine = Self::bootstrap_engine(cx, bounded, file_dev_ino, options.recover_dirty)?;
        if engine.needs_recovery_on_open(cx)? {
            if !options.recover_dirty {
                return Err(unsupported(
                    "NTFS volume or $LogFile is dirty; pass recover_dirty=true to run persistent ARIES recovery",
                ));
            }
            let summary = engine.recover_in_place(cx)?;
            engine.last_recovery = Some(summary);
        }
        // Final clean admission gate: verify structural consistency before authorizing writes.
        engine.check_clean_consistency(cx)?;
        Ok(engine)
    }

    fn probe_device_admission(
        cx: &Cx,
        device: Arc<dyn ByteDevice>,
        base: u64,
        length: u64,
        file_dev_ino: Option<(u64, u64)>,
    ) -> Result<NtfsAdmissionReport> {
        let window = VolumeDevice::new(device, ByteOffset(base), length, VolumeAccess::ReadOnly)?;
        let bounded: Arc<dyn ByteDevice> = Arc::new(window);
        let engine = Self::bootstrap_engine(cx, bounded, file_dev_ino, true)?;
        let (vol_flags, mft_logical, mft_init) = engine.read_volume_status_and_mft_counts(cx)?;
        let log_state = engine.inspect_log_state(cx)?;
        let dirty =
            (vol_flags & 0x0001 != 0) || !log_state.clean || log_state.torn_rstr_slot.is_some();
        if !dirty {
            engine.check_clean_consistency(cx)?;
        }
        Ok(NtfsAdmissionReport {
            admitted_clean_write: !dirty,
            requires_recovery: dirty,
            volume_serial: engine.geometry.serial(),
            volume_bytes: engine.geometry.volume_bytes(),
            cluster_bytes: engine.geometry.cluster_bytes(),
            record_bytes: engine.geometry.record_bytes(),
            index_bytes: engine.geometry.index_bytes(),
            volume_flags: vol_flags,
            mft_records_logical: mft_logical,
            mft_records_initialized: mft_init,
            log_state,
            recovery: None,
        })
    }

    fn bootstrap_engine(
        cx: &Cx,
        bounded: Arc<dyn ByteDevice>,
        file_dev_ino: Option<(u64, u64)>,
        allow_dirty_bootstrap: bool,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let mut boot = [0_u8; SECTOR_BYTES];
        bounded.read_exact_at(cx, ByteOffset(0), &mut boot)?;
        let geometry =
            NtfsGeometry::parse(&boot, bounded.len_bytes()).map_err(|err| parse_err(&err))?;
        let boot_blake3 = *blake3::hash(&boot).as_bytes();

        let record_bytes = geometry.record_bytes() as usize;
        let mft0_off = geometry
            .cluster_offset(geometry.mft_cluster())
            .map_err(|err| parse_err(&err))?;
        let mirr0_off = geometry
            .cluster_offset(geometry.mirror_cluster())
            .map_err(|err| parse_err(&err))?;
        let mut raw_mft0 = vec![0_u8; record_bytes];
        let mut raw_mirr0 = vec![0_u8; record_bytes];
        bounded.read_exact_at(cx, ByteOffset(mft0_off), &mut raw_mft0)?;
        bounded.read_exact_at(cx, ByteOffset(mirr0_off), &mut raw_mirr0)?;
        let mft0 = NtfsFileRecord::parse(&raw_mft0).map_err(|err| parse_err(&err))?;
        let mirr0 = NtfsFileRecord::parse(&raw_mirr0).map_err(|err| parse_err(&err))?;
        if !mft0.in_use() || mft0.number != 0 || !mirr0.in_use() || mirr0.number != 0 {
            return Err(corrupt(0, "invalid $MFT or $MFTMirr record 0 identity"));
        }
        if !same_logical_record(&mft0, &mirr0) && !allow_dirty_bootstrap {
            return Err(corrupt(
                0,
                "$MFT and $MFTMirr record 0 disagree without recovery admission",
            ));
        }

        let mft_runs = extract_plain_nonresident_runs(&geometry, &mft0, DATA, &[])?;
        if mft_runs.first().and_then(|r| r.lcn) != Some(geometry.mft_cluster()) {
            return Err(corrupt(0, "$MFT mapping disagrees with boot cluster"));
        }

        // Validate $Volume (record 3) version 3.1 and volume flags.
        let vol_rec = read_mft_record_via_runs(&bounded, cx, &geometry, &mft_runs, 3)?;
        let vol_info = extract_resident_attr(&vol_rec, VOLUME_INFORMATION, &[])?;
        if vol_info.len() < 12 || vol_info[8..10] != [3, 1] {
            return Err(unsupported(
                "NTFS native transactions admit version 3.1 only",
            ));
        }
        let vol_flags = u16::from_le_bytes([vol_info[10], vol_info[11]]);
        if vol_flags & !0x0001 != 0 {
            return Err(unsupported(format!(
                "NTFS volume flags {vol_flags:#06x} include unsupported chkdsk/resize/upgrade state"
            )));
        }

        // Validate system metadata records 0..11 have no EFS/compression/sparse transforms on primary streams.
        for sys_no in [0_u32, 1, 2, 3, 5, 6, 10] {
            let rec = read_mft_record_via_runs(&bounded, cx, &geometry, &mft_runs, sys_no)?;
            for attr in rec.attributes().map_err(|err| parse_err(&err))? {
                if attr.flags & (COMPRESSED | ENCRYPTED | SPARSE) != 0 {
                    return Err(unsupported(format!(
                        "system record {sys_no} carries compressed/encrypted/sparse metadata"
                    )));
                }
                if attr.kind == 0x100 {
                    return Err(unsupported(
                        "active NTFS $TXF_DATA transactional metadata is refused",
                    ));
                }
            }
        }

        // Load $UpCase (record 10, 128 KiB) and verify idempotency + canonical ASCII folding.
        let upcase_rec = read_mft_record_via_runs(&bounded, cx, &geometry, &mft_runs, 10)?;
        let (upcase_runs, upcase_size, upcase_init) =
            extract_plain_nonresident_stream(&geometry, &upcase_rec, DATA, &[])?;
        if upcase_size != UPCASE_BYTES as u64 || upcase_init != UPCASE_BYTES as u64 {
            return Err(corrupt(0, "invalid $UpCase length"));
        }
        let upcase_raw = read_mapped_runs(&bounded, cx, &geometry, &upcase_runs, 0, UPCASE_BYTES)?;
        let mut upcase = vec![0_u16; 65_536].into_boxed_slice();
        for (idx, &[lo, hi]) in upcase_raw.as_chunks::<2>().0.iter().enumerate() {
            upcase[idx] = u16::from_le_bytes([lo, hi]);
        }
        for (idx, &mapped) in upcase.iter().enumerate() {
            if upcase[usize::from(mapped)] != mapped {
                return Err(corrupt(0, "NTFS $UpCase table is not idempotent"));
            }
            if (usize::from(b'a')..=usize::from(b'z')).contains(&idx)
                && mapped != u16::try_from(idx - 32).unwrap_or(0)
            {
                return Err(unsupported(
                    "NTFS $UpCase does not map ASCII a..=z canonically",
                ));
            }
        }

        // Load $LogFile (record 2).
        let log_rec = read_mft_record_via_runs(&bounded, cx, &geometry, &mft_runs, 2)?;
        let (logfile_runs, logfile_bytes, logfile_init) =
            extract_plain_nonresident_stream(&geometry, &log_rec, DATA, &[])?;
        if logfile_init != logfile_bytes
            || logfile_bytes < 50 * u64::from(LOG_PAGE_BYTES)
            || !logfile_bytes.is_multiple_of(u64::from(LOG_PAGE_BYTES))
        {
            return Err(corrupt(0, "invalid or uninitialized $LogFile::$DATA"));
        }

        let storage_identity = NtfsStorageIdentity {
            volume_serial: geometry.serial(),
            volume_bytes: geometry.volume_bytes(),
            cluster_bytes: geometry.cluster_bytes(),
            record_bytes: geometry.record_bytes(),
            index_bytes: geometry.index_bytes(),
            mft_cluster: geometry.mft_cluster(),
            mirror_cluster: geometry.mirror_cluster(),
            boot_blake3,
            file_dev_ino,
        };

        let mut engine = Self {
            device: bounded,
            geometry,
            storage_identity,
            upcase,
            logfile_runs,
            logfile_bytes,
            ring: None,
            recovery_required: false,
            open_attrs: BTreeMap::new(),
            next_tx_slot_index: 0,
            generation: 0,
            last_recovery: None,
            trace: Vec::new(),
            next_seq: 1,
            committed_renames: BTreeMap::new(),
            stage_hook: None,
        };

        // Refuse active Hibernation / Fast Startup (`hiberfil.sys`), incompatible
        // `$AttrDef`, or active `$Extend` secondary journals/quotas before any write!
        engine.refuse_hibernation_or_txf(cx, &mft_runs)?;
        engine.validate_attrdef_and_extend_admission(cx, &mft0, &mft_runs)?;
        engine.load_clean_ring_if_present(cx)?;
        Ok(engine)
    }

    fn validate_attrdef_and_extend_admission(
        &self,
        cx: &Cx,
        mft0: &NtfsFileRecord,
        mft_runs: &[NtfsRun],
    ) -> Result<()> {
        let (_, _, mft_init_bytes) =
            extract_plain_nonresident_stream(&self.geometry, mft0, DATA, &[])?;
        let init_records = mft_init_bytes / u64::from(self.geometry.record_bytes());
        let mft_bm = self.read_system_stream_bounded(cx, mft0, 0xB0, &[], 4 * 1024 * 1024)?;
        let slot_allocated = |slot: u32| -> bool {
            let bit_idx = u64::from(slot);
            if bit_idx >= init_records {
                return false;
            }
            let byte_idx = (bit_idx / 8) as usize;
            byte_idx < mft_bm.len() && (mft_bm[byte_idx] & (1_u8 << (bit_idx % 8))) != 0
        };

        // 1. Validate $AttrDef (record 4) when allocated on the volume.
        if slot_allocated(4) {
            let attrdef_rec =
                read_mft_record_via_runs(&self.device, cx, &self.geometry, mft_runs, 4)?;
            for attr in attrdef_rec.attributes().map_err(|err| parse_err(&err))? {
                if attr.flags & (COMPRESSED | ENCRYPTED | SPARSE) != 0 || attr.kind == 0x100 {
                    return Err(unsupported(
                        "$AttrDef carries unsupported compressed/encrypted/sparse/TxF metadata",
                    ));
                }
            }
            let attrdef_bytes =
                self.read_system_stream_bounded(cx, &attrdef_rec, DATA, &[], 65_536)?;
            let defs = parse_attr_def_table(&attrdef_bytes).map_err(|err| parse_err(&err))?;
            validate_ntfs31_attr_def_table(&defs)
                .map_err(|err| unsupported(format!("incompatible NTFS $AttrDef schema: {err}")))?;
        }

        // 2. Validate $Extend (record 11) secondary indexes when allocated on the volume.
        if slot_allocated(11) {
            let extend_rec =
                read_mft_record_via_runs(&self.device, cx, &self.geometry, mft_runs, 11)?;
            for attr in extend_rec.attributes().map_err(|err| parse_err(&err))? {
                if attr.flags & (COMPRESSED | ENCRYPTED | SPARSE) != 0 || attr.kind == 0x100 {
                    return Err(unsupported(
                        "$Extend carries unsupported compressed/encrypted/sparse/TxF metadata",
                    ));
                }
            }

            // Refuse active $UsnJrnl ($J / $Max / $DATA).
            if let Some(usn_ref) =
                self.lookup_in_directory_raw(cx, mft_runs, &extend_rec, &USNJRNL_UPPER)?
            {
                let usn_no = u32::try_from(usn_ref.record)
                    .map_err(|_| corrupt(0, "$UsnJrnl record number overflow"))?;
                let usn_rec =
                    read_mft_record_via_runs(&self.device, cx, &self.geometry, mft_runs, usn_no)?;
                if usn_rec.sequence != usn_ref.sequence {
                    return Err(corrupt(0, "stale $Extend/$UsnJrnl directory entry"));
                }
                for attr in usn_rec.attributes().map_err(|err| parse_err(&err))? {
                    if attr.kind == ATTRIBUTE_LIST || attr.kind == DATA || attr.kind == 0x100 {
                        return Err(unsupported(
                            "active NTFS $UsnJrnl change journal is refused for native writes",
                        ));
                    }
                }
            }

            // Refuse active $Quota tracking or enforcement ($Q index).
            if let Some(quota_ref) =
                self.lookup_in_directory_raw(cx, mft_runs, &extend_rec, &QUOTA_UPPER)?
            {
                let quota_no = u32::try_from(quota_ref.record)
                    .map_err(|_| corrupt(0, "$Quota record number overflow"))?;
                let quota_rec =
                    read_mft_record_via_runs(&self.device, cx, &self.geometry, mft_runs, quota_no)?;
                if quota_rec.sequence != quota_ref.sequence {
                    return Err(corrupt(0, "stale $Extend/$Quota directory entry"));
                }
                Self::validate_inactive_quota_record(&quota_rec)?;
            }
        }
        Ok(())
    }

    fn validate_inactive_quota_record(quota_rec: &NtfsFileRecord) -> Result<()> {
        let mut found_root = false;
        for attr in quota_rec.attributes().map_err(|err| parse_err(&err))? {
            if attr.flags != 0 || attr.kind == ATTRIBUTE_LIST || attr.kind == 0x100 {
                return Err(unsupported(
                    "NTFS $Quota with transformed attributes, extension catalog or $TXF_DATA is refused",
                ));
            }
            if attr.kind == 0xA0 && attr.name == DOLLAR_Q_NAME {
                return Err(unsupported(
                    "NTFS $Quota with external $Q index blocks is refused",
                ));
            }
            if attr.kind == 0x90 && attr.name == DOLLAR_Q_NAME {
                if found_root {
                    return Err(corrupt(0, "duplicate $Quota::$Q INDEX_ROOT"));
                }
                let NtfsValue::Resident(ir) = attr.value else {
                    return Err(corrupt(0, "nonresident $Quota::$Q INDEX_ROOT"));
                };
                Self::validate_inactive_quota_root(ir)?;
                found_root = true;
            }
        }
        if !found_root {
            return Err(unsupported(
                "NTFS $Quota lacks a verifiable default $Q state",
            ));
        }
        Ok(())
    }

    fn validate_inactive_quota_root(ir: &[u8]) -> Result<()> {
        if ir.len() < 48 || ir[..4] != [0; 4] || ir[4..8] != 16_u32.to_le_bytes() {
            return Err(corrupt(0, "invalid $Quota::$Q INDEX_ROOT schema"));
        }
        // $Q uses unsigned 32-bit owner keys, not FILE_NAME collation. The
        // complete resident tree must be examined before trusting its defaults.
        if ir[28] != 0 {
            return Err(unsupported(
                "NTFS $Quota with external or unknown $Q B-tree flags is refused",
            ));
        }
        let entries_off = u32::from_le_bytes([ir[16], ir[17], ir[18], ir[19]]) as usize;
        let total_bytes = u32::from_le_bytes([ir[20], ir[21], ir[22], ir[23]]) as usize;
        let allocated = u32::from_le_bytes([ir[24], ir[25], ir[26], ir[27]]) as usize;
        if entries_off < 16
            || !entries_off.is_multiple_of(8)
            || entries_off > total_bytes
            || total_bytes > allocated
            || allocated > ir.len() - 16
            || ir[13..16] != [0; 3]
            || ir[29..32] != [0; 3]
        {
            return Err(corrupt(0, "out-of-bounds $Quota::$Q INDEX_ROOT entries"));
        }
        let mut pos = 16 + entries_off;
        let end = 16 + total_bytes;
        let mut previous_owner = 0;
        let mut found_default = false;
        while pos < end {
            let entry = &ir[pos..end];
            if entry.len() < 16 {
                return Err(corrupt(0, "truncated $Quota::$Q index entry header"));
            }
            let data_off = usize::from(u16::from_le_bytes([entry[0], entry[1]]));
            let data_len = usize::from(u16::from_le_bytes([entry[2], entry[3]]));
            let entry_len = usize::from(u16::from_le_bytes([entry[8], entry[9]]));
            let key_len = usize::from(u16::from_le_bytes([entry[10], entry[11]]));
            let flags = u16::from_le_bytes([entry[12], entry[13]]);
            if entry_len < 16
                || !entry_len.is_multiple_of(8)
                || entry_len > entry.len()
                || entry[4..8] != [0; 4]
                || entry[14..16] != [0; 2]
                || flags & !3 != 0
            {
                return Err(corrupt(0, "invalid $Quota::$Q index entry header"));
            }
            if flags & 1 != 0 {
                return Err(unsupported("NTFS $Quota subnode pointer is refused"));
            }
            if flags & 2 != 0 {
                if entry_len != 16
                    || entry_len != entry.len()
                    || key_len != 0
                    || data_off != 0
                    || data_len != 0
                    || !found_default
                {
                    return Err(corrupt(
                        0,
                        "invalid $Quota::$Q terminal or missing defaults",
                    ));
                }
                return Ok(());
            }
            if key_len != 4
                || entry_len < 20
                || data_off < 20
                || data_off > entry_len
                || data_len > entry_len - data_off
            {
                return Err(corrupt(0, "invalid $Quota::$Q key or payload bounds"));
            }
            let owner = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);
            if owner <= previous_owner {
                return Err(corrupt(0, "unordered or duplicate $Quota::$Q owner IDs"));
            }
            Self::validate_inactive_quota_entry(owner, &entry[data_off..data_off + data_len])?;
            found_default |= owner == 1;
            previous_owner = owner;
            pos += entry_len;
        }
        Err(corrupt(0, "missing $Quota::$Q terminal entry"))
    }

    fn validate_inactive_quota_entry(owner: u32, data: &[u8]) -> Result<()> {
        // NTFS-3G 2022.10.3 mkntfs.c::initialize_quota seeds owner 0x100
        // (S-1-5-32-544, builtin Administrators) even with tracking disabled.
        // Admit only that unused bootstrap entry, never arbitrary user quotas.
        // QUOTA_CONTROL_ENTRY/QUOTA_FLAGS: NTFS-3G layout.h and Linux v6.7
        // fs/ntfs/layout.h; pending deletes is 0x800, not 0x100.
        const ADMINISTRATORS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
        let expected_len = match owner {
            1 => 48,
            0x100 => 64,
            _ => {
                return Err(unsupported(
                    "non-bootstrap per-user NTFS $Quota entries are refused",
                ));
            }
        };
        if data.len() != expected_len {
            return Err(corrupt(0, "invalid $Quota::$Q control entry length"));
        }
        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version != 2 || flags & !1 != 0 || (owner == 0x100 && flags != 1) {
            return Err(unsupported(format!(
                "active or unknown NTFS $Quota state (version {version}, flags {flags:#x}) is refused"
            )));
        }
        if data[8..16] != [0; 8] || data[24..40] != [0xFF; 16] || data[40..48] != [0; 8] {
            return Err(unsupported(
                "initialized or limited NTFS $Quota accounting is refused",
            ));
        }
        if owner == 0x100 && data[48..64] != ADMINISTRATORS {
            return Err(unsupported(
                "non-bootstrap NTFS $Quota owner SID is refused",
            ));
        }
        Ok(())
    }

    fn read_system_stream_bounded(
        &self,
        cx: &Cx,
        record: &NtfsFileRecord,
        kind: u32,
        name: &[u16],
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        for attr in record.attributes().map_err(|err| parse_err(&err))? {
            if attr.kind == kind && attr.name == name {
                return match attr.value {
                    NtfsValue::Resident(bytes) => {
                        if bytes.len() > max_bytes {
                            return Err(unsupported("system attribute exceeds admission cap"));
                        }
                        Ok(bytes.to_vec())
                    }
                    NtfsValue::NonResident(nr) => {
                        if attr.flags != 0 || nr.first_vcn != 0 {
                            return Err(unsupported("transformed or fragmented system attribute"));
                        }
                        if nr.data_bytes > max_bytes as u64 || nr.initialized_bytes < nr.data_bytes
                        {
                            return Err(unsupported(
                                "oversized or uninitialized system attribute stream",
                            ));
                        }
                        let runs = decode_mapping_pairs(
                            nr.mapping_pairs,
                            nr.first_vcn,
                            nr.last_vcn,
                            self.geometry.cluster_count(),
                        )
                        .map_err(|err| parse_err(&err))?;
                        read_mapped_runs(
                            &self.device,
                            cx,
                            &self.geometry,
                            &runs,
                            0,
                            nr.data_bytes as usize,
                        )
                    }
                };
            }
        }
        Err(FfsError::NotFound(format!(
            "system attribute {kind:#x} not found on record {}",
            record.number
        )))
    }

    fn refuse_hibernation_or_txf(&self, cx: &Cx, mft_runs: &[NtfsRun]) -> Result<()> {
        let root_rec = read_mft_record_via_runs(&self.device, cx, &self.geometry, mft_runs, 5)?;
        for attr in root_rec.attributes().map_err(|err| parse_err(&err))? {
            if attr.kind == 0x100 {
                return Err(unsupported(
                    "NTFS root directory carries $TXF_DATA; refusing native write",
                ));
            }
        }
        // Scan root directory entries via our index lookup for hiberfil.sys.
        if let Some(hiber_ref) =
            self.lookup_in_directory_raw(cx, mft_runs, &root_rec, &HIBERFIL_UPPER)?
        {
            let hiber_rec = read_mft_record_via_runs(
                &self.device,
                cx,
                &self.geometry,
                mft_runs,
                u32::try_from(hiber_ref.record)
                    .map_err(|_| corrupt(0, "hiberfil record overflow"))?,
            )?;
            let header_bytes = self.read_file_prefix_raw(cx, &hiber_rec, 4096)?;
            if !header_bytes.is_empty()
                && (header_bytes.len() < 4096 || header_bytes.iter().any(|&b| b != 0))
            {
                return Err(unsupported(
                    "NTFS hibernation / Windows Fast Startup active in hiberfil.sys; refusing native write",
                ));
            }
        }
        Ok(())
    }

    fn read_file_prefix_raw(
        &self,
        cx: &Cx,
        record: &NtfsFileRecord,
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        for attr in record.attributes().map_err(|err| parse_err(&err))? {
            if attr.kind == DATA && attr.name.is_empty() {
                return match attr.value {
                    NtfsValue::Resident(bytes) => Ok(bytes[..bytes.len().min(max_bytes)].to_vec()),
                    NtfsValue::NonResident(nr) => {
                        if nr.data_bytes == 0 || nr.initialized_bytes == 0 {
                            return Ok(Vec::new());
                        }
                        let runs = decode_mapping_pairs(
                            nr.mapping_pairs,
                            nr.first_vcn,
                            nr.last_vcn,
                            self.geometry.cluster_count(),
                        )
                        .map_err(|err| parse_err(&err))?;
                        let to_read =
                            (nr.initialized_bytes.min(nr.data_bytes) as usize).min(max_bytes);
                        read_mapped_runs(&self.device, cx, &self.geometry, &runs, 0, to_read)
                    }
                };
            }
        }
        Ok(Vec::new())
    }

    fn read_volume_status_and_mft_counts(&self, cx: &Cx) -> Result<(u16, u64, u64)> {
        let mft0 = self.read_mft_record_zero(cx)?;
        let (_, mft_size, mft_init) =
            extract_plain_nonresident_stream(&self.geometry, &mft0, DATA, &[])?;
        let mft_runs = extract_plain_nonresident_runs(&self.geometry, &mft0, DATA, &[])?;
        let vol_rec = read_mft_record_via_runs(&self.device, cx, &self.geometry, &mft_runs, 3)?;
        let vol_info = extract_resident_attr(&vol_rec, VOLUME_INFORMATION, &[])?;
        let flags = u16::from_le_bytes([vol_info[10], vol_info[11]]);
        let rec_bytes = u64::from(self.geometry.record_bytes());
        Ok((flags, mft_size / rec_bytes, mft_init / rec_bytes))
    }

    fn needs_recovery_on_open(&self, cx: &Cx) -> Result<bool> {
        let (vol_flags, _, _) = self.read_volume_status_and_mft_counts(cx)?;
        let log_state = self.inspect_log_state(cx)?;
        Ok((vol_flags & 0x0001 != 0) || !log_state.clean || log_state.torn_rstr_slot.is_some())
    }

    #[must_use]
    pub const fn geometry(&self) -> &NtfsGeometry {
        &self.geometry
    }

    #[must_use]
    pub const fn storage_identity(&self) -> &NtfsStorageIdentity {
        &self.storage_identity
    }

    #[must_use]
    pub const fn last_recovery(&self) -> Option<&NtfsRecoverySummary> {
        self.last_recovery.as_ref()
    }

    /// Whether a failed publication requires native recovery before this
    /// engine can issue another transaction or acknowledge synchronization.
    /// A known-uncommitted operation can still leave dirty restart pages.
    #[must_use]
    pub const fn requires_recovery(&self) -> bool {
        self.recovery_required
    }

    pub(super) fn require_clean_writer(&self) -> Result<()> {
        if self.recovery_required {
            return Err(FfsError::RequestRejected {
                errno: libc::EIO,
                detail: "NTFS journal publication is incomplete; native recovery is required before another transaction".into(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn persistence_trace(&self) -> &[NtfsPersistenceEvent] {
        &self.trace
    }

    pub fn take_persistence_trace(&mut self) -> Vec<NtfsPersistenceEvent> {
        std::mem::take(&mut self.trace)
    }

    /// Install or clear a post-stage callback (used by persistence-prefix / fault-cut tests).
    pub fn set_stage_hook(&mut self, hook: Option<NtfsStageHook>) {
        self.stage_hook = hook;
    }

    #[must_use]
    pub fn upcase(&self) -> &[u16] {
        &self.upcase
    }

    /// Explicitly synchronize the underlying backing storage (`fsync` / `sync_fs`).
    pub fn sync_device(&mut self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        self.require_clean_writer()?;
        self.device.sync(cx)
    }

    /// Construct a fresh read-only [`NtfsVolume`] view over the current backing storage.
    pub fn volume_view(&self, cx: &Cx) -> Result<NtfsVolume> {
        NtfsVolume::from_device(
            cx,
            Box::new(ReadOnlyDeviceRef(Arc::clone(&self.device))),
            0,
            self.geometry.volume_bytes(),
        )
    }

    /// Run all independent read-only consistency checkers (`check_allocations`,
    /// `check_record_ownership`, `check_mft_mirror`, `check_namespace`, plus
    /// `check_security_references` whenever `$Secure` record 9 is allocated) on a
    /// fresh [`NtfsVolume`] view and refuse if any reports an inconsistency.
    pub fn check_clean_consistency(&self, cx: &Cx) -> Result<()> {
        let volume = self.volume_view(cx)?;
        let alloc = volume.check_allocations(cx, AllocationLimits::default())?;
        if !alloc.is_consistent() {
            return Err(corrupt(
                0,
                format!("NTFS allocation check failed: {:?}", alloc.issues.first()),
            ));
        }
        let own = volume.check_record_ownership(cx, RecordOwnershipLimits::default())?;
        if !own.is_consistent() {
            return Err(corrupt(
                0,
                format!(
                    "NTFS record ownership check failed: {:?}",
                    own.issues.first()
                ),
            ));
        }
        let mirror = volume.check_mft_mirror(cx, RecordOwnershipLimits::default())?;
        if !mirror.is_consistent() {
            return Err(corrupt(
                0,
                format!("NTFS $MFTMirr check failed: {:?}", mirror.issues.first()),
            ));
        }
        let ns = volume.check_namespace(cx, NamespaceLimits::default())?;
        if !ns.is_consistent() {
            return Err(corrupt(
                0,
                format!("NTFS namespace check failed: {:?}", ns.issues.first()),
            ));
        }
        if self.is_mft_slot_allocated(cx, 9)? {
            let sec =
                volume.check_security_references(cx, SecurityCheckLimits::default(), 1_048_576)?;
            if sec.limit_reached.is_some()
                || sec.errors != 0
                || sec.missing_shared_references != 0
                || sec.extensions_without_owner.unwrap_or(0) != 0
            {
                return Err(corrupt(
                    0,
                    format!("NTFS $Secure check failed: {:?}", sec.issues.first()),
                ));
            }
        }
        Ok(())
    }

    fn is_mft_slot_allocated(&self, cx: &Cx, slot: u32) -> Result<bool> {
        let mft0 = self.read_mft_record_zero(cx)?;
        let (_, _, mft_init_bytes) =
            extract_plain_nonresident_stream(&self.geometry, &mft0, DATA, &[])?;
        let init_records = mft_init_bytes / u64::from(self.geometry.record_bytes());
        let bit_idx = u64::from(slot);
        if bit_idx >= init_records {
            return Ok(false);
        }
        let mft_bm = self.read_system_stream_bounded(cx, &mft0, 0xB0, &[], 4 * 1024 * 1024)?;
        let byte_idx = (bit_idx / 8) as usize;
        Ok(byte_idx < mft_bm.len() && (mft_bm[byte_idx] & (1_u8 << (bit_idx % 8))) != 0)
    }

    pub(super) fn record_event_checked(
        &mut self,
        operation: &str,
        stage: NtfsPersistenceStage,
        transaction_id: u32,
        lsn: u64,
        offset: u64,
        bytes: usize,
    ) -> Result<()> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let event = NtfsPersistenceEvent {
            seq,
            operation: operation.to_owned(),
            stage,
            transaction_id,
            lsn,
            offset,
            bytes,
        };
        self.trace.push(event.clone());
        if let Some(hook) = self.stage_hook.as_mut() {
            hook(&event)?;
        }
        Ok(())
    }

    pub(super) fn read_volume(&self, cx: &Cx, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.device.read_exact_at(cx, ByteOffset(offset), buf)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_volume(
        &mut self,
        cx: &Cx,
        operation: &str,
        stage: NtfsPersistenceStage,
        transaction_id: u32,
        lsn: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        self.device.write_all_at(cx, ByteOffset(offset), data)?;
        self.record_event_checked(operation, stage, transaction_id, lsn, offset, data.len())
    }

    pub(super) fn barrier(
        &mut self,
        cx: &Cx,
        operation: &str,
        stage: NtfsPersistenceStage,
        transaction_id: u32,
        lsn: u64,
    ) -> Result<()> {
        self.device.sync(cx)?;
        self.record_event_checked(operation, stage, transaction_id, lsn, 0, 0)
    }

    pub(super) fn read_logfile(&self, cx: &Cx, vbo: u64, size: usize) -> Result<Vec<u8>> {
        if vbo
            .checked_add(size as u64)
            .is_none_or(|end| end > self.logfile_bytes)
        {
            return Err(corrupt(vbo, "$LogFile read exceeds stream size"));
        }
        read_mapped_runs(
            &self.device,
            cx,
            &self.geometry,
            &self.logfile_runs,
            vbo,
            size,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_logfile_page(
        &mut self,
        cx: &Cx,
        operation: &str,
        stage: NtfsPersistenceStage,
        transaction_id: u32,
        lsn: u64,
        vbo: u64,
        page: &[u8],
    ) -> Result<()> {
        if vbo
            .checked_add(page.len() as u64)
            .is_none_or(|end| end > self.logfile_bytes)
        {
            return Err(corrupt(vbo, "$LogFile write exceeds stream size"));
        }
        write_mapped_runs(
            &self.device,
            cx,
            &self.geometry,
            &self.logfile_runs,
            vbo,
            page,
        )?;
        self.record_event_checked(operation, stage, transaction_id, lsn, vbo, page.len())
    }

    pub(super) fn read_mft_record_zero(&self, cx: &Cx) -> Result<NtfsFileRecord> {
        let mft0_off = self
            .geometry
            .cluster_offset(self.geometry.mft_cluster())
            .map_err(|err| parse_err(&err))?;
        let mut raw = vec![0_u8; self.geometry.record_bytes() as usize];
        self.read_volume(cx, mft0_off, &mut raw)?;
        NtfsFileRecord::parse(&raw).map_err(|err| parse_err(&err))
    }

    pub(super) fn allocate_tx_id(&mut self) -> u32 {
        let idx = self.next_tx_slot_index % 64;
        self.next_tx_slot_index = self.next_tx_slot_index.wrapping_add(1);
        24 + idx * 40
    }

    /// Initialize a virgin (`0xFF`) `$LogFile` with an initial clean `LFS_CLIENT_RESTART`
    /// checkpoint and dual clean `RSTR` pages before appending client transactions.
    pub(super) fn ensure_ring_initialized(&mut self, cx: &Cx, operation: &str) -> Result<()> {
        self.require_clean_writer()?;
        if self.ring.is_some() {
            return Ok(());
        }
        let mut ring =
            NtfsLogRingWriter::new_fresh(LOG_PAGE_BYTES, (1, 1), self.logfile_bytes, 1, 1)
                .map_err(|err| parse_err(&err))?;
        let ckpt = NtfsCheckpointPayload::default()
            .encode()
            .map_err(|err| parse_err(&err))?;
        let rec = ring
            .append_raw_record(LFS_RECORD_CLIENT_RESTART, 0, 0, 0, &ckpt)
            .map_err(|err| parse_err(&err))?;
        // A failed initialization must not be mistaken for an erased journal
        // on the next request. Even the first target write can fail partially.
        self.recovery_required = true;
        self.write_logfile_page(
            cx,
            operation,
            NtfsPersistenceStage::CheckpointWrite,
            0,
            rec.lsn,
            rec.page_vbo,
            &rec.protected_page,
        )?;
        self.barrier(
            cx,
            operation,
            NtfsPersistenceStage::TargetMetadataBarrier,
            0,
            rec.lsn,
        )?;

        let rstr_a = ring
            .build_next_rstr_page(true)
            .map_err(|err| parse_err(&err))?;
        self.write_logfile_page(
            cx,
            operation,
            NtfsPersistenceStage::CleanRestartSlotAWrite,
            0,
            rec.lsn,
            rstr_a.page_vbo,
            &rstr_a.bytes,
        )?;
        self.barrier(
            cx,
            operation,
            NtfsPersistenceStage::CleanRestartSlotABarrier,
            0,
            rec.lsn,
        )?;

        let rstr_b = ring
            .build_next_rstr_page(true)
            .map_err(|err| parse_err(&err))?;
        self.write_logfile_page(
            cx,
            operation,
            NtfsPersistenceStage::CleanRestartSlotBWrite,
            0,
            rec.lsn,
            rstr_b.page_vbo,
            &rstr_b.bytes,
        )?;
        self.barrier(
            cx,
            operation,
            NtfsPersistenceStage::CleanRestartSlotBBarrier,
            0,
            rec.lsn,
        )?;

        self.open_attrs.clear();
        self.ring = Some(ring);
        self.recovery_required = false;
        Ok(())
    }

    /// Write a clean checkpoint (`0x1D` + `0x1E` if open attributes exist + `LFS_CLIENT_RESTART`)
    /// advancing `oldest_lsn` so the `$LogFile` ring can reclaim old pages cleanly,
    /// followed by alternating clean `RSTR` slot A + barrier + slot B + barrier.
    pub(super) fn publish_clean_checkpoint_and_rstr(
        &mut self,
        cx: &Cx,
        operation: &str,
        tx_id: u32,
    ) -> Result<u64> {
        let (pages_to_write, ckpt_lsn, rstr_a, rstr_b) = {
            let ring = self
                .ring
                .as_mut()
                .ok_or_else(|| corrupt(0, "missing initialized $LogFile ring"))?;
            let mut pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            let mut open_table_lsn = 0_u64;
            let mut attr_table_bytes = 0_u32;
            let mut names_lsn = 0_u64;
            let mut attr_names_bytes = 0_u32;
            let mut start_lsn = 0_u64;

            if !self.open_attrs.is_empty() {
                let mut attr_entries = BTreeMap::new();
                let mut attr_names = BTreeMap::new();
                for (&slot, info) in &self.open_attrs {
                    let entry = encode_open_attribute_entry(
                        info.kind,
                        info.index_bytes,
                        info.reference_raw,
                        info.opened_lsn,
                    );
                    attr_entries.insert(slot, entry.to_vec());
                    if !info.name.is_empty() {
                        attr_names.insert(slot, info.name.clone());
                    }
                }
                let attr_dump =
                    encode_restart_table(40, &attr_entries).map_err(|err| parse_err(&err))?;
                let attr_dump_len =
                    u32::try_from(attr_dump.len()).map_err(|_| corrupt(0, "attr_dump overflow"))?;
                let attr_spec = NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::OpenAttributeTableDump,
                    undo_op: NtfsLogOp::Noop,
                    target_attribute: 0,
                    record_offset: 0,
                    attribute_offset: 0,
                    cluster_block_offset: 0,
                    target_vcn: 0,
                    target_lcns: Vec::new(),
                    redo_data: attr_dump,
                    undo_data: Vec::new(),
                };
                let attr_payload =
                    encode_client_update_payload(&attr_spec).map_err(|err| parse_err(&err))?;
                let dump_tx = tx_id.max(24);
                let rec = ring
                    .append_raw_record(LFS_RECORD_CLIENT, dump_tx, 0, 0, &attr_payload)
                    .map_err(|err| map_ring_err(&err))?;
                start_lsn = rec.lsn;
                open_table_lsn = rec.lsn;
                attr_table_bytes = attr_dump_len;
                pages.insert(rec.page_vbo, rec.protected_page);

                if !attr_names.is_empty() {
                    let names_dump =
                        encode_attribute_names_dump(&attr_names).map_err(|err| parse_err(&err))?;
                    let names_dump_len = u32::try_from(names_dump.len())
                        .map_err(|_| corrupt(0, "names_dump overflow"))?;
                    let names_spec = NtfsClientUpdateSpec {
                        redo_op: NtfsLogOp::AttributeNamesDump,
                        undo_op: NtfsLogOp::Noop,
                        target_attribute: 0,
                        record_offset: 0,
                        attribute_offset: 0,
                        cluster_block_offset: 0,
                        target_vcn: 0,
                        target_lcns: Vec::new(),
                        redo_data: names_dump,
                        undo_data: Vec::new(),
                    };
                    let names_payload =
                        encode_client_update_payload(&names_spec).map_err(|err| parse_err(&err))?;
                    let nrec = ring
                        .append_raw_record(
                            LFS_RECORD_CLIENT,
                            dump_tx,
                            open_table_lsn,
                            0,
                            &names_payload,
                        )
                        .map_err(|err| map_ring_err(&err))?;
                    names_lsn = nrec.lsn;
                    attr_names_bytes = names_dump_len;
                    pages.insert(nrec.page_vbo, nrec.protected_page);
                }

                // Close the ephemeral dump transaction slot cleanly with ForgetTransaction.
                let forget_payload = encode_client_update_payload(&NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::ForgetTransaction,
                    undo_op: NtfsLogOp::Noop,
                    target_attribute: 0,
                    record_offset: 0,
                    attribute_offset: 0,
                    cluster_block_offset: 0,
                    target_vcn: 0,
                    target_lcns: Vec::new(),
                    redo_data: Vec::new(),
                    undo_data: Vec::new(),
                })
                .map_err(|err| parse_err(&err))?;
                let prev = if names_lsn != 0 {
                    names_lsn
                } else {
                    open_table_lsn
                };
                let frec = ring
                    .append_raw_record(LFS_RECORD_CLIENT, dump_tx, prev, 0, &forget_payload)
                    .map_err(|err| map_ring_err(&err))?;
                pages.insert(frec.page_vbo, frec.protected_page);
            }

            let ckpt_bytes = NtfsCheckpointPayload {
                start_of_checkpoint_lsn: start_lsn,
                open_attribute_table_lsn: open_table_lsn,
                open_attribute_table_len: attr_table_bytes,
                attribute_names_lsn: names_lsn,
                attribute_names_len: attr_names_bytes,
                dirty_page_table_lsn: 0,
                dirty_page_table_len: 0,
                transaction_table_lsn: 0,
                transaction_table_len: 0,
            }
            .encode()
            .map_err(|err| parse_err(&err))?;
            let ckpt_rec = ring
                .append_raw_record(LFS_RECORD_CLIENT_RESTART, 0, 0, 0, &ckpt_bytes)
                .map_err(|err| map_ring_err(&err))?;
            pages.insert(ckpt_rec.page_vbo, ckpt_rec.protected_page);

            let new_oldest = if start_lsn != 0 {
                start_lsn
            } else {
                ckpt_rec.lsn
            };
            // Update open_attrs opened_lsn <= new_oldest so checkpoint seed stays valid.
            for info in self.open_attrs.values_mut() {
                if info.opened_lsn == 0 || info.opened_lsn > new_oldest {
                    info.opened_lsn = new_oldest;
                }
            }
            ring.advance_oldest_lsn(new_oldest)
                .map_err(|err| parse_err(&err))?;

            let rstr_a = ring
                .build_next_rstr_page(true)
                .map_err(|err| parse_err(&err))?;
            let rstr_b = ring
                .build_next_rstr_page(true)
                .map_err(|err| parse_err(&err))?;
            let staged_vec: Vec<StagedLogPage> = pages
                .into_iter()
                .map(|(page_vbo, bytes)| StagedLogPage { page_vbo, bytes })
                .collect();
            (staged_vec, ckpt_rec.lsn, rstr_a, rstr_b)
        };

        for page in &pages_to_write {
            self.write_logfile_page(
                cx,
                operation,
                NtfsPersistenceStage::CheckpointWrite,
                tx_id,
                ckpt_lsn,
                page.page_vbo,
                &page.bytes,
            )?;
        }
        self.barrier(
            cx,
            operation,
            NtfsPersistenceStage::TargetMetadataBarrier,
            tx_id,
            ckpt_lsn,
        )?;

        self.write_logfile_page(
            cx,
            operation,
            NtfsPersistenceStage::CleanRestartSlotAWrite,
            tx_id,
            ckpt_lsn,
            rstr_a.page_vbo,
            &rstr_a.bytes,
        )?;
        self.barrier(
            cx,
            operation,
            NtfsPersistenceStage::CleanRestartSlotABarrier,
            tx_id,
            ckpt_lsn,
        )?;

        self.write_logfile_page(
            cx,
            operation,
            NtfsPersistenceStage::CleanRestartSlotBWrite,
            tx_id,
            ckpt_lsn,
            rstr_b.page_vbo,
            &rstr_b.bytes,
        )?;
        self.barrier(
            cx,
            operation,
            NtfsPersistenceStage::CleanRestartSlotBBarrier,
            tx_id,
            ckpt_lsn,
        )?;
        Ok(ckpt_lsn)
    }

    pub(super) fn make_token(
        &mut self,
        transaction_id: u32,
        commit_lsn: u64,
        checkpoint_lsn: Option<u64>,
        operation_digest: [u8; 32],
    ) -> NtfsDurableToken {
        self.generation += 1;
        NtfsDurableToken {
            storage: self.storage_identity.clone(),
            transaction_id,
            commit_lsn,
            checkpoint_lsn,
            generation: self.generation,
            operation_digest,
        }
    }
}

pub(super) fn map_ring_err(err: &ParseError) -> FfsError {
    let text = err.to_string();
    if text.contains("ring full") {
        FfsError::NoSpace
    } else {
        parse_err(err)
    }
}

pub(super) fn same_logical_record(left: &NtfsFileRecord, right: &NtfsFileRecord) -> bool {
    let a = left.used_bytes();
    let b = right.used_bytes();
    if a.len() != b.len() || a.len() < 48 {
        return false;
    }
    let usa = usize::from(u16::from_le_bytes([a[4], a[5]]));
    let usa_end = usa + 2 * usize::from(u16::from_le_bytes([a[6], a[7]]));
    usa_end <= a.len() && a[..usa] == b[..usa] && a[usa_end..] == b[usa_end..]
}

pub(super) fn extract_resident_attr(
    record: &NtfsFileRecord,
    kind: u32,
    name: &[u16],
) -> Result<Vec<u8>> {
    for attr in record.attributes().map_err(|err| parse_err(&err))? {
        if attr.kind == kind && attr.name == name {
            let NtfsValue::Resident(bytes) = attr.value else {
                return Err(corrupt(0, "expected resident NTFS attribute"));
            };
            return Ok(bytes.to_vec());
        }
    }
    Err(FfsError::NotFound(format!(
        "resident attribute {kind:#x} not found on record {}",
        record.number
    )))
}

pub(super) fn extract_plain_nonresident_stream(
    geometry: &NtfsGeometry,
    record: &NtfsFileRecord,
    kind: u32,
    name: &[u16],
) -> Result<(Vec<NtfsRun>, u64, u64)> {
    for attr in record.attributes().map_err(|err| parse_err(&err))? {
        if attr.kind == kind && attr.name == name {
            if attr.flags != 0 {
                return Err(unsupported("transformed nonresident system attribute"));
            }
            let NtfsValue::NonResident(nr) = attr.value else {
                return Err(corrupt(0, "expected nonresident NTFS attribute"));
            };
            if nr.first_vcn != 0 {
                return Err(unsupported("multi-extent system stream not supported"));
            }
            let runs = decode_mapping_pairs(
                nr.mapping_pairs,
                nr.first_vcn,
                nr.last_vcn,
                geometry.cluster_count(),
            )
            .map_err(|err| parse_err(&err))?;
            if runs.iter().any(|r| r.lcn.is_none()) {
                return Err(corrupt(0, "sparse hole in plain nonresident stream"));
            }
            return Ok((runs, nr.data_bytes, nr.initialized_bytes));
        }
    }
    Err(FfsError::NotFound(format!(
        "nonresident attribute {kind:#x} not found on record {}",
        record.number
    )))
}

pub(super) fn extract_plain_nonresident_runs(
    geometry: &NtfsGeometry,
    record: &NtfsFileRecord,
    kind: u32,
    name: &[u16],
) -> Result<Vec<NtfsRun>> {
    Ok(extract_plain_nonresident_stream(geometry, record, kind, name)?.0)
}

pub(super) fn map_logical_offset(
    geometry: &NtfsGeometry,
    runs: &[NtfsRun],
    logical: u64,
) -> Result<(u64, u64, u64)> {
    let cluster_bytes = u64::from(geometry.cluster_bytes());
    let vcn = logical / cluster_bytes;
    let within = logical % cluster_bytes;
    let idx = runs
        .partition_point(|r| r.vcn <= vcn)
        .checked_sub(1)
        .ok_or_else(|| corrupt(logical, "logical offset precedes NTFS runlist"))?;
    let run = &runs[idx];
    let rel_vcn = vcn - run.vcn;
    if rel_vcn >= run.clusters {
        return Err(corrupt(logical, "logical offset falls in NTFS runlist gap"));
    }
    let lcn = run
        .lcn
        .and_then(|start| start.checked_add(rel_vcn))
        .ok_or_else(|| corrupt(logical, "sparse or overflowing NTFS run"))?;
    let phys = geometry
        .cluster_offset(lcn)
        .map_err(|err| parse_err(&err))?
        + within;
    let avail = (run.clusters - rel_vcn) * cluster_bytes - within;
    Ok((phys, avail, lcn))
}

pub(super) fn read_mapped_runs(
    device: &Arc<dyn ByteDevice>,
    cx: &Cx,
    geometry: &NtfsGeometry,
    runs: &[NtfsRun],
    offset: u64,
    size: usize,
) -> Result<Vec<u8>> {
    let mut out = vec![0_u8; size];
    let mut done = 0_usize;
    while done < size {
        checkpoint(cx)?;
        let (phys, avail, _) = map_logical_offset(geometry, runs, offset + done as u64)?;
        let chunk = (size - done).min(avail as usize);
        device.read_exact_at(cx, ByteOffset(phys), &mut out[done..done + chunk])?;
        done += chunk;
    }
    Ok(out)
}

pub(super) fn write_mapped_runs(
    device: &Arc<dyn ByteDevice>,
    cx: &Cx,
    geometry: &NtfsGeometry,
    runs: &[NtfsRun],
    offset: u64,
    data: &[u8],
) -> Result<()> {
    let mut done = 0_usize;
    while done < data.len() {
        checkpoint(cx)?;
        let (phys, avail, _) = map_logical_offset(geometry, runs, offset + done as u64)?;
        let chunk = (data.len() - done).min(avail as usize);
        device.write_all_at(cx, ByteOffset(phys), &data[done..done + chunk])?;
        done += chunk;
    }
    Ok(())
}

pub(super) fn read_mft_record_raw_via_runs(
    device: &Arc<dyn ByteDevice>,
    cx: &Cx,
    geometry: &NtfsGeometry,
    mft_runs: &[NtfsRun],
    number: u32,
) -> Result<Vec<u8>> {
    let rec_bytes = geometry.record_bytes() as usize;
    let logical = u64::from(number) * (rec_bytes as u64);
    read_mapped_runs(device, cx, geometry, mft_runs, logical, rec_bytes)
}

pub(super) fn read_mft_record_via_runs(
    device: &Arc<dyn ByteDevice>,
    cx: &Cx,
    geometry: &NtfsGeometry,
    mft_runs: &[NtfsRun],
    number: u32,
) -> Result<NtfsFileRecord> {
    let raw = read_mft_record_raw_via_runs(device, cx, geometry, mft_runs, number)?;
    let rec = NtfsFileRecord::parse(&raw).map_err(|err| parse_err(&err))?;
    if !rec.in_use() || rec.number != number {
        return Err(FfsError::NotFound(format!(
            "MFT record {number} inactive or mismatched"
        )));
    }
    Ok(rec)
}
