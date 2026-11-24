//! Exclusive single-owner native ZFS ZVOL session manager and safe-Rust
//! fixed-newstyle Network Block Device (NBD) block frontend and client.
//!
//! ZVOLs are exposed strictly as block devices (never regular files in FUSE).
//! [`ZfsVolumeManager`] owns [`ZfsTransactionEngine`] by value, enforcing:
//! - At most one active writable [`ZfsZvolSession`] per volume (`EBUSY` on overlap).
//! - Refusal of `zvol_destroy` while any session holds the volume (`EBUSY`).
//! - Epoch invalidation on `zvol_resize` or `revoke_handles` so stale handles fail
//!   closed with `ESTALE` (translated to `NBD_EIO` on the wire).
//! - Encryption-key unload or replacement invalidates existing sessions, including
//!   cached writeback reads. Loading a key again requires opening a fresh session.
//! - Explicit durability semantics via [`ZvolSyncPolicy::Always`] (default: durable
//!   4-label TXG + [`ZfsDurableToken`] before ack) or [`ZvolSyncPolicy::FlushBarrier`]
//!   (explicit writeback staging committed atomically on `FUA` / `FLUSH`, dropped
//!   cleanly on disconnect before flush).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::crypto::UnwrappedDslKey;
use ffs_ondisk::zfs_zpl::Timestamp;
use ffs_types::ByteOffset;
use serde::Serialize;

use crate::reader::dmu::zvol::Zvol;
use crate::transaction::{
    MAX_ZVOL_IO_BYTES, ZVOL_LOGICAL_SECTOR_BYTES, ZfsCommitReceipt, ZfsDataChecksum,
    ZfsDurableToken, ZfsTransactionEngine, ZfsTxOutcome, ZfsZvolCreateOptions, ZfsZvolInfo,
};

// Fixed-newstyle NBD wire protocol constants (big-endian on wire).
const NBD_MAGIC: u64 = 0x4e42_444d_4147_4943; // "NBDMAGIC"
const NBD_IHAVEOPT: u64 = 0x4948_4156_454f_5054; // "IHAVEOPT"
const NBD_REP_MAGIC: u64 = 0x0003_e889_0455_65a9;
const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;

const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;
const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1 << 0;
const NBD_FLAG_C_NO_ZEROES: u32 = 1 << 1;

pub const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
pub const NBD_FLAG_READ_ONLY: u16 = 1 << 1;
pub const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
pub const NBD_FLAG_SEND_FUA: u16 = 1 << 3;
pub const NBD_FLAG_SEND_TRIM: u16 = 1 << 5;

const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_OPT_ABORT: u32 = 2;
const NBD_OPT_LIST: u32 = 3;
const NBD_OPT_INFO: u32 = 6;
const NBD_OPT_GO: u32 = 7;

const NBD_REP_ACK: u32 = 1;
const NBD_REP_SERVER: u32 = 2;
const NBD_REP_INFO: u32 = 3;
const NBD_REP_ERR_UNSUP: u32 = 0x8000_0001;
const NBD_REP_ERR_INVALID: u32 = 0x8000_0003;
const NBD_REP_ERR_UNKNOWN: u32 = 0x8000_0006;

const NBD_INFO_EXPORT: u16 = 0;
const NBD_INFO_BLOCK_SIZE: u16 = 3;

const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;
const NBD_CMD_TRIM: u16 = 4;

const NBD_CMD_FLAG_FUA: u16 = 1 << 0;

pub const NBD_OK: u32 = 0;
pub const NBD_EPERM: u32 = 1;
pub const NBD_EIO: u32 = 5;
pub const NBD_EINVAL: u32 = 22;
pub const NBD_ENOSPC: u32 = 28;
pub const NBD_ESHUTDOWN: u32 = 108;

const MAX_OPTION_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_STAGED_VOLATILE_BYTES: usize = 64 * 1024 * 1024;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const IO_POLL_TIMEOUT: Duration = Duration::from_millis(200);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn reject_errno(errno: i32, detail: impl Into<String>) -> FfsError {
    FfsError::RequestRejected {
        errno,
        detail: detail.into(),
    }
}

fn map_error_to_nbd(err: &FfsError) -> u32 {
    match err {
        FfsError::ReadOnly | FfsError::PermissionDenied => NBD_EPERM,
        FfsError::NoSpace => NBD_ENOSPC,
        FfsError::Format(_) => NBD_EINVAL,
        FfsError::Cancelled => NBD_ESHUTDOWN,
        FfsError::RequestRejected { errno, .. } => match *errno {
            libc::EPERM | libc::EACCES | libc::EROFS => NBD_EPERM,
            libc::EINVAL => NBD_EINVAL,
            libc::ENOSPC | libc::EDQUOT => NBD_ENOSPC,
            _ => NBD_EIO,
        },
        _ => NBD_EIO,
    }
}

fn map_nbd_to_error(code: u32, op: &str) -> FfsError {
    match code {
        NBD_EPERM => FfsError::ReadOnly,
        NBD_EINVAL => reject_errno(libc::EINVAL, format!("NBD {op} rejected with EINVAL")),
        NBD_ENOSPC => FfsError::NoSpace,
        NBD_ESHUTDOWN => FfsError::Cancelled,
        other => FfsError::Io(std::io::Error::other(format!(
            "NBD {op} failed with wire error {other}"
        ))),
    }
}

/// Write/flush durability policy for a writable [`ZfsZvolSession`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZvolSyncPolicy {
    /// Default: every write and discard commits a native 4-label TXG before acknowledging.
    #[default]
    Always,
    /// Explicit writeback staging: non-FUA writes and discards stage dirty `volblocksize`
    /// blocks in memory (bounded to 64 MiB, serving read-your-own-writes), while `FUA`
    /// writes and `FLUSH` commit all staged blocks atomically in one durable TXG.
    FlushBarrier,
}

/// Explicit durability classification emitted in transport audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZvolAckKind {
    ReadOnly,
    DurableTxg,
    DeviceBarrierVerified,
    StagedVolatile,
    Rejected,
}

/// Structured transport audit entry for every NBD handshake and block command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZvolTransportAuditEntry {
    pub seq: u64,
    pub cmd: String,
    pub offset: u64,
    pub length: u64,
    pub fua: bool,
    pub nbd_error: u32,
    pub ack_kind: ZvolAckKind,
    pub committed_txg: Option<u64>,
    pub published_slot: Option<usize>,
    pub token: Option<ZfsDurableToken>,
}

struct ManagerState {
    engine: ZfsTransactionEngine,
    epochs: BTreeMap<u64, u64>,
    active_writable_leases: BTreeSet<u64>,
    active_readonly_counts: BTreeMap<u64, usize>,
}

impl ManagerState {
    fn current_epoch(&mut self, dataset_guid: u64) -> u64 {
        *self.epochs.entry(dataset_guid).or_insert(1)
    }

    fn bump_epoch(&mut self, dataset_guid: u64) -> u64 {
        let entry = self.epochs.entry(dataset_guid).or_insert(1);
        *entry = entry.saturating_add(1);
        *entry
    }

    fn has_active_sessions(&self, dataset_guid: u64) -> bool {
        self.active_writable_leases.contains(&dataset_guid)
            || self
                .active_readonly_counts
                .get(&dataset_guid)
                .copied()
                .unwrap_or(0)
                > 0
    }

    fn any_active_sessions(&self) -> bool {
        !self.active_writable_leases.is_empty()
            || self.active_readonly_counts.values().any(|&c| c > 0)
    }
}

/// Exclusive single-owner manager binding [`ZfsTransactionEngine`] to epoch-checked
/// [`ZfsZvolSession`] handles. Deliberately `!Clone`.
pub struct ZfsVolumeManager {
    state: Arc<Mutex<ManagerState>>,
}

impl ZfsVolumeManager {
    /// Take exclusive ownership of `engine` by value.
    #[must_use]
    pub fn new(engine: ZfsTransactionEngine) -> Self {
        Self {
            state: Arc::new(Mutex::new(ManagerState {
                engine,
                epochs: BTreeMap::new(),
                active_writable_leases: BTreeSet::new(),
                active_readonly_counts: BTreeMap::new(),
            })),
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, ManagerState>> {
        self.state
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZFS volume manager lock poisoned")))
    }

    /// Reclaim the owned [`ZfsTransactionEngine`] once zero sessions remain open.
    pub fn into_engine(self) -> Result<ZfsTransactionEngine> {
        {
            let guard = self.lock_state()?;
            if guard.any_active_sessions() {
                return Err(reject_errno(
                    libc::EBUSY,
                    "cannot release ZfsTransactionEngine while ZVOL sessions remain open",
                ));
            }
        }
        let mutex = Arc::try_unwrap(self.state).map_err(|_| {
            reject_errno(
                libc::EBUSY,
                "cannot release ZfsTransactionEngine while session handles still reference manager",
            )
        })?;
        let inner = mutex
            .into_inner()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZFS volume manager lock poisoned")))?;
        Ok(inner.engine)
    }

    /// Access the underlying engine's currently committed TXG.
    pub fn committed_txg(&self) -> Result<u64> {
        Ok(self.lock_state()?.engine.committed_txg())
    }

    /// Access the underlying engine's currently committed Uberblock slot.
    pub fn committed_slot(&self) -> Result<usize> {
        Ok(self.lock_state()?.engine.committed_slot())
    }

    /// Create a fresh ZVOL under `parent_dataset`.
    pub fn zvol_create(
        &self,
        cx: &Cx,
        parent_dataset: &[Vec<u8>],
        name: &[u8],
        opts: &ZfsZvolCreateOptions,
    ) -> ZfsTxOutcome<ZfsZvolInfo> {
        let mut guard = match self.lock_state() {
            Ok(g) => g,
            Err(e) => return ZfsTxOutcome::NotCommitted(e),
        };
        let outcome = guard.engine.zvol_create(cx, parent_dataset, name, opts);
        if let ZfsTxOutcome::Committed { ref value, .. } = outcome {
            guard.current_epoch(value.dataset_guid);
        }
        outcome
    }

    /// Inspect metadata of a ZVOL head or snapshot.
    pub fn zvol_info(
        &self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        snapshot: Option<&[u8]>,
    ) -> Result<ZfsZvolInfo> {
        self.lock_state()?.engine.zvol_info(cx, dataset, snapshot)
    }

    /// Destroy a ZVOL head, refusing with `EBUSY` while any session holds it open.
    pub fn zvol_destroy(&self, cx: &Cx, dataset: &[Vec<u8>]) -> ZfsTxOutcome<u64> {
        let mut guard = match self.lock_state() {
            Ok(g) => g,
            Err(e) => return ZfsTxOutcome::NotCommitted(e),
        };
        let info = match guard.engine.zvol_info(cx, dataset, None) {
            Ok(info) => info,
            Err(e) => return ZfsTxOutcome::NotCommitted(e),
        };
        if guard.has_active_sessions(info.dataset_guid) {
            return ZfsTxOutcome::NotCommitted(reject_errno(
                libc::EBUSY,
                "cannot destroy ZVOL while active sessions hold it open",
            ));
        }
        let outcome = guard.engine.zvol_destroy(cx, dataset);
        if outcome.is_committed() {
            guard.bump_epoch(info.dataset_guid);
        }
        outcome
    }

    /// Resize a ZVOL head and bump its handle epoch so any pre-resize sessions fail
    /// closed with `ESTALE` rather than issuing I/O against stale geometry.
    pub fn zvol_resize(&self, cx: &Cx, dataset: &[Vec<u8>], new_volsize: u64) -> ZfsTxOutcome<u64> {
        let mut guard = match self.lock_state() {
            Ok(g) => g,
            Err(e) => return ZfsTxOutcome::NotCommitted(e),
        };
        let info = match guard.engine.zvol_info(cx, dataset, None) {
            Ok(info) => info,
            Err(e) => return ZfsTxOutcome::NotCommitted(e),
        };
        let outcome = guard.engine.zvol_resize(cx, dataset, new_volsize);
        if outcome.is_committed() {
            guard.bump_epoch(info.dataset_guid);
        }
        outcome
    }

    /// Create an atomic snapshot on a ZVOL.
    pub fn zvol_snapshot(
        &self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        snap_name: &[u8],
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        let mut guard = match self.lock_state() {
            Ok(g) => g,
            Err(e) => return ZfsTxOutcome::NotCommitted(e),
        };
        guard
            .engine
            .zvol_snapshot(cx, dataset, snap_name, timestamp)
    }

    /// Explicitly revoke all currently open sessions on `dataset_guid` (`ESTALE`).
    pub fn revoke_handles(&self, dataset_guid: u64) -> Result<u64> {
        Ok(self.lock_state()?.bump_epoch(dataset_guid))
    }

    /// Open an exclusive writable [`ZfsZvolSession`] on a ZVOL head.
    /// Rejects readonly ZVOLs with `ReadOnly` and overlapping writable opens with `EBUSY`.
    pub fn open_writable_session(
        &self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        sync_policy: ZvolSyncPolicy,
        allow_discard: bool,
        checksum: ZfsDataChecksum,
    ) -> Result<ZfsZvolSession> {
        checkpoint(cx)?;
        let mut guard = self.lock_state()?;
        let info = guard.engine.zvol_info(cx, dataset, None)?;
        if info.readonly {
            return Err(FfsError::ReadOnly);
        }
        let session_key = SessionKey::capture(cx, &guard.engine, dataset)?;
        if !guard.active_writable_leases.insert(info.dataset_guid) {
            return Err(reject_errno(
                libc::EBUSY,
                "exclusive writable ZVOL session is already open for this volume",
            ));
        }
        let open_epoch = guard.current_epoch(info.dataset_guid);
        drop(guard);
        Ok(ZfsZvolSession {
            state: Arc::clone(&self.state),
            dataset: dataset.to_vec(),
            snapshot: None,
            dataset_guid: info.dataset_guid,
            open_epoch,
            session_key,
            volsize: info.volsize,
            volblocksize: info.volblocksize,
            read_only: false,
            sync_policy,
            allow_discard,
            checksum,
            staged_dirty: BTreeMap::new(),
            staged_bytes: 0,
        })
    }

    /// Open a read-only [`ZfsZvolSession`] on a ZVOL head or named snapshot.
    pub fn open_readonly_session(
        &self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        snapshot: Option<&[u8]>,
    ) -> Result<ZfsZvolSession> {
        checkpoint(cx)?;
        let mut guard = self.lock_state()?;
        let info = guard.engine.zvol_info(cx, dataset, snapshot)?;
        let session_key = SessionKey::capture(cx, &guard.engine, dataset)?;
        let open_epoch = guard.current_epoch(info.dataset_guid);
        *guard
            .active_readonly_counts
            .entry(info.dataset_guid)
            .or_insert(0) += 1;
        drop(guard);
        Ok(ZfsZvolSession {
            state: Arc::clone(&self.state),
            dataset: dataset.to_vec(),
            snapshot: snapshot.map(<[u8]>::to_vec),
            dataset_guid: info.dataset_guid,
            open_epoch,
            session_key,
            volsize: info.volsize,
            volblocksize: info.volblocksize,
            read_only: true,
            sync_policy: ZvolSyncPolicy::Always,
            allow_discard: false,
            checksum: ZfsDataChecksum::Fletcher4,
            staged_dirty: BTreeMap::new(),
            staged_bytes: 0,
        })
    }
}

/// Identity of the loaded key at session open. A weak reference lets unload scrub
/// the key while preventing a later reload from reviving stale cached plaintext.
struct SessionKey {
    encryption_root_ddobj: u64,
    loaded: Weak<UnwrappedDslKey>,
}

impl SessionKey {
    fn capture(
        cx: &Cx,
        engine: &ZfsTransactionEngine,
        dataset: &[Vec<u8>],
    ) -> Result<Option<Self>> {
        let Some(info) = engine.dataset_crypto_info(cx, dataset)? else {
            return Ok(None);
        };
        let loaded = engine
            .keyring()
            .get(info.encryption_root_ddobj)
            .ok_or(FfsError::PermissionDenied)?;
        if loaded.guid != info.record.guid
            || loaded.suite != info.record.suite
            || loaded.version != info.record.version
        {
            return Err(FfsError::PermissionDenied);
        }
        Ok(Some(Self {
            encryption_root_ddobj: info.encryption_root_ddobj,
            loaded: Arc::downgrade(&loaded),
        }))
    }

    fn verify(&self, engine: &ZfsTransactionEngine) -> Result<()> {
        let current = engine
            .keyring()
            .get(self.encryption_root_ddobj)
            .ok_or(FfsError::PermissionDenied)?;
        let opened = self.loaded.upgrade().ok_or(FfsError::PermissionDenied)?;
        if !Arc::ptr_eq(&opened, &current) {
            return Err(FfsError::PermissionDenied);
        }
        Ok(())
    }
}

/// Epoch-bound block I/O session opened from a [`ZfsVolumeManager`]. Encrypted
/// sessions must be reopened after their encryption-root key is unloaded or replaced.
pub struct ZfsZvolSession {
    state: Arc<Mutex<ManagerState>>,
    dataset: Vec<Vec<u8>>,
    snapshot: Option<Vec<u8>>,
    dataset_guid: u64,
    open_epoch: u64,
    session_key: Option<SessionKey>,
    volsize: u64,
    volblocksize: usize,
    read_only: bool,
    sync_policy: ZvolSyncPolicy,
    allow_discard: bool,
    checksum: ZfsDataChecksum,
    staged_dirty: BTreeMap<u64, Option<Vec<u8>>>,
    staged_bytes: usize,
}

enum ZvolCacheUndo {
    Remove(u64),
    Restore(u64, Option<Vec<u8>>),
}

/// Per-command undo log for changes to the session's writeback cache. Native
/// reads, cancellation, and FUA publication can all fail after the first block.
struct StagedEdit<'a> {
    blocks: &'a mut BTreeMap<u64, Option<Vec<u8>>>,
    bytes: &'a mut usize,
    original_bytes: usize,
    undo: Vec<ZvolCacheUndo>,
}

impl<'a> StagedEdit<'a> {
    fn new(blocks: &'a mut BTreeMap<u64, Option<Vec<u8>>>, bytes: &'a mut usize) -> Self {
        Self {
            original_bytes: *bytes,
            blocks,
            bytes,
            undo: Vec::new(),
        }
    }

    fn replace(&mut self, id: u64, block: Option<Vec<u8>>) {
        let new_bytes = block.as_ref().map_or(0, Vec::len);
        let old = self.blocks.insert(id, block);
        let old_bytes = old.as_ref().and_then(Option::as_ref).map_or(0, Vec::len);
        *self.bytes = *self.bytes - old_bytes + new_bytes;
        self.undo.push(match old {
            Some(block) => ZvolCacheUndo::Restore(id, block),
            None => ZvolCacheUndo::Remove(id),
        });
    }

    fn finish(
        mut self,
        cx: &Cx,
        engine: &mut ZfsTransactionEngine,
        dataset: &[Vec<u8>],
        checksum: ZfsDataChecksum,
        durable: bool,
    ) -> Result<(ZvolAckKind, Option<ZfsCommitReceipt>)> {
        let ack = if durable || *self.bytes > MAX_STAGED_VOLATILE_BYTES {
            let (receipt, _) = engine
                .zvol_batch_apply(cx, dataset, self.blocks, checksum)
                .into_result()?;
            self.blocks.clear();
            *self.bytes = 0;
            (ZvolAckKind::DurableTxg, Some(receipt))
        } else {
            (ZvolAckKind::StagedVolatile, None)
        };
        self.undo.clear();
        self.original_bytes = *self.bytes;
        Ok(ack)
    }
}

impl Drop for StagedEdit<'_> {
    fn drop(&mut self) {
        for entry in self.undo.drain(..).rev() {
            match entry {
                ZvolCacheUndo::Remove(id) => {
                    self.blocks.remove(&id);
                }
                ZvolCacheUndo::Restore(id, block) => {
                    self.blocks.insert(id, block);
                }
            }
        }
        *self.bytes = self.original_bytes;
    }
}

impl Drop for ZfsZvolSession {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.state.lock() {
            if self.read_only {
                if let Some(cnt) = guard.active_readonly_counts.get_mut(&self.dataset_guid) {
                    *cnt = cnt.saturating_sub(1);
                    if *cnt == 0 {
                        guard.active_readonly_counts.remove(&self.dataset_guid);
                    }
                }
            } else {
                guard.active_writable_leases.remove(&self.dataset_guid);
            }
        }
    }
}

impl ZfsZvolSession {
    #[must_use]
    pub const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }

    #[must_use]
    pub const fn volsize(&self) -> u64 {
        self.volsize
    }

    #[must_use]
    pub const fn volblocksize(&self) -> usize {
        self.volblocksize
    }

    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    #[must_use]
    pub const fn sync_policy(&self) -> ZvolSyncPolicy {
        self.sync_policy
    }

    #[must_use]
    pub const fn allow_discard(&self) -> bool {
        self.allow_discard
    }

    #[must_use]
    pub fn has_staged_writes(&self) -> bool {
        !self.staged_dirty.is_empty()
    }

    /// Drop any uncommitted `FlushBarrier` volatile writes without mutating on-disk storage.
    pub fn discard_staged_volatile(&mut self) {
        self.staged_dirty.clear();
        self.staged_bytes = 0;
    }

    fn verify_epoch(&self, guard: &ManagerState) -> Result<()> {
        if guard.engine.requires_recovery() {
            return Err(reject_errno(
                libc::EIO,
                "uncertain ZVOL publication requires a fresh engine",
            ));
        }
        let cur = guard.epochs.get(&self.dataset_guid).copied().unwrap_or(1);
        if cur != self.open_epoch {
            return Err(reject_errno(
                libc::ESTALE,
                "ZVOL session handle epoch invalidated by resize, destroy, or revocation",
            ));
        }
        if let Some(key) = &self.session_key {
            key.verify(&guard.engine)?;
        }
        Ok(())
    }

    fn validate_span(&self, offset: u64, len: u64, max_bytes: Option<usize>) -> Result<()> {
        if !offset.is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES as u64)
            || !len.is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES as u64)
        {
            return Err(reject_errno(
                libc::EINVAL,
                "ZVOL request offset and length must be 512-byte aligned",
            ));
        }
        if let Some(limit) = max_bytes
            && len > limit as u64
        {
            return Err(reject_errno(
                libc::EINVAL,
                "ZVOL request exceeds 16 MiB maximum transfer size",
            ));
        }
        if offset.checked_add(len).is_none_or(|end| end > self.volsize) {
            return Err(reject_errno(
                libc::EINVAL,
                "ZVOL request exceeds volume capacity",
            ));
        }
        Ok(())
    }

    /// Sector-aligned read (observing staged `FlushBarrier` writes before flush).
    pub fn read_at(&self, cx: &Cx, offset: u64, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.validate_span(offset, out.len() as u64, Some(MAX_ZVOL_IO_BYTES))?;
        let guard = self
            .state
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZFS volume manager lock poisoned")))?;
        self.verify_epoch(&guard)?;
        if self.staged_dirty.is_empty() {
            return guard.engine.zvol_read_at(
                cx,
                &self.dataset,
                self.snapshot.as_deref(),
                offset,
                out,
            );
        }
        if out.is_empty() {
            return Ok(());
        }
        let bs = self.volblocksize as u64;
        let end = offset + out.len() as u64;
        let first_bid = offset / bs;
        let last_bid = (end - 1) / bs;
        let mut tmp = vec![0_u8; out.len()];
        for bid in first_bid..=last_bid {
            checkpoint(cx)?;
            let block_start = bid * bs;
            let block_end = block_start + bs;
            let read_start = offset.max(block_start);
            let read_end = end.min(block_end);
            let in_block = (read_start - block_start) as usize;
            let in_out = (read_start - offset) as usize;
            let count = (read_end - read_start) as usize;
            match self.staged_dirty.get(&bid) {
                Some(Some(buf)) => {
                    tmp[in_out..in_out + count].copy_from_slice(&buf[in_block..in_block + count]);
                }
                Some(None) => {
                    tmp[in_out..in_out + count].fill(0);
                }
                None => {
                    guard.engine.zvol_read_at(
                        cx,
                        &self.dataset,
                        self.snapshot.as_deref(),
                        read_start,
                        &mut tmp[in_out..in_out + count],
                    )?;
                }
            }
        }
        out.copy_from_slice(&tmp);
        Ok(())
    }

    /// Sector-aligned write with explicit `fua` (Force Unit Access) flag.
    pub fn write_at(
        &mut self,
        cx: &Cx,
        offset: u64,
        data: &[u8],
        fua: bool,
    ) -> Result<(ZvolAckKind, Option<ZfsCommitReceipt>)> {
        checkpoint(cx)?;
        if self.read_only {
            return Err(FfsError::ReadOnly);
        }
        self.validate_span(offset, data.len() as u64, Some(MAX_ZVOL_IO_BYTES))?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZFS volume manager lock poisoned")))?;
        self.verify_epoch(&guard)?;

        if self.sync_policy == ZvolSyncPolicy::Always && self.staged_dirty.is_empty() {
            let (receipt, _) = guard
                .engine
                .zvol_write_at(cx, &self.dataset, offset, data, self.checksum)
                .into_result()?;
            return Ok((ZvolAckKind::DurableTxg, Some(receipt)));
        }

        let mut edit = StagedEdit::new(&mut self.staged_dirty, &mut self.staged_bytes);
        if !data.is_empty() {
            let bs = self.volblocksize as u64;
            let end = offset + data.len() as u64;
            let first_bid = offset / bs;
            let last_bid = (end - 1) / bs;
            for bid in first_bid..=last_bid {
                checkpoint(cx)?;
                let block_start = bid * bs;
                let block_end = block_start + bs;
                let write_start = offset.max(block_start);
                let write_end = end.min(block_end);
                let in_block = (write_start - block_start) as usize;
                let in_data = (write_start - offset) as usize;
                let count = (write_end - write_start) as usize;

                if count == self.volblocksize {
                    edit.replace(bid, Some(data[in_data..in_data + count].to_vec()));
                } else {
                    let mut buf = match edit.blocks.get(&bid) {
                        Some(Some(existing)) => existing.clone(),
                        Some(None) => vec![0_u8; self.volblocksize],
                        None => {
                            let mut base = vec![0_u8; self.volblocksize];
                            guard.engine.zvol_read_at(
                                cx,
                                &self.dataset,
                                None,
                                block_start,
                                &mut base,
                            )?;
                            base
                        }
                    };
                    buf[in_block..in_block + count]
                        .copy_from_slice(&data[in_data..in_data + count]);
                    edit.replace(bid, Some(buf));
                }
            }
        }

        edit.finish(
            cx,
            &mut guard.engine,
            &self.dataset,
            self.checksum,
            fua || self.sync_policy == ZvolSyncPolicy::Always,
        )
    }

    /// Sector-aligned discard / TRIM.
    pub fn discard(
        &mut self,
        cx: &Cx,
        offset: u64,
        len: u64,
    ) -> Result<(ZvolAckKind, Option<ZfsCommitReceipt>)> {
        self.discard_with_fua(cx, offset, len, false)
    }

    /// Discard a range and optionally persist the session's pending I/O before returning.
    pub fn discard_with_fua(
        &mut self,
        cx: &Cx,
        offset: u64,
        len: u64,
        fua: bool,
    ) -> Result<(ZvolAckKind, Option<ZfsCommitReceipt>)> {
        checkpoint(cx)?;
        if self.read_only {
            return Err(FfsError::ReadOnly);
        }
        if !self.allow_discard {
            return Err(reject_errno(
                libc::EINVAL,
                "TRIM/discard is disabled on this ZVOL session",
            ));
        }
        self.validate_span(offset, len, None)?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZFS volume manager lock poisoned")))?;
        self.verify_epoch(&guard)?;

        if (fua || self.sync_policy == ZvolSyncPolicy::Always) && self.staged_dirty.is_empty() {
            let (receipt, _) = guard
                .engine
                .zvol_discard(cx, &self.dataset, offset, len, self.checksum)
                .into_result()?;
            return Ok((ZvolAckKind::DurableTxg, Some(receipt)));
        }

        let mut edit = StagedEdit::new(&mut self.staged_dirty, &mut self.staged_bytes);
        if len > 0 {
            let bs = self.volblocksize as u64;
            let end = offset + len;
            let first_bid = offset / bs;
            let last_bid = (end - 1) / bs;
            for bid in first_bid..=last_bid {
                checkpoint(cx)?;
                let block_start = bid * bs;
                let block_end = block_start + bs;
                let cut_start = offset.max(block_start);
                let cut_end = end.min(block_end);
                if cut_start == block_start && cut_end == block_end {
                    edit.replace(bid, None);
                } else {
                    let mut buf = match edit.blocks.get(&bid) {
                        Some(Some(existing)) => existing.clone(),
                        Some(None) => continue,
                        None => {
                            let mut base = vec![0_u8; self.volblocksize];
                            guard.engine.zvol_read_at(
                                cx,
                                &self.dataset,
                                None,
                                block_start,
                                &mut base,
                            )?;
                            base
                        }
                    };
                    let in_start = (cut_start - block_start) as usize;
                    let in_end = (cut_end - block_start) as usize;
                    buf[in_start..in_end].fill(0);
                    let nonzero = buf.iter().any(|&b| b != 0);
                    edit.replace(bid, nonzero.then_some(buf));
                }
            }
        }

        edit.finish(
            cx,
            &mut guard.engine,
            &self.dataset,
            self.checksum,
            fua || self.sync_policy == ZvolSyncPolicy::Always,
        )
    }

    /// Flush all staged `FlushBarrier` dirty blocks into one durable TXG, or verify a
    /// member-wide device sync barrier when already clean.
    pub fn flush(&mut self, cx: &Cx) -> Result<(ZvolAckKind, ZfsCommitReceipt)> {
        checkpoint(cx)?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZFS volume manager lock poisoned")))?;
        self.verify_epoch(&guard)?;
        if !self.staged_dirty.is_empty() {
            let (receipt, _) = guard
                .engine
                .zvol_batch_apply(cx, &self.dataset, &self.staged_dirty, self.checksum)
                .into_result()?;
            self.staged_dirty.clear();
            self.staged_bytes = 0;
            return Ok((ZvolAckKind::DurableTxg, receipt));
        }
        let receipt = guard.engine.zvol_flush(cx)?;
        Ok((ZvolAckKind::DeviceBarrierVerified, receipt))
    }
}

/// Configuration for [`ZfsZvolNbdServer`].
#[derive(Debug, Clone)]
pub struct NbdServerConfig {
    /// Exact NBD export name admitted during `NBD_OPT_GO` / `NBD_OPT_INFO` / `NBD_OPT_EXPORT_NAME`.
    pub export_name: String,
    /// When `true`, exit cleanly after serving one client connection.
    pub once: bool,
}

enum NbdBackend {
    Session(ZfsZvolSession),
    ReadOnlyZvol(Box<Zvol>),
}

impl NbdBackend {
    fn volsize(&self) -> u64 {
        match self {
            Self::Session(s) => s.volsize(),
            Self::ReadOnlyZvol(z) => z.info().size_bytes,
        }
    }

    fn volblocksize(&self) -> usize {
        match self {
            Self::Session(s) => s.volblocksize(),
            Self::ReadOnlyZvol(z) => z.info().block_bytes,
        }
    }

    fn is_read_only(&self) -> bool {
        match self {
            Self::Session(s) => s.is_read_only(),
            Self::ReadOnlyZvol(_) => true,
        }
    }

    fn allow_discard(&self) -> bool {
        match self {
            Self::Session(s) => !s.is_read_only() && s.allow_discard(),
            Self::ReadOnlyZvol(_) => false,
        }
    }

    fn tx_flags(&self) -> u16 {
        let mut flags = NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH;
        if self.is_read_only() {
            flags |= NBD_FLAG_READ_ONLY;
        } else {
            flags |= NBD_FLAG_SEND_FUA;
            if self.allow_discard() {
                flags |= NBD_FLAG_SEND_TRIM;
            }
        }
        flags
    }

    fn read_at(&mut self, cx: &Cx, offset: u64, out: &mut [u8]) -> Result<()> {
        match self {
            Self::Session(s) => s.read_at(cx, offset, out),
            Self::ReadOnlyZvol(z) => {
                if !offset.is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES as u64)
                    || !out.len().is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES)
                {
                    return Err(reject_errno(
                        libc::EINVAL,
                        "ZVOL NBD read must be 512-byte sector aligned",
                    ));
                }
                if out.len() > MAX_ZVOL_IO_BYTES {
                    return Err(reject_errno(
                        libc::EINVAL,
                        "ZVOL NBD read exceeds 16 MiB transfer limit",
                    ));
                }
                if offset
                    .checked_add(out.len() as u64)
                    .is_none_or(|end| end > z.info().size_bytes)
                {
                    return Err(reject_errno(
                        libc::EINVAL,
                        "ZVOL NBD read exceeds volume capacity",
                    ));
                }
                let bytes = z.read(cx, offset, out.len())?;
                out.copy_from_slice(&bytes);
                Ok(())
            }
        }
    }

    fn write_at(
        &mut self,
        cx: &Cx,
        offset: u64,
        data: &[u8],
        fua: bool,
    ) -> Result<(ZvolAckKind, Option<ZfsCommitReceipt>)> {
        match self {
            Self::Session(s) => s.write_at(cx, offset, data, fua),
            Self::ReadOnlyZvol(_) => Err(FfsError::ReadOnly),
        }
    }

    fn discard(
        &mut self,
        cx: &Cx,
        offset: u64,
        len: u64,
        fua: bool,
    ) -> Result<(ZvolAckKind, Option<ZfsCommitReceipt>)> {
        match self {
            Self::Session(s) => s.discard_with_fua(cx, offset, len, fua),
            Self::ReadOnlyZvol(_) => Err(FfsError::ReadOnly),
        }
    }

    fn discard_staged_volatile(&mut self) {
        if let Self::Session(s) = self {
            s.discard_staged_volatile();
        }
    }

    fn flush(&mut self, cx: &Cx) -> Result<(ZvolAckKind, Option<ZfsCommitReceipt>)> {
        match self {
            Self::Session(s) => {
                let (kind, receipt) = s.flush(cx)?;
                Ok((kind, Some(receipt)))
            }
            Self::ReadOnlyZvol(z) => {
                z.sync(cx)?;
                Ok((ZvolAckKind::ReadOnly, None))
            }
        }
    }
}

enum NbdListener {
    Unix(UnixListener),
    Tcp(TcpListener),
}

enum NbdStream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl NbdStream {
    fn configure_timeouts(&self) -> Result<()> {
        match self {
            Self::Unix(s) => {
                s.set_nonblocking(false)?;
                s.set_read_timeout(Some(IO_POLL_TIMEOUT))?;
                s.set_write_timeout(Some(WRITE_TIMEOUT))?;
            }
            Self::Tcp(s) => {
                s.set_nonblocking(false)?;
                s.set_nodelay(true)?;
                s.set_read_timeout(Some(IO_POLL_TIMEOUT))?;
                s.set_write_timeout(Some(WRITE_TIMEOUT))?;
            }
        }
        Ok(())
    }
}

impl Read for NbdStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Unix(s) => s.read(buf),
            Self::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for NbdStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Unix(s) => s.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Unix(s) => s.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}

fn read_exact_with_cx(cx: &Cx, stream: &mut NbdStream, mut buf: &mut [u8]) -> Result<bool> {
    let mut read_any = false;
    while !buf.is_empty() {
        checkpoint(cx)?;
        match stream.read(buf) {
            Ok(0) => {
                if !read_any {
                    return Ok(false);
                }
                return Err(FfsError::Io(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "NBD peer closed connection mid-frame",
                )));
            }
            Ok(n) => {
                read_any = true;
                let rest = buf;
                buf = &mut rest[n..];
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(err) => return Err(FfsError::Io(err)),
        }
    }
    Ok(true)
}

fn write_all_with_cx(cx: &Cx, stream: &mut NbdStream, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        checkpoint(cx)?;
        match stream.write(buf) {
            Ok(0) => {
                return Err(FfsError::Io(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "NBD peer closed connection during write",
                )));
            }
            Ok(n) => buf = &buf[n..],
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(err) => return Err(FfsError::Io(err)),
        }
    }
    stream.flush()?;
    Ok(())
}

fn drain_exact_with_cx(cx: &Cx, stream: &mut NbdStream, mut remaining: usize) -> Result<()> {
    let mut scratch = [0_u8; 8192];
    while remaining > 0 {
        let chunk = remaining.min(scratch.len());
        let ok = read_exact_with_cx(cx, stream, &mut scratch[..chunk])?;
        if !ok {
            return Err(FfsError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "NBD peer closed connection while draining rejected write payload",
            )));
        }
        remaining -= chunk;
    }
    Ok(())
}

fn write_opt_reply(
    cx: &Cx,
    stream: &mut NbdStream,
    option: u32,
    reply_type: u32,
    payload: &[u8],
) -> Result<()> {
    let mut frame = Vec::with_capacity(20 + payload.len());
    frame.extend_from_slice(&NBD_REP_MAGIC.to_be_bytes());
    frame.extend_from_slice(&option.to_be_bytes());
    frame.extend_from_slice(&reply_type.to_be_bytes());
    let len = u32::try_from(payload.len())
        .map_err(|_| FfsError::Format("NBD option reply payload exceeds u32".into()))?;
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    write_all_with_cx(cx, stream, &frame)
}

fn write_simple_reply(
    cx: &Cx,
    stream: &mut NbdStream,
    error: u32,
    handle: u64,
    payload: Option<&[u8]>,
) -> Result<()> {
    let mut header = [0_u8; 16];
    header[0..4].copy_from_slice(&NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
    header[4..8].copy_from_slice(&error.to_be_bytes());
    header[8..16].copy_from_slice(&handle.to_be_bytes());
    write_all_with_cx(cx, stream, &header)?;
    if let Some(bytes) = payload {
        write_all_with_cx(cx, stream, bytes)?;
    }
    Ok(())
}

/// Safe-Rust fixed-newstyle NBD server exposing one native ZFS ZVOL (read-write via
/// [`ZfsZvolSession`] or strictly read-only via [`Zvol`]).
pub struct ZfsZvolNbdServer {
    listener: NbdListener,
    backend: NbdBackend,
    config: NbdServerConfig,
    audit: Vec<ZvolTransportAuditEntry>,
    seq: u64,
}

impl ZfsZvolNbdServer {
    /// Bind a Unix domain socket listener (caller must supply a fresh unused socket path).
    pub fn bind_session_unix(
        socket_path: &Path,
        session: ZfsZvolSession,
        config: NbdServerConfig,
    ) -> Result<Self> {
        let listener = UnixListener::bind(socket_path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener: NbdListener::Unix(listener),
            backend: NbdBackend::Session(session),
            config,
            audit: Vec::new(),
            seq: 0,
        })
    }

    /// Bind a TCP listener exposing a [`ZfsZvolSession`].
    pub fn bind_session_tcp(
        addr: impl ToSocketAddrs,
        session: ZfsZvolSession,
        config: NbdServerConfig,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener: NbdListener::Tcp(listener),
            backend: NbdBackend::Session(session),
            config,
            audit: Vec::new(),
            seq: 0,
        })
    }

    /// Bind a strictly read-only Unix domain socket listener over an immutable [`Zvol`].
    pub fn bind_readonly_unix(
        socket_path: &Path,
        zvol: Zvol,
        config: NbdServerConfig,
    ) -> Result<Self> {
        let listener = UnixListener::bind(socket_path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener: NbdListener::Unix(listener),
            backend: NbdBackend::ReadOnlyZvol(Box::new(zvol)),
            config,
            audit: Vec::new(),
            seq: 0,
        })
    }

    /// Bind a strictly read-only TCP listener over an immutable [`Zvol`].
    pub fn bind_readonly_tcp(
        addr: impl ToSocketAddrs,
        zvol: Zvol,
        config: NbdServerConfig,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener: NbdListener::Tcp(listener),
            backend: NbdBackend::ReadOnlyZvol(Box::new(zvol)),
            config,
            audit: Vec::new(),
            seq: 0,
        })
    }

    /// Local TCP address when bound to TCP; `None` when bound to a Unix socket.
    pub fn local_tcp_addr(&self) -> Result<Option<SocketAddr>> {
        match &self.listener {
            NbdListener::Tcp(l) => Ok(Some(l.local_addr()?)),
            NbdListener::Unix(_) => Ok(None),
        }
    }

    /// Inspect recorded transport audit entries.
    #[must_use]
    pub fn audit_log(&self) -> &[ZvolTransportAuditEntry] {
        &self.audit
    }

    #[allow(clippy::too_many_arguments)]
    fn record_audit(
        &mut self,
        cmd: &str,
        offset: u64,
        length: u64,
        fua: bool,
        nbd_error: u32,
        ack_kind: ZvolAckKind,
        receipt: Option<&ZfsCommitReceipt>,
    ) {
        self.seq += 1;
        self.audit.push(ZvolTransportAuditEntry {
            seq: self.seq,
            cmd: cmd.to_owned(),
            offset,
            length,
            fua,
            nbd_error,
            ack_kind,
            committed_txg: receipt.map(|r| r.committed_txg),
            published_slot: receipt.map(|r| r.published_slot),
            token: receipt.and_then(|r| r.token.clone()),
        });
    }

    fn accept_next(&self, cx: &Cx) -> Result<NbdStream> {
        loop {
            checkpoint(cx)?;
            let res = match &self.listener {
                NbdListener::Unix(l) => l.accept().map(|(s, _)| NbdStream::Unix(s)),
                NbdListener::Tcp(l) => l.accept().map(|(s, _)| NbdStream::Tcp(s)),
            };
            match res {
                Ok(stream) => {
                    stream.configure_timeouts()?;
                    return Ok(stream);
                }
                Err(err)
                    if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                {
                    thread::sleep(ACCEPT_POLL_INTERVAL);
                }
                Err(err) => return Err(FfsError::Io(err)),
            }
        }
    }

    /// Run the cancel-aware NBD accept and dispatch loop until `once` completes or `cx` cancels.
    pub fn serve(&mut self, cx: &Cx) -> Result<Vec<ZvolTransportAuditEntry>> {
        loop {
            let mut stream = match self.accept_next(cx) {
                Ok(s) => s,
                Err(FfsError::Cancelled) => return Ok(self.audit.clone()),
                Err(err) => return Err(err),
            };
            let _ = self.handle_connection(cx, &mut stream);
            // Unflushed `FlushBarrier` volatile blocks are never silently carried across connections.
            self.backend.discard_staged_volatile();
            if self.config.once || cx.checkpoint().is_err() {
                return Ok(self.audit.clone());
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_connection(&mut self, cx: &Cx, stream: &mut NbdStream) -> Result<()> {
        // 1. Fixed-newstyle server greeting (18 bytes).
        let mut greeting = [0_u8; 18];
        greeting[0..8].copy_from_slice(&NBD_MAGIC.to_be_bytes());
        greeting[8..16].copy_from_slice(&NBD_IHAVEOPT.to_be_bytes());
        greeting[16..18]
            .copy_from_slice(&(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES).to_be_bytes());
        write_all_with_cx(cx, stream, &greeting)?;

        let mut cflags_raw = [0_u8; 4];
        if !read_exact_with_cx(cx, stream, &mut cflags_raw)? {
            return Ok(());
        }
        let client_flags = u32::from_be_bytes(cflags_raw);
        if client_flags & NBD_FLAG_C_FIXED_NEWSTYLE == 0 {
            return Err(FfsError::Format(
                "NBD client did not negotiate FIXED_NEWSTYLE".into(),
            ));
        }

        // 2. Option haggling phase.
        let mut entered_transmission = false;
        while !entered_transmission {
            let mut hdr = [0_u8; 16];
            if !read_exact_with_cx(cx, stream, &mut hdr)? {
                return Ok(());
            }
            let magic = u64::from_be_bytes(hdr[0..8].try_into().expect("8 bytes"));
            if magic != NBD_IHAVEOPT {
                return Err(FfsError::Format("invalid NBD option header magic".into()));
            }
            let option = u32::from_be_bytes(hdr[8..12].try_into().expect("4 bytes"));
            let payload_len = u32::from_be_bytes(hdr[12..16].try_into().expect("4 bytes")) as usize;
            if payload_len > MAX_OPTION_PAYLOAD_BYTES {
                return Err(FfsError::Format(
                    "NBD option payload exceeds 64 KiB budget".into(),
                ));
            }
            let mut payload = vec![0_u8; payload_len];
            if payload_len > 0 && !read_exact_with_cx(cx, stream, &mut payload)? {
                return Ok(());
            }

            match option {
                NBD_OPT_ABORT => {
                    let _ = write_opt_reply(cx, stream, option, NBD_REP_ACK, &[]);
                    self.record_audit(
                        "OPT_ABORT",
                        0,
                        0,
                        false,
                        NBD_OK,
                        ZvolAckKind::ReadOnly,
                        None,
                    );
                    return Ok(());
                }
                NBD_OPT_LIST => {
                    if !payload.is_empty() {
                        write_opt_reply(cx, stream, option, NBD_REP_ERR_INVALID, &[])?;
                        continue;
                    }
                    let name_bytes = self.config.export_name.as_bytes();
                    let mut entry = Vec::with_capacity(4 + name_bytes.len());
                    entry.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                    entry.extend_from_slice(name_bytes);
                    write_opt_reply(cx, stream, option, NBD_REP_SERVER, &entry)?;
                    write_opt_reply(cx, stream, option, NBD_REP_ACK, &[])?;
                    self.record_audit("OPT_LIST", 0, 0, false, NBD_OK, ZvolAckKind::ReadOnly, None);
                }
                NBD_OPT_INFO | NBD_OPT_GO => {
                    let cmd_name = if option == NBD_OPT_GO {
                        "OPT_GO"
                    } else {
                        "OPT_INFO"
                    };
                    let Some(requested_name) = parse_info_or_go_export_name(&payload) else {
                        write_opt_reply(cx, stream, option, NBD_REP_ERR_INVALID, &[])?;
                        self.record_audit(
                            cmd_name,
                            0,
                            0,
                            false,
                            NBD_EINVAL,
                            ZvolAckKind::Rejected,
                            None,
                        );
                        continue;
                    };
                    if requested_name != self.config.export_name.as_bytes() {
                        write_opt_reply(cx, stream, option, NBD_REP_ERR_UNKNOWN, &[])?;
                        self.record_audit(
                            cmd_name,
                            0,
                            0,
                            false,
                            NBD_EINVAL,
                            ZvolAckKind::Rejected,
                            None,
                        );
                        continue;
                    }
                    let mut export_info = [0_u8; 12];
                    export_info[0..2].copy_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
                    export_info[2..10].copy_from_slice(&self.backend.volsize().to_be_bytes());
                    export_info[10..12].copy_from_slice(&self.backend.tx_flags().to_be_bytes());
                    write_opt_reply(cx, stream, option, NBD_REP_INFO, &export_info)?;

                    let mut blk_info = [0_u8; 14];
                    blk_info[0..2].copy_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
                    blk_info[2..6]
                        .copy_from_slice(&(ZVOL_LOGICAL_SECTOR_BYTES as u32).to_be_bytes());
                    blk_info[6..10]
                        .copy_from_slice(&(self.backend.volblocksize() as u32).to_be_bytes());
                    blk_info[10..14].copy_from_slice(&(MAX_ZVOL_IO_BYTES as u32).to_be_bytes());
                    write_opt_reply(cx, stream, option, NBD_REP_INFO, &blk_info)?;

                    write_opt_reply(cx, stream, option, NBD_REP_ACK, &[])?;
                    self.record_audit(
                        cmd_name,
                        0,
                        self.backend.volsize(),
                        false,
                        NBD_OK,
                        ZvolAckKind::ReadOnly,
                        None,
                    );
                    if option == NBD_OPT_GO {
                        entered_transmission = true;
                    }
                }
                NBD_OPT_EXPORT_NAME => {
                    if payload != self.config.export_name.as_bytes() {
                        self.record_audit(
                            "OPT_EXPORT_NAME",
                            0,
                            0,
                            false,
                            NBD_EINVAL,
                            ZvolAckKind::Rejected,
                            None,
                        );
                        return Ok(());
                    }
                    let mut reply = Vec::with_capacity(134);
                    reply.extend_from_slice(&self.backend.volsize().to_be_bytes());
                    reply.extend_from_slice(&self.backend.tx_flags().to_be_bytes());
                    if client_flags & NBD_FLAG_C_NO_ZEROES == 0 {
                        reply.resize(reply.len() + 124, 0);
                    }
                    write_all_with_cx(cx, stream, &reply)?;
                    self.record_audit(
                        "OPT_EXPORT_NAME",
                        0,
                        self.backend.volsize(),
                        false,
                        NBD_OK,
                        ZvolAckKind::ReadOnly,
                        None,
                    );
                    entered_transmission = true;
                }
                _ => {
                    write_opt_reply(cx, stream, option, NBD_REP_ERR_UNSUP, &[])?;
                }
            }
        }

        // 3. Transmission phase (28-byte request headers, 16-byte simple replies).
        loop {
            let mut req = [0_u8; 28];
            if !read_exact_with_cx(cx, stream, &mut req)? {
                return Ok(());
            }
            let magic = u32::from_be_bytes(req[0..4].try_into().expect("4 bytes"));
            if magic != NBD_REQUEST_MAGIC {
                return Err(FfsError::Format("invalid NBD request magic".into()));
            }
            let flags = u16::from_be_bytes(req[4..6].try_into().expect("2 bytes"));
            let cmd = u16::from_be_bytes(req[6..8].try_into().expect("2 bytes"));
            let handle = u64::from_be_bytes(req[8..16].try_into().expect("8 bytes"));
            let offset = u64::from_be_bytes(req[16..24].try_into().expect("8 bytes"));
            let length = u32::from_be_bytes(req[24..28].try_into().expect("4 bytes"));
            let fua = flags & NBD_CMD_FLAG_FUA != 0;

            match cmd {
                NBD_CMD_DISC => {
                    self.record_audit("DISC", 0, 0, false, NBD_OK, ZvolAckKind::ReadOnly, None);
                    return Ok(());
                }
                NBD_CMD_READ => {
                    if length as usize > MAX_ZVOL_IO_BYTES {
                        write_simple_reply(cx, stream, NBD_EINVAL, handle, None)?;
                        self.record_audit(
                            "READ",
                            offset,
                            u64::from(length),
                            false,
                            NBD_EINVAL,
                            ZvolAckKind::Rejected,
                            None,
                        );
                        continue;
                    }
                    let mut buf = vec![0_u8; length as usize];
                    match self.backend.read_at(cx, offset, &mut buf) {
                        Ok(()) => {
                            write_simple_reply(cx, stream, NBD_OK, handle, Some(&buf))?;
                            self.record_audit(
                                "READ",
                                offset,
                                u64::from(length),
                                false,
                                NBD_OK,
                                ZvolAckKind::ReadOnly,
                                None,
                            );
                        }
                        Err(err) => {
                            let code = map_error_to_nbd(&err);
                            write_simple_reply(cx, stream, code, handle, None)?;
                            self.record_audit(
                                "READ",
                                offset,
                                u64::from(length),
                                false,
                                code,
                                ZvolAckKind::Rejected,
                                None,
                            );
                        }
                    }
                }
                NBD_CMD_WRITE => {
                    if length as usize > MAX_ZVOL_IO_BYTES {
                        let _ = write_simple_reply(cx, stream, NBD_EINVAL, handle, None);
                        self.record_audit(
                            "WRITE",
                            offset,
                            u64::from(length),
                            fua,
                            NBD_EINVAL,
                            ZvolAckKind::Rejected,
                            None,
                        );
                        // Do not attempt to drain unbounded malicious payload; close cleanly.
                        return Ok(());
                    }
                    if self.backend.is_read_only() {
                        // Drain exact payload bytes first so connection framing stays intact!
                        drain_exact_with_cx(cx, stream, length as usize)?;
                        write_simple_reply(cx, stream, NBD_EPERM, handle, None)?;
                        self.record_audit(
                            "WRITE",
                            offset,
                            u64::from(length),
                            fua,
                            NBD_EPERM,
                            ZvolAckKind::Rejected,
                            None,
                        );
                        continue;
                    }
                    let mut data = vec![0_u8; length as usize];
                    if !data.is_empty() && !read_exact_with_cx(cx, stream, &mut data)? {
                        return Ok(());
                    }
                    match self.backend.write_at(cx, offset, &data, fua) {
                        Ok((ack_kind, receipt)) => {
                            self.record_audit(
                                "WRITE",
                                offset,
                                u64::from(length),
                                fua,
                                NBD_OK,
                                ack_kind,
                                receipt.as_ref(),
                            );
                            write_simple_reply(cx, stream, NBD_OK, handle, None)?;
                        }
                        Err(err) => {
                            let code = map_error_to_nbd(&err);
                            self.record_audit(
                                "WRITE",
                                offset,
                                u64::from(length),
                                fua,
                                code,
                                ZvolAckKind::Rejected,
                                None,
                            );
                            write_simple_reply(cx, stream, code, handle, None)?;
                        }
                    }
                }
                NBD_CMD_TRIM => match self.backend.discard(cx, offset, u64::from(length), fua) {
                    Ok((ack_kind, receipt)) => {
                        self.record_audit(
                            "TRIM",
                            offset,
                            u64::from(length),
                            fua,
                            NBD_OK,
                            ack_kind,
                            receipt.as_ref(),
                        );
                        write_simple_reply(cx, stream, NBD_OK, handle, None)?;
                    }
                    Err(err) => {
                        let code = map_error_to_nbd(&err);
                        self.record_audit(
                            "TRIM",
                            offset,
                            u64::from(length),
                            fua,
                            code,
                            ZvolAckKind::Rejected,
                            None,
                        );
                        write_simple_reply(cx, stream, code, handle, None)?;
                    }
                },
                NBD_CMD_FLUSH => {
                    if offset != 0 || length != 0 {
                        self.record_audit(
                            "FLUSH",
                            offset,
                            u64::from(length),
                            false,
                            NBD_EINVAL,
                            ZvolAckKind::Rejected,
                            None,
                        );
                        write_simple_reply(cx, stream, NBD_EINVAL, handle, None)?;
                        continue;
                    }
                    match self.backend.flush(cx) {
                        Ok((ack_kind, receipt)) => {
                            self.record_audit(
                                "FLUSH",
                                0,
                                0,
                                false,
                                NBD_OK,
                                ack_kind,
                                receipt.as_ref(),
                            );
                            write_simple_reply(cx, stream, NBD_OK, handle, None)?;
                        }
                        Err(err) => {
                            let code = map_error_to_nbd(&err);
                            self.record_audit(
                                "FLUSH",
                                0,
                                0,
                                false,
                                code,
                                ZvolAckKind::Rejected,
                                None,
                            );
                            write_simple_reply(cx, stream, code, handle, None)?;
                        }
                    }
                }
                _ => {
                    write_simple_reply(cx, stream, NBD_EINVAL, handle, None)?;
                    self.record_audit(
                        "UNKNOWN",
                        offset,
                        u64::from(length),
                        fua,
                        NBD_EINVAL,
                        ZvolAckKind::Rejected,
                        None,
                    );
                }
            }
        }
    }
}

fn parse_info_or_go_export_name(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < 6 {
        return None;
    }
    let name_len = u32::from_be_bytes(payload[0..4].try_into().ok()?) as usize;
    let count_off = 4_usize.checked_add(name_len)?;
    if payload.len() < count_off + 2 {
        return None;
    }
    let req_count = u16::from_be_bytes(payload[count_off..count_off + 2].try_into().ok()?) as usize;
    let expected = count_off.checked_add(2)?.checked_add(req_count * 2)?;
    if payload.len() != expected {
        return None;
    }
    Some(&payload[4..count_off])
}

/// Export geometry and transmission flags negotiated via `NBD_OPT_GO`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NbdExportInfo {
    pub export_name: String,
    pub size_bytes: u64,
    pub tx_flags: u16,
    pub min_block_bytes: u32,
    pub preferred_block_bytes: u32,
    pub max_block_bytes: u32,
}

impl NbdExportInfo {
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.tx_flags & NBD_FLAG_READ_ONLY != 0
    }

    #[must_use]
    pub const fn supports_flush(&self) -> bool {
        self.tx_flags & NBD_FLAG_SEND_FLUSH != 0
    }

    #[must_use]
    pub const fn supports_fua(&self) -> bool {
        self.tx_flags & NBD_FLAG_SEND_FUA != 0
    }

    #[must_use]
    pub const fn supports_trim(&self) -> bool {
        self.tx_flags & NBD_FLAG_SEND_TRIM != 0
    }
}

struct ClientInner {
    stream: Option<NbdStream>,
    next_handle: u64,
}

/// First-party safe-Rust fixed-newstyle NBD client implementing [`ByteDevice`].
pub struct ZfsZvolNbdClient {
    info: NbdExportInfo,
    inner: Mutex<ClientInner>,
}

impl ZfsZvolNbdClient {
    /// Connect to a Unix domain socket NBD server and negotiate `export_name` via `NBD_OPT_GO`.
    pub fn connect_unix(cx: &Cx, socket_path: &Path, export_name: &str) -> Result<Self> {
        checkpoint(cx)?;
        let stream = NbdStream::Unix(UnixStream::connect(socket_path)?);
        stream.configure_timeouts()?;
        Self::handshake(cx, stream, export_name)
    }

    /// Connect to a TCP NBD server and negotiate `export_name` via `NBD_OPT_GO`.
    pub fn connect_tcp(cx: &Cx, addr: impl ToSocketAddrs, export_name: &str) -> Result<Self> {
        checkpoint(cx)?;
        let stream = NbdStream::Tcp(TcpStream::connect(addr)?);
        stream.configure_timeouts()?;
        Self::handshake(cx, stream, export_name)
    }

    /// Query available export names via `NBD_OPT_LIST` over Unix socket.
    pub fn list_exports_unix(cx: &Cx, socket_path: &Path) -> Result<Vec<String>> {
        checkpoint(cx)?;
        let stream = NbdStream::Unix(UnixStream::connect(socket_path)?);
        stream.configure_timeouts()?;
        Self::list_exports_stream(cx, stream)
    }

    /// Query available export names via `NBD_OPT_LIST` over TCP.
    pub fn list_exports_tcp(cx: &Cx, addr: impl ToSocketAddrs) -> Result<Vec<String>> {
        checkpoint(cx)?;
        let stream = NbdStream::Tcp(TcpStream::connect(addr)?);
        stream.configure_timeouts()?;
        Self::list_exports_stream(cx, stream)
    }

    fn read_greeting_and_send_flags(cx: &Cx, stream: &mut NbdStream) -> Result<()> {
        let mut greeting = [0_u8; 18];
        if !read_exact_with_cx(cx, stream, &mut greeting)? {
            return Err(FfsError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "NBD server closed during greeting",
            )));
        }
        let magic = u64::from_be_bytes(greeting[0..8].try_into().expect("8 bytes"));
        let ihave = u64::from_be_bytes(greeting[8..16].try_into().expect("8 bytes"));
        let sflags = u16::from_be_bytes(greeting[16..18].try_into().expect("2 bytes"));
        if magic != NBD_MAGIC || ihave != NBD_IHAVEOPT || sflags & NBD_FLAG_FIXED_NEWSTYLE == 0 {
            return Err(FfsError::Format(
                "unexpected NBD server greeting or missing FIXED_NEWSTYLE".into(),
            ));
        }
        let cflags = NBD_FLAG_C_FIXED_NEWSTYLE
            | if sflags & NBD_FLAG_NO_ZEROES != 0 {
                NBD_FLAG_C_NO_ZEROES
            } else {
                0
            };
        write_all_with_cx(cx, stream, &cflags.to_be_bytes())
    }

    fn send_option(cx: &Cx, stream: &mut NbdStream, option: u32, payload: &[u8]) -> Result<()> {
        let mut buf = Vec::with_capacity(16 + payload.len());
        buf.extend_from_slice(&NBD_IHAVEOPT.to_be_bytes());
        buf.extend_from_slice(&option.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        write_all_with_cx(cx, stream, &buf)
    }

    fn read_option_reply(cx: &Cx, stream: &mut NbdStream) -> Result<(u32, u32, Vec<u8>)> {
        let mut hdr = [0_u8; 20];
        if !read_exact_with_cx(cx, stream, &mut hdr)? {
            return Err(FfsError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "NBD server closed during option reply",
            )));
        }
        let magic = u64::from_be_bytes(hdr[0..8].try_into().expect("8 bytes"));
        if magic != NBD_REP_MAGIC {
            return Err(FfsError::Format("invalid NBD option reply magic".into()));
        }
        let opt = u32::from_be_bytes(hdr[8..12].try_into().expect("4 bytes"));
        let rep = u32::from_be_bytes(hdr[12..16].try_into().expect("4 bytes"));
        let len = u32::from_be_bytes(hdr[16..20].try_into().expect("4 bytes")) as usize;
        if len > MAX_OPTION_PAYLOAD_BYTES {
            return Err(FfsError::Format("NBD option reply exceeds 64 KiB".into()));
        }
        let mut payload = vec![0_u8; len];
        if len > 0 && !read_exact_with_cx(cx, stream, &mut payload)? {
            return Err(FfsError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "NBD server closed mid option reply payload",
            )));
        }
        Ok((opt, rep, payload))
    }

    fn list_exports_stream(cx: &Cx, mut stream: NbdStream) -> Result<Vec<String>> {
        Self::read_greeting_and_send_flags(cx, &mut stream)?;
        Self::send_option(cx, &mut stream, NBD_OPT_LIST, &[])?;
        let mut exports = Vec::new();
        loop {
            let (_, rep, payload) = Self::read_option_reply(cx, &mut stream)?;
            match rep {
                NBD_REP_SERVER => {
                    if payload.len() < 4 {
                        return Err(FfsError::Format("truncated NBD_REP_SERVER payload".into()));
                    }
                    let nlen = u32::from_be_bytes(payload[0..4].try_into().expect("4")) as usize;
                    if payload.len() < 4 + nlen {
                        return Err(FfsError::Format("short NBD export name".into()));
                    }
                    exports.push(String::from_utf8_lossy(&payload[4..4 + nlen]).into_owned());
                }
                NBD_REP_ACK => break,
                _ => {
                    return Err(FfsError::Format(format!(
                        "NBD_OPT_LIST rejected with reply 0x{rep:x}"
                    )));
                }
            }
        }
        let _ = Self::send_option(cx, &mut stream, NBD_OPT_ABORT, &[]);
        Ok(exports)
    }

    fn handshake(cx: &Cx, mut stream: NbdStream, export_name: &str) -> Result<Self> {
        Self::read_greeting_and_send_flags(cx, &mut stream)?;
        let name_bytes = export_name.as_bytes();
        let mut go_payload = Vec::with_capacity(8 + name_bytes.len());
        go_payload.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
        go_payload.extend_from_slice(name_bytes);
        go_payload.extend_from_slice(&1_u16.to_be_bytes());
        go_payload.extend_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
        Self::send_option(cx, &mut stream, NBD_OPT_GO, &go_payload)?;

        let mut size_bytes = None;
        let mut tx_flags = 0_u16;
        let mut min_block = ZVOL_LOGICAL_SECTOR_BYTES as u32;
        let mut pref_block = 4096_u32;
        let mut max_block = MAX_ZVOL_IO_BYTES as u32;

        loop {
            let (_, rep, payload) = Self::read_option_reply(cx, &mut stream)?;
            match rep {
                NBD_REP_INFO => {
                    if payload.len() < 2 {
                        return Err(FfsError::Format("truncated NBD_REP_INFO".into()));
                    }
                    let kind = u16::from_be_bytes(payload[0..2].try_into().expect("2"));
                    if kind == NBD_INFO_EXPORT && payload.len() == 12 {
                        size_bytes =
                            Some(u64::from_be_bytes(payload[2..10].try_into().expect("8")));
                        tx_flags = u16::from_be_bytes(payload[10..12].try_into().expect("2"));
                    } else if kind == NBD_INFO_BLOCK_SIZE && payload.len() == 14 {
                        min_block = u32::from_be_bytes(payload[2..6].try_into().expect("4"));
                        pref_block = u32::from_be_bytes(payload[6..10].try_into().expect("4"));
                        max_block = u32::from_be_bytes(payload[10..14].try_into().expect("4"));
                    }
                }
                NBD_REP_ACK => break,
                NBD_REP_ERR_UNKNOWN => {
                    return Err(FfsError::NotFound(format!(
                        "unknown NBD export {export_name}"
                    )));
                }
                other => {
                    return Err(FfsError::Format(format!(
                        "NBD_OPT_GO rejected with reply 0x{other:x}"
                    )));
                }
            }
        }

        let size = size_bytes
            .ok_or_else(|| FfsError::Format("NBD server omitted NBD_INFO_EXPORT".into()))?;
        Ok(Self {
            info: NbdExportInfo {
                export_name: export_name.to_owned(),
                size_bytes: size,
                tx_flags,
                min_block_bytes: min_block,
                preferred_block_bytes: pref_block,
                max_block_bytes: max_block,
            },
            inner: Mutex::new(ClientInner {
                stream: Some(stream),
                next_handle: 1,
            }),
        })
    }

    #[must_use]
    pub const fn info(&self) -> &NbdExportInfo {
        &self.info
    }

    fn send_request(
        cx: &Cx,
        inner: &mut ClientInner,
        cmd: u16,
        flags: u16,
        offset: u64,
        length: u32,
        write_payload: Option<&[u8]>,
    ) -> Result<u64> {
        let stream = inner.stream.as_mut().ok_or_else(|| {
            FfsError::Io(std::io::Error::other("NBD client already disconnected"))
        })?;
        let handle = inner.next_handle;
        inner.next_handle = inner.next_handle.wrapping_add(1).max(1);
        let mut hdr = [0_u8; 28];
        hdr[0..4].copy_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
        hdr[4..6].copy_from_slice(&flags.to_be_bytes());
        hdr[6..8].copy_from_slice(&cmd.to_be_bytes());
        hdr[8..16].copy_from_slice(&handle.to_be_bytes());
        hdr[16..24].copy_from_slice(&offset.to_be_bytes());
        hdr[24..28].copy_from_slice(&length.to_be_bytes());
        write_all_with_cx(cx, stream, &hdr)?;
        if let Some(bytes) = write_payload {
            write_all_with_cx(cx, stream, bytes)?;
        }
        Ok(handle)
    }

    fn read_reply(
        cx: &Cx,
        inner: &mut ClientInner,
        expected_handle: u64,
        op: &str,
        read_into: Option<&mut [u8]>,
    ) -> Result<()> {
        let stream = inner.stream.as_mut().ok_or_else(|| {
            FfsError::Io(std::io::Error::other("NBD client already disconnected"))
        })?;
        let mut hdr = [0_u8; 16];
        if !read_exact_with_cx(cx, stream, &mut hdr)? {
            return Err(FfsError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "NBD server closed before sending reply",
            )));
        }
        let magic = u32::from_be_bytes(hdr[0..4].try_into().expect("4"));
        if magic != NBD_SIMPLE_REPLY_MAGIC {
            return Err(FfsError::Format("invalid NBD simple reply magic".into()));
        }
        let error = u32::from_be_bytes(hdr[4..8].try_into().expect("4"));
        let handle = u64::from_be_bytes(hdr[8..16].try_into().expect("8"));
        if handle != expected_handle {
            return Err(FfsError::Format("mismatched NBD reply handle".into()));
        }
        if error != NBD_OK {
            return Err(map_nbd_to_error(error, op));
        }
        if let Some(out) = read_into {
            let mut tmp = vec![0_u8; out.len()];
            if !tmp.is_empty() && !read_exact_with_cx(cx, stream, &mut tmp)? {
                return Err(FfsError::Io(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "NBD server closed mid READ payload",
                )));
            }
            out.copy_from_slice(&tmp);
        }
        Ok(())
    }

    pub fn read_at(&self, cx: &Cx, offset: u64, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let len = u32::try_from(out.len())
            .map_err(|_| reject_errno(libc::EINVAL, "NBD read length exceeds u32"))?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NBD client lock poisoned")))?;
        let handle = Self::send_request(cx, &mut guard, NBD_CMD_READ, 0, offset, len, None)?;
        Self::read_reply(cx, &mut guard, handle, "READ", Some(out))
    }

    pub fn write_at(&self, cx: &Cx, offset: u64, data: &[u8], fua: bool) -> Result<()> {
        checkpoint(cx)?;
        let len = u32::try_from(data.len())
            .map_err(|_| reject_errno(libc::EINVAL, "NBD write length exceeds u32"))?;
        let flags = if fua { NBD_CMD_FLAG_FUA } else { 0 };
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NBD client lock poisoned")))?;
        let handle = Self::send_request(
            cx,
            &mut guard,
            NBD_CMD_WRITE,
            flags,
            offset,
            len,
            Some(data),
        )?;
        Self::read_reply(cx, &mut guard, handle, "WRITE", None)
    }

    pub fn trim(&self, cx: &Cx, offset: u64, len: u64) -> Result<()> {
        self.trim_with_fua(cx, offset, len, false)
    }

    /// Discard a range, optionally requiring native durability before acknowledgment.
    pub fn trim_with_fua(&self, cx: &Cx, offset: u64, len: u64, fua: bool) -> Result<()> {
        checkpoint(cx)?;
        let len_u32 = u32::try_from(len)
            .map_err(|_| reject_errno(libc::EINVAL, "NBD TRIM length exceeds u32"))?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NBD client lock poisoned")))?;
        let flags = if fua { NBD_CMD_FLAG_FUA } else { 0 };
        let handle =
            Self::send_request(cx, &mut guard, NBD_CMD_TRIM, flags, offset, len_u32, None)?;
        Self::read_reply(cx, &mut guard, handle, "TRIM", None)
    }

    pub fn flush(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NBD client lock poisoned")))?;
        let handle = Self::send_request(cx, &mut guard, NBD_CMD_FLUSH, 0, 0, 0, None)?;
        Self::read_reply(cx, &mut guard, handle, "FLUSH", None)
    }

    pub fn disconnect(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NBD client lock poisoned")))?;
        if guard.stream.is_some() {
            let _ = Self::send_request(cx, &mut guard, NBD_CMD_DISC, 0, 0, 0, None);
            guard.stream = None;
        }
        Ok(())
    }
}

impl ByteDevice for ZfsZvolNbdClient {
    fn len_bytes(&self) -> u64 {
        self.info.size_bytes
    }

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        true
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.read_at(cx, offset.0, out)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, data: &[u8]) -> Result<()> {
        self.write_at(cx, offset.0, data, false)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.flush(cx)
    }
}
