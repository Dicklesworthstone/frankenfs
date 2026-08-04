//! VFS semantics layer: filesystem-agnostic types and operations trait.
//!
//! This module defines the core VFS abstractions that higher layers (FUSE,
//! test harness) consume. Format-specific implementations (ext4, btrfs) live
//! behind the [`FsOps`] trait so that callers are filesystem-agnostic.

use crate::fs_mvcc_store::FsMvccStore;
use asupersync::Cx;
use ffs_error::FfsError;
use ffs_types::{CommitSeq, InodeNumber, Snapshot};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

// ── VFS semantics layer ─────────────────────────────────────────────────────

const COPY_FILE_RANGE_CHUNK_BYTES: u32 = 1024 * 1024;

fn ranges_overlap(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let Some(a_end) = a_start.checked_add(a_len) else {
        return true;
    };
    let Some(b_end) = b_start.checked_add(b_len) else {
        return true;
    };
    a_start < b_end && b_start < a_end
}

/// Byte range parameters for Linux `FICLONERANGE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileCloneRange {
    pub src_fd: i64,
    pub src_offset: u64,
    pub src_length: u64,
    pub dest_offset: u64,
}

/// Limit payload supplied by `BTRFS_IOC_QGROUP_LIMIT`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsQgroupLimitRequest {
    pub qgroupid: u64,
    pub flags: u64,
    pub max_rfer: u64,
    pub max_excl: u64,
    pub rsv_rfer: u64,
    pub rsv_excl: u64,
}

/// Filesystem-agnostic file type for VFS operations.
///
/// This is the semantics-level file type used by [`FsOps`] methods. It unifies
/// ext4's `Ext4FileType` and btrfs's inode type into a single enum that
/// higher layers (FUSE, harness) consume without filesystem-specific knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    RegularFile,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
}

/// Inode attributes returned by [`FsOps::getattr`] and [`FsOps::lookup`].
///
/// This is the semantics-level stat structure, analogous to POSIX `struct stat`.
/// Format-specific crates (ffs-ext4, ffs-btrfs) convert their on-disk inode
/// representations into `InodeAttr` at the crate boundary.
///
/// # Generation Number Lifecycle
///
/// The `generation` field implements NFS-style stale-handle detection:
///
/// - **ext4:** Per-inode counter stored at on-disk offset `0x64`. Bumped by
///   `wrapping_add(1)` each time an inode number is reused after deletion.
///   This lets FUSE/NFS clients detect that a previously-held file handle now
///   refers to a different file occupying the same inode slot.
///
/// - **btrfs:** Uses the inode-item's `generation` field (transaction generation
///   at inode creation time). Since btrfs inode numbers (objectids) are never
///   reused within a filesystem, the creation-time transaction generation
///   suffices as a unique discriminator. For in-memory-only mutations (COW
///   write path), `BtrfsAllocState.generation` is used.
///
/// The FUSE layer passes this value as the `generation` parameter in
/// `reply.entry()` and `reply.created()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeAttr {
    /// Inode number.
    pub ino: InodeNumber,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Last access time.
    pub atime: SystemTime,
    /// Last modification time.
    pub mtime: SystemTime,
    /// Last status change time.
    pub ctime: SystemTime,
    /// Creation time (if available).
    pub crtime: SystemTime,
    /// File type.
    pub kind: FileType,
    /// POSIX permission bits (lower 12 bits of mode).
    pub perm: u16,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Device ID (for block/char devices).
    pub rdev: u32,
    /// Preferred I/O block size.
    pub blksize: u32,
    /// NFS-style generation number for stale-handle detection.
    ///
    /// See struct-level docs for the per-filesystem lifecycle contract.
    pub generation: u64,
}

/// A directory entry returned by [`FsOps::readdir`].
///
/// Each entry represents one name in a directory listing. The `offset` field
/// is an opaque cookie for resuming iteration — FUSE passes it back on
/// subsequent `readdir` calls so the implementation can skip already-returned
/// entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// Inode number of the target.
    pub ino: InodeNumber,
    /// Opaque offset cookie for readdir continuation.
    pub offset: u64,
    /// File type of the target.
    pub kind: FileType,
    /// Entry name (filename component, not a full path).
    pub name: Vec<u8>,
}

impl DirEntry {
    /// Return the name as a UTF-8 string (lossy).
    #[must_use]
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// Shared page returned by [`FsOps::readdir`].
///
/// The page holds an `Arc` to the full directory snapshot plus a visible range.
/// Hot FUSE callers can iterate the slice without cloning each `DirEntry` name,
/// while tests and convenience wrappers can still materialize an owned `Vec`
/// when they need one.
#[derive(Debug, Clone)]
pub struct ReaddirPage {
    entries: Arc<Vec<DirEntry>>,
    start: usize,
    end: usize,
}

impl ReaddirPage {
    /// Construct a page covering an owned vector.
    #[must_use]
    pub fn new(entries: Vec<DirEntry>) -> Self {
        let end = entries.len();
        Self {
            entries: Arc::new(entries),
            start: 0,
            end,
        }
    }

    /// Construct a page over a shared full listing.
    #[must_use]
    pub(crate) fn from_shared(entries: Arc<Vec<DirEntry>>, start: usize, end: usize) -> Self {
        debug_assert!(start <= end);
        debug_assert!(end <= entries.len());
        Self {
            entries,
            start,
            end,
        }
    }

    /// Return the visible page slice.
    #[must_use]
    pub fn as_slice(&self) -> &[DirEntry] {
        &self.entries[self.start..self.end]
    }

    /// Iterate over the visible entries without cloning.
    pub fn iter(&self) -> std::slice::Iter<'_, DirEntry> {
        self.as_slice().iter()
    }

    /// Number of visible entries in this page.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether this page contains no visible entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Materialize the visible entries as an owned vector.
    #[must_use]
    pub fn to_vec(&self) -> Vec<DirEntry> {
        self.as_slice().to_vec()
    }

    #[cfg(test)]
    pub(crate) fn shares_entries_with(&self, entries: &Arc<Vec<DirEntry>>) -> bool {
        Arc::ptr_eq(&self.entries, entries)
    }
}

impl From<Vec<DirEntry>> for ReaddirPage {
    fn from(entries: Vec<DirEntry>) -> Self {
        Self::new(entries)
    }
}

impl std::ops::Deref for ReaddirPage {
    type Target = [DirEntry];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a ReaddirPage {
    type Item = &'a DirEntry;
    type IntoIter = std::slice::Iter<'a, DirEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A single extent returned by [`FsOps::fiemap`].
///
/// Mirrors `struct fiemap_extent` from `<linux/fiemap.h>`. All offsets and
/// lengths are in **bytes** (not blocks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiemapExtent {
    /// Logical offset in the file (bytes).
    pub logical: u64,
    /// Physical offset on the device (bytes).
    pub physical: u64,
    /// Length in bytes.
    pub length: u64,
    /// Flags bitmap (FIEMAP_EXTENT_* constants).
    pub flags: u32,
}

/// FIEMAP extent flag: this extent is the last in the file.
pub const FIEMAP_EXTENT_LAST: u32 = 0x0001;
/// FIEMAP extent flag: data cannot be read while the fs is unmounted (e.g. it
/// is compressed/encoded on disk).
pub const FIEMAP_EXTENT_ENCODED: u32 = 0x0008;
/// FIEMAP extent flag: extent offsets may not be block aligned.
pub const FIEMAP_EXTENT_NOT_ALIGNED: u32 = 0x0100;
/// FIEMAP extent flag: data is mixed with metadata (inline). Implies
/// `FIEMAP_EXTENT_NOT_ALIGNED`.
pub const FIEMAP_EXTENT_DATA_INLINE: u32 = 0x0200;
/// FIEMAP extent flag: this extent is unwritten / preallocated.
pub const FIEMAP_EXTENT_UNWRITTEN: u32 = 0x0800;
/// FIEMAP extent flag: the disk extent is shared with other files (reflink /
/// snapshot — the extent's refcount is greater than one).
pub const FIEMAP_EXTENT_SHARED: u32 = 0x2000;

/// Seek whence for [`FsOps::lseek`].
///
/// Standard POSIX whence values plus `SEEK_DATA`/`SEEK_HOLE` for sparse file
/// support (FUSE 7.24+). Required for efficient sparse file handling in
/// `cp --sparse`, `rsync`, and `tar`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeekWhence {
    /// Seek relative to start of file.
    Set,
    /// Seek relative to current position (not used by FUSE lseek, but included
    /// for completeness).
    Cur,
    /// Seek relative to end of file.
    End,
    /// Find the next data (non-hole) region at or after the offset.
    Data,
    /// Find the next hole (unallocated) region at or after the offset.
    Hole,
}

impl SeekWhence {
    // POSIX whence constants (from <unistd.h> / libc)
    const SEEK_SET: i32 = 0;
    const SEEK_CUR: i32 = 1;
    const SEEK_END: i32 = 2;
    const SEEK_DATA: i32 = 3;
    const SEEK_HOLE: i32 = 4;

    /// Convert from raw POSIX whence value.
    ///
    /// Returns `None` for unrecognized values.
    #[must_use]
    pub fn from_raw(whence: i32) -> Option<Self> {
        match whence {
            Self::SEEK_SET => Some(Self::Set),
            Self::SEEK_CUR => Some(Self::Cur),
            Self::SEEK_END => Some(Self::End),
            Self::SEEK_DATA => Some(Self::Data),
            Self::SEEK_HOLE => Some(Self::Hole),
            _ => None,
        }
    }
}

/// FUSE/VFS operation kind used for MVCC request-scope hooks.
///
/// These operation tags let `FsOps` implementations choose an MVCC policy per
/// request (for example: read-snapshot only vs. begin write transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RequestOp {
    Getattr,
    Statfs,
    Getxattr,
    Lookup,
    Listxattr,
    Flush,
    Fsync,
    Fsyncdir,
    Open,
    Release,
    Opendir,
    Read,
    Readdir,
    Readlink,
    Lseek,
    // Write operations
    Create,
    Mkdir,
    Unlink,
    Rmdir,
    Rename,
    Link,
    Symlink,
    Fallocate,
    Setattr,
    Setxattr,
    Removexattr,
    Write,
    RepairWriteback,
    IoctlRead,
    IoctlWrite,
}

const fn request_op_bit(op: RequestOp) -> u32 {
    1_u32 << op.as_index()
}

impl RequestOp {
    /// Number of request operation variants.
    pub const COUNT: usize = Self::IoctlWrite as usize + 1;
    const METADATA_WRITE_MASK: u32 = request_op_bit(Self::Create)
        | request_op_bit(Self::Mkdir)
        | request_op_bit(Self::Unlink)
        | request_op_bit(Self::Rmdir)
        | request_op_bit(Self::Rename)
        | request_op_bit(Self::Link)
        | request_op_bit(Self::Symlink)
        | request_op_bit(Self::Setattr)
        | request_op_bit(Self::Setxattr)
        | request_op_bit(Self::Removexattr)
        | request_op_bit(Self::IoctlWrite);
    const WRITE_MASK: u32 = Self::METADATA_WRITE_MASK
        | request_op_bit(Self::Fsync)
        | request_op_bit(Self::Fsyncdir)
        | request_op_bit(Self::Fallocate)
        | request_op_bit(Self::Write)
        | request_op_bit(Self::RepairWriteback);

    /// Dense operation index for hot-path policy tables.
    #[must_use]
    pub const fn as_index(self) -> usize {
        self as usize
    }

    /// Whether this operation mutates the filesystem.
    #[must_use]
    pub const fn is_write(self) -> bool {
        (Self::WRITE_MASK & request_op_bit(self)) != 0
    }

    /// Whether this operation is a metadata-only write.
    #[must_use]
    pub const fn is_metadata_write(self) -> bool {
        (Self::METADATA_WRITE_MASK & request_op_bit(self)) != 0
    }
}

/// Commit boundary policy carried by an MVCC request scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestCommitMode {
    /// The current FUSE behavior: commit before the request returns.
    PerRequest,
    /// A caller is deliberately holding the scope across several writes and
    /// will commit it at a flush/fsync/release boundary.
    DeferredUntilFlush,
}

impl Default for RequestCommitMode {
    fn default() -> Self {
        Self::PerRequest
    }
}

/// MVCC scope acquired for a single VFS request or an explicit writeback batch.
///
/// Current read-only implementations can return an empty scope. Future write
/// implementations may attach a transaction captured at request
/// start so that begin/end hooks can manage commit/abort semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestScope {
    pub snapshot: Option<Snapshot>,
    pub tx: Option<ffs_mvcc::Transaction>,
    #[serde(default)]
    pub commit_mode: RequestCommitMode,
    /// Set by callers (e.g. `readdirplus`) that immediately `getattr` every
    /// returned entry themselves, so the readdir-internal inode-table prefetch
    /// fan-out is pure duplicate work (a second parallel pass over the same
    /// blocks the caller's getattr fan-out already reads). Default `false`
    /// preserves the prefetch for plain-`readdir`-then-stat callers (e.g. a
    /// `find | xargs stat` walk) that DO benefit from the cache warm.
    #[serde(default)]
    pub skip_readdir_prefetch: bool,
}

impl RequestScope {
    /// Create a scope with no snapshot or transaction attached.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            snapshot: None,
            tx: None,
            commit_mode: RequestCommitMode::PerRequest,
            skip_readdir_prefetch: false,
        }
    }

    /// Create a scope tied to a specific MVCC snapshot.
    #[must_use]
    pub fn with_snapshot(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Some(snapshot),
            tx: None,
            commit_mode: RequestCommitMode::PerRequest,
            skip_readdir_prefetch: false,
        }
    }

    /// Create a scope around an existing write transaction.
    #[must_use]
    pub fn with_transaction(tx: ffs_mvcc::Transaction) -> Self {
        Self {
            snapshot: Some(tx.snapshot()),
            tx: Some(tx),
            commit_mode: RequestCommitMode::PerRequest,
            skip_readdir_prefetch: false,
        }
    }

    /// Mark this write scope as intentionally held until a flush boundary.
    pub fn defer_commit_until_flush(&mut self) {
        self.commit_mode = RequestCommitMode::DeferredUntilFlush;
    }

    /// Whether this scope is a deliberate writeback batch.
    #[must_use]
    pub const fn is_deferred_until_flush(&self) -> bool {
        matches!(self.commit_mode, RequestCommitMode::DeferredUntilFlush)
    }

    /// Number of currently staged block writes.
    #[must_use]
    pub fn pending_write_count(&self) -> usize {
        self.tx
            .as_ref()
            .map_or(0, ffs_mvcc::Transaction::pending_writes)
    }

    /// Commit the transaction if one is present.
    ///
    /// Returns the commit sequence on success, or an error if the commit failed.
    /// Returns `Ok(CommitSeq(0))` if no transaction was attached.
    pub(crate) fn commit_if_write(
        &mut self,
        mvcc_store: &FsMvccStore,
    ) -> ffs_error::Result<CommitSeq> {
        self.tx.take().map_or(Ok(CommitSeq(0)), |tx| {
            let tx_id = tx.id().0;
            mvcc_store.commit(tx).map_err(|error| match error {
                ffs_mvcc::CommitError::Conflict { block, .. }
                | ffs_mvcc::CommitError::ChainBackpressure { block, .. } => {
                    ffs_error::FfsError::MvccConflict {
                        tx: tx_id,
                        block: block.0,
                    }
                }
                ffs_mvcc::CommitError::SsiConflict { pivot_block, .. } => {
                    ffs_error::FfsError::MvccConflict {
                        tx: tx_id,
                        block: pivot_block.0,
                    }
                }
                ffs_mvcc::CommitError::DurabilityFailure { detail } => {
                    ffs_error::FfsError::Io(std::io::Error::other(format!(
                        "MVCC durability failure during request-scope commit: {detail}"
                    )))
                }
            })
        })
    }
}

/// Inode state surfaced by the `FS_IOC_FSGETXATTR` / `FS_IOC_FSSETXATTR`
/// ioctls — a Rust mirror of `struct fsxattr` from `<linux/fs.h>`.
///
/// The on-the-wire encoding is 28 bytes little-endian:
/// `xflags | extsize | nextents | projid | cowextsize | 8 bytes pad`.
/// xflags bits are documented in `uapi/linux/fs.h::FS_XFLAG_*` and are
/// the chattr/lsattr-visible projection of the underlying filesystem
/// inode flags. Backends populate the fields they support and zero
/// the rest; ext4 sets `xflags`, `nextents`, and `projid` and leaves
/// `extsize` + `cowextsize` at zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsxattrInfo {
    /// chattr-style flags mapped from filesystem-specific `i_flags`.
    pub xflags: u32,
    /// XFS-specific extent size hint (0 for ext4).
    pub extsize: u32,
    /// Live count of extents allocated to the inode (0 for inline-data
    /// or non-extent-tree inodes).
    pub nextents: u32,
    /// Project ID for project-based quota accounting.
    pub projid: u32,
    /// XFS-specific CoW extent size hint (0 for ext4).
    pub cowextsize: u32,
}

/// Search bounds supplied by `BTRFS_IOC_TREE_SEARCH`.
///
/// The kernel treats btrfs keys as a 136-bit ordered tuple
/// `(objectid, item_type, offset)` and returns every metadata item whose key
/// falls inside the inclusive `[min, max]` range, capped by `nr_items` and the
/// ioctl reply buffer size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsTreeSearchKey {
    /// Tree objectid to search; zero means the mounted subvolume tree.
    pub tree_id: u64,
    pub min_objectid: u64,
    pub max_objectid: u64,
    pub min_offset: u64,
    pub max_offset: u64,
    pub min_transid: u64,
    pub max_transid: u64,
    pub min_type: u32,
    pub max_type: u32,
    /// Caller-requested item cap; the backend returns the actual count.
    pub nr_items: u32,
}

/// xflags bits per `<uapi/linux/fs.h>`. Only the subset that ext4
/// `i_flags` can map onto is used by the FrankenFS backend; the rest
/// are XFS- or DAX-specific and stay zero on a getxattr return.
pub mod xflags {
    pub const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
    pub const FS_XFLAG_APPEND: u32 = 0x0000_0010;
    pub const FS_XFLAG_SYNC: u32 = 0x0000_0020;
    pub const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
    pub const FS_XFLAG_NODUMP: u32 = 0x0000_0080;
    pub const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;
    pub const FS_XFLAG_NODEFRAG: u32 = 0x0000_2000;
    pub const FS_XFLAG_DAX: u32 = 0x0000_8000;
    /// Set when at least one inode-level xflag is in effect; ext4
    /// surfaces this whenever the mapped flag set is non-empty so
    /// userspace can tell "no chattrs" from "queried successfully".
    pub const FS_XFLAG_HASATTR: u32 = 0x8000_0000;
}

/// Request to modify inode attributes via `setattr`.
///
/// Each field is `Option` — only present fields are applied. Missing fields
/// leave the corresponding attribute unchanged.
#[derive(Debug, Clone, Default)]
pub struct SetAttrRequest {
    /// New permission mode bits (lower 12 bits of st_mode).
    pub mode: Option<u16>,
    /// New owner UID.
    pub uid: Option<u32>,
    /// New owner GID.
    pub gid: Option<u32>,
    /// New file size (truncate/extend).
    pub size: Option<u64>,
    /// New access time.
    pub atime: Option<SystemTime>,
    /// New modification time.
    pub mtime: Option<SystemTime>,
}

/// Request to release a backend-managed open file handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseRequest {
    /// Inode whose open file handle is being released.
    pub ino: InodeNumber,
    /// Backend file handle returned from `open`.
    pub fh: u64,
    /// Open flags supplied by the kernel.
    pub flags: i32,
    /// Optional lock owner supplied by the kernel.
    pub lock_owner: Option<u64>,
    /// Whether release should flush pending state.
    pub flush: bool,
}

/// How `setxattr` should treat pre-existing attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrSetMode {
    /// Create if missing, replace if existing.
    Set,
    /// Fail with `EEXIST` if the attribute already exists.
    Create,
    /// Fail with `ENODATA`/`ENOATTR` if the attribute does not exist.
    Replace,
}

/// Filesystem statistics returned by `statfs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsStat {
    /// Total data blocks in filesystem units.
    pub blocks: u64,
    /// Free data blocks.
    pub blocks_free: u64,
    /// Free blocks available to unprivileged callers.
    pub blocks_available: u64,
    /// Total inode count (or object count when available).
    pub files: u64,
    /// Free inode/object count.
    pub files_free: u64,
    /// Preferred block size in bytes.
    pub block_size: u32,
    /// Maximum filename length.
    pub name_max: u32,
    /// Fundamental fragment size in bytes.
    pub fragment_size: u32,
}

/// Quota type (user, group, or project).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuotaType {
    /// User quota (per-UID limits).
    User,
    /// Group quota (per-GID limits).
    Group,
    /// Project quota (per-project-ID limits).
    Project,
}

/// Quota usage and limits for a single ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaEntry {
    /// The ID (UID, GID, or project ID depending on quota type).
    pub id: u32,
    /// Current space usage in bytes.
    pub space_used: u64,
    /// Soft limit for space in bytes (0 = no limit).
    pub space_soft_limit: u64,
    /// Hard limit for space in bytes (0 = no limit).
    pub space_hard_limit: u64,
    /// Current inode usage count.
    pub inodes_used: u64,
    /// Soft limit for inode count (0 = no limit).
    pub inodes_soft_limit: u64,
    /// Hard limit for inode count (0 = no limit).
    pub inodes_hard_limit: u64,
}

/// Summary of filesystem quota configuration and status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaInfo {
    /// Whether user quotas are enabled.
    pub user_quota_enabled: bool,
    /// User quota inode number (if enabled).
    pub user_quota_inum: Option<u32>,
    /// Whether group quotas are enabled.
    pub group_quota_enabled: bool,
    /// Group quota inode number (if enabled).
    pub group_quota_inum: Option<u32>,
    /// Whether project quotas are enabled.
    pub project_quota_enabled: bool,
    /// Project quota inode number (if enabled).
    pub project_quota_inum: Option<u32>,
}

/// VFS operations trait for filesystem access.
///
/// This is the internal interface that FUSE and the test harness call.
/// Format-specific implementations (ext4, btrfs) live behind this trait so
/// that higher layers are filesystem-agnostic.
///
/// # Design Notes
///
/// - All methods take `&Cx` for cooperative cancellation and deadline
///   propagation via the asupersync runtime.
/// - Errors are returned as `ffs_error::FfsError`, which maps to POSIX
///   errnos via [`FfsError::to_errno()`].
/// - The trait is `Send + Sync` so that FUSE can call it from multiple
///   threads concurrently.
/// - Write operations have default implementations returning `FfsError::ReadOnly`.
/// - `begin_request_scope`/`end_request_scope` provide a policy hook for
///   per-request MVCC snapshot/transaction management.
pub trait FsOps: Send + Sync {
    /// Get file attributes by inode number.
    ///
    /// Returns the attributes for the given inode. Returns
    /// `FfsError::NotFound` if the inode does not exist.
    fn getattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr>;

    /// Look up a directory entry by name.
    ///
    /// Returns the attributes of the child inode named `name` within the
    /// directory `parent`. Returns `FfsError::NotFound` if the name does
    /// not exist, or `FfsError::NotDirectory` if `parent` is not a directory.
    fn lookup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<InodeAttr>;

    /// List directory entries starting from `offset`.
    ///
    /// Returns a batch of entries from the directory identified by `ino`.
    /// The `offset` parameter is an opaque cookie from a previous call's
    /// `DirEntry::offset` field (use 0 for the first call). An empty
    /// result indicates the end of the directory.
    ///
    /// Returns `FfsError::NotDirectory` if `ino` is not a directory.
    fn readdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> ffs_error::Result<ReaddirPage>;

    /// Read file data.
    ///
    /// Returns up to `size` bytes starting at byte `offset` within the
    /// file identified by `ino`. Returns fewer bytes at EOF. Returns
    /// `FfsError::IsDirectory` if `ino` is a directory.
    fn read(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>>;

    /// Open a file and optionally return backend-managed handle state.
    ///
    /// Stateless implementations should return `(0, 0)`, matching the FUSE
    /// open reply's default file handle and open flags.
    fn open(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _flags: i32,
    ) -> ffs_error::Result<(u64, u32)> {
        Ok((0, 0))
    }

    /// Read the target of a symbolic link.
    ///
    /// Returns the raw bytes of the symlink target. Returns
    /// `FfsError::Format` if `ino` is not a symlink.
    fn readlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>>;

    /// Return filesystem-level capacity and free-space statistics.
    fn statfs(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<FsStat> {
        Err(FfsError::UnsupportedFeature(
            "statfs is not supported by this backend".to_owned(),
        ))
    }

    /// List extended attribute names for an inode.
    ///
    /// Returns the full attribute names (including namespace prefix, e.g.
    /// `"user.myattr"`, `"security.selinux"`). The default first validates
    /// that the inode exists, then returns an empty list for filesystems that
    /// do not model xattrs.
    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<String>> {
        let mut scope = RequestScope::empty();
        self.getattr(cx, &mut scope, ino)?;
        Ok(Vec::new())
    }

    /// Get the value of an extended attribute by full name.
    ///
    /// The `name` parameter is the full attribute name including namespace
    /// prefix (e.g. `"user.myattr"`). The default first validates that the
    /// inode exists, then returns `None` for filesystems that do not model
    /// xattrs.
    fn getxattr(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<Option<Vec<u8>>> {
        let _ = name;
        let mut scope = RequestScope::empty();
        self.getattr(cx, &mut scope, ino)?;
        Ok(None)
    }

    // ── Write operations (default: return ReadOnly) ─────────────────────

    /// Create, replace, or upsert one extended attribute.
    fn setxattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _name: &str,
        _value: &[u8],
        _mode: XattrSetMode,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Remove one extended attribute.
    ///
    /// Returns `true` if the attribute existed and was removed.
    fn removexattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _name: &str,
    ) -> ffs_error::Result<bool> {
        Err(FfsError::ReadOnly)
    }

    /// Create a regular file in directory `parent` with name `name`.
    ///
    /// Returns attributes of the newly created inode.
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _mode: u16,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Create a directory in `parent` with name `name`.
    #[allow(clippy::too_many_arguments)]
    fn mkdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _mode: u16,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Remove a non-directory entry from `parent`.
    fn unlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Remove an empty directory entry from `parent`.
    fn rmdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Rename an entry from `parent`/`name` to `new_parent`/`new_name`.
    fn rename(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _new_parent: InodeNumber,
        _new_name: &OsStr,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// `mknod(2)` for non-regular file types.
    ///
    /// `mode` carries the full S_IF* + permission bits. `rdev` is the
    /// `makedev(2)`-encoded device number, ignored for FIFO and socket.
    /// Regular-file creation goes through [`Self::create`] and dirs
    /// through [`Self::mkdir`]; this method handles char/block devices,
    /// FIFOs, and sockets — the file types that overlayfs whiteouts,
    /// POSIX named pipes, and Unix-domain socket files depend on.
    ///
    /// The default implementation returns `ENOTSUP` so backends that
    /// only support regular files (e.g. tests, read-only mounts) are
    /// not silently broken when callers expect device-creation
    /// semantics.
    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _mode: u16,
        _rdev: u32,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::Io(std::io::Error::from_raw_os_error(
            libc::ENOTSUP,
        )))
    }

    /// Rename with `renameat2(2)` flags (FUSE_RENAME2 opcode).
    ///
    /// `flags` is the bitset defined by `<linux/fs.h>`:
    /// - `0`  — classic rename (overwrite target if it exists).
    /// - `RENAME_NOREPLACE` (1) — fail with `EEXIST` if the destination
    ///   exists. The check + rename must be atomic under the parent
    ///   directory locks held by the caller.
    /// - `RENAME_EXCHANGE` (2) — atomically swap two existing entries.
    /// - `RENAME_WHITEOUT` (4) — used by overlayfs; not currently supported.
    ///
    /// The default implementation delegates to [`Self::rename`] when
    /// `flags == 0` and returns `EINVAL` for any non-zero flags so that
    /// callers cannot silently get classic-rename semantics on an
    /// implementation that does not honour the requested mode.
    #[allow(clippy::too_many_arguments)]
    fn rename2(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
        flags: u32,
    ) -> ffs_error::Result<()> {
        if flags == 0 {
            return self.rename(cx, scope, parent, name, new_parent, new_name);
        }
        Err(FfsError::Io(std::io::Error::from_raw_os_error(
            libc::EINVAL,
        )))
    }

    /// Write data to file `ino` at byte `offset`. Returns bytes written.
    fn write(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        _data: &[u8],
    ) -> ffs_error::Result<u32> {
        Err(FfsError::ReadOnly)
    }

    /// Copy bytes between two regular files.
    ///
    /// The default implementation preserves Linux `copy_file_range(2)` safety
    /// semantics and streams through the existing read/write contract in large
    /// chunks. Format-specific implementations can override this with an
    /// extent-aware clone path.
    #[allow(clippy::too_many_arguments)]
    fn copy_file_range(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino_in: InodeNumber,
        offset_in: u64,
        ino_out: InodeNumber,
        offset_out: u64,
        len: u64,
    ) -> ffs_error::Result<u64> {
        if len == 0 {
            return Ok(0);
        }
        if offset_in.checked_add(len).is_none() || offset_out.checked_add(len).is_none() {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }
        if ino_in == ino_out && ranges_overlap(offset_in, len, offset_out, len) {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }

        let mut copied = 0_u64;
        while copied < len {
            let remaining = len - copied;
            let request_len =
                COPY_FILE_RANGE_CHUNK_BYTES.min(u32::try_from(remaining).unwrap_or(u32::MAX));
            let src_offset = offset_in + copied;
            let dst_offset = offset_out + copied;
            let mut data = self.read(cx, scope, ino_in, src_offset, request_len)?;
            let request_len = usize::try_from(request_len).unwrap_or(usize::MAX);
            if data.len() > request_len {
                data.truncate(request_len);
            }
            if data.is_empty() {
                break;
            }

            let written = self.write(cx, scope, ino_out, dst_offset, &data)?;
            let written = usize::try_from(written)
                .unwrap_or(usize::MAX)
                .min(data.len());
            if written == 0 {
                break;
            }
            copied = copied.saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
            if written < data.len() {
                break;
            }
        }

        Ok(copied)
    }

    /// Create a hard link to `ino` in `new_parent` under `new_name`.
    fn link(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _new_parent: InodeNumber,
        _new_name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Create a symlink in `parent` named `name` targeting `target`.
    #[allow(clippy::too_many_arguments)]
    fn symlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _target: &Path,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Preallocate or punch file space (POSIX `fallocate`-style).
    fn fallocate(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        _length: u64,
        _mode: i32,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Query extent mappings for a file (FIEMAP semantics).
    ///
    /// Returns extent entries covering the byte range `[start, start+length)`.
    /// If `length` is `u64::MAX`, returns all extents from `start` to EOF.
    /// Directories and symlinks return `FfsError::InvalidArgument`.
    fn fiemap(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _start: u64,
        _length: u64,
    ) -> ffs_error::Result<Vec<FiemapExtent>> {
        Err(FfsError::UnsupportedFeature(
            "fiemap is not supported by this backend".to_owned(),
        ))
    }

    /// Reposition read offset for SEEK_HOLE/SEEK_DATA support.
    ///
    /// Implements the `lseek(2)` system call semantics for sparse file queries:
    ///
    /// - `SeekWhence::Data`: Returns the offset of the next data (non-hole) region
    ///   at or after `offset`. If `offset` points to data, returns `offset`.
    /// - `SeekWhence::Hole`: Returns the offset of the next hole (unallocated) region
    ///   at or after `offset`. If `offset` points to a hole, returns `offset`.
    ///   The virtual hole at EOF counts as a hole.
    ///
    /// Returns `FfsError::InvalidArgument` (maps to `ENXIO`) if:
    /// - `offset` is at or beyond the file size
    /// - No data/hole exists after `offset` (for `SEEK_DATA`/`SEEK_HOLE` respectively)
    ///
    /// Standard `SEEK_SET`/`SEEK_CUR`/`SEEK_END` are handled by the FUSE layer
    /// and do not call this method.
    fn lseek(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        _whence: SeekWhence,
    ) -> ffs_error::Result<u64> {
        Err(FfsError::UnsupportedFeature(
            "lseek SEEK_HOLE/SEEK_DATA is not supported by this backend".to_owned(),
        ))
    }

    /// Read the inode-level state surfaced by `FS_IOC_FSGETXATTR`
    /// (28-byte `struct fsxattr` from `<linux/fs.h>`).
    ///
    /// The default implementation returns
    /// [`FfsError::UnsupportedFeature`]; backends that expose chattr-style
    /// flags + project IDs override this. ext4 maps `i_flags` ->
    /// `fsx_xflags` per uapi/linux/fs.h; `fsx_projid` from `i_projid`;
    /// `fsx_nextents` from the live extent count; `fsx_extsize` and
    /// `fsx_cowextsize` are 0 (ext4 does not implement them).
    fn get_inode_fsxattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<FsxattrInfo> {
        Err(FfsError::UnsupportedFeature(
            "get_inode_fsxattr is not supported by this backend".to_owned(),
        ))
    }

    /// Service `FITRIM` (`_IOWR('X', 121, struct fstrim_range)`).
    ///
    /// `start` + `len` describe the byte range that fstrim(8) wants
    /// the FS to release back to the underlying device; `min_len` is
    /// a hint at the smallest contiguous run worth discarding. The
    /// return value is the number of bytes actually discarded — the
    /// kernel writes it back into `fstrim_range.len` so userspace
    /// can report it.
    ///
    /// FrankenFS runs in userspace over a `BlockDevice` that does not
    /// expose a discard syscall, so the default implementation
    /// validates the range against the underlying device size and
    /// returns 0 (zero bytes discarded, call succeeded) — matches
    /// Linux's behaviour on filesystems mounted on non-discard-capable
    /// devices.
    fn trim_range(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _start: u64,
        _len: u64,
        _min_len: u64,
    ) -> ffs_error::Result<u64> {
        Err(FfsError::UnsupportedFeature(
            "trim_range is not supported by this backend".to_owned(),
        ))
    }

    /// Return the 16-byte filesystem UUID.
    ///
    /// Surfaces what `FS_IOC_GETFSUUID` (Linux 6.5+) returns. ext4
    /// reads `s_uuid`; btrfs reads `s_fsid`. The default returns
    /// [`FfsError::UnsupportedFeature`] for backends that do not
    /// model an FS-level UUID.
    fn fs_uuid(&self) -> ffs_error::Result<[u8; 16]> {
        Err(FfsError::UnsupportedFeature(
            "fs_uuid is not supported by this backend".to_owned(),
        ))
    }

    /// Return the kernel-side sysfs path of the underlying block device,
    /// or an empty `Vec` for backends with no sysfs visibility.
    ///
    /// Surfaces what `FS_IOC_GETFSSYSFSPATH` (Linux 6.7+) returns. The
    /// kernel struct is `u8 len + u8 name[128]` (129 bytes total).
    /// Userspace probes (systemd-mount, blkid, util-linux) treat
    /// `len == 0` as "no sysfs path available" and silently skip rather
    /// than erroring, so a userspace FUSE backend whose `ByteDevice` has
    /// no /sys entry should return an empty `Vec` here. The dispatcher
    /// pads to 128 bytes and writes `len` as the first byte.
    ///
    /// Backends that DO surface a sysfs path (e.g., a future loop-device
    /// adapter that knows its `/sys/block/loopN` path) must return at
    /// most 128 bytes; longer paths are rejected as `EINVAL` by the
    /// dispatcher to keep the wire-format contract.
    fn fs_sysfs_path(&self) -> ffs_error::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    /// Apply userspace-supplied [`FsxattrInfo`] (the `FS_IOC_FSSETXATTR`
    /// payload) to the inode.
    ///
    /// Backends translate `xflags` back into their native flag set,
    /// stash `projid`, and reject unsupported fields with `EINVAL` /
    /// `EOPNOTSUPP`. The default implementation returns
    /// [`FfsError::UnsupportedFeature`] so backends that opt in must
    /// override it explicitly.
    fn set_inode_fsxattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _info: FsxattrInfo,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "set_inode_fsxattr is not supported by this backend".to_owned(),
        ))
    }

    /// Get filesystem-specific inode flags (ext4 `EXT4_IOC_GETFLAGS`).
    ///
    /// Returns the raw `i_flags` field for the given inode.
    fn get_inode_flags(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        Err(FfsError::UnsupportedFeature(
            "get_inode_flags is not supported by this backend".to_owned(),
        ))
    }

    /// Return the kernel-side runtime state bitmap for an inode.
    ///
    /// Surfaces what `EXT4_IOC_GETSTATE` reports — the
    /// `EXT4_STATE_FLAG_*` bits used by `e2fsprogs` and `debugfs` for
    /// diagnostic dumps (`EXT_PRECACHED`, `NEW`, `NEWENTRY`,
    /// `DA_ALLOC_CLOSE`). These are kernel-side transient flags with
    /// no persistent on-disk representation, so a userspace FUSE
    /// backend has nothing meaningful to expose; the default returns
    /// `0`. Backends with inode identity should override this to
    /// validate that `ino` exists.
    fn get_inode_state(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        Ok(0)
    }

    /// Hint that the caller is about to walk the inode and would like
    /// the extent metadata read into the page cache up-front.
    ///
    /// Surfaces what `EXT4_IOC_PRECACHE_EXTENTS` triggers in the kernel:
    /// `fs/ext4/ioctl.c::ext4_ext_precache` walks the on-disk extent
    /// tree for the inode and pulls every internal/leaf block into the
    /// page cache so subsequent reads don't stall on metadata I/O. The
    /// kernel returns 0 even when the inode has no extents — the
    /// contract is "best effort, never an error for a valid inode."
    /// Backends without an out-of-band cache are free to no-op (the
    /// default), but they should still validate that the inode exists.
    fn precache_extents(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Drop the in-memory extent status cache for an inode.
    ///
    /// Surfaces what `EXT4_IOC_CLEAR_ES_CACHE` triggers in the kernel:
    /// `fs/ext4/ioctl.c::ext4_clear_inode_es` removes every cached
    /// `ext4_es_status` entry so the next read repopulates state from
    /// the on-disk extent tree. e2fsprogs uses this to defeat caching
    /// after offline metadata edits via `debugfs`. FrankenFS keeps
    /// extent state per-`RequestScope` rather than in a long-lived
    /// inode-level cache, so the default implementation is a successful
    /// no-op — backends only need to override if they expose a
    /// process-lifetime cache that needs explicit invalidation.
    fn clear_extent_status_cache(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Get ext4 inode generation (`EXT4_IOC_GETVERSION`).
    ///
    /// Returns the raw `i_generation` field for the given inode.
    fn get_inode_generation(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        Err(FfsError::UnsupportedFeature(
            "get_inode_generation is not supported by this backend".to_owned(),
        ))
    }

    /// Set ext4 inode generation (`EXT4_IOC_SETVERSION`).
    fn set_inode_generation(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _generation: u32,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "set_inode_generation is not supported by this backend".to_owned(),
        ))
    }

    /// Get the legacy fscrypt v1 encryption policy (`FS_IOC_GET_ENCRYPTION_POLICY`).
    ///
    /// Returns the raw 12-byte `struct fscrypt_policy_v1` payload for the given
    /// inode. Backends should return `ENODATA` if the inode is not encrypted,
    /// and `EINVAL` if the inode uses a newer policy version.
    fn get_encryption_policy_v1(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<[u8; 12]> {
        Err(FfsError::UnsupportedFeature(
            "get_encryption_policy_v1 is not supported by this backend".to_owned(),
        ))
    }

    /// Get the fscrypt encryption policy (`FS_IOC_GET_ENCRYPTION_POLICY_EX`).
    ///
    /// Returns the policy version (0 for v1, 2 for v2) and the raw policy bytes.
    /// For v1: 12 bytes; for v2: 24 bytes.
    /// Returns `ENODATA` if the inode is not encrypted.
    fn get_encryption_policy_ex(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<(u8, Vec<u8>)> {
        Err(FfsError::UnsupportedFeature(
            "get_encryption_policy_ex is not supported by this backend".to_owned(),
        ))
    }

    /// Get the filesystem label (`FS_IOC_GETFSLABEL`).
    ///
    /// Returns the filesystem label as a null-terminated byte vector.
    /// ext4: up to 16 bytes from `s_volume_name`.
    /// btrfs: up to 256 bytes from superblock `label`.
    fn get_fs_label(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_fs_label is not supported by this backend".to_owned(),
        ))
    }

    /// Set the filesystem label (`FS_IOC_SETFSLABEL`).
    ///
    /// `label` is the userspace payload without the terminating NUL byte.
    /// Backends should reject labels that exceed their filesystem-specific
    /// maximum length with `EINVAL`.
    fn set_fs_label(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _label: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "set_fs_label is not supported by this backend".to_owned(),
        ))
    }

    /// Return the btrfs filesystem-info payload for `BTRFS_IOC_FS_INFO`.
    ///
    /// Implementations should encode a `struct btrfs_ioctl_fs_info_args`
    /// (1024 bytes on x86_64) populated with the live `fs_info` fields:
    /// `max_id`, `num_devices`, `fsid`, `nodesize`, `sectorsize`,
    /// `clone_alignment`, `csum_type`, `csum_size`, `flags`, `generation`,
    /// and `metadata_uuid`.  The returned `Vec<u8>` must be exactly
    /// 1024 bytes so `ffs-fuse` can forward it verbatim to the kernel ioctl
    /// reply buffer.
    ///
    /// Non-btrfs backends must return
    /// `FfsError::UnsupportedFeature`, which `ffs-fuse` maps to
    /// `EOPNOTSUPP` so callers on ext4 see a deterministic rejection
    /// rather than a bogus success.
    fn get_btrfs_fs_info(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_fs_info is not supported by this backend".to_owned(),
        ))
    }

    /// Look up an inode path for `BTRFS_IOC_INO_LOOKUP`.
    ///
    /// Given a `treeid` (subvolume tree objectid, or 0 for the mounted tree)
    /// and an `objectid` (inode number), returns the path from that
    /// subvolume root to the inode. For the subvolume root itself
    /// (objectid == 256), returns an empty path and fills in the actual
    /// mounted treeid when callers pass 0.
    ///
    /// Returns `(treeid, path)` where `treeid` is the resolved tree objectid
    /// and `path` is the NUL-terminated path bytes (empty for root).
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_ino_lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _treeid: u64,
        _objectid: u64,
    ) -> ffs_error::Result<(u64, Vec<u8>)> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_ino_lookup is not supported by this backend".to_owned(),
        ))
    }

    /// Return the btrfs per-device-info payload for `BTRFS_IOC_DEV_INFO`.
    ///
    /// `devid_in` and `uuid_in` are the lookup keys supplied in the ioctl
    /// input struct: the kernel resolves whichever of them is non-zero (or
    /// both) to a device and writes back the full `btrfs_ioctl_dev_info_args`
    /// struct (4096 bytes).  Implementations return the encoded payload on
    /// match, or `FfsError::Io(ENODEV)` when the caller's lookup keys do not
    /// identify a device this filesystem tracks.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`, which
    /// `ffs-fuse` maps to `EOPNOTSUPP`.
    fn get_btrfs_dev_info(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _devid_in: u64,
        _uuid_in: [u8; 16],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_dev_info is not supported by this backend".to_owned(),
        ))
    }

    /// Get btrfs subvolume flags for `BTRFS_IOC_SUBVOL_GETFLAGS`.
    ///
    /// Returns the u64 flags field from the subvolume's ROOT_ITEM. The only
    /// user-visible flag is `BTRFS_SUBVOL_RDONLY` (bit 1).
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn get_subvol_flags(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u64> {
        Err(FfsError::UnsupportedFeature(
            "get_subvol_flags is not supported by this backend".to_owned(),
        ))
    }

    /// Set btrfs subvolume flags for `BTRFS_IOC_SUBVOL_SETFLAGS`.
    ///
    /// Updates the flags field in the subvolume's ROOT_ITEM. The only
    /// user-settable flag is `BTRFS_SUBVOL_RDONLY` (bit 1).
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn set_subvol_flags(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _flags: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "set_subvol_flags is not supported by this backend".to_owned(),
        ))
    }

    /// Set the default btrfs subvolume for `BTRFS_IOC_DEFAULT_SUBVOL`.
    ///
    /// `treeid` is the target ROOT_ITEM objectid. Non-btrfs backends must
    /// return `FfsError::UnsupportedFeature`; read-only btrfs backends should
    /// return `FfsError::ReadOnly`.
    fn btrfs_set_default_subvol(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _treeid: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_set_default_subvol is not supported by this backend".to_owned(),
        ))
    }

    /// Start an explicit btrfs transaction for `BTRFS_IOC_TRANS_START`.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`;
    /// read-only btrfs backends should return `FfsError::ReadOnly`.
    fn btrfs_start_transaction(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_start_transaction is not supported by this backend".to_owned(),
        ))
    }

    /// End an explicit btrfs transaction for `BTRFS_IOC_TRANS_END`.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`;
    /// read-only btrfs backends should return `FfsError::ReadOnly`.
    fn btrfs_end_transaction(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_end_transaction is not supported by this backend".to_owned(),
        ))
    }

    /// Get quota configuration and status.
    ///
    /// Returns a summary of which quota types are enabled and their
    /// corresponding inode numbers. This allows inspection of quota
    /// configuration without parsing quota file contents.
    ///
    /// ext4: Reads `s_usr_quota_inum`, `s_grp_quota_inum`, `s_prj_quota_inum`
    /// from the superblock, conditioned on QUOTA/PROJECT feature bits.
    ///
    /// btrfs: Returns `UnsupportedFeature` (btrfs uses qgroups, not inodes).
    fn get_quota_info(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<QuotaInfo> {
        Err(FfsError::UnsupportedFeature(
            "get_quota_info is not supported by this backend".to_owned(),
        ))
    }

    /// Wait for a btrfs quota rescan to finish (`BTRFS_IOC_QUOTA_RESCAN_WAIT`).
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_wait_quota_rescan(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_wait_quota_rescan is not supported by this backend".to_owned(),
        ))
    }

    /// Query btrfs quota rescan progress (`BTRFS_IOC_QUOTA_RESCAN_STATUS`).
    ///
    /// The returned bytes are the kernel-compatible
    /// `btrfs_ioctl_quota_rescan_args` payload.
    fn btrfs_quota_rescan_status(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_quota_rescan_status is not supported by this backend".to_owned(),
        ))
    }

    /// Start a btrfs quota rescan (`BTRFS_IOC_QUOTA_RESCAN`).
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_start_quota_rescan(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _flags: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_start_quota_rescan is not supported by this backend".to_owned(),
        ))
    }

    /// Control btrfs qgroup quota state (`BTRFS_IOC_QUOTA_CTL`).
    ///
    /// The returned bytes are the kernel-compatible
    /// `btrfs_ioctl_quota_ctl_args` payload.
    fn btrfs_quota_control(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _cmd: u64,
        _status: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_quota_control is not supported by this backend".to_owned(),
        ))
    }

    /// Assign or remove a btrfs qgroup parent/child relationship (`BTRFS_IOC_QGROUP_ASSIGN`).
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_assign_qgroup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _assign: u64,
        _src: u64,
        _dst: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_assign_qgroup is not supported by this backend".to_owned(),
        ))
    }

    /// Create or remove a btrfs qgroup (`BTRFS_IOC_QGROUP_CREATE`).
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_create_qgroup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _create: u64,
        _qgroupid: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_create_qgroup is not supported by this backend".to_owned(),
        ))
    }

    /// Set btrfs qgroup limits (`BTRFS_IOC_QGROUP_LIMIT`).
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_limit_qgroup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _limit: BtrfsQgroupLimitRequest,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_limit_qgroup is not supported by this backend".to_owned(),
        ))
    }

    /// Force filesystem sync/commit (`BTRFS_IOC_SYNC`, `syncfs`).
    ///
    /// For btrfs: commits current transaction if in RW mode.
    /// For ext4: triggers journal checkpoint.
    fn sync_fs(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Start a btrfs transaction sync for `BTRFS_IOC_START_SYNC`.
    ///
    /// Returns the transaction/generation token that callers can later pass to
    /// `BTRFS_IOC_WAIT_SYNC`. Non-btrfs backends must return
    /// `FfsError::UnsupportedFeature`.
    fn btrfs_start_sync(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<u64> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_start_sync is not supported by this backend".to_owned(),
        ))
    }

    /// Wait for a btrfs transaction sync token for `BTRFS_IOC_WAIT_SYNC`.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_wait_sync(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _transid: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_wait_sync is not supported by this backend".to_owned(),
        ))
    }

    /// Get btrfs feature flags for `BTRFS_IOC_GET_FEATURES`.
    ///
    /// Returns 24 bytes: compat_flags (u64) + compat_ro_flags (u64) +
    /// incompat_flags (u64) from the superblock.
    fn get_btrfs_features(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_features is not supported by this backend".to_owned(),
        ))
    }

    /// Get btrfs supported feature flags for `BTRFS_IOC_GET_SUPPORTED_FEATURES`.
    ///
    /// Returns 72 bytes containing three `btrfs_ioctl_feature_flags`
    /// records (each 24 bytes):
    /// 1. Supported features (what this implementation can mount)
    /// 2. Safe-to-set features (what can be enabled on a mounted filesystem)
    /// 3. Safe-to-clear features (what can be disabled on a mounted filesystem)
    ///
    /// Current superblock flags are returned by `get_btrfs_features`.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn get_btrfs_supported_features(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_supported_features is not supported by this backend".to_owned(),
        ))
    }

    /// Set btrfs feature flags for `BTRFS_IOC_SET_FEATURES`.
    ///
    /// Takes raw `btrfs_ioctl_feature_flags[2]` bytes. The kernel interprets
    /// the two 24-byte records as feature bits to enable and feature bits to
    /// clear.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn set_btrfs_features(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _feature_flags: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "set_btrfs_features is not supported by this backend".to_owned(),
        ))
    }

    /// Get btrfs space info for `BTRFS_IOC_SPACE_INFO`.
    ///
    /// Returns per-profile space usage (Data/Metadata/System × Single/DUP/RAID).
    /// Output format: 16-byte header (space_slots=0, total_spaces=N) followed by
    /// N × 24-byte space_info entries (flags, total_bytes, used_bytes).
    ///
    /// `space_slots` is the number of entries the caller can receive. If 0, only
    /// the header is returned with total_spaces set. Otherwise, min(space_slots,
    /// total_spaces) entries are returned.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn get_btrfs_space_info(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _space_slots: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_space_info is not supported by this backend".to_owned(),
        ))
    }

    /// Search a btrfs metadata tree for `BTRFS_IOC_TREE_SEARCH`.
    ///
    /// Returns `(actual_item_count, encoded_headers_and_payloads)`. The byte
    /// vector is the ioctl `buf` tail only: a sequence of 32-byte
    /// `btrfs_ioctl_search_header` records, each immediately followed by the
    /// raw item payload. The FUSE layer writes `actual_item_count` back into
    /// the caller's search key and appends this tail after the 104-byte key.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_tree_search(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _key: BtrfsTreeSearchKey,
    ) -> ffs_error::Result<(u32, Vec<u8>)> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_tree_search is not supported by this backend".to_owned(),
        ))
    }

    /// Get paths referencing an inode for `BTRFS_IOC_INO_PATHS`.
    ///
    /// Given an inode number, walks back-references to find all file paths.
    /// Returns serialized path data matching the kernel's output format.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn get_btrfs_ino_paths(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _inum: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_ino_paths is not supported by this backend".to_owned(),
        ))
    }

    /// Get inodes referencing a logical address for `BTRFS_IOC_LOGICAL_INO`.
    ///
    /// Given a logical byte address, finds inodes with extents covering it.
    /// Returns serialized inode data matching the kernel's output format.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn get_btrfs_logical_ino(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _logical: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_logical_ino is not supported by this backend".to_owned(),
        ))
    }

    /// Extended logical-to-inode lookup for `BTRFS_IOC_LOGICAL_INO_V2`.
    ///
    /// V2 adds flags field (BTRFS_LOGICAL_INO_ARGS_IGNORE_OFFSET).
    fn get_btrfs_logical_ino_v2(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _logical: u64,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_logical_ino_v2 is not supported by this backend".to_owned(),
        ))
    }

    /// Start a btrfs scrub operation for `BTRFS_IOC_SCRUB`.
    ///
    /// Returns 1024-byte scrub_args struct with progress filled in.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_scrub_start(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _devid: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_scrub_start is not supported by this backend".to_owned(),
        ))
    }

    /// Cancel a btrfs scrub operation for `BTRFS_IOC_SCRUB_CANCEL`.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_scrub_cancel(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_scrub_cancel is not supported by this backend".to_owned(),
        ))
    }

    /// Query btrfs scrub progress for `BTRFS_IOC_SCRUB_PROGRESS`.
    ///
    /// Returns 1024-byte scrub_args struct with current progress.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_scrub_progress(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _devid: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_scrub_progress is not supported by this backend".to_owned(),
        ))
    }

    /// Defragment a range of a file for `BTRFS_IOC_DEFRAG_RANGE`.
    ///
    /// Reorganizes extents in the specified range to reduce fragmentation.
    /// For read-only mounts, returns `FfsError::ReadOnly`.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_defrag_range(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _fh: u64,
        _start: u64,
        _len: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_defrag_range is not supported by this backend".to_owned(),
        ))
    }

    /// Create a snapshot for `BTRFS_IOC_SNAP_CREATE_V2`.
    ///
    /// Takes raw vol_args_v2 struct bytes containing source fd, flags, and name.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_snap_create(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_snap_create is not supported by this backend".to_owned(),
        ))
    }

    /// Delete a snapshot for `BTRFS_IOC_SNAP_DESTROY`.
    ///
    /// Takes raw vol_args struct bytes containing the snapshot name.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_snap_destroy(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_snap_destroy is not supported by this backend".to_owned(),
        ))
    }

    /// Delete a snapshot for `BTRFS_IOC_SNAP_DESTROY_V2`.
    ///
    /// V2 variant takes vol_args_v2 with subvolid field.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_snap_destroy_v2(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_snap_destroy_v2 is not supported by this backend".to_owned(),
        ))
    }

    /// Read compressed extents directly for `BTRFS_IOC_ENCODED_READ`.
    ///
    /// Returns raw compressed data without kernel decompression.
    fn btrfs_encoded_read(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_encoded_read is not supported by this backend".to_owned(),
        ))
    }

    /// Write pre-compressed data for `BTRFS_IOC_ENCODED_WRITE`.
    ///
    /// Returns bytes written. Requires write access.
    fn btrfs_encoded_write(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
        _args: &[u8],
    ) -> ffs_error::Result<usize> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_encoded_write is not supported by this backend".to_owned(),
        ))
    }

    /// Resize filesystem for `BTRFS_IOC_RESIZE`.
    ///
    /// Takes vol_args with device:size string.
    fn btrfs_resize(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_resize is not supported by this backend".to_owned(),
        ))
    }

    /// Device replacement control for `BTRFS_IOC_DEV_REPLACE`.
    ///
    /// Start/cancel/query device replacement status.
    fn btrfs_dev_replace(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_dev_replace is not supported by this backend".to_owned(),
        ))
    }

    /// Defragment file for `BTRFS_IOC_DEFRAG` (v1).
    ///
    /// Legacy defrag ioctl, requires write access.
    fn btrfs_defrag(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_defrag is not supported by this backend".to_owned(),
        ))
    }

    /// Scan device for `BTRFS_IOC_SCAN_DEV`.
    ///
    /// Not applicable in FUSE context.
    fn btrfs_scan_dev(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_scan_dev is not supported by this backend".to_owned(),
        ))
    }

    /// Forget a stale device path for `BTRFS_IOC_FORGET_DEV`.
    ///
    /// The ioctl uses `struct btrfs_ioctl_vol_args` and is write-scoped.
    fn btrfs_forget_dev(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_forget_dev is not supported by this backend".to_owned(),
        ))
    }

    /// Send subvolume for `BTRFS_IOC_SEND`.
    ///
    /// Implements btrfs send protocol for incremental/full sends.
    /// `caller_pid` is the PID of the calling process, used to resolve
    /// the `send_fd` via `/proc/<pid>/fd/<fd>`.
    fn btrfs_send(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
        _caller_pid: u32,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_send is not supported by this backend".to_owned(),
        ))
    }

    /// Set received subvol UUID for `BTRFS_IOC_SET_RECEIVED_SUBVOL`.
    ///
    /// Used after btrfs receive to set the received UUID.
    fn btrfs_set_received_subvol(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_set_received_subvol is not supported by this backend".to_owned(),
        ))
    }

    /// Set the btrfs filesystem label for `BTRFS_IOC_SET_FSLABEL`.
    fn btrfs_set_fslabel(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_set_fslabel is not supported by this backend".to_owned(),
        ))
    }

    /// Deduplicate file extents for `BTRFS_IOC_FILE_EXTENT_SAME`.
    fn btrfs_file_extent_same(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_file_extent_same is not supported by this backend".to_owned(),
        ))
    }

    /// Create a subvolume for `BTRFS_IOC_SUBVOL_CREATE_V2`.
    ///
    /// Takes raw vol_args_v2 struct bytes containing flags and name.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_subvol_create(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_subvol_create is not supported by this backend".to_owned(),
        ))
    }

    /// Remove a btrfs device for `BTRFS_IOC_RM_DEV_V2`.
    ///
    /// Takes raw `btrfs_ioctl_vol_args_v2` bytes, which can identify the device
    /// by name or by device id depending on the flags.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_rm_dev_v2(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_rm_dev_v2 is not supported by this backend".to_owned(),
        ))
    }

    /// Add a btrfs device for `BTRFS_IOC_ADD_DEV`.
    ///
    /// Takes raw `btrfs_ioctl_vol_args` bytes containing the device path.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_add_dev(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_add_dev is not supported by this backend".to_owned(),
        ))
    }

    /// Remove a btrfs device for `BTRFS_IOC_RM_DEV`.
    ///
    /// Takes raw `btrfs_ioctl_vol_args` bytes containing the device path.
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_rm_dev(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_rm_dev is not supported by this backend".to_owned(),
        ))
    }

    /// Start a balance operation for `BTRFS_IOC_BALANCE_V2`.
    ///
    /// Takes raw `btrfs_ioctl_balance_args` struct bytes.
    /// Returns `FfsError::ReadOnly` for read-only mounts since balance
    /// requires metadata and data relocation.
    fn btrfs_balance_start(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_balance_start is not supported by this backend".to_owned(),
        ))
    }

    /// Control a running balance operation for `BTRFS_IOC_BALANCE_CTL`.
    ///
    /// `cmd` is the control command (e.g., pause/cancel).
    /// Returns `FfsError::ReadOnly` for read-only mounts.
    fn btrfs_balance_ctl(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _cmd: i32,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_balance_ctl is not supported by this backend".to_owned(),
        ))
    }

    /// Query balance progress for `BTRFS_IOC_BALANCE_PROGRESS`.
    ///
    /// Returns `btrfs_ioctl_balance_args` struct with current progress.
    fn btrfs_balance_progress(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_balance_progress is not supported by this backend".to_owned(),
        ))
    }

    /// Get filesystem label for `BTRFS_IOC_GET_FSLABEL`.
    ///
    /// Returns the label as raw bytes (max 256 bytes, NUL-terminated).
    fn btrfs_get_fslabel(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_get_fslabel is not supported by this backend".to_owned(),
        ))
    }

    /// Get device statistics for `BTRFS_IOC_GET_DEV_STATS`.
    ///
    /// Returns `btrfs_ioctl_get_dev_stats` struct bytes (1032 bytes).
    fn btrfs_get_dev_stats(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _devid: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_get_dev_stats is not supported by this backend".to_owned(),
        ))
    }

    /// Get subvolume info for `BTRFS_IOC_GET_SUBVOL_INFO`.
    ///
    /// Returns `btrfs_ioctl_get_subvol_info_args` struct bytes (504 bytes).
    fn btrfs_get_subvol_info(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_get_subvol_info is not supported by this backend".to_owned(),
        ))
    }

    /// Extended tree search for `BTRFS_IOC_TREE_SEARCH_V2`.
    ///
    /// Like tree_search but with variable-sized output buffer.
    fn btrfs_tree_search_v2(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_tree_search_v2 is not supported by this backend".to_owned(),
        ))
    }

    /// Unprivileged inode lookup for `BTRFS_IOC_INO_LOOKUP_USER`.
    ///
    /// Returns path from subvolume root to inode.
    fn btrfs_ino_lookup_user(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _treeid: u64,
        _dirid: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_ino_lookup_user is not supported by this backend".to_owned(),
        ))
    }

    /// Get subvolume parent references for `BTRFS_IOC_GET_SUBVOL_ROOTREF`.
    ///
    /// Returns array of (dirid, name) pairs for parent directories.
    fn btrfs_get_subvol_rootref(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_get_subvol_rootref is not supported by this backend".to_owned(),
        ))
    }

    /// Clone (reflink) an entire file for `FICLONE`.
    ///
    /// Creates a CoW copy where `dest_ino` shares the source's data extents.
    /// FUSE dispatch resolves the caller's source fd to `src_ino` (same-device
    /// check) before invoking this. Returns `FfsError::ReadOnly` for read-only
    /// mounts.
    fn clone_file(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _dest_ino: InodeNumber,
        _src_ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "clone_file (FICLONE) is not supported by this backend".to_owned(),
        ))
    }

    /// Clone a range of blocks for `FICLONERANGE`.
    ///
    /// Creates a CoW copy of a range where `dest_ino` shares the source's
    /// extents. FUSE dispatch resolves the caller's source fd to `src_ino`
    /// first. `src_length == 0` means "to source EOF". Returns
    /// `FfsError::ReadOnly` for read-only mounts.
    #[allow(clippy::too_many_arguments)]
    fn clone_file_range(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _dest_ino: InodeNumber,
        _src_ino: InodeNumber,
        _src_offset: u64,
        _src_length: u64,
        _dest_offset: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "clone_file_range (FICLONERANGE) is not supported by this backend".to_owned(),
        ))
    }

    /// Set filesystem-specific inode flags (ext4 `EXT4_IOC_SETFLAGS`).
    ///
    /// Updates the raw `i_flags` field. The implementation should validate
    /// which flags are user-settable and reject immutable/system-only flags.
    fn set_inode_flags(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _flags: u32,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Move extents between files (ext4 `EXT4_IOC_MOVE_EXT`).
    ///
    /// `donor_fd` is the userspace donor file descriptor carried by the ioctl
    /// request. `orig_start`, `donor_start`, and `len` are block-based ranges
    /// matching Linux's `struct move_extent`. Implementations that do not
    /// support online defragmentation may return `UnsupportedFeature`.
    #[allow(clippy::too_many_arguments)]
    fn move_ext(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _donor_fd: u32,
        _orig_start: u64,
        _donor_start: u64,
        _len: u64,
    ) -> ffs_error::Result<u64> {
        Err(FfsError::UnsupportedFeature(
            "move_ext is not supported by this backend".to_owned(),
        ))
    }

    /// Register a userspace donor fd mapping for `EXT4_IOC_MOVE_EXT`.
    ///
    /// FUSE dispatch can resolve the caller's donor fd to a mounted-path inode
    /// before invoking [`FsOps::move_ext`]. Backends that key move-ext donor
    /// lookup by userspace fd can override this hook; other backends may keep
    /// the default no-op implementation.
    fn register_move_ext_donor_fd(
        &self,
        _donor_fd: u32,
        _donor_ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Release a temporary donor-fd registration for `EXT4_IOC_MOVE_EXT`.
    ///
    /// Called after `move_ext` returns, regardless of success.
    fn unregister_move_ext_donor_fd(&self, _donor_fd: u32) {}

    /// Extend filesystem by adding blocks for `EXT4_IOC_GROUP_EXTEND`.
    ///
    /// Takes raw argument bytes (8 bytes for block count).
    /// Returns `FfsError::ReadOnly` for read-only mounts.
    fn ext4_group_extend(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "ext4_group_extend is not supported by this backend".to_owned(),
        ))
    }

    /// Resize filesystem for `EXT4_IOC_RESIZE_FS`.
    ///
    /// Takes raw argument bytes (8 bytes for new block count).
    /// Returns `FfsError::ReadOnly` for read-only mounts.
    fn ext4_resize_fs(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "ext4_resize_fs is not supported by this backend".to_owned(),
        ))
    }

    /// Add a block group for `EXT4_IOC_GROUP_ADD`.
    ///
    /// Takes raw `ext4_new_group_input` struct bytes (16 bytes).
    /// Returns `FfsError::ReadOnly` for read-only mounts.
    fn ext4_group_add(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "ext4_group_add is not supported by this backend".to_owned(),
        ))
    }

    /// Force allocation of delayed-allocation blocks for `EXT4_IOC_ALLOC_DA_BLKS`.
    ///
    /// Flushes all delayed-alloc blocks for the given inode.
    /// Returns `FfsError::ReadOnly` for read-only mounts.
    fn ext4_alloc_da_blks(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "ext4_alloc_da_blks is not supported by this backend".to_owned(),
        ))
    }

    /// Migrate inode to ext4 extent format for `EXT4_IOC_MIGRATE`.
    ///
    /// Converts inode from ext3 indirect blocks to ext4 extent tree.
    /// Returns `FfsError::ReadOnly` for read-only mounts.
    fn ext4_migrate(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "ext4_migrate is not supported by this backend".to_owned(),
        ))
    }

    /// Swap contents with boot inode for `EXT4_IOC_SWAP_BOOT`.
    ///
    /// Atomically swaps inode contents with the reserved boot inode.
    /// Returns `FfsError::ReadOnly` for read-only mounts.
    fn ext4_swap_boot(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "ext4_swap_boot is not supported by this backend".to_owned(),
        ))
    }

    /// Shutdown filesystem for `FS_IOC_SHUTDOWN`.
    ///
    /// Emergency shutdown; may cause data loss. Takes 4-byte flags.
    fn fs_shutdown(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _flags: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "fs_shutdown is not supported by this backend".to_owned(),
        ))
    }

    /// Freeze filesystem for `FIFREEZE`.
    ///
    /// Quiesces the filesystem for consistent snapshots.
    /// Returns the freeze level (nesting count).
    fn fs_freeze(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<i32> {
        Err(FfsError::UnsupportedFeature(
            "fs_freeze is not supported by this backend".to_owned(),
        ))
    }

    /// Thaw filesystem for `FITHAW`.
    ///
    /// Resumes a frozen filesystem.
    fn fs_thaw(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "fs_thaw is not supported by this backend".to_owned(),
        ))
    }

    /// Get filesystem block size for `FIGETBSZ`.
    fn get_block_size(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<u32> {
        Err(FfsError::UnsupportedFeature(
            "get_block_size is not supported by this backend".to_owned(),
        ))
    }

    /// Set inode attributes. Returns updated attributes.
    fn setattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _attrs: &SetAttrRequest,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Flush per-handle state on `close(2)`; no durability guarantee required.
    ///
    /// This hook exists for backends that keep per-handle locks or delayed
    /// write errors. Stateless implementations may return `Ok(())`.
    fn flush(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _fh: u64,
        _lock_owner: u64,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Release the last reference to an open file handle.
    ///
    /// Stateless implementations may return `Ok(())`.
    fn release(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _request: ReleaseRequest,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Synchronize file data to stable storage.
    ///
    /// `datasync=true` allows skipping non-essential metadata where supported.
    fn fsync(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Synchronize directory contents to stable storage.
    fn fsyncdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        datasync: bool,
    ) -> ffs_error::Result<()> {
        self.fsync(cx, scope, ino, fh, datasync)
    }

    // ── Request scope hooks ───────────────────────────────────────────

    /// Acquire request scope before executing a VFS operation.
    ///
    /// Default behavior is a no-op for read-only backends.
    fn begin_request_scope(&self, _cx: &Cx, _op: RequestOp) -> ffs_error::Result<RequestScope> {
        Ok(RequestScope::empty())
    }

    /// Release request scope after executing a VFS operation.
    ///
    /// Called even when the operation body fails. Default behavior is a no-op.
    fn end_request_scope(
        &self,
        _cx: &Cx,
        _op: RequestOp,
        _scope: RequestScope,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Commit any write transaction attached to the request scope.
    fn commit_request_scope(&self, _scope: &mut RequestScope) -> ffs_error::Result<CommitSeq> {
        Ok(CommitSeq(0))
    }

    /// Flush all pending writes to durable storage before unmount.
    ///
    /// Called by the FUSE `destroy` callback to ensure in-memory MVCC
    /// data is materialised to the underlying image.  The default
    /// implementation is a no-op.
    fn flush_on_destroy(&self, _cx: &Cx) -> ffs_error::Result<()> {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
impl<T: FsOps + ?Sized> FsOps for Arc<T> {
    fn getattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ref().getattr(cx, scope, ino)
    }

    fn lookup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ref().lookup(cx, scope, parent, name)
    }

    fn readdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        self.as_ref().readdir(cx, scope, ino, offset)
    }

    fn read(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ref().read(cx, scope, ino, offset, size)
    }

    fn open(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        flags: i32,
    ) -> ffs_error::Result<(u64, u32)> {
        self.as_ref().open(cx, scope, ino, flags)
    }

    fn readlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ref().readlink(cx, scope, ino)
    }

    fn statfs(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<FsStat> {
        self.as_ref().statfs(cx, scope, ino)
    }

    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<String>> {
        self.as_ref().listxattr(cx, ino)
    }

    fn getxattr(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<Option<Vec<u8>>> {
        self.as_ref().getxattr(cx, ino, name)
    }

    fn setxattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        name: &str,
        value: &[u8],
        mode: XattrSetMode,
    ) -> ffs_error::Result<()> {
        self.as_ref().setxattr(cx, scope, ino, name, value, mode)
    }

    fn removexattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<bool> {
        self.as_ref().removexattr(cx, scope, ino, name)
    }

    fn create(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ref()
            .create(cx, scope, parent, name, mode, uid, gid)
    }

    fn mkdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ref().mkdir(cx, scope, parent, name, mode, uid, gid)
    }

    fn unlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<()> {
        self.as_ref().unlink(cx, scope, parent, name)
    }

    fn rmdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<()> {
        self.as_ref().rmdir(cx, scope, parent, name)
    }

    fn rename(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> ffs_error::Result<()> {
        self.as_ref()
            .rename(cx, scope, parent, name, new_parent, new_name)
    }

    fn rename2(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
        flags: u32,
    ) -> ffs_error::Result<()> {
        self.as_ref()
            .rename2(cx, scope, parent, name, new_parent, new_name, flags)
    }

    fn write(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> ffs_error::Result<u32> {
        self.as_ref().write(cx, scope, ino, offset, data)
    }

    fn copy_file_range(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino_in: InodeNumber,
        offset_in: u64,
        ino_out: InodeNumber,
        offset_out: u64,
        len: u64,
    ) -> ffs_error::Result<u64> {
        self.as_ref()
            .copy_file_range(cx, scope, ino_in, offset_in, ino_out, offset_out, len)
    }

    fn link(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ref().link(cx, scope, ino, new_parent, new_name)
    }

    fn symlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        target: &Path,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ref()
            .symlink(cx, scope, parent, name, target, uid, gid)
    }

    fn fallocate(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        length: u64,
        mode: i32,
    ) -> ffs_error::Result<()> {
        self.as_ref()
            .fallocate(cx, scope, ino, offset, length, mode)
    }

    fn fiemap(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        start: u64,
        length: u64,
    ) -> ffs_error::Result<Vec<FiemapExtent>> {
        self.as_ref().fiemap(cx, scope, ino, start, length)
    }

    fn lseek(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        whence: SeekWhence,
    ) -> ffs_error::Result<u64> {
        self.as_ref().lseek(cx, scope, ino, offset, whence)
    }

    fn get_inode_fsxattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<FsxattrInfo> {
        self.as_ref().get_inode_fsxattr(cx, scope, ino)
    }

    fn set_inode_fsxattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fsxattr: FsxattrInfo,
    ) -> ffs_error::Result<()> {
        self.as_ref().set_inode_fsxattr(cx, scope, ino, fsxattr)
    }

    fn get_inode_flags(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        self.as_ref().get_inode_flags(cx, scope, ino)
    }

    fn get_inode_state(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        self.as_ref().get_inode_state(cx, scope, ino)
    }

    fn precache_extents(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        self.as_ref().precache_extents(cx, scope, ino)
    }

    fn clear_extent_status_cache(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        self.as_ref().clear_extent_status_cache(cx, scope, ino)
    }

    fn get_inode_generation(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        self.as_ref().get_inode_generation(cx, scope, ino)
    }

    fn set_inode_generation(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        generation: u32,
    ) -> ffs_error::Result<()> {
        self.as_ref()
            .set_inode_generation(cx, scope, ino, generation)
    }

    fn get_encryption_policy_v1(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<[u8; 12]> {
        self.as_ref().get_encryption_policy_v1(cx, scope, ino)
    }

    fn get_encryption_policy_ex(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<(u8, Vec<u8>)> {
        self.as_ref().get_encryption_policy_ex(cx, scope, ino)
    }

    fn get_fs_label(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        self.as_ref().get_fs_label(cx, scope)
    }

    fn set_fs_label(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        label: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().set_fs_label(cx, scope, label)
    }

    fn fs_uuid(&self) -> ffs_error::Result<[u8; 16]> {
        self.as_ref().fs_uuid()
    }

    fn fs_sysfs_path(&self) -> ffs_error::Result<Vec<u8>> {
        self.as_ref().fs_sysfs_path()
    }

    fn get_btrfs_fs_info(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        self.as_ref().get_btrfs_fs_info(cx, scope)
    }

    fn set_btrfs_features(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        feature_flags: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().set_btrfs_features(cx, scope, feature_flags)
    }

    fn sync_fs(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<()> {
        self.as_ref().sync_fs(cx, scope)
    }

    fn btrfs_start_sync(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<u64> {
        self.as_ref().btrfs_start_sync(cx, scope)
    }

    fn btrfs_wait_sync(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        transid: u64,
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_wait_sync(cx, scope, transid)
    }

    fn btrfs_set_default_subvol(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        treeid: u64,
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_set_default_subvol(cx, scope, treeid)
    }

    fn btrfs_start_transaction(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<()> {
        self.as_ref().btrfs_start_transaction(cx, scope)
    }

    fn btrfs_end_transaction(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<()> {
        self.as_ref().btrfs_end_transaction(cx, scope)
    }

    fn btrfs_ino_lookup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        treeid: u64,
        objectid: u64,
    ) -> ffs_error::Result<(u64, Vec<u8>)> {
        self.as_ref().btrfs_ino_lookup(cx, scope, treeid, objectid)
    }

    fn get_btrfs_dev_info(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        devid_in: u64,
        uuid_in: [u8; 16],
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ref()
            .get_btrfs_dev_info(cx, scope, devid_in, uuid_in)
    }

    fn btrfs_tree_search(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        key: BtrfsTreeSearchKey,
    ) -> ffs_error::Result<(u32, Vec<u8>)> {
        self.as_ref().btrfs_tree_search(cx, scope, key)
    }

    fn get_btrfs_logical_ino_v2(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        logical: u64,
        args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ref()
            .get_btrfs_logical_ino_v2(cx, scope, logical, args)
    }

    fn btrfs_resize(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_resize(cx, scope, args)
    }

    fn btrfs_dev_replace(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ref().btrfs_dev_replace(cx, scope, args)
    }

    fn btrfs_forget_dev(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_forget_dev(cx, scope, args)
    }

    fn btrfs_set_fslabel(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_set_fslabel(cx, scope, args)
    }

    fn btrfs_file_extent_same(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: u64,
        args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ref().btrfs_file_extent_same(cx, scope, ino, args)
    }

    fn get_quota_info(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<QuotaInfo> {
        self.as_ref().get_quota_info(cx, scope)
    }

    fn btrfs_wait_quota_rescan(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<()> {
        self.as_ref().btrfs_wait_quota_rescan(cx, scope)
    }

    fn btrfs_quota_rescan_status(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ref().btrfs_quota_rescan_status(cx, scope)
    }

    fn btrfs_start_quota_rescan(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        flags: u64,
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_start_quota_rescan(cx, scope, flags)
    }

    fn btrfs_quota_control(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        cmd: u64,
        status: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ref().btrfs_quota_control(cx, scope, cmd, status)
    }

    fn btrfs_assign_qgroup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        assign: u64,
        src: u64,
        dst: u64,
    ) -> ffs_error::Result<()> {
        self.as_ref()
            .btrfs_assign_qgroup(cx, scope, assign, src, dst)
    }

    fn btrfs_create_qgroup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        create: u64,
        qgroupid: u64,
    ) -> ffs_error::Result<()> {
        self.as_ref()
            .btrfs_create_qgroup(cx, scope, create, qgroupid)
    }

    fn btrfs_limit_qgroup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        limit: BtrfsQgroupLimitRequest,
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_limit_qgroup(cx, scope, limit)
    }

    fn btrfs_rm_dev_v2(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_rm_dev_v2(cx, scope, vol_args)
    }

    fn btrfs_snap_destroy_v2(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_snap_destroy_v2(cx, scope, vol_args)
    }

    fn btrfs_add_dev(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_add_dev(cx, scope, vol_args)
    }

    fn btrfs_rm_dev(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().btrfs_rm_dev(cx, scope, vol_args)
    }

    fn set_inode_flags(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        flags: u32,
    ) -> ffs_error::Result<()> {
        self.as_ref().set_inode_flags(cx, scope, ino, flags)
    }

    fn trim_range(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        start: u64,
        len: u64,
        min_len: u64,
    ) -> ffs_error::Result<u64> {
        self.as_ref().trim_range(cx, scope, start, len, min_len)
    }

    fn mknod(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ref()
            .mknod(cx, scope, parent, name, mode, rdev, uid, gid)
    }

    fn move_ext(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        donor_fd: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> ffs_error::Result<u64> {
        self.as_ref()
            .move_ext(cx, scope, ino, donor_fd, orig_start, donor_start, len)
    }

    fn clone_file(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        dest_ino: InodeNumber,
        src_ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        self.as_ref().clone_file(cx, scope, dest_ino, src_ino)
    }

    fn clone_file_range(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        dest_ino: InodeNumber,
        src_ino: InodeNumber,
        src_offset: u64,
        src_length: u64,
        dest_offset: u64,
    ) -> ffs_error::Result<()> {
        self.as_ref().clone_file_range(
            cx,
            scope,
            dest_ino,
            src_ino,
            src_offset,
            src_length,
            dest_offset,
        )
    }

    fn register_move_ext_donor_fd(
        &self,
        donor_fd: u32,
        donor_ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        self.as_ref()
            .register_move_ext_donor_fd(donor_fd, donor_ino)
    }

    fn unregister_move_ext_donor_fd(&self, donor_fd: u32) {
        self.as_ref().unregister_move_ext_donor_fd(donor_fd);
    }

    fn ext4_group_extend(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().ext4_group_extend(cx, scope, args)
    }

    fn ext4_resize_fs(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().ext4_resize_fs(cx, scope, args)
    }

    fn ext4_group_add(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().ext4_group_add(cx, scope, args)
    }

    fn ext4_alloc_da_blks(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: u64,
    ) -> ffs_error::Result<()> {
        self.as_ref().ext4_alloc_da_blks(cx, scope, ino)
    }

    fn ext4_migrate(&self, cx: &Cx, scope: &mut RequestScope, ino: u64) -> ffs_error::Result<()> {
        self.as_ref().ext4_migrate(cx, scope, ino)
    }

    fn ext4_swap_boot(&self, cx: &Cx, scope: &mut RequestScope, ino: u64) -> ffs_error::Result<()> {
        self.as_ref().ext4_swap_boot(cx, scope, ino)
    }

    fn fs_shutdown(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        flags: &[u8],
    ) -> ffs_error::Result<()> {
        self.as_ref().fs_shutdown(cx, scope, flags)
    }

    fn fs_freeze(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<i32> {
        self.as_ref().fs_freeze(cx, scope)
    }

    fn fs_thaw(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<()> {
        self.as_ref().fs_thaw(cx, scope)
    }

    fn get_block_size(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<u32> {
        self.as_ref().get_block_size(cx, scope)
    }

    fn setattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ref().setattr(cx, scope, ino, attrs)
    }

    fn flush(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        lock_owner: u64,
    ) -> ffs_error::Result<()> {
        self.as_ref().flush(cx, scope, ino, fh, lock_owner)
    }

    fn release(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        request: ReleaseRequest,
    ) -> ffs_error::Result<()> {
        self.as_ref().release(cx, scope, request)
    }

    fn fsync(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        datasync: bool,
    ) -> ffs_error::Result<()> {
        self.as_ref().fsync(cx, scope, ino, fh, datasync)
    }

    fn fsyncdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        datasync: bool,
    ) -> ffs_error::Result<()> {
        self.as_ref().fsyncdir(cx, scope, ino, fh, datasync)
    }

    fn begin_request_scope(&self, cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
        self.as_ref().begin_request_scope(cx, op)
    }

    fn end_request_scope(
        &self,
        cx: &Cx,
        op: RequestOp,
        scope: RequestScope,
    ) -> ffs_error::Result<()> {
        self.as_ref().end_request_scope(cx, op, scope)
    }

    fn commit_request_scope(&self, scope: &mut RequestScope) -> ffs_error::Result<CommitSeq> {
        self.as_ref().commit_request_scope(scope)
    }

    fn flush_on_destroy(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.as_ref().flush_on_destroy(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DefaultXattrFsOpsFixture;

    impl FsOps for DefaultXattrFsOpsFixture {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            if ino != InodeNumber(1) {
                return Err(FfsError::NotFound(format!("inode {ino}")));
            }

            Ok(InodeAttr {
                ino,
                size: 4096,
                blocks: 8,
                atime: SystemTime::UNIX_EPOCH,
                mtime: SystemTime::UNIX_EPOCH,
                ctime: SystemTime::UNIX_EPOCH,
                crtime: SystemTime::UNIX_EPOCH,
                kind: FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 4096,
                generation: 1,
            })
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound(name.to_string_lossy().into_owned()))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<ReaddirPage> {
            Err(FfsError::UnsupportedFeature(
                "readdir fixture path is not supported".to_owned(),
            ))
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            Err(FfsError::UnsupportedFeature(
                "read fixture path is not supported".to_owned(),
            ))
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Err(FfsError::UnsupportedFeature(
                "readlink fixture path is not supported".to_owned(),
            ))
        }
    }

    #[test]
    fn listxattr_default_propagates_missing_inode() {
        let fs = DefaultXattrFsOpsFixture;
        let cx = Cx::for_testing();
        let err = fs.listxattr(&cx, InodeNumber(99)).unwrap_err();

        assert!(matches!(&err, FfsError::NotFound(_)));
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn getxattr_default_propagates_missing_inode() {
        let fs = DefaultXattrFsOpsFixture;
        let cx = Cx::for_testing();
        let err = fs.getxattr(&cx, InodeNumber(99), "user.test").unwrap_err();

        assert!(matches!(&err, FfsError::NotFound(_)));
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn seek_whence_from_raw_valid_values() {
        assert_eq!(SeekWhence::from_raw(0), Some(SeekWhence::Set));
        assert_eq!(SeekWhence::from_raw(1), Some(SeekWhence::Cur));
        assert_eq!(SeekWhence::from_raw(2), Some(SeekWhence::End));
        assert_eq!(SeekWhence::from_raw(3), Some(SeekWhence::Data));
        assert_eq!(SeekWhence::from_raw(4), Some(SeekWhence::Hole));
    }

    #[test]
    fn seek_whence_from_raw_invalid_values() {
        assert_eq!(SeekWhence::from_raw(-1), None);
        assert_eq!(SeekWhence::from_raw(5), None);
        assert_eq!(SeekWhence::from_raw(100), None);
        assert_eq!(SeekWhence::from_raw(i32::MAX), None);
        assert_eq!(SeekWhence::from_raw(i32::MIN), None);
    }

    #[test]
    fn request_op_is_write_true_for_mutating_ops() {
        use RequestOp::*;
        let write_ops = [
            Create,
            Mkdir,
            Unlink,
            Rmdir,
            Rename,
            Link,
            Symlink,
            Fallocate,
            Setattr,
            Setxattr,
            Removexattr,
            Write,
            RepairWriteback,
            IoctlWrite,
            Fsync,
            Fsyncdir,
        ];
        for op in write_ops {
            assert!(op.is_write(), "{op:?} should be a write op");
        }
    }

    #[test]
    fn request_op_is_write_false_for_read_ops() {
        use RequestOp::*;
        let read_ops = [
            Getattr, Statfs, Getxattr, Lookup, Listxattr, Flush, Open, Release, Opendir, Read,
            Readdir, Readlink, Lseek, IoctlRead,
        ];
        for op in read_ops {
            assert!(!op.is_write(), "{op:?} should NOT be a write op");
        }
    }

    #[test]
    fn request_op_is_metadata_write_true_for_metadata_ops() {
        use RequestOp::*;
        let metadata_ops = [
            Create,
            Mkdir,
            Unlink,
            Rmdir,
            Rename,
            Link,
            Symlink,
            Setattr,
            Setxattr,
            Removexattr,
            IoctlWrite,
        ];
        for op in metadata_ops {
            assert!(op.is_metadata_write(), "{op:?} should be a metadata write");
        }
    }

    #[test]
    fn request_op_is_metadata_write_false_for_data_ops() {
        use RequestOp::*;
        assert!(!Write.is_metadata_write(), "Write is data, not metadata");
        assert!(
            !Fallocate.is_metadata_write(),
            "Fallocate is data, not metadata"
        );
        assert!(!RepairWriteback.is_metadata_write());
        assert!(!Fsync.is_metadata_write());
        assert!(!Fsyncdir.is_metadata_write());
    }

    // ── ranges_overlap: copy_file_range overlap detection ────────────────

    #[test]
    fn ranges_overlap_disjoint() {
        assert!(!ranges_overlap(0, 10, 20, 10));
        assert!(!ranges_overlap(20, 10, 0, 10));
    }

    #[test]
    fn ranges_overlap_adjacent() {
        assert!(!ranges_overlap(0, 10, 10, 10));
        assert!(!ranges_overlap(10, 10, 0, 10));
    }

    #[test]
    fn ranges_overlap_partial() {
        assert!(ranges_overlap(0, 15, 10, 10));
        assert!(ranges_overlap(10, 10, 0, 15));
    }

    #[test]
    fn ranges_overlap_contained() {
        assert!(ranges_overlap(0, 100, 10, 10));
        assert!(ranges_overlap(10, 10, 0, 100));
    }

    #[test]
    fn ranges_overlap_zero_length() {
        assert!(!ranges_overlap(0, 0, 0, 10));
        assert!(!ranges_overlap(0, 10, 0, 0));
        assert!(!ranges_overlap(0, 0, 0, 0));
    }

    #[test]
    fn ranges_overlap_same() {
        assert!(ranges_overlap(10, 10, 10, 10));
    }

    // ── SeekWhence::from_raw: whence value parsing ───────────────────────

    #[test]
    fn seek_whence_from_raw_known_values() {
        assert_eq!(SeekWhence::from_raw(0), Some(SeekWhence::Set));
        assert_eq!(SeekWhence::from_raw(1), Some(SeekWhence::Cur));
        assert_eq!(SeekWhence::from_raw(2), Some(SeekWhence::End));
        assert_eq!(SeekWhence::from_raw(3), Some(SeekWhence::Data));
        assert_eq!(SeekWhence::from_raw(4), Some(SeekWhence::Hole));
    }

    #[test]
    fn seek_whence_from_raw_unknown_returns_none() {
        assert!(SeekWhence::from_raw(-1).is_none());
        assert!(SeekWhence::from_raw(5).is_none());
        assert!(SeekWhence::from_raw(999).is_none());
    }

    // ── DirEntry::name_str: lossy UTF-8 conversion ───────────────────────

    #[test]
    fn dir_entry_name_str_ascii() {
        let entry = DirEntry {
            ino: InodeNumber(2),
            offset: 0,
            kind: FileType::RegularFile,
            name: b"hello.txt".to_vec(),
        };
        assert_eq!(entry.name_str(), "hello.txt");
    }

    #[test]
    fn dir_entry_name_str_utf8() {
        let entry = DirEntry {
            ino: InodeNumber(3),
            offset: 0,
            kind: FileType::Directory,
            name: "日本語.dir".as_bytes().to_vec(),
        };
        assert_eq!(entry.name_str(), "日本語.dir");
    }

    #[test]
    fn dir_entry_name_str_invalid_utf8_lossy() {
        let entry = DirEntry {
            ino: InodeNumber(4),
            offset: 0,
            kind: FileType::RegularFile,
            name: vec![0xFF, 0xFE, b'.', b't', b'x', b't'],
        };
        let name = entry.name_str();
        assert!(name.contains(".txt"), "should preserve valid suffix");
        assert!(name.contains('\u{FFFD}'), "should contain replacement char");
    }
}
