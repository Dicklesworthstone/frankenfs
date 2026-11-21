#![forbid(unsafe_code)]
//! Native ZFS pool, DMU, ZPL and admitted read/write filesystem operations.
//!
//! The library retains the reader's explicit topology and root admission rules.
//! ZIL recovery uses a volatile view; it never grants native write authority.
//!
//! Downstream consumers use the same checked reader and `FsOps` implementation
//! as the `ffs-zfs` companion, without including CLI source files:
//!
//! ```no_run
//! use asupersync::Cx;
//! use ffs_error::Result;
//! use ffs_zfs::{Leaf, Pool, ZfsFs};
//! use std::path::Path;
//!
//! fn selected_view(cx: &Cx, image: &Path, pool_guid: u64) -> Result<ZfsFs> {
//!     let leaf = Leaf::open(cx, image, 0, None)?;
//!     let pool = Pool::from_leaves(vec![leaf])?;
//!     let mut objects = pool.objects(cx, 0, 0, pool_guid)?;
//!     let view = objects.zpl(cx, &[])?;
//!     ZfsFs::new(cx, view, 0, 0)
//! }
//! ```

macro_rules! companion_bin_tests {
    ($($item:item)*) => {
        $($item)*
    };
}

pub mod filesystem;
pub mod reader;
pub mod transaction;
pub mod zvol_nbd;

pub use filesystem::{ZfsFs, ZfsMountWriteOptions};
pub use reader::dmu::Objects;
pub use reader::dmu::zpl::Zpl;
pub use reader::dmu::zvol::{VolumeInfo, Zvol};
pub use reader::{Label, Leaf, Pool, RootBlock};
pub use transaction::{
    DEFAULT_VOLBLOCKSIZE, MAX_VOLBLOCKSIZE, MAX_ZVOL_IO_BYTES, ZVOL_LOGICAL_SECTOR_BYTES,
    ZfsAdmissionReport, ZfsBookmarkInfo, ZfsCommitReceipt, ZfsDataChecksum, ZfsDurableToken,
    ZfsFileRangeOperation, ZfsHoldInfo, ZfsPersistenceEvent, ZfsPersistenceStage, ZfsPosixSetAttr,
    ZfsPropertySetValue, ZfsSetAttr, ZfsStorageIdentity, ZfsTopologyKind, ZfsTransactionEngine,
    ZfsTxOutcome, ZfsUnlinkedObject, ZfsWriteOptions, ZfsXattrSetMode, ZfsZvolCreateOptions,
    ZfsZvolInfo, list_bookmarks_in_mos, list_holds_in_mos,
};
pub use zvol_nbd::{
    NbdExportInfo, NbdServerConfig, ZfsVolumeManager, ZfsZvolNbdClient, ZfsZvolNbdServer,
    ZfsZvolSession, ZvolAckKind, ZvolSyncPolicy, ZvolTransportAuditEntry,
};
