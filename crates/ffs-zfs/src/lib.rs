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

pub mod crypto;
pub mod filesystem;
pub mod reader;
pub mod send_recv;
pub mod transaction;
pub mod zvol_nbd;

pub use crypto::{
    WrappingKey, ZfsDatasetCryptoInfo, ZfsKeyMaterial, ZfsKeyRing, ZfsKeyStatus, ZfsNonceGenerator,
    encode_dsl_crypto_key_zap, generate_new_dataset_keys, parse_dsl_crypto_key_zap,
};
pub use ffs_ondisk::zfs::crypto::{DslCryptoKeyRecord, UnwrappedDslKey, ZfsKeyFormat, ZioEncrypt};
pub use filesystem::{ZfsFs, ZfsMountWriteOptions};
pub use reader::dmu::Objects;
pub use reader::dmu::zpl::Zpl;
pub use reader::dmu::zvol::{VolumeInfo, Zvol};
pub use reader::{
    AllocClass, IndirectVdevMap, Label, Leaf, Pool, PoolTopology, RootBlock, TopVdevDescriptor,
    TopVdevKind, VdevHealth,
};
pub use send_recv::{
    ZfsRecvOutcome, ZfsRecvProgress, ZfsRecvReport, ZfsRecvRequest, ZfsRecvStage, ZfsResumeState,
    ZfsSendFrom, ZfsSendReport, ZfsSendRequest, inspect_receive_resume_state_in_mos, send_stream,
};
pub use transaction::{
    DEFAULT_VOLBLOCKSIZE, MAX_VOLBLOCKSIZE, MAX_ZVOL_IO_BYTES, ZVOL_LOGICAL_SECTOR_BYTES,
    ZfsAdmissionReport, ZfsBookmarkInfo, ZfsCheckpointInfo, ZfsCommitReceipt, ZfsCreateVdevKind,
    ZfsCreateVdevSpec, ZfsDataChecksum, ZfsDurableToken, ZfsEncryptionCreateOptions,
    ZfsExpandRaidzReport, ZfsFileRangeOperation, ZfsHoldInfo, ZfsLifecycleReport,
    ZfsObjectIdentity, ZfsPersistenceEvent, ZfsPersistenceStage, ZfsPoolCreateReport,
    ZfsPoolCreateSpec, ZfsPosixSetAttr, ZfsPropertySetValue, ZfsRemoveVdevReport, ZfsRewindReport,
    ZfsScanLimits, ZfsScanReport, ZfsSetAttr, ZfsStorageIdentity, ZfsTopologyKind,
    ZfsTransactionEngine, ZfsTrimReport, ZfsTxOutcome, ZfsUnlinkedObject, ZfsWriteOptions,
    ZfsXattrSetMode, ZfsZvolCreateOptions, ZfsZvolInfo, create_pool_files, create_pool_on_devices,
    export_pool_leaves, import_pool_leaves, list_bookmarks_in_mos, list_holds_in_mos,
};
pub use zvol_nbd::{
    NbdExportInfo, NbdServerConfig, ZfsVolumeManager, ZfsZvolNbdClient, ZfsZvolNbdServer,
    ZfsZvolSession, ZvolAckKind, ZvolSyncPolicy, ZvolTransportAuditEntry,
};
