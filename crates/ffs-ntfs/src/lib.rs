#![forbid(unsafe_code)]
//! Native NTFS 3.1 image reads, read-only filesystem operations, and explicitly
//! admitted native `$LogFile`/allocator/MFT transactions.
//!
//! `NtfsVolume` and `NtfsFs` retain strict read-only admission and volatile
//! overlay recovery without granting write authority. Durable native mutations
//! and persistent `$LogFile` ARIES recovery require the separate explicit
//! [`transaction::NtfsTransactionEngine`] admission path.

macro_rules! companion_bin_tests {
    ($($item:item)*) => {
        $($item)*
    };
}

pub mod efs;
pub mod formatter;
pub mod reader;
pub mod reparse_provider;
pub mod resize;
pub mod security_policy;
pub mod stream_name;
pub mod transaction;

pub use efs::{NtfsEfsKey, NtfsEfsKeyScope, NtfsEfsMetadataInfo, StaticEfsKeyScope};
pub use formatter::{
    NtfsFormatLayout, NtfsFormatOptions, NtfsFormatReport, NtfsFormatStage, NtfsFormatStageHook,
    NtfsFormatVersion, format_device, format_image_file, plan_format,
};
pub use reader::NtfsVolume;
pub use reader::check::repair::{
    NtfsRepairAction, NtfsRepairPlan, apply_bounded_repair, plan_bounded_repair,
};
pub use reader::check::{
    NtfsCheckCategory, NtfsCheckIssue, NtfsCheckLimits, NtfsCheckReport, NtfsCheckStatus,
    NtfsSubcheckSummary, check_image_file, check_volume_device,
};
pub use reader::filesystem::NtfsFs;
pub use reparse_provider::{
    ReparseCapability, classify_reparse_point, validate_writable_reparse_point,
};
pub use resize::{
    NtfsClusterRelocation, NtfsResizeDirection, NtfsResizeOptions, NtfsResizePlan,
    NtfsResizeReport, NtfsResizeStage, NtfsResizeStageHook, plan_resize, run_resize,
};
pub use security_policy::{
    NtfsSecurityPatch, NtfsSidMap, NtfsSidPolicy, apply_security_patch, build_simple_ace,
};
pub use stream_name::StreamName;
pub use transaction::{
    DEFAULT_NTFS_FILETIME, NtfsAdmissionReport, NtfsDurableToken, NtfsEaSetMode,
    NtfsExtendedRenameOutcome, NtfsLogStateSummary, NtfsObjectIdData, NtfsPersistenceEvent,
    NtfsPersistenceStage, NtfsRecoverySummary, NtfsRenameOutcome, NtfsSetAttributes,
    NtfsStorageIdentity, NtfsTransactionEngine, NtfsTxOutcome, NtfsUsnSummary, NtfsWriteOptions,
    validate_ntfs_component_utf16, validate_ntfs_stream_name_utf16,
};
