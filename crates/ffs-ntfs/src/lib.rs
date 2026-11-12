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

pub mod reader;
pub mod stream_name;
pub mod transaction;

pub use reader::NtfsVolume;
pub use reader::filesystem::NtfsFs;
pub use stream_name::StreamName;
pub use transaction::{
    NtfsAdmissionReport, NtfsDurableToken, NtfsLogStateSummary, NtfsPersistenceEvent,
    NtfsPersistenceStage, NtfsRecoverySummary, NtfsStorageIdentity, NtfsTransactionEngine,
    NtfsTxOutcome, NtfsWriteOptions,
};
