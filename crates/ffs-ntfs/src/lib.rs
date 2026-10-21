#![forbid(unsafe_code)]
//! Native NTFS image reads and read-only filesystem operations.
//!
//! Opening and recovery retain the reader's admission rules. Explicit recovery
//! uses a volatile overlay; this crate never grants native write authority.

macro_rules! companion_bin_tests {
    ($($item:item)*) => {
        $($item)*
    };
}

pub mod reader;
pub mod stream_name;

pub use reader::NtfsVolume;
pub use reader::filesystem::NtfsFs;
pub use stream_name::StreamName;
