#![forbid(unsafe_code)]
//! Native ZFS pool, DMU, ZPL and read-only filesystem operations.
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

pub use filesystem::ZfsFs;
pub use reader::dmu::Objects;
pub use reader::dmu::zpl::Zpl;
pub use reader::{Label, Leaf, Pool, RootBlock};
