//! Logical sparse seeks over authenticated DMU pointer trees.
//!
//! Allocation is determined by native hole pointers, never by compressed sizes
//! or zero-filled payloads. The shared DMU walker retains the ordinary reader's
//! pointer validation, selected-root birth limits and bounded metadata cache.

use super::{Cx, Kind, Result, Zpl, checkpoint, unsupported};
use ffs_core::SeekWhence;
use ffs_error::FfsError;

impl Zpl {
    /// Find native logical data/hole boundaries in this immutable head/snapshot.
    /// Budget exhaustion, bad metadata and cancellation remain errors, never
    /// "no more data". Zero-filled allocated and embedded blocks count as data.
    pub fn seek(&mut self, cx: &Cx, number: u64, offset: u64, whence: SeekWhence) -> Result<u64> {
        checkpoint(cx)?;
        let want_data = match whence {
            SeekWhence::Data => true,
            SeekWhence::Hole => false,
            _ => {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL)));
            }
        };
        let (object, metadata) = self.file(cx, number)?;
        if metadata.kind != Kind::Regular {
            return Err(unsupported("ZPL seek requires a regular file"));
        }
        self.objects
            .seek_data_hole(cx, &object, metadata.size, offset, want_data)
    }
}
