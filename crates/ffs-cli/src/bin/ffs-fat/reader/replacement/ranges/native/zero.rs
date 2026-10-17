//! Native ZERO_RANGE allocation through the same ordered publication engine.
//!
//! FAT has no unwritten extents: zeros are actually initialized and verified.
//! KEEP_SIZE reserves capacity without exposing bytes beyond logical EOF.

use super::super::super::super::{FatVolume, checkpoint};
use super::{FileSource, Update, apply_update, modified_timestamp, validate_edit_state};
use anyhow::Result;
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_types::ByteOffset;
use std::ops::Range;

/// Preserve only bytes outside the zeroed interval. In particular, readback
/// must synthesize expected zeros, not read its oracle from the changed image.
struct ZeroSource<'a> {
    original: &'a dyn ByteDevice,
    size: u64,
    zeroed: Range<u64>,
}

impl ByteDevice for ZeroSource<'_> {
    fn len_bytes(&self) -> u64 {
        self.size
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let end = offset
            .0
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= self.size)
            .ok_or_else(|| FfsError::Format("FAT zero source read exceeds its length".into()))?;
        bytes.fill(0);
        let old_end = end.min(self.original.len_bytes());
        let prefix_end = old_end.min(self.zeroed.start);
        if offset.0 < prefix_end {
            self.original.read_exact_at(
                cx,
                offset,
                &mut bytes[..(prefix_end - offset.0) as usize],
            )?;
        }
        let suffix_start = offset.0.max(self.zeroed.end);
        if suffix_start < old_end {
            self.original.read_exact_at(
                cx,
                ByteOffset(suffix_start),
                &mut bytes[(suffix_start - offset.0) as usize..(old_end - offset.0) as usize],
            )?;
        }
        checkpoint(cx)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)
    }
}

pub(super) fn apply(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    offset: u64,
    length: u64,
    mode: i32,
    now: u64,
) -> Result<()> {
    checkpoint(cx)?;
    if mode & !(libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE) != 0 {
        return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP)).into());
    }
    if length == 0 {
        return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL)).into());
    }
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= u64::from(u32::MAX))
        .ok_or_else(|| FfsError::Io(std::io::Error::from_raw_os_error(libc::EFBIG)))?;
    let modified = Some(modified_timestamp(now)?);
    validate_edit_state(cx, volume)?;
    let entry = volume.resolve(cx, path)?.ok_or(FfsError::IsDirectory)?;
    let original = FileSource {
        volume,
        chain: volume.file_chain(cx, &entry)?,
    };
    let old_size = u64::from(original.chain.size);
    let size = if mode & libc::FALLOC_FL_KEEP_SIZE != 0 {
        old_size
    } else {
        old_size.max(end)
    };
    let source = ZeroSource {
        original: &original,
        size,
        zeroed: offset.min(size)..end.min(size),
    };
    // When extending beyond EOF, the gap preceding the requested interval is
    // also initialized. A KEEP_SIZE interval past EOF changes capacity only.
    let changed = offset.min(old_size)..end.min(size);
    apply_update(
        cx,
        volume,
        path,
        &entry,
        &original.chain,
        &source,
        Update {
            capacity: u32::try_from(end.max(size))?,
            modified,
            changed,
        },
    )
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
