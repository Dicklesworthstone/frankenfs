//! Bounded native file-to-file copying. No temporary whole-file payload and no
//! per-megabyte mutation loop: one prepared allocation/update protocol covers
//! the complete admitted request. The caller pins both files with its writer
//! gate. Overlapping same-file ranges are refused, not emulated as memmove.

use super::super::checked_end;
use super::{
    ByteDevice, Cx, FatVolume, FfsError, FileSource, Update, apply_update, checkpoint,
    modified_timestamp,
};
use anyhow::{Context, Result, bail};
use ffs_types::ByteOffset;

fn invalid_range() -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL))
}

/// The requested ranges (not only their EOF-clipped prefix) must be disjoint.
/// Identity is the resolved native slot, so aliases cannot bypass this check.
fn validate_ranges(same_file: bool, input: u64, output: u64, length: u64) -> Result<()> {
    if length == 0 {
        return Ok(());
    }
    let input_end = input.checked_add(length).ok_or_else(invalid_range)?;
    let output_end = output.checked_add(length).ok_or_else(invalid_range)?;
    if same_file && input < output_end && output < input_end {
        return Err(invalid_range().into());
    }
    Ok(())
}

/// A read-only byte projection of the destination after copying. The mutation
/// engine reads only the changed interval/new allocation; its expected copy
/// bytes therefore always come from the pinned INPUT, not overwritten output.
struct CopySource<'a> {
    input: &'a dyn ByteDevice,
    original: &'a dyn ByteDevice,
    input_offset: u64,
    output_offset: u64,
    output_end: u64,
    size: u64,
}

impl<'a> CopySource<'a> {
    fn new(
        input: &'a dyn ByteDevice,
        original: &'a dyn ByteDevice,
        input_offset: u64,
        output_offset: u64,
        length: u64,
    ) -> Result<Self> {
        let input_end = input_offset.checked_add(length).ok_or_else(invalid_range)?;
        let output_end = output_offset
            .checked_add(length)
            .ok_or_else(invalid_range)?;
        if input_end > input.len_bytes() {
            bail!("native copy source does not cover its prepared range");
        }
        Ok(Self {
            input,
            original,
            input_offset,
            output_offset,
            output_end,
            size: if length == 0 {
                original.len_bytes()
            } else {
                original.len_bytes().max(output_end)
            },
        })
    }
}

impl ByteDevice for CopySource<'_> {
    fn len_bytes(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let end = checked_end(at.0, bytes.len(), self.size)?;
        bytes.fill(0);
        let original_end = end.min(self.original.len_bytes());
        let prefix_end = original_end.min(self.output_offset);
        if at.0 < prefix_end {
            self.original
                .read_exact_at(cx, at, &mut bytes[..(prefix_end - at.0) as usize])?;
        }
        let suffix_start = at.0.max(self.output_end);
        if suffix_start < original_end {
            self.original.read_exact_at(
                cx,
                ByteOffset(suffix_start),
                &mut bytes[(suffix_start - at.0) as usize..(original_end - at.0) as usize],
            )?;
        }
        let copy_start = at.0.max(self.output_offset);
        let copy_end = end.min(self.output_end);
        if copy_start < copy_end {
            // Constructor range checks prove this translated span fits input.
            let input = self.input_offset + (copy_start - self.output_offset);
            self.input.read_exact_at(
                cx,
                ByteOffset(input),
                &mut bytes[(copy_start - at.0) as usize..(copy_end - at.0) as usize],
            )?;
        }
        checkpoint(cx)
    }

    fn write_all_at(&self, _cx: &Cx, _at: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)
    }
}

impl FatVolume {
    /// Copy within this admitted volume. Retain the caller's exclusive writer
    /// gate across this call AND mount cache publication: the source chain must
    /// not be overwritten, unlinked, renamed or reallocated between reads.
    /// This is an ordered byte copy, not a reflink or crash-atomic transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn copy_range(
        &self,
        cx: &Cx,
        from: &str,
        input_offset: u64,
        to: &str,
        output_offset: u64,
        length: u64,
        now: u64,
    ) -> Result<u64> {
        checkpoint(cx)?;
        if length == 0 {
            return Ok(0);
        }
        validate_ranges(false, input_offset, output_offset, length)?;
        let input_entry = self.resolve(cx, from)?.ok_or(FfsError::IsDirectory)?;
        let output_entry = self.resolve(cx, to)?.ok_or(FfsError::IsDirectory)?;
        if input_entry.native.is_directory() || output_entry.native.is_directory() {
            return Err(FfsError::IsDirectory.into());
        }
        if output_entry.native.attributes & 1 != 0 {
            return Err(FfsError::PermissionDenied.into());
        }
        if input_entry.native.attributes & 0xC8 != 0 || output_entry.native.attributes & 0xC8 != 0 {
            bail!("unsupported native attributes on copy source or destination");
        }
        validate_ranges(
            input_entry.offset == output_entry.offset,
            input_offset,
            output_offset,
            length,
        )?;
        let length = length.min(u64::from(input_entry.native.size).saturating_sub(input_offset));
        if length == 0 {
            // EOF is not permission to extend or timestamp the destination.
            checkpoint(cx)?;
            return Ok(0);
        }
        let end = output_offset
            .checked_add(length)
            .ok_or_else(invalid_range)?;
        if end > u64::from(u32::MAX) {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EFBIG)).into());
        }
        let input = FileSource {
            volume: self,
            chain: self.file_chain(cx, &input_entry)?,
        };
        let original = FileSource {
            volume: self,
            chain: self.file_chain(cx, &output_entry)?,
        };
        let source = CopySource::new(&input, &original, input_offset, output_offset, length)?;
        let update = Update {
            capacity: u32::try_from(source.size).context("FAT copy exceeds native capacity")?,
            modified: Some(modified_timestamp(now)?),
            changed: output_offset.min(u64::from(original.chain.size))..end,
        };
        // This shared engine checks all ownership before mutation, reserves only
        // missing clusters, initializes gaps/new storage, verifies copied bytes,
        // and synchronizes FAT/directory/clean state in their existing order.
        apply_update(
            cx,
            self,
            to,
            &output_entry,
            &original.chain,
            &source,
            update,
        )?;
        Ok(length)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
