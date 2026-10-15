//! Bounded streaming sources for native range writes and truncation.
//!
//! The replacement engine retains its disjoint-allocation, hash verification,
//! publication and reclamation ordering. Only the source representation changes:
//! old payload, patch bytes and zero extension are composed on demand, never in
//! a file-sized Vec. The old chain remains allocated until all source reads end.

use super::super::{FatVolume, FileChain};
use super::{HASH_BYTES, Replacement, checkpoint};
use anyhow::{Context, Result, anyhow};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_types::ByteOffset;

struct FileSource<'a> {
    volume: &'a FatVolume,
    chain: FileChain,
}

impl ByteDevice for FileSource<'_> {
    fn len_bytes(&self) -> u64 {
        u64::from(self.chain.size)
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        checked_end(offset.0, bytes.len(), self.len_bytes())?;
        let mut at = offset.0;
        // FatVolume::read has a per-request limit, not a file-size limit.
        // Honor it even when a source consumer supplies a large destination.
        for target in bytes.chunks_mut(HASH_BYTES) {
            let read = self.volume.read(cx, &self.chain, at, target.len())?;
            if read.len() != target.len() {
                return Err(FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short read from retained FAT source chain",
                )));
            }
            target.copy_from_slice(&read);
            at += target.len() as u64;
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

fn checked_end(offset: u64, length: usize, limit: u64) -> ffs_error::Result<u64> {
    offset
        .checked_add(length as u64)
        .filter(|end| *end <= limit)
        .ok_or_else(|| FfsError::Format("edited FAT source range exceeds its length".into()))
}

/// Read-only projection of an old byte source, resized and optionally patched.
/// Empty patches implement truncation/zero extension without materialization.
struct EditSource<'a> {
    original: &'a dyn ByteDevice,
    size: u64,
    patch_offset: u64,
    patch_end: u64,
    patch: &'a [u8],
}

impl<'a> EditSource<'a> {
    fn new(
        original: &'a dyn ByteDevice,
        size: u64,
        patch_offset: u64,
        patch: &'a [u8],
    ) -> ffs_error::Result<Self> {
        let patch_end = checked_end(patch_offset, patch.len(), size)?;
        Ok(Self {
            original,
            size,
            patch_offset,
            patch_end,
            patch,
        })
    }
}

impl ByteDevice for EditSource<'_> {
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
        let end = checked_end(offset.0, bytes.len(), self.size)?;
        bytes.fill(0);
        let old_end = end.min(self.original.len_bytes());
        let prefix_end = old_end.min(self.patch_offset);
        if offset.0 < prefix_end {
            self.original.read_exact_at(
                cx,
                offset,
                &mut bytes[..(prefix_end - offset.0) as usize],
            )?;
        }
        let suffix_start = offset.0.max(self.patch_end);
        if suffix_start < old_end {
            self.original.read_exact_at(
                cx,
                ByteOffset(suffix_start),
                &mut bytes[(suffix_start - offset.0) as usize..(old_end - offset.0) as usize],
            )?;
        }
        let patch_start = offset.0.max(self.patch_offset);
        let patch_end = end.min(self.patch_end);
        if patch_start < patch_end {
            bytes[(patch_start - offset.0) as usize..(patch_end - offset.0) as usize]
                .copy_from_slice(
                    &self.patch[(patch_start - self.patch_offset) as usize
                        ..(patch_end - self.patch_offset) as usize],
                );
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

pub fn write_range_in_volume(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    offset: u64,
    data: &[u8],
    now: u64,
) -> Result<usize> {
    checkpoint(cx)?;
    let entry = volume
        .resolve(cx, path)?
        .ok_or_else(|| anyhow!("cannot write to the root directory"))?;
    if entry.native.is_directory() {
        return Err(FfsError::IsDirectory.into());
    }
    if entry.native.attributes & 1 != 0 {
        return Err(FfsError::PermissionDenied.into());
    }
    // A zero-byte write must not extend a file, rewrite timestamps, allocate
    // clusters or enter the dirty-state protocol, even beyond the current EOF.
    if data.is_empty() {
        return Ok(0);
    }
    let end = offset
        .checked_add(data.len() as u64)
        .context("write offset overflow")?;
    let end_u32 = u32::try_from(end).context("FAT regular file write exceeds 4 GiB - 1")?;
    let original = FileSource {
        volume,
        chain: volume.file_chain(cx, &entry)?,
    };
    let source = EditSource::new(
        &original,
        u64::from(entry.native.size.max(end_u32)),
        offset,
        data,
    )?;
    let plan = Replacement::prepare(cx, volume, path, &source, now)?;
    plan.execute(cx, volume, &source, || Ok(()))?;
    Ok(data.len())
}

pub fn truncate_in_volume(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    size: u64,
    now: u64,
) -> Result<()> {
    checkpoint(cx)?;
    let entry = volume
        .resolve(cx, path)?
        .ok_or_else(|| anyhow!("cannot truncate the root directory"))?;
    if entry.native.is_directory() {
        return Err(FfsError::IsDirectory.into());
    }
    let size_u32 = u32::try_from(size).context("FAT regular file truncate exceeds 4 GiB - 1")?;
    if size_u32 == entry.native.size {
        return Ok(());
    }
    let original = FileSource {
        volume,
        chain: volume.file_chain(cx, &entry)?,
    };
    let source = EditSource::new(&original, size, 0, &[])?;
    let plan = Replacement::prepare(cx, volume, path, &source, now)?;
    plan.execute(cx, volume, &source, || Ok(()))?;
    Ok(())
}

companion_bin_tests! {
#[cfg(test)]
mod tests {
    use super::super::{SliceSource, creation, hash_device, open_volume};
    use super::*;

    #[test]
    fn edited_source_matches_materialized_oracle_at_every_window() {
        let cx = Cx::for_testing();
        let original = b"abcdefghijklmnopqrstuvwxyz";
        let device = SliceSource(original);
        for (size, offset, patch) in [
            (26, 8, b"PATCH".as_slice()),
            (26, 0, b"FIRST".as_slice()),
            (36, 32, b"LAST".as_slice()),
            (26, 0, b"".as_slice()),
            (11, 0, b"".as_slice()),
            (40, 0, b"".as_slice()),
            (0, 0, b"".as_slice()),
        ] {
            let source = EditSource::new(&device, size as u64, offset as u64, patch).unwrap();
            let mut expected = original.to_vec();
            expected.resize(size, 0);
            expected[offset..offset + patch.len()].copy_from_slice(patch);
            for start in 0..=size {
                for end in start..=size {
                    let mut actual = vec![0xA5; end - start];
                    source
                        .read_exact_at(&cx, ByteOffset(start as u64), &mut actual)
                        .unwrap();
                    assert_eq!(actual, expected[start..end]);
                }
            }
        }
    }

    #[test]
    fn edited_source_rejects_overflow_out_of_bounds_and_cancellation() {
        let cx = Cx::for_testing();
        let device = SliceSource(b"old");
        assert!(EditSource::new(&device, u64::MAX, u64::MAX, b"x").is_err());
        assert!(EditSource::new(&device, 3, 3, b"x").is_err());
        let source = EditSource::new(&device, 8, 5, b"new").unwrap();
        let mut bytes = [0xA5; 2];
        assert!(source.read_exact_at(&cx, ByteOffset(7), &mut bytes).is_err());
        assert_eq!(bytes, [0xA5; 2]);
        assert!(
            source
                .read_exact_at(&cx, ByteOffset(u64::MAX), &mut bytes)
                .is_err()
        );
        assert!(matches!(
            source.write_all_at(&cx, ByteOffset(0), b"x"),
            Err(FfsError::ReadOnly)
        ));
        cx.set_cancel_requested(true);
        assert!(matches!(
            source.read_exact_at(&cx, ByteOffset(0), &mut bytes),
            Err(FfsError::Cancelled)
        ));
    }

    struct PatternSource(u64);

    impl ByteDevice for PatternSource {
        fn len_bytes(&self) -> u64 {
            self.0
        }

        fn read_exact_at(
            &self,
            cx: &Cx,
            offset: ByteOffset,
            bytes: &mut [u8],
        ) -> ffs_error::Result<()> {
            checkpoint(cx)?;
            checked_end(offset.0, bytes.len(), self.0)?;
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = ((offset.0 + index as u64) % 251) as u8;
            }
            Ok(())
        }

        fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
            Err(FfsError::ReadOnly)
        }

        fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
            checkpoint(cx)
        }
    }

    #[test]
    fn fat32_large_range_write_shrink_and_growth_stream_past_read_limit() {
        use clap::Parser as _;

        let cx = Cx::for_testing();
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("large.fat");
        let cli = crate::Cli::try_parse_from([
            "ffs-fat",
            "format",
            image.to_str().unwrap(),
            "--kind",
            "fat32",
            "--size-mib",
            "64",
        ])
        .unwrap();
        let crate::Command::Format { options } = cli.command else {
            panic!("expected formatter options");
        };
        crate::formatter::create(&cx, &options).unwrap();
        let args = crate::reader::ImageArgs {
            image,
            offset: 0,
            length: None,
            oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii,
            sidecar: None,
        };
        let volume = open_volume(&cx, &args, true).unwrap();
        const NOW: u64 = 1_700_000_000;
        const READ_LIMIT: u64 = 16 * 1024 * 1024;
        let size = READ_LIMIT + 8193;
        let original = PatternSource(size);
        let plan = creation::prepare(&cx, &volume, "/large.bin", &original, NOW).unwrap();
        plan.execute(&cx, &volume, &original, || Ok(())).unwrap();

        assert_eq!(
            write_range_in_volume(&cx, &volume, "/large.bin", READ_LIMIT + 37, b"edited", NOW)
                .unwrap(),
            6
        );
        let entry = volume.resolve(&cx, "/large.bin").unwrap().unwrap();
        let chain = volume.file_chain(&cx, &entry).unwrap();
        assert_eq!(u64::from(entry.native.size), size);
        let mut expected = vec![0; 128];
        original
            .read_exact_at(&cx, ByteOffset(READ_LIMIT), &mut expected)
            .unwrap();
        expected[37..43].copy_from_slice(b"edited");
        assert_eq!(volume.read(&cx, &chain, READ_LIMIT, 128).unwrap(), expected);
        let mut tail = [0; 73];
        original
            .read_exact_at(&cx, ByteOffset(size - 73), &mut tail)
            .unwrap();
        assert_eq!(volume.read(&cx, &chain, size - 73, 73).unwrap(), tail);

        let shorter = size - 4096;
        truncate_in_volume(&cx, &volume, "/large.bin", shorter, NOW).unwrap();
        let entry = volume.resolve(&cx, "/large.bin").unwrap().unwrap();
        assert_eq!(u64::from(entry.native.size), shorter);
        let longer = size + 4096;
        truncate_in_volume(&cx, &volume, "/large.bin", longer, NOW).unwrap();
        let entry = volume.resolve(&cx, "/large.bin").unwrap().unwrap();
        let chain = volume.file_chain(&cx, &entry).unwrap();
        assert_eq!(u64::from(entry.native.size), longer);
        assert_eq!(volume.read(&cx, &chain, READ_LIMIT, 128).unwrap(), expected);
        assert_eq!(volume.read(&cx, &chain, shorter, 8192).unwrap(), vec![0; 8192]);

        let before = hash_device(&cx, volume.device.as_ref()).unwrap();
        assert_eq!(
            write_range_in_volume(&cx, &volume, "/large.bin", longer + 65536, &[], NOW)
                .unwrap(),
            0
        );
        assert_eq!(
            write_range_in_volume(&cx, &volume, "/large.bin", u64::MAX, &[], NOW).unwrap(),
            0
        );
        assert_eq!(hash_device(&cx, volume.device.as_ref()).unwrap(), before);
        let check = volume.check(&cx).unwrap();
        assert!(check.clean && check.complete && check.namespace_complete);
    }
}
}
