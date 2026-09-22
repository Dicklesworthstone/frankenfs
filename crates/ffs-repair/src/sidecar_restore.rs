//! Restore an offline image's saved protection point to a new file.
//!
//! Recovery never overwrites the input image. All groups are reconstructed and
//! checksum-verified in bounded buffers, and the complete staged output must
//! match the archived whole-image digest before its final name is published.
//! Unrecoverable corruption, cancellation, or a pre-existing destination leaves
//! the destination unpublished/unchanged and the original evidence untouched.

use crate::codec::decode_group_with_owned_repair_symbols;
use crate::sidecar::{
    Archive, Header, MemoryGroup, ProtectionInfo, checkpoint, corrupt, load_source, open_image,
    parent_path, publish_new, source_digest,
};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::Path;
use tempfile::NamedTempFile;

/// A successful restore always reproduces the entire archived image digest.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RestoreReport {
    pub protection: ProtectionInfo,
    pub recovered_blocks: u64,
    pub intact_blocks: u64,
    pub discarded_repair_symbols: u64,
    pub output_bytes: u64,
}

fn install_recovered(
    header: &Header,
    source: &mut MemoryGroup,
    corrupt_indices: &[u32],
    expected: &[[u8; 32]],
    recovered: Vec<crate::codec::RecoveredBlock>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for block in recovered {
        let relative = block
            .block
            .0
            .checked_sub(source.first)
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| corrupt("decoder returned an out-of-range source block"))?;
        let index = relative as usize;
        if corrupt_indices.binary_search(&relative).is_err()
            || !seen.insert(relative)
            || block.data.len() != header.options.block_size as usize
            || expected.get(index) != Some(&source_digest(header, block.block.0, &block.data))
        {
            return Err(corrupt("reconstructed source block failed snapshot verification"));
        }
        let destination = source
            .blocks
            .get_mut(index)
            .ok_or_else(|| corrupt("decoder returned a block outside the source group"))?;
        *destination = block.data;
    }
    if seen.len() != corrupt_indices.len() {
        return Err(corrupt("decoder did not reconstruct every damaged source block"));
    }
    Ok(())
}

fn verify_staged_image(cx: &Cx, image: &File, header: &Header) -> Result<()> {
    if image.metadata()?.len() != header.image_bytes {
        return Err(corrupt("restored image length differs from the saved generation"));
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut offset = 0;
    while offset < header.image_bytes {
        checkpoint(cx)?;
        let length = (header.image_bytes - offset).min(buffer.len() as u64) as usize;
        image.read_exact_at(&mut buffer[..length], offset)?;
        hasher.update(&buffer[..length]);
        offset += length as u64;
    }
    checkpoint(cx)?;
    if hasher.finalize().as_bytes() != &header.snapshot_digest {
        return Err(corrupt("restored image does not match the saved whole-image digest"));
    }
    Ok(())
}

/// Reconstruct a saved image generation in a new output file.
///
/// The caller must take the source image offline. Changed source blocks are
/// erasures relative to the protection point, regardless of whether the change
/// was corruption or an intentional later write. This operation therefore
/// requires an explicit new destination rather than rolling back the source.
///
/// A corrupt parity symbol is discarded independently; surviving symbols are
/// used when the codec can still recover the missing data. The current codec
/// requires at least one intact source block per damaged group and may refuse
/// a rank-deficient symbol set even when the symbol count appears sufficient.
/// Such refusals never publish a partial output image.
pub fn restore(
    cx: &Cx,
    image_path: &Path,
    sidecar_path: &Path,
    output_path: &Path,
) -> Result<RestoreReport> {
    let archive = Archive::open(cx, sidecar_path)?;
    let image = open_image(cx, image_path)?;
    let header = &archive.header;
    let mut staged = NamedTempFile::new_in(parent_path(output_path))?;
    let mut report = RestoreReport {
        protection: header.info()?,
        recovered_blocks: 0,
        intact_blocks: 0,
        discarded_repair_symbols: 0,
        output_bytes: header.image_bytes,
    };

    for group in 0..header.groups {
        let record = archive.read_group(cx, group)?;
        let (mut source, unreadable) = load_source(cx, &image, header, group, true)?;
        let corrupt_indices: Vec<u32> = source
            .blocks
            .iter()
            .zip(&record.hashes)
            .enumerate()
            .filter_map(|(index, (bytes, expected))| {
                let relative = index as u32;
                let block = source.first + index as u64;
                (unreadable.binary_search(&relative).is_ok()
                    || source_digest(header, block, bytes) != *expected)
                    .then_some(relative)
            })
            .collect();
        report.discarded_repair_symbols += record.invalid_symbols;

        if !corrupt_indices.is_empty() {
            let outcome = decode_group_with_owned_repair_symbols(
                cx,
                &source,
                &header.seed,
                GroupNumber(group),
                BlockNumber(source.first),
                source.blocks.len() as u32,
                &corrupt_indices,
                record.symbols,
            )?;
            checkpoint(cx)?;
            if !outcome.complete {
                return Err(FfsError::RepairFailed(format!(
                    "sidecar group {group} could not be completely reconstructed"
                )));
            }
            install_recovered(
                header,
                &mut source,
                &corrupt_indices,
                &record.hashes,
                outcome.recovered,
            )?;
        }

        // Verify both reconstructed and originally intact buffers before any
        // bytes from this group are staged. The codec reads this captured
        // MemoryGroup, never a second, potentially changed source-file view.
        for (index, (bytes, expected)) in source.blocks.iter().zip(&record.hashes).enumerate() {
            checkpoint(cx)?;
            let block = source.first + index as u64;
            if source_digest(header, block, bytes) != *expected {
                return Err(corrupt("source group does not match the protection point"));
            }
            staged.write_all(&bytes[..header.real_block_len(block)])?;
        }
        report.recovered_blocks += corrupt_indices.len() as u64;
        report.intact_blocks += (source.blocks.len() - corrupt_indices.len()) as u64;
    }

    // Reread the staged file itself, not merely the buffers sent to write().
    // This also binds every source group to the one archived snapshot digest.
    staged.as_file().sync_all()?;
    verify_staged_image(cx, staged.as_file(), header)?;
    publish_new(cx, staged, output_path)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar::{SidecarOptions, protect, verify};
    use std::path::PathBuf;

    struct Fixture {
        _dir: tempfile::TempDir,
        image: PathBuf,
        sidecar: PathBuf,
        output: PathBuf,
        bytes: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("directory");
            let image = dir.path().join("source.img");
            let sidecar = dir.path().join("source.ffs-rq");
            let output = dir.path().join("recovered.img");
            let bytes: Vec<u8> = (0..19 * 512 + 37)
                .map(|index| ((index * 17 + index / 512) % 251) as u8)
                .collect();
            std::fs::write(&image, &bytes).expect("image");
            let options = SidecarOptions {
                block_size: 512,
                group_blocks: 8,
                repair_symbols: 6,
            };
            protect(&Cx::for_testing(), &image, &sidecar, options).expect("protect");
            Self {
                _dir: dir,
                image,
                sidecar,
                output,
                bytes,
            }
        }

        fn damage(&self, blocks: &[u64]) {
            let file = File::options().write(true).open(&self.image).expect("image");
            for &block in blocks {
                file.write_all_at(&[255], block * 512).expect("damage");
            }
        }

        fn recover(&self) -> Result<RestoreReport> {
            restore(&Cx::for_testing(), &self.image, &self.sidecar, &self.output)
        }
    }

    #[test]
    fn sidecar_restore_recovers_multiple_groups_and_partial_final_block_after_reopen() {
        let fixture = Fixture::new();
        fixture.damage(&[0, 3, 8, 19]);
        let damaged = std::fs::read(&fixture.image).expect("damaged evidence");
        let report = fixture.recover().expect("restore");
        assert_eq!(report.recovered_blocks, 4);
        assert_eq!(report.intact_blocks, 16);
        assert_eq!(report.output_bytes, fixture.bytes.len() as u64);
        assert_eq!(std::fs::read(&fixture.output).expect("output"), fixture.bytes);
        assert_eq!(std::fs::read(&fixture.image).expect("source"), damaged);
        assert!(verify(&Cx::for_testing(), &fixture.output, &fixture.sidecar)
            .expect("verify output")
            .is_healthy());
    }

    #[test]
    fn sidecar_restore_uses_surviving_parity_after_symbol_corruption() {
        let fixture = Fixture::new();
        fixture.damage(&[2]);
        // Independently address the first parity payload using the v1 layout:
        // header + group prefix + eight source digests + metadata digest + ESI.
        let offset = 128 + 32 + 8 * 32 + 32 + 4;
        let file = File::options()
            .read(true)
            .write(true)
            .open(&fixture.sidecar)
            .expect("sidecar");
        let mut byte = [0];
        file.read_exact_at(&mut byte, offset).expect("parity");
        byte[0] ^= 1;
        file.write_all_at(&byte, offset).expect("damage parity");
        let report = fixture.recover().expect("remaining parity must recover");
        assert_eq!(report.recovered_blocks, 1);
        assert_eq!(report.discarded_repair_symbols, 1);
        assert_eq!(std::fs::read(&fixture.output).expect("output"), fixture.bytes);
    }

    #[test]
    fn sidecar_restore_can_rebuild_a_truncated_tail_without_extending_the_source() {
        let fixture = Fixture::new();
        let file = File::options().write(true).open(&fixture.image).expect("image");
        file.set_len(19 * 512).expect("truncate last partial block");
        let report = fixture.recover().expect("restore missing tail");
        assert_eq!(report.recovered_blocks, 1);
        assert_eq!(file.metadata().expect("source length").len(), 19 * 512);
        assert_eq!(std::fs::read(&fixture.output).expect("output"), fixture.bytes);
    }

    #[test]
    fn sidecar_restore_refuses_excess_erasures_without_publishing_a_prefix() {
        let fixture = Fixture::new();
        // Group zero stages successfully; group one exceeds its parity budget.
        fixture.damage(&[8, 9, 10, 11, 12, 13, 14]);
        let damaged = std::fs::read(&fixture.image).expect("evidence");
        assert!(fixture.recover().is_err());
        assert!(!fixture.output.exists());
        assert_eq!(std::fs::read(&fixture.image).expect("unchanged source"), damaged);
    }

    #[test]
    fn sidecar_restore_rejects_corrupt_metadata_and_never_replaces_existing_output() {
        let fixture = Fixture::new();
        std::fs::write(&fixture.output, b"keep existing output").expect("existing");
        assert!(fixture.recover().is_err());
        assert_eq!(
            std::fs::read(&fixture.output).expect("retained"),
            b"keep existing output"
        );
        let file = File::options().write(true).open(&fixture.sidecar).expect("sidecar");
        file.write_all_at(&[255; 32], 160).expect("corrupt source digest table");
        let other = fixture.output.with_extension("new");
        assert!(restore(&Cx::for_testing(), &fixture.image, &fixture.sidecar, &other).is_err());
        assert!(!other.exists());
        assert_eq!(std::fs::read(&fixture.image).expect("source"), fixture.bytes);
    }

    #[test]
    fn sidecar_restore_cancelled_and_alias_destinations_leave_original_intact() {
        let fixture = Fixture::new();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        assert!(matches!(
            restore(&cx, &fixture.image, &fixture.sidecar, &fixture.output),
            Err(FfsError::Cancelled)
        ));
        assert!(!fixture.output.exists());
        std::fs::hard_link(&fixture.image, &fixture.output).expect("alias");
        assert!(fixture.recover().is_err());
        assert_eq!(std::fs::read(&fixture.image).expect("source"), fixture.bytes);
    }

    #[test]
    fn sidecar_restore_holds_source_inode_exclusion_through_aliases() {
        let fixture = Fixture::new();
        let cx = Cx::for_testing();
        let held = open_image(&cx, &fixture.image).expect("hold image");
        let alias = fixture.image.with_extension("alias");
        std::fs::hard_link(&fixture.image, &alias).expect("alias");
        let error = restore(&cx, &alias, &fixture.sidecar, &fixture.output)
            .expect_err("held source must refuse concurrent restore");
        assert!(matches!(error, FfsError::Io(ref error) if error.kind() == std::io::ErrorKind::WouldBlock));
        assert!(!fixture.output.exists());
        drop(held);
        fixture.recover().expect("retry after release");
        assert_eq!(std::fs::read(&fixture.output).expect("output"), fixture.bytes);
    }
}
