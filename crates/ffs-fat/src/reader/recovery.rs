//! Offline diagnostics for native dirty FAT images, separate from mount admission.
//!
//! Checking never opens a repair sidecar, requests a writable handle, clears a
//! dirty bit, or synchronizes the backing. An unadmitted volume stays private to
//! this module; its findings cannot turn into a mounted read or write capability.

mod repair;
pub use repair::{RecoverArgs, RepairParentsArgs, recover, repair_parents};

use super::check::{CheckIssue, FatCheckReport};
use super::{FatGeometry, FatKind, FatVolume, ImageArgs, ReadOnlyImage, checkpoint, corrupt};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX_FINDINGS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

fn open_read_only(path: &Path) -> Result<(File, Stamp)> {
    let named = fs::symlink_metadata(path)?;
    if !named.is_file() || named.file_type().is_symlink() {
        bail!("offline FAT diagnosis requires a regular image, not a symlink or device");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || Stamp::of(&named) != Stamp::of(&opened) {
        bail!("FAT image identity changed while opening for diagnosis");
    }
    file.try_lock_shared()
        .map_err(|error| anyhow::anyhow!("cannot shared-lock FAT image: {error}"))?;
    let stamp = Stamp::of(&opened);
    stable(&file, path, stamp)?;
    Ok((file, stamp))
}

fn stable(file: &File, path: &Path, stamp: Stamp) -> Result<()> {
    let named = fs::symlink_metadata(path)?;
    if !named.is_file()
        || named.file_type().is_symlink()
        || Stamp::of(&named) != stamp
        || Stamp::of(&file.metadata()?) != stamp
    {
        bail!("FAT image changed during offline diagnosis; no consistent result is available");
    }
    Ok(())
}

fn reject_sidecar(args: &ImageArgs) -> Result<()> {
    if args.sidecar.is_some() {
        return Err(FfsError::UnsupportedFeature(
            "strict offline FAT diagnosis does not open repair sidecars; omit --sidecar to inspect native bytes without read-repair".into(),
        ).into());
    }
    Ok(())
}

struct DiagnosticVolume {
    volume: FatVolume,
    boot: [u8; 512],
}

impl DiagnosticVolume {
    fn from_device(cx: &Cx, device: Box<dyn ByteDevice>, args: &ImageArgs) -> Result<Self> {
        let length = args
            .length
            .unwrap_or_else(|| device.len_bytes().saturating_sub(args.offset));
        let (volume, boot) = FatVolume::parse_volume(cx, device, args.offset, length)?;
        let result = Self {
            volume: volume.with_oem_code_page(args.oem_code_page),
            boot,
        };
        result.validate_geometry(cx)?;
        Ok(result)
    }

    fn validate_geometry(&self, cx: &Cx) -> Result<()> {
        let media = self.boot[21];
        if media != 0xF0 && media < 0xF8 {
            return Err(corrupt(21, "invalid FAT media descriptor").into());
        }
        if let Some(sector) = self.volume.geometry.backup_boot_sector() {
            let offset = u64::from(sector) * u64::from(self.volume.geometry.sector_bytes());
            let mut backup = [0; 512];
            self.volume.read_exact(cx, offset, &mut backup)?;
            let geometry = FatGeometry::parse(&backup, self.volume.geometry.volume_bytes())
                .map_err(|error| corrupt(offset, error.to_string()))?;
            if geometry != self.volume.geometry || backup[21] != self.boot[21] {
                return Err(
                    corrupt(offset, "FAT primary and backup boot geometry disagree").into(),
                );
            }
        }
        Ok(())
    }

    fn report(&self, cx: &Cx) -> Result<FatCheckReport> {
        // The ordinary checker deliberately ignores clean bits while verifying
        // an in-flight writer. Offline diagnosis must add that missing evidence.
        // Inspect actual bytes; never manufacture clean headers in an overlay.
        let native = self.native_state(cx)?;
        let mut report = self.volume.check(cx)?;
        for issue in native {
            if report.issues.len() < MAX_FINDINGS {
                report.issues.push(issue);
            } else {
                report.omitted_issues += 1;
            }
        }
        report.scope = "native dirty/error state, allocation ownership, chain lengths, directory structure and primary FSInfo; no file-content integrity or repair";
        report.clean = report.is_clean();
        report.status = if report.clean {
            "clean"
        } else if report.complete {
            "issues_found"
        } else {
            "incomplete"
        };
        checkpoint(cx)?;
        Ok(report)
    }

    fn native_state(&self, cx: &Cx) -> Result<Vec<CheckIssue>> {
        let volume = &self.volume;
        let geometry = &volume.geometry;
        let (state_at, mask, clean, io_ok) = match geometry.kind() {
            FatKind::Fat16 => (37, 0xFFFF_u32, 0x8000_u32, 0x4000_u32),
            FatKind::Fat32 => (65, 0x0FFF_FFFF, 0x0800_0000, 0x0400_0000),
        };
        let mut issues = Vec::new();
        for number in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
            let offset = u64::from(number) * u64::from(geometry.sector_bytes());
            let mut boot = [0; 512];
            volume.read_exact(cx, offset, &mut boot)?;
            for (bits, kind, message) in [
                (1, "native_boot_dirty", "native boot dirty flag is set"),
                (
                    2,
                    "native_surface_test",
                    "native surface-test request is set",
                ),
                (
                    0xFC,
                    "native_boot_flags",
                    "unknown native boot state flags are set",
                ),
            ] {
                if boot[state_at] & bits != 0 {
                    issues.push(state_issue(kind, offset + state_at as u64, message));
                }
            }
        }
        let width = geometry.kind().entry_bytes() as usize;
        let expected_zero = (mask & !0xFF) | u32::from(self.boot[21]);
        for copy in volume.copies() {
            checkpoint(cx)?;
            let offset = geometry
                .entry_offset(copy, 2)
                .map_err(|error| corrupt(0, error.to_string()))?
                - 2 * width as u64;
            let mut header = [0; 8];
            volume.read_exact(cx, offset, &mut header[..2 * width])?;
            let raw = |at: usize| {
                let mut bytes = [0; 4];
                bytes[..width].copy_from_slice(&header[at..at + width]);
                u32::from_le_bytes(bytes) & mask
            };
            if raw(0) != expected_zero {
                issues.push(state_issue(
                    "native_reserved_zero",
                    offset,
                    &format!("reserved FAT entry zero is invalid in copy {copy}"),
                ));
            }
            let value = raw(width);
            let required = mask & !(clean | io_ok);
            if value & required != required {
                issues.push(state_issue(
                    "native_reserved_fat",
                    offset + width as u64,
                    &format!("reserved FAT entry one is invalid in copy {copy}"),
                ));
            }
            if value & clean == 0 {
                issues.push(state_issue(
                    "native_fat_dirty",
                    offset + width as u64,
                    &format!("FAT copy {copy} records an unclean shutdown"),
                ));
            }
            if value & io_ok == 0 {
                issues.push(state_issue(
                    "native_io_error",
                    offset + width as u64,
                    &format!("FAT copy {copy} records a hard I/O error"),
                ));
            }
        }
        Ok(issues)
    }
}

fn state_issue(kind: &'static str, offset: u64, message: &str) -> CheckIssue {
    CheckIssue {
        kind,
        entry_offset: None,
        cluster: None,
        other_entry_offset: None,
        detail: format!("{message} at volume-relative byte {offset}"),
    }
}

/// Diagnose a dirty image without granting normal reader/mount admission.
/// The caller must keep it offline; shared advisory locks are not snapshots.
/// Sidecars are refused because their protected reads may perform read-repair.
pub fn check(cx: &Cx, args: &ImageArgs) -> Result<FatCheckReport> {
    checkpoint(cx)?;
    reject_sidecar(args)?;
    let (file, stamp) = open_read_only(&args.image)?;
    let diagnostic = DiagnosticVolume::from_device(
        cx,
        Box::new(ReadOnlyImage {
            file: file.try_clone()?,
            len: stamp.length,
        }),
        args,
    )
    .context("opening FAT image for non-mutating diagnosis")?;
    let report = diagnostic.report(cx)?;
    stable(&file, &args.image, stamp)?;
    checkpoint(cx)?;
    Ok(report)
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
