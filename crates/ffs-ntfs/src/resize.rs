//! Non-destructive, source-preserving offline NTFS 3.0 / 3.1 resize (`ffs-ntfs resize`).
//!
//! - Opens the source image strictly read-only (`--offline-image`), honoring
//!   `--offset` and `--length` so adjacent partition bytes and sentinels are
//!   never addressable or mutated.
//! - Verifies `SourceStamp` (`dev`, `ino`, `len`, `mtime`, `ctime`) and header
//!   BLAKE3 digest before planning, after copying clusters, and immediately
//!   before primary VBR publication to fail closed on any concurrent source drift.
//! - Supports Grow, free-tail Shrink, and `--relocate` Shrink (moving `$MFTMirr`,
//!   metadata streams, `$I30` `INDX` blocks, `$ATTRIBUTE_LIST` extensions,
//!   compressed/WOF/ADS/user runs by pure physical LCN bijection while refusing
//!   to cross physical bad clusters in `$BadClus:$Bad`).
//! - Withholds primary VBR publication at byte `0` until backup boot sector
//!   write, full readback BLAKE3 digest, and [`crate::reader::check::check_volume_device`]
//!   all succeed.

mod planner;
mod relocator;

use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::{NtfsBootSectorSpec, encode_ntfs_boot_sector};
use ffs_types::ByteOffset;
use serde::Serialize;

use crate::formatter::{CandidateBootOverlayDevice, compute_device_blake3, sync_parent_dir};
use crate::reader::check::{NtfsCheckLimits, NtfsCheckStatus, check_volume_device};
use crate::reader::checkpoint;

/// Resize direction derived from old vs target cluster counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NtfsResizeDirection {
    Grow,
    Shrink,
    Unchanged,
}

/// Parameters controlling non-destructive offline NTFS resize.
#[derive(Debug, Clone)]
pub struct NtfsResizeOptions {
    pub source_image: PathBuf,
    pub source_offset: u64,
    pub source_length: Option<u64>,
    pub output: PathBuf,
    pub size_bytes: Option<u64>,
    pub size_mib: Option<u64>,
    /// Authorize physical cluster relocation when shrinking across live tail clusters.
    pub relocate: bool,
    /// Confirm the source image stays offline and immutable for the entire operation.
    pub offline_image: bool,
    /// Validate source and compute full relocation plan without creating output.
    pub dry_run: bool,
}

/// Ordered persistence stages emitted during resize (for deterministic cut tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NtfsResizeStage {
    SourceVerified,
    PlanBuilt,
    OutputCreated,
    ClustersCopied,
    RelocatedClustersWritten,
    MetadataRewritten,
    BackupBootWritten,
    PrePublishVerified,
    PrimaryBootPublished,
    Synced,
}

/// Fault/cancellation hook invoked at each [`NtfsResizeStage`].
pub type NtfsResizeStageHook = Box<dyn Fn(NtfsResizeStage) -> Result<()> + Send + Sync>;

/// One physical cluster relocation entry planned during shrinking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NtfsClusterRelocation {
    pub record: u64,
    pub attr_kind: u32,
    pub attr_id: u16,
    pub first_vcn: u64,
    pub clusters: u64,
    pub old_lcn: u64,
    pub new_lcn: u64,
}

/// Deterministic resize plan computed strictly read-only.
#[derive(Debug, Clone, Serialize)]
pub struct NtfsResizePlan {
    pub direction: NtfsResizeDirection,
    pub ntfs_version: [u8; 2],
    pub sector_bytes: u32,
    pub cluster_bytes: u32,
    pub old_backing_bytes: u64,
    pub new_backing_bytes: u64,
    pub old_volume_bytes: u64,
    pub new_volume_bytes: u64,
    pub old_clusters: u64,
    pub new_clusters: u64,
    pub allocated_clusters: u64,
    pub relocated_clusters: u64,
    pub relocated_extents: usize,
    pub old_mft_cluster: u64,
    pub new_mft_cluster: u64,
    pub old_mirror_cluster: u64,
    pub new_mirror_cluster: u64,
    pub old_bitmap_bytes: u64,
    pub new_bitmap_bytes: u64,
}

/// Completion receipt returned by [`run_resize`].
#[derive(Debug, Clone, Serialize)]
pub struct NtfsResizeReport {
    pub format: &'static str,
    pub plan: NtfsResizePlan,
    pub dry_run: bool,
    pub boot_published: bool,
    pub source_header_blake3: String,
    pub output_blake3: Option<String>,
    pub check_clean: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl SourceStamp {
    fn of(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            length: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

fn invoke_hook(hook: Option<&NtfsResizeStageHook>, stage: NtfsResizeStage) -> Result<()> {
    if let Some(h) = hook {
        h(stage)?;
    }
    Ok(())
}

struct ReadOnlySliceSource {
    file: File,
    base: u64,
    length: u64,
}

impl ByteDevice for ReadOnlySliceSource {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        if offset
            .0
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(FfsError::Format(
                "NTFS resize source read exceeds selected volume slice".into(),
            ));
        }
        let physical = self
            .base
            .checked_add(offset.0)
            .ok_or_else(|| FfsError::Format("source slice physical offset overflow".into()))?;
        self.file.read_exact_at(data, physical)?;
        checkpoint(cx)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Err(FfsError::ReadOnly)
    }
}

struct OutputFileDevice {
    file: File,
    length: u64,
}

impl ByteDevice for OutputFileDevice {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.file.read_exact_at(data, offset.0)?;
        checkpoint(cx)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, data: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        self.file.write_all_at(data, offset.0)?;
        checkpoint(cx)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        self.file.sync_all()?;
        checkpoint(cx)
    }
}

fn source_header_digest(file: &File, base: u64, slice_len: u64) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let sample_len = usize::try_from(slice_len.min(65_536))
        .map_err(|_| FfsError::Format("header sample overflow".into()))?;
    let mut head = vec![0_u8; sample_len];
    file.read_exact_at(&mut head, base)?;
    hasher.update(&head);
    if slice_len >= 512 {
        let mut tail = [0_u8; 512];
        file.read_exact_at(&mut tail, base + slice_len - 512)?;
        hasher.update(&tail);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn verify_source_unchanged(
    file: &File,
    path: &Path,
    base: u64,
    slice_len: u64,
    stamp: SourceStamp,
    expected_digest: &str,
) -> Result<()> {
    let named = fs::symlink_metadata(path)?;
    if !named.is_file()
        || named.file_type().is_symlink()
        || SourceStamp::of(&named) != stamp
        || SourceStamp::of(&file.metadata()?) != stamp
    {
        return Err(FfsError::Corruption {
            block: 0,
            detail:
                "NTFS resize source metadata changed mid-operation; aborting before VBR publication"
                    .into(),
        });
    }
    let now_digest = source_header_digest(file, base, slice_len)?;
    if now_digest != expected_digest {
        return Err(FfsError::Corruption {
            block: 0,
            detail: "NTFS resize source header bytes drifted mid-operation; aborting before VBR publication".into(),
        });
    }
    Ok(())
}

fn open_source_slice(
    opts: &NtfsResizeOptions,
) -> Result<(File, SourceStamp, u64, String, Arc<dyn ByteDevice>)> {
    if !opts.offline_image {
        return Err(FfsError::UnsupportedFeature(
            "NTFS resize requires explicit --offline-image confirmation".into(),
        ));
    }
    let meta = fs::symlink_metadata(&opts.source_image)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(FfsError::UnsupportedFeature(
            "NTFS resize source must be a regular offline image file".into(),
        ));
    }
    let file = File::open(&opts.source_image)?;
    file.try_lock_shared()
        .map_err(|e| FfsError::Io(std::io::Error::other(e)))?;
    let total_len = meta.len();
    let slice_len = opts
        .source_length
        .unwrap_or_else(|| total_len.saturating_sub(opts.source_offset));
    if slice_len < 512
        || opts
            .source_offset
            .checked_add(slice_len)
            .is_none_or(|end| end > total_len)
    {
        return Err(FfsError::InvalidGeometry(
            "NTFS resize source offset/length exceeds source file size".into(),
        ));
    }
    let stamp = SourceStamp::of(&meta);
    let digest = source_header_digest(&file, opts.source_offset, slice_len)?;
    let handle_for_dev = file.try_clone()?;
    let dev: Arc<dyn ByteDevice> = Arc::new(ReadOnlySliceSource {
        file: handle_for_dev,
        base: opts.source_offset,
        length: slice_len,
    });
    Ok((file, stamp, slice_len, digest, dev))
}

/// Compute an offline NTFS resize plan without creating or modifying any files.
///
/// # Errors
/// Returns an error if the source fails structural checking, is dirty/hibernated,
/// crosses bad clusters, or needs `--relocate` without it set.
pub fn plan_resize(cx: &Cx, opts: &NtfsResizeOptions) -> Result<NtfsResizePlan> {
    checkpoint(cx)?;
    let (_file, _stamp, slice_len, _digest, dev) = open_source_slice(opts)?;
    let internal = planner::build_resize_plan(cx, dev, slice_len, opts)?;
    Ok(internal.public)
}

/// Execute a non-destructive offline NTFS resize into a brand-new standalone
/// output image (`O_CREAT | O_EXCL`, `0600`), leaving the source untouched.
///
/// # Errors
/// Fails closed if source validation fails, target already exists or aliases
/// source, source drifts concurrently, a fault hook/cancellation fires, or
/// pre-publication verification does not certify a clean output image.
pub fn run_resize(
    cx: &Cx,
    opts: &NtfsResizeOptions,
    hook: Option<&NtfsResizeStageHook>,
) -> Result<NtfsResizeReport> {
    checkpoint(cx)?;
    let (src_file, src_stamp, slice_len, header_digest, src_dev) = open_source_slice(opts)?;
    invoke_hook(hook, NtfsResizeStage::SourceVerified)?;

    if !opts.dry_run {
        // Refuse output aliasing source even before O_CREAT|O_EXCL.
        if let Ok(out_meta) = fs::symlink_metadata(&opts.output) {
            if out_meta.dev() == src_stamp.device && out_meta.ino() == src_stamp.inode {
                return Err(FfsError::UnsupportedFeature(
                    "NTFS resize refuses in-place resize (output aliases source)".into(),
                ));
            }
            return Err(FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "NTFS resize output {} already exists",
                    opts.output.display()
                ),
            )));
        }
    }

    let plan = planner::build_resize_plan(cx, Arc::clone(&src_dev), slice_len, opts)?;
    verify_source_unchanged(
        &src_file,
        &opts.source_image,
        opts.source_offset,
        slice_len,
        src_stamp,
        &header_digest,
    )?;
    invoke_hook(hook, NtfsResizeStage::PlanBuilt)?;

    if opts.dry_run {
        return Ok(NtfsResizeReport {
            format: "NTFS",
            plan: plan.public,
            dry_run: true,
            boot_published: false,
            source_header_blake3: header_digest,
            output_blake3: None,
            check_clean: true,
        });
    }

    // Create brand-new standalone output file (0600, O_CREAT | O_EXCL, exclusive flock).
    let out_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&opts.output)?;
    out_file
        .try_lock()
        .map_err(|e| FfsError::Io(std::io::Error::other(e)))?;
    out_file.set_len(plan.public.new_backing_bytes)?;
    let out_dev: Arc<dyn ByteDevice> = Arc::new(OutputFileDevice {
        file: out_file,
        length: plan.public.new_backing_bytes,
    });
    invoke_hook(hook, NtfsResizeStage::OutputCreated)?;

    // Explicitly zero offset 0..sector_bytes (withheld primary VBR).
    let sec_len = usize::try_from(plan.public.sector_bytes)
        .map_err(|_| FfsError::Format("sector_bytes overflow".into()))?;
    out_dev.write_all_at(cx, ByteOffset(0), &vec![0_u8; sec_len])?;

    // Copy retained live clusters (< new_clusters), keeping offset 0..sector_bytes zeroed.
    relocator::copy_retained_clusters(cx, &src_dev, &out_dev, &plan)?;
    verify_source_unchanged(
        &src_file,
        &opts.source_image,
        opts.source_offset,
        slice_len,
        src_stamp,
        &header_digest,
    )?;
    invoke_hook(hook, NtfsResizeStage::ClustersCopied)?;

    // Copy relocated tail clusters to their new free slots < new_clusters.
    relocator::copy_relocated_clusters(cx, &src_dev, &out_dev, &plan)?;
    verify_source_unchanged(
        &src_file,
        &opts.source_image,
        opts.source_offset,
        slice_len,
        src_stamp,
        &header_digest,
    )?;
    invoke_hook(hook, NtfsResizeStage::RelocatedClustersWritten)?;

    // Rewrite MFT records ($Bitmap, $BadClus, and any relocated attributes), $Bitmap stream, and $MFTMirr.
    relocator::rewrite_metadata(cx, &out_dev, &plan)?;
    invoke_hook(hook, NtfsResizeStage::MetadataRewritten)?;

    // Encode new primary/backup VBR sector (updating total_sectors, mft_cluster, mirror_cluster).
    let hidden_sectors = if plan.source_vbr.len() >= 32 {
        u32::from_le_bytes([
            plan.source_vbr[28],
            plan.source_vbr[29],
            plan.source_vbr[30],
            plan.source_vbr[31],
        ])
    } else {
        0
    };
    let new_vbr = encode_ntfs_boot_sector(&NtfsBootSectorSpec {
        sector_bytes: plan.public.sector_bytes,
        sectors_per_cluster: plan.sectors_per_cluster,
        total_sectors: plan.new_total_sectors,
        mft_cluster: plan.public.new_mft_cluster,
        mirror_cluster: plan.public.new_mirror_cluster,
        record_bytes: plan.record_bytes,
        index_bytes: plan.index_bytes,
        serial: plan.serial,
        hidden_sectors,
    })
    .map_err(|e| FfsError::Format(e.to_string()))?;

    // Write trailing backup boot sector and sync before pre-publication verification.
    let backup_off = plan.public.new_backing_bytes - u64::from(plan.public.sector_bytes);
    out_dev.write_all_at(cx, ByteOffset(backup_off), &new_vbr)?;
    out_dev.sync(cx)?;
    invoke_hook(hook, NtfsResizeStage::BackupBootWritten)?;

    // Re-verify source did not drift at any point before publishing output.
    verify_source_unchanged(
        &src_file,
        &opts.source_image,
        opts.source_offset,
        slice_len,
        src_stamp,
        &header_digest,
    )?;

    // Pre-publication verification over candidate VBR overlay + full output readback BLAKE3.
    let overlay: Arc<dyn ByteDevice> = Arc::new(CandidateBootOverlayDevice::new(
        Arc::clone(&out_dev),
        new_vbr.clone(),
    ));
    let check = check_volume_device(
        cx,
        Arc::clone(&overlay),
        0,
        plan.public.new_backing_bytes,
        NtfsCheckLimits::default(),
    )?;
    if !check.clean || check.status != NtfsCheckStatus::Clean {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!(
                "pre-publication NTFS resize check failed ({:?}): {:?}",
                check.status, check.issues
            ),
        });
    }
    let output_blake3 = compute_device_blake3(cx, &overlay, plan.public.new_backing_bytes)?;
    invoke_hook(hook, NtfsResizeStage::PrePublishVerified)?;

    // Final source drift check immediately prior to primary VBR publication!
    verify_source_unchanged(
        &src_file,
        &opts.source_image,
        opts.source_offset,
        slice_len,
        src_stamp,
        &header_digest,
    )?;

    // Publish primary VBR at offset 0 and sync durably!
    out_dev.write_all_at(cx, ByteOffset(0), &new_vbr)?;
    invoke_hook(hook, NtfsResizeStage::PrimaryBootPublished)?;
    out_dev.sync(cx)?;
    sync_parent_dir(&opts.output)?;
    invoke_hook(hook, NtfsResizeStage::Synced)?;

    Ok(NtfsResizeReport {
        format: "NTFS",
        plan: plan.public,
        dry_run: false,
        boot_published: true,
        source_header_blake3: header_digest,
        output_blake3: Some(output_blake3),
        check_clean: true,
    })
}
