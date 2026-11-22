//! Native, crash-safe NTFS 3.1 / 3.0 volume formatter (`ffs-ntfs format`).
//!
//! Creates a complete, external-oracle-compatible NTFS image or device layout
//! (boot sector + trailing backup boot sector, `$MFT`, `$MFTMirr`, clean
//! `$LogFile`, `$Volume`, `$AttrDef`, `.` root `$I30`, `$Bitmap`, `$Boot`,
//! `$BadClus` + `$Bad`, `$Secure` with `$SDS`/`$SII`/`$SDH`, canonical 128 KiB
//! `$UpCase`, `$Extend` + `$ObjId`/`$Quota`/`$Reparse`, and reserved slots
//! `12..15`) while withholding primary VBR publication at byte `0` until full
//! readback verification and [`crate::reader::check::check_volume_device`] pass.

pub mod system_files;
pub mod upcase;

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_types::ByteOffset;
use serde::Serialize;

use crate::reader::check::{NtfsCheckLimits, NtfsCheckStatus, check_volume_device};
use crate::reader::checkpoint;
use crate::transaction::DEFAULT_NTFS_FILETIME;

const MIN_VOLUME_BYTES: u64 = 4 * 1024 * 1024;
const MAX_VOLUME_BYTES: u64 = 1_u64 << 44; // 16 TiB safe offline cap
const DEFAULT_RECORD_BYTES: u32 = 1_024;
const DEFAULT_INDEX_BYTES: u32 = 4_096;
const INITIAL_MFT_RECORDS: u64 = 32;
const LOG_PAGE_BYTES: u64 = 4_096;
const MIN_LOGFILE_BYTES: u64 = 256 * 1024; // 64 * 4 KiB (>= 50 pages required by LFS)
const DEFAULT_LOGFILE_BYTES: u64 = 2 * 1024 * 1024;
const BOOT_STREAM_BYTES: u64 = 8_192;
const IO_CHUNK_BYTES: usize = 64 * 1024;

/// Target NTFS on-disk version profile for native formatting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum NtfsFormatVersion {
    /// NTFS 3.1 (Windows XP+): 48-byte `FILE` header with self `record_number`.
    #[default]
    V3_1,
    /// NTFS 3.0 (Windows 2000): 42-byte `FILE` header, `$Secure` + `$Extend`.
    V3_0,
}

impl NtfsFormatVersion {
    #[must_use]
    pub const fn pair(self) -> [u8; 2] {
        match self {
            Self::V3_1 => [3, 1],
            Self::V3_0 => [3, 0],
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V3_1 => "3.1",
            Self::V3_0 => "3.0",
        }
    }
}

/// Parameters controlling native NTFS formatting.
#[derive(Debug, Clone)]
pub struct NtfsFormatOptions {
    pub image: PathBuf,
    /// When false (default), refuses to overwrite an existing file (`O_CREAT | O_EXCL`).
    pub allow_existing_target: bool,
    /// Explicit confirmation required when formatting over an existing offline image.
    pub offline_image: bool,
    pub size_bytes: Option<u64>,
    pub size_mib: Option<u64>,
    pub sector_bytes: u32,
    pub cluster_bytes: Option<u32>,
    pub version: NtfsFormatVersion,
    pub label: Option<String>,
    pub serial: Option<u64>,
    pub logfile_bytes: Option<u64>,
    pub timestamp_100ns: Option<u64>,
}

impl NtfsFormatOptions {
    /// Construct defaults for creating a brand-new NTFS 3.1 image of `size_mib` MiB.
    #[must_use]
    pub fn new_image(image: PathBuf, size_mib: u64) -> Self {
        Self {
            image,
            allow_existing_target: false,
            offline_image: false,
            size_bytes: None,
            size_mib: Some(size_mib),
            sector_bytes: 512,
            cluster_bytes: None,
            version: NtfsFormatVersion::V3_1,
            label: None,
            serial: None,
            logfile_bytes: None,
            timestamp_100ns: None,
        }
    }
}

/// Deterministic physical layout planned before touching target storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NtfsFormatLayout {
    pub version: [u8; 2],
    pub backing_bytes: u64,
    pub total_sectors: u64,
    pub volume_bytes: u64,
    pub sector_bytes: u32,
    pub sectors_per_cluster: u32,
    pub cluster_bytes: u32,
    pub cluster_count: u64,
    pub record_bytes: u32,
    pub index_bytes: u32,
    pub serial: u64,
    pub boot_clusters: u64,
    pub mft_cluster: u64,
    pub mft_clusters: u64,
    pub mft_records: u64,
    pub mirror_cluster: u64,
    pub mirror_clusters: u64,
    pub mirror_records: u64,
    pub logfile_cluster: u64,
    pub logfile_clusters: u64,
    pub logfile_bytes: u64,
    pub attrdef_cluster: u64,
    pub attrdef_clusters: u64,
    pub bitmap_cluster: u64,
    pub bitmap_clusters: u64,
    pub bitmap_bytes: u64,
    pub sds_cluster: u64,
    pub sds_clusters: u64,
    pub upcase_cluster: u64,
    pub upcase_clusters: u64,
    pub root_indx_cluster: u64,
    pub root_indx_clusters: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
}

/// Ordered persistence stages emitted during formatting (used for deterministic cut tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NtfsFormatStage {
    TargetCreated,
    SystemStreamsWritten,
    MftAndMirrorWritten,
    BackupBootWritten,
    PrePublishVerified,
    PrimaryBootPublished,
    Synced,
}

/// Fault/cancellation hook invoked at each [`NtfsFormatStage`].
pub type NtfsFormatStageHook = Box<dyn Fn(NtfsFormatStage) -> Result<()> + Send + Sync>;

/// Verified completion receipt returned by [`format_device`] and [`format_image_file`].
#[derive(Debug, Clone, Serialize)]
pub struct NtfsFormatReport {
    pub format: &'static str,
    pub ntfs_version: [u8; 2],
    pub backing_bytes: u64,
    pub volume_bytes: u64,
    pub sector_bytes: u32,
    pub cluster_bytes: u32,
    pub cluster_count: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
    pub mft_cluster: u64,
    pub mirror_cluster: u64,
    pub serial: u64,
    pub label: String,
    pub boot_published: bool,
    pub readback_blake3: String,
    pub check_clean: bool,
}

fn invoke_hook(hook: Option<&NtfsFormatStageHook>, stage: NtfsFormatStage) -> Result<()> {
    if let Some(h) = hook {
        h(stage)?;
    }
    Ok(())
}

/// Plan a deterministic, valid NTFS 3.1 or 3.0 volume layout without doing any I/O.
///
/// # Errors
/// Returns [`FfsError::InvalidGeometry`] or [`FfsError::Format`] if size,
/// sector/cluster geometry, volume label, or `$LogFile` bounds are invalid or
/// too small to hold the mandatory NTFS system streams.
pub fn plan_format(opts: &NtfsFormatOptions) -> Result<NtfsFormatLayout> {
    let backing_bytes = match (opts.size_bytes, opts.size_mib) {
        (Some(b), None) => b,
        (None, Some(mib)) => mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| FfsError::InvalidGeometry("size_mib overflows u64".into()))?,
        (Some(_), Some(_)) => {
            return Err(FfsError::Format(
                "specify exactly one of size_bytes or size_mib".into(),
            ));
        }
        (None, None) => {
            return Err(FfsError::Format(
                "must specify size_bytes or size_mib for NTFS formatting".into(),
            ));
        }
    };

    if !(MIN_VOLUME_BYTES..=MAX_VOLUME_BYTES).contains(&backing_bytes) {
        return Err(FfsError::InvalidGeometry(format!(
            "NTFS volume size {backing_bytes} outside admitted range ({MIN_VOLUME_BYTES}..={MAX_VOLUME_BYTES})"
        )));
    }
    if !matches!(opts.sector_bytes, 512 | 1024 | 2048 | 4096) {
        return Err(FfsError::InvalidGeometry(format!(
            "unsupported NTFS sector size {} (expected 512, 1024, 2048, or 4096)",
            opts.sector_bytes
        )));
    }
    if !backing_bytes.is_multiple_of(u64::from(opts.sector_bytes)) {
        return Err(FfsError::InvalidGeometry(format!(
            "backing size {backing_bytes} is not a multiple of sector_bytes {}",
            opts.sector_bytes
        )));
    }

    let cluster_bytes = opts
        .cluster_bytes
        .unwrap_or_else(|| opts.sector_bytes.max(4096));
    if !(512..=65_536).contains(&cluster_bytes)
        || !cluster_bytes.is_power_of_two()
        || cluster_bytes < opts.sector_bytes
    {
        return Err(FfsError::InvalidGeometry(format!(
            "invalid cluster_bytes {cluster_bytes} for sector_bytes {}",
            opts.sector_bytes
        )));
    }
    let sectors_per_cluster = cluster_bytes / opts.sector_bytes;
    if sectors_per_cluster == 0 || sectors_per_cluster > 128 {
        return Err(FfsError::InvalidGeometry(format!(
            "sectors_per_cluster ({sectors_per_cluster}) exceeds NTFS BPB limit 128"
        )));
    }

    if let Some(label) = &opts.label
        && label.encode_utf16().count() > 127
    {
        return Err(FfsError::NameTooLong);
    }

    // Reserve the trailing sector for the mandatory backup boot sector.
    let backing_sectors = backing_bytes / u64::from(opts.sector_bytes);
    let total_sectors = backing_sectors.checked_sub(1).ok_or_else(|| {
        FfsError::InvalidGeometry("backing too small to hold backup boot sector".into())
    })?;
    let volume_bytes = total_sectors * u64::from(opts.sector_bytes);
    let cluster_count = total_sectors / u64::from(sectors_per_cluster);
    if cluster_count < 64 {
        return Err(FfsError::InvalidGeometry(format!(
            "cluster_count ({cluster_count}) too small for NTFS metadata"
        )));
    }

    let cb = u64::from(cluster_bytes);
    let record_bytes = DEFAULT_RECORD_BYTES.max(opts.sector_bytes);
    let index_bytes = DEFAULT_INDEX_BYTES.max(opts.sector_bytes);

    let boot_clusters = BOOT_STREAM_BYTES.div_ceil(cb);
    let mirror_records = 4_u64;
    let mirror_bytes = mirror_records * u64::from(record_bytes);
    let mirror_clusters = mirror_bytes.div_ceil(cb);

    let mft_records = INITIAL_MFT_RECORDS.max(mirror_records);
    let mft_bytes = mft_records * u64::from(record_bytes);
    let mft_clusters = mft_bytes.div_ceil(cb);

    // Choose sensible $LogFile size scaled to volume capacity unless explicitly supplied.
    let default_log = if backing_bytes >= 32 * 1024 * 1024 {
        DEFAULT_LOGFILE_BYTES
    } else if backing_bytes >= 12 * 1024 * 1024 {
        512 * 1024
    } else {
        MIN_LOGFILE_BYTES
    };
    let logfile_bytes = opts.logfile_bytes.unwrap_or(default_log);
    if !(MIN_LOGFILE_BYTES..=64 * 1024 * 1024).contains(&logfile_bytes)
        || !logfile_bytes.is_multiple_of(LOG_PAGE_BYTES)
    {
        return Err(FfsError::InvalidGeometry(format!(
            "logfile_bytes ({logfile_bytes}) must be a 4 KiB multiple in {MIN_LOGFILE_BYTES}..=67108864"
        )));
    }
    let logfile_clusters = logfile_bytes.div_ceil(cb);

    let attrdef_bytes =
        u64::try_from(ffs_ondisk::ntfs::encode_standard_ntfs_attr_def_table().len())
            .map_err(|_| FfsError::Format("attrdef len overflow".into()))?;
    let attrdef_clusters = attrdef_bytes.div_ceil(cb);

    // Round $Bitmap byte length to an 8-byte boundary (matching mkntfs/Windows).
    let bitmap_bytes = cluster_count.div_ceil(8).next_multiple_of(8);
    let bitmap_clusters = bitmap_bytes.div_ceil(cb);

    // $Secure:$SDS spans primary + 256 KiB copy distance (~262,400 bytes -> 256 KiB + 4 KiB).
    let sds_est_bytes = ffs_ondisk::ntfs_security::SDS_COPY_DISTANCE + 4_096;
    let sds_clusters = sds_est_bytes.div_ceil(cb);

    let upcase_clusters = (upcase::UPCASE_TABLE_BYTES as u64).div_ceil(cb);
    let root_indx_clusters = u64::from(index_bytes).div_ceil(cb);

    // Place $MFTMirr cleanly at volume midpoint (like mkntfs/Windows), keeping all
    // early metadata strictly before mirror_cluster (or cleanly packed around it).
    let mft_cluster = boot_clusters.max(4);
    let mut cursor = mft_cluster + mft_clusters;

    let mut mirror_cluster = (cluster_count / 2).max(cursor + 1);
    let early_needed = attrdef_clusters
        + bitmap_clusters
        + sds_clusters
        + upcase_clusters
        + root_indx_clusters
        + logfile_clusters;
    if cursor + early_needed + mirror_clusters >= cluster_count {
        return Err(FfsError::NoSpace);
    }

    // Helper: allocate contiguous clusters avoiding `[mirror_cluster, mirror_cluster + mirror_clusters)`.
    let alloc_run = |cur: &mut u64, count: u64, mirr_start: u64, mirr_len: u64| -> Result<u64> {
        let mut start = *cur;
        let mirr_end = mirr_start + mirr_len;
        if start < mirr_end && start + count > mirr_start {
            start = mirr_end;
        }
        if start + count > cluster_count {
            return Err(FfsError::NoSpace);
        }
        *cur = start + count;
        Ok(start)
    };

    // If midpoint would leave insufficient room after it for large streams, shift mirror earlier cleanly.
    if cursor + early_needed > mirror_cluster
        && mirror_cluster + mirror_clusters + early_needed > cluster_count
    {
        mirror_cluster = cluster_count
            .checked_sub(mirror_clusters)
            .ok_or(FfsError::NoSpace)?;
    }

    let attrdef_cluster = alloc_run(
        &mut cursor,
        attrdef_clusters,
        mirror_cluster,
        mirror_clusters,
    )?;
    let bitmap_cluster = alloc_run(
        &mut cursor,
        bitmap_clusters,
        mirror_cluster,
        mirror_clusters,
    )?;
    let upcase_cluster = alloc_run(
        &mut cursor,
        upcase_clusters,
        mirror_cluster,
        mirror_clusters,
    )?;
    let sds_cluster = alloc_run(&mut cursor, sds_clusters, mirror_cluster, mirror_clusters)?;
    let root_indx_cluster = alloc_run(
        &mut cursor,
        root_indx_clusters,
        mirror_cluster,
        mirror_clusters,
    )?;
    let logfile_cluster = alloc_run(
        &mut cursor,
        logfile_clusters,
        mirror_cluster,
        mirror_clusters,
    )?;

    let allocated_clusters = boot_clusters
        + mft_clusters
        + mirror_clusters
        + attrdef_clusters
        + bitmap_clusters
        + upcase_clusters
        + sds_clusters
        + root_indx_clusters
        + logfile_clusters;
    let free_clusters = cluster_count
        .checked_sub(allocated_clusters)
        .ok_or(FfsError::NoSpace)?;

    let serial = opts.serial.unwrap_or_else(|| {
        // Deterministic non-zero serial derived from geometry + version + label when omitted.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"frankenfs-ntfs-format-v1");
        hasher.update(&backing_bytes.to_le_bytes());
        hasher.update(&cluster_bytes.to_le_bytes());
        hasher.update(&opts.version.pair());
        if let Some(lbl) = &opts.label {
            hasher.update(lbl.as_bytes());
        }
        let digest = hasher.finalize();
        let raw = u64::from_le_bytes(digest.as_bytes()[0..8].try_into().unwrap_or([1; 8]));
        if raw == 0 { 0x4652_414E_4B45_4E31 } else { raw }
    });

    Ok(NtfsFormatLayout {
        version: opts.version.pair(),
        backing_bytes,
        total_sectors,
        volume_bytes,
        sector_bytes: opts.sector_bytes,
        sectors_per_cluster,
        cluster_bytes,
        cluster_count,
        record_bytes,
        index_bytes,
        serial,
        boot_clusters,
        mft_cluster,
        mft_clusters,
        mft_records,
        mirror_cluster,
        mirror_clusters,
        mirror_records,
        logfile_cluster,
        logfile_clusters,
        logfile_bytes,
        attrdef_cluster,
        attrdef_clusters,
        bitmap_cluster,
        bitmap_clusters,
        bitmap_bytes,
        sds_cluster,
        sds_clusters,
        upcase_cluster,
        upcase_clusters,
        root_indx_cluster,
        root_indx_clusters,
        allocated_clusters,
        free_clusters,
    })
}

/// Read-only overlay presenting candidate primary VBR bytes at `[0..vbr.len())`
/// while reading every other byte directly from the underlying target device.
pub(crate) struct CandidateBootOverlayDevice {
    inner: Arc<dyn ByteDevice>,
    vbr: Vec<u8>,
}

impl CandidateBootOverlayDevice {
    pub(crate) fn new(inner: Arc<dyn ByteDevice>, vbr: Vec<u8>) -> Self {
        Self { inner, vbr }
    }
}

impl ByteDevice for CandidateBootOverlayDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let vbr_len = self.vbr.len() as u64;
        if offset.0 >= vbr_len {
            return self.inner.read_exact_at(cx, offset, data);
        }
        let end = offset
            .0
            .checked_add(data.len() as u64)
            .ok_or_else(|| FfsError::Format("overlay read overflow".into()))?;
        if end <= vbr_len {
            let start = offset.0 as usize;
            data.copy_from_slice(&self.vbr[start..start + data.len()]);
            return Ok(());
        }
        let head = (vbr_len - offset.0) as usize;
        let start = offset.0 as usize;
        data[..head].copy_from_slice(&self.vbr[start..]);
        self.inner
            .read_exact_at(cx, ByteOffset(vbr_len), &mut data[head..])
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Err(FfsError::ReadOnly)
    }
}

/// Format an already-opened writable [`ByteDevice`] with a native NTFS 3.1 or 3.0 volume.
///
/// Withholds primary VBR publication at byte `0` until every metadata stream,
/// `$MFT`, `$MFTMirr`, and the trailing backup boot sector have been written,
/// synced, read back, hashed, and verified clean via [`check_volume_device`].
///
/// # Errors
/// Returns an error on invalid options/geometry, insufficient space, device I/O
/// failure, hook fault injection, cancellation, or pre-publication check failure.
pub fn format_device(
    cx: &Cx,
    device: &Arc<dyn ByteDevice>,
    opts: &NtfsFormatOptions,
    hook: Option<&NtfsFormatStageHook>,
) -> Result<NtfsFormatReport> {
    checkpoint(cx)?;
    let layout = plan_format(opts)?;
    if device.len_bytes() < layout.backing_bytes {
        return Err(FfsError::InvalidGeometry(format!(
            "target device length ({}) is smaller than planned backing_bytes ({})",
            device.len_bytes(),
            layout.backing_bytes
        )));
    }
    invoke_hook(hook, NtfsFormatStage::TargetCreated)?;

    let label_str = opts.label.clone().unwrap_or_default();
    let filetime = opts.timestamp_100ns.unwrap_or(DEFAULT_NTFS_FILETIME);
    let built = system_files::build_bootstrap_volume(cx, &layout, &label_str, filetime)?;

    // Ensure offset 0..sector_bytes is explicitly zeroed while writing (primary VBR withheld).
    let zero_vbr = vec![0_u8; built.vbr_sector.len()];
    device.write_all_at(cx, ByteOffset(0), &zero_vbr)?;

    let cb = u64::from(layout.cluster_bytes);
    let write_at_cluster = |cluster: u64, bytes: &[u8]| -> Result<()> {
        let base = cluster
            .checked_mul(cb)
            .ok_or_else(|| FfsError::Format("cluster offset overflow".into()))?;
        let mut done = 0_usize;
        while done < bytes.len() {
            checkpoint(cx)?;
            let chunk = (bytes.len() - done).min(IO_CHUNK_BYTES);
            device.write_all_at(
                cx,
                ByteOffset(base + done as u64),
                &bytes[done..done + chunk],
            )?;
            done += chunk;
        }
        Ok(())
    };

    // Stage 1: Write all non-resident system streams ($Boot tail, $AttrDef, $Bitmap,
    // $UpCase, $Secure:$SDS, root $I30 INDX block, and $LogFile).
    if built.boot_stream.len() > built.vbr_sector.len() {
        device.write_all_at(
            cx,
            ByteOffset(built.vbr_sector.len() as u64),
            &built.boot_stream[built.vbr_sector.len()..],
        )?;
    }
    write_at_cluster(layout.attrdef_cluster, &built.attrdef_bytes)?;
    write_at_cluster(layout.bitmap_cluster, &built.bitmap_bytes)?;
    write_at_cluster(layout.upcase_cluster, &built.upcase_bytes)?;
    write_at_cluster(layout.sds_cluster, &built.sds_bytes)?;
    write_at_cluster(layout.root_indx_cluster, &built.root_indx_block)?;
    write_at_cluster(layout.logfile_cluster, &built.logfile_bytes)?;
    invoke_hook(hook, NtfsFormatStage::SystemStreamsWritten)?;

    // Stage 2: Write $MFT and $MFTMirr.
    write_at_cluster(layout.mft_cluster, &built.mft_bytes)?;
    write_at_cluster(layout.mirror_cluster, &built.mirror_bytes)?;
    invoke_hook(hook, NtfsFormatStage::MftAndMirrorWritten)?;

    // Stage 3: Write trailing backup boot sector and flush before verification.
    let backup_offset = layout.backing_bytes - u64::from(layout.sector_bytes);
    device.write_all_at(cx, ByteOffset(backup_offset), &built.vbr_sector)?;
    device.sync(cx)?;
    invoke_hook(hook, NtfsFormatStage::BackupBootWritten)?;

    // Stage 4: Pre-publication verification via read-only VBR overlay + full readback hash.
    let overlay: Arc<dyn ByteDevice> = Arc::new(CandidateBootOverlayDevice::new(
        Arc::clone(device),
        built.vbr_sector.clone(),
    ));
    let check = check_volume_device(
        cx,
        Arc::clone(&overlay),
        0,
        layout.backing_bytes,
        NtfsCheckLimits::default(),
    )?;
    if !check.clean || check.status != NtfsCheckStatus::Clean {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!(
                "pre-publication NTFS check failed ({:?}): {:?}",
                check.status, check.issues
            ),
        });
    }
    let readback_blake3 = compute_device_blake3(cx, &overlay, layout.backing_bytes)?;
    invoke_hook(hook, NtfsFormatStage::PrePublishVerified)?;

    // Stage 5: Publish primary VBR at offset 0 and sync durably!
    device.write_all_at(cx, ByteOffset(0), &built.vbr_sector)?;
    invoke_hook(hook, NtfsFormatStage::PrimaryBootPublished)?;
    device.sync(cx)?;
    invoke_hook(hook, NtfsFormatStage::Synced)?;

    Ok(NtfsFormatReport {
        format: "NTFS",
        ntfs_version: layout.version,
        backing_bytes: layout.backing_bytes,
        volume_bytes: layout.volume_bytes,
        sector_bytes: layout.sector_bytes,
        cluster_bytes: layout.cluster_bytes,
        cluster_count: layout.cluster_count,
        allocated_clusters: layout.allocated_clusters,
        free_clusters: layout.free_clusters,
        mft_cluster: layout.mft_cluster,
        mirror_cluster: layout.mirror_cluster,
        serial: layout.serial,
        label: label_str,
        boot_published: true,
        readback_blake3,
        check_clean: true,
    })
}

pub(crate) fn compute_device_blake3(
    cx: &Cx,
    device: &Arc<dyn ByteDevice>,
    len: u64,
) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0_u8; IO_CHUNK_BYTES];
    let mut off = 0_u64;
    while off < len {
        checkpoint(cx)?;
        let n = ((len - off).min(IO_CHUNK_BYTES as u64)) as usize;
        device.read_exact_at(cx, ByteOffset(off), &mut buf[..n])?;
        hasher.update(&buf[..n]);
        off += n as u64;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

struct WritableTargetFile {
    file: File,
    len: u64,
}

impl ByteDevice for WritableTargetFile {
    fn len_bytes(&self) -> u64 {
        self.len
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

pub(crate) fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        let dir_path = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(dir) = File::open(dir_path) {
            let _ = dir.sync_all();
        }
    }
}

/// Format a new (or explicitly authorized existing offline) regular image file
/// with a native NTFS 3.1 or 3.0 filesystem.
///
/// # Errors
/// Fails closed if the target already exists without `allow_existing_target && offline_image`,
/// if the target is a symlink/device/directory, or if formatting/verification fails.
pub fn format_image_file(
    cx: &Cx,
    opts: &NtfsFormatOptions,
    hook: Option<&NtfsFormatStageHook>,
) -> Result<NtfsFormatReport> {
    checkpoint(cx)?;
    let layout = plan_format(opts)?;

    let file = if opts.allow_existing_target {
        if !opts.offline_image {
            return Err(FfsError::UnsupportedFeature(
                "overwriting an existing target requires both --offline-image and --allow-overwrite"
                    .into(),
            ));
        }
        let meta = std::fs::symlink_metadata(&opts.image)?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(FfsError::UnsupportedFeature(
                "NTFS formatter refuses symlinks, directories, and special devices".into(),
            ));
        }
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&opts.image)?;
        f.try_lock()
            .map_err(|e| FfsError::Io(std::io::Error::other(e)))?;
        f.set_len(0)?;
        f.set_len(layout.backing_bytes)?;
        f
    } else {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&opts.image)?;
        f.try_lock()
            .map_err(|e| FfsError::Io(std::io::Error::other(e)))?;
        f.set_len(layout.backing_bytes)?;
        f
    };

    let dev: Arc<dyn ByteDevice> = Arc::new(WritableTargetFile {
        file,
        len: layout.backing_bytes,
    });
    let report = format_device(cx, &dev, opts, hook)?;
    sync_parent_dir(&opts.image);
    Ok(report)
}
