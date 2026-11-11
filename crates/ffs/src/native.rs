//! Bounded read-only access to the existing native filesystem engines.

use asupersync::Cx;
use ffs_block::io_engine::{VolumeAccess, VolumeDevice};
use ffs_block::{ByteDevice, FileByteDevice};
use ffs_core::{
    BtrfsMountSelection, DetectedFilesystem, DetectionError, Ext4JournalReplayMode, FsFormatKind,
    FsOps, OpenFs, OpenOptions, detect_all_filesystems_on_device,
};
use ffs_error::{FfsError, Result};
use ffs_ondisk::fat::FatOemCodePage;
use ffs_ondisk::partition::{
    PartitionEntry, PartitionParseError, PartitionParseOptions, PartitionSelector, PartitionTable,
};
use ffs_types::ByteOffset;
use std::io::IoSliceMut;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// An explicitly selected volume or journal inside an additional backing image.
/// The file must remain offline and immutable for the lifetime of the reader.
#[derive(Debug, Clone)]
pub struct ImageSource {
    pub path: PathBuf,
    pub offset: u64,
    pub length: Option<u64>,
}

/// Backend-specific read selection. Explicit selection still probes every
/// format and refuses ambiguous signatures; it never overrides native admission.
#[derive(Debug, Clone, Default)]
pub enum ReadOnlyBackend {
    /// Open the default view of the uniquely detected format.
    #[default]
    Auto,
    Ext4 {
        /// The JBD2 volume, with the same regular-file, lock and bounds admission
        /// as the data image. Recovery writes only to the volatile data overlay.
        external_journal: Option<ImageSource>,
    },
    Btrfs {
        root: BtrfsMountSelection,
        /// Each member retains its admitted descriptor through nested views.
        additional_devices: Vec<ImageSource>,
    },
    Fat {
        oem_code_page: FatOemCodePage,
    },
    /// Strict enumeration is the default. Indexed lookup validates only the
    /// selected native search range; directory enumeration remains complete.
    Ntfs {
        indexed_lookup: bool,
        /// Admit the verified volatile `$LogFile` recovery view. The backing
        /// image stays immutable; automatic detection retains clean admission.
        recover_logfile: bool,
    },
    Zfs(ZfsReadOptions),
}

/// ZFS selection keeps automatic read-only discovery distinct from an exact
/// committed candidate. Neither grants live pool ownership or write authority.
#[derive(Debug, Clone, Default)]
pub enum ZfsRootSelection {
    #[default]
    Auto,
    /// Automatic read-only selection bound to a caller-supplied pool GUID.
    Pool(u64),
    Candidate {
        pool_guid: u64,
        label: usize,
        slot: usize,
    },
}

/// Explicit missing-member extraction retains the native topology and parity
/// budget. It requires an exact exported-pool candidate and forbids log replay.
#[derive(Debug, Clone, Default)]
pub enum ZfsMissingMembers {
    #[default]
    None,
    Mirror(Vec<u64>),
    Raidz(Vec<u64>),
}

/// The same read-only pool, dataset, snapshot and volatile ZIL selections used
/// by the native ZFS engine. Dataset components and snapshot names are raw bytes.
#[derive(Debug, Clone, Default)]
pub struct ZfsReadOptions {
    pub additional_images: Vec<ImageSource>,
    pub root: ZfsRootSelection,
    pub dataset: Vec<Vec<u8>>,
    pub snapshot: Option<Vec<u8>>,
    pub replay_zil: bool,
    pub missing: ZfsMissingMembers,
}

/// Options for one immutable image view. There is deliberately no writable
/// fallback, native repair, external metadata WAL or runtime-construction option.
#[derive(Debug, Clone, Default)]
pub struct ReadOnlyOpenOptions {
    pub offset: u64,
    pub length: Option<u64>,
    /// Optional MBR or GPT partition selector (`1`, `<partuuid>`, `label:<name>`).
    /// Mutually exclusive with manual `offset` / `length`.
    pub partition: Option<PartitionSelector>,
    /// Permit falling back to the backup GPT header when the primary GPT is corrupt.
    pub allow_backup_gpt: bool,
    /// Synthetic ownership for FAT/NTFS/ZFS, as in their existing mount adapters.
    pub uid: u32,
    pub gid: u32,
    pub backend: ReadOnlyBackend,
}

/// Zero-copy, range-clamped [`ByteDevice`] window bound to a validated MBR or GPT
/// [`PartitionEntry`].
///
/// Any read, write, or discard whose start offset `>= entry.byte_len` or whose end
/// offset `> entry.byte_len` is rejected before forwarding to the inner device.
#[derive(Clone, Debug)]
pub struct PartitionByteDevice {
    volume: VolumeDevice,
    entry: PartitionEntry,
}

impl PartitionByteDevice {
    /// Construct a range-clamped partition window over `[entry.start_byte, entry.end_byte())`.
    pub fn new(
        inner: Arc<dyn ByteDevice>,
        entry: PartitionEntry,
        access: VolumeAccess,
    ) -> Result<Self> {
        if entry.byte_len == 0 {
            return Err(FfsError::InvalidGeometry(
                "partition byte_len must be non-zero".to_owned(),
            ));
        }
        let volume = VolumeDevice::new(inner, ByteOffset(entry.start_byte), entry.byte_len, access)?;
        Ok(Self { volume, entry })
    }

    /// Return the validated partition metadata for this slice.
    #[must_use]
    pub const fn entry(&self) -> &PartitionEntry {
        &self.entry
    }

    /// Return the underlying [`VolumeAccess`] policy (`ReadOnly` or `ReadWrite`).
    #[must_use]
    pub fn access(&self) -> VolumeAccess {
        self.volume.access()
    }

    fn check_bounds(&self, cx: &Cx, offset: ByteOffset, count: u64) -> Result<()> {
        checkpoint(cx)?;
        let end = offset.0.checked_add(count).ok_or_else(|| {
            FfsError::InvalidGeometry("partition-relative request overflows u64".to_owned())
        })?;
        if offset.0 >= self.entry.byte_len || end > self.entry.byte_len {
            return Err(FfsError::InvalidGeometry(format!(
                "partition #{} I/O out of bounds: offset={} len={count} partition_len={}",
                self.entry.index, offset.0, self.entry.byte_len
            )));
        }
        Ok(())
    }
}

impl ByteDevice for PartitionByteDevice {
    fn len_bytes(&self) -> u64 {
        self.entry.byte_len
    }

    fn supports_vectored_reads(&self) -> bool {
        self.volume.supports_vectored_reads()
    }

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        self.volume.preserves_read_exact_at_destination_on_error()
    }

    fn preserves_read_vectored_destinations_on_error(&self) -> bool {
        self.volume.preserves_read_vectored_destinations_on_error()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let count = u64::try_from(buf.len())
            .map_err(|_| FfsError::InvalidGeometry("partition buffer overflows u64".to_owned()))?;
        self.check_bounds(cx, offset, count)?;
        self.volume.read_exact_at(cx, offset, buf)
    }

    fn read_exact_at_volatile(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let count = u64::try_from(buf.len())
            .map_err(|_| FfsError::InvalidGeometry("partition buffer overflows u64".to_owned()))?;
        self.check_bounds(cx, offset, count)?;
        self.volume.read_exact_at_volatile(cx, offset, buf)
    }

    fn read_vectored_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        let mut count = 0_u64;
        for buf in bufs.iter() {
            let len = u64::try_from(buf.len()).map_err(|_| {
                FfsError::InvalidGeometry("partition vectored buffer overflows u64".to_owned())
            })?;
            count = count.checked_add(len).ok_or_else(|| {
                FfsError::InvalidGeometry("partition vectored read overflows u64".to_owned())
            })?;
        }
        self.check_bounds(cx, offset, count)?;
        self.volume.read_vectored_exact_at(cx, offset, bufs)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let count = u64::try_from(buf.len())
            .map_err(|_| FfsError::InvalidGeometry("partition buffer overflows u64".to_owned()))?;
        self.check_bounds(cx, offset, count)?;
        self.volume.write_all_at(cx, offset, buf)
    }

    fn write_vectored_all_at(&self, cx: &Cx, offset: ByteOffset, bufs: &[&[u8]]) -> Result<()> {
        let mut count = 0_u64;
        for buf in bufs {
            let len = u64::try_from(buf.len()).map_err(|_| {
                FfsError::InvalidGeometry("partition vectored buffer overflows u64".to_owned())
            })?;
            count = count.checked_add(len).ok_or_else(|| {
                FfsError::InvalidGeometry("partition vectored write overflows u64".to_owned())
            })?;
        }
        self.check_bounds(cx, offset, count)?;
        self.volume.write_vectored_all_at(cx, offset, bufs)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        self.volume.sync(cx)
    }

    fn supports_discard(&self) -> bool {
        self.volume.supports_discard()
    }

    fn discard(&self, cx: &Cx, offset: ByteOffset, length: u64) -> Result<()> {
        self.check_bounds(cx, offset, length)?;
        self.volume.discard(cx, offset, length)
    }
}

fn map_partition_error(err: PartitionParseError) -> FfsError {
    match err {
        PartitionParseError::Io(msg) => FfsError::Io(std::io::Error::other(msg)),
        PartitionParseError::InvalidOptions(_)
        | PartitionParseError::InvalidGeometry(_)
        | PartitionParseError::OverlappingPartitions { .. }
        | PartitionParseError::NestedPartitionTable { .. } => {
            FfsError::InvalidGeometry(err.to_string())
        }
        PartitionParseError::PartitionNotFound(_) => FfsError::NotFound(err.to_string()),
        PartitionParseError::PrimaryGptCorrupt { .. }
        | PartitionParseError::BackupGptCorrupt { .. } => FfsError::Corruption {
            block: 1,
            detail: err.to_string(),
        },
        PartitionParseError::NotAPartitionTable(_) | PartitionParseError::AmbiguousLabel(_) => {
            FfsError::Format(err.to_string())
        }
    }
}

/// Discover and validate the outer MBR or GPT partition table on a [`ByteDevice`].
pub fn discover_partitions_on_device(
    cx: &Cx,
    device: &dyn ByteDevice,
    options: &PartitionParseOptions,
) -> Result<PartitionTable> {
    checkpoint(cx)?;
    PartitionTable::parse_with_reader(device.len_bytes(), options, |offset, buf| {
        device
            .read_exact_at(cx, ByteOffset(offset), buf)
            .map_err(|err| err.to_string())
    })
    .map_err(map_partition_error)
}

/// Discover and validate the outer MBR or GPT partition table of a regular disk image file.
pub fn discover_partitions(
    cx: &Cx,
    path: impl AsRef<Path>,
    options: &PartitionParseOptions,
) -> Result<PartitionTable> {
    let device = open_image(cx, path.as_ref(), 0, None)?;
    discover_partitions_on_device(cx, &device, options)
}

/// Validate the outer partition table, resolve `selector`, reject nested partition-table
/// bombs inside the selected slice, and return a range-clamped [`PartitionByteDevice`].
pub fn select_partition_device(
    cx: &Cx,
    inner: Arc<dyn ByteDevice>,
    selector: &PartitionSelector,
    options: &PartitionParseOptions,
    access: VolumeAccess,
) -> Result<(PartitionTable, PartitionByteDevice)> {
    let table = discover_partitions_on_device(cx, inner.as_ref(), options)?;
    let entry = table.select(selector).map_err(map_partition_error)?.clone();
    let partition_dev = PartitionByteDevice::new(inner, entry.clone(), access)?;
    PartitionTable::ensure_slice_not_nested_partition_table(
        entry.index,
        entry.byte_len,
        table.logical_block_bytes,
        |offset, buf| {
            partition_dev
                .read_exact_at(cx, ByteOffset(offset), buf)
                .map_err(|err| err.to_string())
        },
    )
    .map_err(map_partition_error)?;
    Ok((table, partition_dev))
}

/// Open a regular disk image read-only and return the range-clamped [`PartitionByteDevice`]
/// selected by `selector` (retaining the shared file lock on the underlying descriptor).
pub fn open_partition_read_only(
    cx: &Cx,
    path: impl AsRef<Path>,
    selector: &PartitionSelector,
    options: &PartitionParseOptions,
) -> Result<(PartitionTable, PartitionByteDevice)> {
    let outer = open_image(cx, path.as_ref(), 0, None)?;
    select_partition_device(cx, Arc::new(outer), selector, options, VolumeAccess::ReadOnly)
}

/// An admitted native reader, ready for direct VFS use or a read-only FUSE mount.
/// The trait object exposes no format-specific write-enablement operation.
pub struct ReadOnlyFs {
    pub format: FsFormatKind,
    pub partition: Option<PartitionEntry>,
    pub filesystem: Box<dyn FsOps>,
    ntfs: Option<Arc<ffs_ntfs::NtfsFs>>,
}

impl ReadOnlyFs {
    /// Borrow the NTFS volume admitted by this open, for exact native DATA
    /// stream selection and metadata inspection. Other formats return `None`.
    /// The volume shares the original bounded, locked, OS-read-only descriptor;
    /// no pathname is reopened and no mutable volume reference is exposed.
    #[must_use]
    pub fn ntfs_volume(&self) -> Option<&ffs_ntfs::NtfsVolume> {
        self.ntfs.as_ref().map(|filesystem| filesystem.volume())
    }
}

impl std::fmt::Debug for ReadOnlyFs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadOnlyFs")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn open_image(cx: &Cx, path: &Path, offset: u64, length: Option<u64>) -> Result<VolumeDevice> {
    checkpoint(cx)?;
    let device = FileByteDevice::open_regular_read_only(path)?;
    // Retain this same descriptor under every engine and its clones. A second
    // pathname open could lock a different inode after a concurrent replacement.
    device
        .file()
        .try_lock_shared()
        .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
    let length = match length {
        Some(length) => length,
        None => device.len_bytes().checked_sub(offset).ok_or_else(|| {
            FfsError::InvalidGeometry("volume base exceeds backing length".to_owned())
        })?,
    };
    checkpoint(cx)?;
    VolumeDevice::new(
        Arc::new(device),
        ByteOffset(offset),
        length,
        VolumeAccess::ReadOnly,
    )
}

fn validate_selection(backend: &ReadOnlyBackend) -> Result<()> {
    let ReadOnlyBackend::Zfs(options) = backend else {
        return Ok(());
    };
    if matches!(
        options.root,
        ZfsRootSelection::Pool(0) | ZfsRootSelection::Candidate { pool_guid: 0, .. }
    ) {
        return Err(FfsError::UnsupportedFeature(
            "explicit ZFS pool GUID must be nonzero".to_owned(),
        ));
    }
    let supplied = options
        .additional_images
        .len()
        .checked_add(1)
        .ok_or_else(|| FfsError::UnsupportedFeature("too many ZFS member images".to_owned()))?;
    match &options.missing {
        ZfsMissingMembers::None => {
            if supplied > 8 {
                return Err(FfsError::UnsupportedFeature(
                    "ZFS read profiles admit at most eight supplied members".to_owned(),
                ));
            }
        }
        ZfsMissingMembers::Mirror(missing) => {
            ffs_zfs::reader::Pool::check_mirror_survivors(supplied, missing)?;
        }
        ZfsMissingMembers::Raidz(missing) => {
            ffs_zfs::reader::Pool::check_raidz_survivors(supplied, missing)?;
        }
    }
    if !matches!(options.missing, ZfsMissingMembers::None)
        && (!matches!(options.root, ZfsRootSelection::Candidate { .. }) || options.replay_zil)
    {
        return Err(FfsError::UnsupportedFeature(
            "missing ZFS members require an exact exported-pool candidate without ZIL replay"
                .to_owned(),
        ));
    }
    if options.replay_zil && options.snapshot.is_some() {
        return Err(FfsError::UnsupportedFeature(
            "ZIL replay cannot be combined with a snapshot view".to_owned(),
        ));
    }
    Ok(())
}

fn selection_matches(backend: &ReadOnlyBackend, format: FsFormatKind) -> bool {
    match backend {
        ReadOnlyBackend::Auto => true,
        ReadOnlyBackend::Ext4 { .. } => format == FsFormatKind::Ext4,
        ReadOnlyBackend::Btrfs { .. } => format == FsFormatKind::Btrfs,
        ReadOnlyBackend::Fat { .. } => {
            matches!(format, FsFormatKind::Fat16 | FsFormatKind::Fat32)
        }
        ReadOnlyBackend::Ntfs { .. } => format == FsFormatKind::Ntfs,
        ReadOnlyBackend::Zfs(_) => format == FsFormatKind::Zfs,
    }
}

/// Open any admitted native format through OS read-only, byte-bounded handles.
///
/// The image must remain offline and immutable. Advisory locking is not a
/// substitute for that precondition. ext4 recovery is confined to a volatile
/// overlay; NTFS recovery requires explicit selection and a completed native
/// recovery admission before exposing its volatile view. ZFS automatic
/// selection, explicit extraction and replay retain their native refusal rules.
/// No runtime or process-wide signal handler is created.
///
/// ```no_run
/// # fn example(cx: &asupersync::Cx) -> ffs_error::Result<()> {
/// use ffs::{InodeNumber, RequestScope, ReadOnlyOpenOptions, open_read_only};
/// let image = open_read_only(cx, "disk.img", &ReadOnlyOpenOptions::default())?;
/// let root = image.filesystem.getattr(cx, &mut RequestScope::empty(), InodeNumber(1))?;
/// println!("{} root: {:?}", image.format, root.kind);
/// # Ok(()) }
/// ```
pub fn open_read_only(
    cx: &Cx,
    path: impl AsRef<Path>,
    options: &ReadOnlyOpenOptions,
) -> Result<ReadOnlyFs> {
    checkpoint(cx)?;
    validate_selection(&options.backend)?;
    let (device, resolved_partition) = if let Some(selector) = &options.partition {
        if options.offset != 0 || options.length.is_some() {
            return Err(FfsError::InvalidGeometry(
                "partition selector cannot be combined with manual byte offset/length".to_owned(),
            ));
        }
        let parse_opts = PartitionParseOptions {
            allow_backup_gpt_fallback: options.allow_backup_gpt,
            ..PartitionParseOptions::default()
        };
        let (_table, part_dev) = open_partition_read_only(cx, path.as_ref(), selector, &parse_opts)?;
        let entry = part_dev.entry().clone();
        let vol = VolumeDevice::new(
            Arc::new(part_dev),
            ByteOffset(0),
            entry.byte_len,
            VolumeAccess::ReadOnly,
        )?;
        (vol, Some(entry))
    } else {
        (
            open_image(cx, path.as_ref(), options.offset, options.length)?,
            None,
        )
    };
    let effective_offset = resolved_partition
        .as_ref()
        .map_or(options.offset, |entry| entry.start_byte);
    let partition_id = resolved_partition
        .as_ref()
        .map_or_else(|| "none".to_owned(), PartitionEntry::canonical_id);
    let detected = detect_all_filesystems_on_device(cx, &device).map_err(|error| match error {
        DetectionError::Io(error) => error,
        other => FfsError::Format(other.to_string()),
    })?;
    let format = detected.kind();
    if !selection_matches(&options.backend, format) {
        return Err(FfsError::Format(format!(
            "read selection does not match detected {format} filesystem"
        )));
    }
    tracing::info!(
        target: "ffs::native",
        operation = "open_read_only",
        %format,
        partition_id = %partition_id,
        offset = effective_offset,
        length = device.len_bytes(),
        "opening bounded native read-only view"
    );
    let mut ntfs = None;
    let filesystem: Box<dyn FsOps> = match detected {
        DetectedFilesystem::Ext4(_) | DetectedFilesystem::Btrfs(_) => {
            let mut core_options = OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
                ..OpenOptions::default()
            };
            let mut external_journal: Option<Arc<dyn ByteDevice>> = None;
            let mut btrfs_additional: Vec<Arc<dyn ByteDevice>> = Vec::new();
            match &options.backend {
                ReadOnlyBackend::Ext4 {
                    external_journal: Some(source),
                } => {
                    external_journal = Some(Arc::new(open_image(
                        cx,
                        &source.path,
                        source.offset,
                        source.length,
                    )?));
                }
                ReadOnlyBackend::Btrfs {
                    root,
                    additional_devices,
                } => {
                    core_options.btrfs_mount_selection.clone_from(root);
                    for source in additional_devices {
                        btrfs_additional.push(Arc::new(open_image(
                            cx,
                            &source.path,
                            source.offset,
                            source.length,
                        )?));
                    }
                }
                _ => {}
            }
            Box::new(OpenFs::from_devices(
                cx,
                Box::new(device),
                &core_options,
                VolumeAccess::ReadOnly,
                external_journal,
                btrfs_additional,
            )?)
        }
        DetectedFilesystem::Fat16(_) | DetectedFilesystem::Fat32(_) => {
            let length = device.len_bytes();
            let mut volume =
                ffs_fat::reader::FatVolume::from_device(cx, Box::new(device), 0, length)?;
            if let ReadOnlyBackend::Fat { oem_code_page } = &options.backend {
                volume = volume.with_oem_code_page(*oem_code_page);
            }
            Box::new(ffs_fat::filesystem::FatFs::new(
                cx,
                volume,
                options.uid,
                options.gid,
            )?)
        }
        DetectedFilesystem::Ntfs(_) => {
            let length = device.len_bytes();
            let (indexed_lookup, recover_logfile) = match &options.backend {
                ReadOnlyBackend::Ntfs {
                    indexed_lookup,
                    recover_logfile,
                } => (*indexed_lookup, *recover_logfile),
                _ => (false, false),
            };
            let volume = ffs_ntfs::NtfsVolume::from_device_with_options(
                cx,
                Box::new(device),
                0,
                length,
                recover_logfile,
            )?;
            let filesystem = match (indexed_lookup, recover_logfile) {
                (false, false) => ffs_ntfs::NtfsFs::new(cx, volume, options.uid, options.gid)?,
                (true, false) => {
                    ffs_ntfs::NtfsFs::new_indexed(cx, volume, options.uid, options.gid)?
                }
                (false, true) => {
                    ffs_ntfs::NtfsFs::new_recovered(cx, volume, options.uid, options.gid)?
                }
                (true, true) => {
                    ffs_ntfs::NtfsFs::new_recovered_indexed(cx, volume, options.uid, options.gid)?
                }
            };
            let filesystem = Arc::new(filesystem);
            ntfs = Some(Arc::clone(&filesystem));
            Box::new(filesystem)
        }
        DetectedFilesystem::Zfs(_) => {
            let defaults = ZfsReadOptions::default();
            let selection = match &options.backend {
                ReadOnlyBackend::Zfs(selection) => selection,
                _ => &defaults,
            };
            let length = device.len_bytes();
            let mut leaves = Vec::with_capacity(selection.additional_images.len() + 1);
            leaves.push(ffs_zfs::reader::Leaf::from_device(
                cx,
                Box::new(device),
                0,
                length,
            )?);
            for source in &selection.additional_images {
                let member = open_image(cx, &source.path, source.offset, source.length)?;
                let length = member.len_bytes();
                leaves.push(ffs_zfs::reader::Leaf::from_device(
                    cx,
                    Box::new(member),
                    0,
                    length,
                )?);
            }
            let pool = match &selection.missing {
                ZfsMissingMembers::None => ffs_zfs::reader::Pool::from_leaves(leaves)?,
                ZfsMissingMembers::Mirror(guids) => {
                    ffs_zfs::reader::Pool::from_mirror_survivors(cx, leaves, guids.clone())?
                }
                ZfsMissingMembers::Raidz(guids) => {
                    ffs_zfs::reader::Pool::from_raidz_survivors(cx, leaves, guids.clone())?
                }
            };
            let mut objects = match selection.root {
                ZfsRootSelection::Auto => pool.import_objects(cx, None)?,
                ZfsRootSelection::Pool(guid) => pool.import_objects(cx, Some(guid))?,
                ZfsRootSelection::Candidate {
                    pool_guid,
                    label,
                    slot,
                } => pool.objects(cx, label, slot, pool_guid)?,
            };
            let mut view = match &selection.snapshot {
                Some(snapshot) => objects.zpl_snapshot(cx, &selection.dataset, snapshot)?,
                None => objects.zpl(cx, &selection.dataset)?,
            };
            if selection.replay_zil {
                view.replay_zil(cx)?;
            }
            Box::new(ffs_zfs::filesystem::ZfsFs::new(
                cx,
                view,
                options.uid,
                options.gid,
            )?)
        }
    };
    checkpoint(cx)?;
    Ok(ReadOnlyFs {
        format,
        partition: resolved_partition,
        filesystem,
        ntfs,
    })
}

#[cfg(test)]
mod tests;
