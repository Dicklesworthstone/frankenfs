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
use ffs_types::ByteOffset;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// An explicitly selected volume inside an additional backing image.
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
        external_journal: Option<PathBuf>,
    },
    Btrfs {
        root: BtrfsMountSelection,
        additional_devices: Vec<PathBuf>,
    },
    Fat {
        oem_code_page: FatOemCodePage,
    },
    /// Strict enumeration is the default. Indexed lookup validates only the
    /// selected native search range; directory enumeration remains complete.
    Ntfs {
        indexed_lookup: bool,
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
    /// Synthetic ownership for FAT/NTFS/ZFS, as in their existing mount adapters.
    pub uid: u32,
    pub gid: u32,
    pub backend: ReadOnlyBackend,
}

/// An admitted native reader, ready for direct VFS use or a read-only FUSE mount.
/// The trait object exposes no format-specific write-enablement operation.
pub struct ReadOnlyFs {
    pub format: FsFormatKind,
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
/// overlay; NTFS retains its existing clean-log FsOps admission. ZFS automatic
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
    let device = open_image(cx, path.as_ref(), options.offset, options.length)?;
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
        offset = options.offset,
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
            match &options.backend {
                ReadOnlyBackend::Ext4 { external_journal } => {
                    core_options
                        .external_journal_path
                        .clone_from(external_journal);
                }
                ReadOnlyBackend::Btrfs {
                    root,
                    additional_devices,
                } => {
                    core_options.btrfs_mount_selection.clone_from(root);
                    core_options
                        .btrfs_device_paths
                        .clone_from(additional_devices);
                }
                _ => {}
            }
            Box::new(OpenFs::from_device(cx, Box::new(device), &core_options)?)
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
            let volume = ffs_ntfs::NtfsVolume::from_device(cx, Box::new(device), 0, length)?;
            let filesystem = if matches!(
                &options.backend,
                ReadOnlyBackend::Ntfs {
                    indexed_lookup: true
                }
            ) {
                ffs_ntfs::NtfsFs::new_indexed(cx, volume, options.uid, options.gid)?
            } else {
                ffs_ntfs::NtfsFs::new(cx, volume, options.uid, options.gid)?
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
        filesystem,
        ntfs,
    })
}

#[cfg(test)]
mod tests;
