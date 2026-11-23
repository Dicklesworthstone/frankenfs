//! Explicit, bounded native writer admission using the existing format engines.

use super::{
    BtrfsMountSelection, ByteDevice, ByteOffset, Cx, DetectedFilesystem, DetectionError,
    FatOemCodePage, FfsError, FileByteDevice, FsFormatKind, FsOps, ImageSource, OpenFs,
    OpenOptions, PartitionEntry, PartitionParseOptions, PartitionSelector, Path, RequestScope,
    Result, VolumeAccess, VolumeDevice, checkpoint, detect_all_filesystems_on_device,
    select_partition_device,
};
use std::sync::Arc;

/// Select a native writable profile. Unknown native features remain subject to
/// the selected engine's complete writer admission checks.
#[derive(Debug, Clone, Default)]
pub enum ReadWriteBackend {
    /// Detect ext4, btrfs, FAT16/FAT32 or clean NTFS. ZFS additionally requires
    /// an explicit pool identity and current root candidate.
    #[default]
    Auto,
    /// Existing ext4 writer with its internal journal, when present.
    /// External-journal mutation is not admitted by this facade.
    Ext4,
    /// The core writer admits only a writable root on one Single/DUP device.
    Btrfs {
        root: BtrfsMountSelection,
    },
    Fat {
        oem_code_page: FatOemCodePage,
    },
    Ntfs {
        /// Authorize persistent native log recovery before writable admission.
        recover_dirty: bool,
        /// Explicit SID/ACL policy. None retains synthetic uid/gid presentation
        /// without native ACL enforcement, as in the companion adapter.
        security_policy: Option<ffs_ntfs::security_policy::NtfsSidPolicy>,
    },
    Zfs(ZfsWriteSelection),
}

/// Explicit current-root and complete-storage selection for a native ZFS writer.
/// Snapshots, missing-member extraction and torn-root reconciliation are not
/// writable mount selections. The native engine checks all labels and members.
#[derive(Debug, Clone, Default)]
pub struct ZfsWriteSelection {
    pub pool_guid: u64,
    pub label: usize,
    pub slot: usize,
    pub dataset: Vec<Vec<u8>>,
    /// Additional complete-mirror members, each with independent byte bounds.
    /// Only the path-based entry point opens these paths.
    pub additional_images: Vec<ImageSource>,
    pub mount_options: ffs_zfs::ZfsMountWriteOptions,
}

/// Options for explicitly authorized native mutation of offline images.
///
/// Both authorization flags default to false and are checked before opening
/// any path or reading a supplied device. Advisory locks supplement, rather
/// than establish, the caller's exclusive offline ownership. Selecting a
/// partition cannot be combined with manual primary-volume bounds.
#[derive(Debug, Clone, Default)]
pub struct ReadWriteOpenOptions {
    pub offline_image: bool,
    pub allow_write: bool,
    pub offset: u64,
    pub length: Option<u64>,
    pub partition: Option<PartitionSelector>,
    pub allow_backup_gpt: bool,
    /// Synthetic FAT/NTFS ownership; ZFS retains native owners and permissions.
    pub uid: u32,
    pub gid: u32,
    pub backend: ReadWriteBackend,
}

/// An admitted native writer exposing the common filesystem operations.
/// The engines retain the admitted devices and file locks even when filesystem
/// is moved into a FUSE owner. Dropping this value is not a durability boundary:
/// call sync or the relevant filesystem fsync operation.
pub struct ReadWriteFs {
    pub format: FsFormatKind,
    pub partition: Option<PartitionEntry>,
    pub filesystem: Box<dyn FsOps>,
}

impl ReadWriteFs {
    /// Reach the selected engine's filesystem-wide native durability boundary.
    /// This flushes staged ext4/btrfs state as well as backing storage; merely
    /// syncing the raw image descriptor would not provide that guarantee.
    pub fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        self.filesystem.sync_fs(cx, &mut RequestScope::empty())
    }
}

impl std::fmt::Debug for ReadWriteFs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadWriteFs")
            .field("format", &self.format)
            .field("partition", &self.partition)
            .finish_non_exhaustive()
    }
}

fn validate_options(cx: &Cx, options: &ReadWriteOpenOptions) -> Result<()> {
    checkpoint(cx)?;
    if !options.offline_image || !options.allow_write {
        return Err(FfsError::PermissionDenied);
    }
    if options.partition.is_some() && (options.offset != 0 || options.length.is_some()) {
        return Err(FfsError::InvalidGeometry(
            "partition selector cannot be combined with manual byte offset/length".into(),
        ));
    }
    if let ReadWriteBackend::Zfs(selection) = &options.backend {
        if selection.pool_guid == 0 || selection.label >= 4 {
            return Err(FfsError::Format(
                "ZFS writer requires a nonzero pool GUID and label in 0..4".into(),
            ));
        }
        if selection.additional_images.len() > 7 {
            return Err(FfsError::UnsupportedFeature(
                "ZFS native writer admits at most eight complete mirror members".into(),
            ));
        }
        if selection.dataset.iter().any(|part| {
            part.is_empty()
                || part == b"."
                || part == b".."
                || part.contains(&b'/')
                || part.contains(&0)
        }) {
            return Err(FfsError::Format("invalid ZFS dataset component".into()));
        }
    }
    Ok(())
}

fn bounded_device(
    inner: Arc<dyn ByteDevice>,
    offset: u64,
    length: Option<u64>,
) -> Result<VolumeDevice> {
    let length = match length {
        Some(length) => length,
        None => inner.len_bytes().checked_sub(offset).ok_or_else(|| {
            FfsError::InvalidGeometry("volume base exceeds backing length".into())
        })?,
    };
    VolumeDevice::new(inner, ByteOffset(offset), length, VolumeAccess::ReadWrite)
}

fn primary_volume(
    cx: &Cx,
    inner: Arc<dyn ByteDevice>,
    options: &ReadWriteOpenOptions,
) -> Result<(VolumeDevice, Option<PartitionEntry>)> {
    if let Some(selector) = &options.partition {
        let (_, partition) = select_partition_device(
            cx,
            inner,
            selector,
            &PartitionParseOptions {
                allow_backup_gpt_fallback: options.allow_backup_gpt,
                ..PartitionParseOptions::default()
            },
            VolumeAccess::ReadWrite,
        )?;
        let entry = partition.entry().clone();
        let volume = bounded_device(Arc::new(partition), 0, Some(entry.byte_len))?;
        Ok((volume, Some(entry)))
    } else {
        Ok((bounded_device(inner, options.offset, options.length)?, None))
    }
}

fn detect_writer(
    cx: &Cx,
    device: &dyn ByteDevice,
    backend: &ReadWriteBackend,
) -> Result<FsFormatKind> {
    let detected = detect_all_filesystems_on_device(cx, device).map_err(|error| match error {
        DetectionError::Io(error) => error,
        other => FfsError::Format(other.to_string()),
    })?;
    let format = detected.kind();
    let matches = match backend {
        ReadWriteBackend::Auto => true,
        ReadWriteBackend::Ext4 => format == FsFormatKind::Ext4,
        ReadWriteBackend::Btrfs { .. } => format == FsFormatKind::Btrfs,
        ReadWriteBackend::Fat { .. } => matches!(format, FsFormatKind::Fat16 | FsFormatKind::Fat32),
        ReadWriteBackend::Ntfs { .. } => format == FsFormatKind::Ntfs,
        ReadWriteBackend::Zfs(_) => format == FsFormatKind::Zfs,
    };
    if !matches {
        return Err(FfsError::Format(format!(
            "write selection does not match detected {format} filesystem"
        )));
    }
    if format == FsFormatKind::Zfs && !matches!(backend, ReadWriteBackend::Zfs(_)) {
        return Err(FfsError::UnsupportedFeature(
            "ZFS writes require an explicit pool GUID, label and current root slot".into(),
        ));
    }
    if let DetectedFilesystem::Ext4(superblock) = &detected {
        // Refuse unsupported write semantics before the core can replay a
        // journal or clean up orphans during read-write admission.
        OpenFs::validate_ext4_write_features(superblock)?;
    }
    Ok(format)
}

/// Open a native writer with exclusive, regular-file descriptors and checked
/// byte bounds. It never creates an image or falls back to read-only access.
///
/// Recovery and orphan cleanup may mutate storage during admission: ext4/btrfs
/// follow their existing native recovery policy, NTFS log recovery additionally
/// requires recover_dirty, and ZFS retains clean exported-pool admission.
/// All ZFS members are locked and bounded before the engine can write any of them.
/// No runtime, mount worker, external WAL or repair sidecar is created.
pub fn open_read_write(
    cx: &Cx,
    path: impl AsRef<Path>,
    options: &ReadWriteOpenOptions,
) -> Result<ReadWriteFs> {
    validate_options(cx, options)?;
    let primary = Arc::new(FileByteDevice::open_regular_read_write(path)?);
    let (device, partition) = primary_volume(cx, primary, options)?;
    let detected = detect_writer(cx, &device, &options.backend)?;
    let mut additional = Vec::new();
    if let ReadWriteBackend::Zfs(selection) = &options.backend {
        for source in &selection.additional_images {
            checkpoint(cx)?;
            let member = Arc::new(FileByteDevice::open_regular_read_write(&source.path)?);
            additional.push(
                Box::new(bounded_device(member, source.offset, source.length)?)
                    as Box<dyn ByteDevice>,
            );
        }
    }
    open_admitted_writer(cx, device, partition, additional, detected, options)
}

/// Open a caller-owned device through the same native writer admission and
/// bounds. The caller supplies exclusive offline ownership and writable device
/// authority; this function cannot upgrade an underlying read-only capability.
/// Auxiliary path selections are refused before any device I/O.
pub fn open_read_write_device(
    cx: &Cx,
    device: Arc<dyn ByteDevice>,
    options: &ReadWriteOpenOptions,
) -> Result<ReadWriteFs> {
    open_read_write_devices(cx, device, Vec::new(), options)
}

/// Open a writer with already-bounded additional ZFS mirror members.
/// Every member must belong to the complete native pool storage set.
/// Primary-volume offset/length or partition selection applies only to the
/// primary device; additional devices are the caller's selected volume views.
pub fn open_read_write_devices(
    cx: &Cx,
    primary: Arc<dyn ByteDevice>,
    additional: Vec<Arc<dyn ByteDevice>>,
    options: &ReadWriteOpenOptions,
) -> Result<ReadWriteFs> {
    validate_options(cx, options)?;
    match &options.backend {
        ReadWriteBackend::Zfs(selection) => {
            if !selection.additional_images.is_empty() {
                return Err(FfsError::UnsupportedFeature(
                    "device-based writable admission does not open additional image paths".into(),
                ));
            }
            if additional.len() > 7 {
                return Err(FfsError::UnsupportedFeature(
                    "too many ZFS member devices".into(),
                ));
            }
        }
        _ if !additional.is_empty() => {
            return Err(FfsError::UnsupportedFeature(
                "additional writable devices require an explicit ZFS complete-mirror selection"
                    .into(),
            ));
        }
        _ => {}
    }
    let (device, partition) = primary_volume(cx, primary, options)?;
    let detected = detect_writer(cx, &device, &options.backend)?;
    let additional = additional
        .into_iter()
        .map(|member| {
            bounded_device(member, 0, None).map(|view| Box::new(view) as Box<dyn ByteDevice>)
        })
        .collect::<Result<Vec<_>>>()?;
    open_admitted_writer(cx, device, partition, additional, detected, options)
}

fn open_admitted_writer(
    cx: &Cx,
    device: VolumeDevice,
    partition: Option<PartitionEntry>,
    mut additional: Vec<Box<dyn ByteDevice>>,
    format: FsFormatKind,
    options: &ReadWriteOpenOptions,
) -> Result<ReadWriteFs> {
    checkpoint(cx)?;
    let filesystem: Box<dyn FsOps> = match format {
        FsFormatKind::Ext4 | FsFormatKind::Btrfs => {
            let mut core_options = OpenOptions::default();
            if let ReadWriteBackend::Btrfs { root } = &options.backend {
                core_options.btrfs_mount_selection.clone_from(root);
            }
            let mut fs = OpenFs::from_devices(
                cx,
                Box::new(device),
                &core_options,
                VolumeAccess::ReadWrite,
                None,
                Vec::new(),
            )?;
            fs.attach_ext4_internal_jbd2_writer(cx)?;
            if fs
                .ext4_superblock()
                .is_some_and(|sb| sb.has_compat(ffs_ondisk::Ext4CompatFeatures::HAS_JOURNAL))
                && !fs.has_jbd2_writer()
            {
                return Err(FfsError::UnsupportedFeature(
                    "writable ext4 facade requires the filesystem's native internal journal writer"
                        .into(),
                ));
            }
            fs.enable_writes(cx)?;
            Box::new(fs)
        }
        FsFormatKind::Fat16 | FsFormatKind::Fat32 => {
            let length = device.len_bytes();
            let mut volume = ffs_fat::FatVolume::from_device(cx, Box::new(device), 0, length)?;
            if let ReadWriteBackend::Fat { oem_code_page } = &options.backend {
                volume = volume.with_oem_code_page(*oem_code_page);
            }
            let check = volume.check(cx)?;
            if !check.clean || !check.complete || !check.namespace_complete {
                return Err(FfsError::UnsupportedFeature(
                    "FAT writable admission requires a complete clean allocation/namespace check"
                        .into(),
                ));
            }
            Box::new(ffs_fat::FatFs::new_with_mode(
                cx,
                volume,
                options.uid,
                options.gid,
                true,
            )?)
        }
        FsFormatKind::Ntfs => {
            let length = device.len_bytes();
            let (recover_dirty, policy) = match &options.backend {
                ReadWriteBackend::Ntfs {
                    recover_dirty,
                    security_policy,
                } => (*recover_dirty, security_policy.clone()),
                _ => (false, None),
            };
            let engine = ffs_ntfs::NtfsTransactionEngine::from_device(
                cx,
                Arc::new(device),
                0,
                length,
                ffs_ntfs::NtfsWriteOptions {
                    offline_image: options.offline_image,
                    allow_write: options.allow_write,
                    recover_dirty,
                },
            )?;
            let policy = policy.unwrap_or(ffs_ntfs::security_policy::NtfsSidPolicy::Synthetic {
                uid: options.uid,
                gid: options.gid,
            });
            Box::new(ffs_ntfs::NtfsFs::from_engine_with_policy(
                cx, engine, policy,
            )?)
        }
        FsFormatKind::Zfs => {
            let ReadWriteBackend::Zfs(selection) = &options.backend else {
                return Err(FfsError::UnsupportedFeature(
                    "missing explicit ZFS write selection".into(),
                ));
            };
            let mut devices: Vec<Box<dyn ByteDevice>> = Vec::with_capacity(additional.len() + 1);
            devices.push(Box::new(device));
            devices.append(&mut additional);
            let engine = ffs_zfs::ZfsTransactionEngine::from_devices(
                cx,
                devices,
                ffs_zfs::ZfsWriteOptions {
                    offline_image: options.offline_image,
                    allow_write: options.allow_write,
                    pool_guid: selection.pool_guid,
                    label: selection.label,
                    slot: selection.slot,
                    reconcile_torn_uberblocks: false,
                },
            )?;
            Box::new(ffs_zfs::ZfsFs::with_writer_options(
                cx,
                engine,
                selection.dataset.clone(),
                selection.mount_options,
            )?)
        }
    };
    Ok(ReadWriteFs {
        format,
        partition,
        filesystem,
    })
}

#[cfg(test)]
mod tests;
