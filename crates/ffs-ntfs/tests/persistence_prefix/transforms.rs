//! Comprehensive integration, negative-control, and persistence-prefix fault-cut
//! tests for native NTFS transforms (sparse/hole-punch, LZNT1 compression, WOF
//! decompression-on-write), `$Secure` multi-stripe/inheritance/DACL/SACL + NTFS 3.0
//! `0x50` security, reparse points & `$Extend/$Reparse::$R`, `$OBJECT_ID` &
//! `$Extend/$ObjId::$O`, active `$Extend/$UsnJrnl`, `$EA`, and explicit key-scoped
//! EFS encryption/decryption (`bd-h8n46`).

use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_core::vfs::XattrSetMode;
use ffs_core::{FileType, FsOps, RequestScope, SeekWhence, SetAttrRequest};
use ffs_error::{FfsError, Result};
use ffs_ntfs::NtfsVolume;
use ffs_ntfs::efs::{NtfsEfsKey, StaticEfsKeyScope};
use ffs_ntfs::formatter::{NtfsFormatOptions, NtfsFormatVersion, format_image_file};
use ffs_ntfs::reader::check::{NtfsCheckLimits, check_volume_device};
use ffs_ntfs::reader::filesystem::NtfsFs;
use ffs_ntfs::reader::security::SecurityCheckLimits;
use ffs_ntfs::security_policy::{NtfsSecurityPatch, NtfsSidMap, NtfsSidPolicy, build_simple_ace};
use ffs_ntfs::transaction::{
    DEFAULT_NTFS_FILETIME, NtfsObjectIdData, NtfsPersistenceStage, NtfsTransactionEngine,
    NtfsTxOutcome,
};
use ffs_ondisk::ntfs::NtfsReference;
use ffs_ondisk::ntfs::reparse::{MOUNT_POINT_TAG, NtfsReparseData, NtfsReparsePoint};
use ffs_ondisk::ntfs::usn::{
    USN_PAGE_BYTES, UsnRecordV2, align_usn_offset, parse_usn_journal_slice,
};
use ffs_ondisk::ntfs_security::{
    ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_INHERIT_ONLY, ACE_FLAG_INHERITED, ACE_FLAG_OBJECT_INHERIT,
    ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_DENIED, ACE_TYPE_SYSTEM_AUDIT, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_DELETE_CHILD, FILE_READ_DATA, FILE_READ_EA,
    FILE_WRITE_DATA, FILE_WRITE_EA, NtfsAccessToken, NtfsAcl, NtfsSecurityDescriptor, NtfsSid,
    SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE, STANDARD_DELETE,
};
use ffs_types::{ByteOffset, InodeNumber};

use super::{FaultInjectingNtfsDevice, SECTOR_BYTES, write_options_clean, write_options_recover};

fn format_to_fault_device(
    cx: &Cx,
    size_mib: u64,
    cluster_bytes: u32,
    version: NtfsFormatVersion,
    serial: u64,
) -> (Arc<FaultInjectingNtfsDevice>, u64) {
    let dir = tempfile::tempdir().unwrap();
    let img_path = dir.path().join("ntfs.img");
    let mut opts = NtfsFormatOptions::new_image(img_path.clone(), size_mib);
    opts.cluster_bytes = Some(cluster_bytes);
    opts.version = version;
    opts.serial = Some(serial);
    opts.logfile_bytes = Some(256 * 1024);
    let rep = format_image_file(cx, &opts, None).unwrap();
    assert!(rep.boot_published && rep.check_clean);
    let raw = std::fs::read(&img_path).unwrap();
    let vol_bytes = raw.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(raw);
    (dev, vol_bytes)
}

fn open_clean_engine(
    cx: &Cx,
    dev: &Arc<FaultInjectingNtfsDevice>,
    vol_bytes: u64,
) -> NtfsTransactionEngine {
    NtfsTransactionEngine::from_device(
        cx,
        Arc::clone(dev) as Arc<dyn ByteDevice>,
        0,
        vol_bytes,
        write_options_clean(),
    )
    .unwrap()
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

struct SecurityReadFault {
    inner: Arc<FaultInjectingNtfsDevice>,
    descriptor: Vec<u8>,
    fault: Mutex<Option<FfsError>>,
}

impl ByteDevice for SecurityReadFault {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        self.inner.read_exact_at(cx, offset, buf)?;
        if buf
            .windows(self.descriptor.len())
            .any(|bytes| bytes == self.descriptor.as_slice())
            && let Some(error) = self.fault.lock().unwrap().take()
        {
            return Err(error);
        }
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        self.inner.write_all_at(cx, offset, buf)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)
    }
}

fn stream_acl_policy(caller_uid: u32) -> NtfsSidPolicy {
    NtfsSidPolicy::Mapped {
        caller_uid,
        caller_gid: 2000,
        map: NtfsSidMap {
            enforce_acl: true,
            posix_nfs_sids: true,
            ..NtfsSidMap::default()
        },
    }
}

fn stream_acl_descriptor(denied: u32) -> Vec<u8> {
    NtfsSecurityDescriptor {
        resource_manager_control: 0,
        control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
        owner: Some(NtfsSid {
            authority: 5,
            subauthorities: vec![88, 1, 1001],
        }),
        group: Some(NtfsSid {
            authority: 5,
            subauthorities: vec![88, 2, 2000],
        }),
        sacl: NtfsAcl {
            present: false,
            offset: 0,
            revision: None,
            ace_count: None,
            size: None,
            aces: Vec::new(),
            padding: Vec::new(),
        },
        dacl: NtfsAcl {
            present: true,
            offset: 0,
            revision: Some(2),
            ace_count: Some(2),
            size: None,
            aces: vec![
                build_simple_ace(
                    ACE_TYPE_ACCESS_DENIED,
                    0,
                    denied,
                    NtfsSid {
                        authority: 5,
                        subauthorities: vec![88, 1, 1002],
                    },
                ),
                build_simple_ace(
                    ACE_TYPE_ACCESS_ALLOWED,
                    0,
                    FILE_ALL_ACCESS,
                    NtfsSid::world_everyone(),
                ),
            ],
            padding: Vec::new(),
        },
    }
    .encode()
    .unwrap()
}

#[test]
fn ntfs_mapped_chmod_preserves_denies_and_refuses_partial_compound_updates() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xAC15_0002_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let (file, _) = engine
        .create_file_at(&cx, root, &utf16("native-acl.bin"), b"payload")
        .into_result()
        .unwrap();
    engine
        .link_at(&cx, file, root, &utf16("alias.bin"))
        .into_result()
        .unwrap();
    let descriptor = stream_acl_descriptor(FILE_WRITE_DATA);
    engine
        .set_security_at(&cx, file, &descriptor, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    let (restricted, _) = engine
        .create_file_at(&cx, root, &utf16("owner-denied.bin"), b"retained")
        .into_result()
        .unwrap();
    let mut owner_denied =
        NtfsSecurityDescriptor::parse(&stream_acl_descriptor(FILE_READ_DATA)).unwrap();
    owner_denied.dacl.aces[0]
        .sid
        .clone_from(&owner_denied.owner);
    engine
        .set_security_at(
            &cx,
            restricted,
            &owner_denied.encode().unwrap(),
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1001)).unwrap();
    let mut scope = RequestScope::empty();
    let target = fs
        .lookup(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("native-acl.bin"),
        )
        .unwrap();
    let changed = fs
        .setattr(
            &cx,
            &mut scope,
            target.ino,
            &SetAttrRequest {
                mode: Some(0o666),
                ..SetAttrRequest::default()
            },
        )
        .unwrap();
    assert_eq!(changed.perm, 0o666);
    let before_ads = dev.snapshot_durable_only();
    let writes = dev.write_bytes_total();
    assert!(matches!(
        fs.create_open(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("native-acl.bin:private"),
            0o600,
            1001,
            2000,
            libc::O_RDWR,
        ),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(dev.write_bytes_total(), writes);
    assert_eq!(dev.snapshot_live(), before_ads);
    assert_eq!(dev.snapshot_durable_only(), before_ads);
    let restricted = fs
        .lookup(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("owner-denied.bin"),
        )
        .unwrap();
    let before = dev.snapshot_durable_only();
    let writes = dev.write_bytes_total();
    assert!(matches!(
        fs.setattr(
            &cx,
            &mut scope,
            restricted.ino,
            &SetAttrRequest {
                mode: Some(0o777),
                size: Some(3),
                ..SetAttrRequest::default()
            }
        ),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(dev.write_bytes_total(), writes);
    assert_eq!(dev.snapshot_live(), before);
    assert_eq!(dev.snapshot_durable_only(), before);
    assert_eq!(fs.getattr(&cx, &mut scope, restricted.ino).unwrap().size, 8);
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    let engine = open_clean_engine(&cx, &dev, vol_bytes);
    engine.check_clean_consistency(&cx).unwrap();
    let volume = engine.volume_view(&cx).unwrap();
    let file = volume.resolve(&cx, "/native-acl.bin").unwrap();
    let alias = volume.resolve(&cx, "/alias.bin").unwrap();
    let security = volume.security_descriptor(&cx, &file).unwrap();
    assert_eq!(
        security.descriptor.dacl.aces[0].encode().unwrap(),
        NtfsSecurityDescriptor::parse(&descriptor)
            .unwrap()
            .dacl
            .aces[0]
            .encode()
            .unwrap()
    );
    assert_eq!(
        volume.security_descriptor(&cx, &alias).unwrap().security_id,
        security.security_id
    );
    drop(volume);
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
    let attr = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("alias.bin"))
        .unwrap();
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, 0, 64).unwrap(),
        b"payload"
    );
    let writes = dev.write_bytes_total();
    assert!(matches!(
        fs.write(&cx, &mut scope, attr.ino, 0, b"bad"),
        Err(FfsError::PermissionDenied)
    ));
    assert_eq!(dev.write_bytes_total(), writes);
}

fn mapped_create_fixture(
    cx: &Cx,
    version: NtfsFormatVersion,
    denied: u32,
    deny_owner: bool,
) -> (Arc<FaultInjectingNtfsDevice>, u64, NtfsTransactionEngine) {
    let (dev, length) = format_to_fault_device(cx, 16, 4096, version, 0xAC15_0003_0000_0001);
    let mut engine = open_clean_engine(cx, &dev, length);
    let root = engine.resolve_path_reference(cx, "/").unwrap();
    let mut sd = NtfsSecurityDescriptor::parse(&stream_acl_descriptor(denied)).unwrap();
    if deny_owner {
        sd.dacl.aces[0].sid.clone_from(&sd.owner);
    }
    for ace in &mut sd.dacl.aces {
        ace.flags = ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT;
    }
    engine
        .set_security_at(cx, root, &sd.encode().unwrap(), DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    // Keep the fault experiment about child publication, not a separate MFT
    // capacity-growth transaction.
    engine.grow_mft(cx, 64).into_result().unwrap();
    (dev, length, engine)
}

#[test]
fn ntfs_mapped_create_refuses_unknown_sids_and_incompatible_inheritance_before_writes() {
    for unknown_mapping in [true, false] {
        let cx = Cx::for_testing();
        let (dev, _, engine) =
            mapped_create_fixture(&cx, NtfsFormatVersion::V3_1, FILE_READ_DATA, true);
        let policy = if unknown_mapping {
            NtfsSidPolicy::Mapped {
                caller_uid: 1001,
                caller_gid: 2000,
                map: NtfsSidMap {
                    enforce_acl: false,
                    posix_nfs_sids: false,
                    ..NtfsSidMap::default()
                },
            }
        } else {
            stream_acl_policy(1001)
        };
        let fs = NtfsFs::from_engine_with_policy(&cx, engine, policy).unwrap();
        let mut scope = RequestScope::empty();
        let before = dev.snapshot_durable_only();
        let writes = dev.write_bytes_total();
        assert!(matches!(
            fs.create(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("file"),
                0o600,
                1001,
                2000
            ),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            fs.create_open(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("opened"),
                0o600,
                1001,
                2000,
                libc::O_RDWR
            ),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            fs.mkdir(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("directory"),
                0o700,
                1001,
                2000
            ),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert_eq!(dev.write_bytes_total(), writes);
        assert_eq!(dev.snapshot_live(), before);
        assert_eq!(dev.snapshot_durable_only(), before);
        assert!(fs.last_durable_token().unwrap().is_none());
    }
}

#[test]
fn ntfs_mapped_creation_publishes_security_in_one_transaction_and_recovers_atomically() {
    for version in [NtfsFormatVersion::V3_0, NtfsFormatVersion::V3_1] {
        for directory in [false, true] {
            let cx = Cx::for_testing();
            let (dev, length, mut engine) =
                mapped_create_fixture(&cx, version, FILE_WRITE_DATA, false);
            let events = Arc::new(Mutex::new(Vec::new()));
            let event_log = Arc::clone(&events);
            let cuts = Arc::new(Mutex::new(
                Vec::<(NtfsPersistenceStage, bool, Vec<u8>)>::new(),
            ));
            let saved = Arc::clone(&cuts);
            let storage = Arc::clone(&dev);
            let mut committed = false;
            engine.set_stage_hook(Some(Box::new(move |event| {
                event_log
                    .lock()
                    .unwrap()
                    .push((event.stage, event.transaction_id));
                committed |= event.stage == NtfsPersistenceStage::LogCommitBarrier;
                let mut cuts = saved.lock().unwrap();
                if matches!(
                    event.stage,
                    NtfsPersistenceStage::DirtyRestartBarrier
                        | NtfsPersistenceStage::LogCommitBarrier
                        | NtfsPersistenceStage::TargetMetadataBarrier
                        | NtfsPersistenceStage::AckPublished
                ) && !cuts.iter().any(|(stage, _, _)| *stage == event.stage)
                {
                    cuts.push((event.stage, committed, storage.snapshot_durable_only()));
                }
                Ok(())
            })));
            let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1001)).unwrap();
            let mut scope = RequestScope::empty();
            let mode = if directory { 0o700 } else { 0o600 };
            let attr = if directory {
                fs.mkdir(
                    &cx,
                    &mut scope,
                    InodeNumber(1),
                    OsStr::new("private"),
                    mode,
                    1001,
                    2000,
                )
                .unwrap()
            } else {
                fs.create_open(
                    &cx,
                    &mut scope,
                    InodeNumber(1),
                    OsStr::new("private"),
                    mode,
                    1001,
                    2000,
                    libc::O_RDWR,
                )
                .unwrap()
                .0
            };
            assert_eq!((attr.uid, attr.gid, attr.perm), (1001, 2000, mode));
            let token = fs
                .last_durable_token()
                .unwrap()
                .expect("one completed native create");
            super::assert_one_compound_transaction(events.lock().unwrap().iter().copied(), &token);
            let cuts = std::mem::take(&mut *cuts.lock().unwrap());
            assert_eq!(cuts.len(), 4);
            assert!(cuts.iter().any(|(_, committed, _)| !committed));
            drop(fs);

            for (stage, committed, bytes) in cuts {
                let recovered_device = FaultInjectingNtfsDevice::new(bytes);
                let recovered = NtfsTransactionEngine::from_device(
                    &cx,
                    Arc::clone(&recovered_device) as Arc<dyn ByteDevice>,
                    0,
                    length,
                    write_options_recover(),
                )
                .unwrap_or_else(|error| panic!("recover mapped create at {stage:?}: {error}"));
                recovered.check_clean_consistency(&cx).unwrap();
                let volume = recovered.volume_view(&cx).unwrap();
                if !committed {
                    assert!(
                        matches!(volume.resolve(&cx, "/private"), Err(FfsError::NotFound(_))),
                        "{stage:?}"
                    );
                    continue;
                }
                let record = volume.resolve(&cx, "/private").unwrap();
                assert_eq!(record.is_directory(), directory);
                let info = volume.security_descriptor(&cx, &record).unwrap();
                let map = NtfsSidMap::default();
                assert_eq!(
                    info.descriptor.owner,
                    Some(map.sid_for_uid(1001).unwrap()),
                    "{stage:?}"
                );
                assert_eq!(
                    info.descriptor.group,
                    Some(map.sid_for_gid(2000).unwrap()),
                    "{stage:?}"
                );
                assert_eq!(
                    map.project_posix_mode(&info.descriptor, directory),
                    mode,
                    "{stage:?}"
                );
                assert!(
                    info.descriptor
                        .dacl
                        .aces
                        .iter()
                        .any(|ace| ace.kind == ACE_TYPE_ACCESS_DENIED
                            && ace.flags & ACE_FLAG_INHERITED != 0
                            && ace.sid == Some(map.sid_for_uid(1002).unwrap())),
                    "{stage:?}"
                );
            }
        }
    }
}

#[test]
fn ntfs_mapped_namespace_acl_denials_leave_names_streams_and_storage_unchanged() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xAC15_0006_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    for (name, directory, denied) in [
        ("restricted.bin", false, STANDARD_DELETE),
        ("available.bin", false, 0),
        ("restricted-dir", true, STANDARD_DELETE),
        ("available-dir", true, 0),
        ("victim.bin", false, STANDARD_DELETE),
        ("victim-dir", true, STANDARD_DELETE),
        ("no-files", true, FILE_ADD_FILE),
        ("no-directories", true, FILE_ADD_SUBDIRECTORY),
    ] {
        let (reference, _) = if directory {
            engine.mkdir_at(&cx, root, &utf16(name))
        } else {
            engine.create_file_at(&cx, root, &utf16(name), name.as_bytes())
        }
        .into_result()
        .unwrap();
        if name == "restricted.bin" {
            engine
                .create_stream(&cx, reference, &utf16("audit"), b"retained stream")
                .into_result()
                .unwrap();
        }
        engine
            .set_security_at(
                &cx,
                reference,
                &stream_acl_descriptor(denied),
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
    }
    // An explicit user deny is invisible in the broad owner/group/other mode
    // projection. The adapter itself must enforce the native rights.
    engine
        .set_security_at(
            &cx,
            root,
            &stream_acl_descriptor(FILE_DELETE_CHILD),
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
    let mut scope = RequestScope::empty();
    let root = InodeNumber(1);
    let no_files = fs
        .lookup(&cx, &mut scope, root, OsStr::new("no-files"))
        .unwrap()
        .ino;
    let no_directories = fs
        .lookup(&cx, &mut scope, root, OsStr::new("no-directories"))
        .unwrap()
        .ino;
    let available = fs
        .lookup(&cx, &mut scope, root, OsStr::new("available.bin"))
        .unwrap();
    let victim = fs
        .lookup(&cx, &mut scope, root, OsStr::new("victim.bin"))
        .unwrap();
    let (victim_handle, _) = fs
        .open(&cx, &mut scope, victim.ino, libc::O_RDONLY)
        .unwrap();
    let before = dev.snapshot_live();
    let writes = dev.write_bytes_total();
    for operation in [
        "unlink",
        "rmdir",
        "rename source file",
        "rename source directory",
        "link destination",
        "rename destination file",
        "rename destination directory",
        "replace open file",
        "replace directory",
        "unlink stream",
        "rename stream",
    ] {
        let result = match operation {
            "unlink" => fs.unlink(&cx, &mut scope, root, OsStr::new("restricted.bin")),
            "rmdir" => fs.rmdir(&cx, &mut scope, root, OsStr::new("restricted-dir")),
            "link destination" => fs
                .link(
                    &cx,
                    &mut scope,
                    available.ino,
                    no_files,
                    OsStr::new("linked"),
                )
                .map(|_| ()),
            "unlink stream" => fs.unlink(&cx, &mut scope, root, OsStr::new("restricted.bin:audit")),
            _ => {
                let (source, parent, destination) = match operation {
                    "rename source file" => ("restricted.bin", root, "moved-file"),
                    "rename source directory" => ("restricted-dir", root, "moved-dir"),
                    "rename destination file" => ("available.bin", no_files, "moved-file"),
                    "rename destination directory" => {
                        ("available-dir", no_directories, "moved-dir")
                    }
                    "replace open file" => ("available.bin", root, "victim.bin"),
                    "replace directory" => ("available-dir", root, "victim-dir"),
                    "rename stream" => ("restricted.bin:audit", root, "restricted.bin:new"),
                    _ => unreachable!(),
                };
                fs.rename(
                    &cx,
                    &mut scope,
                    root,
                    OsStr::new(source),
                    parent,
                    OsStr::new(destination),
                )
            }
        };
        assert!(
            matches!(result, Err(FfsError::PermissionDenied)),
            "{operation} must reject the native ACL denial: {result:?}"
        );
        assert_eq!(dev.write_bytes_total(), writes, "{operation}");
    }
    assert_eq!(dev.snapshot_live(), before);
    assert_eq!(dev.snapshot_durable_only(), before);
    assert!(fs.last_durable_token().unwrap().is_none());
    assert_eq!(
        fs.read(&cx, &mut scope, victim.ino, 0, 64).unwrap(),
        b"victim.bin"
    );
    fs.release(
        &cx,
        &mut scope,
        ffs_core::vfs::ReleaseRequest {
            ino: victim.ino,
            fh: victim_handle,
            flags: libc::O_RDONLY,
            lock_owner: None,
            flush: false,
        },
    )
    .unwrap();
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);
    let engine = open_clean_engine(&cx, &dev, vol_bytes);
    engine.check_clean_consistency(&cx).unwrap();
    assert_eq!(
        read_file_by_path(&cx, &engine, "/available.bin"),
        b"available.bin"
    );
    assert_eq!(
        read_file_by_path(&cx, &engine, "/restricted.bin"),
        b"restricted.bin"
    );
    assert!(
        engine
            .resolve_path_reference(&cx, "/restricted-dir")
            .is_ok()
    );
    assert!(engine.resolve_path_reference(&cx, "/victim-dir").is_ok());
}

#[test]
fn ntfs_mapped_namespace_acl_accepts_object_or_parent_delete_authority() {
    let cx = Cx::for_testing();
    for (index, version, deny_object, deny_parent) in [
        (0, NtfsFormatVersion::V3_0, 0, FILE_DELETE_CHILD),
        (1, NtfsFormatVersion::V3_1, STANDARD_DELETE, 0),
    ] {
        let (dev, vol_bytes) =
            format_to_fault_device(&cx, 16, 4096, version, 0xAC15_0007_0000_0001 + index);
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        let root = engine.resolve_path_reference(&cx, "/").unwrap();
        for (name, directory) in [
            ("remove.bin", false),
            ("remove-dir", true),
            ("source.bin", false),
            ("victim.bin", false),
            ("streams.bin", false),
        ] {
            let (reference, _) = if directory {
                engine.mkdir_at(&cx, root, &utf16(name))
            } else {
                engine.create_file_at(&cx, root, &utf16(name), name.as_bytes())
            }
            .into_result()
            .unwrap();
            if name == "streams.bin" {
                engine
                    .create_stream(&cx, reference, &utf16("audit"), b"stream payload")
                    .into_result()
                    .unwrap();
            }
            engine
                .set_security_at(
                    &cx,
                    reference,
                    &stream_acl_descriptor(deny_object),
                    DEFAULT_NTFS_FILETIME,
                )
                .into_result()
                .unwrap();
        }
        engine
            .set_security_at(
                &cx,
                root,
                &stream_acl_descriptor(deny_parent),
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
        let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
        let mut scope = RequestScope::empty();
        let root = InodeNumber(1);
        fs.unlink(&cx, &mut scope, root, OsStr::new("remove.bin"))
            .unwrap();
        fs.rmdir(&cx, &mut scope, root, OsStr::new("remove-dir"))
            .unwrap();
        let source = fs
            .lookup(&cx, &mut scope, root, OsStr::new("source.bin"))
            .unwrap();
        // Adding a hard link does not need DELETE on the source object.
        fs.link(&cx, &mut scope, source.ino, root, OsStr::new("linked.bin"))
            .unwrap();
        fs.rename(
            &cx,
            &mut scope,
            root,
            OsStr::new("source.bin"),
            root,
            OsStr::new("victim.bin"),
        )
        .unwrap();
        fs.rename(
            &cx,
            &mut scope,
            root,
            OsStr::new("streams.bin:audit"),
            root,
            OsStr::new("streams.bin:renamed"),
        )
        .unwrap();
        let stream = fs
            .lookup(&cx, &mut scope, root, OsStr::new("streams.bin:renamed"))
            .unwrap();
        assert_eq!(
            fs.read(&cx, &mut scope, stream.ino, 0, 64).unwrap(),
            b"stream payload"
        );
        fs.unlink(&cx, &mut scope, root, OsStr::new("streams.bin:renamed"))
            .unwrap();
        fs.flush_on_destroy(&cx).unwrap();
        drop(fs);
        let engine = open_clean_engine(&cx, &dev, vol_bytes);
        engine.check_clean_consistency(&cx).unwrap();
        assert_eq!(
            read_file_by_path(&cx, &engine, "/victim.bin"),
            b"source.bin"
        );
        assert_eq!(
            read_file_by_path(&cx, &engine, "/linked.bin"),
            b"source.bin"
        );
        assert_eq!(
            read_file_by_path(&cx, &engine, "/streams.bin"),
            b"streams.bin"
        );
        for path in ["/remove.bin", "/remove-dir", "/source.bin"] {
            assert!(matches!(
                engine.resolve_path_reference(&cx, path),
                Err(FfsError::NotFound(_))
            ));
        }
    }
}

#[test]
fn ntfs_mapped_namespace_acl_does_not_replace_security_read_errors_with_parent_permission() {
    let cx = Cx::for_testing();
    let (initial, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xAC15_0008_0000_0001,
    );
    let descriptor = stream_acl_descriptor(FILE_WRITE_EA);
    let mut engine = open_clean_engine(&cx, &initial, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let (file, _) = engine
        .create_file_at(&cx, root, &utf16("protected.bin"), b"keep")
        .into_result()
        .unwrap();
    engine
        .set_security_at(&cx, file, &descriptor, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    drop(engine);
    let pristine = initial.snapshot_durable_only();
    for fault_kind in ["I/O", "corruption", "cancellation"] {
        let dev = FaultInjectingNtfsDevice::new(pristine.clone());
        let backing = Arc::new(SecurityReadFault {
            inner: Arc::clone(&dev),
            descriptor: descriptor.clone(),
            fault: Mutex::new(None),
        });
        let engine = NtfsTransactionEngine::from_device(
            &cx,
            Arc::clone(&backing) as Arc<dyn ByteDevice>,
            0,
            vol_bytes,
            write_options_clean(),
        )
        .unwrap();
        let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
        let mut scope = RequestScope::empty();
        fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("protected.bin"))
            .unwrap();
        *backing.fault.lock().unwrap() = Some(match fault_kind {
            "I/O" => FfsError::Io(std::io::Error::other("security metadata read failed")),
            "corruption" => FfsError::Corruption {
                block: 0,
                detail: "security metadata is corrupt".into(),
            },
            "cancellation" => FfsError::Cancelled,
            _ => unreachable!(),
        });
        let writes = dev.write_bytes_total();
        let result = fs.unlink(&cx, &mut scope, InodeNumber(1), OsStr::new("protected.bin"));
        assert!(
            backing.fault.lock().unwrap().is_none(),
            "must exercise the descriptor fault"
        );
        assert!(
            matches!(
                (fault_kind, &result),
                ("I/O", Err(FfsError::Io(_)))
                    | ("corruption", Err(FfsError::Corruption { .. }))
                    | ("cancellation", Err(FfsError::Cancelled))
            ),
            "{fault_kind} must propagate instead of granting delete via the parent: {result:?}"
        );
        assert_eq!(dev.write_bytes_total(), writes);
        assert_eq!(dev.snapshot_live(), pristine);
        assert_eq!(dev.snapshot_durable_only(), pristine);
        assert!(fs.last_durable_token().unwrap().is_none());
        drop(fs);
        let engine = open_clean_engine(&cx, &dev, vol_bytes);
        assert_eq!(read_file_by_path(&cx, &engine, "/protected.bin"), b"keep");
    }
}

#[test]
fn ntfs_creation_security_errors_refuse_without_writes() {
    let cx = Cx::for_testing();
    let (initial, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xAC15_0009_0000_0001,
    );
    let descriptor = stream_acl_descriptor(FILE_WRITE_EA);
    let mut engine = open_clean_engine(&cx, &initial, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    engine
        .set_security_at(&cx, root, &descriptor, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    drop(engine);
    let pristine = initial.snapshot_durable_only();

    for operation in ["file-at", "directory-at", "file-path", "directory-path"] {
        for fault_kind in ["I/O", "corruption", "cancellation"] {
            let dev = FaultInjectingNtfsDevice::new(pristine.clone());
            let backing = Arc::new(SecurityReadFault {
                inner: Arc::clone(&dev),
                descriptor: descriptor.clone(),
                fault: Mutex::new(None),
            });
            let mut engine = NtfsTransactionEngine::from_device(
                &cx,
                Arc::clone(&backing) as Arc<dyn ByteDevice>,
                0,
                vol_bytes,
                write_options_clean(),
            )
            .unwrap();
            let root = engine.resolve_path_reference(&cx, "/").unwrap();
            *backing.fault.lock().unwrap() = Some(match fault_kind {
                "I/O" => FfsError::Io(std::io::Error::other("parent security read failed")),
                "corruption" => FfsError::Corruption {
                    block: 0,
                    detail: "parent security is corrupt".into(),
                },
                "cancellation" => FfsError::Cancelled,
                _ => unreachable!(),
            });
            let writes = dev.write_bytes_total();
            let outcome = match operation {
                "file-at" => engine.create_file_at(&cx, root, &utf16("child"), b"payload"),
                "directory-at" => engine.mkdir_at(&cx, root, &utf16("child")),
                "file-path" => engine.create_file(&cx, "/", "child", b"payload"),
                "directory-path" => engine.mkdir(&cx, "/", "child"),
                _ => unreachable!(),
            };
            assert!(backing.fault.lock().unwrap().is_none(), "fault must fire");
            assert!(
                matches!(
                    (fault_kind, &outcome),
                    ("I/O", NtfsTxOutcome::NotCommitted(FfsError::Io(_)))
                        | (
                            "corruption",
                            NtfsTxOutcome::NotCommitted(FfsError::Corruption { .. })
                        )
                        | (
                            "cancellation",
                            NtfsTxOutcome::NotCommitted(FfsError::Cancelled)
                        )
                ),
                "{operation} must preserve {fault_kind} before creating a child: {outcome:?}"
            );
            assert!(!engine.requires_recovery());
            assert_eq!(dev.write_bytes_total(), writes);
            assert_eq!(dev.snapshot_live(), pristine);
            assert_eq!(dev.snapshot_durable_only(), pristine);
            drop(engine);
            let mut reopened = open_clean_engine(&cx, &dev, vol_bytes);
            assert!(matches!(
                reopened.resolve_path_reference(&cx, "/child"),
                Err(FfsError::NotFound(_))
            ));
            // Refusal does not poison the predecessor or consume its resources.
            reopened
                .create_file(&cx, "/", "retry", b"retry payload")
                .into_result()
                .unwrap();
            assert_eq!(
                read_file_by_path(&cx, &reopened, "/retry"),
                b"retry payload"
            );
            reopened.check_clean_consistency(&cx).unwrap();
        }
    }
}

#[test]
fn ntfs_creation_inherits_sacl_without_inheritable_dacl() {
    for version in [NtfsFormatVersion::V3_0, NtfsFormatVersion::V3_1] {
        let cx = Cx::for_testing();
        let (dev, vol_bytes) =
            format_to_fault_device(&cx, 16, 4096, version, 0xAC15_0010_0000_0001);
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        let root = engine.resolve_path_reference(&cx, "/").unwrap();
        let mut descriptor =
            NtfsSecurityDescriptor::parse(&stream_acl_descriptor(FILE_WRITE_EA)).unwrap();
        descriptor.control |= SE_SACL_PRESENT;
        descriptor.sacl = NtfsAcl {
            present: true,
            offset: 0,
            revision: Some(2),
            ace_count: Some(3),
            size: None,
            aces: vec![
                build_simple_ace(
                    ACE_TYPE_SYSTEM_AUDIT,
                    0xC0 | ACE_FLAG_OBJECT_INHERIT,
                    FILE_READ_DATA,
                    NtfsSid::world_everyone(),
                ),
                build_simple_ace(
                    ACE_TYPE_SYSTEM_AUDIT,
                    0xC0 | ACE_FLAG_CONTAINER_INHERIT,
                    FILE_WRITE_DATA,
                    NtfsSid::world_everyone(),
                ),
                build_simple_ace(
                    ACE_TYPE_SYSTEM_AUDIT,
                    0xC0,
                    FILE_READ_EA,
                    NtfsSid::world_everyone(),
                ),
            ],
            padding: Vec::new(),
        };
        let parent_bytes = descriptor.encode().unwrap();
        engine
            .set_security_at(&cx, root, &parent_bytes, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        engine
            .create_file_at(&cx, root, &utf16("file-at"), b"payload")
            .into_result()
            .unwrap();
        engine
            .mkdir_at(&cx, root, &utf16("directory-at"))
            .into_result()
            .unwrap();
        engine
            .create_file(&cx, "/", "file-path", b"payload")
            .into_result()
            .unwrap();
        engine
            .mkdir(&cx, "/", "directory-path")
            .into_result()
            .unwrap();
        engine.check_clean_consistency(&cx).unwrap();
        drop(engine);

        let cold = FaultInjectingNtfsDevice::new(dev.snapshot_durable_only());
        let reopened = open_clean_engine(&cx, &cold, vol_bytes);
        let volume = reopened.volume_view(&cx).unwrap();
        let parent = volume.resolve(&cx, "/").unwrap();
        assert_eq!(
            volume.security_descriptor(&cx, &parent).unwrap().bytes,
            parent_bytes
        );
        for path in ["/file-at", "/file-path", "/directory-at", "/directory-path"] {
            let record = volume.resolve(&cx, path).unwrap();
            let info = volume.security_descriptor(&cx, &record).unwrap();
            let aces = &info.descriptor.sacl.aces;
            assert!(info.descriptor.sacl.present);
            assert_eq!(aces.len(), if record.is_directory() { 2 } else { 1 });
            assert_eq!(aces[0].mask, Some(FILE_READ_DATA));
            assert_eq!(
                aces[0].flags,
                0xC0 | ACE_FLAG_INHERITED
                    | if record.is_directory() {
                        ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_INHERIT_ONLY
                    } else {
                        0
                    }
            );
            if record.is_directory() {
                assert_eq!(aces[1].mask, Some(FILE_WRITE_DATA));
                assert_eq!(
                    aces[1].flags,
                    0xC0 | ACE_FLAG_CONTAINER_INHERIT | ACE_FLAG_INHERITED
                );
            } else {
                assert_eq!(read_file_by_path(&cx, &reopened, path), b"payload");
            }
            assert!(aces.iter().all(|ace| ace.mask != Some(FILE_READ_EA)));
        }
    }
}

#[test]
fn ntfs_mapped_acl_covers_named_stream_io_and_mutations() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xAC15_0001_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let (file, _) = engine
        .create_file_at(&cx, root, &utf16("restricted.bin"), b"base-content")
        .into_result()
        .unwrap();
    engine
        .create_stream(&cx, file, &utf16("audit"), b"stream-content")
        .into_result()
        .unwrap();
    engine
        .set_security_at(
            &cx,
            file,
            &stream_acl_descriptor(FILE_READ_DATA | FILE_WRITE_DATA),
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
    let mut scope = RequestScope::empty();
    let root_ino = InodeNumber(1);
    let base = fs
        .lookup(&cx, &mut scope, root_ino, OsStr::new("restricted.bin"))
        .unwrap();
    let ads = fs
        .lookup(
            &cx,
            &mut scope,
            root_ino,
            OsStr::new("restricted.bin:audit"),
        )
        .unwrap();
    // An explicit deny for this SID cannot be represented by the owner/group/
    // other projection alone. Native checks must apply to both stream kinds.
    assert_ne!(ads.perm & 0o222, 0);
    let before = dev.snapshot_live();
    let writes = dev.write_bytes_total();
    for ino in [base.ino, ads.ino] {
        assert!(matches!(
            fs.read(&cx, &mut scope, ino, 0, 64),
            Err(FfsError::PermissionDenied)
        ));
        for flags in [libc::O_RDONLY, libc::O_WRONLY, libc::O_RDWR] {
            assert!(matches!(
                fs.open(&cx, &mut scope, ino, flags),
                Err(FfsError::PermissionDenied)
            ));
        }
        assert!(matches!(
            fs.open_read_only(&cx, ino, libc::O_RDONLY),
            Err(FfsError::PermissionDenied)
        ));
        assert!(matches!(
            fs.write(&cx, &mut scope, ino, 0, b"forbidden"),
            Err(FfsError::PermissionDenied)
        ));
        assert!(matches!(
            fs.setattr(
                &cx,
                &mut scope,
                ino,
                &SetAttrRequest {
                    size: Some(0),
                    ..SetAttrRequest::default()
                },
            ),
            Err(FfsError::PermissionDenied)
        ));
        assert!(matches!(
            fs.fallocate(&cx, &mut scope, ino, 0, 4, 0x03),
            Err(FfsError::PermissionDenied)
        ));
    }
    assert!(matches!(
        fs.create(
            &cx,
            &mut scope,
            root_ino,
            OsStr::new("restricted.bin:new"),
            0o666,
            1002,
            2000,
        ),
        Err(FfsError::PermissionDenied)
    ));
    assert!(matches!(
        fs.unlink(
            &cx,
            &mut scope,
            root_ino,
            OsStr::new("restricted.bin:audit")
        ),
        Err(FfsError::PermissionDenied)
    ));
    assert!(matches!(
        fs.rename(
            &cx,
            &mut scope,
            root_ino,
            OsStr::new("restricted.bin:audit"),
            root_ino,
            OsStr::new("restricted.bin:moved"),
        ),
        Err(FfsError::PermissionDenied)
    ));
    assert_eq!(dev.write_bytes_total(), writes);
    assert_eq!(dev.snapshot_live(), before);
    assert!(fs.last_durable_token().unwrap().is_none());
    drop(fs);

    // The same native descriptor permits another caller, and changing the ADS
    // must leave the unnamed stream intact.
    let engine = open_clean_engine(&cx, &dev, vol_bytes);
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1001)).unwrap();
    let ads = fs
        .lookup(
            &cx,
            &mut scope,
            root_ino,
            OsStr::new("restricted.bin:audit"),
        )
        .unwrap();
    assert_eq!(
        fs.read(&cx, &mut scope, ads.ino, 0, 64).unwrap(),
        b"stream-content"
    );
    let (fh, _) = fs.open(&cx, &mut scope, ads.ino, libc::O_RDWR).unwrap();
    fs.write(&cx, &mut scope, ads.ino, 0, b"allowed").unwrap();
    fs.setattr(
        &cx,
        &mut scope,
        ads.ino,
        &SetAttrRequest {
            size: Some(7),
            ..SetAttrRequest::default()
        },
    )
    .unwrap();
    fs.fallocate(&cx, &mut scope, ads.ino, 1, 3, 0x03).unwrap();
    assert_eq!(
        fs.read(&cx, &mut scope, ads.ino, 0, 64).unwrap(),
        b"a\0\0\0wed"
    );
    assert_eq!(
        fs.read(&cx, &mut scope, base.ino, 0, 64).unwrap(),
        b"base-content"
    );
    fs.release(
        &cx,
        &mut scope,
        ffs_core::vfs::ReleaseRequest {
            ino: ads.ino,
            fh,
            flags: libc::O_RDWR,
            lock_owner: None,
            flush: false,
        },
    )
    .unwrap();
    fs.flush_on_destroy(&cx).unwrap();
}

#[test]
fn ntfs_mapped_acl_open_checks_read_right_before_truncating_any_stream() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_0,
        0xAC15_0002_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let (file, _) = engine
        .create_file_at(&cx, root, &utf16("write-only.bin"), b"base")
        .into_result()
        .unwrap();
    engine
        .create_stream(&cx, file, &utf16("audit"), b"stream")
        .into_result()
        .unwrap();
    engine
        .set_security_at(
            &cx,
            file,
            &stream_acl_descriptor(FILE_READ_DATA),
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
    let mut scope = RequestScope::empty();
    for name in ["write-only.bin", "write-only.bin:audit"] {
        let attr = fs
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new(name))
            .unwrap();
        let before = dev.snapshot_live();
        let writes = dev.write_bytes_total();
        for flags in [
            libc::O_RDONLY,
            libc::O_RDWR,
            libc::O_RDONLY | libc::O_TRUNC,
            libc::O_RDWR | libc::O_TRUNC,
        ] {
            assert!(
                matches!(
                    fs.open(&cx, &mut scope, attr.ino, flags),
                    Err(FfsError::PermissionDenied)
                ),
                "read access must be checked for {name}, flags={flags}"
            );
        }
        assert_eq!(dev.write_bytes_total(), writes);
        assert_eq!(dev.snapshot_live(), before);
        let (fh, _) = fs.open(&cx, &mut scope, attr.ino, libc::O_WRONLY).unwrap();
        fs.write(&cx, &mut scope, attr.ino, 0, b"ok").unwrap();
        assert!(matches!(
            fs.read(&cx, &mut scope, attr.ino, 0, 2),
            Err(FfsError::PermissionDenied)
        ));
        fs.release(
            &cx,
            &mut scope,
            ffs_core::vfs::ReleaseRequest {
                ino: attr.ino,
                fh,
                flags: libc::O_WRONLY,
                lock_owner: None,
                flush: false,
            },
        )
        .unwrap();
    }
    fs.flush_on_destroy(&cx).unwrap();
}

#[test]
fn ntfs_mapped_stream_creation_uses_file_authority_without_directory_add_rights() {
    let cx = Cx::for_testing();
    for version in [NtfsFormatVersion::V3_0, NtfsFormatVersion::V3_1] {
        let (dev, vol_bytes) =
            format_to_fault_device(&cx, 16, 4096, version, 0xAC15_0004_0000_0001);
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        let root = engine.resolve_path_reference(&cx, "/").unwrap();
        let (writable, _) = engine
            .create_file_at(&cx, root, &utf16("write-only.bin"), b"base")
            .into_result()
            .unwrap();
        let (read_only, _) = engine
            .create_file_at(&cx, root, &utf16("read-only.bin"), b"protected")
            .into_result()
            .unwrap();
        for (target, denied) in [
            (root, FILE_ADD_FILE),
            (writable, FILE_READ_DATA),
            (read_only, FILE_WRITE_DATA),
        ] {
            engine
                .set_security_at(
                    &cx,
                    target,
                    &stream_acl_descriptor(denied),
                    DEFAULT_NTFS_FILETIME,
                )
                .into_result()
                .unwrap();
        }
        let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
        let mut scope = RequestScope::empty();

        // A stream belongs to the existing FILE. Denying new directory entries
        // must not prevent a caller with FILE_WRITE_DATA from adding a stream.
        // The native descriptor projects 0777, so these requests do not claim
        // a narrower security boundary than the shared FILE actually provides.
        let direct = fs
            .create(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("write-only.bin:direct"),
                0o777,
                1002,
                2000,
            )
            .unwrap();
        fs.write(&cx, &mut scope, direct.ino, 0, b"direct").unwrap();
        let (opened, handle, _) = fs
            .create_open(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("write-only.bin:opened"),
                0o777,
                1002,
                2000,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .unwrap();
        fs.write(&cx, &mut scope, opened.ino, 0, b"opened").unwrap();
        assert!(matches!(
            fs.read(&cx, &mut scope, opened.ino, 0, 64),
            Err(FfsError::PermissionDenied)
        ));
        fs.release(
            &cx,
            &mut scope,
            ffs_core::vfs::ReleaseRequest {
                ino: opened.ino,
                fh: handle,
                flags: libc::O_WRONLY,
                lock_owner: None,
                flush: false,
            },
        )
        .unwrap();

        // Parent authority still controls ordinary file creation; base-file
        // authority and requested read access still control stream creation.
        let before = dev.snapshot_live();
        let durable = dev.snapshot_durable_only();
        let writes = dev.write_bytes_total();
        for (name, flags) in [
            ("blocked-file.bin", libc::O_WRONLY),
            ("read-only.bin:blocked", libc::O_WRONLY),
            ("write-only.bin:read", libc::O_RDONLY),
            ("write-only.bin:read-write", libc::O_RDWR),
        ] {
            assert!(matches!(
                fs.create_open(
                    &cx,
                    &mut scope,
                    InodeNumber(1),
                    OsStr::new(name),
                    0o777,
                    1002,
                    2000,
                    flags | libc::O_CREAT | libc::O_EXCL,
                ),
                Err(FfsError::PermissionDenied)
            ));
            assert!(matches!(
                fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new(name)),
                Err(FfsError::NotFound(_))
            ));
        }
        assert!(matches!(
            fs.create(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("write-only.bin:private"),
                0o600,
                1002,
                2000,
            ),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert_eq!(dev.write_bytes_total(), writes);
        assert_eq!(dev.snapshot_live(), before);
        assert_eq!(dev.snapshot_durable_only(), durable);
        fs.flush_on_destroy(&cx).unwrap();
        drop(fs);

        let engine = open_clean_engine(&cx, &dev, vol_bytes);
        engine.check_clean_consistency(&cx).unwrap();
        let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1001)).unwrap();
        for (name, expected) in [
            ("write-only.bin:direct", b"direct".as_slice()),
            ("write-only.bin:opened", b"opened".as_slice()),
            ("write-only.bin", b"base".as_slice()),
            ("read-only.bin", b"protected".as_slice()),
        ] {
            let attr = fs
                .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new(name))
                .unwrap();
            assert_eq!(fs.read(&cx, &mut scope, attr.ino, 0, 64).unwrap(), expected);
        }
    }
}

#[test]
fn ntfs_mapped_acl_create_open_checks_read_before_publishing_named_stream() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xAC15_0003_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let (file, _) = engine
        .create_file_at(&cx, root, &utf16("write-only.bin"), b"base")
        .into_result()
        .unwrap();
    engine
        .set_security_at(
            &cx,
            file,
            &stream_acl_descriptor(FILE_READ_DATA),
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    // The caller can write the existing FILE but cannot add a directory child.
    engine
        .set_security_at(
            &cx,
            root,
            &stream_acl_descriptor(FILE_ADD_FILE),
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
    let mut scope = RequestScope::empty();
    let before = dev.snapshot_live();
    let durable_before = dev.snapshot_durable_only();
    let writes = dev.write_bytes_total();
    for (name, flags) in [
        ("ordinary.bin", libc::O_WRONLY),
        ("write-only.bin:read", libc::O_RDONLY),
        ("write-only.bin:read-write", libc::O_RDWR),
    ] {
        assert!(matches!(
            fs.create_open(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new(name),
                0o777,
                1002,
                2000,
                flags | libc::O_CREAT | libc::O_EXCL,
            ),
            Err(FfsError::PermissionDenied)
        ));
        assert!(matches!(
            fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new(name)),
            Err(FfsError::NotFound(_))
        ));
    }
    assert_eq!(dev.write_bytes_total(), writes);
    assert_eq!(dev.snapshot_live(), before);
    assert_eq!(dev.snapshot_durable_only(), durable_before);
    assert!(fs.last_durable_token().unwrap().is_none());

    let (attr, fh, _) = fs
        .create_open(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("write-only.bin:write"),
            0o777,
            1002,
            2000,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .unwrap();
    fs.write(&cx, &mut scope, attr.ino, 0, b"permitted")
        .unwrap();
    assert!(matches!(
        fs.read(&cx, &mut scope, attr.ino, 0, 64),
        Err(FfsError::PermissionDenied)
    ));
    fs.release(
        &cx,
        &mut scope,
        ffs_core::vfs::ReleaseRequest {
            ino: attr.ino,
            fh,
            flags: libc::O_WRONLY,
            lock_owner: None,
            flush: false,
        },
    )
    .unwrap();
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    let engine = open_clean_engine(&cx, &dev, vol_bytes);
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1001)).unwrap();
    let written = fs
        .lookup(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("write-only.bin:write"),
        )
        .unwrap();
    assert_eq!(
        fs.read(&cx, &mut scope, written.ino, 0, 64).unwrap(),
        b"permitted"
    );
    let (attr, fh, _) = fs
        .create_open(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("write-only.bin:read-write"),
            0o777,
            1001,
            2000,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        )
        .unwrap();
    fs.write(&cx, &mut scope, attr.ino, 0, b"both").unwrap();
    assert_eq!(fs.read(&cx, &mut scope, attr.ino, 0, 64).unwrap(), b"both");
    fs.release(
        &cx,
        &mut scope,
        ffs_core::vfs::ReleaseRequest {
            ino: attr.ino,
            fh,
            flags: libc::O_RDWR,
            lock_owner: None,
            flush: false,
        },
    )
    .unwrap();
    fs.flush_on_destroy(&cx).unwrap();
}

#[test]
fn ntfs_mapped_acl_extended_attribute_rights_are_independent_of_data_rights() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xAC15_0004_0000_0001,
    );
    // Name, denied native rights, DATA access, EA read access, EA write access.
    let cases = [
        (
            "no-ea.bin",
            FILE_READ_EA | FILE_WRITE_EA,
            true,
            false,
            false,
        ),
        (
            "no-data.bin",
            FILE_READ_DATA | FILE_WRITE_DATA,
            false,
            true,
            true,
        ),
        ("write-ea.bin", FILE_READ_EA, true, false, true),
        ("read-ea.bin", FILE_WRITE_EA, true, true, false),
    ];
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    for (name, denied, _, _, _) in cases {
        let (file, _) = engine
            .create_file_at(&cx, root, &utf16(name), b"base")
            .into_result()
            .unwrap();
        engine
            .set_ea_at(
                &cx,
                file,
                b"user.secret",
                b"initial",
                0,
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
        engine
            .set_security_at(
                &cx,
                file,
                &stream_acl_descriptor(denied),
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
    }
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
    let mut scope = RequestScope::empty();
    for (name, _, data_allowed, read_ea_allowed, write_ea_allowed) in cases {
        let attr = fs
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new(name))
            .unwrap();
        if data_allowed {
            assert_eq!(fs.read(&cx, &mut scope, attr.ino, 0, 64).unwrap(), b"base");
            assert_eq!(fs.write(&cx, &mut scope, attr.ino, 0, b"ok").unwrap(), 2);
        } else {
            assert!(matches!(
                fs.read(&cx, &mut scope, attr.ino, 0, 64),
                Err(FfsError::PermissionDenied)
            ));
            assert!(matches!(
                fs.write(&cx, &mut scope, attr.ino, 0, b"forbidden"),
                Err(FfsError::PermissionDenied)
            ));
        }
        let before = dev.snapshot_live();
        let writes = dev.write_bytes_total();
        if read_ea_allowed {
            assert_eq!(
                fs.listxattr(&cx, attr.ino).unwrap(),
                vec!["user.secret".to_owned()]
            );
            assert_eq!(
                fs.getxattr(&cx, attr.ino, "user.secret").unwrap(),
                Some(b"initial".to_vec())
            );
            assert_eq!(fs.getxattr(&cx, attr.ino, "user.missing").unwrap(), None);
        } else {
            assert!(matches!(
                fs.listxattr(&cx, attr.ino),
                Err(FfsError::PermissionDenied)
            ));
            for key in ["user.secret", "user.missing"] {
                assert!(matches!(
                    fs.getxattr(&cx, attr.ino, key),
                    Err(FfsError::PermissionDenied)
                ));
            }
        }
        if write_ea_allowed {
            fs.setxattr(
                &cx,
                &mut scope,
                attr.ino,
                "user.created",
                b"created",
                XattrSetMode::Create,
            )
            .unwrap();
            fs.setxattr(
                &cx,
                &mut scope,
                attr.ino,
                "user.secret",
                b"replaced",
                XattrSetMode::Replace,
            )
            .unwrap();
            assert!(
                fs.removexattr(&cx, &mut scope, attr.ino, "user.secret")
                    .unwrap()
            );
        } else {
            for (key, mode) in [
                ("user.created", XattrSetMode::Create),
                ("user.secret", XattrSetMode::Replace),
            ] {
                assert!(matches!(
                    fs.setxattr(&cx, &mut scope, attr.ino, key, b"forbidden", mode),
                    Err(FfsError::PermissionDenied)
                ));
            }
            for key in ["user.secret", "user.missing"] {
                assert!(matches!(
                    fs.removexattr(&cx, &mut scope, attr.ino, key),
                    Err(FfsError::PermissionDenied)
                ));
            }
            assert_eq!(dev.write_bytes_total(), writes);
            assert_eq!(dev.snapshot_live(), before);
        }
    }
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    let engine = open_clean_engine(&cx, &dev, vol_bytes);
    let volume = engine.volume_view(&cx).unwrap();
    for (name, _, data_allowed, _, write_ea_allowed) in cases {
        let path = format!("/{name}");
        let record = volume.resolve(&cx, &path).unwrap();
        let eas = volume.extended_attributes(&cx, &record).unwrap();
        if write_ea_allowed {
            assert!(eas.find(b"user.secret").is_none());
            assert_eq!(eas.find(b"user.created").unwrap().value, b"created");
        } else {
            assert_eq!(eas.find(b"user.secret").unwrap().value, b"initial");
            assert!(eas.find(b"user.created").is_none());
        }
        assert_eq!(
            read_file_by_path(&cx, &engine, &path),
            if data_allowed { b"okse" } else { b"base" }
        );
    }
}

#[test]
fn ntfs_mapped_acl_timestamp_rights_are_independent_of_data_rights_and_atomic() {
    use ffs_ondisk::ntfs_security::FILE_WRITE_ATTRIBUTES;
    use std::time::Duration;

    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xAC15_0005_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    for (name, denied) in [
        ("no-attributes.bin", FILE_WRITE_ATTRIBUTES),
        ("no-data.bin", FILE_READ_DATA | FILE_WRITE_DATA),
    ] {
        let (file, _) = engine
            .create_file_at(&cx, root, &utf16(name), b"base-content")
            .into_result()
            .unwrap();
        engine
            .set_security_at(
                &cx,
                file,
                &stream_acl_descriptor(denied),
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
    }
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
    let mut scope = RequestScope::empty();
    let no_attributes = fs
        .lookup(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("no-attributes.bin"),
        )
        .unwrap();
    // A DATA write may update timestamps implicitly without WRITE_ATTRIBUTES.
    assert_eq!(
        fs.write(&cx, &mut scope, no_attributes.ino, 0, b"DATA")
            .unwrap(),
        4
    );
    let current = fs.getattr(&cx, &mut scope, no_attributes.ino).unwrap();
    let mtime = current.mtime + Duration::from_secs(31);
    let atime = current.atime + Duration::from_secs(17);
    let before = dev.snapshot_live();
    let writes = dev.write_bytes_total();
    for (label, request) in [
        (
            "mtime",
            SetAttrRequest {
                mtime: Some(mtime),
                ..SetAttrRequest::default()
            },
        ),
        (
            "atime",
            SetAttrRequest {
                atime: Some(atime),
                ..SetAttrRequest::default()
            },
        ),
        (
            "resize and mtime",
            SetAttrRequest {
                size: Some(3),
                mtime: Some(mtime),
                ..SetAttrRequest::default()
            },
        ),
        (
            "resize and atime",
            SetAttrRequest {
                size: Some(3),
                atime: Some(atime),
                ..SetAttrRequest::default()
            },
        ),
        // This stamp equals the current value, but must still override the
        // resize's automatic mtime and therefore needs WRITE_ATTRIBUTES.
        (
            "resize and unchanged mtime",
            SetAttrRequest {
                size: Some(3),
                mtime: Some(current.mtime),
                ..SetAttrRequest::default()
            },
        ),
    ] {
        assert!(
            matches!(
                fs.setattr(&cx, &mut scope, no_attributes.ino, &request),
                Err(FfsError::PermissionDenied)
            ),
            "{label} must require native WRITE_ATTRIBUTES"
        );
        assert_eq!(dev.write_bytes_total(), writes, "{label}");
        assert_eq!(dev.snapshot_live(), before, "{label}");
        assert_eq!(dev.snapshot_durable_only(), before, "{label}");
    }
    assert_eq!(
        fs.read(&cx, &mut scope, no_attributes.ino, 0, 64).unwrap(),
        b"DATA-content"
    );

    let no_data = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("no-data.bin"))
        .unwrap();
    assert!(matches!(
        fs.read(&cx, &mut scope, no_data.ino, 0, 64),
        Err(FfsError::PermissionDenied)
    ));
    assert!(matches!(
        fs.write(&cx, &mut scope, no_data.ino, 0, b"forbidden"),
        Err(FfsError::PermissionDenied)
    ));
    let updated = fs
        .setattr(
            &cx,
            &mut scope,
            no_data.ino,
            &SetAttrRequest {
                atime: Some(atime),
                mtime: Some(mtime),
                ..SetAttrRequest::default()
            },
        )
        .unwrap();
    assert_eq!(updated.atime, atime);
    assert_eq!(updated.mtime, mtime);
    assert_eq!(updated.size, no_data.size);
    let before = dev.snapshot_live();
    let writes = dev.write_bytes_total();
    assert!(matches!(
        fs.setattr(
            &cx,
            &mut scope,
            no_data.ino,
            &SetAttrRequest {
                size: Some(3),
                mtime: Some(mtime + Duration::from_secs(1)),
                ..SetAttrRequest::default()
            }
        ),
        Err(FfsError::PermissionDenied)
    ));
    assert_eq!(dev.write_bytes_total(), writes);
    assert_eq!(dev.snapshot_live(), before);
    assert_eq!(dev.snapshot_durable_only(), before);
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    let engine = open_clean_engine(&cx, &dev, vol_bytes);
    engine.check_clean_consistency(&cx).unwrap();
    assert_eq!(
        read_file_by_path(&cx, &engine, "/no-attributes.bin"),
        b"DATA-content"
    );
    assert_eq!(
        read_file_by_path(&cx, &engine, "/no-data.bin"),
        b"base-content"
    );
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1001)).unwrap();
    let persisted = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("no-data.bin"))
        .unwrap();
    assert_eq!(persisted.atime, atime);
    assert_eq!(persisted.mtime, mtime);
    let allowed = fs
        .lookup(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("no-attributes.bin"),
        )
        .unwrap();
    assert_eq!(allowed.atime, current.atime);
    assert_eq!(allowed.mtime, current.mtime);
    let resized = fs
        .setattr(
            &cx,
            &mut scope,
            allowed.ino,
            &SetAttrRequest {
                size: Some(3),
                mtime: Some(allowed.mtime),
                ..SetAttrRequest::default()
            },
        )
        .unwrap();
    assert_eq!(resized.size, 3);
    assert_eq!(resized.mtime, allowed.mtime);
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    let engine = open_clean_engine(&cx, &dev, vol_bytes);
    engine.check_clean_consistency(&cx).unwrap();
    assert_eq!(
        read_file_by_path(&cx, &engine, "/no-attributes.bin"),
        b"DAT"
    );
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1001)).unwrap();
    let persisted = fs
        .lookup(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("no-attributes.bin"),
        )
        .unwrap();
    assert_eq!(persisted.size, 3);
    assert_eq!(persisted.mtime, allowed.mtime);
}

fn read_file_by_path(cx: &Cx, engine: &NtfsTransactionEngine, path: &str) -> Vec<u8> {
    let vol = engine.volume_view(cx).unwrap();
    let rec = vol.resolve(cx, path).unwrap();
    let stream = vol.data_stream(cx, &rec, &[]).unwrap();
    vol.read(cx, &stream, 0, usize::try_from(stream.size).unwrap())
        .unwrap()
}

#[test]
fn ntfs_sparse_toggle_large_tail_and_hole_punch_fiemap_seek_roundtrip() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0001_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();

    // 1. Create file, mark SPARSE, extend logical tail to 24 MiB (> 16 MiB staging cap!).
    let (file_ref, _) = engine
        .create_file_at(&cx, root, &utf16("sparse.bin"), b"head-prefix")
        .into_result()
        .unwrap();
    engine
        .set_sparse_at(&cx, file_ref, &[], true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    let large_len = 24 * 1024 * 1024_u64;
    engine
        .truncate_stream_at(&cx, file_ref, &[], large_len, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();

    // Write 12 KiB (3 clusters) at offset 20 MiB without allocating the 20 MiB hole.
    let write_off = 20 * 1024 * 1024_u64;
    let payload = vec![0x5Au8; 12 * 1024];
    engine
        .write_stream_range(&cx, file_ref, &[], write_off, &payload)
        .into_result()
        .unwrap();

    // Verify sparse savings: allocated << 24 MiB.
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/sparse.bin").unwrap();
        let st = vol.data_stream(&cx, &rec, &[]).unwrap();
        assert_eq!(st.size, large_len);
        assert_eq!(st.allocated, 4 * 4096); // 1 head cluster + 3 clusters at 20 MiB
        assert_eq!(vol.read(&cx, &st, 0, 11).unwrap(), b"head-prefix");
        assert_eq!(vol.read(&cx, &st, 8192, 4096).unwrap(), vec![0_u8; 4096]);
        assert_eq!(
            vol.read(&cx, &st, write_off, payload.len()).unwrap(),
            payload
        );
    }

    // 2. Punch middle 4 KiB cluster of the 12 KiB run -> reclaims 1 cluster!
    engine
        .punch_hole_at(
            &cx,
            file_ref,
            &[],
            write_off + 4096,
            4096,
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/sparse.bin").unwrap();
        let st = vol.data_stream(&cx, &rec, &[]).unwrap();
        assert_eq!(st.allocated, 3 * 4096); // 1 head cluster + 2 remaining clusters at 20 MiB
    }

    // Verify hole zeros + intact surrounding clusters + FIEMAP/SEEK_HOLE/SEEK_DATA via NtfsFs.
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let attr = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("sparse.bin"))
        .unwrap();
    assert_eq!(attr.size, large_len);
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, write_off, 4096).unwrap(),
        vec![0x5Au8; 4096]
    );
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, write_off + 4096, 4096)
            .unwrap(),
        vec![0_u8; 4096]
    );
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, write_off + 8192, 4096)
            .unwrap(),
        vec![0x5Au8; 4096]
    );
    let extents = fs.fiemap(&cx, &mut scope, attr.ino, 0, u64::MAX).unwrap();
    assert_eq!(extents.len(), 3);
    assert_eq!(extents[0].logical, 0);
    assert_eq!(extents[1].logical, write_off);
    assert_eq!(extents[2].logical, write_off + 8192);
    assert_eq!(
        fs.lseek(&cx, &mut scope, attr.ino, 4096, SeekWhence::Data)
            .unwrap(),
        write_off
    );
    assert_eq!(
        fs.lseek(&cx, &mut scope, attr.ino, write_off, SeekWhence::Hole)
            .unwrap(),
        write_off + 4096
    );

    // 3. Punch via FsOps::fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)!
    fs.fallocate(
        &cx,
        &mut scope,
        attr.ino,
        write_off + 8192,
        4096,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
    )
    .unwrap();
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, write_off + 8192, 4096)
            .unwrap(),
        vec![0_u8; 4096]
    );
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    // 4. Disable sparse on a smaller file -> holes materialize to real allocated clusters.
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let (mat_ref, _) = engine
        .create_file_at(&cx, root, &utf16("materialize.bin"), &[])
        .into_result()
        .unwrap();
    engine
        .set_sparse_at(&cx, mat_ref, &[], true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine
        .write_stream_range(&cx, mat_ref, &[], 16384, b"tail!")
        .into_result()
        .unwrap();
    engine
        .set_sparse_at(&cx, mat_ref, &[], false, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    let readback = read_file_by_path(&cx, &engine, "/materialize.bin");
    assert_eq!(readback.len(), 16389);
    assert!(readback[..16384].iter().all(|&b| b == 0));
    assert_eq!(&readback[16384..], b"tail!");
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn ntfs_lznt1_compression_partial_write_truncate_dir_inherit_and_incompressible() {
    let cx = Cx::for_testing();
    for cluster_bytes in [4096_u32, 512_u32] {
        let (dev, vol_bytes) = format_to_fault_device(
            &cx,
            16,
            cluster_bytes,
            NtfsFormatVersion::V3_1,
            0xBD84_0002_0000_0000 | u64::from(cluster_bytes),
        );
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        let root = engine.resolve_path_reference(&cx, "/").unwrap();

        // 1. Compressible 128 KiB payload -> enable LZNT1 compression -> verify real space savings!
        let mut expected = Vec::with_capacity(128 * 1024);
        for _ in 0..4096_u32 {
            expected.extend_from_slice(b"FRANKENFS-LZNT1-COMPRESS-PATTERN");
        }
        let (file_ref, _) = engine
            .create_file_at(&cx, root, &utf16("comp.bin"), &expected)
            .into_result()
            .unwrap();
        engine
            .set_compression_at(&cx, file_ref, true, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        {
            let vol = engine.volume_view(&cx).unwrap();
            let rec = vol.resolve(&cx, "/comp.bin").unwrap();
            let st = vol.data_stream(&cx, &rec, &[]).unwrap();
            assert_eq!(st.size, expected.len() as u64);
            assert!(
                st.allocated < st.size / 4,
                "expected LZNT1 compression savings for cluster={cluster_bytes}: alloc={} size={}",
                st.allocated,
                st.size
            );
        }
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        // 2. Unaligned cross-unit partial overwrite with incompressible pseudo-random bytes!
        let mut incomp = vec![0_u8; (cluster_bytes as usize) * 16];
        let mut lcg = 0x1234_5678_9ABC_DEF0_u64;
        for b in &mut incomp {
            lcg = lcg
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *b = (lcg >> 33) as u8;
        }
        let patch_off = (cluster_bytes as usize) * 8 + 137;
        let patch_len = incomp.len().min(expected.len() - patch_off);
        engine
            .write_stream_range(&cx, file_ref, &[], patch_off as u64, &incomp[..patch_len])
            .into_result()
            .unwrap();
        expected[patch_off..patch_off + patch_len].copy_from_slice(&incomp[..patch_len]);
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        // 3. Extend + write an all-zero unit + shrink!
        let unit_bytes = u64::from(cluster_bytes) * 16;
        let extended_len = expected.len() as u64 + unit_bytes + 777;
        engine
            .truncate_stream_at(&cx, file_ref, &[], extended_len, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        expected.resize(extended_len as usize, 0);
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        let shrunk_len = (unit_bytes + 513).min(expected.len() as u64);
        engine
            .truncate_stream_at(&cx, file_ref, &[], shrunk_len, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        expected.truncate(shrunk_len as usize);
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        // 4. Toggle compression OFF -> decompress cleanly!
        engine
            .set_compression_at(&cx, file_ref, false, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        // 5. Directory compression inheritance: new child created inside compressed dir inherits compression!
        let (dir_ref, _) = engine
            .mkdir_at(&cx, root, &utf16("cdir"))
            .into_result()
            .unwrap();
        engine
            .set_compression_at(&cx, dir_ref, true, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        let child_data = vec![b'A'; (cluster_bytes as usize) * 32];
        let (_child_ref, _) = engine
            .create_file_at(&cx, dir_ref, &utf16("inherited.bin"), &child_data)
            .into_result()
            .unwrap();
        {
            let vol = engine.volume_view(&cx).unwrap();
            let rec = vol.resolve(&cx, "/cdir/inherited.bin").unwrap();
            let st = vol.data_stream(&cx, &rec, &[]).unwrap();
            assert_eq!(st.size, child_data.len() as u64);
            assert!(
                st.allocated < st.size / 4,
                "child did not inherit LZNT1 compression from parent dir"
            );
            assert_eq!(
                read_file_by_path(&cx, &engine, "/cdir/inherited.bin"),
                child_data
            );
        }
        engine.check_clean_consistency(&cx).unwrap();
    }
}

fn raw_chunk_wof_device(
    cx: &Cx,
    wof_initial: &[u8],
) -> (Arc<FaultInjectingNtfsDevice>, u64, NtfsReference) {
    let (dev, vol_bytes) =
        format_to_fault_device(cx, 16, 4096, NtfsFormatVersion::V3_1, 0xBD84_0003_0000_0001);
    let mut engine = open_clean_engine(cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(cx, "/").unwrap();

    // Native XPRESS4K supports raw chunks. Every entry except the last gives
    // the next chunk's payload-relative offset, followed by the chunk bytes.
    assert_ne!(wof_initial, b"");
    let mut backing = Vec::new();
    for chunk in 1..wof_initial.len().div_ceil(4096) {
        backing.extend_from_slice(&u32::try_from(chunk * 4096).unwrap().to_le_bytes());
    }
    backing.extend_from_slice(wof_initial);
    let (wof_ref, _) = engine
        .create_file_at(cx, root, &utf16("wof.bin"), &[])
        .into_result()
        .unwrap();
    engine
        .set_sparse_at(cx, wof_ref, &[], true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine
        .truncate_stream_at(
            cx,
            wof_ref,
            &[],
            wof_initial.len() as u64,
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    engine
        .create_stream(cx, wof_ref, &utf16("WofCompressedData"), &backing)
        .into_result()
        .unwrap();

    // Install authentic WOF reparse point (version=1, provider=2, file_ver=1, alg=0 XPRESS4K)
    // by writing a temporary opaque tag first? No — `set_reparse_point_at` intentionally refuses
    // direct WOF installation; patch `$REPARSE_POINT` cleanly on-disk via a small helper?
    // Even cleaner: verify `validate_writable_reparse_point` refuses manual WOF installation,
    // AND patch the test fixture's record with a real WOF reparse point so `NtfsVolume::data_stream`
    // opens it via `Storage::Wof`!
    let mut wof_body = Vec::with_capacity(16);
    wof_body.extend_from_slice(&1_u32.to_le_bytes());
    wof_body.extend_from_slice(&2_u32.to_le_bytes());
    wof_body.extend_from_slice(&1_u32.to_le_bytes());
    wof_body.extend_from_slice(&0_u32.to_le_bytes());
    let wof_point = NtfsReparsePoint {
        tag: 0x8000_0017,
        guid: None,
        data: NtfsReparseData::Opaque(wof_body),
    };
    assert!(matches!(
        engine.set_reparse_point_at(cx, wof_ref, &wof_point, true, DEFAULT_NTFS_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
    ));
    // Install a valid opaque placeholder reparse point of exact same 24-byte encoded length
    // (`tag=0x9000_0017`, 16-byte identical payload) so `$REPARSE_POINT` attribute & `$Reparse::$R`
    // exist in the MFT record, then flip the 4-byte tag word in the raw image to `0x8000_0017`
    // and recalculate USA fixups — producing a 100% genuine WOF-backed MFT record!
    let placeholder_point = NtfsReparsePoint {
        tag: 0x9000_0017,
        guid: None,
        data: wof_point.data.clone(),
    };
    engine
        .set_reparse_point_at(cx, wof_ref, &placeholder_point, true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    drop(engine);

    // Patch tag `0x9000_0017` -> `0x8000_0017` in both the file MFT record AND `$Extend/$Reparse::$R`
    // so both the `$REPARSE_POINT` attribute and the `$Reparse` index agree on the WOF tag!
    let mut img = dev.snapshot_durable_only();
    let vol_probe = NtfsVolume::from_device(
        cx,
        Box::new(FaultInjectingNtfsDevice::new(img.clone())),
        0,
        vol_bytes,
    )
    .unwrap();
    let reparse_rec_no = vol_probe.resolve(cx, "/$Extend/$Reparse").unwrap().number as usize;
    let mft_base =
        (vol_probe.geometry.mft_cluster() * u64::from(vol_probe.geometry.cluster_bytes())) as usize;
    let rec_len = vol_probe.geometry.record_bytes() as usize;
    let old_tag = 0x9000_0017_u32.to_le_bytes();
    let new_tag = 0x8000_0017_u32.to_le_bytes();
    for rec_no in [wof_ref.record as usize, reparse_rec_no] {
        let mft_rec_off = mft_base + rec_no * rec_len;
        let mut restored =
            ffs_ondisk::ntfs::restore_record(&img[mft_rec_off..mft_rec_off + rec_len], b"FILE")
                .unwrap();
        let mut replaced_count = 0;
        for pos in 0..restored.len().saturating_sub(4) {
            if restored[pos..pos + 4] == old_tag {
                restored[pos..pos + 4].copy_from_slice(&new_tag);
                replaced_count += 1;
            }
        }
        assert!(
            replaced_count >= 1,
            "missing placeholder tag in rec {rec_no}"
        );
        if rec_no == wof_ref.record as usize {
            // Sparse growth correctly leaves ValidDataLength at zero. WOF's
            // provider data represents initialized logical bytes, so its
            // unnamed sparse placeholder must declare that initialized span.
            let mut at = u16::from_le_bytes(restored[20..22].try_into().unwrap()) as usize;
            let mut initialized_data = false;
            while at + 24 <= restored.len() {
                let kind = u32::from_le_bytes(restored[at..at + 4].try_into().unwrap());
                if kind == u32::MAX {
                    break;
                }
                let length =
                    u32::from_le_bytes(restored[at + 4..at + 8].try_into().unwrap()) as usize;
                assert!(length >= 24 && at + length <= restored.len());
                if kind == ffs_ondisk::ntfs::DATA && restored[at + 9] == 0 {
                    assert_eq!(restored[at + 8], 1);
                    assert!(length >= 72);
                    assert_eq!(
                        u16::from_le_bytes(restored[at + 12..at + 14].try_into().unwrap()),
                        ffs_ondisk::ntfs::SPARSE
                    );
                    let logical_size = (wof_initial.len() as u64).to_le_bytes();
                    assert_eq!(&restored[at + 48..at + 56], &logical_size);
                    assert_eq!(&restored[at + 56..at + 64], &0_u64.to_le_bytes());
                    assert_eq!(&restored[at + 64..at + 72], &0_u64.to_le_bytes());
                    restored[at + 56..at + 64].copy_from_slice(&logical_size);
                    initialized_data = true;
                    break;
                }
                at += length;
            }
            assert!(initialized_data, "missing unnamed sparse WOF DATA");
        }
        let usa_off = u16::from_le_bytes([restored[4], restored[5]]) as usize;
        let usa_cnt = u16::from_le_bytes([restored[6], restored[7]]) as usize;
        let token = [0x22_u8, 0x00];
        restored[usa_off..usa_off + 2].copy_from_slice(&token);
        for s in 1..usa_cnt {
            let end = s * 512;
            let orig = [restored[end - 2], restored[end - 1]];
            restored[usa_off + s * 2..usa_off + s * 2 + 2].copy_from_slice(&orig);
            restored[end - 2..end].copy_from_slice(&token);
        }
        img[mft_rec_off..mft_rec_off + rec_len].copy_from_slice(&restored);
    }
    let wof_dev = FaultInjectingNtfsDevice::new(img);
    (wof_dev, vol_bytes, wof_ref)
}

#[test]
fn ntfs_wof_decompression_on_write_materializes_plaintext_and_cleans_reparse() {
    let cx = Cx::for_testing();
    let wof_initial = b"WOF-INITIAL-PLAINTEXT-PAYLOAD-01".repeat(128);
    let (wof_dev, vol_bytes, wof_ref) = raw_chunk_wof_device(&cx, &wof_initial);

    // Confirm reader opens it as genuine WOF and reads exact initial plaintext!
    let mut engine = open_clean_engine(&cx, &wof_dev, vol_bytes);
    assert_eq!(read_file_by_path(&cx, &engine, "/wof.bin"), wof_initial);

    // Perform positioned write -> triggers WOF decompression-on-write!
    engine
        .write_stream_range(&cx, wof_ref, &[], 4, b"DECOMPRESSED!")
        .into_result()
        .unwrap();
    let mut expected = wof_initial;
    expected[4..17].copy_from_slice(b"DECOMPRESSED!");
    assert_eq!(read_file_by_path(&cx, &engine, "/wof.bin"), expected);

    // Verify `WofCompressedData` AND `$REPARSE_POINT` are completely gone!
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/wof.bin").unwrap();
        assert!(vol.reparse_point(&cx, &rec).unwrap().is_none());
        let streams = vol.data_streams(&cx, &rec).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].name, [] as [u16; 0]);
    }
    engine.check_clean_consistency(&cx).unwrap();
    drop(engine);

    // Reopen only durable bytes so cached plaintext cannot hide a lost write
    // or missing persistent cleanup of the WOF provider metadata.
    let durable = FaultInjectingNtfsDevice::new(wof_dev.snapshot_durable_only());
    let reopened = open_clean_engine(&cx, &durable, vol_bytes);
    assert_eq!(read_file_by_path(&cx, &reopened, "/wof.bin"), expected);
    let vol = reopened.volume_view(&cx).unwrap();
    let rec = vol.resolve(&cx, "/wof.bin").unwrap();
    assert!(vol.reparse_point(&cx, &rec).unwrap().is_none());
    let streams = vol.data_streams(&cx, &rec).unwrap();
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].name, [] as [u16; 0]);
    reopened.check_clean_consistency(&cx).unwrap();
}

#[test]
fn ntfs_resident_promotion_preserves_full_cluster_prefix_and_zero_gap() {
    let cx = Cx::for_testing();
    let (device, vol_bytes) =
        format_to_fault_device(&cx, 16, 512, NtfsFormatVersion::V3_1, 0xBD84_0003_0000_0002);
    let mut engine = open_clean_engine(&cx, &device, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let initial: Vec<u8> = (0_usize..512).map(|i| (i % 251) as u8).collect();
    let (reference, _) = engine
        .create_file_at(&cx, root, &utf16("resident.bin"), &initial)
        .into_result()
        .unwrap();
    let volume = engine.volume_view(&cx).unwrap();
    let record = volume.resolve(&cx, "/resident.bin").unwrap();
    assert!(volume.data_stream(&cx, &record, &[]).unwrap().resident());
    let baseline = device.snapshot_durable_only();
    drop(engine);

    for offset in [512, 513, 1027] {
        let device = FaultInjectingNtfsDevice::new(baseline.clone());
        let mut engine = open_clean_engine(&cx, &device, vol_bytes);
        let replacement = b"promoted";
        let mut expected = initial.clone();
        expected.resize(offset + replacement.len(), 0);
        expected[offset..offset + replacement.len()].copy_from_slice(replacement);
        let (size, _) = engine
            .write_stream_at(
                &cx,
                reference,
                &[],
                offset as u64,
                replacement,
                false,
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
        assert_eq!(size, expected.len() as u64);
        assert_eq!(read_file_by_path(&cx, &engine, "/resident.bin"), expected);
        let volume = engine.volume_view(&cx).unwrap();
        let record = volume.resolve(&cx, "/resident.bin").unwrap();
        assert!(!volume.data_stream(&cx, &record, &[]).unwrap().resident());
        engine.check_clean_consistency(&cx).unwrap();
        drop(engine);

        let durable = FaultInjectingNtfsDevice::new(device.snapshot_durable_only());
        let reopened = open_clean_engine(&cx, &durable, vol_bytes);
        assert_eq!(read_file_by_path(&cx, &reopened, "/resident.bin"), expected);
        reopened.check_clean_consistency(&cx).unwrap();
    }
}

#[test]
fn ntfs_wof_multichunk_writes_preserve_untouched_plaintext_and_zero_gaps() {
    let cx = Cx::for_testing();
    let initial: Vec<u8> = (0_usize..3 * 4096 + 137).map(|i| (i % 251) as u8).collect();
    let (device, vol_bytes, reference) = raw_chunk_wof_device(&cx, &initial);
    let baseline = device.snapshot_durable_only();
    let replacement = b"materialized-range";

    for offset in [4, 4096 + 17, initial.len() - 5, initial.len() + 4096 + 11] {
        let device = FaultInjectingNtfsDevice::new(baseline.clone());
        let mut engine = open_clean_engine(&cx, &device, vol_bytes);
        assert_eq!(read_file_by_path(&cx, &engine, "/wof.bin"), initial);

        let mut expected = initial.clone();
        expected.resize(expected.len().max(offset + replacement.len()), 0);
        expected[offset..offset + replacement.len()].copy_from_slice(replacement);
        let (written, _) = engine
            .write_stream_range(&cx, reference, &[], offset as u64, replacement)
            .into_result()
            .unwrap();
        assert_eq!(written, reference);
        assert_eq!(
            read_file_by_path(&cx, &engine, "/wof.bin"),
            expected,
            "materialization at offset {offset} must preserve every untouched chunk"
        );
        engine.check_clean_consistency(&cx).unwrap();
        drop(engine);

        let durable = FaultInjectingNtfsDevice::new(device.snapshot_durable_only());
        let reopened = open_clean_engine(&cx, &durable, vol_bytes);
        assert_eq!(read_file_by_path(&cx, &reopened, "/wof.bin"), expected);
        let volume = reopened.volume_view(&cx).unwrap();
        let record = volume.resolve(&cx, "/wof.bin").unwrap();
        assert!(volume.reparse_point(&cx, &record).unwrap().is_none());
        let streams = volume.data_streams(&cx, &record).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].name, [] as [u16; 0]);
        reopened.check_clean_consistency(&cx).unwrap();
    }
}

#[test]
fn ntfs_wof_zero_length_write_preserves_plaintext_and_eof_at_any_offset() {
    let cx = Cx::for_testing();
    let initial: Vec<u8> = (0_usize..3 * 4096 + 137).map(|i| (i % 251) as u8).collect();
    let (device, vol_bytes, reference) = raw_chunk_wof_device(&cx, &initial);
    let baseline = device.snapshot_durable_only();
    for offset in [initial.len() as u64 + 4096, u64::MAX] {
        let device = FaultInjectingNtfsDevice::new(baseline.clone());
        let mut engine = open_clean_engine(&cx, &device, vol_bytes);
        let (size, _) = engine
            .write_stream_at(
                &cx,
                reference,
                &[],
                offset,
                &[],
                false,
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
        assert_eq!(size, initial.len() as u64);
        assert_eq!(read_file_by_path(&cx, &engine, "/wof.bin"), initial);
        engine.check_clean_consistency(&cx).unwrap();
        drop(engine);
        let durable = FaultInjectingNtfsDevice::new(device.snapshot_durable_only());
        let reopened = open_clean_engine(&cx, &durable, vol_bytes);
        assert_eq!(read_file_by_path(&cx, &reopened, "/wof.bin"), initial);
    }
}

#[test]
fn ntfs_wof_materialization_recovers_complete_plaintext_at_commit_barriers() {
    let cx = Cx::for_testing();
    let initial: Vec<u8> = (0_usize..3 * 4096 + 137).map(|i| (i % 251) as u8).collect();
    let (device, vol_bytes, reference) = raw_chunk_wof_device(&cx, &initial);
    let mut engine = open_clean_engine(&cx, &device, vol_bytes);
    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(matches!(
        engine.write_stream_range(&cancelled, reference, &[], 4101, b"cancelled"),
        NtfsTxOutcome::NotCommitted(FfsError::Cancelled)
    ));
    assert_eq!(device.write_bytes_total(), writes);
    assert_eq!(device.snapshot_live(), before);

    let cuts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = Arc::clone(&cuts);
    let observed_device = Arc::clone(&device);
    engine.set_stage_hook(Some(Box::new(move |event| {
        if matches!(
            event.stage,
            NtfsPersistenceStage::PayloadBarrier
                | NtfsPersistenceStage::LogCommitBarrier
                | NtfsPersistenceStage::TargetMetadataBarrier
        ) {
            captured
                .lock()
                .unwrap()
                .push((event.stage, observed_device.snapshot_durable_only()));
        }
        Ok(())
    })));
    let replacement = b"complete-after-replay";
    let offset = 4101;
    engine
        .write_stream_range(&cx, reference, &[], offset as u64, replacement)
        .into_result()
        .unwrap();
    engine.set_stage_hook(None);
    let mut expected = initial.clone();
    expected[offset..offset + replacement.len()].copy_from_slice(replacement);

    let cuts = std::mem::take(&mut *cuts.lock().unwrap());
    for expected_stage in [
        NtfsPersistenceStage::PayloadBarrier,
        NtfsPersistenceStage::LogCommitBarrier,
        NtfsPersistenceStage::TargetMetadataBarrier,
    ] {
        assert!(
            cuts.iter().any(|(stage, _)| *stage == expected_stage),
            "missing persistence snapshot at {expected_stage:?}"
        );
    }
    for (stage, snapshot) in cuts {
        let recovery_device = FaultInjectingNtfsDevice::new(snapshot);
        let recovered = NtfsTransactionEngine::from_device(
            &cx,
            Arc::clone(&recovery_device) as Arc<dyn ByteDevice>,
            0,
            vol_bytes,
            write_options_recover(),
        )
        .unwrap();
        let committed = stage != NtfsPersistenceStage::PayloadBarrier;
        assert_eq!(
            read_file_by_path(&cx, &recovered, "/wof.bin"),
            if committed { &expected } else { &initial }.clone(),
            "recovered complete plaintext at {stage:?}"
        );
        let volume = recovered.volume_view(&cx).unwrap();
        let record = volume.resolve(&cx, "/wof.bin").unwrap();
        assert_eq!(
            volume.reparse_point(&cx, &record).unwrap().is_none(),
            committed,
            "reparse removal and plaintext publication must agree at {stage:?}"
        );
        recovered.check_clean_consistency(&cx).unwrap();
    }
}

#[test]
fn ntfs_secure_intern_dedup_multistripe_256k_inheritance_hardlink_dacl_sacl_and_ntfs30() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        24,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0004_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();

    let alice_sid = NtfsSid {
        authority: 5,
        subauthorities: vec![88, 1, 1001],
    };
    let bob_sid = NtfsSid {
        authority: 5,
        subauthorities: vec![88, 1, 1002],
    };
    let grp_sid = NtfsSid {
        authority: 5,
        subauthorities: vec![88, 2, 2000],
    };
    let creator_owner = NtfsSid::creator_owner();

    // 1. Build a descriptor with SACL + DENY-before-ALLOW DACL + inheritable OI/CI/IO ACEs.
    let sd_parent = NtfsSecurityDescriptor {
        resource_manager_control: 0,
        control: SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT,
        owner: Some(alice_sid.clone()),
        group: Some(grp_sid.clone()),
        sacl: NtfsAcl {
            present: true,
            offset: 0,
            revision: Some(2),
            ace_count: Some(1),
            size: None,
            aces: vec![build_simple_ace(
                ACE_TYPE_SYSTEM_AUDIT,
                0xC0 | ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT,
                FILE_WRITE_DATA,
                NtfsSid::world_everyone(),
            )],
            padding: Vec::new(),
        },
        dacl: NtfsAcl {
            present: true,
            offset: 0,
            revision: Some(2),
            ace_count: Some(3),
            size: None,
            aces: vec![
                // Explicit DENY write for Bob (inheritable to files & subdirs)
                build_simple_ace(
                    ACE_TYPE_ACCESS_DENIED,
                    ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT,
                    FILE_WRITE_DATA,
                    bob_sid.clone(),
                ),
                // Inherit-only CREATOR_OWNER full access -> replaced with owner on child!
                build_simple_ace(
                    ACE_TYPE_ACCESS_ALLOWED,
                    ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_INHERIT_ONLY,
                    FILE_ALL_ACCESS,
                    creator_owner,
                ),
                // Broad ALLOW Everyone read+write (Bob's earlier DENY MUST beat this!)
                build_simple_ace(
                    ACE_TYPE_ACCESS_ALLOWED,
                    ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT,
                    FILE_READ_DATA | FILE_WRITE_DATA,
                    NtfsSid::world_everyone(),
                ),
            ],
            padding: Vec::new(),
        },
    };
    let parent_sd_bytes = sd_parent.encode().unwrap();

    let (dir_a, _) = engine
        .mkdir_at(&cx, root, &utf16("sec_a"))
        .into_result()
        .unwrap();
    let (dir_b, _) = engine
        .mkdir_at(&cx, root, &utf16("sec_b"))
        .into_result()
        .unwrap();
    let id_a = engine
        .set_security_at(&cx, dir_a, &parent_sd_bytes, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap()
        .0
        .expect("NTFS 3.1 must assign $Secure security_id");
    let id_b = engine
        .set_security_at(&cx, dir_b, &parent_sd_bytes, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap()
        .0
        .expect("NTFS 3.1 must assign $Secure security_id");
    // Exact `$SDH` hash + byte deduplication!
    assert_eq!(id_a, id_b);

    // 2. Create child inside `sec_a` -> verify inheritance + DENY-before-ALLOW!
    let (child_ref, _) = engine
        .create_file_at(&cx, dir_a, &utf16("secret.txt"), b"classified")
        .into_result()
        .unwrap();
    let bob_tok = NtfsAccessToken {
        user: bob_sid.clone(),
        groups: vec![grp_sid.clone()],
    };
    let alice_tok = NtfsAccessToken {
        user: alice_sid.clone(),
        groups: vec![grp_sid.clone()],
    };
    assert!(
        engine
            .check_access(&cx, child_ref, &alice_tok, FILE_WRITE_DATA)
            .unwrap()
    );
    assert!(
        engine
            .check_access(&cx, child_ref, &bob_tok, FILE_READ_DATA)
            .unwrap()
    );
    assert!(
        !engine
            .check_access(&cx, child_ref, &bob_tok, FILE_WRITE_DATA)
            .unwrap(),
        "explicit DENY ACE must beat subsequent ALLOW Everyone ACE"
    );
    {
        let vol = engine.volume_view(&cx).unwrap();
        let secret_rec = vol.resolve(&cx, "/sec_a/secret.txt").unwrap();
        let info = vol.security_descriptor(&cx, &secret_rec).unwrap();
        assert!(
            info.descriptor
                .dacl
                .aces
                .iter()
                .any(|a| (a.flags & ACE_FLAG_INHERITED) != 0)
        );
        assert!(info.descriptor.sacl.present && info.descriptor.sacl.aces.len() == 1);
    }

    // 3. Hard-link `secret.txt` into `sec_b/alias.txt`: security update applies to both links!
    engine
        .link_at(&cx, child_ref, dir_b, &utf16("alias.txt"))
        .into_result()
        .unwrap();
    let patch_owner = NtfsSecurityPatch {
        owner: Some(bob_sid.clone()),
        ..NtfsSecurityPatch::default()
    };
    engine
        .patch_security_at(&cx, child_ref, &patch_owner, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec_a = vol.resolve(&cx, "/sec_a/secret.txt").unwrap();
        let rec_b = vol.resolve(&cx, "/sec_b/alias.txt").unwrap();
        let info_a = vol.security_descriptor(&cx, &rec_a).unwrap();
        let info_b = vol.security_descriptor(&cx, &rec_b).unwrap();
        assert_eq!(info_a.security_id, info_b.security_id);
        assert_eq!(info_a.descriptor.owner.as_ref(), Some(&bob_sid));
        // SACL preserved across patch!
        assert_eq!(info_a.descriptor.sacl.aces.len(), 1);
    }

    // 4. Push `$Secure::$SDS` across the 256 KiB even/odd stripe mirror boundary AND
    //    split `$SII`/`$SDH` into external `INDX` blocks!
    let (target_ref, _) = engine
        .create_file_at(&cx, root, &utf16("stripe_driver.bin"), b"x")
        .into_result()
        .unwrap();
    // These 60-ACE descriptors encode to 1,988 bytes: 130 total only 258,440
    // bytes, below 256 KiB. 140 distinct descriptors cross that boundary.
    for round in 0_u32..140 {
        let mut aces = Vec::with_capacity(60);
        for k in 0_u32..60 {
            aces.push(build_simple_ace(
                ACE_TYPE_ACCESS_ALLOWED,
                0,
                FILE_READ_DATA,
                NtfsSid {
                    authority: 5,
                    subauthorities: vec![21, 9000 + round, 100 + k, 1000 + round * 64 + k],
                },
            ));
        }
        let big_sd = NtfsSecurityDescriptor {
            resource_manager_control: 0,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
            owner: Some(alice_sid.clone()),
            group: Some(grp_sid.clone()),
            sacl: NtfsAcl {
                present: false,
                offset: 0,
                revision: None,
                ace_count: None,
                size: None,
                aces: Vec::new(),
                padding: Vec::new(),
            },
            dacl: NtfsAcl {
                present: true,
                offset: 0,
                revision: Some(2),
                ace_count: Some(aces.len() as u16),
                size: None,
                aces,
                padding: Vec::new(),
            },
        };
        let raw = big_sd.encode().unwrap();
        engine
            .set_security_at(&cx, target_ref, &raw, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
    }
    {
        let vol = engine.volume_view(&cx).unwrap();
        let sec_rep = vol
            .check_security_references(&cx, SecurityCheckLimits::default(), 1_048_576)
            .unwrap();
        assert!(
            sec_rep.is_consistent(),
            "multi-stripe $Secure check failed: {:?}",
            sec_rep.issues
        );
        assert!(sec_rep.store.security_ids >= 140);
        assert!(
            sec_rep.store.index_blocks >= 2,
            "expected external $SII/$SDH INDX split"
        );
        assert!(
            sec_rep.store.descriptor_bytes > 262_144,
            "expected >256 KiB $SDS multi-stripe"
        );
    }

    // 5. Mapped-SID `NtfsFs`: chmod/chown preserve SACL & enforce DACL PermissionDenied!
    let mapped_policy = NtfsSidPolicy::Mapped {
        caller_uid: 1001,
        caller_gid: 2000,
        map: NtfsSidMap {
            enforce_acl: true,
            posix_nfs_sids: true,
            fallback_uid: 0,
            fallback_gid: 0,
            ..NtfsSidMap::default()
        },
    };
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, mapped_policy).unwrap();
    let mut scope = RequestScope::empty();
    let dir_attr = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("sec_a"))
        .unwrap();
    assert_eq!(dir_attr.uid, 1001);
    assert_eq!(dir_attr.gid, 2000);
    let sec_file = fs
        .lookup(&cx, &mut scope, dir_attr.ino, OsStr::new("secret.txt"))
        .unwrap();
    assert_eq!(sec_file.uid, 1002); // Bob owns it after step 3
    let updated = fs
        .setattr(
            &cx,
            &mut scope,
            sec_file.ino,
            &SetAttrRequest {
                mode: Some(0o640),
                uid: Some(1001),
                ..SetAttrRequest::default()
            },
        )
        .unwrap();
    assert_eq!(updated.uid, 1001);
    assert_eq!(updated.perm & 0o777, 0o640);
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    // Reopen as Bob (uid=1002, not in group 2000, mode=0o640 -> other=0 -> DENIED read!).
    let eng2 = open_clean_engine(&cx, &dev, vol_bytes);
    let bob_policy = NtfsSidPolicy::Mapped {
        caller_uid: 1002,
        caller_gid: 2099,
        map: NtfsSidMap {
            enforce_acl: true,
            posix_nfs_sids: true,
            ..NtfsSidMap::default()
        },
    };
    let fs_bob = NtfsFs::from_engine_with_policy(&cx, eng2, bob_policy).unwrap();
    let dir_a_bob = fs_bob
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("sec_a"))
        .unwrap();
    let secret_bob = fs_bob
        .lookup(&cx, &mut scope, dir_a_bob.ino, OsStr::new("secret.txt"))
        .unwrap();
    assert!(matches!(
        fs_bob.read(&cx, &mut scope, secret_bob.ino, 0, 10),
        Err(FfsError::PermissionDenied)
    ));
    drop(fs_bob);

    // 6. Native NTFS 3.0 volume transaction + 0x50 `$SECURITY_DESCRIPTOR` round-trip!
    let (dev30, vol30_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_0,
        0xBD84_0030_0000_0001,
    );
    let mut eng30 = open_clean_engine(&cx, &dev30, vol30_bytes);
    assert_eq!(eng30.version(), [3, 0]);
    let root30 = eng30.resolve_path_reference(&cx, "/").unwrap();
    let (f30, _) = eng30
        .create_file_at(&cx, root30, &utf16("ntfs30.txt"), b"hello-win2k")
        .into_result()
        .unwrap();
    let (assigned30, _) = eng30
        .set_security_at(&cx, f30, &parent_sd_bytes, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    assert!(
        assigned30.is_none(),
        "NTFS 3.0 stores 0x50 $SECURITY_DESCRIPTOR, not $Secure ID"
    );
    assert_eq!(
        read_file_by_path(&cx, &eng30, "/ntfs30.txt"),
        b"hello-win2k"
    );
    let chk30 = check_volume_device(
        &cx,
        Arc::clone(&dev30) as Arc<dyn ByteDevice>,
        0,
        dev30.len_bytes(),
        NtfsCheckLimits::default(),
    )
    .unwrap();
    assert!(chk30.clean, "NTFS 3.0 check failed: {:?}", chk30.issues);
}

fn usn_publication_records(cx: &Cx, volume: &NtfsVolume) -> Vec<UsnRecordV2> {
    let summary = volume.usn_summary(cx).unwrap().expect("active journal");
    let record = volume.record(cx, u64::from(summary.record), None).unwrap();
    let stream = volume.data_stream(cx, &record, &utf16("$J")).unwrap();
    let bytes = volume
        .read(
            cx,
            &stream,
            summary.lowest_valid_usn,
            usize::try_from(summary.next_usn - summary.lowest_valid_usn).unwrap(),
        )
        .unwrap();
    parse_usn_journal_slice(summary.lowest_valid_usn, &bytes).unwrap()
}

#[test]
fn usn_publication_trims_only_complete_pages_and_clusters() {
    let cx = Cx::for_testing();
    // $Max accepts byte-sized allocation deltas, including ones that do not
    // align to either a USN page or an allocation cluster. Sub-page clusters
    // must not turn such a delta into a retained head in the middle of a record.
    for cluster_bytes in [512_u32, 1024, 2048, 4096, 8192] {
        let (dev, vol_bytes) = format_to_fault_device(
            &cx,
            16,
            cluster_bytes,
            NtfsFormatVersion::V3_1,
            0xBD84_0051_0000_0000 | u64::from(cluster_bytes),
        );
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        let name = format!("{}.bin", "j".repeat(80));
        let (file, _) = engine
            .create_file(&cx, "/", &name, b"x")
            .into_result()
            .unwrap();
        let allocation_delta = USN_PAGE_BYTES + u64::from(cluster_bytes) + 7;
        engine
            .enable_usn_journal(&cx, 4096, allocation_delta, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        let mut expected = Vec::new();
        let mut previous_end = 0;
        let mut trimmed = false;
        for index in 0_u8..96 {
            engine
                .write_stream_range(&cx, file, &[], 0, &[index])
                .into_result()
                .unwrap();
            // Reopen the engine from durable bytes; a warmed metadata view
            // cannot hide a corrupt new $Max/$J pair.
            drop(engine);
            engine = open_clean_engine(&cx, &dev, vol_bytes);
            let volume = engine.volume_view(&cx).unwrap();
            let summary = volume.usn_summary(&cx).unwrap().expect("active journal");
            assert_eq!(summary.allocation_delta, allocation_delta);
            let records = usn_publication_records(&cx, &volume);
            expected.extend(
                records
                    .iter()
                    .filter(|record| record.usn >= previous_end)
                    .cloned(),
            );
            previous_end = summary.next_usn;
            assert_eq!(records.last().unwrap().file_ref, file);
            assert_eq!(records.last().unwrap().name, utf16(&name));
            assert_eq!(
                read_file_by_path(&cx, &engine, &format!("/{name}")),
                [index]
            );
            if summary.lowest_valid_usn != 0 {
                assert!(summary.lowest_valid_usn.is_multiple_of(USN_PAGE_BYTES));
                assert!(
                    summary
                        .lowest_valid_usn
                        .is_multiple_of(u64::from(cluster_bytes))
                );
                let retained: Vec<_> = expected
                    .into_iter()
                    .filter(|record| record.usn >= summary.lowest_valid_usn)
                    .collect();
                assert_eq!(records, retained);
                trimmed = true;
                break;
            }
        }
        assert!(trimmed, "must exercise head trimming for {cluster_bytes}");
        engine.check_clean_consistency(&cx).unwrap();
        let report = check_volume_device(
            &cx,
            Arc::clone(&dev) as Arc<dyn ByteDevice>,
            0,
            dev.len_bytes(),
            NtfsCheckLimits::default(),
        )
        .unwrap();
        assert!(report.clean, "cluster {cluster_bytes}: {:?}", report.issues);
    }
}

#[test]
fn usn_publication_initializes_previous_page_padding_before_extending_journal() {
    let cx = Cx::for_testing();
    for cluster_bytes in [512_u32, 4096, 8192] {
        let (dev, vol_bytes) = format_to_fault_device(
            &cx,
            16,
            cluster_bytes,
            NtfsFormatVersion::V3_1,
            0xBD84_0052_0000_0000 | u64::from(cluster_bytes),
        );
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        let name = format!("{}.bin", "p".repeat(80));
        let (file, _) = engine
            .create_file(&cx, "/", &name, b"old")
            .into_result()
            .unwrap();
        engine
            .enable_usn_journal(&cx, 65_536, 4096, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        let mut prepared = None;
        for _ in 0..32 {
            engine
                .write_stream_range(&cx, file, &[], 0, b"old")
                .into_result()
                .unwrap();
            let volume = engine.volume_view(&cx).unwrap();
            let summary = volume.usn_summary(&cx).unwrap().expect("active journal");
            let records = usn_publication_records(&cx, &volume);
            let next_offset =
                align_usn_offset(summary.next_usn, records.last().unwrap().encoded_len());
            if next_offset > summary.next_usn {
                prepared = Some((volume, summary, records, next_offset));
                break;
            }
        }
        let (volume, before, previous, next_offset) = prepared.expect("page-edge fixture");
        let record = volume.record(&cx, u64::from(before.record), None).unwrap();
        let catalog = volume.attributes(&cx, &record).unwrap();
        let mut seed = dev.snapshot_durable_only();
        let mut poisoned = 0;
        // Bytes beyond the old logical EOF are not initialized file data.
        // A native producer may leave any prior allocation contents there.
        for attr in catalog.all().unwrap() {
            if attr.kind != ffs_ondisk::ntfs::DATA || attr.name != utf16("$J") {
                continue;
            }
            let ffs_ondisk::ntfs::NtfsValue::NonResident(nr) = attr.value else {
                panic!("$J must be nonresident");
            };
            let runs = ffs_ondisk::ntfs::decode_mapping_pairs(
                nr.mapping_pairs,
                nr.first_vcn,
                nr.last_vcn,
                volume.geometry.cluster_count(),
            )
            .unwrap();
            let cb = u64::from(cluster_bytes);
            for run in runs {
                let Some(lcn) = run.lcn else { continue };
                let start = before.next_usn.max(run.vcn * cb);
                let end = next_offset.min((run.vcn + run.clusters) * cb);
                if start < end {
                    let physical =
                        volume.geometry.cluster_offset(lcn).unwrap() + start - run.vcn * cb;
                    let at = usize::try_from(physical).unwrap();
                    let len = usize::try_from(end - start).unwrap();
                    seed[at..at + len].fill(0xA7);
                    poisoned += len;
                }
            }
        }
        assert_eq!(poisoned as u64, next_offset - before.next_usn);
        drop(engine);
        let dev = FaultInjectingNtfsDevice::new(seed);
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        assert_eq!(
            usn_publication_records(&cx, &engine.volume_view(&cx).unwrap()),
            previous
        );
        engine
            .write_stream_range(&cx, file, &[], 0, b"new")
            .into_result()
            .unwrap();
        drop(engine);
        let engine = open_clean_engine(&cx, &dev, vol_bytes);
        let volume = engine.volume_view(&cx).unwrap();
        let after = usn_publication_records(&cx, &volume);
        assert_eq!(&after[..previous.len()], previous);
        assert_eq!(after.len(), previous.len() + 1);
        assert_eq!(after.last().unwrap().usn, next_offset);
        assert_eq!(read_file_by_path(&cx, &engine, &format!("/{name}")), b"new");
        let record = volume.record(&cx, u64::from(before.record), None).unwrap();
        let journal = volume.data_stream(&cx, &record, &utf16("$J")).unwrap();
        let padding = volume
            .read(
                &cx,
                &journal,
                before.next_usn,
                usize::try_from(next_offset - before.next_usn).unwrap(),
            )
            .unwrap();
        assert!(padding.iter().all(|&byte| byte == 0));
        engine.check_clean_consistency(&cx).unwrap();
        let report = check_volume_device(
            &cx,
            Arc::clone(&dev) as Arc<dyn ByteDevice>,
            0,
            dev.len_bytes(),
            NtfsCheckLimits::default(),
        )
        .unwrap();
        assert!(report.clean, "cluster {cluster_bytes}: {:?}", report.issues);
    }
}

#[test]
fn usn_publication_refuses_uninitialized_existing_tail_without_writes() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0053_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    engine.grow_mft(&cx, 64).into_result().unwrap();
    let (file, _) = engine
        .create_file(&cx, "/", "uninitialized-journal.bin", b"old")
        .into_result()
        .unwrap();
    engine
        .enable_usn_journal(&cx, 65_536, 4096, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine
        .write_stream_range(&cx, file, &[], 0, b"old")
        .into_result()
        .unwrap();
    let volume = engine.volume_view(&cx).unwrap();
    let summary = volume.usn_summary(&cx).unwrap().expect("active journal");
    assert!(summary.next_usn > 0);
    let record = volume.record(&cx, u64::from(summary.record), None).unwrap();
    let record_bytes = volume.geometry.record_bytes() as usize;
    let mut restored = record.used_bytes().to_vec();
    restored.resize(record_bytes, 0);
    let mut position = usize::from(u16::from_le_bytes(restored[20..22].try_into().unwrap()));
    let mut patched = false;
    loop {
        let kind = u32::from_le_bytes(restored[position..position + 4].try_into().unwrap());
        if kind == u32::MAX {
            break;
        }
        let length =
            u32::from_le_bytes(restored[position + 4..position + 8].try_into().unwrap()) as usize;
        let name_len = usize::from(restored[position + 9]);
        let name_at = position
            + usize::from(u16::from_le_bytes(
                restored[position + 10..position + 12].try_into().unwrap(),
            ));
        if kind == ffs_ondisk::ntfs::DATA
            && name_len == 2
            && restored[name_at..name_at + 4] == [b'$', 0, b'J', 0]
        {
            assert_eq!(restored[position + 8], 1);
            // A valid nonresident stream can have initialized length below
            // its logical EOF. Its physical tail must remain invisible.
            restored[position + 56..position + 64].copy_from_slice(&0_u64.to_le_bytes());
            patched = true;
        }
        position += length;
    }
    assert!(patched, "fixture has a base $J attribute");
    let protected = ffs_ondisk::ntfs::protect_record(&restored).unwrap();
    let mut seed = dev.snapshot_durable_only();
    let logical_start = u64::from(summary.record) * record_bytes as u64;
    let logical_end = logical_start + record_bytes as u64;
    let cb = u64::from(volume.geometry.cluster_bytes());
    let mft = volume.record(&cx, 0, None).unwrap();
    let mft_attributes = volume.attributes(&cx, &mft).unwrap();
    let mut replaced = 0;
    for attr in mft_attributes.all().unwrap() {
        if attr.kind != ffs_ondisk::ntfs::DATA || !attr.name.is_empty() {
            continue;
        }
        let ffs_ondisk::ntfs::NtfsValue::NonResident(nr) = attr.value else {
            panic!("$MFT must be nonresident");
        };
        for run in ffs_ondisk::ntfs::decode_mapping_pairs(
            nr.mapping_pairs,
            nr.first_vcn,
            nr.last_vcn,
            volume.geometry.cluster_count(),
        )
        .unwrap()
        {
            let start = logical_start.max(run.vcn * cb);
            let end = logical_end.min((run.vcn + run.clusters) * cb);
            if start < end {
                let lcn = run.lcn.expect("allocated $MFT run");
                let physical = volume.geometry.cluster_offset(lcn).unwrap() + start - run.vcn * cb;
                let at = usize::try_from(physical).unwrap();
                let from = usize::try_from(start - logical_start).unwrap();
                let len = usize::try_from(end - start).unwrap();
                seed[at..at + len].copy_from_slice(&protected[from..from + len]);
                replaced += len;
            }
        }
    }
    assert_eq!(replaced, record_bytes);
    drop(engine);
    let dev = FaultInjectingNtfsDevice::new(seed);
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let before = dev.snapshot_durable_only();
    let writes = dev.write_bytes_total();
    let outcome = engine.write_stream_range(&cx, file, &[], 0, b"new");
    assert!(
        matches!(
            outcome,
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(ref detail))
                if detail.contains("fully initialized existing journal")
        ),
        "{outcome:?}"
    );
    assert_eq!(dev.write_bytes_total(), writes);
    assert_eq!(dev.snapshot_live(), before);
    assert_eq!(dev.snapshot_durable_only(), before);
    assert_eq!(
        read_file_by_path(&cx, &engine, "/uninitialized-journal.bin"),
        b"old"
    );
}

#[test]
fn ntfs_reparse_symlink_junction_opaque_objid_usnjrnl_ea_and_refusals() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0005_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();

    // 1. Enable active `$Extend/$UsnJrnl` with small 8 KiB max so we also prove sparse head trimming!
    let (_usn_ref, _) = engine
        .enable_usn_journal(&cx, 8192, 4096, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();

    // 2. Symlink + mount-point junction + opaque reparse preservation & refusal!
    let (_sym_ref, _) = engine
        .create_symlink_at(
            &cx,
            root,
            &utf16("rel_link"),
            &utf16("sub\\target.txt"),
            true,
            false,
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    let (junc_dir, _) = engine
        .mkdir_at(&cx, root, &utf16("junction_dir"))
        .into_result()
        .unwrap();
    let mount_point = NtfsReparsePoint {
        tag: MOUNT_POINT_TAG,
        guid: None,
        data: NtfsReparseData::MountPoint {
            substitute: utf16("\\??\\C:\\mounted"),
            print: utf16("C:\\mounted"),
        },
    };
    engine
        .set_reparse_point_at(&cx, junc_dir, &mount_point, false, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();

    // Opaque third-party tag (0x9000_101A): refused without allow_opaque, admitted with allow_opaque.
    let (opaque_file, _) = engine
        .create_file_at(&cx, root, &utf16("cloud_placeholder.bin"), b"backing")
        .into_result()
        .unwrap();
    let opaque_rp = NtfsReparsePoint {
        tag: 0x9000_101A,
        guid: None,
        data: NtfsReparseData::Opaque(vec![0xFE, 0xCA, 0x01, 0x02, 0x03, 0x04]),
    };
    assert!(matches!(
        engine.set_reparse_point_at(&cx, opaque_file, &opaque_rp, false, DEFAULT_NTFS_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
    ));
    engine
        .set_reparse_point_at(&cx, opaque_file, &opaque_rp, true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    // Ordinary $DATA read & write MUST fail closed while metadata/rename preserve opaque payload!
    {
        let vol = engine.volume_view(&cx).unwrap();
        assert!(matches!(
            vol.resolve(&cx, "/cloud_placeholder.bin"),
            Err(FfsError::UnsupportedFeature(_))
        ));
        let rec = vol
            .resolve_no_follow(&cx, "/cloud_placeholder.bin")
            .unwrap();
        assert!(matches!(
            vol.data_stream(&cx, &rec, &[]),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
    assert!(matches!(
        engine.write_stream_range(&cx, opaque_file, &[], 0, b"nope"),
        NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
    ));
    engine
        .rename_at(
            &cx,
            root,
            &utf16("cloud_placeholder.bin"),
            root,
            &utf16("cloud_moved.bin"),
            opaque_file,
            true,
        )
        .into_result()
        .unwrap();
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve_no_follow(&cx, "/cloud_moved.bin").unwrap();
        let rp = vol.reparse_point(&cx, &rec).unwrap().unwrap();
        assert_eq!(rp, opaque_rp);
    }

    // 3. `$OBJECT_ID` (`0x40`) + `$Extend/$ObjId::$O` uniqueness & cleanup!
    let (f1, _) = engine
        .create_file_at(&cx, root, &utf16("obj1.bin"), b"one")
        .into_result()
        .unwrap();
    let (f2, _) = engine
        .create_file_at(&cx, root, &utf16("obj2.bin"), b"two")
        .into_result()
        .unwrap();
    let oid = NtfsObjectIdData {
        object_id: [0x11; 16],
        birth_volume_id: [0x22; 16],
        birth_object_id: [0x33; 16],
        domain_id: [0x00; 16],
    };
    engine
        .set_object_id_at(&cx, f1, oid, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    // Duplicate GUID on a different file MUST fail with Exists!
    let dup_oid = engine.set_object_id_at(&cx, f2, oid, DEFAULT_NTFS_FILETIME);
    assert!(
        matches!(dup_oid, NtfsTxOutcome::NotCommitted(FfsError::Exists)),
        "expected duplicate object ID to fail with Exists, got {dup_oid:?}"
    );
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/obj1.bin").unwrap();
        assert_eq!(vol.object_id(&cx, &rec).unwrap(), Some(oid));
    }
    engine
        .remove_object_id_at(&cx, f1, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    // Once removed from f1, f2 may claim the same GUID cleanly!
    engine
        .set_object_id_at(&cx, f2, oid, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine
        .unlink_at(&cx, root, &utf16("obj2.bin"), f2)
        .into_result()
        .unwrap();

    // 4. Drive > 160 USN records (exceeding 8 KiB + 4 KiB delta => triggers 4 KiB page pad + head trim!).
    for i in 0_u32..165 {
        let payload = format!("usn-update-{i:04}");
        engine
            .write_stream_range(&cx, f1, &[], 0, payload.as_bytes())
            .into_result()
            .unwrap();
    }
    {
        let vol = engine.volume_view(&cx).unwrap();
        let summary = vol.usn_summary(&cx).unwrap().expect("active $UsnJrnl");
        assert!(
            summary.next_usn > 12_288,
            "expected USN journal growth past 12 KiB"
        );
        assert!(
            summary.lowest_valid_usn >= 4096,
            "expected sparse head trimming to advance lowest_valid_usn: {summary:?}"
        );
        assert!(summary.records_inspected >= 10);
    }

    // 5. Native `$EA` + mounted `FsOps::{symlink, setxattr, getxattr, listxattr, removexattr}`!
    engine
        .set_ea_at(&cx, f1, b"user.tag", b"v1", 0, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let f1_attr = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("obj1.bin"))
        .unwrap();
    assert_eq!(
        fs.getxattr(&cx, f1_attr.ino, "user.tag").unwrap(),
        Some(b"v1".to_vec())
    );
    fs.setxattr(
        &cx,
        &mut scope,
        f1_attr.ino,
        "user.extra",
        b"hello-ea",
        XattrSetMode::Create,
    )
    .unwrap();
    assert!(matches!(
        fs.setxattr(
            &cx,
            &mut scope,
            f1_attr.ino,
            "user.extra",
            b"dup",
            XattrSetMode::Create,
        ),
        Err(FfsError::Exists)
    ));
    let keys = fs.listxattr(&cx, f1_attr.ino).unwrap();
    assert_eq!(keys, vec!["user.extra".to_owned(), "user.tag".to_owned()]);
    assert!(
        fs.removexattr(&cx, &mut scope, f1_attr.ino, "user.tag")
            .unwrap()
    );
    assert_eq!(fs.getxattr(&cx, f1_attr.ino, "user.tag").unwrap(), None);

    // Mounted relative symlink creation + readlink round-trip!
    let sl = fs
        .symlink(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("fs_sym"),
            Path::new("dir/file.txt"),
            1000,
            1000,
        )
        .unwrap();
    assert_eq!(sl.kind, FileType::Symlink);
    assert_eq!(
        fs.readlink(&cx, &mut scope, sl.ino).unwrap(),
        b"dir/file.txt"
    );
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    // Whole-volume non-mutating check must be 100% clean (including active `$UsnJrnl` + reparse)!
    let chk = check_volume_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        dev.len_bytes(),
        NtfsCheckLimits::default(),
    )
    .unwrap();
    assert!(
        chk.clean,
        "check failed after secondary metadata ops: {:?}",
        chk.issues
    );
}

#[test]
fn ntfs_efs_encrypt_raw_keyed_rw_decrypt_negative_controls_and_redaction() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0006_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();

    let key = NtfsEfsKey::from_raw_bytes([0xA5; 32]);
    let wrong_key = NtfsEfsKey::from_raw_bytes([0x5A; 32]);
    let mut good_scope = StaticEfsKeyScope::new();
    good_scope.insert(key.clone());
    let mut bad_scope = StaticEfsKeyScope::new();
    bad_scope.insert(wrong_key);
    let empty_scope = StaticEfsKeyScope::new();

    // Redaction invariant: key bytes never appear in Debug or Display.
    assert!(!format!("{key:?}").contains("a5a5a5"));
    assert!(!format!("{key}").contains("a5a5a5"));

    let plaintext = b"TOP-SECRET-EFS-PAYLOAD-ACROSS-MULTIPLE-512B-SECTORS!".repeat(30); // 1560 bytes
    let (f_ref, _) = engine
        .create_file_at(&cx, root, &utf16("vault.bin"), &plaintext)
        .into_result()
        .unwrap();
    engine
        .encrypt_file_at(&cx, f_ref, &key, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();

    // 1. Unauthorized ordinary stream read & write MUST fail closed!
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/vault.bin").unwrap();
        assert!(matches!(
            vol.data_stream(&cx, &rec, &[]),
            Err(FfsError::UnsupportedFeature(_))
        ));
        let (_meta, info) = vol.efs_metadata(&cx, &rec).unwrap().unwrap();
        assert!(info.encrypted_flag_set && info.explicit_fek_profile);
        let (raw_sz, raw_cipher) = vol.read_raw_efs_ciphertext(&cx, &rec, 0, 2048).unwrap();
        assert_eq!(raw_sz, plaintext.len() as u64);
        assert_ne!(
            &raw_cipher[..plaintext.len()],
            plaintext.as_slice(),
            "ciphertext must not leak plaintext"
        );
        // Missing key and wrong key MUST return PermissionDenied!
        assert!(matches!(
            vol.read_efs_plaintext(&cx, &rec, &empty_scope, 0, 2048),
            Err(FfsError::PermissionDenied)
        ));
        assert!(matches!(
            vol.read_efs_plaintext(&cx, &rec, &bad_scope, 0, 2048),
            Err(FfsError::PermissionDenied)
        ));
        // Authorized scope decrypts exact bytes (including unaligned middle slice)!
        assert_eq!(
            vol.read_efs_plaintext(&cx, &rec, &good_scope, 0, 4096)
                .unwrap(),
            plaintext
        );
        assert_eq!(
            vol.read_efs_plaintext(&cx, &rec, &good_scope, 500, 120)
                .unwrap(),
            plaintext[500..620]
        );
    }
    assert!(matches!(
        engine.write_stream_range(&cx, f_ref, &[], 0, b"blocked"),
        NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
    ));
    assert!(matches!(
        engine.write_efs_stream_at(&cx, f_ref, &bad_scope, 0, b"nope", DEFAULT_NTFS_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::PermissionDenied)
    ));

    // 2. Authorized keyed positioned write + decrypt round-trip!
    engine
        .write_efs_stream_at(
            &cx,
            f_ref,
            &good_scope,
            510,
            b"KEYED-SECTOR-CROSSING-UPDATE",
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    let mut expected = plaintext;
    expected[510..538].copy_from_slice(b"KEYED-SECTOR-CROSSING-UPDATE");
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/vault.bin").unwrap();
        assert_eq!(
            vol.read_efs_plaintext(&cx, &rec, &good_scope, 0, 4096)
                .unwrap(),
            expected
        );
    }

    engine
        .decrypt_file_at(&cx, f_ref, &good_scope, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    assert_eq!(read_file_by_path(&cx, &engine, "/vault.bin"), expected);
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/vault.bin").unwrap();
        assert!(vol.efs_metadata(&cx, &rec).unwrap().is_none());
    }
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn ntfs_transforms_persistence_prefix_fault_cuts_and_cx_cancel() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0007_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let _ = engine
        .enable_usn_journal(&cx, 65_536, 4096, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    let (f_ref, _) = engine
        .create_file_at(&cx, root, &utf16("crash.bin"), &vec![b'Z'; 32 * 1024])
        .into_result()
        .unwrap();

    // Pre-cancelled Cx MUST fail without mutating backing storage!
    let before_cancel = dev.snapshot_durable_only();
    let cancelled_cx = Cx::for_testing();
    cancelled_cx.set_cancel_requested(true);
    assert!(matches!(
        engine.set_compression_at(&cancelled_cx, f_ref, true, DEFAULT_NTFS_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::Cancelled)
    ));
    assert_eq!(dev.snapshot_durable_only(), before_cancel);

    // Fault-cut during LZNT1 compression transaction right after LogCommitBarrier (winner redo)!
    let cut_snapshot: Arc<std::sync::Mutex<Option<Vec<u8>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let cap_dev = Arc::clone(&dev);
    let cap_slot = Arc::clone(&cut_snapshot);
    engine.set_stage_hook(Some(Box::new(move |event| {
        if event.stage == NtfsPersistenceStage::LogCommitBarrier {
            *cap_slot.lock().unwrap() = Some(cap_dev.snapshot_durable_only());
        }
        Ok(())
    })));
    engine
        .set_compression_at(&cx, f_ref, true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine.set_stage_hook(None);

    // Recover the torn post-commit cut image -> ARIES redo MUST complete the compression cleanly!
    let torn_img = cut_snapshot.lock().unwrap().take().expect("captured cut");
    let torn_dev = FaultInjectingNtfsDevice::new(torn_img);
    let recovered = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&torn_dev) as Arc<dyn ByteDevice>,
        0,
        vol_bytes,
        write_options_recover(),
    )
    .unwrap();
    recovered.check_clean_consistency(&cx).unwrap();
    assert_eq!(
        read_file_by_path(&cx, &recovered, "/crash.bin"),
        vec![b'Z'; 32 * 1024]
    );
}
