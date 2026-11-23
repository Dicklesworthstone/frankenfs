//! Comprehensive integration, negative-control, and persistence-prefix fault-cut
//! tests for native NTFS transforms (sparse/hole-punch, LZNT1 compression, WOF
//! decompression-on-write), `$Secure` multi-stripe/inheritance/DACL/SACL + NTFS 3.0
//! `0x50` security, reparse points & `$Extend/$Reparse::$R`, `$OBJECT_ID` &
//! `$Extend/$ObjId::$O`, active `$Extend/$UsnJrnl`, `$EA`, and explicit key-scoped
//! EFS encryption/decryption (`bd-h8n46`).

use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_core::vfs::XattrSetMode;
use ffs_core::{FileType, FsOps, RequestScope, SeekWhence, SetAttrRequest};
use ffs_error::FfsError;
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
use ffs_ondisk::ntfs::reparse::{MOUNT_POINT_TAG, NtfsReparseData, NtfsReparsePoint};
use ffs_ondisk::ntfs_security::{
    ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_INHERIT_ONLY, ACE_FLAG_INHERITED, ACE_FLAG_OBJECT_INHERIT,
    ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_DENIED, ACE_TYPE_SYSTEM_AUDIT, FILE_ALL_ACCESS,
    FILE_READ_DATA, FILE_READ_EA, FILE_WRITE_DATA, FILE_WRITE_EA, NtfsAccessToken, NtfsAcl,
    NtfsSecurityDescriptor, NtfsSid, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
};
use ffs_types::InodeNumber;

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
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, stream_acl_policy(1002)).unwrap();
    let mut scope = RequestScope::empty();
    let before = dev.snapshot_live();
    let durable_before = dev.snapshot_durable_only();
    let writes = dev.write_bytes_total();
    for (name, flags) in [
        ("write-only.bin:read", libc::O_RDONLY),
        ("write-only.bin:read-write", libc::O_RDWR),
    ] {
        assert!(matches!(
            fs.create_open(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new(name),
                0o666,
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
            0o666,
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
            0o666,
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

fn wof_write_fixture(
    cx: &Cx,
    plaintext: &[u8],
    backing: &[u8],
    initialized: usize,
) -> (Arc<FaultInjectingNtfsDevice>, u64) {
    assert!(initialized <= plaintext.len());
    let (dev, vol_bytes) =
        format_to_fault_device(cx, 16, 4096, NtfsFormatVersion::V3_1, 0xBD84_0003_0000_0001);
    let mut engine = open_clean_engine(cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(cx, "/").unwrap();

    // Sparse growth supplies an all-hole placeholder, including a partial
    // final cluster. The provider's initialized span is set explicitly below.
    let (wof_ref, _) = engine
        .create_file_at(cx, root, &utf16("wof.bin"), &[])
        .into_result()
        .unwrap();
    engine
        .set_sparse_at(cx, wof_ref, &[], true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine
        .truncate_stream(cx, wof_ref, &[], plaintext.len() as u64)
        .into_result()
        .unwrap();
    engine
        .create_stream(cx, wof_ref, &utf16("WofCompressedData"), backing)
        .into_result()
        .unwrap();

    // Direct installation is refused. Construct the XPRESS4K provider in the
    // image by replacing an equal-sized opaque tag and its secondary index.
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
    // and recalculate USA fixups.
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
    // Poison every free cluster so allocating a tail without staging its
    // plaintext cannot accidentally pass because the formatter zeroed it.
    let bitmap_record = vol_probe.record(cx, 6, None).unwrap();
    let bitmap_stream = vol_probe.data_stream(cx, &bitmap_record, &[]).unwrap();
    let bitmap = vol_probe
        .read(cx, &bitmap_stream, 0, bitmap_stream.size as usize)
        .unwrap();
    let cluster_bytes = vol_probe.geometry.cluster_bytes() as usize;
    let mut poisoned = 0;
    for cluster in 0..vol_probe.geometry.cluster_count() as usize {
        if bitmap[cluster / 8] & (1 << (cluster % 8)) == 0 {
            img[cluster * cluster_bytes..(cluster + 1) * cluster_bytes].fill(0xD3);
            poisoned += 1;
        }
    }
    assert!(poisoned >= 4);
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
                    assert!(length >= 64);
                    let logical = &restored[at + 48..at + 56];
                    assert_eq!(logical, &(plaintext.len() as u64).to_le_bytes());
                    assert_eq!(&restored[at + 56..at + 64], &0_u64.to_le_bytes());
                    restored[at + 56..at + 64].copy_from_slice(&(initialized as u64).to_le_bytes());
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
    (FaultInjectingNtfsDevice::new(img), vol_bytes)
}

#[test]
fn ntfs_wof_decompression_on_write_materializes_plaintext_and_cleans_reparse() {
    let cx = Cx::for_testing();
    // A single raw XPRESS4K chunk requires no offset table.
    let wof_initial = b"WOF-INITIAL-PLAINTEXT-PAYLOAD-01".repeat(128);
    let (wof_dev, vol_bytes) =
        wof_write_fixture(&cx, &wof_initial, &wof_initial, wof_initial.len());

    // Confirm reader opens it as genuine WOF and reads exact initial plaintext!
    let mut engine = open_clean_engine(&cx, &wof_dev, vol_bytes);
    let wof_ref = engine.resolve_path_reference(&cx, "/wof.bin").unwrap();
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
    let vol = engine.volume_view(&cx).unwrap();
    let rec = vol.resolve(&cx, "/wof.bin").unwrap();
    assert!(vol.reparse_point(&cx, &rec).unwrap().is_none());
    let streams = vol.data_streams(&cx, &rec).unwrap();
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].name, [] as [u16; 0]);
    engine.check_clean_consistency(&cx).unwrap();

    let reopened_device = FaultInjectingNtfsDevice::new(wof_dev.snapshot_durable_only());
    let reopened = open_clean_engine(&cx, &reopened_device, vol_bytes);
    assert_eq!(read_file_by_path(&cx, &reopened, "/wof.bin"), expected);
    reopened.check_clean_consistency(&cx).unwrap();
}

fn multichunk_wof_payload() -> (Vec<u8>, Vec<u8>) {
    // A native XPRESS Huffman chunk: literal A, then a distance-one long
    // match. The other chunks are stored raw, with a partial final chunk.
    let mut compressed = vec![0_u8; 256];
    compressed[usize::from(b'A') / 2] = 0x10;
    compressed[135] = 0x10;
    compressed.extend_from_slice(&[0, 0x40, 0, 0, 0xFF]);
    compressed.extend_from_slice(&4092_u16.to_le_bytes());
    let raw: Vec<_> = (0..4096)
        .map(|index| u8::try_from(index % 251 + 1).unwrap())
        .collect();
    let tail = b"final partial native WOF chunk bytes!";
    let mut backing = Vec::new();
    backing.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_le_bytes());
    backing.extend_from_slice(
        &u32::try_from(compressed.len() + raw.len())
            .unwrap()
            .to_le_bytes(),
    );
    backing.extend_from_slice(&compressed);
    backing.extend_from_slice(&raw);
    backing.extend_from_slice(tail);
    let mut plaintext = vec![b'A'; 4096];
    plaintext.extend_from_slice(&raw);
    plaintext.extend_from_slice(tail);
    (plaintext, backing)
}

fn assert_materialized_wof(cx: &Cx, engine: &NtfsTransactionEngine, expected: &[u8]) {
    assert_eq!(read_file_by_path(cx, engine, "/wof.bin"), expected);
    let volume = engine.volume_view(cx).unwrap();
    let record = volume.resolve(cx, "/wof.bin").unwrap();
    assert!(volume.reparse_point(cx, &record).unwrap().is_none());
    let streams = volume.data_streams(cx, &record).unwrap();
    assert_eq!(streams.len(), 1);
    assert!(streams[0].name.is_empty());
    assert_eq!(
        streams[0].read_profile.as_ref().unwrap().initialized,
        expected.len() as u64
    );
    engine.check_clean_consistency(cx).unwrap();
}

#[test]
fn ntfs_wof_multicluster_writes_preserve_untouched_plaintext_after_reopen() {
    let cx = Cx::for_testing();
    let (plaintext, backing) = multichunk_wof_payload();
    let (seed, vol_bytes) = wof_write_fixture(&cx, &plaintext, &backing, plaintext.len());
    let pristine = seed.snapshot_durable_only();
    let patch = b"DECOMPRESSED!";
    for offset in [
        4,
        4092,
        4096 + 137,
        plaintext.len() - patch.len(),
        plaintext.len(),
        plaintext.len() + 4096 + 17,
    ] {
        let dev = FaultInjectingNtfsDevice::new(pristine.clone());
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        let reference = engine.resolve_path_reference(&cx, "/wof.bin").unwrap();
        assert_eq!(read_file_by_path(&cx, &engine, "/wof.bin"), plaintext);
        let mut expected = plaintext.clone();
        expected.resize(expected.len().max(offset + patch.len()), 0);
        expected[offset..offset + patch.len()].copy_from_slice(patch);
        engine
            .write_stream_range(&cx, reference, &[], offset as u64, patch)
            .into_result()
            .unwrap_or_else(|error| panic!("WOF write at {offset} failed: {error:?}"));
        assert_materialized_wof(&cx, &engine, &expected);
        let durable = dev.snapshot_durable_only();
        drop(engine);
        let reopened_device = FaultInjectingNtfsDevice::new(durable);
        let reopened = open_clean_engine(&cx, &reopened_device, vol_bytes);
        assert_materialized_wof(&cx, &reopened, &expected);
    }
}

#[test]
fn ntfs_wof_empty_writes_materialize_without_extending_file() {
    let cx = Cx::for_testing();
    let (plaintext, backing) = multichunk_wof_payload();
    let (seed, vol_bytes) = wof_write_fixture(&cx, &plaintext, &backing, plaintext.len());
    let pristine = seed.snapshot_durable_only();
    for offset in [u64::MAX, plaintext.len() as u64 + 4096, 0] {
        let dev = FaultInjectingNtfsDevice::new(pristine.clone());
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        let reference = engine.resolve_path_reference(&cx, "/wof.bin").unwrap();
        assert_eq!(read_file_by_path(&cx, &engine, "/wof.bin"), plaintext);
        engine
            .write_stream_range(&cx, reference, &[], offset, &[])
            .into_result()
            .unwrap_or_else(|error| panic!("empty WOF write at {offset} failed: {error:?}"));
        assert_materialized_wof(&cx, &engine, &plaintext);
        let durable = dev.snapshot_durable_only();
        drop(engine);
        let reopened_device = FaultInjectingNtfsDevice::new(durable);
        let reopened = open_clean_engine(&cx, &reopened_device, vol_bytes);
        assert_materialized_wof(&cx, &reopened, &plaintext);
    }
}

#[test]
fn ntfs_wof_materialization_preserves_zero_tail_beyond_valid_data() {
    let cx = Cx::for_testing();
    let (plaintext, backing) = multichunk_wof_payload();
    let initialized = 4096 + 1037;
    let (dev, vol_bytes) = wof_write_fixture(&cx, &plaintext, &backing, initialized);
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let reference = engine.resolve_path_reference(&cx, "/wof.bin").unwrap();
    let mut expected = plaintext;
    expected[initialized..].fill(0);
    assert_eq!(read_file_by_path(&cx, &engine, "/wof.bin"), expected);
    engine
        .write_stream_range(&cx, reference, &[], 4, b"UPDATED")
        .into_result()
        .unwrap();
    expected[4..11].copy_from_slice(b"UPDATED");
    assert_materialized_wof(&cx, &engine, &expected);
    let reopened_device = FaultInjectingNtfsDevice::new(dev.snapshot_durable_only());
    let reopened = open_clean_engine(&cx, &reopened_device, vol_bytes);
    assert_materialized_wof(&cx, &reopened, &expected);
}

#[test]
fn ntfs_wof_invalid_chunk_table_refuses_write_without_mutation() {
    let cx = Cx::for_testing();
    let (plaintext, mut backing) = multichunk_wof_payload();
    // The first compressed chunk is empty: decoding must fail before native
    // metadata or allocation can be published.
    backing[..4].fill(0);
    let (dev, vol_bytes) = wof_write_fixture(&cx, &plaintext, &backing, plaintext.len());
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let reference = engine.resolve_path_reference(&cx, "/wof.bin").unwrap();
    let before = dev.snapshot_live();
    let durable_before = dev.snapshot_durable_only();
    let writes = dev.write_bytes_total();
    assert!(matches!(
        engine.write_stream_range(&cx, reference, &[], 4, b"UPDATED"),
        NtfsTxOutcome::NotCommitted(FfsError::Corruption { .. })
    ));
    assert_eq!(dev.write_bytes_total(), writes);
    assert_eq!(dev.snapshot_live(), before);
    assert_eq!(dev.snapshot_durable_only(), durable_before);
}

#[test]
fn ntfs_resident_spill_preserves_first_cluster_and_initializes_gap() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) =
        format_to_fault_device(&cx, 16, 512, NtfsFormatVersion::V3_1, 0xBD84_0003_0000_0002);
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    for offset in [512_usize, 1536] {
        let name = format!("resident-{offset}");
        let path = format!("/{name}");
        let mut expected = vec![0xA7; 512];
        let (reference, _) = engine
            .create_file_at(&cx, root, &utf16(&name), &expected)
            .into_result()
            .unwrap();
        let volume = engine.volume_view(&cx).unwrap();
        let record = volume.resolve(&cx, &path).unwrap();
        assert!(volume.data_stream(&cx, &record, &[]).unwrap().resident());
        // Exercise the general catalog writer directly, since the path-based
        // fast path can otherwise hide a resident-to-mapped planner failure.
        engine
            .write_stream_at(
                &cx,
                reference,
                &[],
                offset as u64,
                b"tail",
                false,
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
        expected.resize(offset, 0);
        expected.extend_from_slice(b"tail");
        assert_eq!(read_file_by_path(&cx, &engine, &path), expected);
        let reopened_device = FaultInjectingNtfsDevice::new(dev.snapshot_durable_only());
        let reopened = open_clean_engine(&cx, &reopened_device, vol_bytes);
        assert_eq!(read_file_by_path(&cx, &reopened, &path), expected);
        reopened.check_clean_consistency(&cx).unwrap();
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
