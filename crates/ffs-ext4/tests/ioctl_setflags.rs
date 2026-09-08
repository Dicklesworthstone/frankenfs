use asupersync::Cx;
use ffs_core::{Ext4JournalReplayMode, FsOps, OpenFs, OpenOptions, RequestOp, RequestScope};
use ffs_error::FfsError;
use ffs_ondisk::{Ext4IncompatFeatures, ext4_chksum};
use ffs_types::{
    EXT4_COMPR_FL, EXT4_COMPRBLK_FL, EXT4_EXTENTS_FL, EXT4_SB_CHECKSUM_OFFSET,
    EXT4_SUPERBLOCK_OFFSET, InodeNumber,
};
use std::ffi::OsStr;
use std::fs::{File, read, write};
use std::path::{Path, PathBuf};
use std::process::Command;

fn mkfs_ext4_image(name: &str) -> Option<(PathBuf, tempfile::TempDir)> {
    let tmp = tempfile::TempDir::new().expect("tmpdir");
    let image = tmp.path().join(name);
    let file = File::create(&image).expect("create image");
    file.set_len(64 * 1024 * 1024).expect("size image");
    drop(file);

    let mkfs = Command::new("mkfs.ext4")
        .args(["-F", "-b", "4096", image.to_str().expect("utf8 path")])
        .output();
    match mkfs {
        Ok(output) if output.status.success() => {}
        _ => return None,
    }

    let _ = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field / mode 040777",
            image.to_str().expect("utf8 path"),
        ])
        .output();

    Some((image, tmp))
}

fn set_incompat_bits(image: &Path, incompat_bits: u32) {
    let mut bytes = read(image).expect("read ext4 image");
    let sb_off = EXT4_SUPERBLOCK_OFFSET;
    let incompat_off = sb_off + 0x60;
    let checksum_off = sb_off + EXT4_SB_CHECKSUM_OFFSET;
    let mut feature_incompat = u32::from_le_bytes(
        bytes[incompat_off..incompat_off + 4]
            .try_into()
            .expect("feature_incompat bytes"),
    );
    feature_incompat |= incompat_bits;
    bytes[incompat_off..incompat_off + 4].copy_from_slice(&feature_incompat.to_le_bytes());
    let checksum = ext4_chksum(!0u32, &bytes[sb_off..sb_off + EXT4_SB_CHECKSUM_OFFSET]);
    bytes[checksum_off..checksum_off + 4].copy_from_slice(&checksum.to_le_bytes());
    write(image, bytes).expect("rewrite ext4 image");
}

fn open_writable_ext4(image: &Path) -> OpenFs {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, image, &opts).expect("open ext4");
    fs.enable_writes(&cx).expect("enable writes");
    fs
}

fn create_file(fs: &OpenFs, cx: &Cx, name: &str) -> InodeNumber {
    fs.create(cx, InodeNumber(2), OsStr::new(name), 0o644, 0, 0)
        .expect("create file")
        .ino
}

fn ioctl_setflags(fs: &OpenFs, cx: &Cx, ino: InodeNumber, flags: u32) -> Result<(), FfsError> {
    let mut scope = fs
        .begin_request_scope(cx, RequestOp::IoctlWrite)
        .expect("begin ioctl scope");
    let result = fs.set_inode_flags(cx, &mut scope, ino, flags);
    if result.is_ok() {
        fs.commit_request_scope(cx, &mut scope)
            .expect("commit ioctl scope");
    }
    fs.end_request_scope(cx, RequestOp::IoctlWrite, scope)
        .expect("end ioctl scope");
    result
}

#[test]
fn ioctl_setflags_compr_rejects_without_compression_feature() {
    let Some((image, _tmp)) = mkfs_ext4_image("ioctl-setflags.ext4") else {
        return;
    };

    let cx = Cx::for_testing();
    let fs = open_writable_ext4(&image);
    let ino = create_file(&fs, &cx, "reject-compr.txt");

    let err = ioctl_setflags(&fs, &cx, ino, EXT4_COMPR_FL)
        .expect_err("COMPR should be rejected without the feature bit");
    assert!(matches!(err, FfsError::UnsupportedFeature(_)));
}

#[test]
fn ioctl_setflags_compr_accepts_with_compression_feature_and_compresses_writes() {
    let Some((image, _tmp)) = mkfs_ext4_image("ioctl-setflags-compr.ext4") else {
        return;
    };
    set_incompat_bits(&image, Ext4IncompatFeatures::COMPRESSION.0);

    let cx = Cx::for_testing();
    let fs = open_writable_ext4(&image);
    assert!(
        fs.ext4_superblock()
            .expect("ext4 superblock")
            .has_incompat(Ext4IncompatFeatures::COMPRESSION)
    );

    let ino = create_file(&fs, &cx, "accept-compr.txt");
    ioctl_setflags(&fs, &cx, ino, EXT4_COMPR_FL).expect("enable COMPR");

    let mut read_scope = RequestScope::empty();
    let flags = fs
        .get_inode_flags(&cx, &mut read_scope, ino)
        .expect("read flags after setflags");
    assert_ne!(flags & EXT4_COMPR_FL, 0, "COMPR flag should persist");
    assert_eq!(
        flags & EXT4_EXTENTS_FL,
        0,
        "COMPR enable should clear extent mode before e2compr writes"
    );
    assert_eq!((flags >> 23) & 0x7, 2, "cluster shift should seed to 2");
    assert_eq!(((flags >> 26) & 0x1F) as u8, 20, "method should seed to 20");

    let payload = vec![b'Z'; 4096];
    fs.write(&cx, ino, 0, &payload)
        .expect("compressed write after ioctl setflags");
    let readback = fs.read(&cx, ino, 0, 4096).expect("readback");
    assert_eq!(&readback[..payload.len()], payload.as_slice());

    let mut verify_scope = RequestScope::empty();
    let flags_after_write = fs
        .get_inode_flags(&cx, &mut verify_scope, ino)
        .expect("read flags after write");
    assert_ne!(
        flags_after_write & EXT4_COMPRBLK_FL,
        0,
        "compressed writes should mark COMPRBLK"
    );
}
