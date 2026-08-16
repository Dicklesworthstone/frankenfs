use ffs_core::OpenFs;
use std::path::PathBuf;

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

#[test]
fn repro_create() {
    let img_path = PathBuf::from("../ffs-harness/tests/fixtures/images/ext4_small.img");
    if !img_path.exists() {
        return;
    }
    let cx = asupersync::Cx::for_testing();
    let opts = ffs_core::OpenOptions {
        ext4_journal_replay_mode: ffs_core::Ext4JournalReplayMode::SimulateOverlay,
        ..ffs_core::OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, &img_path, &opts).unwrap();
    fs.enable_writes(&cx).unwrap();

    let attr = fs
        .create(
            &cx,
            ffs_types::InodeNumber(2),
            std::ffi::OsStr::new("newfile.txt"),
            0o644,
            1000,
            1000,
        )
        .unwrap();

    let inode = fs.read_inode(&cx, attr.ino).unwrap();
    let magic = u16::from_le_bytes([inode.extent_bytes[0], inode.extent_bytes[1]]);
    assert_eq!(magic, EXT4_EXTENT_MAGIC);
}

#[test]
fn repro_mkdir() {
    let img_path = PathBuf::from("../ffs-harness/tests/fixtures/images/ext4_small.img");
    if !img_path.exists() {
        return;
    }
    let cx = asupersync::Cx::for_testing();
    let opts = ffs_core::OpenOptions {
        ext4_journal_replay_mode: ffs_core::Ext4JournalReplayMode::SimulateOverlay,
        ..ffs_core::OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, &img_path, &opts).unwrap();
    fs.enable_writes(&cx).unwrap();

    let attr = fs
        .mkdir(
            &cx,
            ffs_types::InodeNumber(2),
            std::ffi::OsStr::new("newdir"),
            0o755,
            1000,
            1000,
        )
        .unwrap();

    let inode = fs.read_inode(&cx, attr.ino).unwrap();
    let magic = u16::from_le_bytes([inode.extent_bytes[0], inode.extent_bytes[1]]);
    assert_eq!(magic, EXT4_EXTENT_MAGIC);
}

#[test]
fn repro_symlink() {
    let img_path = PathBuf::from("../ffs-harness/tests/fixtures/images/ext4_small.img");
    if !img_path.exists() {
        return;
    }
    let cx = asupersync::Cx::for_testing();
    let opts = ffs_core::OpenOptions {
        ext4_journal_replay_mode: ffs_core::Ext4JournalReplayMode::SimulateOverlay,
        ..ffs_core::OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, &img_path, &opts).unwrap();
    fs.enable_writes(&cx).unwrap();

    let attr = fs
        .symlink(
            &cx,
            ffs_types::InodeNumber(2),
            std::ffi::OsStr::new("fastlink"),
            std::path::Path::new("sym_target.txt"),
            1000,
            1000,
        )
        .unwrap();

    let target = fs.readlink(&cx, attr.ino).unwrap();
    assert_eq!(target, b"sym_target.txt");
}
