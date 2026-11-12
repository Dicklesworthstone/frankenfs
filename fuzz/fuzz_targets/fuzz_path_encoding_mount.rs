#![no_main]

use asupersync::Cx;
use ffs_core::{DirEntry, FileType, FsOps, InodeAttr, ReaddirPage, RequestScope};
use ffs_error::FfsError;
use ffs_fuse::{FrankenFuse, MountOptions};
use ffs_types::{crc32c, InodeNumber};
use libfuzzer_sys::fuzz_target;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::SystemTime;

const MAX_INPUT_BYTES: usize = 1024;
const MAX_NAME_BYTES: usize = 288;
const MAX_TARGET_BYTES: usize = 320;

#[derive(Debug, Clone, Copy)]
enum ErrorMode {
    Ok,
    NotFound,
    Exists,
    NotDirectory,
    IsDirectory,
    NameTooLong,
    Format,
}

impl ErrorMode {
    fn from_byte(byte: u8) -> Self {
        match byte % 7 {
            0 => Self::Ok,
            1 => Self::NotFound,
            2 => Self::Exists,
            3 => Self::NotDirectory,
            4 => Self::IsDirectory,
            5 => Self::NameTooLong,
            _ => Self::Format,
        }
    }

    fn into_error(self, context: &str) -> Option<FfsError> {
        match self {
            Self::Ok => None,
            Self::NotFound => Some(FfsError::NotFound(format!("{context} miss"))),
            Self::Exists => Some(FfsError::Exists),
            Self::NotDirectory => Some(FfsError::NotDirectory),
            Self::IsDirectory => Some(FfsError::IsDirectory),
            Self::NameTooLong => Some(FfsError::NameTooLong),
            Self::Format => Some(FfsError::Format(format!("{context} rejected"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpOutcome {
    Attr { ino: u64, kind: u8, generation: u64 },
    Entries { count: usize, crc32c: u32 },
    Bytes { len: usize, crc32c: u32 },
    Unit,
    Err(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountPathOutcome {
    lookup: OpOutcome,
    readdir: OpOutcome,
    readlink: OpOutcome,
    create: OpOutcome,
    mkdir: OpOutcome,
    rename: OpOutcome,
    symlink: OpOutcome,
}

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn fill_bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u8()).collect()
    }
}

struct FuzzFs {
    lookup_attr: InodeAttr,
    create_attr: InodeAttr,
    mkdir_attr: InodeAttr,
    symlink_attr: InodeAttr,
    lookup_mode: ErrorMode,
    create_mode: ErrorMode,
    mkdir_mode: ErrorMode,
    rename_mode: ErrorMode,
    symlink_mode: ErrorMode,
    readlink_mode: ErrorMode,
    readlink_target: Vec<u8>,
    readdir_entries: Vec<DirEntry>,
}

impl FuzzFs {
    fn from_cursor(cursor: &mut ByteCursor<'_>) -> Self {
        let lookup_attr = build_attr(cursor, 11, FileType::RegularFile);
        let create_attr = build_attr(cursor, 21, FileType::RegularFile);
        let mkdir_attr = build_attr(cursor, 31, FileType::Directory);
        let symlink_attr = build_attr(cursor, 41, FileType::Symlink);
        let readlink_target = fuzz_target_bytes(cursor);
        let readdir_entries = build_entries(cursor);

        Self {
            lookup_attr,
            create_attr,
            mkdir_attr,
            symlink_attr,
            lookup_mode: ErrorMode::from_byte(cursor.next_u8()),
            create_mode: ErrorMode::from_byte(cursor.next_u8()),
            mkdir_mode: ErrorMode::from_byte(cursor.next_u8()),
            rename_mode: ErrorMode::from_byte(cursor.next_u8()),
            symlink_mode: ErrorMode::from_byte(cursor.next_u8()),
            readlink_mode: ErrorMode::from_byte(cursor.next_u8()),
            readlink_target,
            readdir_entries,
        }
    }
}

impl FsOps for FuzzFs {
    fn getattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        Ok(InodeAttr {
            ino,
            ..self.lookup_attr.clone()
        })
    }

    fn lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        if let Some(err) = validate_name(name) {
            return Err(err);
        }
        if let Some(err) = self.lookup_mode.into_error("lookup") {
            return Err(err);
        }
        Ok(self.lookup_attr.clone())
    }

    fn readdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        Ok(ReaddirPage::new(self.readdir_entries.clone()))
    }

    fn read(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        _size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn readlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        if let Some(err) = self.readlink_mode.into_error("readlink") {
            return Err(err);
        }
        if self.readlink_target.is_empty() {
            return Err(FfsError::Format("empty symlink target".to_owned()));
        }
        Ok(self.readlink_target.clone())
    }

    fn create(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        name: &OsStr,
        _mode: u16,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        if let Some(err) = validate_name(name) {
            return Err(err);
        }
        if let Some(err) = self.create_mode.into_error("create") {
            return Err(err);
        }
        Ok(self.create_attr.clone())
    }

    fn mkdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        name: &OsStr,
        _mode: u16,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        if let Some(err) = validate_name(name) {
            return Err(err);
        }
        if let Some(err) = self.mkdir_mode.into_error("mkdir") {
            return Err(err);
        }
        Ok(self.mkdir_attr.clone())
    }

    fn rename(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        name: &OsStr,
        _new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> ffs_error::Result<()> {
        if let Some(err) = validate_name(name) {
            return Err(err);
        }
        if let Some(err) = validate_name(new_name) {
            return Err(err);
        }
        if let Some(err) = self.rename_mode.into_error("rename") {
            return Err(err);
        }
        Ok(())
    }

    fn symlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        name: &OsStr,
        target: &Path,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        if let Some(err) = validate_name(name) {
            return Err(err);
        }
        if target.as_os_str().is_empty() {
            return Err(FfsError::Format("empty symlink target".to_owned()));
        }
        if let Some(err) = self.symlink_mode.into_error("symlink") {
            return Err(err);
        }
        Ok(self.symlink_attr.clone())
    }
}

fn build_attr(cursor: &mut ByteCursor<'_>, ino: u64, kind: FileType) -> InodeAttr {
    InodeAttr {
        ino: InodeNumber(ino),
        size: u64::from(cursor.next_u16()),
        blocks: 8,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind,
        perm: 0o644,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        blksize: 4096,
        generation: u64::from(cursor.next_u32()),
    }
}

fn fuzz_name(cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    let variant = cursor.next_u8() % 8;
    match variant {
        0 => Vec::new(),
        1 => b".".to_vec(),
        2 => b"..".to_vec(),
        3 => {
            let len = 1 + usize::from(cursor.next_u8() % 8);
            let mut name = cursor.fill_bytes(len.min(MAX_NAME_BYTES));
            if name.is_empty() {
                name.push(b'/');
            } else {
                name[0] = b'/';
            }
            name
        }
        4 => vec![b'a'; 256 + usize::from(cursor.next_u8() % 16)],
        _ => {
            let len = usize::from(cursor.next_u16() % (MAX_NAME_BYTES as u16));
            cursor.fill_bytes(len)
        }
    }
}

fn fuzz_target_bytes(cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    match cursor.next_u8() % 6 {
        0 => Vec::new(),
        1 => b"target".to_vec(),
        2 => b"./relative/target".to_vec(),
        3 => {
            let len = usize::from(cursor.next_u8() % 24);
            let mut target = cursor.fill_bytes(len);
            target.extend_from_slice(b"/x");
            target
        }
        _ => {
            let len = usize::from(cursor.next_u16() % (MAX_TARGET_BYTES as u16));
            cursor.fill_bytes(len)
        }
    }
}

fn build_entries(cursor: &mut ByteCursor<'_>) -> Vec<DirEntry> {
    let count = usize::from(cursor.next_u8() % 4);
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let kind = match cursor.next_u8() % 3 {
            0 => FileType::RegularFile,
            1 => FileType::Directory,
            _ => FileType::Symlink,
        };
        let ino = 50_u64 + u64::from(u16::try_from(index).unwrap_or(u16::MAX));
        let offset = 1_u64 + u64::from(u16::try_from(index).unwrap_or(u16::MAX));
        entries.push(DirEntry {
            ino: InodeNumber(ino),
            offset,
            kind,
            name: fuzz_name(cursor),
        });
    }
    entries
}

fn validate_name(name: &OsStr) -> Option<FfsError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Some(FfsError::Format("empty path component".to_owned()));
    }
    if bytes == b"." || bytes == b".." {
        return Some(FfsError::Format("dot path component".to_owned()));
    }
    if bytes.len() > 255 {
        return Some(FfsError::NameTooLong);
    }
    if bytes.contains(&b'/') {
        return Some(FfsError::Format(
            "embedded separator in single path component".to_owned(),
        ));
    }
    None
}

fn encode_entries(entries: &[DirEntry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(&entry.ino.0.to_le_bytes());
        bytes.extend_from_slice(&entry.offset.to_le_bytes());
        bytes.push(file_type_tag(entry.kind));
        let name_len = u16::try_from(entry.name.len()).unwrap_or(u16::MAX);
        bytes.extend_from_slice(&name_len.to_le_bytes());
        bytes.extend_from_slice(&entry.name);
    }
    bytes
}

fn file_type_tag(kind: FileType) -> u8 {
    match kind {
        FileType::RegularFile => 1,
        FileType::Directory => 2,
        FileType::Symlink => 3,
        FileType::BlockDevice => 4,
        FileType::CharDevice => 5,
        FileType::Fifo => 6,
        FileType::Socket => 7,
    }
}

fn attr_outcome(result: std::result::Result<InodeAttr, i32>) -> OpOutcome {
    match result {
        Ok(attr) => OpOutcome::Attr {
            ino: attr.ino.0,
            kind: file_type_tag(attr.kind),
            generation: attr.generation,
        },
        Err(errno) => OpOutcome::Err(errno),
    }
}

fn bytes_outcome(result: std::result::Result<Vec<u8>, i32>) -> OpOutcome {
    match result {
        Ok(bytes) => OpOutcome::Bytes {
            len: bytes.len(),
            crc32c: crc32c(&bytes),
        },
        Err(errno) => OpOutcome::Err(errno),
    }
}

fn entries_outcome(result: std::result::Result<Vec<DirEntry>, i32>) -> OpOutcome {
    match result {
        Ok(entries) => OpOutcome::Entries {
            count: entries.len(),
            crc32c: crc32c(&encode_entries(&entries)),
        },
        Err(errno) => OpOutcome::Err(errno),
    }
}

fn unit_outcome(result: std::result::Result<(), i32>) -> OpOutcome {
    match result {
        Ok(()) => OpOutcome::Unit,
        Err(errno) => OpOutcome::Err(errno),
    }
}

fn classify_mount_path(data: &[u8]) -> MountPathOutcome {
    let mut cursor = ByteCursor::new(data);
    let read_only = cursor.next_bool();
    let lookup_name = fuzz_name(&mut cursor);
    let create_name = fuzz_name(&mut cursor);
    let mkdir_name = fuzz_name(&mut cursor);
    let rename_name = fuzz_name(&mut cursor);
    let rename_target = fuzz_name(&mut cursor);
    let symlink_name = fuzz_name(&mut cursor);
    let symlink_target = fuzz_target_bytes(&mut cursor);
    let lookup_parent = 1_u64 + u64::from(cursor.next_u8());
    let create_parent = 1_u64 + u64::from(cursor.next_u8());
    let mkdir_parent = 1_u64 + u64::from(cursor.next_u8());
    let rename_parent = 1_u64 + u64::from(cursor.next_u8());
    let rename_new_parent = 1_u64 + u64::from(cursor.next_u8());
    let readlink_ino = 1_u64 + u64::from(cursor.next_u8());
    let readdir_ino = 1_u64 + u64::from(cursor.next_u8());
    let readdir_offset = u64::from(cursor.next_u8() % 4);
    let create_mode = cursor.next_u16();
    let mkdir_mode = cursor.next_u16();
    let uid = cursor.next_u32();
    let gid = cursor.next_u32();
    let fs = FuzzFs::from_cursor(&mut cursor);
    let options = MountOptions {
        read_only,
        ..MountOptions::default()
    };
    let fuse = FrankenFuse::with_options(Box::new(fs), &options);

    MountPathOutcome {
        lookup: attr_outcome(fuse.lookup_for_fuzzing(lookup_parent, &lookup_name)),
        readdir: entries_outcome(fuse.readdir_for_fuzzing(readdir_ino, readdir_offset)),
        readlink: bytes_outcome(fuse.readlink_for_fuzzing(readlink_ino)),
        create: attr_outcome(fuse.create_for_fuzzing(
            create_parent,
            &create_name,
            create_mode,
            uid,
            gid,
        )),
        mkdir: attr_outcome(fuse.mkdir_for_fuzzing(
            mkdir_parent,
            &mkdir_name,
            mkdir_mode,
            uid,
            gid,
        )),
        rename: unit_outcome(fuse.rename_for_fuzzing(
            rename_parent,
            &rename_name,
            rename_new_parent,
            &rename_target,
        )),
        symlink: attr_outcome(fuse.symlink_for_fuzzing(
            create_parent,
            &symlink_name,
            &symlink_target,
            uid,
            gid,
        )),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let first = classify_mount_path(data);
    let second = classify_mount_path(data);
    assert_eq!(
        first, second,
        "mount-path raw-byte classification must be deterministic for identical inputs"
    );
});
