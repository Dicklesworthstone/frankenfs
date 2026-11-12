#![no_main]

use asupersync::Cx;
use ffs_core::{FileType, FsOps, InodeAttr, ReaddirPage, RequestScope};
use ffs_error::FfsError;
use ffs_fuse::{
    mount_option_labels_for_fuzzing, parse_mount_options_for_fuzzing, FrankenFuse, MountOptions,
};
use ffs_types::{crc32c, InodeNumber};
use libfuzzer_sys::fuzz_target;
use std::ffi::OsStr;
use std::sync::Mutex;
use std::time::SystemTime;

const MAX_INPUT_BYTES: usize = 4096;
const MAX_INITIAL_BYTES: usize = 1024;
const MAX_IO_BYTES: usize = 2048;
const MAX_FILE_BYTES: usize = 8192;
const MAX_MOUNT_OPTION_BYTES: usize = 256;

const SRC_INO: u64 = 11;
const DST_INO: u64 = 12;
const TEE_INO: u64 = 13;

#[derive(Debug, Clone, Copy)]
enum FaultMode {
    Ok,
    NotFound,
    IsDirectory,
    Format,
}

impl FaultMode {
    fn from_byte(byte: u8) -> Self {
        match byte % 8 {
            0 => Self::NotFound,
            1 => Self::IsDirectory,
            2 => Self::Format,
            _ => Self::Ok,
        }
    }

    fn into_error(self, context: &str) -> Option<FfsError> {
        match self {
            Self::Ok => None,
            Self::NotFound => Some(FfsError::NotFound(format!("{context} fuzz miss"))),
            Self::IsDirectory => Some(FfsError::IsDirectory),
            Self::Format => Some(FfsError::Format(format!("{context} fuzz rejection"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IoOutcome {
    Bytes { len: usize, crc32c: u32 },
    Count(u32),
    Unit,
    Err(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountOutcome {
    labels: Vec<String>,
    resolved_threads: usize,
    parsed: MountParseOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MountParseOutcome {
    Parsed {
        read_only: bool,
        allow_other: bool,
        auto_unmount: bool,
        worker_threads: usize,
        label_crc32c: u32,
    },
    Rejected {
        error_crc32c: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpliceMountOutcome {
    mount: MountOutcome,
    pipe_read: IoOutcome,
    pipe_write: IoOutcome,
    tee_write: IoOutcome,
    copy_file_range: IoOutcome,
    flush: IoOutcome,
    fsync: IoOutcome,
    final_source: IoOutcome,
    final_dest: IoOutcome,
    final_tee: IoOutcome,
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

struct FileState {
    source: Vec<u8>,
    dest: Vec<u8>,
    tee: Vec<u8>,
}

struct FuzzFs {
    state: Mutex<FileState>,
    read_limit: usize,
    write_limit: usize,
    read_mode: FaultMode,
    write_mode: FaultMode,
    fsync_mode: FaultMode,
}

impl FuzzFs {
    fn from_cursor(cursor: &mut ByteCursor<'_>) -> Self {
        let source_len = usize::from(cursor.next_u16()).min(MAX_INITIAL_BYTES);
        let dest_len = usize::from(cursor.next_u8()).min(64);
        let tee_len = usize::from(cursor.next_u8()).min(64);
        let read_limit = if cursor.next_bool() {
            MAX_IO_BYTES
        } else {
            usize::from(cursor.next_u16()).min(MAX_IO_BYTES)
        };
        let write_limit = if cursor.next_bool() {
            MAX_IO_BYTES
        } else {
            usize::from(cursor.next_u16()).min(MAX_IO_BYTES)
        };

        Self {
            state: Mutex::new(FileState {
                source: cursor.fill_bytes(source_len),
                dest: cursor.fill_bytes(dest_len),
                tee: cursor.fill_bytes(tee_len),
            }),
            read_limit,
            write_limit,
            read_mode: FaultMode::from_byte(cursor.next_u8()),
            write_mode: FaultMode::from_byte(cursor.next_u8()),
            fsync_mode: FaultMode::from_byte(cursor.next_u8()),
        }
    }

    fn attr_for(&self, ino: InodeNumber) -> ffs_error::Result<InodeAttr> {
        let state = self
            .state
            .lock()
            .map_err(|_| FfsError::Format("fuzz file state poisoned".to_owned()))?;
        let file = file_for_inode(&state, ino)
            .ok_or_else(|| FfsError::NotFound(format!("inode {}", ino.0)))?;
        Ok(InodeAttr {
            ino,
            size: u64::try_from(file.len()).unwrap_or(u64::MAX),
            blocks: 1,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            generation: 1,
        })
    }
}

impl FsOps for FuzzFs {
    fn getattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        self.attr_for(ino)
    }

    fn lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::NotFound("lookup fuzz miss".to_owned()))
    }

    fn readdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        Ok(ReaddirPage::new(Vec::new()))
    }

    fn read(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        if let Some(err) = self.read_mode.into_error("read") {
            return Err(err);
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start > MAX_FILE_BYTES {
            return Ok(Vec::new());
        }
        let requested = usize::try_from(size)
            .unwrap_or(MAX_IO_BYTES)
            .min(MAX_IO_BYTES)
            .min(self.read_limit);
        let state = self
            .state
            .lock()
            .map_err(|_| FfsError::Format("fuzz file state poisoned".to_owned()))?;
        let file = file_for_inode(&state, ino)
            .ok_or_else(|| FfsError::NotFound(format!("inode {}", ino.0)))?;
        if start >= file.len() || requested == 0 {
            return Ok(Vec::new());
        }
        let end = file.len().min(start.saturating_add(requested));
        Ok(file[start..end].to_vec())
    }

    fn readlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::Format("readlink fuzz rejection".to_owned()))
    }

    fn write(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> ffs_error::Result<u32> {
        if let Some(err) = self.write_mode.into_error("write") {
            return Err(err);
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start > MAX_FILE_BYTES {
            return Err(FfsError::Format("write offset exceeds fuzz cap".to_owned()));
        }
        let accepted = data.len().min(self.write_limit).min(MAX_FILE_BYTES - start);
        let mut state = self
            .state
            .lock()
            .map_err(|_| FfsError::Format("fuzz file state poisoned".to_owned()))?;
        let file = file_for_inode_mut(&mut state, ino)
            .ok_or_else(|| FfsError::NotFound(format!("inode {}", ino.0)))?;
        if accepted == 0 {
            return Ok(0);
        }
        if file.len() < start {
            file.resize(start, 0);
        }
        let end = start + accepted;
        if file.len() < end {
            file.resize(end, 0);
        }
        file[start..end].copy_from_slice(&data[..accepted]);
        Ok(u32::try_from(accepted).unwrap_or(u32::MAX))
    }

    fn fsync(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> ffs_error::Result<()> {
        if let Some(err) = self.fsync_mode.into_error("fsync") {
            return Err(err);
        }
        Ok(())
    }
}

fn file_for_inode(state: &FileState, ino: InodeNumber) -> Option<&[u8]> {
    match ino.0 {
        SRC_INO => Some(state.source.as_slice()),
        DST_INO => Some(state.dest.as_slice()),
        TEE_INO => Some(state.tee.as_slice()),
        _ => None,
    }
}

fn file_for_inode_mut(state: &mut FileState, ino: InodeNumber) -> Option<&mut Vec<u8>> {
    match ino.0 {
        SRC_INO => Some(&mut state.source),
        DST_INO => Some(&mut state.dest),
        TEE_INO => Some(&mut state.tee),
        _ => None,
    }
}

fn contains_label(labels: &[String], needle: &str) -> bool {
    labels.iter().any(|label| label == needle)
}

fn contains_prefix(labels: &[String], prefix: &str) -> bool {
    labels.iter().any(|label| label.starts_with(prefix))
}

fn fuzz_worker_threads(cursor: &mut ByteCursor<'_>) -> usize {
    match cursor.next_u8() % 6 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 8,
        4 => usize::from(cursor.next_u16() % 128),
        _ => 4096,
    }
}

fn fuzz_mount_option_bytes(cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    let len = usize::from(cursor.next_u16()).min(MAX_MOUNT_OPTION_BYTES);
    cursor.fill_bytes(len)
}

fn fuzz_len(cursor: &mut ByteCursor<'_>) -> u32 {
    match cursor.next_u8() % 6 {
        0 => 0,
        1 => 1,
        2 => 4096,
        3 => u32::try_from(MAX_IO_BYTES).unwrap_or(u32::MAX),
        _ => u32::from(cursor.next_u16()).min(u32::try_from(MAX_IO_BYTES).unwrap_or(u32::MAX)),
    }
}

fn fuzz_offset(cursor: &mut ByteCursor<'_>) -> i64 {
    match cursor.next_u8() % 8 {
        0 => -1,
        1 => 0,
        2 => 1,
        3 => i64::from(cursor.next_u16()),
        4 => i64::try_from(MAX_FILE_BYTES - 1).unwrap_or(i64::MAX),
        5 => i64::try_from(MAX_FILE_BYTES).unwrap_or(i64::MAX),
        6 => i64::MAX,
        _ => i64::from(cursor.next_u32()),
    }
}

fn fuzz_ino(cursor: &mut ByteCursor<'_>) -> u64 {
    match cursor.next_u8() % 5 {
        0 => SRC_INO,
        1 => DST_INO,
        2 => TEE_INO,
        3 => 1,
        _ => 999,
    }
}

fn mount_outcome(cursor: &mut ByteCursor<'_>) -> (MountOptions, MountOutcome) {
    let mount_option_bytes = fuzz_mount_option_bytes(cursor);
    let options = MountOptions {
        read_only: cursor.next_bool(),
        allow_other: cursor.next_bool(),
        auto_unmount: cursor.next_bool(),
        worker_threads: fuzz_worker_threads(cursor),
        ..MountOptions::default()
    };
    let labels = mount_option_labels_for_fuzzing(&options);

    assert!(contains_label(&labels, "fsname=frankenfs"));
    assert!(contains_label(&labels, "subtype=ffs"));
    assert!(contains_label(&labels, "default_permissions"));
    assert!(contains_label(&labels, "noatime"));
    assert!(contains_prefix(&labels, "max_read="));
    assert_eq!(contains_label(&labels, "ro"), options.read_only);
    assert_eq!(contains_label(&labels, "allow_other"), options.allow_other);
    assert_eq!(
        contains_label(&labels, "auto_unmount"),
        options.auto_unmount
    );
    assert!(labels.iter().all(|label| {
        !label.is_empty() && !label.as_bytes().contains(&0) && !label.contains("writeback_cache")
    }));

    if options.worker_threads == 0 {
        assert!(!contains_prefix(&labels, "max_background="));
        assert!(!contains_prefix(&labels, "congestion_threshold="));
    } else {
        let max_background = options.resolved_thread_count();
        let congestion_threshold = max_background.saturating_mul(3).saturating_div(4).max(1);
        assert!(contains_label(
            &labels,
            &format!("max_background={max_background}")
        ));
        assert!(contains_label(
            &labels,
            &format!("congestion_threshold={congestion_threshold}")
        ));
    }

    (
        options.clone(),
        MountOutcome {
            labels,
            resolved_threads: options.resolved_thread_count(),
            parsed: mount_parse_outcome(&mount_option_bytes),
        },
    )
}

fn mount_parse_outcome(input: &[u8]) -> MountParseOutcome {
    match parse_mount_options_for_fuzzing(input) {
        Ok(options) => {
            let labels = mount_option_labels_for_fuzzing(&options);
            MountParseOutcome::Parsed {
                read_only: options.read_only,
                allow_other: options.allow_other,
                auto_unmount: options.auto_unmount,
                worker_threads: options.worker_threads,
                label_crc32c: crc32c(labels.join(",").as_bytes()),
            }
        }
        Err(error) => MountParseOutcome::Rejected {
            error_crc32c: crc32c(format!("{error:?}").as_bytes()),
        },
    }
}

fn bytes_outcome(result: std::result::Result<Vec<u8>, i32>) -> IoOutcome {
    match result {
        Ok(bytes) => IoOutcome::Bytes {
            len: bytes.len(),
            crc32c: crc32c(&bytes),
        },
        Err(errno) => IoOutcome::Err(errno),
    }
}

fn count_outcome(result: std::result::Result<u32, i32>) -> IoOutcome {
    match result {
        Ok(count) => IoOutcome::Count(count),
        Err(errno) => IoOutcome::Err(errno),
    }
}

fn unit_outcome(result: std::result::Result<(), i32>) -> IoOutcome {
    match result {
        Ok(()) => IoOutcome::Unit,
        Err(errno) => IoOutcome::Err(errno),
    }
}

fn write_pipe_payload(
    fuse: &FrankenFuse,
    read_result: &std::result::Result<Vec<u8>, i32>,
    ino: u64,
    offset: i64,
) -> IoOutcome {
    match read_result {
        Ok(bytes) => count_outcome(fuse.write_for_fuzzing(ino, offset, bytes)),
        Err(errno) => IoOutcome::Err(*errno),
    }
}

fn classify_splice_mount(data: &[u8]) -> SpliceMountOutcome {
    let mut cursor = ByteCursor::new(data);
    let (options, mount) = mount_outcome(&mut cursor);
    let fs = FuzzFs::from_cursor(&mut cursor);
    let fuse = FrankenFuse::with_options(Box::new(fs), &options);

    let pipe_read_ino = fuzz_ino(&mut cursor);
    let pipe_read_offset = fuzz_offset(&mut cursor);
    let pipe_read_len = fuzz_len(&mut cursor);
    let pipe_write_ino = fuzz_ino(&mut cursor);
    let pipe_write_offset = fuzz_offset(&mut cursor);
    let tee_write_ino = fuzz_ino(&mut cursor);
    let tee_write_offset = fuzz_offset(&mut cursor);
    let copy_in_ino = fuzz_ino(&mut cursor);
    let copy_out_ino = fuzz_ino(&mut cursor);
    let copy_in_offset = fuzz_offset(&mut cursor);
    let copy_out_offset = fuzz_offset(&mut cursor);
    let copy_len = u64::from(fuzz_len(&mut cursor));
    let copy_flags = if cursor.next_bool() {
        0
    } else {
        cursor.next_u32()
    };
    let flush_ino = fuzz_ino(&mut cursor);
    let fsync_ino = fuzz_ino(&mut cursor);
    let fsync_datasync = cursor.next_bool();

    let pipe_read_result = fuse.read_for_fuzzing(pipe_read_ino, pipe_read_offset, pipe_read_len);
    let pipe_write =
        write_pipe_payload(&fuse, &pipe_read_result, pipe_write_ino, pipe_write_offset);
    let tee_write = write_pipe_payload(&fuse, &pipe_read_result, tee_write_ino, tee_write_offset);
    let copy_file_range = count_outcome(fuse.copy_file_range_for_fuzzing(
        copy_in_ino,
        copy_in_offset,
        copy_out_ino,
        copy_out_offset,
        copy_len,
        copy_flags,
    ));
    let flush = unit_outcome(fuse.flush_for_fuzzing(flush_ino, 0, 0));
    let fsync = unit_outcome(fuse.fsync_for_fuzzing(fsync_ino, 0, fsync_datasync));

    SpliceMountOutcome {
        mount,
        pipe_read: bytes_outcome(pipe_read_result),
        pipe_write,
        tee_write,
        copy_file_range,
        flush,
        fsync,
        final_source: bytes_outcome(fuse.read_for_fuzzing(
            SRC_INO,
            0,
            u32::try_from(MAX_FILE_BYTES).unwrap_or(u32::MAX),
        )),
        final_dest: bytes_outcome(fuse.read_for_fuzzing(
            DST_INO,
            0,
            u32::try_from(MAX_FILE_BYTES).unwrap_or(u32::MAX),
        )),
        final_tee: bytes_outcome(fuse.read_for_fuzzing(
            TEE_INO,
            0,
            u32::try_from(MAX_FILE_BYTES).unwrap_or(u32::MAX),
        )),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let first = classify_splice_mount(data);
    let second = classify_splice_mount(data);
    assert_eq!(
        first, second,
        "FUSE splice/sendfile-style dispatch and mount option labels must be deterministic"
    );
});
