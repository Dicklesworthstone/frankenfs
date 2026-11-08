#![no_main]

use asupersync::Cx;
use ffs_core::{
    DirEntry, FiemapExtent, FileType, FsOps, FsStat, FsxattrInfo, InodeAttr, RequestScope,
};
use ffs_error::FfsError;
use ffs_fuse::{FrankenFuse, MountOptions};
use ffs_types::{InodeNumber, crc32c};
use libfuzzer_sys::fuzz_target;
use std::ffi::OsStr;
use std::time::SystemTime;

const MAX_INPUT_BYTES: usize = 512;

const FS_IOC_FIEMAP: u32 = 0xC020_660B;
const EXT4_IOC_GETFLAGS: u32 = 0x8008_6601;
const EXT4_IOC_GETVERSION: u32 = 0x8008_6603;
const EXT4_IOC_SETVERSION: u32 = 0x4008_6604;
const FS_IOC_GET_ENCRYPTION_POLICY: u32 = 0x400C_6615;
const FS_IOC_GET_ENCRYPTION_POLICY_EX: u32 = 0xC009_6616;
const EXT4_IOC_SETFLAGS: u32 = 0x4008_6602;
const EXT4_IOC_MOVE_EXT: u32 = 0xC028_660F;
const FS_IOC_GETFSLABEL: u32 = 0x8100_9431;
const FS_IOC_SETFSLABEL: u32 = 0x4100_9432;
const BTRFS_IOC_FS_INFO: u32 = 0x8400_941F;
const BTRFS_IOC_DEV_INFO: u32 = 0xD000_941E;
const BTRFS_IOC_INO_LOOKUP: u32 = 0xD000_9412;

const FIEMAP_FLAG_SYNC: u32 = 0x0000_0001;
const FSCRYPT_POLICY_V1_SIZE: usize = 12;
const FSCRYPT_POLICY_V2_SIZE: usize = 24;
const FSCRYPT_POLICY_EX_HEADER_SIZE: usize = 8;
const FIEMAP_HEADER_SIZE: usize = 32;
const FIEMAP_EXTENT_SIZE: usize = 56;
const FS_IOC_FSGETXATTR: u32 = 0x801C_5821;
const FS_IOC_FSGETXATTR_SIZE: usize = 28;
const FIBMAP: u32 = 0x0000_0001;
const FIBMAP_SIZE: usize = 4;
const FITRIM: u32 = 0xC018_5879;
const FITRIM_SIZE: usize = 24;
const FS_IOC_GETFSUUID: u32 = 0x8011_1500;
const FS_IOC_GETFSUUID_SIZE: usize = 17;
const FS_IOC_FSSETXATTR: u32 = 0x401C_5820;
const FS_IOC_FSSETXATTR_SIZE: usize = 28;
const EXT4_IOC_PRECACHE_EXTENTS: u32 = 0x0000_6626;
const EXT4_IOC_CLEAR_ES_CACHE: u32 = 0x0000_6628;
const MOVE_EXT_SIZE: usize = 40;
const FSLABEL_MAX: usize = 256;
const BTRFS_IOC_FS_INFO_SIZE: usize = 1024;
const BTRFS_IOC_DEV_INFO_SIZE: usize = 4096;
const BTRFS_INO_LOOKUP_ARGS_SIZE: usize = 4096;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

#[derive(Clone, Copy)]
enum CommandKind {
    Fiemap,
    GetFlags,
    GetVersion,
    Fibmap,
    Fitrim,
    GetFsUuid,
    GetFsxattr,
    SetFsxattr,
    PrecacheExtents,
    ClearExtentStatusCache,
    SetVersion,
    GetEncryptionPolicy,
    GetEncryptionPolicyEx,
    SetFlags,
    MoveExt,
    GetFsLabel,
    SetFsLabel,
    BtrfsFsInfo,
    BtrfsDevInfo,
    BtrfsInoLookup,
    Unknown,
}

impl CommandKind {
    fn from_selector(selector: u8) -> Self {
        match selector % 21 {
            0 => Self::Fiemap,
            1 => Self::GetFlags,
            2 => Self::GetVersion,
            3 => Self::Fibmap,
            4 => Self::Fitrim,
            5 => Self::GetFsUuid,
            6 => Self::GetFsxattr,
            7 => Self::SetFsxattr,
            8 => Self::PrecacheExtents,
            9 => Self::ClearExtentStatusCache,
            10 => Self::SetVersion,
            11 => Self::GetEncryptionPolicy,
            12 => Self::GetEncryptionPolicyEx,
            13 => Self::SetFlags,
            14 => Self::MoveExt,
            15 => Self::GetFsLabel,
            16 => Self::SetFsLabel,
            17 => Self::BtrfsFsInfo,
            18 => Self::BtrfsDevInfo,
            19 => Self::BtrfsInoLookup,
            _ => Self::Unknown,
        }
    }

    fn cmd(self) -> u32 {
        match self {
            Self::Fiemap => FS_IOC_FIEMAP,
            Self::GetFlags => EXT4_IOC_GETFLAGS,
            Self::GetVersion => EXT4_IOC_GETVERSION,
            Self::Fibmap => FIBMAP,
            Self::Fitrim => FITRIM,
            Self::GetFsUuid => FS_IOC_GETFSUUID,
            Self::GetFsxattr => FS_IOC_FSGETXATTR,
            Self::SetFsxattr => FS_IOC_FSSETXATTR,
            Self::PrecacheExtents => EXT4_IOC_PRECACHE_EXTENTS,
            Self::ClearExtentStatusCache => EXT4_IOC_CLEAR_ES_CACHE,
            Self::SetVersion => EXT4_IOC_SETVERSION,
            Self::GetEncryptionPolicy => FS_IOC_GET_ENCRYPTION_POLICY,
            Self::GetEncryptionPolicyEx => FS_IOC_GET_ENCRYPTION_POLICY_EX,
            Self::SetFlags => EXT4_IOC_SETFLAGS,
            Self::MoveExt => EXT4_IOC_MOVE_EXT,
            Self::GetFsLabel => FS_IOC_GETFSLABEL,
            Self::SetFsLabel => FS_IOC_SETFSLABEL,
            Self::BtrfsFsInfo => BTRFS_IOC_FS_INFO,
            Self::BtrfsDevInfo => BTRFS_IOC_DEV_INFO,
            Self::BtrfsInoLookup => BTRFS_IOC_INO_LOOKUP,
            Self::Unknown => 0xDEAD_BEEF,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IoctlOutcome {
    Data { len: usize, crc32c: u32 },
    Err(i32),
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

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
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
    attr: InodeAttr,
    flags: u32,
    generation: u32,
    encryption_policy_v1: [u8; FSCRYPT_POLICY_V1_SIZE],
    encryption_policy_ex: (u8, Vec<u8>),
    fs_label: Vec<u8>,
    btrfs_fs_info: Vec<u8>,
    btrfs_dev_info: Vec<u8>,
    btrfs_ino_lookup: (u64, Vec<u8>),
    fiemap_extents: Vec<FiemapExtent>,
    fsxattr_info: FsxattrInfo,
    fs_uuid: [u8; 16],
    stat_block_size: u32,
    trim_result: u64,
    move_ext_result: u64,
}

impl FuzzFs {
    fn from_cursor(cursor: &mut ByteCursor<'_>) -> Self {
        let kind = match cursor.next_u8() % 3 {
            0 => FileType::RegularFile,
            1 => FileType::Directory,
            _ => FileType::Symlink,
        };
        let size = u64::from(cursor.next_u8()) * 1024;
        let blksize = 512_u32 << (cursor.next_u8() % 4);
        let attr = InodeAttr {
            ino: InodeNumber(11),
            size,
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
            blksize,
            generation: u64::from(cursor.next_u32()),
        };

        let mut policy_v1 = [0_u8; FSCRYPT_POLICY_V1_SIZE];
        policy_v1.copy_from_slice(&cursor.fill_bytes(FSCRYPT_POLICY_V1_SIZE));

        let encryption_policy_ex = if cursor.next_bool() {
            (0, policy_v1.to_vec())
        } else {
            (2, cursor.fill_bytes(FSCRYPT_POLICY_V2_SIZE))
        };

        let fs_label_len = usize::from(cursor.next_u8() % 32);
        let mut fs_label = cursor.fill_bytes(fs_label_len);
        if cursor.next_bool() {
            fs_label.push(0);
        }

        let btrfs_fs_info = build_payload(cursor, BTRFS_IOC_FS_INFO_SIZE);
        let btrfs_dev_info = build_payload(cursor, BTRFS_IOC_DEV_INFO_SIZE);
        let ino_lookup_name_len = usize::from(cursor.next_u8() % 32);
        let btrfs_ino_lookup = (
            cursor.next_u64(),
            nul_terminated_bytes(cursor, ino_lookup_name_len),
        );
        let fiemap_extents = build_extents(cursor);
        let fsxattr_info = FsxattrInfo {
            xflags: cursor.next_u32(),
            extsize: cursor.next_u32(),
            nextents: cursor.next_u32(),
            projid: cursor.next_u32(),
            cowextsize: cursor.next_u32(),
        };
        let fs_uuid = build_uuid(cursor);
        let stat_block_size = match cursor.next_u8() % 6 {
            0 => 0,
            1 => 512,
            2 => 1024,
            3 => 4096,
            4 => 65_536,
            _ => u32::from(cursor.next_u16()).max(1),
        };

        Self {
            attr,
            flags: if cursor.next_bool() {
                EXT4_EXTENTS_FL
            } else {
                0
            },
            generation: cursor.next_u32(),
            encryption_policy_v1: policy_v1,
            encryption_policy_ex,
            fs_label,
            btrfs_fs_info,
            btrfs_dev_info,
            btrfs_ino_lookup,
            fiemap_extents,
            fsxattr_info,
            fs_uuid,
            stat_block_size,
            trim_result: cursor.next_u64(),
            move_ext_result: cursor.next_u64() & 0xFFFF,
        }
    }
}

impl FsOps for FuzzFs {
    fn getattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        Ok(self.attr.clone())
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
    ) -> ffs_error::Result<Vec<DirEntry>> {
        Ok(Vec::new())
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
        Ok(b"target".to_vec())
    }

    fn statfs(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<FsStat> {
        Ok(FsStat {
            blocks: 1024,
            blocks_free: 512,
            blocks_available: 256,
            files: 64,
            files_free: 32,
            block_size: self.stat_block_size,
            name_max: 255,
            fragment_size: self.stat_block_size,
        })
    }

    fn fsync(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    fn fiemap(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _start: u64,
        _length: u64,
    ) -> ffs_error::Result<Vec<FiemapExtent>> {
        Ok(self.fiemap_extents.clone())
    }

    fn get_inode_fsxattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<FsxattrInfo> {
        Ok(self.fsxattr_info)
    }

    fn trim_range(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _start: u64,
        len: u64,
        _min_len: u64,
    ) -> ffs_error::Result<u64> {
        Ok(self.trim_result.min(len))
    }

    fn fs_uuid(&self) -> ffs_error::Result<[u8; 16]> {
        Ok(self.fs_uuid)
    }

    fn set_inode_fsxattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _info: FsxattrInfo,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    fn precache_extents(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    fn clear_extent_status_cache(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    fn get_inode_flags(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        Ok(self.flags)
    }

    fn get_inode_generation(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        Ok(self.generation)
    }

    fn set_inode_generation(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _generation: u32,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    fn get_encryption_policy_v1(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<[u8; 12]> {
        Ok(self.encryption_policy_v1)
    }

    fn get_encryption_policy_ex(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<(u8, Vec<u8>)> {
        Ok(self.encryption_policy_ex.clone())
    }

    fn get_fs_label(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        Ok(self.fs_label.clone())
    }

    fn set_fs_label(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        label: &[u8],
    ) -> ffs_error::Result<()> {
        if label.len() > FSLABEL_MAX {
            return Err(FfsError::Format(
                "filesystem label exceeds maximum length".to_owned(),
            ));
        }
        Ok(())
    }

    fn get_btrfs_fs_info(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        Ok(self.btrfs_fs_info.clone())
    }

    fn btrfs_ino_lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _treeid: u64,
        _objectid: u64,
    ) -> ffs_error::Result<(u64, Vec<u8>)> {
        Ok(self.btrfs_ino_lookup.clone())
    }

    fn get_btrfs_dev_info(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _devid_in: u64,
        _uuid_in: [u8; 16],
    ) -> ffs_error::Result<Vec<u8>> {
        Ok(self.btrfs_dev_info.clone())
    }

    fn set_inode_flags(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _flags: u32,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    fn move_ext(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _donor_fd: u32,
        _orig_start: u64,
        _donor_start: u64,
        len: u64,
    ) -> ffs_error::Result<u64> {
        Ok(self.move_ext_result.min(len))
    }
}

fn build_payload(cursor: &mut ByteCursor<'_>, len: usize) -> Vec<u8> {
    let mut payload = vec![0_u8; len];
    let copy_len = len.min(usize::from(cursor.next_u8()).saturating_mul(8));
    if copy_len > 0 {
        payload[..copy_len].copy_from_slice(&cursor.fill_bytes(copy_len));
    }
    payload
}

fn nul_terminated_bytes(cursor: &mut ByteCursor<'_>, len: usize) -> Vec<u8> {
    let mut bytes = cursor.fill_bytes(len);
    bytes.push(0);
    bytes
}

fn build_extents(cursor: &mut ByteCursor<'_>) -> Vec<FiemapExtent> {
    let count = usize::from(cursor.next_u8() % 4);
    let mut logical = 0_u64;
    let mut extents = Vec::with_capacity(count);
    for _ in 0..count {
        let length = 512_u64 * (1 + u64::from(cursor.next_u8() % 16));
        extents.push(FiemapExtent {
            logical,
            physical: logical ^ u64::from(cursor.next_u16()),
            length,
            flags: if cursor.next_bool() { 1 } else { 0 },
        });
        logical = logical.saturating_add(length);
    }
    extents
}

fn build_uuid(cursor: &mut ByteCursor<'_>) -> [u8; 16] {
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&cursor.fill_bytes(16));
    uuid
}

fn fiemap_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let mut request = vec![0_u8; FIEMAP_HEADER_SIZE];
    request[0..8].copy_from_slice(&cursor.next_u64().to_ne_bytes());
    request[8..16].copy_from_slice(&cursor.next_u64().to_ne_bytes());
    let flags = if cursor.next_bool() {
        FIEMAP_FLAG_SYNC
    } else {
        cursor.next_u32()
    };
    request[16..20].copy_from_slice(&flags.to_ne_bytes());
    request[24..28].copy_from_slice(&u32::from(cursor.next_u8() % 8).to_ne_bytes());
    let out_size = match cursor.next_u8() % 4 {
        0 => 0,
        1 => (FIEMAP_HEADER_SIZE - 1) as u32,
        2 => FIEMAP_HEADER_SIZE as u32,
        _ => {
            (FIEMAP_HEADER_SIZE + FIEMAP_EXTENT_SIZE * usize::from(1 + cursor.next_u8() % 3)) as u32
        }
    };
    (request, out_size)
}

fn fibmap_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let mut request = cursor.next_u32().to_ne_bytes().to_vec();
    match cursor.next_u8() % 4 {
        0 => request.clear(),
        1 => request.truncate(FIBMAP_SIZE - 1),
        2 => {}
        _ => request.extend(cursor.fill_bytes(4)),
    }
    let out_size = match cursor.next_u8() % 3 {
        0 => 0,
        1 => (FIBMAP_SIZE - 1) as u32,
        _ => FIBMAP_SIZE as u32,
    };
    (request, out_size)
}

fn fitrim_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let mut request = Vec::with_capacity(FITRIM_SIZE);
    request.extend_from_slice(&cursor.next_u64().to_ne_bytes());
    request.extend_from_slice(&cursor.next_u64().to_ne_bytes());
    request.extend_from_slice(&cursor.next_u64().to_ne_bytes());
    match cursor.next_u8() % 4 {
        0 => request.clear(),
        1 => request.truncate(FITRIM_SIZE - 1),
        2 => {}
        _ => request.extend(cursor.fill_bytes(8)),
    }
    let out_size = match cursor.next_u8() % 3 {
        0 => 0,
        1 => (FITRIM_SIZE - 1) as u32,
        _ => FITRIM_SIZE as u32,
    };
    (request, out_size)
}

fn fs_uuid_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let input_len = usize::from(cursor.next_u8() % 8);
    let out_size = match cursor.next_u8() % 3 {
        0 => 0,
        1 => (FS_IOC_GETFSUUID_SIZE - 1) as u32,
        _ => FS_IOC_GETFSUUID_SIZE as u32,
    };
    (cursor.fill_bytes(input_len), out_size)
}

fn fsxattr_get_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let input_len = usize::from(cursor.next_u8() % 8);
    let out_size = match cursor.next_u8() % 3 {
        0 => 0,
        1 => (FS_IOC_FSGETXATTR_SIZE - 1) as u32,
        _ => FS_IOC_FSGETXATTR_SIZE as u32,
    };
    (cursor.fill_bytes(input_len), out_size)
}

fn fsxattr_set_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let mut request = Vec::with_capacity(FS_IOC_FSSETXATTR_SIZE);
    request.extend_from_slice(&cursor.next_u32().to_le_bytes());
    request.extend_from_slice(&cursor.next_u32().to_le_bytes());
    request.extend_from_slice(&cursor.next_u32().to_le_bytes());
    request.extend_from_slice(&cursor.next_u32().to_le_bytes());
    request.extend_from_slice(&cursor.next_u32().to_le_bytes());
    request.extend_from_slice(&cursor.fill_bytes(8));
    match cursor.next_u8() % 4 {
        0 => request.clear(),
        1 => request.truncate(FS_IOC_FSSETXATTR_SIZE - 1),
        2 => {}
        _ => request.extend(cursor.fill_bytes(8)),
    }
    (request, cursor.next_u32())
}

fn no_payload_hint_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let input_len = usize::from(cursor.next_u8() % 16);
    (cursor.fill_bytes(input_len), cursor.next_u32())
}

fn get_encryption_policy_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let in_len = usize::from(cursor.next_u8() % 16);
    let request = cursor.fill_bytes(in_len);
    let out_size = match cursor.next_u8() % 4 {
        0 => 0,
        1 => (FSCRYPT_POLICY_V1_SIZE - 1) as u32,
        _ => FSCRYPT_POLICY_V1_SIZE as u32,
    };
    (request, out_size)
}

fn get_encryption_policy_ex_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let capacity = match cursor.next_u8() % 4 {
        0 => 0,
        1 => (FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V1_SIZE - 1) as u32,
        2 => (FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V1_SIZE) as u32,
        _ => (FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V2_SIZE) as u32,
    };
    let in_len = usize::try_from(capacity).unwrap_or(0);
    let mut request = cursor.fill_bytes(in_len);
    if request.len() >= FSCRYPT_POLICY_EX_HEADER_SIZE {
        let policy_capacity = request.len() - FSCRYPT_POLICY_EX_HEADER_SIZE;
        request[..FSCRYPT_POLICY_EX_HEADER_SIZE]
            .copy_from_slice(&(policy_capacity as u64).to_ne_bytes());
    }
    (request, capacity)
}

fn move_ext_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let mut request = vec![0_u8; MOVE_EXT_SIZE];
    let reserved = if cursor.next_bool() {
        0
    } else {
        cursor.next_u32()
    };
    let donor_fd = if cursor.next_bool() {
        i32::from(cursor.next_u8())
    } else {
        -1
    };
    request[0..4].copy_from_slice(&reserved.to_ne_bytes());
    request[4..8].copy_from_slice(&donor_fd.to_ne_bytes());
    request[8..16].copy_from_slice(&cursor.next_u64().to_ne_bytes());
    request[16..24].copy_from_slice(&cursor.next_u64().to_ne_bytes());
    request[24..32].copy_from_slice(&cursor.next_u64().to_ne_bytes());
    let out_size = match cursor.next_u8() % 3 {
        0 => 0,
        1 => (MOVE_EXT_SIZE - 1) as u32,
        _ => MOVE_EXT_SIZE as u32,
    };
    (request, out_size)
}

fn fs_label_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let len = usize::from(cursor.next_u8() % 40);
    let mut request = cursor.fill_bytes(len);
    if cursor.next_bool() {
        request.push(0);
    }
    let out_size = match cursor.next_u8() % 3 {
        0 => 0,
        1 => (FSLABEL_MAX - 1) as u32,
        _ => FSLABEL_MAX as u32,
    };
    (request, out_size)
}

fn fs_info_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let out_size = match cursor.next_u8() % 3 {
        0 => 0,
        1 => (BTRFS_IOC_FS_INFO_SIZE - 1) as u32,
        _ => BTRFS_IOC_FS_INFO_SIZE as u32,
    };
    (Vec::new(), out_size)
}

fn btrfs_dev_info_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let mut request = vec![0_u8; 24];
    request[0..8].copy_from_slice(&cursor.next_u64().to_le_bytes());
    request[8..24].copy_from_slice(&cursor.fill_bytes(16));
    if cursor.next_bool() {
        let extra_len = usize::from(cursor.next_u8() % 16);
        request.extend(cursor.fill_bytes(extra_len));
    }
    let out_size = match cursor.next_u8() % 3 {
        0 => 0,
        1 => (BTRFS_IOC_DEV_INFO_SIZE - 1) as u32,
        _ => BTRFS_IOC_DEV_INFO_SIZE as u32,
    };
    (request, out_size)
}

fn btrfs_ino_lookup_request(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, u32) {
    let mut request = vec![0_u8; BTRFS_INO_LOOKUP_ARGS_SIZE];
    request[0..8].copy_from_slice(&cursor.next_u64().to_le_bytes());
    request[8..16].copy_from_slice(&cursor.next_u64().to_le_bytes());
    let tail_len = usize::from(cursor.next_u8() % 32);
    request[16..16 + tail_len].copy_from_slice(&cursor.fill_bytes(tail_len));
    let out_size = match cursor.next_u8() % 3 {
        0 => 0,
        1 => (BTRFS_INO_LOOKUP_ARGS_SIZE - 1) as u32,
        _ => BTRFS_INO_LOOKUP_ARGS_SIZE as u32,
    };
    (request, out_size)
}

fn build_ioctl_request(kind: CommandKind, cursor: &mut ByteCursor<'_>) -> (u32, Vec<u8>, u32) {
    match kind {
        CommandKind::Fiemap => {
            let (request, out_size) = fiemap_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::GetFlags | CommandKind::GetVersion => {
            let out_size = if cursor.next_bool() {
                4
            } else {
                cursor.next_u32() % 4
            };
            (kind.cmd(), Vec::new(), out_size)
        }
        CommandKind::Fibmap => {
            let (request, out_size) = fibmap_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::Fitrim => {
            let (request, out_size) = fitrim_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::GetFsUuid => {
            let (request, out_size) = fs_uuid_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::GetFsxattr => {
            let (request, out_size) = fsxattr_get_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::SetFsxattr => {
            let (request, out_size) = fsxattr_set_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::PrecacheExtents | CommandKind::ClearExtentStatusCache => {
            let (request, out_size) = no_payload_hint_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::SetVersion | CommandKind::SetFlags => {
            let request_len = usize::from(cursor.next_u8() % 8);
            let request = cursor.fill_bytes(request_len);
            (kind.cmd(), request, 0)
        }
        CommandKind::GetEncryptionPolicy => {
            let (request, out_size) = get_encryption_policy_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::GetEncryptionPolicyEx => {
            let (request, out_size) = get_encryption_policy_ex_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::MoveExt => {
            let (request, out_size) = move_ext_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::GetFsLabel | CommandKind::SetFsLabel => {
            let (request, out_size) = fs_label_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::BtrfsFsInfo => {
            let (request, out_size) = fs_info_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::BtrfsDevInfo => {
            let (request, out_size) = btrfs_dev_info_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::BtrfsInoLookup => {
            let (request, out_size) = btrfs_ino_lookup_request(cursor);
            (kind.cmd(), request, out_size)
        }
        CommandKind::Unknown => {
            let cmd = cursor.next_u32();
            let request_len = usize::from(cursor.next_u8() % 64);
            (cmd, cursor.fill_bytes(request_len), cursor.next_u32())
        }
    }
}

fn classify_ioctl(data: &[u8]) -> IoctlOutcome {
    let mut cursor = ByteCursor::new(data);
    let kind = CommandKind::from_selector(cursor.next_u8());
    let read_only = cursor.next_bool();
    let ino = 1_u64 + u64::from(cursor.next_u8());
    let fh = u64::from(cursor.next_u16());
    let caller_pid = std::process::id();
    let fs = FuzzFs::from_cursor(&mut cursor);
    let options = MountOptions {
        read_only,
        ..MountOptions::default()
    };
    let fuse = FrankenFuse::with_options(Box::new(fs), &options);
    let (cmd, in_data, out_size) = build_ioctl_request(kind, &mut cursor);

    match fuse.dispatch_ioctl_for_fuzzing(caller_pid, 0, 0, ino, fh, cmd, &in_data, out_size) {
        Ok(payload) => IoctlOutcome::Data {
            len: payload.len(),
            crc32c: crc32c(&payload),
        },
        Err(errno) => IoctlOutcome::Err(errno),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let first = classify_ioctl(data);
    let second = classify_ioctl(data);
    assert_eq!(
        first, second,
        "ioctl dispatch classification must be deterministic for identical inputs"
    );
});
