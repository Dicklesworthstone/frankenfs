#![forbid(unsafe_code)]
//! FUSE adapter for FrankenFS.
//!
//! This crate is a thin translation layer: kernel FUSE requests arrive via the
//! `fuser` crate, get forwarded to a [`FsOps`] implementation (from `ffs-core`),
//! and errors are mapped through [`FfsError::to_errno()`].
//!
//! See [`per_core::PerCoreDispatcher`] for thread-per-core dispatch routing.

pub mod per_core;

use asupersync::Cx;
use ffs_core::{
    BackpressureDecision, BackpressureGate, BtrfsQgroupLimitRequest, BtrfsTreeSearchKey,
    DirEntry as FfsDirEntry, FIEMAP_EXTENT_UNWRITTEN, FiemapExtent, FileType as FfsFileType, FsOps,
    FsStat, FsxattrInfo, InodeAttr, ReleaseRequest, RequestOp, RequestScope, SeekWhence,
    SetAttrRequest, XattrSetMode,
};
use ffs_error::FfsError;
use ffs_types::{EXT4_EXTENTS_FL, InodeNumber};
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, MountOption, PollHandle, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLock,
    ReplyLseek, ReplyOpen, ReplyPoll, ReplyStatfs, ReplyStatx, ReplyWrite, ReplyXattr, Request,
    TimeOrNow, consts as fuse_consts, fuse_forget_one,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::raw::c_int;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

/// Default TTL for cached attributes and entries.
///
/// Read-only images are immutable, so a generous TTL is safe.
const ATTR_TTL: Duration = Duration::from_secs(60);
const MIN_SEQUENTIAL_READS_FOR_BATCH: u32 = 2;
const COALESCED_FETCH_MULTIPLIER: u32 = 4;
const MAX_COALESCED_READ_SIZE: u32 = 256 * 1024;
const FUSE_MAX_READ_BYTES: u32 = 16 * 1024 * 1024;
const MAX_PENDING_READAHEAD_ENTRIES: usize = 64;
const MAX_ACCESS_PREDICTOR_ENTRIES: usize = 4096;
const MAX_WRITEBACK_BATCH_PENDING_WRITES: usize = 8192;
const BACKPRESSURE_THROTTLE_DELAY: Duration = Duration::from_millis(5);
const BACKPRESSURE_SLEEP_CHECK_INTERVAL: Duration = Duration::from_millis(10);
const MOUNT_HANDLE_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const XATTR_FLAG_CREATE: i32 = 0x1;
const XATTR_FLAG_REPLACE: i32 = 0x2;
const FS_IOC_FIEMAP: u32 = 0xC020_660B;
const FIEMAP_HEADER_SIZE: usize = 32;
const FIEMAP_EXTENT_SIZE: usize = 56;
const FIEMAP_FLAG_SYNC: u32 = 0x0000_0001;
#[cfg(test)]
const FIEMAP_FLAG_XATTR: u32 = 0x0000_0002;
const FIEMAP_SUPPORTED_FLAGS: u32 = FIEMAP_FLAG_SYNC;
/// `EXT4_IOC_GETFLAGS` = `_IOR('f', 1, long)` on x86_64.
///
/// Linux FUSE fileattr plumbing still transfers these flags as `u32`
/// buffers, so the FUSE handler must not assume an 8-byte payload.
const EXT4_IOC_GETFLAGS: u32 = 0x8008_6601;
/// `EXT4_IOC_GETVERSION` = `_IOR('f', 3, long)` on x86_64.
///
/// The ext4 generation value is likewise surfaced through a `u32` payload in
/// the FUSE fileattr path.
const EXT4_IOC_GETVERSION: u32 = 0x8008_6603;
/// `EXT4_IOC_SETVERSION` = `_IOW('f', 4, long)` on x86_64.
///
/// The write-side FUSE payload is likewise treated as a 4-byte `u32`.
const EXT4_IOC_SETVERSION: u32 = 0x4008_6604;
/// `FS_IOC_GET_ENCRYPTION_POLICY` = `_IOW('f', 21, struct fscrypt_policy_v1)` on x86_64.
const FS_IOC_GET_ENCRYPTION_POLICY: u32 = 0x400C_6615;
/// `FS_IOC_GET_ENCRYPTION_POLICY_EX` = `_IOWR('f', 22, __u8[9])` on x86_64.
const FS_IOC_GET_ENCRYPTION_POLICY_EX: u32 = 0xC009_6616;
/// `EXT4_IOC_SETFLAGS` = `_IOW('f', 2, long)` on x86_64.
const EXT4_IOC_SETFLAGS: u32 = 0x4008_6602;
/// `EXT4_IOC_GETSTATE` = `_IOR('f', 41, __u32)` = `0x8004_6629`.
/// Returns the kernel-side runtime state bitmap for an inode
/// (`EXT4_STATE_FLAG_EXT_PRECACHED`, `NEW`, `NEWENTRY`,
/// `DA_ALLOC_CLOSE`). e2fsprogs / debugfs read it for diagnostic
/// dumps. Output is a single host-native `u32`.
const EXT4_IOC_GETSTATE: u32 = 0x8004_6629;
const EXT4_IOC_GETSTATE_SIZE: u32 = 4;
/// `FS_IOC_FSGETXATTR` = `_IOR('X', 31, struct fsxattr)` on x86_64.
/// `struct fsxattr` is 28 bytes: u32 xflags + u32 extsize + u32 nextents
/// + u32 projid + u32 cowextsize + 8-byte pad.
const FS_IOC_FSGETXATTR: u32 = 0x801C_5821;
const FS_IOC_FSGETXATTR_SIZE: u32 = 28;
/// `FIBMAP` = `_IO(0, 1)` = `0x0000_0001`. Legacy ioctl used by
/// `filefrag -B`, e2fsck, and e2image. Userspace passes a u32 input
/// holding the *logical* block index; the kernel rewrites the same
/// 4-byte buffer with the *physical* block number on return (0 for
/// a hole). FrankenFS routes this through `FsOps::fiemap` over a
/// 1-block window — fiemap already does the extent-tree walk.
const FIBMAP: u32 = 0x0000_0001;
const FIBMAP_SIZE: u32 = 4;
/// `FITRIM` = `_IOWR('X', 121, struct fstrim_range)` on x86_64.
/// `struct fstrim_range` is 24 bytes (3 x u64): start + len + minlen.
/// On success the kernel writes the bytes-discarded count back into
/// the `len` field of the user-supplied buffer; FrankenFS's userspace
/// FUSE has no direct discard path so this round-trips len = 0.
const FITRIM: u32 = 0xC018_5879;
const FITRIM_SIZE: u32 = 24;
/// `FS_IOC_GETFSUUID` = `_IOR(0x15, 0, struct fsuuid2)` on x86_64
/// (Linux 6.5+, see `<uapi/linux/fs.h>` `struct fsuuid2`). Reply is
/// 17 bytes: `u8 len` + `u8 uuid[16]`. Encoded ioctl number per
/// `_IOR((dir=2)<<30 | (size=17)<<16 | (type=0x15)<<8 | nr=0)` =
/// `0x8011_1500`.
const FS_IOC_GETFSUUID: u32 = 0x8011_1500;
const FS_IOC_GETFSUUID_SIZE: u32 = 17;
/// `FS_IOC_GETFSSYSFSPATH` = `_IOR(0x15, 1, struct fs_sysfs_path)` on
/// x86_64 (Linux 6.7+, see `<uapi/linux/fs.h>` `struct fs_sysfs_path`).
/// Reply is 129 bytes: `u8 len` + `u8 name[128]`. Encoded ioctl number
/// per `_IOR((dir=2)<<30 | (size=129)<<16 | (type=0x15)<<8 | nr=1)` =
/// `0x8081_1501`. Userspace probes (systemd-mount, blkid, util-linux)
/// silently skip `len == 0` rather than treating it as an error, so a
/// userspace FUSE backend whose `ByteDevice` has no /sys entry should
/// surface an empty path here — that mirrors what tmpfs / overlayfs
/// already do.
const FS_IOC_GETFSSYSFSPATH: u32 = 0x8081_1501;
const FS_IOC_GETFSSYSFSPATH_SIZE: u32 = 129;
const FS_IOC_GETFSSYSFSPATH_NAME_MAX: usize = 128;
/// `FS_IOC_FSSETXATTR` = `_IOW('X', 32, struct fsxattr)` on x86_64.
/// Same 28-byte payload as the GET side; userspace passes the new
/// projid + xflags, ext4 rejects non-zero extsize/cowextsize and
/// any unknown xflags bit (see `xflags_to_ext4_flags`).
const FS_IOC_FSSETXATTR: u32 = 0x401C_5820;
const FS_IOC_FSSETXATTR_SIZE: usize = 28;
/// `EXT4_IOC_PRECACHE_EXTENTS` = `_IO('f', 38)` = `0x0000_6626`. Hint
/// ioctl that asks ext4 to pull the inode's on-disk extent tree into
/// the page cache so subsequent reads don't stall on metadata I/O —
/// `e2fsck` pass 1 and `debugfs dump_extents` use it before walking
/// large fragmented files. No input or output payload (it's `_IO`,
/// size=0); the kernel returns 0 on success and never on a valid
/// inode (block-mapped inodes are a no-op, not an error).
const EXT4_IOC_PRECACHE_EXTENTS: u32 = 0x0000_6626;
/// `EXT4_IOC_CLEAR_ES_CACHE` = `_IO('f', 40)` = `0x0000_6628`. Hint
/// ioctl that asks ext4 to drop the in-memory extent status (`es`)
/// cache for an inode so the next read repopulates it from the
/// on-disk extent tree. e2fsprogs uses it to defeat caching after
/// offline metadata edits via `debugfs`. No input or output payload
/// (it's `_IO`, size=0).
const EXT4_IOC_CLEAR_ES_CACHE: u32 = 0x0000_6628;
/// `EXT4_IOC_MOVE_EXT` = `_IOWR('f', 15, struct move_extent)` on x86_64.
const EXT4_IOC_MOVE_EXT: u32 = 0xC028_660F;
/// `EXT4_IOC_GROUP_EXTEND` = `_IOW('f', 7, unsigned long)` on x86_64.
/// Extend the filesystem by adding blocks to the last block group.
const EXT4_IOC_GROUP_EXTEND: u32 = 0x4008_6607;
/// `EXT4_IOC_RESIZE_FS` = `_IOW('f', 16, __u64)` on x86_64.
/// Resize filesystem to specified number of blocks.
const EXT4_IOC_RESIZE_FS: u32 = 0x4008_6610;
/// `EXT4_IOC_GROUP_ADD` = `_IOW('f', 8, struct ext4_new_group_input)` on x86_64.
/// Add a new block group to the filesystem.
const EXT4_IOC_GROUP_ADD: u32 = 0x4010_6608;
/// `EXT4_IOC_ALLOC_DA_BLKS` = `_IO('f', 12)`.
/// Force allocation of all delayed-allocation blocks.
const EXT4_IOC_ALLOC_DA_BLKS: u32 = 0x0000_660C;
/// `EXT4_IOC_MIGRATE` = `_IO('f', 9)`.
/// Migrate inode from ext3 format to ext4 format (extents).
const EXT4_IOC_MIGRATE: u32 = 0x0000_6609;
/// `EXT4_IOC_SWAP_BOOT` = `_IO('f', 17)`.
/// Swap contents with the boot inode for boot loader installation.
const EXT4_IOC_SWAP_BOOT: u32 = 0x0000_6611;
/// `FS_IOC_SHUTDOWN` = `_IOW('X', 125, __u32)`.
/// Shutdown filesystem (emergency stop, data loss risk).
const FS_IOC_SHUTDOWN: u32 = 0x4004_587D;
/// `FIFREEZE` = `_IOWR('X', 119, int)`.
/// Freeze the filesystem (quiesce for snapshots).
const FIFREEZE: u32 = 0xC004_5877;
/// `FITHAW` = `_IOWR('X', 120, int)`.
/// Thaw a frozen filesystem.
const FITHAW: u32 = 0xC004_5878;
/// `FIGETBSZ` = `_IO(0x00, 2)`.
/// Get filesystem block size.
const FIGETBSZ: u32 = 0x0000_0002;
/// `FS_IOC_GETVERSION` = `_IOR('v', 1, long)`.
/// Get inode generation number (generic VFS variant).
const FS_IOC_GETVERSION: u32 = 0x8008_7601;
/// `FS_IOC_SETVERSION` = `_IOW('v', 2, long)`.
/// Set inode generation number (generic VFS variant).
const FS_IOC_SETVERSION: u32 = 0x4008_7602;
/// `FS_IOC_GETFSLABEL` = `_IOR(0x94, 0x31, char[FSLABEL_MAX])` on x86_64.
const FS_IOC_GETFSLABEL: u32 = 0x8100_9431;
/// `FS_IOC_SETFSLABEL` = `_IOW(0x94, 0x32, char[FSLABEL_MAX])` on x86_64.
const FS_IOC_SETFSLABEL: u32 = 0x4100_9432;
const FSLABEL_MAX: usize = 256;
const FSLABEL_MAX_U32: u32 = 256;
/// `BTRFS_IOC_FS_INFO` = `_IOR(0x94, 0x1F, struct btrfs_ioctl_fs_info_args)`
/// on x86_64.  The args struct is 1024 bytes of read-only fs metadata
/// (`max_id`, `num_devices`, `fsid`, `nodesize`, `sectorsize`,
/// `clone_alignment`, `csum_type/size`, `flags`, `generation`,
/// `metadata_uuid`, plus pad-to-1K).
const BTRFS_IOC_FS_INFO: u32 = 0x8400_941F;
/// Size of the `btrfs_ioctl_fs_info_args` reply payload, mirrored from
/// `ffs_core::BTRFS_FS_INFO_ARGS_SIZE` so the FUSE ioctl handler can
/// reject undersized out buffers with `EINVAL` before dispatching to
/// the backend.
const BTRFS_IOC_FS_INFO_SIZE: u32 = 1024;
/// `BTRFS_IOC_DEV_INFO` = `_IOWR(0x94, 0x1E, struct btrfs_ioctl_dev_info_args)`
/// on x86_64.  `_IOWR` means the ioctl carries both input (caller-selected
/// `devid` + `uuid` lookup keys) and output (resolved device metadata).  The
/// args struct is 4096 bytes: 40 bytes of named fields (devid, uuid[16],
/// bytes_used, total_bytes), 3032 bytes of reserved `__u64 unused[379]`, and
/// a 1024-byte `path` tail.
const BTRFS_IOC_DEV_INFO: u32 = 0xD000_941E;
/// Size of the `btrfs_ioctl_dev_info_args` payload (input and output share
/// the same struct shape for `_IOWR` ioctls).  Mirrored from
/// `ffs_core::BTRFS_DEV_INFO_ARGS_SIZE`.
const BTRFS_IOC_DEV_INFO_SIZE: u32 = 4096;
/// `BTRFS_IOC_INO_LOOKUP` = `_IOWR(0x94, 18, struct btrfs_ioctl_ino_lookup_args)`
/// on x86_64. The args struct is 4096 bytes: treeid(u64) + objectid(u64) + name[4080].
const BTRFS_IOC_INO_LOOKUP: u32 = 0xD000_9412;
/// Size of `btrfs_ioctl_ino_lookup_args`: 8 + 8 + 4080 = 4096 bytes.
const BTRFS_INO_LOOKUP_ARGS_SIZE: u32 = 4096;
/// `BTRFS_IOC_DEFAULT_SUBVOL` = `_IOW(0x94, 19, __u64)` on x86_64.
/// Sets the filesystem default subvolume tree objectid.
const BTRFS_IOC_DEFAULT_SUBVOL: u32 = 0x4008_9413;
/// `BTRFS_IOC_TREE_SEARCH` = `_IOWR(0x94, 17, struct btrfs_ioctl_search_args)`
/// on x86_64. The args struct is a 104-byte search key followed by a 3992-byte
/// buffer of `(btrfs_ioctl_search_header, item_payload)` records.
const BTRFS_IOC_TREE_SEARCH: u32 = 0xD000_9411;
const BTRFS_TREE_SEARCH_KEY_SIZE: usize = 104;
const BTRFS_TREE_SEARCH_ARGS_SIZE: u32 = 4096;
const BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET: usize = 64;
/// `BTRFS_IOC_SUBVOL_GETFLAGS` = `_IOR(0x94, 25, __u64)` on x86_64.
/// Returns subvolume flags (BTRFS_SUBVOL_RDONLY etc.) as a u64.
const BTRFS_IOC_SUBVOL_GETFLAGS: u32 = 0x8008_9419;
/// `BTRFS_IOC_SUBVOL_SETFLAGS` = `_IOW(0x94, 26, __u64)` on x86_64.
/// Sets subvolume flags (BTRFS_SUBVOL_RDONLY etc.) from a u64.
const BTRFS_IOC_SUBVOL_SETFLAGS: u32 = 0x4008_941A;
/// `BTRFS_IOC_SYNC` = `_IO(0x94, 8)` on x86_64.
/// Forces filesystem sync/commit.
const BTRFS_IOC_SYNC: u32 = 0x9408;
/// `BTRFS_IOC_TRANS_START` = `_IO(0x94, 6)` on x86_64.
/// Starts an explicit btrfs transaction.
const BTRFS_IOC_TRANS_START: u32 = 0x9406;
/// `BTRFS_IOC_TRANS_END` = `_IO(0x94, 7)` on x86_64.
/// Ends an explicit btrfs transaction.
const BTRFS_IOC_TRANS_END: u32 = 0x9407;
/// `BTRFS_IOC_START_SYNC` = `_IOR(0x94, 24, __u64)` on x86_64.
/// Starts a transaction sync and returns a generation/transid token.
const BTRFS_IOC_START_SYNC: u32 = 0x8008_9418;
/// `BTRFS_IOC_WAIT_SYNC` = `_IOW(0x94, 22, __u64)` on x86_64.
/// Waits for the supplied generation/transid token to become durable.
const BTRFS_IOC_WAIT_SYNC: u32 = 0x4008_9416;
const BTRFS_SYNC_TRANSID_SIZE: u32 = 8;
/// `BTRFS_IOC_GET_FEATURES` = `_IOR(0x94, 57, struct btrfs_ioctl_feature_flags)`.
/// Returns compat/compat_ro/incompat feature flags (3 x u64 = 24 bytes).
const BTRFS_IOC_GET_FEATURES: u32 = 0x8018_9439;
const BTRFS_FEATURE_FLAGS_SIZE: u32 = 24;
/// `BTRFS_IOC_SET_FEATURES` = `_IOW(0x94, 57, struct btrfs_ioctl_feature_flags[2])`.
/// Sets and clears btrfs feature-flag deltas.
const BTRFS_IOC_SET_FEATURES: u32 = 0x4030_9439;
const BTRFS_SET_FEATURES_ARGS_SIZE: u32 = 48;
/// `BTRFS_IOC_GET_SUPPORTED_FEATURES` = `_IOR(0x94, 57, struct btrfs_ioctl_feature_flags[3])`.
/// Returns three 24-byte feature-flag sets: supported, safe-to-set, and safe-to-clear.
const BTRFS_IOC_GET_SUPPORTED_FEATURES: u32 = 0x8048_9439;
const BTRFS_SUPPORTED_FEATURE_FLAGS_SIZE: u32 = 72;
/// `BTRFS_IOC_SPACE_INFO` = `_IOWR(0x94, 20, struct btrfs_ioctl_space_args)`.
/// Returns per-profile space usage (Data/Metadata/System × Single/DUP/RAID).
/// Input: 16-byte header with space_slots count. Output: header + space_info array.
const BTRFS_IOC_SPACE_INFO: u32 = 0xC010_9414;
const BTRFS_SPACE_ARGS_HEADER_SIZE: u32 = 16;
/// `BTRFS_IOC_INO_PATHS` = `_IOWR(0x94, 35, struct btrfs_ioctl_ino_path_args)`.
/// Given an inode number, returns all file paths that reference it.
const BTRFS_IOC_INO_PATHS: u32 = 0xC038_9423;
const BTRFS_INO_PATH_ARGS_SIZE: u32 = 56;
/// `BTRFS_IOC_LOGICAL_INO` = `_IOWR(0x94, 36, struct btrfs_ioctl_logical_ino_args)`.
/// Given a logical byte address, returns inodes that reference it.
const BTRFS_IOC_LOGICAL_INO: u32 = 0xC038_9424;
const BTRFS_LOGICAL_INO_ARGS_SIZE: u32 = 56;
/// `BTRFS_IOC_SCRUB` = `_IOWR(0x94, 27, struct btrfs_ioctl_scrub_args)`.
/// Start or continue a scrub operation on a device.
const BTRFS_IOC_SCRUB: u32 = 0xC400_941B;
/// `BTRFS_IOC_SCRUB_CANCEL` = `_IO(0x94, 28)`.
/// Cancel a running scrub operation.
const BTRFS_IOC_SCRUB_CANCEL: u32 = 0x0000_941C;
/// `BTRFS_IOC_SCRUB_PROGRESS` = `_IOWR(0x94, 29, struct btrfs_ioctl_scrub_args)`.
/// Query progress of a running scrub operation.
const BTRFS_IOC_SCRUB_PROGRESS: u32 = 0xC400_941D;
const BTRFS_SCRUB_ARGS_SIZE: u32 = 1024;
/// `BTRFS_IOC_QUOTA_RESCAN_WAIT` = `_IO(0x94, 46)` on x86_64.
/// Waits for an in-progress qgroup quota rescan to finish.
const BTRFS_IOC_QUOTA_RESCAN_WAIT: u32 = 0x942E;
/// `BTRFS_IOC_QUOTA_RESCAN_STATUS` = `_IOR(0x94, 45, struct btrfs_ioctl_quota_rescan_args)`.
/// Queries qgroup quota rescan progress.
const BTRFS_IOC_QUOTA_RESCAN_STATUS: u32 = 0x8040_942D;
/// `BTRFS_IOC_QUOTA_RESCAN` = `_IOW(0x94, 44, struct btrfs_ioctl_quota_rescan_args)`.
/// Starts a qgroup quota rescan.
const BTRFS_IOC_QUOTA_RESCAN: u32 = 0x4040_942C;
const BTRFS_QUOTA_RESCAN_ARGS_SIZE: u32 = 64;
/// `BTRFS_IOC_QUOTA_CTL` = `_IOWR(0x94, 40, struct btrfs_ioctl_quota_ctl_args)`.
/// Enables, disables, or enables simple btrfs quotas.
const BTRFS_IOC_QUOTA_CTL: u32 = 0xC010_9428;
const BTRFS_QUOTA_CTL_ARGS_SIZE: u32 = 16;
/// `BTRFS_IOC_QGROUP_ASSIGN` = `_IOW(0x94, 41, struct btrfs_ioctl_qgroup_assign_args)`.
/// Assigns or removes a btrfs qgroup parent/child relationship.
const BTRFS_IOC_QGROUP_ASSIGN: u32 = 0x4018_9429;
const BTRFS_QGROUP_ASSIGN_ARGS_SIZE: u32 = 24;
/// `BTRFS_IOC_QGROUP_CREATE` = `_IOW(0x94, 42, struct btrfs_ioctl_qgroup_create_args)`.
/// Creates or removes a btrfs qgroup.
const BTRFS_IOC_QGROUP_CREATE: u32 = 0x4010_942A;
const BTRFS_QGROUP_CREATE_ARGS_SIZE: u32 = 16;
/// `BTRFS_IOC_QGROUP_LIMIT` = `_IOR(0x94, 43, struct btrfs_ioctl_qgroup_limit_args)`.
/// Sets btrfs qgroup limit fields.
const BTRFS_IOC_QGROUP_LIMIT: u32 = 0x8030_942B;
const BTRFS_QGROUP_LIMIT_ARGS_SIZE: u32 = 48;
/// `BTRFS_IOC_DEFRAG_RANGE` = `_IOW(0x94, 16, struct btrfs_ioctl_defrag_range_args)`.
/// Defragment a range of a file.
const BTRFS_IOC_DEFRAG_RANGE: u32 = 0x4030_9410;
const BTRFS_DEFRAG_RANGE_ARGS_SIZE: u32 = 48;
/// `BTRFS_IOC_SNAP_CREATE_V2` = `_IOW(0x94, 23, struct btrfs_ioctl_vol_args_v2)`.
/// Create a snapshot of a subvolume.
const BTRFS_IOC_SNAP_CREATE_V2: u32 = 0x5000_9417;
/// `BTRFS_IOC_SNAP_DESTROY` = `_IOW(0x94, 15, struct btrfs_ioctl_vol_args)`.
/// Delete a snapshot or subvolume.
const BTRFS_IOC_SNAP_DESTROY: u32 = 0x5000_940F;
/// `BTRFS_IOC_SNAP_DESTROY_V2` = `_IOW(0x94, 63, struct btrfs_ioctl_vol_args_v2)`.
/// Extended snapshot destroy with subvol_id field.
const BTRFS_IOC_SNAP_DESTROY_V2: u32 = 0x5000_943F;
/// `BTRFS_IOC_LOGICAL_INO_V2` = `_IOWR(0x94, 59, struct btrfs_ioctl_logical_ino_args)`.
/// Extended logical to inode mapping with flags.
const BTRFS_IOC_LOGICAL_INO_V2: u32 = 0xD038_943B;
/// `BTRFS_IOC_SUBVOL_CREATE_V2` = `_IOW(0x94, 24, struct btrfs_ioctl_vol_args_v2)`.
/// Create a new subvolume.
const BTRFS_IOC_SUBVOL_CREATE_V2: u32 = 0x5000_9418;
/// `BTRFS_IOC_ADD_DEV` = `_IOW(0x94, 10, struct btrfs_ioctl_vol_args)`.
/// Add a btrfs device by path.
const BTRFS_IOC_ADD_DEV: u32 = 0x5000_940A;
/// `BTRFS_IOC_RM_DEV` = `_IOW(0x94, 11, struct btrfs_ioctl_vol_args)`.
/// Remove a btrfs device by path.
const BTRFS_IOC_RM_DEV: u32 = 0x5000_940B;
/// `BTRFS_IOC_RM_DEV_V2` = `_IOW(0x94, 58, struct btrfs_ioctl_vol_args_v2)`.
/// Remove a btrfs device by name or device id.
const BTRFS_IOC_RM_DEV_V2: u32 = 0x5000_943A;
/// `BTRFS_IOC_ENCODED_READ` = `_IOR(0x94, 64, struct btrfs_ioctl_encoded_io_args)`.
/// Read compressed extents directly without decompression.
const BTRFS_IOC_ENCODED_READ: u32 = 0x8040_9440;
/// `BTRFS_IOC_ENCODED_WRITE` = `_IOW(0x94, 65, struct btrfs_ioctl_encoded_io_args)`.
/// Write pre-compressed data directly.
const BTRFS_IOC_ENCODED_WRITE: u32 = 0x4040_9441;
const BTRFS_ENCODED_IO_ARGS_SIZE: u32 = 64;
/// `BTRFS_IOC_RESIZE` = `_IOW(0x94, 3, struct btrfs_ioctl_vol_args)`.
/// Resize filesystem (grow or shrink).
const BTRFS_IOC_RESIZE: u32 = 0x5000_9403;
/// `BTRFS_IOC_DEV_REPLACE` = `_IOWR(0x94, 53, struct btrfs_ioctl_dev_replace_args)`.
/// Start/cancel/query device replacement.
const BTRFS_IOC_DEV_REPLACE: u32 = 0xCA28_9435;
const BTRFS_DEV_REPLACE_ARGS_SIZE: u32 = 2600;
/// `BTRFS_IOC_DEFRAG` = `_IOW(0x94, 2, struct btrfs_ioctl_vol_args)`.
/// Defragment file (v1 legacy ioctl).
const BTRFS_IOC_DEFRAG: u32 = 0x5000_9402;
/// `BTRFS_IOC_SCAN_DEV` = `_IOW(0x94, 4, struct btrfs_ioctl_vol_args)`.
/// Scan device for btrfs filesystem.
const BTRFS_IOC_SCAN_DEV: u32 = 0x5000_9404;
/// `BTRFS_IOC_FORGET_DEV` = `_IOW(0x94, 5, struct btrfs_ioctl_vol_args)`.
/// Forget a stale btrfs device by path.
const BTRFS_IOC_FORGET_DEV: u32 = 0x5000_9405;
/// `BTRFS_IOC_SEND` = `_IOW(0x94, 38, struct btrfs_ioctl_send_args)`.
/// Send subvolume as byte stream for btrfs send/receive.
const BTRFS_IOC_SEND: u32 = 0x4048_9426;
const BTRFS_SEND_ARGS_SIZE: u32 = 72;
/// `BTRFS_IOC_SET_RECEIVED_SUBVOL` = `_IOWR(0x94, 37, struct btrfs_ioctl_received_subvol_args)`.
/// Set received UUID after btrfs receive.
const BTRFS_IOC_SET_RECEIVED_SUBVOL: u32 = 0xC040_9425;
const BTRFS_RECEIVED_SUBVOL_ARGS_SIZE: u32 = 64;
/// `BTRFS_IOC_SET_FSLABEL` = `_IOW(0x94, 50, char[256])`.
/// Set filesystem label.
const BTRFS_IOC_SET_FSLABEL: u32 = 0x4100_9432;
/// `BTRFS_IOC_FILE_EXTENT_SAME` = `_IOWR(0x94, 54, struct btrfs_ioctl_same_args)`.
/// Deduplicate file extents (alias for FIDEDUPERANGE).
const BTRFS_IOC_FILE_EXTENT_SAME: u32 = 0xC018_9436;
const BTRFS_SAME_ARGS_SIZE: u32 = 24;
const BTRFS_VOL_ARGS_SIZE: u32 = 4096;
/// `FICLONE` = `_IOW(0x94, 9, int)`.
/// Clone (reflink) entire file from source fd.
const FICLONE: u32 = 0x4004_9409;
/// `BTRFS_IOC_CLONE` - alias for FICLONE.
const BTRFS_IOC_CLONE: u32 = FICLONE;
/// `FICLONERANGE` = `_IOW(0x94, 13, struct file_clone_range)`.
/// Clone a range of blocks between files.
const FICLONERANGE: u32 = 0x4020_940D;
/// `BTRFS_IOC_CLONE_RANGE` - alias for FICLONERANGE.
const BTRFS_IOC_CLONE_RANGE: u32 = FICLONERANGE;
const FILE_CLONE_RANGE_SIZE: u32 = 32;
/// `BTRFS_IOC_BALANCE_V2` = `_IOWR(0x94, 32, struct btrfs_ioctl_balance_args)`.
/// Start balance operation with filters.
const BTRFS_IOC_BALANCE_V2: u32 = 0xC400_9420;
/// `BTRFS_IOC_BALANCE_CTL` = `_IOW(0x94, 33, int)`.
/// Control balance: pause (1), cancel (2), resume (3).
const BTRFS_IOC_BALANCE_CTL: u32 = 0x4004_9421;
/// `BTRFS_IOC_BALANCE_PROGRESS` = `_IOR(0x94, 34, struct btrfs_ioctl_balance_args)`.
/// Query balance progress.
const BTRFS_IOC_BALANCE_PROGRESS: u32 = 0x8400_9422;
const BTRFS_BALANCE_ARGS_SIZE: u32 = 1024;
/// `BTRFS_IOC_GET_FSLABEL` = `_IOR(0x94, 49, char[256])`.
/// Get filesystem label from superblock.
const BTRFS_IOC_GET_FSLABEL: u32 = 0x8100_9431;
const BTRFS_FSLABEL_SIZE: u32 = 256;
/// `BTRFS_IOC_GET_DEV_STATS` = `_IOWR(0x94, 52, struct btrfs_ioctl_get_dev_stats)`.
/// Get device error statistics (1032 bytes).
const BTRFS_IOC_GET_DEV_STATS: u32 = 0xC408_9434;
const BTRFS_DEV_STATS_SIZE: u32 = 1032;
/// `BTRFS_IOC_GET_SUBVOL_INFO` = `_IOR(0x94, 60, struct btrfs_ioctl_get_subvol_info_args)`.
/// Get subvolume info for the mounted subvol or specified inode.
const BTRFS_IOC_GET_SUBVOL_INFO: u32 = 0x81F8_943C;
const BTRFS_SUBVOL_INFO_SIZE: u32 = 504;
/// `BTRFS_IOC_TREE_SEARCH_V2` = `_IOWR(0x94, 17, struct btrfs_ioctl_search_args_v2)`.
/// Extended tree search with variable-sized buffer.
const BTRFS_IOC_TREE_SEARCH_V2: u32 = 0xC070_9411;
const BTRFS_TREE_SEARCH_V2_HEADER_SIZE: usize = BTRFS_TREE_SEARCH_KEY_SIZE + 8;
const BTRFS_TREE_SEARCH_V2_HEADER_SIZE_U32: u32 = 112;
/// `BTRFS_IOC_INO_LOOKUP_USER` = `_IOWR(0x94, 62, struct btrfs_ioctl_ino_lookup_user_args)`.
/// Unprivileged inode path lookup (4096 byte args).
const BTRFS_IOC_INO_LOOKUP_USER: u32 = 0xD000_943E;
const BTRFS_INO_LOOKUP_USER_SIZE: u32 = 4096;
/// `BTRFS_IOC_GET_SUBVOL_ROOTREF` = `_IOWR(0x94, 61, struct btrfs_ioctl_get_subvol_rootref_args)`.
/// Get subvolume parent references (4096 byte args).
const BTRFS_IOC_GET_SUBVOL_ROOTREF: u32 = 0xD000_943D;
const BTRFS_SUBVOL_ROOTREF_SIZE: u32 = 4096;
const FSCRYPT_POLICY_V1_SIZE: usize = 12;
#[cfg(test)]
const FSCRYPT_POLICY_V2_VERSION: u8 = 2;
#[cfg(test)]
const FSCRYPT_POLICY_V2_SIZE: usize = 24;
#[cfg(test)]
const FSCRYPT_POLICY_V1_SIZE_U32: u32 = 12;
#[cfg(test)]
const FSCRYPT_POLICY_V2_SIZE_U32: u32 = 24;
const FSCRYPT_POLICY_EX_HEADER_SIZE: usize = 8;
#[cfg(test)]
const FSCRYPT_POLICY_EX_HEADER_SIZE_U32: u32 = 8;
const FIEMAP_START_OFFSET: usize = 0;
const FIEMAP_LENGTH_OFFSET: usize = 8;
const FIEMAP_FLAGS_OFFSET: usize = 16;
const FIEMAP_MAPPED_EXTENTS_OFFSET: usize = 20;
const FIEMAP_EXTENT_COUNT_OFFSET: usize = 24;
const MOVE_EXT_SIZE: usize = 40;
const MOVE_EXT_RESERVED_OFFSET: usize = 0;
const MOVE_EXT_DONOR_FD_OFFSET: usize = 4;
const MOVE_EXT_ORIG_START_OFFSET: usize = 8;
const MOVE_EXT_DONOR_START_OFFSET: usize = 16;
const MOVE_EXT_LEN_OFFSET: usize = 24;
const MOVE_EXT_MOVED_LEN_OFFSET: usize = 32;
const MOVE_EXT_PAGE_SIZE_BYTES: u64 = 4096;
const EXT4_MOVE_EXT_MAX_BLOCKS: u64 = 0xFFFF_FFFF;
const MOVE_EXT_SCENARIO_ID: &str = "ext4_ioctl_move_ext";
const MOVE_EXT_SUCCESS_ERROR_CLASS: &str = "none";

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FuseError {
    #[error("invalid mountpoint: {0}")]
    InvalidMountpoint(String),
    #[error(transparent)]
    UnsupportedFeature(#[from] FfsError),
    #[error("mount I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ── FUSE error context ─────────────────────────────────────────────────────

/// Structured error context for FUSE operation failures.
///
/// Captures the operation name, inode, optional offset, and the underlying
/// error. Used to produce consistent, structured tracing for every FUSE
/// error reply.
pub struct FuseErrorContext<'a> {
    pub error: &'a FfsError,
    pub operation: &'static str,
    pub ino: u64,
    pub offset: Option<u64>,
}

impl FuseErrorContext<'_> {
    /// Log this error context via tracing and return the errno for the reply.
    pub fn log_and_errno(&self) -> c_int {
        let errno = self.error.to_errno();
        // ENOENT on lookup is normal — log at trace instead of warn.
        if errno == libc::ENOENT {
            trace!(
                op = self.operation,
                ino = self.ino,
                errno,
                error = %self.error,
                "FUSE op returned ENOENT"
            );
        } else {
            warn!(
                op = self.operation,
                ino = self.ino,
                offset = self.offset,
                errno,
                error = %self.error,
                "FUSE op failed"
            );
        }
        errno
    }
}

// ── Type conversions ────────────────────────────────────────────────────────

/// Convert an `ffs_core::FileType` to `fuser::FileType`.
fn to_fuser_file_type(ft: FfsFileType) -> FileType {
    match ft {
        FfsFileType::RegularFile => FileType::RegularFile,
        FfsFileType::Directory => FileType::Directory,
        FfsFileType::Symlink => FileType::Symlink,
        FfsFileType::BlockDevice => FileType::BlockDevice,
        FfsFileType::CharDevice => FileType::CharDevice,
        FfsFileType::Fifo => FileType::NamedPipe,
        FfsFileType::Socket => FileType::Socket,
    }
}

/// Convert an `ffs_core::InodeAttr` to `fuser::FileAttr`.
fn to_file_attr(attr: &InodeAttr) -> FileAttr {
    FileAttr {
        ino: attr.ino.0,
        size: attr.size,
        blocks: attr.blocks,
        atime: attr.atime,
        mtime: attr.mtime,
        ctime: attr.ctime,
        crtime: attr.crtime,
        kind: to_fuser_file_type(attr.kind),
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        blksize: attr.blksize,
        flags: 0,
    }
}

// ── Mount options ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WritebackCacheMode {
    #[default]
    Disabled,
    Enabled,
}

impl WritebackCacheMode {
    #[must_use]
    pub const fn from_enabled(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Debug, Clone)]
pub struct MountOptions {
    pub read_only: bool,
    pub allow_other: bool,
    pub auto_unmount: bool,
    /// Explicit opt-in to the kernel FUSE `writeback_cache` mount option.
    ///
    /// Defaults off. Callers must only enable this after the writeback-cache
    /// audit gate and dirty-page ordering oracle have accepted the mount.
    pub writeback_cache: WritebackCacheMode,
    /// Optional append-only trace file for recording every FUSE ioctl callback.
    ///
    /// Used by end-to-end harness tests to distinguish kernel/VFS rejections
    /// from requests that actually reached FrankenFS userspace handling.
    pub ioctl_trace_path: Option<PathBuf>,
    /// Number of worker threads for FUSE dispatch.
    ///
    /// For explicit non-zero values, FrankenFS maps this to kernel FUSE queue
    /// tuning (`max_background` and `congestion_threshold`) so mount behavior
    /// changes under load. A value of `0` means "auto" and uses defaults.
    pub worker_threads: usize,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: true,
            allow_other: false,
            auto_unmount: true,
            writeback_cache: WritebackCacheMode::Disabled,
            ioctl_trace_path: None,
            worker_threads: 0,
        }
    }
}

impl MountOptions {
    /// Resolved thread count.
    ///
    /// `worker_threads == 0` means "auto": `min(available_parallelism, 8)`.
    /// Non-zero values are returned as-is (clamped to at least 1).
    #[must_use]
    pub fn resolved_thread_count(&self) -> usize {
        if self.worker_threads == 0 {
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(8)
        } else {
            self.worker_threads.max(1)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum MountOptionParseError {
    NonUtf8,
    EmptyOption,
    EmptyKey,
    MissingValue { option: String },
    UnexpectedValue { option: String },
    InvalidValue { option: String, value: String },
    UnknownOption { option: String },
}

#[doc(hidden)]
pub fn parse_mount_options_for_fuzzing(
    input: &[u8],
) -> Result<MountOptions, MountOptionParseError> {
    let text = std::str::from_utf8(input).map_err(|_| MountOptionParseError::NonUtf8)?;
    parse_mount_option_text(text)
}

fn parse_mount_option_text(text: &str) -> Result<MountOptions, MountOptionParseError> {
    let mut options = MountOptions::default();
    if text.trim().is_empty() {
        return Ok(options);
    }

    for raw_option in text.split(',') {
        let option = raw_option.trim();
        if option.is_empty() {
            return Err(MountOptionParseError::EmptyOption);
        }
        apply_mount_option(option, &mut options)?;
    }

    Ok(options)
}

fn apply_mount_option(
    option: &str,
    options: &mut MountOptions,
) -> Result<(), MountOptionParseError> {
    let (key, value) = split_mount_option(option)?;
    match key {
        "ro" => {
            reject_mount_option_value(key, value)?;
            options.read_only = true;
        }
        "rw" => {
            reject_mount_option_value(key, value)?;
            options.read_only = false;
        }
        "read_only" => {
            options.read_only = parse_mount_bool(key, value)?;
        }
        "allow_other" => {
            options.allow_other = parse_mount_bool_or_flag(key, value, true)?;
        }
        "noallow_other" => {
            reject_mount_option_value(key, value)?;
            options.allow_other = false;
        }
        "auto_unmount" => {
            options.auto_unmount = parse_mount_bool_or_flag(key, value, true)?;
        }
        "noauto_unmount" => {
            reject_mount_option_value(key, value)?;
            options.auto_unmount = false;
        }
        "writeback_cache" => {
            options.writeback_cache =
                WritebackCacheMode::from_enabled(parse_mount_bool_or_flag(key, value, true)?);
        }
        "nowriteback_cache" => {
            reject_mount_option_value(key, value)?;
            options.writeback_cache = WritebackCacheMode::Disabled;
        }
        "worker_threads" | "threads" => {
            options.worker_threads = parse_mount_usize(key, value)?;
        }
        "fsname" | "subtype" => {
            let _ = require_mount_option_value(key, value)?;
        }
        "max_read" | "max_background" | "congestion_threshold" => {
            let _ = parse_mount_usize(key, value)?;
        }
        "default_permissions" | "noatime" => {
            reject_mount_option_value(key, value)?;
        }
        _ => {
            return Err(MountOptionParseError::UnknownOption {
                option: key.to_owned(),
            });
        }
    }
    Ok(())
}

fn split_mount_option(option: &str) -> Result<(&str, Option<&str>), MountOptionParseError> {
    let mut pieces = option.splitn(2, '=');
    let Some(key) = pieces.next() else {
        return Err(MountOptionParseError::EmptyOption);
    };
    let key = key.trim();
    if key.is_empty() {
        return Err(MountOptionParseError::EmptyKey);
    }
    Ok((key, pieces.next().map(str::trim)))
}

fn require_mount_option_value<'a>(
    option: &str,
    value: Option<&'a str>,
) -> Result<&'a str, MountOptionParseError> {
    let Some(value) = value else {
        return Err(MountOptionParseError::MissingValue {
            option: option.to_owned(),
        });
    };
    if value.is_empty() {
        return Err(MountOptionParseError::InvalidValue {
            option: option.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(value)
}

fn reject_mount_option_value(
    option: &str,
    value: Option<&str>,
) -> Result<(), MountOptionParseError> {
    if value.is_some() {
        return Err(MountOptionParseError::UnexpectedValue {
            option: option.to_owned(),
        });
    }
    Ok(())
}

fn parse_mount_bool(option: &str, value: Option<&str>) -> Result<bool, MountOptionParseError> {
    match require_mount_option_value(option, value)? {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        value => Err(MountOptionParseError::InvalidValue {
            option: option.to_owned(),
            value: value.to_owned(),
        }),
    }
}

fn parse_mount_bool_or_flag(
    option: &str,
    value: Option<&str>,
    flag_value: bool,
) -> Result<bool, MountOptionParseError> {
    match value {
        Some(_) => parse_mount_bool(option, value),
        None => Ok(flag_value),
    }
}

fn parse_mount_usize(option: &str, value: Option<&str>) -> Result<usize, MountOptionParseError> {
    let value = require_mount_option_value(option, value)?;
    value
        .parse::<usize>()
        .map_err(|_| MountOptionParseError::InvalidValue {
            option: option.to_owned(),
            value: value.to_owned(),
        })
}

// ── Cache-line padding ──────────────────────────────────────────────────────

/// Pad a value to 64 bytes to avoid false sharing between hot counters
/// updated on different CPU cores.
#[repr(C, align(64))]
pub struct CacheLinePadded<T>(pub T);

impl<T: std::fmt::Debug> std::fmt::Debug for CacheLinePadded<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// ── Atomic metrics ──────────────────────────────────────────────────────────

/// Lock-free per-mount request counters.
///
/// Each counter sits on its own cache line (64 B) so cores updating
/// different counters never invalidate each other's L1 lines.
#[repr(C)]
pub struct AtomicMetrics {
    pub requests_total: CacheLinePadded<AtomicU64>,
    pub requests_ok: CacheLinePadded<AtomicU64>,
    pub requests_err: CacheLinePadded<AtomicU64>,
    pub bytes_read: CacheLinePadded<AtomicU64>,
    /// Requests delayed by backpressure throttling.
    pub requests_throttled: CacheLinePadded<AtomicU64>,
    /// Requests rejected (shed) by backpressure.
    pub requests_shed: CacheLinePadded<AtomicU64>,
}

impl AtomicMetrics {
    #[allow(
        deprecated,
        reason = "try_update requires Rust 1.95; workspace MSRV is 1.85"
    )]
    fn saturating_add(counter: &AtomicU64, delta: u64) {
        while counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(delta))
            })
            .is_err()
        {
            std::hint::spin_loop();
        }
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            requests_total: CacheLinePadded(AtomicU64::new(0)),
            requests_ok: CacheLinePadded(AtomicU64::new(0)),
            requests_err: CacheLinePadded(AtomicU64::new(0)),
            bytes_read: CacheLinePadded(AtomicU64::new(0)),
            requests_throttled: CacheLinePadded(AtomicU64::new(0)),
            requests_shed: CacheLinePadded(AtomicU64::new(0)),
        }
    }

    fn record_ok(&self) {
        Self::saturating_add(&self.requests_total.0, 1);
        Self::saturating_add(&self.requests_ok.0, 1);
    }

    fn record_err(&self) {
        Self::saturating_add(&self.requests_total.0, 1);
        Self::saturating_add(&self.requests_err.0, 1);
    }

    fn record_bytes_read(&self, n: u64) {
        Self::saturating_add(&self.bytes_read.0, n);
    }

    fn record_throttled(&self) {
        Self::saturating_add(&self.requests_throttled.0, 1);
    }

    fn record_shed(&self) {
        Self::saturating_add(&self.requests_shed.0, 1);
    }

    /// Snapshot of all counters (for diagnostics / reporting).
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.0.load(Ordering::Relaxed),
            requests_ok: self.requests_ok.0.load(Ordering::Relaxed),
            requests_err: self.requests_err.0.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.0.load(Ordering::Relaxed),
            requests_throttled: self.requests_throttled.0.load(Ordering::Relaxed),
            requests_shed: self.requests_shed.0.load(Ordering::Relaxed),
        }
    }
}

impl Default for AtomicMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AtomicMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.snapshot();
        f.debug_struct("AtomicMetrics")
            .field("requests_total", &s.requests_total)
            .field("requests_ok", &s.requests_ok)
            .field("requests_err", &s.requests_err)
            .field("bytes_read", &s.bytes_read)
            .field("requests_throttled", &s.requests_throttled)
            .field("requests_shed", &s.requests_shed)
            .finish()
    }
}

/// Point-in-time snapshot of metrics (all plain `u64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_ok: u64,
    pub requests_err: u64,
    pub bytes_read: u64,
    /// Requests delayed by backpressure throttling.
    pub requests_throttled: u64,
    /// Requests rejected (shed) by backpressure.
    pub requests_shed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessDirection {
    Forward,
    Backward,
}

#[derive(Debug, Clone, Copy)]
struct AccessPattern {
    last_offset: u64,
    last_size: u32,
    sequential_count: u32,
    direction: AccessDirection,
    last_touch: u64,
}

#[derive(Debug, Default)]
struct AccessPredictorState {
    history: BTreeMap<u64, AccessPattern>,
    lru: BTreeMap<u64, u64>,
    next_touch: u64,
}

impl AccessPredictorState {
    fn rebase_touches(&mut self) {
        if self.history.is_empty() {
            self.lru.clear();
            self.next_touch = 0;
            return;
        }

        let mut entries: Vec<(u64, u64)> = self
            .history
            .iter()
            .map(|(ino, entry)| (entry.last_touch, *ino))
            .collect();
        entries.sort_by_key(|(touch, _)| *touch);

        self.lru.clear();
        let mut next = 1_u64;
        for (_touch, ino) in entries {
            if let Some(entry) = self.history.get_mut(&ino) {
                entry.last_touch = next;
            }
            self.lru.insert(next, ino);
            next = next.saturating_add(1);
        }

        self.next_touch = next.saturating_sub(1);
    }
}

#[derive(Debug)]
struct AccessPredictor {
    state: Mutex<AccessPredictorState>,
    max_entries: usize,
}

impl Default for AccessPredictor {
    fn default() -> Self {
        Self::new(MAX_ACCESS_PREDICTOR_ENTRIES)
    }
}

impl AccessPredictor {
    fn new(max_entries: usize) -> Self {
        Self {
            state: Mutex::new(AccessPredictorState::default()),
            max_entries: max_entries.max(1),
        }
    }

    fn fetch_size(&self, ino: InodeNumber, offset: u64, requested: u32) -> u32 {
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("AccessPredictor state lock poisoned in fetch_size, recovering");
                poisoned.into_inner()
            }
        };
        let pattern = guard.history.get(&ino.0).copied();
        drop(guard);

        let Some(pattern) = pattern else {
            return requested;
        };
        let next_forward_offset = pattern
            .last_offset
            .saturating_add(u64::from(pattern.last_size));
        let should_batch = pattern.direction == AccessDirection::Forward
            && pattern.last_size == requested
            && pattern.sequential_count >= MIN_SEQUENTIAL_READS_FOR_BATCH
            && next_forward_offset == offset;
        if should_batch {
            requested
                .saturating_mul(COALESCED_FETCH_MULTIPLIER)
                .clamp(requested, MAX_COALESCED_READ_SIZE.max(requested))
        } else {
            requested
        }
    }

    fn record_read(&self, ino: InodeNumber, offset: u64, size: u32) {
        if size == 0 {
            return;
        }
        {
            let mut guard = match self.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("AccessPredictor state lock poisoned in record_read, recovering");
                    poisoned.into_inner()
                }
            };

            if guard.next_touch == u64::MAX {
                guard.rebase_touches();
            }
            guard.next_touch = guard.next_touch.saturating_add(1);
            let touch = guard.next_touch;
            if let Some(old_touch) = guard.history.get(&ino.0).map(|old| old.last_touch) {
                guard.lru.remove(&old_touch);
            }
            guard.lru.insert(touch, ino.0);

            let entry = guard.history.entry(ino.0).or_insert(AccessPattern {
                last_offset: offset,
                last_size: size,
                sequential_count: 1,
                direction: AccessDirection::Forward,
                last_touch: touch,
            });

            let next_forward_offset = entry.last_offset.saturating_add(u64::from(entry.last_size));
            let next_backward_offset = offset.saturating_add(u64::from(size));

            if entry.last_size == size && next_forward_offset == offset {
                entry.sequential_count = entry.sequential_count.saturating_add(1);
                entry.direction = AccessDirection::Forward;
            } else if entry.last_size == size && next_backward_offset == entry.last_offset {
                entry.sequential_count = entry.sequential_count.saturating_add(1);
                entry.direction = AccessDirection::Backward;
            } else {
                entry.sequential_count = 1;
                entry.direction = AccessDirection::Forward;
            }
            entry.last_offset = offset;
            entry.last_size = size;
            entry.last_touch = touch;

            while guard.history.len() > self.max_entries {
                if let Some((_, oldest_inode)) = guard.lru.pop_first() {
                    let _ = guard.history.remove(&oldest_inode);
                } else {
                    break;
                }
            }

            drop(guard);
        }
    }

    fn invalidate_inode(&self, ino: InodeNumber) {
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("AccessPredictor state lock poisoned in invalidate, recovering");
                poisoned.into_inner()
            }
        };
        if let Some(entry) = guard.history.remove(&ino.0) {
            guard.lru.remove(&entry.last_touch);
        }
    }
}

#[derive(Debug, Default)]
struct ReadaheadState {
    map: BTreeMap<(u64, u64), Vec<u8>>,
    fifo: std::collections::VecDeque<(u64, u64)>,
}

#[derive(Debug)]
struct ReadaheadManager {
    pending: Mutex<ReadaheadState>,
    max_pending: usize,
}

impl ReadaheadManager {
    fn new(max_pending: usize) -> Self {
        Self {
            pending: Mutex::new(ReadaheadState::default()),
            max_pending: max_pending.max(1),
        }
    }

    fn remove_fifo_entry(state: &mut ReadaheadState, key: (u64, u64)) {
        state.fifo.retain(|&existing| existing != key);
    }

    fn enforce_limit(&self, state: &mut ReadaheadState) {
        while state.fifo.len() > self.max_pending {
            if let Some(key) = state.fifo.pop_front() {
                let _ = state.map.remove(&key);
            } else {
                break;
            }
        }
    }

    fn insert_locked(&self, state: &mut ReadaheadState, key: (u64, u64), data: Vec<u8>) {
        let _ = state.map.insert(key, data);
        Self::remove_fifo_entry(state, key);
        state.fifo.push_back(key);
        self.enforce_limit(state);
    }

    fn insert(&self, ino: InodeNumber, offset: u64, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let mut guard = match self.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("ReadaheadCache pending lock poisoned in insert, recovering");
                poisoned.into_inner()
            }
        };
        let key = (ino.0, offset);
        self.insert_locked(&mut guard, key, data);
        drop(guard);
    }

    fn take(&self, ino: InodeNumber, offset: u64, requested_len: usize) -> Option<Vec<u8>> {
        if requested_len == 0 {
            return None;
        }
        let mut guard = match self.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("ReadaheadCache pending lock poisoned in take, recovering");
                poisoned.into_inner()
            }
        };
        let mut cached = guard.map.remove(&(ino.0, offset))?;
        // Remove from FIFO to avoid zombies.
        Self::remove_fifo_entry(&mut guard, (ino.0, offset));

        if cached.len() <= requested_len {
            drop(guard);
            return Some(cached);
        }

        let tail = cached.split_off(requested_len);
        let consumed = u64::try_from(cached.len()).unwrap_or(u64::MAX);
        let next_offset = offset.saturating_add(consumed);
        self.insert_locked(&mut guard, (ino.0, next_offset), tail);
        drop(guard);
        Some(cached)
    }

    fn invalidate_inode(&self, ino: InodeNumber) {
        let mut guard = match self.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("ReadaheadCache pending lock poisoned in invalidate, recovering");
                poisoned.into_inner()
            }
        };
        guard.map.retain(|(cached_ino, _), _| *cached_ino != ino.0);
        guard.fifo.retain(|(cached_ino, _)| *cached_ino != ino.0);
        drop(guard);
    }
}

// ── Shared FUSE inner state ─────────────────────────────────────────────────

/// Thread-safe shared state for the FUSE backend.
///
/// All fields are `Send + Sync`:
/// - `ops` delegates to `FsOps` which is `Send + Sync` by trait bound.
/// - `metrics` uses atomic counters with cache-line padding.
/// - `thread_count` is immutable after mount.
///
/// # Subsystem lock-ordering invariant (bd-omus6)
///
/// Four subsystem locks live inside this struct, each guarding
/// independent state:
///
/// | Field              | Inner lock                          | Rank |
/// |--------------------|-------------------------------------|------|
/// | `kernel_notifier`  | `Mutex<Option<Notifier>>`           | leaf |
/// | `access_predictor` | `AccessPredictor.state: Mutex`      | leaf |
/// | `readahead`        | `ReadaheadManager.pending: Mutex`   | leaf |
/// | `writeback_batches` | table mutex + per-batch scope mutex | leaf/table-only, then per-handle scope |
/// | `inode_locks`      | `FuseInodeLocks.table: Mutex`       | 0 (see bd-pfv55 doc on FuseInodeLocks for the per-inode `held` rank-1 sublock) |
///
/// Production callers comply by **never nesting two subsystem
/// locks**: every method that touches one of these subsystems
/// drains the value via clone or returns the guard immediately,
/// so no caller holds two simultaneously. Specifically:
///
/// | Method                          | Touches            | Pattern                          |
/// |---------------------------------|--------------------|----------------------------------|
/// | `install_kernel_notifier`       | kernel_notifier    | leaf-only                        |
/// | `kernel_notifier`               | kernel_notifier    | drain-clone-release              |
/// | `notify_*` family               | (notifier clone)   | no FUSE-inner lock held          |
/// | `AccessPredictor::fetch_size`   | access_predictor   | leaf-only, copy out pattern      |
/// | `AccessPredictor::record_read`  | access_predictor   | leaf-only                        |
/// | `AccessPredictor::invalidate_inode` | access_predictor | leaf-only                        |
/// | `ReadaheadManager::insert/take` | readahead          | leaf-only                        |
/// | `ReadaheadManager::invalidate_inode` | readahead       | leaf-only                        |
/// | `get_or_begin_writeback_batch` | writeback_batches  | table-only; no inode/readahead lock held |
/// | `commit_writeback_batch_for_key` | writeback_batches | drain batch, release table, then commit |
/// | `FuseInodeLocks::acquire`       | inode_locks        | rank 0 → drop → rank 1 (sorted)  |
/// | `FuseInodeLocks::try_acquire`   | inode_locks        | rank 0 → drop → rank 1 (sorted)  |
/// | `FuseInodeGuard::Drop`          | inode_locks        | rank 0 → rank 1 (nested)         |
///
/// New methods on `FrankenFuse`/`FuseInner` MUST NOT acquire two
/// subsystem locks simultaneously without first declaring a total
/// rank between them and updating both this matrix and the
/// individual struct-level docs. Holding (e.g.) `readahead.pending`
/// while acquiring `inode_locks.table` would be an unranked
/// nesting — refactor by draining the readahead value first, then
/// acquiring the inode-locks separately. The same rule applies to
/// background mount workers created via `fuser::spawn_mount2` and
/// any future async runtime integration.
///
/// Each subsystem's internal lock-ordering invariants (notably the
/// table → per-inode held nesting on `FuseInodeLocks`) are
/// documented and regression-tested separately:
/// `lock_ordering_under_concurrent_acquire_and_drop` (bd-pfv55).
struct FuseInner {
    ops: Arc<dyn FsOps>,
    metrics: Arc<AtomicMetrics>,
    thread_count: usize,
    read_only: bool,
    writeback_cache: bool,
    mountpoint: Option<PathBuf>,
    kernel_notifier: Mutex<Option<fuser::Notifier>>,
    ioctl_trace: Option<IoctlTraceProbe>,
    backpressure: Option<Arc<BackpressureGate>>,
    writeback_batches: Mutex<BTreeMap<WritebackKey, Arc<WritebackBatch>>>,
    access_predictor: AccessPredictor,
    readahead: ReadaheadManager,
    inode_locks: Arc<FuseInodeLocks>,
    /// Dedicated pool that `read` requests are dispatched onto so the single
    /// fuser session loop can immediately fetch the next kernel request
    /// instead of serving reads one-at-a-time. The mounted multi-file read
    /// storm profiled the daemon at ~1.5 busy CPUs with wall bounded by this
    /// serial dispatch (2026-07-22 ledger entry), which is exactly the
    /// "per-request dispatch model" bd-kdmu4 calls for. `None` when disabled
    /// (`FFS_FUSE_ASYNC_READ=0`) or when only one worker thread is resolved —
    /// reads then reply inline on the session loop, the pre-lever behavior.
    read_offload: Option<rayon::ThreadPool>,
}

/// Whether `read` requests are dispatched onto the offload pool (default on).
/// Set `FFS_FUSE_ASYNC_READ=0` (or `off`) to reply inline on the session loop —
/// the pre-lever behavior — so the lever can be A/B'd in one binary.
fn fuse_async_read_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        !matches!(
            std::env::var("FFS_FUSE_ASYNC_READ")
                .ok()
                .as_deref()
                .map(str::trim),
            Some("0" | "off" | "false")
        )
    })
}

/// Build the `read`-request offload pool: `thread_count` dedicated threads
/// (the same knob that already sizes `max_background`). Returns `None` when
/// the lever is disabled or the pool cannot be built — callers then reply
/// inline, which is always correct.
fn build_read_offload_pool(thread_count: usize) -> Option<rayon::ThreadPool> {
    if !fuse_async_read_enabled() || thread_count < 2 {
        return None;
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .thread_name(|i| format!("ffs-fuse-rd-{i}"))
        .build()
        .map_err(|error| {
            warn!(%error, "read offload pool build failed; reads reply inline");
            error
        })
        .ok()
}

impl std::fmt::Debug for FuseInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuseInner")
            .field("metrics", &self.metrics)
            .field("thread_count", &self.thread_count)
            .field("read_only", &self.read_only)
            .field("writeback_cache", &self.writeback_cache)
            .field("mountpoint", &self.mountpoint)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct WritebackKey {
    ino: InodeNumber,
    fh: u64,
}

impl WritebackKey {
    const fn new(ino: InodeNumber, fh: u64) -> Self {
        Self { ino, fh }
    }
}

#[derive(Debug)]
struct WritebackBatch {
    scope: Mutex<Option<RequestScope>>,
}

impl WritebackBatch {
    fn new(scope: RequestScope) -> Self {
        Self {
            scope: Mutex::new(Some(scope)),
        }
    }
}

/// Per-inode lock registry shared across FUSE handler threads.
///
/// # Lock ordering invariant (bd-pfv55)
///
/// The struct holds two nested lock layers — the `table` mutex
/// guarding the inode → `Arc<FuseInodeLock>` map, and the per-inode
/// `FuseInodeLock.held` mutex (paired with a Condvar). Any code path
/// that acquires both MUST do so in this order to prevent AB-BA
/// deadlock:
///
/// ```text
///     table  ──→  per-inode held
///                (acquired in sorted-by-inode-number order
///                 across multi-inode batches)
/// ```
///
/// Production callers comply:
///
/// | Caller                        | table | per-inode held    | Notes              |
/// |-------------------------------|-------|-------------------|--------------------|
/// | `acquire`                     | W     | W (sorted, after table dropped) | Condvar-wait on contention |
/// | `try_acquire`                 | W     | W (sorted, short-circuit on contention) | Returns None on contention |
/// | `FuseInodeGuard::Drop`        | W     | W (nested)        | Notifies, then drops one `users` ref and evicts at 0 |
///
/// Acquiring a per-inode `held` lock BEFORE the table mutex (e.g., a
/// hypothetical `release_without_table_check` that took held first
/// then table) would deadlock against `FuseInodeGuard::Drop`, which
/// holds table while waiting on held.
///
/// The **sorted-inode-number** rule on multi-inode batches is the
/// secondary invariant: `acquire([5, 7])` and `acquire([7, 5])` both
/// take inode 5 before inode 7, preventing AB-BA across two batches
/// that share the same inode set in opposite orders. Callers that
/// bypass `acquire`/`try_acquire` to lock inodes in a different order
/// would deadlock against any concurrent batch.
///
/// New methods on this struct must respect both invariants. The
/// `lock_ordering_under_concurrent_acquire_and_drop` test exercises
/// them under contention with a watchdog timeout.
#[derive(Default)]
struct FuseInodeLocks {
    /// Inode → per-inode-lock slot. **Lock-rank 0** — must be acquired
    /// before any per-inode `held` lock. Multi-inode batches must
    /// acquire in sorted-by-inode-number order.
    table: Mutex<BTreeMap<InodeNumber, LockSlot>>,
}

/// Table entry for one inode: the shared per-inode lock plus an explicit
/// `users` count (live guards + in-flight acquirers + waiters). The entry is
/// evicted exactly when `users` reaches 0, all under the `table` mutex — this
/// is deterministic, unlike an `Arc::strong_count` heuristic which could skip
/// eviction whenever a transient clone (e.g. a failed `try_acquire`) inflated
/// the count, permanently leaking the entry.
struct LockSlot {
    lock: Arc<FuseInodeLock>,
    users: usize,
}

impl FuseInodeLocks {
    fn acquire(self: &Arc<Self>, inodes: &[InodeNumber]) -> FuseInodeGuards {
        let mut ordered = inodes.to_vec();
        ordered.sort_unstable_by_key(|ino| ino.0);
        ordered.dedup();

        let entries: Vec<(InodeNumber, Arc<FuseInodeLock>)> = {
            let mut table = match self.table.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("FuseInodeLocks table poisoned, recovering");
                    poisoned.into_inner()
                }
            };
            ordered
                .into_iter()
                .map(|ino| {
                    let slot = table.entry(ino).or_insert_with(|| LockSlot {
                        lock: Arc::new(FuseInodeLock::default()),
                        users: 0,
                    });
                    // Count this in-flight acquirer before releasing the table
                    // lock so the entry cannot be evicted while we block on
                    // `held`.
                    slot.users += 1;
                    (ino, Arc::clone(&slot.lock))
                })
                .collect()
        };

        FuseInodeGuards {
            _guards: entries
                .into_iter()
                .map(|(ino, lock)| lock.acquire(ino, Arc::clone(self)))
                .collect(),
        }
    }

    /// Drop one `users` reference for `ino` (held under the table mutex) and
    /// evict the entry when it reaches 0. Used by the guard `Drop` and by the
    /// `try_acquire` abandon path; `ptr_eq` guards against decrementing a newer
    /// slot that replaced an already-evicted one.
    fn release_slot_user(&self, ino: InodeNumber, lock: &Arc<FuseInodeLock>) {
        let mut table = match self.table.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("FuseInodeLocks table poisoned during slot release, recovering");
                poisoned.into_inner()
            }
        };
        if let Some(slot) = table.get_mut(&ino)
            && Arc::ptr_eq(&slot.lock, lock)
        {
            slot.users -= 1;
            if slot.users == 0 {
                table.remove(&ino);
            }
        }
    }

    fn try_acquire(self: &Arc<Self>, inodes: &[InodeNumber]) -> Option<FuseInodeGuards> {
        let mut ordered = inodes.to_vec();
        ordered.sort_unstable_by_key(|ino| ino.0);
        ordered.dedup();

        let mut guards = Vec::with_capacity(ordered.len());
        for ino in ordered {
            let lock = {
                let mut table = match self.table.try_lock() {
                    Ok(guard) => guard,
                    Err(TryLockError::Poisoned(poisoned)) => {
                        warn!("FuseInodeLocks table poisoned during try_acquire, recovering");
                        poisoned.into_inner()
                    }
                    Err(TryLockError::WouldBlock) => return None,
                };
                let slot = table.entry(ino).or_insert_with(|| LockSlot {
                    lock: Arc::new(FuseInodeLock::default()),
                    users: 0,
                });
                slot.users += 1;
                let lock = Arc::clone(&slot.lock);
                drop(table);
                lock
            };
            if let Some(guard) = lock.try_acquire(ino, Arc::clone(self)) {
                guards.push(guard);
            } else {
                // Contended: this clone never became a holder, so drop its
                // `users` reference (and evict if it was the last) before
                // bailing. The guards already pushed release their own
                // references via their `Drop`.
                self.release_slot_user(ino, &lock);
                return None;
            }
        }

        Some(FuseInodeGuards { _guards: guards })
    }

    #[cfg(test)]
    fn table_len(&self) -> usize {
        match self.table.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

#[derive(Default)]
struct FuseInodeLock {
    held: Mutex<bool>,
    ready: Condvar,
}

impl FuseInodeLock {
    fn acquire(self: &Arc<Self>, ino: InodeNumber, locks: Arc<FuseInodeLocks>) -> FuseInodeGuard {
        let mut held = match self.held.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("FuseInodeLock held flag poisoned, recovering");
                poisoned.into_inner()
            }
        };
        while *held {
            held = match self.ready.wait(held) {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("FuseInodeLock wait poisoned, recovering");
                    poisoned.into_inner()
                }
            };
        }
        *held = true;
        drop(held);
        FuseInodeGuard {
            lock: Arc::clone(self),
            ino,
            locks,
        }
    }

    fn try_acquire(
        self: &Arc<Self>,
        ino: InodeNumber,
        locks: Arc<FuseInodeLocks>,
    ) -> Option<FuseInodeGuard> {
        let mut held = match self.held.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => {
                warn!("FuseInodeLock held flag poisoned during try_acquire, recovering");
                poisoned.into_inner()
            }
            Err(TryLockError::WouldBlock) => return None,
        };
        if *held {
            return None;
        }
        *held = true;
        drop(held);
        Some(FuseInodeGuard {
            lock: Arc::clone(self),
            ino,
            locks,
        })
    }
}

struct FuseInodeGuard {
    lock: Arc<FuseInodeLock>,
    ino: InodeNumber,
    locks: Arc<FuseInodeLocks>,
}

impl Drop for FuseInodeGuard {
    fn drop(&mut self) {
        // Hold the table mutex across the held-flag release + eviction check so
        // no concurrent acquire() can observe an empty entry and clone a new
        // Arc between our strong_count read and the table mutation.
        let mut table = match self.locks.table.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("FuseInodeLocks table poisoned during guard drop, recovering");
                poisoned.into_inner()
            }
        };

        {
            let mut held = match self.lock.held.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("FuseInodeLock held flag poisoned during drop, recovering");
                    poisoned.into_inner()
                }
            };
            *held = false;
            drop(held);
            self.lock.ready.notify_one();
        }

        // Drop this guard's `users` reference and evict the entry only when no
        // live guard, in-flight acquirer, or waiter remains (users == 0). This
        // is decided entirely under the table mutex, so — unlike an
        // `Arc::strong_count` snapshot — a concurrent failed `try_acquire`
        // clone can never trick us into skipping (and thus permanently leaking)
        // the final eviction. `ptr_eq` guards against a newer slot.
        if let Some(slot) = table.get_mut(&self.ino)
            && Arc::ptr_eq(&slot.lock, &self.lock)
        {
            slot.users -= 1;
            if slot.users == 0 {
                table.remove(&self.ino);
            }
        }
    }
}

struct FuseInodeGuards {
    _guards: Vec<FuseInodeGuard>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WriteIntent {
    fh: u64,
    write_flags: u32,
    flags: i32,
}

impl WriteIntent {
    const fn from_fuse(fh: u64, write_flags: u32, flags: i32) -> Self {
        Self {
            fh,
            write_flags,
            flags,
        }
    }

    #[cfg(target_os = "linux")]
    const fn nowait(self) -> bool {
        self.write_flags & fuse_consts::RWF_NOWAIT != 0
    }

    #[cfg(not(target_os = "linux"))]
    const fn nowait(self) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    const fn append_to_eof(self) -> bool {
        let explicit_append = self.write_flags & fuse_consts::RWF_APPEND != 0;
        let suppress_open_append = self.write_flags & fuse_consts::RWF_NOAPPEND != 0;
        let open_append = self.flags & libc::O_APPEND == libc::O_APPEND;
        explicit_append || (open_append && !suppress_open_append)
    }

    #[cfg(not(target_os = "linux"))]
    const fn append_to_eof(self) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    const fn unsupported_errno(self) -> Option<i32> {
        if self.write_flags & fuse_consts::RWF_APPEND != 0
            && self.write_flags & fuse_consts::RWF_NOAPPEND != 0
        {
            return Some(libc::EINVAL);
        }

        let unsupported = self.write_flags & (fuse_consts::RWF_ATOMIC | fuse_consts::RWF_DONTCACHE);
        if unsupported == 0 {
            None
        } else {
            Some(libc::EOPNOTSUPP)
        }
    }

    #[cfg(not(target_os = "linux"))]
    const fn unsupported_errno(self) -> Option<i32> {
        None
    }

    #[cfg(target_os = "linux")]
    const fn sync_mode(self) -> Option<WriteSyncMode> {
        if self.flags & libc::O_SYNC == libc::O_SYNC {
            Some(WriteSyncMode::Full)
        } else if self.flags & libc::O_DSYNC == libc::O_DSYNC {
            Some(WriteSyncMode::Data)
        } else {
            None
        }
    }

    #[cfg(not(target_os = "linux"))]
    const fn sync_mode(self) -> Option<WriteSyncMode> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteSyncMode {
    Data,
    Full,
}

impl WriteSyncMode {
    const fn datasync(self) -> bool {
        matches!(self, Self::Data)
    }
}

/// Bounded queue capacity for the ioctl trace writer.  Sized so a busy
/// dispatcher can buffer ~4k callbacks before backpressure forces drops; in
/// practice the trace is only enabled by harness tests with low ioctl volume.
const IOCTL_TRACE_CHANNEL_CAPACITY: usize = 4096;

#[derive(Debug)]
enum IoctlTraceMsg {
    Record {
        ino: u64,
        cmd: u32,
        in_len: usize,
        out_size: u32,
    },
    /// Synchronisation barrier: the writer drains all preceding `Record`
    /// messages, then signals on the supplied reply channel.  Used by tests
    /// (and any caller that needs a happens-before guarantee for an external
    /// reader of the trace file).
    #[cfg_attr(not(test), allow(dead_code))]
    Flush(SyncSender<()>),
}

/// Off-thread ioctl trace sink.
///
/// `record` enqueues onto a bounded channel and returns immediately, so the
/// FUSE dispatcher thread is never blocked on file I/O.  A dedicated writer
/// thread drains the channel and appends each event to the configured trace
/// file as a single `write(2)` syscall (no in-process buffering — the kernel
/// page cache is buffer enough for a low-volume diagnostic, and skipping a
/// user-space buffer means external readers see events as soon as the writer
/// thread is scheduled).
///
/// On backpressure (channel full) the record is dropped and `dropped_events`
/// is incremented; the count is surfaced as a `warn!` on shutdown so the
/// trace's lossiness under load is auditable.
#[derive(Debug)]
struct IoctlTraceProbe {
    path: PathBuf,
    sender: Option<SyncSender<IoctlTraceMsg>>,
    worker: Option<JoinHandle<()>>,
    dropped_events: Arc<AtomicU64>,
}

impl IoctlTraceProbe {
    #[allow(
        deprecated,
        reason = "try_update requires Rust 1.95; workspace MSRV is 1.85"
    )]
    fn saturating_add_u64(counter: &AtomicU64, delta: u64) {
        while counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(delta))
            })
            .is_err()
        {
            std::hint::spin_loop();
        }
    }

    fn record_dropped_event(&self) {
        Self::saturating_add_u64(&self.dropped_events, 1);
    }

    fn disabled(path: PathBuf, dropped_events: Arc<AtomicU64>) -> Self {
        Self {
            path,
            sender: None,
            worker: None,
            dropped_events,
        }
    }

    fn new(path: PathBuf) -> Self {
        let dropped_events = Arc::new(AtomicU64::new(0));
        if let Err(error) = validate_ioctl_trace_path(&path) {
            warn!(
                path = %path.display(),
                %error,
                "disabling ioctl trace because trace path is not a regular appendable file"
            );
            return Self::disabled(path, dropped_events);
        }

        let (sender, receiver) = sync_channel::<IoctlTraceMsg>(IOCTL_TRACE_CHANNEL_CAPACITY);
        let worker_path = path.clone();
        let worker = match thread::Builder::new()
            .name("ffs-ioctl-trace".into())
            .spawn(move || ioctl_trace_writer_loop(&worker_path, &receiver))
        {
            Ok(worker) => Some(worker),
            Err(error) => {
                warn!(
                    path = %path.display(),
                    %error,
                    "disabling ioctl trace because writer thread could not be spawned"
                );
                None
            }
        };
        Self {
            path,
            sender: worker.as_ref().map(|_| sender),
            worker,
            dropped_events,
        }
    }

    /// Non-blocking enqueue.  Increments `dropped_events` if the channel is
    /// full (writer thread is behind) so the loss is observable.
    fn record(&self, ino: u64, cmd: u32, in_len: usize, out_size: u32) {
        let Some(sender) = self.sender.as_ref() else {
            return;
        };
        if sender
            .try_send(IoctlTraceMsg::Record {
                ino,
                cmd,
                in_len,
                out_size,
            })
            .is_err()
        {
            self.record_dropped_event();
        }
    }

    /// Round-trip a `Flush` barrier through the writer thread.  When this
    /// returns, all previously enqueued `Record` messages have been written
    /// to the trace file (visible to any same-process reader).
    #[cfg_attr(not(test), allow(dead_code))]
    fn flush_sync(&self) -> std::io::Result<()> {
        let sender = self.sender.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ioctl trace writer terminated",
            )
        })?;
        let (reply_tx, reply_rx) = sync_channel::<()>(1);
        sender.send(IoctlTraceMsg::Flush(reply_tx)).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ioctl trace writer terminated",
            )
        })?;
        reply_rx.recv().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ioctl trace writer dropped flush reply",
            )
        })
    }
}

impl Drop for IoctlTraceProbe {
    fn drop(&mut self) {
        // Drop the sender first so the writer thread observes channel close
        // and exits its `recv()` loop.
        drop(self.sender.take());
        if let Some(worker) = self.worker.take()
            && let Err(panic) = worker.join()
        {
            warn!(
                path = %self.path.display(),
                ?panic,
                "ioctl trace writer thread panicked"
            );
        }
        let dropped = self.dropped_events.load(Ordering::Relaxed);
        if dropped > 0 {
            warn!(
                path = %self.path.display(),
                dropped,
                "ioctl trace lost events to writer-thread backpressure"
            );
        }
    }
}

fn validate_ioctl_trace_path(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_file() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "ioctl trace path must be a regular file or absent, found {}",
                        ioctl_trace_file_type_name(file_type)
                    ),
                ))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn ioctl_trace_file_type_name(file_type: std::fs::FileType) -> &'static str {
    if file_type.is_dir() {
        "directory"
    } else if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_fifo() {
        "fifo"
    } else if file_type.is_socket() {
        "socket"
    } else if file_type.is_char_device() {
        "character device"
    } else if file_type.is_block_device() {
        "block device"
    } else {
        "non-regular file"
    }
}

fn open_ioctl_trace_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    options.custom_flags(libc::O_NONBLOCK);
    options.open(path)
}

fn ioctl_trace_writer_loop(path: &Path, receiver: &Receiver<IoctlTraceMsg>) {
    let mut file = match open_ioctl_trace_file(path) {
        Ok(file) => file,
        Err(error) => {
            warn!(
                path = %path.display(),
                %error,
                "ioctl trace writer failed to open log; dropping all events"
            );
            // Drain the channel to unblock senders that may be holding
            // `try_send` slots; flush replies still complete so callers do
            // not deadlock on a missing trace file.
            for msg in receiver {
                if let IoctlTraceMsg::Flush(reply) = msg {
                    let _ = reply.send(());
                }
            }
            return;
        }
    };
    while let Ok(msg) = receiver.recv() {
        match msg {
            IoctlTraceMsg::Record {
                ino,
                cmd,
                in_len,
                out_size,
            } => {
                let line =
                    format!("ino={ino} cmd=0x{cmd:08x} in_len={in_len} out_size={out_size}\n");
                if let Err(error) = file.write_all(line.as_bytes()) {
                    warn!(path = %path.display(), %error, "ioctl trace write failed");
                }
            }
            IoctlTraceMsg::Flush(reply) => {
                let _ = reply.send(());
            }
        }
    }
}

// ── FUSE filesystem adapter ─────────────────────────────────────────────────

/// FUSE adapter that delegates all operations to a [`FsOps`] implementation.
///
/// Internally wraps all state in `Arc<FuseInner>` so it is `Send + Sync`
/// and ready for multi-threaded FUSE dispatch.  All `FsOps` calls go
/// through `self.inner.ops` (which is `Arc<dyn FsOps>`), and lock-free
/// [`AtomicMetrics`] are updated on every request.
pub struct FrankenFuse {
    inner: Arc<FuseInner>,
}

// Compile-time assertions: FrankenFuse must be Send + Sync.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<FrankenFuse>;
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XattrReplyPlan {
    Size(u32),
    Data,
    Error(c_int),
}

#[derive(Debug)]
enum MutationDispatchError {
    Errno(c_int),
    Operation {
        error: FfsError,
        offset: Option<u64>,
    },
}

#[derive(Clone, Copy)]
struct MoveExtLogContext<'a> {
    operation_id: &'a str,
    ino: u64,
    donor_ino: Option<InodeNumber>,
    donor_fd: u32,
    orig_start: u64,
    donor_start: u64,
    len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MoveExtLogRecord<'a> {
    target: &'static str,
    operation_id: &'a str,
    scenario_id: &'static str,
    outcome: &'static str,
    error_class: &'static str,
    ino: u64,
    donor_ino: Option<u64>,
    donor_fd: u32,
    orig_start: u64,
    donor_start: u64,
    len: u64,
    moved_len: Option<u64>,
    errno: Option<c_int>,
}

impl FrankenFuse {
    fn with_inner(
        ops: Box<dyn FsOps>,
        options: &MountOptions,
        mountpoint: Option<&Path>,
        backpressure: Option<Arc<BackpressureGate>>,
    ) -> Self {
        let thread_count = options.resolved_thread_count();
        if backpressure.is_some() {
            info!(thread_count, "FrankenFuse initialized with backpressure");
        } else {
            info!(thread_count, "FrankenFuse initialized");
        }
        Self {
            inner: Arc::new(FuseInner {
                ops: Arc::from(ops),
                metrics: Arc::new(AtomicMetrics::new()),
                thread_count,
                read_only: options.read_only,
                writeback_cache: options.writeback_cache.is_enabled(),
                mountpoint: mountpoint.map(Path::to_path_buf),
                kernel_notifier: Mutex::new(None),
                ioctl_trace: options.ioctl_trace_path.clone().map(IoctlTraceProbe::new),
                backpressure,
                writeback_batches: Mutex::new(BTreeMap::new()),
                access_predictor: AccessPredictor::default(),
                readahead: ReadaheadManager::new(MAX_PENDING_READAHEAD_ENTRIES),
                inode_locks: Arc::new(FuseInodeLocks::default()),
                read_offload: build_read_offload_pool(thread_count),
            }),
        }
    }

    /// Create a new FUSE adapter wrapping the given `FsOps` implementation.
    ///
    /// Uses default thread count (auto-detected).
    #[must_use]
    pub fn new(ops: Box<dyn FsOps>) -> Self {
        Self::with_options(ops, &MountOptions::default())
    }

    /// Create a new FUSE adapter with explicit mount options.
    ///
    /// The resolved `thread_count` is logged at info level.
    #[must_use]
    pub fn with_options(ops: Box<dyn FsOps>, options: &MountOptions) -> Self {
        Self::with_inner(ops, options, None, None)
    }

    fn with_mount_config(
        ops: Box<dyn FsOps>,
        mountpoint: Option<&Path>,
        config: &MountConfig,
    ) -> Self {
        Self::with_inner(
            ops,
            &config.options,
            mountpoint,
            config.backpressure.clone(),
        )
    }

    /// Create a FUSE adapter with an attached backpressure gate.
    #[must_use]
    pub fn with_backpressure(
        ops: Box<dyn FsOps>,
        options: &MountOptions,
        gate: BackpressureGate,
    ) -> Self {
        Self::with_inner(ops, options, None, Some(Arc::new(gate)))
    }

    /// Get a reference to the shared metrics.
    #[must_use]
    pub fn metrics(&self) -> &AtomicMetrics {
        &self.inner.metrics
    }

    /// Configured thread count.
    #[must_use]
    pub fn thread_count(&self) -> usize {
        self.inner.thread_count
    }

    fn shared_handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Serve one FUSE `read` request and send its reply. Runs either inline on
    /// the session loop (offload disabled) or on the `read_offload` pool; the
    /// body is identical in both cases — the exact code the inline `read` op
    /// ran before the dispatch lever.
    fn serve_read_request(&self, ino: u64, fh: u64, byte_offset: u64, size: u32, reply: ReplyData) {
        let cx = Self::cx_for_request();
        match self.read_with_readahead(&cx, InodeNumber(ino), fh, byte_offset, size) {
            Ok(data) => {
                self.inner
                    .metrics
                    .record_bytes_read(u64::try_from(data.len()).unwrap_or(u64::MAX));
                reply.data(&data);
            }
            Err(e) => {
                Self::reply_error_data(
                    &FuseErrorContext {
                        error: &e,
                        operation: "read",
                        ino,
                        offset: Some(byte_offset),
                    },
                    reply,
                );
            }
        }
    }

    fn install_kernel_notifier(&self, notifier: fuser::Notifier) {
        let mut guard = match self.inner.kernel_notifier.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("FUSE kernel notifier slot poisoned, recovering");
                poisoned.into_inner()
            }
        };
        *guard = Some(notifier);
    }

    fn kernel_notifier(&self) -> Option<fuser::Notifier> {
        match self.inner.kernel_notifier.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                warn!("FUSE kernel notifier slot poisoned, recovering");
                poisoned.into_inner().clone()
            }
        }
    }

    fn notify_entry_invalidation(&self, parent: u64, name: &OsStr) {
        let Some(notifier) = self.kernel_notifier() else {
            return;
        };
        if let Err(error) = notifier.inval_entry(parent, name) {
            debug!(
                parent,
                name = ?name,
                error = %error,
                "FUSE kernel entry invalidation failed"
            );
        }
    }

    /// Execute the internal ioctl dispatcher without a live kernel mount.
    ///
    /// This is a narrow hook for fuzz/integration harnesses that need to drive
    /// the real ioctl argument parser and backend routing from userspace.
    /// The return shape intentionally mirrors the kernel contract:
    /// successful commands yield the raw reply payload, failed commands yield
    /// the errno that would be sent back through FUSE.
    #[doc(hidden)]
    pub fn dispatch_ioctl_for_fuzzing(
        &self,
        caller_pid: u32,
        ino: u64,
        fh: u64,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
    ) -> std::result::Result<Vec<u8>, c_int> {
        match self.dispatch_ioctl(caller_pid, ino, fh, cmd, in_data, out_size) {
            IoctlResult::Data(data) => Ok(data),
            IoctlResult::Error(errno) => Err(errno),
        }
    }

    /// Execute open without a live kernel mount.
    #[doc(hidden)]
    pub fn open_for_fuzzing(&self, ino: u64, flags: i32) -> std::result::Result<(u64, u32), c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Open, |cx, scope| {
            self.inner.ops.open(cx, scope, InodeNumber(ino), flags)
        })
        .map(|(fh, open_flags)| (fh, Self::kernel_open_flags(flags, open_flags)))
        .map_err(|error| error.to_errno())
    }

    /// Execute read without a live kernel mount.
    #[doc(hidden)]
    pub fn read_for_fuzzing(
        &self,
        ino: u64,
        offset: i64,
        size: u32,
    ) -> std::result::Result<Vec<u8>, c_int> {
        let byte_offset = u64::try_from(offset).map_err(|_| libc::EINVAL)?;
        let cx = Self::cx_for_request();
        let data = self
            .read_with_readahead(&cx, InodeNumber(ino), 0, byte_offset, size)
            .map_err(|error| error.to_errno())?;
        self.inner
            .metrics
            .record_bytes_read(u64::try_from(data.len()).unwrap_or(u64::MAX));
        Ok(data)
    }

    /// Execute write without a live kernel mount.
    #[doc(hidden)]
    pub fn write_for_fuzzing(
        &self,
        ino: u64,
        offset: i64,
        data: &[u8],
    ) -> std::result::Result<u32, c_int> {
        self.dispatch_write(ino, offset, data)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute copy-file-range without a live kernel mount.
    #[doc(hidden)]
    pub fn copy_file_range_for_fuzzing(
        &self,
        ino_in: u64,
        offset_in: i64,
        ino_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
    ) -> std::result::Result<u32, c_int> {
        self.dispatch_copy_file_range(ino_in, offset_in, ino_out, offset_out, len, flags)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute flush without a live kernel mount.
    #[doc(hidden)]
    pub fn flush_for_fuzzing(
        &self,
        ino: u64,
        fh: u64,
        lock_owner: u64,
    ) -> std::result::Result<(), c_int> {
        let cx = Self::cx_for_request();
        let key = WritebackKey::new(InodeNumber(ino), fh);
        self.commit_writeback_batch_for_key(&cx, key)
            .map_err(|error| error.to_errno())?;
        self.with_request_scope(&cx, RequestOp::Flush, |cx, scope| {
            self.inner
                .ops
                .flush(cx, scope, InodeNumber(ino), fh, lock_owner)
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute fsync without a live kernel mount.
    #[doc(hidden)]
    pub fn fsync_for_fuzzing(
        &self,
        ino: u64,
        fh: u64,
        datasync: bool,
    ) -> std::result::Result<(), c_int> {
        if self.inner.read_only {
            return Err(libc::EROFS);
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Fsync) {
            return Err(errno);
        }
        let key = WritebackKey::new(InodeNumber(ino), fh);
        self.commit_writeback_batch_for_key(&cx, key)
            .map_err(|error| error.to_errno())?;
        self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
            self.inner
                .ops
                .fsync(cx, scope, InodeNumber(ino), fh, datasync)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute release without a live kernel mount.
    #[doc(hidden)]
    pub fn release_for_fuzzing(
        &self,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
    ) -> std::result::Result<(), c_int> {
        let cx = Self::cx_for_request();
        let key = WritebackKey::new(InodeNumber(ino), fh);
        self.commit_writeback_batch_for_key(&cx, key)
            .map_err(|error| error.to_errno())?;
        self.with_request_scope(&cx, RequestOp::Release, |cx, scope| {
            self.inner.ops.release(
                cx,
                scope,
                ReleaseRequest {
                    ino: InodeNumber(ino),
                    fh,
                    flags,
                    lock_owner,
                    flush,
                },
            )
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute lookup with raw path-component bytes and return the backend
    /// result without a live kernel mount.
    #[doc(hidden)]
    pub fn lookup_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
    ) -> std::result::Result<InodeAttr, c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Lookup, |cx, scope| {
            self.inner.ops.lookup(cx, scope, InodeNumber(parent), name)
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute getattr without a live kernel mount.
    #[doc(hidden)]
    pub fn getattr_for_fuzzing(&self, ino: u64) -> std::result::Result<InodeAttr, c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Getattr, |cx, scope| {
            self.inner.ops.getattr(cx, scope, InodeNumber(ino))
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute statfs without a live kernel mount.
    #[doc(hidden)]
    pub fn statfs_for_fuzzing(&self, ino: u64) -> std::result::Result<FsStat, c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Statfs, |cx, scope| {
            self.inner.ops.statfs(cx, scope, InodeNumber(ino))
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute readdir and force the same raw-byte name conversion the live
    /// FUSE path performs before replying.
    #[doc(hidden)]
    pub fn readdir_for_fuzzing(
        &self,
        ino: u64,
        offset: u64,
    ) -> std::result::Result<Vec<FfsDirEntry>, c_int> {
        let cx = Self::cx_for_request();
        let entries = self
            .with_request_scope(&cx, RequestOp::Readdir, |cx, scope| {
                self.inner.ops.readdir(cx, scope, InodeNumber(ino), offset)
            })
            .map_err(|error| error.to_errno())?;

        for entry in &entries {
            #[cfg(unix)]
            let _ = OsStr::from_bytes(&entry.name);
            #[cfg(not(unix))]
            let _ = entry.name_str();
        }

        Ok(entries.to_vec())
    }

    /// Execute readlink without a live mount.
    #[doc(hidden)]
    pub fn readlink_for_fuzzing(&self, ino: u64) -> std::result::Result<Vec<u8>, c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Readlink, |cx, scope| {
            self.inner.ops.readlink(cx, scope, InodeNumber(ino))
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute create with raw path-component bytes without a live kernel
    /// mount.
    #[doc(hidden)]
    pub fn create_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        if self.inner.read_only {
            return Err(libc::EROFS);
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Create) {
            return Err(errno);
        }

        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.with_request_scope(&cx, RequestOp::Create, |cx, scope| {
            let attr =
                self.inner
                    .ops
                    .create(cx, scope, InodeNumber(parent), name, mode, uid, gid)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute setattr without a live kernel mount.
    #[doc(hidden)]
    pub fn setattr_for_fuzzing(
        &self,
        ino: u64,
        attrs: &SetAttrRequest,
    ) -> std::result::Result<InodeAttr, c_int> {
        self.setattr_for_fuzzing_as(ino, attrs, 0)
    }

    /// Execute setattr as a specific caller without a live kernel mount.
    #[doc(hidden)]
    pub fn setattr_for_fuzzing_as(
        &self,
        ino: u64,
        attrs: &SetAttrRequest,
        caller_uid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        if self.inner.read_only {
            return Err(libc::EROFS);
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Setattr) {
            return Err(errno);
        }

        self.dispatch_setattr(&cx, ino, attrs, caller_uid)
            .map_err(|error| error.to_errno())
    }

    fn dispatch_setattr(
        &self,
        cx: &Cx,
        ino: u64,
        attrs: &SetAttrRequest,
        caller_uid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.with_request_scope(cx, RequestOp::Setattr, |cx, scope| {
            self.authorize_setattr_owner_change(cx, scope, InodeNumber(ino), attrs, caller_uid)?;
            let attr = self.inner.ops.setattr(cx, scope, InodeNumber(ino), attrs)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        })
    }

    fn authorize_setattr_owner_change(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
        caller_uid: u32,
    ) -> ffs_error::Result<()> {
        if caller_uid == 0 || (attrs.uid.is_none() && attrs.gid.is_none()) {
            return Ok(());
        }

        let current = self.inner.ops.getattr(cx, scope, ino)?;
        let uid_unchanged = attrs.uid.is_none_or(|uid| uid == current.uid);
        let gid_unchanged = attrs.gid.is_none_or(|gid| gid == current.gid);
        if uid_unchanged && gid_unchanged {
            return Ok(());
        }

        Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EPERM)))
    }

    /// Execute mkdir with raw path-component bytes without a live kernel mount.
    #[doc(hidden)]
    pub fn mkdir_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.dispatch_mkdir(parent, name, mode, uid, gid)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute rmdir with raw path-component bytes without a live kernel mount.
    #[doc(hidden)]
    pub fn rmdir_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
    ) -> std::result::Result<(), c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.dispatch_rmdir(parent, name)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute unlink with raw path-component bytes without a live kernel mount.
    #[doc(hidden)]
    pub fn unlink_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
    ) -> std::result::Result<(), c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.dispatch_unlink(parent, name)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute mknod without a live kernel mount.
    ///
    /// Regular files route through `FsOps::create`, supported special nodes
    /// route through `FsOps::mknod`, and unsupported node types fail with
    /// `EOPNOTSUPP`.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn mknod_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        mode: u32,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.dispatch_mknod(parent, name, mode, rdev, uid, gid)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute rename with raw path-component bytes without a live kernel
    /// mount.
    #[doc(hidden)]
    pub fn rename_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        newparent: u64,
        newname_bytes: &[u8],
    ) -> std::result::Result<(), c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        #[cfg(not(unix))]
        let owned_newname = OsString::from(String::from_utf8_lossy(newname_bytes).into_owned());
        #[cfg(unix)]
        let new_name = OsStr::from_bytes(newname_bytes);
        #[cfg(not(unix))]
        let new_name = owned_newname.as_os_str();

        self.dispatch_rename(parent, name, newparent, new_name, 0)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute symlink with raw path/name bytes without a live kernel mount.
    #[doc(hidden)]
    pub fn symlink_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        target_bytes: &[u8],
        uid: u32,
        gid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        if self.inner.read_only {
            return Err(libc::EROFS);
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Symlink) {
            return Err(errno);
        }

        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        #[cfg(unix)]
        let target = PathBuf::from(OsString::from_vec(target_bytes.to_vec()));
        #[cfg(not(unix))]
        let target = PathBuf::from(String::from_utf8_lossy(target_bytes).into_owned());

        self.with_request_scope(&cx, RequestOp::Symlink, |cx, scope| {
            let attr =
                self.inner
                    .ops
                    .symlink(cx, scope, InodeNumber(parent), name, &target, uid, gid)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        })
        .map_err(|error| error.to_errno())
    }

    fn backpressure_errno(&self, cx: &Cx, op: RequestOp) -> Option<c_int> {
        match self.should_shed_with_cx(cx, op) {
            Ok(false) => None,
            Ok(true) => Some(libc::EBUSY),
            Err(error) => Some(error.to_errno()),
        }
    }

    /// Check backpressure for an operation. Returns `true` if the operation
    /// should be rejected (shed).
    fn should_shed_with_cx(&self, cx: &Cx, op: RequestOp) -> ffs_error::Result<bool> {
        let Some(gate) = self.inner.backpressure.as_ref() else {
            return Ok(false);
        };

        match gate.check(op) {
            BackpressureDecision::Proceed => Ok(false),
            BackpressureDecision::Throttle => {
                self.inner.metrics.record_throttled();
                trace!(
                    ?op,
                    delay_ms = BACKPRESSURE_THROTTLE_DELAY.as_millis(),
                    "backpressure: throttling request"
                );
                Self::sleep_with_cx_budget(cx, BACKPRESSURE_THROTTLE_DELAY)?;
                Ok(false)
            }
            BackpressureDecision::Shed => {
                self.inner.metrics.record_shed();
                Ok(true)
            }
        }
    }

    fn sleep_with_cx_budget(cx: &Cx, delay: Duration) -> ffs_error::Result<()> {
        if delay.is_zero() {
            return Ok(());
        }

        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let budget = cx.budget();
        let now = cx.now();
        if budget.is_past_deadline(now)
            || budget
                .remaining_time(now)
                .is_some_and(|remaining| remaining <= delay)
        {
            return Err(FfsError::Cancelled);
        }
        let mut remaining = delay;
        while !remaining.is_zero() {
            let slice = remaining.min(BACKPRESSURE_SLEEP_CHECK_INTERVAL);
            let budget = cx.budget();
            let now = cx.now();
            if budget.is_past_deadline(now)
                || budget
                    .remaining_time(now)
                    .is_some_and(|remaining| remaining <= slice)
            {
                return Err(FfsError::Cancelled);
            }
            std::thread::sleep(slice);
            remaining = remaining.saturating_sub(slice);
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        }

        Ok(())
    }

    #[cfg(test)]
    fn should_shed(&self, op: RequestOp) -> bool {
        let cx = Self::cx_for_request();
        self.should_shed_with_cx(&cx, op).unwrap_or(true)
    }

    fn acquire_mutation_inode_guards(&self, inodes: &[InodeNumber]) -> FuseInodeGuards {
        self.inner.inode_locks.acquire(inodes)
    }

    fn try_acquire_mutation_inode_guards(&self, inodes: &[InodeNumber]) -> Option<FuseInodeGuards> {
        self.inner.inode_locks.try_acquire(inodes)
    }

    /// Create a `Cx` for a FUSE request.
    ///
    /// In the future this could inherit deadlines or tracing spans from the
    /// fuser `Request`, but for now we use a plain request context.
    fn cx_for_request() -> Cx {
        Cx::for_request()
    }

    fn reply_error_attr(ctx: &FuseErrorContext<'_>, reply: ReplyAttr) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_entry(ctx: &FuseErrorContext<'_>, reply: ReplyEntry) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_data(ctx: &FuseErrorContext<'_>, reply: ReplyData) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_dir(ctx: &FuseErrorContext<'_>, reply: ReplyDirectory) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_xattr(ctx: &FuseErrorContext<'_>, reply: ReplyXattr) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_empty(ctx: &FuseErrorContext<'_>, reply: ReplyEmpty) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_write(ctx: &FuseErrorContext<'_>, reply: ReplyWrite) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_create(ctx: &FuseErrorContext<'_>, reply: ReplyCreate) {
        reply.error(ctx.log_and_errno());
    }

    fn classify_xattr_reply(size: u32, payload_len: usize) -> XattrReplyPlan {
        match u32::try_from(payload_len) {
            Ok(payload_len_u32) if size == 0 => XattrReplyPlan::Size(payload_len_u32),
            Ok(payload_len_u32) if payload_len_u32 <= size => XattrReplyPlan::Data,
            Ok(_) => XattrReplyPlan::Error(libc::ERANGE),
            Err(_) => XattrReplyPlan::Error(libc::EOVERFLOW),
        }
    }

    fn reply_xattr_payload(size: u32, payload: &[u8], reply: ReplyXattr) {
        match Self::classify_xattr_reply(size, payload.len()) {
            XattrReplyPlan::Size(payload_len) => reply.size(payload_len),
            XattrReplyPlan::Data => reply.data(payload),
            XattrReplyPlan::Error(errno) => reply.error(errno),
        }
    }

    #[cfg(target_os = "linux")]
    const fn missing_xattr_errno() -> c_int {
        libc::ENODATA
    }

    #[cfg(not(target_os = "linux"))]
    const fn missing_xattr_errno() -> c_int {
        libc::ENOATTR
    }

    fn parse_setxattr_mode(flags: i32, position: u32) -> Result<XattrSetMode, c_int> {
        if position != 0 {
            return Err(libc::EINVAL);
        }

        let known = XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE;
        if flags & !known != 0 {
            return Err(libc::EINVAL);
        }

        let create = flags & XATTR_FLAG_CREATE != 0;
        let replace = flags & XATTR_FLAG_REPLACE != 0;
        if create && replace {
            return Err(libc::EINVAL);
        }

        if create {
            Ok(XattrSetMode::Create)
        } else if replace {
            Ok(XattrSetMode::Replace)
        } else {
            Ok(XattrSetMode::Set)
        }
    }

    fn xattr_names_encoded_len(names: &[String]) -> usize {
        names.iter().map(|name| name.len() + 1).sum()
    }

    fn encode_xattr_names(names: &[String]) -> Vec<u8> {
        let total_len = Self::xattr_names_encoded_len(names);
        let mut bytes = Vec::with_capacity(total_len);
        for name in names {
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    fn parse_fiemap_request(in_data: &[u8]) -> Result<(u64, u64, u32, u32), c_int> {
        if in_data.len() < FIEMAP_HEADER_SIZE {
            return Err(libc::EINVAL);
        }

        let fm_start = u64::from_ne_bytes(
            in_data[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let fm_length = u64::from_ne_bytes(
            in_data[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let fm_flags = u32::from_ne_bytes(
            in_data[FIEMAP_FLAGS_OFFSET..FIEMAP_FLAGS_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let fm_extent_count = u32::from_ne_bytes(
            in_data[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );

        Ok((fm_start, fm_length, fm_flags, fm_extent_count))
    }

    fn parse_move_ext_request(in_data: &[u8]) -> Result<(u32, u64, u64, u64), c_int> {
        if in_data.len() < MOVE_EXT_SIZE {
            return Err(libc::EINVAL);
        }

        let reserved = u32::from_ne_bytes(
            in_data[MOVE_EXT_RESERVED_OFFSET..MOVE_EXT_RESERVED_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        if reserved != 0 {
            return Err(libc::EINVAL);
        }

        let donor_fd = i32::from_ne_bytes(
            in_data[MOVE_EXT_DONOR_FD_OFFSET..MOVE_EXT_DONOR_FD_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        if donor_fd < 0 {
            return Err(libc::EBADF);
        }
        let orig_start = u64::from_ne_bytes(
            in_data[MOVE_EXT_ORIG_START_OFFSET..MOVE_EXT_ORIG_START_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let donor_start = u64::from_ne_bytes(
            in_data[MOVE_EXT_DONOR_START_OFFSET..MOVE_EXT_DONOR_START_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let len = u64::from_ne_bytes(
            in_data[MOVE_EXT_LEN_OFFSET..MOVE_EXT_LEN_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );

        if orig_start.checked_add(len).is_none() || donor_start.checked_add(len).is_none() {
            return Err(libc::EINVAL);
        }

        Ok((
            u32::try_from(donor_fd).map_err(|_| libc::EBADF)?,
            orig_start,
            donor_start,
            len,
        ))
    }

    fn parse_u32_ioctl_arg(in_data: &[u8]) -> Result<u32, c_int> {
        if in_data.len() < std::mem::size_of::<u32>() {
            return Err(libc::EINVAL);
        }
        let mut bytes = [0_u8; std::mem::size_of::<u32>()];
        bytes.copy_from_slice(&in_data[..std::mem::size_of::<u32>()]);
        Ok(u32::from_ne_bytes(bytes))
    }

    fn parse_btrfs_tree_search_key(in_data: &[u8]) -> Result<BtrfsTreeSearchKey, c_int> {
        if in_data.len() < BTRFS_TREE_SEARCH_KEY_SIZE {
            return Err(libc::EINVAL);
        }

        let read_u64 = |offset: usize| -> u64 {
            u64::from_ne_bytes(
                in_data[offset..offset + 8]
                    .try_into()
                    .expect("validated btrfs search key u64 field"),
            )
        };
        let read_u32 = |offset: usize| -> u32 {
            u32::from_ne_bytes(
                in_data[offset..offset + 4]
                    .try_into()
                    .expect("validated btrfs search key u32 field"),
            )
        };

        Ok(BtrfsTreeSearchKey {
            tree_id: read_u64(0),
            min_objectid: read_u64(8),
            max_objectid: read_u64(16),
            min_offset: read_u64(24),
            max_offset: read_u64(32),
            min_transid: read_u64(40),
            max_transid: read_u64(48),
            min_type: read_u32(56),
            max_type: read_u32(60),
            nr_items: read_u32(BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET),
        })
    }

    fn parse_inode_flags(in_data: &[u8]) -> Result<u32, c_int> {
        Self::parse_u32_ioctl_arg(in_data)
    }

    fn parse_fs_label_request(in_data: &[u8]) -> Result<Vec<u8>, c_int> {
        let parse_window = &in_data[..in_data.len().min(FSLABEL_MAX)];
        let Some(nul_pos) = parse_window.iter().position(|&byte| byte == 0) else {
            return Err(libc::EINVAL);
        };
        Ok(parse_window[..nul_pos].to_vec())
    }

    fn clamp_fiemap_extent_count(requested: u32, out_size: u32) -> usize {
        let max_extents_by_count = usize::try_from(requested).unwrap_or(usize::MAX);
        let max_extents_by_size = if usize::try_from(out_size).unwrap_or(0) > FIEMAP_HEADER_SIZE {
            (usize::try_from(out_size).unwrap_or(0) - FIEMAP_HEADER_SIZE) / FIEMAP_EXTENT_SIZE
        } else {
            0
        };
        max_extents_by_count.min(max_extents_by_size)
    }

    /// Serialise an [`FsxattrInfo`] into the 28-byte `struct fsxattr`
    /// payload returned by `FS_IOC_FSGETXATTR`. Layout per
    /// `<uapi/linux/fs.h>`: `xflags | extsize | nextents | projid |
    /// cowextsize | 8 bytes pad`. The Linux FUSE driver does no byte-swapping
    /// on ioctl payloads, so the FS daemon must match host byte order.
    /// Parse the 24-byte `struct fstrim_range` from FITRIM input.
    /// Layout: u64 start + u64 len + u64 minlen, host-native.
    fn parse_fstrim_range(buf: &[u8]) -> Result<(u64, u64, u64), i32> {
        if buf.len() < FITRIM_SIZE as usize {
            return Err(libc::EINVAL);
        }
        let start = u64::from_ne_bytes(buf[0..8].try_into().map_err(|_| libc::EINVAL)?);
        let len = u64::from_ne_bytes(buf[8..16].try_into().map_err(|_| libc::EINVAL)?);
        let min_len = u64::from_ne_bytes(buf[16..24].try_into().map_err(|_| libc::EINVAL)?);
        Ok((start, len, min_len))
    }

    /// Serialise the FITRIM response: the kernel writes the
    /// bytes-discarded count back into `fstrim_range.len` while
    /// leaving start + minlen unchanged.
    fn encode_fstrim_response(start: u64, bytes_discarded: u64, min_len: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FITRIM_SIZE as usize);
        buf.extend_from_slice(&start.to_ne_bytes());
        buf.extend_from_slice(&bytes_discarded.to_ne_bytes());
        buf.extend_from_slice(&min_len.to_ne_bytes());
        debug_assert_eq!(buf.len(), FITRIM_SIZE as usize);
        buf
    }

    /// Serialise the FS UUID into the 17-byte `struct fsuuid2`
    /// payload returned by `FS_IOC_GETFSUUID`. Layout per
    /// `<uapi/linux/fs.h>`: `u8 len` (always 16 for ext4 + btrfs) +
    /// `u8 uuid[16]`. The kernel copies the struct verbatim into
    /// userspace so byte order is host-native (the UUID itself is an
    /// opaque 16-byte token).
    fn encode_fsuuid_response(uuid: &[u8; 16]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FS_IOC_GETFSUUID_SIZE as usize);
        buf.push(16); // fsuuid2.len
        buf.extend_from_slice(uuid);
        debug_assert_eq!(buf.len(), FS_IOC_GETFSUUID_SIZE as usize);
        buf
    }

    /// Serialise a sysfs path into the 129-byte `struct fs_sysfs_path`
    /// payload returned by `FS_IOC_GETFSSYSFSPATH`. Layout per
    /// `<uapi/linux/fs.h>`: `u8 len` + `u8 name[128]`. `name` is
    /// zero-padded; `len` records the actual byte count. An empty path
    /// (the FUSE-backend default) encodes to `len = 0` followed by 128
    /// NUL bytes — userspace probes treat that as "no sysfs visibility"
    /// and skip silently. Returns `Err(EINVAL)` if the backend hands us
    /// a path longer than the 128-byte field can hold; the dispatcher
    /// turns that into a userspace EINVAL per the ioctl contract.
    fn encode_fs_sysfs_path_response(path: &[u8]) -> Result<Vec<u8>, i32> {
        if path.len() > FS_IOC_GETFSSYSFSPATH_NAME_MAX {
            return Err(libc::EINVAL);
        }
        let mut buf = vec![0_u8; FS_IOC_GETFSSYSFSPATH_SIZE as usize];
        // Cast is safe: bounds-checked against NAME_MAX (128) above.
        #[expect(clippy::cast_possible_truncation)]
        {
            buf[0] = path.len() as u8; // len byte
        }
        buf[1..=path.len()].copy_from_slice(path);
        // bytes [1 + path.len() .. 129] stay zero (NUL-padded name field).
        debug_assert_eq!(buf.len(), FS_IOC_GETFSSYSFSPATH_SIZE as usize);
        Ok(buf)
    }

    /// Parse the 28-byte `struct fsxattr` payload that userspace passes
    /// through `FS_IOC_FSSETXATTR`. Returns `EINVAL` if the buffer is
    /// the wrong length — callers must surface that errno verbatim per
    /// the Linux ioctl contract.
    fn parse_fsxattr_request(buf: &[u8]) -> Result<FsxattrInfo, i32> {
        if buf.len() < FS_IOC_FSSETXATTR_SIZE {
            return Err(libc::EINVAL);
        }
        let xflags = u32::from_ne_bytes(buf[0..4].try_into().map_err(|_| libc::EINVAL)?);
        let extsize = u32::from_ne_bytes(buf[4..8].try_into().map_err(|_| libc::EINVAL)?);
        // fsx_nextents (bytes 8..12) is read-only on the SET path and
        // must be ignored — kernel zeroes it on its own copy.
        let proj = u32::from_ne_bytes(buf[12..16].try_into().map_err(|_| libc::EINVAL)?);
        let cowextsize = u32::from_ne_bytes(buf[16..20].try_into().map_err(|_| libc::EINVAL)?);
        // fsx_pad[8] (bytes 20..28) is reserved; tolerate non-zero
        // padding to match the kernel which silently zeroes it.
        Ok(FsxattrInfo {
            xflags,
            extsize,
            nextents: 0,
            projid: proj,
            cowextsize,
        })
    }

    fn encode_fsxattr_response(fsx: &FsxattrInfo) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FS_IOC_FSGETXATTR_SIZE as usize);
        buf.extend_from_slice(&fsx.xflags.to_ne_bytes());
        buf.extend_from_slice(&fsx.extsize.to_ne_bytes());
        buf.extend_from_slice(&fsx.nextents.to_ne_bytes());
        buf.extend_from_slice(&fsx.projid.to_ne_bytes());
        buf.extend_from_slice(&fsx.cowextsize.to_ne_bytes());
        buf.extend_from_slice(&[0_u8; 8]); // fsx_pad[8]
        debug_assert_eq!(buf.len(), FS_IOC_FSGETXATTR_SIZE as usize);
        buf
    }

    fn encode_fiemap_response(
        fm_start: u64,
        fm_length: u64,
        requested_extent_count: u32,
        extents: &[FiemapExtent],
        out_size: u32,
    ) -> Vec<u8> {
        let returned_extents = extents
            .iter()
            .take(Self::clamp_fiemap_extent_count(
                requested_extent_count,
                out_size,
            ))
            .collect::<Vec<_>>();
        let mapped_count = u32::try_from(returned_extents.len()).unwrap_or(u32::MAX);

        let response_size = FIEMAP_HEADER_SIZE + returned_extents.len() * FIEMAP_EXTENT_SIZE;
        let mut response = vec![0_u8; response_size];

        response[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8]
            .copy_from_slice(&fm_start.to_ne_bytes());
        response[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
            .copy_from_slice(&fm_length.to_ne_bytes());
        response[FIEMAP_MAPPED_EXTENTS_OFFSET..FIEMAP_MAPPED_EXTENTS_OFFSET + 4]
            .copy_from_slice(&mapped_count.to_ne_bytes());
        response[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
            .copy_from_slice(&requested_extent_count.to_ne_bytes());

        for (i, ext) in returned_extents.iter().enumerate() {
            let off = FIEMAP_HEADER_SIZE + i * FIEMAP_EXTENT_SIZE;
            response[off..off + 8].copy_from_slice(&ext.logical.to_ne_bytes());
            response[off + 8..off + 16].copy_from_slice(&ext.physical.to_ne_bytes());
            response[off + 16..off + 24].copy_from_slice(&ext.length.to_ne_bytes());
            response[off + 40..off + 44].copy_from_slice(&ext.flags.to_ne_bytes());
        }

        response
    }

    fn encode_move_ext_response(
        donor_fd: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
        moved_len: u64,
    ) -> Vec<u8> {
        let mut response = vec![0_u8; MOVE_EXT_SIZE];
        response[MOVE_EXT_DONOR_FD_OFFSET..MOVE_EXT_DONOR_FD_OFFSET + 4]
            .copy_from_slice(&donor_fd.to_ne_bytes());
        response[MOVE_EXT_ORIG_START_OFFSET..MOVE_EXT_ORIG_START_OFFSET + 8]
            .copy_from_slice(&orig_start.to_ne_bytes());
        response[MOVE_EXT_DONOR_START_OFFSET..MOVE_EXT_DONOR_START_OFFSET + 8]
            .copy_from_slice(&donor_start.to_ne_bytes());
        response[MOVE_EXT_LEN_OFFSET..MOVE_EXT_LEN_OFFSET + 8].copy_from_slice(&len.to_ne_bytes());
        response[MOVE_EXT_MOVED_LEN_OFFSET..MOVE_EXT_MOVED_LEN_OFFSET + 8]
            .copy_from_slice(&moved_len.to_ne_bytes());
        response
    }

    fn validate_move_ext_range(
        blksize: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> Result<(), c_int> {
        let blocks_per_page = (MOVE_EXT_PAGE_SIZE_BYTES / u64::from(blksize.max(1))).max(1);
        if orig_start % blocks_per_page != donor_start % blocks_per_page {
            return Err(libc::EINVAL);
        }

        let orig_end = orig_start.checked_add(len).ok_or(libc::EINVAL)?;
        let donor_end = donor_start.checked_add(len).ok_or(libc::EINVAL)?;
        if orig_start >= EXT4_MOVE_EXT_MAX_BLOCKS
            || donor_start >= EXT4_MOVE_EXT_MAX_BLOCKS
            || len > EXT4_MOVE_EXT_MAX_BLOCKS
            || orig_end >= EXT4_MOVE_EXT_MAX_BLOCKS
            || donor_end >= EXT4_MOVE_EXT_MAX_BLOCKS
        {
            return Err(libc::EINVAL);
        }

        Ok(())
    }

    fn validate_move_ext_source(attr: &InodeAttr, flags: u32) -> Result<(), c_int> {
        if attr.kind != FfsFileType::RegularFile {
            return Err(libc::EINVAL);
        }
        if attr.size == 0 {
            return Err(libc::EINVAL);
        }
        if flags & EXT4_EXTENTS_FL == 0 {
            return Err(libc::EOPNOTSUPP);
        }
        Ok(())
    }

    fn move_ext_operation_id(
        ino: u64,
        donor_fd: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> String {
        format!("fuse-move-ext-{ino}-{donor_fd}-{orig_start}-{donor_start}-{len}")
    }

    fn classify_move_ext_error(error: &FfsError) -> &'static str {
        match error {
            FfsError::ReadOnly => "read_only",
            FfsError::UnsupportedFeature(_) => "unsupported_feature",
            FfsError::InvalidGeometry(_) | FfsError::Format(_) | FfsError::Parse(_) => {
                "invalid_request"
            }
            FfsError::NotFound(_) => "not_found",
            FfsError::Io(io_error) => match io_error.raw_os_error() {
                Some(libc::EBADF) => "bad_donor_fd",
                Some(libc::EINVAL) => "invalid_request",
                Some(libc::EPERM) => "permission_denied",
                Some(libc::EROFS) => "read_only",
                Some(libc::EOPNOTSUPP) => "unsupported_feature",
                Some(libc::ENOTTY) => "unsupported_ioctl",
                _ => "io_error",
            },
            _ => "operation_failed",
        }
    }

    fn move_ext_success_log_record(
        ctx: MoveExtLogContext<'_>,
        moved_len: u64,
    ) -> MoveExtLogRecord<'_> {
        MoveExtLogRecord {
            target: "ffs::ioctl",
            operation_id: ctx.operation_id,
            scenario_id: MOVE_EXT_SCENARIO_ID,
            outcome: "applied",
            error_class: MOVE_EXT_SUCCESS_ERROR_CLASS,
            ino: ctx.ino,
            donor_ino: ctx.donor_ino.map(|ino| ino.0),
            donor_fd: ctx.donor_fd,
            orig_start: ctx.orig_start,
            donor_start: ctx.donor_start,
            len: ctx.len,
            moved_len: Some(moved_len),
            errno: None,
        }
    }

    fn move_ext_error_log_record<'a>(
        ctx: MoveExtLogContext<'a>,
        error: &FfsError,
    ) -> MoveExtLogRecord<'a> {
        let error_class = Self::classify_move_ext_error(error);
        let outcome = match error.to_errno() {
            libc::EBADF
            | libc::EINVAL
            | libc::EPERM
            | libc::EROFS
            | libc::EOPNOTSUPP
            | libc::ENOTTY => "rejected",
            _ => "failed",
        };
        MoveExtLogRecord {
            target: "ffs::ioctl",
            operation_id: ctx.operation_id,
            scenario_id: MOVE_EXT_SCENARIO_ID,
            outcome,
            error_class,
            ino: ctx.ino,
            donor_ino: ctx.donor_ino.map(|ino| ino.0),
            donor_fd: ctx.donor_fd,
            orig_start: ctx.orig_start,
            donor_start: ctx.donor_start,
            len: ctx.len,
            moved_len: None,
            errno: Some(error.to_errno()),
        }
    }

    fn log_move_ext_success(ctx: MoveExtLogContext<'_>, moved_len: u64) {
        let record = Self::move_ext_success_log_record(ctx, moved_len);
        let logged_moved_len = record.moved_len.unwrap_or(0);
        info!(
            target: "ffs::ioctl",
            operation_id = record.operation_id,
            scenario_id = record.scenario_id,
            outcome = record.outcome,
            error_class = record.error_class,
            ino = record.ino,
            donor_ino = record.donor_ino,
            donor_fd = record.donor_fd,
            orig_start = record.orig_start,
            donor_start = record.donor_start,
            len = record.len,
            moved_len = logged_moved_len,
            "ext4 move_ext completed"
        );
    }

    fn log_move_ext_error(ctx: MoveExtLogContext<'_>, error: &FfsError) {
        let record = Self::move_ext_error_log_record(ctx, error);
        let logged_errno = record.errno.unwrap_or(libc::EIO);
        warn!(
            target: "ffs::ioctl",
            operation_id = record.operation_id,
            scenario_id = record.scenario_id,
            outcome = record.outcome,
            error_class = record.error_class,
            ino = record.ino,
            donor_ino = record.donor_ino,
            donor_fd = record.donor_fd,
            orig_start = record.orig_start,
            donor_start = record.donor_start,
            len = record.len,
            errno = logged_errno,
            error = %error,
            "ext4 move_ext rejected"
        );
    }

    fn resolve_move_ext_donor(
        &self,
        caller_pid: u32,
        donor_fd: u32,
    ) -> ffs_error::Result<InodeNumber> {
        let proc_fd_path = PathBuf::from(format!("/proc/{caller_pid}/fd/{donor_fd}"));
        let donor_file = std::fs::File::open(&proc_fd_path)
            .map_err(|_| FfsError::Io(std::io::Error::from_raw_os_error(libc::EBADF)))?;
        let donor_meta = donor_file
            .metadata()
            .map_err(|_| FfsError::Io(std::io::Error::from_raw_os_error(libc::EBADF)))?;

        if let Some(mountpoint) = self.inner.mountpoint.as_ref() {
            let mount_meta = std::fs::metadata(mountpoint)
                .map_err(|_| FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL)))?;
            if donor_meta.dev() != mount_meta.dev() {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                    libc::EINVAL,
                )));
            }
        }

        Ok(InodeNumber(donor_meta.ino()))
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_ioctl(
        &self,
        caller_pid: u32,
        ino: u64,
        fh: u64,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
    ) -> IoctlResult {
        let cmd = match cmd {
            BTRFS_IOC_CLONE => FICLONE,
            BTRFS_IOC_CLONE_RANGE => FICLONERANGE,
            other => other,
        };
        match cmd {
            FS_IOC_FIEMAP => {
                let (fm_start, fm_length, fm_flags, fm_extent_count) =
                    match Self::parse_fiemap_request(in_data) {
                        Ok(request) => request,
                        Err(errno) => return IoctlResult::Error(errno),
                    };
                if fm_flags & !FIEMAP_SUPPORTED_FLAGS != 0 {
                    return IoctlResult::Error(libc::EBADR);
                }

                if out_size < u32::try_from(FIEMAP_HEADER_SIZE).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }

                let cx = Self::cx_for_request();
                if fm_flags & FIEMAP_FLAG_SYNC != 0 && !self.inner.read_only {
                    match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
                        self.inner
                            .ops
                            .fsync(cx, scope, InodeNumber(ino), fh, false)?;
                        self.inner.ops.commit_request_scope(scope)?;
                        Ok(())
                    }) {
                        Ok(()) => {}
                        Err(error) => return IoctlResult::Error(error.to_errno()),
                    }
                }
                let extents =
                    match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                        self.inner
                            .ops
                            .fiemap(cx, scope, InodeNumber(ino), fm_start, fm_length)
                    }) {
                        Ok(exts) => exts,
                        Err(error) => return IoctlResult::Error(error.to_errno()),
                    };

                IoctlResult::Data(Self::encode_fiemap_response(
                    fm_start,
                    fm_length,
                    fm_extent_count,
                    &extents,
                    out_size,
                ))
            }
            EXT4_IOC_GETFLAGS => {
                if out_size < u32::try_from(std::mem::size_of::<u32>()).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_inode_flags(cx, scope, InodeNumber(ino))
                }) {
                    Ok(flags) => IoctlResult::Data(flags.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_GETSTATE => {
                // _IOR with a 4-byte payload: validate the user buffer
                // can hold the u32 reply, route through FsOps under
                // an IoctlRead scope, and encode the host-native u32
                // back to userspace. The kernel never returns an
                // error for a valid inode here, but we propagate
                // backend errors (e.g. ENOENT) the same way.
                if out_size < EXT4_IOC_GETSTATE_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_inode_state(cx, scope, InodeNumber(ino))
                }) {
                    Ok(state) => IoctlResult::Data(state.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            cmd if cmd == EXT4_IOC_GETVERSION || cmd == FS_IOC_GETVERSION => {
                if out_size < u32::try_from(std::mem::size_of::<u32>()).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_inode_generation(cx, scope, InodeNumber(ino))
                }) {
                    Ok(generation) => IoctlResult::Data(generation.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FIBMAP => {
                if out_size < FIBMAP_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let logical = match Self::parse_u32_ioctl_arg(in_data) {
                    Ok(value) => u64::from(value),
                    Err(errno) => return IoctlResult::Error(errno),
                };
                let cx = Self::cx_for_request();
                let (block_size, extents) =
                    match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                        let stats = self.inner.ops.statfs(cx, scope, InodeNumber(ino))?;
                        let block_size = u64::from(stats.block_size);
                        if block_size == 0 {
                            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                                libc::EINVAL,
                            )));
                        }
                        let extents = self.inner.ops.fiemap(
                            cx,
                            scope,
                            InodeNumber(ino),
                            logical.saturating_mul(block_size),
                            block_size,
                        )?;
                        Ok((block_size, extents))
                    }) {
                        Ok(result) => result,
                        Err(error) => return IoctlResult::Error(error.to_errno()),
                    };
                let req_byte = logical.saturating_mul(block_size);
                // Hole / sparse range -> 0 per fs/ext4/inode.c::ext4_get_block.
                let physical_block = extents
                    .into_iter()
                    .find(|e| {
                        // The first extent that actually covers the
                        // queried logical block (fiemap may return an
                        // extent that starts later if the query falls
                        // in a hole).
                        e.logical <= req_byte && req_byte < e.logical.saturating_add(e.length)
                    })
                    .map_or(0_u64, |e| {
                        if e.flags & FIEMAP_EXTENT_UNWRITTEN != 0 {
                            return 0;
                        }
                        let offset_into = req_byte - e.logical;
                        e.physical.saturating_add(offset_into) / block_size
                    });
                let physical_u32 = u32::try_from(physical_block).unwrap_or(u32::MAX);
                IoctlResult::Data(physical_u32.to_ne_bytes().to_vec())
            }
            FITRIM => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if out_size < FITRIM_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let (start, len, min_len) = match Self::parse_fstrim_range(in_data) {
                    Ok(parsed) => parsed,
                    Err(errno) => return IoctlResult::Error(errno),
                };
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.trim_range(cx, scope, start, len, min_len)
                }) {
                    Ok(bytes_discarded) => IoctlResult::Data(Self::encode_fstrim_response(
                        start,
                        bytes_discarded,
                        min_len,
                    )),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_GETFSUUID => {
                if out_size < FS_IOC_GETFSUUID_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                match self.inner.ops.fs_uuid() {
                    Ok(uuid) => IoctlResult::Data(Self::encode_fsuuid_response(&uuid)),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_GETFSSYSFSPATH => {
                if out_size < FS_IOC_GETFSSYSFSPATH_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                match self.inner.ops.fs_sysfs_path() {
                    Ok(path) => match Self::encode_fs_sysfs_path_response(&path) {
                        Ok(buf) => IoctlResult::Data(buf),
                        Err(errno) => IoctlResult::Error(errno),
                    },
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_FSGETXATTR => {
                if out_size < FS_IOC_FSGETXATTR_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_inode_fsxattr(cx, scope, InodeNumber(ino))
                }) {
                    Ok(fsx) => IoctlResult::Data(Self::encode_fsxattr_response(&fsx)),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_FSSETXATTR => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let fsx = match Self::parse_fsxattr_request(in_data) {
                    Ok(fsx) => fsx,
                    Err(errno) => return IoctlResult::Error(errno),
                };
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .set_inode_fsxattr(cx, scope, InodeNumber(ino), fsx)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_PRECACHE_EXTENTS => {
                // _IO with no payload: ignore in_data / out_size and
                // run the precache walk under a read scope. ext4 always
                // returns 0 for valid inodes (the per-inode precache is
                // a best-effort hint), so propagate backend errors but
                // keep success as an empty Data reply.
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.precache_extents(cx, scope, InodeNumber(ino))
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_CLEAR_ES_CACHE => {
                // _IO with no payload: same dispatch shape as
                // EXT4_IOC_PRECACHE_EXTENTS. ext4_clear_inode_es is
                // always a successful no-op for a valid inode in the
                // kernel; we mirror that contract by routing through
                // FsOps::clear_extent_status_cache and propagating only
                // backend errors (e.g. ENOENT for a bogus inode).
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .clear_extent_status_cache(cx, scope, InodeNumber(ino))
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            cmd if cmd == EXT4_IOC_SETVERSION || cmd == FS_IOC_SETVERSION => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let generation = match Self::parse_u32_ioctl_arg(in_data) {
                    Ok(generation) => generation,
                    Err(errno) => return IoctlResult::Error(errno),
                };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .set_inode_generation(cx, scope, InodeNumber(ino), generation)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_GET_ENCRYPTION_POLICY => {
                // Linux exposes the legacy v1 fscrypt getter as an `_IOW` ioctl,
                // so real mounted-path requests often arrive with a caller buffer
                // in `in_data` and `out_size == 0`. Unit tests that bypass the
                // kernel still use the simpler `out_size` form, so accept either
                // request shape as long as one side advertises a full v1 policy
                // buffer. Note that restricted FUSE still cannot return success
                // data for this ioctl shape: the kernel advertises zero output
                // bytes and converts any non-empty reply into `EIO`.
                let advertised_len =
                    usize::max(in_data.len(), usize::try_from(out_size).unwrap_or(0));
                if advertised_len < FSCRYPT_POLICY_V1_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_encryption_policy_v1(cx, scope, InodeNumber(ino))
                }) {
                    Ok(policy) => IoctlResult::Data(policy.to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_GET_ENCRYPTION_POLICY_EX => {
                // The _EX ioctl uses a struct fscrypt_get_policy_ex_arg:
                //   policy_size: u64 (in/out)
                //   policy: union { v1: [u8; 12], v2: [u8; 24] }
                // Input: caller sets policy_size to buffer capacity
                // Output: kernel sets policy_size to actual size
                //
                // Real mounted requests carry the caller's policy capacity in
                // the `policy_size` field. Direct unit tests that bypass the
                // kernel use `out_size`, so accept either advertised capacity.
                let advertised_by_in_data = if in_data.len() >= FSCRYPT_POLICY_EX_HEADER_SIZE {
                    let mut raw_size = [0_u8; FSCRYPT_POLICY_EX_HEADER_SIZE];
                    raw_size.copy_from_slice(&in_data[..FSCRYPT_POLICY_EX_HEADER_SIZE]);
                    usize::try_from(u64::from_ne_bytes(raw_size))
                        .ok()
                        .and_then(|policy_size| {
                            policy_size.checked_add(FSCRYPT_POLICY_EX_HEADER_SIZE)
                        })
                        .unwrap_or(usize::MAX)
                } else {
                    in_data.len()
                };
                let advertised_len = if in_data.len() >= FSCRYPT_POLICY_EX_HEADER_SIZE {
                    advertised_by_in_data
                } else {
                    usize::try_from(out_size).unwrap_or(0)
                };

                // We must check the caller's advertised capacity against the
                // actual policy size returned by the backend, not just the v1
                // minimum, to avoid returning more bytes than the caller can
                // accept for v2 policies.
                let min_out_size = FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V1_SIZE;
                if advertised_len < min_out_size {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_encryption_policy_ex(cx, scope, InodeNumber(ino))
                }) {
                    Ok((version, policy)) => {
                        let required_size = FSCRYPT_POLICY_EX_HEADER_SIZE + policy.len();
                        if advertised_len < required_size {
                            // Caller buffer too small for the actual policy version.
                            return IoctlResult::Error(libc::EOVERFLOW);
                        }
                        let policy_size = policy.len() as u64;
                        let mut buf = vec![0_u8; required_size];
                        buf[..8].copy_from_slice(&policy_size.to_ne_bytes());
                        buf[8..8 + policy.len()].copy_from_slice(&policy);
                        if version == 0 {
                            // v1 policy: version byte is already 0 in position 8
                        } else {
                            // v2 policy: set version byte at position 8
                            buf[8] = version;
                        }
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_SETFLAGS => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let flags = match Self::parse_inode_flags(in_data) {
                    Ok(flags) => flags,
                    Err(errno) => return IoctlResult::Error(errno),
                };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .set_inode_flags(cx, scope, InodeNumber(ino), flags)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_MOVE_EXT => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if out_size < u32::try_from(MOVE_EXT_SIZE).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let (donor_fd, orig_start, donor_start, len) =
                    match Self::parse_move_ext_request(in_data) {
                        Ok(request) => request,
                        Err(errno) => return IoctlResult::Error(errno),
                    };
                let operation_id =
                    Self::move_ext_operation_id(ino, donor_fd, orig_start, donor_start, len);
                let log_ctx = MoveExtLogContext {
                    operation_id: &operation_id,
                    ino,
                    donor_ino: None,
                    donor_fd,
                    orig_start,
                    donor_start,
                    len,
                };

                let cx = Self::cx_for_request();
                let mut donor_ino = None;
                let mut donor_registered = false;
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    let attr = self.inner.ops.getattr(cx, scope, InodeNumber(ino))?;
                    let flags = self
                        .inner
                        .ops
                        .get_inode_flags(cx, scope, InodeNumber(ino))?;
                    Self::validate_move_ext_source(&attr, flags)
                        .map_err(|errno| FfsError::Io(std::io::Error::from_raw_os_error(errno)))?;
                    Self::validate_move_ext_range(attr.blksize, orig_start, donor_start, len)
                        .map_err(|_| FfsError::InvalidGeometry("invalid move_ext range".into()))?;
                    let resolved_donor = self.resolve_move_ext_donor(caller_pid, donor_fd)?;
                    donor_ino = Some(resolved_donor);
                    self.inner
                        .ops
                        .register_move_ext_donor_fd(donor_fd, resolved_donor)?;
                    donor_registered = true;
                    let moved_len = self.inner.ops.move_ext(
                        cx,
                        scope,
                        InodeNumber(ino),
                        donor_fd,
                        orig_start,
                        donor_start,
                        len,
                    )?;
                    self.inner.ops.unregister_move_ext_donor_fd(donor_fd);
                    donor_registered = false;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(moved_len)
                }) {
                    Ok(moved_len) => {
                        let mut success_ctx = log_ctx;
                        success_ctx.donor_ino = donor_ino;
                        Self::log_move_ext_success(success_ctx, moved_len);
                        IoctlResult::Data(Self::encode_move_ext_response(
                            donor_fd,
                            orig_start,
                            donor_start,
                            len,
                            moved_len,
                        ))
                    }
                    Err(error) => {
                        if donor_registered {
                            self.inner.ops.unregister_move_ext_donor_fd(donor_fd);
                        }
                        let mut error_ctx = log_ctx;
                        error_ctx.donor_ino = donor_ino;
                        Self::log_move_ext_error(error_ctx, &error);
                        IoctlResult::Error(error.to_errno())
                    }
                }
            }
            EXT4_IOC_GROUP_EXTEND => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_group_extend(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_RESIZE_FS => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_resize_fs(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_GROUP_ADD => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 16 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_group_add(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_ALLOC_DA_BLKS => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_alloc_da_blks(cx, scope, ino)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_MIGRATE => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_migrate(cx, scope, ino)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_SWAP_BOOT => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_swap_boot(cx, scope, ino)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_SHUTDOWN => {
                if in_data.len() < 4 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.fs_shutdown(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FIFREEZE => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.fs_freeze(cx, scope)
                }) {
                    Ok(level) => {
                        let mut buf = [0u8; 4];
                        buf.copy_from_slice(&level.to_ne_bytes());
                        IoctlResult::Data(buf.to_vec())
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FITHAW => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.fs_thaw(cx, scope)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FIGETBSZ => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_block_size(cx, scope)
                }) {
                    Ok(bsz) => {
                        let mut buf = [0u8; 4];
                        // FIGETBSZ returns i32; block sizes are always small (<= 65536)
                        #[expect(clippy::cast_possible_wrap)]
                        let bsz_i32 = bsz as i32;
                        buf.copy_from_slice(&bsz_i32.to_ne_bytes());
                        IoctlResult::Data(buf.to_vec())
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            cmd if cmd == FS_IOC_GETFSLABEL || cmd == BTRFS_IOC_GET_FSLABEL => {
                if out_size < FSLABEL_MAX_U32 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                debug_assert_eq!(BTRFS_FSLABEL_SIZE, FSLABEL_MAX_U32);
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_fs_label(cx, scope)
                }) {
                    Ok(label) => {
                        let mut buf = vec![0_u8; FSLABEL_MAX];
                        let copy_len = label.len().min(FSLABEL_MAX);
                        buf[..copy_len].copy_from_slice(&label[..copy_len]);
                        if copy_len < FSLABEL_MAX {
                            buf[copy_len] = 0;
                        }
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            cmd if cmd == FS_IOC_SETFSLABEL || cmd == BTRFS_IOC_SET_FSLABEL => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let label = match Self::parse_fs_label_request(in_data) {
                    Ok(label) => label,
                    Err(errno) => return IoctlResult::Error(errno),
                };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.set_fs_label(cx, scope, &label)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_FS_INFO => {
                // Reject if the caller's out buffer can't hold the full 1024-byte
                // `btrfs_ioctl_fs_info_args` struct — the kernel would truncate
                // it and hand back garbage padding, so fail deterministically.
                if out_size < BTRFS_IOC_FS_INFO_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_fs_info(cx, scope)
                }) {
                    Ok(payload) => {
                        // Backend contract: exactly 1024 bytes.  Be defensive
                        // — pad/truncate to that width so a single backend
                        // bug can't corrupt the kernel reply buffer.
                        let mut buf = vec![0_u8; BTRFS_IOC_FS_INFO_SIZE as usize];
                        let copy_len = payload.len().min(buf.len());
                        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEV_INFO => {
                // `_IOWR`: the caller's in_data carries `devid` + `uuid` lookup
                // keys (24 bytes are enough — offsets 0x00..0x08 + 0x08..0x18),
                // and the caller's out buffer must be able to hold the full
                // 4096-byte struct reply.  Any smaller shape is rejected
                // deterministically rather than silently truncated.
                if in_data.len() < 24 || out_size < BTRFS_IOC_DEV_INFO_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let mut raw_devid = [0_u8; 8];
                raw_devid.copy_from_slice(&in_data[0..8]);
                let devid_in = u64::from_ne_bytes(raw_devid);
                let mut uuid_in = [0_u8; 16];
                uuid_in.copy_from_slice(&in_data[8..24]);

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_btrfs_dev_info(cx, scope, devid_in, uuid_in)
                }) {
                    Ok(payload) => {
                        let mut buf = vec![0_u8; BTRFS_IOC_DEV_INFO_SIZE as usize];
                        let copy_len = payload.len().min(buf.len());
                        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_TREE_SEARCH => {
                if out_size < BTRFS_TREE_SEARCH_ARGS_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let search_key = match Self::parse_btrfs_tree_search_key(in_data) {
                    Ok(search_key) => search_key,
                    Err(errno) => return IoctlResult::Error(errno),
                };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_tree_search(cx, scope, search_key)
                }) {
                    Ok((nr_items, payload)) => {
                        let mut buf = vec![0_u8; BTRFS_TREE_SEARCH_ARGS_SIZE as usize];
                        buf[..BTRFS_TREE_SEARCH_KEY_SIZE]
                            .copy_from_slice(&in_data[..BTRFS_TREE_SEARCH_KEY_SIZE]);
                        buf[BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET
                            ..BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET + 4]
                            .copy_from_slice(&nr_items.to_ne_bytes());

                        let tail_start = BTRFS_TREE_SEARCH_KEY_SIZE;
                        let copy_len = payload.len().min(buf.len() - tail_start);
                        buf[tail_start..tail_start + copy_len]
                            .copy_from_slice(&payload[..copy_len]);
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_INO_LOOKUP => {
                // Require full 4096-byte buffer for input and output.
                if in_data.len() < BTRFS_INO_LOOKUP_ARGS_SIZE as usize
                    || out_size < BTRFS_INO_LOOKUP_ARGS_SIZE
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                // Parse input: treeid (u64 at offset 0), objectid (u64 at offset 8).
                let mut raw_treeid = [0_u8; 8];
                raw_treeid.copy_from_slice(&in_data[0..8]);
                let treeid = u64::from_ne_bytes(raw_treeid);
                let mut raw_objectid = [0_u8; 8];
                raw_objectid.copy_from_slice(&in_data[8..16]);
                let objectid = u64::from_ne_bytes(raw_objectid);

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_ino_lookup(cx, scope, treeid, objectid)
                }) {
                    Ok((resolved_treeid, path)) => {
                        // Build output: treeid (8 bytes) + objectid (8 bytes) + name[4080].
                        let mut buf = vec![0_u8; BTRFS_INO_LOOKUP_ARGS_SIZE as usize];
                        buf[0..8].copy_from_slice(&resolved_treeid.to_ne_bytes());
                        buf[8..16].copy_from_slice(&objectid.to_ne_bytes());
                        let path_len = path.len().min(4080);
                        buf[16..16 + path_len].copy_from_slice(&path[..path_len]);
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEFAULT_SUBVOL => {
                if in_data.len() < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let mut raw = [0_u8; 8];
                raw.copy_from_slice(&in_data[0..8]);
                let treeid = u64::from_ne_bytes(raw);
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_set_default_subvol(cx, scope, treeid)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SUBVOL_GETFLAGS => {
                if out_size < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_subvol_flags(cx, scope, InodeNumber(ino))
                }) {
                    Ok(flags) => IoctlResult::Data(flags.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SUBVOL_SETFLAGS => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let mut raw = [0_u8; 8];
                raw.copy_from_slice(&in_data[0..8]);
                let flags = u64::from_ne_bytes(raw);

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .set_subvol_flags(cx, scope, InodeNumber(ino), flags)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SYNC => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
                    self.inner.ops.sync_fs(cx, scope)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_TRANS_START => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_start_transaction(cx, scope)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_TRANS_END => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_end_transaction(cx, scope)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_START_SYNC => {
                if out_size < BTRFS_SYNC_TRANSID_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
                    self.inner.ops.btrfs_start_sync(cx, scope)
                }) {
                    Ok(transid) => IoctlResult::Data(transid.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_WAIT_SYNC => {
                if in_data.len() < BTRFS_SYNC_TRANSID_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let mut raw = [0_u8; 8];
                raw.copy_from_slice(&in_data[0..8]);
                let transid = u64::from_ne_bytes(raw);
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
                    self.inner.ops.btrfs_wait_sync(cx, scope, transid)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_FEATURES => {
                if out_size < BTRFS_FEATURE_FLAGS_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_features(cx, scope)
                }) {
                    Ok(flags) => IoctlResult::Data(flags),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SET_FEATURES => {
                if in_data.len() < BTRFS_SET_FEATURES_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.set_btrfs_features(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_SUPPORTED_FEATURES => {
                if out_size < BTRFS_SUPPORTED_FEATURE_FLAGS_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_supported_features(cx, scope)
                }) {
                    Ok(flags) => IoctlResult::Data(flags),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SPACE_INFO => {
                // Input: 16-byte header with space_slots (number of entries caller can receive)
                // Output: header (space_slots ignored, total_spaces set) + array of space_info
                if in_data.len() < BTRFS_SPACE_ARGS_HEADER_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let space_slots = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_space_info(cx, scope, space_slots)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_INO_PATHS => {
                // Input: 56-byte struct with inum, size, reserved, fspath pointer
                // For now, return EOPNOTSUPP as implementing backref resolution is complex
                if in_data.len() < BTRFS_INO_PATH_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let inum = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_ino_paths(cx, scope, inum)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_LOGICAL_INO => {
                // Input: 56-byte struct with logical addr, size, reserved, flags, inodes pointer
                // For now, return EOPNOTSUPP as implementing logical-to-inode is complex
                if in_data.len() < BTRFS_LOGICAL_INO_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let logical = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_logical_ino(cx, scope, logical)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_LOGICAL_INO_V2 => {
                // V2 adds flags field at offset 32 for BTRFS_LOGICAL_INO_ARGS_IGNORE_OFFSET
                if in_data.len() < BTRFS_LOGICAL_INO_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let logical = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_btrfs_logical_ino_v2(cx, scope, logical, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SCRUB => {
                // Input: 1024-byte struct with devid, start, end, flags, progress
                if in_data.len() < BTRFS_SCRUB_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let devid = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_scrub_start(cx, scope, devid)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SCRUB_CANCEL => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_scrub_cancel(cx, scope)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SCRUB_PROGRESS => {
                // Input: 1024-byte struct with devid to query
                if in_data.len() < BTRFS_SCRUB_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let devid = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_scrub_progress(cx, scope, devid)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QUOTA_RESCAN_WAIT => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_wait_quota_rescan(cx, scope)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QUOTA_RESCAN_STATUS => {
                if out_size < BTRFS_QUOTA_RESCAN_ARGS_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_quota_rescan_status(cx, scope)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QUOTA_RESCAN => {
                if in_data.len() < BTRFS_QUOTA_RESCAN_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let flags = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_start_quota_rescan(cx, scope, flags)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QUOTA_CTL => {
                if in_data.len() < BTRFS_QUOTA_CTL_ARGS_SIZE as usize
                    || out_size < BTRFS_QUOTA_CTL_ARGS_SIZE
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cmd = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let status = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_quota_control(cx, scope, cmd, status)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QGROUP_ASSIGN => {
                if in_data.len() < BTRFS_QGROUP_ASSIGN_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let assign = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let src = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let dst = u64::from_le_bytes(in_data[16..24].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_assign_qgroup(cx, scope, assign, src, dst)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QGROUP_CREATE => {
                if in_data.len() < BTRFS_QGROUP_CREATE_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let create = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let qgroupid = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_create_qgroup(cx, scope, create, qgroupid)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QGROUP_LIMIT => {
                if in_data.len() < BTRFS_QGROUP_LIMIT_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let limit = BtrfsQgroupLimitRequest {
                    qgroupid: u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8])),
                    flags: u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8])),
                    max_rfer: u64::from_le_bytes(in_data[16..24].try_into().unwrap_or([0; 8])),
                    max_excl: u64::from_le_bytes(in_data[24..32].try_into().unwrap_or([0; 8])),
                    rsv_rfer: u64::from_le_bytes(in_data[32..40].try_into().unwrap_or([0; 8])),
                    rsv_excl: u64::from_le_bytes(in_data[40..48].try_into().unwrap_or([0; 8])),
                };
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_limit_qgroup(cx, scope, limit)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEFRAG_RANGE => {
                // Input: 48-byte struct with start, len, flags, extent_thresh, compress_type
                if in_data.len() < BTRFS_DEFRAG_RANGE_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let start = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let len = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_defrag_range(cx, scope, fh, start, len)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SNAP_CREATE_V2 => {
                // Input: 4096-byte vol_args_v2 with fd, transid, flags, name
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_snap_create(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SNAP_DESTROY => {
                // Input: 4096-byte vol_args with name
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_snap_destroy(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SNAP_DESTROY_V2 => {
                // Input: 4096-byte vol_args_v2 with subvolid field
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_snap_destroy_v2(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_ENCODED_READ => {
                // Input: 64-byte encoded_io_args with iovec info
                if in_data.len() < BTRFS_ENCODED_IO_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_encoded_read(cx, scope, ino, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_ENCODED_WRITE => {
                // Write is unsupported on read-only filesystem
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_encoded_write(cx, scope, ino, in_data)
                }) {
                    Ok(len) => {
                        let mut out = vec![0u8; 8];
                        out[0..8].copy_from_slice(&(len as u64).to_le_bytes());
                        IoctlResult::Data(out)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_RESIZE => {
                // Resize requires write access
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_resize(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEV_REPLACE => {
                // Input: 2600-byte dev_replace_args with cmd + status
                if in_data.len() < BTRFS_DEV_REPLACE_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_dev_replace(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEFRAG => {
                // v1 defrag requires write access
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_defrag(cx, scope, ino)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SCAN_DEV => {
                // Device scanning - not applicable in FUSE context
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_scan_dev(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_FORGET_DEV => {
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_forget_dev(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SEND => {
                // Send requires implementing the full btrfs send stream protocol
                if in_data.len() < BTRFS_SEND_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_send(cx, scope, in_data, caller_pid)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SET_RECEIVED_SUBVOL => {
                // Set received UUID requires write access
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < BTRFS_RECEIVED_SUBVOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_set_received_subvol(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_FILE_EXTENT_SAME => {
                // Dedupe requires write access
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < BTRFS_SAME_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_file_extent_same(cx, scope, ino, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SUBVOL_CREATE_V2 => {
                // Input: 4096-byte vol_args_v2 with flags and name
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_subvol_create(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_RM_DEV_V2 => {
                // Input: 4096-byte vol_args_v2 with flags and name/devid.
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_rm_dev_v2(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_ADD_DEV => {
                // Input: 4096-byte vol_args with device path.
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_add_dev(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_RM_DEV => {
                // Input: 4096-byte vol_args with device path.
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_rm_dev(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FICLONE => {
                // Reflink: writes dst's extent tree, so a read-only mount must
                // reject with EROFS. Input: 4-byte source fd.
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 4 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let src_fd = i32::from_le_bytes(in_data[0..4].try_into().unwrap_or([0; 4]));
                let Ok(src_fd) = u32::try_from(src_fd) else {
                    return IoctlResult::Error(libc::EBADF);
                };
                let cx = Self::cx_for_request();
                // Resolve the caller's source fd to a same-device inode (reuses
                // the move_ext donor resolver), then share its extents into the
                // ioctl target (`ino`). bd-vh8p9.
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    let src_ino = self.resolve_move_ext_donor(caller_pid, src_fd)?;
                    self.inner
                        .ops
                        .clone_file(cx, scope, InodeNumber(ino), src_ino)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FICLONERANGE => {
                // Input: 32-byte file_clone_range struct. Writes dst, so RO
                // mounts reject with EROFS.
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < FILE_CLONE_RANGE_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let src_fd = i64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let src_offset = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let src_length = u64::from_le_bytes(in_data[16..24].try_into().unwrap_or([0; 8]));
                let dest_offset = u64::from_le_bytes(in_data[24..32].try_into().unwrap_or([0; 8]));
                let Ok(src_fd) = u32::try_from(src_fd) else {
                    return IoctlResult::Error(libc::EBADF);
                };
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    let src_ino = self.resolve_move_ext_donor(caller_pid, src_fd)?;
                    self.inner.ops.clone_file_range(
                        cx,
                        scope,
                        InodeNumber(ino),
                        src_ino,
                        src_offset,
                        src_length,
                        dest_offset,
                    )?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_BALANCE_V2 => {
                // Input: 1024-byte balance_args with filters
                if in_data.len() < BTRFS_BALANCE_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_balance_start(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_BALANCE_CTL => {
                // Input: 4-byte int (1=pause, 2=cancel, 3=resume)
                if in_data.len() < 4 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cmd = i32::from_le_bytes(in_data[0..4].try_into().unwrap_or([0; 4]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_balance_ctl(cx, scope, cmd)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_BALANCE_PROGRESS => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_balance_progress(cx, scope)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_DEV_STATS => {
                // Input: 1032-byte struct with devid
                if in_data.len() < BTRFS_DEV_STATS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let devid = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_get_dev_stats(cx, scope, devid)
                }) {
                    Ok(mut data) => {
                        data.resize(BTRFS_DEV_STATS_SIZE as usize, 0);
                        IoctlResult::Data(data)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_SUBVOL_INFO => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_get_subvol_info(cx, scope, InodeNumber(ino))
                }) {
                    Ok(mut data) => {
                        data.resize(BTRFS_SUBVOL_INFO_SIZE as usize, 0);
                        IoctlResult::Data(data)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_TREE_SEARCH_V2 => {
                if in_data.len() < BTRFS_TREE_SEARCH_V2_HEADER_SIZE
                    || out_size < BTRFS_TREE_SEARCH_V2_HEADER_SIZE_U32
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_tree_search_v2(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_INO_LOOKUP_USER => {
                if in_data.len() < BTRFS_INO_LOOKUP_USER_SIZE as usize
                    || out_size < BTRFS_INO_LOOKUP_USER_SIZE
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let dirid = u64::from_ne_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let treeid = u64::from_ne_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_ino_lookup_user(cx, scope, treeid, dirid)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_SUBVOL_ROOTREF => {
                if in_data.len() < BTRFS_SUBVOL_ROOTREF_SIZE as usize
                    || out_size < BTRFS_SUBVOL_ROOTREF_SIZE
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_get_subvol_rootref(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            _ => IoctlResult::Error(libc::ENOTTY),
        }
    }

    fn record_ioctl_probe(&self, ino: u64, cmd: u32, in_len: usize, out_size: u32) {
        let Some(trace) = self.inner.ioctl_trace.as_ref() else {
            return;
        };
        // Non-blocking enqueue onto the writer thread's bounded channel.
        // Backpressure is recorded inside the probe and surfaced on shutdown.
        trace.record(ino, cmd, in_len, out_size);
    }

    fn with_request_scope<T, F>(&self, cx: &Cx, op: RequestOp, f: F) -> ffs_error::Result<T>
    where
        F: FnOnce(&Cx, &mut RequestScope) -> ffs_error::Result<T>,
    {
        let mut scope = match self.inner.ops.begin_request_scope(cx, op) {
            Ok(scope) => scope,
            Err(e) => {
                self.inner.metrics.record_err();
                return Err(e);
            }
        };
        let op_result = f(cx, &mut scope);
        let end_result = self.inner.ops.end_request_scope(cx, op, scope);

        match (op_result, end_result) {
            (Ok(value), Ok(())) => {
                self.inner.metrics.record_ok();
                Ok(value)
            }
            (Ok(_), Err(end_err)) => {
                self.inner.metrics.record_err();
                Err(end_err)
            }
            (Err(op_err), Ok(())) => {
                self.inner.metrics.record_err();
                Err(op_err)
            }
            (Err(op_err), Err(end_err)) => {
                self.inner.metrics.record_err();
                warn!(?op, error = %end_err, "request scope cleanup failed after operation error");
                Err(op_err)
            }
        }
    }

    fn lock_writeback_batches(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<WritebackKey, Arc<WritebackBatch>>> {
        match self.inner.writeback_batches.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("FUSE writeback batch table poisoned, recovering");
                poisoned.into_inner()
            }
        }
    }

    fn lock_writeback_scope(
        batch: &WritebackBatch,
    ) -> std::sync::MutexGuard<'_, Option<RequestScope>> {
        match batch.scope.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("FUSE writeback batch scope poisoned, recovering");
                poisoned.into_inner()
            }
        }
    }

    fn begin_deferred_write_scope(&self, cx: &Cx) -> ffs_error::Result<RequestScope> {
        let mut scope = self.inner.ops.begin_request_scope(cx, RequestOp::Write)?;
        scope.defer_commit_until_flush();
        Ok(scope)
    }

    fn end_deferred_write_scope(&self, cx: &Cx, scope: RequestScope) -> ffs_error::Result<()> {
        self.inner
            .ops
            .end_request_scope(cx, RequestOp::Write, scope)
    }

    fn commit_deferred_write_scope(
        &self,
        cx: &Cx,
        mut scope: RequestScope,
    ) -> ffs_error::Result<ffs_types::CommitSeq> {
        let commit_result = self.inner.ops.commit_request_scope(&mut scope);
        let end_result = self.end_deferred_write_scope(cx, scope);

        match (commit_result, end_result) {
            (Ok(commit), Ok(())) => Ok(commit),
            (Ok(_), Err(end_err)) => Err(end_err),
            (Err(commit_err), Ok(())) => Err(commit_err),
            (Err(commit_err), Err(end_err)) => {
                warn!(
                    error = %end_err,
                    "writeback batch cleanup failed after commit error"
                );
                Err(commit_err)
            }
        }
    }

    fn writeback_batch(&self, key: WritebackKey) -> Option<Arc<WritebackBatch>> {
        self.lock_writeback_batches().get(&key).cloned()
    }

    fn get_or_begin_writeback_batch(
        &self,
        cx: &Cx,
        key: WritebackKey,
    ) -> ffs_error::Result<Arc<WritebackBatch>> {
        if let Some(batch) = self.writeback_batch(key) {
            return Ok(batch);
        }

        let scope = self.begin_deferred_write_scope(cx)?;
        let batch = Arc::new(WritebackBatch::new(scope));
        let mut batches = self.lock_writeback_batches();
        if let Some(existing) = batches.get(&key) {
            let existing = Arc::clone(existing);
            drop(batches);
            let mut scope_guard = Self::lock_writeback_scope(&batch);
            if let Some(scope) = scope_guard.take() {
                drop(scope_guard);
                self.end_deferred_write_scope(cx, scope)?;
            }
            return Ok(existing);
        }
        batches.insert(key, Arc::clone(&batch));
        drop(batches);
        Ok(batch)
    }

    fn remove_writeback_batch_if_same(&self, key: WritebackKey, batch: &Arc<WritebackBatch>) {
        let mut batches = self.lock_writeback_batches();
        if batches
            .get(&key)
            .is_some_and(|existing| Arc::ptr_eq(existing, batch))
        {
            batches.remove(&key);
        }
    }

    fn commit_writeback_batch_for_key(
        &self,
        cx: &Cx,
        key: WritebackKey,
    ) -> ffs_error::Result<Option<ffs_types::CommitSeq>> {
        let batch = self.lock_writeback_batches().remove(&key);
        let Some(batch) = batch else {
            return Ok(None);
        };
        let mut scope_guard = Self::lock_writeback_scope(&batch);
        let Some(scope) = scope_guard.take() else {
            return Ok(None);
        };
        drop(scope_guard);
        self.commit_deferred_write_scope(cx, scope).map(Some)
    }

    fn commit_all_writeback_batches(&self, cx: &Cx) -> ffs_error::Result<usize> {
        let batches: Vec<_> = {
            let mut table = self.lock_writeback_batches();
            let batches = table.values().cloned().collect();
            table.clear();
            batches
        };
        let mut committed = 0;
        for batch in batches {
            let mut scope_guard = Self::lock_writeback_scope(&batch);
            let Some(scope) = scope_guard.take() else {
                continue;
            };
            drop(scope_guard);
            self.commit_deferred_write_scope(cx, scope)?;
            committed += 1;
        }
        Ok(committed)
    }

    fn dispatch_opendir(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<(u64, u32)> {
        self.with_request_scope(cx, RequestOp::Opendir, |cx, scope| {
            let attr = self.inner.ops.getattr(cx, scope, ino)?;
            Self::validate_opendir_attr(&attr)?;
            Ok((0, 0))
        })
    }

    fn validate_opendir_attr(attr: &InodeAttr) -> ffs_error::Result<()> {
        if attr.kind == FfsFileType::Directory {
            Ok(())
        } else {
            Err(FfsError::NotDirectory)
        }
    }

    fn enforce_mutation_guards(
        &self,
        cx: &Cx,
        op: RequestOp,
        ino_for_logging: u64,
    ) -> Result<(), MutationDispatchError> {
        if self.inner.read_only {
            return Err(MutationDispatchError::Errno(libc::EROFS));
        }
        if let Some(errno) = self.backpressure_errno(cx, op) {
            warn!(
                ino = ino_for_logging,
                ?op,
                "backpressure: shedding mutation request"
            );
            return Err(MutationDispatchError::Errno(errno));
        }
        Ok(())
    }

    fn dispatch_mkdir(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttr, MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Mkdir, parent)?;
        {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
            self.with_request_scope(&cx, RequestOp::Mkdir, |cx, scope| {
                let attr =
                    self.inner
                        .ops
                        .mkdir(cx, scope, InodeNumber(parent), name, mode, uid, gid)?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(attr)
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })
    }

    fn dispatch_rmdir(&self, parent: u64, name: &OsStr) -> Result<(), MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Rmdir, parent)?;
        let result = {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
            self.with_request_scope(&cx, RequestOp::Rmdir, |cx, scope| {
                self.inner.ops.rmdir(cx, scope, InodeNumber(parent), name)?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(())
            })
        };
        result.map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })?;
        self.notify_entry_invalidation(parent, name);
        Ok(())
    }

    fn dispatch_unlink(&self, parent: u64, name: &OsStr) -> Result<(), MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Unlink, parent)?;
        let result = {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
            self.with_request_scope(&cx, RequestOp::Unlink, |cx, scope| {
                self.inner
                    .ops
                    .unlink(cx, scope, InodeNumber(parent), name)?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(())
            })
        };
        result.map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })?;
        self.notify_entry_invalidation(parent, name);
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn dispatch_mknod(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttr, MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Create, parent)?;

        let s_ifmt = mode & libc::S_IFMT;
        // Regular files keep the legacy `create` fast path so we avoid
        // mode-bit churn for the common case. Char/block devices,
        // FIFOs, and Unix-domain sockets route through ops.mknod which
        // sets up the device-type inode shape (no extents, rdev in
        // i_block for char/block). overlayfs whiteouts land here as
        // S_IFCHR + rdev = makedev(0,0) = 0.
        if rdev == 0 && s_ifmt == libc::S_IFREG {
            return {
                let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
                self.with_request_scope(&cx, RequestOp::Create, |cx, scope| {
                    let attr = self.inner.ops.create(
                        cx,
                        scope,
                        InodeNumber(parent),
                        name,
                        (mode & 0o7777) as u16,
                        uid,
                        gid,
                    )?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(attr)
                })
            }
            .map_err(|error| MutationDispatchError::Operation {
                error,
                offset: None,
            });
        }
        let supported_type = matches!(
            s_ifmt,
            libc::S_IFCHR | libc::S_IFBLK | libc::S_IFIFO | libc::S_IFSOCK
        );
        if !supported_type {
            return Err(MutationDispatchError::Errno(libc::EOPNOTSUPP));
        }

        // Build the full ext4-flavoured 16-bit mode (file-type bits +
        // permission bits). Truncation is bounded by S_IFMT being
        // the high 4 bits of mode and 0o7777 capping the lower 12.
        let full_mode = u16::try_from(s_ifmt | (mode & 0o7777))
            .map_err(|_| MutationDispatchError::Errno(libc::EINVAL))?;

        {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
            self.with_request_scope(&cx, RequestOp::Create, |cx, scope| {
                let attr = self.inner.ops.mknod(
                    cx,
                    scope,
                    InodeNumber(parent),
                    name,
                    full_mode,
                    rdev,
                    uid,
                    gid,
                )?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(attr)
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })
    }

    fn dispatch_rename(
        &self,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
    ) -> Result<(), MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Rename, parent)?;
        let result = {
            let _inode_guards =
                self.acquire_mutation_inode_guards(&[InodeNumber(parent), InodeNumber(newparent)]);
            self.with_request_scope(&cx, RequestOp::Rename, |cx, scope| {
                self.inner.ops.rename2(
                    cx,
                    scope,
                    InodeNumber(parent),
                    name,
                    InodeNumber(newparent),
                    newname,
                    flags,
                )?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(())
            })
        };
        result.map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })?;
        Ok(())
    }

    fn dispatch_write(
        &self,
        ino: u64,
        offset: i64,
        data: &[u8],
    ) -> Result<u32, MutationDispatchError> {
        self.dispatch_write_with_intent(ino, offset, data, WriteIntent::default())
    }

    fn dispatch_write_with_intent(
        &self,
        ino: u64,
        offset: i64,
        data: &[u8],
        intent: WriteIntent,
    ) -> Result<u32, MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Write, ino)?;
        if let Some(errno) = intent.unsupported_errno() {
            return Err(MutationDispatchError::Errno(errno));
        }
        let byte_offset =
            u64::try_from(offset).map_err(|_| MutationDispatchError::Errno(libc::EINVAL))?;
        if !self.inner.writeback_cache || intent.nowait() {
            return self.dispatch_write_per_request(&cx, ino, byte_offset, data, intent);
        }
        if intent.sync_mode().is_some() {
            let key = WritebackKey::new(InodeNumber(ino), intent.fh);
            self.commit_writeback_batch_for_key(&cx, key)
                .map_err(|error| MutationDispatchError::Operation {
                    error,
                    offset: Some(byte_offset),
                })?;
            return self.dispatch_write_per_request(&cx, ino, byte_offset, data, intent);
        }
        self.dispatch_write_batched(&cx, ino, byte_offset, data, intent)
    }

    fn dispatch_write_per_request(
        &self,
        cx: &Cx,
        ino: u64,
        byte_offset: u64,
        data: &[u8],
        intent: WriteIntent,
    ) -> Result<u32, MutationDispatchError> {
        let mut operation_offset = byte_offset;
        let (written, _commit_seq) = {
            let _inode_guards = if intent.nowait() {
                self.try_acquire_mutation_inode_guards(&[InodeNumber(ino)])
                    .ok_or(MutationDispatchError::Errno(libc::EAGAIN))?
            } else {
                self.acquire_mutation_inode_guards(&[InodeNumber(ino)])
            };
            self.with_request_scope(cx, RequestOp::Write, |cx, scope| {
                let write_offset = if intent.append_to_eof() {
                    self.inner.ops.getattr(cx, scope, InodeNumber(ino))?.size
                } else {
                    byte_offset
                };
                operation_offset = write_offset;
                let bytes =
                    self.inner
                        .ops
                        .write(cx, scope, InodeNumber(ino), write_offset, data)?;
                let seq = self.inner.ops.commit_request_scope(scope)?;
                self.inner.readahead.invalidate_inode(InodeNumber(ino));
                if let Some(sync_mode) = intent.sync_mode() {
                    self.inner.ops.fsync(
                        cx,
                        scope,
                        InodeNumber(ino),
                        intent.fh,
                        sync_mode.datasync(),
                    )?;
                }
                Ok((bytes, seq))
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: Some(operation_offset),
        })?;
        // Update writeback barrier if enabled.
        Ok(written)
    }

    fn dispatch_write_batched(
        &self,
        cx: &Cx,
        ino: u64,
        byte_offset: u64,
        data: &[u8],
        intent: WriteIntent,
    ) -> Result<u32, MutationDispatchError> {
        let key = WritebackKey::new(InodeNumber(ino), intent.fh);
        let mut operation_offset = byte_offset;
        let write_result: ffs_error::Result<u32> = (|| {
            loop {
                let batch = self.get_or_begin_writeback_batch(cx, key)?;
                let inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(ino)]);
                let mut scope_guard = Self::lock_writeback_scope(&batch);
                let Some(scope) = scope_guard.as_mut() else {
                    drop(scope_guard);
                    drop(inode_guards);
                    self.remove_writeback_batch_if_same(key, &batch);
                    continue;
                };
                let write_offset = if intent.append_to_eof() {
                    self.inner.ops.getattr(cx, scope, InodeNumber(ino))?.size
                } else {
                    byte_offset
                };
                operation_offset = write_offset;
                let bytes =
                    self.inner
                        .ops
                        .write(cx, scope, InodeNumber(ino), write_offset, data)?;
                self.inner.readahead.invalidate_inode(InodeNumber(ino));
                if scope.pending_write_count() < MAX_WRITEBACK_BATCH_PENDING_WRITES {
                    return Ok(bytes);
                }
                let scope = scope_guard.take().expect("scope present after as_mut");
                drop(scope_guard);
                drop(inode_guards);
                self.remove_writeback_batch_if_same(key, &batch);
                self.commit_deferred_write_scope(cx, scope)?;
                return Ok(bytes);
            }
        })();
        let written = write_result.map_err(|error| MutationDispatchError::Operation {
            error,
            offset: Some(operation_offset),
        })?;
        Ok(written)
    }

    fn kernel_open_flags(request_flags: i32, backend_open_flags: u32) -> u32 {
        let direct_io_requested = request_flags & libc::O_DIRECT != 0;
        let direct_io_forced = backend_open_flags & fuse_consts::FOPEN_DIRECT_IO != 0;
        if direct_io_requested || direct_io_forced {
            backend_open_flags
        } else {
            backend_open_flags | fuse_consts::FOPEN_KEEP_CACHE
        }
    }

    fn dispatch_copy_file_range(
        &self,
        ino_in: u64,
        offset_in: i64,
        ino_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
    ) -> Result<u32, MutationDispatchError> {
        if flags != 0 {
            return Err(MutationDispatchError::Errno(libc::EINVAL));
        }
        let src_offset =
            u64::try_from(offset_in).map_err(|_| MutationDispatchError::Errno(libc::EINVAL))?;
        let dst_offset =
            u64::try_from(offset_out).map_err(|_| MutationDispatchError::Errno(libc::EINVAL))?;
        if len == 0 {
            return Ok(0);
        }
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Write, ino_out)?;
        let copy_len = len.min(u64::from(u32::MAX));
        let copied = {
            let _inode_guards =
                self.acquire_mutation_inode_guards(&[InodeNumber(ino_in), InodeNumber(ino_out)]);
            self.with_request_scope(&cx, RequestOp::Write, |cx, scope| {
                let copied = self.inner.ops.copy_file_range(
                    cx,
                    scope,
                    InodeNumber(ino_in),
                    src_offset,
                    InodeNumber(ino_out),
                    dst_offset,
                    copy_len,
                )?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(copied)
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: Some(dst_offset),
        })?;
        if copied > 0 {
            self.inner.readahead.invalidate_inode(InodeNumber(ino_out));
        }
        Ok(u32::try_from(copied).unwrap_or(u32::MAX))
    }

    fn dispatch_setxattr(
        &self,
        cx: &Cx,
        ino: u64,
        name: &str,
        value: &[u8],
        flags: i32,
        position: u32,
    ) -> Result<XattrSetMode, MutationDispatchError> {
        self.enforce_mutation_guards(cx, RequestOp::Setxattr, ino)?;
        let mode =
            Self::parse_setxattr_mode(flags, position).map_err(MutationDispatchError::Errno)?;
        {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(ino)]);
            self.with_request_scope(cx, RequestOp::Setxattr, |cx, scope| {
                self.inner
                    .ops
                    .setxattr(cx, scope, InodeNumber(ino), name, value, mode)?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(())
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })?;
        Ok(mode)
    }

    fn read_with_readahead(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        fh: u64,
        byte_offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        let requested_len = usize::try_from(size).unwrap_or(usize::MAX);
        if self.inner.writeback_cache {
            let key = WritebackKey::new(ino, fh);
            if let Some(batch) = self.writeback_batch(key) {
                let mut scope_guard = Self::lock_writeback_scope(&batch);
                if let Some(scope) = scope_guard.as_mut() {
                    let mut data = self.inner.ops.read(cx, scope, ino, byte_offset, size)?;
                    data.truncate(requested_len);
                    self.inner.access_predictor.record_read(
                        ino,
                        byte_offset,
                        u32::try_from(data.len()).unwrap_or(u32::MAX),
                    );
                    return Ok(data);
                }
            }
        }
        self.with_request_scope(cx, RequestOp::Read, |cx, scope| {
            let mut served = self
                .inner
                .readahead
                .take(ino, byte_offset, requested_len)
                .map_or_else(Vec::new, |prefetched| {
                    trace!(
                        target: "ffs::fuse::io",
                        event = "readahead_hit",
                        ino = ino.0,
                        offset = byte_offset,
                        bytes = prefetched.len()
                    );
                    prefetched
                });

            if served.len() < requested_len {
                let remaining_req =
                    size.saturating_sub(u32::try_from(served.len()).unwrap_or(u32::MAX));
                let next_offset =
                    byte_offset.saturating_add(u64::try_from(served.len()).unwrap_or(u64::MAX));
                let fetch_size =
                    self.inner
                        .access_predictor
                        .fetch_size(ino, next_offset, remaining_req);

                let mut fetched = self
                    .inner
                    .ops
                    .read(cx, scope, ino, next_offset, fetch_size)?;
                let fetched_served_len = (requested_len - served.len()).min(fetched.len());
                let tail = fetched.split_off(fetched_served_len);

                // With no cached prefix and no prefetch tail, the backend's
                // allocation is exactly the reply: move it instead of making
                // `Vec::append` allocate and copy the whole requested range.
                // Keep append for partial-cache hits and coalesced reads; moving
                // only the head of a larger prefetch buffer retains excess
                // capacity and measured worse (bd-kdmu4).
                if served.is_empty() && tail.is_empty() {
                    served = fetched;
                } else {
                    served.append(&mut fetched);
                }

                if !tail.is_empty() {
                    let consumed = u64::try_from(fetched_served_len).unwrap_or(u64::MAX);
                    let prefetch_offset = next_offset.saturating_add(consumed);
                    let prefetch_bytes = tail.len();
                    self.inner.readahead.insert(ino, prefetch_offset, tail);
                    debug!(
                        target: "ffs::fuse::io",
                        event = "readahead_queued",
                        ino = ino.0,
                        offset = prefetch_offset,
                        bytes = prefetch_bytes
                    );
                }
            }

            self.inner.access_predictor.record_read(
                ino,
                byte_offset,
                u32::try_from(served.len()).unwrap_or(u32::MAX),
            );

            Ok(served)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IoctlResult {
    Data(Vec<u8>),
    Error(c_int),
}

/// Check POSIX access permissions for a file.
///
/// Returns `true` if the user has all requested permissions.
/// Root (uid=0) always has access.
///
/// # Arguments
/// * `perm` - File permission bits (e.g., 0o755)
/// * `file_uid` - Owner UID of the file
/// * `file_gid` - Owner GID of the file
/// * `req_uid` - UID of the requesting user
/// * `req_gid` - Primary GID of the requesting user
/// * `mask` - Access mask (R_OK | W_OK | X_OK)
#[must_use]
#[expect(clippy::similar_names)]
fn check_access_permission(
    perm: u16,
    file_uid: u32,
    file_gid: u32,
    req_uid: u32,
    req_gid: u32,
    mask: i32,
) -> bool {
    // Root always has access
    if req_uid == 0 {
        return true;
    }

    let perm = u32::from(perm);
    let is_owner = req_uid == file_uid;
    let is_group = req_gid == file_gid;

    let mut allowed = true;

    if mask & libc::R_OK != 0 {
        let can_read = if is_owner {
            perm & 0o400 != 0
        } else if is_group {
            perm & 0o040 != 0
        } else {
            perm & 0o004 != 0
        };
        allowed = allowed && can_read;
    }

    if mask & libc::W_OK != 0 {
        let can_write = if is_owner {
            perm & 0o200 != 0
        } else if is_group {
            perm & 0o020 != 0
        } else {
            perm & 0o002 != 0
        };
        allowed = allowed && can_write;
    }

    if mask & libc::X_OK != 0 {
        let can_exec = if is_owner {
            perm & 0o100 != 0
        } else if is_group {
            perm & 0o010 != 0
        } else {
            perm & 0o001 != 0
        };
        allowed = allowed && can_exec;
    }

    allowed
}

impl Filesystem for FrankenFuse {
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), c_int> {
        let splice_caps = fuse_consts::FUSE_SPLICE_READ
            | fuse_consts::FUSE_SPLICE_WRITE
            | fuse_consts::FUSE_SPLICE_MOVE;
        match config.add_capabilities(splice_caps) {
            Ok(()) => debug!("FUSE splice read/write/move capabilities enabled"),
            Err(missing) => debug!(
                missing,
                "kernel declined one or more FUSE splice capabilities"
            ),
        }

        match config.set_max_stack_depth(1) {
            Ok(_) => match config.add_capabilities(fuse_consts::FUSE_PASSTHROUGH) {
                Ok(()) => debug!("FUSE passthrough capability enabled"),
                Err(missing) => debug!(missing, "kernel declined FUSE passthrough capability"),
            },
            Err(max_supported) => debug!(
                max_supported,
                "kernel declined FUSE passthrough stack depth"
            ),
        }

        Ok(())
    }

    fn destroy(&mut self) {
        let cx = Self::cx_for_request();
        match self.commit_all_writeback_batches(&cx) {
            Ok(committed) if committed > 0 => {
                debug!(
                    committed,
                    "committed deferred writeback batches during destroy"
                );
            }
            Ok(_) => {}
            Err(e) => warn!("writeback batch commit failed during FUSE destroy: {e}"),
        }
        if let Err(e) = self.inner.ops.flush_on_destroy(&cx) {
            warn!("flush_on_destroy failed during FUSE destroy: {e}");
        }
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, _nlookup: u64) {
        let inode = InodeNumber(ino);
        self.inner.readahead.invalidate_inode(inode);
        self.inner.access_predictor.invalidate_inode(inode);
    }

    fn batch_forget(&mut self, _req: &Request<'_>, nodes: &[fuse_forget_one]) {
        for node in nodes {
            let inode = InodeNumber(node.nodeid);
            self.inner.readahead.invalidate_inode(inode);
            self.inner.access_predictor.invalidate_inode(inode);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Getattr, |cx, scope| {
            self.inner.ops.getattr(cx, scope, InodeNumber(ino))
        }) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_file_attr(&attr)),
            Err(e) => {
                Self::reply_error_attr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "getattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn access(&mut self, req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        // F_OK (existence check) always succeeds if we can get attributes
        // R_OK/W_OK/X_OK check read/write/execute permissions
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Getattr, |cx, scope| {
            self.inner.ops.getattr(cx, scope, InodeNumber(ino))
        }) {
            Ok(attr) => {
                if check_access_permission(
                    attr.perm,
                    attr.uid,
                    attr.gid,
                    req.uid(),
                    req.gid(),
                    mask,
                ) {
                    reply.ok();
                } else {
                    reply.error(libc::EACCES);
                }
            }
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn statx(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: Option<u64>,
        _flags: u32,
        _mask: u32,
        reply: ReplyStatx,
    ) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Getattr, |cx, scope| {
            self.inner.ops.getattr(cx, scope, InodeNumber(ino))
        }) {
            Ok(attr) => reply.statx(&ATTR_TTL, &to_file_attr(&attr)),
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "statx",
                    ino,
                    offset: None,
                };
                reply.error(ctx.log_and_errno());
            }
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyStatfs) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Statfs, |cx, scope| {
            self.inner.ops.statfs(cx, scope, InodeNumber(ino))
        }) {
            Ok(stats) => reply.statfs(
                stats.blocks,
                stats.blocks_free,
                stats.blocks_available,
                stats.files,
                stats.files_free,
                stats.block_size,
                stats.name_max,
                stats.fragment_size,
            ),
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "statfs",
                    ino,
                    offset: None,
                };
                reply.error(ctx.log_and_errno());
            }
        }
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Lookup, |cx, scope| {
            self.inner.ops.lookup(cx, scope, InodeNumber(parent), name)
        }) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), attr.generation),
            Err(e) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &e,
                        operation: "lookup",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Open, |cx, scope| {
            self.inner.ops.open(cx, scope, InodeNumber(ino), flags)
        }) {
            Ok((fh, open_flags)) => reply.opened(fh, Self::kernel_open_flags(flags, open_flags)),
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "open",
                    ino,
                    offset: None,
                };
                reply.error(ctx.log_and_errno());
            }
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let cx = Self::cx_for_request();
        match self.dispatch_opendir(&cx, InodeNumber(ino)) {
            Ok((fh, open_flags)) => reply.opened(fh, open_flags),
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "opendir",
                    ino,
                    offset: None,
                };
                reply.error(ctx.log_and_errno());
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Ok(byte_offset) = u64::try_from(offset) else {
            warn!(ino, offset, "read: negative offset");
            reply.error(libc::EINVAL);
            return;
        };
        // Dispatch the read onto the offload pool so this single session loop
        // can immediately fetch the next kernel request. Every structure the
        // handler touches lives behind `Arc<FuseInner>` (`read_with_readahead`
        // takes `&self`), the fuser reply owns a `Send` channel sender built
        // for exactly this cross-thread reply pattern, and FUSE imposes no
        // reply-ordering requirement across concurrent requests. Bytes,
        // errors, and metrics are identical to the inline path — only the
        // thread that executes them changes.
        if let Some(pool) = &self.inner.read_offload {
            let handle = self.shared_handle();
            pool.spawn(move || handle.serve_read_request(ino, fh, byte_offset, size, reply));
        } else {
            self.serve_read_request(ino, fh, byte_offset, size, reply);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let cx = Self::cx_for_request();
        let Ok(fs_offset) = u64::try_from(offset) else {
            warn!(ino, offset, "readdir: negative offset");
            reply.error(libc::EINVAL);
            return;
        };
        match self.with_request_scope(&cx, RequestOp::Readdir, |cx, scope| {
            self.inner
                .ops
                .readdir(cx, scope, InodeNumber(ino), fs_offset)
        }) {
            Ok(entries) => {
                for entry in &entries {
                    #[cfg(unix)]
                    let name = OsStr::from_bytes(&entry.name);
                    #[cfg(not(unix))]
                    let owned_name = entry.name_str();
                    #[cfg(not(unix))]
                    let name = OsStr::new(&owned_name);

                    let full = reply.add(
                        entry.ino.0,
                        i64::try_from(entry.offset).unwrap_or(i64::MAX),
                        to_fuser_file_type(entry.kind),
                        name,
                    );
                    if full {
                        break;
                    }
                }
                reply.ok();
            }
            Err(e) => {
                Self::reply_error_dir(
                    &FuseErrorContext {
                        error: &e,
                        operation: "readdir",
                        ino,
                        offset: Some(fs_offset),
                    },
                    reply,
                );
            }
        }
    }

    fn readdirplus(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let cx = Self::cx_for_request();
        let Ok(fs_offset) = u64::try_from(offset) else {
            warn!(ino, offset, "readdirplus: negative offset");
            reply.error(libc::EINVAL);
            return;
        };
        match self.with_request_scope(&cx, RequestOp::Readdir, |cx, scope| {
            // readdirplus getattrs every returned entry itself (below), so the
            // readdir-internal inode-table prefetch fan-out is a redundant SECOND
            // parallel pass over the same blocks the getattr fan-out reads. Skip
            // it here (plain `readdir` leaves it on for readdir-then-stat walks).
            scope.skip_readdir_prefetch = true;
            self.inner
                .ops
                .readdir(cx, scope, InodeNumber(ino), fs_offset)
        }) {
            Ok(entries) => {
                // bd-xmh5g.399: fetch entries' attributes in PARALLEL so a cold
                // `ls -l` does not pay a serial inode-table-block read per entry;
                // then add them to the reply in original order. I/O-overlap: the
                // blocking inode reads park their cores and overlap across the
                // rayon pool. Conformance-neutral — identical entries, attributes,
                // and ordering; getattr is already concurrency-safe (the FUSE
                // dispatcher calls it from multiple worker threads), Cx is Sync, and
                // with_request_scope takes &self.
                //
                // The `ops.readdir` page is capped at 512 entries, but the client
                // reply buffer fills (`reply.add` -> `full`) after only ~150-200,
                // so a single 512-wide fan-out computed ~300 getattrs whose results
                // are discarded — and because successive readdirplus cookies advance
                // by only the entries that fit, a full `ls -l` re-fetched that
                // discarded window on every page (~512·N/F getattrs vs the ideal N).
                // Fan out in BOUNDED BATCHES in entry order and stop the moment the
                // reply buffer is full: identical entries/attrs/order, but wasted
                // getattrs are bounded to < one batch instead of 512−F.
                use rayon::prelude::*;
                // Batch wide enough to saturate the rayon pool for I/O-overlap,
                // small enough that overshoot past a full buffer stays tiny.
                const READDIRPLUS_GETATTR_BATCH: usize = 128;

                let this: &Self = &*self;
                let cx_ref = &cx;
                let mut buffer_full = false;
                for batch in entries.chunks(READDIRPLUS_GETATTR_BATCH) {
                    let attrs: Vec<Option<FileAttr>> = batch
                        .par_iter()
                        .map(|entry| {
                            this.with_request_scope(cx_ref, RequestOp::Getattr, |cx, scope| {
                                this.inner.ops.getattr(cx, scope, entry.ino)
                            })
                            .ok()
                            .map(|attr| to_file_attr(&attr))
                        })
                        .collect();

                    for (entry, attr) in batch.iter().zip(attrs) {
                        // If we couldn't get attrs, skip this entry (same as before).
                        let Some(attr) = attr else {
                            continue;
                        };
                        #[cfg(unix)]
                        let name = OsStr::from_bytes(&entry.name);
                        #[cfg(not(unix))]
                        let owned_name = entry.name_str();
                        #[cfg(not(unix))]
                        let name = OsStr::new(&owned_name);

                        let full = reply.add(
                            entry.ino.0,
                            i64::try_from(entry.offset).unwrap_or(i64::MAX),
                            name,
                            &ATTR_TTL,
                            &attr,
                            0, // generation - not tracked
                        );
                        if full {
                            buffer_full = true;
                            break;
                        }
                    }
                    if buffer_full {
                        break;
                    }
                }
                reply.ok();
            }
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "readdirplus",
                    ino,
                    offset: Some(fs_offset),
                };
                reply.error(ctx.log_and_errno());
            }
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Readlink, |cx, scope| {
            self.inner.ops.readlink(cx, scope, InodeNumber(ino))
        }) {
            Ok(target) => reply.data(&target),
            Err(e) => {
                Self::reply_error_data(
                    &FuseErrorContext {
                        error: &e,
                        operation: "readlink",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Symlink) {
            warn!(parent, "backpressure: shedding symlink");
            reply.error(errno);
            return;
        }
        match self.with_request_scope(&cx, RequestOp::Symlink, |cx, scope| {
            let attr = self.inner.ops.symlink(
                cx,
                scope,
                InodeNumber(parent),
                name,
                link,
                req.uid(),
                req.gid(),
            )?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        }) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), attr.generation),
            Err(e) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &e,
                        operation: "symlink",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Getxattr, |cx, _scope| {
            self.inner.ops.getxattr(cx, InodeNumber(ino), name)
        }) {
            Ok(Some(value)) => Self::reply_xattr_payload(size, &value, reply),
            Ok(None) => reply.error(Self::missing_xattr_errno()),
            Err(e) => {
                Self::reply_error_xattr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "getxattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn setxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Setxattr) {
            warn!(ino, "backpressure: shedding setxattr");
            reply.error(errno);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        match self.dispatch_setxattr(&cx, ino, name, value, flags, position) {
            Ok(_) => reply.ok(),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error: e, .. }) => {
                let mode = match Self::parse_setxattr_mode(flags, position) {
                    Ok(mode) => mode,
                    Err(errno) => {
                        reply.error(errno);
                        return;
                    }
                };
                if matches!(mode, XattrSetMode::Replace)
                    && matches!(e, FfsError::NotFound(_))
                    && self
                        .inner
                        .ops
                        .getattr(&cx, &mut RequestScope::empty(), InodeNumber(ino))
                        .is_ok()
                {
                    reply.error(Self::missing_xattr_errno());
                    return;
                }
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "setxattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn removexattr(&mut self, _req: &Request<'_>, ino: u64, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Removexattr) {
            warn!(ino, "backpressure: shedding removexattr");
            reply.error(errno);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };

        match self.with_request_scope(&cx, RequestOp::Removexattr, |cx, scope| {
            let removed = self
                .inner
                .ops
                .removexattr(cx, scope, InodeNumber(ino), name)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(removed)
        }) {
            Ok(true) => reply.ok(),
            Ok(false) => reply.error(Self::missing_xattr_errno()),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "removexattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Listxattr, |cx, _scope| {
            self.inner.ops.listxattr(cx, InodeNumber(ino))
        }) {
            Ok(names) => {
                if size == 0 {
                    match u32::try_from(Self::xattr_names_encoded_len(&names)) {
                        Ok(payload_len) => reply.size(payload_len),
                        Err(_) => reply.error(libc::EOVERFLOW),
                    }
                    return;
                }
                let payload = Self::encode_xattr_names(&names);
                Self::reply_xattr_payload(size, &payload, reply);
            }
            Err(e) => {
                Self::reply_error_xattr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "listxattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    // ── Write operations ─────────────────────────────────────────────────

    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Setattr) {
            warn!(ino, "backpressure: shedding setattr");
            reply.error(errno);
            return;
        }
        let resolve_time = |t: TimeOrNow| -> SystemTime {
            match t {
                TimeOrNow::SpecificTime(st) => st,
                TimeOrNow::Now => SystemTime::now(),
            }
        };
        let attrs = SetAttrRequest {
            #[allow(clippy::cast_possible_truncation)]
            mode: mode.map(|m| m as u16), // FUSE mode is u32, ext4 mode is u16
            uid,
            gid,
            size,
            atime: atime.map(resolve_time),
            mtime: mtime.map(resolve_time),
        };
        match self.dispatch_setattr(&cx, ino, &attrs, req.uid()) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_file_attr(&attr)),
            Err(e) => {
                Self::reply_error_attr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "setattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)] // FUSE mode u32 → ext4 u16
    fn mknod(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        match self.dispatch_mknod(parent, name, mode, rdev, req.uid(), req.gid()) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), attr.generation),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &error,
                        operation: "mknod",
                        ino: parent,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)] // FUSE mode u32 → ext4 u16
    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        match self.dispatch_mkdir(parent, name, mode as u16, req.uid(), req.gid()) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), attr.generation),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &error,
                        operation: "mkdir",
                        ino: parent,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Unlink) {
            warn!(parent, "backpressure: shedding unlink");
            reply.error(errno);
            return;
        }
        match self.with_request_scope(&cx, RequestOp::Unlink, |cx, scope| {
            self.inner
                .ops
                .unlink(cx, scope, InodeNumber(parent), name)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "unlink",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.dispatch_rmdir(parent, name) {
            Ok(()) => reply.ok(),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &error,
                        operation: "rmdir",
                        ino: parent,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        // RENAME_NOREPLACE and RENAME_EXCHANGE are honoured atomically
        // (see OpenFs::rename2). RENAME_WHITEOUT still returns EINVAL inside
        // FsOps::rename2; we no longer pre-reject every non-zero flag.
        match self.dispatch_rename(parent, name, newparent, newname, flags) {
            Ok(()) => {
                reply.ok();
                self.notify_entry_invalidation(parent, name);
                self.notify_entry_invalidation(newparent, newname);
            }
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &error,
                        operation: "rename",
                        ino: parent,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    fn link(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Link) {
            warn!(ino, "backpressure: shedding link");
            reply.error(errno);
            return;
        }
        match self.with_request_scope(&cx, RequestOp::Link, |cx, scope| {
            let attr = self.inner.ops.link(
                cx,
                scope,
                InodeNumber(ino),
                InodeNumber(newparent),
                newname,
            )?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        }) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), attr.generation),
            Err(e) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &e,
                        operation: "link",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        trace!(
            ino,
            offset,
            len = data.len(),
            write_flags,
            flags,
            "FUSE write"
        );
        match self.dispatch_write_with_intent(
            ino,
            offset,
            data,
            WriteIntent::from_fuse(fh, write_flags, flags),
        ) {
            Ok(written) => reply.written(written),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_write(
                    &FuseErrorContext {
                        error: &error,
                        operation: "write",
                        ino,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    fn copy_file_range(
        &mut self,
        _req: &Request<'_>,
        ino_in: u64,
        _fh_in: u64,
        offset_in: i64,
        ino_out: u64,
        _fh_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
        reply: ReplyWrite,
    ) {
        trace!(
            ino_in,
            offset_in, ino_out, offset_out, len, flags, "FUSE copy_file_range"
        );
        match self.dispatch_copy_file_range(ino_in, offset_in, ino_out, offset_out, len, flags) {
            Ok(written) => reply.written(written),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_write(
                    &FuseErrorContext {
                        error: &error,
                        operation: "copy_file_range",
                        ino: ino_out,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    fn fallocate(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Fallocate) {
            warn!(ino, "backpressure: shedding fallocate");
            reply.error(errno);
            return;
        }

        let Ok(byte_offset) = u64::try_from(offset) else {
            reply.error(libc::EINVAL);
            return;
        };
        let Ok(byte_length) = u64::try_from(length) else {
            reply.error(libc::EINVAL);
            return;
        };
        match self.with_request_scope(&cx, RequestOp::Fallocate, |cx, scope| {
            self.inner.ops.fallocate(
                cx,
                scope,
                InodeNumber(ino),
                byte_offset,
                byte_length,
                mode,
            )?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "fallocate",
                        ino,
                        offset: Some(byte_offset),
                    },
                    reply,
                );
            }
        }
    }

    fn ioctl(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        _flags: u32,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: ReplyIoctl,
    ) {
        self.record_ioctl_probe(ino, cmd, in_data.len(), out_size);
        match self.dispatch_ioctl(req.pid(), ino, fh, cmd, in_data, out_size) {
            IoctlResult::Data(data) => reply.ioctl(0, &data),
            IoctlResult::Error(errno) => {
                if errno == libc::ENOTTY {
                    debug!(ino, cmd, "ioctl: unsupported command");
                }
                reply.error(errno);
            }
        }
    }

    fn lseek(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        // SEEK_SET/CUR/END are handled by the kernel; only SEEK_DATA/SEEK_HOLE
        // reach this handler.
        let Some(seek_whence) = SeekWhence::from_raw(whence) else {
            debug!(ino, whence, "lseek: unsupported whence");
            reply.error(libc::EINVAL);
            return;
        };

        // Convert offset to u64 (SEEK_DATA/SEEK_HOLE require non-negative offset).
        let Ok(offset_u64) = u64::try_from(offset) else {
            reply.error(libc::EINVAL);
            return;
        };

        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Lseek, |cx, scope| {
            self.inner
                .ops
                .lseek(cx, scope, InodeNumber(ino), offset_u64, seek_whence)
        }) {
            Ok(new_offset) => {
                // ReplyLseek::offset expects i64.
                match i64::try_from(new_offset) {
                    Ok(v) => reply.offset(v),
                    Err(_) => reply.error(libc::EOVERFLOW),
                }
            }
            Err(e) => {
                // For SEEK_DATA/SEEK_HOLE, Format errors with "ENXIO" message map to ENXIO.
                // This handles "offset >= file_size" and "no data/hole found" cases.
                let errno = if let FfsError::Format(msg) = &e {
                    if msg.contains("ENXIO") {
                        libc::ENXIO
                    } else {
                        e.to_errno()
                    }
                } else {
                    e.to_errno()
                };
                trace!(ino, offset, whence, errno, "lseek failed");
                reply.error(errno);
            }
        }
    }

    fn flush(&mut self, _req: &Request<'_>, ino: u64, fh: u64, lock_owner: u64, reply: ReplyEmpty) {
        let cx = Self::cx_for_request();
        let key = WritebackKey::new(InodeNumber(ino), fh);
        if let Err(e) = self.commit_writeback_batch_for_key(&cx, key) {
            Self::reply_error_empty(
                &FuseErrorContext {
                    error: &e,
                    operation: "flush",
                    ino,
                    offset: None,
                },
                reply,
            );
            return;
        }
        match self.with_request_scope(&cx, RequestOp::Flush, |cx, scope| {
            self.inner
                .ops
                .flush(cx, scope, InodeNumber(ino), fh, lock_owner)
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "flush",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
        reply: ReplyEmpty,
    ) {
        let cx = Self::cx_for_request();
        let key = WritebackKey::new(InodeNumber(ino), fh);
        if let Err(e) = self.commit_writeback_batch_for_key(&cx, key) {
            Self::reply_error_empty(
                &FuseErrorContext {
                    error: &e,
                    operation: "release",
                    ino,
                    offset: None,
                },
                reply,
            );
            return;
        }
        match self.with_request_scope(&cx, RequestOp::Release, |cx, scope| {
            self.inner.ops.release(
                cx,
                scope,
                ReleaseRequest {
                    ino: InodeNumber(ino),
                    fh,
                    flags,
                    lock_owner,
                    flush,
                },
            )
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "release",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn fsync(&mut self, _req: &Request<'_>, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Fsync) {
            warn!(ino, "backpressure: shedding fsync");
            reply.error(errno);
            return;
        }
        let key = WritebackKey::new(InodeNumber(ino), fh);
        if let Err(e) = self.commit_writeback_batch_for_key(&cx, key) {
            Self::reply_error_empty(
                &FuseErrorContext {
                    error: &e,
                    operation: "fsync",
                    ino,
                    offset: None,
                },
                reply,
            );
            return;
        }
        match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
            self.inner
                .ops
                .fsync(cx, scope, InodeNumber(ino), fh, datasync)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "fsync",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn fsyncdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Fsyncdir) {
            warn!(ino, "backpressure: shedding fsyncdir");
            reply.error(errno);
            return;
        }
        match self.with_request_scope(&cx, RequestOp::Fsyncdir, |cx, scope| {
            self.inner
                .ops
                .fsyncdir(cx, scope, InodeNumber(ino), fh, datasync)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "fsyncdir",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        // Directory handles are stateless in this adapter, so there is no
        // backend resource to release.
        reply.ok();
    }

    fn poll(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _ph: PollHandle,
        events: u32,
        _flags: u32,
        reply: ReplyPoll,
    ) {
        // Regular files are always ready for I/O. Return the requested events
        // as the ready events (POLLIN | POLLOUT typically).
        reply.poll(events);
    }

    fn getlk(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        // Return "no conflicting lock" - the kernel handles local locking anyway.
        // F_UNLCK = 2 indicates no lock conflict.
        reply.locked(0, 0, libc::F_UNLCK, 0);
    }

    fn setlk(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        _sleep: bool,
        reply: ReplyEmpty,
    ) {
        // Accept all lock requests - POSIX locks are advisory and the kernel
        // handles local locking. For a FUSE filesystem, implementing these
        // methods prevents ENOSYS errors from applications that probe locking.
        reply.ok();
    }

    #[allow(clippy::cast_possible_truncation)] // FUSE mode u32 → ext4 u16
    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Create) {
            warn!(parent, "backpressure: shedding create");
            reply.error(errno);
            return;
        }
        match self.with_request_scope(&cx, RequestOp::Create, |cx, scope| {
            let attr = self.inner.ops.create(
                cx,
                scope,
                InodeNumber(parent),
                name,
                mode as u16,
                req.uid(),
                req.gid(),
            )?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        }) {
            Ok(attr) => {
                reply.created(&ATTR_TTL, &to_file_attr(&attr), attr.generation, 0, 0);
            }
            Err(e) => {
                Self::reply_error_create(
                    &FuseErrorContext {
                        error: &e,
                        operation: "create",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }
}

// ── Mount entrypoint ────────────────────────────────────────────────────────

/// Build a list of `fuser::MountOption` from our `MountOptions`.
fn build_mount_options(options: &MountOptions) -> Vec<MountOption> {
    let mut opts = vec![
        MountOption::FSName("frankenfs".to_owned()),
        MountOption::Subtype("ffs".to_owned()),
        MountOption::DefaultPermissions,
        MountOption::NoAtime,
        MountOption::CUSTOM(format!("max_read={FUSE_MAX_READ_BYTES}")),
    ];

    if options.read_only {
        opts.push(MountOption::RO);
    }
    if options.allow_other {
        opts.push(MountOption::AllowOther);
    }
    if options.auto_unmount {
        opts.push(MountOption::AutoUnmount);
    }
    if options.writeback_cache.is_enabled() {
        opts.push(MountOption::CUSTOM("writeback_cache".to_owned()));
    }
    if options.worker_threads > 0 {
        let max_background = options.resolved_thread_count();
        let congestion_threshold = max_background.saturating_mul(3).saturating_div(4).max(1);
        opts.push(MountOption::CUSTOM(format!(
            "max_background={max_background}"
        )));
        opts.push(MountOption::CUSTOM(format!(
            "congestion_threshold={congestion_threshold}"
        )));
    }

    opts
}

fn validate_mount_options(options: &MountOptions) -> Result<(), FuseError> {
    if options.writeback_cache.is_enabled() && options.read_only {
        return Err(FfsError::UnsupportedFeature(
            "kernel FUSE writeback_cache requires an explicit read-write mount; flush is non-durable and fsync/fsyncdir are the durability boundaries"
                .to_owned(),
        )
        .into());
    }
    Ok(())
}

fn mount_option_label(option: &MountOption) -> String {
    match option {
        MountOption::FSName(value) => format!("fsname={value}"),
        MountOption::Subtype(value) => format!("subtype={value}"),
        MountOption::CUSTOM(value) => value.clone(),
        MountOption::AllowOther => "allow_other".to_owned(),
        MountOption::AllowRoot => "allow_root".to_owned(),
        MountOption::AutoUnmount => "auto_unmount".to_owned(),
        MountOption::DefaultPermissions => "default_permissions".to_owned(),
        MountOption::Dev => "dev".to_owned(),
        MountOption::NoDev => "nodev".to_owned(),
        MountOption::Suid => "suid".to_owned(),
        MountOption::NoSuid => "nosuid".to_owned(),
        MountOption::RO => "ro".to_owned(),
        MountOption::RW => "rw".to_owned(),
        MountOption::Exec => "exec".to_owned(),
        MountOption::NoExec => "noexec".to_owned(),
        MountOption::Atime => "atime".to_owned(),
        MountOption::NoAtime => "noatime".to_owned(),
        MountOption::DirSync => "dirsync".to_owned(),
        MountOption::Sync => "sync".to_owned(),
        MountOption::Async => "async".to_owned(),
    }
}

/// Return canonical mount-option labels without requiring a live mount.
#[doc(hidden)]
#[must_use]
pub fn mount_option_labels_for_fuzzing(options: &MountOptions) -> Vec<String> {
    build_mount_options(options)
        .iter()
        .map(mount_option_label)
        .collect()
}

fn validate_mountpoint(mountpoint: &Path) -> Result<(), FuseError> {
    if mountpoint.as_os_str().is_empty() {
        return Err(FuseError::InvalidMountpoint(
            "mountpoint cannot be empty".to_owned(),
        ));
    }
    if !mountpoint.exists() {
        return Err(FuseError::InvalidMountpoint(format!(
            "mountpoint does not exist: {}",
            mountpoint.display()
        )));
    }
    if !mountpoint.is_dir() {
        return Err(FuseError::InvalidMountpoint(format!(
            "mountpoint is not a directory: {}",
            mountpoint.display()
        )));
    }
    Ok(())
}

/// Mount a FrankenFS filesystem at the given mountpoint (blocking).
///
/// This function blocks until the filesystem is unmounted.
pub fn mount(
    ops: Box<dyn FsOps>,
    mountpoint: impl AsRef<Path>,
    options: &MountOptions,
) -> Result<(), FuseError> {
    validate_mount_options(options)?;
    let mountpoint = mountpoint.as_ref();
    validate_mountpoint(mountpoint)?;
    let fuse_opts = build_mount_options(options);
    let fs = FrankenFuse::with_inner(ops, options, Some(mountpoint), None);
    let mut session = fuser::Session::new(fs.shared_handle(), mountpoint, &fuse_opts)?;
    fs.install_kernel_notifier(session.notifier());
    session.run()?;
    Ok(())
}

/// Mount a FrankenFS filesystem in the background, returning a session handle.
///
/// The filesystem is unmounted when the returned `BackgroundSession` is dropped.
pub fn mount_background(
    ops: Box<dyn FsOps>,
    mountpoint: impl AsRef<Path>,
    options: &MountOptions,
) -> Result<fuser::BackgroundSession, FuseError> {
    validate_mount_options(options)?;
    let mountpoint = mountpoint.as_ref();
    validate_mountpoint(mountpoint)?;
    let fuse_opts = build_mount_options(options);
    let fs = FrankenFuse::with_inner(ops, options, Some(mountpoint), None);
    let notifier_owner = fs.shared_handle();
    let session = fuser::spawn_mount2(fs, mountpoint, &fuse_opts)?;
    notifier_owner.install_kernel_notifier(session.notifier());
    Ok(session)
}

// ── Mount lifecycle ─────────────────────────────────────────────────────────

/// Configuration for a managed mount with lifecycle control.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Base mount options (RO, allow_other, threads, etc.).
    pub options: MountOptions,
    /// Optional adaptive backpressure gate for managed mount runtimes.
    ///
    /// `None` preserves the default-off behavior: no request is throttled or
    /// shed by the FUSE layer.
    pub backpressure: Option<Arc<BackpressureGate>>,
    /// Grace period for in-flight requests during unmount.
    pub unmount_timeout: Duration,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            options: MountOptions::default(),
            backpressure: None,
            unmount_timeout: Duration::from_secs(30),
        }
    }
}

/// Handle for a live FUSE mount with lifecycle control.
///
/// Dropping the handle triggers a clean unmount.  Call [`Self::wait`] to block
/// until external shutdown (Ctrl+C / programmatic `shutdown()`).
///
/// # Signal Handling
///
/// `MountHandle` exposes a shared `shutdown` flag (`Arc<AtomicBool>`).
/// The CLI (or any owner) should wire SIGTERM / SIGINT handlers that set
/// this flag.  [`Self::wait`] polls the flag and triggers unmount when set.
/// The `AutoUnmount` fuser option provides a safety net: the kernel
/// unmounts the filesystem if the process exits without a clean unmount.
pub struct MountHandle {
    session: Option<fuser::BackgroundSession>,
    mountpoint: PathBuf,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    metrics: Arc<AtomicMetrics>,
    config: MountConfig,
}

impl MountHandle {
    /// The mountpoint path.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Shared shutdown flag.
    ///
    /// Set this to `true` (from a signal handler or another thread) to
    /// trigger a graceful unmount.
    #[must_use]
    pub fn shutdown_flag(&self) -> &Arc<std::sync::atomic::AtomicBool> {
        &self.shutdown
    }

    /// Get a snapshot of the mount metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Block until the shutdown flag is set, then unmount cleanly.
    ///
    /// Returns the final metrics snapshot.
    #[must_use]
    pub fn wait(mut self) -> MetricsSnapshot {
        info!(mountpoint = %self.mountpoint.display(), "waiting for shutdown signal");
        loop {
            if self.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                info!(
                    mountpoint = %self.mountpoint.display(),
                    "shutdown signal received"
                );
                break;
            }
            if let Some(session) = self.session.as_ref() {
                if session.guard.is_finished() {
                    warn!(
                        mountpoint = %self.mountpoint.display(),
                        "fuse background session ended without explicit shutdown"
                    );
                    break;
                }
            }
            std::thread::sleep(MOUNT_HANDLE_WAIT_POLL_INTERVAL);
        }
        self.do_unmount()
    }

    /// Trigger a graceful unmount.
    ///
    /// Returns the final metrics snapshot.
    #[must_use]
    pub fn unmount(mut self) -> MetricsSnapshot {
        self.do_unmount()
    }

    fn do_unmount(&mut self) -> MetricsSnapshot {
        let snap = self.metrics.snapshot();
        if let Some(session) = self.session.take() {
            info!(
                mountpoint = %self.mountpoint.display(),
                requests_total = snap.requests_total,
                requests_ok = snap.requests_ok,
                requests_err = snap.requests_err,
                bytes_read = snap.bytes_read,
                requests_throttled = snap.requests_throttled,
                requests_shed = snap.requests_shed,
                "unmounting FUSE filesystem"
            );

            let timeout = self.config.unmount_timeout;
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                drop(session);
                let _ = tx.send(());
            });

            if rx.recv_timeout(timeout).is_err() {
                warn!("unmount timed out after {:?}", timeout);
            } else {
                info!(mountpoint = %self.mountpoint.display(), "unmount complete");
            }
        }
        snap
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        if self.session.is_some() {
            self.do_unmount();
        }
    }
}

impl std::fmt::Debug for MountHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountHandle")
            .field("mountpoint", &self.mountpoint)
            .field("active", &self.session.is_some())
            .field(
                "shutdown",
                &self.shutdown.load(std::sync::atomic::Ordering::Relaxed),
            )
            .field("metrics", &self.metrics.snapshot())
            .field("unmount_timeout", &self.config.unmount_timeout)
            .finish()
    }
}

/// Mount a FrankenFS filesystem with full lifecycle control.
///
/// Returns a [`MountHandle`] that can be used to wait for signals,
/// query metrics, and trigger a clean unmount.
///
/// # Example
/// ```no_run
/// # use ffs_fuse::{MountConfig, mount_managed};
/// # fn example(ops: Box<dyn ffs_core::FsOps>) {
/// let handle = mount_managed(ops, "/mnt/ffs", &MountConfig::default()).unwrap();
/// // Wire Ctrl+C to the shutdown flag (e.g. via ctrlc crate):
/// let flag = handle.shutdown_flag().clone();
/// // ... register signal handler that sets `flag.store(true, ...)` ...
/// let stats = handle.wait();
/// println!("served {} requests", stats.requests_total);
/// # }
/// ```
pub fn mount_managed(
    ops: Box<dyn FsOps>,
    mountpoint: impl AsRef<Path>,
    config: &MountConfig,
) -> Result<MountHandle, FuseError> {
    validate_mount_options(&config.options)?;
    let mountpoint = mountpoint.as_ref();
    validate_mountpoint(mountpoint)?;

    let thread_count = config.options.resolved_thread_count();
    info!(
        mountpoint = %mountpoint.display(),
        thread_count,
        read_only = config.options.read_only,
        adaptive_backpressure = config.backpressure.is_some(),
        unmount_timeout_secs = config.unmount_timeout.as_secs(),
        "mounting FrankenFS"
    );

    let fuse_opts = build_mount_options(&config.options);
    let fs = FrankenFuse::with_mount_config(ops, Some(mountpoint), config);
    let metrics_ref = Arc::clone(&fs.inner.metrics);
    let notifier_owner = fs.shared_handle();

    let session = fuser::spawn_mount2(fs, mountpoint, &fuse_opts)?;
    notifier_owner.install_kernel_notifier(session.notifier());

    info!(mountpoint = %mountpoint.display(), "FUSE mount active");

    Ok(MountHandle {
        session: Some(session),
        mountpoint: mountpoint.to_owned(),
        shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        metrics: metrics_ref,
        config: config.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_core::{
        DirEntry as FfsDirEntry, FIEMAP_EXTENT_LAST, FIEMAP_EXTENT_UNWRITTEN,
        ReaddirPage as FfsReaddirPage, RequestScope,
    };
    use ffs_types::CommitSeq;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Instant, SystemTime};

    /// Minimal FsOps test helper for tests that don't need real filesystem behavior.
    struct MinimalTestFs;
    impl FsOps for MinimalTestFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("test fs miss".into()))
        }
        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("test fs miss".into()))
        }
        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<FfsReaddirPage> {
            Ok(vec![].into())
        }
        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }
        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    fn existing_file_mountpoint() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
    }

    #[test]
    fn file_type_conversion_roundtrip() {
        let cases = [
            (FfsFileType::RegularFile, FileType::RegularFile),
            (FfsFileType::Directory, FileType::Directory),
            (FfsFileType::Symlink, FileType::Symlink),
            (FfsFileType::BlockDevice, FileType::BlockDevice),
            (FfsFileType::CharDevice, FileType::CharDevice),
            (FfsFileType::Fifo, FileType::NamedPipe),
            (FfsFileType::Socket, FileType::Socket),
        ];
        for (ffs_ft, expected_fuser_ft) in &cases {
            assert_eq!(to_fuser_file_type(*ffs_ft), *expected_fuser_ft);
        }
    }

    // ── Access permission tests ─────────────────────────────────────────────

    #[test]
    fn access_permission_root_always_allowed() {
        // Root (uid=0) bypasses all permission checks
        assert!(check_access_permission(0o000, 1000, 1000, 0, 0, libc::R_OK));
        assert!(check_access_permission(0o000, 1000, 1000, 0, 0, libc::W_OK));
        assert!(check_access_permission(0o000, 1000, 1000, 0, 0, libc::X_OK));
        assert!(check_access_permission(
            0o000,
            1000,
            1000,
            0,
            0,
            libc::R_OK | libc::W_OK | libc::X_OK
        ));
    }

    #[test]
    fn access_permission_owner_read() {
        // Owner can read with 0o400
        assert!(check_access_permission(
            0o400,
            1000,
            1000,
            1000,
            2000,
            libc::R_OK
        ));
        // Owner cannot read with 0o300
        assert!(!check_access_permission(
            0o300,
            1000,
            1000,
            1000,
            2000,
            libc::R_OK
        ));
    }

    #[test]
    fn access_permission_owner_write() {
        // Owner can write with 0o200
        assert!(check_access_permission(
            0o200,
            1000,
            1000,
            1000,
            2000,
            libc::W_OK
        ));
        // Owner cannot write with 0o500
        assert!(!check_access_permission(
            0o500,
            1000,
            1000,
            1000,
            2000,
            libc::W_OK
        ));
    }

    #[test]
    fn access_permission_owner_execute() {
        // Owner can execute with 0o100
        assert!(check_access_permission(
            0o100,
            1000,
            1000,
            1000,
            2000,
            libc::X_OK
        ));
        // Owner cannot execute with 0o600
        assert!(!check_access_permission(
            0o600,
            1000,
            1000,
            1000,
            2000,
            libc::X_OK
        ));
    }

    #[test]
    fn access_permission_group_read() {
        // Group member can read with 0o040
        assert!(check_access_permission(
            0o040,
            1000,
            2000,
            3000,
            2000,
            libc::R_OK
        ));
        // Group member cannot read with 0o030
        assert!(!check_access_permission(
            0o030,
            1000,
            2000,
            3000,
            2000,
            libc::R_OK
        ));
    }

    #[test]
    fn access_permission_group_write() {
        // Group member can write with 0o020
        assert!(check_access_permission(
            0o020,
            1000,
            2000,
            3000,
            2000,
            libc::W_OK
        ));
        // Group member cannot write with 0o050
        assert!(!check_access_permission(
            0o050,
            1000,
            2000,
            3000,
            2000,
            libc::W_OK
        ));
    }

    #[test]
    fn access_permission_group_execute() {
        // Group member can execute with 0o010
        assert!(check_access_permission(
            0o010,
            1000,
            2000,
            3000,
            2000,
            libc::X_OK
        ));
        // Group member cannot execute with 0o060
        assert!(!check_access_permission(
            0o060,
            1000,
            2000,
            3000,
            2000,
            libc::X_OK
        ));
    }

    #[test]
    fn access_permission_other_read() {
        // Other can read with 0o004
        assert!(check_access_permission(
            0o004,
            1000,
            2000,
            3000,
            4000,
            libc::R_OK
        ));
        // Other cannot read with 0o003
        assert!(!check_access_permission(
            0o003,
            1000,
            2000,
            3000,
            4000,
            libc::R_OK
        ));
    }

    #[test]
    fn access_permission_other_write() {
        // Other can write with 0o002
        assert!(check_access_permission(
            0o002,
            1000,
            2000,
            3000,
            4000,
            libc::W_OK
        ));
        // Other cannot write with 0o005
        assert!(!check_access_permission(
            0o005,
            1000,
            2000,
            3000,
            4000,
            libc::W_OK
        ));
    }

    #[test]
    fn access_permission_other_execute() {
        // Other can execute with 0o001
        assert!(check_access_permission(
            0o001,
            1000,
            2000,
            3000,
            4000,
            libc::X_OK
        ));
        // Other cannot execute with 0o006
        assert!(!check_access_permission(
            0o006,
            1000,
            2000,
            3000,
            4000,
            libc::X_OK
        ));
    }

    #[test]
    fn access_permission_combined_mask() {
        // Owner needs all of rwx for mask R_OK|W_OK|X_OK
        assert!(check_access_permission(
            0o700,
            1000,
            1000,
            1000,
            2000,
            libc::R_OK | libc::W_OK | libc::X_OK
        ));
        // Missing execute permission fails the combined check
        assert!(!check_access_permission(
            0o600,
            1000,
            1000,
            1000,
            2000,
            libc::R_OK | libc::W_OK | libc::X_OK
        ));
    }

    #[test]
    fn access_permission_f_ok_always_succeeds() {
        // F_OK (existence check, mask=0) always succeeds for non-root
        assert!(check_access_permission(0o000, 1000, 1000, 2000, 2000, 0));
    }

    // ── Mount option parsing tests ──────────────────────────────────────────

    #[test]
    fn parse_mount_option_empty_string_returns_defaults() {
        let opts = parse_mount_option_text("").unwrap();
        assert!(opts.read_only); // default is read_only
        assert!(!opts.allow_other);
        assert!(opts.auto_unmount);
    }

    #[test]
    fn parse_mount_option_whitespace_only_returns_defaults() {
        let opts = parse_mount_option_text("   ").unwrap();
        assert!(opts.read_only);
    }

    #[test]
    fn parse_mount_option_ro_sets_read_only() {
        let opts = parse_mount_option_text("ro").unwrap();
        assert!(opts.read_only);
    }

    #[test]
    fn parse_mount_option_rw_clears_read_only() {
        let opts = parse_mount_option_text("rw").unwrap();
        assert!(!opts.read_only);
    }

    #[test]
    fn parse_mount_option_allow_other_flag() {
        let opts = parse_mount_option_text("allow_other").unwrap();
        assert!(opts.allow_other);
    }

    #[test]
    fn parse_mount_option_allow_other_equals_true() {
        let opts = parse_mount_option_text("allow_other=true").unwrap();
        assert!(opts.allow_other);
    }

    #[test]
    fn parse_mount_option_allow_other_equals_false() {
        let opts = parse_mount_option_text("allow_other=false").unwrap();
        assert!(!opts.allow_other);
    }

    #[test]
    fn parse_mount_option_noallow_other() {
        // First enable, then disable
        let opts = parse_mount_option_text("allow_other,noallow_other").unwrap();
        assert!(!opts.allow_other);
    }

    #[test]
    fn parse_mount_option_worker_threads() {
        let opts = parse_mount_option_text("worker_threads=8").unwrap();
        assert_eq!(opts.worker_threads, 8);
    }

    #[test]
    fn parse_mount_option_threads_alias() {
        let opts = parse_mount_option_text("threads=4").unwrap();
        assert_eq!(opts.worker_threads, 4);
    }

    #[test]
    fn parse_mount_option_multiple_options() {
        let opts = parse_mount_option_text("rw,allow_other,worker_threads=16").unwrap();
        assert!(!opts.read_only);
        assert!(opts.allow_other);
        assert_eq!(opts.worker_threads, 16);
    }

    #[test]
    fn parse_mount_option_empty_option_in_list_fails() {
        let err = parse_mount_option_text("ro,,rw").unwrap_err();
        assert!(matches!(err, MountOptionParseError::EmptyOption));
    }

    #[test]
    fn parse_mount_option_unknown_option_fails() {
        let err = parse_mount_option_text("unknown_option").unwrap_err();
        assert!(matches!(err, MountOptionParseError::UnknownOption { .. }));
    }

    #[test]
    fn parse_mount_option_missing_value_fails() {
        let err = parse_mount_option_text("worker_threads").unwrap_err();
        assert!(matches!(err, MountOptionParseError::MissingValue { .. }));
    }

    #[test]
    fn parse_mount_option_unexpected_value_fails() {
        let err = parse_mount_option_text("ro=true").unwrap_err();
        assert!(matches!(err, MountOptionParseError::UnexpectedValue { .. }));
    }

    #[test]
    fn parse_mount_option_invalid_bool_fails() {
        let err = parse_mount_option_text("allow_other=maybe").unwrap_err();
        assert!(matches!(err, MountOptionParseError::InvalidValue { .. }));
    }

    #[test]
    fn parse_mount_option_invalid_number_fails() {
        let err = parse_mount_option_text("worker_threads=abc").unwrap_err();
        assert!(matches!(err, MountOptionParseError::InvalidValue { .. }));
    }

    #[test]
    fn parse_mount_bool_accepts_true_variants() {
        for val in ["1", "true", "yes", "on"] {
            assert!(
                parse_mount_bool("opt", Some(val)).unwrap(),
                "'{val}' should be true"
            );
        }
    }

    #[test]
    fn parse_mount_bool_accepts_false_variants() {
        for val in ["0", "false", "no", "off"] {
            assert!(
                !parse_mount_bool("opt", Some(val)).unwrap(),
                "'{val}' should be false"
            );
        }
    }

    #[test]
    fn parse_mount_bool_rejects_invalid() {
        let err = parse_mount_bool("opt", Some("maybe")).unwrap_err();
        assert!(matches!(err, MountOptionParseError::InvalidValue { .. }));
    }

    #[test]
    fn parse_mount_bool_requires_value() {
        let err = parse_mount_bool("opt", None).unwrap_err();
        assert!(matches!(err, MountOptionParseError::MissingValue { .. }));
    }

    #[test]
    fn parse_mount_usize_valid() {
        assert_eq!(parse_mount_usize("threads", Some("4")).unwrap(), 4);
        assert_eq!(parse_mount_usize("threads", Some("0")).unwrap(), 0);
        assert_eq!(parse_mount_usize("threads", Some("1000")).unwrap(), 1000);
    }

    #[test]
    fn parse_mount_usize_rejects_negative() {
        let err = parse_mount_usize("threads", Some("-1")).unwrap_err();
        assert!(matches!(err, MountOptionParseError::InvalidValue { .. }));
    }

    #[test]
    fn parse_mount_usize_rejects_non_numeric() {
        let err = parse_mount_usize("threads", Some("abc")).unwrap_err();
        assert!(matches!(err, MountOptionParseError::InvalidValue { .. }));
    }

    #[test]
    fn split_mount_option_key_only() {
        let (key, value) = split_mount_option("ro").unwrap();
        assert_eq!(key, "ro");
        assert!(value.is_none());
    }

    #[test]
    fn split_mount_option_key_value() {
        let (key, value) = split_mount_option("threads=4").unwrap();
        assert_eq!(key, "threads");
        assert_eq!(value, Some("4"));
    }

    #[test]
    fn split_mount_option_value_with_equals() {
        let (key, value) = split_mount_option("fsname=my=fs").unwrap();
        assert_eq!(key, "fsname");
        assert_eq!(value, Some("my=fs"));
    }

    #[test]
    fn split_mount_option_empty_value() {
        let (key, value) = split_mount_option("opt=").unwrap();
        assert_eq!(key, "opt");
        assert_eq!(value, Some(""));
    }

    #[test]
    fn require_mount_option_value_returns_value() {
        assert_eq!(
            require_mount_option_value("opt", Some("val")).unwrap(),
            "val"
        );
    }

    #[test]
    fn require_mount_option_value_rejects_none() {
        let err = require_mount_option_value("opt", None).unwrap_err();
        assert!(matches!(err, MountOptionParseError::MissingValue { .. }));
    }

    #[test]
    fn require_mount_option_value_rejects_empty() {
        let err = require_mount_option_value("opt", Some("")).unwrap_err();
        assert!(matches!(err, MountOptionParseError::InvalidValue { .. }));
    }

    // ── Ioctl parsing tests ─────────────────────────────────────────────────

    #[test]
    fn parse_fiemap_request_valid() {
        // Build a valid 32-byte FIEMAP header
        let mut data = vec![0u8; FIEMAP_HEADER_SIZE];
        // fm_start at offset 0 (u64)
        data[0..8].copy_from_slice(&100u64.to_ne_bytes());
        // fm_length at offset 8 (u64)
        data[8..16].copy_from_slice(&4096u64.to_ne_bytes());
        // fm_flags at offset 16 (u32)
        data[16..20].copy_from_slice(&FIEMAP_FLAG_SYNC.to_ne_bytes());
        // fm_extent_count at offset 24 (u32)
        data[24..28].copy_from_slice(&10u32.to_ne_bytes());

        let (start, length, flags, count) = FrankenFuse::parse_fiemap_request(&data).unwrap();
        assert_eq!(start, 100);
        assert_eq!(length, 4096);
        assert_eq!(flags, FIEMAP_FLAG_SYNC);
        assert_eq!(count, 10);
    }

    #[test]
    fn parse_fiemap_request_too_short() {
        let data = vec![0u8; FIEMAP_HEADER_SIZE - 1];
        let err = FrankenFuse::parse_fiemap_request(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn parse_fiemap_request_zeros() {
        let data = vec![0u8; FIEMAP_HEADER_SIZE];
        let (start, length, flags, count) = FrankenFuse::parse_fiemap_request(&data).unwrap();
        assert_eq!(start, 0);
        assert_eq!(length, 0);
        assert_eq!(flags, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn parse_u32_ioctl_arg_valid() {
        let data = 0x1234_5678u32.to_ne_bytes();
        let value = FrankenFuse::parse_u32_ioctl_arg(&data).unwrap();
        assert_eq!(value, 0x1234_5678);
    }

    #[test]
    fn parse_u32_ioctl_arg_too_short() {
        let data = [0u8; 3];
        let err = FrankenFuse::parse_u32_ioctl_arg(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn parse_inode_flags_valid() {
        let data = 0x0000_0800u32.to_ne_bytes(); // EXT4_ENCRYPT_FL
        let flags = FrankenFuse::parse_inode_flags(&data).unwrap();
        assert_eq!(flags, 0x0000_0800);
    }

    #[test]
    fn parse_inode_flags_too_short() {
        let data = [0u8; 3];
        let err = FrankenFuse::parse_inode_flags(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn parse_btrfs_tree_search_key_valid() {
        // Build a valid 104-byte btrfs tree search key
        let mut data = vec![0u8; BTRFS_TREE_SEARCH_KEY_SIZE];
        // tree_id at offset 0 (u64)
        data[0..8].copy_from_slice(&5u64.to_ne_bytes()); // FS_TREE
        // min_objectid at offset 8 (u64)
        data[8..16].copy_from_slice(&256u64.to_ne_bytes());
        // max_objectid at offset 16 (u64)
        data[16..24].copy_from_slice(&u64::MAX.to_ne_bytes());
        // min_offset at offset 24 (u64)
        data[24..32].copy_from_slice(&0u64.to_ne_bytes());
        // max_offset at offset 32 (u64)
        data[32..40].copy_from_slice(&u64::MAX.to_ne_bytes());
        // min_transid at offset 40 (u64)
        data[40..48].copy_from_slice(&0u64.to_ne_bytes());
        // max_transid at offset 48 (u64)
        data[48..56].copy_from_slice(&u64::MAX.to_ne_bytes());
        // min_type at offset 56 (u32)
        data[56..60].copy_from_slice(&1u32.to_ne_bytes()); // INODE_ITEM
        // max_type at offset 60 (u32)
        data[60..64].copy_from_slice(&255u32.to_ne_bytes());
        // nr_items at offset 64 (u32)
        data[64..68].copy_from_slice(&100u32.to_ne_bytes());

        let key = FrankenFuse::parse_btrfs_tree_search_key(&data).unwrap();
        assert_eq!(key.tree_id, 5);
        assert_eq!(key.min_objectid, 256);
        assert_eq!(key.max_objectid, u64::MAX);
        assert_eq!(key.min_offset, 0);
        assert_eq!(key.max_offset, u64::MAX);
        assert_eq!(key.min_transid, 0);
        assert_eq!(key.max_transid, u64::MAX);
        assert_eq!(key.min_type, 1);
        assert_eq!(key.max_type, 255);
        assert_eq!(key.nr_items, 100);
    }

    #[test]
    fn parse_btrfs_tree_search_key_too_short() {
        let data = vec![0u8; BTRFS_TREE_SEARCH_KEY_SIZE - 1];
        let err = FrankenFuse::parse_btrfs_tree_search_key(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn parse_btrfs_tree_search_key_zeros() {
        let data = vec![0u8; BTRFS_TREE_SEARCH_KEY_SIZE];
        let key = FrankenFuse::parse_btrfs_tree_search_key(&data).unwrap();
        assert_eq!(key.tree_id, 0);
        assert_eq!(key.min_objectid, 0);
        assert_eq!(key.nr_items, 0);
    }

    #[test]
    fn parse_fs_label_request_valid() {
        let data = b"my_label\0padding".to_vec();
        let label = FrankenFuse::parse_fs_label_request(&data).unwrap();
        assert_eq!(label, b"my_label");
    }

    #[test]
    fn parse_fs_label_request_empty_label() {
        let data = b"\0rest".to_vec();
        let label = FrankenFuse::parse_fs_label_request(&data).unwrap();
        assert!(label.is_empty());
    }

    #[test]
    fn parse_fs_label_request_no_nul_terminator() {
        let data = b"label_without_nul".to_vec();
        let err = FrankenFuse::parse_fs_label_request(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn parse_fs_label_request_max_length() {
        // Label exactly at FSLABEL_MAX-1 bytes + NUL
        let mut data = vec![b'a'; FSLABEL_MAX - 1];
        data.push(0);
        let label = FrankenFuse::parse_fs_label_request(&data).unwrap();
        assert_eq!(label.len(), FSLABEL_MAX - 1);
    }

    #[test]
    fn parse_fs_label_request_truncates_beyond_max() {
        // Data longer than FSLABEL_MAX, NUL after FSLABEL_MAX
        let mut data = vec![b'x'; FSLABEL_MAX + 10];
        data[FSLABEL_MAX + 5] = 0; // NUL beyond the parse window
        // Should fail because no NUL in first FSLABEL_MAX bytes
        let err = FrankenFuse::parse_fs_label_request(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn parse_move_ext_request_valid() {
        let mut data = vec![0u8; MOVE_EXT_SIZE];
        // reserved at offset 0 (u32) = 0 (already zeros)
        // donor_fd at offset 4 (i32) = 5
        data[4..8].copy_from_slice(&5i32.to_ne_bytes());
        // orig_start at offset 8 (u64) = 4096
        data[8..16].copy_from_slice(&4096u64.to_ne_bytes());
        // donor_start at offset 16 (u64) = 8192
        data[16..24].copy_from_slice(&8192u64.to_ne_bytes());
        // len at offset 24 (u64) = 1024
        data[24..32].copy_from_slice(&1024u64.to_ne_bytes());

        let (donor_fd, orig_start, donor_start, len) =
            FrankenFuse::parse_move_ext_request(&data).unwrap();
        assert_eq!(donor_fd, 5);
        assert_eq!(orig_start, 4096);
        assert_eq!(donor_start, 8192);
        assert_eq!(len, 1024);
    }

    #[test]
    fn parse_move_ext_request_too_short() {
        let data = vec![0u8; MOVE_EXT_SIZE - 1];
        let err = FrankenFuse::parse_move_ext_request(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn parse_move_ext_request_nonzero_reserved_fails() {
        let mut data = vec![0u8; MOVE_EXT_SIZE];
        data[0..4].copy_from_slice(&1u32.to_ne_bytes()); // reserved != 0
        data[4..8].copy_from_slice(&5i32.to_ne_bytes()); // valid donor_fd
        let err = FrankenFuse::parse_move_ext_request(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn parse_move_ext_request_negative_fd_fails() {
        let mut data = vec![0u8; MOVE_EXT_SIZE];
        // reserved = 0 (already zeros)
        data[4..8].copy_from_slice(&(-1i32).to_ne_bytes()); // negative fd
        let err = FrankenFuse::parse_move_ext_request(&data).unwrap_err();
        assert_eq!(err, libc::EBADF);
    }

    #[test]
    fn parse_move_ext_request_overflow_fails() {
        let mut data = vec![0u8; MOVE_EXT_SIZE];
        data[4..8].copy_from_slice(&5i32.to_ne_bytes()); // valid fd
        data[8..16].copy_from_slice(&(u64::MAX - 10).to_ne_bytes()); // orig_start
        data[24..32].copy_from_slice(&100u64.to_ne_bytes()); // len causes overflow
        let err = FrankenFuse::parse_move_ext_request(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn parse_fstrim_range_valid() {
        let mut data = [0u8; 24];
        let start = 4096u64;
        let len = 1024u64;
        let minlen = 512u64;
        data[0..8].copy_from_slice(&start.to_ne_bytes());
        data[8..16].copy_from_slice(&len.to_ne_bytes());
        data[16..24].copy_from_slice(&minlen.to_ne_bytes());
        let (s, l, m) = FrankenFuse::parse_fstrim_range(&data).unwrap();
        assert_eq!(s, start);
        assert_eq!(l, len);
        assert_eq!(m, minlen);
    }

    #[test]
    fn parse_fstrim_range_too_short() {
        let data = [0u8; 20];
        let err = FrankenFuse::parse_fstrim_range(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn encode_fstrim_response_layout() {
        let start = 0x1000u64;
        let discarded = 0x2000u64;
        let minlen = 0x100u64;
        let buf = FrankenFuse::encode_fstrim_response(start, discarded, minlen);
        assert_eq!(buf.len(), 24);
        assert_eq!(u64::from_ne_bytes(buf[0..8].try_into().unwrap()), start);
        assert_eq!(
            u64::from_ne_bytes(buf[8..16].try_into().unwrap()),
            discarded
        );
        assert_eq!(u64::from_ne_bytes(buf[16..24].try_into().unwrap()), minlen);
    }

    #[test]
    fn fstrim_parse_encode_roundtrip() {
        let start = 8192u64;
        let len = 65536u64;
        let minlen = 4096u64;
        let encoded = FrankenFuse::encode_fstrim_response(start, len, minlen);
        let (s, l, m) = FrankenFuse::parse_fstrim_range(&encoded).unwrap();
        assert_eq!(s, start);
        assert_eq!(l, len);
        assert_eq!(m, minlen);
    }

    #[test]
    fn encode_fsuuid_response_layout() {
        let uuid: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let buf = FrankenFuse::encode_fsuuid_response(&uuid);
        assert_eq!(buf.len(), 17);
        assert_eq!(buf[0], 16);
        assert_eq!(&buf[1..], &uuid[..]);
    }

    #[test]
    fn parse_fsxattr_request_valid() {
        let mut data = [0u8; 28];
        let xflags = 0x0000_0001_u32;
        let extsize = 4096u32;
        let projid = 42u32;
        let cowextsize = 65536u32;
        data[0..4].copy_from_slice(&xflags.to_ne_bytes());
        data[4..8].copy_from_slice(&extsize.to_ne_bytes());
        data[12..16].copy_from_slice(&projid.to_ne_bytes());
        data[16..20].copy_from_slice(&cowextsize.to_ne_bytes());
        let fsx = FrankenFuse::parse_fsxattr_request(&data).unwrap();
        assert_eq!(fsx.xflags, xflags);
        assert_eq!(fsx.extsize, extsize);
        assert_eq!(fsx.projid, projid);
        assert_eq!(fsx.cowextsize, cowextsize);
        assert_eq!(fsx.nextents, 0);
    }

    #[test]
    fn parse_fsxattr_request_too_short() {
        let data = [0u8; 20];
        let err = FrankenFuse::parse_fsxattr_request(&data).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn encode_fsxattr_response_layout() {
        let fsx = FsxattrInfo {
            xflags: 0x0000_0001,
            extsize: 4096,
            nextents: 100,
            projid: 42,
            cowextsize: 65536,
        };
        let buf = FrankenFuse::encode_fsxattr_response(&fsx);
        assert_eq!(buf.len(), 28);
        assert_eq!(
            u32::from_ne_bytes(buf[0..4].try_into().unwrap()),
            fsx.xflags
        );
        assert_eq!(
            u32::from_ne_bytes(buf[4..8].try_into().unwrap()),
            fsx.extsize
        );
        assert_eq!(
            u32::from_ne_bytes(buf[8..12].try_into().unwrap()),
            fsx.nextents
        );
        assert_eq!(
            u32::from_ne_bytes(buf[12..16].try_into().unwrap()),
            fsx.projid
        );
        assert_eq!(
            u32::from_ne_bytes(buf[16..20].try_into().unwrap()),
            fsx.cowextsize
        );
    }

    #[test]
    fn fsxattr_parse_encode_roundtrip() {
        let mut data = [0u8; 28];
        let xflags = 0x0000_0002_u32;
        let extsize = 8192u32;
        let projid = 100u32;
        let cowextsize = 131_072_u32;
        data[0..4].copy_from_slice(&xflags.to_ne_bytes());
        data[4..8].copy_from_slice(&extsize.to_ne_bytes());
        data[12..16].copy_from_slice(&projid.to_ne_bytes());
        data[16..20].copy_from_slice(&cowextsize.to_ne_bytes());
        let parsed = FrankenFuse::parse_fsxattr_request(&data).unwrap();
        let encoded = FrankenFuse::encode_fsxattr_response(&parsed);
        assert_eq!(
            u32::from_ne_bytes(encoded[0..4].try_into().unwrap()),
            xflags
        );
        assert_eq!(
            u32::from_ne_bytes(encoded[4..8].try_into().unwrap()),
            extsize
        );
        assert_eq!(
            u32::from_ne_bytes(encoded[12..16].try_into().unwrap()),
            projid
        );
        assert_eq!(
            u32::from_ne_bytes(encoded[16..20].try_into().unwrap()),
            cowextsize
        );
    }

    #[test]
    fn encode_fs_sysfs_path_response_empty_path() {
        let buf = FrankenFuse::encode_fs_sysfs_path_response(b"").unwrap();
        assert_eq!(buf.len(), 129);
        assert_eq!(buf[0], 0);
        assert!(buf[1..].iter().all(|&b| b == 0));
    }

    #[test]
    #[expect(clippy::cast_possible_truncation)] // path.len() < 128 by construction
    fn encode_fs_sysfs_path_response_short_path() {
        let path = b"/sys/fs/ext4/sda1";
        let buf = FrankenFuse::encode_fs_sysfs_path_response(path).unwrap();
        assert_eq!(buf.len(), 129);
        assert_eq!(buf[0], path.len() as u8);
        assert_eq!(&buf[1..=path.len()], path);
        assert!(buf[1 + path.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn encode_fs_sysfs_path_response_max_length_path() {
        let path = [b'a'; 128];
        let buf = FrankenFuse::encode_fs_sysfs_path_response(&path).unwrap();
        assert_eq!(buf.len(), 129);
        assert_eq!(buf[0], 128);
        assert_eq!(&buf[1..], &path[..]);
    }

    #[test]
    fn encode_fs_sysfs_path_response_too_long_path() {
        let path = [b'x'; 129];
        let err = FrankenFuse::encode_fs_sysfs_path_response(&path).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn encode_move_ext_response_layout() {
        let buf = FrankenFuse::encode_move_ext_response(7, 4096, 8192, 1024, 512);
        assert_eq!(buf.len(), MOVE_EXT_SIZE);
        assert_eq!(
            u32::from_ne_bytes(
                buf[MOVE_EXT_DONOR_FD_OFFSET..MOVE_EXT_DONOR_FD_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            7
        );
        assert_eq!(
            u64::from_ne_bytes(
                buf[MOVE_EXT_ORIG_START_OFFSET..MOVE_EXT_ORIG_START_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            4096
        );
        assert_eq!(
            u64::from_ne_bytes(
                buf[MOVE_EXT_DONOR_START_OFFSET..MOVE_EXT_DONOR_START_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            8192
        );
        assert_eq!(
            u64::from_ne_bytes(
                buf[MOVE_EXT_LEN_OFFSET..MOVE_EXT_LEN_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            1024
        );
        assert_eq!(
            u64::from_ne_bytes(
                buf[MOVE_EXT_MOVED_LEN_OFFSET..MOVE_EXT_MOVED_LEN_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            512
        );
    }

    #[test]
    #[expect(clippy::cast_possible_truncation)] // test buffer size fits u32
    fn clamp_fiemap_extent_count_request_limited() {
        // Request 5 extents but buffer can hold more - limited by request
        let out_size = (FIEMAP_HEADER_SIZE + 10 * FIEMAP_EXTENT_SIZE) as u32;
        assert_eq!(FrankenFuse::clamp_fiemap_extent_count(5, out_size), 5);
    }

    #[test]
    #[expect(clippy::cast_possible_truncation)] // test buffer size fits u32
    fn clamp_fiemap_extent_count_buffer_limited() {
        // Request 100 extents but buffer can only hold 2
        let out_size = (FIEMAP_HEADER_SIZE + 2 * FIEMAP_EXTENT_SIZE) as u32;
        assert_eq!(FrankenFuse::clamp_fiemap_extent_count(100, out_size), 2);
    }

    #[test]
    #[expect(clippy::cast_possible_truncation)] // FIEMAP_HEADER_SIZE fits u32
    fn clamp_fiemap_extent_count_zero_extents() {
        // Buffer too small for any extents (only header fits)
        let out_size = FIEMAP_HEADER_SIZE as u32;
        assert_eq!(FrankenFuse::clamp_fiemap_extent_count(10, out_size), 0);
    }

    #[test]
    fn clamp_fiemap_extent_count_tiny_buffer() {
        // Buffer smaller than header
        assert_eq!(FrankenFuse::clamp_fiemap_extent_count(10, 16), 0);
    }

    #[test]
    fn inode_attr_to_file_attr_conversion() {
        let iattr = InodeAttr {
            ino: InodeNumber(42),
            size: 1024,
            blocks: 2,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: FfsFileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            generation: 7,
        };
        let fattr = to_file_attr(&iattr);
        assert_eq!(fattr.ino, 42);
        assert_eq!(fattr.size, 1024);
        assert_eq!(fattr.blocks, 2);
        assert_eq!(fattr.kind, FileType::RegularFile);
        assert_eq!(fattr.perm, 0o644);
        assert_eq!(fattr.nlink, 1);
        assert_eq!(fattr.uid, 1000);
        assert_eq!(fattr.gid, 1000);
        assert_eq!(fattr.rdev, 0);
        assert_eq!(fattr.blksize, 4096);
        assert_eq!(fattr.flags, 0);
    }

    #[test]
    fn to_file_attr_maps_each_timestamp_field_distinctly() {
        // Distinct per-field values so an atime/mtime swap or ctime->crtime
        // miscopy in the getattr translation cannot pass unnoticed.
        let atime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1);
        let mtime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2);
        let ctime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(3);
        let creation_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(4);
        let iattr = InodeAttr {
            ino: InodeNumber(1),
            size: 0,
            blocks: 0,
            atime,
            mtime,
            ctime,
            crtime: creation_time,
            kind: FfsFileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            generation: 0,
        };
        let fattr = to_file_attr(&iattr);
        assert_eq!(fattr.atime, atime, "atime");
        assert_eq!(fattr.mtime, mtime, "mtime");
        assert_eq!(fattr.ctime, ctime, "ctime");
        assert_eq!(fattr.crtime, creation_time, "crtime");
    }

    #[test]
    fn to_fuser_file_type_all_variants() {
        assert_eq!(
            to_fuser_file_type(FfsFileType::RegularFile),
            FileType::RegularFile
        );
        assert_eq!(
            to_fuser_file_type(FfsFileType::Directory),
            FileType::Directory
        );
        assert_eq!(to_fuser_file_type(FfsFileType::Symlink), FileType::Symlink);
        assert_eq!(
            to_fuser_file_type(FfsFileType::BlockDevice),
            FileType::BlockDevice
        );
        assert_eq!(
            to_fuser_file_type(FfsFileType::CharDevice),
            FileType::CharDevice
        );
        assert_eq!(to_fuser_file_type(FfsFileType::Fifo), FileType::NamedPipe);
        assert_eq!(to_fuser_file_type(FfsFileType::Socket), FileType::Socket);
    }

    #[test]
    fn mount_options_default_is_read_only() {
        let opts = MountOptions::default();
        assert!(opts.read_only);
        assert!(!opts.allow_other);
        assert!(opts.auto_unmount);
        assert!(!opts.writeback_cache.is_enabled());
        assert!(opts.ioctl_trace_path.is_none());
        assert_eq!(
            opts.worker_threads, 0,
            "default worker_threads should be 0 (auto)"
        );
    }

    #[test]
    fn writeback_cache_mode_from_enabled() {
        assert!(matches!(
            WritebackCacheMode::from_enabled(true),
            WritebackCacheMode::Enabled
        ));
        assert!(matches!(
            WritebackCacheMode::from_enabled(false),
            WritebackCacheMode::Disabled
        ));
    }

    #[test]
    fn writeback_cache_mode_is_enabled() {
        assert!(WritebackCacheMode::Enabled.is_enabled());
        assert!(!WritebackCacheMode::Disabled.is_enabled());
    }

    #[test]
    fn writeback_cache_mode_default_is_disabled() {
        assert!(matches!(
            WritebackCacheMode::default(),
            WritebackCacheMode::Disabled
        ));
    }

    #[test]
    fn resolved_thread_count_zero_uses_auto() {
        let opts = MountOptions {
            worker_threads: 0,
            ..MountOptions::default()
        };
        let count = opts.resolved_thread_count();
        assert!((1..=8).contains(&count));
    }

    #[test]
    fn resolved_thread_count_explicit_value() {
        let opts = MountOptions {
            worker_threads: 4,
            ..MountOptions::default()
        };
        assert_eq!(opts.resolved_thread_count(), 4);
    }

    #[test]
    fn resolved_thread_count_clamps_to_minimum_one() {
        let opts = MountOptions {
            worker_threads: 1,
            ..MountOptions::default()
        };
        assert_eq!(opts.resolved_thread_count(), 1);
    }

    #[test]
    fn atomic_metrics_new_starts_at_zero() {
        let m = AtomicMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.requests_total, 0);
        assert_eq!(s.requests_ok, 0);
        assert_eq!(s.requests_err, 0);
        assert_eq!(s.bytes_read, 0);
        assert_eq!(s.requests_throttled, 0);
        assert_eq!(s.requests_shed, 0);
    }

    #[test]
    fn atomic_metrics_record_ok_increments_counters() {
        let m = AtomicMetrics::new();
        m.record_ok();
        m.record_ok();
        let s = m.snapshot();
        assert_eq!(s.requests_total, 2);
        assert_eq!(s.requests_ok, 2);
        assert_eq!(s.requests_err, 0);
    }

    #[test]
    fn atomic_metrics_record_err_increments_counters() {
        let m = AtomicMetrics::new();
        m.record_err();
        let s = m.snapshot();
        assert_eq!(s.requests_total, 1);
        assert_eq!(s.requests_err, 1);
        assert_eq!(s.requests_ok, 0);
    }

    #[test]
    fn atomic_metrics_record_bytes_read() {
        let m = AtomicMetrics::new();
        m.record_bytes_read(1024);
        m.record_bytes_read(2048);
        let s = m.snapshot();
        assert_eq!(s.bytes_read, 3072);
    }

    #[test]
    fn atomic_metrics_default_equals_new() {
        let from_new = AtomicMetrics::new();
        let from_default = AtomicMetrics::default();
        let snap_new = from_new.snapshot();
        let snap_default = from_default.snapshot();
        assert_eq!(snap_new.requests_total, snap_default.requests_total);
        assert_eq!(snap_new.requests_ok, snap_default.requests_ok);
        assert_eq!(snap_new.requests_err, snap_default.requests_err);
        assert_eq!(snap_new.bytes_read, snap_default.bytes_read);
        assert_eq!(snap_new.requests_throttled, snap_default.requests_throttled);
        assert_eq!(snap_new.requests_shed, snap_default.requests_shed);
    }

    #[test]
    fn atomic_metrics_record_throttled() {
        let m = AtomicMetrics::new();
        assert_eq!(m.snapshot().requests_throttled, 0);
        m.record_throttled();
        m.record_throttled();
        assert_eq!(m.snapshot().requests_throttled, 2);
    }

    #[test]
    fn atomic_metrics_record_shed() {
        let m = AtomicMetrics::new();
        assert_eq!(m.snapshot().requests_shed, 0);
        m.record_shed();
        assert_eq!(m.snapshot().requests_shed, 1);
    }

    #[test]
    fn access_predictor_new_clamps_max_entries() {
        let p = AccessPredictor::new(0);
        assert_eq!(p.max_entries, 1);
    }

    #[test]
    fn access_predictor_default_uses_max_entries() {
        let p = AccessPredictor::default();
        assert_eq!(p.max_entries, MAX_ACCESS_PREDICTOR_ENTRIES);
    }

    #[test]
    fn access_predictor_fetch_size_returns_requested_for_unknown_inode() {
        let p = AccessPredictor::default();
        let size = p.fetch_size(InodeNumber(999), 0, 4096);
        assert_eq!(size, 4096);
    }

    #[test]
    fn access_predictor_invalidate_removes_entry() {
        let p = AccessPredictor::new(100);
        p.record_read(InodeNumber(1), 0, 4096);
        p.invalidate_inode(InodeNumber(1));
        // After invalidation, should return requested size (no history)
        let size = p.fetch_size(InodeNumber(1), 4096, 4096);
        assert_eq!(size, 4096);
    }

    #[test]
    fn readahead_manager_new_clamps_max_pending() {
        let r = ReadaheadManager::new(0);
        assert_eq!(r.max_pending, 1);
    }

    #[test]
    fn readahead_manager_insert_and_take() {
        let r = ReadaheadManager::new(10);
        let data = vec![1, 2, 3, 4];
        r.insert(InodeNumber(1), 0, data.clone());
        let taken = r.take(InodeNumber(1), 0, 4);
        assert_eq!(taken, Some(data));
    }

    #[test]
    fn fuse_inode_locks_evict_slots_when_guards_drop() {
        let locks = Arc::new(FuseInodeLocks {
            table: Mutex::new(std::collections::BTreeMap::new()),
        });

        // A single-inode acquire creates one slot with users == 1.
        let g = locks.acquire(&[InodeNumber(5)]);
        assert_eq!(locks.table.lock().unwrap().len(), 1);
        assert_eq!(locks.table.lock().unwrap()[&InodeNumber(5)].users, 1);
        // Dropping the guard evicts the slot (users reaches 0) — no leak.
        drop(g);
        assert!(locks.table.lock().unwrap().is_empty());

        // A multi-inode batch creates one slot per distinct inode, all evicted.
        let g2 = locks.acquire(&[InodeNumber(5), InodeNumber(7)]);
        assert_eq!(locks.table.lock().unwrap().len(), 2);
        drop(g2);
        assert!(locks.table.lock().unwrap().is_empty());
    }

    #[test]
    fn readahead_manager_reinsert_does_not_evict_updated_entry() {
        let r = ReadaheadManager::new(2);
        r.insert(InodeNumber(1), 0, vec![1]);
        r.insert(InodeNumber(1), 0, vec![2]); // re-insert same key: dedups the FIFO slot
        r.insert(InodeNumber(2), 0, vec![3]);

        // With FIFO dedup, both distinct keys fit within max_pending=2; the
        // re-inserted entry was not spuriously evicted and holds the new value.
        assert_eq!(r.take(InodeNumber(1), 0, 1), Some(vec![2]));
        assert_eq!(r.take(InodeNumber(2), 0, 1), Some(vec![3]));
    }

    #[test]
    fn readahead_manager_evicts_oldest_when_over_limit() {
        let r = ReadaheadManager::new(2);
        r.insert(InodeNumber(1), 0, vec![1]);
        r.insert(InodeNumber(2), 0, vec![2]);
        r.insert(InodeNumber(3), 0, vec![3]); // exceeds max_pending=2

        // The oldest entry was evicted to keep the cache bounded.
        assert!(r.take(InodeNumber(1), 0, 1).is_none());
        // The two most recent entries survive.
        assert_eq!(r.take(InodeNumber(2), 0, 1), Some(vec![2]));
        assert_eq!(r.take(InodeNumber(3), 0, 1), Some(vec![3]));
    }

    #[test]
    fn readahead_manager_take_removes_entry() {
        let r = ReadaheadManager::new(10);
        r.insert(InodeNumber(1), 0, vec![1, 2, 3, 4]);
        let _ = r.take(InodeNumber(1), 0, 4);
        let second_take = r.take(InodeNumber(1), 0, 4);
        assert!(second_take.is_none());
    }

    #[test]
    fn readahead_manager_invalidate_removes_entry() {
        let r = ReadaheadManager::new(10);
        r.insert(InodeNumber(1), 0, vec![1, 2, 3, 4]);
        r.invalidate_inode(InodeNumber(1));
        let taken = r.take(InodeNumber(1), 0, 4);
        assert!(taken.is_none());
    }

    #[test]
    fn mount_config_default_values() {
        let cfg = MountConfig::default();
        assert!(cfg.options.read_only);
        assert!(cfg.backpressure.is_none());
        assert_eq!(cfg.unmount_timeout, Duration::from_secs(30));
    }

    fn make_test_attr(kind: FfsFileType, size: u64) -> InodeAttr {
        InodeAttr {
            ino: InodeNumber(1),
            size,
            blocks: 1,
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
            generation: 1,
        }
    }

    struct OpendirAttrFs {
        kind: Option<FfsFileType>,
    }

    impl FsOps for OpendirAttrFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            let Some(kind) = self.kind else {
                return Err(FfsError::NotFound(format!("inode {ino}")));
            };
            let mut attr = make_test_attr(kind, 4096);
            attr.ino = ino;
            Ok(attr)
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            unreachable!("opendir validation only calls getattr")
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<FfsReaddirPage> {
            unreachable!("opendir validation only calls getattr")
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            unreachable!("opendir validation only calls getattr")
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            unreachable!("opendir validation only calls getattr")
        }
    }

    #[test]
    fn opendir_dispatch_accepts_directory_inode() {
        let fuse = FrankenFuse::new(Box::new(OpendirAttrFs {
            kind: Some(FfsFileType::Directory),
        }));
        let cx = Cx::for_testing();

        let result = fuse
            .dispatch_opendir(&cx, InodeNumber(7))
            .expect("directory opendir");

        assert_eq!(result, (0, 0));
    }

    #[test]
    fn opendir_dispatch_rejects_regular_file_inode() {
        let fuse = FrankenFuse::new(Box::new(OpendirAttrFs {
            kind: Some(FfsFileType::RegularFile),
        }));
        let cx = Cx::for_testing();

        let err = fuse
            .dispatch_opendir(&cx, InodeNumber(7))
            .expect_err("regular file opendir should fail");

        assert!(matches!(err, FfsError::NotDirectory));
        assert_eq!(err.to_errno(), libc::ENOTDIR);
    }

    #[test]
    fn opendir_dispatch_preserves_missing_inode_error() {
        let fuse = FrankenFuse::new(Box::new(OpendirAttrFs { kind: None }));
        let cx = Cx::for_testing();

        let err = fuse
            .dispatch_opendir(&cx, InodeNumber(999))
            .expect_err("missing inode opendir should fail");

        assert!(matches!(err, FfsError::NotFound(_)));
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn validate_move_ext_source_accepts_valid_file() {
        let attr = make_test_attr(FfsFileType::RegularFile, 4096);
        assert!(FrankenFuse::validate_move_ext_source(&attr, EXT4_EXTENTS_FL).is_ok());
    }

    #[test]
    fn validate_move_ext_source_rejects_directory() {
        let attr = make_test_attr(FfsFileType::Directory, 4096);
        assert_eq!(
            FrankenFuse::validate_move_ext_source(&attr, EXT4_EXTENTS_FL),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn validate_move_ext_source_rejects_empty_file() {
        let attr = make_test_attr(FfsFileType::RegularFile, 0);
        assert_eq!(
            FrankenFuse::validate_move_ext_source(&attr, EXT4_EXTENTS_FL),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn validate_move_ext_source_rejects_non_extent_file() {
        let attr = make_test_attr(FfsFileType::RegularFile, 4096);
        assert_eq!(
            FrankenFuse::validate_move_ext_source(&attr, 0),
            Err(libc::EOPNOTSUPP)
        );
    }

    #[test]
    fn validate_move_ext_range_accepts_aligned_offsets() {
        assert!(FrankenFuse::validate_move_ext_range(4096, 0, 0, 100).is_ok());
        assert!(FrankenFuse::validate_move_ext_range(4096, 1, 1, 100).is_ok());
    }

    #[test]
    fn validate_move_ext_range_rejects_misaligned_offsets() {
        // With 1024-byte blocks, blocks_per_page = 4096/1024 = 4.
        // orig_start=0 gives 0%4=0, donor_start=1 gives 1%4=1 -> misaligned
        assert_eq!(
            FrankenFuse::validate_move_ext_range(1024, 0, 1, 100),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn validate_move_ext_range_rejects_overflow() {
        assert_eq!(
            FrankenFuse::validate_move_ext_range(4096, u64::MAX - 10, 0, 100),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn classify_move_ext_error_read_only() {
        assert_eq!(
            FrankenFuse::classify_move_ext_error(&FfsError::ReadOnly),
            "read_only"
        );
    }

    #[test]
    fn classify_move_ext_error_unsupported_feature() {
        assert_eq!(
            FrankenFuse::classify_move_ext_error(&FfsError::UnsupportedFeature("test".into())),
            "unsupported_feature"
        );
    }

    #[test]
    fn classify_move_ext_error_not_found() {
        assert_eq!(
            FrankenFuse::classify_move_ext_error(&FfsError::NotFound("test".into())),
            "not_found"
        );
    }

    #[test]
    fn classify_move_ext_error_io_ebadf() {
        let io_err = std::io::Error::from_raw_os_error(libc::EBADF);
        assert_eq!(
            FrankenFuse::classify_move_ext_error(&FfsError::Io(io_err)),
            "bad_donor_fd"
        );
    }

    #[test]
    fn move_ext_operation_id_format() {
        let id = FrankenFuse::move_ext_operation_id(100, 7, 0, 1024, 4096);
        assert_eq!(id, "fuse-move-ext-100-7-0-1024-4096");
    }

    #[test]
    fn build_mount_options_includes_ro_when_read_only() {
        let opts = MountOptions::default();
        let mount_opts = build_mount_options(&opts);
        assert!(
            mount_opts
                .iter()
                .any(|option| matches!(option, MountOption::CUSTOM(v) if v == "max_read=16777216")),
            "default mount options should negotiate the large read ceiling: {mount_opts:?}"
        );
        assert!(mount_opts.len() >= 6);
    }

    #[test]
    fn mount_rejects_empty_mountpoint() {
        // We can't construct a real FsOps without a filesystem, but we can
        // verify the mountpoint validation fires before any FsOps call.
        // Use a minimal test helper.
        struct NeverCalledFs;
        impl FsOps for NeverCalledFs {
            fn getattr(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _ino: InodeNumber,
            ) -> ffs_error::Result<InodeAttr> {
                unreachable!()
            }
            fn lookup(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _parent: InodeNumber,
                _name: &OsStr,
            ) -> ffs_error::Result<InodeAttr> {
                unreachable!()
            }
            fn readdir(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _ino: InodeNumber,
                _offset: u64,
            ) -> ffs_error::Result<FfsReaddirPage> {
                unreachable!()
            }
            fn read(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _ino: InodeNumber,
                _offset: u64,
                _size: u32,
            ) -> ffs_error::Result<Vec<u8>> {
                unreachable!()
            }
            fn readlink(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _ino: InodeNumber,
            ) -> ffs_error::Result<Vec<u8>> {
                unreachable!()
            }
        }
        let err = mount(Box::new(NeverCalledFs), "", &MountOptions::default()).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn mount_rejects_nonexistent_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(MinimalTestFs);
        let err = mount(
            ops,
            "/tmp/frankenfs_no_such_dir_xyzzy",
            &MountOptions::default(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "expected 'does not exist' in error: {err}"
        );
    }

    #[test]
    fn mount_background_rejects_nonexistent_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(MinimalTestFs);
        let err = mount_background(
            ops,
            "/tmp/frankenfs_no_such_dir_xyzzy",
            &MountOptions::default(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "expected 'does not exist' in error: {err}"
        );
    }

    #[test]
    fn mount_rejects_file_mountpoint() {
        let file_path = existing_file_mountpoint();
        let ops: Box<dyn FsOps> = Box::new(MinimalTestFs);
        let err = mount(ops, &file_path, &MountOptions::default()).unwrap_err();
        let err_text = err.to_string();
        assert!(
            err_text.contains("not a directory"),
            "expected 'not a directory' in error: {err_text}"
        );
    }

    #[test]
    fn mount_background_rejects_file_mountpoint() {
        let file_path = existing_file_mountpoint();
        let ops: Box<dyn FsOps> = Box::new(MinimalTestFs);
        let err = mount_background(ops, &file_path, &MountOptions::default()).unwrap_err();
        let err_text = err.to_string();
        assert!(
            err_text.contains("not a directory"),
            "expected 'not a directory' in error: {err_text}"
        );
    }

    #[test]
    fn franken_fuse_construction() {
        let _fuse = FrankenFuse::new(Box::new(MinimalTestFs));
        // Verify the Cx creation helper works.
        let _cx = FrankenFuse::cx_for_request();
    }

    #[test]
    fn encode_xattr_names_empty_is_empty_payload() {
        let encoded = FrankenFuse::encode_xattr_names(&[]);
        assert!(encoded.is_empty());
    }

    #[test]
    fn encode_xattr_names_produces_nul_separated_list() {
        let encoded = FrankenFuse::encode_xattr_names(&[
            "user.project".to_owned(),
            "security.selinux".to_owned(),
        ]);
        assert_eq!(encoded, b"user.project\0security.selinux\0");
    }

    #[test]
    fn classify_xattr_reply_size_probe_returns_size() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(0, 11),
            XattrReplyPlan::Size(11)
        );
    }

    #[test]
    fn classify_xattr_reply_data_when_buffer_fits() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(64, 32),
            XattrReplyPlan::Data
        );
    }

    #[test]
    fn classify_xattr_reply_erange_when_buffer_too_small() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(8, 32),
            XattrReplyPlan::Error(libc::ERANGE)
        );
    }

    #[test]
    fn classify_xattr_reply_eoverflow_for_oversized_payload() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(0, usize::MAX),
            XattrReplyPlan::Error(libc::EOVERFLOW)
        );
    }

    #[test]
    fn missing_xattr_errno_matches_platform() {
        #[cfg(target_os = "linux")]
        assert_eq!(FrankenFuse::missing_xattr_errno(), libc::ENODATA);

        #[cfg(not(target_os = "linux"))]
        assert_eq!(FrankenFuse::missing_xattr_errno(), libc::ENOATTR);
    }

    #[test]
    fn parse_setxattr_mode_defaults_to_set() {
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(0, 0).unwrap(),
            XattrSetMode::Set
        );
    }

    #[test]
    fn parse_setxattr_mode_accepts_create_and_replace_flags() {
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(XATTR_FLAG_CREATE, 0).unwrap(),
            XattrSetMode::Create
        );
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(XATTR_FLAG_REPLACE, 0).unwrap(),
            XattrSetMode::Replace
        );
    }

    #[test]
    fn parse_setxattr_mode_rejects_invalid_flag_combinations() {
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE, 0)
                .unwrap_err(),
            libc::EINVAL
        );
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(0x40, 0).unwrap_err(),
            libc::EINVAL
        );
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(XATTR_FLAG_CREATE, 1).unwrap_err(),
            libc::EINVAL
        );
    }

    #[test]
    fn parse_fiemap_request_reads_linux_header_layout() {
        let mut request = vec![0_u8; FIEMAP_HEADER_SIZE];
        let start = 4096_u64;
        let length = 16384_u64;
        let flags = FIEMAP_FLAG_SYNC;
        let mapped_extents = 7_u32;
        let extent_count = 3_u32;

        request[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8].copy_from_slice(&start.to_ne_bytes());
        request[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
            .copy_from_slice(&length.to_ne_bytes());
        request[FIEMAP_FLAGS_OFFSET..FIEMAP_FLAGS_OFFSET + 4].copy_from_slice(&flags.to_ne_bytes());
        request[FIEMAP_MAPPED_EXTENTS_OFFSET..FIEMAP_MAPPED_EXTENTS_OFFSET + 4]
            .copy_from_slice(&mapped_extents.to_ne_bytes());
        request[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
            .copy_from_slice(&extent_count.to_ne_bytes());

        let parsed = FrankenFuse::parse_fiemap_request(&request).expect("parse fiemap request");
        assert_eq!(parsed, (start, length, flags, extent_count));
    }

    #[test]
    fn encode_fiemap_response_writes_linux_header_offsets() {
        let extents = vec![
            FiemapExtent {
                logical: 0,
                physical: 8192,
                length: 4096,
                flags: 0,
            },
            FiemapExtent {
                logical: 4096,
                physical: 12288,
                length: 4096,
                flags: FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_UNWRITTEN,
            },
        ];

        let response = FrankenFuse::encode_fiemap_response(0, u64::MAX, 8, &extents, 4096);
        assert_eq!(
            u32::from_ne_bytes(
                response[FIEMAP_MAPPED_EXTENTS_OFFSET..FIEMAP_MAPPED_EXTENTS_OFFSET + 4]
                    .try_into()
                    .expect("mapped count bytes")
            ),
            2
        );
        assert_eq!(
            u32::from_ne_bytes(
                response[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
                    .try_into()
                    .expect("extent count bytes")
            ),
            8
        );
        let second_extent_offset = FIEMAP_HEADER_SIZE + FIEMAP_EXTENT_SIZE;
        assert_eq!(
            u32::from_ne_bytes(
                response[second_extent_offset + 40..second_extent_offset + 44]
                    .try_into()
                    .expect("extent flags")
            ),
            FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_UNWRITTEN
        );
    }

    #[test]
    fn encode_fiemap_response_writes_extent_logical_physical_length_fields() {
        // Distinct values so a logical/physical swap or a misplaced length fails.
        let extents = vec![FiemapExtent {
            logical: 0x1111,
            physical: 0x2222,
            length: 0x3333,
            flags: 0,
        }];
        let response = FrankenFuse::encode_fiemap_response(0, u64::MAX, 4, &extents, 4096);
        let off = FIEMAP_HEADER_SIZE;
        assert_eq!(
            u64::from_ne_bytes(response[off..off + 8].try_into().expect("logical")),
            0x1111,
            "logical at off"
        );
        assert_eq!(
            u64::from_ne_bytes(response[off + 8..off + 16].try_into().expect("physical")),
            0x2222,
            "physical at off+8"
        );
        assert_eq!(
            u64::from_ne_bytes(response[off + 16..off + 24].try_into().expect("length")),
            0x3333,
            "length at off+16"
        );
    }

    #[test]
    fn encode_fiemap_response_limits_extents_to_output_buffer_capacity() {
        let extents = vec![
            FiemapExtent {
                logical: 0,
                physical: 4096,
                length: 4096,
                flags: 0,
            },
            FiemapExtent {
                logical: 4096,
                physical: 8192,
                length: 4096,
                flags: 0,
            },
        ];

        let response = FrankenFuse::encode_fiemap_response(
            0,
            8192,
            2,
            &extents,
            u32::try_from(FIEMAP_HEADER_SIZE + FIEMAP_EXTENT_SIZE).expect("out_size"),
        );
        assert_eq!(response.len(), FIEMAP_HEADER_SIZE + FIEMAP_EXTENT_SIZE);
        assert_eq!(
            u32::from_ne_bytes(
                response[FIEMAP_MAPPED_EXTENTS_OFFSET..FIEMAP_MAPPED_EXTENTS_OFFSET + 4]
                    .try_into()
                    .expect("mapped count bytes")
            ),
            1
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum IoctlCall {
        Begin(RequestOp),
        Fiemap(InodeNumber, u64, u64),
        Fsync(InodeNumber, u64, bool),
        GetEncryptionPolicy(InodeNumber),
        GetEncryptionPolicyEx(InodeNumber),
        GetFlags(InodeNumber),
        GetState(InodeNumber),
        GetFsLabel,
        SetFsLabel(Vec<u8>),
        GetBtrfsFsInfo,
        BtrfsStartTransaction,
        BtrfsEndTransaction,
        BtrfsStartSync,
        BtrfsWaitSync(u64),
        BtrfsSetDefaultSubvol(u64),
        SetBtrfsFeatures(Vec<u8>),
        GetBtrfsDevInfo(u64, [u8; 16]),
        BtrfsTreeSearch(BtrfsTreeSearchKey),
        BtrfsInoLookup(u64, u64),
        BtrfsLogicalInoV2(u64, Vec<u8>),
        BtrfsQuotaRescanWait,
        BtrfsQuotaRescanStatus,
        BtrfsStartQuotaRescan(u64),
        BtrfsQuotaControl(u64, u64),
        BtrfsAssignQgroup(u64, u64, u64),
        BtrfsCreateQgroup(u64, u64),
        BtrfsLimitQgroup(BtrfsQgroupLimitRequest),
        BtrfsRemoveDeviceV2(Vec<u8>),
        BtrfsSnapDestroyV2(Vec<u8>),
        BtrfsAddDevice(Vec<u8>),
        BtrfsRemoveDevice(Vec<u8>),
        BtrfsForgetDevice(Vec<u8>),
        BtrfsResize(Vec<u8>),
        BtrfsDevReplace(Vec<u8>),
        Getattr(InodeNumber),
        Statfs(InodeNumber),
        GetVersion(InodeNumber),
        SetVersion(InodeNumber, u32),
        MoveExt(InodeNumber, u32, u64, u64, u64),
        RegisterMoveExtDonor(u32, InodeNumber),
        SetFlags(InodeNumber, u32),
        GetFsxattr(InodeNumber),
        SetFsxattr(InodeNumber, FsxattrInfo),
        FsUuid,
        FsSysfsPath,
        PrecacheExtents(InodeNumber),
        ClearEsCache(InodeNumber),
        TrimRange(u64, u64, u64),
        Commit,
        End(RequestOp),
        UnregisterMoveExtDonor(u32),
    }

    struct IoctlRecordingFs {
        encryption_policy: Option<[u8; FSCRYPT_POLICY_V1_SIZE]>,
        encryption_policy_ex: Option<(u8, Vec<u8>)>,
        encryption_policy_errno: Option<i32>,
        flags: u32,
        generation: u32,
        attr_kind: FfsFileType,
        attr_size: u64,
        blksize: u32,
        move_ext_result: Option<u64>,
        move_ext_errno: Option<i32>,
        register_move_ext_errno: Option<i32>,
        commit_errno: Option<i32>,
        fs_label: Vec<u8>,
        btrfs_fs_info: Option<Vec<u8>>,
        btrfs_dev_info: Option<Vec<u8>>,
        btrfs_tree_search_result: Option<(u32, Vec<u8>)>,
        btrfs_ino_lookup_result: Option<(u64, Vec<u8>)>,
        fiemap_fixture: Option<Vec<FiemapExtent>>,
        calls: Arc<Mutex<Vec<IoctlCall>>>,
    }

    impl IoctlRecordingFs {
        fn new(flags: u32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: None,
                encryption_policy_errno: None,
                flags,
                generation: 0,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize: 4096,
                move_ext_result: None,
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_generation(flags: u32, generation: u32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: None,
                encryption_policy_errno: None,
                flags,
                generation,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize: 4096,
                move_ext_result: None,
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_encryption_policy(
            policy: [u8; FSCRYPT_POLICY_V1_SIZE],
            calls: Arc<Mutex<Vec<IoctlCall>>>,
        ) -> Self {
            Self {
                encryption_policy: Some(policy),
                encryption_policy_ex: None,
                encryption_policy_errno: None,
                flags: 0,
                generation: 0,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize: 4096,
                move_ext_result: None,
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_encryption_policy_errno(errno: i32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: None,
                encryption_policy_errno: Some(errno),
                flags: 0,
                generation: 0,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize: 4096,
                move_ext_result: None,
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_move_ext_result(moved_len: u64, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: None,
                encryption_policy_errno: None,
                flags: EXT4_EXTENTS_FL,
                generation: 0,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize: 4096,
                move_ext_result: Some(moved_len),
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_move_ext_error(errno: i32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            let mut fs = Self::with_move_ext_result(0, calls);
            fs.move_ext_errno = Some(errno);
            fs
        }

        fn with_move_ext_register_error(errno: i32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            let mut fs = Self::with_move_ext_result(1, calls);
            fs.register_move_ext_errno = Some(errno);
            fs
        }

        fn with_move_ext_commit_error(errno: i32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            let mut fs = Self::with_move_ext_result(1, calls);
            fs.commit_errno = Some(errno);
            fs
        }

        fn with_move_ext_blksize(blksize: u32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: None,
                encryption_policy_errno: None,
                flags: EXT4_EXTENTS_FL,
                generation: 0,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize,
                move_ext_result: Some(1),
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_move_ext_source(
            kind: FfsFileType,
            size: u64,
            flags: u32,
            calls: Arc<Mutex<Vec<IoctlCall>>>,
        ) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: None,
                encryption_policy_errno: None,
                flags,
                generation: 0,
                attr_kind: kind,
                attr_size: size,
                blksize: 4096,
                move_ext_result: Some(1),
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_encryption_policy_ex(
            version: u8,
            policy: &[u8],
            calls: Arc<Mutex<Vec<IoctlCall>>>,
        ) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: Some((version, policy.to_vec())),
                encryption_policy_errno: None,
                flags: 0,
                generation: 0,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize: 4096,
                move_ext_result: None,
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_fs_label(label: &[u8], calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: None,
                encryption_policy_errno: None,
                flags: 0,
                generation: 0,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize: 4096,
                move_ext_result: None,
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: label.to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_btrfs_fs_info(payload: Vec<u8>, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: None,
                encryption_policy_errno: None,
                flags: 0,
                generation: 0,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize: 4096,
                move_ext_result: None,
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: Some(payload),
                btrfs_dev_info: None,
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_btrfs_dev_info(payload: Vec<u8>, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                encryption_policy: None,
                encryption_policy_ex: None,
                encryption_policy_errno: None,
                flags: 0,
                generation: 0,
                attr_kind: FfsFileType::RegularFile,
                attr_size: 64 * 1024,
                blksize: 4096,
                move_ext_result: None,
                move_ext_errno: None,
                register_move_ext_errno: None,
                commit_errno: None,
                fs_label: b"test_label\0".to_vec(),
                btrfs_fs_info: None,
                btrfs_dev_info: Some(payload),
                btrfs_tree_search_result: None,
                btrfs_ino_lookup_result: None,
                fiemap_fixture: None,
                calls,
            }
        }

        fn with_btrfs_tree_search(
            nr_items: u32,
            payload: Vec<u8>,
            calls: Arc<Mutex<Vec<IoctlCall>>>,
        ) -> Self {
            let mut fs = Self::new(0, calls);
            fs.btrfs_tree_search_result = Some((nr_items, payload));
            fs
        }

        fn with_fiemap_fixture(
            fiemap_fixture: Vec<FiemapExtent>,
            calls: Arc<Mutex<Vec<IoctlCall>>>,
        ) -> Self {
            let mut fs = Self::new(0, calls);
            fs.fiemap_fixture = Some(fiemap_fixture);
            fs
        }
    }

    fn flush_ioctl_trace_for_testing(fuse: &FrankenFuse) {
        fuse.inner
            .ioctl_trace
            .as_ref()
            .expect("ioctl trace configured")
            .flush_sync()
            .expect("ioctl trace flush_sync");
    }

    fn dispatch_ioctl_for_testing(
        fuse: &FrankenFuse,
        ino: u64,
        fh: u64,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
    ) -> IoctlResult {
        fuse.dispatch_ioctl(std::process::id(), ino, fh, cmd, in_data, out_size)
    }

    impl FsOps for IoctlRecordingFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Getattr(ino));
            Ok(InodeAttr {
                ino,
                size: self.attr_size,
                blocks: 0,
                atime: SystemTime::UNIX_EPOCH,
                mtime: SystemTime::UNIX_EPOCH,
                ctime: SystemTime::UNIX_EPOCH,
                crtime: SystemTime::UNIX_EPOCH,
                kind: self.attr_kind,
                perm: 0o644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: self.blksize,
                generation: 0,
            })
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("test fs miss".into()))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<FfsReaddirPage> {
            Ok(vec![].into())
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn statfs(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<FsStat> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Statfs(ino));
            Ok(FsStat {
                blocks: 4096,
                blocks_free: 1024,
                blocks_available: 768,
                files: 512,
                files_free: 256,
                block_size: self.blksize,
                name_max: 255,
                fragment_size: self.blksize,
            })
        }

        fn get_inode_flags(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<u32> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetFlags(ino));
            Ok(self.flags)
        }

        fn get_inode_state(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<u32> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetState(ino));
            Ok(0xA5A5_1234)
        }

        fn get_inode_fsxattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<FsxattrInfo> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetFsxattr(ino));
            // Synthesize a deterministic shape so the encoder test can
            // pin the on-the-wire byte layout.
            Ok(FsxattrInfo {
                xflags: 0x0000_8048, // IMMUTABLE (0x08) | NOATIME (0x40) | DAX (0x8000) bits
                extsize: 0,
                nextents: 5,
                projid: 0xCAFE_BABE,
                cowextsize: 0,
            })
        }

        fn set_inode_fsxattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            fsxattr_info: FsxattrInfo,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::SetFsxattr(ino, fsxattr_info));
            Ok(())
        }

        fn trim_range(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            start: u64,
            len: u64,
            min_len: u64,
        ) -> ffs_error::Result<u64> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::TrimRange(start, len, min_len));
            // Pretend the device discarded a third of the requested
            // range so the encoder regression can pin a non-zero
            // bytes-discarded value.
            Ok(len / 3)
        }

        fn fs_uuid(&self) -> ffs_error::Result<[u8; 16]> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::FsUuid);
            // Deterministic test fixture so the encoder regression can
            // pin the on-the-wire byte layout.
            Ok([
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x00,
            ])
        }

        fn fs_sysfs_path(&self) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::FsSysfsPath);
            // Deterministic non-empty fixture so the encoder regression
            // can pin both the len byte and the NUL-padded tail. The
            // production OpenFs override returns Vec::new() for both
            // ext4 and btrfs (no sysfs visibility through ByteDevice),
            // so a separate empty-path test exercises that contract.
            Ok(b"/sys/fs/frankenfs/fixture".to_vec())
        }

        fn precache_extents(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::PrecacheExtents(ino));
            Ok(())
        }

        fn clear_extent_status_cache(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::ClearEsCache(ino));
            Ok(())
        }

        fn get_inode_generation(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<u32> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetVersion(ino));
            Ok(self.generation)
        }

        fn set_inode_generation(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            generation: u32,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::SetVersion(ino, generation));
            Ok(())
        }

        fn get_encryption_policy_v1(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<[u8; FSCRYPT_POLICY_V1_SIZE]> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetEncryptionPolicy(ino));
            if let Some(errno) = self.encryption_policy_errno {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(errno)));
            }
            self.encryption_policy.ok_or_else(|| {
                FfsError::UnsupportedFeature("get_encryption_policy_v1 not configured".into())
            })
        }

        fn get_encryption_policy_ex(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<(u8, Vec<u8>)> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetEncryptionPolicyEx(ino));
            if let Some(errno) = self.encryption_policy_errno {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(errno)));
            }
            self.encryption_policy_ex
                .clone()
                .or_else(|| self.encryption_policy.map(|p| (0_u8, p.to_vec())))
                .ok_or_else(|| {
                    FfsError::UnsupportedFeature("get_encryption_policy_ex not configured".into())
                })
        }

        fn get_fs_label(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetFsLabel);
            Ok(self.fs_label.clone())
        }

        fn set_fs_label(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            label: &[u8],
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::SetFsLabel(label.to_vec()));
            Ok(())
        }

        fn get_btrfs_fs_info(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
        ) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetBtrfsFsInfo);
            self.btrfs_fs_info.clone().ok_or_else(|| {
                FfsError::UnsupportedFeature(
                    "get_btrfs_fs_info: recorder not configured with a payload".into(),
                )
            })
        }

        fn btrfs_start_sync(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<u64> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsStartSync);
            Ok(0xCAFE_BABE_DEAD_BEEF)
        }

        fn btrfs_wait_sync(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            transid: u64,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsWaitSync(transid));
            Ok(())
        }

        fn btrfs_set_default_subvol(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            treeid: u64,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsSetDefaultSubvol(treeid));
            Ok(())
        }

        fn btrfs_start_transaction(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsStartTransaction);
            Ok(())
        }

        fn btrfs_end_transaction(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsEndTransaction);
            Ok(())
        }

        fn btrfs_ino_lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            treeid: u64,
            objectid: u64,
        ) -> ffs_error::Result<(u64, Vec<u8>)> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsInoLookup(treeid, objectid));
            self.btrfs_ino_lookup_result.clone().ok_or_else(|| {
                FfsError::UnsupportedFeature(
                    "btrfs_ino_lookup: recorder not configured with a result".into(),
                )
            })
        }

        fn btrfs_wait_quota_rescan(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsQuotaRescanWait);
            Ok(())
        }

        fn btrfs_quota_rescan_status(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
        ) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsQuotaRescanStatus);
            Ok(vec![0xAB; BTRFS_QUOTA_RESCAN_ARGS_SIZE as usize])
        }

        fn btrfs_start_quota_rescan(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            flags: u64,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsStartQuotaRescan(flags));
            Ok(())
        }

        fn btrfs_quota_control(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            cmd: u64,
            status: u64,
        ) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsQuotaControl(cmd, status));
            let mut data = Vec::with_capacity(BTRFS_QUOTA_CTL_ARGS_SIZE as usize);
            data.extend_from_slice(&cmd.to_le_bytes());
            data.extend_from_slice(&(status | 0x10).to_le_bytes());
            Ok(data)
        }

        fn btrfs_assign_qgroup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            assign: u64,
            src: u64,
            dst: u64,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsAssignQgroup(assign, src, dst));
            Ok(())
        }

        fn btrfs_create_qgroup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            create: u64,
            qgroupid: u64,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsCreateQgroup(create, qgroupid));
            Ok(())
        }

        fn btrfs_limit_qgroup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            limit: BtrfsQgroupLimitRequest,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsLimitQgroup(limit));
            Ok(())
        }

        fn set_btrfs_features(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            feature_flags: &[u8],
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::SetBtrfsFeatures(feature_flags.to_vec()));
            Ok(())
        }

        fn btrfs_rm_dev_v2(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            vol_args: &[u8],
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsRemoveDeviceV2(vol_args.to_vec()));
            Ok(())
        }

        fn get_btrfs_logical_ino_v2(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            logical: u64,
            args: &[u8],
        ) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsLogicalInoV2(logical, args.to_vec()));
            Ok(vec![0_u8; 16])
        }

        fn btrfs_snap_destroy_v2(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            vol_args: &[u8],
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsSnapDestroyV2(vol_args.to_vec()));
            Ok(())
        }

        fn btrfs_add_dev(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            vol_args: &[u8],
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsAddDevice(vol_args.to_vec()));
            Ok(())
        }

        fn btrfs_rm_dev(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            vol_args: &[u8],
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsRemoveDevice(vol_args.to_vec()));
            Ok(())
        }

        fn btrfs_forget_dev(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            vol_args: &[u8],
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsForgetDevice(vol_args.to_vec()));
            Ok(())
        }

        fn btrfs_resize(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            args: &[u8],
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsResize(args.to_vec()));
            Ok(())
        }

        fn btrfs_dev_replace(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            args: &[u8],
        ) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsDevReplace(args.to_vec()));
            Ok(vec![0_u8; BTRFS_DEV_REPLACE_ARGS_SIZE as usize])
        }

        fn get_btrfs_dev_info(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            devid_in: u64,
            uuid_in: [u8; 16],
        ) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetBtrfsDevInfo(devid_in, uuid_in));
            self.btrfs_dev_info.clone().ok_or_else(|| {
                FfsError::UnsupportedFeature(
                    "get_btrfs_dev_info: recorder not configured with a payload".into(),
                )
            })
        }

        fn btrfs_tree_search(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            key: BtrfsTreeSearchKey,
        ) -> ffs_error::Result<(u32, Vec<u8>)> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::BtrfsTreeSearch(key));
            self.btrfs_tree_search_result.clone().ok_or_else(|| {
                FfsError::UnsupportedFeature(
                    "btrfs_tree_search: recorder not configured with a result".into(),
                )
            })
        }

        fn fiemap(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            start: u64,
            length: u64,
        ) -> ffs_error::Result<Vec<FiemapExtent>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Fiemap(ino, start, length));
            Ok(self.fiemap_fixture.clone().unwrap_or_default())
        }

        fn fsync(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            fh: u64,
            datasync: bool,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Fsync(ino, fh, datasync));
            Ok(())
        }

        fn set_inode_flags(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            flags: u32,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::SetFlags(ino, flags));
            Ok(())
        }

        fn move_ext(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            donor_fd: u32,
            orig_start: u64,
            donor_start: u64,
            len: u64,
        ) -> ffs_error::Result<u64> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::MoveExt(
                    ino,
                    donor_fd,
                    orig_start,
                    donor_start,
                    len,
                ));
            if let Some(errno) = self.move_ext_errno {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(errno)));
            }
            Ok(self.move_ext_result.unwrap_or(len))
        }

        fn register_move_ext_donor_fd(
            &self,
            donor_fd: u32,
            donor_ino: InodeNumber,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::RegisterMoveExtDonor(donor_fd, donor_ino));
            if let Some(errno) = self.register_move_ext_errno {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(errno)));
            }
            Ok(())
        }

        fn unregister_move_ext_donor_fd(&self, donor_fd: u32) {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::UnregisterMoveExtDonor(donor_fd));
        }

        fn begin_request_scope(&self, _cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Begin(op));
            Ok(RequestScope::empty())
        }

        fn end_request_scope(
            &self,
            _cx: &Cx,
            op: RequestOp,
            _scope: RequestScope,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::End(op));
            Ok(())
        }

        fn commit_request_scope(&self, _scope: &mut RequestScope) -> ffs_error::Result<CommitSeq> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Commit);
            if let Some(errno) = self.commit_errno {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(errno)));
            }
            Ok(CommitSeq(1))
        }
    }

    #[test]
    fn dispatch_ioctl_fsgetxattr_encodes_28_byte_struct_in_native_endian() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0x1234_5678,
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 17, 0, FS_IOC_FSGETXATTR, &[], 28);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected IoctlResult::Data, got {response:?}"
        );
        let IoctlResult::Data(bytes) = response else {
            return;
        };
        assert_eq!(bytes.len(), 28, "fsxattr struct is exactly 28 bytes");

        // Field-by-field native-endian decode mirroring uapi/linux/fs.h.
        let xflags = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let extsize = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        let nextents = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let projid = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        let cowextsize = u32::from_ne_bytes(bytes[16..20].try_into().unwrap());
        let pad = &bytes[20..28];
        assert_eq!(xflags, 0x0000_8048);
        assert_eq!(extsize, 0);
        assert_eq!(nextents, 5);
        assert_eq!(projid, 0xCAFE_BABE);
        assert_eq!(cowextsize, 0);
        assert_eq!(pad, &[0_u8; 8], "fsx_pad[8] must be zero-filled");

        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetFsxattr(InodeNumber(17)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getstate_encodes_u32_state_in_native_endian() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 29, 0, EXT4_IOC_GETSTATE, &[], 4);
        assert_eq!(
            response,
            IoctlResult::Data(0xA5A5_1234_u32.to_ne_bytes().to_vec())
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetState(InodeNumber(29)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getstate_short_output_returns_einval() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));
        let response = dispatch_ioctl_for_testing(&fuse, 29, 0, EXT4_IOC_GETSTATE, &[], 3);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_fibmap_short_input_returns_einval() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));
        // 3 bytes < FIBMAP_SIZE (4).
        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FIBMAP, &[0, 0, 0], 4);
        assert!(
            matches!(response, IoctlResult::Error(libc::EINVAL)),
            "short input must surface EINVAL, got {response:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_fibmap_short_output_returns_einval() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));
        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FIBMAP, &0_u32.to_ne_bytes(), 3);
        assert!(
            matches!(response, IoctlResult::Error(libc::EINVAL)),
            "short out_size must surface EINVAL, got {response:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_fibmap_maps_written_extent_physical_block() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fixture = vec![FiemapExtent {
            logical: 8192,
            physical: 32768,
            length: 4096,
            flags: FIEMAP_EXTENT_LAST,
        }];
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_fiemap_fixture(
            fixture,
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 17, 0, FIBMAP, &2_u32.to_ne_bytes(), 4);
        assert_eq!(response, IoctlResult::Data(8_u32.to_ne_bytes().to_vec()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::Statfs(InodeNumber(17)),
                IoctlCall::Fiemap(InodeNumber(17), 8192, 4096),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_fibmap_uses_statfs_block_size() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fixture = vec![FiemapExtent {
            logical: 2048,
            physical: 5120,
            length: 1024,
            flags: FIEMAP_EXTENT_LAST,
        }];
        let mut recorder = IoctlRecordingFs::with_fiemap_fixture(fixture, Arc::clone(&calls));
        recorder.blksize = 1024;
        let fuse = FrankenFuse::new(Box::new(recorder));

        let response = dispatch_ioctl_for_testing(&fuse, 23, 0, FIBMAP, &2_u32.to_ne_bytes(), 4);
        assert_eq!(response, IoctlResult::Data(5_u32.to_ne_bytes().to_vec()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::Statfs(InodeNumber(23)),
                IoctlCall::Fiemap(InodeNumber(23), 2048, 1024),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_fibmap_zero_statfs_block_size_returns_einval() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fixture = vec![FiemapExtent {
            logical: 0,
            physical: 0,
            length: 4096,
            flags: FIEMAP_EXTENT_LAST,
        }];
        let mut recorder = IoctlRecordingFs::with_fiemap_fixture(fixture, Arc::clone(&calls));
        recorder.blksize = 0;
        let fuse = FrankenFuse::new(Box::new(recorder));

        let response = dispatch_ioctl_for_testing(&fuse, 31, 0, FIBMAP, &0_u32.to_ne_bytes(), 4);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::Statfs(InodeNumber(31)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_fibmap_unwritten_extent_returns_hole_zero() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fixture = vec![FiemapExtent {
            logical: 4096,
            physical: 16384,
            length: 4096,
            flags: FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_UNWRITTEN,
        }];
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_fiemap_fixture(
            fixture,
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 19, 0, FIBMAP, &1_u32.to_ne_bytes(), 4);
        assert_eq!(response, IoctlResult::Data(0_u32.to_ne_bytes().to_vec()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::Statfs(InodeNumber(19)),
                IoctlCall::Fiemap(InodeNumber(19), 4096, 4096),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_fitrim_round_trips_24_byte_struct_writing_back_bytes_discarded() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        // start=4096, len=12_288, min_len=4096
        let mut req = Vec::with_capacity(24);
        req.extend_from_slice(&4096_u64.to_ne_bytes());
        req.extend_from_slice(&12_288_u64.to_ne_bytes());
        req.extend_from_slice(&4096_u64.to_ne_bytes());

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FITRIM, &req, 24);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected IoctlResult::Data, got {response:?}"
        );
        let IoctlResult::Data(reply) = response else {
            return;
        };
        assert_eq!(reply.len(), 24);
        let start = u64::from_ne_bytes(reply[0..8].try_into().unwrap());
        let len = u64::from_ne_bytes(reply[8..16].try_into().unwrap());
        let min_len = u64::from_ne_bytes(reply[16..24].try_into().unwrap());
        assert_eq!(start, 4096, "FITRIM must echo start unchanged");
        assert_eq!(
            len,
            12_288 / 3,
            "FITRIM rewrites len with bytes_discarded (test helper returns len/3)"
        );
        assert_eq!(min_len, 4096, "FITRIM must echo minlen unchanged");

        let trace = calls.lock().expect("lock ioctl calls").clone();
        assert!(
            trace
                .iter()
                .any(|c| matches!(c, IoctlCall::TrimRange(4096, 12_288, 4096))),
            "must record TrimRange call: {trace:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_fitrim_short_input_returns_einval() {
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FITRIM, &[0_u8; 23], 24);
        assert!(
            matches!(response, IoctlResult::Error(libc::EINVAL)),
            "23-byte input must surface EINVAL, got {response:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_fitrim_read_only_mount_returns_erofs() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));
        let req = vec![0_u8; 24];
        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FITRIM, &req, 24);
        assert!(
            matches!(response, IoctlResult::Error(libc::EROFS)),
            "read-only mount must reject FITRIM with EROFS, got {response:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_getfsuuid_encodes_17_byte_struct() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FS_IOC_GETFSUUID, &[], 17);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected IoctlResult::Data, got {response:?}"
        );
        let IoctlResult::Data(bytes) = response else {
            return;
        };
        assert_eq!(bytes.len(), 17, "fsuuid2 struct is exactly 17 bytes");
        assert_eq!(bytes[0], 16, "fsuuid2.len must be 16 for ext4 + btrfs");
        assert_eq!(
            &bytes[1..17],
            &[
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x00,
            ]
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[IoctlCall::FsUuid]
        );
    }

    #[test]
    fn dispatch_ioctl_getfsuuid_short_buffer_returns_einval() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));
        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FS_IOC_GETFSUUID, &[], 16);
        assert!(
            matches!(response, IoctlResult::Error(libc::EINVAL)),
            "out_size < 17 must surface EINVAL, got {response:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_getfssysfspath_encodes_129_byte_struct_with_fixture_path() {
        // bd-04xv6: round-trip a non-empty backend path through the
        // FS_IOC_GETFSSYSFSPATH wire format. The IoctlRecordingFs fixture
        // hands us "/sys/fs/frankenfs/fixture" (25 bytes); the encoder
        // must emit len=25 + the path + NUL padding for a total of 129.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FS_IOC_GETFSSYSFSPATH, &[], 129);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected IoctlResult::Data, got {response:?}"
        );
        let IoctlResult::Data(bytes) = response else {
            return;
        };
        assert_eq!(
            bytes.len(),
            129,
            "fs_sysfs_path struct is exactly 129 bytes (1 len + 128 name)"
        );
        let expected_path = b"/sys/fs/frankenfs/fixture";
        let expected_len = u8::try_from(expected_path.len()).expect("fixture <= 128 bytes");
        assert_eq!(bytes[0], expected_len);
        assert_eq!(&bytes[1..=expected_path.len()], expected_path);
        // Tail must be NUL-padded.
        assert!(
            bytes[expected_path.len() + 1..].iter().all(|&b| b == 0),
            "name field tail must be NUL-padded"
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[IoctlCall::FsSysfsPath]
        );
    }

    #[test]
    fn encode_fs_sysfs_path_response_empty_path_encodes_len_zero_with_nul_padding() {
        // bd-04xv6: prove the empty-path encoding (the production
        // OpenFs default for both ext4 and btrfs since a userspace
        // FUSE backend has no /sys entry to surface) round-trips as
        // len=0 + 128 zero bytes. Userspace probes treat this as
        // "no sysfs visibility" and skip silently.
        let buf = FrankenFuse::encode_fs_sysfs_path_response(&[]).expect("encode empty path");
        assert_eq!(buf.len(), 129);
        assert_eq!(buf[0], 0, "len byte must be 0 for empty backend path");
        assert!(
            buf[1..].iter().all(|&b| b == 0),
            "all 128 name bytes must be NUL when backend reports no path"
        );
    }

    #[test]
    fn dispatch_ioctl_getfssysfspath_short_buffer_returns_einval() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));
        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FS_IOC_GETFSSYSFSPATH, &[], 128);
        assert!(
            matches!(response, IoctlResult::Error(libc::EINVAL)),
            "out_size < 129 must surface EINVAL, got {response:?}"
        );
    }

    #[test]
    fn encode_fs_sysfs_path_response_rejects_overlong_path_with_einval() {
        // The 128-byte name field cannot accommodate a 129-byte path;
        // backends that try to surface one must surface EINVAL through
        // the dispatcher rather than truncating silently.
        let too_long = vec![b'/'; 129];
        let err = FrankenFuse::encode_fs_sysfs_path_response(&too_long).unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }

    #[test]
    fn encode_fs_sysfs_path_response_accepts_max_length_path() {
        // 128-byte path fills the name field exactly; len=128, no padding.
        let max = vec![b'a'; 128];
        let buf = FrankenFuse::encode_fs_sysfs_path_response(&max).expect("encode 128-byte path");
        assert_eq!(buf.len(), 129);
        assert_eq!(buf[0], 128);
        assert!(buf[1..].iter().all(|&b| b == b'a'));
    }

    #[test]
    fn dispatch_ioctl_precache_extents_routes_to_fsops_with_empty_reply() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 42, 0, EXT4_IOC_PRECACHE_EXTENTS, &[], 0);
        assert_eq!(
            response,
            IoctlResult::Data(Vec::new()),
            "PRECACHE_EXTENTS returns success with no payload, got {response:?}"
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::PrecacheExtents(InodeNumber(42)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_precache_extents_ignores_input_payload_and_out_size() {
        // _IO ioctls have no payload; the kernel still accepts buffers
        // of any size because they're never read or written. Our
        // dispatcher must mirror that: don't reject on non-zero
        // in_data length or non-zero out_size, just route through.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            7,
            0,
            EXT4_IOC_PRECACHE_EXTENTS,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            64,
        );
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::PrecacheExtents(InodeNumber(7)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_clear_es_cache_routes_to_fsops_with_empty_reply() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 91, 0, EXT4_IOC_CLEAR_ES_CACHE, &[], 0);
        assert_eq!(
            response,
            IoctlResult::Data(Vec::new()),
            "CLEAR_ES_CACHE returns success with no payload, got {response:?}"
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::ClearEsCache(InodeNumber(91)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_clear_es_cache_ignores_input_payload_and_out_size() {
        // _IO has no payload; the dispatcher must accept any in_data
        // length or out_size and never read either, matching the
        // kernel's `_IO` contract.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            13,
            0,
            EXT4_IOC_CLEAR_ES_CACHE,
            &[0xCA, 0xFE, 0xBA, 0xBE, 0x00],
            128,
        );
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::ClearEsCache(InodeNumber(13)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getstate_encodes_4_byte_u32_reply() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 73, 0, EXT4_IOC_GETSTATE, &[], 4);
        assert_eq!(
            response,
            IoctlResult::Data(0xA5A5_1234_u32.to_ne_bytes().to_vec()),
            "GETSTATE returns the host-native u32 fixture, got {response:?}"
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetState(InodeNumber(73)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getstate_short_buffer_returns_einval() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, EXT4_IOC_GETSTATE, &[], 3);
        assert!(
            matches!(response, IoctlResult::Error(libc::EINVAL)),
            "out_size < 4 must surface EINVAL, got {response:?}"
        );
        // Bail before backend dispatch — no GetState recorded.
        let trace = calls.lock().expect("lock ioctl calls").clone();
        assert!(
            !trace.iter().any(|c| matches!(c, IoctlCall::GetState(_))),
            "must not call FsOps::get_inode_state on a short buffer: {trace:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_fssetxattr_decodes_28_byte_payload_and_routes_to_fsops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0x1234_5678, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        // Build the 28-byte struct: xflags=IMMUTABLE|NOATIME|HASATTR
        // (kernel sometimes ships HASATTR back through SET — our
        // backend will reject it, but the dispatcher must still parse
        // the buffer cleanly), projid=0x1234_5678.
        let mut buf = Vec::with_capacity(28);
        buf.extend_from_slice(&0x0000_0048_u32.to_ne_bytes()); // xflags
        buf.extend_from_slice(&0_u32.to_ne_bytes()); // extsize
        buf.extend_from_slice(&0_u32.to_ne_bytes()); // nextents (kernel zero)
        buf.extend_from_slice(&0x1234_5678_u32.to_ne_bytes()); // projid
        buf.extend_from_slice(&0_u32.to_ne_bytes()); // cowextsize
        buf.extend_from_slice(&[0_u8; 8]); // pad

        let response = dispatch_ioctl_for_testing(&fuse, 19, 0, FS_IOC_FSSETXATTR, &buf, 0);
        assert!(
            matches!(response, IoctlResult::Data(ref data) if data.is_empty()),
            "set ioctl returns empty data on success, got {response:?}"
        );

        let trace = calls.lock().expect("lock ioctl calls").clone();
        let set_call = trace
            .iter()
            .find(|c| matches!(c, IoctlCall::SetFsxattr(InodeNumber(19), _)))
            .expect("must record SetFsxattr trace");
        let IoctlCall::SetFsxattr(_, info) = set_call else {
            unreachable!()
        };
        assert_eq!(info.xflags, 0x0000_0048);
        assert_eq!(info.projid, 0x1234_5678);
        assert_eq!(
            info.nextents, 0,
            "parser must zero fsx_nextents on the SET path (kernel-set field)"
        );
        // Commit must follow on the write path so the MVCC scope is durable.
        assert!(
            trace.iter().any(|c| matches!(c, IoctlCall::Commit)),
            "FS_IOC_FSSETXATTR must commit the request scope, trace: {trace:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_fssetxattr_short_buffer_returns_einval() {
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FS_IOC_FSSETXATTR, &[0_u8; 27], 0);
        assert!(
            matches!(response, IoctlResult::Error(libc::EINVAL)),
            "27-byte buffer must surface EINVAL, got {response:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_fssetxattr_read_only_mount_returns_erofs() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));
        let buf = vec![0_u8; 28];
        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, FS_IOC_FSSETXATTR, &buf, 0);
        assert!(
            matches!(response, IoctlResult::Error(libc::EROFS)),
            "read-only mount must reject FS_IOC_FSSETXATTR with EROFS, got {response:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_fsgetxattr_rejects_too_small_output_buffer() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0x1234_5678,
            Arc::new(Mutex::new(Vec::new())),
        )));

        // 27 bytes < FS_IOC_FSGETXATTR_SIZE (28).
        let response = dispatch_ioctl_for_testing(&fuse, 17, 0, FS_IOC_FSGETXATTR, &[], 27);
        assert!(
            matches!(response, IoctlResult::Error(libc::EINVAL)),
            "short out_size must surface EINVAL, got {response:?}"
        );
    }

    #[test]
    fn dispatch_ioctl_getflags_encodes_u32_response_for_fileattr_path() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0x1234_5678,
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 11, 0, EXT4_IOC_GETFLAGS, &[], 4);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected ioctl data response"
        );
        let IoctlResult::Data(bytes) = response else {
            unreachable!("asserted IoctlResult::Data above");
        };
        assert_eq!(bytes.len(), 4);
        assert_eq!(
            u32::from_ne_bytes(bytes.try_into().expect("4-byte ioctl payload")),
            0x1234_5678_u32
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetFlags(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getflags_rejects_too_small_output_buffer() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0x1234_5678,
            Arc::new(Mutex::new(Vec::new())),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 11, 0, EXT4_IOC_GETFLAGS, &[], 3);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_getversion_encodes_u32_response_for_inode_generation() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_generation(
            0,
            0xDEAD_BEEF,
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 11, 0, EXT4_IOC_GETVERSION, &[], 4);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected ioctl data response"
        );
        let IoctlResult::Data(bytes) = response else {
            unreachable!("asserted IoctlResult::Data above");
        };
        assert_eq!(bytes.len(), 4);
        assert_eq!(
            u32::from_ne_bytes(bytes.try_into().expect("4-byte ioctl payload")),
            0xDEAD_BEEF_u32
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetVersion(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getversion_rejects_too_small_output_buffer() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_generation(
            0,
            7,
            Arc::new(Mutex::new(Vec::new())),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 11, 0, EXT4_IOC_GETVERSION, &[], 3);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_setversion_passes_generation_to_backend_and_commits() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &options,
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            11,
            0,
            EXT4_IOC_SETVERSION,
            &0x2468_ACED_u32.to_ne_bytes(),
            0,
        );
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::SetVersion(InodeNumber(11), 0x2468_ACED),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_setversion_rejects_too_small_input_buffer() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );

        let response =
            dispatch_ioctl_for_testing(&fuse, 11, 0, EXT4_IOC_SETVERSION, &[0x01, 0x02, 0x03], 0);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_encodes_v1_payload() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let policy = [0, 1, 4, 0, b'm', b'k', b'd', b'e', b's', b'c', b'4', b'2'];
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy(
            policy,
            Arc::clone(&calls),
        )));

        let response =
            dispatch_ioctl_for_testing(&fuse, 11, 0, FS_IOC_GET_ENCRYPTION_POLICY, &[], 12);
        assert_eq!(response, IoctlResult::Data(policy.to_vec()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetEncryptionPolicy(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_accepts_legacy_iow_request_shape() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let policy = [0, 1, 4, 0, b'm', b'k', b'd', b'e', b's', b'c', b'4', b'2'];
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy(
            policy,
            Arc::clone(&calls),
        )));

        let request_buffer = [0_u8; FSCRYPT_POLICY_V1_SIZE];
        let response = dispatch_ioctl_for_testing(
            &fuse,
            11,
            0,
            FS_IOC_GET_ENCRYPTION_POLICY,
            &request_buffer,
            0,
        );
        assert_eq!(response, IoctlResult::Data(policy.to_vec()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetEncryptionPolicy(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_rejects_too_small_output_buffer() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy(
            [0; FSCRYPT_POLICY_V1_SIZE],
            Arc::new(Mutex::new(Vec::new())),
        )));

        let response =
            dispatch_ioctl_for_testing(&fuse, 11, 0, FS_IOC_GET_ENCRYPTION_POLICY, &[], 11);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_propagates_enodata() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy_errno(
            libc::ENODATA,
            Arc::clone(&calls),
        )));

        let response =
            dispatch_ioctl_for_testing(&fuse, 11, 0, FS_IOC_GET_ENCRYPTION_POLICY, &[], 12);
        assert_eq!(response, IoctlResult::Error(libc::ENODATA));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetEncryptionPolicy(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getfslabel_returns_label_in_256_byte_buffer() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_fs_label(
            b"frankenfs_test\0",
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 2, 0, FS_IOC_GETFSLABEL, &[], 256);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected ioctl data response"
        );
        let IoctlResult::Data(bytes) = response else {
            unreachable!("asserted IoctlResult::Data above");
        };
        assert_eq!(bytes.len(), 256);
        let label_end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        assert_eq!(&bytes[..label_end], b"frankenfs_test");
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetFsLabel,
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getfslabel_rejects_too_small_output_buffer() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_fs_label(
            b"test\0",
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 2, 0, FS_IOC_GETFSLABEL, &[], 255);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_setfslabel_passes_label_to_backend_and_commits() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let requested = b"ffs-renamed";
        let mut buffer = vec![0_u8; FSLABEL_MAX];
        buffer[..requested.len()].copy_from_slice(requested);
        buffer[requested.len()] = 0;

        let response = dispatch_ioctl_for_testing(&fuse, 2, 0, FS_IOC_SETFSLABEL, &buffer, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::SetFsLabel(requested.to_vec()),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_setfslabel_rejects_non_terminated_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response =
            dispatch_ioctl_for_testing(&fuse, 2, 0, FS_IOC_SETFSLABEL, b"not-terminated", 0);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_start_sync_returns_transid() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_START_SYNC, &[], 8);
        assert_eq!(
            response,
            IoctlResult::Data(0xCAFE_BABE_DEAD_BEEF_u64.to_ne_bytes().to_vec())
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::Fsync),
                IoctlCall::BtrfsStartSync,
                IoctlCall::End(RequestOp::Fsync),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_start_sync_rejects_short_output_buffer() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_START_SYNC, &[], 7);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_wait_sync_passes_transid() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let transid = 0x0123_4567_89AB_CDEF_u64;

        let response =
            dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_WAIT_SYNC, &transid.to_ne_bytes(), 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::Fsync),
                IoctlCall::BtrfsWaitSync(transid),
                IoctlCall::End(RequestOp::Fsync),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_wait_sync_rejects_short_input_buffer() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_WAIT_SYNC, &[0_u8; 7], 0);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_default_subvol_passes_treeid_and_commits() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let treeid = 0x0102_0304_0506_0708_u64;

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_DEFAULT_SUBVOL,
            &treeid.to_ne_bytes(),
            0,
        );
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsSetDefaultSubvol(treeid),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_default_subvol_rejects_short_input_buffer() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response =
            dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_DEFAULT_SUBVOL, &[0_u8; 7], 0);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_quota_rescan_wait_uses_read_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_QUOTA_RESCAN_WAIT, &[], 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::BtrfsQuotaRescanWait,
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_quota_rescan_status_uses_read_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QUOTA_RESCAN_STATUS,
            &[],
            BTRFS_QUOTA_RESCAN_ARGS_SIZE,
        );
        assert_eq!(
            response,
            IoctlResult::Data(vec![0xAB; BTRFS_QUOTA_RESCAN_ARGS_SIZE as usize])
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::BtrfsQuotaRescanStatus,
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_quota_rescan_status_rejects_short_output() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QUOTA_RESCAN_STATUS,
            &[],
            BTRFS_QUOTA_RESCAN_ARGS_SIZE - 1,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_quota_rescan_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = vec![0_u8; BTRFS_QUOTA_RESCAN_ARGS_SIZE as usize];
        input[0..8].copy_from_slice(&0xA5A5_u64.to_le_bytes());

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_QUOTA_RESCAN, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsStartQuotaRescan(0xA5A5),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_quota_rescan_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QUOTA_RESCAN,
            &[0_u8; BTRFS_QUOTA_RESCAN_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_quota_rescan_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_QUOTA_RESCAN_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_QUOTA_RESCAN, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_quota_ctl_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = Vec::with_capacity(BTRFS_QUOTA_CTL_ARGS_SIZE as usize);
        input.extend_from_slice(&4_u64.to_le_bytes());
        input.extend_from_slice(&0x20_u64.to_le_bytes());

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QUOTA_CTL,
            &input,
            BTRFS_QUOTA_CTL_ARGS_SIZE,
        );
        let mut expected = Vec::with_capacity(BTRFS_QUOTA_CTL_ARGS_SIZE as usize);
        expected.extend_from_slice(&4_u64.to_le_bytes());
        expected.extend_from_slice(&0x30_u64.to_le_bytes());
        assert_eq!(response, IoctlResult::Data(expected));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsQuotaControl(4, 0x20),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_quota_ctl_rejects_short_input_or_output() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let input = vec![0_u8; BTRFS_QUOTA_CTL_ARGS_SIZE as usize];

        let short_input = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QUOTA_CTL,
            &input[..BTRFS_QUOTA_CTL_ARGS_SIZE as usize - 1],
            BTRFS_QUOTA_CTL_ARGS_SIZE,
        );
        assert_eq!(short_input, IoctlResult::Error(libc::EINVAL));

        let short_output = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QUOTA_CTL,
            &input,
            BTRFS_QUOTA_CTL_ARGS_SIZE - 1,
        );
        assert_eq!(short_output, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_quota_ctl_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_QUOTA_CTL_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QUOTA_CTL,
            &input,
            BTRFS_QUOTA_CTL_ARGS_SIZE,
        );
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_qgroup_assign_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = Vec::with_capacity(BTRFS_QGROUP_ASSIGN_ARGS_SIZE as usize);
        input.extend_from_slice(&1_u64.to_le_bytes());
        input.extend_from_slice(&256_u64.to_le_bytes());
        input.extend_from_slice(&257_u64.to_le_bytes());

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_QGROUP_ASSIGN, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsAssignQgroup(1, 256, 257),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_qgroup_assign_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QGROUP_ASSIGN,
            &[0_u8; BTRFS_QGROUP_ASSIGN_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_qgroup_assign_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_QGROUP_ASSIGN_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_QGROUP_ASSIGN, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_qgroup_create_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = Vec::with_capacity(BTRFS_QGROUP_CREATE_ARGS_SIZE as usize);
        input.extend_from_slice(&1_u64.to_le_bytes());
        input.extend_from_slice(&256_u64.to_le_bytes());

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_QGROUP_CREATE, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsCreateQgroup(1, 256),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_qgroup_create_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QGROUP_CREATE,
            &[0_u8; BTRFS_QGROUP_CREATE_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_qgroup_create_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_QGROUP_CREATE_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_QGROUP_CREATE, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_qgroup_limit_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let expected = BtrfsQgroupLimitRequest {
            qgroupid: 256,
            flags: 0x3,
            max_rfer: 10,
            max_excl: 11,
            rsv_rfer: 12,
            rsv_excl: 13,
        };
        let mut input = Vec::with_capacity(BTRFS_QGROUP_LIMIT_ARGS_SIZE as usize);
        for field in [
            expected.qgroupid,
            expected.flags,
            expected.max_rfer,
            expected.max_excl,
            expected.rsv_rfer,
            expected.rsv_excl,
        ] {
            input.extend_from_slice(&field.to_le_bytes());
        }

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_QGROUP_LIMIT, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsLimitQgroup(expected),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_qgroup_limit_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_QGROUP_LIMIT,
            &[0_u8; BTRFS_QGROUP_LIMIT_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_qgroup_limit_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_QGROUP_LIMIT_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_QGROUP_LIMIT, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_snap_destroy_v2_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];
        input[16..24].copy_from_slice(&256_u64.to_le_bytes());
        input[64..68].copy_from_slice(b"snap");

        let response =
            dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_SNAP_DESTROY_V2, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsSnapDestroyV2(input),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_snap_destroy_v2_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_SNAP_DESTROY_V2,
            &[0_u8; BTRFS_VOL_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_snap_destroy_v2_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];

        let response =
            dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_SNAP_DESTROY_V2, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_rm_dev_v2_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];
        input[16..24].copy_from_slice(&1_u64.to_le_bytes()); // flags: by-name path
        input[64..70].copy_from_slice(b"dev-sd");

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_RM_DEV_V2, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsRemoveDeviceV2(input),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_rm_dev_v2_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_RM_DEV_V2,
            &[0_u8; BTRFS_VOL_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_rm_dev_v2_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_RM_DEV_V2, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_add_dev_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];
        input[0..10].copy_from_slice(b"/dev/loop0");

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_ADD_DEV, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsAddDevice(input),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_add_dev_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_ADD_DEV,
            &[0_u8; BTRFS_VOL_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_add_dev_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_ADD_DEV, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_rm_dev_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];
        input[0..10].copy_from_slice(b"/dev/loop1");

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_RM_DEV, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsRemoveDevice(input),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_rm_dev_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_RM_DEV,
            &[0_u8; BTRFS_VOL_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_rm_dev_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_RM_DEV, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_forget_dev_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];
        input[0..10].copy_from_slice(b"/dev/loop2");

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_FORGET_DEV, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsForgetDevice(input),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_forget_dev_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_FORGET_DEV,
            &[0_u8; BTRFS_VOL_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_forget_dev_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_FORGET_DEV, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_resize_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];
        input[0..6].copy_from_slice(b"1:+10G");

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_RESIZE, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsResize(input),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_resize_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_RESIZE,
            &[0_u8; BTRFS_VOL_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_resize_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_VOL_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_RESIZE, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_dev_replace_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = vec![0_u8; BTRFS_DEV_REPLACE_ARGS_SIZE as usize];
        input[0..8].copy_from_slice(&1_u64.to_le_bytes());

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_DEV_REPLACE, &input, 0);
        assert_eq!(
            response,
            IoctlResult::Data(vec![0_u8; BTRFS_DEV_REPLACE_ARGS_SIZE as usize])
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsDevReplace(input),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_dev_replace_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_DEV_REPLACE,
            &[0_u8; BTRFS_DEV_REPLACE_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_dev_replace_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_DEV_REPLACE_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_DEV_REPLACE, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_trans_start_commits_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_TRANS_START, &[], 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsStartTransaction,
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_trans_end_commits_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_TRANS_END, &[], 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::BtrfsEndTransaction,
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_fs_info_returns_backend_payload_verbatim() {
        // Canned 1024-byte payload with distinctive marker bytes at each
        // named field offset so the dispatcher can't silently corrupt them.
        let mut payload = vec![0_u8; BTRFS_IOC_FS_INFO_SIZE as usize];
        payload[0x00..0x08].copy_from_slice(&7_u64.to_ne_bytes()); // max_id
        payload[0x08..0x10].copy_from_slice(&3_u64.to_ne_bytes()); // num_devices
        payload[0x10..0x20].copy_from_slice(&[0x22_u8; 16]); // fsid
        payload[0x20..0x24].copy_from_slice(&16_u32.pow(2).to_ne_bytes()); // nodesize = 256
        payload[0x24..0x28].copy_from_slice(&4096_u32.to_ne_bytes()); // sectorsize
        payload[0x28..0x2C].copy_from_slice(&4096_u32.to_ne_bytes()); // clone_alignment
        payload[0x2C..0x2E].copy_from_slice(&0_u16.to_ne_bytes()); // csum_type (CRC32C)
        payload[0x2E..0x30].copy_from_slice(&4_u16.to_ne_bytes()); // csum_size
        payload[0x38..0x40].copy_from_slice(&0xDEAD_BEEF_1234_5678_u64.to_ne_bytes()); // generation
        payload[0x40..0x50].copy_from_slice(&[0x22_u8; 16]); // metadata_uuid == fsid

        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_btrfs_fs_info(
            payload.clone(),
            Arc::clone(&calls),
        )));

        let response =
            dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_FS_INFO, &[], BTRFS_IOC_FS_INFO_SIZE);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected IoctlResult::Data, got {response:?}"
        );
        let IoctlResult::Data(bytes) = response else {
            return;
        };
        assert_eq!(
            bytes.len(),
            BTRFS_IOC_FS_INFO_SIZE as usize,
            "reply must be exactly 1024 bytes"
        );
        assert_eq!(
            &bytes[..],
            &payload[..],
            "dispatcher must forward backend payload verbatim"
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetBtrfsFsInfo,
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_fs_info_rejects_too_small_output_buffer() {
        // Anything below the full 1024-byte width must short-circuit with
        // EINVAL *before* touching the backend — a partial struct handed
        // back to userspace would look like valid but scrambled metadata.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_btrfs_fs_info(
            vec![0_u8; BTRFS_IOC_FS_INFO_SIZE as usize],
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_FS_INFO,
            &[],
            BTRFS_IOC_FS_INFO_SIZE - 1,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(
            calls.lock().expect("lock ioctl calls").is_empty(),
            "backend must not be called when the out buffer is undersized"
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_fs_info_surfaces_backend_unsupported_as_eopnotsupp() {
        // Non-btrfs backends return UnsupportedFeature, which must land on
        // the caller as EOPNOTSUPP — that's the contract ext4 images rely
        // on to surface a deterministic "not a btrfs filesystem" errno.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response =
            dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_FS_INFO, &[], BTRFS_IOC_FS_INFO_SIZE);
        assert_eq!(response, IoctlResult::Error(libc::EOPNOTSUPP));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetBtrfsFsInfo,
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    /// Helper: build the 24-byte input prefix (`devid` || `uuid`) a
    /// well-formed BTRFS_IOC_DEV_INFO request needs to carry.
    fn btrfs_dev_info_in(devid: u64, uuid: &[u8; 16]) -> Vec<u8> {
        let mut buf = vec![0_u8; 24];
        buf[0..8].copy_from_slice(&devid.to_ne_bytes());
        buf[8..24].copy_from_slice(uuid);
        buf
    }

    fn btrfs_tree_search_in(key: BtrfsTreeSearchKey) -> Vec<u8> {
        let mut buf = vec![0_u8; BTRFS_TREE_SEARCH_KEY_SIZE];
        buf[0..8].copy_from_slice(&key.tree_id.to_ne_bytes());
        buf[8..16].copy_from_slice(&key.min_objectid.to_ne_bytes());
        buf[16..24].copy_from_slice(&key.max_objectid.to_ne_bytes());
        buf[24..32].copy_from_slice(&key.min_offset.to_ne_bytes());
        buf[32..40].copy_from_slice(&key.max_offset.to_ne_bytes());
        buf[40..48].copy_from_slice(&key.min_transid.to_ne_bytes());
        buf[48..56].copy_from_slice(&key.max_transid.to_ne_bytes());
        buf[56..60].copy_from_slice(&key.min_type.to_ne_bytes());
        buf[60..64].copy_from_slice(&key.max_type.to_ne_bytes());
        buf[BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET..BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET + 4]
            .copy_from_slice(&key.nr_items.to_ne_bytes());
        buf
    }

    fn btrfs_tree_search_v2_in(key: BtrfsTreeSearchKey, buf_size: u64) -> Vec<u8> {
        let mut buf = btrfs_tree_search_in(key);
        buf.extend_from_slice(&buf_size.to_ne_bytes());
        buf
    }

    fn btrfs_ino_lookup_user_in(dirid: u64, treeid: u64) -> Vec<u8> {
        let mut buf = vec![0_u8; BTRFS_INO_LOOKUP_USER_SIZE as usize];
        buf[0..8].copy_from_slice(&dirid.to_ne_bytes());
        buf[8..16].copy_from_slice(&treeid.to_ne_bytes());
        buf
    }

    fn btrfs_subvol_rootref_in(min_treeid: u64) -> Vec<u8> {
        let mut buf = vec![0_u8; BTRFS_SUBVOL_ROOTREF_SIZE as usize];
        buf[0..8].copy_from_slice(&min_treeid.to_ne_bytes());
        buf
    }

    fn btrfs_defrag_range_in(start: u64, len: u64) -> Vec<u8> {
        let mut buf = vec![0_u8; BTRFS_DEFRAG_RANGE_ARGS_SIZE as usize];
        buf[0..8].copy_from_slice(&start.to_le_bytes());
        buf[8..16].copy_from_slice(&len.to_le_bytes());
        buf
    }

    #[test]
    fn dispatch_ioctl_btrfs_dev_info_returns_backend_payload_verbatim() {
        // Canned 4096-byte payload with distinctive marker values at every
        // named field offset so the dispatcher can't silently corrupt them.
        let mut payload = vec![0_u8; BTRFS_IOC_DEV_INFO_SIZE as usize];
        payload[0x00..0x08].copy_from_slice(&1_u64.to_ne_bytes()); // devid
        payload[0x08..0x18].copy_from_slice(&[0x77_u8; 16]); // uuid
        payload[0x18..0x20].copy_from_slice(&0xCAFE_BABE_u64.to_ne_bytes()); // bytes_used
        payload[0x20..0x28].copy_from_slice(&(128_u64 * 1024 * 1024).to_ne_bytes()); // total_bytes

        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_btrfs_dev_info(
            payload.clone(),
            Arc::clone(&calls),
        )));

        let devid_in = 1_u64;
        let uuid_in = [0x77_u8; 16];
        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_DEV_INFO,
            &btrfs_dev_info_in(devid_in, &uuid_in),
            BTRFS_IOC_DEV_INFO_SIZE,
        );
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected IoctlResult::Data, got {response:?}"
        );
        let IoctlResult::Data(bytes) = response else {
            return;
        };
        assert_eq!(
            bytes.len(),
            BTRFS_IOC_DEV_INFO_SIZE as usize,
            "reply must be exactly 4096 bytes"
        );
        assert_eq!(
            &bytes[..],
            &payload[..],
            "dispatcher must forward backend payload verbatim"
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetBtrfsDevInfo(devid_in, uuid_in),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_dev_info_rejects_too_small_output_buffer() {
        // Anything below the full 4096-byte struct width must short-circuit
        // with EINVAL *before* touching the backend — a partial struct in
        // userspace is worse than no answer.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_btrfs_dev_info(
            vec![0_u8; BTRFS_IOC_DEV_INFO_SIZE as usize],
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_DEV_INFO,
            &btrfs_dev_info_in(0, &[0_u8; 16]),
            BTRFS_IOC_DEV_INFO_SIZE - 1,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(
            calls.lock().expect("lock ioctl calls").is_empty(),
            "backend must not be called when the out buffer is undersized"
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_dev_info_rejects_short_input_buffer_with_einval() {
        // Same short-circuit guard for the input side: we need 24 bytes
        // (devid + uuid) to have well-defined lookup keys; anything shorter
        // must fail before dispatch.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_btrfs_dev_info(
            vec![0_u8; BTRFS_IOC_DEV_INFO_SIZE as usize],
            Arc::clone(&calls),
        )));

        let short_in = vec![0_u8; 23]; // one byte shy of the 24-byte keys prefix
        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_DEV_INFO,
            &short_in,
            BTRFS_IOC_DEV_INFO_SIZE,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(
            calls.lock().expect("lock ioctl calls").is_empty(),
            "backend must not be called when the input keys are truncated"
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_dev_info_surfaces_backend_unsupported_as_eopnotsupp() {
        // The default recorder has no btrfs_dev_info payload → the trait
        // impl returns UnsupportedFeature, which the dispatcher must map
        // to EOPNOTSUPP so an ext4 caller sees the deterministic "not a
        // btrfs filesystem" errno.  Note: the dispatcher still performs
        // its input-length guard *before* reaching the backend, so the
        // caller must supply a well-formed 24-byte keys prefix even in
        // the unsupported-backend path.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_DEV_INFO,
            &btrfs_dev_info_in(1, &[0_u8; 16]),
            BTRFS_IOC_DEV_INFO_SIZE,
        );
        assert_eq!(response, IoctlResult::Error(libc::EOPNOTSUPP));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetBtrfsDevInfo(1, [0_u8; 16]),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_tree_search_updates_count_and_appends_payload() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut payload = vec![0_u8; 40];
        payload[0..8].copy_from_slice(&9_u64.to_ne_bytes()); // transid
        payload[8..16].copy_from_slice(&256_u64.to_ne_bytes()); // objectid
        payload[16..24].copy_from_slice(&0_u64.to_ne_bytes()); // offset
        payload[24..28].copy_from_slice(&1_u32.to_ne_bytes()); // type
        payload[28..32].copy_from_slice(&8_u32.to_ne_bytes()); // len
        payload[32..40].copy_from_slice(b"raw-item");
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_btrfs_tree_search(
            1,
            payload.clone(),
            Arc::clone(&calls),
        )));
        let search_key = BtrfsTreeSearchKey {
            tree_id: 5,
            min_objectid: 256,
            max_objectid: 256,
            min_offset: 0,
            max_offset: u64::MAX,
            min_transid: 0,
            max_transid: u64::MAX,
            min_type: 1,
            max_type: 1,
            nr_items: 64,
        };

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_TREE_SEARCH,
            &btrfs_tree_search_in(search_key),
            BTRFS_TREE_SEARCH_ARGS_SIZE,
        );
        let IoctlResult::Data(bytes) = response else {
            panic!("expected tree-search data response, got {response:?}");
        };

        assert_eq!(bytes.len(), BTRFS_TREE_SEARCH_ARGS_SIZE as usize);
        assert_eq!(
            u32::from_ne_bytes(
                bytes[BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET..BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET + 4]
                    .try_into()
                    .expect("nr_items bytes")
            ),
            1
        );
        assert_eq!(
            &bytes[BTRFS_TREE_SEARCH_KEY_SIZE..BTRFS_TREE_SEARCH_KEY_SIZE + payload.len()],
            payload.as_slice()
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::BtrfsTreeSearch(search_key),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_tree_search_rejects_short_input_or_output() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_btrfs_tree_search(
            0,
            Vec::new(),
            Arc::clone(&calls),
        )));
        let search_key = BtrfsTreeSearchKey {
            tree_id: 5,
            min_objectid: 0,
            max_objectid: u64::MAX,
            min_offset: 0,
            max_offset: u64::MAX,
            min_transid: 0,
            max_transid: u64::MAX,
            min_type: 0,
            max_type: u32::MAX,
            nr_items: 1,
        };
        let input = btrfs_tree_search_in(search_key);

        let short_input = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_TREE_SEARCH,
            &input[..BTRFS_TREE_SEARCH_KEY_SIZE - 1],
            BTRFS_TREE_SEARCH_ARGS_SIZE,
        );
        assert_eq!(short_input, IoctlResult::Error(libc::EINVAL));
        let short_output = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_TREE_SEARCH,
            &input,
            BTRFS_TREE_SEARCH_ARGS_SIZE - 1,
        );
        assert_eq!(short_output, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_tree_search_surfaces_backend_unsupported_as_eopnotsupp() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let search_key = BtrfsTreeSearchKey {
            tree_id: 1,
            min_objectid: 0,
            max_objectid: u64::MAX,
            min_offset: 0,
            max_offset: u64::MAX,
            min_transid: 0,
            max_transid: u64::MAX,
            min_type: 0,
            max_type: u32::MAX,
            nr_items: 1,
        };

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_TREE_SEARCH,
            &btrfs_tree_search_in(search_key),
            BTRFS_TREE_SEARCH_ARGS_SIZE,
        );
        assert_eq!(response, IoctlResult::Error(libc::EOPNOTSUPP));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::BtrfsTreeSearch(search_key),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_tree_search_v2_rejects_short_input_or_output() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let search_key = BtrfsTreeSearchKey {
            tree_id: 5,
            min_objectid: 0,
            max_objectid: u64::MAX,
            min_offset: 0,
            max_offset: u64::MAX,
            min_transid: 0,
            max_transid: u64::MAX,
            min_type: 0,
            max_type: u32::MAX,
            nr_items: 1,
        };
        let input = btrfs_tree_search_v2_in(search_key, 4096);

        let short_input = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_TREE_SEARCH_V2,
            &input[..BTRFS_TREE_SEARCH_V2_HEADER_SIZE - 1],
            BTRFS_TREE_SEARCH_V2_HEADER_SIZE_U32,
        );
        assert_eq!(short_input, IoctlResult::Error(libc::EINVAL));

        let short_output = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_TREE_SEARCH_V2,
            &input,
            BTRFS_TREE_SEARCH_V2_HEADER_SIZE_U32 - 1,
        );
        assert_eq!(short_output, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_tree_search_v2_valid_request_reaches_backend() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = btrfs_tree_search_v2_in(
            BtrfsTreeSearchKey {
                tree_id: 5,
                min_objectid: 0,
                max_objectid: u64::MAX,
                min_offset: 0,
                max_offset: u64::MAX,
                min_transid: 0,
                max_transid: u64::MAX,
                min_type: 0,
                max_type: u32::MAX,
                nr_items: 1,
            },
            4096,
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_TREE_SEARCH_V2,
            &input,
            BTRFS_TREE_SEARCH_V2_HEADER_SIZE_U32,
        );
        assert_eq!(response, IoctlResult::Error(libc::EOPNOTSUPP));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_logical_ino_v2_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_LOGICAL_INO_V2,
            &[0_u8; BTRFS_LOGICAL_INO_ARGS_SIZE as usize - 1],
            16,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_logical_ino_v2_routes_full_args_to_backend() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let mut input = vec![0_u8; BTRFS_LOGICAL_INO_ARGS_SIZE as usize];
        input[0..8].copy_from_slice(&0x1234_5678_u64.to_le_bytes());
        input[32..40].copy_from_slice(&1_u64.to_le_bytes());

        let response =
            dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_LOGICAL_INO_V2, &input, 16);
        assert_eq!(response, IoctlResult::Data(vec![0_u8; 16]));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::BtrfsLogicalInoV2(0x1234_5678, input),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_ino_lookup_user_rejects_short_input_or_output() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = btrfs_ino_lookup_user_in(256, 257);

        let short_input = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_INO_LOOKUP_USER,
            &input[..BTRFS_INO_LOOKUP_USER_SIZE as usize - 1],
            BTRFS_INO_LOOKUP_USER_SIZE,
        );
        assert_eq!(short_input, IoctlResult::Error(libc::EINVAL));

        let short_output = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_INO_LOOKUP_USER,
            &input,
            BTRFS_INO_LOOKUP_USER_SIZE - 1,
        );
        assert_eq!(short_output, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_get_subvol_rootref_rejects_short_input_or_output() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = btrfs_subvol_rootref_in(256);

        let short_input = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_GET_SUBVOL_ROOTREF,
            &input[..BTRFS_SUBVOL_ROOTREF_SIZE as usize - 1],
            BTRFS_SUBVOL_ROOTREF_SIZE,
        );
        assert_eq!(short_input, IoctlResult::Error(libc::EINVAL));

        let short_output = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_GET_SUBVOL_ROOTREF,
            &input,
            BTRFS_SUBVOL_ROOTREF_SIZE - 1,
        );
        assert_eq!(short_output, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_defrag_range_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let input = btrfs_defrag_range_in(4096, 8192);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            99,
            BTRFS_IOC_DEFRAG_RANGE,
            &input[..BTRFS_DEFRAG_RANGE_ARGS_SIZE as usize - 1],
            0,
        );

        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_defrag_range_read_only_mount_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            99,
            BTRFS_IOC_DEFRAG_RANGE,
            &btrfs_defrag_range_in(4096, 8192),
            0,
        );

        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_defrag_range_rw_backend_unsupported_returns_eopnotsupp() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            99,
            BTRFS_IOC_DEFRAG_RANGE,
            &btrfs_defrag_range_in(4096, 8192),
            0,
        );

        assert_eq!(response, IoctlResult::Error(libc::EOPNOTSUPP));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_set_features_uses_write_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );
        let mut input = vec![0_u8; BTRFS_SET_FEATURES_ARGS_SIZE as usize];
        input[0..8].copy_from_slice(&0x10_u64.to_le_bytes());
        input[24..32].copy_from_slice(&0x20_u64.to_le_bytes());

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_SET_FEATURES, &input, 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::SetBtrfsFeatures(input),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_set_features_rejects_short_input() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &MountOptions {
                read_only: false,
                ..MountOptions::default()
            },
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_SET_FEATURES,
            &[0_u8; BTRFS_SET_FEATURES_ARGS_SIZE as usize - 1],
            0,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_set_features_read_only_returns_erofs() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let input = vec![0_u8; BTRFS_SET_FEATURES_ARGS_SIZE as usize];

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, BTRFS_IOC_SET_FEATURES, &input, 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_get_supported_features_rejects_too_small_output_buffer() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        // Buffer smaller than 72 bytes should be rejected with EINVAL before
        // calling the backend.
        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_GET_SUPPORTED_FEATURES,
            &[],
            71, // one byte too small
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        // No backend calls should have been made.
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_btrfs_get_supported_features_surfaces_backend_unsupported_as_eopnotsupp() {
        // The default trait implementation returns UnsupportedFeature, which
        // must surface as EOPNOTSUPP for non-btrfs filesystems.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            1,
            0,
            BTRFS_IOC_GET_SUPPORTED_FEATURES,
            &[],
            BTRFS_SUPPORTED_FEATURE_FLAGS_SIZE,
        );
        assert_eq!(response, IoctlResult::Error(libc::EOPNOTSUPP));
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_ex_encodes_v1_policy() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let policy = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        ];
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy(
            policy,
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            11,
            0,
            FS_IOC_GET_ENCRYPTION_POLICY_EX,
            &[],
            FSCRYPT_POLICY_EX_HEADER_SIZE_U32 + FSCRYPT_POLICY_V2_SIZE_U32,
        );
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected ioctl data response"
        );
        let IoctlResult::Data(bytes) = response else {
            unreachable!("asserted IoctlResult::Data above");
        };
        assert_eq!(
            bytes.len(),
            FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V1_SIZE
        );
        let policy_size = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(policy_size, FSCRYPT_POLICY_V1_SIZE as u64);
        assert_eq!(&bytes[8..], &policy);
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetEncryptionPolicyEx(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_ex_encodes_v2_policy() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut policy = vec![0_u8; FSCRYPT_POLICY_V2_SIZE];
        policy[0] = FSCRYPT_POLICY_V2_VERSION;
        policy[1] = 1;
        policy[2] = 4;
        policy[4] = 9;
        policy[8..24].copy_from_slice(b"0123456789abcdef");
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy_ex(
            FSCRYPT_POLICY_V2_VERSION,
            &policy,
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            11,
            0,
            FS_IOC_GET_ENCRYPTION_POLICY_EX,
            &[],
            FSCRYPT_POLICY_EX_HEADER_SIZE_U32 + FSCRYPT_POLICY_V2_SIZE_U32,
        );
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected ioctl data response"
        );
        let IoctlResult::Data(bytes) = response else {
            unreachable!("asserted IoctlResult::Data above");
        };
        assert_eq!(
            bytes.len(),
            FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V2_SIZE
        );
        let policy_size = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(policy_size, FSCRYPT_POLICY_V2_SIZE as u64);
        assert_eq!(&bytes[8..], policy.as_slice());
        assert_eq!(bytes[8], FSCRYPT_POLICY_V2_VERSION);
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetEncryptionPolicyEx(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_ex_uses_in_data_policy_size_for_v2_policy() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut policy = vec![0_u8; FSCRYPT_POLICY_V2_SIZE];
        policy[0] = FSCRYPT_POLICY_V2_VERSION;
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy_ex(
            FSCRYPT_POLICY_V2_VERSION,
            &policy,
            Arc::clone(&calls),
        )));
        let mut in_data = vec![0_u8; FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V2_SIZE];
        in_data[..FSCRYPT_POLICY_EX_HEADER_SIZE]
            .copy_from_slice(&(FSCRYPT_POLICY_V2_SIZE as u64).to_ne_bytes());

        // Even if the transport reports a larger output area, the UAPI header
        // is the caller's advertised policy capacity when present.
        let response = dispatch_ioctl_for_testing(
            &fuse,
            11,
            0,
            FS_IOC_GET_ENCRYPTION_POLICY_EX,
            &in_data,
            FSCRYPT_POLICY_EX_HEADER_SIZE_U32 + FSCRYPT_POLICY_V2_SIZE_U32,
        );

        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected ioctl data response"
        );
        let IoctlResult::Data(bytes) = response else {
            unreachable!("asserted IoctlResult::Data above");
        };
        assert_eq!(
            bytes.len(),
            FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V2_SIZE
        );
        let policy_size = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(policy_size, FSCRYPT_POLICY_V2_SIZE as u64);
        assert_eq!(&bytes[8..], policy.as_slice());
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetEncryptionPolicyEx(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_ex_rejects_v2_when_policy_size_is_v1() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut policy = vec![0_u8; FSCRYPT_POLICY_V2_SIZE];
        policy[0] = FSCRYPT_POLICY_V2_VERSION;
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy_ex(
            FSCRYPT_POLICY_V2_VERSION,
            &policy,
            Arc::clone(&calls),
        )));
        let mut in_data = vec![0_u8; FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V2_SIZE];
        in_data[..FSCRYPT_POLICY_EX_HEADER_SIZE]
            .copy_from_slice(&(FSCRYPT_POLICY_V1_SIZE as u64).to_ne_bytes());

        let response = dispatch_ioctl_for_testing(
            &fuse,
            11,
            0,
            FS_IOC_GET_ENCRYPTION_POLICY_EX,
            &in_data,
            FSCRYPT_POLICY_EX_HEADER_SIZE_U32 + FSCRYPT_POLICY_V1_SIZE_U32,
        );

        assert_eq!(response, IoctlResult::Error(libc::EOVERFLOW));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetEncryptionPolicyEx(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_ex_rejects_too_small_output_buffer() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy(
            [0; FSCRYPT_POLICY_V1_SIZE],
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            11,
            0,
            FS_IOC_GET_ENCRYPTION_POLICY_EX,
            &[],
            FSCRYPT_POLICY_EX_HEADER_SIZE_U32 + FSCRYPT_POLICY_V1_SIZE_U32 - 1,
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_ex_v2_rejects_v1_sized_buffer() {
        // Regression test: v2 policy must not be returned to a caller that only
        // advertised enough capacity for a v1 policy. The handler must check the
        // actual policy size against out_size, not just the v1 minimum.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut policy = vec![0_u8; FSCRYPT_POLICY_V2_SIZE];
        policy[0] = FSCRYPT_POLICY_V2_VERSION;
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy_ex(
            FSCRYPT_POLICY_V2_VERSION,
            &policy,
            Arc::clone(&calls),
        )));

        // Caller advertises buffer capacity for v1 (header + 12 bytes)
        // but the backend returns a v2 policy (24 bytes)
        let response = dispatch_ioctl_for_testing(
            &fuse,
            11,
            0,
            FS_IOC_GET_ENCRYPTION_POLICY_EX,
            &[],
            FSCRYPT_POLICY_EX_HEADER_SIZE_U32 + FSCRYPT_POLICY_V1_SIZE_U32,
        );

        // Must reject with EOVERFLOW since caller buffer is insufficient for v2 payload.
        assert_eq!(response, IoctlResult::Error(libc::EOVERFLOW));

        // The backend SHOULD have been called to retrieve the policy
        // (we need to know the actual size to reject properly)
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetEncryptionPolicyEx(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_get_encryption_policy_ex_propagates_enodata() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_encryption_policy_errno(
            libc::ENODATA,
            Arc::clone(&calls),
        )));

        let response = dispatch_ioctl_for_testing(
            &fuse,
            11,
            0,
            FS_IOC_GET_ENCRYPTION_POLICY_EX,
            &[],
            FSCRYPT_POLICY_EX_HEADER_SIZE_U32 + FSCRYPT_POLICY_V1_SIZE_U32,
        );
        assert_eq!(response, IoctlResult::Error(libc::ENODATA));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetEncryptionPolicyEx(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_setflags_rejects_read_only_mount() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response =
            dispatch_ioctl_for_testing(&fuse, 7, 0, EXT4_IOC_SETFLAGS, &1_u32.to_ne_bytes(), 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_setflags_routes_to_fsops_and_commits() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &options,
        );

        let response =
            dispatch_ioctl_for_testing(&fuse, 9, 0, EXT4_IOC_SETFLAGS, &0x42_u32.to_ne_bytes(), 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::SetFlags(InodeNumber(9), 0x42),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_setflags_accepts_8_byte_long_payload_by_using_low_u32() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &options,
        );

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_SETFLAGS,
            &0x0000_0001_0000_0042_u64.to_ne_bytes(),
            0,
        );
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::SetFlags(InodeNumber(9), 0x42),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_read_only_mount() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_too_short_payload() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );

        let response = dispatch_ioctl_for_testing(&fuse, 5, 0, EXT4_IOC_MOVE_EXT, &[0_u8; 16], 40);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_nonzero_reserved_field() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );
        let mut request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);
        request[MOVE_EXT_RESERVED_OFFSET..MOVE_EXT_RESERVED_OFFSET + 4]
            .copy_from_slice(&1_u32.to_ne_bytes());

        let response = dispatch_ioctl_for_testing(
            &fuse,
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_negative_donor_fd() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );
        let mut request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);
        request[MOVE_EXT_DONOR_FD_OFFSET..MOVE_EXT_DONOR_FD_OFFSET + 4]
            .copy_from_slice(&(-1_i32).to_ne_bytes());

        let response = dispatch_ioctl_for_testing(
            &fuse,
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EBADF));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_non_extent_source_inode() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_source(
                FfsFileType::RegularFile,
                64 * 1024,
                0,
                Arc::clone(&calls),
            )),
            &options,
        );
        let request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EOPNOTSUPP));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::Getattr(InodeNumber(9)),
                IoctlCall::GetFlags(InodeNumber(9)),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_non_regular_source_inode() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_source(
                FfsFileType::Directory,
                64 * 1024,
                EXT4_EXTENTS_FL,
                Arc::clone(&calls),
            )),
            &options,
        );
        let request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::Getattr(InodeNumber(9)),
                IoctlCall::GetFlags(InodeNumber(9)),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_empty_source_inode() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_source(
                FfsFileType::RegularFile,
                0,
                EXT4_EXTENTS_FL,
                Arc::clone(&calls),
            )),
            &options,
        );
        let request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::Getattr(InodeNumber(9)),
                IoctlCall::GetFlags(InodeNumber(9)),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_overflowing_ranges() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );

        let request = FrankenFuse::encode_move_ext_response(7, u64::MAX, 22, 1, 0);
        let response = dispatch_ioctl_for_testing(
            &fuse,
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));

        let request = FrankenFuse::encode_move_ext_response(7, 11, u64::MAX, 1, 0);
        let response = dispatch_ioctl_for_testing(
            &fuse,
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_misaligned_page_offsets() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_blksize(
                1024,
                Arc::clone(&calls),
            )),
            &options,
        );
        let request = FrankenFuse::encode_move_ext_response(7, 1, 2, 1, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_ext_max_blocks_boundaries() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_source(
                FfsFileType::RegularFile,
                64 * 1024,
                EXT4_EXTENTS_FL,
                Arc::new(Mutex::new(Vec::new())),
            )),
            &options,
        );

        let request = FrankenFuse::encode_move_ext_response(7, EXT4_MOVE_EXT_MAX_BLOCKS, 0, 1, 0);
        let response = dispatch_ioctl_for_testing(
            &fuse,
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));

        let request =
            FrankenFuse::encode_move_ext_response(7, EXT4_MOVE_EXT_MAX_BLOCKS - 1, 0, 1, 0);
        let response = dispatch_ioctl_for_testing(
            &fuse,
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_too_small_output_buffer() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );
        let request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE - 1).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_routes_to_fsops_and_commits() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_result(
                21,
                Arc::clone(&calls),
            )),
            &options,
        );
        let donor_file = std::fs::File::open("/dev/null").expect("open donor fd");
        let donor_fd = u32::try_from(donor_file.as_raw_fd()).expect("donor fd fits u32");
        let donor_ino = InodeNumber(donor_file.metadata().expect("donor metadata").ino());
        let request = FrankenFuse::encode_move_ext_response(donor_fd, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(
            response,
            IoctlResult::Data(FrankenFuse::encode_move_ext_response(
                donor_fd, 11, 22, 33, 21,
            ))
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::Getattr(InodeNumber(9)),
                IoctlCall::GetFlags(InodeNumber(9)),
                IoctlCall::RegisterMoveExtDonor(donor_fd, donor_ino),
                IoctlCall::MoveExt(InodeNumber(9), donor_fd, 11, 22, 33),
                IoctlCall::UnregisterMoveExtDonor(donor_fd),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_move_ext_unregisters_donor_after_fsops_error() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_error(
                libc::EIO,
                Arc::clone(&calls),
            )),
            &options,
        );
        let donor_file = std::fs::File::open("/dev/null").expect("open donor fd");
        let donor_fd = u32::try_from(donor_file.as_raw_fd()).expect("donor fd fits u32");
        let donor_ino = InodeNumber(donor_file.metadata().expect("donor metadata").ino());
        let request = FrankenFuse::encode_move_ext_response(donor_fd, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EIO));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::Getattr(InodeNumber(9)),
                IoctlCall::GetFlags(InodeNumber(9)),
                IoctlCall::RegisterMoveExtDonor(donor_fd, donor_ino),
                IoctlCall::MoveExt(InodeNumber(9), donor_fd, 11, 22, 33),
                IoctlCall::End(RequestOp::IoctlWrite),
                IoctlCall::UnregisterMoveExtDonor(donor_fd),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_move_ext_does_not_unregister_after_register_error() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_register_error(
                libc::EIO,
                Arc::clone(&calls),
            )),
            &options,
        );
        let donor_file = std::fs::File::open("/dev/null").expect("open donor fd");
        let donor_fd = u32::try_from(donor_file.as_raw_fd()).expect("donor fd fits u32");
        let donor_ino = InodeNumber(donor_file.metadata().expect("donor metadata").ino());
        let request = FrankenFuse::encode_move_ext_response(donor_fd, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EIO));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::Getattr(InodeNumber(9)),
                IoctlCall::GetFlags(InodeNumber(9)),
                IoctlCall::RegisterMoveExtDonor(donor_fd, donor_ino),
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_move_ext_does_not_double_unregister_after_commit_error() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_commit_error(
                libc::EIO,
                Arc::clone(&calls),
            )),
            &options,
        );
        let donor_file = std::fs::File::open("/dev/null").expect("open donor fd");
        let donor_fd = u32::try_from(donor_file.as_raw_fd()).expect("donor fd fits u32");
        let donor_ino = InodeNumber(donor_file.metadata().expect("donor metadata").ino());
        let request = FrankenFuse::encode_move_ext_response(donor_fd, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EIO));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::Getattr(InodeNumber(9)),
                IoctlCall::GetFlags(InodeNumber(9)),
                IoctlCall::RegisterMoveExtDonor(donor_fd, donor_ino),
                IoctlCall::MoveExt(InodeNumber(9), donor_fd, 11, 22, 33),
                IoctlCall::UnregisterMoveExtDonor(donor_fd),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_move_ext_success_logs_contract_fields() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_result(
                21,
                Arc::clone(&calls),
            )),
            &options,
        );
        let donor_file = std::fs::File::open("/dev/null").expect("open donor fd");
        let donor_fd = u32::try_from(donor_file.as_raw_fd()).expect("donor fd fits u32");
        let request = FrankenFuse::encode_move_ext_response(donor_fd, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(
            response,
            IoctlResult::Data(FrankenFuse::encode_move_ext_response(
                donor_fd, 11, 22, 33, 21,
            ))
        );

        let operation_id = FrankenFuse::move_ext_operation_id(9, donor_fd, 11, 22, 33);
        let record = FrankenFuse::move_ext_success_log_record(
            MoveExtLogContext {
                operation_id: &operation_id,
                ino: 9,
                donor_ino: Some(InodeNumber(123)),
                donor_fd,
                orig_start: 11,
                donor_start: 22,
                len: 33,
            },
            21,
        );
        assert_eq!(record.scenario_id, MOVE_EXT_SCENARIO_ID);
        assert_eq!(record.outcome, "applied");
        assert_eq!(record.error_class, MOVE_EXT_SUCCESS_ERROR_CLASS);
        assert_eq!(record.target, "ffs::ioctl");
        assert_eq!(record.ino, 9);
        assert_eq!(record.donor_fd, donor_fd);
        assert_eq!(record.moved_len, Some(21));
        assert!(!record.operation_id.is_empty());
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejection_logs_contract_fields() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_source(
                FfsFileType::RegularFile,
                64 * 1024,
                0,
                Arc::clone(&calls),
            )),
            &options,
        );
        let request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);

        let response = dispatch_ioctl_for_testing(
            &fuse,
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EOPNOTSUPP));

        let operation_id = FrankenFuse::move_ext_operation_id(9, 7, 11, 22, 33);
        let record = FrankenFuse::move_ext_error_log_record(
            MoveExtLogContext {
                operation_id: &operation_id,
                ino: 9,
                donor_ino: None,
                donor_fd: 7,
                orig_start: 11,
                donor_start: 22,
                len: 33,
            },
            &FfsError::UnsupportedFeature("move_ext requires extent-backed regular file".into()),
        );
        assert_eq!(record.scenario_id, MOVE_EXT_SCENARIO_ID);
        assert_eq!(record.outcome, "rejected");
        assert_eq!(record.error_class, "unsupported_feature");
        assert_eq!(record.target, "ffs::ioctl");
        assert_eq!(record.ino, 9);
        assert_eq!(record.donor_fd, 7);
        assert_eq!(record.errno, Some(libc::EOPNOTSUPP));
        assert!(!record.operation_id.is_empty());
    }

    #[test]
    fn dispatch_ioctl_fiemap_rejects_unsupported_request_flags() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let mut request = vec![0_u8; FIEMAP_HEADER_SIZE];
        request[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
            .copy_from_slice(&4096_u64.to_ne_bytes());
        request[FIEMAP_FLAGS_OFFSET..FIEMAP_FLAGS_OFFSET + 4]
            .copy_from_slice(&FIEMAP_FLAG_XATTR.to_ne_bytes());

        let response = dispatch_ioctl_for_testing(
            &fuse,
            5,
            0,
            FS_IOC_FIEMAP,
            &request,
            u32::try_from(FIEMAP_HEADER_SIZE).expect("header size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EBADR));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_fiemap_sync_fsyncs_before_extent_lookup() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &options,
        );
        let mut request = vec![0_u8; FIEMAP_HEADER_SIZE];
        request[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8]
            .copy_from_slice(&8192_u64.to_ne_bytes());
        request[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
            .copy_from_slice(&4096_u64.to_ne_bytes());
        request[FIEMAP_FLAGS_OFFSET..FIEMAP_FLAGS_OFFSET + 4]
            .copy_from_slice(&FIEMAP_FLAG_SYNC.to_ne_bytes());

        let response = dispatch_ioctl_for_testing(
            &fuse,
            13,
            91,
            FS_IOC_FIEMAP,
            &request,
            u32::try_from(FIEMAP_HEADER_SIZE).expect("header size fits"),
        );
        assert_eq!(
            response,
            IoctlResult::Data(FrankenFuse::encode_fiemap_response(8192, 4096, 0, &[], 32))
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::Fsync),
                IoctlCall::Fsync(InodeNumber(13), 91, false),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::Fsync),
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::Fiemap(InodeNumber(13), 8192, 4096),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_unknown_command_returns_enotty() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));

        let response = dispatch_ioctl_for_testing(&fuse, 1, 0, 0xDEAD_BEEF, &[], 0);
        assert_eq!(response, IoctlResult::Error(libc::ENOTTY));
    }

    #[test]
    fn record_ioctl_probe_appends_lines_via_buffered_sink() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let trace_path = std::env::temp_dir().join(format!(
            "ffs_fuse_ioctl_trace_{}_{}.log",
            std::process::id(),
            unique
        ));
        std::fs::write(&trace_path, "seed\n").expect("seed ioctl trace");
        let options = MountOptions {
            ioctl_trace_path: Some(trace_path.clone()),
            ..MountOptions::default()
        };

        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(
                0x1234_5678,
                Arc::new(Mutex::new(Vec::new())),
            )),
            &options,
        );

        fuse.record_ioctl_probe(11, EXT4_IOC_GETFLAGS, 0, 4);
        fuse.record_ioctl_probe(12, 0xDEAD_BEEF, 0, 0);
        flush_ioctl_trace_for_testing(&fuse);

        let trace = std::fs::read_to_string(&trace_path).expect("read ioctl trace");
        let lines = trace.lines().collect::<Vec<_>>();
        assert_eq!(
            lines,
            vec![
                "seed",
                "ino=11 cmd=0x80086601 in_len=0 out_size=4",
                "ino=12 cmd=0xdeadbeef in_len=0 out_size=0",
            ]
        );
    }

    #[test]
    fn ioctl_trace_dropped_events_saturate_at_numeric_limits() {
        let probe = IoctlTraceProbe {
            path: PathBuf::new(),
            sender: None,
            worker: None,
            dropped_events: Arc::new(AtomicU64::new(u64::MAX - 1)),
        };

        probe.record_dropped_event();
        probe.record_dropped_event();

        assert_eq!(probe.dropped_events.load(Ordering::Relaxed), u64::MAX);
        probe.dropped_events.store(0, Ordering::Relaxed);
    }

    #[test]
    fn ioctl_trace_special_path_disables_writer_without_blocking_drop() {
        let trace_path = PathBuf::from("/dev/null");
        let started = Instant::now();
        let probe = IoctlTraceProbe::new(trace_path);

        assert!(probe.sender.is_none());
        assert!(probe.worker.is_none());
        assert!(probe.flush_sync().is_err());

        drop(probe);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "unsupported special trace path must not leave a blocking writer to join"
        );
    }

    #[test]
    fn ioctl_trace_directory_path_disables_writer_without_draining_thread() {
        let trace_path = std::env::temp_dir();
        let probe = IoctlTraceProbe::new(trace_path);

        assert!(probe.sender.is_none());
        assert!(probe.worker.is_none());
        assert!(probe.flush_sync().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn ioctl_trace_symlink_path_disables_writer_without_following_target() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let trace_dir = std::env::temp_dir();
        let target_path = trace_dir.join(format!(
            "ffs_fuse_ioctl_trace_symlink_target_{}_{}.log",
            std::process::id(),
            unique
        ));
        let symlink_path = trace_dir.join(format!(
            "ffs_fuse_ioctl_trace_symlink_{}_{}.log",
            std::process::id(),
            unique
        ));
        std::fs::write(&target_path, "seed\n").expect("seed symlink target");
        std::os::unix::fs::symlink(&target_path, &symlink_path)
            .expect("create ioctl trace symlink");

        let err = validate_ioctl_trace_path(&symlink_path).expect_err("symlink must be rejected");
        assert!(
            err.to_string().contains("symlink"),
            "unexpected validation error: {err}"
        );

        let probe = IoctlTraceProbe::new(symlink_path);
        assert!(probe.sender.is_none());
        assert!(probe.worker.is_none());
        assert!(probe.flush_sync().is_err());
    }

    #[test]
    fn ioctl_trace_flush_sync_is_happens_before_barrier_for_concurrent_recorders() {
        // Spawning many threads that all enqueue records concurrently, then
        // a single `flush_sync` from the main thread, must guarantee that
        // every previously enqueued record is visible in the on-disk file by
        // the time `flush_sync` returns.  This is the core contract of the
        // off-thread writer: the dispatcher never blocks on file I/O, but
        // tests get a deterministic synchronisation point.
        const RECORDER_THREADS: usize = 8;
        const RECORDS_PER_THREAD: usize = 32;

        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let trace_path = std::env::temp_dir().join(format!(
            "ffs_fuse_ioctl_trace_concurrent_{}_{}.log",
            std::process::id(),
            unique
        ));
        let options = MountOptions {
            ioctl_trace_path: Some(trace_path.clone()),
            ..MountOptions::default()
        };
        let fuse = Arc::new(FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        ));

        let barrier = Arc::new(std::sync::Barrier::new(RECORDER_THREADS));
        let mut handles = Vec::with_capacity(RECORDER_THREADS);
        for thread_idx in 0..RECORDER_THREADS {
            let fuse = Arc::clone(&fuse);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for record_idx in 0..RECORDS_PER_THREAD {
                    fuse.record_ioctl_probe(
                        (thread_idx * RECORDS_PER_THREAD + record_idx) as u64,
                        EXT4_IOC_GETFLAGS,
                        0,
                        4,
                    );
                }
            }));
        }
        for h in handles {
            h.join().expect("recorder thread");
        }
        flush_ioctl_trace_for_testing(&fuse);

        let trace = std::fs::read_to_string(&trace_path).expect("read ioctl trace");
        let line_count = trace.lines().count();
        assert_eq!(
            line_count,
            RECORDER_THREADS * RECORDS_PER_THREAD,
            "every recorded ioctl event must be visible after flush_sync; \
             channel capacity ({IOCTL_TRACE_CHANNEL_CAPACITY}) is far above this test's load"
        );
    }

    #[test]
    fn dispatch_ioctl_setflags_rejects_too_short_payload() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );

        // 3 bytes is too short for a u32 flags value.
        let response =
            dispatch_ioctl_for_testing(&fuse, 5, 0, EXT4_IOC_SETFLAGS, &[0x01, 0x02, 0x03], 0);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));

        // Empty payload is also rejected.
        let response = dispatch_ioctl_for_testing(&fuse, 5, 0, EXT4_IOC_SETFLAGS, &[], 0);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_fiemap_rejects_short_input_and_output_buffers() {
        const FIEMAP_HEADER_SIZE_U32: u32 = 32;

        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        for input_len in 0..FIEMAP_HEADER_SIZE {
            let short_header = vec![0_u8; input_len];
            let response = dispatch_ioctl_for_testing(
                &fuse,
                3,
                0,
                FS_IOC_FIEMAP,
                &short_header,
                FIEMAP_HEADER_SIZE_U32,
            );
            assert_eq!(
                response,
                IoctlResult::Error(libc::EINVAL),
                "FIEMAP input length {input_len} must fail before FsOps dispatch"
            );
        }

        let request = vec![0_u8; FIEMAP_HEADER_SIZE];
        for out_size in 0..FIEMAP_HEADER_SIZE_U32 {
            let response =
                dispatch_ioctl_for_testing(&fuse, 3, 0, FS_IOC_FIEMAP, &request, out_size);
            assert_eq!(
                response,
                IoctlResult::Error(libc::EINVAL),
                "FIEMAP output size {out_size} must fail before FsOps dispatch"
            );
        }

        let no_calls_recorded = match calls.lock() {
            Ok(guard) => guard.is_empty(),
            Err(poisoned) => poisoned.into_inner().is_empty(),
        };
        assert!(no_calls_recorded);
    }

    #[test]
    fn dispatch_ioctl_btrfs_encoded_read_rejects_short_input() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));

        // BTRFS_IOC_ENCODED_READ requires 64-byte input (encoded_io_args)
        let short_input = vec![0_u8; 32];
        let response =
            dispatch_ioctl_for_testing(&fuse, 2, 0, BTRFS_IOC_ENCODED_READ, &short_input, 0);
        assert_eq!(
            response,
            IoctlResult::Error(libc::EINVAL),
            "BTRFS_IOC_ENCODED_READ with short input must return EINVAL"
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_encoded_write_rejects_on_read_only() {
        let opts = MountOptions {
            read_only: true,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &opts,
        );

        let input = vec![0_u8; 64];
        let response = dispatch_ioctl_for_testing(&fuse, 2, 0, BTRFS_IOC_ENCODED_WRITE, &input, 0);
        assert_eq!(
            response,
            IoctlResult::Error(libc::EROFS),
            "BTRFS_IOC_ENCODED_WRITE on read-only must return EROFS"
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_subvol_setflags_rejects_short_input() {
        let opts = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &opts,
        );

        // BTRFS_IOC_SUBVOL_SETFLAGS requires 8-byte input (u64 flags)
        let short_input = vec![0_u8; 4];
        let response =
            dispatch_ioctl_for_testing(&fuse, 2, 0, BTRFS_IOC_SUBVOL_SETFLAGS, &short_input, 0);
        assert_eq!(
            response,
            IoctlResult::Error(libc::EINVAL),
            "BTRFS_IOC_SUBVOL_SETFLAGS with short input must return EINVAL"
        );
    }

    #[test]
    fn dispatch_ioctl_btrfs_subvol_setflags_rejects_on_read_only() {
        let opts = MountOptions {
            read_only: true,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &opts,
        );

        let input = 0_u64.to_ne_bytes().to_vec();
        let response =
            dispatch_ioctl_for_testing(&fuse, 2, 0, BTRFS_IOC_SUBVOL_SETFLAGS, &input, 0);
        assert_eq!(
            response,
            IoctlResult::Error(libc::EROFS),
            "BTRFS_IOC_SUBVOL_SETFLAGS on read-only must return EROFS"
        );
    }

    #[test]
    fn access_predictor_doubles_fetch_size_for_forward_sequence() {
        let predictor = AccessPredictor::default();
        let ino = InodeNumber(11);
        let size = 4096_u32;

        assert_eq!(predictor.fetch_size(ino, 0, size), size);
        predictor.record_read(ino, 0, size);
        assert_eq!(predictor.fetch_size(ino, u64::from(size), size), size);

        predictor.record_read(ino, u64::from(size), size);
        assert_eq!(
            predictor.fetch_size(ino, u64::from(size) * 2, size),
            size.saturating_mul(COALESCED_FETCH_MULTIPLIER)
                .min(MAX_COALESCED_READ_SIZE)
        );
    }

    #[test]
    fn readahead_manager_partial_take_requeues_tail() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(5);

        manager.insert(ino, 100, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(manager.take(ino, 100, 4), Some(vec![1, 2, 3, 4]));
        assert_eq!(manager.take(ino, 104, 8), Some(vec![5, 6]));
    }

    #[test]
    fn readahead_manager_tail_requeue_refreshes_fifo_order() {
        let manager = ReadaheadManager::new(3);
        let ino = InodeNumber(6);

        manager.insert(ino, 0, vec![1, 2, 3, 4, 5, 6]);
        manager.insert(ino, 4, vec![9, 9]);
        manager.insert(ino, 8, vec![7, 7]);

        assert_eq!(manager.take(ino, 0, 4), Some(vec![1, 2, 3, 4]));

        manager.insert(ino, 12, vec![8, 8]);
        manager.insert(ino, 16, vec![9, 9]);

        assert_eq!(manager.take(ino, 8, 2), None);
        assert_eq!(manager.take(ino, 4, 2), Some(vec![5, 6]));
    }

    #[test]
    fn readahead_manager_zero_len_take_preserves_entry() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(7);

        manager.insert(ino, 0, vec![1, 2, 3]);
        assert_eq!(manager.take(ino, 0, 0), None);
        assert_eq!(manager.take(ino, 0, 3), Some(vec![1, 2, 3]));
    }

    #[test]
    fn readahead_manager_caps_pending_entries() {
        let manager = ReadaheadManager::new(2);
        let ino = InodeNumber(9);

        manager.insert(ino, 0, vec![0]);
        manager.insert(ino, 8, vec![1]);
        manager.insert(ino, 16, vec![2]);

        assert_eq!(manager.take(ino, 0, 1), None);
        assert_eq!(manager.take(ino, 8, 1), Some(vec![1]));
        assert_eq!(manager.take(ino, 16, 1), Some(vec![2]));
    }

    #[test]
    fn readahead_manager_reinsert_refreshes_fifo_order() {
        let manager = ReadaheadManager::new(2);
        let ino = InodeNumber(11);

        manager.insert(ino, 0, vec![1]);
        manager.insert(ino, 8, vec![2]);
        // Reinsert offset 0 to refresh its FIFO position.
        manager.insert(ino, 0, vec![3]);
        manager.insert(ino, 16, vec![4]); // Evicts the oldest remaining entry.

        assert_eq!(manager.take(ino, 8, 1), None);
        assert_eq!(manager.take(ino, 0, 1), Some(vec![3]));
        assert_eq!(manager.take(ino, 16, 1), Some(vec![4]));
    }

    #[test]
    fn readahead_manager_invalidate_inode_removes_only_matching_entries() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(9);
        let other = InodeNumber(10);

        manager.insert(ino, 0, vec![1, 2, 3]);
        manager.insert(ino, 16, vec![4, 5, 6]);
        manager.insert(other, 0, vec![7, 8, 9]);

        manager.invalidate_inode(ino);

        assert_eq!(manager.take(ino, 0, 3), None);
        assert_eq!(manager.take(ino, 16, 3), None);
        assert_eq!(manager.take(other, 0, 3), Some(vec![7, 8, 9]));
    }

    struct CountingReadFs {
        data: Vec<u8>,
        read_calls: Arc<AtomicU64>,
    }

    impl CountingReadFs {
        fn new(data: Vec<u8>, read_calls: Arc<AtomicU64>) -> Self {
            Self { data, read_calls }
        }
    }

    impl FsOps for CountingReadFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("test fs miss".into()))
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("test fs miss".into()))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<FfsReaddirPage> {
            Ok(vec![].into())
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            offset: u64,
            size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            self.read_calls.fetch_add(1, Ordering::Relaxed);
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            if start >= self.data.len() {
                return Ok(vec![]);
            }
            let requested = usize::try_from(size).unwrap_or(usize::MAX);
            let end = start.saturating_add(requested).min(self.data.len());
            Ok(self.data[start..end].to_vec())
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    #[test]
    fn sequential_reads_use_prefetched_tail_without_extra_backend_call() {
        let read_calls = Arc::new(AtomicU64::new(0));
        let data: Vec<u8> = (0_u8..64).collect();
        let fuse = FrankenFuse::new(Box::new(CountingReadFs::new(data, Arc::clone(&read_calls))));
        let cx = Cx::for_testing();
        let ino = InodeNumber(1);

        assert_eq!(
            fuse.read_with_readahead(&cx, ino, 0, 0, 4).unwrap(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(
            fuse.read_with_readahead(&cx, ino, 0, 4, 4).unwrap(),
            vec![4, 5, 6, 7]
        );
        assert_eq!(
            fuse.read_with_readahead(&cx, ino, 0, 8, 4).unwrap(),
            vec![8, 9, 10, 11]
        );
        assert_eq!(
            fuse.read_with_readahead(&cx, ino, 0, 12, 4).unwrap(),
            vec![12, 13, 14, 15]
        );

        // The third read uses a doubled fetch and queues the tail for the
        // fourth read, so only three backend reads are needed.
        assert_eq!(read_calls.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn long_sequential_reads_exceed_two_x_call_reduction() {
        let read_calls = Arc::new(AtomicU64::new(0));
        let data: Vec<u8> = (0_u8..128).collect();
        let fuse = FrankenFuse::new(Box::new(CountingReadFs::new(data, Arc::clone(&read_calls))));
        let cx = Cx::for_testing();
        let ino = InodeNumber(2);

        for index in 0_u64..12 {
            let offset = index * 4;
            let expected_start = u8::try_from(offset).unwrap_or(u8::MAX);
            let expected = vec![
                expected_start,
                expected_start.saturating_add(1),
                expected_start.saturating_add(2),
                expected_start.saturating_add(3),
            ];
            assert_eq!(
                fuse.read_with_readahead(&cx, ino, 0, offset, 4).unwrap(),
                expected
            );
        }

        // 12 logical reads complete with at most 5 backend reads, which is
        // >2x reduction versus the unbatched baseline of 12 calls.
        assert!(read_calls.load(Ordering::Relaxed) <= 5);
    }

    #[test]
    fn non_sequential_reads_do_not_trigger_coalescing() {
        let read_calls = Arc::new(AtomicU64::new(0));
        let data: Vec<u8> = (0_u8..128).collect();
        let fuse = FrankenFuse::new(Box::new(CountingReadFs::new(data, Arc::clone(&read_calls))));
        let cx = Cx::for_testing();
        let ino = InodeNumber(3);
        let offsets = [0_u64, 32, 4, 48, 8, 64];

        for offset in offsets {
            let _ = fuse.read_with_readahead(&cx, ino, 0, offset, 4).unwrap();
        }

        assert_eq!(
            read_calls.load(Ordering::Relaxed),
            u64::try_from(offsets.len()).unwrap_or(u64::MAX)
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HookEvent {
        Begin(RequestOp),
        Body(RequestOp),
        End(RequestOp),
    }

    struct HookFs {
        events: Arc<Mutex<Vec<HookEvent>>>,
        fail_begin: bool,
        fail_end: bool,
    }

    impl HookFs {
        fn new(events: Arc<Mutex<Vec<HookEvent>>>, fail_begin: bool, fail_end: bool) -> Self {
            Self {
                events,
                fail_begin,
                fail_end,
            }
        }
    }

    impl FsOps for HookFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("test fs miss".into()))
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("test fs miss".into()))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<FfsReaddirPage> {
            Ok(vec![].into())
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn begin_request_scope(&self, _cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
            self.events.lock().unwrap().push(HookEvent::Begin(op));
            if self.fail_begin {
                return Err(FfsError::Io(std::io::Error::other("begin failed")));
            }
            Ok(RequestScope::empty())
        }

        fn end_request_scope(
            &self,
            _cx: &Cx,
            op: RequestOp,
            _scope: RequestScope,
        ) -> ffs_error::Result<()> {
            self.events.lock().unwrap().push(HookEvent::End(op));
            if self.fail_end {
                return Err(FfsError::Io(std::io::Error::other("end failed")));
            }
            Ok(())
        }
    }

    #[test]
    fn request_scope_calls_begin_and_end_for_successful_operation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_events = Arc::clone(&events);

        let out = fuse
            .with_request_scope(&cx, RequestOp::Read, |_cx, _scope| {
                body_events
                    .lock()
                    .unwrap()
                    .push(HookEvent::Body(RequestOp::Read));
                Ok::<u32, FfsError>(7)
            })
            .unwrap();
        assert_eq!(out, 7);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                HookEvent::Begin(RequestOp::Read),
                HookEvent::Body(RequestOp::Read),
                HookEvent::End(RequestOp::Read)
            ]
        );
    }

    #[test]
    fn request_scope_short_circuits_body_when_begin_fails() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), true, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_called = Arc::new(AtomicBool::new(false));
        let body_called_ref = Arc::clone(&body_called);

        let err = fuse
            .with_request_scope(&cx, RequestOp::Lookup, |_cx, _scope| {
                body_called_ref.store(true, Ordering::Relaxed);
                Ok::<(), FfsError>(())
            })
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::EIO);
        assert!(!body_called.load(Ordering::Relaxed));
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[HookEvent::Begin(RequestOp::Lookup)]
        );
        let metrics = fuse.metrics().snapshot();
        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.requests_ok, 0);
        assert_eq!(metrics.requests_err, 1);
    }

    #[test]
    fn request_scope_prefers_operation_error_when_body_and_end_fail() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, true);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_events = Arc::clone(&events);

        let err = fuse
            .with_request_scope(&cx, RequestOp::Readlink, |_cx, _scope| {
                body_events
                    .lock()
                    .unwrap()
                    .push(HookEvent::Body(RequestOp::Readlink));
                Err::<(), FfsError>(FfsError::NotFound("missing".into()))
            })
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                HookEvent::Begin(RequestOp::Readlink),
                HookEvent::Body(RequestOp::Readlink),
                HookEvent::End(RequestOp::Readlink)
            ]
        );
    }

    #[test]
    fn request_scope_returns_cleanup_error_when_operation_succeeds() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, true);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_events = Arc::clone(&events);

        let err = fuse
            .with_request_scope(&cx, RequestOp::Getattr, |_cx, _scope| {
                body_events
                    .lock()
                    .unwrap()
                    .push(HookEvent::Body(RequestOp::Getattr));
                Ok::<(), FfsError>(())
            })
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::EIO);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                HookEvent::Begin(RequestOp::Getattr),
                HookEvent::Body(RequestOp::Getattr),
                HookEvent::End(RequestOp::Getattr)
            ]
        );
    }

    fn test_inode_attr(ino: u64, kind: FfsFileType, perm: u16) -> InodeAttr {
        InodeAttr {
            ino: InodeNumber(ino),
            size: 0,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind,
            perm,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            generation: 1,
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum MutationCall {
        Begin {
            op: RequestOp,
        },
        Commit,
        End {
            op: RequestOp,
        },
        Getattr {
            ino: InodeNumber,
        },
        Statfs {
            ino: InodeNumber,
        },
        Lookup {
            parent: InodeNumber,
            name: String,
        },
        Open {
            ino: InodeNumber,
            flags: i32,
        },
        Create {
            parent: InodeNumber,
            name: String,
            mode: u16,
            uid: u32,
            gid: u32,
        },
        Mknod {
            parent: InodeNumber,
            name: String,
            mode: u16,
            rdev: u32,
            uid: u32,
            gid: u32,
        },
        Readdir {
            ino: InodeNumber,
            offset: u64,
        },
        Readlink {
            ino: InodeNumber,
        },
        Read {
            ino: InodeNumber,
            offset: u64,
            size: u32,
        },
        Write {
            ino: InodeNumber,
            offset: u64,
            data: Vec<u8>,
        },
        Mkdir {
            parent: InodeNumber,
            name: String,
            mode: u16,
            uid: u32,
            gid: u32,
        },
        Rmdir {
            parent: InodeNumber,
            name: String,
        },
        Unlink {
            parent: InodeNumber,
            name: String,
        },
        Rename {
            parent: InodeNumber,
            name: String,
            new_parent: InodeNumber,
            new_name: String,
        },
        Symlink {
            parent: InodeNumber,
            name: String,
            target: String,
            uid: u32,
            gid: u32,
        },
        Flush {
            ino: InodeNumber,
            fh: u64,
            lock_owner: u64,
        },
        Fsync {
            ino: InodeNumber,
            fh: u64,
            datasync: bool,
        },
        Release {
            ino: InodeNumber,
            fh: u64,
            flags: i32,
            lock_owner: Option<u64>,
            flush: bool,
        },
        Setattr {
            ino: InodeNumber,
            mode: Option<u16>,
            uid: Option<u32>,
            gid: Option<u32>,
            size: Option<u64>,
            atime: Option<SystemTime>,
            mtime: Option<SystemTime>,
        },
        Setxattr {
            ino: InodeNumber,
            name: String,
            value: Vec<u8>,
            mode: XattrSetMode,
        },
    }

    struct MutationRecordingFs {
        calls: Arc<Mutex<Vec<MutationCall>>>,
        fsync_errno: Option<i32>,
        record_scopes: bool,
        getattr_size: u64,
    }

    impl MutationRecordingFs {
        fn new(calls: Arc<Mutex<Vec<MutationCall>>>) -> Self {
            Self {
                calls,
                fsync_errno: None,
                record_scopes: false,
                getattr_size: 0,
            }
        }

        fn with_scope_recording(calls: Arc<Mutex<Vec<MutationCall>>>) -> Self {
            Self {
                calls,
                fsync_errno: None,
                record_scopes: true,
                getattr_size: 0,
            }
        }

        fn with_scope_recording_and_getattr_size(
            calls: Arc<Mutex<Vec<MutationCall>>>,
            getattr_size: u64,
        ) -> Self {
            Self {
                calls,
                fsync_errno: None,
                record_scopes: true,
                getattr_size,
            }
        }

        fn with_failing_fsync(calls: Arc<Mutex<Vec<MutationCall>>>, errno: i32) -> Self {
            Self {
                calls,
                fsync_errno: Some(errno),
                record_scopes: true,
                getattr_size: 0,
            }
        }
    }

    impl FsOps for MutationRecordingFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Getattr { ino });
            let mut attr = test_inode_attr(ino.0, FfsFileType::RegularFile, 0o644);
            attr.size = self.getattr_size;
            Ok(attr)
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Lookup {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                });
            Ok(test_inode_attr(202, FfsFileType::RegularFile, 0o640))
        }

        fn statfs(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<FsStat> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Statfs { ino });
            Ok(FsStat {
                blocks: 4096,
                blocks_free: 1024,
                blocks_available: 768,
                files: 512,
                files_free: 256,
                block_size: 4096,
                name_max: 255,
                fragment_size: 1024,
            })
        }

        fn open(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            flags: i32,
        ) -> ffs_error::Result<(u64, u32)> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Open { ino, flags });
            Ok((9001, 0x2))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            offset: u64,
        ) -> ffs_error::Result<FfsReaddirPage> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Readdir { ino, offset });
            Ok(vec![FfsDirEntry {
                ino: InodeNumber(404),
                offset: offset + 1,
                kind: FfsFileType::RegularFile,
                name: b"entry.txt".to_vec(),
            }]
            .into())
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            offset: u64,
            size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Read { ino, offset, size });
            Ok(b"read-data".to_vec())
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Readlink { ino });
            Ok(b"target/path".to_vec())
        }

        fn mkdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
            mode: u16,
            uid: u32,
            gid: u32,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Mkdir {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                    mode,
                    uid,
                    gid,
                });
            Ok(test_inode_attr(101, FfsFileType::Directory, mode))
        }

        fn create(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
            mode: u16,
            uid: u32,
            gid: u32,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Create {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                    mode,
                    uid,
                    gid,
                });
            Ok(test_inode_attr(303, FfsFileType::RegularFile, mode))
        }

        fn mknod(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
            mode: u16,
            rdev: u32,
            uid: u32,
            gid: u32,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Mknod {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                    mode,
                    rdev,
                    uid,
                    gid,
                });
            let kind = match mode & ffs_types::S_IFMT {
                ffs_types::S_IFCHR => FfsFileType::CharDevice,
                ffs_types::S_IFBLK => FfsFileType::BlockDevice,
                ffs_types::S_IFIFO => FfsFileType::Fifo,
                ffs_types::S_IFSOCK => FfsFileType::Socket,
                _ => FfsFileType::RegularFile,
            };
            let mut attr = test_inode_attr(313, kind, mode & 0o7777);
            attr.rdev = rdev;
            Ok(attr)
        }

        fn rmdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Rmdir {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                });
            Ok(())
        }

        fn unlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Unlink {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                });
            Ok(())
        }

        fn rename(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
            new_parent: InodeNumber,
            new_name: &OsStr,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Rename {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                    new_parent,
                    new_name: new_name.to_string_lossy().into_owned(),
                });
            Ok(())
        }

        fn symlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
            target: &Path,
            uid: u32,
            gid: u32,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Symlink {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                    target: target.display().to_string(),
                    uid,
                    gid,
                });
            Ok(test_inode_attr(505, FfsFileType::Symlink, 0o777))
        }

        fn write(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            offset: u64,
            data: &[u8],
        ) -> ffs_error::Result<u32> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Write {
                    ino,
                    offset,
                    data: data.to_vec(),
                });
            Ok(u32::try_from(data.len()).unwrap_or(u32::MAX))
        }

        fn flush(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            fh: u64,
            lock_owner: u64,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Flush {
                    ino,
                    fh,
                    lock_owner,
                });
            Ok(())
        }

        fn fsync(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            fh: u64,
            datasync: bool,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Fsync { ino, fh, datasync });
            if let Some(errno) = self.fsync_errno {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(errno)));
            }
            Ok(())
        }

        fn release(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            request: ReleaseRequest,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Release {
                    ino: request.ino,
                    fh: request.fh,
                    flags: request.flags,
                    lock_owner: request.lock_owner,
                    flush: request.flush,
                });
            Ok(())
        }

        fn setxattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            name: &str,
            value: &[u8],
            mode: XattrSetMode,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Setxattr {
                    ino,
                    name: name.to_owned(),
                    value: value.to_vec(),
                    mode,
                });
            Ok(())
        }

        fn setattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            attrs: &SetAttrRequest,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Setattr {
                    ino,
                    mode: attrs.mode,
                    uid: attrs.uid,
                    gid: attrs.gid,
                    size: attrs.size,
                    atime: attrs.atime,
                    mtime: attrs.mtime,
                });
            let mut attr = test_inode_attr(ino.0, FfsFileType::RegularFile, 0o644);
            if let Some(mode) = attrs.mode {
                attr.perm = mode;
            }
            if let Some(uid) = attrs.uid {
                attr.uid = uid;
            }
            if let Some(gid) = attrs.gid {
                attr.gid = gid;
            }
            if let Some(size) = attrs.size {
                attr.size = size;
            }
            if let Some(atime) = attrs.atime {
                attr.atime = atime;
            }
            if let Some(mtime) = attrs.mtime {
                attr.mtime = mtime;
            }
            Ok(attr)
        }

        fn begin_request_scope(&self, _cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
            if self.record_scopes {
                self.calls
                    .lock()
                    .expect("lock mutation calls")
                    .push(MutationCall::Begin { op });
            }
            Ok(RequestScope::empty())
        }

        fn end_request_scope(
            &self,
            _cx: &Cx,
            op: RequestOp,
            _scope: RequestScope,
        ) -> ffs_error::Result<()> {
            if self.record_scopes {
                self.calls
                    .lock()
                    .expect("lock mutation calls")
                    .push(MutationCall::End { op });
            }
            Ok(())
        }

        fn commit_request_scope(
            &self,
            _scope: &mut RequestScope,
        ) -> ffs_error::Result<ffs_types::CommitSeq> {
            if self.record_scopes {
                self.calls
                    .lock()
                    .expect("lock mutation calls")
                    .push(MutationCall::Commit);
            }
            Ok(ffs_types::CommitSeq(0))
        }
    }

    #[test]
    fn conformance_fuse_lookup_metadata_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::new(Arc::clone(&calls))));

        let attr = fuse
            .lookup_for_fuzzing(2, b"alpha.txt")
            .expect("lookup round trip");

        assert_eq!(attr.ino, InodeNumber(202));
        assert_eq!(attr.kind, FfsFileType::RegularFile);
        assert_eq!(attr.perm, 0o640);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Lookup {
                parent: InodeNumber(2),
                name: "alpha.txt".to_owned(),
            }]
        );
    }

    #[test]
    fn conformance_fuse_getattr_metadata_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::new(Arc::clone(&calls))));

        let attr = fuse.getattr_for_fuzzing(42).expect("getattr round trip");

        assert_eq!(attr.ino, InodeNumber(42));
        assert_eq!(attr.kind, FfsFileType::RegularFile);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Getattr {
                ino: InodeNumber(42),
            }]
        );
    }

    #[test]
    fn conformance_fuse_statfs_filesystem_stats_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::with_scope_recording(
            Arc::clone(&calls),
        )));

        let stats = fuse.statfs_for_fuzzing(1).expect("statfs round trip");

        assert_eq!(
            stats,
            FsStat {
                blocks: 4096,
                blocks_free: 1024,
                blocks_available: 768,
                files: 512,
                files_free: 256,
                block_size: 4096,
                name_max: 255,
                fragment_size: 1024,
            }
        );
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Statfs,
                },
                MutationCall::Statfs {
                    ino: InodeNumber(1),
                },
                MutationCall::End {
                    op: RequestOp::Statfs,
                },
            ]
        );
    }

    #[test]
    fn authorize_setattr_owner_change_denies_non_root_chown() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );
        // The mock getattr reports uid=1000, gid=1000 for every inode.

        let uid_change = SetAttrRequest {
            mode: None,
            uid: Some(501),
            gid: None,
            size: None,
            atime: None,
            mtime: None,
        };
        // Root may change ownership.
        assert!(fuse.setattr_for_fuzzing_as(7, &uid_change, 0).is_ok());
        // A non-root caller changing uid to a different value is refused (EPERM).
        assert!(matches!(
            fuse.setattr_for_fuzzing_as(7, &uid_change, 1000),
            Err(errno) if errno == libc::EPERM
        ));
        // Same for an actual gid change.
        let gid_change = SetAttrRequest {
            mode: None,
            uid: None,
            gid: Some(999),
            size: None,
            atime: None,
            mtime: None,
        };
        assert!(matches!(
            fuse.setattr_for_fuzzing_as(7, &gid_change, 1000),
            Err(errno) if errno == libc::EPERM
        ));
        // A non-root no-op (uid/gid set to their current values) is allowed.
        let noop = SetAttrRequest {
            mode: None,
            uid: Some(1000),
            gid: Some(1000),
            size: None,
            atime: None,
            mtime: None,
        };
        assert!(fuse.setattr_for_fuzzing_as(7, &noop, 1000).is_ok());
        // A non-root change to non-ownership attributes is allowed.
        let mode_change = SetAttrRequest {
            mode: Some(0o600),
            uid: None,
            gid: None,
            size: None,
            atime: None,
            mtime: None,
        };
        assert!(fuse.setattr_for_fuzzing_as(7, &mode_change, 1000).is_ok());
    }

    #[test]
    fn conformance_fuse_setattr_metadata_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );
        let atime = SystemTime::UNIX_EPOCH + Duration::from_secs(11);
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(22);
        let attrs = SetAttrRequest {
            mode: Some(0o600),
            uid: Some(501),
            gid: Some(20),
            size: Some(4096),
            atime: Some(atime),
            mtime: Some(mtime),
        };

        let attr = fuse
            .setattr_for_fuzzing(55, &attrs)
            .expect("setattr round trip");

        assert_eq!(attr.ino, InodeNumber(55));
        assert_eq!(attr.perm, 0o600);
        assert_eq!(attr.uid, 501);
        assert_eq!(attr.gid, 20);
        assert_eq!(attr.size, 4096);
        assert_eq!(attr.atime, atime);
        assert_eq!(attr.mtime, mtime);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Setattr {
                ino: InodeNumber(55),
                mode: Some(0o600),
                uid: Some(501),
                gid: Some(20),
                size: Some(4096),
                atime: Some(atime),
                mtime: Some(mtime),
            }]
        );
    }

    #[test]
    fn fuse_setattr_uid_gid_same_owner_noop_commits_for_non_root() -> Result<(), String> {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );
        let attrs = SetAttrRequest {
            mode: Some(0o600),
            uid: Some(1000),
            gid: Some(1000),
            size: None,
            atime: None,
            mtime: None,
        };

        let attr = fuse
            .setattr_for_fuzzing_as(55, &attrs, 1000)
            .map_err(|errno| format!("same-owner setattr returned errno {errno}"))?;

        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
        assert_eq!(attr.perm, 0o600);
        let recorded_calls = calls
            .lock()
            .map_err(|_| "mutation call log poisoned".to_owned())?
            .clone();
        assert_eq!(
            recorded_calls,
            vec![
                MutationCall::Begin {
                    op: RequestOp::Setattr,
                },
                MutationCall::Getattr {
                    ino: InodeNumber(55),
                },
                MutationCall::Setattr {
                    ino: InodeNumber(55),
                    mode: Some(0o600),
                    uid: Some(1000),
                    gid: Some(1000),
                    size: None,
                    atime: None,
                    mtime: None,
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Setattr,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn fuse_setattr_uid_gid_change_rejects_non_root_before_backend_mutation() -> Result<(), String>
    {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );
        let attrs = SetAttrRequest {
            mode: Some(0o600),
            uid: Some(501),
            gid: Some(20),
            size: None,
            atime: None,
            mtime: None,
        };

        let result = fuse.setattr_for_fuzzing_as(55, &attrs, 1000);

        assert!(
            matches!(result, Err(errno) if errno == libc::EPERM),
            "non-root uid/gid change must return EPERM, got {result:?}"
        );
        let recorded_calls = calls
            .lock()
            .map_err(|_| "mutation call log poisoned".to_owned())?
            .clone();
        assert_eq!(
            recorded_calls,
            vec![
                MutationCall::Begin {
                    op: RequestOp::Setattr,
                },
                MutationCall::Getattr {
                    ino: InodeNumber(55),
                },
                MutationCall::End {
                    op: RequestOp::Setattr,
                },
            ],
            "unauthorized uid/gid changes must not dispatch backend setattr or commit"
        );
        Ok(())
    }

    #[test]
    fn conformance_fuse_mknod_regular_file_metadata_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );
        let mode = libc::S_IFREG | 0o640;

        let attr = fuse
            .mknod_for_fuzzing(7, b"node.txt", mode, 0, 1001, 1002)
            .expect("mknod round trip");

        assert_eq!(attr.ino, InodeNumber(303));
        assert_eq!(attr.kind, FfsFileType::RegularFile);
        assert_eq!(attr.perm, 0o640);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Create {
                parent: InodeNumber(7),
                name: "node.txt".to_owned(),
                mode: 0o640,
                uid: 1001,
                gid: 1002,
            }]
        );
    }

    #[test]
    fn conformance_fuse_mknod_special_node_dispatches_to_backend() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );
        let mode = libc::S_IFCHR | 0o600;

        let attr = fuse
            .mknod_for_fuzzing(7, b"whiteout", mode, 0, 1001, 1002)
            .expect("special-node mknod round trip");

        assert_eq!(attr.ino, InodeNumber(313));
        assert_eq!(attr.kind, FfsFileType::CharDevice);
        assert_eq!(attr.perm, 0o600);
        assert_eq!(attr.rdev, 0);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Create,
                },
                MutationCall::Mknod {
                    parent: InodeNumber(7),
                    name: "whiteout".to_owned(),
                    mode: ffs_types::S_IFCHR | 0o600,
                    rdev: 0,
                    uid: 1001,
                    gid: 1002,
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Create,
                },
            ]
        );
    }

    #[test]
    fn conformance_fuse_mknod_unsupported_type_rejects_before_backend() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let err = fuse
            .mknod_for_fuzzing(7, b"dir", libc::S_IFDIR | 0o755, 0, 1001, 1002)
            .expect_err("directory mknod is unsupported");

        assert_eq!(err, libc::EOPNOTSUPP);
        assert!(calls.lock().expect("lock calls").is_empty());
    }

    #[test]
    fn conformance_fuse_readdir_directory_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::new(Arc::clone(&calls))));

        let entries = fuse.readdir_for_fuzzing(2, 7).expect("readdir round trip");

        assert_eq!(
            entries,
            vec![FfsDirEntry {
                ino: InodeNumber(404),
                offset: 8,
                kind: FfsFileType::RegularFile,
                name: b"entry.txt".to_vec(),
            }]
        );
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Readdir {
                ino: InodeNumber(2),
                offset: 7,
            }]
        );
    }

    #[test]
    fn conformance_fuse_readlink_directory_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::new(Arc::clone(&calls))));

        let target = fuse.readlink_for_fuzzing(12).expect("readlink round trip");

        assert_eq!(target, b"target/path".to_vec());
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Readlink {
                ino: InodeNumber(12),
            }]
        );
    }

    #[test]
    fn conformance_fuse_mkdir_directory_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let attr = fuse
            .mkdir_for_fuzzing(2, b"logs", 0o750, 1001, 1002)
            .expect("mkdir round trip");

        assert_eq!(attr.ino, InodeNumber(101));
        assert_eq!(attr.kind, FfsFileType::Directory);
        assert_eq!(attr.perm, 0o750);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Mkdir {
                parent: InodeNumber(2),
                name: "logs".to_owned(),
                mode: 0o750,
                uid: 1001,
                gid: 1002,
            }]
        );
    }

    #[test]
    fn conformance_fuse_rmdir_directory_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        fuse.rmdir_for_fuzzing(2, b"old").expect("rmdir round trip");

        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Rmdir {
                parent: InodeNumber(2),
                name: "old".to_owned(),
            }]
        );
    }

    #[test]
    fn conformance_fuse_unlink_directory_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        fuse.unlink_for_fuzzing(2, b"stale.txt")
            .expect("unlink round trip");

        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Unlink {
                parent: InodeNumber(2),
                name: "stale.txt".to_owned(),
            }]
        );
    }

    #[test]
    fn conformance_fuse_rename_directory_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        fuse.rename_for_fuzzing(2, b"old.txt", 3, b"new.txt")
            .expect("rename round trip");

        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Rename {
                parent: InodeNumber(2),
                name: "old.txt".to_owned(),
                new_parent: InodeNumber(3),
                new_name: "new.txt".to_owned(),
            }]
        );
    }

    #[test]
    fn conformance_fuse_symlink_directory_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let attr = fuse
            .symlink_for_fuzzing(2, b"link", b"target/path", 1001, 1002)
            .expect("symlink round trip");

        assert_eq!(attr.ino, InodeNumber(505));
        assert_eq!(attr.kind, FfsFileType::Symlink);
        assert_eq!(attr.perm, 0o777);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Symlink {
                parent: InodeNumber(2),
                name: "link".to_owned(),
                target: "target/path".to_owned(),
                uid: 1001,
                gid: 1002,
            }]
        );
    }

    #[test]
    fn conformance_fuse_symlink_path_max_minus_one_target_round_trip() {
        const LINUX_PATH_MAX: usize = 4096;

        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );
        let target = "a".repeat(LINUX_PATH_MAX - 1);

        let attr = fuse
            .symlink_for_fuzzing(2, b"max_link", target.as_bytes(), 1001, 1002)
            .expect("PATH_MAX-1 symlink target should reach backend");

        assert_eq!(attr.kind, FfsFileType::Symlink);
        let observed = calls.lock().expect("lock mutation calls");
        assert_eq!(observed.len(), 1);
        let observed_call = observed[0].clone();
        drop(observed);
        let MutationCall::Symlink {
            parent,
            name,
            target: observed_target,
            uid,
            gid,
        } = observed_call
        else {
            panic!("expected symlink call, got {observed_call:?}");
        };
        assert_eq!(parent, InodeNumber(2));
        assert_eq!(name, "max_link");
        assert_eq!(observed_target.len(), target.len());
        assert_eq!(observed_target, target);
        assert_eq!((uid, gid), (1001, 1002));
    }

    #[test]
    fn conformance_fuse_open_file_lifecycle_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::with_scope_recording(
            Arc::clone(&calls),
        )));

        let (fh, open_flags) = fuse.open_for_fuzzing(44, libc::O_RDONLY).expect("open");

        assert_eq!(fh, 9001);
        assert_eq!(open_flags, 0x2);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Open,
                },
                MutationCall::Open {
                    ino: InodeNumber(44),
                    flags: libc::O_RDONLY,
                },
                MutationCall::End {
                    op: RequestOp::Open,
                },
            ]
        );
    }

    #[test]
    fn open_reply_preserves_kernel_cache_for_buffered_io_only() {
        assert_eq!(
            FrankenFuse::kernel_open_flags(libc::O_RDONLY, 0),
            fuse_consts::FOPEN_KEEP_CACHE
        );
        assert_eq!(FrankenFuse::kernel_open_flags(libc::O_DIRECT, 0), 0);
        assert_eq!(
            FrankenFuse::kernel_open_flags(libc::O_RDONLY, fuse_consts::FOPEN_DIRECT_IO),
            fuse_consts::FOPEN_DIRECT_IO
        );
    }

    #[test]
    fn conformance_fuse_read_file_lifecycle_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::with_scope_recording(
            Arc::clone(&calls),
        )));

        let data = fuse.read_for_fuzzing(44, 8, 4).expect("read");

        assert_eq!(data, b"read".to_vec());
        assert_eq!(fuse.metrics().snapshot().bytes_read, 4);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Read,
                },
                MutationCall::Read {
                    ino: InodeNumber(44),
                    offset: 8,
                    size: 4,
                },
                MutationCall::End {
                    op: RequestOp::Read,
                },
            ]
        );
    }

    #[test]
    fn conformance_fuse_write_file_lifecycle_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        let written = fuse.write_for_fuzzing(44, 16, b"payload").expect("write");

        assert_eq!(written, 7);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(44),
                    offset: 16,
                    data: b"payload".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Write,
                },
            ]
        );
    }

    #[test]
    fn writeback_cache_write_defers_commit_until_flush() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            writeback_cache: WritebackCacheMode::Enabled,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        let written = fuse
            .dispatch_write_with_intent(44, 16, b"payload", WriteIntent::from_fuse(9001, 0, 0))
            .expect("writeback-cache write");
        assert_eq!(written, 7);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(44),
                    offset: 16,
                    data: b"payload".to_vec(),
                },
            ],
            "buffered writeback-cache writes must not commit before a boundary"
        );

        fuse.flush_for_fuzzing(44, 9001, 0xABCD)
            .expect("flush commits pending batch");
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(44),
                    offset: 16,
                    data: b"payload".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Write,
                },
                MutationCall::Begin {
                    op: RequestOp::Flush,
                },
                MutationCall::Flush {
                    ino: InodeNumber(44),
                    fh: 9001,
                    lock_owner: 0xABCD,
                },
                MutationCall::End {
                    op: RequestOp::Flush,
                },
            ]
        );
    }

    #[test]
    fn writeback_cache_fsync_commits_pending_writes_before_fsync() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            writeback_cache: WritebackCacheMode::Enabled,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        fuse.dispatch_write_with_intent(44, 0, b"abc", WriteIntent::from_fuse(9001, 0, 0))
            .expect("writeback-cache write");
        fuse.fsync_for_fuzzing(44, 9001, true)
            .expect("fsync commits pending batch");

        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(44),
                    offset: 0,
                    data: b"abc".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Write,
                },
                MutationCall::Begin {
                    op: RequestOp::Fsync,
                },
                MutationCall::Fsync {
                    ino: InodeNumber(44),
                    fh: 9001,
                    datasync: true,
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Fsync,
                },
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writeback_cache_sync_write_drains_existing_batch_first() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            writeback_cache: WritebackCacheMode::Enabled,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        fuse.dispatch_write_with_intent(44, 0, b"old", WriteIntent::from_fuse(9001, 0, 0))
            .expect("deferred write");
        fuse.dispatch_write_with_intent(
            44,
            3,
            b"sync",
            WriteIntent::from_fuse(9001, 0, libc::O_DSYNC),
        )
        .expect("sync write");

        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(44),
                    offset: 0,
                    data: b"old".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Write,
                },
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(44),
                    offset: 3,
                    data: b"sync".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::Fsync {
                    ino: InodeNumber(44),
                    fh: 9001,
                    datasync: true,
                },
                MutationCall::End {
                    op: RequestOp::Write,
                },
            ],
            "a sync write must publish any older deferred writes before its own fsync boundary"
        );
    }

    #[test]
    fn writeback_cache_read_reuses_live_write_scope_for_same_handle() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            writeback_cache: WritebackCacheMode::Enabled,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        fuse.write_for_fuzzing(44, 16, b"payload")
            .expect("writeback-cache write");
        let data = fuse.read_for_fuzzing(44, 16, 4).expect("same-handle read");

        assert_eq!(data, b"read".to_vec());
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(44),
                    offset: 16,
                    data: b"payload".to_vec(),
                },
                MutationCall::Read {
                    ino: InodeNumber(44),
                    offset: 16,
                    size: 4,
                },
            ],
            "same-handle reads must use the deferred write scope, not a new read snapshot"
        );
    }

    #[test]
    fn conformance_fuse_copy_file_range_lifecycle_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        let copied = fuse
            .copy_file_range_for_fuzzing(44, 8, 45, 32, 4, 0)
            .expect("copy_file_range");

        assert_eq!(copied, 4);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Read {
                    ino: InodeNumber(44),
                    offset: 8,
                    size: 4,
                },
                MutationCall::Write {
                    ino: InodeNumber(45),
                    offset: 32,
                    data: b"read".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Write,
                },
            ]
        );
    }

    #[test]
    fn conformance_fuse_flush_file_lifecycle_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::with_scope_recording(
            Arc::clone(&calls),
        )));

        fuse.flush_for_fuzzing(44, 9001, 0xABCD).expect("flush");

        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Flush,
                },
                MutationCall::Flush {
                    ino: InodeNumber(44),
                    fh: 9001,
                    lock_owner: 0xABCD,
                },
                MutationCall::End {
                    op: RequestOp::Flush,
                },
            ]
        );
    }

    #[test]
    fn conformance_fuse_fsync_file_lifecycle_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        fuse.fsync_for_fuzzing(44, 9001, true).expect("fsync");

        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Fsync,
                },
                MutationCall::Fsync {
                    ino: InodeNumber(44),
                    fh: 9001,
                    datasync: true,
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Fsync,
                },
            ]
        );
    }

    #[test]
    fn conformance_fuse_release_file_lifecycle_round_trip() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::with_scope_recording(
            Arc::clone(&calls),
        )));

        fuse.release_for_fuzzing(44, 9001, libc::O_RDWR, Some(0xABCD), true)
            .expect("release");

        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Release,
                },
                MutationCall::Release {
                    ino: InodeNumber(44),
                    fh: 9001,
                    flags: libc::O_RDWR,
                    lock_owner: Some(0xABCD),
                    flush: true,
                },
                MutationCall::End {
                    op: RequestOp::Release,
                },
            ]
        );
    }

    fn record_max_active(max_active: &AtomicUsize, current: usize) {
        let mut observed = max_active.load(Ordering::Relaxed);
        while current > observed {
            match max_active.compare_exchange_weak(
                observed,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => observed = actual,
            }
        }
    }

    struct RenameConcurrencyProbeFs {
        active_renames: Arc<AtomicUsize>,
        max_active_renames: Arc<AtomicUsize>,
        delay: Duration,
    }

    impl RenameConcurrencyProbeFs {
        fn new(delay: Duration) -> (Self, Arc<AtomicUsize>) {
            let active_renames = Arc::new(AtomicUsize::new(0));
            let max_active_renames = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    active_renames,
                    max_active_renames: Arc::clone(&max_active_renames),
                    delay,
                },
                max_active_renames,
            )
        }
    }

    impl FsOps for RenameConcurrencyProbeFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("test fs miss".into()))
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("test fs miss".into()))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<FfsReaddirPage> {
            Ok(vec![].into())
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn rename(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
            _new_parent: InodeNumber,
            _new_name: &OsStr,
        ) -> ffs_error::Result<()> {
            let current = self.active_renames.fetch_add(1, Ordering::SeqCst) + 1;
            record_max_active(&self.max_active_renames, current);
            std::thread::sleep(self.delay);
            self.active_renames.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn dispatch_write_routes_to_fsops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let written = fuse
            .dispatch_write(42, 4096, b"abc")
            .expect("dispatch write");
        assert_eq!(written, 3);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Write {
                ino: InodeNumber(42),
                offset: 4096,
                data: b"abc".to_vec(),
            }]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_dsync_flags_trigger_datasync_boundary() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        let written = fuse
            .dispatch_write_with_intent(
                42,
                4096,
                b"abc",
                WriteIntent::from_fuse(9001, 0, libc::O_DSYNC),
            )
            .expect("dispatch DSync write");
        assert_eq!(written, 3);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(42),
                    offset: 4096,
                    data: b"abc".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::Fsync {
                    ino: InodeNumber(42),
                    fh: 9001,
                    datasync: true,
                },
                MutationCall::End {
                    op: RequestOp::Write,
                },
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_sync_flags_trigger_full_fsync_boundary() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        fuse.dispatch_write_with_intent(
            42,
            0,
            b"sync",
            WriteIntent::from_fuse(9002, 0, libc::O_SYNC),
        )
        .expect("dispatch sync write");
        assert!(
            calls
                .lock()
                .expect("lock calls")
                .contains(&MutationCall::Fsync {
                    ino: InodeNumber(42),
                    fh: 9002,
                    datasync: false,
                }),
            "O_SYNC must request a full fsync boundary"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_fuse_lockowner_flag_does_not_imply_dsync() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        fuse.dispatch_write_with_intent(
            42,
            0,
            b"lockowner",
            WriteIntent::from_fuse(9003, fuse_consts::FUSE_WRITE_LOCKOWNER, 0),
        )
        .expect("dispatch lockowner write");
        assert!(
            calls
                .lock()
                .expect("lock calls")
                .iter()
                .all(|call| !matches!(call, MutationCall::Fsync { .. })),
            "FUSE_WRITE_LOCKOWNER shares the raw bit used by RWF_DSYNC, so only the FUSE flags field can drive sync intent"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_fuse_kill_suidgid_flag_does_not_imply_sync() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        let written = fuse
            .dispatch_write_with_intent(
                42,
                21,
                b"kill-suidgid",
                WriteIntent::from_fuse(9005, fuse_consts::FUSE_WRITE_KILL_SUIDGID, 0),
            )
            .expect("dispatch kill-suidgid write");

        assert_eq!(written, 12);
        assert_eq!(
            fuse_consts::FUSE_WRITE_KILL_SUIDGID,
            fuse_consts::RWF_SYNC,
            "FUSE_WRITE_KILL_SUIDGID shares the raw bit used by RWF_SYNC"
        );
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(42),
                    offset: 21,
                    data: b"kill-suidgid".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Write,
                },
            ],
            "bit 2 must stay a FUSE metadata hint, not an RWF_SYNC fsync request"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_fuse_cache_flag_rwf_hipri_hint_keeps_normal_write_contract() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        let written = fuse
            .dispatch_write_with_intent(
                42,
                11,
                b"hipri",
                WriteIntent::from_fuse(9004, fuse_consts::RWF_HIPRI, 0),
            )
            .expect("dispatch RWF_HIPRI/FUSE_WRITE_CACHE write");

        assert_eq!(written, 5);
        assert_eq!(
            fuse_consts::RWF_HIPRI,
            fuse_consts::FUSE_WRITE_CACHE,
            "RWF_HIPRI shares bit 0 with the FUSE cached-write hint"
        );
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Write {
                    ino: InodeNumber(42),
                    offset: 11,
                    data: b"hipri".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Write,
                },
            ],
            "bit 0 must stay a harmless priority/cache hint, not sync, NOWAIT, append, or unsupported intent"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_rwf_append_uses_current_file_size_as_offset() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording_and_getattr_size(
                Arc::clone(&calls),
                123,
            )),
            &options,
        );

        let written = fuse
            .dispatch_write_with_intent(
                42,
                0,
                b"append",
                WriteIntent::from_fuse(0, fuse_consts::RWF_APPEND, 0),
            )
            .expect("dispatch append write");
        assert_eq!(written, 6);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[
                MutationCall::Begin {
                    op: RequestOp::Write,
                },
                MutationCall::Getattr {
                    ino: InodeNumber(42),
                },
                MutationCall::Write {
                    ino: InodeNumber(42),
                    offset: 123,
                    data: b"append".to_vec(),
                },
                MutationCall::Commit,
                MutationCall::End {
                    op: RequestOp::Write,
                },
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_o_append_uses_current_file_size_as_offset() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording_and_getattr_size(
                Arc::clone(&calls),
                321,
            )),
            &options,
        );

        fuse.dispatch_write_with_intent(
            42,
            9,
            b"open-append",
            WriteIntent::from_fuse(0, 0, libc::O_APPEND),
        )
        .expect("dispatch O_APPEND write");
        assert!(
            calls
                .lock()
                .expect("lock calls")
                .contains(&MutationCall::Write {
                    ino: InodeNumber(42),
                    offset: 321,
                    data: b"open-append".to_vec(),
                }),
            "O_APPEND should resolve the write offset to current EOF"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_rwf_noappend_suppresses_open_append_offset_rewrite() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording_and_getattr_size(
                Arc::clone(&calls),
                999,
            )),
            &options,
        );

        fuse.dispatch_write_with_intent(
            42,
            17,
            b"noappend",
            WriteIntent::from_fuse(0, fuse_consts::RWF_NOAPPEND, libc::O_APPEND),
        )
        .expect("dispatch NOAPPEND write");
        let (did_getattr, wrote_at_requested_offset) = {
            let observed = calls.lock().expect("lock calls");
            (
                observed
                    .iter()
                    .any(|call| matches!(call, MutationCall::Getattr { .. })),
                observed.contains(&MutationCall::Write {
                    ino: InodeNumber(42),
                    offset: 17,
                    data: b"noappend".to_vec(),
                }),
            )
        };
        assert!(
            !did_getattr,
            "RWF_NOAPPEND should avoid EOF lookup for O_APPEND file flags"
        );
        assert!(
            wrote_at_requested_offset,
            "RWF_NOAPPEND should preserve the caller-provided offset"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_rwf_append_noappend_conflict_rejects_before_mutation() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording_and_getattr_size(
                Arc::clone(&calls),
                777,
            )),
            &options,
        );

        let err = fuse
            .dispatch_write_with_intent(
                42,
                17,
                b"append-noappend",
                WriteIntent::from_fuse(
                    0,
                    fuse_consts::RWF_APPEND | fuse_consts::RWF_NOAPPEND,
                    libc::O_APPEND,
                ),
            )
            .expect_err("conflicting RWF_APPEND/RWF_NOAPPEND write should fail");

        assert!(matches!(err, MutationDispatchError::Errno(libc::EINVAL)));
        assert!(
            calls.lock().expect("lock calls").is_empty(),
            "Linux rejects RWF_APPEND|RWF_NOAPPEND before EOF lookup or mutation"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_rwf_atomic_rejects_before_mutation() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let err = fuse
            .dispatch_write_with_intent(
                42,
                0,
                b"atomic",
                WriteIntent::from_fuse(0, fuse_consts::RWF_ATOMIC, 0),
            )
            .expect_err("unsupported RWF_ATOMIC write should fail");

        assert!(matches!(
            err,
            MutationDispatchError::Errno(libc::EOPNOTSUPP)
        ));
        assert!(
            calls.lock().expect("lock calls").is_empty(),
            "unsupported RWF_ATOMIC must not reach FsOps::write"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_rwf_dontcache_rejects_before_mutation() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let err = fuse
            .dispatch_write_with_intent(
                42,
                0,
                b"dontcache",
                WriteIntent::from_fuse(0, fuse_consts::RWF_DONTCACHE, 0),
            )
            .expect_err("unsupported RWF_DONTCACHE write should fail");

        assert!(matches!(
            err,
            MutationDispatchError::Errno(libc::EOPNOTSUPP)
        ));
        assert!(
            calls.lock().expect("lock calls").is_empty(),
            "unsupported RWF_DONTCACHE must not reach FsOps::write"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_nowait_returns_eagain_when_inode_lock_is_held() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );
        let _held = fuse.acquire_mutation_inode_guards(&[InodeNumber(42)]);

        let started = Instant::now();
        let err = fuse
            .dispatch_write_with_intent(
                42,
                0,
                b"nowait",
                WriteIntent::from_fuse(0, fuse_consts::RWF_NOWAIT, 0),
            )
            .expect_err("NOWAIT write should not block behind held inode lock");

        assert!(matches!(err, MutationDispatchError::Errno(libc::EAGAIN)));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(10),
            "NOWAIT path should fail fast instead of waiting for the inode mutation lock"
        );
        assert!(calls.lock().expect("lock calls").is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dispatch_write_sync_failure_still_invalidates_readahead_for_committed_inode()
    -> Result<(), String> {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_failing_fsync(
                Arc::clone(&calls),
                libc::EIO,
            )),
            &options,
        );

        let cached_ino = InodeNumber(42);
        let other_ino = InodeNumber(77);
        fuse.inner.readahead.insert(cached_ino, 100, vec![1, 2, 3]);
        fuse.inner.readahead.insert(other_ino, 100, vec![9, 9, 9]);

        let err = fuse
            .dispatch_write_with_intent(
                cached_ino.0,
                0,
                b"sync-fail",
                WriteIntent::from_fuse(9004, 0, libc::O_DSYNC),
            )
            .expect_err("failing fsync should surface as a write operation error");
        let MutationDispatchError::Operation { error, offset } = err else {
            return Err(format!(
                "expected operation error from fsync failure, got {err:?}"
            ));
        };
        assert_eq!(error.to_errno(), libc::EIO);
        assert_eq!(offset, Some(0));

        assert_eq!(fuse.inner.readahead.take(cached_ino, 100, 3), None);
        assert_eq!(
            fuse.inner.readahead.take(other_ino, 100, 3),
            Some(vec![9, 9, 9])
        );
        Ok(())
    }

    #[test]
    fn dispatch_write_invalidates_readahead_for_inode() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let cached_ino = InodeNumber(42);
        let other_ino = InodeNumber(77);
        fuse.inner.readahead.insert(cached_ino, 100, vec![1, 2, 3]);
        fuse.inner.readahead.insert(other_ino, 100, vec![9, 9, 9]);

        let written = fuse
            .dispatch_write(cached_ino.0, 0, b"abc")
            .expect("dispatch write");
        assert_eq!(written, 3);

        assert_eq!(fuse.inner.readahead.take(cached_ino, 100, 3), None);
        assert_eq!(
            fuse.inner.readahead.take(other_ino, 100, 3),
            Some(vec![9, 9, 9])
        );
    }

    #[test]
    fn dispatch_mkdir_routes_to_fsops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let attr = fuse
            .dispatch_mkdir(2, OsStr::new("logs"), 0o755, 123, 456)
            .expect("dispatch mkdir");
        assert_eq!(attr.ino, InodeNumber(101));
        assert_eq!(attr.kind, FfsFileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Mkdir {
                parent: InodeNumber(2),
                name: "logs".to_owned(),
                mode: 0o755,
                uid: 123,
                gid: 456,
            }]
        );
    }

    #[test]
    fn dispatch_rmdir_routes_to_fsops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        fuse.dispatch_rmdir(7, OsStr::new("tmp"))
            .expect("dispatch rmdir");
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Rmdir {
                parent: InodeNumber(7),
                name: "tmp".to_owned(),
            }]
        );
    }

    #[test]
    fn dispatch_rename_routes_to_fsops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        fuse.dispatch_rename(8, OsStr::new("old"), 9, OsStr::new("new"), 0)
            .expect("dispatch rename");
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Rename {
                parent: InodeNumber(8),
                name: "old".to_owned(),
                new_parent: InodeNumber(9),
                new_name: "new".to_owned(),
            }]
        );
    }

    #[test]
    fn dispatch_rename_serializes_overlapping_parent_pairs() {
        let (probe, max_active_renames) = RenameConcurrencyProbeFs::new(Duration::from_millis(40));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = Arc::new(FrankenFuse::with_options(Box::new(probe), &options));
        let start = Arc::new(std::sync::Barrier::new(2));

        std::thread::scope(|scope| {
            for (parent, name, new_parent, new_name) in
                [(8, "alpha", 9, "beta"), (9, "beta", 8, "alpha")]
            {
                let fuse = Arc::clone(&fuse);
                let start = Arc::clone(&start);
                scope.spawn(move || {
                    start.wait();
                    fuse.dispatch_rename(
                        parent,
                        OsStr::new(name),
                        new_parent,
                        OsStr::new(new_name),
                        0,
                    )
                    .expect("dispatch rename");
                });
            }
        });

        assert_eq!(max_active_renames.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dispatch_rename_allows_parallel_disjoint_parent_pairs() {
        let (probe, max_active_renames) = RenameConcurrencyProbeFs::new(Duration::from_millis(40));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = Arc::new(FrankenFuse::with_options(Box::new(probe), &options));
        let start = Arc::new(std::sync::Barrier::new(2));

        std::thread::scope(|scope| {
            for (parent, name, new_parent, new_name) in
                [(8, "alpha", 9, "beta"), (10, "gamma", 11, "delta")]
            {
                let fuse = Arc::clone(&fuse);
                let start = Arc::clone(&start);
                scope.spawn(move || {
                    start.wait();
                    fuse.dispatch_rename(
                        parent,
                        OsStr::new(name),
                        new_parent,
                        OsStr::new(new_name),
                        0,
                    )
                    .expect("dispatch rename");
                });
            }
        });

        assert_eq!(max_active_renames.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dispatch_write_rejects_negative_offset() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let err = fuse
            .dispatch_write(99, -1, b"z")
            .expect_err("negative offset should fail");
        assert!(matches!(err, MutationDispatchError::Errno(libc::EINVAL)));
        assert!(calls.lock().expect("lock calls").is_empty());
    }

    #[test]
    fn dispatch_copy_file_range_rejects_invalid_flags_before_backend() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        assert!(matches!(
            fuse.dispatch_copy_file_range(1, 0, 2, 0, 4096, 1),
            Err(MutationDispatchError::Errno(errno)) if errno == libc::EINVAL
        ));
        assert!(
            calls.lock().expect("lock calls").is_empty(),
            "backend must not be called for invalid copy_file_range flags"
        );
    }

    #[test]
    fn dispatch_copy_file_range_zero_length_returns_without_backend_scope() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
        );

        assert_eq!(
            fuse.dispatch_copy_file_range(1, 5, 2, 7, 0, 0)
                .expect("zero-length copy_file_range should succeed"),
            0
        );
        assert!(
            calls.lock().expect("lock calls").is_empty(),
            "zero-length copy_file_range must not open a request scope, commit, read, or write"
        );
    }

    #[test]
    fn dispatch_copy_file_range_zero_length_bypasses_read_only_guard() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::with_scope_recording(
            Arc::clone(&calls),
        )));

        assert_eq!(
            fuse.dispatch_copy_file_range(1, 5, 2, 7, 0, 0)
                .expect("zero-length copy_file_range should not require a writable mount"),
            0
        );
        assert!(
            calls.lock().expect("lock calls").is_empty(),
            "zero-length copy_file_range must bypass read-only guards and backend scopes"
        );
    }

    #[test]
    fn dispatch_copy_file_range_rejects_overlapping_same_inode_ranges() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        assert!(matches!(
            fuse.dispatch_copy_file_range(1, 0, 1, 2, 4096, 0),
            Err(MutationDispatchError::Operation { error, .. })
                if error.to_errno() == libc::EINVAL
        ));
        assert!(
            calls.lock().expect("lock calls").is_empty(),
            "overlapping same-inode copy must not touch the backend"
        );
    }

    #[test]
    fn dispatch_mutations_return_erofs_when_read_only() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::new(Arc::clone(&calls))));

        assert!(matches!(
            fuse.dispatch_write(1, 0, b"x"),
            Err(MutationDispatchError::Errno(libc::EROFS))
        ));
        assert!(matches!(
            fuse.dispatch_copy_file_range(1, 0, 2, 0, 1, 0),
            Err(MutationDispatchError::Errno(libc::EROFS))
        ));
        assert!(matches!(
            fuse.dispatch_mkdir(1, OsStr::new("d"), 0o755, 1, 1),
            Err(MutationDispatchError::Errno(libc::EROFS))
        ));
        assert!(matches!(
            fuse.dispatch_rmdir(1, OsStr::new("d")),
            Err(MutationDispatchError::Errno(libc::EROFS))
        ));
        assert!(matches!(
            fuse.dispatch_rename(1, OsStr::new("a"), 2, OsStr::new("b"), 0),
            Err(MutationDispatchError::Errno(libc::EROFS))
        ));
        assert!(calls.lock().expect("lock calls").is_empty());
    }

    #[test]
    fn dispatch_write_returns_ebusy_under_emergency_backpressure() {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let pressure = Arc::new(SystemPressure::with_headroom(0.02));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);
        let fuse = FrankenFuse::with_backpressure(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
            gate,
        );

        let err = fuse
            .dispatch_write(11, 0, b"abc")
            .expect_err("write should be shed");
        assert!(matches!(err, MutationDispatchError::Errno(libc::EBUSY)));
        assert!(calls.lock().expect("lock calls").is_empty());
    }

    #[test]
    fn fuse_boundary_emergency_backpressure_sheds_metadata_mutations_without_backend_scope() {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let pressure = Arc::new(SystemPressure::with_headroom(0.02));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);
        let fuse = FrankenFuse::with_backpressure(
            Box::new(MutationRecordingFs::with_scope_recording(Arc::clone(
                &calls,
            ))),
            &options,
            gate,
        );

        let create = fuse.create_for_fuzzing(2, b"pressure-create", 0o644, 1000, 1000);
        assert!(
            matches!(create, Err(errno) if errno == libc::EBUSY),
            "create under emergency backpressure should return EBUSY, got {create:?}"
        );

        let attrs = SetAttrRequest {
            mode: Some(0o600),
            uid: None,
            gid: None,
            size: Some(128),
            atime: None,
            mtime: None,
        };
        let setattr = fuse.setattr_for_fuzzing(11, &attrs);
        assert!(
            matches!(setattr, Err(errno) if errno == libc::EBUSY),
            "setattr under emergency backpressure should return EBUSY, got {setattr:?}"
        );

        let cx = FrankenFuse::cx_for_request();
        let setxattr =
            fuse.dispatch_setxattr(&cx, 11, "user.pressure", b"blocked", XATTR_FLAG_CREATE, 0);
        assert!(
            matches!(setxattr, Err(MutationDispatchError::Errno(errno)) if errno == libc::EBUSY),
            "setxattr under emergency backpressure should return EBUSY, got {setxattr:?}"
        );

        let recorded_calls = match calls.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        assert!(
            recorded_calls.is_empty(),
            "shed metadata mutations must not begin backend scopes or mutate FsOps: {recorded_calls:?}"
        );

        let metrics = fuse.metrics().snapshot();
        assert_eq!(
            metrics.requests_shed, 3,
            "each rejected metadata mutation should increment the FUSE shed counter"
        );
    }

    #[test]
    fn dispatch_setxattr_rejects_invalid_requests_before_backend_mutation() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );
        let invalid_cases = [
            (
                "create_replace",
                XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE,
                0_u32,
            ),
            ("unknown_flag_bits", 0x40, 0_u32),
            ("nonzero_position", XATTR_FLAG_CREATE, 1_u32),
        ];

        let cx = FrankenFuse::cx_for_request();
        for (label, flags, position) in invalid_cases {
            let err = fuse
                .dispatch_setxattr(&cx, 42, "user.bad", b"value", flags, position)
                .unwrap_err();
            assert!(
                matches!(err, MutationDispatchError::Errno(libc::EINVAL)),
                "{label} should reject with EINVAL, got {err:?}"
            );
        }

        assert!(
            calls.lock().expect("lock calls").is_empty(),
            "invalid requests must not touch the backend"
        );
    }

    #[test]
    fn fuse_error_context_returns_correct_errno() {
        let cases: Vec<(FfsError, libc::c_int)> = vec![
            (FfsError::NotFound("test".into()), libc::ENOENT),
            (FfsError::PermissionDenied, libc::EACCES),
            (FfsError::IsDirectory, libc::EISDIR),
            (FfsError::NotDirectory, libc::ENOTDIR),
            (FfsError::ReadOnly, libc::EROFS),
            (FfsError::NoSpace, libc::ENOSPC),
            (FfsError::NameTooLong, libc::ENAMETOOLONG),
            (FfsError::NotEmpty, libc::ENOTEMPTY),
            (FfsError::Exists, libc::EEXIST),
            (FfsError::Cancelled, libc::EINTR),
            (FfsError::MvccConflict { tx: 1, block: 2 }, libc::EAGAIN),
            (
                FfsError::Corruption {
                    block: 0,
                    detail: "bad csum".into(),
                },
                libc::EIO,
            ),
            (FfsError::Format("bad".into()), libc::EINVAL),
            (
                FfsError::UnsupportedFeature("ENCRYPT".into()),
                libc::EOPNOTSUPP,
            ),
            (FfsError::RepairFailed("irrecoverable".into()), libc::EIO),
        ];

        for (error, expected) in &cases {
            let ctx = FuseErrorContext {
                error,
                operation: "test_op",
                ino: 42,
                offset: None,
            };
            assert_eq!(ctx.log_and_errno(), *expected, "wrong errno for {error:?}");
        }
    }

    #[test]
    fn fuse_error_context_with_offset() {
        let error = FfsError::NotFound("file.txt".into());
        let ctx = FuseErrorContext {
            error: &error,
            operation: "read",
            ino: 100,
            offset: Some(4096),
        };
        assert_eq!(ctx.log_and_errno(), libc::ENOENT);
    }

    // ── Thread safety tests ──────────────────────────────────────────────

    #[test]
    fn franken_fuse_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FrankenFuse>();
        assert_send_sync::<FuseInner>();
        assert_send_sync::<AtomicMetrics>();
    }

    #[test]
    fn mount_options_resolved_thread_count() {
        let mut opts = MountOptions::default();
        assert_eq!(opts.worker_threads, 0);
        // Auto resolution gives at least 1.
        assert!(opts.resolved_thread_count() >= 1);
        assert!(opts.resolved_thread_count() <= 8);

        opts.worker_threads = 4;
        assert_eq!(opts.resolved_thread_count(), 4);
    }

    #[test]
    fn franken_fuse_with_options_sets_thread_count() {
        let opts = MountOptions {
            worker_threads: 6,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(Box::new(MinimalTestFs), &opts);
        assert_eq!(fuse.thread_count(), 6);
    }

    #[test]
    fn vendored_fuser_exposes_abi_7_40_protocol_surface() {
        assert_eq!(fuse_consts::FOPEN_PASSTHROUGH, 1_u32 << 7);
        assert_eq!(fuse_consts::FUSE_SPLICE_WRITE, 1_u64 << 7);
        assert_eq!(fuse_consts::FUSE_SPLICE_MOVE, 1_u64 << 8);
        assert_eq!(fuse_consts::FUSE_SPLICE_READ, 1_u64 << 9);
        assert_eq!(fuse_consts::FUSE_PASSTHROUGH, 1_u64 << 37);
        assert_eq!(fuse_consts::FUSE_WRITE_KILL_SUIDGID, 1_u32 << 2);
        assert_eq!(
            fuse_consts::FUSE_WRITE_KILL_PRIV,
            fuse_consts::FUSE_WRITE_KILL_SUIDGID
        );

        #[cfg(target_os = "linux")]
        {
            assert_eq!(fuse_consts::RWF_HIPRI, 0x0000_0001);
            assert_eq!(fuse_consts::RWF_DSYNC, 0x0000_0002);
            assert_eq!(fuse_consts::RWF_SYNC, 0x0000_0004);
            assert_eq!(fuse_consts::RWF_NOWAIT, 0x0000_0008);
            assert_eq!(fuse_consts::RWF_APPEND, 0x0000_0010);
            assert_eq!(fuse_consts::RWF_NOAPPEND, 0x0000_0020);
            assert_eq!(fuse_consts::RWF_ATOMIC, 0x0000_0040);
            assert_eq!(fuse_consts::RWF_DONTCACHE, 0x0000_0080);
            assert_eq!(
                fuse_consts::RWF_SUPPORTED,
                fuse_consts::RWF_HIPRI
                    | fuse_consts::RWF_DSYNC
                    | fuse_consts::RWF_SYNC
                    | fuse_consts::RWF_NOWAIT
                    | fuse_consts::RWF_APPEND
                    | fuse_consts::RWF_NOAPPEND
                    | fuse_consts::RWF_ATOMIC
                    | fuse_consts::RWF_DONTCACHE
            );
        }
    }

    #[test]
    fn atomic_metrics_snapshot_initially_zero() {
        let m = AtomicMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.requests_total, 0);
        assert_eq!(s.requests_ok, 0);
        assert_eq!(s.requests_err, 0);
        assert_eq!(s.bytes_read, 0);
    }

    #[test]
    fn atomic_metrics_record_ok_and_err() {
        let m = AtomicMetrics::new();
        m.record_ok();
        m.record_ok();
        m.record_err();
        m.record_bytes_read(1024);
        let s = m.snapshot();
        assert_eq!(s.requests_total, 3);
        assert_eq!(s.requests_ok, 2);
        assert_eq!(s.requests_err, 1);
        assert_eq!(s.bytes_read, 1024);
    }

    #[test]
    fn atomic_metrics_saturate_at_numeric_limits() {
        let m = AtomicMetrics::new();
        m.requests_total.0.store(u64::MAX - 1, Ordering::Relaxed);
        m.requests_ok.0.store(u64::MAX, Ordering::Relaxed);
        m.requests_err.0.store(u64::MAX - 1, Ordering::Relaxed);
        m.bytes_read.0.store(u64::MAX - 8, Ordering::Relaxed);
        m.requests_throttled.0.store(u64::MAX, Ordering::Relaxed);
        m.requests_shed.0.store(u64::MAX - 1, Ordering::Relaxed);

        m.record_ok();
        m.record_err();
        m.record_bytes_read(16);
        m.record_throttled();
        m.record_shed();

        let s = m.snapshot();
        assert_eq!(s.requests_total, u64::MAX);
        assert_eq!(s.requests_ok, u64::MAX);
        assert_eq!(s.requests_err, u64::MAX);
        assert_eq!(s.bytes_read, u64::MAX);
        assert_eq!(s.requests_throttled, u64::MAX);
        assert_eq!(s.requests_shed, u64::MAX);
    }

    #[test]
    fn cache_line_padded_alignment() {
        let padded = CacheLinePadded(AtomicU64::new(0));
        let ptr = std::ptr::addr_of!(padded) as usize;
        // Must be 64-byte aligned.
        assert_eq!(ptr % 64, 0);
    }

    #[test]
    fn request_scope_updates_metrics() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();

        // Successful request.
        let _ = fuse.with_request_scope(&cx, RequestOp::Read, |_cx, _scope| Ok::<u32, FfsError>(7));

        let s = fuse.metrics().snapshot();
        assert_eq!(s.requests_total, 1);
        assert_eq!(s.requests_ok, 1);
        assert_eq!(s.requests_err, 0);
    }

    #[test]
    fn request_scope_records_err_metric() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();

        let _ = fuse.with_request_scope(&cx, RequestOp::Read, |_cx, _scope| {
            Err::<u32, FfsError>(FfsError::NotFound("gone".into()))
        });

        let s = fuse.metrics().snapshot();
        assert_eq!(s.requests_total, 1);
        assert_eq!(s.requests_ok, 0);
        assert_eq!(s.requests_err, 1);
    }

    #[test]
    fn concurrent_fsops_access_no_deadlock() {
        // Verify FsOps can be called concurrently from multiple threads
        // via Arc<dyn FsOps>.
        let fs: Arc<dyn FsOps> = Arc::new(MinimalTestFs);
        let barrier = Arc::new(std::sync::Barrier::new(10));

        std::thread::scope(|s| {
            for _ in 0..10 {
                let fs: Arc<dyn FsOps> = Arc::clone(&fs);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    let cx = Cx::for_testing();
                    barrier.wait();
                    for _ in 0..100 {
                        let _ = fs.getattr(&cx, &mut RequestScope::empty(), InodeNumber(1));
                        let _ = fs.readdir(&cx, &mut RequestScope::empty(), InodeNumber(1), 0);
                        let _ = fs.read(&cx, &mut RequestScope::empty(), InodeNumber(1), 0, 4096);
                    }
                });
            }
        });
    }

    #[test]
    fn concurrent_metrics_stress() {
        // 10 threads x 1000 increments each.
        let metrics = Arc::new(AtomicMetrics::new());
        let barrier = Arc::new(std::sync::Barrier::new(10));

        std::thread::scope(|s| {
            for _ in 0..10 {
                let m = Arc::clone(&metrics);
                let b = Arc::clone(&barrier);
                s.spawn(move || {
                    b.wait();
                    for _ in 0..1000 {
                        m.record_ok();
                        m.record_bytes_read(512);
                    }
                });
            }
        });

        let s = metrics.snapshot();
        assert_eq!(s.requests_total, 10_000);
        assert_eq!(s.requests_ok, 10_000);
        assert_eq!(s.requests_err, 0);
        assert_eq!(s.bytes_read, 10_000 * 512);
    }

    #[test]
    fn fuse_inner_shared_across_threads() {
        // Simulate multi-threaded FUSE dispatch: multiple threads share
        // the same FuseInner via Arc and call FsOps concurrently.
        let inner = Arc::new(FuseInner {
            ops: Arc::new(MinimalTestFs),
            metrics: Arc::new(AtomicMetrics::new()),
            thread_count: 4,
            read_only: true,
            writeback_cache: false,
            mountpoint: None,
            kernel_notifier: Mutex::new(None),
            ioctl_trace: None,
            backpressure: None,
            writeback_batches: Mutex::new(BTreeMap::new()),
            access_predictor: AccessPredictor::default(),
            readahead: ReadaheadManager::new(MAX_PENDING_READAHEAD_ENTRIES),
            inode_locks: Arc::new(FuseInodeLocks::default()),
            read_offload: None,
        });
        let barrier = Arc::new(std::sync::Barrier::new(10));

        std::thread::scope(|s| {
            for _ in 0..10 {
                let inner = Arc::clone(&inner);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    let cx = Cx::for_testing();
                    barrier.wait();
                    for _ in 0..1000 {
                        let _ = inner
                            .ops
                            .getattr(&cx, &mut RequestScope::empty(), InodeNumber(2));
                        inner.metrics.record_ok();
                        let _ = inner.ops.read(
                            &cx,
                            &mut RequestScope::empty(),
                            InodeNumber(2),
                            0,
                            4096,
                        );
                        inner.metrics.record_bytes_read(4096);
                    }
                });
            }
        });

        let snap = inner.metrics.snapshot();
        assert_eq!(snap.requests_ok, 10_000);
        assert_eq!(snap.bytes_read, 10_000 * 4096);
    }

    // ── Mount lifecycle tests ─────────────────────────────────────────

    #[test]
    fn mount_config_default_has_30s_timeout() {
        let cfg = MountConfig::default();
        assert_eq!(cfg.unmount_timeout, Duration::from_secs(30));
        assert!(cfg.options.read_only);
    }

    #[test]
    fn mount_managed_rejects_empty_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(MinimalTestFs);
        let err = mount_managed(ops, "", &MountConfig::default()).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "expected 'empty' in error: {err}"
        );
    }

    #[test]
    fn mount_managed_rejects_nonexistent_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(MinimalTestFs);
        let err = mount_managed(
            ops,
            "/tmp/frankenfs_no_such_dir_xyzzy",
            &MountConfig::default(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "expected 'does not exist' in error: {err}"
        );
    }

    #[test]
    fn mount_managed_rejects_file_mountpoint() {
        let file_path = existing_file_mountpoint();
        let ops: Box<dyn FsOps> = Box::new(MinimalTestFs);
        let err = mount_managed(ops, &file_path, &MountConfig::default()).unwrap_err();
        let err_text = err.to_string();
        assert!(
            err_text.contains("not a directory"),
            "expected 'not a directory' in error: {err_text}"
        );
    }

    #[test]
    fn mount_handle_shutdown_flag_lifecycle() {
        // Build a MountHandle manually (without a real FUSE session) to
        // exercise the shutdown flag + metrics plumbing.
        let metrics = Arc::new(AtomicMetrics::new());
        metrics.record_ok();
        metrics.record_ok();
        metrics.record_bytes_read(8192);

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/test"),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::clone(&metrics),
            config: MountConfig::default(),
        };

        // Shutdown flag starts false.
        assert!(!handle.shutdown_flag().load(Ordering::Relaxed));

        // Metrics snapshot reflects pre-recorded data.
        let snap = handle.metrics_snapshot();
        assert_eq!(snap.requests_ok, 2);
        assert_eq!(snap.bytes_read, 8192);

        // Unmount returns final snapshot.
        let final_snap = handle.unmount();
        assert_eq!(final_snap.requests_ok, 2);
    }

    #[test]
    fn mount_handle_debug_format() {
        const MOUNT_HANDLE_DEBUG_GOLDEN: &str = concat!(
            "MountHandle { ",
            "mountpoint: \"/mnt/dbg\", ",
            "active: false, ",
            "shutdown: false, ",
            "metrics: MetricsSnapshot { requests_total: 0, requests_ok: 0, requests_err: 0, ",
            "bytes_read: 0, requests_throttled: 0, requests_shed: 0 }, ",
            "unmount_timeout: 30s }"
        );

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/dbg"),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(AtomicMetrics::new()),
            config: MountConfig::default(),
        };
        let dbg = format!("{handle:?}");
        assert_eq!(dbg, MOUNT_HANDLE_DEBUG_GOLDEN);
    }

    #[test]
    fn mount_handle_drop_is_safe_without_session() {
        // Verify that dropping a MountHandle with no session doesn't panic.
        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/drop"),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(AtomicMetrics::new()),
            config: MountConfig::default(),
        };
        drop(handle);
    }

    #[test]
    fn mount_handle_wait_returns_on_shutdown() {
        let metrics = Arc::new(AtomicMetrics::new());
        metrics.record_ok();

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/wait"),
            shutdown: Arc::clone(&shutdown),
            metrics,
            config: MountConfig::default(),
        };

        // Set the shutdown flag from another thread after one poll interval.
        let trigger_delay = MOUNT_HANDLE_WAIT_POLL_INTERVAL;
        let max_wait = MOUNT_HANDLE_WAIT_POLL_INTERVAL.saturating_mul(6);
        let shutdown_thread = std::thread::spawn(move || {
            std::thread::sleep(trigger_delay);
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        let started = std::time::Instant::now();
        let snap = handle.wait();
        let elapsed = started.elapsed();
        shutdown_thread
            .join()
            .expect("shutdown trigger thread should not panic");
        assert_eq!(snap.requests_ok, 1);
        assert!(
            elapsed < max_wait,
            "MountHandle::wait should observe shutdown within {max_wait:?}, elapsed={elapsed:?}"
        );
    }

    #[test]
    fn mount_handle_wait_respects_unmount_timeout() {
        let config = MountConfig {
            options: MountOptions::default(),
            backpressure: None,
            unmount_timeout: Duration::from_millis(60),
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/timeout"),
            shutdown: Arc::clone(&shutdown),
            metrics: Arc::new(AtomicMetrics::new()),
            config: config.clone(),
        };

        // Set the shutdown flag after a delay. Since session is None,
        // do_unmount will exit immediately. We just want to ensure it doesn't hang.
        let shutdown_thread = std::thread::spawn(move || {
            std::thread::sleep(config.unmount_timeout);
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        let started = Instant::now();
        let snap = handle.wait();
        let elapsed = started.elapsed();

        shutdown_thread.join().unwrap();

        assert_eq!(snap.requests_total, 0);
        assert!(elapsed >= config.unmount_timeout);
        assert!(elapsed < Duration::from_millis(500));
    }

    // ── FuseErrorContext errno mapping for all 21 variants (bd-2s4.6) ──

    #[test]
    fn fuse_error_context_log_and_errno_covers_all_variants() {
        let cases: Vec<(FfsError, libc::c_int)> = vec![
            (FfsError::Io(std::io::Error::other("test")), libc::EIO),
            (
                FfsError::Corruption {
                    block: 1,
                    detail: "bad crc".into(),
                },
                libc::EIO,
            ),
            (FfsError::Format("bad magic".into()), libc::EINVAL),
            (FfsError::Parse("truncated".into()), libc::EINVAL),
            (
                FfsError::UnsupportedFeature("ENCRYPT".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::IncompatibleFeature("missing FILETYPE".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::UnsupportedBlockSize("8192".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::InvalidGeometry("blocks_per_group=0".into()),
                libc::EINVAL,
            ),
            (FfsError::MvccConflict { tx: 1, block: 2 }, libc::EAGAIN),
            (FfsError::Cancelled, libc::EINTR),
            (FfsError::NoSpace, libc::ENOSPC),
            (FfsError::NotFound("gone".into()), libc::ENOENT),
            (FfsError::PermissionDenied, libc::EACCES),
            (FfsError::ReadOnly, libc::EROFS),
            (FfsError::NotDirectory, libc::ENOTDIR),
            (FfsError::IsDirectory, libc::EISDIR),
            (FfsError::NotEmpty, libc::ENOTEMPTY),
            (FfsError::NameTooLong, libc::ENAMETOOLONG),
            (FfsError::Exists, libc::EEXIST),
            (FfsError::RepairFailed("checksum".into()), libc::EIO),
        ];

        // 20 variants listed; verify count matches expectation.
        assert_eq!(
            cases.len(),
            20,
            "expected all 20 constructible FfsError variants"
        );

        for (error, expected) in &cases {
            let ctx = FuseErrorContext {
                error,
                operation: "test_op",
                ino: 99,
                offset: Some(0),
            };
            assert_eq!(ctx.log_and_errno(), *expected, "wrong errno for {error:?}");
        }
    }

    #[test]
    fn fuse_error_context_io_preserves_raw_os_error() {
        let raw = std::io::Error::from_raw_os_error(libc::EPERM);
        let err = FfsError::Io(raw);
        let ctx = FuseErrorContext {
            error: &err,
            operation: "open",
            ino: 5,
            offset: None,
        };
        assert_eq!(ctx.log_and_errno(), libc::EPERM);
    }

    #[test]
    fn fuse_error_context_enoent_does_not_panic() {
        // ENOENT is logged at trace, not warn — ensure it doesn't panic.
        let err = FfsError::NotFound("test".into());
        let ctx = FuseErrorContext {
            error: &err,
            operation: "lookup",
            ino: 2,
            offset: None,
        };
        assert_eq!(ctx.log_and_errno(), libc::ENOENT);
    }

    // ── Read-only flag propagation ───────────────────────────────────────

    #[test]
    fn fuse_inner_read_only_true_when_mount_option_set() {
        let opts = MountOptions {
            read_only: true,
            ..Default::default()
        };
        let fuse = FrankenFuse::with_options(Box::new(MinimalTestFs), &opts);
        assert!(fuse.inner.read_only);
    }

    #[test]
    fn fuse_inner_read_only_false_when_writable() {
        let opts = MountOptions {
            read_only: false,
            ..Default::default()
        };
        let fuse = FrankenFuse::with_options(Box::new(MinimalTestFs), &opts);
        assert!(!fuse.inner.read_only);
    }

    #[test]
    fn build_mount_options_omits_ro_when_read_write() {
        let opts = MountOptions {
            read_only: false,
            allow_other: false,
            auto_unmount: true,
            writeback_cache: WritebackCacheMode::Disabled,
            ioctl_trace_path: None,
            worker_threads: 0,
        };
        let mount_opts = build_mount_options(&opts);
        // Should NOT contain RO
        let has_ro = mount_opts.iter().any(|o| matches!(o, MountOption::RO));
        assert!(!has_ro, "RO should not be present when read_only=false");
    }

    #[test]
    fn build_mount_options_includes_allow_other_when_set() {
        let opts = MountOptions {
            read_only: true,
            allow_other: true,
            auto_unmount: false,
            writeback_cache: WritebackCacheMode::Disabled,
            ioctl_trace_path: None,
            worker_threads: 0,
        };
        let mount_opts = build_mount_options(&opts);
        let has_allow = mount_opts
            .iter()
            .any(|o| matches!(o, MountOption::AllowOther));
        assert!(has_allow, "AllowOther should be present");
    }

    #[test]
    fn build_mount_options_includes_queue_tuning_when_worker_threads_explicit() {
        let opts = MountOptions {
            read_only: true,
            allow_other: false,
            auto_unmount: true,
            writeback_cache: WritebackCacheMode::Disabled,
            ioctl_trace_path: None,
            worker_threads: 8,
        };
        let mount_opts = build_mount_options(&opts);
        assert!(
            mount_opts
                .iter()
                .any(|o| matches!(o, MountOption::CUSTOM(v) if v == "max_background=8"))
        );
        assert!(
            mount_opts
                .iter()
                .any(|o| matches!(o, MountOption::CUSTOM(v) if v == "congestion_threshold=6"))
        );
    }

    #[test]
    fn parse_mount_options_accepts_supported_csv_flags() {
        let opts = parse_mount_options_for_fuzzing(
            b"rw,allow_other,auto_unmount=false,worker_threads=4,fsname=frankenfs,subtype=ffs",
        )
        .expect("supported mount option csv should parse");

        assert!(!opts.read_only);
        assert!(opts.allow_other);
        assert!(!opts.auto_unmount);
        assert!(!opts.writeback_cache.is_enabled());
        assert_eq!(opts.worker_threads, 4);
    }

    #[test]
    fn parse_mount_options_rejects_malformed_csv() {
        assert!(matches!(
            parse_mount_options_for_fuzzing(b"rw,,allow_other"),
            Err(MountOptionParseError::EmptyOption)
        ));
        assert!(matches!(
            parse_mount_options_for_fuzzing(b"worker_threads=not-a-number"),
            Err(MountOptionParseError::InvalidValue { .. })
        ));
        assert!(matches!(
            parse_mount_options_for_fuzzing(&[0xFF, b'r', b'o']),
            Err(MountOptionParseError::NonUtf8)
        ));
    }

    #[test]
    fn build_mount_options_auto_worker_threads_omits_queue_tuning() {
        let opts = MountOptions {
            read_only: true,
            allow_other: false,
            auto_unmount: true,
            writeback_cache: WritebackCacheMode::Disabled,
            ioctl_trace_path: None,
            worker_threads: 0,
        };
        let mount_opts = build_mount_options(&opts);
        assert!(
            !mount_opts
                .iter()
                .any(|o| matches!(o, MountOption::CUSTOM(v) if v.starts_with("max_background=")))
        );
        assert!(!mount_opts.iter().any(
            |o| matches!(o, MountOption::CUSTOM(v) if v.starts_with("congestion_threshold="))
        ));
    }

    #[test]
    fn build_mount_options_excludes_kernel_writeback_cache_mode() {
        let opts = MountOptions::default();
        let mount_opts = build_mount_options(&opts);
        assert!(
            !mount_opts.iter().any(
                |option| matches!(option, MountOption::CUSTOM(v) if v.contains("writeback_cache"))
            ),
            "writeback_cache should remain disabled in V1 mount options: {mount_opts:?}"
        );
        let debug_dump = format!("{mount_opts:?}").to_ascii_lowercase();
        assert!(
            !debug_dump.contains("writebackcache"),
            "unexpected WritebackCache-like option in mount options: {mount_opts:?}"
        );
    }

    #[test]
    fn build_mount_options_excludes_writeback_cache_across_variants() {
        let cases = vec![
            ("default_ro", MountOptions::default()),
            (
                "read_write",
                MountOptions {
                    read_only: false,
                    ..MountOptions::default()
                },
            ),
            (
                "rw_allow_other",
                MountOptions {
                    read_only: false,
                    allow_other: true,
                    ..MountOptions::default()
                },
            ),
            (
                "rw_no_auto_unmount",
                MountOptions {
                    read_only: false,
                    auto_unmount: false,
                    ..MountOptions::default()
                },
            ),
            (
                "rw_allow_other_threads",
                MountOptions {
                    read_only: false,
                    allow_other: true,
                    auto_unmount: false,
                    writeback_cache: WritebackCacheMode::Disabled,
                    ioctl_trace_path: None,
                    worker_threads: 8,
                },
            ),
        ];

        for (case, opts) in cases {
            let labels = mount_option_labels_for_fuzzing(&opts);
            let mount_opts = build_mount_options(&opts);
            let debug_dump = mount_option_debug_lines(&mount_opts);
            println!(
                "WRITEBACK_CACHE_FUSER_OPTIONS|case={case}|labels={}|debug={}",
                labels.join(";"),
                debug_dump.replace('\n', "|")
            );

            assert!(
                labels.iter().all(|label| {
                    let label = label.to_ascii_lowercase();
                    !label.contains("writeback_cache") && !label.contains("writebackcache")
                }),
                "writeback_cache surfaced in canonical mount labels for {case}: {labels:?}"
            );
            assert!(
                !mount_opts
                    .iter()
                    .any(|option| matches!(option, MountOption::CUSTOM(value)
                        if value.to_ascii_lowercase().contains("writeback_cache"))),
                "writeback_cache surfaced as a custom FUSE option for {case}: {mount_opts:?}"
            );
            assert!(
                !debug_dump.to_ascii_lowercase().contains("writebackcache"),
                "WritebackCache-like enum appeared for {case}: {debug_dump}"
            );
        }
    }

    #[test]
    fn parse_mount_options_accepts_explicit_writeback_cache_token() {
        let opts = parse_mount_options_for_fuzzing(b"rw,writeback_cache")
            .expect("explicit rw writeback_cache option should parse");
        assert!(!opts.read_only);
        assert!(opts.writeback_cache.is_enabled());
    }

    #[test]
    fn build_mount_options_includes_writeback_cache_only_when_opted_in() {
        let opts = MountOptions {
            read_only: false,
            writeback_cache: WritebackCacheMode::Enabled,
            ..MountOptions::default()
        };
        let labels = mount_option_labels_for_fuzzing(&opts);
        println!(
            "WRITEBACK_CACHE_OPT_IN_FUSER_OPTIONS|case=explicit_rw_opt_in|labels={}",
            labels.join(";")
        );
        assert!(
            labels.iter().any(|label| label == "writeback_cache"),
            "explicit writeback_cache opt-in should reach canonical mount labels: {labels:?}"
        );
    }

    #[test]
    fn validate_mount_options_rejects_read_only_writeback_cache() {
        let opts = MountOptions {
            read_only: true,
            writeback_cache: WritebackCacheMode::Enabled,
            ..MountOptions::default()
        };
        let err = validate_mount_options(&opts)
            .expect_err("read-only writeback_cache request must fail before mounting");
        let message = err.to_string();
        assert!(
            message.contains("writeback_cache requires an explicit read-write mount"),
            "unexpected error: {message}"
        );
    }

    // ── should_shed backpressure tests ───────────────────────────────────

    fn backpressure_gate_for_headroom(headroom: f32) -> Arc<BackpressureGate> {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        let pressure = Arc::new(SystemPressure::with_headroom(headroom));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        Arc::new(BackpressureGate::new(fsm))
    }

    #[test]
    fn should_shed_returns_false_without_backpressure_gate() {
        let fuse = FrankenFuse::new(Box::new(MinimalTestFs));
        // No backpressure gate → never shed.
        assert!(!fuse.should_shed(RequestOp::Read));
        assert!(!fuse.should_shed(RequestOp::Write));
        assert!(!fuse.should_shed(RequestOp::Create));
        assert!(!fuse.should_shed(RequestOp::Mkdir));
    }

    #[test]
    fn mount_config_default_keeps_backpressure_disabled() {
        let config = MountConfig::default();
        assert!(config.backpressure.is_none());

        let fuse = FrankenFuse::with_mount_config(Box::new(MinimalTestFs), None, &config);

        assert!(!fuse.should_shed(RequestOp::Write));
        assert!(!fuse.should_shed(RequestOp::Create));
        let metrics = fuse.metrics().snapshot();
        assert_eq!(metrics.requests_throttled, 0);
        assert_eq!(metrics.requests_shed, 0);
    }

    #[test]
    fn mount_config_backpressure_gate_reaches_should_shed_and_metrics() {
        let cases = [
            ("green", 0.95_f32, RequestOp::Write, false, 0, 0),
            ("yellow", 0.75_f32, RequestOp::Write, false, 0, 0),
            ("orange", 0.50_f32, RequestOp::Write, false, 1, 0),
            ("red", 0.20_f32, RequestOp::Create, true, 0, 1),
        ];

        for (label, headroom, op, expected_shed, expected_throttled, expected_shed_count) in cases {
            let config = MountConfig {
                backpressure: Some(backpressure_gate_for_headroom(headroom)),
                ..MountConfig::default()
            };
            let fuse = FrankenFuse::with_mount_config(Box::new(MinimalTestFs), None, &config);

            assert_eq!(fuse.should_shed(op), expected_shed, "{label}");
            let metrics = fuse.metrics().snapshot();
            assert_eq!(metrics.requests_throttled, expected_throttled, "{label}");
            assert_eq!(metrics.requests_shed, expected_shed_count, "{label}");
        }
    }

    #[test]
    fn should_shed_with_emergency_gate_sheds_writes() {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        // Emergency level: headroom 0.02 → all writes shed.
        let pressure = Arc::new(SystemPressure::with_headroom(0.02));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        let opts = MountOptions::default();
        let fuse = FrankenFuse::with_backpressure(Box::new(MinimalTestFs), &opts, gate);

        // Reads proceed.
        assert!(!fuse.should_shed(RequestOp::Read));
        assert!(!fuse.should_shed(RequestOp::Lookup));
        assert!(!fuse.should_shed(RequestOp::Getattr));
        assert!(!fuse.should_shed(RequestOp::Readdir));

        // Writes are shed.
        assert!(fuse.should_shed(RequestOp::Write));
        assert!(fuse.should_shed(RequestOp::Create));
        assert!(fuse.should_shed(RequestOp::Mkdir));
        assert!(fuse.should_shed(RequestOp::Unlink));
        assert!(fuse.should_shed(RequestOp::Rmdir));
        assert!(fuse.should_shed(RequestOp::Rename));
        assert!(fuse.should_shed(RequestOp::Link));
        assert!(fuse.should_shed(RequestOp::Symlink));
        assert!(fuse.should_shed(RequestOp::Fallocate));
        assert!(fuse.should_shed(RequestOp::Setattr));
        assert!(fuse.should_shed(RequestOp::Setxattr));
        assert!(fuse.should_shed(RequestOp::Removexattr));
    }

    #[test]
    fn should_shed_with_normal_gate_proceeds_all() {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        // Normal level: headroom 0.9 → all ops proceed.
        let pressure = Arc::new(SystemPressure::with_headroom(0.9));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        let opts = MountOptions::default();
        let fuse = FrankenFuse::with_backpressure(Box::new(MinimalTestFs), &opts, gate);

        assert!(!fuse.should_shed(RequestOp::Read));
        assert!(!fuse.should_shed(RequestOp::Write));
        assert!(!fuse.should_shed(RequestOp::Create));
        assert!(!fuse.should_shed(RequestOp::Mkdir));
    }

    #[test]
    fn should_shed_with_degraded_gate_throttles_without_shedding() {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        // Degraded level: headroom 0.2 -> writes are throttled (not shed).
        let pressure = Arc::new(SystemPressure::with_headroom(0.2));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        let opts = MountOptions::default();
        let fuse = FrankenFuse::with_backpressure(Box::new(MinimalTestFs), &opts, gate);

        let start = std::time::Instant::now();
        assert!(!fuse.should_shed(RequestOp::Write));
        assert!(start.elapsed() >= BACKPRESSURE_THROTTLE_DELAY);
    }

    #[test]
    fn should_shed_with_degraded_gate_honors_expired_cx_without_sleeping() {
        use asupersync::{Budget, SystemPressure};
        use ffs_core::DegradationFsm;

        let pressure = Arc::new(SystemPressure::with_headroom(0.2));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        let opts = MountOptions::default();
        let fuse = FrankenFuse::with_backpressure(Box::new(MinimalTestFs), &opts, gate);
        let expired = Budget::new().with_deadline(asupersync::types::Time::ZERO);
        let cx = Cx::for_testing_with_budget(expired);

        let start = std::time::Instant::now();
        let err = fuse
            .should_shed_with_cx(&cx, RequestOp::Write)
            .expect_err("expired request budget should reject throttle admission");

        assert!(matches!(err, FfsError::Cancelled));
        assert!(
            start.elapsed() < BACKPRESSURE_THROTTLE_DELAY,
            "expired Cx should not pay the throttle sleep"
        );
        let metrics = fuse.metrics().snapshot();
        assert_eq!(metrics.requests_throttled, 1);
        assert_eq!(metrics.requests_shed, 0);
    }

    #[test]
    fn backpressure_sleep_observes_mid_sleep_cancellation() {
        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();
        let delay = Duration::from_millis(250);

        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(15));
            cancel_cx.set_cancel_requested(true);
        });

        let start = std::time::Instant::now();
        let err = FrankenFuse::sleep_with_cx_budget(&cx, delay)
            .expect_err("cancelled Cx should interrupt backpressure sleep");
        let elapsed = start.elapsed();
        canceller.join().expect("canceller thread should finish");

        assert!(matches!(err, FfsError::Cancelled));
        assert!(
            elapsed < delay / 2,
            "cancelled Cx should interrupt throttle delay promptly, elapsed={elapsed:?}"
        );
    }

    // ── AccessPredictor backward sequence detection ──────────────────────

    #[test]
    fn access_predictor_backward_sequence_does_not_batch() {
        let predictor = AccessPredictor::default();
        let ino = InodeNumber(20);
        let size = 4096_u32;

        // Read backward: 3*4096, 2*4096, 1*4096, 0
        predictor.record_read(ino, u64::from(size) * 3, size);
        predictor.record_read(ino, u64::from(size) * 2, size);
        predictor.record_read(ino, u64::from(size), size);

        // After backward sequence, fetch_size should NOT batch (returns requested).
        assert_eq!(predictor.fetch_size(ino, 0, size), size);
    }

    #[test]
    fn access_predictor_random_access_does_not_batch() {
        let predictor = AccessPredictor::default();
        let ino = InodeNumber(21);
        let size = 4096_u32;

        // Random offsets.
        predictor.record_read(ino, 0, size);
        predictor.record_read(ino, u64::from(size) * 10, size);
        predictor.record_read(ino, u64::from(size) * 3, size);
        predictor.record_read(ino, u64::from(size) * 7, size);

        // Not sequential → no batching.
        assert_eq!(predictor.fetch_size(ino, u64::from(size) * 8, size), size);
    }

    #[test]
    fn access_predictor_different_inodes_are_independent() {
        let predictor = AccessPredictor::default();
        let size = 4096_u32;

        // Build forward sequence on inode 30.
        for i in 0..5_u64 {
            predictor.record_read(InodeNumber(30), i * u64::from(size), size);
        }

        // Inode 31 has no history — should not batch.
        assert_eq!(predictor.fetch_size(InodeNumber(31), 0, size), size);
    }

    #[test]
    fn access_predictor_history_is_bounded() {
        let predictor = AccessPredictor::new(3);
        let size = 4096_u32;

        for ino in 0..10_u64 {
            predictor.record_read(InodeNumber(100 + ino), 0, size);
        }

        let tracked = {
            let guard = match predictor.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.history.len()
        };
        assert_eq!(tracked, 3);
    }

    #[test]
    fn access_predictor_rebases_on_touch_overflow() {
        let predictor = AccessPredictor::new(3);
        let size = 4096_u32;

        {
            let mut guard = match predictor.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.history.insert(
                1,
                AccessPattern {
                    last_offset: 0,
                    last_size: size,
                    sequential_count: 1,
                    direction: AccessDirection::Forward,
                    last_touch: u64::MAX - 1,
                },
            );
            guard.history.insert(
                2,
                AccessPattern {
                    last_offset: u64::from(size),
                    last_size: size,
                    sequential_count: 1,
                    direction: AccessDirection::Forward,
                    last_touch: u64::MAX,
                },
            );
            guard.lru.insert(u64::MAX - 1, 1);
            guard.lru.insert(u64::MAX, 2);
            guard.next_touch = u64::MAX;
        }

        predictor.record_read(InodeNumber(3), 0, size);

        let (history_len, lru_len, next_touch) = {
            let guard = match predictor.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            (guard.history.len(), guard.lru.len(), guard.next_touch)
        };

        assert_eq!(history_len, 3);
        assert_eq!(lru_len, 3);
        assert!(next_touch < u64::MAX);
    }

    #[test]
    fn access_predictor_evicts_least_recent_inode() {
        let predictor = AccessPredictor::new(2);
        let size = 4096_u32;

        predictor.record_read(InodeNumber(1), 0, size);
        predictor.record_read(InodeNumber(2), 0, size);
        predictor.record_read(InodeNumber(1), u64::from(size), size);
        predictor.record_read(InodeNumber(3), 0, size);

        let (tracked, has_one, has_two, has_three) = {
            let guard = match predictor.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            (
                guard.history.len(),
                guard.history.contains_key(&1),
                guard.history.contains_key(&2),
                guard.history.contains_key(&3),
            )
        };
        assert_eq!(tracked, 2);
        assert!(has_one);
        assert!(!has_two);
        assert!(has_three);
    }

    #[test]
    fn access_predictor_invalidate_inode_removes_entry() {
        let predictor = AccessPredictor::default();
        let size = 4096_u32;
        let ino = InodeNumber(42);

        predictor.record_read(ino, 0, size);
        predictor.record_read(ino, u64::from(size), size);

        let has_before = {
            let guard = predictor.state.lock().unwrap();
            guard.history.contains_key(&ino.0)
        };
        assert!(has_before);

        predictor.invalidate_inode(ino);

        let has_after = {
            let guard = predictor.state.lock().unwrap();
            guard.history.contains_key(&ino.0)
        };
        assert!(!has_after);
    }

    #[test]
    fn access_predictor_invalidate_nonexistent_is_noop() {
        let predictor = AccessPredictor::default();
        predictor.invalidate_inode(InodeNumber(999));
        let count = {
            let guard = predictor.state.lock().unwrap();
            guard.history.len()
        };
        assert_eq!(count, 0);
    }

    // ── Concurrent AccessPredictor stress ────────────────────────────────

    #[test]
    fn access_predictor_concurrent_stress() {
        let predictor = Arc::new(AccessPredictor::default());
        let barrier = Arc::new(std::sync::Barrier::new(8));

        std::thread::scope(|s| {
            for thread_id in 0_u64..8 {
                let predictor = Arc::clone(&predictor);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    let ino = InodeNumber(100 + thread_id);
                    barrier.wait();
                    for i in 0_u64..500 {
                        let offset = i * 4096;
                        let _ = predictor.fetch_size(ino, offset, 4096);
                        predictor.record_read(ino, offset, 4096);
                    }
                });
            }
        });

        // No panic or deadlock = success. Verify state is queryable.
        for thread_id in 0_u64..8 {
            let _ = predictor.fetch_size(InodeNumber(100 + thread_id), 0, 4096);
        }
    }

    // ── Metrics record_err tracking ──────────────────────────────────────

    #[test]
    fn atomic_metrics_tracks_errors_separately() {
        let metrics = AtomicMetrics::new();
        metrics.record_ok();
        metrics.record_ok();
        metrics.record_err();
        metrics.record_bytes_read(1024);

        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 3);
        assert_eq!(snap.requests_ok, 2);
        assert_eq!(snap.requests_err, 1);
        assert_eq!(snap.bytes_read, 1024);
    }

    // ── MountOptions thread count resolution ─────────────────────────────

    #[test]
    fn resolved_thread_count_auto_is_bounded() {
        let opts = MountOptions {
            worker_threads: 0,
            ..Default::default()
        };
        let count = opts.resolved_thread_count();
        assert!(count >= 1);
        assert!(count <= 8);
    }

    #[test]
    fn resolved_thread_count_explicit_value_passes_through() {
        let opts = MountOptions {
            worker_threads: 4,
            ..Default::default()
        };
        assert_eq!(opts.resolved_thread_count(), 4);
    }

    #[test]
    fn resolved_thread_count_clamps_to_at_least_one() {
        // worker_threads=0 means auto, so test with 1.
        let opts = MountOptions {
            worker_threads: 1,
            ..Default::default()
        };
        assert_eq!(opts.resolved_thread_count(), 1);
    }

    // ── FrankenFuse thread_count accessor ────────────────────────────────

    #[test]
    fn franken_fuse_thread_count_matches_options() {
        let opts = MountOptions {
            worker_threads: 3,
            ..Default::default()
        };
        let fuse = FrankenFuse::with_options(Box::new(MinimalTestFs), &opts);
        assert_eq!(fuse.thread_count(), 3);
    }

    // ── ReadaheadManager edge cases ──────────────────────────────────────

    #[test]
    fn readahead_manager_miss_returns_none() {
        let manager = ReadaheadManager::new(8);
        // No data inserted → take returns None.
        assert_eq!(manager.take(InodeNumber(1), 0, 4), None);
    }

    #[test]
    fn readahead_manager_wrong_offset_returns_none() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(2);
        manager.insert(ino, 100, vec![1, 2, 3]);
        // Wrong offset → miss.
        assert_eq!(manager.take(ino, 200, 3), None);
        // Correct offset → hit.
        assert_eq!(manager.take(ino, 100, 3), Some(vec![1, 2, 3]));
    }

    #[test]
    fn readahead_manager_exact_size_take() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(3);
        manager.insert(ino, 0, vec![10, 20, 30, 40]);
        // Take exactly the stored amount.
        assert_eq!(manager.take(ino, 0, 4), Some(vec![10, 20, 30, 40]));
        // Second take should return None (consumed).
        assert_eq!(manager.take(ino, 0, 4), None);
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    const REPRESENTATIVE_RW_ALLOW_OTHER_THREADS_MOUNT_OPTIONS_GOLDEN: &str = r#"FSName("frankenfs")
Subtype("ffs")
DefaultPermissions
NoAtime
CUSTOM("max_read=16777216")
AllowOther
CUSTOM("max_background=4")
CUSTOM("congestion_threshold=3")"#;

    fn mount_option_debug_lines(options: &[MountOption]) -> String {
        options
            .iter()
            .map(|option| format!("{option:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn build_mount_options_rw_allow_other_with_threads() {
        let opts = MountOptions {
            read_only: false,
            allow_other: true,
            auto_unmount: false,
            writeback_cache: WritebackCacheMode::Disabled,
            ioctl_trace_path: None,
            worker_threads: 4,
        };
        let mount_opts = build_mount_options(&opts);
        let actual = mount_option_debug_lines(&mount_opts);
        assert_eq!(
            actual,
            REPRESENTATIVE_RW_ALLOW_OTHER_THREADS_MOUNT_OPTIONS_GOLDEN
        );
    }

    #[test]
    fn build_mount_options_zero_threads_omits_custom_background() {
        let opts = MountOptions {
            worker_threads: 0,
            ..MountOptions::default()
        };
        let mount_opts = build_mount_options(&opts);
        let dbg = format!("{mount_opts:?}");
        assert!(
            !dbg.contains("max_background"),
            "zero threads should not set max_background: {dbg}"
        );
    }

    #[test]
    fn mount_option_labels_for_fuzzing_returns_readable_labels() {
        let opts = MountOptions {
            read_only: true,
            allow_other: true,
            auto_unmount: false,
            writeback_cache: WritebackCacheMode::Disabled,
            ioctl_trace_path: None,
            worker_threads: 0,
        };
        let labels = mount_option_labels_for_fuzzing(&opts);
        assert!(labels.contains(&"ro".to_owned()));
        assert!(labels.contains(&"allow_other".to_owned()));
        assert!(labels.contains(&"fsname=frankenfs".to_owned()));
        assert!(labels.contains(&"subtype=ffs".to_owned()));
    }

    #[test]
    fn metrics_snapshot_equality() {
        let a = MetricsSnapshot {
            requests_total: 10,
            requests_ok: 7,
            requests_err: 3,
            bytes_read: 4096,
            requests_throttled: 0,
            requests_shed: 0,
        };
        let b = a;
        assert_eq!(a, b);

        let c = MetricsSnapshot {
            requests_total: 10,
            requests_ok: 6,
            requests_err: 4,
            bytes_read: 4096,
            requests_throttled: 0,
            requests_shed: 0,
        };
        assert_ne!(a, c);
    }

    #[test]
    fn atomic_metrics_tracks_pressure_counters() {
        let m = AtomicMetrics::new();
        m.record_throttled();
        m.record_throttled();
        m.record_shed();
        let snap = m.snapshot();
        assert_eq!(snap.requests_throttled, 2);
        assert_eq!(snap.requests_shed, 1);
    }

    #[test]
    fn atomic_metrics_debug_shows_fields() {
        const ATOMIC_METRICS_DEBUG_GOLDEN: &str = concat!(
            "AtomicMetrics { ",
            "requests_total: 1, ",
            "requests_ok: 1, ",
            "requests_err: 0, ",
            "bytes_read: 512, ",
            "requests_throttled: 1, ",
            "requests_shed: 0",
            " }"
        );

        let m = AtomicMetrics::new();
        m.record_ok();
        m.record_bytes_read(512);
        m.record_throttled();
        let dbg = format!("{m:?}");
        assert_eq!(dbg, ATOMIC_METRICS_DEBUG_GOLDEN);
    }

    #[test]
    fn cache_line_padded_debug_delegates_to_inner() {
        const CACHE_LINE_PADDED_DEBUG_GOLDEN: &str = "42";

        let padded = CacheLinePadded(42_u32);
        let dbg = format!("{padded:?}");
        assert_eq!(dbg, CACHE_LINE_PADDED_DEBUG_GOLDEN);
    }

    #[test]
    fn access_predictor_backward_sequence_not_coalesced() {
        // Backward sequential reads should increment sequential_count
        // but NOT trigger coalescing (only forward does).
        let predictor = AccessPredictor::new(64);
        let ino = InodeNumber(50);
        let size = 4096_u32;

        // Read offsets: 3*4096, 2*4096, 1*4096, 0 (backward).
        for i in (0..4).rev() {
            predictor.record_read(ino, u64::from(size) * i, size);
        }
        // Asking for the next backward read shouldn't coalesce.
        // Since coalescing is only for forward, fetch_size should return `size`.
        let fetch = predictor.fetch_size(ino, 0, size);
        assert_eq!(
            fetch, size,
            "backward sequence should not trigger coalescing"
        );
    }

    #[test]
    fn access_predictor_capacity_one_evicts_oldest() {
        let predictor = AccessPredictor::new(1);
        let size = 4096_u32;

        // Record inode 1, then inode 2 → inode 1 should be evicted.
        predictor.record_read(InodeNumber(1), 0, size);
        predictor.record_read(InodeNumber(2), 0, size);

        // Inode 1 should be unknown now.
        assert_eq!(predictor.fetch_size(InodeNumber(1), 0, size), size);

        // Inode 2 is still known.
        {
            let state = predictor.state.lock().unwrap();
            assert!(state.history.contains_key(&2));
            assert!(!state.history.contains_key(&1));
            drop(state);
        }
    }

    #[test]
    fn access_predictor_non_sequential_resets_count() {
        let predictor = AccessPredictor::new(64);
        let ino = InodeNumber(77);
        let size = 4096_u32;

        // Build forward sequential: 0, 4096, 8192.
        predictor.record_read(ino, 0, size);
        predictor.record_read(ino, 4096, size);
        predictor.record_read(ino, 8192, size);

        // Random jump to offset 999999 → resets sequential count.
        predictor.record_read(ino, 999_999, size);

        // Next forward read from expected position shouldn't coalesce
        // because sequential_count was reset to 1.
        let fetch = predictor.fetch_size(ino, 999_999 + u64::from(size), size);
        assert_eq!(fetch, size, "jump should reset sequential count");
    }

    #[test]
    fn readahead_manager_overwrite_same_key() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(10);

        // Insert at offset 0 with data [1,2,3].
        manager.insert(ino, 0, vec![1, 2, 3]);
        // Overwrite at same key with [4,5,6].
        manager.insert(ino, 0, vec![4, 5, 6]);

        // Should get the latest data.
        assert_eq!(manager.take(ino, 0, 3), Some(vec![4, 5, 6]));
    }

    #[test]
    fn readahead_manager_empty_insert_is_noop() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(20);

        manager.insert(ino, 0, vec![]);
        assert_eq!(manager.take(ino, 0, 0), None);
    }

    // ── validate_mountpoint tests ───────────────────────────────────────────

    #[test]
    fn validate_mountpoint_empty_path_rejected() {
        use std::path::Path;
        let result = validate_mountpoint(Path::new(""));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FuseError::InvalidMountpoint(ref msg) if msg.contains("empty")),
            "expected empty error, got: {err:?}"
        );
    }

    #[test]
    fn validate_mountpoint_nonexistent_rejected() {
        use std::path::PathBuf;
        let nonexistent = PathBuf::from("/this/path/does/not/exist/at/all/ever");
        let result = validate_mountpoint(&nonexistent);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FuseError::InvalidMountpoint(ref msg) if msg.contains("does not exist")),
            "expected not-exist error, got: {err:?}"
        );
    }

    #[test]
    fn validate_mountpoint_file_rejected() {
        // /etc/passwd exists on all Linux systems as a regular file.
        use std::path::Path;
        let file_path = Path::new("/etc/passwd");
        if file_path.exists() && !file_path.is_dir() {
            let result = validate_mountpoint(file_path);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(err, FuseError::InvalidMountpoint(ref msg) if msg.contains("not a directory")),
                "expected not-dir error, got: {err:?}"
            );
        }
    }

    #[test]
    fn validate_mountpoint_valid_directory_accepted() {
        use std::path::Path;
        // /tmp always exists as a directory on Linux.
        let dir_path = Path::new("/tmp");
        let result = validate_mountpoint(dir_path);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn fuse_error_display_variants() {
        const INVALID_MOUNTPOINT_DISPLAY_GOLDEN: &str = "invalid mountpoint: bad path";
        const IO_ERROR_DISPLAY_GOLDEN: &str = "mount I/O error: disk gone";

        let invalid_mp = FuseError::InvalidMountpoint("bad path".into());
        assert_eq!(invalid_mp.to_string(), INVALID_MOUNTPOINT_DISPLAY_GOLDEN);

        let io_err = FuseError::Io(std::io::Error::other("disk gone"));
        assert_eq!(io_err.to_string(), IO_ERROR_DISPLAY_GOLDEN);
    }

    #[test]
    fn fuse_inner_debug_shows_non_exhaustive() {
        const FUSE_INNER_DEBUG_GOLDEN: &str = concat!(
            "FuseInner { ",
            "metrics: AtomicMetrics { requests_total: 0, requests_ok: 0, requests_err: 0, ",
            "bytes_read: 0, requests_throttled: 0, requests_shed: 0 }, ",
            "thread_count: 2, ",
            "read_only: false, ",
            "writeback_cache: false, ",
            "mountpoint: None, ",
            ".. }"
        );

        let inner = FuseInner {
            ops: Arc::new(MinimalTestFs),
            metrics: Arc::new(AtomicMetrics::new()),
            thread_count: 2,
            read_only: false,
            writeback_cache: false,
            mountpoint: None,
            kernel_notifier: Mutex::new(None),
            ioctl_trace: None,
            backpressure: None,
            writeback_batches: Mutex::new(BTreeMap::new()),
            access_predictor: AccessPredictor::default(),
            readahead: ReadaheadManager::new(8),
            inode_locks: Arc::new(FuseInodeLocks::default()),
            read_offload: None,
        };
        let dbg = format!("{inner:?}");
        assert_eq!(dbg, FUSE_INNER_DEBUG_GOLDEN);
    }

    #[test]
    fn mount_options_worker_threads_one_resolves_to_one() {
        let opts = MountOptions {
            worker_threads: 1,
            ..MountOptions::default()
        };
        assert_eq!(opts.resolved_thread_count(), 1);
    }

    #[test]
    fn classify_xattr_reply_data_exact_fit() {
        // payload_len == size → Data.
        assert_eq!(
            FrankenFuse::classify_xattr_reply(32, 32),
            XattrReplyPlan::Data
        );
    }

    #[test]
    fn classify_xattr_reply_size_zero_payload() {
        // size=0, payload=0 → Size(0).
        assert_eq!(
            FrankenFuse::classify_xattr_reply(0, 0),
            XattrReplyPlan::Size(0)
        );
    }

    #[test]
    fn access_direction_equality() {
        assert_eq!(AccessDirection::Forward, AccessDirection::Forward);
        assert_eq!(AccessDirection::Backward, AccessDirection::Backward);
        assert_ne!(AccessDirection::Forward, AccessDirection::Backward);
    }

    // ── Mount runtime benchmark scenario tests (bd-h6nz.2.5) ──────────

    #[test]
    fn benchmark_per_core_dispatch_routing_is_deterministic() {
        use crate::per_core::{PerCoreConfig, PerCoreDispatcher};

        let config = PerCoreConfig {
            num_cores: 8,
            ..PerCoreConfig::default()
        };
        let d = PerCoreDispatcher::new(config);

        // Same inode always routes to same core.
        let core_a = d.route_inode(42);
        let core_b = d.route_inode(42);
        assert_eq!(core_a, core_b);
        assert!(core_a < 8);

        // Same parent always routes to same core for lookup.
        let lk_a = d.route_lookup(42);
        let lk_b = d.route_lookup(42);
        assert_eq!(lk_a, lk_b);
        assert!(lk_a < 8);
    }

    #[test]
    fn benchmark_per_core_aggregate_metrics_zero_when_idle() {
        use crate::per_core::{PerCoreConfig, PerCoreDispatcher};

        let d = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 4,
            ..PerCoreConfig::default()
        });
        let agg = d.aggregate_metrics();
        assert_eq!(agg.total_requests, 0);
        assert_eq!(agg.total_cache_hits, 0);
        assert_eq!(agg.total_cache_misses, 0);
        assert!((agg.aggregate_hit_rate - 0.0).abs() < f64::EPSILON);
        assert_eq!(agg.per_core.len(), 4);
    }

    #[test]
    fn benchmark_per_core_should_steal_false_when_balanced() {
        use crate::per_core::{PerCoreConfig, PerCoreDispatcher};

        let d = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 4,
            ..PerCoreConfig::default()
        });
        // Equal load on all cores.
        for core_id in 0..4_u32 {
            if let Some(m) = d.core_metrics(core_id) {
                for _ in 0..100 {
                    m.record_request();
                }
            }
        }
        // No core should want to steal when balanced.
        for core_id in 0..4_u32 {
            assert!(
                !d.should_steal(core_id),
                "core {core_id} should not steal when balanced"
            );
        }
    }

    #[test]
    fn benchmark_backpressure_decision_normal_never_sheds() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        let pressure = Arc::new(SystemPressure::new());
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        let gate = BackpressureGate::new(fsm);

        // Normal pressure: neither reads nor writes are shed.
        assert_eq!(gate.check(RequestOp::Read), BackpressureDecision::Proceed);
        assert_eq!(gate.check(RequestOp::Write), BackpressureDecision::Proceed);
    }

    #[test]
    fn benchmark_backpressure_decision_emergency_sheds_writes() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        let pressure = Arc::new(SystemPressure::with_headroom(0.02));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        // Emergency: reads proceed, writes shed.
        assert_eq!(gate.check(RequestOp::Read), BackpressureDecision::Proceed);
        assert_eq!(gate.check(RequestOp::Write), BackpressureDecision::Shed);
    }

    #[test]
    fn benchmark_metrics_snapshot_isolation() {
        // Snapshot must be a frozen copy — further writes don't affect it.
        let m = AtomicMetrics::new();
        m.record_ok();
        m.record_ok();
        let snap = m.snapshot();
        assert_eq!(snap.requests_total, 2);

        m.record_ok();
        // Original snapshot unchanged.
        assert_eq!(snap.requests_total, 2);
        // New snapshot reflects the third write.
        assert_eq!(m.snapshot().requests_total, 3);
    }

    // ── Degraded-mode pressure behavior tests (bd-h6nz.5.4) ──────────

    #[test]
    fn degraded_pressure_warning_does_not_affect_foreground() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        // Warning level: headroom 0.75 → no impact on foreground (asupersync 0.3: light)
        let pressure = Arc::new(SystemPressure::with_headroom(0.75));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        // Both reads and writes should proceed at warning level.
        assert_eq!(gate.check(RequestOp::Read), BackpressureDecision::Proceed);
        assert_eq!(gate.check(RequestOp::Write), BackpressureDecision::Proceed);
        assert_eq!(gate.check(RequestOp::Create), BackpressureDecision::Proceed);
    }

    #[test]
    fn degraded_pressure_critical_throttles_writes_sheds_metadata() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        // Critical level: headroom 0.15 (asupersync 0.3: heavy, level 3)
        let pressure = Arc::new(SystemPressure::with_headroom(0.15));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        // Reads proceed.
        assert_eq!(gate.check(RequestOp::Read), BackpressureDecision::Proceed);
        // Writes throttled.
        assert_eq!(gate.check(RequestOp::Write), BackpressureDecision::Throttle);
        // Metadata writes (mkdir, unlink, etc.) are shed.
        assert_eq!(gate.check(RequestOp::Mkdir), BackpressureDecision::Shed);
        assert_eq!(gate.check(RequestOp::Unlink), BackpressureDecision::Shed);
    }

    #[test]
    fn degraded_pressure_fsm_tick_drives_transitions() {
        use asupersync::SystemPressure;
        use ffs_core::{DegradationFsm, DegradationLevel};

        let pressure = Arc::new(SystemPressure::new());
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));

        // Starts at Normal.
        assert_eq!(fsm.level(), DegradationLevel::Normal);

        // Tick at normal headroom stays Normal.
        fsm.tick();
        assert_eq!(fsm.level(), DegradationLevel::Normal);
    }

    #[test]
    fn degraded_pressure_concurrent_checks_are_safe() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        let pressure = Arc::new(SystemPressure::new());
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        let gate = Arc::new(BackpressureGate::new(fsm));

        // Run 4 threads hammering check() concurrently.
        std::thread::scope(|s| {
            for _ in 0..4 {
                let g = Arc::clone(&gate);
                s.spawn(move || {
                    for _ in 0..1000 {
                        let decision = g.check(RequestOp::Read);
                        assert_eq!(decision, BackpressureDecision::Proceed);
                    }
                });
            }
        });
    }

    #[test]
    fn degraded_pressure_escalation_order_is_monotonic() {
        use ffs_core::DegradationLevel;

        // Levels must be ordered Normal < Warning < Degraded < Critical < Emergency.
        assert!(DegradationLevel::Normal < DegradationLevel::Warning);
        assert!(DegradationLevel::Warning < DegradationLevel::Degraded);
        assert!(DegradationLevel::Degraded < DegradationLevel::Critical);
        assert!(DegradationLevel::Critical < DegradationLevel::Emergency);
    }

    // ── FuseInodeLocks eviction tests (bd-elah2) ──────────────────────────

    #[test]
    fn fuse_inode_locks_evict_entry_on_last_guard_drop() {
        let locks = Arc::new(FuseInodeLocks::default());
        {
            let _guards = locks.acquire(&[InodeNumber(42)]);
            assert_eq!(locks.table_len(), 1, "entry present while guard live");
        }
        assert_eq!(
            locks.table_len(),
            0,
            "entry must be evicted once the last guard drops"
        );
    }

    #[test]
    fn fuse_inode_locks_bounded_under_sequential_churn() {
        let locks = Arc::new(FuseInodeLocks::default());
        for ino in 0..100_000u64 {
            let _guards = locks.acquire(&[InodeNumber(ino)]);
            // guard drops at end of scope — table should return to empty
        }
        assert_eq!(
            locks.table_len(),
            0,
            "sequential acquire/drop of 100K inodes must not accumulate"
        );
    }

    #[test]
    fn fuse_inode_locks_try_acquire_failure_does_not_preinsert_idle_entries() {
        let locks = Arc::new(FuseInodeLocks::default());
        let held_guard = locks.acquire(&[InodeNumber(1)]);

        assert!(
            locks
                .try_acquire(&[InodeNumber(1), InodeNumber(2)])
                .is_none(),
            "try_acquire should fail while the first inode is already held"
        );
        assert_eq!(
            locks.table_len(),
            1,
            "failed try_acquire must not retain an idle entry for an inode it never acquired"
        );

        drop(held_guard);
        assert_eq!(
            locks.table_len(),
            0,
            "the original held inode should still evict on final guard drop"
        );
    }

    #[test]
    fn fuse_inode_locks_retain_entry_while_second_guard_blocked() {
        let locks = Arc::new(FuseInodeLocks::default());
        let ino = InodeNumber(7);

        // Hold guard A, then kick off waiter B in a thread. B will block on
        // the held flag because A owns it. While B is blocked the table entry
        // must stay — evicting it here would break the mutual-exclusion
        // contract for B.
        let guard_a = locks.acquire(&[ino]);
        assert_eq!(locks.table_len(), 1);

        let locks_b = Arc::clone(&locks);
        let waiter_ready = Arc::new(std::sync::Barrier::new(2));
        let waiter_ready_clone = Arc::clone(&waiter_ready);
        let handle = std::thread::spawn(move || {
            waiter_ready_clone.wait();
            let _guard_b = locks_b.acquire(&[ino]);
        });
        waiter_ready.wait();

        // Give the waiter time to clone its Arc and enter the condvar wait.
        // Spinning the table_len check keeps this deterministic without a
        // fixed sleep: once B has entered acquire(), the strong_count on the
        // per-inode lock is >= 4 here: table + guard A + this diagnostic
        // snapshot + waiter B.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let entries: Vec<(InodeNumber, Arc<FuseInodeLock>)> = {
                let table = locks.table.lock().unwrap();
                table
                    .iter()
                    .map(|(k, v)| (*k, Arc::clone(&v.lock)))
                    .collect()
            };
            assert_eq!(entries.len(), 1);
            let waiter_cloned_entry = Arc::strong_count(&entries[0].1) >= 4;
            drop(entries);
            if waiter_cloned_entry {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "waiter thread never entered acquire()"
            );
            std::thread::yield_now();
        }

        drop(guard_a);
        handle.join().unwrap();

        // After both guards have fully dropped, the entry must be gone.
        assert_eq!(
            locks.table_len(),
            0,
            "entry must be evicted after both guards drop"
        );
    }

    #[test]
    fn fuse_inode_locks_preserve_total_order_under_contention() {
        // Mutual-exclusion regression: with eviction enabled we must still
        // serialize concurrent acquires of the same inode set.
        let locks = Arc::new(FuseInodeLocks::default());
        let counter = Arc::new(Mutex::new(0u32));
        let observed_max = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(16));

        std::thread::scope(|s| {
            for _ in 0..16 {
                let locks = Arc::clone(&locks);
                let counter = Arc::clone(&counter);
                let observed_max = Arc::clone(&observed_max);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    barrier.wait();
                    for _ in 0..128 {
                        let _g = locks.acquire(&[InodeNumber(1), InodeNumber(2)]);
                        let mut slot = counter.lock().unwrap();
                        *slot += 1;
                        observed_max.fetch_max(*slot, std::sync::atomic::Ordering::Relaxed);
                        assert_eq!(*slot, 1, "two holders of the same inode set");
                        *slot -= 1;
                    }
                });
            }
        });

        assert_eq!(
            observed_max.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "critical section must be single-occupant"
        );
        assert_eq!(
            locks.table_len(),
            0,
            "all guards dropped, table must be empty"
        );
    }

    /// bd-pfv55 — regression guard for the canonical lock-ordering
    /// invariant on `FuseInodeLocks` (table → per-inode held;
    /// sorted-by-inode-number order across multi-inode batches).
    /// Spawns three concurrent worker classes that exercise the three
    /// nested-lock code paths simultaneously: `acquire` (table.W →
    /// drop → held.W per sorted inode), `try_acquire` (same plus
    /// short-circuit on contention), and the implicit `Drop` path
    /// (table.W → held.W → notify → maybe-evict). A watchdog thread
    /// fails the test with a tagged assertion if the workers do not
    /// finish within 15s; any future AB-BA introduced by a refactor
    /// surfaces as a clear failure rather than a silent stall.
    #[test]
    fn lock_ordering_under_concurrent_acquire_and_drop() {
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        const FUSE_INODE_LOCK_WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(10);

        let locks = Arc::new(FuseInodeLocks::default());
        let deadline = Instant::now() + Duration::from_secs(15);

        // Worker A: full-blocking acquire/drop pipeline. Exercises
        // `acquire` (table → drop → held per sorted inode) and the
        // implicit Drop (table → held nested → maybe-evict).
        let locks_a = Arc::clone(&locks);
        let worker_a = thread::spawn(move || {
            for i in 0..64_u64 {
                // Pair of inodes — sorted by lib invariant inside acquire().
                let _g = locks_a.acquire(&[InodeNumber(i % 4 + 1), InodeNumber(i % 4 + 2)]);
                // Hold briefly so other threads contend.
                thread::yield_now();
            }
        });

        // Worker B: try_acquire pipeline. Exercises the same lock
        // graph but short-circuits on contention rather than waiting
        // on the Condvar; tests the alternate code path that bypasses
        // the wait.
        let locks_b = Arc::clone(&locks);
        let worker_b = thread::spawn(move || {
            for i in 0..64_u64 {
                if let Some(_g) = locks_b.try_acquire(&[InodeNumber(i % 4 + 1)]) {
                    thread::yield_now();
                }
                // None outcome is fine — we're testing for hang, not
                // for guaranteed acquisition.
            }
        });

        // Worker C: reverse-order pair. Calls acquire with [7, 3] on
        // every iteration. The library MUST sort to [3, 7] before
        // taking per-inode locks — if it didn't, this worker would
        // deadlock against worker A which uses ascending inodes.
        let locks_c = Arc::clone(&locks);
        let worker_c = thread::spawn(move || {
            for _ in 0..64_u64 {
                let _g = locks_c.acquire(&[InodeNumber(7), InodeNumber(3)]);
                thread::yield_now();
            }
        });

        while !(worker_a.is_finished() && worker_b.is_finished() && worker_c.is_finished()) {
            let now = Instant::now();
            assert!(
                now < deadline,
                "bd-pfv55: FuseInodeLocks lock-ordering watchdog tripped — \
                 acquire/try_acquire/drop workers did not finish within 15s, \
                 indicating a likely AB-BA deadlock"
            );
            thread::sleep(
                FUSE_INODE_LOCK_WATCHDOG_POLL_INTERVAL.min(deadline.saturating_duration_since(now)),
            );
        }

        worker_a.join().expect("worker A panicked");
        worker_b.join().expect("worker B panicked");
        worker_c.join().expect("worker C panicked");

        // Sanity: all guards dropped, table should be empty.
        assert_eq!(
            locks.table_len(),
            0,
            "all guards dropped — table must be empty"
        );
    }

    // ── to_fuser_file_type: file type conversion ────────────────────────────

    #[test]
    fn to_fuser_file_type_regular_file() {
        use super::{FfsFileType, to_fuser_file_type};
        use fuser::FileType;
        assert!(matches!(
            to_fuser_file_type(FfsFileType::RegularFile),
            FileType::RegularFile
        ));
    }

    #[test]
    fn to_fuser_file_type_directory() {
        use super::{FfsFileType, to_fuser_file_type};
        use fuser::FileType;
        assert!(matches!(
            to_fuser_file_type(FfsFileType::Directory),
            FileType::Directory
        ));
    }

    #[test]
    fn to_fuser_file_type_symlink() {
        use super::{FfsFileType, to_fuser_file_type};
        use fuser::FileType;
        assert!(matches!(
            to_fuser_file_type(FfsFileType::Symlink),
            FileType::Symlink
        ));
    }

    #[test]
    fn to_fuser_file_type_fifo_to_named_pipe() {
        use super::{FfsFileType, to_fuser_file_type};
        use fuser::FileType;
        assert!(matches!(
            to_fuser_file_type(FfsFileType::Fifo),
            FileType::NamedPipe
        ));
    }

    #[test]
    fn to_fuser_file_type_socket() {
        use super::{FfsFileType, to_fuser_file_type};
        use fuser::FileType;
        assert!(matches!(
            to_fuser_file_type(FfsFileType::Socket),
            FileType::Socket
        ));
    }

    // ── split_mount_option: additional edge cases ──────────────────────────

    #[test]
    fn split_mount_option_trims_whitespace() {
        use super::split_mount_option;
        let (key, val) = split_mount_option("  key  =  value  ").unwrap();
        assert_eq!(key, "key");
        assert_eq!(val, Some("value"));
    }

    #[test]
    fn split_mount_option_empty_key_is_error() {
        use super::split_mount_option;
        assert!(split_mount_option("=value").is_err());
        assert!(split_mount_option("   =value").is_err());
    }

    // ── Proptest property-based tests ─────────────────────────────────────

    #[expect(clippy::cast_possible_truncation)] // test-only: proptest ranges guarantee safe casts
    mod proptests {
        use super::*;
        use crate::per_core::{
            CoreMetrics, PerCoreConfig, PerCoreDispatcher, inode_to_core, lookup_to_core,
        };
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            // ── inode_to_core properties ────────────────────────────────

            /// Routing is always deterministic: same inputs produce same output.
            #[test]
            fn inode_routing_is_deterministic(ino in 0_u64..=u64::MAX, cores in 1_u32..=256) {
                let a = inode_to_core(ino, cores);
                let b = inode_to_core(ino, cores);
                prop_assert_eq!(a, b);
            }

            /// Routing output is always within [0, num_cores).
            #[test]
            fn inode_routing_in_range(ino in 0_u64..=u64::MAX, cores in 1_u32..=256) {
                let core = inode_to_core(ino, cores);
                prop_assert!(core < cores, "core {core} >= num_cores {cores}");
            }

            /// Routing with num_cores=0 always returns 0.
            #[test]
            fn inode_routing_zero_cores_always_zero(ino in 0_u64..=u64::MAX) {
                prop_assert_eq!(inode_to_core(ino, 0), 0);
            }

            /// With 1 core, every inode routes to core 0.
            #[test]
            fn inode_routing_single_core(ino in 0_u64..=u64::MAX) {
                prop_assert_eq!(inode_to_core(ino, 1), 0);
            }

            /// lookup_to_core delegates to inode_to_core on parent.
            #[test]
            fn lookup_routes_same_as_inode(parent in 0_u64..=u64::MAX, cores in 1_u32..=256) {
                prop_assert_eq!(
                    lookup_to_core(parent, cores),
                    inode_to_core(parent, cores)
                );
            }

            // ── classify_xattr_reply properties ────────────────────────

            /// size=0 always produces Size variant (probe mode).
            #[test]
            fn xattr_probe_always_returns_size(payload_len in 0_usize..=u32::MAX as usize) {
                let plan = FrankenFuse::classify_xattr_reply(0, payload_len);
                match plan {
                    XattrReplyPlan::Size(n) => {
                        prop_assert_eq!(n, u32::try_from(payload_len).unwrap());
                    }
                    _ => prop_assert!(false, "expected Size variant, got {plan:?}"),
                }
            }

            /// When buffer fits (payload <= size), always produces Data.
            #[test]
            fn xattr_data_when_fits(
                size in 1_u32..=u32::MAX,
                payload_len in 0_u32..=u32::MAX,
            ) {
                // Only test when payload_len <= size
                if payload_len <= size {
                    let plan = FrankenFuse::classify_xattr_reply(size, payload_len as usize);
                    prop_assert_eq!(plan, XattrReplyPlan::Data);
                }
            }

            /// When buffer too small (payload > size > 0), produces ERANGE.
            #[test]
            fn xattr_erange_when_too_small(
                size in 1_u32..=u32::MAX - 1,
                extra in 1_u32..=1024,
            ) {
                let payload_len = (u64::from(size) + u64::from(extra)).min(u64::from(u32::MAX)) as usize;
                if payload_len > usize::try_from(size).unwrap() {
                    let plan = FrankenFuse::classify_xattr_reply(size, payload_len);
                    prop_assert_eq!(plan, XattrReplyPlan::Error(libc::ERANGE));
                }
            }

            // ── parse_setxattr_mode properties ─────────────────────────

            /// Valid flags (0, CREATE, REPLACE) with position=0 always succeed.
            #[test]
            fn setxattr_valid_flags_succeed(flag in prop_oneof![
                Just(0_i32),
                Just(XATTR_FLAG_CREATE),
                Just(XATTR_FLAG_REPLACE),
            ]) {
                prop_assert!(FrankenFuse::parse_setxattr_mode(flag, 0).is_ok());
            }

            /// Non-zero position always fails with EINVAL.
            #[test]
            fn setxattr_nonzero_position_fails(flags in 0_i32..=3, position in 1_u32..=u32::MAX) {
                let result = FrankenFuse::parse_setxattr_mode(flags, position);
                prop_assert_eq!(result, Err(libc::EINVAL));
            }

            /// Unknown flags (bits outside CREATE|REPLACE) always fail.
            #[test]
            fn setxattr_unknown_flags_fail(unknown_bits in 4_i32..=i32::MAX) {
                // Ensure at least one bit outside the known mask is set.
                let known = XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE;
                if unknown_bits & !known != 0 {
                    let result = FrankenFuse::parse_setxattr_mode(unknown_bits, 0);
                    prop_assert_eq!(result, Err(libc::EINVAL));
                }
            }

            /// CREATE|REPLACE together always fail.
            #[test]
            fn setxattr_create_and_replace_fail(_dummy in 0_u8..1) {
                let result = FrankenFuse::parse_setxattr_mode(
                    XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE, 0
                );
                prop_assert_eq!(result, Err(libc::EINVAL));
            }

            // ── encode_xattr_names properties ──────────────────────────

            /// Encoded output length = sum(name.len() + 1) for each name.
            #[test]
            fn xattr_encode_length_property(
                names in prop::collection::vec("[a-z]{1,20}", 0..10)
            ) {
                let encoded = FrankenFuse::encode_xattr_names(&names);
                let expected_len: usize = names.iter().map(|n| n.len() + 1).sum();
                prop_assert_eq!(encoded.len(), expected_len);
                prop_assert_eq!(FrankenFuse::xattr_names_encoded_len(&names), expected_len);
            }

            /// Each encoded name ends with NUL separator.
            #[test]
            fn xattr_encode_nul_separated(
                names in prop::collection::vec("[a-z]{1,20}", 1..10)
            ) {
                let encoded = FrankenFuse::encode_xattr_names(&names);
                if !encoded.is_empty() {
                    prop_assert_eq!(*encoded.last().unwrap(), 0_u8);
                }
                // Count NUL bytes = number of names.
                #[expect(clippy::naive_bytecount)] // test: bytecount crate not warranted
                let nul_count = encoded.iter().filter(|&&b| b == 0).count();
                prop_assert_eq!(nul_count, names.len());
            }

            // ── AccessPredictor properties ──────────────────────────────

            /// History never exceeds max_entries.
            #[test]
            fn access_predictor_bounded_history(
                max_entries in 1_usize..=16,
                num_reads in 1_usize..=64,
            ) {
                let predictor = AccessPredictor::new(max_entries);
                for i in 0..u64::try_from(num_reads).unwrap() {
                    predictor.record_read(InodeNumber(i), 0, 4096);
                }
                let count = match predictor.state.lock() {
                    Ok(guard) => guard.history.len(),
                    Err(poisoned) => poisoned.into_inner().history.len(),
                };
                prop_assert!(count <= max_entries, "history {count} > max {max_entries}");
            }

            /// Fetch size for unknown inode equals requested size.
            #[test]
            fn access_predictor_unknown_inode_returns_requested(
                ino in 0_u64..=u64::MAX,
                offset in 0_u64..=u64::MAX,
                size in 1_u32..=65536,
            ) {
                let predictor = AccessPredictor::new(16);
                prop_assert_eq!(predictor.fetch_size(InodeNumber(ino), offset, size), size);
            }

            /// Zero-size reads are silently dropped (no state mutation).
            #[test]
            fn access_predictor_zero_size_read_is_noop(ino in 0_u64..=1000) {
                let predictor = AccessPredictor::new(16);
                predictor.record_read(InodeNumber(ino), 0, 0);
                let count = match predictor.state.lock() {
                    Ok(guard) => guard.history.len(),
                    Err(poisoned) => poisoned.into_inner().history.len(),
                };
                prop_assert_eq!(count, 0);
            }

            /// Coalesced fetch size is always >= requested size.
            #[test]
            fn access_predictor_fetch_at_least_requested(
                offset in 0_u64..=1_000_000,
                size in 1_u32..=65536,
            ) {
                let predictor = AccessPredictor::new(64);
                let ino = InodeNumber(42);
                // Build some sequential history.
                for i in 0..5_u64 {
                    predictor.record_read(ino, i * u64::from(size), size);
                }
                let fetch = predictor.fetch_size(ino, offset, size);
                prop_assert!(fetch >= size, "fetch {fetch} < requested {size}");
            }

            /// Coalesced fetch size never exceeds MAX_COALESCED_READ_SIZE.
            #[test]
            fn access_predictor_fetch_capped(size in 1_u32..=65536) {
                let predictor = AccessPredictor::new(64);
                let ino = InodeNumber(99);
                // Build long forward sequence.
                for i in 0..20_u64 {
                    predictor.record_read(ino, i * u64::from(size), size);
                }
                let next_offset = 20 * u64::from(size);
                let fetch = predictor.fetch_size(ino, next_offset, size);
                prop_assert!(
                    fetch <= MAX_COALESCED_READ_SIZE.max(size),
                    "fetch {fetch} > cap {}",
                    MAX_COALESCED_READ_SIZE.max(size)
                );
            }

            // ── ReadaheadManager properties ─────────────────────────────

            /// insert then take at same offset returns the data.
            #[test]
            fn readahead_insert_take_roundtrip(
                ino in 1_u64..=1000,
                offset in 0_u64..=1_000_000,
                data in prop::collection::vec(any::<u8>(), 1..128),
            ) {
                let manager = ReadaheadManager::new(64);
                let data_clone = data.clone();
                manager.insert(InodeNumber(ino), offset, data);
                let taken = manager.take(InodeNumber(ino), offset, data_clone.len());
                prop_assert_eq!(taken, Some(data_clone));
            }

            /// take after consume returns None.
            #[test]
            fn readahead_double_take_returns_none(
                ino in 1_u64..=1000,
                offset in 0_u64..=1_000_000,
                data in prop::collection::vec(any::<u8>(), 1..64),
            ) {
                let manager = ReadaheadManager::new(64);
                let len = data.len();
                manager.insert(InodeNumber(ino), offset, data);
                let _ = manager.take(InodeNumber(ino), offset, len);
                let second = manager.take(InodeNumber(ino), offset, len);
                prop_assert_eq!(second, None);
            }

            /// Pending entries never exceed max_pending.
            #[test]
            fn readahead_bounded_entries(
                max_pending in 1_usize..=8,
                num_inserts in 1_usize..=32,
            ) {
                let manager = ReadaheadManager::new(max_pending);
                for i in 0..u64::try_from(num_inserts).unwrap() {
                    manager.insert(InodeNumber(1), i * 1024, vec![0xAA]);
                }
                let count = match manager.pending.lock() {
                    Ok(guard) => guard.map.len(),
                    Err(poisoned) => poisoned.into_inner().map.len(),
                };
                prop_assert!(count <= max_pending, "entries {count} > max {max_pending}");
            }

            /// Empty data insertions are silently ignored.
            #[test]
            fn readahead_empty_insert_ignored(ino in 1_u64..=100, offset in 0_u64..=1000) {
                let manager = ReadaheadManager::new(8);
                manager.insert(InodeNumber(ino), offset, vec![]);
                let count = match manager.pending.lock() {
                    Ok(guard) => guard.map.len(),
                    Err(poisoned) => poisoned.into_inner().map.len(),
                };
                prop_assert_eq!(count, 0);
            }

            /// Partial take returns prefix and preserves tail at correct offset.
            #[test]
            fn readahead_partial_take_preserves_tail(
                data in prop::collection::vec(any::<u8>(), 4..128),
                take_len in 1_usize..=3,
            ) {
                let manager = ReadaheadManager::new(16);
                let ino = InodeNumber(7);
                let offset = 0_u64;
                let data_clone = data.clone();
                let actual_take = take_len.min(data.len() - 1); // Ensure a tail exists.
                if actual_take < data.len() {
                    manager.insert(ino, offset, data);
                    let prefix = manager.take(ino, offset, actual_take);
                    prop_assert_eq!(prefix.as_deref(), Some(&data_clone[..actual_take]));

                    // Tail should be at offset + actual_take.
                    let tail_offset = offset + u64::try_from(actual_take).unwrap();
                    let tail = manager.take(ino, tail_offset, data_clone.len());
                    prop_assert_eq!(tail.as_deref(), Some(&data_clone[actual_take..]));
                }
            }

            // ── AtomicMetrics properties ────────────────────────────────

            /// ok + err always equals total.
            #[test]
            fn metrics_ok_plus_err_equals_total(
                num_ok in 0_u64..=500,
                num_err in 0_u64..=500,
            ) {
                let metrics = AtomicMetrics::new();
                for _ in 0..num_ok { metrics.record_ok(); }
                for _ in 0..num_err { metrics.record_err(); }
                let snap = metrics.snapshot();
                prop_assert_eq!(snap.requests_ok, num_ok);
                prop_assert_eq!(snap.requests_err, num_err);
                prop_assert_eq!(snap.requests_total, num_ok + num_err);
            }

            /// bytes_read accumulates correctly.
            #[test]
            fn metrics_bytes_read_accumulates(
                reads in prop::collection::vec(1_u64..=8192, 0..50),
            ) {
                let metrics = AtomicMetrics::new();
                let expected: u64 = reads.iter().sum();
                for &n in &reads {
                    metrics.record_bytes_read(n);
                }
                prop_assert_eq!(metrics.snapshot().bytes_read, expected);
            }

            // ── MountOptions properties ─────────────────────────────────

            /// Resolved thread count is always >= 1.
            #[test]
            fn mount_options_resolved_at_least_one(threads in 0_usize..=256) {
                let opts = MountOptions {
                    worker_threads: threads,
                    ..Default::default()
                };
                prop_assert!(opts.resolved_thread_count() >= 1);
            }

            /// Explicit worker_threads passes through (when > 0).
            #[test]
            fn mount_options_explicit_passthrough(threads in 1_usize..=256) {
                let opts = MountOptions {
                    worker_threads: threads,
                    ..Default::default()
                };
                prop_assert_eq!(opts.resolved_thread_count(), threads);
            }

            // ── PerCoreConfig properties ────────────────────────────────

            /// total_cache_blocks = resolved_cores * cache_blocks_per_core.
            #[test]
            fn per_core_total_cache_blocks(
                cores in 1_u32..=16,
                blocks_per_core in 1_u32..=65536,
            ) {
                let cfg = PerCoreConfig {
                    num_cores: cores,
                    cache_blocks_per_core: blocks_per_core,
                    steal_threshold: 2.0,
                    advisory_affinity: true,
                };
                prop_assert_eq!(
                    cfg.total_cache_blocks(),
                    u64::from(cores) * u64::from(blocks_per_core)
                );
            }

            /// PerCoreDispatcher has exactly num_cores metrics slots.
            #[test]
            fn dispatcher_correct_num_metrics(cores in 1_u32..=16) {
                let cfg = PerCoreConfig {
                    num_cores: cores,
                    ..Default::default()
                };
                let disp = PerCoreDispatcher::new(cfg);
                prop_assert_eq!(disp.num_cores(), cores);
                for c in 0..cores {
                    prop_assert!(disp.core_metrics(c).is_some());
                }
                prop_assert!(disp.core_metrics(cores).is_none());
            }

            /// Aggregate total_requests = sum of per-core requests.
            #[test]
            fn dispatcher_aggregate_sums(
                per_core_counts in prop::collection::vec(0_u64..=1000, 2..=8),
            ) {
                let n = per_core_counts.len() as u32;
                let cfg = PerCoreConfig {
                    num_cores: n,
                    ..Default::default()
                };
                let disp = PerCoreDispatcher::new(cfg);
                let mut expected_total = 0_u64;
                for (i, &count) in per_core_counts.iter().enumerate() {
                    let m = disp.core_metrics(i as u32).unwrap();
                    for _ in 0..count {
                        m.begin_request();
                        m.record_request();
                    }
                    expected_total += count;
                }
                let agg = disp.aggregate_metrics();
                prop_assert_eq!(agg.total_requests, expected_total);
                prop_assert_eq!(agg.per_core.len(), n as usize);
            }

            /// Hit rate is in [0.0, 1.0] range.
            #[test]
            fn core_metrics_hit_rate_bounded(
                hits in 0_u64..=1000,
                misses in 0_u64..=1000,
            ) {
                let m = CoreMetrics::new();
                for _ in 0..hits { m.record_hit(); }
                for _ in 0..misses { m.record_miss(); }
                let rate = m.snapshot().hit_rate();
                prop_assert!((0.0..=1.0).contains(&rate), "hit_rate {rate} out of bounds");
            }

            /// Imbalance ratio >= 1.0 (or infinity if min is zero).
            #[test]
            fn dispatcher_imbalance_ratio_at_least_one(
                per_core_counts in prop::collection::vec(0_u64..=1000, 2..=8),
            ) {
                let n = per_core_counts.len() as u32;
                let cfg = PerCoreConfig {
                    num_cores: n,
                    ..Default::default()
                };
                let disp = PerCoreDispatcher::new(cfg);
                for (i, &count) in per_core_counts.iter().enumerate() {
                    let m = disp.core_metrics(i as u32).unwrap();
                    for _ in 0..count {
                        m.begin_request();
                        m.record_request();
                    }
                }
                let ratio = disp.aggregate_metrics().imbalance_ratio();
                prop_assert!(ratio >= 1.0 || ratio.is_infinite(),
                    "imbalance_ratio {ratio} < 1.0");
            }

            // ── Metamorphic relation properties (MR) ─────────────────────

            /// MR1: readahead write-then-read returns identical bytes.
            /// This is the core metamorphic relation for data integrity.
            #[test]
            fn mr_readahead_write_read_identity(
                ino in 1_u64..=1000,
                offset in 0_u64..=1_000_000,
                data in prop::collection::vec(any::<u8>(), 1..4096),
            ) {
                let manager = ReadaheadManager::new(64);
                let expected = data.clone();
                manager.insert(InodeNumber(ino), offset, data);
                let readback = manager.take(InodeNumber(ino), offset, expected.len());
                prop_assert_eq!(readback, Some(expected), "write-then-read must return identical bytes");
            }

            /// MR2: readahead insert-then-invalidate returns None (idempotent delete).
            #[test]
            fn mr_readahead_create_delete_idempotent(
                ino in 1_u64..=1000,
                offset in 0_u64..=1_000_000,
                data in prop::collection::vec(any::<u8>(), 1..256),
            ) {
                let manager = ReadaheadManager::new(64);
                let len = data.len();
                manager.insert(InodeNumber(ino), offset, data);
                manager.invalidate_inode(InodeNumber(ino));
                let after_delete = manager.take(InodeNumber(ino), offset, len);
                prop_assert_eq!(after_delete, None, "invalidate must remove entry");
            }

            /// MR3: truncate-to-N then read returns first N bytes.
            #[test]
            fn mr_readahead_truncate_preserves_prefix(
                data in prop::collection::vec(any::<u8>(), 4..256),
                truncate_to in 1_usize..=3,
            ) {
                let manager = ReadaheadManager::new(64);
                let ino = InodeNumber(42);
                let offset = 0_u64;
                let expected_prefix = data[..truncate_to].to_vec();
                manager.insert(ino, offset, data);
                // Partial take simulates truncate-then-read
                let prefix = manager.take(ino, offset, truncate_to);
                prop_assert_eq!(prefix, Some(expected_prefix), "truncate must preserve first N bytes");
            }

            /// MR4: concurrent independent inodes do not interfere.
            #[test]
            fn mr_readahead_concurrent_independent_no_interference(
                data1 in prop::collection::vec(any::<u8>(), 1..128),
                data2 in prop::collection::vec(any::<u8>(), 1..128),
            ) {
                let manager = ReadaheadManager::new(64);
                let ino1 = InodeNumber(100);
                let ino2 = InodeNumber(200);
                let expected1 = data1.clone();
                let expected2 = data2.clone();
                // Write to two independent inodes
                manager.insert(ino1, 0, data1);
                manager.insert(ino2, 0, data2);
                // Read back - each should see its own data
                let read1 = manager.take(ino1, 0, expected1.len());
                let read2 = manager.take(ino2, 0, expected2.len());
                prop_assert_eq!(read1, Some(expected1), "ino1 must read its own data");
                prop_assert_eq!(read2, Some(expected2), "ino2 must read its own data");
            }

            /// MR5: xattr encode-decode roundtrip preserves names (rename-back identity).
            #[test]
            fn mr_xattr_encode_decode_identity(
                names in prop::collection::vec("[a-z]{1,20}", 1..10),
            ) {
                let encoded = FrankenFuse::encode_xattr_names(&names);
                // Decode by splitting on NUL
                let decoded: Vec<String> = encoded
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                prop_assert_eq!(decoded, names, "encode-decode must be identity");
            }

            /// MR6: inode routing is deterministic (fsync-like stability).
            #[test]
            fn mr_inode_routing_stable_under_repeated_calls(
                ino in 0_u64..=u64::MAX,
                cores in 1_u32..=256,
            ) {
                let first = inode_to_core(ino, cores);
                let second = inode_to_core(ino, cores);
                let third = inode_to_core(ino, cores);
                prop_assert_eq!(first, second, "routing must be stable");
                prop_assert_eq!(second, third, "routing must be stable across multiple calls");
            }
        }
    }
}
