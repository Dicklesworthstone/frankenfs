#![forbid(unsafe_code)]

use asupersync::{Cx, RaptorQConfig};
use ffs_block::{
    ByteDevice, FileByteDevice, read_btrfs_superblock_region, read_ext4_superblock_region,
};
use ffs_error::FfsError;
use ffs_mvcc::{CommitError, MvccStore, Transaction};
use ffs_ondisk::{BtrfsSuperblock, Ext4Superblock};
use ffs_types::{BlockNumber, CommitSeq, InodeNumber, ParseError, Snapshot};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::Path;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsFlavor {
    Ext4(Ext4Superblock),
    Btrfs(BtrfsSuperblock),
}

#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("image does not decode as supported ext4/btrfs superblock")]
    UnsupportedImage,
    #[error("I/O error while probing image: {0}")]
    Io(#[from] FfsError),
}

pub fn detect_filesystem(image: &[u8]) -> Result<FsFlavor, DetectionError> {
    if let Ok(ext4) = Ext4Superblock::parse_from_image(image) {
        return Ok(FsFlavor::Ext4(ext4));
    }

    if let Ok(btrfs) = BtrfsSuperblock::parse_from_image(image) {
        return Ok(FsFlavor::Btrfs(btrfs));
    }

    Err(DetectionError::UnsupportedImage)
}

pub fn detect_filesystem_on_device(
    cx: &Cx,
    dev: &dyn ByteDevice,
) -> Result<FsFlavor, DetectionError> {
    let len = dev.len_bytes();

    let ext4_end =
        u64::try_from(ffs_types::EXT4_SUPERBLOCK_OFFSET + ffs_types::EXT4_SUPERBLOCK_SIZE)
            .map_err(|_| FfsError::Format("ext4 superblock end offset overflows u64".to_owned()))?;
    if len >= ext4_end {
        let ext4_region = read_ext4_superblock_region(cx, dev)?;
        if let Ok(sb) = Ext4Superblock::parse_superblock_region(&ext4_region) {
            return Ok(FsFlavor::Ext4(sb));
        }
    }

    let btrfs_end =
        u64::try_from(ffs_types::BTRFS_SUPER_INFO_OFFSET + ffs_types::BTRFS_SUPER_INFO_SIZE)
            .map_err(|_| {
                FfsError::Format("btrfs superblock end offset overflows u64".to_owned())
            })?;
    if len >= btrfs_end {
        let btrfs_region = read_btrfs_superblock_region(cx, dev)?;
        if let Ok(sb) = BtrfsSuperblock::parse_superblock_region(&btrfs_region) {
            return Ok(FsFlavor::Btrfs(sb));
        }
    }

    Err(DetectionError::UnsupportedImage)
}

pub fn detect_filesystem_at_path(
    cx: &Cx,
    path: impl AsRef<Path>,
) -> Result<FsFlavor, DetectionError> {
    let dev = FileByteDevice::open(path)?;
    detect_filesystem_on_device(cx, &dev)
}

// ── OpenFs API ──────────────────────────────────────────────────────────────

/// Options controlling how a filesystem image is opened.
///
/// By default, mount-time validation is enabled. Disable it only for
/// recovery or diagnostic workflows where reading a partially-corrupt
/// image is intentional.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    /// Skip mount-time validation (geometry, features, checksums).
    ///
    /// When `true`, the superblock is parsed but not validated via
    /// `validate_v1()`. Use for recovery or diagnostics only.
    pub skip_validation: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            skip_validation: false,
        }
    }
}

/// Pre-computed ext4 geometry derived from the superblock.
///
/// These values are computed once at open time and cached so that
/// downstream code does not re-derive them on every operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ext4Geometry {
    /// Number of block groups.
    pub groups_count: u32,
    /// Size of each group descriptor (32 or 64 bytes).
    pub group_desc_size: u16,
    /// Checksum seed for metadata_csum verification.
    pub csum_seed: u32,
    /// Whether the filesystem uses 64-bit block addressing.
    pub is_64bit: bool,
}

/// An opened filesystem image, ready for VFS operations.
///
/// `OpenFs` bundles a validated superblock, pre-computed geometry, and the
/// block device handle into a single context. The constructor validates by
/// default so callers cannot accidentally operate on unvalidated metadata.
///
/// # Opening a filesystem
///
/// ```ignore
/// let cx = Cx::for_request();
/// let fs = OpenFs::open(&cx, "/path/to/image.ext4")?;
/// println!("block_size = {}", fs.block_size());
/// ```
pub struct OpenFs {
    /// Detected filesystem type with parsed superblock.
    pub flavor: FsFlavor,
    /// Pre-computed ext4 geometry (None for btrfs).
    pub ext4_geometry: Option<Ext4Geometry>,
    /// Block device for I/O operations.
    dev: Box<dyn ByteDevice>,
}

impl std::fmt::Debug for OpenFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenFs")
            .field("flavor", &self.flavor)
            .field("ext4_geometry", &self.ext4_geometry)
            .field("dev_len", &self.dev.len_bytes())
            .finish()
    }
}

impl OpenFs {
    /// Open a filesystem image at `path` with default options (validation enabled).
    pub fn open(cx: &Cx, path: impl AsRef<Path>) -> Result<Self, FfsError> {
        Self::open_with_options(cx, path, &OpenOptions::default())
    }

    /// Open a filesystem image with custom options.
    pub fn open_with_options(
        cx: &Cx,
        path: impl AsRef<Path>,
        options: &OpenOptions,
    ) -> Result<Self, FfsError> {
        let dev = FileByteDevice::open(path.as_ref())?;
        Self::from_device(cx, Box::new(dev), options)
    }

    /// Open a filesystem from an already-opened device.
    pub fn from_device(
        cx: &Cx,
        dev: Box<dyn ByteDevice>,
        options: &OpenOptions,
    ) -> Result<Self, FfsError> {
        let flavor = detect_filesystem_on_device(cx, &*dev).map_err(|e| match e {
            DetectionError::UnsupportedImage => {
                FfsError::Format("image is not a recognized ext4 or btrfs filesystem".into())
            }
            DetectionError::Io(ffs_err) => ffs_err,
        })?;

        let ext4_geometry = match &flavor {
            FsFlavor::Ext4(sb) => {
                if !options.skip_validation {
                    sb.validate_v1().map_err(parse_error_to_ffs)?;
                }
                Some(Ext4Geometry {
                    groups_count: sb.groups_count(),
                    group_desc_size: sb.group_desc_size(),
                    csum_seed: sb.csum_seed(),
                    is_64bit: sb.is_64bit(),
                })
            }
            FsFlavor::Btrfs(_) => None,
        };

        Ok(Self {
            flavor,
            ext4_geometry,
            dev,
        })
    }

    /// The block device backing this filesystem.
    #[must_use]
    pub fn device(&self) -> &dyn ByteDevice {
        &*self.dev
    }

    /// Block size in bytes.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        match &self.flavor {
            FsFlavor::Ext4(sb) => sb.block_size,
            FsFlavor::Btrfs(sb) => sb.sectorsize,
        }
    }

    /// Whether this is an ext4 filesystem.
    #[must_use]
    pub fn is_ext4(&self) -> bool {
        matches!(self.flavor, FsFlavor::Ext4(_))
    }

    /// Whether this is a btrfs filesystem.
    #[must_use]
    pub fn is_btrfs(&self) -> bool {
        matches!(self.flavor, FsFlavor::Btrfs(_))
    }

    /// Device length in bytes.
    #[must_use]
    pub fn device_len(&self) -> u64 {
        self.dev.len_bytes()
    }
}

/// Convert a mount-time `ParseError` into the appropriate `FfsError` variant.
///
/// This is the crate-boundary conversion described in the `ffs-error` error
/// taxonomy. During mount-time validation, `ParseError::InvalidField` is
/// mapped based on the field name to distinguish unsupported features from
/// geometry errors from format errors.
fn parse_error_to_ffs(e: &ParseError) -> FfsError {
    match e {
        ParseError::InvalidField { field, reason } => {
            // Feature validation failures → UnsupportedFeature
            if field.contains("feature") || reason.contains("unsupported") {
                FfsError::UnsupportedFeature(format!("{field}: {reason}"))
            }
            // Geometry failures → InvalidGeometry
            else if field.contains("block_size")
                || field.contains("blocks_per_group")
                || field.contains("inodes_per_group")
                || field.contains("inode_size")
            {
                FfsError::InvalidGeometry(format!("{field}: {reason}"))
            }
            // Everything else → Format
            else {
                FfsError::Format(e.to_string())
            }
        }
        ParseError::InvalidMagic { .. } => FfsError::Format(e.to_string()),
        ParseError::InsufficientData { .. } | ParseError::IntegerConversion { .. } => {
            FfsError::Corruption {
                block: 0,
                detail: e.to_string(),
            }
        }
    }
}

// ── VFS semantics layer ─────────────────────────────────────────────────────

/// Filesystem-agnostic file type for VFS operations.
///
/// This is the semantics-level file type used by [`FsOps`] methods. It unifies
/// ext4's `Ext4FileType` and btrfs's inode type into a single enum that
/// higher layers (FUSE, harness) consume without filesystem-specific knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    RegularFile,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
}

/// Inode attributes returned by [`FsOps::getattr`] and [`FsOps::lookup`].
///
/// This is the semantics-level stat structure, analogous to POSIX `struct stat`.
/// Format-specific crates (ffs-ext4, ffs-btrfs) convert their on-disk inode
/// representations into `InodeAttr` at the crate boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeAttr {
    /// Inode number.
    pub ino: InodeNumber,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Last access time.
    pub atime: SystemTime,
    /// Last modification time.
    pub mtime: SystemTime,
    /// Last status change time.
    pub ctime: SystemTime,
    /// Creation time (if available).
    pub crtime: SystemTime,
    /// File type.
    pub kind: FileType,
    /// POSIX permission bits (lower 12 bits of mode).
    pub perm: u16,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Device ID (for block/char devices).
    pub rdev: u32,
    /// Preferred I/O block size.
    pub blksize: u32,
}

/// A directory entry returned by [`FsOps::readdir`].
///
/// Each entry represents one name in a directory listing. The `offset` field
/// is an opaque cookie for resuming iteration — FUSE passes it back on
/// subsequent `readdir` calls so the implementation can skip already-returned
/// entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// Inode number of the target.
    pub ino: InodeNumber,
    /// Opaque offset cookie for readdir continuation.
    pub offset: u64,
    /// File type of the target.
    pub kind: FileType,
    /// Entry name (filename component, not a full path).
    pub name: Vec<u8>,
}

impl DirEntry {
    /// Return the name as a UTF-8 string (lossy).
    #[must_use]
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// Minimal VFS operations trait for read-only filesystem access.
///
/// This is the internal interface that FUSE and the test harness call.
/// Format-specific implementations (ext4, btrfs) live behind this trait so
/// that higher layers are filesystem-agnostic.
///
/// # Design Notes
///
/// - All methods take `&Cx` for cooperative cancellation and deadline
///   propagation via the asupersync runtime.
/// - Errors are returned as `ffs_error::FfsError`, which maps to POSIX
///   errnos via [`FfsError::to_errno()`].
/// - The trait is `Send + Sync` so that FUSE can call it from multiple
///   threads concurrently.
/// - Only read-only operations are included in this initial version.
///   Write operations (create, write, mkdir, unlink, etc.) will be added
///   in a future bead once the MVCC write path is ready.
pub trait FsOps: Send + Sync {
    /// Get file attributes by inode number.
    ///
    /// Returns the attributes for the given inode. Returns
    /// `FfsError::NotFound` if the inode does not exist.
    fn getattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<InodeAttr>;

    /// Look up a directory entry by name.
    ///
    /// Returns the attributes of the child inode named `name` within the
    /// directory `parent`. Returns `FfsError::NotFound` if the name does
    /// not exist, or `FfsError::NotDirectory` if `parent` is not a directory.
    fn lookup(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> ffs_error::Result<InodeAttr>;

    /// List directory entries starting from `offset`.
    ///
    /// Returns a batch of entries from the directory identified by `ino`.
    /// The `offset` parameter is an opaque cookie from a previous call's
    /// `DirEntry::offset` field (use 0 for the first call). An empty
    /// result indicates the end of the directory.
    ///
    /// Returns `FfsError::NotDirectory` if `ino` is not a directory.
    fn readdir(&self, cx: &Cx, ino: InodeNumber, offset: u64) -> ffs_error::Result<Vec<DirEntry>>;

    /// Read file data.
    ///
    /// Returns up to `size` bytes starting at byte `offset` within the
    /// file identified by `ino`. Returns fewer bytes at EOF. Returns
    /// `FfsError::IsDirectory` if `ino` is a directory.
    fn read(&self, cx: &Cx, ino: InodeNumber, offset: u64, size: u32)
    -> ffs_error::Result<Vec<u8>>;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DurabilityPosterior {
    pub alpha: f64,
    pub beta: f64,
}

impl Default for DurabilityPosterior {
    fn default() -> Self {
        Self {
            alpha: 1.0,
            beta: 1.0,
        }
    }
}

impl DurabilityPosterior {
    /// Observe a single Bernoulli event ("did we see any corruption?").
    ///
    /// This is intentionally coarse; prefer `observe_blocks()` when scrub can
    /// report counts.
    pub fn observe_event(&mut self, corruption_event: bool) {
        self.observe_blocks(1, u64::from(corruption_event));
    }

    /// Observe scrub results as counts of scanned vs corrupted blocks.
    ///
    /// Uses a Beta-Binomial conjugate update where `alpha` counts "corrupt"
    /// and `beta` counts "clean".
    pub fn observe_blocks(&mut self, scanned_blocks: u64, corrupted_blocks: u64) {
        let scanned = scanned_blocks as f64;
        let corrupted = (corrupted_blocks.min(scanned_blocks)) as f64;
        let clean = (scanned - corrupted).max(0.0);
        self.alpha += corrupted;
        self.beta += clean;
    }

    #[must_use]
    pub fn expected_corruption_rate(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    #[must_use]
    pub fn variance(&self) -> f64 {
        let a = self.alpha;
        let b = self.beta;
        let denom = (a + b).powi(2) * (a + b + 1.0);
        if denom <= 0.0 {
            return 0.0;
        }
        (a * b) / denom
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DurabilityLossModel {
    pub corruption_cost: f64,
    pub redundancy_cost: f64,
    pub z_score: f64,
}

impl Default for DurabilityLossModel {
    fn default() -> Self {
        Self {
            corruption_cost: 10_000.0,
            redundancy_cost: 25.0,
            z_score: 3.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RedundancyDecision {
    pub repair_overhead: f64,
    pub expected_loss: f64,
    pub posterior_mean_corruption_rate: f64,
    pub posterior_hi_corruption_rate: f64,
    pub unrecoverable_risk_bound: f64,
    pub redundancy_loss: f64,
    pub corruption_loss: f64,
}

impl RedundancyDecision {
    #[must_use]
    pub fn to_raptorq_config(self, block_size: u32) -> RaptorQConfig {
        let mut cfg = RaptorQConfig::default();
        cfg.encoding.repair_overhead = self.repair_overhead;
        cfg.encoding.max_block_size = usize::try_from(block_size).unwrap_or(4096);
        cfg.encoding.symbol_size = u16::try_from(block_size.clamp(64, 1024)).unwrap_or(256);
        cfg
    }
}

#[derive(Debug, Clone, Default)]
pub struct DurabilityAutopilot {
    posterior: DurabilityPosterior,
    loss: DurabilityLossModel,
}

impl DurabilityAutopilot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_event(&mut self, corruption_event: bool) {
        self.posterior.observe_event(corruption_event);
    }

    pub fn observe_scrub(&mut self, scanned_blocks: u64, corrupted_blocks: u64) {
        self.posterior
            .observe_blocks(scanned_blocks, corrupted_blocks);
    }

    #[must_use]
    pub fn choose_overhead(&self, candidates: &[f64]) -> RedundancyDecision {
        self.choose_overhead_for_group(candidates, 32_768)
    }

    #[must_use]
    pub fn choose_overhead_for_group(
        &self,
        candidates: &[f64],
        source_block_count: u32,
    ) -> RedundancyDecision {
        const MIN_OVERHEAD: f64 = 1.01;
        const MAX_OVERHEAD: f64 = 1.10;
        const DEFAULT_OVERHEAD: f64 = 1.05;

        let p_mean = self.posterior.expected_corruption_rate();
        let p_hi = self
            .loss
            .z_score
            .mul_add(self.posterior.variance().sqrt(), p_mean)
            .clamp(0.0, 1.0);

        let mut best = RedundancyDecision {
            repair_overhead: DEFAULT_OVERHEAD,
            expected_loss: f64::INFINITY,
            posterior_mean_corruption_rate: p_mean,
            posterior_hi_corruption_rate: p_hi,
            unrecoverable_risk_bound: 1.0,
            redundancy_loss: 0.0,
            corruption_loss: f64::INFINITY,
        };

        let k = f64::from(source_block_count.max(1));
        let mut considered_any = false;

        for candidate in candidates {
            if !candidate.is_finite() || *candidate < MIN_OVERHEAD || *candidate > MAX_OVERHEAD {
                continue;
            }
            considered_any = true;

            // Repair budget fraction relative to source blocks.
            let rho = (candidate - 1.0).clamp(0.0, 1.0);

            // Conservative tail-risk estimate (Chernoff bound) for:
            //   P(N >= rho*K) where N ~ Binomial(K, p) and p is conservatively taken as p_hi.
            let risk_bound = if p_hi <= 0.0 {
                0.0
            } else if rho <= p_hi {
                1.0
            } else {
                let eps = 1e-12;
                let q = rho.clamp(eps, 1.0 - eps);
                let p = p_hi.clamp(eps, 1.0 - eps);
                let kl = q * (q / p).ln() + (1.0 - q) * ((1.0 - q) / (1.0 - p)).ln();
                (-k * kl.max(0.0)).exp()
            };

            let redundancy_loss = self.loss.redundancy_cost * rho;
            let corruption_loss = self.loss.corruption_cost * risk_bound;
            let expected_loss = redundancy_loss + corruption_loss;

            if expected_loss < best.expected_loss {
                best = RedundancyDecision {
                    repair_overhead: *candidate,
                    expected_loss,
                    posterior_mean_corruption_rate: p_mean,
                    posterior_hi_corruption_rate: p_hi,
                    unrecoverable_risk_bound: risk_bound,
                    redundancy_loss,
                    corruption_loss,
                };
            }
        }

        if !considered_any {
            best.repair_overhead = DEFAULT_OVERHEAD;
            best.redundancy_loss = self.loss.redundancy_cost * (DEFAULT_OVERHEAD - 1.0);
            best.corruption_loss = self.loss.corruption_cost;
            best.expected_loss = best.redundancy_loss + best.corruption_loss;
        }

        best
    }
}

#[derive(Debug, Default)]
pub struct FrankenFsEngine {
    store: MvccStore,
}

impl FrankenFsEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: MvccStore::new(),
        }
    }

    pub fn begin(&mut self) -> Transaction {
        self.store.begin()
    }

    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        self.store.commit(txn)
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.store.current_snapshot()
    }

    #[must_use]
    pub fn read(&self, block: BlockNumber, snapshot: Snapshot) -> Option<&[u8]> {
        self.store.read_visible(block, snapshot)
    }

    pub fn checkpoint(cx: &Cx) -> Result<(), Box<asupersync::Error>> {
        cx.checkpoint().map_err(Box::new)
    }

    pub fn inspect_image(image: &[u8]) -> Result<FsFlavor, DetectionError> {
        detect_filesystem(image)
    }

    pub fn parse_ext4(image: &[u8]) -> Result<Ext4Superblock, ParseError> {
        Ext4Superblock::parse_from_image(image)
    }

    pub fn parse_btrfs(image: &[u8]) -> Result<BtrfsSuperblock, ParseError> {
        BtrfsSuperblock::parse_from_image(image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_types::{
        BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, ByteOffset, EXT4_SUPER_MAGIC,
        EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE,
    };
    use std::sync::Mutex;

    /// In-memory ByteDevice for testing (no file I/O).
    #[derive(Debug)]
    struct TestDevice {
        data: Mutex<Vec<u8>>,
    }

    impl TestDevice {
        fn from_vec(v: Vec<u8>) -> Self {
            Self {
                data: Mutex::new(v),
            }
        }
    }

    impl ByteDevice for TestDevice {
        fn len_bytes(&self) -> u64 {
            self.data.lock().unwrap().len() as u64
        }

        fn read_exact_at(
            &self,
            _cx: &Cx,
            offset: ByteOffset,
            buf: &mut [u8],
        ) -> ffs_error::Result<()> {
            let off = offset.0 as usize;
            let data = self.data.lock().unwrap();
            let end = off + buf.len();
            if end > data.len() {
                return Err(FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "read past end",
                )));
            }
            buf.copy_from_slice(&data[off..end]);
            Ok(())
        }

        fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> ffs_error::Result<()> {
            let off = offset.0 as usize;
            let mut data = self.data.lock().unwrap();
            let end = off + buf.len();
            if end > data.len() {
                return Err(FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "write past end",
                )));
            }
            data[off..end].copy_from_slice(buf);
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn detect_ext4_and_btrfs_images() {
        let mut ext4_img = vec![0_u8; EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE];
        let sb = EXT4_SUPERBLOCK_OFFSET;
        ext4_img[sb + 0x38..sb + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        ext4_img[sb + 0x18..sb + 0x1C].copy_from_slice(&0_u32.to_le_bytes());
        let ext4 = detect_filesystem(&ext4_img).expect("detect ext4");
        assert!(matches!(ext4, FsFlavor::Ext4(_)));

        let mut btrfs_img = vec![0_u8; BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE];
        let sb2 = BTRFS_SUPER_INFO_OFFSET;
        btrfs_img[sb2 + 0x40..sb2 + 0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        btrfs_img[sb2 + 0x90..sb2 + 0x94].copy_from_slice(&4096_u32.to_le_bytes());
        btrfs_img[sb2 + 0x94..sb2 + 0x98].copy_from_slice(&4096_u32.to_le_bytes());
        let btrfs = detect_filesystem(&btrfs_img).expect("detect btrfs");
        assert!(matches!(btrfs, FsFlavor::Btrfs(_)));
    }

    // ── FsOps VFS trait tests ─────────────────────────────────────────

    /// A stub FsOps implementation for testing that the trait is object-safe
    /// and can be used as a trait object behind `dyn`.
    struct StubFs;

    impl FsOps for StubFs {
        fn getattr(&self, _cx: &Cx, ino: InodeNumber) -> ffs_error::Result<InodeAttr> {
            if ino == InodeNumber(1) {
                Ok(InodeAttr {
                    ino,
                    size: 4096,
                    blocks: 8,
                    atime: SystemTime::UNIX_EPOCH,
                    mtime: SystemTime::UNIX_EPOCH,
                    ctime: SystemTime::UNIX_EPOCH,
                    crtime: SystemTime::UNIX_EPOCH,
                    kind: FileType::Directory,
                    perm: 0o755,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 4096,
                })
            } else {
                Err(FfsError::NotFound(format!("inode {ino}")))
            }
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _parent: InodeNumber,
            name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            if name == "hello.txt" {
                Ok(InodeAttr {
                    ino: InodeNumber(11),
                    size: 13,
                    blocks: 8,
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
                })
            } else {
                Err(FfsError::NotFound(name.to_string_lossy().into_owned()))
            }
        }

        fn readdir(
            &self,
            _cx: &Cx,
            ino: InodeNumber,
            offset: u64,
        ) -> ffs_error::Result<Vec<DirEntry>> {
            if ino != InodeNumber(1) {
                return Err(FfsError::NotDirectory);
            }
            let all = vec![
                DirEntry {
                    ino: InodeNumber(1),
                    offset: 1,
                    kind: FileType::Directory,
                    name: b".".to_vec(),
                },
                DirEntry {
                    ino: InodeNumber(1),
                    offset: 2,
                    kind: FileType::Directory,
                    name: b"..".to_vec(),
                },
                DirEntry {
                    ino: InodeNumber(11),
                    offset: 3,
                    kind: FileType::RegularFile,
                    name: b"hello.txt".to_vec(),
                },
            ];
            Ok(all.into_iter().filter(|e| e.offset > offset).collect())
        }

        fn read(
            &self,
            _cx: &Cx,
            ino: InodeNumber,
            offset: u64,
            size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            if ino == InodeNumber(1) {
                return Err(FfsError::IsDirectory);
            }
            let data = b"Hello, world!";
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(data.len());
            let end = (start + size as usize).min(data.len());
            Ok(data[start..end].to_vec())
        }
    }

    #[test]
    fn fsops_getattr_root() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let attr = fs.getattr(&cx, InodeNumber(1)).unwrap();
        assert_eq!(attr.ino, InodeNumber(1));
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.nlink, 2);
    }

    #[test]
    fn fsops_getattr_not_found() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let err = fs.getattr(&cx, InodeNumber(999)).unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn fsops_lookup_found() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let attr = fs
            .lookup(&cx, InodeNumber(1), OsStr::new("hello.txt"))
            .unwrap();
        assert_eq!(attr.ino, InodeNumber(11));
        assert_eq!(attr.kind, FileType::RegularFile);
    }

    #[test]
    fn fsops_lookup_not_found() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let err = fs
            .lookup(&cx, InodeNumber(1), OsStr::new("missing"))
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn fsops_readdir_with_offset() {
        let fs = StubFs;
        let cx = Cx::for_testing();

        // Full listing from offset 0
        let entries = fs.readdir(&cx, InodeNumber(1), 0).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name_str(), ".");
        assert_eq!(entries[2].name_str(), "hello.txt");

        // Resume from offset 2 (skip . and ..)
        let entries = fs.readdir(&cx, InodeNumber(1), 2).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name_str(), "hello.txt");
    }

    #[test]
    fn fsops_readdir_not_directory() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let err = fs.readdir(&cx, InodeNumber(11), 0).unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOTDIR);
    }

    #[test]
    fn fsops_read_file() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let data = fs.read(&cx, InodeNumber(11), 0, 5).unwrap();
        assert_eq!(&data, b"Hello");

        // Read from offset
        let data = fs.read(&cx, InodeNumber(11), 7, 100).unwrap();
        assert_eq!(&data, b"world!");
    }

    #[test]
    fn fsops_read_directory_returns_is_directory() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let err = fs.read(&cx, InodeNumber(1), 0, 4096).unwrap_err();
        assert_eq!(err.to_errno(), libc::EISDIR);
    }

    #[test]
    fn fsops_trait_is_object_safe() {
        // Verify FsOps can be used as dyn trait object
        let fs: Box<dyn FsOps> = Box::new(StubFs);
        let cx = Cx::for_testing();
        let attr = fs.getattr(&cx, InodeNumber(1)).unwrap();
        assert_eq!(attr.kind, FileType::Directory);
    }

    #[test]
    fn dir_entry_name_str() {
        let entry = DirEntry {
            ino: InodeNumber(5),
            offset: 1,
            kind: FileType::RegularFile,
            name: b"test.txt".to_vec(),
        };
        assert_eq!(entry.name_str(), "test.txt");
    }

    #[test]
    fn file_type_variants_are_distinct() {
        let types = [
            FileType::RegularFile,
            FileType::Directory,
            FileType::Symlink,
            FileType::BlockDevice,
            FileType::CharDevice,
            FileType::Fifo,
            FileType::Socket,
        ];
        for (i, a) in types.iter().enumerate() {
            for (j, b) in types.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── OpenFs tests ─────────────────────────────────────────────────────

    /// Build a minimal synthetic ext4 image for OpenFs testing.
    fn build_ext4_image(block_size_log: u32) -> Vec<u8> {
        let block_size = 1024_u32 << block_size_log;
        let image_size = 128 * 1024; // 128K
        let mut image = vec![0_u8; image_size];
        let sb_off = EXT4_SUPERBLOCK_OFFSET;

        // magic
        image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        // log_block_size
        image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&block_size_log.to_le_bytes());
        // blocks_count_lo
        let blocks_count = (image_size as u32) / block_size;
        image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
        // inodes_count
        image[sb_off + 0x00..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
        // first_data_block
        let first_data = if block_size == 1024 { 1_u32 } else { 0_u32 };
        image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&first_data.to_le_bytes());
        // blocks_per_group
        image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
        // inodes_per_group
        image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
        // inode_size = 256
        image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
        // rev_level = 1 (dynamic)
        image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
        // feature_incompat = FILETYPE | EXTENTS
        let filetype: u32 = 0x0002;
        let extents: u32 = 0x0040;
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&(filetype | extents).to_le_bytes());
        // first_ino
        image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

        image
    }

    #[test]
    fn open_options_default_enables_validation() {
        let opts = OpenOptions::default();
        assert!(!opts.skip_validation);
    }

    #[test]
    fn open_fs_from_ext4_image() {
        let image = build_ext4_image(2); // 4K blocks
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        assert!(fs.is_ext4());
        assert!(!fs.is_btrfs());
        assert_eq!(fs.block_size(), 4096);
        assert!(fs.ext4_geometry.is_some());

        let geom = fs.ext4_geometry.as_ref().unwrap();
        assert!(geom.groups_count > 0);
        assert!(geom.group_desc_size == 32 || geom.group_desc_size == 64);
    }

    #[test]
    fn open_fs_debug_format() {
        let image = build_ext4_image(2);
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let debug = format!("{fs:?}");
        assert!(debug.contains("OpenFs"));
        assert!(debug.contains("dev_len"));
    }

    #[test]
    fn open_fs_rejects_garbage() {
        let garbage = vec![0xAB_u8; 1024 * 128];
        let dev = TestDevice::from_vec(garbage);
        let cx = Cx::for_testing();

        let err = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap_err();
        assert_eq!(err.to_errno(), libc::EINVAL); // Format error
    }

    #[test]
    fn open_fs_skip_validation() {
        // Build an image with bad features (should fail validation but pass with skip)
        let mut image = build_ext4_image(2);
        let sb_off = EXT4_SUPERBLOCK_OFFSET;
        // Set unsupported incompat feature (COMPRESSION = 0x0001)
        let bad_incompat: u32 = 0x0002 | 0x0040 | 0x0001; // FILETYPE | EXTENTS | COMPRESSION
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&bad_incompat.to_le_bytes());

        let dev = TestDevice::from_vec(image.clone());
        let cx = Cx::for_testing();

        // Should fail with default options
        let err = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap_err();
        assert!(
            matches!(err, FfsError::UnsupportedFeature(_) | FfsError::Format(_)),
            "expected feature/format error, got {err:?}",
        );

        // Should succeed with skip_validation
        let dev2 = TestDevice::from_vec(image);
        let opts = OpenOptions {
            skip_validation: true,
        };
        let fs = OpenFs::from_device(&cx, Box::new(dev2), &opts).unwrap();
        assert!(fs.is_ext4());
    }

    #[test]
    fn parse_error_to_ffs_mapping() {
        // Feature error
        let e = parse_error_to_ffs(ParseError::InvalidField {
            field: "feature_incompat",
            reason: "unsupported flags",
        });
        assert!(matches!(e, FfsError::UnsupportedFeature(_)));

        // Geometry error
        let e = parse_error_to_ffs(ParseError::InvalidField {
            field: "block_size",
            reason: "out of range",
        });
        assert!(matches!(e, FfsError::InvalidGeometry(_)));

        // Generic format error
        let e = parse_error_to_ffs(ParseError::InvalidField {
            field: "magic",
            reason: "wrong value",
        });
        assert!(matches!(e, FfsError::Format(_)));

        // Magic error
        let e = parse_error_to_ffs(ParseError::InvalidMagic {
            expected: 0xEF53,
            actual: 0x0000,
        });
        assert!(matches!(e, FfsError::Format(_)));

        // Truncation error
        let e = parse_error_to_ffs(ParseError::InsufficientData {
            needed: 100,
            offset: 0,
            actual: 50,
        });
        assert!(matches!(e, FfsError::Corruption { .. }));
    }

    #[test]
    fn durability_autopilot_prefers_more_redundancy_when_failures_observed() {
        let candidates = [1.02, 1.05, 1.10];

        let mut clean = DurabilityAutopilot::new();
        clean.observe_scrub(10_000, 0);
        let clean_decision = clean.choose_overhead(&candidates);
        assert!((clean_decision.repair_overhead - 1.02).abs() < 1e-12);

        let mut dirty = DurabilityAutopilot::new();
        dirty.observe_scrub(10_000, 300);
        let dirty_decision = dirty.choose_overhead(&candidates);
        assert!(dirty_decision.repair_overhead >= 1.05);
    }
}
