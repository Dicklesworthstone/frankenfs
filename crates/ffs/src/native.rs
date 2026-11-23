//! Bounded read-only access to the existing native filesystem engines.

use asupersync::Cx;
use ffs_block::io_engine::{VolumeAccess, VolumeDevice};
use ffs_block::{ByteDevice, FileByteDevice};
use ffs_core::{
    BtrfsMountSelection, DetectedFilesystem, DetectionError, Ext4JournalReplayMode, FileType,
    FsFormatKind, FsOps, OpenFs, OpenOptions, RequestScope, detect_all_filesystems_on_device,
};
use ffs_error::{FfsError, Result};
use ffs_ondisk::fat::FatOemCodePage;
use ffs_ondisk::partition::{
    PartitionEntry, PartitionParseError, PartitionParseOptions, PartitionSelector, PartitionTable,
};
use ffs_types::{ByteOffset, InodeNumber};
use std::io::IoSliceMut;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Six-axis independent resource budget for untrusted or bounded native image reads (`bd-mizd2`).
///
/// A metadata-count cap alone cannot stop sparse/decompression expansion bombs,
/// deep/cyclic reference chains, or degraded-replica retry storms; each axis is
/// tracked and enforced independently. `None` on an axis leaves that axis unbounded
/// at the facade layer while still recording exact usage telemetry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceBudget {
    pub max_physical_io_bytes: Option<u64>,
    pub max_decoded_bytes: Option<u64>,
    pub max_retained_bytes: Option<u64>,
    pub max_reference_depth: Option<u32>,
    pub max_operations: Option<u64>,
    pub max_retry_attempts: Option<u32>,
}

/// Point-in-time snapshot of the six independent resource counters on [`ReadOnlyFs`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceUsageSnapshot {
    pub physical_io_bytes: u64,
    pub decoded_bytes: u64,
    pub retained_bytes: u64,
    pub peak_retained_bytes: u64,
    pub current_reference_depth: u32,
    pub peak_reference_depth: u32,
    pub operations: u64,
    pub retry_attempts: u32,
}

/// Shared atomic tracker enforcing a [`ResourceBudget`] across primary/companion
/// [`BoundedByteDevice`] handles and bounded facade traversals.
#[derive(Debug)]
pub struct ResourceTracker {
    budget: ResourceBudget,
    physical_io_bytes: AtomicU64,
    decoded_bytes: AtomicU64,
    retained_bytes: AtomicU64,
    peak_retained_bytes: AtomicU64,
    current_reference_depth: AtomicU32,
    peak_reference_depth: AtomicU32,
    operations: AtomicU64,
    retry_attempts: AtomicU32,
}

impl ResourceTracker {
    #[must_use]
    pub fn new(budget: ResourceBudget) -> Self {
        Self {
            budget,
            physical_io_bytes: AtomicU64::new(0),
            decoded_bytes: AtomicU64::new(0),
            retained_bytes: AtomicU64::new(0),
            peak_retained_bytes: AtomicU64::new(0),
            current_reference_depth: AtomicU32::new(0),
            peak_reference_depth: AtomicU32::new(0),
            operations: AtomicU64::new(0),
            retry_attempts: AtomicU32::new(0),
        }
    }

    #[must_use]
    pub const fn budget(&self) -> ResourceBudget {
        self.budget
    }

    #[must_use]
    pub fn snapshot(&self) -> ResourceUsageSnapshot {
        ResourceUsageSnapshot {
            physical_io_bytes: self.physical_io_bytes.load(Ordering::SeqCst),
            decoded_bytes: self.decoded_bytes.load(Ordering::SeqCst),
            retained_bytes: self.retained_bytes.load(Ordering::SeqCst),
            peak_retained_bytes: self.peak_retained_bytes.load(Ordering::SeqCst),
            current_reference_depth: self.current_reference_depth.load(Ordering::SeqCst),
            peak_reference_depth: self.peak_reference_depth.load(Ordering::SeqCst),
            operations: self.operations.load(Ordering::SeqCst),
            retry_attempts: self.retry_attempts.load(Ordering::SeqCst),
        }
    }

    pub fn charge_operation(&self) -> Result<()> {
        charge_u64(&self.operations, 1, self.budget.max_operations, "operations").map(|_| ())
    }

    pub fn charge_physical_io(&self, bytes: u64) -> Result<()> {
        self.charge_operation()?;
        charge_u64(
            &self.physical_io_bytes,
            bytes,
            self.budget.max_physical_io_bytes,
            "physical_io_bytes",
        )
        .map(|_| ())
    }

    pub fn charge_decoded_bytes(&self, bytes: u64) -> Result<()> {
        charge_u64(
            &self.decoded_bytes,
            bytes,
            self.budget.max_decoded_bytes,
            "decoded_bytes",
        )
        .map(|_| ())
    }

    pub fn acquire_retained_bytes(self: &Arc<Self>, bytes: u64) -> Result<RetainedBytesGuard> {
        let next = charge_u64(
            &self.retained_bytes,
            bytes,
            self.budget.max_retained_bytes,
            "retained_bytes",
        )?;
        self.peak_retained_bytes.fetch_max(next, Ordering::SeqCst);
        Ok(RetainedBytesGuard {
            tracker: Arc::clone(self),
            bytes,
        })
    }

    pub fn enter_reference_depth(self: &Arc<Self>) -> Result<ReferenceDepthGuard> {
        let next = charge_u32(
            &self.current_reference_depth,
            self.budget.max_reference_depth,
            "reference_depth",
        )?;
        self.peak_reference_depth.fetch_max(next, Ordering::SeqCst);
        Ok(ReferenceDepthGuard {
            tracker: Arc::clone(self),
        })
    }

    pub fn charge_retry_attempt(&self) -> Result<()> {
        charge_u32(
            &self.retry_attempts,
            self.budget.max_retry_attempts,
            "retry_attempts",
        )
        .map(|_| ())
    }
}

// Publish only admitted values. Increment-then-rollback temporarily exposes
// wrapped counters to another reader, which can admit work past the same cap.
fn charge_u64(counter: &AtomicU64, amount: u64, limit: Option<u64>, axis: &str) -> Result<u64> {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            current
                .checked_add(amount)
                .filter(|next| limit.is_none_or(|cap| *next <= cap))
        })
        .map(|previous| previous + amount)
        .map_err(|previous| budget_error(axis, previous.checked_add(amount), limit))
}

fn charge_u32(counter: &AtomicU32, limit: Option<u32>, axis: &str) -> Result<u32> {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            current
                .checked_add(1)
                .filter(|next| limit.is_none_or(|cap| *next <= cap))
        })
        .map(|previous| previous + 1)
        .map_err(|previous| {
            budget_error(
                axis,
                previous.checked_add(1).map(u64::from),
                limit.map(u64::from),
            )
        })
}

fn budget_error(axis: &str, next: Option<u64>, limit: Option<u64>) -> FfsError {
    let detail = match (next, limit) {
        (Some(next), Some(limit)) => {
            format!("resource budget exceeded: {axis} {next} > max_{axis} {limit}")
        }
        _ => format!("resource budget overflow: {axis}"),
    };
    FfsError::Io(std::io::Error::other(detail))
}

/// RAII guard releasing retained working-memory bytes when dropped.
#[derive(Debug)]
pub struct RetainedBytesGuard {
    tracker: Arc<ResourceTracker>,
    bytes: u64,
}

impl RetainedBytesGuard {
    fn resize(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.bytes {
            let next = charge_u64(
                &self.tracker.retained_bytes,
                bytes - self.bytes,
                self.tracker.budget.max_retained_bytes,
                "retained_bytes",
            )?;
            self.tracker
                .peak_retained_bytes
                .fetch_max(next, Ordering::SeqCst);
        } else {
            self.tracker
                .retained_bytes
                .fetch_sub(self.bytes - bytes, Ordering::SeqCst);
        }
        self.bytes = bytes;
        Ok(())
    }
}

/// Reserve a requested decode before asking the backend to allocate its result.
/// Unused bytes from EOF or a failed call do not consume the lifetime budget.
struct DecodedBytesReservation<'a> {
    tracker: &'a ResourceTracker,
    bytes: u64,
}

impl DecodedBytesReservation<'_> {
    fn commit(mut self, bytes: u64) {
        self.tracker
            .decoded_bytes
            .fetch_sub(self.bytes - bytes, Ordering::SeqCst);
        self.bytes = 0;
    }
}

impl Drop for DecodedBytesReservation<'_> {
    fn drop(&mut self) {
        self.tracker
            .decoded_bytes
            .fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl Drop for RetainedBytesGuard {
    fn drop(&mut self) {
        self.tracker
            .retained_bytes
            .fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

/// RAII guard decrementing reference traversal depth when dropped.
#[derive(Debug)]
pub struct ReferenceDepthGuard {
    tracker: Arc<ResourceTracker>,
}

impl Drop for ReferenceDepthGuard {
    fn drop(&mut self) {
        self.tracker
            .current_reference_depth
            .fetch_sub(1, Ordering::SeqCst);
    }
}

/// Read-only [`ByteDevice`] decorator enforcing physical-I/O, operation-count, and
/// replica-retry budgets while rejecting every write, sync, commit, or discard before
/// reaching the inner device.
#[derive(Clone)]
pub struct BoundedByteDevice {
    inner: Arc<dyn ByteDevice>,
    tracker: Arc<ResourceTracker>,
}

impl std::fmt::Debug for BoundedByteDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedByteDevice")
            .field("len_bytes", &self.inner.len_bytes())
            .field("tracker", &self.tracker)
            .finish()
    }
}

impl BoundedByteDevice {
    #[must_use]
    pub fn new(inner: Arc<dyn ByteDevice>, tracker: Arc<ResourceTracker>) -> Self {
        Self { inner, tracker }
    }

    #[must_use]
    pub const fn tracker(&self) -> &Arc<ResourceTracker> {
        &self.tracker
    }

    /// Execute a read across candidate replica devices, charging one retry attempt per
    /// failed replica fallback and failing closed if `max_retry_attempts` is exceeded.
    pub fn read_across_replicas(
        cx: &Cx,
        replicas: &[Self],
        offset: ByteOffset,
        buf: &mut [u8],
    ) -> Result<usize> {
        checkpoint(cx)?;
        if replicas.is_empty() {
            return Err(FfsError::Io(std::io::Error::other(
                "no replica devices supplied",
            )));
        }
        let mut last_err = None;
        for (idx, replica) in replicas.iter().enumerate() {
            if idx > 0 {
                replica.tracker.charge_retry_attempt()?;
            }
            match replica.read_exact_at(cx, offset, buf) {
                Ok(()) => return Ok(idx),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or(FfsError::ReadOnly))
    }
}

impl ByteDevice for BoundedByteDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn supports_vectored_reads(&self) -> bool {
        self.inner.supports_vectored_reads()
    }

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        self.inner.preserves_read_exact_at_destination_on_error()
    }

    fn preserves_read_vectored_destinations_on_error(&self) -> bool {
        self.inner.preserves_read_vectored_destinations_on_error()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let count = u64::try_from(buf.len())
            .map_err(|_| FfsError::InvalidGeometry("read buffer overflows u64".to_owned()))?;
        self.tracker.charge_physical_io(count)?;
        self.inner.read_exact_at(cx, offset, buf)
    }

    fn read_exact_at_volatile(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let count = u64::try_from(buf.len())
            .map_err(|_| FfsError::InvalidGeometry("read buffer overflows u64".to_owned()))?;
        self.tracker.charge_physical_io(count)?;
        self.inner.read_exact_at_volatile(cx, offset, buf)
    }

    fn read_vectored_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        checkpoint(cx)?;
        let mut total = 0_u64;
        for b in bufs.iter() {
            let len = u64::try_from(b.len()).map_err(|_| {
                FfsError::InvalidGeometry("vectored read buffer overflows u64".to_owned())
            })?;
            total = total.checked_add(len).ok_or_else(|| {
                FfsError::InvalidGeometry("vectored read total overflows u64".to_owned())
            })?;
        }
        self.tracker.charge_physical_io(total)?;
        self.inner.read_vectored_exact_at(cx, offset, bufs)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn write_vectored_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bufs: &[&[u8]]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn begin_durability_commit(&self, _cx: &Cx) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn discard(&self, _cx: &Cx, _offset: ByteOffset, _length: u64) -> Result<()> {
        Err(FfsError::ReadOnly)
    }
}

/// Summary returned by [`ReadOnlyFs::walk_bounded`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundedWalkSummary {
    pub directories_visited: u64,
    pub files_visited: u64,
    pub symlinks_visited: u64,
    pub decoded_file_bytes: u64,
    pub usage: ResourceUsageSnapshot,
}

/// An explicitly selected volume or journal inside an additional backing image.
/// The file must remain offline and immutable for the lifetime of the reader.
#[derive(Debug, Clone)]
pub struct ImageSource {
    pub path: PathBuf,
    pub offset: u64,
    pub length: Option<u64>,
}

/// Backend-specific read selection. Explicit selection still probes every
/// format and refuses ambiguous signatures; it never overrides native admission.
#[derive(Debug, Clone, Default)]
pub enum ReadOnlyBackend {
    /// Open the default view of the uniquely detected format.
    #[default]
    Auto,
    Ext4 {
        /// The JBD2 volume, with the same regular-file, lock and bounds admission
        /// as the data image. Recovery writes only to the volatile data overlay.
        external_journal: Option<ImageSource>,
    },
    Btrfs {
        root: BtrfsMountSelection,
        /// Each member retains its admitted descriptor through nested views.
        additional_devices: Vec<ImageSource>,
    },
    Fat {
        oem_code_page: FatOemCodePage,
    },
    /// Strict enumeration is the default. Indexed lookup validates only the
    /// selected native search range; directory enumeration remains complete.
    Ntfs {
        indexed_lookup: bool,
        /// Admit the verified volatile `$LogFile` recovery view. The backing
        /// image stays immutable; automatic detection retains clean admission.
        recover_logfile: bool,
    },
    Zfs(ZfsReadOptions),
}

/// ZFS selection keeps automatic read-only discovery distinct from an exact
/// committed candidate. Neither grants live pool ownership or write authority.
#[derive(Debug, Clone, Default)]
pub enum ZfsRootSelection {
    #[default]
    Auto,
    /// Automatic read-only selection bound to a caller-supplied pool GUID.
    Pool(u64),
    Candidate {
        pool_guid: u64,
        label: usize,
        slot: usize,
    },
}

/// Explicit missing-member extraction retains the native topology and parity
/// budget. It requires an exact exported-pool candidate and forbids log replay.
#[derive(Debug, Clone, Default)]
pub enum ZfsMissingMembers {
    #[default]
    None,
    Mirror(Vec<u64>),
    Raidz(Vec<u64>),
}

/// The same read-only pool, dataset, snapshot and volatile ZIL selections used
/// by the native ZFS engine. Dataset components and snapshot names are raw bytes.
#[derive(Debug, Clone, Default)]
pub struct ZfsReadOptions {
    pub additional_images: Vec<ImageSource>,
    pub root: ZfsRootSelection,
    pub dataset: Vec<Vec<u8>>,
    pub snapshot: Option<Vec<u8>>,
    pub replay_zil: bool,
    pub missing: ZfsMissingMembers,
}

/// Options for one immutable image view. There is deliberately no writable
/// fallback, native repair, external metadata WAL or runtime-construction option.
#[derive(Debug, Clone, Default)]
pub struct ReadOnlyOpenOptions {
    pub offset: u64,
    pub length: Option<u64>,
    /// Optional MBR or GPT partition selector (`1`, `<partuuid>`, `label:<name>`).
    /// Mutually exclusive with manual `offset` / `length`.
    pub partition: Option<PartitionSelector>,
    /// Permit falling back to the backup GPT header when the primary GPT is corrupt.
    pub allow_backup_gpt: bool,
    /// Synthetic ownership for FAT/NTFS/ZFS, as in their existing mount adapters.
    pub uid: u32,
    pub gid: u32,
    pub backend: ReadOnlyBackend,
    /// Six-axis independent resource budget enforced across primary/companion I/O
    /// and bounded facade traversals (`bd-mizd2`).
    pub budget: ResourceBudget,
}

/// Zero-copy, range-clamped [`ByteDevice`] window bound to a validated MBR or GPT
/// [`PartitionEntry`].
///
/// Any read, write, or discard whose start offset `>= entry.byte_len` or whose end
/// offset `> entry.byte_len` is rejected before forwarding to the inner device.
#[derive(Clone, Debug)]
pub struct PartitionByteDevice {
    volume: VolumeDevice,
    entry: PartitionEntry,
}

impl PartitionByteDevice {
    /// Construct a range-clamped partition window over `[entry.start_byte, entry.end_byte())`.
    pub fn new(
        inner: Arc<dyn ByteDevice>,
        entry: PartitionEntry,
        access: VolumeAccess,
    ) -> Result<Self> {
        if entry.byte_len == 0 {
            return Err(FfsError::InvalidGeometry(
                "partition byte_len must be non-zero".to_owned(),
            ));
        }
        let volume =
            VolumeDevice::new(inner, ByteOffset(entry.start_byte), entry.byte_len, access)?;
        Ok(Self { volume, entry })
    }

    /// Return the validated partition metadata for this slice.
    #[must_use]
    pub const fn entry(&self) -> &PartitionEntry {
        &self.entry
    }

    /// Return the underlying [`VolumeAccess`] policy (`ReadOnly` or `ReadWrite`).
    #[must_use]
    pub fn access(&self) -> VolumeAccess {
        self.volume.access()
    }

    fn check_bounds(&self, cx: &Cx, offset: ByteOffset, count: u64) -> Result<()> {
        checkpoint(cx)?;
        let end = offset.0.checked_add(count).ok_or_else(|| {
            FfsError::InvalidGeometry("partition-relative request overflows u64".to_owned())
        })?;
        if offset.0 >= self.entry.byte_len || end > self.entry.byte_len {
            return Err(FfsError::InvalidGeometry(format!(
                "partition #{} I/O out of bounds: offset={} len={count} partition_len={}",
                self.entry.index, offset.0, self.entry.byte_len
            )));
        }
        Ok(())
    }
}

impl ByteDevice for PartitionByteDevice {
    fn len_bytes(&self) -> u64 {
        self.entry.byte_len
    }

    fn supports_vectored_reads(&self) -> bool {
        self.volume.supports_vectored_reads()
    }

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        self.volume.preserves_read_exact_at_destination_on_error()
    }

    fn preserves_read_vectored_destinations_on_error(&self) -> bool {
        self.volume.preserves_read_vectored_destinations_on_error()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let count = u64::try_from(buf.len())
            .map_err(|_| FfsError::InvalidGeometry("partition buffer overflows u64".to_owned()))?;
        self.check_bounds(cx, offset, count)?;
        self.volume.read_exact_at(cx, offset, buf)
    }

    fn read_exact_at_volatile(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let count = u64::try_from(buf.len())
            .map_err(|_| FfsError::InvalidGeometry("partition buffer overflows u64".to_owned()))?;
        self.check_bounds(cx, offset, count)?;
        self.volume.read_exact_at_volatile(cx, offset, buf)
    }

    fn read_vectored_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        let mut count = 0_u64;
        for buf in bufs.iter() {
            let len = u64::try_from(buf.len()).map_err(|_| {
                FfsError::InvalidGeometry("partition vectored buffer overflows u64".to_owned())
            })?;
            count = count.checked_add(len).ok_or_else(|| {
                FfsError::InvalidGeometry("partition vectored read overflows u64".to_owned())
            })?;
        }
        self.check_bounds(cx, offset, count)?;
        self.volume.read_vectored_exact_at(cx, offset, bufs)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let count = u64::try_from(buf.len())
            .map_err(|_| FfsError::InvalidGeometry("partition buffer overflows u64".to_owned()))?;
        self.check_bounds(cx, offset, count)?;
        self.volume.write_all_at(cx, offset, buf)
    }

    fn write_vectored_all_at(&self, cx: &Cx, offset: ByteOffset, bufs: &[&[u8]]) -> Result<()> {
        let mut count = 0_u64;
        for buf in bufs {
            let len = u64::try_from(buf.len()).map_err(|_| {
                FfsError::InvalidGeometry("partition vectored buffer overflows u64".to_owned())
            })?;
            count = count.checked_add(len).ok_or_else(|| {
                FfsError::InvalidGeometry("partition vectored write overflows u64".to_owned())
            })?;
        }
        self.check_bounds(cx, offset, count)?;
        self.volume.write_vectored_all_at(cx, offset, bufs)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        self.volume.sync(cx)
    }

    fn begin_durability_commit(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        self.volume.begin_durability_commit(cx)
    }

    fn complete_durability_commit(&self) {
        self.volume.complete_durability_commit();
    }

    fn abort_durability_commit(&self) {
        self.volume.abort_durability_commit();
    }

    fn supports_discard(&self) -> bool {
        self.volume.supports_discard()
    }

    fn discard(&self, cx: &Cx, offset: ByteOffset, length: u64) -> Result<()> {
        self.check_bounds(cx, offset, length)?;
        self.volume.discard(cx, offset, length)
    }
}

fn map_partition_error(err: PartitionParseError) -> FfsError {
    match err {
        PartitionParseError::Io(msg) => FfsError::Io(std::io::Error::other(msg)),
        PartitionParseError::InvalidOptions(_)
        | PartitionParseError::InvalidGeometry(_)
        | PartitionParseError::OverlappingPartitions { .. }
        | PartitionParseError::NestedPartitionTable { .. } => {
            FfsError::InvalidGeometry(err.to_string())
        }
        PartitionParseError::PartitionNotFound(_) => FfsError::NotFound(err.to_string()),
        PartitionParseError::PrimaryGptCorrupt { .. }
        | PartitionParseError::BackupGptCorrupt { .. } => FfsError::Corruption {
            block: 1,
            detail: err.to_string(),
        },
        PartitionParseError::NotAPartitionTable(_) | PartitionParseError::AmbiguousLabel(_) => {
            FfsError::Format(err.to_string())
        }
    }
}

/// Discover and validate the outer MBR or GPT partition table on a [`ByteDevice`].
pub fn discover_partitions_on_device(
    cx: &Cx,
    device: &dyn ByteDevice,
    options: &PartitionParseOptions,
) -> Result<PartitionTable> {
    checkpoint(cx)?;
    PartitionTable::parse_with_reader(device.len_bytes(), options, |offset, buf| {
        device
            .read_exact_at(cx, ByteOffset(offset), buf)
            .map_err(|err| err.to_string())
    })
    .map_err(map_partition_error)
}

/// Discover and validate the outer MBR or GPT partition table of a regular disk image file.
pub fn discover_partitions(
    cx: &Cx,
    path: impl AsRef<Path>,
    options: &PartitionParseOptions,
) -> Result<PartitionTable> {
    let device = open_image(cx, path.as_ref(), 0, None)?;
    discover_partitions_on_device(cx, &device, options)
}

/// Validate the outer partition table, resolve `selector`, reject nested partition-table
/// bombs inside the selected slice, and return a range-clamped [`PartitionByteDevice`].
pub fn select_partition_device(
    cx: &Cx,
    inner: Arc<dyn ByteDevice>,
    selector: &PartitionSelector,
    options: &PartitionParseOptions,
    access: VolumeAccess,
) -> Result<(PartitionTable, PartitionByteDevice)> {
    let table = discover_partitions_on_device(cx, inner.as_ref(), options)?;
    let entry = table.select(selector).map_err(map_partition_error)?.clone();
    let partition_dev = PartitionByteDevice::new(inner, entry.clone(), access)?;
    PartitionTable::ensure_slice_not_nested_partition_table(
        entry.index,
        entry.byte_len,
        table.logical_block_bytes,
        |offset, buf| {
            partition_dev
                .read_exact_at(cx, ByteOffset(offset), buf)
                .map_err(|err| err.to_string())
        },
    )
    .map_err(map_partition_error)?;
    Ok((table, partition_dev))
}

/// Open a regular disk image read-only and return the range-clamped [`PartitionByteDevice`]
/// selected by `selector` (retaining the shared file lock on the underlying descriptor).
pub fn open_partition_read_only(
    cx: &Cx,
    path: impl AsRef<Path>,
    selector: &PartitionSelector,
    options: &PartitionParseOptions,
) -> Result<(PartitionTable, PartitionByteDevice)> {
    let outer = open_image(cx, path.as_ref(), 0, None)?;
    select_partition_device(
        cx,
        Arc::new(outer),
        selector,
        options,
        VolumeAccess::ReadOnly,
    )
}

/// An admitted native reader, ready for direct VFS use or a read-only FUSE mount.
/// The trait object exposes no format-specific write-enablement operation.
pub struct ReadOnlyFs {
    pub format: FsFormatKind,
    pub partition: Option<PartitionEntry>,
    pub filesystem: Box<dyn FsOps>,
    ntfs: Option<Arc<ffs_ntfs::NtfsFs>>,
    tracker: Arc<ResourceTracker>,
}

struct BoundedReadRange {
    ino: InodeNumber,
    offset: u64,
    total_len: u64,
    chunk_size: u32,
}

/// Brent's cycle detector keeps opaque continuation cookies bounded in memory.
/// Cookies need not be numerically increasing; a repeated deterministic suffix
/// still cannot make a read-only directory walk spin forever.
#[derive(Default)]
struct DirectoryCursor {
    offset: u64,
    checkpoint: u64,
    distance: u64,
    period: u64,
}

impl DirectoryCursor {
    fn advance(&mut self, ino: InodeNumber, next: u64) -> Result<()> {
        if next == self.offset || next == self.checkpoint {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "cyclic directory continuation cookie {next} at inode {}",
                    ino.0
                ),
            });
        }
        self.offset = next;
        self.distance += 1;
        if self.distance >= self.period.max(1) {
            self.checkpoint = next;
            self.distance = 0;
            self.period = self.period.max(1).saturating_mul(2);
        }
        Ok(())
    }
}

struct WalkFrame {
    ino: InodeNumber,
    cursor: DirectoryCursor,
    children: Vec<InodeNumber>,
    next_child: usize,
    children_memory: RetainedBytesGuard,
    _depth: ReferenceDepthGuard,
}

fn allocation_bytes<T>(capacity: usize) -> Result<u64> {
    capacity
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| budget_error("retained_bytes", None, None))
}

/// Count both allocations during a possible relocation, and count capacity,
/// not merely initialized elements. Spare capacity is bounded by the same cap.
fn reserve_bounded_vec<T>(
    tracker: &Arc<ResourceTracker>,
    values: &mut Vec<T>,
    additional: usize,
    retained: &mut RetainedBytesGuard,
) -> Result<()> {
    let required = values
        .len()
        .checked_add(additional)
        .ok_or_else(|| budget_error("retained_bytes", None, None))?;
    if required <= values.capacity() {
        return Ok(());
    }
    let desired = required.max(values.capacity().saturating_mul(2));
    let available = tracker.budget.max_retained_bytes.map_or(usize::MAX, |cap| {
        let bytes = cap.saturating_sub(tracker.retained_bytes.load(Ordering::SeqCst));
        usize::try_from(bytes).unwrap_or(usize::MAX) / std::mem::size_of::<T>().max(1)
    });
    let desired = required.max(desired.min(available));
    let mut next_memory = tracker.acquire_retained_bytes(allocation_bytes::<T>(desired)?)?;
    values
        .try_reserve_exact(desired - values.len())
        .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
    next_memory.resize(allocation_bytes::<T>(values.capacity())?)?;
    *retained = next_memory;
    Ok(())
}

impl ReadOnlyFs {
    /// Borrow the NTFS volume admitted by this open, for exact native DATA
    /// stream selection and metadata inspection. Other formats return `None`.
    /// The volume shares the original bounded, locked, OS-read-only descriptor;
    /// no pathname is reopened and no mutable volume reference is exposed.
    #[must_use]
    pub fn ntfs_volume(&self) -> Option<&ffs_ntfs::NtfsVolume> {
        self.ntfs
            .as_ref()
            .and_then(|filesystem| filesystem.volume())
    }

    /// Snapshot the six independent resource counters accumulated on this reader.
    #[must_use]
    pub fn resource_usage(&self) -> ResourceUsageSnapshot {
        self.tracker.snapshot()
    }

    /// Borrow the shared [`ResourceTracker`] governing this reader.
    #[must_use]
    pub const fn tracker(&self) -> &Arc<ResourceTracker> {
        &self.tracker
    }

    /// Read `[offset, offset + total_len)` in `chunk_size` increments, bounding
    /// requested decode buffers and the accumulated output before allocation.
    /// Retained accounting covers facade working buffers, including spare
    /// capacity and relocation; the returned `Vec` becomes caller-owned.
    pub fn read_bounded(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        offset: u64,
        total_len: u64,
        chunk_size: u32,
    ) -> Result<Vec<u8>> {
        let mut scope = RequestScope::empty();
        let mut retained = self.tracker.acquire_retained_bytes(0)?;
        let mut out = Vec::new();
        self.read_chunks_bounded(
            cx,
            &mut scope,
            BoundedReadRange {
                ino,
                offset,
                total_len,
                chunk_size,
            },
            |chunk| {
                reserve_bounded_vec(&self.tracker, &mut out, chunk.len(), &mut retained)?;
                out.extend_from_slice(chunk);
                Ok(())
            },
        )?;
        Ok(out)
    }

    fn read_chunks_bounded(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        range: BoundedReadRange,
        mut consume: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        checkpoint(cx)?;
        if range.chunk_size == 0 {
            return Err(FfsError::InvalidGeometry(
                "bounded read chunk_size must be non-zero".to_owned(),
            ));
        }
        let end = range.offset.checked_add(range.total_len).ok_or_else(|| {
            FfsError::InvalidGeometry("bounded read range overflows u64".to_owned())
        })?;
        let mut pos = range.offset;
        while pos < end {
            checkpoint(cx)?;
            self.tracker.charge_operation()?;
            let requested = (end - pos).min(u64::from(range.chunk_size));
            self.tracker.charge_decoded_bytes(requested)?;
            let decoded = DecodedBytesReservation {
                tracker: &self.tracker,
                bytes: requested,
            };
            let mut retained = self.tracker.acquire_retained_bytes(requested)?;
            let size = u32::try_from(requested).expect("request is bounded by a u32 chunk size");
            let chunk = self.filesystem.read(cx, scope, range.ino, pos, size)?;
            let actual = u64::try_from(chunk.len())
                .map_err(|_| FfsError::InvalidGeometry("chunk length overflows u64".to_owned()))?;
            if actual > requested {
                return Err(FfsError::Corruption {
                    block: 0,
                    detail: format!(
                        "inode {} returned {actual} bytes for a {requested}-byte read",
                        range.ino.0
                    ),
                });
            }
            retained.resize(allocation_bytes::<u8>(chunk.capacity())?)?;
            decoded.commit(actual);
            if chunk.is_empty() {
                break;
            }
            consume(&chunk)?;
            // `actual <= requested <= end - pos`, including near u64::MAX.
            pos += actual;
        }
        Ok(pos - range.offset)
    }

    /// Traverse `/` with a bounded heap stack and per-page child lists. File
    /// contents are consumed a chunk at a time instead of retained in full.
    /// Directory cycles and repeating opaque continuation cookies are refused.
    /// The retained budget covers facade buffers; native engine caches and
    /// allocations made inside `readdir` remain subject to backend limits.
    pub fn walk_bounded(&self, cx: &Cx, read_files: bool) -> Result<BoundedWalkSummary> {
        checkpoint(cx)?;
        let mut scope = RequestScope::empty();
        let mut summary = BoundedWalkSummary::default();
        let mut stack_memory = self.tracker.acquire_retained_bytes(0)?;
        let mut stack = Vec::new();
        self.push_walk_frame(&mut stack, &mut stack_memory, InodeNumber(1))?;
        summary.directories_visited = 1;
        while let Some(frame) = stack.last_mut() {
            checkpoint(cx)?;
            let Some(child_ino) = self.next_walk_child(cx, &mut scope, frame)? else {
                stack.pop();
                continue;
            };
            self.tracker.charge_operation()?;
            let attr = self.filesystem.getattr(cx, &mut scope, child_ino)?;
            match attr.kind {
                FileType::Directory => {
                    self.push_walk_frame(&mut stack, &mut stack_memory, attr.ino)?;
                    summary.directories_visited = summary.directories_visited.saturating_add(1);
                }
                FileType::RegularFile => {
                    summary.files_visited = summary.files_visited.saturating_add(1);
                    if read_files && attr.size > 0 {
                        let _leaf_depth = self.tracker.enter_reference_depth()?;
                        let decoded = self.read_chunks_bounded(
                            cx,
                            &mut scope,
                            BoundedReadRange {
                                ino: attr.ino,
                                offset: 0,
                                total_len: attr.size,
                                chunk_size: 65_536,
                            },
                            |_| Ok(()),
                        )?;
                        summary.decoded_file_bytes =
                            summary.decoded_file_bytes.saturating_add(decoded);
                    }
                }
                FileType::Symlink => {
                    let _sym_depth = self.tracker.enter_reference_depth()?;
                    self.tracker.charge_operation()?;
                    self.tracker.charge_decoded_bytes(attr.size)?;
                    let decoded = DecodedBytesReservation {
                        tracker: &self.tracker,
                        bytes: attr.size,
                    };
                    let mut memory = self.tracker.acquire_retained_bytes(attr.size)?;
                    let target = self.filesystem.readlink(cx, &mut scope, attr.ino)?;
                    let actual = allocation_bytes::<u8>(target.len())?;
                    if actual > attr.size {
                        return Err(FfsError::Corruption {
                            block: 0,
                            detail: format!("symlink {} exceeds its declared size", attr.ino.0),
                        });
                    }
                    memory.resize(allocation_bytes::<u8>(target.capacity())?)?;
                    decoded.commit(actual);
                    summary.symlinks_visited = summary.symlinks_visited.saturating_add(1);
                }
                _ => {}
            }
        }
        drop(stack);
        drop(stack_memory);
        summary.usage = self.tracker.snapshot();
        Ok(summary)
    }

    fn push_walk_frame(
        &self,
        stack: &mut Vec<WalkFrame>,
        memory: &mut RetainedBytesGuard,
        ino: InodeNumber,
    ) -> Result<()> {
        if stack.iter().any(|frame| frame.ino == ino) {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!("cyclic directory reference detected at inode {}", ino.0),
            });
        }
        let depth = self.tracker.enter_reference_depth()?;
        self.tracker.charge_operation()?;
        reserve_bounded_vec(&self.tracker, stack, 1, memory)?;
        stack.push(WalkFrame {
            ino,
            cursor: DirectoryCursor::default(),
            children: Vec::new(),
            next_child: 0,
            children_memory: self.tracker.acquire_retained_bytes(0)?,
            _depth: depth,
        });
        Ok(())
    }

    fn next_walk_child(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        frame: &mut WalkFrame,
    ) -> Result<Option<InodeNumber>> {
        loop {
            checkpoint(cx)?;
            if let Some(child) = frame.children.get(frame.next_child).copied() {
                frame.next_child += 1;
                return Ok(Some(child));
            }
            // Release the previous page before requesting the next, and before
            // reserving its replacement. No whole-directory child accumulator.
            frame.children = Vec::new();
            frame.children_memory.resize(0)?;
            frame.next_child = 0;
            self.tracker.charge_operation()?;
            // The page drops before its reservation, including on error.
            let _page_memory;
            let page = self
                .filesystem
                .readdir(cx, scope, frame.ino, frame.cursor.offset)?;
            if page.is_empty() {
                return Ok(None);
            }
            let next = page
                .as_slice()
                .last()
                .ok_or_else(|| FfsError::Io(std::io::Error::other("empty directory page")))?
                .offset;
            frame.cursor.advance(frame.ino, next)?;
            let page_bytes = page.iter().try_fold(
                allocation_bytes::<ffs_core::DirEntry>(page.len())?,
                |bytes, entry| {
                    bytes
                        .checked_add(allocation_bytes::<u8>(entry.name.capacity())?)
                        .ok_or_else(|| budget_error("retained_bytes", None, None))
                },
            )?;
            _page_memory = self.tracker.acquire_retained_bytes(page_bytes)?;
            reserve_bounded_vec(
                &self.tracker,
                &mut frame.children,
                page.len(),
                &mut frame.children_memory,
            )?;
            for entry in &page {
                checkpoint(cx)?;
                self.tracker.charge_operation()?;
                if entry.name == b"." || entry.name == b".." {
                    continue;
                }
                frame.children.push(entry.ino);
            }
        }
    }
}

impl std::fmt::Debug for ReadOnlyFs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadOnlyFs")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn open_image(cx: &Cx, path: &Path, offset: u64, length: Option<u64>) -> Result<VolumeDevice> {
    checkpoint(cx)?;
    let device = FileByteDevice::open_regular_read_only(path)?;
    // Retain this same descriptor under every engine and its clones. A second
    // pathname open could lock a different inode after a concurrent replacement.
    device
        .file()
        .try_lock_shared()
        .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
    let length = match length {
        Some(length) => length,
        None => device.len_bytes().checked_sub(offset).ok_or_else(|| {
            FfsError::InvalidGeometry("volume base exceeds backing length".to_owned())
        })?,
    };
    checkpoint(cx)?;
    VolumeDevice::new(
        Arc::new(device),
        ByteOffset(offset),
        length,
        VolumeAccess::ReadOnly,
    )
}

fn validate_selection(backend: &ReadOnlyBackend) -> Result<()> {
    let ReadOnlyBackend::Zfs(options) = backend else {
        return Ok(());
    };
    if matches!(
        options.root,
        ZfsRootSelection::Pool(0) | ZfsRootSelection::Candidate { pool_guid: 0, .. }
    ) {
        return Err(FfsError::UnsupportedFeature(
            "explicit ZFS pool GUID must be nonzero".to_owned(),
        ));
    }
    let supplied = options
        .additional_images
        .len()
        .checked_add(1)
        .ok_or_else(|| FfsError::UnsupportedFeature("too many ZFS member images".to_owned()))?;
    match &options.missing {
        ZfsMissingMembers::None => {
            if supplied > 8 {
                return Err(FfsError::UnsupportedFeature(
                    "ZFS read profiles admit at most eight supplied members".to_owned(),
                ));
            }
        }
        ZfsMissingMembers::Mirror(missing) => {
            ffs_zfs::reader::Pool::check_mirror_survivors(supplied, missing)?;
        }
        ZfsMissingMembers::Raidz(missing) => {
            ffs_zfs::reader::Pool::check_raidz_survivors(supplied, missing)?;
        }
    }
    if !matches!(options.missing, ZfsMissingMembers::None)
        && (!matches!(options.root, ZfsRootSelection::Candidate { .. }) || options.replay_zil)
    {
        return Err(FfsError::UnsupportedFeature(
            "missing ZFS members require an exact exported-pool candidate without ZIL replay"
                .to_owned(),
        ));
    }
    if options.replay_zil && options.snapshot.is_some() {
        return Err(FfsError::UnsupportedFeature(
            "ZIL replay cannot be combined with a snapshot view".to_owned(),
        ));
    }
    Ok(())
}

fn selection_matches(backend: &ReadOnlyBackend, format: FsFormatKind) -> bool {
    match backend {
        ReadOnlyBackend::Auto => true,
        ReadOnlyBackend::Ext4 { .. } => format == FsFormatKind::Ext4,
        ReadOnlyBackend::Btrfs { .. } => format == FsFormatKind::Btrfs,
        ReadOnlyBackend::Fat { .. } => {
            matches!(format, FsFormatKind::Fat16 | FsFormatKind::Fat32)
        }
        ReadOnlyBackend::Ntfs { .. } => format == FsFormatKind::Ntfs,
        ReadOnlyBackend::Zfs(_) => format == FsFormatKind::Zfs,
    }
}

fn validate_device_only_backend(backend: &ReadOnlyBackend) -> Result<()> {
    match backend {
        ReadOnlyBackend::Ext4 {
            external_journal: Some(_),
        } => Err(FfsError::UnsupportedFeature(
            "open_read_only_device does not open external journal paths".to_owned(),
        )),
        ReadOnlyBackend::Btrfs {
            additional_devices, ..
        } if !additional_devices.is_empty() => Err(FfsError::UnsupportedFeature(
            "open_read_only_device does not open additional btrfs device paths".to_owned(),
        )),
        ReadOnlyBackend::Zfs(options) if !options.additional_images.is_empty() => {
            Err(FfsError::UnsupportedFeature(
                "open_read_only_device does not open additional ZFS member paths".to_owned(),
            ))
        }
        _ => Ok(()),
    }
}

/// Open any admitted native format from an already-admitted [`ByteDevice`] with
/// strict read-only authority and zero ambient pathname opens.
///
/// The supplied device is wrapped in a `VolumeAccess::ReadOnly` [`VolumeDevice`]
/// (and optional [`PartitionByteDevice`] when `options.partition` is set) before
/// any signature probe or native engine executes. Companion path options
/// (`external_journal`, `additional_devices`, `additional_images`) are rejected
/// with [`FfsError::UnsupportedFeature`].
pub fn open_read_only_device(
    cx: &Cx,
    inner: Arc<dyn ByteDevice>,
    options: &ReadOnlyOpenOptions,
) -> Result<ReadOnlyFs> {
    checkpoint(cx)?;
    validate_selection(&options.backend)?;
    validate_device_only_backend(&options.backend)?;
    let (device, resolved_partition) = if let Some(selector) = &options.partition {
        if options.offset != 0 || options.length.is_some() {
            return Err(FfsError::InvalidGeometry(
                "partition selector cannot be combined with manual byte offset/length".to_owned(),
            ));
        }
        let parse_opts = PartitionParseOptions {
            allow_backup_gpt_fallback: options.allow_backup_gpt,
            ..PartitionParseOptions::default()
        };
        let (_table, part_dev) =
            select_partition_device(cx, inner, selector, &parse_opts, VolumeAccess::ReadOnly)?;
        let entry = part_dev.entry().clone();
        let vol = VolumeDevice::new(
            Arc::new(part_dev),
            ByteOffset(0),
            entry.byte_len,
            VolumeAccess::ReadOnly,
        )?;
        (vol, Some(entry))
    } else {
        let length = match options.length {
            Some(length) => length,
            None => inner
                .len_bytes()
                .checked_sub(options.offset)
                .ok_or_else(|| {
                    FfsError::InvalidGeometry("volume base exceeds backing length".to_owned())
                })?,
        };
        checkpoint(cx)?;
        (
            VolumeDevice::new(
                inner,
                ByteOffset(options.offset),
                length,
                VolumeAccess::ReadOnly,
            )?,
            None,
        )
    };
    open_admitted_volume(
        cx,
        device,
        resolved_partition,
        options,
        "open_read_only_device",
        false,
    )
}

/// Open any admitted native format through OS read-only, byte-bounded handles.
///
/// The image must remain offline and immutable. Advisory locking is not a
/// substitute for that precondition. ext4 recovery is confined to a volatile
/// overlay; NTFS recovery requires explicit selection and a completed native
/// recovery admission before exposing its volatile view. ZFS automatic
/// selection, explicit extraction and replay retain their native refusal rules.
/// No runtime or process-wide signal handler is created.
///
/// ```no_run
/// # fn example(cx: &asupersync::Cx) -> ffs_error::Result<()> {
/// use ffs::{InodeNumber, RequestScope, ReadOnlyOpenOptions, open_read_only};
/// let image = open_read_only(cx, "disk.img", &ReadOnlyOpenOptions::default())?;
/// let root = image.filesystem.getattr(cx, &mut RequestScope::empty(), InodeNumber(1))?;
/// println!("{} root: {:?}", image.format, root.kind);
/// # Ok(()) }
/// ```
pub fn open_read_only(
    cx: &Cx,
    path: impl AsRef<Path>,
    options: &ReadOnlyOpenOptions,
) -> Result<ReadOnlyFs> {
    checkpoint(cx)?;
    validate_selection(&options.backend)?;
    let (device, resolved_partition) = if let Some(selector) = &options.partition {
        if options.offset != 0 || options.length.is_some() {
            return Err(FfsError::InvalidGeometry(
                "partition selector cannot be combined with manual byte offset/length".to_owned(),
            ));
        }
        let parse_opts = PartitionParseOptions {
            allow_backup_gpt_fallback: options.allow_backup_gpt,
            ..PartitionParseOptions::default()
        };
        let (_table, part_dev) =
            open_partition_read_only(cx, path.as_ref(), selector, &parse_opts)?;
        let entry = part_dev.entry().clone();
        let vol = VolumeDevice::new(
            Arc::new(part_dev),
            ByteOffset(0),
            entry.byte_len,
            VolumeAccess::ReadOnly,
        )?;
        (vol, Some(entry))
    } else {
        (
            open_image(cx, path.as_ref(), options.offset, options.length)?,
            None,
        )
    };
    open_admitted_volume(
        cx,
        device,
        resolved_partition,
        options,
        "open_read_only",
        true,
    )
}

fn open_admitted_volume(
    cx: &Cx,
    device: VolumeDevice,
    resolved_partition: Option<PartitionEntry>,
    options: &ReadOnlyOpenOptions,
    operation: &'static str,
    allow_companion_paths: bool,
) -> Result<ReadOnlyFs> {
    if !allow_companion_paths {
        validate_device_only_backend(&options.backend)?;
    }
    let tracker = Arc::new(ResourceTracker::new(options.budget));
    let device = BoundedByteDevice::new(Arc::new(device), Arc::clone(&tracker));
    let effective_offset = resolved_partition
        .as_ref()
        .map_or(options.offset, |entry| entry.start_byte);
    let partition_id = resolved_partition
        .as_ref()
        .map_or_else(|| "none".to_owned(), PartitionEntry::canonical_id);
    let detected = detect_all_filesystems_on_device(cx, &device).map_err(|error| match error {
        DetectionError::Io(error) => error,
        other => FfsError::Format(other.to_string()),
    })?;
    let format = detected.kind();
    if !selection_matches(&options.backend, format) {
        return Err(FfsError::Format(format!(
            "read selection does not match detected {format} filesystem"
        )));
    }
    tracing::info!(
        target: "ffs::native",
        operation,
        %format,
        partition_id = %partition_id,
        offset = effective_offset,
        length = device.len_bytes(),
        "opening bounded native read-only view"
    );
    let mut ntfs = None;
    let filesystem: Box<dyn FsOps> = match detected {
        DetectedFilesystem::Ext4(_) | DetectedFilesystem::Btrfs(_) => {
            let mut core_options = OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
                ..OpenOptions::default()
            };
            let mut external_journal: Option<Arc<dyn ByteDevice>> = None;
            let mut btrfs_additional: Vec<Arc<dyn ByteDevice>> = Vec::new();
            match &options.backend {
                ReadOnlyBackend::Ext4 {
                    external_journal: Some(source),
                } => {
                    let jdev = open_image(cx, &source.path, source.offset, source.length)?;
                    external_journal = Some(Arc::new(BoundedByteDevice::new(
                        Arc::new(jdev),
                        Arc::clone(&tracker),
                    )));
                }
                ReadOnlyBackend::Btrfs {
                    root,
                    additional_devices,
                } => {
                    core_options.btrfs_mount_selection.clone_from(root);
                    for source in additional_devices {
                        let mdev = open_image(cx, &source.path, source.offset, source.length)?;
                        btrfs_additional.push(Arc::new(BoundedByteDevice::new(
                            Arc::new(mdev),
                            Arc::clone(&tracker),
                        )));
                    }
                }
                _ => {}
            }
            Box::new(OpenFs::from_devices(
                cx,
                Box::new(device),
                &core_options,
                VolumeAccess::ReadOnly,
                external_journal,
                btrfs_additional,
            )?)
        }
        DetectedFilesystem::Fat16(_) | DetectedFilesystem::Fat32(_) => {
            let length = device.len_bytes();
            let mut volume =
                ffs_fat::reader::FatVolume::from_device(cx, Box::new(device), 0, length)?;
            if let ReadOnlyBackend::Fat { oem_code_page } = &options.backend {
                volume = volume.with_oem_code_page(*oem_code_page);
            }
            Box::new(ffs_fat::filesystem::FatFs::new(
                cx,
                volume,
                options.uid,
                options.gid,
            )?)
        }
        DetectedFilesystem::Ntfs(_) => {
            let length = device.len_bytes();
            let (indexed_lookup, recover_logfile) = match &options.backend {
                ReadOnlyBackend::Ntfs {
                    indexed_lookup,
                    recover_logfile,
                } => (*indexed_lookup, *recover_logfile),
                _ => (false, false),
            };
            let volume = ffs_ntfs::NtfsVolume::from_device_with_options(
                cx,
                Box::new(device),
                0,
                length,
                recover_logfile,
            )?;
            let filesystem = match (indexed_lookup, recover_logfile) {
                (false, false) => ffs_ntfs::NtfsFs::new(cx, volume, options.uid, options.gid)?,
                (true, false) => {
                    ffs_ntfs::NtfsFs::new_indexed(cx, volume, options.uid, options.gid)?
                }
                (false, true) => {
                    ffs_ntfs::NtfsFs::new_recovered(cx, volume, options.uid, options.gid)?
                }
                (true, true) => {
                    ffs_ntfs::NtfsFs::new_recovered_indexed(cx, volume, options.uid, options.gid)?
                }
            };
            let filesystem = Arc::new(filesystem);
            ntfs = Some(Arc::clone(&filesystem));
            Box::new(filesystem)
        }
        DetectedFilesystem::Zfs(_) => {
            let defaults = ZfsReadOptions::default();
            let selection = match &options.backend {
                ReadOnlyBackend::Zfs(selection) => selection,
                _ => &defaults,
            };
            let length = device.len_bytes();
            let mut leaves = Vec::with_capacity(selection.additional_images.len() + 1);
            leaves.push(ffs_zfs::reader::Leaf::from_device(
                cx,
                Box::new(device),
                0,
                length,
            )?);
            for source in &selection.additional_images {
                let member = BoundedByteDevice::new(
                    Arc::new(open_image(cx, &source.path, source.offset, source.length)?),
                    Arc::clone(&tracker),
                );
                let length = member.len_bytes();
                leaves.push(ffs_zfs::reader::Leaf::from_device(
                    cx,
                    Box::new(member),
                    0,
                    length,
                )?);
            }
            let pool = match &selection.missing {
                ZfsMissingMembers::None => ffs_zfs::reader::Pool::from_leaves(leaves)?,
                ZfsMissingMembers::Mirror(guids) => {
                    ffs_zfs::reader::Pool::from_mirror_survivors(cx, leaves, guids.clone())?
                }
                ZfsMissingMembers::Raidz(guids) => {
                    ffs_zfs::reader::Pool::from_raidz_survivors(cx, leaves, guids.clone())?
                }
            };
            let mut objects = match selection.root {
                ZfsRootSelection::Auto => pool.import_objects(cx, None)?,
                ZfsRootSelection::Pool(guid) => pool.import_objects(cx, Some(guid))?,
                ZfsRootSelection::Candidate {
                    pool_guid,
                    label,
                    slot,
                } => pool.objects(cx, label, slot, pool_guid)?,
            };
            let mut view = match &selection.snapshot {
                Some(snapshot) => objects.zpl_snapshot(cx, &selection.dataset, snapshot)?,
                None => objects.zpl(cx, &selection.dataset)?,
            };
            if selection.replay_zil {
                view.replay_zil(cx)?;
            }
            Box::new(ffs_zfs::filesystem::ZfsFs::new(
                cx,
                view,
                options.uid,
                options.gid,
            )?)
        }
    };
    checkpoint(cx)?;
    Ok(ReadOnlyFs {
        format,
        partition: resolved_partition,
        filesystem,
        ntfs,
        tracker,
    })
}

#[cfg(test)]
mod tests;
