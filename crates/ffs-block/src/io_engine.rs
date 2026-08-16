//! Pluggable I/O engine abstraction for kernel-bypass backends.
//!
//! Defines the [`IoEngine`] trait that abstracts over different I/O
//! submission strategies:
//!
//! - **[`PreadPwriteEngine`]**: Standard `pread`/`pwrite` syscalls (default).
//! - **io_uring** (future, behind `iouring` feature flag): Linux 5.1+
//!   submission queue for async I/O without syscall overhead per operation.
//! - **SPDK** (future): User-space NVMe driver for zero-copy DMA.
//!
//! # Design
//!
//! The engine handles batch I/O submission. Callers build a batch of
//! [`IoOp`] requests (read/write/sync), submit them to the engine, and
//! receive [`IoCompletion`] results. This maps naturally to io_uring's
//! submission/completion queue model while also working for synchronous
//! engines that execute operations immediately.
//!
//! # Integration with [`super::VectoredBlockDevice`]
//!
//! The `VectoredBlockDevice` trait can delegate to an `IoEngine` for
//! true vectored I/O when available, falling back to scalar operations
//! on engines that don't support batching.
//!
//! # `unsafe_code = "forbid"` Compliance
//!
//! All engines use safe Rust. The io_uring engine (when implemented)
//! will use a safe wrapper crate (`io-uring` or similar) that handles
//! the unsafe kernel interface internally.

use ffs_error::{FfsError, Result};
use std::path::Path;
use std::sync::Arc;

/// A single I/O operation in a batch.
#[derive(Debug)]
pub enum IoOp {
    /// Read `len` bytes from `offset` into the provided buffer.
    Read {
        /// File offset in bytes.
        offset: u64,
        /// Buffer to read into.
        buf: Vec<u8>,
    },
    /// Write `data` at `offset`.
    Write {
        /// File offset in bytes.
        offset: u64,
        /// Data to write.
        data: Vec<u8>,
    },
    /// Sync.
    ///
    /// NOTE: this is implemented with `sync_all` (fsync), not fdatasync,
    /// despite what this comment said until 2026-08-16. Corrected rather
    /// than changed: `FileByteDevice::sync` was moved to `sync_data`
    /// because that device provably cannot extend its file, and whether
    /// the same holds for this engine's file has NOT been established.
    /// Asserting fdatasync semantics in a doc comment while calling fsync
    /// is how a reader concludes the flush is already cheap and stops
    /// looking.
    Sync,
}

/// Result of a completed I/O operation.
#[derive(Debug)]
pub enum IoCompletion {
    /// Read completed: returns the filled buffer.
    Read(Vec<u8>),
    /// Write completed.
    Write,
    /// Sync completed.
    Sync,
    /// Operation failed.
    Error(FfsError),
}

/// I/O engine statistics.
#[derive(Debug, Clone, Default)]
pub struct IoEngineStats {
    /// Total reads submitted.
    pub reads: u64,
    /// Total writes submitted.
    pub writes: u64,
    /// Total syncs submitted.
    pub syncs: u64,
    /// Total bytes read.
    pub bytes_read: u64,
    /// Total bytes written.
    pub bytes_written: u64,
    /// Total batches submitted.
    pub batches: u64,
}

impl IoEngineStats {
    fn record_batch(&mut self) {
        self.batches = self.batches.saturating_add(1);
    }

    fn record_read_submission(&mut self) {
        self.reads = self.reads.saturating_add(1);
    }

    fn record_write_submission(&mut self) {
        self.writes = self.writes.saturating_add(1);
    }

    fn record_sync_submission(&mut self) {
        self.syncs = self.syncs.saturating_add(1);
    }

    fn record_bytes_read(&mut self, bytes: usize) {
        self.bytes_read = self.bytes_read.saturating_add(Self::usize_to_u64(bytes));
    }

    fn record_bytes_written(&mut self, bytes: usize) {
        self.bytes_written = self.bytes_written.saturating_add(Self::usize_to_u64(bytes));
    }

    fn usize_to_u64(value: usize) -> u64 {
        u64::try_from(value).unwrap_or(u64::MAX)
    }
}

/// Pluggable I/O engine interface.
///
/// Engines accept a batch of I/O operations and return completions.
/// This models both synchronous (pread/pwrite) and asynchronous
/// (io_uring, SPDK) backends.
pub trait IoEngine: Send + Sync {
    /// Submit a batch of I/O operations and return their completions.
    ///
    /// Completions are returned in the same order as the input operations.
    /// For synchronous engines, this blocks until all operations complete.
    /// For async engines, this submits to the queue and polls for completion.
    fn submit_batch(&self, ops: Vec<IoOp>) -> Vec<IoCompletion>;

    /// Engine name for diagnostics.
    fn name(&self) -> &'static str;

    /// Current statistics.
    fn stats(&self) -> IoEngineStats;
}

// ── pread/pwrite engine ────────────────────────────────────────────────────

/// Standard `pread`/`pwrite` I/O engine.
///
/// Each operation maps to a single syscall. Simple and portable,
/// but incurs syscall overhead per I/O and cannot overlap operations.
pub struct PreadPwriteEngine {
    file: Arc<std::fs::File>,
    stats: parking_lot::Mutex<IoEngineStats>,
}

impl PreadPwriteEngine {
    /// Open a file for I/O with this engine.
    ///
    /// Opens read-write if possible, read-only otherwise.
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .or_else(|_| std::fs::OpenOptions::new().read(true).open(path))
            .map_err(FfsError::Io)?;

        Ok(Self {
            file: Arc::new(file),
            stats: parking_lot::Mutex::new(IoEngineStats::default()),
        })
    }

    /// Create from an existing open file.
    #[must_use]
    pub fn from_file(file: Arc<std::fs::File>) -> Self {
        Self {
            file,
            stats: parking_lot::Mutex::new(IoEngineStats::default()),
        }
    }
}

impl std::fmt::Debug for PreadPwriteEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreadPwriteEngine")
            .field("stats", &*self.stats.lock())
            .finish_non_exhaustive()
    }
}

impl IoEngine for PreadPwriteEngine {
    fn submit_batch(&self, ops: Vec<IoOp>) -> Vec<IoCompletion> {
        use std::os::unix::fs::FileExt;

        {
            let mut stats = self.stats.lock();
            stats.record_batch();
        }

        let results: Vec<IoCompletion> = ops
            .into_iter()
            .map(|op| match op {
                IoOp::Read { offset, mut buf } => {
                    self.stats.lock().record_read_submission();
                    match self.file.read_exact_at(&mut buf, offset) {
                        Ok(()) => {
                            let mut s = self.stats.lock();
                            s.record_bytes_read(buf.len());
                            drop(s);
                            IoCompletion::Read(buf)
                        }
                        Err(e) => IoCompletion::Error(FfsError::Io(e)),
                    }
                }
                IoOp::Write { offset, data } => {
                    self.stats.lock().record_write_submission();
                    match self.file.write_all_at(&data, offset) {
                        Ok(()) => {
                            let mut s = self.stats.lock();
                            s.record_bytes_written(data.len());
                            drop(s);
                            IoCompletion::Write
                        }
                        Err(e) => IoCompletion::Error(FfsError::Io(e)),
                    }
                }
                IoOp::Sync => {
                    self.stats.lock().record_sync_submission();
                    match self.file.sync_all() {
                        Ok(()) => IoCompletion::Sync,
                        Err(e) => IoCompletion::Error(FfsError::Io(e)),
                    }
                }
            })
            .collect();
        results
    }

    fn name(&self) -> &'static str {
        "pread/pwrite"
    }

    fn stats(&self) -> IoEngineStats {
        self.stats.lock().clone()
    }
}

// ── In-memory engine (for testing) ─────────────────────────────────────────

/// In-memory I/O engine for testing and benchmarking.
///
/// All I/O operates on a `Vec<u8>` buffer, eliminating disk latency
/// to isolate engine overhead.
///
/// # Lock-order invariant (bd-6hopq)
///
/// `MemIoEngine` holds two mutexes — `data` and `stats`. The
/// established lock order is **`data` → `stats`** (the data lock is
/// the OUTER lock, the stats lock is the INNER lock):
///
/// * [`MemIoEngine::submit_batch`] acquires `data` first (held for
///   the whole batch) and then takes `stats` repeatedly (release-
///   on-loop-iteration) for every per-op counter update.
/// * [`MemIoEngine::stats`] and the `Debug` impl take **only**
///   `stats`, never `data`.
///
/// **Any future code path that holds both locks MUST acquire `data`
/// first.** A path that took `stats` then `data` would create an
/// AB-BA deadlock the first time it ran concurrently with a
/// `submit_batch` call. The
/// `mem_io_engine_no_deadlock_under_concurrent_submit_and_stats`
/// regression test exercises high-contention concurrent
/// `submit_batch` + `stats()` calls and asserts no deadlock plus
/// stats-accumulation correctness.
pub struct MemIoEngine {
    data: parking_lot::Mutex<Vec<u8>>,
    stats: parking_lot::Mutex<IoEngineStats>,
}

impl MemIoEngine {
    /// Create a new in-memory engine with the given size in bytes.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            data: parking_lot::Mutex::new(vec![0_u8; size]),
            stats: parking_lot::Mutex::new(IoEngineStats::default()),
        }
    }

    fn checked_range(
        offset: u64,
        len: usize,
        capacity: usize,
        out_of_bounds_kind: std::io::ErrorKind,
        out_of_bounds_message: &'static str,
    ) -> Result<std::ops::Range<usize>> {
        let start = usize::try_from(offset).map_err(|_| {
            FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "memory I/O offset does not fit usize",
            ))
        })?;
        let end = start.checked_add(len).ok_or_else(|| {
            FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "memory I/O range overflows usize",
            ))
        })?;
        if end > capacity {
            return Err(FfsError::Io(std::io::Error::new(
                out_of_bounds_kind,
                out_of_bounds_message,
            )));
        }
        Ok(start..end)
    }
}

impl std::fmt::Debug for MemIoEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemIoEngine")
            .field("size", &self.data.lock().len())
            .finish_non_exhaustive()
    }
}

impl IoEngine for MemIoEngine {
    fn submit_batch(&self, ops: Vec<IoOp>) -> Vec<IoCompletion> {
        let mut data = self.data.lock();
        self.stats.lock().record_batch();

        let results: Vec<IoCompletion> = ops
            .into_iter()
            .map(|op| match op {
                IoOp::Read { offset, mut buf } => {
                    self.stats.lock().record_read_submission();
                    let range = match Self::checked_range(
                        offset,
                        buf.len(),
                        data.len(),
                        std::io::ErrorKind::UnexpectedEof,
                        "read past end of memory",
                    ) {
                        Ok(range) => range,
                        Err(err) => return IoCompletion::Error(err),
                    };
                    buf.copy_from_slice(&data[range]);
                    let mut s = self.stats.lock();
                    s.record_bytes_read(buf.len());
                    drop(s);
                    IoCompletion::Read(buf)
                }
                IoOp::Write { offset, data: wd } => {
                    self.stats.lock().record_write_submission();
                    let range = match Self::checked_range(
                        offset,
                        wd.len(),
                        data.len(),
                        std::io::ErrorKind::WriteZero,
                        "write past end of memory",
                    ) {
                        Ok(range) => range,
                        Err(err) => return IoCompletion::Error(err),
                    };
                    data[range].copy_from_slice(&wd);
                    let mut s = self.stats.lock();
                    s.record_bytes_written(wd.len());
                    IoCompletion::Write
                }
                IoOp::Sync => {
                    self.stats.lock().record_sync_submission();
                    IoCompletion::Sync
                }
            })
            .collect();
        results
    }

    fn name(&self) -> &'static str {
        "memory"
    }

    fn stats(&self) -> IoEngineStats {
        self.stats.lock().clone()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[derive(Clone, Debug)]
    enum MemOpPlan {
        Read { offset: usize, len: usize },
        Write { offset: usize, data: Vec<u8> },
        Sync,
    }

    fn mem_op_plan_strategy(max_size: usize) -> impl Strategy<Value = MemOpPlan> {
        let read_op = (0_usize..max_size)
            .prop_flat_map(move |offset| {
                let max_len = (max_size - offset).min(64);
                (Just(offset), 1_usize..=max_len)
            })
            .prop_map(|(offset, len)| MemOpPlan::Read { offset, len });

        let write_op = (0_usize..max_size)
            .prop_flat_map(move |offset| {
                let max_len = (max_size - offset).min(64);
                (
                    Just(offset),
                    prop::collection::vec(any::<u8>(), 1_usize..=max_len),
                )
            })
            .prop_map(|(offset, data)| MemOpPlan::Write { offset, data });

        prop_oneof![3 => read_op, 3 => write_op, 1 => Just(MemOpPlan::Sync)]
    }

    #[test]
    fn mem_engine_read_write_roundtrip() {
        let engine = MemIoEngine::new(4096);

        // Write 4K of data.
        let data = vec![0xAB_u8; 4096];
        let completions = engine.submit_batch(vec![IoOp::Write {
            offset: 0,
            data: data.clone(),
        }]);
        assert!(matches!(completions[0], IoCompletion::Write));

        // Read it back.
        let completions = engine.submit_batch(vec![IoOp::Read {
            offset: 0,
            buf: vec![0_u8; 4096],
        }]);
        assert!(matches!(completions[0], IoCompletion::Read(_)));
        if let IoCompletion::Read(buf) = &completions[0] {
            assert_eq!(buf, &data);
        }
    }

    #[test]
    fn mem_engine_batch_operations() {
        let engine = MemIoEngine::new(8192);

        // Submit a batch: write + write + read.
        let completions = engine.submit_batch(vec![
            IoOp::Write {
                offset: 0,
                data: vec![1_u8; 4096],
            },
            IoOp::Write {
                offset: 4096,
                data: vec![2_u8; 4096],
            },
            IoOp::Read {
                offset: 0,
                buf: vec![0_u8; 4096],
            },
        ]);

        assert!(matches!(completions[0], IoCompletion::Write));
        assert!(matches!(completions[1], IoCompletion::Write));
        assert!(
            matches!(completions[2], IoCompletion::Read(_)),
            "expected Read, got {:?}",
            completions[2]
        );
        if let IoCompletion::Read(buf) = &completions[2] {
            assert_eq!(buf[0], 1);
        }
    }

    #[test]
    fn mem_engine_read_past_end_returns_error() {
        let engine = MemIoEngine::new(1024);

        let completions = engine.submit_batch(vec![IoOp::Read {
            offset: 512,
            buf: vec![0_u8; 1024], // 512 + 1024 > 1024
        }]);

        assert!(matches!(completions[0], IoCompletion::Error(_)));
        let stats = engine.stats();
        assert_eq!(stats.batches, 1);
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.bytes_read, 0);
    }

    #[test]
    fn mem_engine_rejects_overflowing_read_range() {
        let engine = MemIoEngine::new(1024);

        let completions = engine.submit_batch(vec![IoOp::Read {
            offset: u64::MAX,
            buf: vec![0_u8; 1],
        }]);

        let IoCompletion::Error(err) = &completions[0] else {
            panic!("expected Error, got {:?}", completions[0]);
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("overflows usize"),
            "expected the range-overflow error, got: {msg}"
        );
        let stats = engine.stats();
        assert_eq!(stats.batches, 1);
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.bytes_read, 0);
    }

    #[test]
    fn mem_engine_rejects_overflowing_write_range() {
        let engine = MemIoEngine::new(1024);

        let completions = engine.submit_batch(vec![IoOp::Write {
            offset: u64::MAX,
            data: vec![0_u8; 1],
        }]);

        let IoCompletion::Error(err) = &completions[0] else {
            panic!("expected Error, got {:?}", completions[0]);
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("overflows usize"),
            "expected the range-overflow error, got: {msg}"
        );
        let stats = engine.stats();
        assert_eq!(stats.batches, 1);
        assert_eq!(stats.writes, 1);
        assert_eq!(stats.bytes_written, 0);
    }

    #[test]
    fn mem_engine_sync_succeeds() {
        let engine = MemIoEngine::new(1024);
        let completions = engine.submit_batch(vec![IoOp::Sync]);
        assert!(matches!(completions[0], IoCompletion::Sync));
    }

    #[test]
    fn mem_engine_stats_tracking() {
        let engine = MemIoEngine::new(4096);

        engine.submit_batch(vec![
            IoOp::Write {
                offset: 0,
                data: vec![0_u8; 1024],
            },
            IoOp::Read {
                offset: 0,
                buf: vec![0_u8; 512],
            },
            IoOp::Sync,
        ]);

        let stats = engine.stats();
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.writes, 1);
        assert_eq!(stats.syncs, 1);
        assert_eq!(stats.bytes_written, 1024);
        assert_eq!(stats.bytes_read, 512);
        assert_eq!(stats.batches, 1);
    }

    #[test]
    fn mem_engine_multiple_batches_accumulate() {
        let engine = MemIoEngine::new(4096);

        engine.submit_batch(vec![IoOp::Write {
            offset: 0,
            data: vec![0_u8; 100],
        }]);
        engine.submit_batch(vec![IoOp::Write {
            offset: 100,
            data: vec![0_u8; 200],
        }]);

        let stats = engine.stats();
        assert_eq!(stats.writes, 2);
        assert_eq!(stats.bytes_written, 300);
        assert_eq!(stats.batches, 2);
    }

    #[test]
    fn mem_engine_stats_saturate_at_numeric_limits() {
        let engine = MemIoEngine::new(4096);
        {
            let mut stats = engine.stats.lock();
            stats.batches = u64::MAX;
            stats.reads = u64::MAX;
            stats.writes = u64::MAX;
            stats.syncs = u64::MAX;
            stats.bytes_read = u64::MAX - 1;
            stats.bytes_written = u64::MAX - 1;
        }

        let completions = engine.submit_batch(vec![
            IoOp::Read {
                offset: 0,
                buf: vec![0_u8; 4],
            },
            IoOp::Write {
                offset: 0,
                data: vec![1_u8; 4],
            },
            IoOp::Sync,
        ]);

        assert!(matches!(completions[0], IoCompletion::Read(_)));
        assert!(matches!(completions[1], IoCompletion::Write));
        assert!(matches!(completions[2], IoCompletion::Sync));

        let stats = engine.stats();
        assert_eq!(stats.batches, u64::MAX);
        assert_eq!(stats.reads, u64::MAX);
        assert_eq!(stats.writes, u64::MAX);
        assert_eq!(stats.syncs, u64::MAX);
        assert_eq!(stats.bytes_read, u64::MAX);
        assert_eq!(stats.bytes_written, u64::MAX);
    }

    #[test]
    fn pread_pwrite_engine_from_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.img");

        // Create a 4K file.
        std::fs::write(&path, vec![0_u8; 4096]).unwrap();

        let engine = PreadPwriteEngine::open(&path).unwrap();
        assert_eq!(engine.name(), "pread/pwrite");

        // Write + read roundtrip.
        let data = vec![0x42_u8; 512];
        let completions = engine.submit_batch(vec![IoOp::Write {
            offset: 0,
            data: data.clone(),
        }]);
        assert!(matches!(completions[0], IoCompletion::Write));

        let completions = engine.submit_batch(vec![IoOp::Read {
            offset: 0,
            buf: vec![0_u8; 512],
        }]);
        assert!(matches!(completions[0], IoCompletion::Read(_)));
        if let IoCompletion::Read(buf) = &completions[0] {
            assert_eq!(buf, &data);
        }

        // Check stats.
        let stats = engine.stats();
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.writes, 1);
    }

    #[test]
    fn pread_pwrite_engine_failed_read_counts_submission_but_not_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.img");
        std::fs::write(&path, vec![0_u8; 16]).unwrap();

        let engine = PreadPwriteEngine::open(&path).unwrap();
        let completions = engine.submit_batch(vec![IoOp::Read {
            offset: 8,
            buf: vec![0_u8; 32],
        }]);

        assert!(matches!(completions[0], IoCompletion::Error(_)));
        let stats = engine.stats();
        assert_eq!(stats.batches, 1);
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.bytes_read, 0);
    }

    #[test]
    fn batch_vs_scalar_same_result() {
        let engine = MemIoEngine::new(8192);

        // Write blocks individually.
        for i in 0..4 {
            let byte = u8::try_from(i + 1).expect("test byte fits in u8");
            engine.submit_batch(vec![IoOp::Write {
                offset: i * 2048,
                data: vec![byte; 2048],
            }]);
        }

        // Read them back as a batch.
        let completions = engine.submit_batch(vec![
            IoOp::Read {
                offset: 0,
                buf: vec![0_u8; 2048],
            },
            IoOp::Read {
                offset: 2048,
                buf: vec![0_u8; 2048],
            },
            IoOp::Read {
                offset: 4096,
                buf: vec![0_u8; 2048],
            },
            IoOp::Read {
                offset: 6144,
                buf: vec![0_u8; 2048],
            },
        ]);

        for (i, comp) in completions.iter().enumerate() {
            let expected = u8::try_from(i + 1).expect("test byte fits in u8");
            let IoCompletion::Read(buf) = comp else {
                assert!(
                    matches!(comp, IoCompletion::Read(_)),
                    "expected Read, got {comp:?}"
                );
                continue;
            };
            assert_eq!(buf[0], expected, "block {i} mismatch");
        }
    }

    #[test]
    fn engine_name_correct() {
        let mem = MemIoEngine::new(1024);
        assert_eq!(mem.name(), "memory");
    }

    #[test]
    fn representative_io_engine_debug_exact_golden_contract() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("engine.img");
        std::fs::write(&path, vec![0_u8; 64]).expect("seed file");

        let pread = PreadPwriteEngine::open(&path).expect("open");
        let mem = MemIoEngine::new(128);
        let actual = [
            format!(
                "{:?}",
                IoOp::Read {
                    offset: 7,
                    buf: vec![1, 2, 3],
                }
            ),
            format!("{:?}", IoCompletion::Read(vec![4, 5])),
            format!(
                "{:?}",
                IoEngineStats {
                    reads: 1,
                    writes: 2,
                    syncs: 3,
                    bytes_read: 4,
                    bytes_written: 5,
                    batches: 6,
                }
            ),
            format!("{mem:?}"),
            format!("{pread:?}"),
        ]
        .join("\n");

        let expected = concat!(
            "Read { offset: 7, buf: [1, 2, 3] }\n",
            "Read([4, 5])\n",
            "IoEngineStats { reads: 1, writes: 2, syncs: 3, bytes_read: 4, bytes_written: 5, batches: 6 }\n",
            "MemIoEngine { size: 128, .. }\n",
            "PreadPwriteEngine { stats: IoEngineStats { reads: 0, writes: 0, syncs: 0, bytes_read: 0, bytes_written: 0, batches: 0 }, .. }"
        );
        assert_eq!(actual, expected);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn mem_engine_proptest_batch_semantics_and_stats(
            script in prop::collection::vec(mem_op_plan_strategy(512), 1..80),
        ) {
            const MEM_SIZE: usize = 512;

            let engine = MemIoEngine::new(MEM_SIZE);
            let mut model = vec![0_u8; MEM_SIZE];

            let ops: Vec<IoOp> = script
                .iter()
                .map(|plan| match plan {
                    MemOpPlan::Read { offset, len } => IoOp::Read {
                        offset: u64::try_from(*offset).expect("offset fits in u64"),
                        buf: vec![0_u8; *len],
                    },
                    MemOpPlan::Write { offset, data } => IoOp::Write {
                        offset: u64::try_from(*offset).expect("offset fits in u64"),
                        data: data.clone(),
                    },
                    MemOpPlan::Sync => IoOp::Sync,
                })
                .collect();

            let completions = engine.submit_batch(ops);
            prop_assert_eq!(completions.len(), script.len());

            let mut expected_reads = 0_u64;
            let mut expected_writes = 0_u64;
            let mut expected_syncs = 0_u64;
            let mut expected_bytes_read = 0_u64;
            let mut expected_bytes_written = 0_u64;

            for (plan, completion) in script.iter().zip(completions.iter()) {
                match plan {
                    MemOpPlan::Read { offset, len } => {
                        expected_reads += 1;
                        expected_bytes_read +=
                            u64::try_from(*len).expect("read length fits in u64");
                        match completion {
                            IoCompletion::Read(buf) => {
                                prop_assert_eq!(buf.len(), *len);
                                prop_assert_eq!(buf.as_slice(), &model[*offset..(*offset + *len)]);
                            }
                            other => prop_assert!(false, "expected Read completion, got {other:?}"),
                        }
                    }
                    MemOpPlan::Write { offset, data } => {
                        expected_writes += 1;
                        expected_bytes_written +=
                            u64::try_from(data.len()).expect("write length fits in u64");
                        match completion {
                            IoCompletion::Write => {
                                model[*offset..(*offset + data.len())].copy_from_slice(data);
                            }
                            other => prop_assert!(false, "expected Write completion, got {other:?}"),
                        }
                    }
                    MemOpPlan::Sync => {
                        expected_syncs += 1;
                        prop_assert!(matches!(completion, IoCompletion::Sync));
                    }
                }
            }

            let stats = engine.stats();
            prop_assert_eq!(stats.batches, 1);
            prop_assert_eq!(stats.reads, expected_reads);
            prop_assert_eq!(stats.writes, expected_writes);
            prop_assert_eq!(stats.syncs, expected_syncs);
            prop_assert_eq!(stats.bytes_read, expected_bytes_read);
            prop_assert_eq!(stats.bytes_written, expected_bytes_written);
        }

        #[test]
        fn mem_engine_proptest_read_oob_is_error_and_not_counted(
            size in 1_usize..1024,
            offset in 0_usize..2048,
            len in 1_usize..1024,
        ) {
            prop_assume!(offset > size || len > (size - offset));

            let engine = MemIoEngine::new(size);
            let completions = engine.submit_batch(vec![IoOp::Read {
                offset: u64::try_from(offset).expect("offset fits in u64"),
                buf: vec![0_u8; len],
            }]);

            prop_assert_eq!(completions.len(), 1);
            prop_assert!(matches!(completions[0], IoCompletion::Error(_)));

            let stats = engine.stats();
            prop_assert_eq!(stats.batches, 1);
            prop_assert_eq!(stats.reads, 1);
            prop_assert_eq!(stats.bytes_read, 0);
        }

        #[test]
        fn mem_engine_proptest_write_oob_is_error_and_not_counted(
            size in 1_usize..1024,
            offset in 0_usize..2048,
            len in 1_usize..1024,
            payload in prop::collection::vec(any::<u8>(), 1_usize..1024),
        ) {
            let write_len = len.min(payload.len());
            prop_assume!(offset > size || write_len > (size - offset));

            let engine = MemIoEngine::new(size);
            let completions = engine.submit_batch(vec![IoOp::Write {
                offset: u64::try_from(offset).expect("offset fits in u64"),
                data: payload[..write_len].to_vec(),
            }]);

            prop_assert_eq!(completions.len(), 1);
            prop_assert!(matches!(completions[0], IoCompletion::Error(_)));

            let stats = engine.stats();
            prop_assert_eq!(stats.batches, 1);
            prop_assert_eq!(stats.writes, 1);
            prop_assert_eq!(stats.bytes_written, 0);
        }
    }

    /// bd-6hopq — Regression for the `MemIoEngine` data → stats
    /// lock-order invariant.
    ///
    /// `submit_batch` holds `data` for the entire batch and takes
    /// `stats` repeatedly inside the loop. `stats()` and `Debug`
    /// take only `stats`. Any future path that took `stats` then
    /// `data` would create an AB-BA deadlock under contention.
    ///
    /// This test runs N writers calling `submit_batch` and N
    /// pollers calling `stats()` concurrently for a fixed duration,
    /// then asserts:
    ///
    ///   1. No thread is stuck in a futex (the joins return).
    ///   2. The final `stats.writes` count equals the cumulative
    ///      writes the writers logged. This proves the inner
    ///      `stats` lock serialized correctly under the outer
    ///      `data` lock — a regression that violated the order
    ///      would either deadlock or under-count.
    #[test]
    fn mem_io_engine_no_deadlock_under_concurrent_submit_and_stats() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::thread;

        const WRITERS: usize = 4;
        const POLLERS: usize = 4;
        const WRITES_PER_THREAD: u64 = 256;

        let engine = Arc::new(MemIoEngine::new(64 * 1024));
        let writers_done = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for w in 0..WRITERS {
            let e = Arc::clone(&engine);
            let done = Arc::clone(&writers_done);
            handles.push(thread::spawn(move || {
                let writer_byte = u8::try_from(w).expect("fixed writer count fits in u8");
                let writer_offset_base = u64::try_from(w).expect("fixed writer count fits in u64");
                for i in 0..WRITES_PER_THREAD {
                    let offset = (writer_offset_base * 1024 + i % 1024) % (64 * 1024 - 8);
                    let _ = e.submit_batch(vec![IoOp::Write {
                        offset,
                        data: vec![writer_byte; 8],
                    }]);
                }
                done.fetch_add(WRITES_PER_THREAD, Ordering::Relaxed);
            }));
        }

        for _ in 0..POLLERS {
            let e = Arc::clone(&engine);
            handles.push(thread::spawn(move || {
                for _ in 0..1024 {
                    let s = e.stats();
                    // touching counters proves stats acquired
                    // without dependency on `data`
                    let _ = s.writes;
                    let _ = s.bytes_written;
                }
            }));
        }

        for h in handles {
            h.join().expect("no panic in worker thread");
        }

        let expected_writes =
            u64::try_from(WRITERS).expect("fixed writer count fits in u64") * WRITES_PER_THREAD;
        let final_stats = engine.stats();
        assert_eq!(
            writers_done.load(Ordering::Relaxed),
            expected_writes,
            "all writer batches must complete (no deadlock)"
        );
        assert_eq!(
            final_stats.writes, expected_writes,
            "stats.writes must equal total writes — proves the inner stats \
             lock serialized correctly under the outer data lock"
        );
        assert_eq!(
            final_stats.batches, expected_writes,
            "stats.batches must equal total batches"
        );
    }
}
