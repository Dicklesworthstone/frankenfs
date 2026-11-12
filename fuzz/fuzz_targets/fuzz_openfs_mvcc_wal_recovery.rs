#![no_main]

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_core::{OpenFs, OpenOptions};
use ffs_error::{FfsError, Result};
use ffs_mvcc::persist::WalRecoveryReport;
use ffs_mvcc::wal::{self, WalCommit, WalHeader, WalWrite, HEADER_SIZE as WAL_HEADER_SIZE};
use ffs_mvcc::wal_replay::{ReplayOutcome as WalReplayOutcome, TailPolicy};
use ffs_ondisk::EXT4_VALID_FS;
use ffs_types::{
    crc32c, BlockNumber, ByteOffset, CommitSeq, TxnId, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPER_MAGIC,
};
use libfuzzer_sys::fuzz_target;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

const MAX_INPUT_BYTES: usize = 256;
const IMAGE_SIZE: usize = 128 * 1024;
const EXT4_BLOCK_SIZE_LOG: u32 = 2;
const TRACKED_BLOCKS: [u64; 5] = [1, 2, 3, 10, 20];

#[derive(Clone, Copy)]
enum SeedCase {
    Clean,
    TruncatedTail,
    CorruptHeader,
    MonotonicityViolation,
    EmptyFile,
    NoWalPath,
}

impl SeedCase {
    fn from_selector(selector: u8) -> Self {
        match selector % 6 {
            0 => Self::Clean,
            1 => Self::TruncatedTail,
            2 => Self::CorruptHeader,
            3 => Self::MonotonicityViolation,
            4 => Self::EmptyFile,
            _ => Self::NoWalPath,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecoveryOutcomeClass {
    Clean,
    EmptyLog,
    TruncatedTail {
        records_discarded: u64,
    },
    CorruptTail {
        records_discarded: u64,
        first_corrupt_offset: u64,
    },
    MonotonicityViolation {
        violating_seq: u64,
        expected_after: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveryClass {
    outcome: RecoveryOutcomeClass,
    commits_replayed: u64,
    versions_replayed: u64,
    records_discarded: u64,
    wal_valid_bytes: u64,
    wal_total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OutcomeClass {
    Open {
        fail_fast: bool,
        recovery: Option<RecoveryClass>,
        version_count: usize,
        visible_entries: usize,
        visible_digest: u32,
    },
    Err {
        errno: i32,
        detail: String,
    },
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

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u16()) % len
        }
    }
}

#[derive(Debug)]
struct MemByteDevice {
    data: Arc<Mutex<Vec<u8>>>,
}

impl MemByteDevice {
    fn from_vec(data: Vec<u8>) -> Self {
        Self {
            data: Arc::new(Mutex::new(data)),
        }
    }
}

impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        let data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        u64::try_from(data.len()).unwrap_or(u64::MAX)
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let off = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset does not fit usize".to_owned()))?;
        let data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("read offset overflow".to_owned()))?;
        if end > data.len() {
            return Err(FfsError::Format(format!(
                "read out of bounds: {off}..{end} > {}",
                data.len()
            )));
        }
        buf.copy_from_slice(&data[off..end]);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let off = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset does not fit usize".to_owned()))?;
        let mut data = self
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("write offset overflow".to_owned()))?;
        if end > data.len() {
            return Err(FfsError::Format(format!(
                "write out of bounds: {off}..{end} > {}",
                data.len()
            )));
        }
        data[off..end].copy_from_slice(buf);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn build_ext4_image() -> Vec<u8> {
    let mut image = vec![0_u8; IMAGE_SIZE];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;
    let block_size = 1024_u32 << EXT4_BLOCK_SIZE_LOG;
    let blocks_count =
        u32::try_from(IMAGE_SIZE / usize::try_from(block_size).unwrap_or(1)).unwrap_or(u32::MAX);

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&EXT4_BLOCK_SIZE_LOG.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&(0x0002_u32 | 0x0040_u32).to_le_bytes());
    image[sb_off + 0x3A..sb_off + 0x3C].copy_from_slice(&EXT4_VALID_FS.to_le_bytes());
    image[sb_off + 0xE0..sb_off + 0xE4].copy_from_slice(&8_u32.to_le_bytes());
    image
}

fn make_commit(
    seq: u64,
    txn: u64,
    block: u64,
    fill: u8,
    len: usize,
    extra_block: Option<(u64, u8, usize)>,
) -> WalCommit {
    let mut writes = vec![WalWrite {
        block: BlockNumber(block),
        data: vec![fill; len.max(1)],
    }];
    if let Some((extra, extra_fill, extra_len)) = extra_block {
        writes.push(WalWrite {
            block: BlockNumber(extra),
            data: vec![extra_fill; extra_len.max(1)],
        });
    }
    WalCommit {
        commit_seq: CommitSeq(seq),
        txn_id: TxnId(txn),
        writes,
    }
}

fn corrupt_header_bytes(cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    let short_len = usize::from((cursor.next_u8() % 12) + 1);
    vec![cursor.next_u8(); short_len]
}

fn base_wal_bytes(seed: SeedCase, cursor: &mut ByteCursor<'_>) -> Option<Vec<u8>> {
    if matches!(seed, SeedCase::NoWalPath) {
        return None;
    }
    if matches!(seed, SeedCase::EmptyFile) {
        return Some(Vec::new());
    }
    if matches!(seed, SeedCase::CorruptHeader) {
        return Some(corrupt_header_bytes(cursor));
    }

    let len_a = usize::from((cursor.next_u8() % 24) + 1);
    let len_b = usize::from((cursor.next_u8() % 24) + 1);
    let extra_len = usize::from(cursor.next_u8() % 8);
    let mut bytes = Vec::from(wal::encode_header(&WalHeader::default()));

    match seed {
        SeedCase::Clean | SeedCase::TruncatedTail | SeedCase::EmptyFile | SeedCase::NoWalPath => {
            let c1 = make_commit(1, 1, 1, cursor.next_u8(), len_a, None);
            let c2 = make_commit(
                2,
                2,
                2,
                cursor.next_u8(),
                len_b,
                Some((3, cursor.next_u8(), extra_len)),
            );
            bytes.extend_from_slice(&wal::encode_commit(&c1).ok()?);
            bytes.extend_from_slice(&wal::encode_commit(&c2).ok()?);
            if matches!(seed, SeedCase::TruncatedTail) && bytes.len() > WAL_HEADER_SIZE + 4 {
                let chop = usize::from((cursor.next_u8() % 8) + 1);
                let new_len = bytes.len().saturating_sub(chop);
                bytes.truncate(new_len.max(WAL_HEADER_SIZE + 1));
            }
        }
        SeedCase::MonotonicityViolation => {
            let c1 = make_commit(2, 1, 10, cursor.next_u8(), len_a, None);
            let c2 = make_commit(1, 2, 20, cursor.next_u8(), len_b, None);
            bytes.extend_from_slice(&wal::encode_commit(&c1).ok()?);
            bytes.extend_from_slice(&wal::encode_commit(&c2).ok()?);
        }
        SeedCase::CorruptHeader => return Some(corrupt_header_bytes(cursor)),
    }

    Some(bytes)
}

fn mutate_bytes(bytes: &mut Vec<u8>, cursor: &mut ByteCursor<'_>) {
    if bytes.is_empty() {
        return;
    }

    let interesting = [
        0,
        1,
        2,
        3,
        4,
        WAL_HEADER_SIZE.saturating_sub(1),
        WAL_HEADER_SIZE,
        WAL_HEADER_SIZE + 1,
        bytes.len() / 2,
        bytes.len().saturating_sub(1),
    ];

    let flips = usize::from(cursor.next_u8() % 6);
    for _ in 0..flips {
        let offset = interesting[cursor.next_index(interesting.len())].min(bytes.len() - 1);
        bytes[offset] ^= cursor.next_u8();
    }

    if cursor.next_bool() && bytes.len() > WAL_HEADER_SIZE + 1 {
        let chop = usize::from(cursor.next_u8() % 8);
        bytes.truncate(bytes.len().saturating_sub(chop));
    }

    if cursor.next_bool() {
        let append = usize::from(cursor.next_u8() % 8);
        for _ in 0..append {
            bytes.push(cursor.next_u8());
        }
    }
}

fn persistent_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("frankenfs-fuzz-bd-mxdc9-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir
    })
}

fn persistent_path(name: &str) -> PathBuf {
    persistent_dir().join(name)
}

fn set_persistent_bytes(path: &Path, bytes: Option<&[u8]>) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match bytes {
        Some(payload) => {
            let _ = std::fs::write(path, payload);
        }
        None => {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn classify_report(report: &WalRecoveryReport) -> RecoveryClass {
    let outcome = match &report.outcome {
        WalReplayOutcome::Clean => RecoveryOutcomeClass::Clean,
        WalReplayOutcome::EmptyLog => RecoveryOutcomeClass::EmptyLog,
        WalReplayOutcome::TruncatedTail { records_discarded } => {
            RecoveryOutcomeClass::TruncatedTail {
                records_discarded: *records_discarded,
            }
        }
        WalReplayOutcome::CorruptTail {
            records_discarded,
            first_corrupt_offset,
        } => RecoveryOutcomeClass::CorruptTail {
            records_discarded: *records_discarded,
            first_corrupt_offset: *first_corrupt_offset,
        },
        WalReplayOutcome::MonotonicityViolation {
            violating_seq,
            expected_after,
        } => RecoveryOutcomeClass::MonotonicityViolation {
            violating_seq: *violating_seq,
            expected_after: *expected_after,
        },
    };

    RecoveryClass {
        outcome,
        commits_replayed: report.commits_replayed,
        versions_replayed: report.versions_replayed,
        records_discarded: report.records_discarded,
        wal_valid_bytes: report.wal_valid_bytes,
        wal_total_bytes: report.wal_total_bytes,
    }
}

fn store_digest(fs: &OpenFs) -> (usize, usize, u32) {
    let snapshot = fs.current_snapshot();
    let version_count = fs.mvcc_telemetry().version_count;
    let mut digest_bytes = Vec::new();
    let mut visible_entries = 0usize;

    for block in TRACKED_BLOCKS {
        if let Some(data) = fs.mvcc_read_visible(BlockNumber(block), snapshot) {
            visible_entries = visible_entries.saturating_add(1);
            digest_bytes.extend_from_slice(&block.to_le_bytes());
            let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
            digest_bytes.extend_from_slice(&len.to_le_bytes());
            digest_bytes.extend_from_slice(&data);
        }
    }

    (version_count, visible_entries, crc32c(&digest_bytes))
}

fn classify_open(wal_bytes: Option<&[u8]>, fail_fast: bool) -> OutcomeClass {
    let wal_path = persistent_path("openfs_mvcc_recovery.wal");
    set_persistent_bytes(&wal_path, wal_bytes);

    let cx = Cx::for_testing();
    let dev = MemByteDevice::from_vec(build_ext4_image());
    let options = OpenOptions {
        skip_validation: true,
        mvcc_wal_path: if wal_bytes.is_some() || fail_fast {
            Some(wal_path)
        } else {
            None
        },
        mvcc_replay_policy: if fail_fast {
            TailPolicy::FailFast
        } else {
            TailPolicy::TruncateToLastGood
        },
        ..OpenOptions::default()
    };

    match OpenFs::from_device(&cx, Box::new(dev), &options) {
        Ok(fs) => {
            let recovery = fs.mvcc_wal_recovery().map(classify_report);
            let (version_count, visible_entries, visible_digest) = store_digest(&fs);

            if let Some(report) = &recovery {
                assert!(
                    report.wal_valid_bytes <= report.wal_total_bytes,
                    "valid bytes must never exceed the total WAL bytes"
                );
                if report.commits_replayed > 0 {
                    assert!(
                        report.versions_replayed >= report.commits_replayed,
                        "replayed versions must cover every replayed commit"
                    );
                }
                if matches!(
                    report.outcome,
                    RecoveryOutcomeClass::Clean | RecoveryOutcomeClass::EmptyLog
                ) {
                    assert_eq!(
                        report.records_discarded, 0,
                        "clean or empty replay must not discard records"
                    );
                }
            }

            if fail_fast
                && recovery
                    .as_ref()
                    .is_some_and(|report| !matches!(report.outcome, RecoveryOutcomeClass::Clean))
            {
                assert_eq!(
                    version_count, 0,
                    "FailFast replay fallback must not leave visible MVCC versions behind"
                );
                assert_eq!(
                    visible_entries, 0,
                    "FailFast replay fallback must not leave visible block contents behind"
                );
            }

            OutcomeClass::Open {
                fail_fast,
                recovery,
                version_count,
                visible_entries,
                visible_digest,
            }
        }
        Err(err) => OutcomeClass::Err {
            errno: err.to_errno(),
            detail: err.to_string(),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let seed = SeedCase::from_selector(cursor.next_u8());
    let mut wal_bytes = base_wal_bytes(seed, &mut cursor);
    if let Some(bytes) = &mut wal_bytes {
        mutate_bytes(bytes, &mut cursor);
    }
    let fail_fast = cursor.next_bool();

    let first = classify_open(wal_bytes.as_deref(), fail_fast);
    let second = classify_open(wal_bytes.as_deref(), fail_fast);
    assert_eq!(
        first, second,
        "mount-time WAL recovery classification should be deterministic"
    );
});
